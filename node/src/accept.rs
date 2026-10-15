//! Block acceptance pipeline — acceptance separated from connection.
//!
//! Moved out of `main.rs` so integration tests can drive the REAL pipeline
//! (`gnb::accept::accept_block`). `main.rs` declares this module and `use`s the
//! same function names and signatures.
//!
//! # Semantics (audit DAG-1)
//!
//! Like Bitcoin Core's `AcceptBlock` / `ConnectBlock` split, and Kaspa's
//! "disqualified from chain" status:
//!
//! **Acceptance** (every block, any arrival order): parents known, header
//! height = max parent DAG height + 1, expected ASERT bits, timestamp, at/after
//! the hardening activation the context-free block rules of
//! `core::block_rules` (wire size, tagged Merkle root, 64-byte transactions,
//! coinbase height / parents / witness commitment), proof of work, and the
//! context-free consensus checks (canonical-encoding limits, MoneyRange; the
//! structural checks run in `validate_structure` before this function). A
//! failure here is context-free, so every node rejects the block and it is
//! never stored. A block that passes is inserted into GhostDAG and
//! its body is stored — fork-losers included — WITHOUT validating its
//! transactions against the current tip's UTXO set.
//!
//! **Connection**: the applied UTXO set always corresponds to the selected-
//! parent chain of the best (highest blue_work, blue_score, hash) block that is
//! not chain-disqualified. After an insertion the pipeline computes the plan
//! from the applied tip to that best block (an extension, several blocks, or a
//! reorg) and executes it in ONE atomic RocksDB batch (`reorg::connect_plan`),
//! validating every block of the plan against ITS OWN selected-chain context
//! (inputs, double spends, coinbase maturity, signatures, fees, coinbase
//! value). Merged (non-selected) blocks never affect the UTXO set — as before.
//!
//! **Invalid blocks**: a connect-time failure that depends only on data the
//! block id commits to is a deterministic property of the block and its
//! selected-parent chain, so it is permanent. The failing
//! block and every block whose selected-parent chain passes through it are
//! marked chain-disqualified, in memory (`GhostDAG::mark_invalid`) and on disk
//! (`Storage::stage_invalid_block`), and the next-best block is tried; the
//! old tip is kept when nothing better is valid. A disqualified block is never
//! selected, applied or offered as a template parent, and a new block whose
//! selected parent is disqualified is disqualified on arrival. `accept_block`
//! reports such blocks as rejected (`Err`).
//!
//! **Witness-dependent failures below the hardening activation**: there the
//! block id does not commit to non-coinbase `script_sig` bytes, so a relay
//! can alter them (breaking a signature, padding past the minimum fee)
//! without changing the id. Such a failure (`BlockInvalidity::
//! witness_dependent`) is a property of THIS BODY, not of the block: the body
//! is deleted, nothing is persisted, and the block (with its selected-chain
//! descendants) waits in memory for another body
//! (`GhostDAG::mark_body_pending`). The ingress paths do not treat it as
//! known (`is_known_block`), the processor re-requests it from peers, and a
//! copy with a different witness root replaces the body and is re-evaluated.
//! A block whose body is missing waits the same way. At/after the activation
//! the witness commitment is checked before the block is stored, so every
//! connect-time failure is permanent.
//!
//! **Blocks stored by a pre-upgrade binary**: at start-up
//! (`reconcile_on_startup`) the stored blocks at header height >= the
//! hardening activation are rechecked once against the context-free
//! hardening rules (`recheck_stored_blocks_under_hardening`); one that fails
//! for a reason its id commits to is disqualified with every DAG descendant
//! through ANY parent edge, since no upgraded peer can accept a block that
//! references it.
//!
//! Disqualified blocks are KEPT in the DAG (their insertion is not rolled
//! back) on purpose: whether a node evaluates a block at all depends on
//! arrival order (a fork-loser is never connected), so a block one node
//! disqualified can be an unevaluated tip on another node, which may merge it
//! as a NON-selected parent. If the first node had deleted the block it could
//! never accept that honest merging block, and the two would split. Since a
//! block's validity depends only on its selected-parent chain, keeping the
//! disqualified block lets both nodes accept the merger and converge.
//!
//! Policy refusals (reorg deeper than `MAX_REORG_DEPTH`, a new selected tip at
//! or below the finalized height) are NOT invalidity: the triggering block's
//! DAG insertion is rolled back and nothing is recorded, as before.
//!
//! **Arrival-order independence**: given the same block set, every node ends
//! with the applied tip = the best block whose selected chain is valid in its
//! own context, and the same UTXO set (the deterministic application of that
//! chain), whatever order the blocks arrived in (within the reorg-depth and
//! finality windows, which are local policy).
//!
//! # Serialization (audit DAG-10)
//!
//! The whole pipeline runs under `Storage::acceptance_lock()`. Lock order:
//! acceptance lock → DAG lock → everything else.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use log::{error, info, warn};
use parking_lot::RwLock;
use tokio::sync::broadcast;

use crate::coherence::ShieldedPool;
use crate::consensus::{self, BlockHash};
use crate::core;
use crate::mempool::{self, admission};
use crate::pow;
use crate::reorg::{self, ConnectError, ConnectHooks, ConnectOutcome, UtxoView};
use crate::rpc;
use crate::storage;
use crate::tip;

/// [no-fork] Set true while the miner is mining through a stalled IBD latch
/// (the announced heaviest tip is unreachable and we mine our locally-heaviest
/// validated tip to keep the chain live). While frozen we do NOT advance
/// `finalized_height`, so a strictly-heavier chain can still deep-reorg us back
/// once its holder becomes reachable — mine-through can never self-finalize a
/// solo fork. Driven by the miner loop; cleared when synced / catching up.
pub static FINALITY_FROZEN: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Set once from `--archive` at startup. Same static-flag shape as
/// FINALITY_FROZEN above: accept_block runs far from the CLI struct and
/// threading a bool through every caller would be noise for a value that is
/// fixed for the process lifetime.
pub static ARCHIVE_MODE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

// ── Invalid-set persistence ──────────────────────────────────────────────────

/// Reason prefix of the persisted marks written by the start-up hardening
/// recheck ([`recheck_stored_blocks_under_hardening`]). Such marks are
/// reloaded as all-edges roots (`GhostDAG::mark_invalid_all_edges`).
pub const HARDENING_RECHECK_REASON: &str = "fails the hardening block rules";

/// Load the persisted chain-disqualified set into `dag` once (start-up does it
/// via `reconcile_on_startup`; this is the lazy fallback).
pub fn ensure_invalid_set_loaded(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
) {
    if dag.read().invalid_set_loaded() {
        return;
    }
    match store.load_invalid_blocks_with_reasons() {
        Ok(marks) => {
            let (all_edges, selected): (Vec<_>, Vec<_>) = marks.into_iter()
                .partition(|(_, reason)| reason.starts_with(HARDENING_RECHECK_REASON));
            let n = dag.write().load_invalid_sets(
                selected.into_iter().map(|(h, _)| h),
                all_edges.into_iter().map(|(h, _)| h),
            );
            if n > 0 {
                info!("loaded {} chain-disqualified block(s)", n);
            }
        }
        Err(e) => error!("cannot read the persisted invalid-block set: {}", e),
    }
}

/// True iff `hash` is in the DAG but a body for it is still wanted: it waits
/// for a body after a witness-dependent failure
/// (`GhostDAG::is_body_pending`), or its body is missing although it was
/// never pruned (a body dropped after such a failure, before a restart). A
/// copy of such a block is processed (and re-requested from peers) instead of
/// being discarded as already known.
pub fn awaits_body(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
    hash: &BlockHash,
) -> bool {
    awaits_body_in(&dag.read(), store, hash)
}

/// [`awaits_body`] under a DAG guard the caller already holds.
pub fn awaits_body_in(d: &consensus::GhostDAG, store: &storage::Storage, hash: &BlockHash) -> bool {
    if d.is_body_pending(hash) {
        return true;
    }
    let dag_height = match d.get_block_data(hash) {
        Some(data) if !data.parents.is_empty() => data.height,
        _ => return false, // unknown, or the genesis
    };
    // Pruning removes bodies by HEADER height, which is >= the DAG height:
    // a block whose DAG height is at or above the pruning cursor was never
    // pruned.
    dag_height >= store.pruned_height() && matches!(store.has_block_body(hash), Ok(false))
}

/// True iff `hash` needs no further copy: it is in the DAG and does not
/// [`awaits_body`]. The dedup every ingress path (gossip, pulls, IBD,
/// `submitblock`) applies before `accept_block`.
pub fn is_known_block(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
    hash: &BlockHash,
) -> bool {
    is_known_block_in(&dag.read(), store, hash)
}

/// [`is_known_block`] under a DAG guard the caller already holds.
pub fn is_known_block_in(d: &consensus::GhostDAG, store: &storage::Storage, hash: &BlockHash) -> bool {
    d.has_block(hash) && !awaits_body_in(d, store, hash)
}

/// Stage the CF_DAG (+ integrity, + reachability delta) record of `hash`. If
/// the selected parent is the genesis and its integrity record was never
/// written (fixture stores), the genesis record is staged lazily in the same
/// batch; any other missing parent record is an error (DAG-11).
fn stage_dag_record_for(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
    batch: &mut rocksdb::WriteBatch,
    hash: &BlockHash,
) -> Result<(), String> {
    let data = dag.read().get_block_data(hash).cloned()
        .ok_or_else(|| format!("block {} vanished from the DAG", hex::encode(&hash[..8])))?;
    let mut parent_override = None;
    if let Some(sp) = data.selected_parent {
        let missing = store.get_integrity_hash(&sp).map_err(|e| e.to_string())?.is_none();
        let genesis = dag.read().store.genesis;
        if missing && genesis == Some(sp) {
            let gd = dag.read().get_block_data(&sp).cloned()
                .ok_or_else(|| "genesis vanished from the DAG".to_string())?;
            let gi = store.stage_dag_record(batch, &sp, &gd, &[], &[], None)
                .map_err(|e| e.to_string())?;
            parent_override = Some(gi);
        } else if missing {
            // Checked BEFORE draining the reachability delta below, so a
            // refused batch does not lose it.
            return Err(format!(
                "DAG record: integrity record of selected parent {} is missing; refusing to \
                 write a zero-filled chain link",
                hex::encode(&sp[..8])
            ));
        }
    }
    let (ups, rems) = if dag.read().maintains_reachability_index() {
        dag.write().reach_take_delta()
    } else {
        (Vec::new(), Vec::new())
    };
    store.stage_dag_record(batch, hash, &data, &ups, &rems, parent_override)
        .map(|_| ())
        .map_err(|e| format!("DAG record: {}", e))
}

// ── In-context block validation ──────────────────────────────────────────────

/// A connect-time rejection, classified by what it depends on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockInvalidity {
    pub reason: String,
    /// The failure depends on bytes the block id does not commit to: a
    /// non-coinbase `script_sig` (script parse, pubkey hash, signature, and
    /// the size-based minimum fee) of a block below the hardening activation.
    /// Another body with the same id may be valid, so the id must not be
    /// disqualified. Always `false` at/after the activation, where the
    /// witness commitment (checked before the block is stored) fixes every
    /// byte of the body.
    pub witness_dependent: bool,
}

/// A transaction-level rejection; `witness` = it depends on the
/// transaction's `script_sig` bytes (see [`BlockInvalidity`]).
#[derive(Debug)]
struct TxFailure {
    reason: String,
    witness: bool,
}

impl From<String> for TxFailure {
    fn from(reason: String) -> Self {
        Self { reason, witness: false }
    }
}

/// Validate `tx` (a non-coinbase transaction of a block at header height
/// `block_height`) against `view` plus the outputs of the transactions
/// STRICTLY BEFORE it in the block (`earlier`). The transaction rules
/// (version, witness, digest) are evaluated at `block_height` under
/// `activation_height`; coinbase maturity at `maturity_height` (the block
/// path passes `block_height`; `0` skips the maturity check). When
/// `same_block_coinbase` is `Some` (hardening rules, audit VAL-3) an input
/// spending that coinbase's outputs is rejected. Returns the fee.
#[allow(clippy::too_many_arguments)]
fn validate_tx_in_view(
    tx: &core::Transaction,
    view: &dyn UtxoView,
    earlier: &HashMap<([u8; 32], u32), core::TxOutput>,
    spent_in_block: &mut HashSet<([u8; 32], u32)>,
    block_height: u64,
    maturity_height: u64,
    same_block_coinbase: Option<&[u8; 32]>,
    activation_height: u64,
) -> Result<u64, TxFailure> {
    if let Some(cb) = same_block_coinbase {
        if let Some(i) = tx.inputs.iter().position(|inp| &inp.prev_txid == cb) {
            return Err(format!(
                "coinbase maturity: input {} spends the coinbase of its own block (0 confirmations, need {})",
                i, core::COINBASE_MATURITY
            ).into());
        }
    }
    core::check_coinbase_maturity(tx, maturity_height, |txid| {
        view.view_coinbase_height(txid).ok().flatten()
    })?;
    let lookup = |txid: &[u8; 32], idx: u32| -> Result<Option<core::TxOutput>, String> {
        if let Some(out) = earlier.get(&(*txid, idx)) {
            return Ok(Some(out.clone()));
        }
        view.view_utxo(txid, idx)
    };
    validate_tx_inputs_classified(tx, &lookup, Some(spent_in_block), block_height, activation_height)
}

/// BIP30 (audit VAL-2) for one transaction of a block subject to the
/// hardening rules: none of `tx`'s outputs may have the outpoint of a coin
/// that is unspent in `view` (the parent's state). The block path checks every
/// transaction of the block, the coinbase included, before validating any;
/// [`validate_tx_in_block_with_maturity`] checks the transaction it validates.
fn check_no_unspent_overwrite(view: &dyn UtxoView, tx: &core::Transaction) -> Result<(), String> {
    let txid = tx.txid();
    for j in 0..tx.outputs.len() as u32 {
        if view.view_utxo(&txid, j)?.is_some() {
            return Err(format!(
                "BIP30: output {}:{} would overwrite an unspent coin",
                hex::encode(&txid[..8]), j
            ));
        }
    }
    Ok(())
}

/// Full in-context validation of a block's transactions against `view` (the
/// UTXO state of its selected parent): every non-coinbase transaction (inputs
/// exist, no double spend, maturity, scripts, value, minimum fee) and the
/// coinbase value against subsidy + fees. The rules are exactly the ones the
/// pre-fix `accept_block` applied to an extension block; the difference is
/// only WHICH state a block is checked against (its own, never the tip's).
///
/// THE shared connect-time rule: the acceptance pipeline calls it for an
/// extension and for every block of a reorg (`reorg::connect_plan`), under
/// the process-wide hardening activation height (see
/// [`validate_block_in_view_at`] for the rules that change there). The
/// pipeline itself calls the classified variant
/// ([`validate_block_in_view_classified`], same verdict); this unclassified
/// form is library API (tests), unused by the `gnb` binary, which compiles
/// this file as its own module.
#[allow(dead_code)]
pub fn validate_block_in_view(view: &dyn UtxoView, block: &core::Block) -> Result<(), String> {
    validate_block_in_view_at(view, block, core::activation::hardening_activation_height())
}

/// [`validate_block_in_view`] for an explicit activation height. At/after
/// the activation (`core::block_rules::rules_active_at(block.height, ..)`):
///
/// * **BIP30 (audit VAL-2)**: no output of the block may have the outpoint of
///   a coin that is unspent in `view` (the parent's state), checked for every
///   transaction, the coinbase included, before any transaction is validated;
/// * **no same-block coinbase spend (audit VAL-3)**: the coinbase's outputs
///   are not in the in-block prevout map, and an input spending them is
///   rejected as a coinbase-maturity violation.
///
/// Below the activation both rules are absent, exactly as before. The
/// transaction rules of the same activation (version 3 / sighash v3 /
/// canonical witnesses, `core::sighash`) are evaluated at the same height
/// (`block.height`, also the coinbase-maturity height) under the same
/// `activation_height` (`admission::verify_input_scripts_at`). Library API
/// like [`validate_block_in_view`] (unused by the `gnb` binary).
#[allow(dead_code)]
pub fn validate_block_in_view_at(
    view: &dyn UtxoView,
    block: &core::Block,
    activation_height: u64,
) -> Result<(), String> {
    validate_block_in_view_classified_at(view, block, activation_height).map_err(|e| e.reason)
}

/// [`validate_block_in_view`] with the failure classified (see
/// [`BlockInvalidity`]): the acceptance pipeline uses the class to decide
/// whether the block id is disqualified (persisted) or only this body is
/// dropped. The verdict (`Ok` / `Err`) is exactly `validate_block_in_view`'s.
pub fn validate_block_in_view_classified(view: &dyn UtxoView, block: &core::Block) -> Result<(), BlockInvalidity> {
    validate_block_in_view_classified_at(view, block, core::activation::hardening_activation_height())
}

/// [`validate_block_in_view_classified`] for an explicit activation height.
pub fn validate_block_in_view_classified_at(
    view: &dyn UtxoView,
    block: &core::Block,
    activation_height: u64,
) -> Result<(), BlockInvalidity> {
    let committed = |reason: String| BlockInvalidity { reason, witness_dependent: false };
    let height = block.height;
    let hardened = core::block_rules::rules_active_at(height, activation_height);
    if hardened {
        for tx in &block.transactions {
            check_no_unspent_overwrite(view, tx).map_err(committed)?;
        }
    }
    let same_block_coinbase = if hardened {
        block.transactions.first().map(|cb| cb.txid())
    } else {
        None
    };
    let mut spent_in_block: HashSet<([u8; 32], u32)> = HashSet::new();
    let mut earlier: HashMap<([u8; 32], u32), core::TxOutput> = HashMap::new();
    let mut total_fees: u64 = 0;
    for (i, tx) in block.transactions.iter().enumerate() {
        if i > 0 {
            let fee = validate_tx_in_view(
                tx, view, &earlier, &mut spent_in_block, height, height, same_block_coinbase.as_ref(),
                activation_height,
            ).map_err(|f| BlockInvalidity {
                reason: f.reason,
                // At/after the activation the witness commitment fixed the body.
                witness_dependent: f.witness && !hardened,
            })?;
            total_fees = core::limits::money_add(total_fees, fee)
                .map_err(|e| committed(format!("block fee sum: {}", e)))?;
        }
        if hardened && i == 0 {
            continue; // VAL-3: the coinbase's outputs are not spendable in its own block
        }
        let txid = tx.txid();
        for (j, o) in tx.outputs.iter().enumerate() {
            earlier.insert((txid, j as u32), o.clone());
        }
    }
    block.validate_coinbase_value(total_fees)
        .map_err(|e| committed(format!("coinbase rejected: {}", e)))
}

// ── Shielded state (COH-2) ───────────────────────────────────────────────────
//
// The shielded pool moves with the applied chain: `ShieldedPool::stage_plan`
// moves it in memory along the plan (no clone: in-place apply/undo with an
// exact revert journal) and returns its writes, which `stage_extra` folds into
// the plan's WriteBatch; after the commit the staged plan is committed, on
// any failure it is reverted. The shielded lock is taken only for those short
// steps (acceptance is serialized by the acceptance lock, and the pipeline is
// the only user of the pool).

// ── Mempool maintenance after a connect (MEM-3, MEM-7) ──────────────────────

/// Bring the mempool in line with a committed chain move: drop confirmed txs
/// and every tx conflicting with an outpoint the connected blocks spent;
/// after a reorg re-admit the disconnected txs through the shared admission
/// function and re-validate the whole pool against the new UTXO set; clear
/// the recent-rejects filter (the tip changed) and expire stale entries.
///
/// `next_height` is the node's next template height on the DAG AFTER the
/// move (`template::next_template_height`, the value `accept_block` passes):
/// the ONE height admission, eviction, re-injection, templates and wallets
/// use. It is NOT the new tip's header height + 1: a tip that merged a
/// parent with a greater DAG height than its selected parent has a header
/// height above its DAG height (DAG-8), while a child of that tip alone sits
/// at its DAG height + 1, so the header height would evict transactions that
/// are still valid for the next block. It is recorded in
/// `Mempool::next_height` first, so concurrent admissions re-check against it.
/// Call under the acceptance lock.
pub fn update_mempool_after_connect(
    store: &storage::Storage,
    mempool: &mempool::Mempool,
    outcome: &ConnectOutcome,
    next_height: u64,
) {
    let previous = mempool.set_next_height(next_height);
    let confirmed: Vec<[u8; 32]> = outcome.connected.iter()
        .flat_map(|b| b.transactions.iter().map(|t| t.txid()))
        .collect();
    mempool.remove_confirmed(&confirmed);
    let spent: Vec<([u8; 32], u32)> = outcome.connected.iter()
        .flat_map(|b| b.transactions.iter().filter(|t| !t.is_coinbase()))
        .flat_map(|t| t.inputs.iter().map(|i| (i.prev_txid, i.prev_index)))
        .collect();
    let swept = mempool.remove_conflicts(&spent);
    if !swept.is_empty() {
        info!("mempool: removed {} tx(s) conflicting with the connected block(s)", swept.len());
    }
    // CRY-3 activation: after EVERY connect (extension or reorg) drop pooled
    // transactions whose version is invalid or non-standard for the next
    // block (version 1/2 once the next block is at/after the hardening
    // activation; version >= 3 after a reorg back below it). Cheap: no I/O,
    // no signatures.
    // When the next height went DOWN on an extension (the new tip merged the
    // tip that set the old, higher template height), maturity can also be
    // lost: run the full signature-free revalidation instead (a reorg runs it
    // below anyway).
    if !outcome.connected.is_empty() {
        let lower = previous != 0 && next_height < previous && outcome.disconnected.is_empty();
        let stale = if lower {
            revalidate_mempool(store, mempool, next_height)
        } else {
            evict_version_invalid(mempool, next_height)
        };
        if stale > 0 {
            info!("mempool: evicted {} tx(s) no longer valid for the next block at height {}", stale, next_height);
        }
    }
    if !outcome.disconnected.is_empty() {
        // Oldest disconnected block first: a child confirmed after its parent
        // is re-admitted after it, as an in-pool chain (MEM-6).
        let candidates: Vec<core::Transaction> = outcome.disconnected_txs_oldest_first();
        let (re, dropped) = reorg::reinject_disconnected(store, mempool, candidates, next_height);
        let stale = revalidate_mempool(store, mempool, next_height);
        info!("reorg: mempool reinjected={} discarded={} invalidated={}", re, dropped, stale);
    }
    mempool.clear_recent_rejects();
    let expired = mempool.expire_older_than(mempool::MEMPOOL_EXPIRY_SECS);
    if expired > 0 {
        info!("mempool: expired {} tx(s) older than {} s", expired, mempool::MEMPOOL_EXPIRY_SECS);
    }
}

/// Drop every pooled tx whose version the consensus rule or the version policy
/// rejects for a block at `next_height`, or that the 64-byte rule forbids
/// there (`admission::check_tx_for_next_block`). Returns how many were
/// removed.
pub fn evict_version_invalid(mempool: &mempool::Mempool, next_height: u64) -> usize {
    mempool.retain_valid(|e| admission::check_tx_for_next_block(&e.tx, next_height).is_ok())
}

/// MEM-3: drop every pooled tx that is no longer minable on the current
/// UTXO set (an input missing, an immature coinbase input at `next_height`,
/// a fee below the consensus minimum, a version invalid or non-standard at
/// `next_height`, or a 64-byte txid preimage at/after the activation:
/// `admission::check_tx_for_next_block`). An input may also be an output of
/// another pooled tx (MEM-6 chains); a tx that fails is removed together
/// with its in-pool descendants. Signature-free and cheap. Returns how many
/// were removed.
pub fn revalidate_mempool(store: &storage::Storage, mempool: &mempool::Mempool, next_height: u64) -> usize {
    mempool.retain_valid_with(|e, pool_output| {
        if admission::check_tx_for_next_block(&e.tx, next_height).is_err() {
            return false;
        }
        let mut total_in: u64 = 0;
        for inp in &e.tx.inputs {
            let prev = match store.get_utxo(&inp.prev_txid, inp.prev_index) {
                Ok(Some(o)) => Some(o),
                Ok(None) => pool_output(&inp.prev_txid, inp.prev_index),
                Err(_) => None,
            };
            match prev {
                Some(o) => match core::limits::money_add(total_in, o.value) {
                    Ok(t) => total_in = t,
                    Err(_) => return false,
                },
                None => return false,
            }
        }
        if core::check_coinbase_maturity(&e.tx, next_height, |t| store.get_coinbase_height(t).ok().flatten()).is_err() {
            return false;
        }
        match core::limits::check_tx_money_range(&e.tx) {
            Ok(out) if out <= total_in => core::check_min_fee(&e.tx, total_in - out).is_ok(),
            _ => false,
        }
    })
}

/// Keep `Mempool::next_height` equal to the node's next template height after
/// a DAG change that connected nothing (a fork-loser or merge candidate
/// stored, a block disqualified): a new tip with a greater DAG height, or a
/// disqualified one, moves the template height without moving the applied
/// tip. When the height moved, clear the recent-rejects filter (its verdicts
/// were computed for the old height), drop the transactions whose version is
/// invalid or non-standard at the new height and, when it went down, the ones
/// no longer mature (`revalidate_mempool`). Call under the acceptance lock (or
/// at start-up before any concurrent acceptance). Returns the height.
pub fn sync_mempool_next_height(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
    mempool: &mempool::Mempool,
) -> u64 {
    let next = crate::template::next_template_height(&dag.read(), store);
    let previous = mempool.set_next_height(next);
    if previous != next {
        // Review finding: the recent-rejects filter holds verdicts computed
        // for the previous next height (the version rule and policy, the
        // 64-byte rule, coinbase maturity). Without a tip change nothing else
        // clears it, so a transaction refused for H-1 stayed "recently
        // rejected" at H (RPC and gossip) until the next tip change.
        mempool.clear_recent_rejects();
    }
    if previous != 0 && previous != next {
        let dropped = if next < previous {
            revalidate_mempool(store, mempool, next)
        } else {
            evict_version_invalid(mempool, next)
        };
        if dropped > 0 {
            info!("mempool: next block height {} -> {}: evicted {} tx(s) no longer valid for it",
                previous, next, dropped);
        }
    }
    next
}

// ── The pipeline ─────────────────────────────────────────────────────────────

/// Outcome of resolving the best valid chain after a DAG change.
enum Resolution {
    /// The applied tip did not move (fork-loser, merged-only, or every better
    /// candidate turned out invalid).
    Unchanged,
    /// The applied chain moved (extension or reorg) and was committed.
    Connected { plan: reorg::ReorgPlan, outcome: ConnectOutcome },
}

/// Why resolution stopped without a usable result.
enum ResolveStop {
    /// Policy refusal: roll the trigger back, nothing is invalid.
    Refused(String),
    /// Storage failure: roll the trigger back, retry later.
    Failed(String),
}

/// Where `resolve_best_chain` records what it found on the way.
#[derive(Default)]
struct ResolveLog {
    /// (root, reason) for every newly disqualified root (persisted).
    invalid: Vec<(BlockHash, String)>,
    /// (block, reason) for every block whose body was dropped after a
    /// witness-dependent failure (never persisted; see `drop_body_and_wait`).
    body_rejected: Vec<(BlockHash, String)>,
}

/// Move the applied chain to the best valid block, marking blocks invalid as
/// they fail. `trigger` is the block whose insertion prompted the call (the
/// finality rule applies to it); its DAG record is folded into the commit
/// batch when `stage_trigger_record` (a new insertion, not a body
/// replacement). `log` accumulates the disqualified roots and the dropped
/// bodies.
///
/// A block of the plan whose body is missing, or whose body fails a rule
/// that depends on witness bytes its id does not commit to (below the
/// hardening activation), is NOT disqualified: its body is dropped and it
/// waits, in memory only, for another body (`GhostDAG::mark_body_pending`);
/// the next-best chain is tried meanwhile.
#[allow(clippy::too_many_arguments)]
fn resolve_best_chain(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
    shielded: &Arc<RwLock<ShieldedPool>>,
    applied_tip: BlockHash,
    trigger: Option<BlockHash>,
    stage_trigger_record: bool,
    trigger_header_height: u64,
    finalized_height: u64,
    log: &mut ResolveLog,
) -> Result<Resolution, ResolveStop> {
    // Each iteration either commits, stops, or disqualifies (or parks) at
    // least one more block; the DAG is finite, so this terminates. The bound
    // is a guard.
    for _ in 0..10_000 {
        let cand = match dag.read().selected_tip() {
            Some(c) => c,
            None => return Ok(Resolution::Unchanged),
        };
        if cand == applied_tip {
            return Ok(Resolution::Unchanged);
        }
        let plan = {
            let d = dag.read();
            // The best valid block can be an ANCESTOR of the applied tip when
            // applied blocks were disqualified (start-up hardening recheck):
            // then the plan only disconnects.
            reorg::compute_connect_plan(&d, &applied_tip, &cand)
                .or_else(|| reorg::compute_rollback_plan(&d, &applied_tip, &cand))
        };
        let plan = match plan {
            Some(p) => p,
            None => return Err(ResolveStop::Failed(format!(
                "U.4: unexpected selected-tip transition (applied={}, best={}): no connect plan",
                hex::encode(&applied_tip[..8]), hex::encode(&cand[..8])))),
        };

        // Finality invariant: a block at or below the finalized height must
        // never become the selected tip (it would rewrite finalized history).
        if let Some(t) = trigger {
            if plan.to_apply.contains(&t) && trigger_header_height <= finalized_height {
                return Err(ResolveStop::Refused(format!(
                    "finality: block h={} may not become the selected tip at or below finalized height {}",
                    trigger_header_height, finalized_height
                )));
            }
        }

        // A block without a stored body cannot be connected: wait for one.
        let mut missing = None;
        for h in &plan.to_apply {
            match store.has_block_body(h) {
                Ok(true) => {}
                Ok(false) => {
                    missing = Some(*h);
                    break;
                }
                Err(e) => return Err(ResolveStop::Failed(e.to_string())),
            }
        }
        if let Some(h) = missing {
            warn!("block {} has no stored body; waiting for one before connecting its chain",
                hex::encode(&h[..8]));
            dag.write().mark_body_pending(h, None);
            continue;
        }

        let staged_shielded = shielded.write().stage_plan(store, &plan);
        let staged_shielded = match staged_shielded {
            Ok(s) => s,
            Err(ConnectError::Invalid { block, reason, .. }) => {
                // The shielded bytes are committed by the header root.
                disqualify(dag, block, reason, &mut log.invalid);
                continue;
            }
            Err(e) => return Err(ResolveStop::Failed(e.to_string())),
        };

        let reorg_depth = plan.to_rollback.len();
        if reorg_depth > 0 {
            crate::metrics::inc_reorg_attempt();
            crate::metrics::set_fork_depth(reorg_depth as i64);
            crate::metrics::observe_reorg_depth(reorg_depth as f64);
        }

        // The validator reports, beside the verdict, whether the failure
        // depends on witness bytes (block id, witness root of the body).
        let witness_failure: std::cell::Cell<Option<(BlockHash, [u8; 32])>> = std::cell::Cell::new(None);
        let validate = |view: &dyn UtxoView, b: &core::Block| -> Result<(), String> {
            match validate_block_in_view_classified(view, b) {
                Ok(()) => Ok(()),
                Err(e) => {
                    witness_failure.set(e.witness_dependent.then(|| {
                        (b.block_hash(), core::block_rules::witness_root(&b.transactions).0)
                    }));
                    Err(e.reason)
                }
            }
        };
        let new_tip = cand;
        let log_snapshot = log.invalid.clone();
        let stage_extra = |st: &storage::Storage, batch: &mut rocksdb::WriteBatch| -> Result<(), String> {
            if let (Some(t), true) = (trigger, stage_trigger_record) {
                if dag.read().has_block(&t) {
                    stage_dag_record_for(dag, st, batch, &t)?;
                }
            }
            stage_invalid_marks(dag, st, batch, &log_snapshot)?;
            // COH-2: the shielded state of the plan, in the same batch.
            staged_shielded.stage_into(st, batch)?;
            st.stage_meta(batch, "tip_hash", &new_tip).map_err(|e| e.to_string())
        };
        let hooks = ConnectHooks { validate: &validate, stage_extra: &stage_extra };
        let result = reorg::connect_plan(store, &plan, &hooks);
        match &result {
            Ok(_) => shielded.write().commit_staged(staged_shielded),
            Err(_) => shielded.write().revert_staged(staged_shielded),
        }
        match result {
            Ok(outcome) => {
                if reorg_depth > 0 { crate::metrics::inc_reorg_success(); }
                // Marks were persisted in the batch.
                log.invalid.clear();
                return Ok(Resolution::Connected { plan, outcome });
            }
            Err(ConnectError::Invalid { block, reason, .. }) => {
                if reorg_depth > 0 { crate::metrics::inc_reorg_failure(); }
                match witness_failure.take() {
                    Some((h, witness_root)) if h == block => {
                        drop_body_and_wait(dag, store, block, witness_root, reason, &mut log.body_rejected);
                    }
                    _ => disqualify(dag, block, reason, &mut log.invalid),
                }
                continue;
            }
            Err(ConnectError::Refused(m)) => {
                if reorg_depth > 0 { crate::metrics::inc_reorg_failure(); }
                return Err(ResolveStop::Refused(m));
            }
            Err(ConnectError::Failed(m)) => {
                if reorg_depth > 0 { crate::metrics::inc_reorg_failure(); }
                return Err(ResolveStop::Failed(m));
            }
        }
    }
    Err(ResolveStop::Failed("resolve_best_chain: iteration guard reached".into()))
}

/// `block`'s stored body failed a rule that depends on witness bytes its id
/// does not commit to (below the hardening activation a relay can change a
/// non-coinbase `script_sig` without changing the block id). Unlike
/// [`disqualify`], nothing is persisted and the block id is not poisoned:
/// the body is deleted (so it is never served to peers again) and the block,
/// with its selected-chain descendants, waits in memory for a different body
/// (`GhostDAG::mark_body_pending`), which every ingress path accepts
/// (`awaits_body`) and the message processor re-requests from peers.
fn drop_body_and_wait(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
    block: BlockHash,
    witness_root: [u8; 32],
    reason: String,
    body_log: &mut Vec<(BlockHash, String)>,
) {
    let marked = dag.write().mark_body_pending(block, Some(witness_root));
    if let Err(e) = store.delete_block_body(&block) {
        error!("could not delete the rejected body of {}: {}", hex::encode(&block[..8]), e);
    }
    warn!(
        "block {} body rejected ({}): the failure depends on witness bytes the block id does not \
         commit to, so the id is NOT disqualified; body dropped, waiting for another copy \
         ({} selected-chain descendant(s) wait with it)",
        hex::encode(&block[..8]), reason, marked.len().saturating_sub(1)
    );
    body_log.push((block, reason));
}

/// Disqualify `block` (and its selected-chain descendants) in memory and
/// remember the root + reason for persistence.
fn disqualify(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    block: BlockHash,
    reason: String,
    invalid_log: &mut Vec<(BlockHash, String)>,
) {
    let marked = dag.write().mark_invalid(block);
    warn!(
        "block {} is invalid in its own context ({}); disqualified with {} selected-chain descendant(s)",
        hex::encode(&block[..8]), reason, marked.len().saturating_sub(1)
    );
    invalid_log.push((block, reason));
}

/// Stage persistent marks for every logged root and its marked descendants.
fn stage_invalid_marks(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
    batch: &mut rocksdb::WriteBatch,
    log: &[(BlockHash, String)],
) -> Result<(), String> {
    for (root, reason) in log {
        if !dag.read().has_block(root) {
            continue;
        }
        store.stage_invalid_block(batch, root, reason).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Persist the trigger's DAG record (if it is still in the DAG) and every
/// pending invalid mark in one batch — used when the applied chain did not
/// move.
fn persist_unchanged(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
    trigger: Option<BlockHash>,
    invalid_log: &[(BlockHash, String)],
) -> Result<(), String> {
    let mut batch = rocksdb::WriteBatch::default();
    if let Some(t) = trigger {
        if dag.read().has_block(&t) {
            stage_dag_record_for(dag, store, &mut batch, &t)?;
        }
    }
    stage_invalid_marks(dag, store, &mut batch, invalid_log)?;
    store.write_batch(batch).map_err(|e| e.to_string())
}

/// What one or more acceptance calls did to the applied (selected) chain:
/// the NET effect of every committed plan, accumulated in order (a block
/// connected by one call and disconnected by a later one appears in neither
/// list). Under the selected-chain-only ledger (docs/CONSENSUS.md) these are
/// the only blocks whose transactions were applied or un-applied; a block
/// stored as a fork-loser or merge candidate applies nothing. Consumers: the
/// orphan-transaction bookkeeping (`mempool::relay::TxRelay::on_chain_moved`),
/// which must treat exactly the transactions the mempool treats as confirmed
/// (`update_mempool_after_connect` reads the same `ConnectOutcome`).
#[derive(Debug, Default, Clone)]
pub struct ChainMove {
    /// Blocks added to the applied chain and still on it, in connect order.
    pub connected: Vec<core::Block>,
    /// Blocks removed from the applied chain that were on it before the first
    /// recorded plan, in disconnect order (tip first).
    pub disconnected: Vec<core::Block>,
}

impl ChainMove {
    /// Fold one committed plan's outcome in.
    pub fn record(&mut self, outcome: ConnectOutcome) {
        for b in outcome.disconnected {
            let h = b.block_hash();
            match self.connected.iter().position(|c| c.block_hash() == h) {
                Some(i) => {
                    self.connected.remove(i);
                }
                None => self.disconnected.push(b),
            }
        }
        for b in outcome.connected {
            let h = b.block_hash();
            match self.disconnected.iter().position(|d| d.block_hash() == h) {
                Some(i) => {
                    self.disconnected.remove(i);
                }
                None => self.connected.push(b),
            }
        }
    }

    /// True iff the applied chain did not move.
    pub fn is_empty(&self) -> bool {
        self.connected.is_empty() && self.disconnected.is_empty()
    }

    /// Every transaction of the connected blocks (coinbases included), in
    /// connect order.
    pub fn connected_txs(&self) -> Vec<core::Transaction> {
        self.connected.iter().flat_map(|b| b.transactions.iter().cloned()).collect()
    }

    /// The non-coinbase transactions of the disconnected blocks, oldest
    /// disconnected block first (the order reorg re-injection uses).
    pub fn disconnected_txs(&self) -> Vec<core::Transaction> {
        self.disconnected.iter().rev()
            .flat_map(|b| b.transactions.iter().filter(|t| !t.is_coinbase()).cloned())
            .collect()
    }
}

/// Accept a block: acceptance checks, DAG insertion, then connect the best
/// valid chain atomically (see the module documentation for the semantics).
/// Returns `Ok(block_hash)` when the block was accepted into the DAG and is
/// not disqualified (connected or stored as a fork-loser / merge candidate).
/// Returns `Err` for every rejection, including a block stored but
/// disqualified (invalid in its own context, or descending from an invalid
/// selected parent).
#[allow(clippy::too_many_arguments)]
pub fn accept_block(
    block:      &core::Block,
    block_hash: [u8; 32],
    height:     u64,
    dag:        &Arc<RwLock<consensus::GhostDAG>>,
    store:      &Arc<storage::Storage>,
    mempool:    &Arc<mempool::Mempool>,
    node_state: &Arc<RwLock<rpc::NodeState>>,
    // Sprint 2.c: tip-change broadcast for stratum re-notify.
    // None disables notification (tests, CLI without --stratum).
    tip_tx:     Option<&broadcast::Sender<tip::TipChanged>>,
    // Coherence C2: the node's shielded-pool engine. Applied only for blocks
    // that join the selected chain (COH-2).
    shielded:   &Arc<RwLock<ShieldedPool>>,
) -> Result<[u8; 32], String> {
    let mut ignored = ChainMove::default();
    accept_block_tracking(block, block_hash, height, dag, store, mempool, node_state, tip_tx, shielded, &mut ignored)
}

/// [`accept_block`] that also records into `chain` what the call did to the
/// applied chain ([`ChainMove`]): nothing for a fork-loser / merge candidate
/// (the block is accepted but applies no transaction), the connected and
/// disconnected blocks of a committed extension or reorg — also when the
/// arriving block itself is reported invalid while another chain was
/// connected.
#[allow(clippy::too_many_arguments)]
pub fn accept_block_tracking(
    block:      &core::Block,
    block_hash: [u8; 32],
    height:     u64,
    dag:        &Arc<RwLock<consensus::GhostDAG>>,
    store:      &Arc<storage::Storage>,
    mempool:    &Arc<mempool::Mempool>,
    node_state: &Arc<RwLock<rpc::NodeState>>,
    tip_tx:     Option<&broadcast::Sender<tip::TipChanged>>,
    shielded:   &Arc<RwLock<ShieldedPool>>,
    chain:      &mut ChainMove,
) -> Result<[u8; 32], String> {
    // DAG-10: one acceptance at a time, across every ingress path.
    let _accept_guard = store.acceptance_lock();
    ensure_invalid_set_loaded(dag, store);

    // Sprint 2.c: snapshot the selected tip BEFORE any DAG mutation so we can
    // detect whether this block changed the chain's head.
    let old_tip = { dag.read().selected_tip() };

    // ── Early dedup ──────────────────────────────────────────────────
    // A block already in the DAG is refused, unless it waits for a body
    // (its previous body failed a witness-dependent rule, or is missing):
    // then this copy REPLACES the body and is re-evaluated, after the same
    // acceptance checks as a new block.
    let in_dag = dag.read().has_block(&block_hash);
    let replacing = if in_dag {
        if !awaits_body(dag, store, &block_hash) {
            return Err(format!(
                "consensus rejection: block already in DAG: {}",
                hex::encode(block_hash)
            ));
        }
        let witness_root = core::block_rules::witness_root(&block.transactions).0;
        if dag.read().body_rejected_before(&block_hash, &witness_root) {
            return Err(format!(
                "consensus rejection: block already in DAG: {} (this body was already rejected; \
                 waiting for a different one)",
                hex::encode(block_hash)
            ));
        }
        true
    } else {
        false
    };

    // ── Parents must be known (cheap, before anything else) ──────────
    if block.header.parents.is_empty() {
        return Err("consensus rejection: non-genesis block without parents".into());
    }
    let parent_data: Vec<(u64, u64)> = {
        let d = dag.read();
        let mut v = Vec::with_capacity(block.header.parents.len());
        for p in &block.header.parents {
            match d.get_block_data(p) {
                Some(data) => v.push((data.height, data.timestamp)),
                None => return Err(format!(
                    "consensus rejection: unknown parent {}", hex::encode(p))),
            }
        }
        v
    };

    // ── FIX VULN-02: header height = max parent DAG height + 1 ───────
    let expected_height = parent_data.iter().map(|(h, _)| *h).max().unwrap_or(0) + 1;
    if block.height != expected_height || height != expected_height {
        return Err(format!(
            "invalid height: block claims h={} but expected h={}",
            block.height, expected_height
        ));
    }

    // ── FIX VULN-01: difficulty bits must equal the ASERT schedule ───
    let parent_ts = core::difficulty_parent_timestamp(parent_data.iter().map(|(_, t)| *t));
    let expected_bits = pow::expected_bits(parent_ts, block.height)
        .map_err(|e| format!("invalid difficulty: {}", e))?;
    if block.header.bits != expected_bits {
        return Err(format!(
            "invalid difficulty: block bits 0x{:08x} != expected 0x{:08x}",
            block.header.bits, expected_bits
        ));
    }

    let finalized_height = store.get_meta("finalized_height").ok().flatten()
        .and_then(|b| b.as_slice().try_into().ok().map(u64::from_le_bytes))
        .unwrap_or(0);

    // ── FIX VULN-04: Validate timestamp ──────────────────────────────
    {
        let parent_ts = parent_data.iter().map(|(_, t)| *t).max().unwrap_or(0);
        block.validate_timestamp(parent_ts)
            .map_err(|e| format!("timestamp rejected: {}", e))?;
    }

    // ── Hardening block rules (context-free; the header height is now
    //    verified). At/after the activation: wire-size limit, tagged Merkle
    //    root, no 64-byte transaction, coinbase height / parents / witness
    //    commitment (audit VAL-2, VAL-10, VAL-12, CRY-1). Checked BEFORE the
    //    block is stored and before any signature work, so a block whose
    //    witnesses were altered in transit (same block id) is refused without
    //    a trace, and the honest copy of that id is still accepted later. A
    //    no-op below the activation.
    core::block_rules::check_block_hardened_at(block, core::activation::hardening_activation_height())
        .map_err(|e| format!("consensus rejection: {}", e))?;

    // ── Proof of work (expensive: 64 MiB GnB-SMH, cached by block id) ─
    if !block.validate_pow() {
        return Err("consensus rejection: invalid GnB-SMH proof of work".into());
    }

    // ── Context-free consensus checks (VAL-11 MoneyRange, VAL-12 canonical
    //    encoding limits). No-ops for every block that went through the wire
    //    parser; they stop an in-process block that could not be read back.
    core::limits::check_block_context_free(block)
        .map_err(|e| format!("consensus rejection: {}", e))?;
    // The connect-time validator treats transaction 0 as the coinbase and
    // keys in-block prevouts by txid. Every ingress path already enforces
    // both rules through `validate_structure`; re-checking them here (cheap)
    // keeps the pipeline sound for any in-process caller that does not.
    if !block.validate_coinbase_format() {
        return Err("consensus rejection: invalid coinbase format".into());
    }
    block.validate_no_duplicate_txs()
        .map_err(|e| format!("consensus rejection: {}", e))?;

    // Shielded transactions cannot validate without an active verifier
    // (RejectAll is the default): context-free rejection, exactly as before.
    if !block.shielded_transactions.is_empty() && !shielded.read().verifier.is_active() {
        return Err("shielded consensus rejection: ProofInvalid (no shielded verifier active)".into());
    }

    // ── Insert into GhostDAG and store the body ──────────────────────
    let applied_tip = match old_tip {
        Some(t) => t,
        None => return Err("consensus rejection: DAG has no genesis".into()),
    };
    if replacing {
        // Same id (header, txids, coinbase), different witness bytes: store
        // this body and let the blocks that waited for it compete again.
        store.put_block_body(block).map_err(|e| e.to_string())?;
        dag.write().clear_body_pending(&block_hash);
        info!("block {} h={}: new body stored for a block that waited for one; re-evaluating",
            hex::encode(&block_hash[..8]), block.height);
    } else {
        let work = pow::work_from_bits(block.header.bits);
        dag.write().add_block(block_hash, block.header.parents.clone(), block.header.timestamp, work)
            .map_err(|e| format!("consensus rejection: {}", e))?;
        if let Err(e) = store.put_block_body(block) {
            dag.write().remove_block(&block_hash);
            return Err(e.to_string());
        }
    }
    // Informational only (RPC / tip notifications).
    let _ = store.put_meta("current_bits", &block.header.bits.to_le_bytes());

    // Undo this call's storage effects (nothing was committed): a new block
    // leaves the DAG; a replacement body is dropped again and the block keeps
    // waiting for one.
    let roll_back = |why: &str| {
        let _ = store.delete_block_body(&block_hash);
        if replacing {
            dag.write().mark_body_pending(block_hash, None);
        } else if !dag.write().remove_block(&block_hash) {
            warn!("could not roll back DAG insertion of {} ({})", hex::encode(&block_hash[..8]), why);
        }
    };

    let mut log = ResolveLog::default();
    // A new block whose selected parent is disqualified for a reason the
    // block id commits to is disqualified with it (persisted). One that only
    // descends from a block waiting for a body is not: it waits too.
    if !replacing && dag.read().is_invalid_all_edges(&block_hash) {
        // It references (through any parent edge) a block that fails the
        // hardening block rules: no upgraded node can ever accept it.
        log.invalid.push((block_hash, format!(
            "{}: references a block stored by a pre-upgrade binary that fails them",
            HARDENING_RECHECK_REASON
        )));
    } else if !replacing && dag.read().is_invalid(&block_hash) && dag.read().is_invalid_persistently(&block_hash) {
        let sp = dag.read().get_block_data(&block_hash).and_then(|d| d.selected_parent);
        log.invalid.push((block_hash, format!(
            "selected parent {} is invalid",
            sp.map(|p| hex::encode(&p[..8])).unwrap_or_default()
        )));
    }

    // ── Connect the best valid chain ─────────────────────────────────
    let resolution = resolve_best_chain(
        dag, store, shielded, applied_tip, Some(block_hash), !replacing, block.height,
        finalized_height, &mut log,
    );

    let resolution = match resolution {
        Ok(r) => r,
        Err(stop) => {
            // Policy refusal or storage failure: roll the in-memory change
            // back (nothing was committed), drop the body, but keep any
            // deterministic invalid marks discovered on the way.
            roll_back("resolution stopped");
            if !log.invalid.is_empty() {
                if let Err(e) = persist_unchanged(dag, store, None, &log.invalid) {
                    error!("failed to persist invalid-block marks: {}", e);
                }
            }
            // Disqualifications found on the way change the valid tips.
            sync_mempool_next_height(dag, store, mempool);
            return Err(match stop {
                ResolveStop::Refused(m) if m.starts_with("finality:") => m,
                ResolveStop::Refused(m) => format!("U.4: execute_reorg failed: {}", m),
                ResolveStop::Failed(m) => format!("block {} not committed: {}", hex::encode(&block_hash[..8]), m),
            });
        }
    };

    let connected = match resolution {
        Resolution::Unchanged => {
            let record = if replacing { None } else { Some(block_hash) };
            if let Err(e) = persist_unchanged(dag, store, record, &log.invalid) {
                // The DAG record of a non-applied block failed to persist:
                // undo the in-memory insertion so memory and disk agree.
                error!("failed to persist DAG record of {}: {}", hex::encode(&block_hash[..8]), e);
                roll_back("DAG record not persisted");
                sync_mempool_next_height(dag, store, mempool);
                return Err(format!("block {} not committed: {}", hex::encode(&block_hash[..8]), e));
            }
            // A stored fork-loser / merge candidate (or a disqualification)
            // can move the template height without moving the applied tip.
            sync_mempool_next_height(dag, store, mempool);
            false
        }
        Resolution::Connected { plan, outcome } => {
            if plan.to_rollback.is_empty() {
                info!("block h={} {} connected ({} block(s))",
                    block.height, hex::encode(&block_hash[..8]), plan.to_apply.len());
            } else {
                info!("🔀 Reorg at h={}: rolled back {} block(s), applied {} (lca={})",
                    block.height, plan.to_rollback.len(), plan.to_apply.len(),
                    hex::encode(&plan.lca[..8]));
            }
            // The next height on the DAG after the move: the template
            // height (never the new tip's header height + 1, DAG-8).
            let next_height = crate::template::next_template_height(&dag.read(), store);
            update_mempool_after_connect(store, mempool, &outcome, next_height);
            chain.record(outcome);
            true
        }
    };

    // ── Update node state ────────────────────────────────────────────
    {
        let mut s = node_state.write();
        s.tip_blue_score = dag.read().tip_blue_score();
        s.block_count    = dag.read().block_count() as u64;
        s.mempool_size   = mempool.size();
    }

    // The arriving block itself is disqualified: it is reported as rejected
    // (it is kept in the DAG — see the module docs — but never selected or
    // applied). Computed now, returned after the tip bookkeeping below.
    //
    // Its BODY was rejected for a witness-dependent reason: reported as
    // rejected too, but the id is not disqualified (a different body is
    // re-evaluated). A block that only waits for an ancestor's body is
    // accepted into the DAG (like a fork-loser) and connects when that body
    // arrives.
    let trigger_invalid: Option<String> = if !dag.read().is_invalid(&block_hash) {
        None
    } else if dag.read().is_body_pending(&block_hash) {
        let reason = log.body_rejected.iter().rev()
            .find(|(h, _)| *h == block_hash)
            .map(|(_, r)| r.clone())
            .unwrap_or_else(|| "body missing".to_string());
        Some(format!(
            "consensus rejection: block {} body rejected ({}); the block id commits to no witness \
             bytes below the hardening activation, so it is not disqualified and a different body \
             will be re-evaluated",
            hex::encode(&block_hash[..8]), reason
        ))
    } else if dag.read().is_invalid_persistently(&block_hash) {
        let reason = store.invalid_block_reason(&block_hash).ok().flatten()
            .unwrap_or_else(|| "descends from an invalid block".to_string());
        Some(format!(
            "consensus rejection: block {} is invalid in its own chain context: {}",
            hex::encode(&block_hash[..8]), reason
        ))
    } else {
        info!("block {} waits for the body of an ancestor before it can be connected",
            hex::encode(&block_hash[..8]));
        None
    };

    if !connected {
        if let Some(e) = trigger_invalid {
            return Err(e);
        }
        info!("block h={} {} accepted into the DAG (not on the selected chain)",
            block.height, hex::encode(&block_hash[..8]));
        return Ok(block_hash);
    }
    if trigger_invalid.is_none() {
        info!("✓ block h={} accepted", height);
    }

    // ── Update finality checkpoint ───────────────────────────────────
    // NOTE: this MUST be the selected tip's DAG height, not tip_blue_score()
    // (see the DAG-8 note on `GhostdagData::height`).
    let tip_height = {
        let d = dag.read();
        d.selected_tip()
            .and_then(|h| d.get_block_data(&h).map(|data| data.height))
            .unwrap_or(0)
    };
    if tip_height > core::CHECKPOINT_DEPTH
        && !FINALITY_FROZEN.load(std::sync::atomic::Ordering::Relaxed)
    {
        let new_finalized = tip_height - core::CHECKPOINT_DEPTH;
        let current_finalized = store.get_meta("finalized_height").ok().flatten()
            .and_then(|b| b.as_slice().try_into().ok().map(u64::from_le_bytes))
            .unwrap_or(0);
        if new_finalized > current_finalized {
            store.put_meta("finalized_height", &new_finalized.to_le_bytes()).ok();
        }
    }

    // ── Prune old block bodies ───────────────────────────────────────
    if ARCHIVE_MODE.load(std::sync::atomic::Ordering::Relaxed) {
        if tip_height % 10_000 == 0 {
            info!("archival mode: retaining ALL block bodies (h={}); pruning disabled", tip_height);
        }
    } else if tip_height > core::PRUNING_DEPTH {
        let prune_below = tip_height - core::PRUNING_DEPTH;
        let last_pruned = store.pruned_height();
        if prune_below > last_pruned + 1000 {
            match store.prune_blocks_below(prune_below) {
                Ok(n) if n > 0 => info!("Pruned {} block bodies below h={}", n, prune_below),
                Err(e)         => warn!("Prune failed: {}", e),
                _ => {}
            }
        }
    }

    // ── Sprint 2.c: emit TipChanged if the selected tip moved ────────
    if let Some(tip_tx) = tip_tx {
        // Presence only (no decode): this runs at every acceptance.
        let has_body = |h: &[u8; 32]| store.has_block_body(h).unwrap_or(false);
        let new_tip = { dag.read().best_bodied_tip(has_body) };
        if new_tip != old_tip {
            if let Some(tip_hash) = new_tip {
                let d = dag.read();
                if let Some(data) = d.get_block_data(&tip_hash).cloned() {
                    // The template's own parents (memoized parent predicate,
                    // `template::eligible_parent`), not a second predicate.
                    let tips_parents: Vec<[u8; 32]> = crate::template::template_parents_and_height(&d, store).0;
                    drop(d);
                    let bits = store.get_meta("current_bits").ok().flatten()
                        .and_then(|b| b.as_slice().try_into().ok().map(u32::from_le_bytes))
                        .unwrap_or(0x1d00ffff_u32);
                    let _ = tip_tx.send(tip::TipChanged {
                        hash:       tip_hash,
                        height:     data.height,
                        blue_score: data.blue_score,
                        parents:    tips_parents,
                        bits,
                    });
                }
            }
        }
    }

    match trigger_invalid {
        Some(e) => Err(e),
        None => Ok(block_hash),
    }
}

// ── Start-up recheck of stored blocks under the hardening rules ─────────────

/// Meta key recording the hardening activation height the stored DAG was
/// last rechecked against ([`recheck_stored_blocks_under_hardening`]).
pub const HARDENING_RECHECK_META: &str = "hardening_block_rules_checked";

/// Verdict of the hardening block rules on a STORED body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredBlockCheck {
    /// The body passes (or the rules do not apply at its height).
    Valid,
    /// It fails for a reason the block id commits to: every body with this
    /// id fails (the header Merkle root, the coinbase — its txid covers its
    /// `script_sig`, hence the commitment's tag, height and parents — or a
    /// transaction's txid preimage). The block must be disqualified.
    IdCommitted(&'static str),
    /// Only this body fails (its witness root differs from the committed
    /// one, or its transaction list does not match the header at all):
    /// another body with the same id may be valid.
    BodyOnly(&'static str),
}

/// Classify a stored body against the context-free hardening rules
/// (`check_block_hardened_at` + `validate_structure_without_pow_at`) at
/// `activation_height`.
pub fn classify_stored_block(b: &core::Block, activation_height: u64) -> StoredBlockCheck {
    use core::block_rules;
    let reason = match block_rules::check_block_hardened_at(b, activation_height)
        .and_then(|()| b.validate_structure_without_pow_at(activation_height))
    {
        Ok(()) => return StoredBlockCheck::Valid,
        Err(e) => e,
    };
    if !b.validate_merkle_at(activation_height) {
        // The header root is not the tagged root of these txids. If it is
        // their LEGACY root, the id commits to a legacy-format block, which
        // no body can turn into a valid one; otherwise this body's
        // transaction list is simply not the id's.
        return if b.validate_merkle_at(core::activation::NEVER) {
            StoredBlockCheck::IdCommitted(reason)
        } else {
            StoredBlockCheck::BodyOnly(reason)
        };
    }
    // The header root matches: the txids (and so the coinbase and every
    // txid preimage) are the id's.
    if !b.validate_coinbase_format()
        || b.transactions.iter().any(|t| block_rules::check_tx_not_64_bytes(t).is_err())
    {
        return StoredBlockCheck::IdCommitted(reason);
    }
    match block_rules::check_coinbase_commitment(b) {
        // Tag, height and parents match but not the witness root: a body
        // with other witness bytes.
        Err(e) if e.starts_with("bad witness commitment") => StoredBlockCheck::BodyOnly(e),
        // Ok: the witness root matches, so this body IS the committed one
        // and any other failure (size, duplicates, dust) is the id's.
        _ => StoredBlockCheck::IdCommitted(reason),
    }
}

/// What [`recheck_stored_blocks_under_hardening`] did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RecheckReport {
    /// `false` when the DAG had already been rechecked at this activation.
    pub ran: bool,
    /// Blocks checked (stored bodies at header height >= the activation).
    pub checked: usize,
    /// Blocks disqualified (with all their DAG descendants).
    pub disqualified: Vec<BlockHash>,
    /// Blocks whose body was dropped to wait for another one.
    pub bodies_dropped: Vec<BlockHash>,
    /// Candidates without a stored body (pruned): not checkable.
    pub unchecked: usize,
}

/// Recheck the blocks a PRE-UPGRADE binary may have stored at a header
/// height at or above the hardening activation against the context-free
/// hardening rules (wire size, tagged Merkle root, 64-byte transactions,
/// coinbase commitment). An upgraded node never stores such a block, so one left in
/// the DAG (a legacy-format fork-loser, or a legacy chain the node applied
/// while it still ran the old binary) would stay a valid template parent and
/// make this node's blocks unacceptable to every upgraded peer.
///
/// A block failing for a reason its id commits to is disqualified together
/// with EVERY block that descends from it through any parent edge
/// (`GhostDAG::mark_invalid_all_edges`; later arrivals referencing one of
/// them are disqualified on insertion), and persisted with a reason starting
/// with [`HARDENING_RECHECK_REASON`] so the next start reloads it with the
/// same reach. A block whose only failure is its witness root (only this
/// body is wrong) is not disqualified: an unapplied one drops its body and
/// waits for another (`GhostDAG::mark_body_pending`).
///
/// Runs once per activation height (meta key [`HARDENING_RECHECK_META`]);
/// it reads no body when no stored block is at or above the activation (a
/// mainnet node upgraded before it). Call it BEFORE reconnecting the best
/// chain, so the reconnect rolls the applied tip off a disqualified branch.
pub fn recheck_stored_blocks_under_hardening(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
    activation_height: u64,
) -> Result<RecheckReport, String> {
    let done = store.get_meta(HARDENING_RECHECK_META).map_err(|e| e.to_string())?
        .and_then(|v| <[u8; 8]>::try_from(v.as_slice()).ok().map(u64::from_le_bytes));
    if done == Some(activation_height) {
        return Ok(RecheckReport::default());
    }
    let mut report = RecheckReport { ran: true, ..Default::default() };
    let candidates = dag.read().blocks_with_header_height_at_least(activation_height.max(1));
    let mut batch = rocksdb::WriteBatch::default();
    for h in candidates {
        if dag.read().is_invalid_all_edges(&h) {
            continue; // already disqualified through an ancestor checked earlier
        }
        let body = match store.get_block(&h).map_err(|e| e.to_string())? {
            Some(b) => b,
            None => {
                report.unchecked += 1;
                continue;
            }
        };
        report.checked += 1;
        match classify_stored_block(&body, activation_height) {
            StoredBlockCheck::Valid => {}
            StoredBlockCheck::IdCommitted(reason) => {
                let marked = dag.write().mark_invalid_all_edges(h);
                error!(
                    "stored block {} h={} fails the hardening block rules ({}); it was stored by a \
                     pre-upgrade binary: disqualified with {} descendant(s)",
                    hex::encode(&h[..8]), body.height, reason, marked.len().saturating_sub(1)
                );
                store.stage_invalid_block(&mut batch, &h, &format!(
                    "{}: {} (stored by a pre-upgrade binary)", HARDENING_RECHECK_REASON, reason
                )).map_err(|e| e.to_string())?;
                report.disqualified.push(h);
            }
            StoredBlockCheck::BodyOnly(reason) => {
                if store.get_undo_data(&h).map_err(|e| e.to_string())?.is_some() {
                    // Applied: its body is needed to roll it back. Cannot
                    // happen for a body stored by any binary (the old one
                    // never stores a tagged root, the new one checks the
                    // commitment first); left alone and reported.
                    error!("applied block {} has a body whose witnesses do not match its commitment ({}); \
                            left in place", hex::encode(&h[..8]), reason);
                    continue;
                }
                warn!("stored body of {} fails the hardening rules only by its witnesses ({}); \
                       dropped, waiting for another copy", hex::encode(&h[..8]), reason);
                let wr = core::block_rules::witness_root(&body.transactions).0;
                dag.write().mark_body_pending(h, Some(wr));
                store.delete_block_body(&h).map_err(|e| e.to_string())?;
                report.bodies_dropped.push(h);
            }
        }
    }
    store.stage_meta(&mut batch, HARDENING_RECHECK_META, &activation_height.to_le_bytes())
        .map_err(|e| e.to_string())?;
    store.write_batch(batch).map_err(|e| e.to_string())?;
    if !report.disqualified.is_empty() || !report.bodies_dropped.is_empty() || report.unchecked > 0 {
        warn!(
            "hardening recheck at activation {}: {} checked, {} disqualified, {} bodies dropped, {} without a body",
            activation_height, report.checked, report.disqualified.len(), report.bodies_dropped.len(), report.unchecked
        );
    }
    Ok(report)
}

// ── Start-up reconciliation (DAG-11) ─────────────────────────────────────────

/// Reconcile the chain state on boot, before any block is accepted:
///
/// 1. load the persisted chain-disqualified set into the DAG, then recheck
///    the blocks a pre-upgrade binary may have stored at or above the
///    hardening activation ([`recheck_stored_blocks_under_hardening`]);
/// 2. roll back the UTXO effects of any block that has an undo record but no
///    CF_DAG record — the footprint of the pre-fix, non-atomic extension
///    commit crashing between "apply UTXO effects" and "persist DAG data"
///    (audit VAL-4 / DAG-11). Its inputs would otherwise read as spent and the
///    block would be refused forever on re-receipt. The tip pointer (and the
///    shielded tip) is set, in the same batch, to the block the UTXO set then
///    describes: the heaviest DAG block that holds an undo record, even when
///    step 1 disqualified it (not the DAG's selected tip);
/// 3. if the applied tip pointer is not the best valid block, connect the
///    best valid chain with the same atomic machinery as `accept_block` (a
///    rollback-only plan when step 1 disqualified applied blocks).
///
/// Every step is idempotent and cheap (one scan of CF_UNDO keys). New writes
/// can no longer produce a state that needs step 2: an extension now commits
/// UTXO effects, undo data, DAG record and tip pointer in one batch.
///
/// `shielded` must be the state [`ShieldedPool::load`] returned for `store`
/// (audit COH-2: it sits at the applied tip). Step 1 and the explorer
/// aggregate rebuild (NET-12) leave the applied tip where it is; steps 2 and
/// 3 move the shielded state with the chain, in the same batches.
pub fn reconcile_on_startup(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &Arc<storage::Storage>,
    shielded: &Arc<RwLock<ShieldedPool>>,
) -> Result<(), String> {
    let _guard = store.acceptance_lock();
    ensure_invalid_set_loaded(dag, store);
    let recheck = match recheck_stored_blocks_under_hardening(
        dag, store, core::activation::hardening_activation_height(),
    ) {
        Ok(r) => r,
        Err(e) => {
            error!("reconcile: hardening recheck of stored blocks failed: {}", e);
            RecheckReport::default()
        }
    };

    // NET-12: a database written before the explorer aggregates existed gets
    // them built once, from scratch (later connects keep them current in the
    // same batches as the UTXO changes).
    match store.ensure_aggregates() {
        Ok(true) => info!("NET-12: explorer aggregates rebuilt from the UTXO set and undo records"),
        Ok(false) => {}
        Err(e) => error!("NET-12: explorer aggregates could not be rebuilt: {} (explorer statistics stay unavailable)", e),
    }

    // Step 2: applied-but-unrecorded blocks.
    let mut orphan_applied: Vec<(u64, BlockHash)> = Vec::new();
    let mut orphan_parents: Vec<BlockHash> = Vec::new();
    let undo_hashes = store.undo_block_hashes().map_err(|e| e.to_string())?;
    for &h in &undo_hashes {
        if !dag.read().has_block(&h) {
            if let Ok(Some(b)) = store.get_block(&h) {
                orphan_applied.push((b.height, h));
                orphan_parents.extend_from_slice(&b.header.parents);
            } else {
                warn!("reconcile: undo record for unknown block {} without a body; ignoring",
                    hex::encode(&h[..8]));
            }
        }
    }
    if !orphan_applied.is_empty() {
        orphan_applied.sort_by(|a, b| b.cmp(a)); // tip-first
        let to_rollback: Vec<BlockHash> = orphan_applied.iter().map(|(_, h)| *h).collect();
        // Once they are gone, the UTXO set describes the chain of the DAG
        // blocks that still hold an undo record (every connect writes one,
        // every disconnect deletes it), so its tip is the heaviest of those:
        // they are all its ancestors. Neither pointer the node keeps is a
        // witness for it:
        // - the DAG's selected tip: step 1 may have disqualified applied
        //   blocks (they stay applied until step 3 disconnects them), and a
        //   pre-fix reorg that crashed before its DAG write left the UTXO set
        //   on a branch the DAG alone does not select;
        // - meta tip_hash: that crashed reorg had not rewritten it, and the
        //   crashed extension may have written it as the unrecorded block;
        // - the unrecorded blocks' parents: a pre-fix binary that kept
        //   running after the crash connected later blocks on top of them.
        // Pointing the tip (and the shielded tip) at a block the UTXO set does
        // not sit on would leave effects applied under a tip that excludes
        // them, or drop effects of blocks it includes, with nothing to
        // repair it. When no DAG block holds an undo record (genesis has
        // none; a chain connected before undo records existed neither) the
        // unrecorded blocks sit on their selected parent. Step 3 then moves
        // the chain from this real applied tip to the best valid block.
        let back_to = {
            let d = dag.read();
            let recorded: Vec<BlockHash> = undo_hashes.iter().copied().filter(|h| d.has_block(h)).collect();
            d.heaviest_among(&recorded).or_else(|| d.heaviest_among(&orphan_parents))
        };
        let Some(back_to) = back_to else {
            return Err(format!(
                "reconcile: {} block(s) have applied UTXO effects but no DAG record, and the DAG holds \
                 neither an applied block nor one of their parents, so the chain position of the UTXO \
                 set is unknown; resynchronize this data directory",
                to_rollback.len()));
        };
        warn!(
            "reconcile: {} block(s) have applied UTXO effects but no DAG record (interrupted \
             pre-fix commit); rolling them back atomically to {}",
            to_rollback.len(), hex::encode(&back_to[..8])
        );
        // COH-2: these blocks predate shielded persistence; the shielded tip
        // follows the UTXO tip in the same batch.
        let staged_shielded = shielded.write().stage_retip(store, &to_rollback, back_to)
            .map_err(|e| format!("reconcile rollback: {e}"))?;
        let plan = reorg::ReorgPlan { lca: back_to, to_rollback, to_apply: vec![] };
        let validate = |_: &dyn UtxoView, _: &core::Block| -> Result<(), String> { Ok(()) };
        let stage_extra = |st: &storage::Storage, batch: &mut rocksdb::WriteBatch| -> Result<(), String> {
            st.stage_meta(batch, "tip_hash", &back_to).map_err(|e| e.to_string())?;
            staged_shielded.stage_into(st, batch)
        };
        let hooks = ConnectHooks { validate: &validate, stage_extra: &stage_extra };
        let result = reorg::connect_plan(store, &plan, &hooks);
        match &result {
            Ok(_) => shielded.write().commit_staged(staged_shielded),
            Err(_) => shielded.write().revert_staged(staged_shielded),
        }
        result.map_err(|e| format!("reconcile rollback: {}", e))?;
    }

    // Step 3: applied tip vs best valid block.
    let applied = store.get_meta("tip_hash").ok().flatten()
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok());
    let best = dag.read().selected_tip();
    if let (Some(applied), Some(best)) = (applied, best) {
        if applied != best && dag.read().has_block(&applied) {
            warn!("reconcile: applied tip {} != best valid block {}; reconnecting",
                hex::encode(&applied[..8]), hex::encode(&best[..8]));
            let mut log = ResolveLog::default();
            match resolve_best_chain(dag, store, shielded, applied, None, false, 0, 0, &mut log) {
                Ok(_) => {
                    if !log.invalid.is_empty() {
                        persist_unchanged(dag, store, None, &log.invalid)?;
                    }
                }
                Err(ResolveStop::Refused(m)) | Err(ResolveStop::Failed(m)) => {
                    error!("reconcile: cannot reconnect the best valid chain: {}", m);
                    if !recheck.disqualified.is_empty() {
                        error!(
                            "reconcile: the applied chain contains blocks a pre-upgrade binary stored that \
                             fail the hardening block rules, and leaving them needs a rollback this node \
                             refuses (deeper than the reorg cap); resynchronize this data directory"
                        );
                    }
                    return Err(m);
                }
            }
        }
    }
    Ok(())
}

// ── Unified TX validation ────────────────────────────────────────────────────
// FIX #10: Single validation core used by all code paths.

/// Core input validation logic shared by all TX validation paths.
/// Resolves each input's UTXO (rejecting duplicate outpoints), then checks
/// every input script under the rules of a block at header height
/// `block_height` (version rule, witness, pubkey hash vs prevout, hybrid
/// signature under the digest the version selects — cached, see
/// `admission::verify_input_scripts`), value conservation and the consensus
/// minimum fee. All amounts are MoneyRange-checked (VAL-11). Uses the
/// process-wide hardening activation height.
pub fn validate_tx_inputs(
    tx:           &core::Transaction,
    utxo_lookup:  &dyn Fn(&[u8; 32], u32) -> Result<Option<core::TxOutput>, String>,
    spent_set:    Option<&mut HashSet<([u8; 32], u32)>>,
    block_height: u64,
) -> Result<u64, String> {
    validate_tx_inputs_classified(
        tx, utxo_lookup, spent_set, block_height, core::activation::hardening_activation_height(),
    )
    .map_err(|f| f.reason)
}

/// Prevout lookup used by the input validation: `Ok(None)` = not found.
type UtxoLookup<'a> = dyn Fn(&[u8; 32], u32) -> Result<Option<core::TxOutput>, String> + 'a;

/// [`validate_tx_inputs`] with the failure classified and an explicit
/// hardening activation height: script failures (the `script_sig` must
/// parse — canonically from the activation —, its public key must hash to
/// the prevout's script_pubkey, its signature must verify) and the minimum fee (measured on the wire size, `script_sig`
/// included) depend on witness bytes; every other check, the transaction
/// version rule included, depends only on data the txid commits to. (The
/// caller clears the witness flag at/after the activation, where the block's
/// witness commitment fixes every `script_sig`.)
fn validate_tx_inputs_classified(
    tx:           &core::Transaction,
    utxo_lookup:  &UtxoLookup<'_>,
    mut spent_set: Option<&mut HashSet<([u8; 32], u32)>>,
    block_height: u64,
    activation_height: u64,
) -> Result<u64, TxFailure> {
    let witness = |reason: String| TxFailure { reason, witness: true };
    let mut total_in = 0u64;

    // C-R3-2: the intra-tx duplicate-outpoint check is UNCONDITIONAL.
    let mut local_spent: HashSet<([u8; 32], u32)> = HashSet::new();
    let mut prevouts: Vec<core::TxOutput> = Vec::with_capacity(tx.inputs.len());

    for inp in tx.inputs.iter() {
        let outpoint = (inp.prev_txid, inp.prev_index);
        let cross_tx_dup = spent_set.as_ref().is_some_and(|s| s.contains(&outpoint));
        if cross_tx_dup || !local_spent.insert(outpoint) {
            return Err(format!("double-spend: {}:{} already consumed",
                hex::encode(&inp.prev_txid[..8]), inp.prev_index).into());
        }
        let utxo = utxo_lookup(&inp.prev_txid, inp.prev_index)?
            .ok_or_else(|| format!("UTXO {}:{} not found",
                hex::encode(&inp.prev_txid[..8]), inp.prev_index))?;
        total_in = core::limits::money_add(total_in, utxo.value)
            .map_err(|e| format!("input overflow: {}", e))?;
        prevouts.push(utxo);
    }

    // The version rule depends only on data the txid commits to (and below
    // the activation every version is valid): never witness-dependent. The
    // witness, pubkey-hash and signature checks that follow are.
    core::sighash::check_tx_version(tx.version, block_height, activation_height)?;
    admission::verify_input_scripts_at(tx, &prevouts, block_height, activation_height).map_err(witness)?;

    if let Some(spent) = spent_set.as_mut() {
        for inp in &tx.inputs {
            spent.insert((inp.prev_txid, inp.prev_index));
        }
    }

    let total_out = core::limits::check_tx_money_range(tx)
        .map_err(|e| format!("output sum overflow: {}", e))?;
    if total_in < total_out {
        return Err(format!("inputs {} < outputs {}", total_in, total_out).into());
    }
    let fee = total_in - total_out;
    core::check_min_fee(tx, fee).map_err(witness)?;
    Ok(fee)
}

/// Compute the total fee the miner's OWN block template may claim across
/// `txs`, reading prevout values from the persistent UTXO set.
///
/// SECURITY (Legacy N-7): counts each of a transaction's outpoints ONCE —
/// insert-as-check, mirroring the C-R3-2 duplicate-outpoint rejection real
/// admission applies. A transaction listing the same outpoint N times
/// contributes zero (it can never be mined).
pub fn miner_template_total_fees(
    txs:   &[core::Transaction],
    store: &storage::Storage,
) -> u64 {
    txs.iter().map(|tx| {
        let mut seen_outpoints: HashSet<([u8; 32], u32)> = HashSet::new();
        let mut has_duplicate_outpoint = false;
        let mut total_in: u64 = 0;
        for inp in &tx.inputs {
            if !seen_outpoints.insert((inp.prev_txid, inp.prev_index)) {
                has_duplicate_outpoint = true;
                continue;
            }
            if let Ok(Some(out)) = store.get_utxo(&inp.prev_txid, inp.prev_index) {
                total_in = total_in.saturating_add(out.value);
            }
        }
        if has_duplicate_outpoint {
            return 0;
        }
        let total_out: u64 = tx.outputs.iter()
            .try_fold(0u64, |acc, o| acc.checked_add(o.value))
            .unwrap_or(u64::MAX);
        total_in.saturating_sub(total_out)
    }).fold(0u64, |a, b| a.saturating_add(b))
}

/// Validate a transaction within a block context.
/// Uses both in-block outputs and persistent UTXO set, with double-spend
/// tracking. No coinbase-maturity check (see
/// [`validate_tx_in_block_with_maturity`]).
#[allow(dead_code)]
pub fn validate_tx_in_block(
    block:          &core::Block,
    tx:             &core::Transaction,
    store:          &Arc<storage::Storage>,
    spent_in_block: &mut HashSet<([u8; 32], u32)>,
) -> Result<(), String> {
    validate_tx_in_block_with_maturity(block, tx, store, spent_in_block, 0)?;
    Ok(())
}

/// FIX VULN-03: Validate the non-coinbase transaction `tx` of `block` against
/// the COMMITTED store, including coinbase maturity. Returns the fee.
///
/// SECURITY (Legacy C-2): the in-block prevout map holds ONLY the
/// transactions STRICTLY BEFORE `tx` in `block.transactions` (identified by
/// txid), so a transaction can never spend a later transaction's output.
///
/// Heights: every consensus rule is evaluated at the block's header height
/// `block.height` under the process-wide hardening activation, exactly as
/// the connect path (`validate_block_in_view`) evaluates it for this
/// transaction: the transaction rules (version 3 / sighash v3 / canonical
/// witnesses, `core::sighash`), BIP30 for `tx`'s outputs (audit VAL-2) and
/// no spend of the block's own coinbase (audit VAL-3). `current_height` is
/// used ONLY for coinbase maturity (`0` skips it; the connect path uses
/// `block.height`). Unlike the connect path this checks one transaction, so
/// the block-level rules (BIP30 of the other transactions, the coinbase
/// value) are the caller's.
pub fn validate_tx_in_block_with_maturity(
    block:          &core::Block,
    tx:             &core::Transaction,
    store:          &Arc<storage::Storage>,
    spent_in_block: &mut HashSet<([u8; 32], u32)>,
    current_height: u64,
) -> Result<u64, String> {
    let tx_txid = tx.txid();
    let cutoff = block.transactions.iter()
        .position(|t| t.txid() == tx_txid)
        .unwrap_or(block.transactions.len());
    // Same gate and height as `validate_block_in_view_classified_at`.
    let activation_height = core::activation::hardening_activation_height();
    let hardened = core::block_rules::rules_active_at(block.height, activation_height);
    let view: &storage::Storage = store;
    if hardened {
        check_no_unspent_overwrite(view, tx)?;
    }
    let same_block_coinbase = if hardened { block.transactions.first().map(|cb| cb.txid()) } else { None };
    let earlier: HashMap<([u8; 32], u32), core::TxOutput> = block.transactions[..cutoff]
        .iter()
        .filter(|t| !(hardened && t.is_coinbase()))
        .flat_map(|t| {
            let txid = t.txid();
            t.outputs.iter().enumerate().map(move |(i, o)| ((txid, i as u32), o.clone()))
        })
        .collect();
    validate_tx_in_view(
        tx, view, &earlier, spent_in_block, block.height, current_height, same_block_coinbase.as_ref(),
        activation_height,
    )
    .map_err(|f| f.reason)
}

/// Standalone tx validation (no mempool context): the shared admission rules
/// (`mempool::admission::check_transaction`) with signatures, evaluated for a
/// block at `current_height` (`0` skips the maturity check). Returns the fee.
pub fn validate_tx_standalone(
    tx:    &core::Transaction,
    store: &Arc<storage::Storage>,
    current_height: u64,
) -> Result<u64, String> {
    let policy = admission::AdmissionPolicy {
        next_block_height: current_height,
        check_signatures: true,
        use_reject_filter: false,
    };
    admission::check_transaction(store, None, tx, &policy).map_err(|e| e.to_string())
}
