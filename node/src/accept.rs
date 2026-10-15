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
//! A block whose body is missing waits the same way — also one whose body was
//! PRUNED while it was on the selected chain and that a reorg left unapplied
//! (audit DAG-6: without a reorg-depth limit the chain through it can become
//! the best again): `resolve_best_chain` makes every bodiless block of the
//! best chain wait at once, and the chain connects when the last body is
//! back. One predicate ([`awaits_body`]) decides whether a body of a DAG block
//! is wanted, one request path fetches it, and one acceptance path
//! (`accept_block`'s body replacement) binds a copy to the header height the
//! DAG parents imply and to the witness-root rules. At/after the activation
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
//! **No reorg-depth limit, no finality checkpoint (audit DAG-6)**: the old
//! `MAX_REORG_DEPTH` cap and `finalized_height` gate compared a fork with THIS
//! node's own history, so two nodes given the same blocks in different orders
//! could end on different chains. Both are gone. Like Bitcoin Core, the node
//! always ends on the best valid chain of the blocks it holds; deep reorgs are
//! logged and counted (`reorg::DEEP_REORG_ALERT_DEPTH`), never refused.
//! Bounded merging is enforced objectively by GhostDAG's merge depth after the
//! hardening activation. Operators override the choice explicitly and
//! persistently with [`invalidate_block`] / [`reconsider_block`] (the RPCs
//! `invalidateblock` / `reconsiderblock`), which reuse the disqualification
//! machinery below. `reconsiderblock` never removes a consensus verdict
//! without re-validating it: a hardening-recheck mark goes only if the stored
//! body now passes those rules, a connect-time mark only with the batch that
//! re-validates and applies the block.
//!
//! **Arrival-order independence**: given the same block set, every node ends
//! with the applied tip = the best block whose selected chain is valid in its
//! own context, and the same UTXO set (the deterministic application of that
//! chain), whatever order the blocks arrived in, at any depth
//! (`node/tests/fix_chain_selection.rs`).
//!
//! **Chain-state check (audit DAG-11)**: [`check_chain_state`] detects, at
//! start-up, the footprint a crash or write error of the pre-fix NON-atomic
//! extension commit leaves (UTXO effects without an undo record), which
//! [`reconcile_on_startup`] cannot repair (it runs after reconciliation's
//! step 2, which repairs the states it can); [`rebuild_chain_state`] rebuilds
//! the chain state — UTXO set and indexes, undo records, shielded state,
//! explorer aggregates — from the block bodies.
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

/// Set once from `--archive` at startup: accept_block runs far from the CLI
/// struct and threading a bool through every caller would be noise for a
/// value that is fixed for the process lifetime. (The former `FINALITY_FROZEN`
/// flag is gone with the finality checkpoint it froze, audit DAG-6.)
pub static ARCHIVE_MODE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Reason recorded with a disqualification made by the operator
/// (`invalidateblock`). Marks carrying it survive a chain-state rebuild
/// (DAG-11); consensus disqualifications are re-derived instead.
pub const OPERATOR_INVALIDATE_REASON: &str = "invalidateblock (operator)";

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
            let (selected, all_edges) = split_marks(marks);
            let n = dag.write().load_invalid_sets(selected, all_edges);
            if n > 0 {
                info!("loaded {} chain-disqualified block(s)", n);
            }
        }
        Err(e) => error!("cannot read the persisted invalid-block set: {}", e),
    }
}

/// True iff `hash` is in the DAG but a body for it is still wanted — THE one
/// predicate for "a body of this DAG block is wanted" (see "Blocks in the DAG
/// without a usable body" below): it waits for a body
/// (`GhostDAG::is_body_pending`: its body failed a witness-dependent rule,
/// or a connect of the best chain — or an operator override — needs a body
/// that is missing, pruned ones included, audit DAG-6), or its body is
/// missing although it was never pruned (a body dropped after such a
/// failure, before a restart). A copy of such a block is processed (and
/// requested from peers) instead of being discarded as already known; any
/// other copy of a DAG block — an unrequested old body included — is known.
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
//
// Rolled-back blocks whose body was pruned (audit DAG-6) are disconnected from
// the shielded undo record (never pruned); whether they carried shielded
// transactions comes from the record written when their body was pruned
// (`storage::PrunedBodyRecord::had_shielded`), see `ShieldedPool::stage_plan`.

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
        let lower = previous != 0 && next_height < previous && outcome.rolled_back() == 0;
        let stale = if lower {
            revalidate_mempool(store, mempool, next_height)
        } else {
            evict_version_invalid(mempool, next_height)
        };
        if stale > 0 {
            info!("mempool: evicted {} tx(s) no longer valid for the next block at height {}", stale, next_height);
        }
    }
    // Any rollback — also a pure one (operator `invalidateblock`, DAG-6) and
    // one through pruned bodies, whose transactions cannot be re-admitted —
    // re-validates the pool against the new UTXO set.
    if outcome.rolled_back() > 0 {
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

/// Where `resolve_best_chain` records what it found on the way.
#[derive(Default)]
struct ResolveLog {
    /// (root, reason) for every newly disqualified root (persisted).
    invalid: Vec<(BlockHash, String)>,
    /// (block, reason) for every block whose body was dropped after a
    /// witness-dependent failure (never persisted; see `drop_body_and_wait`).
    body_rejected: Vec<(BlockHash, String)>,
}

/// What `resolve_best_chain` does when the plan to the best candidate must
/// APPLY blocks whose body is not stored (dropped after a witness-dependent
/// failure, or pruned and since reorganized away from, audit DAG-6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MissingBodies {
    /// Acceptance and start-up: every such block waits for a body
    /// (`GhostDAG::mark_body_pending`, in memory only: the one record of
    /// "a body of this DAG block is wanted", see [`awaits_body`]), the
    /// processor requests them, and the next-best chain is tried meanwhile.
    Wait,
    /// Operator overrides: stop with [`reorg::ERR_MISSING_BODIES`] before
    /// anything is committed (the caller names the bodies and asks for a
    /// retry once they are restored).
    Stop,
}

/// Persisted disqualification marks an operator `reconsiderblock` removes
/// (audit DAG-6), committed in the same batch as the chain move.
#[derive(Default)]
struct MarkClears {
    /// Removed in any case (operator marks, marks inherited from a selected
    /// parent, hardening-recheck marks whose stored body now passes).
    always: Vec<BlockHash>,
    /// Marks of genuine connect-time consensus failures: removed only by the
    /// batch that RE-VALIDATES the block (it is in the committed plan's
    /// `to_apply`, every block of which `connect_plan` validated in its own
    /// context; `resolve_best_chain` lifts the consensus mark of every such
    /// block). A block the move does not apply keeps its mark, also in memory
    /// ([`remark_unvalidated`]).
    if_applied: Vec<BlockHash>,
}

/// Move the applied chain to the best valid block, marking blocks invalid as
/// they fail. `trigger` is the block whose insertion prompted the call; its
/// DAG record is folded into the commit batch when `stage_trigger_record` (a
/// new insertion, not a body replacement). `log` accumulates the
/// disqualified roots and the dropped bodies; `clears` lists persisted marks
/// to delete in the same batch (operator `reconsiderblock`). Whatever the
/// caller, a committed move also deletes the persisted consensus or inherited
/// mark of every block it applies (validated in its own context just before):
/// an applied block never carries a mark that would disqualify it again at
/// the next start.
///
/// A block of the plan whose body fails a rule that depends on witness bytes
/// its id does not commit to (below the hardening activation) is NOT
/// disqualified: its body is dropped and it waits, in memory only, for
/// another body (`GhostDAG::mark_body_pending`); the next-best chain is tried
/// meanwhile. Blocks of the plan without a stored body are handled as
/// `missing` says ([`MissingBodies`]).
///
/// There is no depth limit and no finality gate (audit DAG-6): the plan to the
/// best valid block is executed at any depth. `Err` is a storage / missing-
/// data failure only (nothing committed; the caller rolls its trigger back).
#[allow(clippy::too_many_arguments)]
fn resolve_best_chain(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
    shielded: &Arc<RwLock<ShieldedPool>>,
    applied_tip: BlockHash,
    trigger: Option<BlockHash>,
    stage_trigger_record: bool,
    log: &mut ResolveLog,
    clears: &MarkClears,
    missing: MissingBodies,
) -> Result<Resolution, String> {
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
            // applied blocks were disqualified (start-up hardening recheck,
            // operator `invalidateblock`): then the plan only disconnects.
            reorg::compute_connect_plan(&d, &applied_tip, &cand)
        };
        let plan = match plan {
            Some(p) => p,
            None => return Err(format!(
                "U.4: unexpected selected-tip transition (applied={}, best={}): no connect plan",
                hex::encode(&applied_tip[..8]), hex::encode(&cand[..8]))),
        };

        // A block without a stored body cannot be connected.
        let mut bodiless = Vec::new();
        for h in &plan.to_apply {
            if !store.has_block_body(h).map_err(|e| e.to_string())? {
                bodiless.push(*h);
            }
        }
        if let Some(first) = bodiless.first() {
            match missing {
                MissingBodies::Stop => return Err(format!(
                    "{}: {} block(s) to connect have no body (first {})",
                    reorg::ERR_MISSING_BODIES, bodiless.len(), hex::encode(&first[..8]))),
                MissingBodies::Wait => {
                    // All of them at once, so they are requested together.
                    warn!("{} block(s) of the best chain have no stored body (first {}); waiting for \
                           them before connecting it", bodiless.len(), hex::encode(&first[..8]));
                    let mut d = dag.write();
                    for h in &bodiless {
                        d.mark_body_pending(*h, None);
                    }
                    continue;
                }
            }
        }

        let staged_shielded = shielded.write().stage_plan(store, &plan);
        let staged_shielded = match staged_shielded {
            Ok(s) => s,
            Err(ConnectError::Invalid { block, reason, .. }) => {
                // The shielded bytes are committed by the header root.
                disqualify(dag, block, reason, &mut log.invalid);
                continue;
            }
            Err(e) => return Err(e.to_string()),
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
            // Operator `reconsiderblock`: the marks it removes in any case.
            for h in &clears.always {
                st.stage_clear_invalid_block(batch, h).map_err(|e| e.to_string())?;
            }
            // A consensus (or inherited) mark goes with the batch that
            // RE-VALIDATED its block: `connect_plan` validated every block of
            // `to_apply` in its own context before this runs. This covers the
            // `reconsiderblock` marks (`clears.if_applied`) and any stale mark
            // whose block connects through an ordinary acceptance, so an
            // applied block never keeps a mark that would disqualify it again
            // at the next restart.
            for h in &plan.to_apply {
                if let Some(reason) = st.invalid_block_reason(h).map_err(|e| e.to_string())? {
                    match mark_kind(&reason) {
                        MarkKind::Consensus | MarkKind::Inherited => {
                            st.stage_clear_invalid_block(batch, h).map_err(|e| e.to_string())?;
                        }
                        // Never lifted by a connect: only `reconsiderblock`
                        // removes these (it re-checks a hardening mark).
                        kind @ (MarkKind::Operator | MarkKind::Hardening) => warn!(
                            "block {} connects although it carries a persisted {:?} mark ({}); \
                             the mark is kept", hex::encode(&h[..8]), kind, reason),
                    }
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
            Err(ConnectError::Failed(m)) => {
                if reorg_depth > 0 { crate::metrics::inc_reorg_failure(); }
                return Err(m);
            }
        }
    }
    Err("resolve_best_chain: iteration guard reached".into())
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

/// Persist the trigger's DAG record (if it is still in the DAG), the removal
/// of every `cleared` mark and every pending invalid mark in one batch — used
/// when the applied chain did not move.
fn persist_unchanged(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
    trigger: Option<BlockHash>,
    invalid_log: &[(BlockHash, String)],
    cleared: &[BlockHash],
) -> Result<(), String> {
    let mut batch = rocksdb::WriteBatch::default();
    if let Some(t) = trigger {
        if dag.read().has_block(&t) {
            stage_dag_record_for(dag, store, &mut batch, &t)?;
        }
    }
    for h in cleared {
        store.stage_clear_invalid_block(&mut batch, h).map_err(|e| e.to_string())?;
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
    /// Fold one committed plan's outcome in. A block rolled back from its
    /// undo record alone (body pruned, audit DAG-6) has no transactions to
    /// report; it only cancels an earlier connect of the same block.
    pub fn record(&mut self, outcome: ConnectOutcome) {
        for h in &outcome.disconnected_pruned {
            if let Some(i) = self.connected.iter().position(|c| c.block_hash() == *h) {
                self.connected.remove(i);
            }
        }
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
            "{}{} is invalid", INHERITED_REASON_PREFIX,
            sp.map(|p| hex::encode(&p[..8])).unwrap_or_default()
        )));
    }

    // ── Connect the best valid chain (any depth, audit DAG-6) ────────
    let resolution = resolve_best_chain(
        dag, store, shielded, applied_tip, Some(block_hash), !replacing,
        &mut log, &MarkClears::default(), MissingBodies::Wait,
    );

    let resolution = match resolution {
        Ok(r) => r,
        Err(m) => {
            // Storage failure: roll the in-memory change back (nothing was
            // committed), drop the body, but keep any deterministic invalid
            // marks discovered on the way.
            roll_back("resolution stopped");
            if !log.invalid.is_empty() {
                if let Err(e) = persist_unchanged(dag, store, None, &log.invalid, &[]) {
                    error!("failed to persist invalid-block marks: {}", e);
                }
            }
            // Disqualifications found on the way change the valid tips.
            sync_mempool_next_height(dag, store, mempool);
            return Err(format!("block {} not committed: {}", hex::encode(&block_hash[..8]), m));
        }
    };

    let connected = match resolution {
        Resolution::Unchanged => {
            let record = if replacing { None } else { Some(block_hash) };
            if let Err(e) = persist_unchanged(dag, store, record, &log.invalid, &[]) {
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

    // (No finality checkpoint any more — audit DAG-6. The pruning cursor
    // below uses the selected tip's DAG height, never tip_blue_score(); see
    // the DAG-8 note on `GhostdagData::height`.)
    let tip_height = {
        let d = dag.read();
        d.selected_tip()
            .and_then(|h| d.get_block_data(&h).map(|data| data.height))
            .unwrap_or(0)
    };

    // ── Prune old block bodies ───────────────────────────────────────
    // Bodies only: undo records are kept for every connected block and a
    // rollback record is written for each pruned body, so a reorg of any
    // depth still works on a pruned node (DAG-6).
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
/// 3. refuse (an error naming the faults) if the chain state still carries
///    the footprint of an interrupted pre-fix commit that steps 1-2 cannot
///    repair ([`check_chain_state`], audit DAG-11 residual; run only after
///    step 2, which repairs the states it handles, so it never misfires on
///    them): the caller rebuilds ([`rebuild_chain_state`]) and calls this
///    again;
/// 4. if the applied tip pointer is not the best valid block, connect the
///    best valid chain with the same atomic machinery as `accept_block` (a
///    rollback-only plan when step 1 disqualified applied blocks), at any
///    depth (audit DAG-6); blocks of that chain whose body is missing wait
///    for one, and the best chain the node can connect is connected
///    meanwhile.
///
/// Every step is idempotent and cheap (one scan of CF_UNDO keys). New writes
/// can no longer produce a state that needs step 2: an extension now commits
/// UTXO effects, undo data, DAG record and tip pointer in one batch.
///
/// `shielded` must be the state [`ShieldedPool::load`] returned for `store`
/// (audit COH-2: it sits at the applied tip). Step 1 and the explorer
/// aggregate rebuild (NET-12) leave the applied tip where it is; steps 2 and
/// 4 move the shielded state with the chain, in the same batches.
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
        //   blocks (they stay applied until step 4 disconnects them), and a
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
        // unrecorded blocks sit on their selected parent. Step 4 then moves
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

    // DAG-11 residual: never connect anything on top of a chain state that
    // carries the footprint of an interrupted pre-fix commit (step 4 would
    // validate blocks against it and could disqualify valid ones). The
    // caller rebuilds (`rebuild_chain_state`) or stops.
    let faults = check_chain_state(dag, store)?;
    if !faults.is_empty() {
        let list: Vec<String> = faults.iter().map(|f| f.to_string()).collect();
        return Err(format!(
            "chain state inconsistent ({}); rebuild it from the block bodies \
             (`rebuild_chain_state`, done by `gnb` at start-up with --carryover-snapshot)",
            list.join("; ")
        ));
    }

    // Step 4: applied tip vs best valid block.
    let applied = store.get_meta("tip_hash").ok().flatten()
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok());
    let best = dag.read().selected_tip();
    if let (Some(applied), Some(best)) = (applied, best) {
        if applied != best && dag.read().has_block(&applied) {
            warn!("reconcile: applied tip {} != best valid block {}; reconnecting",
                hex::encode(&applied[..8]), hex::encode(&best[..8]));
            let mut log = ResolveLog::default();
            match resolve_best_chain(dag, store, shielded, applied, None, false, &mut log,
                                     &MarkClears::default(), MissingBodies::Wait) {
                Ok(_) => {
                    if !log.invalid.is_empty() {
                        persist_unchanged(dag, store, None, &log.invalid, &[])?;
                    }
                }
                Err(m) => {
                    error!("reconcile: cannot reconnect the best valid chain: {}", m);
                    if !recheck.disqualified.is_empty() {
                        // There is no reorg-depth limit (audit DAG-6): the
                        // rollback off them failed on storage or missing data.
                        error!(
                            "reconcile: the applied chain still contains blocks a pre-upgrade binary stored \
                             that fail the hardening block rules, and the rollback off them failed; \
                             resynchronize this data directory if this persists"
                        );
                    }
                    return Err(m);
                }
            }
        }
    }
    Ok(())
}

// ── Start-up chain-state check and rebuild (DAG-11 residual) ─────────────────

/// CF_META flag set while [`rebuild_chain_state`] is between its two commits.
pub const REBUILD_PENDING_META: &str = "chainstate_rebuild_pending";

/// A footprint of the PRE-FIX, non-atomic extension commit that
/// `reconcile_on_startup` cannot repair (audit DAG-11 residual).
///
/// The pre-fix extension wrote, one RocksDB write at a time and in this
/// order: per transaction `tx_index` row, created outputs, then the coinbase
/// row or the input deletions; the undo record LAST; then the tip pointer and
/// the CF_DAG record — and a write error was only logged. RocksDB recovers a
/// prefix of the issued writes after a crash, so:
///
/// * a crash (or error) before the undo record leaves `tx_index` rows of the
///   block — the first write for every transaction whose effects started —
///   pointing at a block WITHOUT an undo record: [`UnrecordedEffects`];
/// * a write error followed by the (logged-and-ignored) tip / CF_DAG writes
///   leaves the block on the applied chain without an undo record:
///   [`AppliedWithoutUndo`].
///
/// This release cannot produce either: every chain move commits UTXO effects,
/// undo record, chain indexes, DAG record and tip pointer in ONE batch
/// (`reorg::connect_plan`), so a crash leaves all of them or none. The
/// footprints can only come from a database written by an earlier release.
///
/// [`UnrecordedEffects`]: ChainStateFault::UnrecordedEffects
/// [`AppliedWithoutUndo`]: ChainStateFault::AppliedWithoutUndo
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainStateFault {
    /// `rows` CF_TX_INDEX rows point at `block`, which has no undo record.
    UnrecordedEffects { block: BlockHash, rows: usize },
    /// `block` is on the applied chain (tip pointer back to genesis) but has
    /// no undo record.
    AppliedWithoutUndo { block: BlockHash },
    /// A previous [`rebuild_chain_state`] stopped between its two commits.
    RebuildInterrupted,
}

impl std::fmt::Display for ChainStateFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainStateFault::UnrecordedEffects { block, rows } => write!(
                f, "{} transaction-index row(s) point at block {} which has no undo record \
                    (UTXO effects of an interrupted pre-fix commit)", rows, hex::encode(&block[..8])),
            ChainStateFault::AppliedWithoutUndo { block } => write!(
                f, "block {} is on the applied chain but has no undo record", hex::encode(&block[..8])),
            ChainStateFault::RebuildInterrupted => write!(f, "a chain-state rebuild was interrupted"),
        }
    }
}

/// Detect every [`ChainStateFault`]. Cheap enough for every start-up: one
/// scan of the CF_UNDO keys and of CF_TX_INDEX, plus a walk of the applied
/// chain. The genesis block has no undo record by construction and is
/// exempt.
pub fn check_chain_state(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
) -> Result<Vec<ChainStateFault>, String> {
    let mut faults = Vec::new();
    if store.get_meta(REBUILD_PENDING_META).map_err(|e| e.to_string())?.as_deref() == Some(&[1u8][..]) {
        faults.push(ChainStateFault::RebuildInterrupted);
    }
    let genesis = dag.read().store.genesis;
    let undo: HashSet<BlockHash> = store.undo_block_hashes().map_err(|e| e.to_string())?
        .into_iter().collect();
    let mut unrecorded: HashMap<BlockHash, usize> = HashMap::new();
    for (_, block) in store.tx_index_entries().map_err(|e| e.to_string())? {
        if Some(block) != genesis && !undo.contains(&block) {
            *unrecorded.entry(block).or_insert(0) += 1;
        }
    }
    let mut unrecorded: Vec<(BlockHash, usize)> = unrecorded.into_iter().collect();
    unrecorded.sort_unstable();
    faults.extend(unrecorded.into_iter()
        .map(|(block, rows)| ChainStateFault::UnrecordedEffects { block, rows }));

    let applied = store.get_meta("tip_hash").map_err(|e| e.to_string())?
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok());
    if let Some(tip) = applied {
        let d = dag.read();
        // A tip pointer the DAG does not know is reconcile step 2's case.
        let mut cur = if d.has_block(&tip) { Some(tip) } else { None };
        while let Some(h) = cur {
            if Some(h) == genesis {
                break;
            }
            if !undo.contains(&h) {
                faults.push(ChainStateFault::AppliedWithoutUndo { block: h });
            }
            cur = d.get_block_data(&h).and_then(|x| x.selected_parent);
        }
    }
    Ok(faults)
}

/// What [`rebuild_chain_state`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RebuildReport {
    /// Chain-state rows deleted before the rebuild.
    pub cleared_rows: usize,
    /// Consensus disqualification marks dropped (re-derived while connecting).
    pub cleared_marks: usize,
    /// Selected-chain blocks connected from genesis.
    pub connected_blocks: usize,
}

/// Rebuild the chain state — UTXO set, coinbase heights, transaction index,
/// undo records, selected-chain indexes, address history, the shielded-pool
/// state (audit COH-2) and the explorer aggregates (audit NET-12) — from the
/// block bodies (audit DAG-11 residual).
///
/// 1. Check that every block of the best valid chain whose body was PRUNED
///    still has it (a pruned node cannot rebuild: it must resync from a fresh
///    data dir or an archival copy; a body missing above the pruning cursor
///    is waited for like on acceptance). Operator `invalidateblock` marks and
///    the context-free hardening-recheck marks (they depend on the stored
///    bodies only, and the recheck does not run again) are kept; connect-time
///    consensus marks are dropped, since they may have been made against the
///    inconsistent state, and are re-derived by step 3.
/// 2. One batch: delete every chain-state row (shielded state included), mark
///    the explorer aggregates incomplete, stage the genesis state (`seed`:
///    the carryover UTXOs and the genesis transaction index, exactly what
///    first boot writes), the genesis chain-index rows, the tip pointer =
///    genesis and the `REBUILD_PENDING_META` flag; the in-memory shielded
///    pool is reset to the genesis state.
/// 3. Connect the best valid chain from genesis with the normal atomic
///    machinery (`resolve_best_chain`: every block validated in its own
///    context, the shielded state staged into the same batches), recompute
///    the explorer aggregates from scratch, then clear the flag. If the
///    process stops before the flag is cleared, the next start-up reports
///    `RebuildInterrupted` and rebuilds again (each step is idempotent).
///
/// The result is the state a node that never crashed holds: the UTXO set is
/// the deterministic application of the best valid chain to the genesis
/// state (`node/tests/fix_chain_selection.rs` compares UTXO-set digests).
pub fn rebuild_chain_state(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &Arc<storage::Storage>,
    shielded: &Arc<RwLock<ShieldedPool>>,
    seed: &dyn Fn(&storage::Storage, &mut rocksdb::WriteBatch) -> Result<(), String>,
) -> Result<RebuildReport, String> {
    let _guard = store.acceptance_lock();
    ensure_invalid_set_loaded(dag, store);
    let genesis = dag.read().store.genesis.ok_or("rebuild: the DAG has no genesis")?;

    // 1. Marks, then the bodies of the best valid chain under them.
    let marks = store.load_invalid_blocks_with_reasons().map_err(|e| e.to_string())?;
    let (keep, drop): (Vec<_>, Vec<_>) = marks.into_iter()
        .partition(|(_, r)| matches!(mark_kind(r), MarkKind::Operator | MarkKind::Hardening));
    {
        let (selected, all_edges) = split_marks(keep.iter().cloned());
        dag.write().reset_invalid_sets(selected, all_edges);
    }
    let pruned_below = store.pruned_height();
    let missing_body = {
        let d = dag.read();
        let mut cur = d.selected_tip();
        let mut missing = None;
        while let Some(h) = cur {
            if h == genesis {
                break;
            }
            let height = d.get_block_data(&h).map(|x| x.height).unwrap_or(0);
            if height < pruned_below && !store.has_block_body(&h).map_err(|e| e.to_string())? {
                missing = Some((h, height));
                break;
            }
            cur = d.get_block_data(&h).and_then(|x| x.selected_parent);
        }
        missing
    };
    if let Some((h, height)) = missing_body {
        // Nothing was written: restore the in-memory disqualified set.
        reload_persisted_marks(dag, store);
        return Err(format!(
            "rebuild impossible: the body of selected-chain block {} (h={}) has been \
             pruned. Resync from a fresh --data-dir (with --carryover-snapshot) or from \
             an archival node's data dir.",
            hex::encode(&h[..8]), height
        ));
    }

    // 2. Clear + genesis state, one batch.
    let mut batch = rocksdb::WriteBatch::default();
    store.stage_aggregates_incomplete(&mut batch).map_err(|e| e.to_string())?;
    let cleared_rows = store.stage_clear_chain_state(&mut batch).map_err(|e| e.to_string())?;
    seed(store, &mut batch)?;
    if let Some(gb) = store.get_block(&genesis).map_err(|e| e.to_string())? {
        store.stage_chain_index(&mut batch, &gb, &HashMap::new()).map_err(|e| e.to_string())?;
    }
    for (h, _) in &drop {
        store.stage_clear_invalid_block(&mut batch, h).map_err(|e| e.to_string())?;
    }
    store.stage_meta(&mut batch, "tip_hash", &genesis).map_err(|e| e.to_string())?;
    store.stage_meta(&mut batch, REBUILD_PENDING_META, &[1u8]).map_err(|e| e.to_string())?;
    store.write_batch(batch).map_err(|e| e.to_string())?;
    shielded.write().reset_for_rebuild();

    // 3. Connect the best valid chain from genesis.
    let mut log = ResolveLog::default();
    let connected_blocks = match resolve_best_chain(dag, store, shielded, genesis, None, false, &mut log,
                                                    &MarkClears::default(), MissingBodies::Wait)? {
        Resolution::Connected { outcome, .. } => outcome.connected.len(),
        Resolution::Unchanged => {
            if !log.invalid.is_empty() {
                persist_unchanged(dag, store, None, &log.invalid, &[])?;
            }
            0
        }
    };
    store.rebuild_aggregates(&std::sync::atomic::AtomicBool::new(false)).map_err(|e| e.to_string())?;
    store.put_meta(REBUILD_PENDING_META, &[0u8]).map_err(|e| e.to_string())?;
    warn!("chain state rebuilt from block bodies: {} row(s) cleared, {} consensus mark(s) re-derived, \
           {} block(s) connected", cleared_rows, drop.len(), connected_blocks);
    Ok(RebuildReport { cleared_rows, cleared_marks: drop.len(), connected_blocks })
}

// ── Blocks in the DAG without a usable body (audit DAG-6 / VAL-1x) ──────────
//
// Two situations leave a block in the DAG without a body the node can use:
// its body failed a rule that depends on witness bytes the id does not commit
// to (below the hardening activation, `drop_body_and_wait`), or its body was
// pruned while it was on the selected chain and a reorg then left it
// unapplied (DAG-6: no reorg-depth limit, so the chain through it can become
// the best one again). Both are ONE state: the block waits for a body
// (`GhostDAG::mark_body_pending`, in memory) — set by `resolve_best_chain`
// for every block of the best chain it cannot connect, or by
// [`request_bodies`] for the bodies an operator override needs —, and
// [`awaits_body`] is the one predicate every ingress path consults. The
// message processor requests those bodies through its missing-parent tracker
// (`ingress::awaited_bodies_to_request`), and a copy that arrives goes
// through `accept_block`'s body-replacement path: bound to the header height
// the DAG parents imply, the expected bits, the timestamp, the hardening
// block rules (witness commitment), the proof of work and the
// rejected-witness-root memo, then stored with the metadata acceptance
// derives.

/// The blocks a connect of a block with these `parents` would APPLY that
/// have no stored body: its selected-chain ancestors that are not applied
/// (no undo record), walking down from the parent of greatest
/// `(blue_work, blue_score, hash)`, nearest first, at most `limit`.
///
/// Operator overrides name exactly these when the chain they move to needs
/// bodies this pruned node no longer has ([`OverrideError::MissingBodies`]).
pub fn missing_bodies_below(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
    parents: &[BlockHash],
    limit: usize,
) -> Vec<BlockHash> {
    let d = dag.read();
    let genesis = d.store.genesis;
    let mut cur = parents.iter()
        .filter_map(|p| d.get_block_data(p).map(|x| (x.blue_work, x.blue_score, *p)))
        .max()
        .map(|(_, _, p)| p);
    let mut out = Vec::new();
    while let Some(h) = cur {
        if out.len() >= limit || Some(h) == genesis || store.has_undo_data(&h).unwrap_or(true) {
            break;
        }
        if !store.has_block_body(&h).unwrap_or(true) {
            out.push(h);
        }
        cur = d.get_block_data(&h).and_then(|x| x.selected_parent);
    }
    out
}

/// Make the blocks of `hashes` whose body is wanted wait for one
/// (`GhostDAG::mark_body_pending`), so [`awaits_body`] admits a copy and the
/// message processor requests it: blocks in the DAG, not the genesis, without
/// a stored body and NOT applied (an applied block never needs its body: a
/// rollback works from its undo record), and not on the selected chain of
/// the selected tip (marking those would move the selected tip without a
/// connect; the acceptance pipeline marks the bodies the best chain needs
/// itself). Returns the hashes marked. Used for the bodies an operator
/// override needs (audit DAG-6).
pub fn request_bodies(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
    hashes: &[BlockHash],
) -> Vec<BlockHash> {
    let mut d = dag.write();
    let genesis = d.store.genesis;
    let tip = d.selected_tip();
    let mut marked = Vec::new();
    for h in hashes {
        let wanted = d.has_block(h)
            && Some(*h) != genesis
            && matches!(store.has_block_body(h), Ok(false))
            && matches!(store.has_undo_data(h), Ok(false))
            && !tip.is_some_and(|t| d.is_on_selected_chain_of(h, &t));
        if wanted {
            d.mark_body_pending(*h, None);
            marked.push(*h);
        }
    }
    marked
}

// ── Operator recovery: invalidateblock / reconsiderblock (DAG-6) ─────────────

/// Reason prefix of a mark a block inherits from its disqualified selected
/// parent (`accept_block`, a new block on a disqualified chain).
pub const INHERITED_REASON_PREFIX: &str = "selected parent ";

/// What a persisted disqualification mark records, by its reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarkKind {
    /// Operator `invalidateblock` ([`OPERATOR_INVALIDATE_REASON`]).
    Operator,
    /// The context-free hardening block rules (start-up recheck of blocks a
    /// pre-upgrade binary stored, or a block referencing one): reason
    /// starting with [`HARDENING_RECHECK_REASON`], reloaded as an all-edges
    /// root.
    Hardening,
    /// Inherited from a disqualified selected parent
    /// ([`INHERITED_REASON_PREFIX`]): a consequence, not a verdict on the
    /// block itself.
    Inherited,
    /// The block itself failed a connect-time consensus rule in its own
    /// selected-chain context.
    Consensus,
}

/// Classify a persisted mark by its recorded reason.
pub fn mark_kind(reason: &str) -> MarkKind {
    if reason == OPERATOR_INVALIDATE_REASON {
        MarkKind::Operator
    } else if reason.starts_with(HARDENING_RECHECK_REASON) {
        MarkKind::Hardening
    } else if reason.starts_with(INHERITED_REASON_PREFIX) {
        MarkKind::Inherited
    } else {
        MarkKind::Consensus
    }
}

/// Persisted marks as GhostDAG loads them: (roots spread along selected-parent
/// chains, roots spread through every parent edge — hardening marks).
fn split_marks<I: IntoIterator<Item = (BlockHash, String)>>(marks: I) -> (Vec<BlockHash>, Vec<BlockHash>) {
    let mut selected = Vec::new();
    let mut all_edges = Vec::new();
    for (h, reason) in marks {
        if mark_kind(&reason) == MarkKind::Hardening {
            all_edges.push(h);
        } else {
            selected.push(h);
        }
    }
    (selected, all_edges)
}

/// Re-derive the in-memory disqualified set from the persisted marks (the
/// in-memory body-pending roots are kept): after an override that committed
/// nothing.
fn reload_persisted_marks(dag: &Arc<RwLock<consensus::GhostDAG>>, store: &storage::Storage) {
    match store.load_invalid_blocks_with_reasons() {
        Ok(marks) => {
            let (selected, all_edges) = split_marks(marks);
            dag.write().reset_invalid_sets(selected, all_edges);
        }
        Err(e) => error!("cannot re-read the persisted invalid-block set: {}", e),
    }
}

/// Result of an operator chain override.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainOverride {
    /// The applied tip after the call.
    pub tip: BlockHash,
    /// Its DAG height.
    pub tip_height: u64,
    /// Selected-chain blocks rolled back / connected by the call.
    pub rolled_back: usize,
    pub connected: usize,
    /// Blocks marked (invalidate) or unmarked (reconsider).
    pub affected: usize,
}

/// Why an operator chain override changed nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverrideError {
    /// Refused or failed (unknown block, genesis, storage error, ...).
    Failed(String),
    /// Pruned nodes: the chain to move to must apply blocks whose bodies this
    /// node pruned (`reorg::ERR_MISSING_BODIES`). Nothing was committed and
    /// the marks are as before the call. `missing` are the next bodies to
    /// re-fetch (unapplied selected-chain blocks without a body, nearest the
    /// new tip first, at most `ingress::MAX_BODY_REFETCH`); they now wait for
    /// a body ([`request_bodies`]: the processor requests them), and once they
    /// are restored the same call is retried (and asks for the next ones).
    MissingBodies { missing: Vec<BlockHash>, reason: String },
}

impl std::fmt::Display for OverrideError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OverrideError::Failed(m) => f.write_str(m),
            OverrideError::MissingBodies { missing, reason } => write!(
                f, "{} block bod(ies) must be re-fetched first ({})", missing.len(), reason),
        }
    }
}

impl std::error::Error for OverrideError {}

impl From<String> for OverrideError {
    fn from(m: String) -> Self {
        OverrideError::Failed(m)
    }
}

impl From<&str> for OverrideError {
    fn from(m: &str) -> Self {
        OverrideError::Failed(m.to_string())
    }
}

/// Shared tail of the two operator calls: move the applied chain to the best
/// valid block, persisting `log` marks and removing the `clears` marks in the
/// same batch (a consensus mark only if the move re-validated its block),
/// then refresh the mempool and the RPC-visible state. The caller's in-memory
/// marks are still in place on return; on `Err` the caller restores them from
/// disk (nothing was committed).
#[allow(clippy::too_many_arguments)]
fn apply_operator_override(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &Arc<storage::Storage>,
    mempool: &Arc<mempool::Mempool>,
    node_state: &Arc<RwLock<rpc::NodeState>>,
    tip_tx: Option<&broadcast::Sender<tip::TipChanged>>,
    shielded: &Arc<RwLock<ShieldedPool>>,
    log: Vec<(BlockHash, String)>,
    clears: MarkClears,
    affected: usize,
) -> Result<ChainOverride, OverrideError> {
    let applied = store.get_meta("tip_hash").map_err(|e| e.to_string())?
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
        .ok_or("no applied tip pointer")?;
    let (mut rolled_back, mut connected) = (0usize, 0usize);
    let mut rlog = ResolveLog { invalid: log, body_rejected: Vec::new() };
    let resolution = match resolve_best_chain(dag, store, shielded, applied, None, false, &mut rlog,
                                              &clears, MissingBodies::Stop) {
        Ok(r) => r,
        Err(m) if m.contains(reorg::ERR_MISSING_BODIES) => {
            // DAG-6, pruned nodes: name the bodies to re-fetch while the
            // operator's marks still select the candidate that needs them.
            let cand = dag.read().selected_tip();
            let missing = match cand {
                Some(c) => missing_bodies_below(dag, store, &[c], crate::ingress::MAX_BODY_REFETCH),
                None => Vec::new(),
            };
            return Err(if missing.is_empty() {
                OverrideError::Failed(m)
            } else {
                OverrideError::MissingBodies { missing, reason: m }
            });
        }
        Err(m) => return Err(OverrideError::Failed(m)),
    };
    // First, before anything reads the valid tips (the next template height
    // below, the TipChanged parents): the consensus marks this move did not
    // re-validate are persisted still, so they hold in memory again.
    remark_unvalidated(dag, store, &clears.if_applied);
    match resolution {
        Resolution::Unchanged => {
            persist_unchanged(dag, store, None, &rlog.invalid, &clears.always)?;
            // The marks change the valid tips, hence the template height.
            sync_mempool_next_height(dag, store, mempool);
        }
        Resolution::Connected { plan, outcome } => {
            rolled_back = outcome.rolled_back();
            connected = outcome.connected.len();
            warn!("operator override: rolled back {} block(s), connected {} (lca={})",
                rolled_back, connected, hex::encode(&plan.lca[..8]));
            // The next height on the DAG after the move: the template height
            // (never the new tip's header height + 1, DAG-8).
            let next_height = crate::template::next_template_height(&dag.read(), store);
            update_mempool_after_connect(store, mempool, &outcome, next_height);
        }
    }
    let (tip, tip_height, score) = {
        let d = dag.read();
        let t = d.selected_tip().ok_or("DAG has no tip")?;
        let data = d.get_block_data(&t).cloned().ok_or("tip vanished")?;
        (t, data.height, data.blue_score)
    };
    {
        let mut s = node_state.write();
        s.tip_blue_score = score;
        s.block_count = dag.read().block_count() as u64;
        s.mempool_size = mempool.size();
    }
    if let Some(tx) = tip_tx {
        // Presence only (no decode), as on acceptance.
        let has_body = |h: &[u8; 32]| store.has_block_body(h).unwrap_or(false);
        let d = dag.read();
        if let Some(best) = d.best_bodied_tip(has_body) {
            if let Some(data) = d.get_block_data(&best).cloned() {
                // The template's own parents (memoized parent predicate).
                let parents = crate::template::template_parents_and_height(&d, store).0;
                drop(d);
                let bits = store.get_meta("current_bits").ok().flatten()
                    .and_then(|b| b.as_slice().try_into().ok().map(u32::from_le_bytes))
                    .unwrap_or(0x1d00ffff_u32);
                let _ = tx.send(tip::TipChanged {
                    hash: best, height: data.height, blue_score: data.blue_score, parents, bits,
                });
            }
        }
    }
    Ok(ChainOverride { tip, tip_height, rolled_back, connected, affected })
}

/// After a committed `reconsiderblock` move: every consensus mark in
/// `if_applied` whose block the move did not re-validate (not applied now)
/// is still persisted, so it holds in memory again, as a persistent root.
/// Also when the block is already disqualified in memory only through a
/// body-pending mark (its stored body was just rejected for a
/// witness-dependent reason, or it waits for an ancestor's body): that mark
/// is cleared when a body arrives, and without the root the block would
/// then connect while `invalid_block/<id>` stays on disk, to be disqualified
/// again at the next start (review of the P3 merge). The block is not an
/// ancestor of the applied tip (it is not applied), so the selected tip does
/// not move. Call before anything reads the valid tips.
fn remark_unvalidated(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
    if_applied: &[BlockHash],
) {
    for r in if_applied {
        // A read error counts as "still persisted" (the stricter memory).
        let persisted = store.invalid_block_reason(r).map(|m| m.is_some()).unwrap_or(true);
        if persisted && !store.has_undo_data(r).unwrap_or(false) {
            dag.write().mark_invalid(*r);
        }
    }
}

/// After an override that committed nothing: restore the in-memory marks from
/// disk and, when the chain to move to needs pruned bodies, make them wait for
/// a body ([`request_bodies`]) so the processor fetches them.
fn after_failed_override(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
    err: &OverrideError,
) {
    reload_persisted_marks(dag, store);
    if let OverrideError::MissingBodies { missing, .. } = err {
        let marked = request_bodies(dag, store, missing);
        info!("operator override: {} pruned block bod(ies) requested; retry once they arrived",
            marked.len());
    }
}

/// Operator `invalidateblock` (Bitcoin Core's `InvalidateBlock`): disqualify
/// `hash` and every block whose selected-parent chain passes through it,
/// persist the mark (`invalid_block/<hash>`, reason
/// [`OPERATOR_INVALIDATE_REASON`]) and move the applied chain to the best
/// valid block that remains — rolling back past `hash` if it was applied —
/// in one atomic batch. Survives restarts; undone by [`reconsider_block`].
/// A block that already carries a persisted mark keeps it (a consensus or
/// hardening verdict never becomes an operator mark the operator could clear
/// without re-validation): the call changes nothing. On a pruned node whose
/// new chain needs pruned bodies it changes nothing and returns
/// [`OverrideError::MissingBodies`] (they are requested; retry).
#[allow(clippy::too_many_arguments)]
pub fn invalidate_block(
    hash: BlockHash,
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &Arc<storage::Storage>,
    mempool: &Arc<mempool::Mempool>,
    node_state: &Arc<RwLock<rpc::NodeState>>,
    tip_tx: Option<&broadcast::Sender<tip::TipChanged>>,
    shielded: &Arc<RwLock<ShieldedPool>>,
) -> Result<ChainOverride, OverrideError> {
    let _guard = store.acceptance_lock();
    ensure_invalid_set_loaded(dag, store);
    if !dag.read().has_block(&hash) {
        return Err(format!("block {} not found", hex::encode(hash)).into());
    }
    if dag.read().store.genesis == Some(hash) {
        return Err("the genesis block cannot be invalidated".into());
    }
    if let Some(reason) = store.invalid_block_reason(&hash).map_err(|e| e.to_string())? {
        info!("invalidateblock {}: already disqualified ({}); nothing to do", hex::encode(&hash[..8]), reason);
        return apply_operator_override(dag, store, mempool, node_state, tip_tx, shielded,
                                       Vec::new(), MarkClears::default(), 0);
    }
    let marked = dag.write().mark_invalid(hash);
    warn!("invalidateblock {}: {} block(s) disqualified by the operator",
        hex::encode(&hash[..8]), marked.len());
    let log = vec![(hash, OPERATOR_INVALIDATE_REASON.to_string())];
    let res = apply_operator_override(dag, store, mempool, node_state, tip_tx, shielded, log,
                                      MarkClears::default(), marked.len());
    if let Err(e) = &res {
        // Nothing was committed.
        after_failed_override(dag, store, e);
    }
    res
}

/// Operator `reconsiderblock` (Bitcoin Core's `ReconsiderBlock`): consider
/// every persisted disqualification whose root is `hash`, a selected-chain
/// ancestor of `hash` or a block whose selected chain passes through `hash`,
/// and move the applied chain to the best valid block, in one atomic batch:
///
/// * operator marks and marks inherited from a selected parent are removed;
/// * a hardening-recheck mark (context-free, audit VAL/CRY hardening rules)
///   is removed only if the stored body now passes those rules
///   (`classify_stored_block`); otherwise it stays (a pruned body cannot be
///   re-checked and stays too);
/// * a connect-time consensus mark is removed only by the batch that
///   RE-VALIDATES the block — the move applies it, after validating it in its
///   own context; a block the move does not apply keeps its mark, and one
///   that fails again is disqualified again with its new reason.
///
/// Like [`invalidate_block`], it returns [`OverrideError::MissingBodies`] and
/// changes nothing when the chain to move to needs bodies this pruned node no
/// longer has.
#[allow(clippy::too_many_arguments)]
pub fn reconsider_block(
    hash: BlockHash,
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &Arc<storage::Storage>,
    mempool: &Arc<mempool::Mempool>,
    node_state: &Arc<RwLock<rpc::NodeState>>,
    tip_tx: Option<&broadcast::Sender<tip::TipChanged>>,
    shielded: &Arc<RwLock<ShieldedPool>>,
) -> Result<ChainOverride, OverrideError> {
    let _guard = store.acceptance_lock();
    ensure_invalid_set_loaded(dag, store);
    if !dag.read().has_block(&hash) {
        return Err(format!("block {} not found", hex::encode(hash)).into());
    }
    let marks = store.load_invalid_blocks_with_reasons().map_err(|e| e.to_string())?;
    let activation = core::activation::hardening_activation_height();
    let mut clears = MarkClears::default();
    let mut kept: Vec<(BlockHash, String)> = Vec::new();
    let mut still_failing = 0usize;
    {
        let d = dag.read();
        for (r, reason) in marks {
            if !(d.is_on_selected_chain_of(&r, &hash) || d.is_on_selected_chain_of(&hash, &r)) {
                kept.push((r, reason));
                continue;
            }
            match mark_kind(&reason) {
                MarkKind::Operator | MarkKind::Inherited => clears.always.push(r),
                MarkKind::Hardening => {
                    let passes = matches!(store.get_block(&r), Ok(Some(b))
                        if classify_stored_block(&b, activation) == StoredBlockCheck::Valid);
                    if passes {
                        clears.always.push(r);
                    } else {
                        still_failing += 1;
                        kept.push((r, reason));
                    }
                }
                MarkKind::Consensus => clears.if_applied.push(r),
            }
        }
    }
    if still_failing > 0 {
        warn!("reconsiderblock {}: {} mark(s) kept: the block still fails the hardening block rules \
               (or its body is pruned and cannot be re-checked)", hex::encode(&hash[..8]), still_failing);
    }
    let before = dag.read().invalid_count();
    {
        let (selected, all_edges) = split_marks(kept);
        dag.write().reset_invalid_sets(selected, all_edges);
    }
    let affected = before.saturating_sub(dag.read().invalid_count());
    info!("reconsiderblock {}: {} mark(s) removed, {} re-validated by the move, {} block(s) re-qualified",
        hex::encode(&hash[..8]), clears.always.len(), clears.if_applied.len(), affected);
    let res = apply_operator_override(dag, store, mempool, node_state, tip_tx, shielded, Vec::new(), clears, affected);
    if let Err(e) = &res {
        after_failed_override(dag, store, e);
    }
    res
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
