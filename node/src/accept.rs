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
//! height = max parent DAG height + 1, expected ASERT bits, timestamp, proof of
//! work, and the context-free consensus checks (canonical-encoding limits,
//! MoneyRange; the structural checks run in `validate_structure` before this
//! function). A failure here is context-free, so every node rejects the block
//! and it is never stored. A block that passes is inserted into GhostDAG and
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
//! **Invalid blocks**: a connect-time failure is a deterministic property of
//! the block and its selected-parent chain, so it is permanent. The failing
//! block and every block whose selected-parent chain passes through it are
//! marked chain-disqualified, in memory (`GhostDAG::mark_invalid`) and on disk
//! (`Storage::stage_invalid_block`), and the next-best block is tried; the
//! old tip is kept when nothing better is valid. A disqualified block is never
//! selected, applied or offered as a template parent, and a new block whose
//! selected parent is disqualified is disqualified on arrival. `accept_block`
//! reports such blocks as rejected (`Err`).
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

/// Load the persisted chain-disqualified set into `dag` once (start-up does it
/// via `reconcile_on_startup`; this is the lazy fallback).
pub fn ensure_invalid_set_loaded(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
) {
    if dag.read().invalid_set_loaded() {
        return;
    }
    match store.load_invalid_blocks() {
        Ok(hashes) => {
            let n = dag.write().load_invalid(hashes);
            if n > 0 {
                info!("loaded {} chain-disqualified block(s)", n);
            }
        }
        Err(e) => error!("cannot read the persisted invalid-block set: {}", e),
    }
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

/// Validate `tx` (the transaction at index `idx` of `block`) against `view`
/// plus the outputs of the transactions STRICTLY BEFORE it in the block
/// (`earlier`). Coinbase maturity uses the block's header height. Returns the
/// fee.
fn validate_tx_in_view(
    tx: &core::Transaction,
    view: &dyn UtxoView,
    earlier: &HashMap<([u8; 32], u32), core::TxOutput>,
    spent_in_block: &mut HashSet<([u8; 32], u32)>,
    current_height: u64,
) -> Result<u64, String> {
    core::check_coinbase_maturity(tx, current_height, |txid| {
        view.view_coinbase_height(txid).ok().flatten()
    })?;
    let lookup = |txid: &[u8; 32], idx: u32| -> Result<Option<core::TxOutput>, String> {
        if let Some(out) = earlier.get(&(*txid, idx)) {
            return Ok(Some(out.clone()));
        }
        view.view_utxo(txid, idx)
    };
    validate_tx_inputs(tx, &lookup, Some(spent_in_block), current_height)
}

/// Full in-context validation of a block's transactions against `view` (the
/// UTXO state of its selected parent): every non-coinbase transaction (inputs
/// exist, no double spend, maturity, scripts, value, minimum fee) and the
/// coinbase value against subsidy + fees. The rules are exactly the ones the
/// pre-fix `accept_block` applied to an extension block; the difference is
/// only WHICH state a block is checked against (its own, never the tip's).
pub fn validate_block_in_view(view: &dyn UtxoView, block: &core::Block) -> Result<(), String> {
    let height = block.height;
    let mut spent_in_block: HashSet<([u8; 32], u32)> = HashSet::new();
    let mut earlier: HashMap<([u8; 32], u32), core::TxOutput> = HashMap::new();
    let mut total_fees: u64 = 0;
    for (i, tx) in block.transactions.iter().enumerate() {
        if i > 0 {
            let fee = validate_tx_in_view(tx, view, &earlier, &mut spent_in_block, height)?;
            total_fees = core::limits::money_add(total_fees, fee)
                .map_err(|e| format!("block fee sum: {}", e))?;
        }
        let txid = tx.txid();
        for (j, o) in tx.outputs.iter().enumerate() {
            earlier.insert((txid, j as u32), o.clone());
        }
    }
    block.validate_coinbase_value(total_fees)
        .map_err(|e| format!("coinbase rejected: {}", e))
}

// ── Shielded state (COH-2) ───────────────────────────────────────────────────

/// Compute the shielded pool after moving the applied chain along `plan`
/// (disconnect `to_rollback` tip-first, connect `to_apply` in order) on a
/// CLONE. The caller swaps it in only after the RocksDB batch committed.
fn shielded_after_plan(
    shielded: &Arc<RwLock<ShieldedPool>>,
    store: &storage::Storage,
    plan: &reorg::ReorgPlan,
) -> Result<ShieldedPool, ConnectError> {
    let mut next = shielded.read().clone();
    for h in &plan.to_rollback {
        let had = store.get_block(h).ok().flatten()
            .map(|b| !b.shielded_transactions.is_empty())
            .unwrap_or(true);
        next.disconnect_for_reorg(*h, had).map_err(|e| ConnectError::Failed(format!(
            "shielded disconnect of {} failed: {:?}", hex::encode(&h[..8]), e)))?;
    }
    for h in &plan.to_apply {
        let b = store.get_block(h).map_err(|e| ConnectError::Failed(e.to_string()))?
            .ok_or_else(|| ConnectError::Failed("block body missing for shielded apply".into()))?;
        if let Err(e) = next.apply_block_self(*h, &b.shielded_transactions) {
            return Err(ConnectError::Invalid {
                block: *h,
                height: b.height,
                reason: format!("shielded consensus rejection: {:?}", e),
            });
        }
    }
    Ok(next)
}

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
        let candidates: Vec<core::Transaction> = outcome.disconnected.iter()
            .flat_map(|b| b.transactions.iter().filter(|t| !t.is_coinbase()).cloned())
            .collect();
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
/// rejects for a block at `next_height`
/// (`admission::check_version_for_next_block`). Returns how many were removed.
pub fn evict_version_invalid(mempool: &mempool::Mempool, next_height: u64) -> usize {
    mempool.retain_valid(|e| admission::check_version_for_next_block(&e.tx, next_height).is_ok())
}

/// MEM-3: drop every pooled tx that is no longer minable on the current
/// UTXO set (an input missing, an immature coinbase input at `next_height`,
/// a fee below the consensus minimum, or a version invalid or non-standard at
/// `next_height`). Signature-free and cheap. Returns how many were removed.
pub fn revalidate_mempool(store: &storage::Storage, mempool: &mempool::Mempool, next_height: u64) -> usize {
    mempool.retain_valid(|e| {
        if admission::check_version_for_next_block(&e.tx, next_height).is_err() {
            return false;
        }
        let mut total_in: u64 = 0;
        for inp in &e.tx.inputs {
            match store.get_utxo(&inp.prev_txid, inp.prev_index) {
                Ok(Some(o)) => match core::limits::money_add(total_in, o.value) {
                    Ok(t) => total_in = t,
                    Err(_) => return false,
                },
                _ => return false,
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
/// tip. When the height moved, drop the transactions whose version is invalid
/// or non-standard at the new height and, when it went down, the ones no
/// longer mature (`revalidate_mempool`). Call under the acceptance lock (or
/// at start-up before any concurrent acceptance). Returns the height.
pub fn sync_mempool_next_height(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
    mempool: &mempool::Mempool,
) -> u64 {
    let next = crate::template::next_template_height(&dag.read(), store);
    let previous = mempool.set_next_height(next);
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

/// Move the applied chain to the best valid block, marking blocks invalid as
/// they fail. `trigger` is the block whose insertion prompted the call (its
/// DAG record is folded into the commit batch). `invalid_log` accumulates
/// (root, reason) for every newly disqualified root.
#[allow(clippy::too_many_arguments)]
fn resolve_best_chain(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
    shielded: &Arc<RwLock<ShieldedPool>>,
    applied_tip: BlockHash,
    trigger: Option<BlockHash>,
    trigger_header_height: u64,
    finalized_height: u64,
    invalid_log: &mut Vec<(BlockHash, String)>,
) -> Result<Resolution, ResolveStop> {
    // Each iteration either commits, stops, or disqualifies at least one more
    // block; the DAG is finite, so this terminates. The bound is a guard.
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
            reorg::compute_connect_plan(&d, &applied_tip, &cand)
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

        let next_shielded = match shielded_after_plan(shielded, store, &plan) {
            Ok(s) => s,
            Err(ConnectError::Invalid { block, reason, .. }) => {
                disqualify(dag, block, reason, invalid_log);
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

        let validate = |view: &dyn UtxoView, b: &core::Block| validate_block_in_view(view, b);
        let new_tip = cand;
        let log_snapshot = invalid_log.clone();
        let stage_extra = |st: &storage::Storage, batch: &mut rocksdb::WriteBatch| -> Result<(), String> {
            if let Some(t) = trigger {
                if dag.read().has_block(&t) {
                    stage_dag_record_for(dag, st, batch, &t)?;
                }
            }
            stage_invalid_marks(dag, st, batch, &log_snapshot)?;
            st.stage_meta(batch, "tip_hash", &new_tip).map_err(|e| e.to_string())
        };
        let hooks = ConnectHooks { validate: &validate, stage_extra: &stage_extra };
        match reorg::connect_plan(store, &plan, &hooks) {
            Ok(outcome) => {
                if reorg_depth > 0 { crate::metrics::inc_reorg_success(); }
                *shielded.write() = next_shielded;
                // Marks were persisted in the batch.
                invalid_log.clear();
                return Ok(Resolution::Connected { plan, outcome });
            }
            Err(ConnectError::Invalid { block, reason, .. }) => {
                if reorg_depth > 0 { crate::metrics::inc_reorg_failure(); }
                disqualify(dag, block, reason, invalid_log);
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
    // DAG-10: one acceptance at a time, across every ingress path.
    let _accept_guard = store.acceptance_lock();
    ensure_invalid_set_loaded(dag, store);

    // Sprint 2.c: snapshot the selected tip BEFORE any DAG mutation so we can
    // detect whether this block changed the chain's head.
    let old_tip = { dag.read().selected_tip() };

    // ── Early dedup ──────────────────────────────────────────────────
    if dag.read().get_block_data(&block_hash).is_some() {
        return Err(format!(
            "consensus rejection: block already in DAG: {}",
            hex::encode(block_hash)
        ));
    }

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
    let work = pow::work_from_bits(block.header.bits);
    dag.write().add_block(block_hash, block.header.parents.clone(), block.header.timestamp, work)
        .map_err(|e| format!("consensus rejection: {}", e))?;
    if let Err(e) = store.put_block_body(block) {
        dag.write().remove_block(&block_hash);
        return Err(e.to_string());
    }
    // Informational only (RPC / tip notifications).
    let _ = store.put_meta("current_bits", &block.header.bits.to_le_bytes());

    let mut invalid_log: Vec<(BlockHash, String)> = Vec::new();
    if dag.read().is_invalid(&block_hash) {
        let sp = dag.read().get_block_data(&block_hash).and_then(|d| d.selected_parent);
        invalid_log.push((block_hash, format!(
            "selected parent {} is invalid",
            sp.map(|p| hex::encode(&p[..8])).unwrap_or_default()
        )));
    }

    // ── Connect the best valid chain ─────────────────────────────────
    let resolution = resolve_best_chain(
        dag, store, shielded, applied_tip, Some(block_hash), block.height,
        finalized_height, &mut invalid_log,
    );

    let resolution = match resolution {
        Ok(r) => r,
        Err(stop) => {
            // Policy refusal or storage failure: roll the in-memory insertion
            // back (nothing was committed), drop the body, but keep any
            // deterministic invalid marks discovered on the way.
            if !dag.write().remove_block(&block_hash) {
                warn!("could not roll back DAG insertion of {}", hex::encode(&block_hash[..8]));
            }
            let _ = store.delete_block_body(&block_hash);
            if !invalid_log.is_empty() {
                if let Err(e) = persist_unchanged(dag, store, None, &invalid_log) {
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

    let connected = match &resolution {
        Resolution::Unchanged => {
            if let Err(e) = persist_unchanged(dag, store, Some(block_hash), &invalid_log) {
                // The DAG record of a non-applied block failed to persist:
                // undo the in-memory insertion so memory and disk agree.
                error!("failed to persist DAG record of {}: {}", hex::encode(&block_hash[..8]), e);
                dag.write().remove_block(&block_hash);
                let _ = store.delete_block_body(&block_hash);
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
            update_mempool_after_connect(store, mempool, outcome, next_height);
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
    let trigger_invalid: Option<String> = if dag.read().is_invalid(&block_hash) {
        let reason = store.invalid_block_reason(&block_hash).ok().flatten()
            .unwrap_or_else(|| "descends from an invalid block".to_string());
        Some(format!(
            "consensus rejection: block {} is invalid in its own chain context: {}",
            hex::encode(&block_hash[..8]), reason
        ))
    } else {
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
        let has_body = |h: &[u8; 32]| store.get_block(h).ok().flatten().is_some();
        let new_tip = { dag.read().best_bodied_tip(has_body) };
        if new_tip != old_tip {
            if let Some(tip_hash) = new_tip {
                let d = dag.read();
                if let Some(data) = d.get_block_data(&tip_hash).cloned() {
                    let tips_parents: Vec<[u8; 32]> = d.template_parents(core::MAX_PARENTS, has_body);
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

// ── Start-up reconciliation (DAG-11) ─────────────────────────────────────────

/// Reconcile the chain state on boot, before any block is accepted:
///
/// 1. load the persisted chain-disqualified set into the DAG;
/// 2. roll back the UTXO effects of any block that has an undo record but no
///    CF_DAG record — the footprint of the pre-fix, non-atomic extension
///    commit crashing between "apply UTXO effects" and "persist DAG data"
///    (audit VAL-4 / DAG-11). Its inputs would otherwise read as spent and the
///    block would be refused forever on re-receipt;
/// 3. if the applied tip pointer is not the best valid block, connect the
///    best valid chain with the same atomic machinery as `accept_block`.
///
/// Every step is idempotent and cheap (one scan of CF_UNDO keys). New writes
/// can no longer produce a state that needs step 2: an extension now commits
/// UTXO effects, undo data, DAG record and tip pointer in one batch.
pub fn reconcile_on_startup(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &Arc<storage::Storage>,
    shielded: &Arc<RwLock<ShieldedPool>>,
) -> Result<(), String> {
    let _guard = store.acceptance_lock();
    ensure_invalid_set_loaded(dag, store);

    // Step 2: applied-but-unrecorded blocks.
    let mut orphan_applied: Vec<(u64, BlockHash)> = Vec::new();
    for h in store.undo_block_hashes().map_err(|e| e.to_string())? {
        if !dag.read().has_block(&h) {
            if let Ok(Some(b)) = store.get_block(&h) {
                orphan_applied.push((b.height, h));
            } else {
                warn!("reconcile: undo record for unknown block {} without a body; ignoring",
                    hex::encode(&h[..8]));
            }
        }
    }
    if !orphan_applied.is_empty() {
        orphan_applied.sort_by(|a, b| b.cmp(a)); // tip-first
        let to_rollback: Vec<BlockHash> = orphan_applied.iter().map(|(_, h)| *h).collect();
        let back_to = dag.read().selected_tip();
        warn!(
            "reconcile: {} block(s) have applied UTXO effects but no DAG record (interrupted \
             pre-fix commit); rolling them back atomically",
            to_rollback.len()
        );
        let plan = reorg::ReorgPlan { lca: back_to.unwrap_or([0u8; 32]), to_rollback, to_apply: vec![] };
        let validate = |_: &dyn UtxoView, _: &core::Block| -> Result<(), String> { Ok(()) };
        let stage_extra = |st: &storage::Storage, batch: &mut rocksdb::WriteBatch| -> Result<(), String> {
            if let Some(t) = back_to {
                st.stage_meta(batch, "tip_hash", &t).map_err(|e| e.to_string())?;
            }
            Ok(())
        };
        let hooks = ConnectHooks { validate: &validate, stage_extra: &stage_extra };
        reorg::connect_plan(store, &plan, &hooks).map_err(|e| format!("reconcile rollback: {}", e))?;
    }

    // Step 3: applied tip vs best valid block.
    let applied = store.get_meta("tip_hash").ok().flatten()
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok());
    let best = dag.read().selected_tip();
    if let (Some(applied), Some(best)) = (applied, best) {
        if applied != best && dag.read().has_block(&applied) {
            warn!("reconcile: applied tip {} != best valid block {}; reconnecting",
                hex::encode(&applied[..8]), hex::encode(&best[..8]));
            let mut log = Vec::new();
            match resolve_best_chain(dag, store, shielded, applied, None, 0, 0, &mut log) {
                Ok(_) => {
                    if !log.is_empty() {
                        persist_unchanged(dag, store, None, &log)?;
                    }
                }
                Err(ResolveStop::Refused(m)) | Err(ResolveStop::Failed(m)) => {
                    error!("reconcile: cannot reconnect the best valid chain: {}", m);
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
/// minimum fee. All amounts are MoneyRange-checked (VAL-11).
pub fn validate_tx_inputs(
    tx:           &core::Transaction,
    utxo_lookup:  &dyn Fn(&[u8; 32], u32) -> Result<Option<core::TxOutput>, String>,
    mut spent_set: Option<&mut HashSet<([u8; 32], u32)>>,
    block_height: u64,
) -> Result<u64, String> {
    let mut total_in = 0u64;

    // C-R3-2: the intra-tx duplicate-outpoint check is UNCONDITIONAL.
    let mut local_spent: HashSet<([u8; 32], u32)> = HashSet::new();
    let mut prevouts: Vec<core::TxOutput> = Vec::with_capacity(tx.inputs.len());

    for inp in tx.inputs.iter() {
        let outpoint = (inp.prev_txid, inp.prev_index);
        let cross_tx_dup = spent_set.as_ref().is_some_and(|s| s.contains(&outpoint));
        if cross_tx_dup || !local_spent.insert(outpoint) {
            return Err(format!("double-spend: {}:{} already consumed",
                hex::encode(&inp.prev_txid[..8]), inp.prev_index));
        }
        let utxo = utxo_lookup(&inp.prev_txid, inp.prev_index)?
            .ok_or_else(|| format!("UTXO {}:{} not found",
                hex::encode(&inp.prev_txid[..8]), inp.prev_index))?;
        total_in = core::limits::money_add(total_in, utxo.value)
            .map_err(|e| format!("input overflow: {}", e))?;
        prevouts.push(utxo);
    }

    admission::verify_input_scripts(tx, &prevouts, block_height)?;

    if let Some(spent) = spent_set.as_mut() {
        for inp in &tx.inputs {
            spent.insert((inp.prev_txid, inp.prev_index));
        }
    }

    let total_out = core::limits::check_tx_money_range(tx)
        .map_err(|e| format!("output sum overflow: {}", e))?;
    if total_in < total_out {
        return Err(format!("inputs {} < outputs {}", total_in, total_out));
    }
    let fee = total_in - total_out;
    core::check_min_fee(tx, fee)?;
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
/// Uses both in-block outputs and persistent UTXO set, with double-spend tracking.
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

/// FIX VULN-03: Validate TX within a block against the COMMITTED store,
/// including coinbase maturity. Returns the fee.
///
/// SECURITY (Legacy C-2): the in-block prevout map holds ONLY the
/// transactions STRICTLY BEFORE `tx` in `block.transactions` (identified by
/// txid), so a transaction can never spend a later transaction's output. The
/// acceptance pipeline uses the equivalent `validate_block_in_view`, which
/// checks a block against its own context through a staging overlay.
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
    let earlier: HashMap<([u8; 32], u32), core::TxOutput> = block.transactions[..cutoff]
        .iter()
        .flat_map(|t| {
            let txid = t.txid();
            t.outputs.iter().enumerate().map(move |(i, o)| ((txid, i as u32), o.clone()))
        })
        .collect();
    let view: &storage::Storage = store;
    validate_tx_in_view(tx, view, &earlier, spent_in_block, current_height)
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
