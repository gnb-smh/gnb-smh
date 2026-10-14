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
//! machinery below.
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
//! [`reconcile_on_startup`] cannot repair; [`rebuild_chain_state`] rebuilds the
//! chain state from the block bodies.
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
    validate_tx_inputs(tx, &lookup, Some(spent_in_block))
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
    let verifier_active = next.verifier.is_active();
    for h in &plan.to_rollback {
        // Whether the block carried shielded transactions: from its body, or
        // from the record kept when the body was pruned (DAG-6). A body pruned
        // by an older release has no record; with no active verifier no block
        // carrying shielded transactions can have been accepted (context-free
        // rejection in `accept_block`), so the answer is then "no".
        let had = match store.get_block(h).ok().flatten() {
            Some(b) => !b.shielded_transactions.is_empty(),
            None => store.get_pruned_body_record(h).ok().flatten()
                .map(|r| r.had_shielded)
                .unwrap_or(verifier_active),
        };
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
/// `next_height` is the height of the next block on the new applied tip
/// (`admission::next_block_height`), also for a pure rollback.
pub fn update_mempool_after_connect(
    store: &storage::Storage,
    mempool: &mempool::Mempool,
    outcome: &ConnectOutcome,
    next_height: u64,
) {
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
    if outcome.rolled_back() > 0 {
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

/// MEM-3: drop every pooled tx that is no longer minable on the current
/// UTXO set (an input missing, an immature coinbase input at `next_height`,
/// or a fee below the consensus minimum). Signature-free and cheap. Returns
/// how many were removed.
pub fn revalidate_mempool(store: &storage::Storage, mempool: &mempool::Mempool, next_height: u64) -> usize {
    mempool.retain_valid(|e| {
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

// ── The pipeline ─────────────────────────────────────────────────────────────

/// Outcome of resolving the best valid chain after a DAG change.
enum Resolution {
    /// The applied tip did not move (fork-loser, merged-only, or every better
    /// candidate turned out invalid).
    Unchanged,
    /// The applied chain moved (extension or reorg) and was committed.
    Connected { plan: reorg::ReorgPlan, outcome: ConnectOutcome },
}

/// Move the applied chain to the best valid block, marking blocks invalid as
/// they fail. `trigger` is the block whose insertion prompted the call (its
/// DAG record is folded into the commit batch). `invalid_log` accumulates
/// (root, reason) for every newly disqualified root; `cleared` lists persisted
/// marks to delete in the same batch (operator `reconsiderblock`).
///
/// There is no depth limit and no finality gate (audit DAG-6): the plan to the
/// best valid block is executed at any depth. `Err` is a storage / missing-
/// data failure only (nothing committed; the caller rolls its trigger back).
fn resolve_best_chain(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &storage::Storage,
    shielded: &Arc<RwLock<ShieldedPool>>,
    applied_tip: BlockHash,
    trigger: Option<BlockHash>,
    invalid_log: &mut Vec<(BlockHash, String)>,
    cleared: &[BlockHash],
) -> Result<Resolution, String> {
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
            None => return Err(format!(
                "U.4: unexpected selected-tip transition (applied={}, best={}): no connect plan",
                hex::encode(&applied_tip[..8]), hex::encode(&cand[..8]))),
        };

        let next_shielded = match shielded_after_plan(shielded, store, &plan) {
            Ok(s) => s,
            Err(ConnectError::Invalid { block, reason, .. }) => {
                disqualify(dag, block, reason, invalid_log);
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

        let validate = |view: &dyn UtxoView, b: &core::Block| validate_block_in_view(view, b);
        let new_tip = cand;
        let log_snapshot = invalid_log.clone();
        let stage_extra = |st: &storage::Storage, batch: &mut rocksdb::WriteBatch| -> Result<(), String> {
            if let Some(t) = trigger {
                if dag.read().has_block(&t) {
                    stage_dag_record_for(dag, st, batch, &t)?;
                }
            }
            for h in cleared {
                st.stage_clear_invalid_block(batch, h).map_err(|e| e.to_string())?;
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
            Err(ConnectError::Failed(m)) => {
                if reorg_depth > 0 { crate::metrics::inc_reorg_failure(); }
                return Err(m);
            }
        }
    }
    Err("resolve_best_chain: iteration guard reached".into())
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

    // ── Connect the best valid chain (any depth, audit DAG-6) ────────
    let resolution = resolve_best_chain(
        dag, store, shielded, applied_tip, Some(block_hash), &mut invalid_log, &[],
    );

    let resolution = match resolution {
        Ok(r) => r,
        Err(m) => {
            // Storage failure: roll the in-memory insertion back (nothing was
            // committed), drop the body, but keep any deterministic invalid
            // marks discovered on the way.
            if !dag.write().remove_block(&block_hash) {
                warn!("could not roll back DAG insertion of {}", hex::encode(&block_hash[..8]));
            }
            let _ = store.delete_block_body(&block_hash);
            if !invalid_log.is_empty() {
                if let Err(e) = persist_unchanged(dag, store, None, &invalid_log, &[]) {
                    error!("failed to persist invalid-block marks: {}", e);
                }
            }
            return Err(format!("block {} not committed: {}", hex::encode(&block_hash[..8]), m));
        }
    };

    let connected = match &resolution {
        Resolution::Unchanged => {
            if let Err(e) = persist_unchanged(dag, store, Some(block_hash), &invalid_log, &[]) {
                // The DAG record of a non-applied block failed to persist:
                // undo the in-memory insertion so memory and disk agree.
                error!("failed to persist DAG record of {}: {}", hex::encode(&block_hash[..8]), e);
                dag.write().remove_block(&block_hash);
                let _ = store.delete_block_body(&block_hash);
                return Err(format!("block {} not committed: {}", hex::encode(&block_hash[..8]), e));
            }
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
            let next_height = mempool::admission::next_block_height(&dag.read());
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

    // DAG-11 residual: never connect anything on top of a chain state that
    // carries the footprint of an interrupted pre-fix commit (step 3 would
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

    // Step 3: applied tip vs best valid block.
    let applied = store.get_meta("tip_hash").ok().flatten()
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok());
    let best = dag.read().selected_tip();
    if let (Some(applied), Some(best)) = (applied, best) {
        if applied != best && dag.read().has_block(&applied) {
            warn!("reconcile: applied tip {} != best valid block {}; reconnecting",
                hex::encode(&applied[..8]), hex::encode(&best[..8]));
            let mut log = Vec::new();
            match resolve_best_chain(dag, store, shielded, applied, None, &mut log, &[]) {
                Ok(_) => {
                    if !log.is_empty() {
                        persist_unchanged(dag, store, None, &log, &[])?;
                    }
                }
                Err(m) => {
                    error!("reconcile: cannot reconnect the best valid chain: {}", m);
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
/// undo records, selected-chain indexes, address history — from the block
/// bodies (audit DAG-11 residual).
///
/// 1. Check that every block of the best valid chain still has its body (a
///    pruned node cannot rebuild: it must resync from a fresh data dir or an
///    archival copy). Operator `invalidateblock` marks are kept; consensus
///    marks are dropped, since they may have been made against the
///    inconsistent state, and are re-derived by step 3.
/// 2. One batch: delete every chain-state row, stage the genesis state
///    (`seed`: the carryover UTXOs and the genesis transaction index, exactly
///    what first boot writes), the genesis chain-index rows, the tip pointer =
///    genesis and the `REBUILD_PENDING_META` flag.
/// 3. Connect the best valid chain from genesis with the normal atomic
///    machinery (`resolve_best_chain`: every block validated in its own
///    context), then clear the flag. If the process stops before the flag is
///    cleared, the next start-up reports `RebuildInterrupted` and rebuilds
///    again (each step is idempotent).
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
    let all_roots: Vec<BlockHash> = marks.iter().map(|(h, _)| *h).collect();
    let (keep, drop): (Vec<_>, Vec<_>) =
        marks.into_iter().partition(|(_, r)| r == OPERATOR_INVALIDATE_REASON);
    dag.write().reset_invalid(keep.iter().map(|(h, _)| *h));
    let missing_body = {
        let d = dag.read();
        let mut cur = d.selected_tip();
        let mut missing = None;
        while let Some(h) = cur {
            if h == genesis {
                break;
            }
            if store.get_block(&h).map_err(|e| e.to_string())?.is_none() {
                missing = Some((h, d.get_block_data(&h).map(|x| x.height).unwrap_or(0)));
                break;
            }
            cur = d.get_block_data(&h).and_then(|x| x.selected_parent);
        }
        missing
    };
    if let Some((h, height)) = missing_body {
        // Nothing was written: restore the in-memory disqualified set.
        dag.write().reset_invalid(all_roots);
        return Err(format!(
            "rebuild impossible: the body of selected-chain block {} (h={}) has been \
             pruned. Resync from a fresh --data-dir (with --carryover-snapshot) or from \
             an archival node's data dir.",
            hex::encode(&h[..8]), height
        ));
    }

    // 2. Clear + genesis state, one batch.
    let mut batch = rocksdb::WriteBatch::default();
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
    *shielded.write() = ShieldedPool::new();

    // 3. Connect the best valid chain from genesis.
    let mut log = Vec::new();
    let connected_blocks = match resolve_best_chain(dag, store, shielded, genesis, None, &mut log, &[])? {
        Resolution::Connected { outcome, .. } => outcome.connected.len(),
        Resolution::Unchanged => {
            if !log.is_empty() {
                persist_unchanged(dag, store, None, &log, &[])?;
            }
            0
        }
    };
    store.put_meta(REBUILD_PENDING_META, &[0u8]).map_err(|e| e.to_string())?;
    warn!("chain state rebuilt from block bodies: {} row(s) cleared, {} consensus mark(s) re-derived, \
           {} block(s) connected", cleared_rows, drop.len(), connected_blocks);
    Ok(RebuildReport { cleared_rows, cleared_marks: drop.len(), connected_blocks })
}

// ── Operator recovery: invalidateblock / reconsiderblock (DAG-6) ─────────────

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

/// Shared tail of the two operator calls: move the applied chain to the best
/// valid block, persisting `log` marks and removing `cleared` marks in the
/// same batch, then refresh the mempool and the RPC-visible state.
#[allow(clippy::too_many_arguments)]
fn apply_operator_override(
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &Arc<storage::Storage>,
    mempool: &Arc<mempool::Mempool>,
    node_state: &Arc<RwLock<rpc::NodeState>>,
    tip_tx: Option<&broadcast::Sender<tip::TipChanged>>,
    shielded: &Arc<RwLock<ShieldedPool>>,
    mut log: Vec<(BlockHash, String)>,
    cleared: &[BlockHash],
    affected: usize,
) -> Result<ChainOverride, String> {
    let applied = store.get_meta("tip_hash").map_err(|e| e.to_string())?
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
        .ok_or("no applied tip pointer")?;
    let (mut rolled_back, mut connected) = (0usize, 0usize);
    match resolve_best_chain(dag, store, shielded, applied, None, &mut log, cleared)? {
        Resolution::Unchanged => persist_unchanged(dag, store, None, &log, cleared)?,
        Resolution::Connected { plan, outcome } => {
            rolled_back = outcome.rolled_back();
            connected = outcome.connected.len();
            warn!("operator override: rolled back {} block(s), connected {} (lca={})",
                rolled_back, connected, hex::encode(&plan.lca[..8]));
            let next_height = mempool::admission::next_block_height(&dag.read());
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
        let has_body = |h: &[u8; 32]| store.get_block(h).ok().flatten().is_some();
        let d = dag.read();
        if let Some(best) = d.best_bodied_tip(has_body) {
            if let Some(data) = d.get_block_data(&best).cloned() {
                let parents = d.template_parents(core::MAX_PARENTS, has_body);
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

/// Operator `invalidateblock` (Bitcoin Core's `InvalidateBlock`): disqualify
/// `hash` and every block whose selected-parent chain passes through it,
/// persist the mark (`invalid_block/<hash>`, reason
/// [`OPERATOR_INVALIDATE_REASON`]) and move the applied chain to the best
/// valid block that remains — rolling back past `hash` if it was applied —
/// in one atomic batch. Survives restarts; undone by [`reconsider_block`].
#[allow(clippy::too_many_arguments)]
pub fn invalidate_block(
    hash: BlockHash,
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &Arc<storage::Storage>,
    mempool: &Arc<mempool::Mempool>,
    node_state: &Arc<RwLock<rpc::NodeState>>,
    tip_tx: Option<&broadcast::Sender<tip::TipChanged>>,
    shielded: &Arc<RwLock<ShieldedPool>>,
) -> Result<ChainOverride, String> {
    let _guard = store.acceptance_lock();
    ensure_invalid_set_loaded(dag, store);
    if !dag.read().has_block(&hash) {
        return Err(format!("block {} not found", hex::encode(hash)));
    }
    if dag.read().store.genesis == Some(hash) {
        return Err("the genesis block cannot be invalidated".into());
    }
    let marked = dag.write().mark_invalid(hash);
    warn!("invalidateblock {}: {} block(s) disqualified by the operator",
        hex::encode(&hash[..8]), marked.len());
    let log = vec![(hash, OPERATOR_INVALIDATE_REASON.to_string())];
    let res = apply_operator_override(dag, store, mempool, node_state, tip_tx, shielded, log, &[], marked.len());
    if res.is_err() {
        // Nothing was committed: restore the in-memory set from disk.
        if let Ok(roots) = store.load_invalid_blocks() {
            dag.write().reset_invalid(roots);
        }
    }
    res
}

/// Operator `reconsiderblock` (Bitcoin Core's `ReconsiderBlock`): remove every
/// persisted disqualification whose root is `hash`, a selected-chain ancestor
/// of `hash` or a block whose selected chain passes through `hash`, recompute
/// the disqualified set from the remaining marks, and move the applied chain
/// to the best valid block (which re-validates the reconsidered chain in its
/// own context: a block that really is invalid is disqualified again, with a
/// consensus reason), all in one atomic batch.
#[allow(clippy::too_many_arguments)]
pub fn reconsider_block(
    hash: BlockHash,
    dag: &Arc<RwLock<consensus::GhostDAG>>,
    store: &Arc<storage::Storage>,
    mempool: &Arc<mempool::Mempool>,
    node_state: &Arc<RwLock<rpc::NodeState>>,
    tip_tx: Option<&broadcast::Sender<tip::TipChanged>>,
    shielded: &Arc<RwLock<ShieldedPool>>,
) -> Result<ChainOverride, String> {
    let _guard = store.acceptance_lock();
    ensure_invalid_set_loaded(dag, store);
    if !dag.read().has_block(&hash) {
        return Err(format!("block {} not found", hex::encode(hash)));
    }
    let roots = store.load_invalid_blocks().map_err(|e| e.to_string())?;
    let (cleared, kept): (Vec<BlockHash>, Vec<BlockHash>) = {
        let d = dag.read();
        roots.into_iter().partition(|r| {
            d.is_on_selected_chain_of(r, &hash) || d.is_on_selected_chain_of(&hash, r)
        })
    };
    let before = dag.read().invalid_count();
    dag.write().reset_invalid(kept);
    let affected = before.saturating_sub(dag.read().invalid_count());
    info!("reconsiderblock {}: {} mark(s) removed, {} block(s) re-qualified",
        hex::encode(&hash[..8]), cleared.len(), affected);
    let res = apply_operator_override(dag, store, mempool, node_state, tip_tx, shielded, Vec::new(), &cleared, affected);
    if res.is_err() {
        if let Ok(roots) = store.load_invalid_blocks() {
            dag.write().reset_invalid(roots);
        }
    }
    res
}

// ── Unified TX validation ────────────────────────────────────────────────────
// FIX #10: Single validation core used by all code paths.

/// Core input validation logic shared by all TX validation paths.
/// Resolves each input's UTXO (rejecting duplicate outpoints), then checks
/// every input script (pubkey hash vs prevout, hybrid signature — cached, see
/// `admission::verify_input_scripts`), value conservation and the consensus
/// minimum fee. All amounts are MoneyRange-checked (VAL-11).
pub fn validate_tx_inputs(
    tx:           &core::Transaction,
    utxo_lookup:  &dyn Fn(&[u8; 32], u32) -> Result<Option<core::TxOutput>, String>,
    mut spent_set: Option<&mut HashSet<([u8; 32], u32)>>,
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

    admission::verify_input_scripts(tx, &prevouts)?;

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
