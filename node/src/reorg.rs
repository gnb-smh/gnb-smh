//! Bloch-SIS Protocol — Reorg detection & execution (Sprint U.3).
//!
//! Pure functions that compute *what* a chain move looks like
//! (`compute_reorg_plan`, `compute_connect_plan`) and *perform* one atomically
//! against storage (`connect_plan`, used by the acceptance pipeline in
//! `accept.rs` for extensions AND reorgs, audit DAG-1/DAG-11) or against
//! storage + mempool (`execute_reorg`, the standalone U.3 entry point).
//!
//! (Historical note below: U.4 has since wired these primitives into the
//! node; `accept::accept_block` now drives every chain move through
//! `connect_plan`.)
//!
//! # Rationale for splitting U.3 / U.4
//!
//! `accept_block` is large (1100+ lines) and couples DAG insertion, storage
//! mutations, mempool updates, node-state locks, and RPC-visible metrics.
//! Introducing a reorg path inside it safely requires an end-to-end test
//! harness, which is U.4's scope. U.3 delivers the pieces that harness will
//! drive, with their own unit tests against mock DAG data and small fixture
//! blocks so the algorithms can be validated in isolation.
//!
//! # Audit reference
//!
//! Finding **C-1** — `accept_block` is forward-only, so a fork with higher
//! blue work silently leaves the UTXO state inconsistent. U.1 persisted undo
//! data; U.2 added `rollback_block`; U.3 adds reorg planning and execution;
//! U.4 will integrate and test end-to-end.

use std::collections::{HashMap, HashSet};

use crate::consensus::{BlockHash, GhostDAG, GhostdagData};
use crate::core::{Block, Transaction, TxOutput, UndoData, UndoEntry};
use crate::mempool::Mempool;
use crate::storage::Storage;

// ─────────────────────────────────────────────────────────────────────────────
// Deep reorgs: alert, never refuse (audit DAG-6)
// ─────────────────────────────────────────────────────────────────────────────
//
// There is NO reorg-depth limit. The old `MAX_REORG_DEPTH` (1,000 blocks) and
// the `finalized_height` gate compared a fork against THIS node's history, so
// two nodes holding the same blocks could end on different chains depending on
// the order the blocks arrived in (the audit's node X refused a 1,101-block
// reorg that node Z, fed the same blocks interleaved, followed). Like Bitcoin
// Core (no depth limit, no checkpoints), a node now always ends on the best
// valid chain of the blocks it holds. Bounded MERGING is enforced objectively
// by GhostDAG's merge depth after the hardening activation; operators recover
// from an unwanted chain with `invalidateblock` / `reconsiderblock`.
//
// Undo records are kept for every connected block (pruning removes bodies,
// never undo records), and a pruned body's rollback needs are recorded when it
// is pruned (`storage::PrunedBodyRecord`), so a reorg of any depth can be
// executed on a pruned node.

/// A committed chain move that rolled back more than this many selected-chain
/// blocks is logged at error level and counted
/// (`gnb_deep_reorgs_total`). Alert only: it never changes which chain the
/// node follows.
pub const DEEP_REORG_ALERT_DEPTH: u64 = crate::core::CHECKPOINT_DEPTH;

/// Marker of a connect that cannot run because blocks it must APPLY have no
/// stored body: a pruned node that reorganized away from blocks whose bodies
/// it had pruned, and now needs them again. The ingress re-fetches them
/// (`accept::missing_bodies_below`, `ingress::BlockIngress`); nothing is
/// written in the meantime.
pub const ERR_MISSING_BODIES: &str = "missing block bodies";

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

/// The steps needed to move the selected chain tip from one block to another.
///
/// `to_rollback` is ordered *tip-first*: the first element is the current
/// tip, the last element is the child of the LCA. Rolling back in this order
/// undoes each block's mutations cleanly because each `rollback_block` call
/// is self-contained (reads UndoData, replays in reverse).
///
/// `to_apply` is ordered *LCA-first*: the first element is the child of the
/// LCA on the new chain, the last element is the new tip. Applying in this
/// order mirrors how `accept_block` builds state forward.
///
/// Note: the LCA block itself appears in neither vector — it is the common
/// root that stays in place throughout the reorg.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReorgPlan {
    pub lca:         BlockHash,
    pub to_rollback: Vec<BlockHash>,
    pub to_apply:    Vec<BlockHash>,
}

/// Statistics returned by `execute_reorg`. Fed into logs / metrics by the
/// U.4 caller. All counts reflect successful operations only.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReorgOutcome {
    pub rolled_back:    usize,
    pub applied:        usize,
    pub txs_reinjected: usize,
    pub txs_discarded:  usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// LCA computation
// ─────────────────────────────────────────────────────────────────────────────

/// Walk the selected-parent chain from `start` up to genesis, collecting
/// every hash we visit. Used by `find_lca` to mark A's ancestors so we can
/// scan B's ancestors for the first intersection.
///
/// The walk terminates at genesis (selected_parent = None) or when a
/// referenced selected_parent is absent from the DAG — the latter should
/// never happen on a consistent store but we don't panic on it.
fn collect_selected_ancestors(
    dag: &GhostDAG,
    start: &BlockHash,
) -> HashSet<BlockHash> {
    let mut out = HashSet::new();
    let mut cur = Some(*start);
    while let Some(h) = cur {
        if !out.insert(h) {
            // Cycle (shouldn't happen on a DAG) — break to avoid infinite loop.
            break;
        }
        cur = match dag.get_block_data(&h) {
            Some(data) => data.selected_parent,
            None       => None,
        };
    }
    out
}

/// Find the lowest common ancestor of two blocks along their selected-parent
/// chains. Returns None if the two chains never intersect — this indicates
/// either a corrupted DAG or blocks from incompatible genesis, and the
/// caller should refuse to reorg.
///
/// Runtime: O(depth_a + depth_b) hash-map lookups; a deep reorg pays one
/// walk proportional to its depth.
pub fn find_lca(
    dag: &GhostDAG,
    a: &BlockHash,
    b: &BlockHash,
) -> Option<BlockHash> {
    if a == b { return Some(*a); }

    let a_ancestors = collect_selected_ancestors(dag, a);

    // Walk B's chain; first hit in A's ancestor set is the LCA.
    let mut cur = Some(*b);
    while let Some(h) = cur {
        if a_ancestors.contains(&h) {
            return Some(h);
        }
        cur = dag.get_block_data(&h).and_then(|d| d.selected_parent);
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Plan computation
// ─────────────────────────────────────────────────────────────────────────────

/// Build the path from `start` along selected_parent, EXCLUSIVE of `stop`.
/// Returns tip-first ordering: path[0] == start.
///
/// Returns None if `stop` is not reachable from `start` via selected_parent
/// (caller should have verified via find_lca first; this is defensive).
fn selected_path_to(
    dag: &GhostDAG,
    start: &BlockHash,
    stop: &BlockHash,
) -> Option<Vec<BlockHash>> {
    let mut path = Vec::new();
    let mut cur = Some(*start);
    while let Some(h) = cur {
        if h == *stop { return Some(path); }
        path.push(h);
        cur = dag.get_block_data(&h).and_then(|d| d.selected_parent);
    }
    None  // walked to genesis without hitting stop
}

/// Compute the rollback + apply sequence needed to move the selected chain
/// tip from `old_tip` to `new_tip`.
///
/// Returns `None` — meaning no reorg is needed / possible — in these cases:
///
///   * `old_tip == new_tip`: trivially a no-op.
///   * `old_tip` is an ancestor of `new_tip`: this is a forward extension,
///     not a reorg. Caller should use the normal accept_block path.
///   * `new_tip` is an ancestor of `old_tip`: this would be going backwards
///     and shouldn't be a valid state transition; we refuse.
///   * The two chains share no common ancestor: DAG corruption or
///     cross-genesis blocks.
///
/// A returned plan has both `to_rollback` and `to_apply` non-empty.
pub fn compute_reorg_plan(
    dag: &GhostDAG,
    old_tip: &BlockHash,
    new_tip: &BlockHash,
) -> Option<ReorgPlan> {
    if old_tip == new_tip { return None; }

    let lca = find_lca(dag, old_tip, new_tip)?;

    // Forward extension case: the "old tip" IS the LCA, meaning new_tip is
    // a descendant. That's just a chain extension, not a reorg.
    if lca == *old_tip { return None; }

    // Backward case: new_tip is an ancestor of old_tip. Refuse.
    if lca == *new_tip { return None; }

    // Build the two paths. Each excludes the LCA itself — the LCA stays in
    // place, its state is untouched by the reorg.
    let to_rollback = selected_path_to(dag, old_tip, &lca)?;
    let to_apply_reversed = selected_path_to(dag, new_tip, &lca)?;

    // to_apply_reversed is tip-first; we need LCA-first so the caller can
    // replay mutations in natural forward order.
    let mut to_apply = to_apply_reversed;
    to_apply.reverse();

    // Defensive: both paths must be non-empty by construction (we excluded
    // equal-tip and ancestor cases above) but assert rather than silently
    // emit a malformed plan.
    if to_rollback.is_empty() || to_apply.is_empty() {
        return None;
    }

    Some(ReorgPlan { lca, to_rollback, to_apply })
}

/// Compute the plan that moves the APPLIED selected chain from `from` (the
/// currently applied tip) to `to` (the new best valid block). Unlike
/// [`compute_reorg_plan`] this also covers pure forward moves: `to_rollback`
/// is empty when `from` is an ancestor of `to` on the selected-parent chain
/// (an ordinary extension, possibly of several blocks), and pure backward
/// moves: `to_apply` is empty when `to` is a selected-chain ancestor of
/// `from`. A backward move only happens when applied blocks were
/// disqualified: by an operator `invalidateblock` (DAG-6), or by the start-up
/// hardening recheck of blocks a pre-upgrade binary stored and applied (the
/// applied tip is otherwise valid and heavier than its ancestors). Returns
/// `None` when `from == to` or when the chains share no ancestor.
pub fn compute_connect_plan(
    dag: &GhostDAG,
    from: &BlockHash,
    to: &BlockHash,
) -> Option<ReorgPlan> {
    if from == to { return None; }
    let lca = find_lca(dag, from, to)?;
    let to_rollback = selected_path_to(dag, from, &lca)?;
    let mut to_apply = selected_path_to(dag, to, &lca)?;
    to_apply.reverse();
    if to_apply.is_empty() && to_rollback.is_empty() { return None; }
    Some(ReorgPlan { lca, to_rollback, to_apply })
}

// ─────────────────────────────────────────────────────────────────────────────
// Block UTXO mutation (forward apply)
// ─────────────────────────────────────────────────────────────────────────────

/// Apply a block's UTXO / tx_index / coinbase_info mutations forward,
/// capturing UndoData so the block can later be rolled back.
///
/// Mirrors the mutation loop of `accept_block` in main.rs deliberately —
/// same ordering (put_tx_index → put_utxo per output → put_coinbase_info OR
/// capture-and-delete per input) so the UndoData captured here is shaped
/// identically to what `accept_block` produces for forward accepts. This
/// symmetry is load-bearing: `rollback_block` (U.2) works on either.
///
/// Non-atomic (one write at a time): the acceptance pipeline uses the
/// batched twin (`apply_block_utxo_mutations_batched` via `connect_plan`);
/// this one remains for tests and tools.
///
/// # Errors
///
/// SECURITY (Legacy L-1): every write below used to be `let _ =` — a RocksDB
/// error (disk full, I/O failure, corruption) was silently swallowed, and
/// the function returned `Ok(())` as if the block had been fully applied
/// even when some of its UTXO mutations never happened. Since this function
/// is NOT atomic across its own writes (that is Legacy M-7, tracked
/// separately — see `ReorgBatch` below for the atomic alternative used by
/// reorg), silently continuing past a failed write already risked a
/// half-applied block; silently RETURNING SUCCESS on top of that hid the
/// failure from every caller, including the startup/health checks that
/// might otherwise have caught it. Every write now propagates its error
/// immediately (fail closed, stop at the first failure) instead of being
/// discarded.
pub fn apply_block_utxo_mutations(
    store: &Storage,
    block: &Block,
) -> Result<(), String> {
    let block_hash = block.block_hash();
    let mut undo = UndoData::new(block_hash, block.height);

    for tx in &block.transactions {
        let txid = tx.txid();

        // VAL-2: capture every row this block replaces (restored on rollback).
        // Reads fail the apply, never read as "absent" (re-audit B1-T12).
        let read = |what: &str, e: crate::storage::StorageError| format!("apply_block_utxo_mutations: {what} failed: {e}");
        if let Some((prev_block, prev_height)) = store.get_tx_location(&txid).map_err(|e| read("get_tx_location", e))? {
            undo.overwritten.tx_index.push((txid, prev_block, prev_height));
        }
        store.put_tx_index(&txid, &block_hash, block.height)
            .map_err(|e| format!("apply_block_utxo_mutations: put_tx_index failed for {}: {}",
                hex::encode(txid), e))?;
        undo.tx_index_keys.push(txid);

        for (j, out) in tx.outputs.iter().enumerate() {
            if let Some(prev) = store.get_utxo(&txid, j as u32).map_err(|e| read("get_utxo", e))? {
                undo.overwritten.utxos.push(UndoEntry { prev_txid: txid, prev_index: j as u32, output: prev });
            }
            store.put_utxo(&txid, j as u32, out)
                .map_err(|e| format!("apply_block_utxo_mutations: put_utxo failed for {}:{}: {}",
                    hex::encode(txid), j, e))?;
            undo.created_utxo_keys.push((txid, j as u32));
        }

        if tx.is_coinbase() {
            if let Some(prev_height) = store.get_coinbase_height(&txid).map_err(|e| read("get_coinbase_height", e))? {
                undo.overwritten.coinbase_heights.push((txid, prev_height));
            }
            store.put_coinbase_info(&txid, block.height)
                .map_err(|e| format!("apply_block_utxo_mutations: put_coinbase_info failed for {}: {}",
                    hex::encode(txid), e))?;
            undo.coinbase_txids.push(txid);
        } else {
            for inp in &tx.inputs {
                // Capture BEFORE delete so rollback can restore the pre-spend output.
                if let Some(output) = store.get_utxo(&inp.prev_txid, inp.prev_index).map_err(|e| read("get_utxo", e))? {
                    undo.spent_utxos.push(UndoEntry {
                        prev_txid:  inp.prev_txid,
                        prev_index: inp.prev_index,
                        output,
                    });
                }
                store.delete_utxo(&inp.prev_txid, inp.prev_index)
                    .map_err(|e| format!("apply_block_utxo_mutations: delete_utxo failed for {}:{}: {}",
                        hex::encode(inp.prev_txid), inp.prev_index, e))?;
            }
        }
    }

    store.put_undo_data(&block_hash, &undo)
        .map_err(|e| format!("apply_block_utxo_mutations: put_undo_data failed: {}", e))?;
    // NET-12: the block joined the connected chain (holder aggregates already
    // followed the put/delete calls above).
    store.note_block_connected(&block_hash, block.transactions.len() as u64)
        .map_err(|e| format!("apply_block_utxo_mutations: aggregates: {}", e))
}

// ─────────────────────────────────────────────────────────────────────────────
// Atomic reorg batch (crash-consistency hardening)
// ─────────────────────────────────────────────────────────────────────────────
//
// SECURITY: `execute_reorg` previously mutated storage in place, block by
// block (rollback_block / apply_block_utxo_mutations). A crash — or a
// mid-reorg error such as a missing undo record — left the chain state
// half-applied: some blocks rolled back, others not, with no recovery marker.
// `ReorgBatch` stages EVERY chain-switch mutation into a single RocksDB
// `WriteBatch` and commits it with one `db.write()` call, which RocksDB
// guarantees is atomic. Any error before the commit simply drops the batch:
// storage is byte-identical to the pre-reorg state.
//
// Because staged writes are not visible to reads until commit, the batch
// keeps an in-memory overlay for the two column families the reorg logic
// reads back during staging (UTXO set + coinbase index). Reads go
// overlay-first, then fall through to the committed DB — this is what lets
// `validate_fork_block_state` (audit H1) see the *incrementally-reorged*
// state while nothing has hit disk yet.
//
// Key/value layouts and CF names below MIRROR src/storage/mod.rs exactly
// (utxo_key / addr_utxo_key / put_tx_index / put_coinbase_info /
// put_undo_data and the CF_* constants — those are private to the storage
// module, so they are replicated here byte-for-byte). The
// `reorg_batch_column_families_exist` unit test guards against CF renames;
// `reorg.rs` staging drifting from `storage.rs` layouts would be caught by
// the state-equality integration tests (tests/reorg_hardening.rs).

const CF_UTXO:            &str = "utxo";
const CF_ADDR_UTXO:       &str = "addr_utxo";
const CF_COINBASE:        &str = "coinbase";
const CF_TX_INDEX:        &str = "tx_index";
const CF_UNDO:            &str = "undo";
const CF_ADDR_TX_HISTORY: &str = "addr_tx_history";

/// UTXO key: `[txid][4B index LE]` — mirrors `storage::utxo_key`.
fn utxo_key(txid: &[u8; 32], index: u32) -> Vec<u8> {
    let mut k = txid.to_vec();
    k.extend_from_slice(&index.to_le_bytes());
    k
}

/// Address-index key: `[script_pubkey][txid][4B index LE]` — mirrors
/// `storage::addr_utxo_key` (which receives the full script_pubkey).
fn addr_utxo_key(script_pubkey: &[u8], txid: &[u8; 32], index: u32) -> Vec<u8> {
    // Capacity hint only; saturating is exact for every real script.
    let mut k = Vec::with_capacity(script_pubkey.len().saturating_add(36));
    k.extend_from_slice(script_pubkey);
    k.extend_from_slice(txid);
    k.extend_from_slice(&index.to_le_bytes());
    k
}

/// bincode encoding identical to the storage module's private `encode`.
fn bc_encode<T: serde::Serialize>(v: &T) -> Result<Vec<u8>, String> {
    bincode::serde::encode_to_vec(v, bincode::config::standard())
        .map_err(|e| format!("reorg batch: encode failed: {}", e))
}

/// A failure to READ a [`UtxoView`] (an I/O error, a corrupted or
/// undecodable row, an inconsistent index): the view could not answer, so
/// nothing can be concluded about the block being validated (re-audit
/// B1-T12). It is never a consensus verdict and is never persisted; the
/// connect fails as a storage failure (`ConnectError::Failed`), nothing is
/// written, and the block can be validated again once the row reads.
/// Bitcoin Core makes the same distinction: a coins-database read error goes
/// to `CCoinsViewErrorCatcher`, which aborts the node, and only genuine
/// consensus failures are cached as `BLOCK_FAILED_VALID`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewError(pub String);

impl std::fmt::Display for ViewError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "storage read failed: {}", self.0)
    }
}

/// Read-only view of a UTXO set plus its coinbase-height index. Implemented by
/// the committed [`Storage`] and by the staging overlay of an in-progress
/// connect, so the SAME validation code checks a block against the live tip
/// state (extension) or against the incrementally re-organised state (reorg).
/// `Ok(None)` means "absent"; a read that fails is a [`ViewError`], never
/// "absent".
pub trait UtxoView {
    fn view_utxo(&self, txid: &[u8; 32], index: u32) -> Result<Option<TxOutput>, ViewError>;
    /// The HEADER height of the block whose coinbase `txid` is (the
    /// coinbase-height row), `None` for any other txid.
    fn view_coinbase_height(&self, txid: &[u8; 32]) -> Result<Option<u64>, ViewError>;
    /// The block that holds `txid` on the applied chain (the tx-index row,
    /// written by every connect together with the transaction's coins).
    fn view_tx_block(&self, txid: &[u8; 32]) -> Result<Option<BlockHash>, ViewError>;
    /// The HEADER height of the block that holds `txid` on the applied chain
    /// (the same tx-index row), for relative timelocks below the activation
    /// (`blockval::check_policy_spends`, `accept::MaturityRule`). `Ok(None)`
    /// when unknown.
    fn view_tx_height(&self, txid: &[u8; 32]) -> Result<Option<u64>, ViewError>;
    /// The persisted GhostDAG record of `block` (blocks are persisted when
    /// accepted, before any later block is connected on them).
    fn view_dag_data(&self, block: &BlockHash) -> Result<Option<GhostdagData>, ViewError>;
}

impl UtxoView for Storage {
    fn view_utxo(&self, txid: &[u8; 32], index: u32) -> Result<Option<TxOutput>, ViewError> {
        self.get_utxo(txid, index).map_err(|e| ViewError(e.to_string()))
    }
    fn view_coinbase_height(&self, txid: &[u8; 32]) -> Result<Option<u64>, ViewError> {
        self.get_coinbase_height(txid).map_err(|e| ViewError(e.to_string()))
    }
    fn view_tx_block(&self, txid: &[u8; 32]) -> Result<Option<BlockHash>, ViewError> {
        self.get_tx_location(txid).map(|l| l.map(|(b, _)| b)).map_err(|e| ViewError(e.to_string()))
    }
    fn view_dag_data(&self, block: &BlockHash) -> Result<Option<GhostdagData>, ViewError> {
        self.get_dag_data(block).map_err(|e| ViewError(e.to_string()))
    }
    fn view_tx_height(&self, txid: &[u8; 32]) -> Result<Option<u64>, ViewError> {
        self.get_tx_location(txid).map(|o| o.map(|(_, h)| h)).map_err(|e| ViewError(e.to_string()))
    }
}

impl<'a> UtxoView for ReorgBatch<'a> {
    fn view_utxo(&self, txid: &[u8; 32], index: u32) -> Result<Option<TxOutput>, ViewError> {
        self.get_utxo(txid, index).map_err(ViewError)
    }
    fn view_coinbase_height(&self, txid: &[u8; 32]) -> Result<Option<u64>, ViewError> {
        self.get_coinbase_height(txid).map_err(ViewError)
    }
    fn view_tx_block(&self, txid: &[u8; 32]) -> Result<Option<BlockHash>, ViewError> {
        self.get_tx_location(txid).map(|l| l.map(|(b, _)| b)).map_err(ViewError)
    }
    fn view_dag_data(&self, block: &BlockHash) -> Result<Option<GhostdagData>, ViewError> {
        // DAG records are never staged by a connect plan: every block of the
        // plan was persisted when it was accepted, except the trigger, whose
        // record is staged in the same batch and never read here (maturity
        // reads the DAG records of a block's PARENTS and of the blocks whose
        // coinbases it spends, all accepted before it; no block spends its
        // own coinbase from the activation, VAL-3).
        self.store.get_dag_data(block).map_err(|e| ViewError(e.to_string()))
    }
    fn view_tx_height(&self, txid: &[u8; 32]) -> Result<Option<u64>, ViewError> {
        self.get_tx_location(txid).map(|o| o.map(|(_, h)| h)).map_err(ViewError)
    }
}

/// All chain-switch mutations staged for one atomic commit, with an overlay
/// so staged UTXO / coinbase state is readable before the commit.
///
/// NET-12: the explorer aggregates (holder balances, supply tiers, chain
/// totals and per-block cumulative totals — `storage::aggregates`) are
/// updated in the SAME batch, so they follow every connect and disconnect
/// atomically. The aggregate lock is held from creation to commit/drop.
struct ReorgBatch<'a> {
    store: &'a Storage,
    batch: rocksdb::WriteBatch,
    /// utxo_key → Some(output) if staged-created/restored, None if staged-deleted.
    utxo_overlay: HashMap<Vec<u8>, Option<TxOutput>>,
    /// coinbase txid → Some(height) if staged-put, None if staged-deleted.
    coinbase_overlay: HashMap<[u8; 32], Option<u64>>,
    /// txid → Some((block, height)) if staged-put, None if staged-deleted
    /// (read back when a block replaces a tx-index row, audit VAL-2).
    tx_index_overlay: HashMap<[u8; 32], Option<([u8; 32], u64)>>,
    /// NET-12: net holder changes of every staged UTXO mutation.
    holders: crate::storage::aggregates::HolderDeltas,
    /// NET-12: running connected-chain totals.
    chain: crate::storage::aggregates::ChainTotals,
    /// NET-12: running XOR of the connected blocks' hashes (`agg/conn`).
    conn: [u8; 32],
    _agg: parking_lot::MutexGuard<'a, ()>,
}

impl<'a> ReorgBatch<'a> {
    fn new(store: &'a Storage) -> Result<Self, String> {
        let agg = store.agg_lock();
        let chain = store.chain_totals().map_err(|e| format!("reorg batch: aggregates: {}", e))?;
        let conn = store.conn_fingerprint().map_err(|e| format!("reorg batch: aggregates: {}", e))?.unwrap_or_default();
        Ok(ReorgBatch {
            store,
            batch: rocksdb::WriteBatch::default(),
            utxo_overlay: HashMap::new(),
            coinbase_overlay: HashMap::new(),
            tx_index_overlay: HashMap::new(),
            holders: Default::default(),
            chain,
            conn,
            _agg: agg,
        })
    }

    fn cf(&self, name: &str) -> Result<&'a rocksdb::ColumnFamily, String> {
        self.store.db().cf_handle(name)
            .ok_or_else(|| format!("reorg batch: missing column family '{}'", name))
    }

    /// Overlay-aware UTXO read: staged state wins, otherwise committed DB.
    fn get_utxo(&self, txid: &[u8; 32], index: u32) -> Result<Option<TxOutput>, String> {
        if let Some(staged) = self.utxo_overlay.get(&utxo_key(txid, index)) {
            return Ok(staged.clone());
        }
        self.store.get_utxo(txid, index)
            .map_err(|e| format!("reorg batch: get_utxo failed: {}", e))
    }

    /// Overlay-aware coinbase-height read.
    fn get_coinbase_height(&self, txid: &[u8; 32]) -> Result<Option<u64>, String> {
        if let Some(staged) = self.coinbase_overlay.get(txid) {
            return Ok(*staged);
        }
        self.store.get_coinbase_height(txid)
            .map_err(|e| format!("reorg batch: get_coinbase_height failed: {}", e))
    }

    /// Overlay-aware tx-index read.
    fn get_tx_location(&self, txid: &[u8; 32]) -> Result<Option<([u8; 32], u64)>, String> {
        if let Some(staged) = self.tx_index_overlay.get(txid) {
            return Ok(*staged);
        }
        self.store.get_tx_location(txid)
            .map_err(|e| format!("reorg batch: get_tx_location failed: {}", e))
    }

    /// Mirrors `Storage::put_utxo` (CF_UTXO row + CF_ADDR_UTXO index row).
    fn put_utxo(&mut self, txid: &[u8; 32], index: u32, output: &TxOutput) -> Result<(), String> {
        if let Some(prev) = self.get_utxo(txid, index)? {
            self.holders.remove(&prev);
        }
        self.holders.add(output);
        let key = utxo_key(txid, index);
        let cf_u = self.cf(CF_UTXO)?;
        self.batch.put_cf(cf_u, &key, &bc_encode(output)?);
        if output.script_pubkey.len() >= 20 {
            let cf_ai = self.cf(CF_ADDR_UTXO)?;
            self.batch.put_cf(cf_ai, &addr_utxo_key(&output.script_pubkey, txid, index), b"");
        }
        self.utxo_overlay.insert(key, Some(output.clone()));
        Ok(())
    }

    /// Mirrors `Storage::delete_utxo`, but resolves the output for the
    /// address-index cleanup through the OVERLAY — a UTXO restored earlier in
    /// this same batch is not on disk yet.
    fn delete_utxo(&mut self, txid: &[u8; 32], index: u32) -> Result<(), String> {
        if let Some(output) = self.get_utxo(txid, index)? {
            if output.script_pubkey.len() >= 20 {
                let cf_ai = self.cf(CF_ADDR_UTXO)?;
                self.batch.delete_cf(cf_ai, &addr_utxo_key(&output.script_pubkey, txid, index));
            }
            self.holders.remove(&output);
        }
        let key = utxo_key(txid, index);
        let cf_u = self.cf(CF_UTXO)?;
        self.batch.delete_cf(cf_u, &key);
        self.utxo_overlay.insert(key, None);
        Ok(())
    }

    /// Mirrors `Storage::put_coinbase_info` (txid → height LE).
    fn put_coinbase_info(&mut self, txid: &[u8; 32], height: u64) -> Result<(), String> {
        let cf = self.cf(CF_COINBASE)?;
        self.batch.put_cf(cf, txid, &height.to_le_bytes());
        self.coinbase_overlay.insert(*txid, Some(height));
        Ok(())
    }

    fn delete_coinbase_info(&mut self, txid: &[u8; 32]) -> Result<(), String> {
        let cf = self.cf(CF_COINBASE)?;
        self.batch.delete_cf(cf, txid);
        self.coinbase_overlay.insert(*txid, None);
        Ok(())
    }

    /// Mirrors `Storage::put_tx_index` (txid → [32B block_hash][8B height LE]).
    fn put_tx_index(&mut self, txid: &[u8; 32], block_hash: &[u8; 32], height: u64) -> Result<(), String> {
        let cf = self.cf(CF_TX_INDEX)?;
        let mut val = Vec::with_capacity(40);
        val.extend_from_slice(block_hash);
        val.extend_from_slice(&height.to_le_bytes());
        self.batch.put_cf(cf, txid, &val);
        self.tx_index_overlay.insert(*txid, Some((*block_hash, height)));
        Ok(())
    }

    fn delete_tx_index(&mut self, txid: &[u8; 32]) -> Result<(), String> {
        let cf = self.cf(CF_TX_INDEX)?;
        self.batch.delete_cf(cf, txid);
        self.tx_index_overlay.insert(*txid, None);
        Ok(())
    }

    /// Mirrors `Storage::put_undo_data` (`UndoData::to_bytes`: the legacy
    /// encoding plus the VAL-2 extension when the block replaced a row).
    fn put_undo_data(&mut self, block_hash: &[u8; 32], data: &UndoData) -> Result<(), String> {
        let encoded = data.to_bytes().map_err(|e| format!("reorg batch: {}", e))?;
        let cf = self.cf(CF_UNDO)?;
        self.batch.put_cf(cf, block_hash, &encoded);
        Ok(())
    }

    fn delete_undo_data(&mut self, block_hash: &[u8; 32]) -> Result<(), String> {
        let cf = self.cf(CF_UNDO)?;
        self.batch.delete_cf(cf, block_hash);
        Ok(())
    }

    /// Mirrors `Storage::stage_delete_pruned_body_record`.
    fn delete_pruned_record(&mut self, block_hash: &[u8; 32]) -> Result<(), String> {
        self.store.stage_delete_pruned_body_record(&mut self.batch, block_hash)
            .map_err(|e| format!("reorg batch: {}", e))
    }

    /// Stage deletion of one addr_tx_history row (key precomputed by the
    /// caller via `storage::indexer::make_key`).
    fn delete_addr_history_key(&mut self, key: &[u8]) -> Result<(), String> {
        let cf = self.cf(CF_ADDR_TX_HISTORY)?;
        self.batch.delete_cf(cf, key);
        Ok(())
    }

    /// NET-12: a block left (`delta = -1`) or joined (`+1`) the connected
    /// chain with `txs` transactions; stage the running totals and the
    /// block's cumulative record.
    fn note_chain_move(&mut self, hash: &[u8; 32], txs: u64, joined: bool) -> Result<(), String> {
        if joined {
            self.chain.blocks += 1;
            self.chain.txs = self.chain.txs.saturating_add(txs);
        } else {
            self.chain.blocks = self.chain.blocks.saturating_sub(1);
            self.chain.txs = self.chain.txs.saturating_sub(txs);
        }
        crate::storage::aggregates::xor_into(&mut self.conn, hash);
        let rec = if joined { Some(self.chain) } else { None };
        self.store.stage_chain_cumulative(&mut self.batch, hash, rec)
            .map_err(|e| format!("reorg batch: aggregates: {}", e))
    }

    /// Commit every staged mutation atomically. Consumes the batch; RocksDB
    /// applies a WriteBatch all-or-nothing. The NET-12 aggregates are staged
    /// last, from the committed values plus this batch's net changes.
    fn commit(mut self) -> Result<(), String> {
        self.store.stage_holder_deltas(&mut self.batch, &self.holders)
            .map_err(|e| format!("reorg batch: aggregates: {}", e))?;
        self.store.stage_chain_totals(&mut self.batch, self.chain, &self.conn)
            .map_err(|e| format!("reorg batch: aggregates: {}", e))?;
        let ReorgBatch { store, batch, _agg, .. } = self;
        let r = store.db().write(batch)
            .map_err(|e| format!("reorg batch: atomic commit failed: {}", e));
        drop(_agg);
        r
    }
}

/// Load the undo record a rollback of `block_hash` needs.
fn undo_for_rollback(store: &Storage, block_hash: &BlockHash) -> Result<UndoData, String> {
    store.get_undo_data(block_hash)
        .map_err(|e| format!("rollback: get_undo_data failed: {}", e))?
        .ok_or_else(|| format!(
            "rollback: no undo data for block {}..",
            hex::encode(&block_hash[..4]),
        ))
}

/// Steps 2-6 of a rollback, shared by the bodied and the pruned path: they
/// need only the undo record. Restore spent UTXOs, delete created UTXOs,
/// coinbase-info and tx_index rows, then the undo record itself.
fn rollback_undo_effects(
    batch: &mut ReorgBatch,
    undo: &UndoData,
    block_hash: &BlockHash,
) -> Result<(), String> {
    // 2. Restore spent UTXOs (also restages the CF_ADDR_UTXO row).
    for entry in &undo.spent_utxos {
        batch.put_utxo(&entry.prev_txid, entry.prev_index, &entry.output)?;
    }

    // 3. Delete created UTXOs (also cleans the CF_ADDR_UTXO row), then
    //    restore the coins those outputs overwrote (audit VAL-2: a node that
    //    applied and disconnected the block must end with the UTXO set of a
    //    node that never applied it).
    for (txid, idx) in &undo.created_utxo_keys {
        batch.delete_utxo(txid, *idx)?;
    }
    for entry in &undo.overwritten.utxos {
        batch.put_utxo(&entry.prev_txid, entry.prev_index, &entry.output)?;
    }

    // 4. Delete coinbase-info rows, restore the ones they replaced.
    for txid in &undo.coinbase_txids {
        batch.delete_coinbase_info(txid)?;
    }
    for (txid, height) in &undo.overwritten.coinbase_heights {
        batch.put_coinbase_info(txid, *height)?;
    }

    // 5. Delete tx_index rows, restore the ones they replaced.
    for txid in &undo.tx_index_keys {
        batch.delete_tx_index(txid)?;
    }
    for (txid, prev_block, prev_height) in &undo.overwritten.tx_index {
        batch.put_tx_index(txid, prev_block, *prev_height)?;
    }

    // 6. Delete the undo record itself.
    batch.delete_undo_data(block_hash)
}

/// Stage the full rollback of one block into the batch — the batched twin of
/// `Storage::rollback_block` (U.2), preserving its exact mutation set and
/// ordering: addr_tx_history unindex, restore spent UTXOs, delete created
/// UTXOs, delete coinbase infos, delete tx_index rows, delete the undo record.
fn rollback_block_batched(
    batch: &mut ReorgBatch,
    block: &Block,
    block_hash: &BlockHash,
) -> Result<(), String> {
    let undo = undo_for_rollback(batch.store, block_hash)?;

    // Spent-output lookup from UndoData — same rationale as
    // `Storage::unindex_tx_addresses` (deterministic accept-time capture).
    let spent_lookup: HashMap<([u8; 32], u32), TxOutput> = undo.spent_utxos.iter()
        .map(|e| ((e.prev_txid, e.prev_index), e.output.clone()))
        .collect();

    // 1. Un-index addr_tx_history: exactly the keys `stage_chain_index`
    //    wrote (`indexer::addr_history_keys`, the single definition).
    for key in crate::storage::indexer::addr_history_keys(block, &spent_lookup) {
        batch.delete_addr_history_key(&key)?;
    }

    rollback_undo_effects(batch, &undo, block_hash)?;

    // 7. Selected-chain height/timestamp index rows (DAG-12).
    batch.store.stage_chain_unindex(&mut batch.batch, block)
        .map_err(|e| format!("rollback: chain unindex failed: {}", e))?;

    // 8. NET-12: the block leaves the connected chain.
    batch.note_chain_move(block_hash, undo.tx_index_keys.len() as u64, false)?;

    Ok(())
}

/// Stage the rollback of a selected-chain block whose BODY HAS BEEN PRUNED
/// (audit DAG-6: no reorg-depth limit, so a deep reorg on a pruned node
/// disconnects pruned blocks). The UTXO effects, coinbase, tx-index and
/// chain-index rows come from the undo record alone; the address-history keys
/// from the `PrunedBodyRecord` written when the body was pruned. Bodies pruned
/// by an older release have no such record: their address-history rows (a
/// non-consensus explorer index) are left in place and a warning is logged;
/// the UTXO set is still restored exactly.
fn rollback_pruned_block_batched(
    batch: &mut ReorgBatch,
    block_hash: &BlockHash,
) -> Result<(), String> {
    let undo = undo_for_rollback(batch.store, block_hash)?;
    match batch.store.get_pruned_body_record(block_hash)
        .map_err(|e| format!("rollback: pruned-body record unreadable: {}", e))?
    {
        Some(rec) => {
            for key in &rec.addr_history_keys {
                batch.delete_addr_history_key(key)?;
            }
            batch.delete_pruned_record(block_hash)?;
        }
        None => log::warn!(
            "rollback: block {}.. (h={}) was pruned without a rollback record; its \
             address-history rows stay (UTXO state is restored exactly from the undo record)",
            hex::encode(&block_hash[..4]), undo.block_height
        ),
    }
    rollback_undo_effects(batch, &undo, block_hash)?;
    batch.store.stage_chain_unindex_at(&mut batch.batch, undo.block_height, block_hash)
        .map_err(|e| format!("rollback: chain unindex failed: {}", e))?;
    // NET-12: the block leaves the connected chain, exactly as on the bodied
    // path (its transaction count is the undo record's tx-index key count).
    batch.note_chain_move(block_hash, undo.tx_index_keys.len() as u64, false)
}

/// Stage the forward application of one fork block — the batched twin of
/// `apply_block_utxo_mutations`, identical mutation set and ordering so the
/// staged UndoData is byte-compatible with what the direct path produces.
fn apply_block_utxo_mutations_batched(
    batch: &mut ReorgBatch,
    block: &Block,
) -> Result<(), String> {
    let block_hash = block.block_hash();
    let mut undo = UndoData::new(block_hash, block.height);
    // DAG-12: the selected-chain indexes (height → hash, height → timestamp,
    // address history) are written when the block JOINS the selected chain,
    // in this same batch. Input rows resolve through the undo capture so they
    // match what `rollback_block_batched` later deletes.
    let stage_index = |batch: &mut ReorgBatch, undo: &UndoData| -> Result<(), String> {
        let spent: HashMap<([u8; 32], u32), TxOutput> = undo.spent_utxos.iter()
            .map(|e| ((e.prev_txid, e.prev_index), e.output.clone()))
            .collect();
        batch.store.stage_chain_index(&mut batch.batch, block, &spent)
            .map_err(|e| format!("apply: chain index failed: {}", e))
    };

    for tx in &block.transactions {
        let txid = tx.txid();

        // VAL-2: capture every row this block replaces, through the overlay
        // (an earlier block of the same plan may have staged it). Restored by
        // `rollback_block_batched` after the block's own rows are deleted.
        if let Some((prev_block, prev_height)) = batch.get_tx_location(&txid)? {
            undo.overwritten.tx_index.push((txid, prev_block, prev_height));
        }
        batch.put_tx_index(&txid, &block_hash, block.height)?;
        undo.tx_index_keys.push(txid);

        for (j, out) in tx.outputs.iter().enumerate() {
            if let Some(prev) = batch.get_utxo(&txid, j as u32)? {
                undo.overwritten.utxos.push(UndoEntry { prev_txid: txid, prev_index: j as u32, output: prev });
            }
            batch.put_utxo(&txid, j as u32, out)?;
            undo.created_utxo_keys.push((txid, j as u32));
        }

        if tx.is_coinbase() {
            if let Some(prev_height) = batch.get_coinbase_height(&txid)? {
                undo.overwritten.coinbase_heights.push((txid, prev_height));
            }
            batch.put_coinbase_info(&txid, block.height)?;
            undo.coinbase_txids.push(txid);
        } else {
            for inp in &tx.inputs {
                // Capture BEFORE delete (through the overlay — the pre-spend
                // output may have been staged by an earlier fork block). A
                // read error fails the apply (re-audit B1-T12): swallowing it
                // wrote an undo record without the spent coin, which a
                // rollback could never restore.
                if let Some(output) = batch.get_utxo(&inp.prev_txid, inp.prev_index)? {
                    undo.spent_utxos.push(UndoEntry {
                        prev_txid:  inp.prev_txid,
                        prev_index: inp.prev_index,
                        output,
                    });
                }
                batch.delete_utxo(&inp.prev_txid, inp.prev_index)?;
            }
        }
    }

    stage_index(batch, &undo)?;
    batch.put_undo_data(&block_hash, &undo)?;
    // NET-12: the block joins the connected chain.
    batch.note_chain_move(&block_hash, block.transactions.len() as u64, true)
}

/// SECURITY (audit H1): re-validate a fork block's transactions against the
/// *incrementally-reorged* UTXO state before applying it during a reorg.
///
/// Signatures are state-independent and were already verified at accept time,
/// so we re-check only the rules that differ between the accept-time
/// (main-chain) view and the fork's own context: input existence, no
/// double-spend, value conservation, and coinbase maturity. Without this, a
/// fork-loser block that spends an output which only ever existed on the main
/// chain — or that double-spends — would be applied unvalidated and mint coins
/// from nothing when the fork wins.
///
/// Reads go through the [`ReorgBatch`] overlay so the "incrementally-reorged"
/// state is visible even though nothing has been committed to disk yet.
pub fn validate_fork_block_state(batch: &dyn UtxoView, block: &Block) -> Result<(), ValidationFailure> {
    // Outputs created earlier in THIS block (outpoint -> value) so a later tx
    // can spend an earlier one; coinbase outputs are tracked separately because
    // they are immature to spend within the same block.
    let mut created: HashMap<([u8; 32], u32), u64> = HashMap::new();
    let mut created_coinbase: HashSet<([u8; 32], u32)> = HashSet::new();
    let mut spent: HashSet<([u8; 32], u32)> = HashSet::new();

    for tx in &block.transactions {
        let txid = tx.txid();
        if !tx.is_coinbase() {
            let mut in_sum: u64 = 0;
            for inp in &tx.inputs {
                let op = (inp.prev_txid, inp.prev_index);
                if !spent.insert(op) {
                    return Err(format!("double-spend of {}:{} within fork block",
                        hex::encode(&op.0[..4]), op.1).into());
                }
                let val = if let Some(v) = created.get(&op) {
                    if created_coinbase.contains(&op) {
                        return Err(format!("spends immature same-block coinbase {}:{}",
                            hex::encode(&op.0[..4]), op.1).into());
                    }
                    *v
                } else {
                    match batch.view_utxo(&inp.prev_txid, inp.prev_index) {
                        Ok(Some(out)) => out.value,
                        Ok(None) => return Err(format!("input {}:{} absent from reorged UTXO set",
                            hex::encode(&op.0[..4]), op.1).into()),
                        Err(e) => return Err(e.into()),
                    }
                };
                in_sum = in_sum.saturating_add(val);
            }
            let out_sum: u64 = tx.outputs.iter().map(|o| o.value).sum();
            if in_sum < out_sum {
                return Err(format!("value violation: inputs {} < outputs {}", in_sum, out_sum).into());
            }
            // The connect path's own maturity rule (re-audit B1-T14):
            // header heights below the activation, selected-chain depth
            // from it.
            let spend_dag_height = || crate::accept::block_dag_height(batch, block);
            let rule = if crate::core::block_rules::rules_active_at(
                block.height, crate::core::activation::hardening_activation_height(),
            ) {
                crate::accept::MaturityRule::SelectedChainDepth(&spend_dag_height)
            } else {
                crate::accept::MaturityRule::HeaderHeights(block.height)
            };
            crate::accept::check_coinbase_maturity_in_view(tx, batch, rule)??;
        }
        for (j, out) in tx.outputs.iter().enumerate() {
            let op = (txid, j as u32);
            created.insert(op, out.value);
            if tx.is_coinbase() { created_coinbase.insert(op); }
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Mempool reinject (with validation)
// ─────────────────────────────────────────────────────────────────────────────

/// Re-admit the non-coinbase transactions of disconnected blocks to the
/// mempool after a committed chain switch. Returns (reinjected, discarded).
///
/// Audit MEM-7 fix: re-injected transactions used to skip the maturity and
/// minimum-fee checks applied at normal admission, so a reorg to a lower
/// height could re-admit immature coinbase spends (or fee-less txs) that then
/// poisoned every block template. They now go through the SAME admission
/// function as gossip and RPC (`mempool::admission::admit`), evaluated at the
/// new tip: size, standardness (dust, MoneyRange, script limits), duplicate,
/// conflicts, UTXO presence, coinbase maturity at `next_block_height`, the
/// version rule and policy at `next_block_height`, consensus minimum fee and
/// relay fee. The witness standardness step is skipped, and so is the
/// signature step below the hardening activation (`check_signatures =
/// false`): every one of these transactions was signature-checked when the
/// disconnected block was connected, and below the activation every version
/// uses sighash v2 at every height. At/after the activation the input scripts
/// ARE verified again (normally a verified-signature cache hit): a version-3
/// transaction mined below the activation was checked against the v2 digest
/// only. `next_block_height` is the node's next template height after the
/// move (`Mempool::next_height`), never the new tip's header height + 1.
pub fn reinject_disconnected(
    store: &Storage,
    mempool: &Mempool,
    txs: Vec<Transaction>,
    next_block_height: u64,
) -> (usize, usize) {
    let policy = crate::mempool::admission::AdmissionPolicy::reinjection(next_block_height);
    let mut reinjected: usize = 0;
    let mut discarded: usize = 0;
    for tx in txs {
        match crate::mempool::admission::admit(store, mempool, tx, &policy) {
            Ok(_)  => reinjected = reinjected.saturating_add(1),
            Err(_) => discarded = discarded.saturating_add(1),
        }
    }
    (reinjected, discarded)
}

// ─────────────────────────────────────────────────────────────────────────────
// Atomic connect (extension or reorg) — audit DAG-1 / DAG-11
// ─────────────────────────────────────────────────────────────────────────────

/// Why a [`connect_plan`] did not commit. In every case NOTHING was written:
/// the staged batch is dropped. (There is no policy refusal: no reorg-depth
/// limit, audit DAG-6.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectError {
    /// `block` (at header height `height`) is invalid in its own selected-
    /// chain context. Deterministic and permanent: every node evaluating the
    /// same block in the same context reaches the same verdict.
    Invalid { block: BlockHash, height: u64, reason: String },
    /// Storage / missing-data failure. Transient from the caller's view.
    Failed(String),
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectError::Invalid { height, reason, .. } =>
                write!(f, "reorg aborted: fork block h={} invalid: {}", height, reason),
            ConnectError::Failed(m) => write!(f, "{}", m),
        }
    }
}

/// What a committed [`connect_plan`] changed.
#[derive(Debug, Clone, Default)]
pub struct ConnectOutcome {
    /// Blocks removed from the selected chain, tip-first, whose bodies were
    /// available (their transactions can be re-admitted to the mempool).
    pub disconnected: Vec<Block>,
    /// Blocks removed from the selected chain whose bodies had been pruned
    /// (rolled back from their undo records; nothing to re-admit), tip-first.
    pub disconnected_pruned: Vec<BlockHash>,
    /// Blocks added to the selected chain, LCA-first (last = new tip).
    pub connected: Vec<Block>,
}

impl ConnectOutcome {
    /// The non-coinbase transactions of the disconnected blocks in the order
    /// they must be re-admitted to the mempool: OLDEST disconnected block
    /// first, block order inside each block (Bitcoin Core's
    /// `DisconnectedBlockTransactions`). A child confirmed one block after its
    /// parent therefore comes back after the parent, as an in-pool chain
    /// (MEM-6); `disconnected` itself is tip-first, and re-admitting in that
    /// order refused the child with "missing inputs" and lost it.
    pub fn disconnected_txs_oldest_first(&self) -> Vec<Transaction> {
        self.disconnected.iter().rev()
            .flat_map(|b| b.transactions.iter().filter(|t| !t.is_coinbase()).cloned())
            .collect()
    }

    /// Number of selected-chain blocks the move rolled back.
    pub fn rolled_back(&self) -> usize {
        self.disconnected.len() + self.disconnected_pruned.len()
    }
}

/// Why a [`ConnectHooks::validate`] call did not pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationFailure {
    /// The block is invalid in its own selected-chain context: a verdict
    /// ([`ConnectError::Invalid`]).
    Invalid(String),
    /// The view could not be read ([`ViewError`]): NO verdict. The connect
    /// fails as [`ConnectError::Failed`] (nothing written, nothing marked;
    /// re-audit B1-T12).
    Storage(String),
}

impl From<String> for ValidationFailure {
    fn from(reason: String) -> Self {
        ValidationFailure::Invalid(reason)
    }
}

impl From<ViewError> for ValidationFailure {
    fn from(e: ViewError) -> Self {
        ValidationFailure::Storage(e.0)
    }
}

/// Hooks the caller plugs into [`connect_plan`].
pub struct ConnectHooks<'h> {
    /// Validate one block against the staged view of ITS OWN selected-chain
    /// context (every earlier block of the plan already staged).
    /// `Err(Invalid)` marks the block invalid (see [`ConnectError::Invalid`]);
    /// `Err(Storage)` is a read failure and fails the connect without any
    /// verdict ([`ConnectError::Failed`]).
    pub validate: &'h dyn Fn(&dyn UtxoView, &Block) -> Result<(), ValidationFailure>,
    /// Extra writes folded into the SAME batch right before the commit (DAG
    /// record of the arriving block, tip pointer, invalid marks, ...).
    pub stage_extra: &'h dyn Fn(&Storage, &mut rocksdb::WriteBatch) -> Result<(), String>,
}

/// Move the applied selected chain along `plan` in ONE atomic RocksDB batch.
///
/// `plan.to_rollback` may be empty (a forward extension) and so may
/// `plan.to_apply` (a pure rollback after an operator `invalidateblock`).
/// There is no depth limit (audit DAG-6): a rolled-back block whose body was
/// pruned is disconnected from its undo record. Every block of
/// `plan.to_apply` is validated by `hooks.validate` against the
/// incrementally-staged state before it is staged, so a block is only ever
/// applied in its own context. All UTXO effects, undo records, chain indexes
/// and the caller's extra writes land together or not at all (DAG-11): a crash
/// leaves either the complete old state or the complete new state.
pub fn connect_plan(
    store: &Storage,
    plan: &ReorgPlan,
    hooks: &ConnectHooks,
) -> Result<ConnectOutcome, ConnectError> {
    // A block to APPLY needs its body. A pruned node that reorganized away
    // from blocks it had pruned lacks theirs: report that up front, before
    // staging anything (the ingress re-fetches the bodies, DAG-6).
    let mut missing = 0usize;
    let mut first_missing = None;
    for h in &plan.to_apply {
        if !store.has_block_body(h).map_err(|e| ConnectError::Failed(e.to_string()))? {
            missing += 1;
            first_missing.get_or_insert(*h);
        }
    }
    if let Some(first) = first_missing {
        return Err(ConnectError::Failed(format!(
            "{}: {} block(s) to connect have no body (first {})",
            ERR_MISSING_BODIES, missing, hex::encode(&first[..8]),
        )));
    }

    let mut batch = ReorgBatch::new(store).map_err(ConnectError::Failed)?;
    let mut outcome = ConnectOutcome::default();

    for hash in &plan.to_rollback {
        let body = store.get_block(hash)
            .map_err(|e| ConnectError::Failed(format!(
                "execute_reorg: get_block on rollback target failed: {}", e)))?;
        match body {
            Some(block) => {
                rollback_block_batched(&mut batch, &block, hash)
                    .map_err(|e| ConnectError::Failed(format!(
                        "execute_reorg: rollback failed at h={} (reorg aborted, no storage mutation committed): {}",
                        block.height, e
                    )))?;
                outcome.disconnected.push(block);
            }
            None => {
                rollback_pruned_block_batched(&mut batch, hash)
                    .map_err(|e| ConnectError::Failed(format!(
                        "execute_reorg: rollback of pruned block {}.. failed (reorg aborted, no storage \
                         mutation committed): {}",
                        hex::encode(&hash[..4]), e
                    )))?;
                outcome.disconnected_pruned.push(*hash);
            }
        }
    }

    for hash in &plan.to_apply {
        let block = store.get_block(hash)
            .map_err(|e| ConnectError::Failed(format!(
                "execute_reorg: get_block on apply target failed: {}", e)))?
            .ok_or_else(|| ConnectError::Failed(
                "execute_reorg: block body missing for apply target".to_string()))?;
        match (hooks.validate)(&batch, &block) {
            Ok(()) => {}
            Err(ValidationFailure::Invalid(reason)) => {
                log::warn!(
                    "connect: block h={} {} failed in-context validation ({}); batch dropped, storage untouched",
                    block.height, hex::encode(&hash[..8]), reason
                );
                return Err(ConnectError::Invalid { block: *hash, height: block.height, reason });
            }
            Err(ValidationFailure::Storage(m)) => {
                log::error!(
                    "connect: block h={} {} could not be validated, storage read failed ({}); no verdict, \
                     batch dropped, storage untouched",
                    block.height, hex::encode(&hash[..8]), m
                );
                return Err(ConnectError::Failed(format!(
                    "connect: block h={} {} could not be validated (storage read failed, no verdict): {}",
                    block.height, hex::encode(&hash[..8]), m)));
            }
        }
        apply_block_utxo_mutations_batched(&mut batch, &block)
            .map_err(|e| ConnectError::Failed(format!(
                "execute_reorg: batched apply failed at h={}: {}", block.height, e)))?;
        outcome.connected.push(block);
    }

    (hooks.stage_extra)(store, &mut batch.batch).map_err(ConnectError::Failed)?;
    batch.commit().map_err(ConnectError::Failed)?;

    // Deep-reorg alerting (policy that never changes the outcome).
    let depth = outcome.rolled_back() as u64;
    if depth > DEEP_REORG_ALERT_DEPTH {
        crate::metrics::inc_deep_reorg();
        log::error!(
            "DEEP REORG committed: rolled back {} selected-chain block(s) (alert depth {}; {} with \
             pruned bodies), applied {} (lca={}). The node follows the best valid chain at any depth; \
             if this chain is unwanted, inspect it and use `invalidateblock`.",
            depth, DEEP_REORG_ALERT_DEPTH, outcome.disconnected_pruned.len(),
            outcome.connected.len(), hex::encode(&plan.lca[..8]),
        );
    }
    Ok(outcome)
}

// ─────────────────────────────────────────────────────────────────────────────
// Execution
// ─────────────────────────────────────────────────────────────────────────────

/// Execute a reorg plan against storage + mempool.
///
/// # Phases
///
/// 1. **Rollback** each block in `plan.to_rollback` (tip-first). For each
///    rolled-back block, collect non-coinbase txs as reinject candidates.
/// 2. **Apply** each block in `plan.to_apply` (LCA-first). Each apply
///    captures fresh UndoData so the new chain is also reorg-capable.
/// 3. **Reinject** candidate txs into the mempool through the shared
///    admission function (`reinject_disconnected`, audit MEM-7): UTXO
///    presence, maturity and minimum fees at the new tip. Candidates are
///    re-admitted OLDEST disconnected block first, in block order
///    ([`ConnectOutcome::disconnected_txs_oldest_first`]), so a parent is
///    back in the pool before a child confirmed in a later block. Rejected
///    ones are counted as discarded.
///
/// Fork blocks are re-validated with the audit-H1 UTXO-state rules
/// (`validate_fork_block_state`). The acceptance pipeline does not call this
/// function: it calls [`connect_plan`] directly with the FULL in-context
/// block validator.
///
/// # Preconditions
///
/// * Every hash in `plan.to_rollback` has an undo record (every connected
///   block keeps one; pruning never removes it). Its body may have been
///   pruned: the rollback then works from the undo record and the
///   pruned-body record (audit DAG-6).
/// * Every hash in `plan.to_apply` has a persisted block body whose UTXO
///   mutations have NOT been applied yet. (This is true for blocks that
///   were inserted into the DAG as non-selected tips.)
///
/// # Failure mode
///
/// All chain-switch storage mutations (phases 1 + 2) are staged into a single
/// RocksDB `WriteBatch` and committed atomically. Any error before the commit
/// — a missing undo record, a missing body of a block to APPLY, or a fork
/// block failing H1 re-validation — drops the batch, so
/// storage stays byte-identical to the pre-reorg state. A crash mid-reorg
/// likewise leaves either the complete old state (commit not reached) or the
/// complete new state (commit durable); half-applied chain state is no
/// longer reachable. Mempool reinject (phase 3) runs only after the commit.
///
/// # Caller concerns (NOT handled here)
///
/// * Updating `selected_chain_tip` / `current_bits` meta keys — that's
///   U.4's plumbing.
/// * Locking the DAG / node_state — U.4 coordinates higher-level locks.
/// * RPC event emission — U.4 emits reorg events post-hoc from the outcome.
pub fn execute_reorg(
    store: &Storage,
    mempool: &Mempool,
    plan: &ReorgPlan,
) -> Result<ReorgOutcome, String> {
    // Sprint FF observability: record every attempt and surface the fork
    // depth before doing any work. Failures increment the failures counter —
    // that is the one to alert on.
    // S5: the depth histogram keeps the per-attempt distribution (the gauge
    // is last-value-only), and the explicit success counter makes the success
    // rate a direct series (invariant: attempts == success + failures).
    crate::metrics::inc_reorg_attempt();
    crate::metrics::set_fork_depth(plan.to_rollback.len() as i64);
    crate::metrics::observe_reorg_depth(plan.to_rollback.len() as f64);
    let result = execute_reorg_inner(store, mempool, plan);
    match &result {
        Ok(_)  => crate::metrics::inc_reorg_success(),
        Err(_) => crate::metrics::inc_reorg_failure(),
    }
    result
}

fn execute_reorg_inner(
    store: &Storage,
    mempool: &Mempool,
    plan: &ReorgPlan,
) -> Result<ReorgOutcome, String> {
    // Same staging and atomic commit as the acceptance
    // pipeline (`connect_plan`); this standalone entry point re-validates
    // fork blocks with the audit-H1 UTXO-state rules only. The acceptance
    // pipeline plugs the FULL in-context validator (signatures, fees,
    // coinbase value) into `connect_plan` instead.
    //
    // Shielded state: the acceptance pipeline (`accept::accept_block`)
    // disconnects/connects the shielded pool for exactly the blocks of the
    // committed plan (audit COH-2); this storage-only entry point does not
    // touch it.
    let validate = |view: &dyn UtxoView, block: &Block| validate_fork_block_state(view, block);
    let no_extra = |_: &Storage, _: &mut rocksdb::WriteBatch| -> Result<(), String> { Ok(()) };
    let hooks = ConnectHooks { validate: &validate, stage_extra: &no_extra };
    let outcome = connect_plan(store, plan, &hooks).map_err(|e| e.to_string())?;

    // Phase 3: re-admit the disconnected blocks' transactions through the
    // shared admission function, evaluated at the new tip (MEM-7), oldest
    // disconnected block first so parents precede their children (MEM-6).
    // Blocks rolled back from their undo records alone (pruned bodies,
    // DAG-6) have no transactions to re-admit.
    let candidates: Vec<Transaction> = outcome.disconnected_txs_oldest_first();
    // The next block's height: this storage-only entry point has no DAG, so
    // it uses the new tip's DAG height + 1 (its CF_DAG record) — the template
    // height when the new tip is the only tip — never the tip's HEADER height
    // + 1, which exceeds it when the tip merged a parent with a greater DAG
    // height (DAG-8). The acceptance pipeline passes the template height.
    // The new tip is the last connected block, or the LCA for a pure
    // rollback (DAG-6: compute_connect_plan plans backward moves).
    let new_tip = outcome.connected.last().map(|b| b.block_hash()).unwrap_or(plan.lca);
    let next_height = match store.get_dag_data(&new_tip) {
        Ok(Some(d)) => d.height.saturating_add(1),
        _ => outcome.connected.last().map(|b| b.height.saturating_add(1))
            .or_else(|| outcome.disconnected.last().map(|b| b.height))
            .unwrap_or(0),
    };
    if next_height != 0 {
        mempool.set_next_height(next_height);
    }
    let (txs_reinjected, txs_discarded) =
        reinject_disconnected(store, mempool, candidates, next_height);

    Ok(ReorgOutcome {
        rolled_back:    plan.to_rollback.len(),
        applied:        plan.to_apply.len(),
        txs_reinjected,
        txs_discarded,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Regression tests — depth cap + atomic batch.
//
// Broader reorg behavior (plans, H1 abort-restore, byte-exact symmetry) is
// covered by tests/sprint_u3_reorg.rs, tests/reorg_hardening.rs and
// tests/sprint_u4_reorg_e2e.rs, which now exercise the batch path end to end.
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod reorg_hardening_unit_tests {
    use super::*;
    use crate::core::{BlockHeader, TxInput};
    use tempfile::TempDir;

    fn mk_storage() -> (TempDir, Storage) {
        let tmp = TempDir::new().unwrap();
        let s = Storage::open(tmp.path()).unwrap();
        (tmp, s)
    }

    fn mk_output(addr_byte: u8, value: u64) -> TxOutput {
        TxOutput { value, script_pubkey: vec![addr_byte; 20] }
    }

    fn mk_block_at(height: u64, nonce_tag: u64, txs: Vec<Transaction>) -> Block {
        Block {
            header: BlockHeader {
                version:     1,
                parents:     vec![],
                merkle_root: crate::core::MerkleRoot::ZERO,
                timestamp:   1_700_000_000 + height,
                bits:        0x1d00ffff,
                nonce:       nonce_tag,
            },
            transactions: txs,
            blue_score: height,
            height,
            shielded_transactions: Vec::new(),
            powit: Default::default(),
        }
    }

    fn mk_coinbase(addr_byte: u8, value: u64, height: u64, tag: u8) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid:  [0u8; 32],
                prev_index: 0xffff_ffff,
                script_sig: format!("cb:{}:{}:{}", height, addr_byte, tag).into_bytes(),
                sequence:   0xffff_ffff,
            }],
            outputs: vec![mk_output(addr_byte, value)],
            locktime: 0,
        }
    }

    fn mk_spend_tx(prev_txid: [u8; 32], prev_index: u32, to_addr: u8, value: u64, tag: u8) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid,
                prev_index,
                script_sig: vec![0xde, 0xad, 0xbe, tag],
                sequence:   0xffff_ffff,
            }],
            outputs: vec![mk_output(to_addr, value)],
            locktime: 0,
        }
    }

    fn hash_of(i: u64) -> BlockHash {
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&i.to_le_bytes());
        h[31] = 0xFD; // avoid colliding with real fixture hashes
        h
    }

    /// The CF names ReorgBatch stages into must exist in the live schema —
    /// guards the mirrored constants against renames in src/storage/mod.rs.
    #[test]
    fn reorg_batch_column_families_exist() {
        let (_tmp, store) = mk_storage();
        for name in [CF_UTXO, CF_ADDR_UTXO, CF_COINBASE, CF_TX_INDEX, CF_UNDO, CF_ADDR_TX_HISTORY] {
            assert!(
                store.db().cf_handle(name).is_some(),
                "column family '{}' missing — reorg batch constants must mirror src/storage/mod.rs",
                name,
            );
        }
    }

    /// Legacy L-1 regression: every write inside `apply_block_utxo_mutations`
    /// must propagate ITS OWN error, not just the final `put_undo_data`
    /// call. A read-only-opened store rejects every mutating call
    /// deterministically, so `put_tx_index` (the FIRST write in the loop)
    /// fails before `put_undo_data` is ever reached. Under the old
    /// `let _ =`-everywhere code, EVERY earlier failure was silently
    /// swallowed and the function only ever surfaced `put_undo_data`'s own
    /// failure — so this error message would never mention `put_tx_index`.
    /// Reverting the fix makes this test fail (the message would only ever
    /// contain "put_undo_data failed", never "put_tx_index failed").
    #[test]
    fn apply_block_utxo_mutations_propagates_the_first_failing_write() {
        let tmp = TempDir::new().unwrap();
        let db_path = tmp.path().join("db");
        { let _ = Storage::open(&db_path).unwrap(); } // create the CFs once, then drop the handle
        let ro_store = Storage::open_read_only(&db_path).unwrap();

        let cb = mk_coinbase(0xAA, 1_000, 1, 0);
        let block = mk_block_at(1, 0, vec![cb]);

        let err = apply_block_utxo_mutations(&ro_store, &block)
            .expect_err("every write must fail against a read-only store");
        assert!(err.contains("put_tx_index failed"),
            "expected the FIRST failing write (put_tx_index) to be named in the error, got: {err}");
    }

    /// Audit DAG-6: there is no reorg-depth limit. A plan rolling back more
    /// than the old 1,000-block cap (now only the alert depth) is executed:
    /// here it proceeds to the rollback staging and fails only because the
    /// fixture blocks have no undo records — never with a depth refusal.
    /// (Replaces `reorg_depth_cap_refuses_plan_beyond_max_depth` and
    /// `reorg_depth_cap_allows_plan_at_exact_cap`, which pinned the cap.)
    #[test]
    fn plan_deeper_than_the_old_cap_is_not_refused() {
        let (_tmp, store) = mk_storage();
        let mempool = Mempool::new();
        let target = mk_block_at(1, 0x0E0E, vec![mk_coinbase(0xEE, 100, 1, 9)]);
        store.put_block_body(&target).unwrap();

        let plan = ReorgPlan {
            lca:         [0u8; 32],
            to_rollback: (0..=DEEP_REORG_ALERT_DEPTH).map(hash_of).collect(), // old cap + 1
            to_apply:    vec![target.block_hash()],
        };
        let err = execute_reorg(&store, &mempool, &plan).unwrap_err();
        assert!(!err.contains("depth"), "no depth refusal any more: {}", err);
        assert!(
            err.contains("no undo data"),
            "the deep plan must reach the rollback staging and fail on the missing fixtures: {}", err,
        );
    }

    /// A pure backward move (the new best block is a selected-chain ancestor
    /// of the applied tip — only reachable after an operator
    /// `invalidateblock`) is a rollback-only plan, executed atomically.
    #[test]
    fn rollback_only_plan_is_planned_and_executed() {
        let (_tmp, store) = mk_storage();
        let mempool = Mempool::new();

        let g = [0x10u8; 32];
        let a1 = mk_block_at(1, 0x0A01, vec![mk_coinbase(0xA1, 100, 1, 1)]);
        let a2 = mk_block_at(2, 0x0A02, vec![mk_coinbase(0xA2, 100, 2, 2)]);
        let (a1h, a2h) = (a1.block_hash(), a2.block_hash());
        let mut dag = GhostDAG::with_default_k();
        dag.add_genesis(g, 0);
        dag.add_block(a1h, vec![g], 1, 1).unwrap();
        dag.add_block(a2h, vec![a1h], 2, 1).unwrap();
        for b in [&a1, &a2] {
            store.put_block(b).unwrap();
            apply_block_utxo_mutations(&store, b).unwrap();
        }

        let plan = compute_connect_plan(&dag, &a2h, &a1h).expect("backward plan");
        assert_eq!(plan, ReorgPlan { lca: a1h, to_rollback: vec![a2h], to_apply: vec![] });
        assert_eq!(compute_connect_plan(&dag, &a2h, &g).unwrap().to_rollback, vec![a2h, a1h]);

        let out = execute_reorg(&store, &mempool, &plan).expect("rollback-only plan commits");
        assert_eq!((out.rolled_back, out.applied), (1, 0));
        let cb_a2 = a2.transactions[0].txid();
        assert!(store.get_utxo(&cb_a2, 0).unwrap().is_none(), "A2's output rolled back");
        assert!(store.get_undo_data(&a2h).unwrap().is_none());
        assert!(store.get_utxo(&a1.transactions[0].txid(), 0).unwrap().is_some(), "A1 stays applied");
    }

    /// Atomic-batch regression (crash-consistency): a reorg that fails MIDWAY
    /// through rollback (second rollback target has no undo record, e.g.
    /// pruned) must leave storage byte-identical to the pre-reorg state.
    ///
    /// Before the batch conversion, execute_reorg committed each
    /// rollback_block individually: the FIRST target (A2) was already rolled
    /// back on disk when the second (A1) failed, leaving a half-applied chain
    /// state — A2's coinbase UTXO deleted and its undo record gone. Both
    /// assertions below fail on that code.
    #[test]
    fn reorg_atomic_batch_no_partial_state_on_mid_rollback_failure() {
        let (_tmp, store) = mk_storage();
        let mempool = Mempool::new();

        // Established chain: A1 (h=1) ← A2 (h=2), both applied with undo data.
        let a1 = mk_block_at(1, 0x0A01, vec![mk_coinbase(0xA1, 100, 1, 1)]);
        let a2 = mk_block_at(2, 0x0A02, vec![mk_coinbase(0xA2, 100, 2, 2)]);
        let (a1h, a2h) = (a1.block_hash(), a2.block_hash());
        store.put_block(&a1).unwrap();
        apply_block_utxo_mutations(&store, &a1).unwrap();
        store.put_block(&a2).unwrap();
        apply_block_utxo_mutations(&store, &a2).unwrap();

        // Simulate a pruned/lost undo record for A1 — the SECOND rollback
        // target in tip-first order, so the failure hits mid-plan.
        store.delete_undo_data(&a1h).unwrap();

        // Fork target (content irrelevant; rollback fails before apply).
        let b1 = mk_block_at(1, 0x0B01, vec![mk_coinbase(0xB1, 100, 1, 3)]);
        let b1h = b1.block_hash();
        store.put_block(&b1).unwrap();

        let plan = ReorgPlan {
            lca:         [0u8; 32],
            to_rollback: vec![a2h, a1h], // tip-first
            to_apply:    vec![b1h],
        };

        let cb_a2_txid = a2.transactions[0].txid();
        let err = execute_reorg(&store, &mempool, &plan).unwrap_err();
        assert!(err.contains("no undo data"), "failure must be the missing undo record: {}", err);

        // Atomicity: A2's rollback was STAGED before the failure but must not
        // have reached disk — all-or-nothing.
        assert!(
            store.get_utxo(&cb_a2_txid, 0).unwrap().is_some(),
            "A2's coinbase UTXO must survive an aborted reorg (no partial rollback)",
        );
        assert!(
            store.get_undo_data(&a2h).unwrap().is_some(),
            "A2's undo record must survive an aborted reorg (no partial rollback)",
        );
        assert!(
            store.get_coinbase_height(&cb_a2_txid).unwrap().is_some(),
            "A2's coinbase-info row must survive an aborted reorg",
        );
        // And nothing of the fork leaked in.
        assert!(store.get_utxo(&b1.transactions[0].txid(), 0).unwrap().is_none());
    }

    /// Atomic-batch success path: after a committed reorg, ALL reorg keys are
    /// applied — old chain fully rolled back, every fork block fully applied
    /// (UTXOs, coinbase index, tx index, fresh undo records) — including a
    /// fork block that spends an output created by the PRECEDING fork block,
    /// which is only visible through the batch overlay while staging.
    #[test]
    fn reorg_atomic_batch_applies_all_keys_on_success() {
        let (_tmp, store) = mk_storage();
        let mempool = Mempool::new();

        // Seed a spendable outpoint U that exists independently of both forks.
        let u_txid = [0x55u8; 32];
        store.put_utxo(&u_txid, 0, &mk_output(0x99, 100)).unwrap();

        // Established chain: A1 applied.
        let a1 = mk_block_at(1, 0x0A01, vec![mk_coinbase(0xA1, 100, 1, 1)]);
        let a1h = a1.block_hash();
        store.put_block(&a1).unwrap();
        apply_block_utxo_mutations(&store, &a1).unwrap();

        // Fork: B1 = [cb_b1, tx1: U(100) → X(90)], B2 = [cb_b2, tx2: X(90) → Y(80)].
        let cb_b1 = mk_coinbase(0xB1, 100, 1, 2);
        let tx1   = mk_spend_tx(u_txid, 0, 0xB2, 90, 1);
        let x_txid = tx1.txid();
        let b1 = mk_block_at(1, 0x0B01, vec![cb_b1.clone(), tx1]);

        let cb_b2 = mk_coinbase(0xB3, 100, 2, 3);
        let tx2   = mk_spend_tx(x_txid, 0, 0xB4, 80, 2);
        let y_txid = tx2.txid();
        let b2 = mk_block_at(2, 0x0B02, vec![cb_b2.clone(), tx2.clone()]);

        let (b1h, b2h) = (b1.block_hash(), b2.block_hash());
        store.put_block(&b1).unwrap();
        store.put_block(&b2).unwrap();

        let plan = ReorgPlan {
            lca:         [0u8; 32],
            to_rollback: vec![a1h],
            to_apply:    vec![b1h, b2h],
        };
        let outcome = execute_reorg(&store, &mempool, &plan).expect("reorg must succeed");
        assert_eq!(outcome.rolled_back, 1);
        assert_eq!(outcome.applied, 2);

        // Old chain fully rolled back.
        let cb_a1_txid = a1.transactions[0].txid();
        assert!(store.get_utxo(&cb_a1_txid, 0).unwrap().is_none(), "A1 coinbase UTXO removed");
        assert!(store.get_undo_data(&a1h).unwrap().is_none(),      "A1 undo record removed");
        assert!(store.get_coinbase_height(&cb_a1_txid).unwrap().is_none(), "A1 coinbase info removed");

        // New chain fully applied.
        assert!(store.get_utxo(&cb_b1.txid(), 0).unwrap().is_some(), "B1 coinbase UTXO present");
        assert!(store.get_utxo(&cb_b2.txid(), 0).unwrap().is_some(), "B2 coinbase UTXO present");
        assert!(store.get_utxo(&u_txid, 0).unwrap().is_none(),       "U spent by B1");
        assert!(store.get_utxo(&x_txid, 0).unwrap().is_none(),       "X spent by B2 (intra-fork chain)");
        assert!(store.get_utxo(&y_txid, 0).unwrap().is_some(),       "Y (B2 output) present");
        assert!(store.get_undo_data(&b1h).unwrap().is_some(),        "B1 reorg-capable (undo present)");
        assert!(store.get_undo_data(&b2h).unwrap().is_some(),        "B2 reorg-capable (undo present)");
        assert_eq!(
            store.get_tx_location(&tx2.txid()).unwrap().map(|(h, _)| h),
            Some(b2h),
            "tx index points at the fork block",
        );
    }
}
