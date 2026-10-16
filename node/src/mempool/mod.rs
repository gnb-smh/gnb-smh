//! Bloch-SIS Protocol — Mempool
//!
//! FIX #5: In-memory transaction pool with basic validation.
//! Accepts transactions, deduplicates, evicts by fee rate.
//! Sprint N-min: per-tx size cap, intra-mempool double-spend detection.
//!
//! # Relay policy (audit MEM-6; node-local, no consensus change)
//!
//! The full policy is specified in `docs/MEMPOOL.md`. In short:
//!
//! * **Chains of unconfirmed transactions.** A transaction may spend outputs
//!   of transactions that are still in the pool. Every entry records its
//!   in-pool `parents` and `children`. A transaction is refused when its
//!   ancestor set (itself included) would exceed [`MAX_ANCESTORS`] entries or
//!   [`MAX_PACKAGE_BYTES`] bytes, or when it would push any ancestor's
//!   descendant set past [`MAX_DESCENDANTS`] / [`MAX_PACKAGE_BYTES`]
//!   (Bitcoin Core's ancestor/descendant limits, 25 / 25).
//! * **Child pays for parent.** Block templates select whole ancestor
//!   packages by package fee rate (sum of fees over sum of sizes of the
//!   not-yet-selected ancestors plus the transaction), parents before
//!   children ([`select_packages`]).
//! * **Removal is closed under descendants.** Whenever a transaction leaves
//!   the pool for any reason other than being confirmed (conflict with a
//!   connected block, failed re-validation after a reorg, expiry, eviction,
//!   replacement, template self-check), every in-pool descendant leaves with
//!   it. A confirmed parent keeps its children (they now spend a UTXO).
//! * **Eviction** removes the entry with the lowest descendant score
//!   (`max(own fee rate, descendant-package fee rate)`) together with its
//!   descendants, and raises the rolling minimum fee rate.
//! * **Replacement: full-RBF** (no opt-in signalling) with the economic
//!   rules of BIP125 / Bitcoin Core: a transaction that conflicts with pool
//!   entries replaces them iff (rule 2) every unconfirmed input it spends was
//!   already spent by one of the transactions it conflicts with, (rule 3) it
//!   pays an absolute fee at least the sum of the fees of every transaction it
//!   evicts (direct conflicts and all their descendants), (rule 4) the
//!   difference pays [`INCREMENTAL_RELAY_FEE_RATE`] on the replacement's own
//!   size, (rule 5) it evicts at most [`MAX_REPLACEMENT_EVICTIONS`]
//!   transactions, (rule 6) its fee rate exceeds every direct conflict's, and
//!   it does not spend an output of a transaction it replaces. The raw
//!   [`Mempool::add`] stays first-seen (it never replaces); replacement goes
//!   through [`Mempool::add_with_replacement`], used by the shared admission
//!   function.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use parking_lot::{Mutex, RwLock};
use crate::core::{Transaction, TxOutput};

/// Shared standardness-and-admission function (audit MEM-1/4/5/7) used by
/// gossip, RPC `sendrawtransaction` and reorg re-injection.
pub mod admission;
/// Bounded pool of transactions whose parents are unknown (audit MEM-6).
pub mod orphanage;
/// Validated gossip relay of transactions (audit MEM-5 / NET-2 / NET-4).
pub mod relay;

/// Maximum number of pooled transactions (count cap; see also
/// [`MAX_MEMPOOL_BYTES`]).
pub const MAX_MEMPOOL_SIZE: usize = 50_000;

/// Audit MEM-3: a transaction that has not been mined within this many
/// seconds is dropped (Bitcoin Core's default `-mempoolexpiry` is 336 h; GnB
/// blocks are 20× faster, 72 h is ample).
pub const MEMPOOL_EXPIRY_SECS: u64 = 72 * 3600;

/// Audit MEM-6: half-life of the rolling minimum fee rate raised by
/// evictions (Bitcoin Core uses 12 h).
pub const ROLLING_FEE_HALFLIFE_SECS: u64 = 12 * 3600;

/// Audit MEM-6: incremental relay fee rate, sat/byte, added on top of an
/// evicted transaction's rate when it raises the rolling minimum, and the
/// minimum rate a replacement must pay for its own size on top of the fees
/// of everything it evicts (BIP125 rule 4).
pub const INCREMENTAL_RELAY_FEE_RATE: u64 = 1;

/// Audit MEM-5: bound on the recent-rejects filter (entries are 32-byte
/// wtxids; FIFO eviction). Cleared whenever the selected tip changes.
pub const MAX_RECENT_REJECTS: usize = 50_000;

/// Audit MEM-6: maximum number of in-pool ancestors of a transaction,
/// itself included (Bitcoin Core `-limitancestorcount`).
pub const MAX_ANCESTORS: usize = 25;
/// Audit MEM-6: maximum number of in-pool descendants of any transaction,
/// itself included (Bitcoin Core `-limitdescendantcount`).
pub const MAX_DESCENDANTS: usize = 25;
/// Audit MEM-6: maximum total size (bincode bytes, the consensus block-size
/// measure) of an ancestor or descendant package. Half a block, so a full
/// package always fits a template.
pub const MAX_PACKAGE_BYTES: usize = 500_000;
/// Audit MEM-6 (BIP125 rule 5): a replacement may evict at most this many
/// transactions (direct conflicts plus all their descendants).
pub const MAX_REPLACEMENT_EVICTIONS: usize = 100;

/// P0 memory bound (roadmap §3.4 / §1.4): total serialized bytes the mempool
/// will hold. The count cap alone allowed 50_000 × 400 KiB ≈ 20 GB worst case;
/// this caps actual memory. 300 MiB is a conservative default — it must be
/// tuned against real block sizes and load-tested (not yet done). Eviction
/// enforces BOTH this and MAX_MEMPOOL_SIZE.
pub const MAX_MEMPOOL_BYTES: usize = 300 * 1024 * 1024;

/// SECURITY (audit L2): minimum relay fee rate in satoshis per serialized byte.
/// Rejects free / dust-rate transactions that would otherwise let an actor with
/// spendable UTXOs flood the mempool and skew fee-estimation RPCs.
pub const MIN_RELAY_FEE_RATE: u64 = 1;
/// Fixed-point scale so fee-rate (fee/size) comparisons don't truncate to 0.
const FEE_RATE_SCALE: u128 = 1_000_000;

/// Sprint N-min: max serialized bytes per tx accepted into mempool.
/// 400 KB accommodates legitimate consolidation (~120 ML-DSA-65 inputs)
/// while rejecting pathological transactions that could exhaust memory.
/// Transport layer (libp2p gossipsub) caps at 4 MB; this is a tighter
/// application-level bound.
pub const MAX_TX_SIZE: usize = 400 * 1024;

/// One pooled transaction.
#[derive(Clone, Debug)]
pub struct MempoolEntry {
    pub tx:         Transaction,
    pub fee:        u64,
    pub added_at:   u64,
    /// Bincode size (`Transaction::actual_size`, the consensus block-size
    /// measure), cached.
    pub size:       usize,
    /// Canonical wire size (`to_wire_bytes(true)`, the unit of the consensus
    /// minimum fee), cached at admission so fee-rate estimates never
    /// re-encode the pool (B1-T21 review).
    pub wire_size:  usize,
    /// MEM-6: pooled transactions whose outputs this one spends.
    pub parents:    BTreeSet<[u8; 32]>,
    /// MEM-6: pooled transactions spending outputs of this one.
    pub children:   BTreeSet<[u8; 32]>,
}

/// P1 (roadmap §3): fixed-point fee-RATE key, `(fee * FEE_RATE_SCALE) / size`,
/// as an `Ord` newtype over `u128`. Ordering is ascending, so the lowest-rate
/// (eviction-target) tx is `btree.iter().next()` and the highest-rate
/// (block-template head) is `btree.iter().next_back()`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct FeeRateKey(u128);

#[inline]
fn fee_rate_key(fee: u64, size: usize) -> FeeRateKey {
    package_rate_key(fee as u128, size as u128)
}

#[inline]
fn package_rate_key(fee: u128, size: u128) -> FeeRateKey {
    FeeRateKey(fee.saturating_mul(FEE_RATE_SCALE) / size.max(1))
}

/// Behavior-neutral time seam (roadmap §4 DST prerequisite). Production reads
/// the wall clock (`SystemClock`), so node behavior is unchanged; the DST
/// harness can inject a deterministic clock via `Mempool::with_clock`. This
/// replaces the direct `SystemTime::now()` call that stamped `added_at`.
pub trait Clock: Send + Sync {
    /// Current time as Unix seconds.
    fn now_secs(&self) -> u64;
}

/// Real-wall-clock `Clock` used by `Mempool::new()`. Behavior-identical to the
/// pre-seam `SystemTime::now()` call.
pub struct SystemClock;
impl Clock for SystemClock {
    fn now_secs(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// Every index of the pool, guarded by ONE lock so the cross-index
/// invariants (see [`Mempool::debug_check_invariants`]) can never be observed
/// half-updated.
#[derive(Default)]
struct Inner {
    txs: HashMap<[u8; 32], MempoolEntry>,
    /// Sprint N-min: outpoint → the pooled tx spending it (O(1) intra-pool
    /// double-spend detection).
    spent: HashMap<([u8; 32], u32), [u8; 32]>,
    /// MEM-6: prev txid → pooled txs with an input referencing it. A tx's
    /// in-pool children are exactly `by_prev_txid[txid]`, also when the
    /// children entered the pool BEFORE the parent (reorg re-injection).
    by_prev_txid: HashMap<[u8; 32], BTreeSet<[u8; 32]>>,
    /// P1: own fee rate → txids.
    rate_index: BTreeMap<FeeRateKey, BTreeSet<[u8; 32]>>,
    /// MEM-6: descendant score → txids (eviction order).
    evict_index: BTreeMap<FeeRateKey, BTreeSet<[u8; 32]>>,
    evict_key: HashMap<[u8; 32], FeeRateKey>,
    /// Running Σ size over `txs`.
    total_bytes: usize,
}

fn index_insert(idx: &mut BTreeMap<FeeRateKey, BTreeSet<[u8; 32]>>, key: FeeRateKey, txid: [u8; 32]) {
    idx.entry(key).or_default().insert(txid);
}

fn index_remove(idx: &mut BTreeMap<FeeRateKey, BTreeSet<[u8; 32]>>, key: FeeRateKey, txid: &[u8; 32]) {
    if let Some(set) = idx.get_mut(&key) {
        set.remove(txid);
        if set.is_empty() {
            idx.remove(&key);
        }
    }
}

impl Inner {
    /// In-pool ancestors of a pooled tx (itself excluded).
    fn ancestors(&self, txid: &[u8; 32]) -> BTreeSet<[u8; 32]> {
        let start = self.txs.get(txid).map(|e| e.parents.iter().copied().collect()).unwrap_or_default();
        self.closure_up(start)
    }

    /// `start` plus all their in-pool ancestors.
    fn closure_up(&self, start: Vec<[u8; 32]>) -> BTreeSet<[u8; 32]> {
        let mut out = BTreeSet::new();
        let mut stack = start;
        while let Some(p) = stack.pop() {
            if let Some(e) = self.txs.get(&p) {
                if out.insert(p) {
                    stack.extend(e.parents.iter().copied());
                }
            }
        }
        out
    }

    /// In-pool descendants of a pooled tx (itself excluded).
    fn descendants(&self, txid: &[u8; 32]) -> BTreeSet<[u8; 32]> {
        let mut out = self.with_descendants(std::iter::once(*txid));
        out.remove(txid);
        out
    }

    /// The pooled members of `roots` plus all their in-pool descendants.
    fn with_descendants<I: IntoIterator<Item = [u8; 32]>>(&self, roots: I) -> BTreeSet<[u8; 32]> {
        let mut out = BTreeSet::new();
        let mut stack: Vec<[u8; 32]> = roots.into_iter().collect();
        while let Some(t) = stack.pop() {
            if let Some(e) = self.txs.get(&t) {
                if out.insert(t) {
                    stack.extend(e.children.iter().copied());
                }
            }
        }
        out
    }

    /// Pooled transactions whose outputs `tx` spends.
    fn pool_parents_of(&self, tx: &Transaction) -> BTreeSet<[u8; 32]> {
        tx.inputs.iter()
            .map(|i| i.prev_txid)
            .filter(|p| self.txs.contains_key(p))
            .collect()
    }

    /// MEM-6 eviction score: `max(own rate, descendant-package rate)`.
    fn desc_score(&self, txid: &[u8; 32]) -> Option<FeeRateKey> {
        let e = self.txs.get(txid)?;
        let own = fee_rate_key(e.fee, e.size);
        let (mut fee, mut size) = (e.fee as u128, e.size as u128);
        for d in self.descendants(txid) {
            if let Some(de) = self.txs.get(&d) {
                fee = fee.saturating_add(de.fee as u128);
                size = size.saturating_add(de.size as u128);
            }
        }
        Some(own.max(package_rate_key(fee, size)))
    }

    fn reindex_evict(&mut self, txid: &[u8; 32]) {
        if let Some(old) = self.evict_key.remove(txid) {
            index_remove(&mut self.evict_index, old, txid);
        }
        if let Some(k) = self.desc_score(txid) {
            index_insert(&mut self.evict_index, k, *txid);
            self.evict_key.insert(*txid, k);
        }
    }

    /// MEM-6: ancestor / descendant limits for a NEW tx of `size` bytes whose
    /// in-pool parents are `parents`, ignoring every tx in `excluded` (the
    /// set a replacement is about to evict).
    fn check_chain_limits(
        &self,
        parents: &BTreeSet<[u8; 32]>,
        size: usize,
        excluded: &BTreeSet<[u8; 32]>,
    ) -> Result<(), String> {
        let ancestors = self.closure_up(parents.iter().copied().collect());
        if ancestors.len().saturating_add(1) > MAX_ANCESTORS {
            return Err(format!(
                "too many unconfirmed ancestors: {} (max {} including the transaction)",
                ancestors.len(), MAX_ANCESTORS - 1));
        }
        let anc_bytes: usize = ancestors.iter()
            .filter_map(|a| self.txs.get(a).map(|e| e.size))
            .fold(size, |acc, s| acc.saturating_add(s));
        if anc_bytes > MAX_PACKAGE_BYTES {
            return Err(format!("ancestor package of {} bytes exceeds {}", anc_bytes, MAX_PACKAGE_BYTES));
        }
        for a in &ancestors {
            let mut desc = self.with_descendants(std::iter::once(*a));
            desc.retain(|d| !excluded.contains(d));
            let count = desc.len().saturating_add(1);
            if count > MAX_DESCENDANTS {
                return Err(format!(
                    "unconfirmed ancestor {} would have {} descendants (max {} including itself)",
                    hex::encode(&a[..8]), count, MAX_DESCENDANTS));
            }
            let bytes: usize = desc.iter()
                .filter_map(|d| self.txs.get(d).map(|e| e.size))
                .fold(size, |acc, s| acc.saturating_add(s));
            if bytes > MAX_PACKAGE_BYTES {
                return Err(format!(
                    "descendant package of ancestor {} would be {} bytes (max {})",
                    hex::encode(&a[..8]), bytes, MAX_PACKAGE_BYTES));
            }
        }
        Ok(())
    }

    /// MEM-6: the full-RBF rules for `tx` (fee `fee`, size `size`) against
    /// its `direct` conflicts. Returns every transaction the replacement
    /// evicts (direct conflicts and all their descendants).
    fn replacement_set(
        &self,
        tx: &Transaction,
        fee: u64,
        size: usize,
        direct: &BTreeSet<[u8; 32]>,
    ) -> Result<BTreeSet<[u8; 32]>, String> {
        let all = self.with_descendants(direct.iter().copied());
        // Rule 5: bounded eviction.
        if all.len() > MAX_REPLACEMENT_EVICTIONS {
            return Err(format!(
                "replacement would evict {} transactions (max {})", all.len(), MAX_REPLACEMENT_EVICTIONS));
        }
        // A replacement cannot spend an output of a transaction it evicts.
        if let Some(inp) = tx.inputs.iter().find(|i| all.contains(&i.prev_txid)) {
            return Err(format!(
                "replacement spends an output of {} which it would evict", hex::encode(&inp.prev_txid[..8])));
        }
        // Rule 2: no NEW unconfirmed inputs.
        let conflict_parents: HashSet<[u8; 32]> = direct.iter()
            .filter_map(|c| self.txs.get(c))
            .flat_map(|e| e.tx.inputs.iter().map(|i| i.prev_txid))
            .collect();
        if let Some(inp) = tx.inputs.iter()
            .find(|i| self.txs.contains_key(&i.prev_txid) && !conflict_parents.contains(&i.prev_txid))
        {
            return Err(format!(
                "replacement adds a new unconfirmed input from {}", hex::encode(&inp.prev_txid[..8])));
        }
        // Rule 6: a higher fee rate than every direct conflict.
        let new_rate = fee_rate_key(fee, size);
        for c in direct {
            if let Some(e) = self.txs.get(c) {
                if new_rate <= fee_rate_key(e.fee, e.size) {
                    return Err(format!(
                        "replacement fee rate does not exceed that of {}", hex::encode(&c[..8])));
                }
            }
        }
        // Rule 3: absolute fee at least the sum of everything evicted.
        let evicted_fees: u64 = all.iter()
            .filter_map(|t| self.txs.get(t).map(|e| e.fee))
            .fold(0u64, |a, f| a.saturating_add(f));
        if fee < evicted_fees {
            return Err(format!(
                "replacement fee {} below the {} sat paid by the {} transaction(s) it evicts",
                fee, evicted_fees, all.len()));
        }
        // Rule 4: the additional fee pays the incremental relay rate on the
        // replacement's own size.
        let extra_needed = (size as u64).saturating_mul(INCREMENTAL_RELAY_FEE_RATE);
        if fee - evicted_fees < extra_needed {
            return Err(format!(
                "replacement adds {} sat of fee, below the incremental relay fee of {} sat for {} bytes",
                fee - evicted_fees, extra_needed, size));
        }
        Ok(all)
    }

    /// Insert a new entry, linking it to its in-pool parents and children
    /// and re-scoring every ancestor.
    fn insert(&mut self, txid: [u8; 32], mut entry: MempoolEntry) {
        let parents = self.pool_parents_of(&entry.tx);
        let children: BTreeSet<[u8; 32]> = self.by_prev_txid.get(&txid).cloned().unwrap_or_default();
        for p in &parents {
            if let Some(pe) = self.txs.get_mut(p) {
                pe.children.insert(txid);
            }
        }
        for c in &children {
            if let Some(ce) = self.txs.get_mut(c) {
                ce.parents.insert(txid);
            }
        }
        for inp in &entry.tx.inputs {
            self.spent.insert((inp.prev_txid, inp.prev_index), txid);
            self.by_prev_txid.entry(inp.prev_txid).or_default().insert(txid);
        }
        entry.parents = parents;
        entry.children = children;
        index_insert(&mut self.rate_index, fee_rate_key(entry.fee, entry.size), txid);
        self.total_bytes = self.total_bytes.saturating_add(entry.size);
        self.txs.insert(txid, entry);
        self.reindex_evict(&txid);
        for a in self.ancestors(&txid) {
            self.reindex_evict(&a);
        }
    }

    /// Remove exactly the pooled members of `set` (NOT their descendants —
    /// callers that need closure pass `with_descendants(..)`), unlinking
    /// survivors and re-scoring their surviving ancestors.
    fn remove_set(&mut self, set: &BTreeSet<[u8; 32]>) -> Vec<([u8; 32], MempoolEntry)> {
        let mut affected: BTreeSet<[u8; 32]> = BTreeSet::new();
        for t in set {
            for a in self.ancestors(t) {
                if !set.contains(&a) {
                    affected.insert(a);
                }
            }
        }
        let mut removed = Vec::new();
        for t in set {
            let Some(e) = self.txs.remove(t) else { continue };
            self.total_bytes = self.total_bytes.saturating_sub(e.size);
            index_remove(&mut self.rate_index, fee_rate_key(e.fee, e.size), t);
            if let Some(k) = self.evict_key.remove(t) {
                index_remove(&mut self.evict_index, k, t);
            }
            for inp in &e.tx.inputs {
                let op = (inp.prev_txid, inp.prev_index);
                if self.spent.get(&op) == Some(t) {
                    self.spent.remove(&op);
                }
                if let Some(s) = self.by_prev_txid.get_mut(&inp.prev_txid) {
                    s.remove(t);
                    if s.is_empty() {
                        self.by_prev_txid.remove(&inp.prev_txid);
                    }
                }
            }
            for p in &e.parents {
                if let Some(pe) = self.txs.get_mut(p) {
                    pe.children.remove(t);
                }
            }
            for c in &e.children {
                if let Some(ce) = self.txs.get_mut(c) {
                    ce.parents.remove(t);
                }
            }
            removed.push((*t, e));
        }
        for a in affected {
            if self.txs.contains_key(&a) {
                self.reindex_evict(&a);
            }
        }
        removed
    }
}

/// What [`Mempool::add_with_replacement`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AddOutcome {
    pub txid: [u8; 32],
    /// Transactions evicted by the replacement (conflicts + descendants).
    pub replaced: Vec<[u8; 32]>,
    /// Transactions evicted to make room (size / count caps).
    pub evicted_for_space: usize,
}

pub struct Mempool {
    inner: RwLock<Inner>,
    /// P1 time seam (behavior-neutral): stamps `added_at`. Defaults to
    /// `SystemClock`.
    clock: Box<dyn Clock>,
    /// MEM-6: rolling minimum fee rate (fixed-point `FeeRateKey` units) and
    /// the time it was last raised. Raised on eviction, halves every
    /// `ROLLING_FEE_HALFLIFE_SECS`.
    rolling_min: Mutex<(u128, u64)>,
    /// MEM-5: recent-rejects filter (wtxid set + FIFO order).
    recent_rejects: Mutex<(HashSet<[u8; 32]>, VecDeque<[u8; 32]>)>,
    /// Generation of the recent-rejects filter: bumped (under the filter's
    /// lock) by every [`Self::clear_recent_rejects`], i.e. whenever the
    /// selected tip or the next block's height changes. A verdict computed in
    /// an older epoch is not remembered ([`Self::note_rejected_in_epoch`]).
    recent_rejects_epoch: AtomicU64,
    /// Header height of the next block the pool targets: the height of the
    /// node's own next template (`template::next_template_height`), the ONE
    /// height admission, post-connect eviction, re-injection, templates and
    /// `getdaginfo.next_block_height` (wallets) use. Written only under the
    /// store's acceptance lock, after every DAG change (`accept.rs`); `0` =
    /// not known yet (callers then compute it). `admission::admit` re-checks
    /// the height-dependent rules against it under the same lock.
    next_height: AtomicU64,
}

impl Mempool {
    pub fn new() -> Self {
        Self::with_clock(Box::new(SystemClock))
    }

    /// Construct a mempool with an injected clock (DST / deterministic tests).
    /// Behavior is identical to `new()` when passed a `SystemClock`.
    pub fn with_clock(clock: Box<dyn Clock>) -> Self {
        Self {
            inner: RwLock::new(Inner::default()),
            clock,
            rolling_min: Mutex::new((0, 0)),
            recent_rejects: Mutex::new((HashSet::new(), VecDeque::new())),
            recent_rejects_epoch: AtomicU64::new(0),
            next_height: AtomicU64::new(0),
        }
    }

    /// Header height of the next block the pool targets (`0` = unknown; see
    /// the field documentation).
    pub fn next_height(&self) -> u64 {
        self.next_height.load(Ordering::SeqCst)
    }

    /// Record the next block's height. Call under the store's acceptance lock
    /// (or before any concurrent acceptance, at start-up). Returns the
    /// previous value.
    pub fn set_next_height(&self, height: u64) -> u64 {
        self.next_height.swap(height, Ordering::SeqCst)
    }

    /// Current time from the injected clock (Unix seconds).
    pub fn now_secs(&self) -> u64 {
        self.clock.now_secs()
    }

    /// Add a transaction to the mempool, FIRST-SEEN: a transaction spending
    /// an outpoint already spent by a pooled tx is refused with
    /// [`MempoolError::Conflict`] (replacement is an admission decision, see
    /// [`Self::add_with_replacement`]). Returns `Ok(txid)`.
    ///
    /// Checks: structure, `MAX_TX_SIZE`, minimum relay fee rate, output
    /// overflow, duplicate, conflict, chain limits; then inserts (linking
    /// in-pool parents/children) and trims the pool to its count and byte
    /// caps by evicting the lowest descendant-score package.
    pub fn add(&self, tx: Transaction, fee: u64) -> Result<[u8; 32], MempoolError> {
        self.add_inner(tx, fee, false, false).map(|o| o.txid)
    }

    /// [`Self::add`] with full-RBF: conflicting pool transactions are
    /// replaced when the replacement rules hold (see the module docs),
    /// otherwise [`MempoolError::Replacement`].
    pub fn add_with_replacement(&self, tx: Transaction, fee: u64) -> Result<AddOutcome, MempoolError> {
        self.add_inner(tx, fee, true, false)
    }

    /// Audit B1-T20: re-admission of a transaction from a disconnected block
    /// (`reorg::reinject_disconnected`): [`Self::add_with_replacement`]
    /// WITHOUT trimming the pool to its caps (Bitcoin Core re-adds reorged
    /// transactions with `bypass_limits`, then trims once with
    /// `LimitMempoolSize`). The caller must call [`Self::trim_to_size`] after
    /// the batch; the pool can exceed its caps by at most the re-admitted
    /// transactions in between (`reorg::MAX_DISCONNECTED_TX_POOL_BYTES`).
    pub fn add_readmitted(&self, tx: Transaction, fee: u64) -> Result<AddOutcome, MempoolError> {
        self.add_inner(tx, fee, true, true)
    }

    /// True iff the pool holds at least [`MAX_MEMPOOL_SIZE`] transactions or
    /// [`MAX_MEMPOOL_BYTES`] bytes.
    pub fn is_full(&self) -> bool {
        let g = self.inner.read();
        g.txs.len() >= MAX_MEMPOOL_SIZE || g.total_bytes >= MAX_MEMPOOL_BYTES
    }

    /// Audit B1-T20: whether inserting a new transaction paying `fee` for
    /// `size` bytes (no in-pool descendants yet) could only be undone by the
    /// next trim: the pool is full and the transaction's fee rate does not
    /// exceed the lowest descendant score in the pool (the first package
    /// [`Self::trim_to_size`] evicts). Re-admission skips such a transaction
    /// instead of inserting it and trimming it straight back out.
    pub fn would_only_trim(&self, fee: u64, size: usize) -> bool {
        let g = self.inner.read();
        if g.txs.len() < MAX_MEMPOOL_SIZE && g.total_bytes.saturating_add(size) <= MAX_MEMPOOL_BYTES {
            return false;
        }
        match g.evict_index.keys().next() {
            Some(lowest) => fee_rate_key(fee, size) <= *lowest,
            None => false,
        }
    }

    /// Evict the lowest descendant-score packages until the pool is within
    /// [`MAX_MEMPOOL_SIZE`] and [`MAX_MEMPOOL_BYTES`] (Bitcoin Core's
    /// `TrimToSize`); every eviction raises the rolling minimum fee rate.
    /// Returns the number of transactions evicted.
    pub fn trim_to_size(&self) -> usize {
        let mut g = self.inner.write();
        let mut evicted = 0usize;
        while g.txs.len() > MAX_MEMPOOL_SIZE || g.total_bytes > MAX_MEMPOOL_BYTES {
            let Some((key, victim)) = g.evict_index.iter().next()
                .and_then(|(k, set)| set.iter().next().map(|t| (*k, *t)))
            else { break };
            let package = g.with_descendants(std::iter::once(victim));
            self.raise_rolling_min(key.0);
            evicted += g.remove_set(&package).len();
        }
        evicted
    }

    fn add_inner(&self, tx: Transaction, fee: u64, allow_replacement: bool, bypass_limits: bool)
        -> Result<AddOutcome, MempoolError>
    {
        // P1 (roadmap §2): additive instrumentation span.
        let _span = tracing::debug_span!("mempool.add", fee).entered();
        let txid = tx.txid();

        // Structural checks (cheap, before taking the write lock).
        if tx.inputs.is_empty()  { crate::metrics::inc_tx_rejected("invalid"); return Err(MempoolError::Invalid("no inputs".into())); }
        if tx.outputs.is_empty() { crate::metrics::inc_tx_rejected("invalid"); return Err(MempoolError::Invalid("no outputs".into())); }
        if tx.is_coinbase()      { crate::metrics::inc_tx_rejected("invalid"); return Err(MempoolError::Invalid("coinbase not allowed".into())); }

        // Sprint N-min: size cap.
        let size = tx.actual_size();
        if size > MAX_TX_SIZE {
            crate::metrics::inc_tx_rejected("oversized");
            return Err(MempoolError::Oversized { size, max: MAX_TX_SIZE });
        }
        let wire_size = tx.to_wire_bytes(true).len();

        // SECURITY (audit L2): enforce a minimum relay fee rate (sat/byte).
        if fee < (size as u64).saturating_mul(MIN_RELAY_FEE_RATE) {
            crate::metrics::inc_tx_rejected("low_fee");
            return Err(MempoolError::Invalid(format!(
                "fee {} below minimum relay rate ({} sat/byte for {} bytes)",
                fee, MIN_RELAY_FEE_RATE, size
            )));
        }

        // Overflow check on outputs.
        let _total_out: u64 = tx.outputs.iter()
            .map(|o| o.value)
            .try_fold(0u64, |acc, v| acc.checked_add(v))
            .ok_or_else(|| {
                crate::metrics::inc_tx_rejected("overflow");
                MempoolError::Invalid("output overflow".into())
            })?;

        let mut g = self.inner.write();

        if g.txs.contains_key(&txid) {
            crate::metrics::inc_tx_rejected("duplicate");
            tracing::debug!(reason = "duplicate", "mempool tx rejected");
            return Err(MempoolError::Duplicate);
        }

        // Sprint N-min: intra-mempool double-spend detection.
        let mut direct: BTreeSet<[u8; 32]> = BTreeSet::new();
        let mut first_conflict = None;
        for inp in &tx.inputs {
            let op = (inp.prev_txid, inp.prev_index);
            if let Some(existing) = g.spent.get(&op) {
                direct.insert(*existing);
                first_conflict.get_or_insert((op, *existing));
            }
        }
        let replaced: BTreeSet<[u8; 32]> = match first_conflict {
            None => BTreeSet::new(),
            Some(((outpoint_txid, outpoint_idx), existing_spender)) if !allow_replacement => {
                crate::metrics::inc_tx_rejected("conflict");
                tracing::debug!(reason = "conflict", "mempool tx rejected");
                return Err(MempoolError::Conflict { outpoint_txid, outpoint_idx, existing_spender });
            }
            Some(_) => g.replacement_set(&tx, fee, size, &direct).map_err(|e| {
                crate::metrics::inc_tx_rejected("replacement");
                MempoolError::Replacement(e)
            })?,
        };

        // MEM-6: ancestor / descendant limits.
        let parents = g.pool_parents_of(&tx);
        g.check_chain_limits(&parents, size, &replaced).map_err(|e| {
            crate::metrics::inc_tx_rejected("chain_limit");
            MempoolError::ChainLimit(e)
        })?;

        let replaced_ids: Vec<[u8; 32]> = g.remove_set(&replaced).into_iter().map(|(t, _)| t).collect();
        let now = self.clock.now_secs();
        g.insert(txid, MempoolEntry {
            tx, fee, added_at: now, size, wire_size, parents: BTreeSet::new(), children: BTreeSet::new(),
        });

        // Trim to both caps: evict the lowest descendant-score package. If
        // that package contains the new tx, the new tx is refused instead
        // (Bitcoin Core's TrimToSize semantics: the pool never keeps a worse
        // package at the expense of a better one).
        let mut evicted_for_space = 0usize;
        while !bypass_limits && (g.txs.len() > MAX_MEMPOOL_SIZE || g.total_bytes > MAX_MEMPOOL_BYTES) {
            let Some((key, victim)) = g.evict_index.iter().next()
                .and_then(|(k, set)| set.iter().next().map(|t| (*k, *t)))
            else { break };
            let package = g.with_descendants(std::iter::once(victim));
            if package.contains(&txid) {
                g.remove_set(&package);
                crate::metrics::inc_tx_rejected("full");
                tracing::debug!(reason = "full", evicted_for_space, "mempool tx rejected");
                return Err(MempoolError::Full);
            }
            // MEM-6: an eviction raises the rolling minimum fee rate to the
            // evicted package's rate plus the incremental relay rate.
            self.raise_rolling_min(key.0);
            evicted_for_space += g.remove_set(&package).len();
        }
        drop(g);
        crate::metrics::inc_tx_accepted();
        tracing::debug!(size, evicted_for_space, "mempool tx accepted");
        Ok(AddOutcome { txid, replaced: replaced_ids, evicted_for_space })
    }

    /// Remove `txid` AND every in-pool descendant (they spend outputs that
    /// no longer exist anywhere). Returns whether `txid` was pooled.
    pub fn remove(&self, txid: &[u8; 32]) -> bool {
        let mut g = self.inner.write();
        if !g.txs.contains_key(txid) {
            return false;
        }
        let set = g.with_descendants(std::iter::once(*txid));
        g.remove_set(&set);
        true
    }

    pub fn contains(&self, txid: &[u8; 32]) -> bool {
        self.inner.read().txs.contains_key(txid)
    }

    pub fn size(&self) -> usize {
        self.inner.read().txs.len()
    }

    /// Up to `limit` txs in block-template order: whole ancestor packages by
    /// package fee rate, parents before children ([`select_packages`]). With
    /// no in-pool chains this is highest fee RATE first (P1 / audit L2).
    pub fn get_for_block(&self, limit: usize) -> Vec<Transaction> {
        let cands = self.package_candidates();
        let order = select_packages(&cands, usize::MAX, limit, |_| Ok(()));
        let g = self.inner.read();
        order.iter().filter_map(|t| g.txs.get(t).map(|e| e.tx.clone())).collect()
    }

    /// List all txids in the mempool
    pub fn txids(&self) -> Vec<[u8; 32]> {
        self.inner.read().txs.keys().cloned().collect()
    }

    /// List all entries with metadata (for RPC verbose mempool)
    pub fn entries(&self) -> Vec<([u8; 32], u64, u64)> {
        self.inner.read().txs.iter().map(|(k, e)| (*k, e.fee, e.added_at)).collect()
    }

    /// Median ABSOLUTE fee across all mempool entries. Diagnostics only:
    /// the `estimatefee` RPC uses `estimate_fee_rate_per_kb` (MEM-6), which is
    /// bounded below by the consensus minimum.
    pub fn median_fee(&self) -> u64 {
        let g = self.inner.read();
        if g.txs.is_empty() { return 1000; } // default 1000 sats
        let mut fees: Vec<u64> = g.txs.values().map(|e| e.fee).collect();
        fees.sort();
        fees[fees.len() / 2]
    }

    /// Remove txs confirmed by a connected block. Their in-pool children
    /// STAY (they now spend confirmed outputs) and are unlinked.
    pub fn remove_confirmed(&self, txids: &[[u8; 32]]) {
        let set: BTreeSet<[u8; 32]> = txids.iter().cloned().collect();
        self.inner.write().remove_set(&set);
    }

    /// Audit MEM-3: remove every pooled transaction that spends one of
    /// `outpoints` (outpoints just consumed by a connected block), together
    /// with all its in-pool descendants (MEM-6). Returns the removed txids.
    pub fn remove_conflicts(&self, outpoints: &[([u8; 32], u32)]) -> Vec<[u8; 32]> {
        let mut g = self.inner.write();
        let victims: Vec<[u8; 32]> = outpoints.iter().filter_map(|op| g.spent.get(op).copied()).collect();
        if victims.is_empty() {
            return Vec::new();
        }
        let set = g.with_descendants(victims);
        g.remove_set(&set).into_iter().map(|(t, _)| t).collect()
    }

    /// Audit MEM-3: re-check every pooled transaction with `still_valid` and
    /// drop the failures together with their in-pool descendants (MEM-6).
    /// Returns how many were removed.
    pub fn retain_valid<F: Fn(&MempoolEntry) -> bool>(&self, still_valid: F) -> usize {
        self.retain_valid_with(|e, _| still_valid(e))
    }

    /// [`Self::retain_valid`] whose predicate can also look up outputs of
    /// pooled transactions (`pool_output(txid, index)`), so a child spending
    /// a pooled parent is judged against the pool, not only the UTXO set.
    pub fn retain_valid_with<F>(&self, still_valid: F) -> usize
    where
        F: Fn(&MempoolEntry, &dyn Fn(&[u8; 32], u32) -> Option<TxOutput>) -> bool,
    {
        let mut g = self.inner.write();
        let doomed: Vec<[u8; 32]> = {
            let inner: &Inner = &g;
            let lookup = |t: &[u8; 32], i: u32| -> Option<TxOutput> {
                inner.txs.get(t).and_then(|e| e.tx.outputs.get(i as usize).cloned())
            };
            inner.txs.iter()
                .filter(|(_, e)| !still_valid(e, &lookup))
                .map(|(k, _)| *k)
                .collect()
        };
        if doomed.is_empty() {
            return 0;
        }
        let set = g.with_descendants(doomed);
        g.remove_set(&set).len()
    }

    /// Audit MEM-3: drop transactions older than `max_age_secs` (by the
    /// injected clock) together with their in-pool descendants (MEM-6).
    /// Returns how many were removed.
    pub fn expire_older_than(&self, max_age_secs: u64) -> usize {
        let now = self.clock.now_secs();
        let mut g = self.inner.write();
        let doomed: Vec<[u8; 32]> = g.txs.iter()
            .filter(|(_, e)| now.saturating_sub(e.added_at) > max_age_secs)
            .map(|(k, _)| *k)
            .collect();
        if doomed.is_empty() {
            return 0;
        }
        let set = g.with_descendants(doomed);
        g.remove_set(&set).len()
    }

    /// Entries by OWN fee rate, highest first, with the bincode size. Ties
    /// broken by txid. (Diagnostics; templates use [`select_packages`].)
    pub fn entries_by_fee_rate(&self) -> Vec<(Transaction, u64, usize)> {
        let g = self.inner.read();
        let mut out = Vec::with_capacity(g.txs.len());
        for (_key, set) in g.rate_index.iter().rev() {
            for txid in set {
                if let Some(e) = g.txs.get(txid) {
                    out.push((e.tx.clone(), e.fee, e.size));
                }
            }
        }
        out
    }

    /// MEM-6: metadata of every pooled transaction for [`select_packages`]
    /// (no transaction bodies are cloned). Sizes are the pool's bincode
    /// sizes (`Transaction::actual_size`).
    pub fn package_candidates(&self) -> Vec<PackageCandidate> {
        self.package_candidates_with(|_, size| size)
    }

    /// [`Self::package_candidates`] with every candidate's size given by
    /// `size_of(tx, pool_size)` — the block-size measure of the template's
    /// height (the canonical wire size at/after the hardening activation,
    /// VAL-12), so package fee rates and the byte budget use one measure.
    pub fn package_candidates_with<F>(&self, size_of: F) -> Vec<PackageCandidate>
    where
        F: Fn(&Transaction, usize) -> usize,
    {
        let g = self.inner.read();
        let mut v: Vec<PackageCandidate> = g.txs.iter().map(|(t, e)| PackageCandidate {
            txid: *t,
            fee: e.fee,
            size: size_of(&e.tx, e.size),
            parents: e.parents.iter().copied().collect(),
        }).collect();
        v.sort_by(|a, b| a.txid.cmp(&b.txid));
        v
    }

    /// MEM-6: the output `index` of pooled transaction `txid`, if both exist.
    pub fn pool_output(&self, txid: &[u8; 32], index: u32) -> Option<TxOutput> {
        self.inner.read().txs.get(txid).and_then(|e| e.tx.outputs.get(index as usize).cloned())
    }

    /// The pooled transaction spending `outpoint`, if any.
    pub fn spender_of(&self, outpoint: &([u8; 32], u32)) -> Option<[u8; 32]> {
        self.inner.read().spent.get(outpoint).copied()
    }

    /// In-pool ancestors of `txid` (itself excluded).
    pub fn ancestors_of(&self, txid: &[u8; 32]) -> BTreeSet<[u8; 32]> {
        self.inner.read().ancestors(txid)
    }

    /// In-pool descendants of `txid` (itself excluded).
    pub fn descendants_of(&self, txid: &[u8; 32]) -> BTreeSet<[u8; 32]> {
        self.inner.read().descendants(txid)
    }

    /// MEM-6: the pool-relative checks of an admission, evaluated BEFORE the
    /// (expensive) signature step: the replacement rules when `tx` conflicts
    /// with pooled transactions and the chain limits. Returns the txids a
    /// replacement would evict (empty without conflicts). The same checks
    /// are repeated atomically by [`Self::add_with_replacement`].
    pub fn preflight(&self, tx: &Transaction, fee: u64) -> Result<Vec<[u8; 32]>, MempoolError> {
        let size = tx.actual_size();
        let g = self.inner.read();
        let direct: BTreeSet<[u8; 32]> = tx.inputs.iter()
            .filter_map(|i| g.spent.get(&(i.prev_txid, i.prev_index)).copied())
            .collect();
        let replaced = if direct.is_empty() {
            BTreeSet::new()
        } else {
            g.replacement_set(tx, fee, size, &direct).map_err(MempoolError::Replacement)?
        };
        let parents = g.pool_parents_of(tx);
        g.check_chain_limits(&parents, size, &replaced).map_err(MempoolError::ChainLimit)?;
        Ok(replaced.into_iter().collect())
    }

    // ── MEM-6: rolling minimum fee ───────────────────────────────────────

    fn raise_rolling_min(&self, evicted_rate: u128) {
        let now = self.clock.now_secs();
        let bumped = evicted_rate
            .saturating_add(INCREMENTAL_RELAY_FEE_RATE as u128 * FEE_RATE_SCALE);
        let mut g = self.rolling_min.lock();
        let current = Self::decayed(*g, now);
        if bumped > current {
            *g = (bumped, now);
        }
    }

    fn decayed((rate, at): (u128, u64), now: u64) -> u128 {
        let halvings = now.saturating_sub(at) / ROLLING_FEE_HALFLIFE_SECS;
        if halvings >= 128 { 0 } else { rate >> halvings }
    }

    /// The rolling minimum fee rate in sat/byte (rounded up), after decay.
    /// Zero until the pool has had to evict.
    pub fn rolling_min_fee_rate(&self) -> u64 {
        let now = self.clock.now_secs();
        let r = Self::decayed(*self.rolling_min.lock(), now);
        u64::try_from(r.div_ceil(FEE_RATE_SCALE)).unwrap_or(u64::MAX)
    }

    /// True iff `fee` for a tx of bincode `size` meets the rolling minimum.
    pub fn meets_rolling_min(&self, fee: u64, size: usize) -> bool {
        let now = self.clock.now_secs();
        let floor = Self::decayed(*self.rolling_min.lock(), now);
        fee_rate_key(fee, size).0 >= floor
    }

    /// Fee rates (sat per 1,000 wire bytes) of the pooled transactions,
    /// ascending (B1-T21: the advanced estimate's tiers are rates, applied to
    /// the caller's transaction size). Review: computed from the wire size
    /// cached on each entry at admission and sorted after the pool's lock is
    /// released; it re-encoded every pooled transaction (up to
    /// `MAX_MEMPOOL_BYTES`) under the read lock on every call, which held off
    /// admission, eviction and block-connect cleanup.
    pub fn fee_rates_per_kb(&self) -> Vec<u64> {
        let mut rates: Vec<u64> = {
            let g = self.inner.read();
            g.txs.values().map(|e| e.fee.saturating_mul(1000) / e.wire_size.max(1) as u64).collect()
        };
        rates.sort_unstable();
        rates
    }

    /// Audit MEM-6: fee-rate estimate in sat per 1,000 bytes of the canonical
    /// wire encoding — the unit of the consensus minimum fee. The median rate
    /// of the pool, never below the consensus minimum rate
    /// (`MIN_FEE_RATE_SAT_PER_KB`) nor the rolling minimum.
    pub fn estimate_fee_rate_per_kb(&self) -> u64 {
        let floor = crate::core::tokenomics::MIN_FEE_RATE_SAT_PER_KB
            .max(self.rolling_min_fee_rate().saturating_mul(1000));
        let rates = self.fee_rates_per_kb();
        rates.get(rates.len() / 2).map_or(floor, |r| (*r).max(floor))
    }

    /// Test hook: overwrite the cached wire size of a pooled transaction.
    #[cfg(test)]
    pub(crate) fn set_cached_wire_size(&self, txid: &[u8; 32], wire_size: usize) {
        if let Some(e) = self.inner.write().txs.get_mut(txid) {
            e.wire_size = wire_size;
        }
    }

    // ── MEM-5: recent-rejects filter ─────────────────────────────────────

    /// True iff a transaction with this wtxid was rejected since the last
    /// change of the selected tip or of the next block's height.
    pub fn is_recently_rejected(&self, wtxid: &[u8; 32]) -> bool {
        self.recent_rejects.lock().0.contains(wtxid)
    }

    /// Remember a rejected wtxid (bounded, FIFO).
    pub fn note_rejected(&self, wtxid: [u8; 32]) {
        let mut g = self.recent_rejects.lock();
        Self::insert_reject(&mut g, wtxid);
    }

    fn insert_reject(g: &mut (HashSet<[u8; 32]>, VecDeque<[u8; 32]>), wtxid: [u8; 32]) {
        let (set, order) = g;
        if set.insert(wtxid) {
            order.push_back(wtxid);
            while order.len() > MAX_RECENT_REJECTS {
                if let Some(old) = order.pop_front() {
                    set.remove(&old);
                }
            }
        }
    }

    /// The recent-rejects filter's current epoch (see
    /// [`Self::note_rejected_in_epoch`]). Read it BEFORE reading any state a
    /// verdict depends on.
    pub fn recent_rejects_epoch(&self) -> u64 {
        self.recent_rejects_epoch.load(Ordering::SeqCst)
    }

    /// Remember a rejected wtxid only if the filter was not cleared since
    /// `epoch` was read ([`Self::recent_rejects_epoch`]): a verdict computed
    /// against the previous tip or next height must not outlive the change
    /// (it would be replayed at the new height). Returns whether it was
    /// remembered.
    pub fn note_rejected_in_epoch(&self, wtxid: [u8; 32], epoch: u64) -> bool {
        let mut g = self.recent_rejects.lock();
        if self.recent_rejects_epoch.load(Ordering::SeqCst) != epoch {
            return false;
        }
        Self::insert_reject(&mut g, wtxid);
        true
    }

    /// Forget every remembered rejection and start a new epoch. Called when
    /// the selected tip changes (a tx rejected against the old tip may be
    /// valid now) and when the next block's height changes without a tip
    /// change (`accept::sync_mempool_next_height`: a version, 64-byte or
    /// maturity verdict computed for the old height says nothing about the
    /// new one).
    pub fn clear_recent_rejects(&self) {
        let mut g = self.recent_rejects.lock();
        g.0.clear();
        g.1.clear();
        self.recent_rejects_epoch.fetch_add(1, Ordering::SeqCst);
    }

    /// Number of remembered rejections.
    pub fn recent_rejects_len(&self) -> usize {
        self.recent_rejects.lock().0.len()
    }

    /// True iff `outpoint` is spent by a pooled transaction.
    pub fn spends_outpoint(&self, outpoint: &([u8; 32], u32)) -> bool {
        self.inner.read().spent.contains_key(outpoint)
    }

    /// P0: total serialized bytes currently held (for the byte-cap metric /
    /// diagnostics). O(1) — reads the running counter.
    pub fn size_bytes(&self) -> usize {
        self.inner.read().total_bytes
    }

    /// Assert every cross-index invariant. Returns `Err(reason)` on the
    /// first drift found. This is the property the `mempool_ops` fuzz target
    /// and the `tests/mempool_index_prop.rs` proptest assert never breaks.
    /// Not a hot-path method — it walks every map.
    ///
    /// Checks:
    ///   1. `rate_index` multiset == txs key set, each at its own fee rate.
    ///   2. every `spent` entry points at a live tx that claims that outpoint,
    ///      and every input of every pooled tx is in `spent`.
    ///   3. `total_bytes` == Σ size (bounded by MAX_MEMPOOL_BYTES), and each
    ///      cached `size` equals `actual_size()`.
    ///   4. `size()` <= MAX_MEMPOOL_SIZE.
    ///   5. MEM-6 links: `parents(x)` = pooled txs whose outputs x spends;
    ///      `children` is the exact inverse; `by_prev_txid` indexes every
    ///      input; the parent graph is acyclic.
    ///   6. MEM-6 eviction index: every tx at its descendant score.
    pub fn debug_check_invariants(&self) -> Result<(), String> {
        let g = self.inner.read();

        // 4. count bound.
        if g.txs.len() > MAX_MEMPOOL_SIZE {
            return Err(format!("size {} > MAX_MEMPOOL_SIZE {}", g.txs.len(), MAX_MEMPOOL_SIZE));
        }

        // 1. rate index ↔ txs.
        let mut indexed = 0usize;
        for (key, set) in g.rate_index.iter() {
            if set.is_empty() {
                return Err("rate_index has an empty bucket (should be pruned)".into());
            }
            for txid in set {
                indexed += 1;
                match g.txs.get(txid) {
                    None => return Err(format!("rate_index txid {} absent from txs", hex::encode(txid))),
                    Some(e) => {
                        let expect = fee_rate_key(e.fee, e.tx.actual_size());
                        if expect != *key {
                            return Err(format!(
                                "rate_index txid {} filed under {:?} but its key is {:?}",
                                hex::encode(txid), key, expect
                            ));
                        }
                    }
                }
            }
        }
        if indexed != g.txs.len() {
            return Err(format!("rate_index has {} members but txs has {}", indexed, g.txs.len()));
        }

        // 2. spent ↔ txs.
        for ((prev_txid, prev_index), spender) in g.spent.iter() {
            match g.txs.get(spender) {
                None => return Err(format!("spent points at absent tx {}", hex::encode(spender))),
                Some(e) => {
                    let claims = e.tx.inputs.iter()
                        .any(|inp| inp.prev_txid == *prev_txid && inp.prev_index == *prev_index);
                    if !claims {
                        return Err(format!(
                            "spent outpoint {}:{} attributed to {} which does not claim it",
                            hex::encode(prev_txid), prev_index, hex::encode(spender)
                        ));
                    }
                }
            }
        }
        for (txid, e) in g.txs.iter() {
            for inp in &e.tx.inputs {
                if g.spent.get(&(inp.prev_txid, inp.prev_index)) != Some(txid) {
                    return Err(format!("input of {} missing from spent", hex::encode(txid)));
                }
                if !g.by_prev_txid.get(&inp.prev_txid).is_some_and(|s| s.contains(txid)) {
                    return Err(format!("input of {} missing from by_prev_txid", hex::encode(txid)));
                }
            }
        }
        for (prev, spenders) in g.by_prev_txid.iter() {
            if spenders.is_empty() {
                return Err("by_prev_txid has an empty bucket".into());
            }
            for s in spenders {
                let ok = g.txs.get(s).is_some_and(|e| e.tx.inputs.iter().any(|i| i.prev_txid == *prev));
                if !ok {
                    return Err(format!("by_prev_txid lists {} which does not spend {}", hex::encode(s), hex::encode(prev)));
                }
            }
        }

        // 3. byte counter.
        let mut sum = 0usize;
        for (txid, e) in g.txs.iter() {
            if e.size != e.tx.actual_size() {
                return Err(format!("cached size of {} is stale", hex::encode(txid)));
            }
            sum += e.size;
        }
        if sum != g.total_bytes {
            return Err(format!("total_bytes {} != Σ actual_size {}", g.total_bytes, sum));
        }
        if g.total_bytes > MAX_MEMPOOL_BYTES {
            return Err(format!("total_bytes {} > MAX_MEMPOOL_BYTES {}", g.total_bytes, MAX_MEMPOOL_BYTES));
        }

        // 5. links.
        for (txid, e) in g.txs.iter() {
            let expect_parents = g.pool_parents_of(&e.tx);
            if expect_parents != e.parents {
                return Err(format!("parents of {} drifted", hex::encode(txid)));
            }
            let expect_children: BTreeSet<[u8; 32]> = g.by_prev_txid.get(txid).cloned().unwrap_or_default();
            if expect_children != e.children {
                return Err(format!("children of {} drifted", hex::encode(txid)));
            }
            if g.ancestors(txid).contains(txid) {
                return Err(format!("{} is its own ancestor", hex::encode(txid)));
            }
        }

        // 6. eviction index.
        let mut evict_members = 0usize;
        for (key, set) in g.evict_index.iter() {
            if set.is_empty() {
                return Err("evict_index has an empty bucket".into());
            }
            for t in set {
                evict_members += 1;
                if g.evict_key.get(t) != Some(key) {
                    return Err(format!("evict_key of {} disagrees with evict_index", hex::encode(t)));
                }
                if g.desc_score(t) != Some(*key) {
                    return Err(format!("descendant score of {} is stale", hex::encode(t)));
                }
            }
        }
        if evict_members != g.txs.len() || g.evict_key.len() != g.txs.len() {
            return Err(format!("evict_index has {} members, txs {}", evict_members, g.txs.len()));
        }

        Ok(())
    }
}

// ── MEM-6: package (CPFP) selection ─────────────────────────────────────────

/// Metadata of one pooled transaction for [`select_packages`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageCandidate {
    pub txid:    [u8; 32],
    pub fee:     u64,
    pub size:    usize,
    /// In-pool parents (txids of candidates this one spends).
    pub parents: Vec<[u8; 32]>,
}

/// MEM-6: child-pays-for-parent selection (Bitcoin Core's
/// `BlockAssembler::addPackageTxs`, with a lazily re-scored max-heap).
///
/// Repeatedly takes the candidate whose ANCESTOR PACKAGE — itself plus every
/// not-yet-selected in-pool ancestor — has the highest package fee rate
/// (Σ fee / Σ size), and appends that whole package parents-first. A package
/// that does not fit `budget_bytes` (or would exceed `max_txs`) is skipped;
/// its members may still be selected later through a smaller package.
/// `accept` sees each package in block order and may refuse it with
/// `Err(bad_txid)`: `bad_txid` and every candidate depending on it are then
/// never selected (the rest of that package stays eligible).
///
/// Returns the selected txids in block order: every transaction appears
/// after all of its in-pool ancestors.
pub fn select_packages<F>(
    cands: &[PackageCandidate],
    budget_bytes: usize,
    max_txs: usize,
    mut accept: F,
) -> Vec<[u8; 32]>
where
    F: FnMut(&[[u8; 32]]) -> Result<(), [u8; 32]>,
{
    let pos: HashMap<[u8; 32], usize> = cands.iter().enumerate().map(|(i, c)| (c.txid, i)).collect();
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); cands.len()];
    let parents: Vec<Vec<usize>> = cands.iter().enumerate().map(|(i, c)| {
        let ps: Vec<usize> = c.parents.iter().filter_map(|p| pos.get(p).copied()).collect();
        for &p in &ps {
            children[p].push(i);
        }
        ps
    }).collect();
    // Full in-candidate ancestor sets (bounded by the chain limits).
    let ancestors: Vec<BTreeSet<usize>> = (0..cands.len()).map(|i| {
        let mut out = BTreeSet::new();
        let mut stack = parents[i].clone();
        while let Some(p) = stack.pop() {
            if out.insert(p) {
                stack.extend(parents[p].iter().copied());
            }
        }
        out
    }).collect();

    let mut selected: Vec<bool> = vec![false; cands.len()];
    let mut failed: Vec<bool> = vec![false; cands.len()];
    let package_of = |i: usize, selected: &[bool]| -> Vec<usize> {
        let mut pkg: Vec<usize> = ancestors[i].iter().copied().filter(|a| !selected[*a]).collect();
        pkg.push(i);
        pkg
    };
    let score_of = |pkg: &[usize]| -> (FeeRateKey, usize) {
        let (fee, size) = pkg.iter().fold((0u128, 0usize), |(f, s), &j| {
            (f.saturating_add(cands[j].fee as u128), s.saturating_add(cands[j].size))
        });
        (package_rate_key(fee, size as u128), size)
    };

    let mut heap: BinaryHeap<(FeeRateKey, Reverse<[u8; 32]>, usize)> = BinaryHeap::with_capacity(cands.len());
    for (i, c) in cands.iter().enumerate() {
        let pkg = package_of(i, &selected);
        heap.push((score_of(&pkg).0, Reverse(c.txid), i));
    }

    let mut out: Vec<[u8; 32]> = Vec::new();
    let mut used = 0usize;
    while let Some((score, _, i)) = heap.pop() {
        if out.len() >= max_txs {
            break;
        }
        if selected[i] || failed[i] {
            continue;
        }
        if ancestors[i].iter().any(|a| failed[*a]) {
            failed[i] = true;
            continue;
        }
        let mut pkg = package_of(i, &selected);
        let (now_score, pkg_size) = score_of(&pkg);
        if now_score != score {
            heap.push((now_score, Reverse(cands[i].txid), i));
            continue;
        }
        if used.saturating_add(pkg_size) > budget_bytes || out.len().saturating_add(pkg.len()) > max_txs {
            // Does not fit now and `used` only grows: never again as this
            // package. Its ancestors stay eligible on their own.
            failed[i] = true;
            continue;
        }
        // Parents first: an ancestor's ancestor set is a strict subset.
        pkg.sort_by_key(|j| (ancestors[*j].len(), cands[*j].txid));
        let ids: Vec<[u8; 32]> = pkg.iter().map(|j| cands[*j].txid).collect();
        match accept(&ids) {
            Ok(()) => {
                for &j in &pkg {
                    selected[j] = true;
                }
                used = used.saturating_add(pkg_size);
                out.extend_from_slice(&ids);
                // Every descendant's package shrank: re-score them all
                // (bounded by the descendant limit).
                let mut stack: Vec<usize> = pkg.iter().flat_map(|&j| children[j].iter().copied()).collect();
                let mut seen: HashSet<usize> = HashSet::new();
                while let Some(c) = stack.pop() {
                    if !seen.insert(c) {
                        continue;
                    }
                    if !selected[c] && !failed[c] {
                        let cp = package_of(c, &selected);
                        heap.push((score_of(&cp).0, Reverse(cands[c].txid), c));
                    }
                    stack.extend(children[c].iter().copied());
                }
            }
            Err(bad) => {
                if let Some(&b) = pos.get(&bad) {
                    failed[b] = true;
                }
                failed[i] = true;
                // Package members other than `bad` (and its dependants) stay
                // eligible: put them back with fresh scores.
                for &j in &pkg {
                    if !failed[j] && !ancestors[j].iter().any(|a| failed[*a]) {
                        let jp = package_of(j, &selected);
                        heap.push((score_of(&jp).0, Reverse(cands[j].txid), j));
                    }
                }
            }
        }
    }
    out
}

// ── Sprint A additions ──────────────────────────────────────────

impl Mempool {
    /// Sprint A: Get a full Transaction by txid.
    pub fn get_tx(&self, txid: &[u8; 32]) -> Option<Transaction> {
        self.inner.read().txs.get(txid).map(|e| e.tx.clone())
    }

    /// Sprint A: Get full mempool entry (tx + fee + timestamp) by txid.
    pub fn get_entry(&self, txid: &[u8; 32]) -> Option<MempoolEntry> {
        self.inner.read().txs.get(txid).cloned()
    }

    /// Sprint A: Scan mempool for txs that spend from or pay to the
    /// given address. Returns Vec of AddressTxInfo sorted newest first.
    pub fn txs_affecting_address(
        &self,
        addr_hash: &[u8; 20],
        utxo_lookup: Option<&dyn Fn(&[u8; 32], u32) -> Option<crate::core::TxOutput>>,
    ) -> Vec<AddressTxInfo> {
        let g = self.inner.read();
        let mut results = Vec::new();

        for (txid, entry) in g.txs.iter() {
            let incoming: u64 = entry.tx.outputs.iter()
                .filter(|o| o.script_pubkey.as_slice() == addr_hash.as_slice())
                .map(|o| o.value)
                .sum();

            let outgoing: u64 = if let Some(lookup) = utxo_lookup {
                entry.tx.inputs.iter()
                    .filter_map(|inp| {
                        let utxo = lookup(&inp.prev_txid, inp.prev_index)?;
                        if utxo.script_pubkey.as_slice() == addr_hash.as_slice() {
                            Some(utxo.value)
                        } else {
                            None
                        }
                    })
                    .sum()
            } else {
                0
            };

            if incoming > 0 || outgoing > 0 {
                results.push(AddressTxInfo {
                    txid:     *txid,
                    tx:       entry.tx.clone(),
                    incoming,
                    outgoing,
                    fee:      entry.fee,
                    added_at: entry.added_at,
                });
            }
        }

        results.sort_by(|a, b| b.added_at.cmp(&a.added_at));
        results
    }

    /// Sprint A: Compute pending balance changes for an address.
    /// Returns (incoming_sats, outgoing_sats).
    pub fn pending_balance_for(
        &self,
        addr_hash: &[u8; 20],
        utxo_lookup: Option<&dyn Fn(&[u8; 32], u32) -> Option<crate::core::TxOutput>>,
    ) -> (u64, u64) {
        let txs = self.txs_affecting_address(addr_hash, utxo_lookup);
        let incoming: u64 = txs.iter().map(|t| t.incoming).sum();
        let outgoing: u64 = txs.iter().map(|t| t.outgoing).sum();
        (incoming, outgoing)
    }
}

/// Sprint A: Info about a mempool tx affecting a specific address.
#[derive(Clone, Debug)]
pub struct AddressTxInfo {
    pub txid:     [u8; 32],
    pub tx:       Transaction,
    pub incoming: u64,
    pub outgoing: u64,
    pub fee:      u64,
    pub added_at: u64,
}

impl Default for Mempool {
    fn default() -> Self { Self::new() }
}

#[derive(Debug, thiserror::Error)]
pub enum MempoolError {
    #[error("duplicate transaction")]
    Duplicate,
    #[error("mempool full")]
    Full,
    #[error("invalid transaction: {0}")]
    Invalid(String),
    /// Sprint N-min: new tx conflicts with a tx already in the mempool
    /// (both spend the same UTXO) and replacement was not requested.
    #[error("conflicts with mempool tx {}: outpoint {}:{} already spent", hex::encode(existing_spender), hex::encode(outpoint_txid), outpoint_idx)]
    Conflict {
        outpoint_txid:    [u8; 32],
        outpoint_idx:     u32,
        existing_spender: [u8; 32],
    },
    /// Sprint N-min: transaction serialized size exceeds MAX_TX_SIZE.
    #[error("transaction too large: {size} bytes (max {max})")]
    Oversized { size: usize, max: usize },
    /// MEM-6: an ancestor or descendant limit would be exceeded.
    #[error("too-long-mempool-chain: {0}")]
    ChainLimit(String),
    /// MEM-6: a conflicting transaction failed the replacement rules.
    #[error("replacement rejected: {0}")]
    Replacement(String),
}
