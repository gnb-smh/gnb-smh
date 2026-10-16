//! Interval-based reachability index for GhostDAG (Kaspa-style).
//!
//! # Why this exists
//!
//! The legacy `is_ancestor` in `mod.rs` answers DAG-ancestry with a **bounded**
//! backwards BFS (`MAX_REACHABILITY_DEPTH = 1024`, plus a `depth_limit*10`
//! visited cap). When the height-difference between two blocks exceeds that
//! bound the BFS silently clamps and can return a **false negative** — it is
//! O(height_diff) and, worse, *result-affecting when the bound is hit*.
//!
//! This module provides an **unbounded, O(1)/O(log n)** replacement based on
//! the selected-parent-tree interval labeling + future-covering-set (FCS)
//! technique from Sompolinsky/Wyborski/Zohar and its implementation in
//! kaspanet/rusty-kaspa (`consensus/src/processes/reachability`).
//!
//! # Consensus status
//!
//! The index is on the live consensus path: GnB colors every block with it
//! (`CORRECTED_COLORING_ACTIVATION_HEIGHT = 0`, `GhostDAG::maintains_reachability_index`),
//! and the mergeset, the exact coloring and the merge-depth check of hardened
//! blocks query it. Only its ANSWERS matter (`is_chain_ancestor`,
//! `is_dag_ancestor`); the interval layout is a private, rebuildable cache
//! that never enters `GhostdagData` or the integrity chain. Any layout that
//! answers exactly gives bit-identical GhostDAG output, which is what the
//! differential and replay tests check.
//!
//! # Reindexing (audit DAG-7 residual)
//!
//! A block takes half of the free interval after its parent's last child. When
//! the parent has none left the index is reindexed, following Kaspa's
//! reindex-root scheme (`tree.rs` / `reindex.rs`): a chain block
//! [`REINDEX_DEPTH`] blocks below the selected tip is the *reindex root*; when
//! it advances, the chain from the old root to the new one is *concentrated*
//! (the siblings of each chain block are packed tightly, the chain block gets
//! the rest of its parent's interval, and [`REINDEX_SLACK`] free slots are
//! reserved on both sides of every concentrated parent's children). A block
//! in the reindex root's future is reindexed inside that bounded window; a
//! block below it — a deep side block, a genesis sibling — reclaims slack
//! along the chain toward the root (reserving fresh slack on the way back),
//! so it re-lays out only its own branch and the side branches it shifts,
//! never the subtree of the whole chain above it. The previous scheme
//! re-laid out the whole subtree under the first ancestor with room: one
//! genesis sibling or deep side block cost O(DAG) under the DAG write lock.
//!
//! The reindex root is persisted as a trailer of the tree root's record (a
//! reader that does not know it ignores it). A layout loaded without one (an
//! older data dir) is re-laid out once and concentrated before the first
//! advance. Every step uses checked arithmetic; an inconsistency falls back to
//! a full re-layout from the tree root (the previous behaviour) instead of a
//! panic.
//!
//! # Correctness harness
//!
//! Every query answered by this index is validated in tests against
//! [`brute_force_is_ancestor`], an unbounded BFS oracle over the parent graph.
//! A mis-labeled interval or a stale FCS silently mis-colors blocks, so this
//! oracle equivalence is the single highest-value guard in the whole change.

use std::collections::{HashMap, VecDeque};
use super::{BlockHash, DagStore};

/// A half-open-free interval `[start, end]` (both inclusive) in the reachability
/// labeling. A node's own identity point is its `end`; its tree-children are
/// laid out within `[start, end-1]`. Thus node `a` is a *chain* (selected-parent
/// tree) ancestor of node `b` iff `a`'s interval strictly contains `b`'s.
/// An empty interval is `end = start - 1` (Kaspa's convention).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Interval {
    pub start: u64,
    pub end: u64,
}

/// An inconsistency met while reindexing (the caller falls back to a full
/// re-layout from the tree root).
#[derive(Debug)]
struct ReindexError(&'static str);

type Res<T> = Result<T, ReindexError>;

fn err<T>(why: &'static str) -> Res<T> {
    Err(ReindexError(why))
}

impl Interval {
    fn new(start: u64, end: u64) -> Res<Self> {
        if start == 0 || end.checked_add(1).is_none_or(|e1| e1 < start) {
            return err("malformed interval");
        }
        Ok(Interval { start, end })
    }

    #[inline]
    fn contains(&self, other: &Interval) -> bool {
        self.start <= other.start && other.end <= self.end
    }

    #[inline]
    fn strictly_contains(&self, other: &Interval) -> bool {
        self.start <= other.start && other.end < self.end
    }

    /// Number of integer slots, inclusive (0 for an empty interval).
    #[inline]
    fn size(&self) -> u64 {
        (self.end + 1).saturating_sub(self.start)
    }

    fn increase(&self, o: u64) -> Res<Self> {
        Self::new(self.start.checked_add(o).ok_or(ReindexError("overflow"))?,
                  self.end.checked_add(o).ok_or(ReindexError("overflow"))?)
    }
    fn decrease(&self, o: u64) -> Res<Self> {
        Self::new(self.start.checked_sub(o).ok_or(ReindexError("underflow"))?,
                  self.end.checked_sub(o).ok_or(ReindexError("underflow"))?)
    }
    fn increase_start(&self, o: u64) -> Res<Self> {
        Self::new(self.start.checked_add(o).ok_or(ReindexError("overflow"))?, self.end)
    }
    fn decrease_start(&self, o: u64) -> Res<Self> {
        Self::new(self.start.checked_sub(o).ok_or(ReindexError("underflow"))?, self.end)
    }
    fn increase_end(&self, o: u64) -> Res<Self> {
        Self::new(self.start, self.end.checked_add(o).ok_or(ReindexError("overflow"))?)
    }
    fn decrease_end(&self, o: u64) -> Res<Self> {
        Self::new(self.start, self.end.checked_sub(o).ok_or(ReindexError("underflow"))?)
    }

    /// The left half (rounded up) of the interval.
    fn left_half(&self) -> Res<Self> {
        let left = self.size().div_ceil(2);
        Self::new(self.start, self.start + left - 1)
    }

    /// Exactly `sizes.len()` consecutive parts of these sizes (their sum must
    /// be the interval's size).
    fn split_exact(&self, sizes: &[u64]) -> Res<Vec<Self>> {
        let sum = sizes.iter().try_fold(0u64, |a, s| a.checked_add(*s)).ok_or(ReindexError("overflow"))?;
        if sum != self.size() {
            return err("split_exact: sizes do not add up to the interval");
        }
        let mut start = self.start;
        let mut out = Vec::with_capacity(sizes.len());
        for s in sizes {
            out.push(Self::new(start, (start + s).checked_sub(1).ok_or(ReindexError("underflow"))?)?);
            start += s;
        }
        Ok(out)
    }

    /// Kaspa's `split_exponential`: every part gets at least its size, and
    /// the remaining slots are biased toward the larger subtrees, as
    /// `2^size` (the subtree that grows the most — the selected chain — gets
    /// almost all of them).
    fn split_exponential(&self, sizes: &[u64]) -> Res<Vec<Self>> {
        let total = self.size();
        let sum = sizes.iter().try_fold(0u64, |a, s| a.checked_add(*s)).ok_or(ReindexError("overflow"))?;
        if sum == 0 || total < sum {
            return err("split_exponential: interval smaller than the subtrees");
        }
        if total == sum {
            return self.split_exact(sizes);
        }
        let mut remaining_bias = total - sum;
        let total_bias = remaining_bias as f64;
        let max = sizes.iter().copied().max().unwrap_or(0);
        let mut fractions: Vec<f64> = sizes.iter().map(|s| 1f64 / 2f64.powf((max - s) as f64)).collect();
        let fsum: f64 = fractions.iter().sum();
        for f in &mut fractions {
            *f /= fsum;
        }
        let mut biased = Vec::with_capacity(sizes.len());
        for (i, f) in fractions.iter().enumerate() {
            let bias = if i == fractions.len() - 1 {
                remaining_bias
            } else {
                remaining_bias.min((total_bias * f).round() as u64)
            };
            biased.push(sizes[i] + bias);
            remaining_bias -= bias;
        }
        self.split_exact(&biased)
    }
}

/// Root interval upper bound. 2^62 leaves head-room so that, for any realistic
/// DAG, reindexing is rare and never runs out of address space.
const ROOT_END: u64 = 1u64 << 62;
const ROOT_START: u64 = 1;

/// Kaspa's `DEFAULT_REINDEX_DEPTH`: the reindex root trails the selected tip
/// by this many chain blocks; reindexing above it stays inside this window.
pub const REINDEX_DEPTH: u64 = 100;

/// Kaspa's `DEFAULT_REINDEX_SLACK`: free slots reserved on each side of the
/// children of every concentrated chain block (room for side blocks without a
/// reindex), and the height lead a competing chain needs before the reindex
/// root follows it (alternating reorgs cannot make it oscillate). 2^12 per
/// chain block leaves room for 2^49 chain blocks in the 2^62 root interval.
pub const REINDEX_SLACK: u64 = 1 << 12;

/// Trailer tag of the tree root's record carrying the reindex root.
const REINDEX_ROOT_TAG: u8 = b'R';

/// Interval-labeling + future-covering-set reachability index.
///
/// Owns no `GhostdagData` and feeds nothing into `canonical_encode` /
/// `compute_integrity_hash`; it is a pure cache and can be rebuilt freely by
/// replaying block insertions in topological order.
pub struct ReachabilityStore {
    interval: HashMap<BlockHash, Interval>,
    tree_parent: HashMap<BlockHash, BlockHash>,
    /// Tree children in insertion order, which is also the order of their
    /// intervals (every reindex operation preserves it).
    children: HashMap<BlockHash, Vec<BlockHash>>,
    /// Tree height (the GhostDAG height: selected parent + 1, root 0).
    height: HashMap<BlockHash, u64>,
    /// Future covering set per block: blocks `b` for which this block is in
    /// `mergeset(b)`. Kept sorted by interval start. Used to answer non-tree
    /// (merge-edge) ancestry.
    fcs: HashMap<BlockHash, Vec<BlockHash>>,
    root: Option<BlockHash>,
    /// The reindex root (see the module docs). `None` = the layout is not
    /// managed by the reindex-root scheme yet (fresh index, or one loaded
    /// from an older data dir): the first advance re-lays it out first.
    reindex_root: Option<BlockHash>,
    /// Durability tracking (Phase 1 — persistent reachability index).
    ///
    /// `dirty` holds every block whose persisted record (interval / remaining /
    /// tree_parent / children / fcs) changed since the last
    /// [`take_persist_delta`]. A single `add_block` can dirty many blocks when a
    /// reindex reshuffles a subtree, so this set — not just the newly-added hash
    /// — is what must be flushed to keep the on-disk index consistent with
    /// memory. `tombstones` holds blocks removed by [`remove_leaf`] that must be
    /// deleted from the CF. Both are drained atomically alongside the CF_DAG
    /// write; see `docs/adr/ADR-035-*` and `Storage::put_dag_with_integrity_and_reach`.
    ///
    /// These sets are pure bookkeeping — they are NOT part of any query answer,
    /// NOT consensus state, and are empty on a freshly-loaded index.
    dirty: std::collections::HashSet<BlockHash>,
    tombstones: std::collections::HashSet<BlockHash>,
    /// Instrumentation (audit DAG-7): nodes visited by reindexing (subtree
    /// counting and interval assignment), cumulative. Not persisted.
    work: std::sync::atomic::AtomicU64,
}

/// Version tag for the serialized per-block reachability record layout. Bumped
/// whenever [`ReachabilityStore::encode_record`] / [`decode_record`] change
/// incompatibly, so a boot against an older on-disk index triggers a rebuild
/// rather than mis-decoding. Persisted as `reachability/meta/version` in CF_META.
/// (The reindex-root trailer of the root's record is a compatible extension:
/// a version-1 reader ignores trailing bytes.)
pub const REACHABILITY_RECORD_VERSION: u32 = 1;

impl Default for ReachabilityStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-operation cache of subtree sizes (Kaspa's `ReindexOperationContext`).
#[derive(Default)]
struct Ctx {
    sizes: HashMap<BlockHash, u64>,
}

impl ReachabilityStore {
    pub fn new() -> Self {
        Self {
            interval: HashMap::new(),
            tree_parent: HashMap::new(),
            children: HashMap::new(),
            height: HashMap::new(),
            fcs: HashMap::new(),
            root: None,
            reindex_root: None,
            dirty: std::collections::HashSet::new(),
            tombstones: std::collections::HashSet::new(),
            work: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Nodes visited by reindexing (subtree counting and interval
    /// assignment) since this index was created: the cost tests of audit
    /// DAG-7 compare it before and after an insertion.
    #[allow(dead_code)] // tests only; the node binary compiles this module too
    pub fn reindex_work(&self) -> u64 {
        self.work.load(std::sync::atomic::Ordering::Relaxed)
    }

    #[inline]
    fn note_work(&self) {
        self.work.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// The root (genesis) block of the labeling, if registered.
    pub fn root(&self) -> Option<BlockHash> {
        self.root
    }

    /// The current reindex root (`None` until the index is managed by the
    /// reindex-root scheme).
    #[allow(dead_code)] // tests and diagnostics; the node binary compiles this module too
    pub fn reindex_root(&self) -> Option<BlockHash> {
        self.reindex_root
    }

    #[inline]
    fn mark_dirty(&mut self, hash: BlockHash) {
        // A block cannot be both live-and-dirty and a tombstone.
        self.tombstones.remove(&hash);
        self.dirty.insert(hash);
    }

    pub fn is_empty(&self) -> bool {
        self.interval.is_empty()
    }

    pub fn len(&self) -> usize {
        self.interval.len()
    }

    pub fn has(&self, hash: &BlockHash) -> bool {
        self.interval.contains_key(hash)
    }

    /// Register the genesis / root block. Idempotent-guarded by the caller.
    pub fn add_genesis(&mut self, hash: BlockHash) {
        let iv = Interval { start: ROOT_START, end: ROOT_END };
        self.interval.insert(hash, iv);
        self.children.insert(hash, Vec::new());
        self.height.insert(hash, 0);
        self.fcs.insert(hash, Vec::new());
        self.root = Some(hash);
        self.reindex_root = Some(hash);
        self.mark_dirty(hash);
    }

    /// Add a non-genesis block: `selected_parent` is the tree edge, `mergeset`
    /// is `past(block) \ past(selected_parent) \ {selected_parent}` (exactly the
    /// GhostDAG mergeset). Both the tree interval and the future-covering sets
    /// are updated.
    ///
    /// Blocks MUST be added in a topological order (parents before children);
    /// `GhostDAG::add_block` guarantees this.
    pub fn add_block(
        &mut self,
        hash: BlockHash,
        selected_parent: &BlockHash,
        mergeset: &[BlockHash],
    ) {
        self.add_tree_block(hash, selected_parent);
        // Update the future covering set of every merged block.
        for m in mergeset {
            self.insert_to_fcs(*m, hash);
        }
    }

    // ── store accessors ─────────────────────────────────────────────────────

    fn iv(&self, h: &BlockHash) -> Res<Interval> {
        self.interval.get(h).copied().ok_or(ReindexError("block not in the index"))
    }

    fn set_interval(&mut self, h: BlockHash, iv: Interval) {
        self.note_work();
        self.interval.insert(h, iv);
        self.mark_dirty(h);
    }

    fn parent_of(&self, h: &BlockHash) -> Res<BlockHash> {
        self.tree_parent.get(h).copied().ok_or(ReindexError("block has no tree parent"))
    }

    fn height_of(&self, h: &BlockHash) -> Res<u64> {
        self.height.get(h).copied().ok_or(ReindexError("block has no height"))
    }

    fn children_of(&self, h: &BlockHash) -> Vec<BlockHash> {
        self.children.get(h).cloned().unwrap_or_default()
    }

    /// The slots available to `h`'s tree children: its interval minus its own
    /// end point.
    fn children_capacity(&self, h: &BlockHash) -> Res<Interval> {
        self.iv(h)?.decrease_end(1)
    }

    /// Free slots before `h`'s first child (all of the capacity if none).
    fn remaining_before(&self, h: &BlockHash) -> Res<Interval> {
        let cap = self.children_capacity(h)?;
        match self.children.get(h).and_then(|c| c.first()) {
            Some(first) => Interval::new(cap.start, self.iv(first)?.start.checked_sub(1).ok_or(ReindexError("underflow"))?),
            None => Ok(cap),
        }
    }

    /// Free slots after `h`'s last child (all of the capacity if none): where
    /// a new child is allocated.
    fn remaining_after(&self, h: &BlockHash) -> Res<Interval> {
        let cap = self.children_capacity(h)?;
        match self.children.get(h).and_then(|c| c.last()) {
            Some(last) => Interval::new(self.iv(last)?.end + 1, cap.end),
            None => Ok(cap),
        }
    }

    /// Non-strict chain ancestry from intervals (`a` = `b` counts).
    fn chain_ancestor_or_self(&self, a: &BlockHash, b: &BlockHash) -> Res<bool> {
        Ok(self.iv(a)?.contains(&self.iv(b)?))
    }

    fn strict_chain_ancestor(&self, a: &BlockHash, b: &BlockHash) -> Res<bool> {
        Ok(self.iv(a)?.strictly_contains(&self.iv(b)?))
    }

    /// The child of `ancestor` on the tree path to `descendant` (binary search
    /// of the ordered children by interval; Kaspa's
    /// `get_next_chain_ancestor_unchecked`).
    fn next_chain_ancestor(&self, descendant: &BlockHash, ancestor: &BlockHash) -> Res<BlockHash> {
        let d = self.iv(descendant)?;
        let children = self.children.get(ancestor).ok_or(ReindexError("no children"))?;
        let mut lo = 0usize;
        let mut hi = children.len();
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.iv(&children[mid])?.start <= d.end {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if lo == 0 {
            return err("next chain ancestor not found");
        }
        let c = children[lo - 1];
        if self.iv(&c)?.contains(&d) {
            Ok(c)
        } else {
            err("next chain ancestor not found")
        }
    }

    // ── tree interval maintenance ───────────────────────────────────────────

    /// Kaspa's `add_tree_block`: the new child gets the left half of the free
    /// interval after its parent's last child; with none left it gets the
    /// empty interval at the end of the parent's capacity and the index is
    /// reindexed around the current reindex root.
    fn add_tree_block(&mut self, child: BlockHash, parent: &BlockHash) {
        let remaining = self.remaining_after(parent);
        self.tree_parent.insert(child, *parent);
        self.children.entry(*parent).or_default().push(child);
        self.children.entry(child).or_default();
        self.fcs.entry(child).or_default();
        let ph = self.height.get(parent).copied().unwrap_or(0);
        self.height.insert(child, ph + 1);
        self.mark_dirty(*parent);
        self.mark_dirty(child);
        match remaining {
            Ok(r) if r.size() > 0 => {
                match r.left_half() {
                    Ok(iv) => {
                        self.interval.insert(child, iv);
                    }
                    Err(e) => self.full_relayout(e),
                }
            }
            Ok(r) => {
                // The empty interval exactly at the end of the capacity.
                self.interval.insert(child, r);
                let root = self.reindex_root.or(self.root).unwrap_or(child);
                let mut ctx = Ctx::default();
                if let Err(e) = self.reindex_intervals(&mut ctx, child, root) {
                    self.full_relayout(e);
                }
            }
            Err(e) => {
                // Parent unknown to the index: give the child a placeholder
                // and re-lay out everything (never on a consistent index).
                self.interval.insert(child, Interval { start: ROOT_END, end: ROOT_END - 1 });
                self.full_relayout(e);
            }
        }
    }

    /// The previous behaviour, as a last resort: re-lay out the whole tree
    /// from the root (O(index)). Only reached on an inconsistent layout.
    fn full_relayout(&mut self, why: ReindexError) {
        let Some(root) = self.root else { return };
        log::warn!("reachability: {} during a reindex; re-laying out the whole index", why.0);
        let mut ctx = Ctx::default();
        self.interval.insert(root, Interval { start: ROOT_START, end: ROOT_END });
        self.mark_dirty(root);
        if let Err(e) = self.propagate_interval(&mut ctx, root) {
            // More than 2^62 blocks: impossible in practice.
            log::error!("reachability: full re-layout failed: {}", e.0);
        }
    }

    /// Kaspa's `reindex_intervals`: find the nearest ancestor of `new_child`
    /// with room for its subtree and re-lay that subtree out, unless the walk
    /// leaves the reindex root's future first, in which case slack is
    /// reclaimed along the chain toward the root.
    fn reindex_intervals(&mut self, ctx: &mut Ctx, new_child: BlockHash, reindex_root: BlockHash) -> Res<()> {
        let mut current = new_child;
        loop {
            let iv = self.iv(&current)?;
            let size = self.count_subtrees(ctx, current)?;
            if iv.size() >= size {
                break;
            }
            let parent = self.parent_of(&current)?;
            if current == reindex_root {
                return err("the reindex root is out of capacity");
            }
            if self.strict_chain_ancestor(&parent, &reindex_root)? {
                // `parent` is on the chain below the reindex root: reclaim
                // slack along the chain instead of re-laying out the subtree
                // above `parent` (which holds the root and most recent
                // blocks). Doubles `current`'s capacity.
                return self.reindex_intervals_earlier_than_root(ctx, current, reindex_root, parent, size);
            }
            current = parent;
        }
        self.propagate_interval(ctx, current)
    }

    /// Subtree sizes of `block`'s subtree into `ctx` (iterative; Kaspa's
    /// `count_subtrees`). Returns the size of `block`'s subtree.
    fn count_subtrees(&self, ctx: &mut Ctx, block: BlockHash) -> Res<u64> {
        if let Some(s) = ctx.sizes.get(&block) {
            return Ok(*s);
        }
        let mut stack: Vec<(BlockHash, bool)> = vec![(block, false)];
        while let Some((n, children_done)) = stack.pop() {
            if ctx.sizes.contains_key(&n) {
                continue;
            }
            self.note_work();
            let children = self.children.get(&n);
            if children_done {
                let mut below = 0u64;
                if let Some(ch) = children {
                    for c in ch {
                        below += ctx.sizes.get(c).copied().ok_or(ReindexError("subtree size missing"))?;
                    }
                }
                ctx.sizes.insert(n, below + 1);
            } else {
                stack.push((n, true));
                if let Some(ch) = children {
                    for c in ch {
                        if !ctx.sizes.contains_key(c) {
                            stack.push((*c, false));
                        }
                    }
                }
            }
        }
        ctx.sizes.get(&block).copied().ok_or(ReindexError("subtree size missing"))
    }

    /// Kaspa's `propagate_interval`: re-lay out `block`'s subtree inside its
    /// current interval (BFS; each node's children split its capacity with
    /// `split_exponential`).
    fn propagate_interval(&mut self, ctx: &mut Ctx, block: BlockHash) -> Res<()> {
        self.count_subtrees(ctx, block)?;
        let mut queue = VecDeque::from([block]);
        while let Some(current) = queue.pop_front() {
            let children = self.children_of(&current);
            if children.is_empty() {
                continue;
            }
            let sizes: Vec<u64> = children.iter()
                .map(|c| ctx.sizes.get(c).copied().ok_or(ReindexError("subtree size missing")))
                .collect::<Res<_>>()?;
            let parts = self.children_capacity(&current)?.split_exponential(&sizes)?;
            for (c, iv) in children.iter().zip(parts) {
                self.set_interval(*c, iv);
            }
            queue.extend(children);
        }
        Ok(())
    }

    /// `allocation_block` (a child of `common_ancestor`, which is on the chain
    /// below `reindex_root`) needs `required` more slots.
    fn reindex_intervals_earlier_than_root(
        &mut self,
        ctx: &mut Ctx,
        allocation_block: BlockHash,
        reindex_root: BlockHash,
        common_ancestor: BlockHash,
        required: u64,
    ) -> Res<()> {
        let chosen = self.next_chain_ancestor(&reindex_root, &common_ancestor)?;
        if self.iv(&allocation_block)?.start < self.iv(&chosen)?.start {
            self.reclaim_interval_before(ctx, allocation_block, common_ancestor, chosen, reindex_root, required)
        } else {
            self.reclaim_interval_after(ctx, allocation_block, common_ancestor, chosen, reindex_root, required)
        }
    }

    fn reclaim_interval_before(
        &mut self,
        ctx: &mut Ctx,
        allocation_block: BlockHash,
        common_ancestor: BlockHash,
        chosen: BlockHash,
        reindex_root: BlockHash,
        required: u64,
    ) -> Res<()> {
        let mut slack_sum = 0u64;
        let mut path_len = 0u64;
        let mut path_slack_alloc = 0u64;
        let mut current = chosen;
        // Walk the chain from the chosen child toward the reindex root.
        loop {
            if current == reindex_root {
                // The root holds plenty of room: take what is still missing
                // plus fresh slack for every chain block walked.
                let offset = required.checked_add(REINDEX_SLACK.checked_mul(path_len).ok_or(ReindexError("overflow"))?)
                    .and_then(|x| x.checked_sub(slack_sum)).ok_or(ReindexError("underflow"))?;
                self.apply_and_propagate(ctx, current, offset, Interval::increase_start)?;
                self.offset_siblings_before(ctx, allocation_block, current, offset)?;
                path_slack_alloc = REINDEX_SLACK;
                break;
            }
            let slack = self.remaining_before(&current)?.size();
            slack_sum += slack;
            if slack_sum >= required {
                let offset = slack - (slack_sum - required);
                self.apply(current, offset, Interval::increase_start)?;
                self.offset_siblings_before(ctx, allocation_block, current, offset)?;
                break;
            }
            current = self.next_chain_ancestor(&reindex_root, &current)?;
            path_len += 1;
        }
        // Back down toward the common ancestor, passing the reclaimed room on.
        loop {
            current = self.parent_of(&current)?;
            if current == common_ancestor {
                break;
            }
            let slack = self.remaining_before(&current)?.size();
            let offset = slack.checked_sub(path_slack_alloc).ok_or(ReindexError("underflow"))?;
            self.apply(current, offset, Interval::increase_start)?;
            self.offset_siblings_before(ctx, allocation_block, current, offset)?;
        }
        Ok(())
    }

    fn reclaim_interval_after(
        &mut self,
        ctx: &mut Ctx,
        allocation_block: BlockHash,
        common_ancestor: BlockHash,
        chosen: BlockHash,
        reindex_root: BlockHash,
        required: u64,
    ) -> Res<()> {
        let mut slack_sum = 0u64;
        let mut path_len = 0u64;
        let mut path_slack_alloc = 0u64;
        let mut current = chosen;
        loop {
            if current == reindex_root {
                let offset = required.checked_add(REINDEX_SLACK.checked_mul(path_len).ok_or(ReindexError("overflow"))?)
                    .and_then(|x| x.checked_sub(slack_sum)).ok_or(ReindexError("underflow"))?;
                self.apply_and_propagate(ctx, current, offset, Interval::decrease_end)?;
                self.offset_siblings_after(ctx, allocation_block, current, offset)?;
                path_slack_alloc = REINDEX_SLACK;
                break;
            }
            let slack = self.remaining_after(&current)?.size();
            slack_sum += slack;
            if slack_sum >= required {
                let offset = slack - (slack_sum - required);
                self.apply(current, offset, Interval::decrease_end)?;
                self.offset_siblings_after(ctx, allocation_block, current, offset)?;
                break;
            }
            current = self.next_chain_ancestor(&reindex_root, &current)?;
            path_len += 1;
        }
        loop {
            current = self.parent_of(&current)?;
            if current == common_ancestor {
                break;
            }
            let slack = self.remaining_after(&current)?.size();
            let offset = slack.checked_sub(path_slack_alloc).ok_or(ReindexError("underflow"))?;
            self.apply(current, offset, Interval::decrease_end)?;
            self.offset_siblings_after(ctx, allocation_block, current, offset)?;
        }
        Ok(())
    }

    /// Shift the siblings before `current` up by `offset`, giving the room to
    /// `allocation_block` when it is one of them.
    fn offset_siblings_before(&mut self, ctx: &mut Ctx, allocation_block: BlockHash, current: BlockHash, offset: u64) -> Res<()> {
        let parent = self.parent_of(&current)?;
        let children = self.children_of(&parent);
        let pos = children.iter().position(|c| *c == current).ok_or(ReindexError("child not found"))?;
        for sibling in children[..pos].iter().rev() {
            if *sibling == allocation_block {
                self.apply_and_propagate(ctx, allocation_block, offset, Interval::increase_end)?;
                break;
            }
            self.apply_and_propagate(ctx, *sibling, offset, Interval::increase)?;
        }
        Ok(())
    }

    /// Shift the siblings after `current` down by `offset`, giving the room
    /// to `allocation_block` when it is one of them.
    fn offset_siblings_after(&mut self, ctx: &mut Ctx, allocation_block: BlockHash, current: BlockHash, offset: u64) -> Res<()> {
        let parent = self.parent_of(&current)?;
        let children = self.children_of(&parent);
        let pos = children.iter().position(|c| *c == current).ok_or(ReindexError("child not found"))?;
        for sibling in &children[pos + 1..] {
            if *sibling == allocation_block {
                self.apply_and_propagate(ctx, allocation_block, offset, Interval::decrease_start)?;
                break;
            }
            self.apply_and_propagate(ctx, *sibling, offset, Interval::decrease)?;
        }
        Ok(())
    }

    fn apply(&mut self, block: BlockHash, offset: u64, op: fn(&Interval, u64) -> Res<Interval>) -> Res<()> {
        let iv = op(&self.iv(&block)?, offset)?;
        self.set_interval(block, iv);
        Ok(())
    }

    fn apply_and_propagate(
        &mut self,
        ctx: &mut Ctx,
        block: BlockHash,
        offset: u64,
        op: fn(&Interval, u64) -> Res<Interval>,
    ) -> Res<()> {
        self.apply(block, offset, op)?;
        self.propagate_interval(ctx, block)
    }

    // ── reindex root (Kaspa's `try_advancing_reindex_root`) ────────────────

    /// Hint that `hint` is (a candidate for) the selected tip. Moves the
    /// reindex root to the chain block `REINDEX_DEPTH` below it, concentrating
    /// the intervals of the chain from the old root to the new one. Only a
    /// performance hint: the answers of the index never depend on it.
    pub fn hint_virtual_selected_parent(&mut self, hint: &BlockHash) {
        if !self.has(hint) || self.root.is_none() {
            return;
        }
        if self.reindex_root.is_none() {
            // A layout not managed by this scheme yet (loaded from an older
            // data dir): lay it out afresh from the tree root, then
            // concentrate from there.
            let mut ctx = Ctx::default();
            let root = self.root.expect("checked above");
            self.interval.insert(root, Interval { start: ROOT_START, end: ROOT_END });
            self.mark_dirty(root);
            if let Err(e) = self.propagate_interval(&mut ctx, root) {
                log::error!("reachability: re-layout for the reindex root failed: {}", e.0);
                return;
            }
            self.set_reindex_root(root);
        }
        if let Err(e) = self.try_advancing_reindex_root(*hint) {
            // Re-lay out from scratch and concentrate from the tree root
            // once; the index answers exactly either way.
            self.full_relayout(e);
            if let Some(root) = self.root {
                self.set_reindex_root(root);
                if let Err(e2) = self.try_advancing_reindex_root(*hint) {
                    log::warn!("reachability: reindex root not advanced ({})", e2.0);
                    self.full_relayout(e2);
                    self.set_reindex_root(root);
                }
            }
        }
    }

    fn set_reindex_root(&mut self, r: BlockHash) {
        if self.reindex_root != Some(r) {
            self.reindex_root = Some(r);
            // Persisted as a trailer of the tree root's record.
            if let Some(root) = self.root {
                self.mark_dirty(root);
            }
        }
    }

    fn try_advancing_reindex_root(&mut self, hint: BlockHash) -> Res<()> {
        let current = self.reindex_root.or(self.root).ok_or(ReindexError("no root"))?;
        let (mut ancestor, next) = self.find_next_reindex_root(current, hint)?;
        if current == next {
            return Ok(());
        }
        while ancestor != next {
            let child = self.next_chain_ancestor(&next, &ancestor)?;
            let mut ctx = Ctx::default();
            self.concentrate_interval(&mut ctx, ancestor, child, child == next)?;
            ancestor = child;
        }
        self.set_reindex_root(next);
        Ok(())
    }

    /// Kaspa's `find_next_reindex_root`: (the block to concentrate from, the
    /// new reindex root).
    fn find_next_reindex_root(&self, current: BlockHash, hint: BlockHash) -> Res<(BlockHash, BlockHash)> {
        if current == hint {
            return Ok((current, current));
        }
        let hint_height = self.height_of(&hint)?;
        let mut ancestor = current;
        let mut next = current;
        if self.chain_ancestor_or_self(&current, &hint)? {
            // Hysteresis (GnB): advance only once the root trails the hint by
            // 2 x REINDEX_DEPTH, then jump REINDEX_DEPTH at once. Moving one
            // block per block (Kaspa) re-lays out the window under the new
            // root every other block (the propagation gives each chain block
            // its parent's whole capacity, so the next root is not inside its
            // slack-narrowed allocation); jumping does it once per
            // REINDEX_DEPTH blocks. The window above the root stays bounded
            // (at most 2 x REINDEX_DEPTH chain blocks).
            let current_height = self.height_of(&current)?;
            if hint_height.saturating_sub(current_height) < 2 * REINDEX_DEPTH {
                return Ok((current, current));
            }
        } else {
            // A reorg: follow the other chain only once it leads by
            // REINDEX_SLACK (alternating reorgs cannot make the root
            // oscillate); then concentrate from the fork point.
            let current_height = self.height_of(&current)?;
            if hint_height < current_height || hint_height - current_height < REINDEX_SLACK {
                return Ok((current, current));
            }
            let common = self.find_common_tree_ancestor(hint, current)?;
            ancestor = common;
            next = common;
        }
        loop {
            if next == hint {
                break;
            }
            let child = self.next_chain_ancestor(&hint, &next)?;
            let child_height = self.height_of(&child)?;
            if hint_height < child_height {
                return err("hint below its chain ancestor");
            }
            if hint_height - child_height < REINDEX_DEPTH {
                break;
            }
            next = child;
        }
        Ok((ancestor, next))
    }

    fn find_common_tree_ancestor(&self, block: BlockHash, reindex_root: BlockHash) -> Res<BlockHash> {
        let mut current = block;
        loop {
            if self.chain_ancestor_or_self(&current, &reindex_root)? {
                return Ok(current);
            }
            current = self.parent_of(&current)?;
        }
    }

    /// Kaspa's `concentrate_interval`: pack `child`'s siblings tightly at the
    /// two ends of `parent`'s interval (keeping `REINDEX_SLACK` free slots
    /// outside them) and give `child` everything in between.
    fn concentrate_interval(&mut self, ctx: &mut Ctx, parent: BlockHash, child: BlockHash, is_final: bool) -> Res<()> {
        let children = self.children_of(&parent);
        let pos = children.iter().position(|c| *c == child).ok_or(ReindexError("child not found"))?;
        let before_sum = self.tighten_before(ctx, parent, &children[..pos])?;
        let after_sum = self.tighten_after(ctx, parent, &children[pos + 1..])?;
        self.expand_to_chosen(ctx, parent, child, before_sum, after_sum, is_final)
    }

    fn tighten_before(&mut self, ctx: &mut Ctx, parent: BlockHash, siblings: &[BlockHash]) -> Res<u64> {
        let sizes: Vec<u64> = siblings.iter().map(|b| self.count_subtrees(ctx, *b)).collect::<Res<_>>()?;
        let sum: u64 = sizes.iter().sum();
        if sum == 0 {
            return Ok(0);
        }
        let iv = self.iv(&parent)?;
        let start = iv.start.checked_add(REINDEX_SLACK).ok_or(ReindexError("overflow"))?;
        let region = Interval::new(start, start + sum - 1)?;
        if region.end >= iv.end {
            return err("parent too small for its siblings");
        }
        for (c, civ) in siblings.iter().zip(region.split_exact(&sizes)?) {
            self.set_interval(*c, civ);
            self.propagate_interval(ctx, *c)?;
        }
        Ok(sum)
    }

    fn tighten_after(&mut self, ctx: &mut Ctx, parent: BlockHash, siblings: &[BlockHash]) -> Res<u64> {
        let sizes: Vec<u64> = siblings.iter().map(|b| self.count_subtrees(ctx, *b)).collect::<Res<_>>()?;
        let sum: u64 = sizes.iter().sum();
        if sum == 0 {
            return Ok(0);
        }
        let iv = self.iv(&parent)?;
        let end = iv.end.checked_sub(REINDEX_SLACK + 1).ok_or(ReindexError("underflow"))?;
        let start = (end + 1).checked_sub(sum).ok_or(ReindexError("underflow"))?;
        let region = Interval::new(start, end)?;
        if region.start < iv.start {
            return err("parent too small for its siblings");
        }
        for (c, civ) in siblings.iter().zip(region.split_exact(&sizes)?) {
            self.set_interval(*c, civ);
            self.propagate_interval(ctx, *c)?;
        }
        Ok(sum)
    }

    fn expand_to_chosen(
        &mut self,
        ctx: &mut Ctx,
        parent: BlockHash,
        child: BlockHash,
        before_sum: u64,
        after_sum: u64,
        is_final: bool,
    ) -> Res<()> {
        let iv = self.iv(&parent)?;
        let start = iv.start.checked_add(before_sum + REINDEX_SLACK).ok_or(ReindexError("overflow"))?;
        let end = iv.end.checked_sub(after_sum + REINDEX_SLACK + 1).ok_or(ReindexError("underflow"))?;
        let allocation = Interval::new(start, end)?;
        let current = self.iv(&child)?;
        if is_final && !allocation.contains(&current) {
            // Lay the new root's subtree out with slack on both sides, so the
            // next advance most likely finds it inside its allocation.
            let narrowed = Interval::new(
                allocation.start.checked_add(REINDEX_SLACK).ok_or(ReindexError("overflow"))?,
                allocation.end.checked_sub(REINDEX_SLACK).ok_or(ReindexError("underflow"))?,
            )?;
            self.set_interval(child, narrowed);
            self.propagate_interval(ctx, child)?;
        }
        self.set_interval(child, allocation);
        Ok(())
    }

    // ── future covering set maintenance ─────────────────────────────────────

    fn insert_to_fcs(&mut self, block: BlockHash, new_future: BlockHash) {
        let new_iv = match self.interval.get(&new_future) {
            Some(iv) => *iv,
            None => return,
        };
        // Snapshot the current FCS for the search phase (avoids a simultaneous
        // mutable+immutable borrow of `self`).
        let fcs_snapshot = self.fcs.get(&block).cloned().unwrap_or_default();
        // rightmost element whose start <= new_iv.start
        let pp = partition_point(&fcs_snapshot, |h, this| {
            this.interval.get(h).map(|iv| iv.start <= new_iv.start).unwrap_or(false)
        }, self);
        if pp > 0 {
            let cand = fcs_snapshot[pp - 1];
            if let Some(civ) = self.interval.get(&cand) {
                if civ.contains(&new_iv) {
                    // `new_future` is already covered by an existing FCS block
                    // that is its chain ancestor — nothing to insert.
                    return;
                }
            }
        }
        // `new_future` is the newest block, so it cannot be an ancestor of any
        // existing FCS member — a plain sorted insert keeps the set correct.
        self.fcs.entry(block).or_default().insert(pp, new_future);
        self.mark_dirty(block);
    }

    // ── queries ─────────────────────────────────────────────────────────────

    /// Is `a` a selected-parent-tree (chain) ancestor of `b`? Strict: returns
    /// `false` when `a == b`. O(1).
    pub fn is_chain_ancestor(&self, a: &BlockHash, b: &BlockHash) -> bool {
        if a == b {
            return false;
        }
        match (self.interval.get(a), self.interval.get(b)) {
            (Some(ia), Some(ib)) => ia.contains(ib),
            _ => false,
        }
    }

    /// Is `a` a DAG ancestor of `b` (i.e. `a ∈ past(b)`)? Strict: `false` when
    /// `a == b`, matching the semantics of the legacy `is_ancestor`.
    /// O(log |FCS|).
    pub fn is_dag_ancestor(&self, a: &BlockHash, b: &BlockHash) -> bool {
        if a == b {
            return false;
        }
        if self.is_chain_ancestor(a, b) {
            return true;
        }
        let b_iv = match self.interval.get(b) {
            Some(iv) => *iv,
            None => return false,
        };
        let fcs = match self.fcs.get(a) {
            Some(f) => f,
            None => return false,
        };
        // rightmost FCS element whose start <= b.start
        let pp = partition_point(fcs, |h, this| {
            this.interval.get(h).map(|iv| iv.start <= b_iv.start).unwrap_or(false)
        }, self);
        if pp > 0 {
            let cand = fcs[pp - 1];
            // cand is a chain ancestor of b  ⇒  a → cand → b, so a reaches b.
            if self.is_chain_ancestor(&cand, b) || cand == *b {
                return true;
            }
        }
        false
    }

    /// Remove a childless leaf, exactly inverting a just-performed `add_block`
    /// (its slots go back to the free space of its parent). Used by the
    /// reorg-undo path. Returns `false` (no mutation) if the block is unknown
    /// or still has tree children.
    pub fn remove_leaf(&mut self, hash: &BlockHash, mergeset: &[BlockHash]) -> bool {
        if self.children.get(hash).map_or(false, |c| !c.is_empty()) {
            return false;
        }
        if !self.interval.contains_key(hash) {
            return false;
        }
        // Undo FCS insertions.
        for m in mergeset {
            if let Some(f) = self.fcs.get_mut(m) {
                if let Some(pos) = f.iter().position(|x| x == hash) {
                    f.remove(pos);
                    self.mark_dirty(*m);
                }
            }
        }
        // Undo tree edge.
        let parent = self.tree_parent.remove(hash);
        if let Some(parent) = parent {
            if let Some(ch) = self.children.get_mut(&parent) {
                if let Some(pos) = ch.iter().position(|x| x == hash) {
                    ch.remove(pos);
                }
            }
            self.mark_dirty(parent);
        }
        if self.reindex_root == Some(*hash) {
            self.reindex_root = parent.or(self.root);
            if let Some(root) = self.root {
                self.mark_dirty(root);
            }
        }
        self.interval.remove(hash);
        self.height.remove(hash);
        self.children.remove(hash);
        self.fcs.remove(hash);
        // Removal wins over any pending dirty flag for this block.
        self.dirty.remove(hash);
        self.tombstones.insert(*hash);
        true
    }

    // ── durable serialization (Phase 1) ──────────────────────────────────────

    /// Deterministically encode a single block's reachability record.
    ///
    /// Layout (all integers little-endian):
    /// ```text
    /// [start u64][end u64][rem_lo u64][rem_hi u64]
    /// [parent_tag u8][parent 32B]           // tag 0 = no tree parent (root)
    /// [children_len u32][children 32B*]      // insertion order preserved
    /// [fcs_len u32][fcs 32B*]                // interval-start-sorted order
    /// ['R' u8][reindex root 32B]             // tree root's record only (DAG-7)
    /// ```
    /// `rem_lo..rem_hi` is the free interval after the last child (derived;
    /// kept for the layout's stability). Byte-for-byte reproducible from equal
    /// in-memory state. Returns `None` if the block has no interval (never
    /// registered / already removed).
    fn encode_record(&self, hash: &BlockHash) -> Option<Vec<u8>> {
        let iv = self.interval.get(hash)?;
        let (lo, hi) = match self.remaining_after(hash) {
            Ok(r) => (r.start, r.end),
            Err(_) => (1, 0),
        };
        let children = self.children.get(hash).cloned().unwrap_or_default();
        let fcs = self.fcs.get(hash).cloned().unwrap_or_default();
        let mut out = Vec::with_capacity(41 + 4 + children.len() * 32 + 4 + fcs.len() * 32 + 33);
        out.extend_from_slice(&iv.start.to_le_bytes());
        out.extend_from_slice(&iv.end.to_le_bytes());
        out.extend_from_slice(&lo.to_le_bytes());
        out.extend_from_slice(&hi.to_le_bytes());
        match self.tree_parent.get(hash) {
            Some(p) => { out.push(1); out.extend_from_slice(p); }
            None => { out.push(0); out.extend_from_slice(&[0u8; 32]); }
        }
        out.extend_from_slice(&(children.len() as u32).to_le_bytes());
        for c in &children { out.extend_from_slice(c); }
        out.extend_from_slice(&(fcs.len() as u32).to_le_bytes());
        for f in &fcs { out.extend_from_slice(f); }
        if Some(*hash) == self.root {
            if let Some(r) = self.reindex_root {
                out.push(REINDEX_ROOT_TAG);
                out.extend_from_slice(&r);
            }
        }
        Some(out)
    }

    /// Drain the pending durability delta: `(upserts, deletes)`. `upserts` are
    /// `(block_hash, encoded_record)` pairs for every block whose record changed
    /// since the last drain; `deletes` are blocks removed from the index. The
    /// caller MUST persist all of these in the SAME atomic batch as the
    /// corresponding CF_DAG write, then this drain leaves the tracking sets
    /// empty. Idempotent when nothing changed (returns two empty vecs).
    pub fn take_persist_delta(&mut self) -> (Vec<(BlockHash, Vec<u8>)>, Vec<BlockHash>) {
        let mut upserts = Vec::with_capacity(self.dirty.len());
        // Deterministic order (sorted by hash) so identical logical state
        // produces identical write sequences — helps reproducibility/debugging.
        let mut dirty: Vec<BlockHash> = self.dirty.drain().collect();
        dirty.sort_unstable();
        for h in dirty {
            if let Some(rec) = self.encode_record(&h) {
                upserts.push((h, rec));
            }
        }
        let mut deletes: Vec<BlockHash> = self.tombstones.drain().collect();
        deletes.sort_unstable();
        (upserts, deletes)
    }

    /// Snapshot the ENTIRE index as `(block_hash, encoded_record)` pairs, in
    /// hash-sorted order. Used to write a freshly-rebuilt index in one batch and
    /// by round-trip tests. Does not touch the dirty/tombstone tracking.
    pub fn export_all(&self) -> Vec<(BlockHash, Vec<u8>)> {
        let mut hashes: Vec<BlockHash> = self.interval.keys().copied().collect();
        hashes.sort_unstable();
        hashes.iter().filter_map(|h| self.encode_record(h).map(|r| (*h, r))).collect()
    }

    /// Rebuild the whole index in-memory from persisted records + the stored
    /// root. Replaces any current state. Returns `Err` on a malformed record.
    /// After this the dirty/tombstone sets are empty (the on-disk copy is
    /// authoritative and already matches memory). Tree heights are recomputed;
    /// the reindex root comes from the root's record (absent in a data dir
    /// written before audit DAG-7's reindex-root scheme: the first advance
    /// then re-lays the index out once).
    pub fn load_from_records(
        &mut self,
        records: &[(BlockHash, Vec<u8>)],
        root: Option<BlockHash>,
    ) -> Result<(), String> {
        self.interval.clear();
        self.tree_parent.clear();
        self.children.clear();
        self.height.clear();
        self.fcs.clear();
        self.dirty.clear();
        self.tombstones.clear();
        self.root = root;
        self.reindex_root = None;
        let mut reindex_root = None;
        for (h, bytes) in records {
            let (iv, _rem, parent, children, fcs, rr) = decode_record(bytes)
                .map_err(|e| format!("reachability record for {} malformed: {e}", hex::encode(&h[..4])))?;
            self.interval.insert(*h, iv);
            if let Some(p) = parent { self.tree_parent.insert(*h, p); }
            self.children.insert(*h, children);
            self.fcs.insert(*h, fcs);
            if Some(*h) == root {
                reindex_root = rr;
            }
        }
        // Heights: breadth-first from the root.
        if let Some(r) = root {
            let mut queue = VecDeque::from([(r, 0u64)]);
            while let Some((h, d)) = queue.pop_front() {
                self.height.insert(h, d);
                if let Some(ch) = self.children.get(&h) {
                    queue.extend(ch.iter().map(|c| (*c, d + 1)));
                }
            }
        }
        self.reindex_root = reindex_root.filter(|r| self.interval.contains_key(r));
        Ok(())
    }
}

/// A decoded record: interval, stored free range, tree parent, children,
/// future covering set, and (tree root only) the reindex root.
type DecodedRecord = (Interval, (u64, u64), Option<BlockHash>, Vec<BlockHash>, Vec<BlockHash>, Option<BlockHash>);

/// Decode a record produced by `ReachabilityStore::encode_record`.
fn decode_record(b: &[u8]) -> Result<DecodedRecord, String> {
    let mut o = 0usize;
    let rd_u64 = |b: &[u8], o: &mut usize| -> Result<u64, String> {
        if *o + 8 > b.len() { return Err("truncated u64".into()); }
        let v = u64::from_le_bytes(
            b[*o..*o + 8].try_into().map_err(|_| "u64 slice".to_string())?,
        );
        *o += 8; Ok(v)
    };
    let rd_hash = |b: &[u8], o: &mut usize| -> Result<BlockHash, String> {
        if *o + 32 > b.len() { return Err("truncated hash".into()); }
        let mut h = [0u8; 32]; h.copy_from_slice(&b[*o..*o + 32]); *o += 32; Ok(h)
    };
    let start = rd_u64(b, &mut o)?;
    let end = rd_u64(b, &mut o)?;
    let lo = rd_u64(b, &mut o)?;
    let hi = rd_u64(b, &mut o)?;
    if o >= b.len() { return Err("truncated parent tag".into()); }
    let tag = b[o]; o += 1;
    let parent_raw = rd_hash(b, &mut o)?;
    let parent = if tag == 1 { Some(parent_raw) } else { None };
    if o + 4 > b.len() { return Err("truncated children len".into()); }
    let clen = u32::from_le_bytes(b[o..o + 4].try_into().map_err(|_| "children len slice".to_string())?) as usize; o += 4;
    let mut children = Vec::with_capacity(clen);
    for _ in 0..clen { children.push(rd_hash(b, &mut o)?); }
    if o + 4 > b.len() { return Err("truncated fcs len".into()); }
    let flen = u32::from_le_bytes(b[o..o + 4].try_into().map_err(|_| "fcs len slice".to_string())?) as usize; o += 4;
    let mut fcs = Vec::with_capacity(flen);
    for _ in 0..flen { fcs.push(rd_hash(b, &mut o)?); }
    let reindex_root = if b.len() >= o + 33 && b[o] == REINDEX_ROOT_TAG {
        o += 1;
        Some(rd_hash(b, &mut o)?)
    } else {
        None
    };
    if start == 0 || end.checked_add(1).is_none_or(|e1| e1 < start) {
        return Err("malformed interval".into());
    }
    Ok((Interval { start, end }, (lo, hi), parent, children, fcs, reindex_root))
}

/// `Vec` partition point where the elements form a prefix satisfying `pred`.
/// Reimplemented (rather than `slice::partition_point`) because the predicate
/// needs `&ReachabilityStore` to look up intervals.
fn partition_point<F>(v: &[BlockHash], pred: F, store: &ReachabilityStore) -> usize
where
    F: Fn(&BlockHash, &ReachabilityStore) -> bool,
{
    let mut lo = 0usize;
    let mut hi = v.len();
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if pred(&v[mid], store) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo
}

/// Unbounded brute-force DAG-ancestry oracle over the raw parent graph.
///
/// This is the ground truth the interval index is validated against. It is the
/// *correct* (unbounded) answer — note this can differ from the legacy bounded
/// `is_ancestor` when the legacy bound is hit; that difference is precisely the
/// latent-consensus question the differential test exists to answer.
pub fn brute_force_is_ancestor(store: &DagStore, a: &BlockHash, b: &BlockHash) -> bool {
    use std::collections::{HashSet, VecDeque};
    if a == b {
        return false;
    }
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    if let Some(d) = store.get(b) {
        for p in &d.parents {
            queue.push_back(*p);
        }
    }
    while let Some(h) = queue.pop_front() {
        if &h == a {
            return true;
        }
        if visited.insert(h) {
            if let Some(d) = store.get(&h) {
                for p in &d.parents {
                    if !visited.contains(p) {
                        queue.push_back(*p);
                    }
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(n: u16) -> BlockHash {
        let mut out = [0u8; 32];
        out[0] = (n >> 8) as u8;
        out[1] = (n & 0xff) as u8;
        out
    }

    #[test]
    fn chain_ancestry_linear() {
        let mut r = ReachabilityStore::new();
        let g = h(0);
        r.add_genesis(g);
        let mut prev = g;
        let mut all = vec![g];
        for i in 1..=50u16 {
            let b = h(i);
            r.add_block(b, &prev, &[]); // linear: empty mergeset
            prev = b;
            all.push(b);
        }
        // Every earlier block is an ancestor of every later block.
        for (i, a) in all.iter().enumerate() {
            for b in all.iter().skip(i + 1) {
                assert!(r.is_dag_ancestor(a, b), "{i} should be ancestor");
                assert!(!r.is_dag_ancestor(b, a), "reverse must be false");
            }
            assert!(!r.is_dag_ancestor(a, a), "strict: not self-ancestor");
        }
    }

    #[test]
    fn diamond_merge_ancestry() {
        // g -> a, g -> b, c merges {a,b} (selected_parent = a, mergeset = {b})
        let mut r = ReachabilityStore::new();
        let (g, a, b, c) = (h(0), h(1), h(2), h(3));
        r.add_genesis(g);
        r.add_block(a, &g, &[]);
        r.add_block(b, &g, &[]);
        // suppose a is selected parent of c; b is merged
        r.add_block(c, &a, &[b]);
        assert!(r.is_dag_ancestor(&g, &c));
        assert!(r.is_dag_ancestor(&a, &c));
        assert!(r.is_dag_ancestor(&b, &c), "merge-edge ancestry via FCS");
        assert!(!r.is_dag_ancestor(&a, &b), "siblings are anticone");
        assert!(!r.is_dag_ancestor(&b, &a));
        assert!(!r.is_dag_ancestor(&c, &a));
    }

    /// Serialize → clear → reload must answer every ancestry query identically.
    #[test]
    fn persist_roundtrip_matches() {
        let mut r = ReachabilityStore::new();
        let g = h(0);
        r.add_genesis(g);
        // Build a merging DAG that forces at least one reindex + non-trivial FCS.
        let mut prev = g;
        let mut all = vec![g];
        for i in 1..=40u16 {
            let l = h(i);
            let rr = h(1000 + i);
            let m = h(2000 + i);
            r.add_block(l, &prev, &[]);
            r.add_block(rr, &prev, &[]);
            r.add_block(m, &l, &[rr]); // selected_parent = l, merges rr
            all.push(l); all.push(rr); all.push(m);
            prev = m;
        }
        let root = r.root();
        let records = r.export_all();

        let mut restored = ReachabilityStore::new();
        restored.load_from_records(&records, root).expect("reload");
        assert_eq!(restored.len(), r.len());
        for a in &all {
            for b in &all {
                assert_eq!(
                    r.is_dag_ancestor(a, b),
                    restored.is_dag_ancestor(a, b),
                    "roundtrip mismatch for pair"
                );
            }
        }
    }

    /// The structural invariant every answer relies on: each child's interval
    /// is non-empty and inside its parent's children capacity, and siblings
    /// are disjoint, in child order.
    fn check_layout(r: &ReachabilityStore) {
        for (p, children) in &r.children {
            let cap = r.children_capacity(p).expect("parent interval");
            let mut prev_end: Option<u64> = None;
            for c in children {
                let iv = r.iv(c).expect("child interval");
                assert!(iv.size() > 0, "empty interval");
                assert!(cap.contains(&iv), "child outside its parent's capacity");
                if let Some(e) = prev_end {
                    assert!(e < iv.start, "siblings overlap or are out of order");
                }
                prev_end = Some(iv.end);
            }
        }
    }

    fn tree_ancestor(r: &ReachabilityStore, a: &BlockHash, b: &BlockHash) -> bool {
        let mut x = *b;
        while let Some(p) = r.tree_parent.get(&x) {
            if p == a {
                return true;
            }
            x = *p;
        }
        false
    }

    /// A random tree — mostly extending a recent block, with deep side blocks
    /// and genesis siblings — grown with the selected-tip hint the GhostDAG
    /// gives (the newest deepest block): every layout the reindexing produces
    /// is well formed, `count_subtrees` matches a direct count, and the index
    /// answers exactly.
    #[test]
    fn random_tree_with_hints_answers_exactly() {
        let mut r = ReachabilityStore::new();
        let g = h(0);
        r.add_genesis(g);
        let mut all = vec![g];
        let mut deepest = g;
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        for i in 1..=1_500u16 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let parent = match state % 10 {
                0 => g,
                1 => all[(state as usize / 10) % all.len()],
                _ => all[all.len() - 1 - (state as usize / 10) % all.len().min(3)],
            };
            let b = h(i);
            r.add_block(b, &parent, &[]);
            all.push(b);
            if r.height[&b] > r.height[&deepest] {
                deepest = b;
                r.hint_virtual_selected_parent(&b);
            }
        }
        check_layout(&r);
        let mut ctx = Ctx::default();
        for n in all.iter().rev() {
            let mut direct = 0u64;
            let mut stack = vec![*n];
            while let Some(x) = stack.pop() {
                direct += 1;
                stack.extend(r.children[&x].iter().copied());
            }
            assert_eq!(r.count_subtrees(&mut ctx, *n).unwrap(), direct);
        }
        for a in all.iter().step_by(7) {
            for b in all.iter().step_by(5) {
                assert_eq!(r.is_dag_ancestor(a, b), tree_ancestor(&r, a, b));
            }
        }
        let root = r.reindex_root().expect("managed");
        assert!(r.height[&deepest] - r.height[&root] < 2 * REINDEX_DEPTH, "the reindex root trails the tip");
    }

    /// Audit DAG-7: on a 6,000-block chain whose reindex root follows the tip,
    /// a deep side block, many side blocks under the same parent and a
    /// genesis sibling each cost a bounded amount of reindexing (the old
    /// scheme re-laid out the whole subtree under the parent: thousands of
    /// nodes), and the root's record carries the reindex root through a
    /// persistence round trip.
    #[test]
    fn deep_side_blocks_reindex_a_bounded_window() {
        let mut r = ReachabilityStore::new();
        let g = h(0);
        r.add_genesis(g);
        let mut chain = vec![g];
        for i in 1..=6_000u16 {
            let b = h(i);
            r.add_block(b, chain.last().unwrap(), &[]);
            r.hint_virtual_selected_parent(&b);
            chain.push(b);
        }
        let root = r.reindex_root().expect("managed");
        assert!(r.height[&root] >= 6_000 - 2 * REINDEX_DEPTH, "the reindex root follows the tip");
        let mut n = 10_000u16;
        let mut worst = 0u64;
        let mut add = |r: &mut ReachabilityStore, parent: BlockHash| {
            n += 1;
            let before = r.reindex_work();
            r.add_block(h(n), &parent, &[]);
            worst = worst.max(r.reindex_work() - before);
        };
        add(&mut r, chain[3_000]);
        add(&mut r, g);
        for _ in 0..50 {
            add(&mut r, chain[2_000]);
        }
        for _ in 0..50 {
            add(&mut r, g);
        }
        assert!(worst <= 500, "one deep insertion cost {worst} reindex steps");
        check_layout(&r);
        for a in chain.iter().step_by(97) {
            for b in chain.iter().step_by(89) {
                assert_eq!(r.is_dag_ancestor(a, b), tree_ancestor(&r, a, b));
            }
        }

        let rr = r.reindex_root();
        let records = r.export_all();
        let mut back = ReachabilityStore::new();
        back.load_from_records(&records, r.root()).unwrap();
        assert_eq!(back.reindex_root(), rr, "persisted with the root's record");
        assert_eq!(back.export_all(), records);
        // A record set without the trailer (an older data dir) loads
        // unmanaged; the first hint re-lays it out and keeps answering.
        let stripped: Vec<(BlockHash, Vec<u8>)> = records.iter().map(|(k, v)| {
            if Some(*k) == r.root() { (*k, v[..v.len() - 33].to_vec()) } else { (*k, v.clone()) }
        }).collect();
        let mut old = ReachabilityStore::new();
        old.load_from_records(&stripped, r.root()).unwrap();
        assert_eq!(old.reindex_root(), None);
        old.hint_virtual_selected_parent(chain.last().unwrap());
        assert!(old.reindex_root().is_some());
        check_layout(&old);
        for a in chain.iter().step_by(101) {
            for b in chain.iter().step_by(83) {
                assert_eq!(old.is_dag_ancestor(a, b), tree_ancestor(&old, a, b));
            }
        }
    }

    /// The incremental delta drain reproduces the same records as a full export.
    #[test]
    fn delta_drain_reconstructs_full_index() {
        let mut r = ReachabilityStore::new();
        let g = h(0);
        r.add_genesis(g);
        let mut prev = g;
        for i in 1..=25u16 {
            let a = h(i);
            let b = h(500 + i);
            r.add_block(a, &prev, &[]);
            r.add_block(b, &a, &[]); // linear-ish with occasional sibling
            prev = a;
            let _ = b;
        }
        // Apply the drained upserts into a fresh map and compare to export_all.
        let (upserts, deletes) = r.take_persist_delta();
        assert!(deletes.is_empty(), "no removals happened");
        let mut disk: std::collections::HashMap<BlockHash, Vec<u8>> =
            upserts.into_iter().collect();
        // A second drain must be empty (idempotent).
        let (u2, d2) = r.take_persist_delta();
        assert!(u2.is_empty() && d2.is_empty(), "delta must be empty after drain");
        let full: std::collections::HashMap<BlockHash, Vec<u8>> =
            r.export_all().into_iter().collect();
        // Every current block's delta-record equals its full-export record.
        for (h, rec) in &full {
            assert_eq!(disk.remove(h).as_ref(), Some(rec), "record mismatch");
        }
        assert!(disk.is_empty(), "delta had records for unknown blocks");
    }
}
