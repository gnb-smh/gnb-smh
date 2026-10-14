//! Bloch-SIS Protocol — GhostDAG Consensus (PHANTOM Protocol)
//!
//! Implementation based on:
//!   Sompolinsky, Wyborski, Zohar — "PHANTOM GHOSTDAG: A Scalable
//!   Generalization of Nakamoto Consensus" (2021)
//!
//! Reference: kaspanet/rusty-kaspa consensus/src/processes/ghostdag/
//!
//! Key invariants:
//!   - selected_parent = argmax(blue_work) over parents
//!   - blue_score(B) = blue_score(selected_parent) + |mergeset_blues(B)| + 1
//!   - Block C is blue in B's context iff |anticone(C) ∩ blue_set(B)| ≤ K
//!   - Both candidate and existing blue blocks satisfy the K constraint
//!
//! Performance:
//!   - is_ancestor: O(height_diff) with blue_score/height shortcuts (vs O(DAG) naive)
//!   - past_blue_set: bounded to K*100 depth on selected chain (audit H-5)
//!   - blue_work: cumulative chain work (Kaspa-aligned)
//!
//! Hardening activation (audit 2026-10-14, DAG-3 / DAG-4 / DAG-7):
//!   Blocks whose `GhostdagData::height` is at or above
//!   [`GhostDAG::hardening_activation_height`] (mainnet 110,000; testnet and
//!   regtest 0, see `crate::core::activation`) are processed under corrected
//!   rules. Blocks below it are processed exactly as before.
//!   - blue_work = sp.blue_work + work of the mergeset blues + own work, i.e.
//!     the work of blue(B) ∪ {B} (DAG-3). Below activation: sp.blue_work + own.
//!   - coloring: exact GHOSTDAG k-cluster rule over the full blue anticone,
//!     selected chain included (DAG-4). Below activation: the old coloring.
//!   - mergeset at most [`MAX_MERGESET_SIZE`] blocks (selected parent
//!     included) and no red merged from below the merge-depth root
//!     ([`MERGE_DEPTH`]) unless a merged blue covers it (DAG-7).
//!
//!   The ledger stays selected-chain-only at every height: transactions of
//!   merged blocks are never applied (docs/CONSENSUS.md).

use std::collections::{HashMap, HashSet, VecDeque};
use serde::{Serialize, Deserialize};
use log::warn;
use crate::core::GHOSTDAG_K;
use crate::core::activation;

/// Maximum mergeset size of a block at or above the hardening activation,
/// counting the selected parent (Kaspa's convention: `mergeset_blues` there
/// includes the selected parent; GnB stores it separately, so the check is
/// `1 + |mergeset_blues| + |mergeset_reds| <= MAX_MERGESET_SIZE`).
///
/// Why 180: it is Kaspa's mainnet `mergeset_size_limit`, in production since
/// 2021. With k = 10 at most k + 1 = 11 entries are blue, so the limit leaves
/// 169 slots for reds: at the 30 s target an honest block merges a few blocks,
/// and a partition that produced up to ~170 blocks on the losing side can still
/// be merged in one block (larger ones are merged over several blocks, or not
/// at all once they fall below the merge-depth root). The limit bounds the
/// coloring cost of one block to 179 candidates, each checked with the k + 1
/// early-exit walk below (measured in `node/tests/fix_ghostdag_dag7_perf.rs`).
/// It is below `MAX_PARENTS` (256), so templates must pick their parents with
/// [`GhostDAG::select_parents_for_template`].
pub const MAX_MERGESET_SIZE: usize = 180;

/// Merge depth, in blue score, for blocks at or above the hardening
/// activation. The merge-depth root of a block B is the highest block of B's
/// selected chain whose blue_score is at most `B.blue_score - MERGE_DEPTH`. A
/// red block in B's mergeset must be in the future of that root, or in the past
/// of a mergeset blue that is (Kaspa's "kosherizing" rule). Blues need no check:
/// a blue that deep would have more than k blues in its anticone.
///
/// Why 360: 3 hours at the 30 s target, comparable to Kaspa's one hour and far
/// above any propagation delay, yet well inside the 1,000-block reorg and
/// finality depth (`CHECKPOINT_DEPTH`), as Kaspa keeps merge depth below its
/// finality depth.
pub const MERGE_DEPTH: u64 = 360;

pub mod reachability;
use reachability::ReachabilityStore;

// ── Types ────────────────────────────────────────────────────────────────────

pub type BlockHash = [u8; 32];

/// All GhostDAG consensus data for a single block.
/// Mirrors kaspa-rs `GhostdagData`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GhostdagData {
    /// Number of blue blocks in this block's past (including itself if blue)
    pub blue_score: u64,
    /// Accumulated PoW work of blue blocks (for tie-breaking)
    pub blue_work: u128,
    /// Selected parent — parent with highest blue_score (ties broken by hash)
    pub selected_parent: Option<BlockHash>,
    /// Blue blocks from the mergeset (topologically ordered)
    pub mergeset_blues: Vec<BlockHash>,
    /// Red blocks from the mergeset
    pub mergeset_reds: Vec<BlockHash>,
    /// For each blue block in mergeset: its anticone size w.r.t. this block's blue set
    pub blues_anticone_sizes: HashMap<BlockHash, usize>,
    /// This block's parents
    pub parents: Vec<BlockHash>,
    /// Height (longest path from genesis)
    pub height: u64,
    /// Timestamp
    pub timestamp: u64,
}

impl GhostdagData {
    pub fn genesis() -> Self {
        Self {
            blue_score: 0,
            blue_work: 0,
            selected_parent: None,
            mergeset_blues: vec![],
            mergeset_reds: vec![],
            blues_anticone_sizes: HashMap::new(),
            parents: vec![],
            height: 0,
            timestamp: 0,
        }
    }
}

// ── Sprint Y (M-2): GhostdagData integrity chain ─────────────────────────────
//
// A hash-chain over per-block GhostdagData, persisted alongside CF_DAG in a
// separate column family (`CF_DAG_INTEGRITY`). Each block's integrity hash
// covers its own canonical bytes plus its selected-parent's integrity hash,
// so tampering with any ancestor's data (or swapping an ancestor for a
// competing-chain block) breaks the chain at that point and every
// descendant validates as mismatched.
//
// See `load_persisted_validated` and `docs/audit/AUDIT-2026-04-20.md` (M-2)
// for the full threat model and the scope of what this does/doesn't protect
// against.

/// Serialize a `GhostdagData` deterministically, regardless of the
/// `HashMap` iteration order for `blues_anticone_sizes`. The output is
/// the canonical pre-image for `compute_integrity_hash`.
///
/// Contract: any two `GhostdagData` values that are structurally equal
/// (same field values, same map contents) MUST produce byte-identical
/// output. Breaking this contract breaks the integrity chain for every
/// node in existence.
pub fn canonical_encode(d: &GhostdagData) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(&d.blue_score.to_le_bytes());
    out.extend_from_slice(&d.blue_work.to_le_bytes());
    out.extend_from_slice(&d.height.to_le_bytes());
    out.extend_from_slice(&d.timestamp.to_le_bytes());

    // selected_parent: 1 byte tag + 32 bytes of hash (or 32 zeros for None)
    match &d.selected_parent {
        Some(sp) => {
            out.push(1);
            out.extend_from_slice(sp);
        }
        None => {
            out.push(0);
            out.extend_from_slice(&[0u8; 32]);
        }
    }

    // parents: length-prefixed, SORTED lexicographically for determinism.
    // Block validation order doesn't depend on parent vector order and
    // the DAG doesn't ascribe meaning to it, so canonical ordering here
    // is safe and necessary.
    let mut parents_sorted = d.parents.clone();
    parents_sorted.sort();
    out.extend_from_slice(&(parents_sorted.len() as u32).to_le_bytes());
    for p in &parents_sorted {
        out.extend_from_slice(p);
    }

    // mergeset_blues: insertion order IS meaningful (topologically sorted,
    // ancestors-first per Kaspa convention). Preserve order verbatim —
    // changing it would change GhostDAG semantics.
    out.extend_from_slice(&(d.mergeset_blues.len() as u32).to_le_bytes());
    for m in &d.mergeset_blues {
        out.extend_from_slice(m);
    }

    // mergeset_reds: same — order-preserving.
    out.extend_from_slice(&(d.mergeset_reds.len() as u32).to_le_bytes());
    for m in &d.mergeset_reds {
        out.extend_from_slice(m);
    }

    // blues_anticone_sizes is the single HashMap in the struct. Its
    // iteration order is non-deterministic across hasher seeds. Sort
    // by key (lexicographic on BlockHash) so the canonical form is
    // stable across machines and across process restarts.
    let mut anticone: Vec<(&BlockHash, &usize)> = d.blues_anticone_sizes.iter().collect();
    anticone.sort_by_key(|(k, _)| *k);
    out.extend_from_slice(&(anticone.len() as u32).to_le_bytes());
    for (k, v) in anticone {
        out.extend_from_slice(k);
        out.extend_from_slice(&(*v as u64).to_le_bytes());
    }

    out
}

/// Hash-chain link: SHA-256 of (block_hash || canonical_encode(data) ||
/// parent_integrity_hash). For genesis, parent_integrity_hash is all zeros.
///
/// Chaining guarantees that altering any ancestor's GhostdagData
/// invalidates every descendant's integrity hash, because the chain
/// carries forward via selected_parent.
pub fn compute_integrity_hash(
    block_hash: &BlockHash,
    data: &GhostdagData,
    parent_integrity: &[u8; 32],
) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut h = Sha256::new();
    h.update(block_hash);
    h.update(&canonical_encode(data));
    h.update(parent_integrity);
    h.finalize().into()
}

/// Outcome of `GhostDAG::load_persisted_validated`.
#[derive(Debug)]
pub struct LoadedIntegrity {
    pub blocks_loaded: usize,
    /// True if CF_DAG_INTEGRITY was empty on load and the caller should
    /// persist `fresh_map`. Indicates first boot after Sprint Y upgrade.
    pub self_healed:   bool,
    /// Newly-computed integrity map the caller must persist if self_healed.
    pub fresh_map:     Option<std::collections::HashMap<BlockHash, [u8; 32]>>,
}

/// Errors that can be returned by `load_persisted_validated`. Every
/// variant is, in the intended threat model, fatal: the caller should
/// log loudly and exit rather than continue with an unverifiable DAG.
#[derive(Debug)]
pub enum IntegrityError {
    /// Some blocks have integrity records and some don't. Ambiguous —
    /// could be crash mid-write or could be targeted tampering.
    PartialCoverage { present: usize, total: usize },
    /// A block referenced a selected_parent that didn't appear in the
    /// loaded set. Should never happen on a clean DB.
    ParentNotLoaded { block: BlockHash, parent: BlockHash },
    /// CF_DAG_INTEGRITY had records but this specific block's is missing.
    MissingEntry { block: BlockHash },
    /// The stored integrity hash does not match what we recompute from
    /// the stored GhostdagData + parent integrity. Strongest signal
    /// of tampering or corruption.
    ChainMismatch {
        block:    BlockHash,
        expected: [u8; 32],
        stored:   [u8; 32],
    },
}

impl std::fmt::Display for IntegrityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IntegrityError::PartialCoverage { present, total } => write!(f,
                "CF_DAG_INTEGRITY has partial coverage: {}/{} blocks have \
                 integrity records. This is ambiguous — either a crash \
                 mid-write or targeted deletion. Investigate manually.",
                present, total),
            IntegrityError::ParentNotLoaded { block, parent } => write!(f,
                "block {} references selected_parent {} which was not \
                 persisted. The DAG store is incomplete — possible \
                 partial-write corruption.",
                hex::encode(&block[..8]), hex::encode(&parent[..8])),
            IntegrityError::MissingEntry { block } => write!(f,
                "block {} is in CF_DAG but has no integrity record in \
                 CF_DAG_INTEGRITY. A targeted deletion, or partial \
                 recovery from backup.",
                hex::encode(&block[..8])),
            IntegrityError::ChainMismatch { block, expected, stored } => write!(f,
                "integrity mismatch on block {}: expected {} but stored \
                 {}. The GhostdagData for this block, or for one of its \
                 ancestors, has been altered since it was written.",
                hex::encode(&block[..8]),
                hex::encode(&expected[..8]),
                hex::encode(&stored[..8])),
        }
    }
}

impl std::error::Error for IntegrityError {}

// ── DAG Store ────────────────────────────────────────────────────────────────

/// In-memory DAG — production would use RocksDB for this
pub struct DagStore {
    /// GhostDAG data per block
    pub data: HashMap<BlockHash, GhostdagData>,
    /// Children index: block → set of blocks that reference it as parent
    pub children: HashMap<BlockHash, HashSet<BlockHash>>,
    /// Current tips (leaf blocks with no children)
    pub tips: HashSet<BlockHash>,
    /// Genesis hash
    pub genesis: Option<BlockHash>,
}

impl DagStore {
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
            children: HashMap::new(),
            tips: HashSet::new(),
            genesis: None,
        }
    }

    pub fn get(&self, hash: &BlockHash) -> Option<&GhostdagData> {
        self.data.get(hash)
    }

    pub fn has(&self, hash: &BlockHash) -> bool {
        self.data.contains_key(hash)
    }

    pub fn insert(&mut self, hash: BlockHash, data: GhostdagData) {
        // Remove parents from tips (they now have a child)
        for p in &data.parents {
            self.tips.remove(p);
            self.children.entry(*p).or_default().insert(hash);
        }
        // This block is a new tip
        self.tips.insert(hash);
        self.data.insert(hash, data);
    }
}

// ── Reachability ─────────────────────────────────────────────────────────────

/// Check if `ancestor` is in the past of `descendant`.
///
/// Optimizations over naive BFS:
///   1. Blue-score shortcut: if ancestor.blue_score > descendant.blue_score,
///      ancestor cannot be in descendant's past (DAG is monotonic).
///   2. Height shortcut: if ancestor.height >= descendant.height, impossible.
///   3. Bounded BFS: stops after visiting MAX_REACHABILITY_DEPTH levels.
///
/// Production improvement: interval-based reachability tree (O(1)).
const MAX_REACHABILITY_DEPTH: u64 = 1024;

pub fn is_ancestor(
    store: &DagStore,
    ancestor: &BlockHash,
    descendant: &BlockHash,
) -> bool {
    if ancestor == descendant { return false; }

    // Shortcut: compare blue_score — ancestor must have lower score
    let a_score = store.get(ancestor).map(|d| d.blue_score).unwrap_or(u64::MAX);
    let d_score = store.get(descendant).map(|d| d.blue_score).unwrap_or(0);
    if a_score >= d_score { return false; }

    // Shortcut: compare height — ancestor must have lower height
    let a_height = store.get(ancestor).map(|d| d.height).unwrap_or(u64::MAX);
    let d_height = store.get(descendant).map(|d| d.height).unwrap_or(0);
    if a_height >= d_height { return false; }

    // Bounded BFS from descendant backwards.
    //
    // Audit M-3 fix: when the height-diff between the two blocks would
    // exceed MAX_REACHABILITY_DEPTH, we silently clamp and the BFS might
    // fail to find a true ancestor. That's a silent consensus split at
    // the DAG-reachability layer. Log a warning when the clamp triggers
    // so production deployments can spot it before it matters.
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(*descendant);
    let raw_depth_limit = d_height.saturating_sub(a_height) + 1;
    let depth_limit = raw_depth_limit.min(MAX_REACHABILITY_DEPTH);
    if raw_depth_limit > MAX_REACHABILITY_DEPTH {
        warn!(
            "is_ancestor: height-diff {} exceeds MAX_REACHABILITY_DEPTH={} \
             when checking ancestor {} → descendant {}. Clamping bound; \
             ancestry check may return a false negative. If this repeats, \
             a reachability tree upgrade is required for correctness.",
            raw_depth_limit,
            MAX_REACHABILITY_DEPTH,
            hex::encode(ancestor),
            hex::encode(descendant),
        );
    }
    let mut depth = 0u64;

    while let Some(h) = queue.pop_front() {
        if &h == ancestor { return true; }
        if visited.insert(h) {
            if let Some(d) = store.get(&h) {
                // Don't go below ancestor's height
                if d.height > a_height || d.height == 0 {
                    for p in &d.parents {
                        if !visited.contains(p) {
                            queue.push_back(*p);
                        }
                    }
                }
            }
        }
        depth += 1;
        if depth > depth_limit * 10 { break; } // safety bound on visited nodes
    }
    false
}

/// Compute past(B) — all ancestors of B (exclusive of B itself)
fn compute_past(store: &DagStore, b: &BlockHash) -> HashSet<BlockHash> {
    let mut past = HashSet::new();
    let mut queue = VecDeque::new();
    if let Some(data) = store.get(b) {
        for p in &data.parents {
            queue.push_back(*p);
        }
    }
    while let Some(h) = queue.pop_front() {
        if past.insert(h) {
            if let Some(data) = store.get(&h) {
                for p in &data.parents {
                    if !past.contains(p) {
                        queue.push_back(*p);
                    }
                }
            }
        }
    }
    past
}

/// Compute the blue set of block B (all blue blocks in past(B))
#[allow(dead_code)]
fn compute_blue_set(store: &DagStore, b: &BlockHash) -> HashSet<BlockHash> {
    let past = compute_past(store, b);
    let mut blue_set = HashSet::new();
    for h in &past {
        if let Some(_data) = store.get(h) {
            // A block is in the blue set if it appears in any ancestor's mergeset_blues
            // or is the genesis
            blue_set.insert(*h); // simplified: walk selected parent chain
        }
    }
    // More precisely: walk selected parent chain + collect mergeset_blues
    let mut blue = HashSet::new();
    let mut cur = Some(*b);
    while let Some(h) = cur {
        if let Some(data) = store.get(&h) {
            for mb in &data.mergeset_blues {
                blue.insert(*mb);
            }
            cur = data.selected_parent;
        } else {
            break;
        }
    }
    blue
}

// ── Mergeset computation ──────────────────────────────────────────────────────

/// Compute mergeset(B, selected_parent):
/// All blocks in past(B) that are NOT in past(selected_parent) and not selected_parent itself.
/// These are blocks B "merges" by referencing parents other than selected_parent.
///
/// O(|past(selected_parent)|): kept as the fallback for a DAG whose
/// reachability index is not populated. `GhostDAG::compute_mergeset_bounded`
/// returns the identical list in O(|mergeset|) when the index is ready.
fn compute_mergeset(
    store: &DagStore,
    b_parents: &[BlockHash],
    selected_parent: &BlockHash,
) -> Vec<BlockHash> {
    let sp_past = compute_past(store, selected_parent);
    let mut mergeset_set: HashSet<BlockHash> = HashSet::new();

    // Collect all ancestors of non-selected parents that are not in sp_past
    for parent in b_parents {
        if parent == selected_parent { continue; }
        let mut queue = VecDeque::new();
        queue.push_back(*parent);
        while let Some(h) = queue.pop_front() {
            if !sp_past.contains(&h) && h != *selected_parent && mergeset_set.insert(h) {
                if let Some(data) = store.get(&h) {
                    for p in &data.parents {
                        if !sp_past.contains(p) && p != selected_parent {
                            queue.push_back(*p);
                        }
                    }
                }
            }
        }
    }

    // Topological sort of mergeset (ancestors before descendants)
    topological_sort(store, mergeset_set.into_iter().collect())
}

/// Topological sort: ancestors first, descendants last
fn topological_sort(store: &DagStore, blocks: Vec<BlockHash>) -> Vec<BlockHash> {
    // Build in-degree map within this set
    let set: HashSet<BlockHash> = blocks.iter().cloned().collect();
    let mut in_degree: HashMap<BlockHash, usize> = HashMap::new();
    let mut reverse_deps: HashMap<BlockHash, Vec<BlockHash>> = HashMap::new();

    for &b in &blocks {
        in_degree.entry(b).or_insert(0);
        if let Some(data) = store.get(&b) {
            for p in &data.parents {
                if set.contains(p) {
                    *in_degree.entry(b).or_insert(0) += 1;
                    reverse_deps.entry(*p).or_default().push(b);
                }
            }
        }
    }

    let mut result = Vec::with_capacity(blocks.len());
    let mut queue: VecDeque<BlockHash> = in_degree.iter()
        .filter(|(_, &d)| d == 0)
        .map(|(&h, _)| h)
        .collect();
    // Sort for determinism (break ties by hash)
    let mut sorted_start: Vec<BlockHash> = queue.drain(..).collect();
    sorted_start.sort_unstable();
    queue.extend(sorted_start);

    while let Some(b) = queue.pop_front() {
        result.push(b);
        if let Some(children) = reverse_deps.get(&b) {
            let mut next: Vec<BlockHash> = children.iter()
                .filter_map(|c| {
                    let deg = in_degree.get_mut(c)?;
                    *deg -= 1;
                    if *deg == 0 { Some(*c) } else { None }
                })
                .collect();
            next.sort_unstable();
            queue.extend(next);
        }
    }
    result
}

// ── GhostDAG protocol ────────────────────────────────────────────────────────

/// Selects how `classify_mergeset` computes the blue/red partition.
///
/// # SAFETY / consensus status
///
/// `Legacy` is the byte-for-byte, currently-deployed mainnet-beta behavior:
/// bounded `is_ancestor` BFS + `k*100`-bounded `past_blue_set`. It is the
/// default for every live constructor and MUST stay the default until a
/// differential replay over the real ≥397k history proves `Fast` is
/// byte-identical.
///
/// `Fast` routes all ancestry queries through the interval reachability index
/// (`reachability::ReachabilityStore`), removing the bounded BFS. It is
/// **result-identical to `Legacy` on every DAG where the legacy bound never
/// bit**, and is exercised by `tests/ghostdag_differential.rs`. Where the two
/// diverge, the legacy (bug-compatible) answer is the consensus-correct one to
/// keep; adopting `Fast`'s answer there would be a FORK and requires an
/// activation-height gate. `Fast` is therefore an opt-in mode, never selected
/// on the live path in this change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColoringMode {
    /// Deployed behavior — bounded BFS. Default everywhere.
    Legacy,
    /// Interval-index-backed unbounded coloring. Opt-in / test-only.
    Fast,
}

/// Activation height for the corrected (`Fast`) GhostDAG coloring.
///
/// # TOKEN / HISTORY PRESERVATION — READ BEFORE CHANGING
///
/// This is a soft-fork-style activation gate. On the live path (`self.coloring
/// == Legacy`), a block at `height` is colored with:
///
/// ```text
/// if height >= CORRECTED_COLORING_ACTIVATION_HEIGHT { Fast } else { Legacy }
/// ```
///
/// **CORRECTED (was stale as of the original writing of this paragraph):**
/// this comment used to say the constant "defaults to `u64::MAX` = DISABLED"
/// and "changes ZERO live behavior". That was true only until WS-A
/// (2026-08-05) armed it — see the "Coordinated-release sentinel" and
/// "FLAG-DAY LOWERED" notes below, which were added at that time but never
/// reconciled against this paragraph. The constant has been `21_430`, not
/// `u64::MAX`, since the flag day, and roughly 46% of the Genesis-3 chain's
/// eventual terminal height (39,918, reached 2026-08-24) was mined AT OR
/// ABOVE this gate, i.e. under `Fast` coloring, not `Legacy`. Historical
/// blocks are never *recolored* after the fact regardless of where the gate
/// sits: they are loaded from CF_DAG verbatim (`load_persisted` /
/// `load_persisted_validated` insert stored data without recomputation), so
/// each block's coloring — decided once, at the height it was mined, by
/// comparing that height against whatever this constant was AT THE TIME — is
/// preserved unconditionally. "Preserved" here means "frozen as originally
/// computed", not "computed under `Legacy`".
///
/// ## Setting a real activation height (founder action only)
///
/// The value MUST be a **future** height, strictly greater than the current
/// chain tip at the moment of the coordinated upgrade, and MUST be adopted by
/// ALL nodes simultaneously (a soft-fork upgrade). Only blocks mined at or
/// above that future height are colored with `Fast`; every block below it keeps
/// its `Legacy` coloring, so no historical block is ever recomputed and no
/// reorg of history occurs.
///
/// Setting this to a height at or below the current tip is **FORBIDDEN**: it
/// would retroactively recolor already-mined blocks, which is a history reorg
/// that can change balances. Do not do it. The replay harness
/// (`tests/ghostdag_replay_snapshot.rs`) is the tool that first proves whether
/// `Fast` even differs from `Legacy` on real history; if it is byte-identical
/// everywhere, `Fast` is a transparent speedup and no activation is needed at
/// all.
///
/// ## Coordinated-release sentinel (Phase 3) — SUPERSEDED, see WS-A below
///
/// This paragraph originally left the value at `u64::MAX` =
/// `TBD_COORDINATED_RELEASE` and said "every live node stays byte-for-byte on
/// the `Legacy` coloring until this constant changes". That description is
/// **no longer current**: WS-A armed the gate at a real height (`21_430`,
/// later documented below) as exactly the coordinated soft-fork this
/// paragraph called for — all fleet nodes adopted the same future height
/// simultaneously, per this constant's own rule. The general principle still
/// holds for any FUTURE re-arming (a real height is a coordinated soft-fork
/// decision, never a code-review default, and the dev/test env override
/// `GNB_GHOSTDAG_COLORING=fast` remains node-local and not a substitute for
/// it); only the "still disabled" conclusion is stale.
///
/// WS-A (2026-08-05): armed to a FUTURE flag-day height. The replay-snapshot
/// proof (h18532) showed `Fast` is NOT byte-identical to `Legacy` — it diverges
/// only in the `blues_anticone_sizes` metadata field (Legacy's bounded seed
/// under-counts), with **zero** blue_score / mergeset / selected-chain / balance
/// changes. Adopting the exact `Fast` coloring is therefore a consensus change
/// and MUST be gated at a height ABOVE every already-mined block: history below
/// the gate keeps its Legacy `GhostdagData` (no reorg, no balance recompute) and
/// only blocks at/above the gate use the exact index-based coloring.
///
/// GnB: a new chain has no Legacy-colored history to preserve, so the exact
/// index-based (`Fast`) coloring applies from genesis. The Legacy path stays
/// in the code only for the replay/differential tests inherited from Bloch.
pub const CORRECTED_COLORING_ACTIVATION_HEIGHT: u64 = 0;

pub struct GhostDAG {
    pub k: usize,
    pub store: DagStore,
    /// Coloring strategy. Defaults to `Legacy` (unchanged mainnet behavior).
    pub coloring: ColoringMode,
    /// Interval reachability index. Maintained only while `coloring == Fast`;
    /// left empty (zero overhead) in `Legacy` mode. Never consensus state.
    reach: ReachabilityStore,
    /// Hardening activation height (DAG-3/4/7): blocks with
    /// `GhostdagData::height >= hardening_activation` use the corrected rules.
    /// Fixed for the lifetime of the DAG (stored data is interpreted with it).
    hardening_activation: u64,
    /// Cache, never consensus state: PoW work of blocks at or above the
    /// activation (their own work is not recoverable from `GhostdagData` in
    /// O(1)). Missing entries are derived from the stored data; see `work_of`.
    block_work: HashMap<BlockHash, u128>,
    /// Cache, never consensus state, for blocks below the activation: the
    /// nearest block at or below the key on its selected chain whose
    /// `mergeset_blues` is non-empty (`None` = none down to genesis). Lets the
    /// pre-activation chain walk skip blocks that contribute nothing; a missing
    /// entry falls back to a plain one-step walk.
    merge_skip: HashMap<BlockHash, Option<BlockHash>>,
}

/// Result of [`GhostDAG::compute_block`]: everything `add_block` needs,
/// computed without mutating the DAG.
struct ComputedBlock {
    data: GhostdagData,
    selected_parent: BlockHash,
    /// Blues ∪ reds, i.e. the mergeset, for the reachability index.
    mergeset: Vec<BlockHash>,
    /// Work values derived while computing blue_work, worth caching.
    derived_work: HashMap<BlockHash, u128>,
}

impl GhostDAG {
    fn new_with(k: usize, coloring: ColoringMode, hardening_activation: u64) -> Self {
        Self {
            k,
            store: DagStore::new(),
            coloring,
            reach: ReachabilityStore::new(),
            hardening_activation,
            block_work: HashMap::new(),
            merge_skip: HashMap::new(),
        }
    }

    pub fn with_default_k() -> Self {
        Self::new_with(GHOSTDAG_K, ColoringMode::Legacy, activation::hardening_activation_height())
    }

    pub fn with_k(k: usize) -> Self {
        Self::new_with(k, ColoringMode::Legacy, activation::hardening_activation_height())
    }

    /// Test/benchmark constructor: same as `with_k` but selects the `Fast`
    /// (interval-index) coloring mode. NOT for live use — see [`ColoringMode`].
    pub fn with_k_fast(k: usize) -> Self {
        Self::new_with(k, ColoringMode::Fast, activation::hardening_activation_height())
    }

    /// Same as [`with_k`](Self::with_k) with an explicit hardening activation
    /// height: `0` applies the corrected rules from genesis,
    /// `activation::NEVER` (`u64::MAX`) keeps the old rules forever. The other
    /// constructors take the height from the node's chain id
    /// (`activation::hardening_activation_height`).
    pub fn with_k_and_activation(k: usize, activation_height: u64) -> Self {
        Self::new_with(k, ColoringMode::Legacy, activation_height)
    }

    /// Builder form: replace the hardening activation height. Must be called
    /// before any block is added, because stored data is interpreted with it.
    pub fn with_hardening_activation(mut self, activation_height: u64) -> Self {
        assert!(
            self.store.data.is_empty(),
            "the hardening activation height must be set before blocks are added"
        );
        self.hardening_activation = activation_height;
        self
    }

    /// The hardening activation height this DAG applies.
    pub fn hardening_activation_height(&self) -> u64 {
        self.hardening_activation
    }

    /// Whether a block at `height` (its `GhostdagData::height`) is processed
    /// under the corrected rules.
    pub fn is_hardened_at(&self, height: u64) -> bool {
        activation::is_active_at(height, self.hardening_activation)
    }

    /// Construct with the default K, honoring the **dev/test** coloring override.
    ///
    /// # Activation shape (Phase 3) — SAFE BY DEFAULT
    ///
    /// The shipped default is ALWAYS `Legacy`: with no override set this is
    /// exactly [`with_default_k`], and the live gate
    /// [`CORRECTED_COLORING_ACTIVATION_HEIGHT`] stays at `u64::MAX`. Nothing on
    /// the live chain changes from this branch.
    ///
    /// For local testing / replay ONLY, setting the env var
    /// `GNB_GHOSTDAG_COLORING=fast` selects the `Fast` interval-index coloring
    /// from genesis so an operator can exercise the durable index + rebuild on a
    /// throwaway datadir. This is a node-local switch — it colors THIS node's
    /// view and is NOT a network activation. Flipping the whole network to Fast
    /// is a coordinated soft-fork that sets a real future
    /// `CORRECTED_COLORING_ACTIVATION_HEIGHT`; the env override deliberately does
    /// not and cannot do that.
    pub fn with_default_k_env() -> Self {
        match Self::coloring_from_env() {
            ColoringMode::Fast => {
                log::warn!(
                    "GNB_GHOSTDAG_COLORING=fast — running the interval-index (Fast) \
                     coloring from genesis. DEV/TEST ONLY: this is a node-local view, \
                     NOT a network activation. Do not use on a shared/live datadir."
                );
                Self::with_k_fast(GHOSTDAG_K)
            }
            ColoringMode::Legacy => Self::with_default_k(),
        }
    }

    /// Read the dev/test coloring override. Defaults to `Legacy` for any unset /
    /// unrecognized value — the safe, live-preserving default.
    pub fn coloring_from_env() -> ColoringMode {
        match std::env::var("GNB_GHOSTDAG_COLORING") {
            Ok(v) if v.eq_ignore_ascii_case("fast") => ColoringMode::Fast,
            _ => ColoringMode::Legacy,
        }
    }

    /// Read-only handle to the reachability index (for tests/diagnostics).
    pub fn reachability(&self) -> &ReachabilityStore {
        &self.reach
    }

    /// The coloring mode that applies to a block at the given `height`.
    ///
    /// - `self.coloring == Fast` (test/replay constructor): always `Fast`.
    /// - `self.coloring == Legacy` (every live constructor): the
    ///   [`CORRECTED_COLORING_ACTIVATION_HEIGHT`] soft-fork gate decides — `Fast`
    ///   at/above the activation height, `Legacy` below it. With the activation
    ///   height at its default `u64::MAX` this is `Legacy` for every reachable
    ///   height, so live behavior is unchanged and all history stays
    ///   Legacy-colored.
    fn effective_coloring(&self, height: u64) -> ColoringMode {
        match self.coloring {
            ColoringMode::Fast => ColoringMode::Fast,
            ColoringMode::Legacy => {
                if height >= CORRECTED_COLORING_ACTIVATION_HEIGHT {
                    ColoringMode::Fast
                } else {
                    ColoringMode::Legacy
                }
            }
        }
    }

    /// Whether the reachability index must be maintained for this DAG.
    ///
    /// True when the DAG is a `Fast` constructor OR when the corrected-coloring
    /// activation gate is armed (a real future height is configured) — in the
    /// armed case the index must be built from genesis so `Fast` classification
    /// is ready by the time the activation height is reached. When the gate is
    /// disabled (`u64::MAX`, the default) and the DAG is `Legacy`, this is
    /// `false` and the index is never touched — zero overhead, zero change.
    pub fn maintains_reachability_index(&self) -> bool {
        self.coloring == ColoringMode::Fast
            || CORRECTED_COLORING_ACTIVATION_HEIGHT != u64::MAX
    }

    // ── Durable reachability index plumbing (Phase 1 / 2) ────────────────────

    /// Drain the pending reachability durability delta so the caller can fold it
    /// into the same atomic write as the block's CF_DAG entry. Empty unless the
    /// index is being maintained.
    pub fn reach_take_delta(&mut self) -> (Vec<(BlockHash, Vec<u8>)>, Vec<BlockHash>) {
        self.reach.take_persist_delta()
    }

    /// The current reachability root (genesis), for persisting the meta tag.
    pub fn reach_root(&self) -> Option<BlockHash> {
        self.reach.root()
    }

    /// Full snapshot of the reachability index for a one-batch rebuild write.
    pub fn reach_export_all(&self) -> Vec<(BlockHash, Vec<u8>)> {
        self.reach.export_all()
    }

    /// Load a persisted reachability index into memory (boot fast-path). The
    /// caller is responsible for having validated version + coverage first.
    pub fn reach_load_records(
        &mut self,
        records: &[(BlockHash, Vec<u8>)],
        root: Option<BlockHash>,
    ) -> Result<(), String> {
        self.reach.load_from_records(records, root)
    }

    /// Rebuild the reachability index from scratch by replaying the SAME
    /// `reach.add_block` code path over the in-memory DAG in topological order
    /// (parents strictly before children). Used by the boot migration when the
    /// persisted index is missing / version-mismatched / fails its self-check.
    /// Returns the number of blocks indexed. Leaves the delta pre-populated
    /// (every block dirty) so the caller can flush a full snapshot.
    pub fn rebuild_reachability_from_store(&mut self) -> Result<usize, String> {
        self.reach = ReachabilityStore::new();
        let order = self.topological_order()?;
        for h in &order {
            let d = self.store.get(h).ok_or_else(|| {
                format!("rebuild: block {} vanished from store", hex::encode(&h[..4]))
            })?;
            if d.parents.is_empty() {
                self.reach.add_genesis(*h);
            } else {
                let sp = d.selected_parent.ok_or_else(|| {
                    format!("rebuild: non-genesis {} has no selected parent", hex::encode(&h[..4]))
                })?;
                let mut mergeset = d.mergeset_blues.clone();
                mergeset.extend_from_slice(&d.mergeset_reds);
                self.reach.add_block(*h, &sp, &mergeset);
            }
        }
        Ok(order.len())
    }

    /// Kahn topological sort of the in-memory DAG: every parent strictly
    /// precedes its children, so a downstream `reach.add_block` always finds its
    /// selected parent and all mergeset members already indexed. Ties broken by
    /// (blue_score, height, hash) for determinism. `Err` if the store is not a
    /// DAG or references an absent parent.
    fn topological_order(&self) -> Result<Vec<BlockHash>, String> {
        let mut indegree: HashMap<BlockHash, usize> = HashMap::new();
        let mut children: HashMap<BlockHash, Vec<BlockHash>> = HashMap::new();
        for h in self.store.data.keys() {
            indegree.entry(*h).or_insert(0);
        }
        for (h, d) in &self.store.data {
            for p in &d.parents {
                if !self.store.data.contains_key(p) {
                    return Err(format!(
                        "block {} references parent {} absent from store",
                        hex::encode(&h[..4]), hex::encode(&p[..4])
                    ));
                }
                // `h` is a key of `self.store.data`, and every such key was
                // seeded into `indegree` above, so this lookup is infallible.
                // Return an error instead of panicking to keep this consensus
                // path fail-closed rather than aborting the node (DoS).
                *indegree
                    .get_mut(h)
                    .ok_or_else(|| format!("indegree missing {}", hex::encode(&h[..4])))? += 1;
                children.entry(*p).or_default().push(*h);
            }
        }
        let key = |h: &BlockHash| {
            let d = &self.store.data[h];
            (d.blue_score, d.height, *h)
        };
        let mut ready: Vec<BlockHash> = indegree.iter()
            .filter(|(_, &deg)| deg == 0).map(|(h, _)| *h).collect();
        ready.sort_by_key(key);
        let mut queue: VecDeque<BlockHash> = ready.into_iter().collect();
        let mut out = Vec::with_capacity(self.store.data.len());
        while let Some(h) = queue.pop_front() {
            out.push(h);
            if let Some(ch) = children.get(&h) {
                let mut newly = Vec::new();
                for c in ch {
                    // `c` is a child recorded from a parent edge whose endpoint
                    // is a store key, so it is always present in `indegree`.
                    // Fail-closed (error) rather than panic on the impossible
                    // branch.
                    let deg = indegree
                        .get_mut(c)
                        .ok_or_else(|| format!("indegree missing child {}", hex::encode(&c[..4])))?;
                    *deg -= 1;
                    if *deg == 0 { newly.push(*c); }
                }
                if !newly.is_empty() {
                    let mut rest: Vec<BlockHash> = queue.drain(..).collect();
                    rest.extend(newly);
                    rest.sort_by_key(key);
                    queue = rest.into_iter().collect();
                }
            }
        }
        if out.len() != self.store.data.len() {
            return Err(format!(
                "topological sort visited {}/{} blocks — parent graph has a cycle",
                out.len(), self.store.data.len()
            ));
        }
        Ok(out)
    }

    /// Random-sample self-check of the reachability index against the unbounded
    /// brute-force oracle over the raw parent graph. Draws `samples` random
    /// ordered block pairs with the given `seed` and returns `Err` on the first
    /// disagreement. A cheap boot-time guard that a loaded/rebuilt index is not
    /// silently mis-labeled before it is trusted for classification.
    pub fn reach_self_check_sample(&self, samples: usize, seed: u64) -> Result<usize, String> {
        let blocks: Vec<BlockHash> = self.store.data.keys().copied().collect();
        if blocks.len() < 2 {
            return Ok(0);
        }
        let mut state = seed | 1;
        let mut next = || {
            state ^= state >> 12; state ^= state << 25; state ^= state >> 27;
            state.wrapping_mul(0x2545F4914F6CDD1D)
        };
        let n = blocks.len();
        let mut checked = 0usize;
        for _ in 0..samples {
            let a = blocks[(next() as usize) % n];
            let b = blocks[(next() as usize) % n];
            if a == b { continue; }
            let idx = self.reach.is_dag_ancestor(&a, &b);
            let oracle = reachability::brute_force_is_ancestor(&self.store, &a, &b);
            if idx != oracle {
                return Err(format!(
                    "reachability self-check MISMATCH: is_ancestor({},{}) index={} oracle={}",
                    hex::encode(&a[..4]), hex::encode(&b[..4]), idx, oracle
                ));
            }
            checked += 1;
        }
        Ok(checked)
    }

    /// Add genesis block
    pub fn add_genesis(&mut self, hash: BlockHash, timestamp: u64) {
        let data = GhostdagData {
            blue_score: 0,
            blue_work: 0,
            selected_parent: None,
            mergeset_blues: vec![],
            mergeset_reds: vec![],
            blues_anticone_sizes: HashMap::new(),
            parents: vec![],
            height: 0,
            timestamp,
        };
        self.store.genesis = Some(hash);
        if self.maintains_reachability_index() {
            self.reach.add_genesis(hash);
        }
        self.store.insert(hash, data);
    }

    /// Reconstruct DAG from persisted GhostdagData entries.
    /// Entries are sorted by blue_score to approximate topological order,
    /// then inserted directly (no re-computation of PHANTOM — the stored
    /// data already contains mergeset_blues/reds, selected_parent, etc.).
    pub fn load_persisted(&mut self, mut entries: Vec<(BlockHash, GhostdagData)>) {
        // Sort by blue_score (ascending) to insert parents before children
        entries.sort_by_key(|(_, d)| d.blue_score);

        for (hash, data) in entries {
            if data.parents.is_empty() {
                // Genesis
                self.store.genesis = Some(hash);
            }
            self.store.insert(hash, data);
        }
    }

    /// Sprint Y (M-2): verified variant of `load_persisted`.
    ///
    /// Same behavior as `load_persisted` on the happy path, but validates
    /// an integrity hash-chain over GhostdagData before inserting anything
    /// into the in-memory DAG. Detects three concrete tampering patterns:
    ///
    ///   * Silent RocksDB corruption (bit flip, bad hardware): any field
    ///     mutation changes the recomputed hash.
    ///   * Adversary with disk access altering `blue_score`,
    ///     `mergeset_blues`, or other consensus-critical fields.
    ///   * Downgrade attack: swapping CF_DAG contents with a competing
    ///     chain's data. The parent chain link breaks unless the attacker
    ///     also forges every ancestor back to genesis.
    ///
    /// Returns `Ok(n)` where n is the number of blocks loaded. `Err` on
    /// any mismatch — the caller is expected to treat this as fatal.
    ///
    /// `integrity_map` is `Option<[u8; 32]>` per block: `None` means
    /// the integrity record was missing from CF_DAG_INTEGRITY. If ALL
    /// records are missing, the function self-heals by computing and
    /// returning the fresh integrity map to the caller (to be persisted).
    /// Mixed presence (some present, some missing) is treated as an
    /// error — the attacker may have deleted specific records.
    pub fn load_persisted_validated(
        &mut self,
        entries: Vec<(BlockHash, GhostdagData)>,
        integrity_map: std::collections::HashMap<BlockHash, [u8; 32]>,
    ) -> Result<LoadedIntegrity, IntegrityError> {
        let total = entries.len();
        let integrity_count = integrity_map.len();

        // All-or-nothing for the migration path. Mixed state is suspicious.
        let self_heal = if integrity_count == 0 {
            true
        } else if integrity_count == total {
            false
        } else {
            return Err(IntegrityError::PartialCoverage {
                present: integrity_count,
                total,
            });
        };

        // Sort by blue_score so parents process before children. This is
        // load-bearing for the chain check: we need parent's integrity
        // hash computed and available when we validate the child.
        let mut sorted = entries;
        sorted.sort_by_key(|(_, d)| d.blue_score);

        let mut computed: std::collections::HashMap<BlockHash, [u8; 32]> =
            std::collections::HashMap::with_capacity(sorted.len());

        for (hash, data) in &sorted {
            let parent_integrity = match &data.selected_parent {
                Some(sp) => *computed.get(sp).ok_or_else(|| {
                    // This should never trip if blue_score ordering holds
                    // and the DAG is well-formed. If it does, the stored
                    // GhostdagData references a parent that was not
                    // persisted — corruption or a partial write mid-crash.
                    IntegrityError::ParentNotLoaded {
                        block: *hash,
                        parent: *sp,
                    }
                })?,
                None => [0u8; 32], // Genesis: no parent link.
            };

            let expected = compute_integrity_hash(hash, data, &parent_integrity);

            if !self_heal {
                let stored = integrity_map.get(hash).ok_or_else(|| {
                    IntegrityError::MissingEntry { block: *hash }
                })?;
                if stored != &expected {
                    return Err(IntegrityError::ChainMismatch {
                        block: *hash,
                        expected,
                        stored: *stored,
                    });
                }
            }

            computed.insert(*hash, expected);
        }

        // All checks passed (or self-heal, which is also OK). Now the
        // in-memory insertion, identical to load_persisted's loop.
        for (hash, data) in sorted {
            if data.parents.is_empty() {
                self.store.genesis = Some(hash);
            }
            self.store.insert(hash, data);
        }

        Ok(LoadedIntegrity {
            blocks_loaded: total,
            self_healed:   self_heal,
            fresh_map:     if self_heal { Some(computed) } else { None },
        })
    }

    /// Add a new block and compute its full GhostDAG data.
    /// Returns the computed GhostdagData on success.
    ///
    /// Audit M-9 fix: previously used `assert!` for the two preconditions,
    /// which panicked the whole node if an invalid block slipped past
    /// upstream validation (gossipsub, accept_block, etc). Now returns
    /// a `ConsensusError` variant so callers can reject the block
    /// cleanly without tearing down the process.
    ///
    /// Hardening (DAG-3/4/7): a block whose height (`selected_parent.height +
    /// 1`) is at or above [`hardening_activation_height`](Self::hardening_activation_height)
    /// is colored with the exact GHOSTDAG rule, gets Kaspa blue work, and is
    /// rejected with [`ConsensusError::MergesetTooLarge`] or
    /// [`ConsensusError::MergeDepthViolation`] when it breaks the new limits.
    /// Below that height the result is bit-identical to the old code. Nothing
    /// is mutated when an error is returned.
    pub fn add_block(
        &mut self,
        hash: BlockHash,
        parents: Vec<BlockHash>,
        timestamp: u64,
        work: u128,  // PoW work of this block (difficulty)
    ) -> Result<GhostdagData, ConsensusError> {
        if parents.is_empty() {
            return Err(ConsensusError::NoParents);
        }
        if self.store.has(&hash) {
            return Err(ConsensusError::DuplicateBlock(hash));
        }

        // Warm the pre-activation skip cache for the selected chain (pure
        // performance; `compute_block` gives the same answer without it).
        let selected_parent = self.select_parent(&parents);
        let sp_height = self.store.get(&selected_parent).map(|d| d.height);
        let hardened = matches!(sp_height, Some(h) if self.is_hardened_at(h + 1));
        if sp_height.is_some() && !hardened {
            self.ensure_merge_skip(&selected_parent);
        }

        let ComputedBlock { data, selected_parent, mergeset, derived_work } =
            self.compute_block(&parents, timestamp, work)?;

        // Maintain the reachability index (Fast mode only). Register `hash`
        // now, after classification, before it is inserted into the store — so
        // subsequent blocks can query its ancestry.
        if self.maintains_reachability_index() {
            self.reach.add_block(hash, &selected_parent, &mergeset);
        }

        // Non-consensus caches.
        self.block_work.extend(derived_work);
        if hardened {
            self.block_work.insert(hash, work);
        } else if !data.mergeset_blues.is_empty() {
            self.merge_skip.insert(hash, Some(hash));
        } else if let Some(below) = self.merge_skip.get(&selected_parent).copied() {
            self.merge_skip.insert(hash, below);
        }

        let result = data.clone();
        self.store.insert(hash, data);
        Ok(result)
    }

    /// Compute a block's `GhostdagData` from its parents without touching the
    /// DAG. Shared by [`add_block`](Self::add_block) and
    /// [`select_parents_for_template`](Self::select_parents_for_template), so a
    /// template is checked with exactly the consensus code.
    fn compute_block(
        &self,
        parents: &[BlockHash],
        timestamp: u64,
        work: u128,
    ) -> Result<ComputedBlock, ConsensusError> {
        if parents.is_empty() {
            return Err(ConsensusError::NoParents);
        }

        // 1. Select parent: argmax blue_score, tie-break by hash (lexicographic)
        let selected_parent = self.select_parent(parents);

        // The selected parent must be present in the store. A block whose
        // selected parent is absent is an orphan the sync layer should have
        // buffered; reaching here means it slipped past upstream validation.
        // Reject cleanly rather than panic (completes Audit M-9 — previously a
        // `.expect()` here, inconsistent with the tolerant lookups elsewhere).
        let sp_data = self.store.get(&selected_parent)
            .ok_or(ConsensusError::MissingSelectedParent(selected_parent))?;

        // 2. Compute height from the (now validated) selected parent.
        let height = sp_data.height + 1;
        let hardened = self.is_hardened_at(height);
        let use_index = self.ancestry_index_ready(parents, &selected_parent);

        // 3. Compute mergeset (topologically sorted, ancestors first). The
        //    index-based walk returns the same list as the O(past) one; the
        //    size limit applies only at or above the activation.
        let limit = if hardened { Some(MAX_MERGESET_SIZE - 1) } else { None };
        let mergeset = if use_index {
            self.compute_mergeset_bounded(parents, &selected_parent, limit)?
        } else {
            let m = compute_mergeset(&self.store, parents, &selected_parent);
            if let Some(limit) = limit {
                if m.len() > limit {
                    return Err(ConsensusError::MergesetTooLarge { limit: MAX_MERGESET_SIZE });
                }
            }
            m
        };

        // 4. Classify mergeset blocks as blue or red using PHANTOM constraint.
        //    In Fast mode the reachability index must contain every existing
        //    block before classification queries it; the index is maintained
        //    incrementally, so it already does. `hash` itself is not queried
        //    during its own classification, so we register it afterwards.
        //    Below the hardening activation the coloring is chosen by the
        //    height-gated `effective_coloring`, exactly as before (Legacy below
        //    CORRECTED_COLORING_ACTIVATION_HEIGHT, Fast at/above it). At or
        //    above the hardening activation the exact GHOSTDAG coloring applies.
        let (mergeset_blues, mergeset_reds, blues_anticone_sizes) = if hardened {
            self.classify_mergeset_exact(&mergeset, &selected_parent, use_index)
        } else {
            match self.effective_coloring(height) {
                ColoringMode::Legacy => self.classify_mergeset(&mergeset, &selected_parent),
                ColoringMode::Fast => self.classify_mergeset_fast(&mergeset, &selected_parent),
            }
        };

        // 5. Compute blue_score and blue_work
        let blue_score = sp_data.blue_score + mergeset_blues.len() as u64 + 1;
        let mut derived_work = HashMap::new();
        let blue_work = if hardened {
            // DAG-3: Kaspa blue work. sp.blue_work already counts the selected
            // parent's own work, so adding every mergeset blue and this block's
            // work makes blue_work(B) the total work of blue(B) ∪ {B}.
            let merged: u128 = mergeset_blues
                .iter()
                .map(|m| self.work_of(m, &mut derived_work))
                .sum();
            sp_data.blue_work + merged + work
        } else {
            // Pre-activation rule: cumulative PoW along the selected chain plus
            // this block's work; merged blues add nothing.
            sp_data.blue_work + work
        };

        // 6. Merge depth (DAG-7), at or above the activation only.
        if hardened && !mergeset_reds.is_empty() {
            self.check_merge_depth(&selected_parent, blue_score, &mergeset_blues, &mergeset_reds, use_index)?;
        }

        let data = GhostdagData {
            blue_score,
            blue_work,
            selected_parent: Some(selected_parent),
            mergeset_blues,
            mergeset_reds,
            blues_anticone_sizes,
            parents: parents.to_vec(),
            height,
            timestamp,
        };
        Ok(ComputedBlock { data, selected_parent, mergeset, derived_work })
    }

    /// Remove a just-added LEAF block, exactly inverting `DagStore::insert`.
    ///
    /// CONSENSUS-HALT FIX (DAG-vs-UTXO ordering): `accept_block` inserts a
    /// block into the DAG *before* it knows whether the reorg the block
    /// triggers will be accepted. When `reorg::execute_reorg` REFUSES the
    /// plan (depth cap) the UTXO store is untouched — but without an undo,
    /// `selected_tip()` has already permanently adopted the fork tip, so
    /// every later legitimate extension of the real chain is misclassified
    /// as a fork-loser: a durable consensus halt. This method lets the
    /// accept path roll the in-memory insertion back on a refused/failed
    /// disposition (the CF_DAG persist is deferred until after success, see
    /// `accept_block` in main.rs).
    ///
    /// Guards — all return `false` with NO mutation:
    ///   * `hash` is not in the store,
    ///   * `hash` is genesis,
    ///   * `hash` has children (only leaf/tip blocks are safely removable;
    ///     removing an interior block would corrupt descendants' GhostDAG
    ///     data — the accept path only ever removes the block it just added).
    ///
    /// Returns `true` when the block was removed and each parent regained
    /// tip status iff it no longer has any remaining children.
    pub fn remove_block(&mut self, hash: &BlockHash) -> bool {
        if self.store.genesis == Some(*hash) {
            return false;
        }
        if self.store.children.get(hash).map_or(false, |c| !c.is_empty()) {
            return false;
        }
        let data = match self.store.data.remove(hash) {
            Some(d) => d,
            None => return false,
        };
        // Keep the reachability index consistent (Fast mode only). The mergeset
        // used at insert time is recoverable as blues ∪ reds.
        if self.maintains_reachability_index() {
            let mut mergeset = data.mergeset_blues.clone();
            mergeset.extend_from_slice(&data.mergeset_reds);
            self.reach.remove_leaf(hash, &mergeset);
        }
        // Drop the non-consensus caches for this block. A leaf is nobody's
        // selected parent and nobody's merged blue, so no other entry refers
        // to it.
        self.block_work.remove(hash);
        self.merge_skip.remove(hash);
        self.store.tips.remove(hash);
        self.store.children.remove(hash);
        // Exact inverse of `DagStore::insert`: drop the child edge from each
        // parent; a parent becomes a tip again iff it is still stored and now
        // has no children at all.
        for p in &data.parents {
            if let Some(ch) = self.store.children.get_mut(p) {
                ch.remove(hash);
                if ch.is_empty() {
                    self.store.children.remove(p);
                }
            }
            if self.store.data.contains_key(p)
                && self.store.children.get(p).map_or(true, |c| c.is_empty())
            {
                self.store.tips.insert(*p);
            }
        }
        true
    }

    /// Select parent with highest blue_work (heaviest chain).
    /// Tie-break: blue_score, then hash (lexicographic, deterministic).
    fn select_parent(&self, parents: &[BlockHash]) -> BlockHash {
        *parents.iter().max_by(|a, b| {
            let da = self.store.get(*a);
            let db = self.store.get(*b);
            let work_a = da.map(|d| d.blue_work).unwrap_or(0);
            let work_b = db.map(|d| d.blue_work).unwrap_or(0);
            let score_a = da.map(|d| d.blue_score).unwrap_or(0);
            let score_b = db.map(|d| d.blue_score).unwrap_or(0);
            work_a.cmp(&work_b)
                .then(score_a.cmp(&score_b))
                .then(a.cmp(b))
        }).expect("parents non-empty")
    }

    /// Classify mergeset blocks as blue or red.
    ///
    /// A block C from the mergeset is blue if BOTH:
    ///   (a) |anticone(C) ∩ current_blue_set| ≤ K   (candidate constraint)
    ///   (b) For every already-blue block B: |(anticone(B) ∩ new_blue_set) ∪ {C}| ≤ K
    ///
    /// The "current blue set" grows as we iterate topologically over the mergeset.
    fn classify_mergeset(
        &self,
        mergeset: &[BlockHash],
        selected_parent: &BlockHash,
    ) -> (Vec<BlockHash>, Vec<BlockHash>, HashMap<BlockHash, usize>) {
        // Start blue set from selected parent's full blue lineage
        let mut blue_set: HashSet<BlockHash> = self.past_blue_set(selected_parent);
        blue_set.insert(*selected_parent);

        // Track anticone sizes for each blue block w.r.t. current blue set
        // Key: blue block hash, Value: |anticone(blue_block) ∩ blue_set|
        let mut blues_anticone_sizes: HashMap<BlockHash, usize> = HashMap::new();

        let mut mergeset_blues = Vec::new();
        let mut mergeset_reds = Vec::new();

        // Initialize anticone sizes for existing blue set
        // (simplified: we track the sizes incrementally)
        for b in &blue_set {
            blues_anticone_sizes.insert(*b, 0);
        }

        // Iterate mergeset topologically (ancestors first)
        for &candidate in mergeset {
            let candidate_anticone_in_blue = self.anticone_size_in_set(
                &candidate, &blue_set
            );

            if candidate_anticone_in_blue > self.k {
                // Constraint (a) violated — candidate is red
                mergeset_reds.push(candidate);
                continue;
            }

            // Check constraint (b): for each blue block, would adding candidate
            // push its anticone size over K?
            let mut constraint_b_ok = true;
            for (&blue_block, &current_anticone_size) in &blues_anticone_sizes {
                // Is candidate in anticone of blue_block?
                // anticone(B) = blocks neither in past(B) nor in future(B)
                let in_anticone = self.is_in_anticone(&candidate, &blue_block);
                if in_anticone && current_anticone_size + 1 > self.k {
                    constraint_b_ok = false;
                    break;
                }
            }

            if !constraint_b_ok {
                mergeset_reds.push(candidate);
                continue;
            }

            // Candidate is blue — add to blue set and update anticone sizes
            mergeset_blues.push(candidate);
            blue_set.insert(candidate);
            blues_anticone_sizes.insert(candidate, candidate_anticone_in_blue);

            // Update anticone sizes of existing blue blocks
            for (&blue_block, anticone_size) in blues_anticone_sizes.iter_mut() {
                if blue_block != candidate && self.is_in_anticone(&candidate, &blue_block) {
                    *anticone_size += 1;
                }
            }
        }

        (mergeset_blues, mergeset_reds, blues_anticone_sizes)
    }

    /// WS-B: compact, `O(k · mergeset)` GHOSTDAG coloring (Kaspa protocol).
    ///
    /// Replaces the old whole-blue-set seed + per-candidate full-set scan — which
    /// walked the ENTIRE selected chain (`past_blue_set_unbounded`, O(depth)) and
    /// materialized every historical blue — with a BOUNDED selected-chain walk:
    /// for each mergeset candidate we scan only each chain block's
    /// `mergeset_blues`, stopping the instant a chain block is an ancestor of the
    /// candidate (everything deeper is in the candidate's past, never its
    /// anticone). The per-block `blues_anticone_sizes` map is now COMPACT — only
    /// the blues this block adds and the sizes it bumps — and is read back for
    /// later blocks via [`blue_anticone_size`](Self::blue_anticone_size).
    ///
    /// Byte-identity note: the blue/red DECISIONS — hence `mergeset_blues`,
    /// `blue_score`, and the selected chain — are identical to the exact
    /// whole-set algorithm (validated against Legacy by `ghostdag_differential`).
    /// The `blues_anticone_sizes` map SHAPE differs (compact vs whole-history);
    /// that difference is exactly the gated-consensus metadata change activated
    /// with the reachability index at [`CORRECTED_COLORING_ACTIVATION_HEIGHT`].
    ///
    /// Audit DAG-4: this coloring is NOT exact GHOSTDAG. The selected parent is
    /// not part of GnB's `mergeset_blues`, so the chain walk never counts the
    /// selected-chain blocks below the immediate selected parent, and the
    /// anticone sizes of historical blues restart at 0 per block. It is kept
    /// bit-for-bit as the rule for blocks below the hardening activation;
    /// [`classify_mergeset_exact`](Self::classify_mergeset_exact) applies at or
    /// above it.
    fn classify_mergeset_fast(
        &self,
        mergeset: &[BlockHash],
        selected_parent: &BlockHash,
    ) -> (Vec<BlockHash>, Vec<BlockHash>, HashMap<BlockHash, usize>) {
        // Re-seeded semantics matching `classify_mergeset` (the consensus
        // reference), but with its O(depth) whole-blue-set seed + per-candidate
        // full scan replaced by the BOUNDED chain walk in
        // `candidate_anticone_blues`. `cur_blues_anticone_sizes` is COMPACT: an
        // entry exists only once a blue's (re-seeded) anticone count is set —
        // `selected_parent`, this block's own mergeset blues, and any historical
        // blue this block bumps. An absent blue counts as 0. This is exactly the
        // whole-history map with its zero entries dropped, so it carries the SAME
        // value on every key it keeps (validated by `ghostdag_differential`).
        // The selected parent is seeded blue (size 0) and stripped from the
        // returned `mergeset_blues` (blue_score = sp.blue_score + |blues| + 1).
        let mut cur_mergeset_blues: Vec<BlockHash> = Vec::with_capacity(mergeset.len() + 1);
        let mut cur_blues_anticone_sizes: HashMap<BlockHash, usize> = HashMap::new();
        cur_mergeset_blues.push(*selected_parent);
        cur_blues_anticone_sizes.insert(*selected_parent, 0);

        let mut mergeset_reds: Vec<BlockHash> = Vec::new();

        for &candidate in mergeset {
            // Every blue in the candidate's anticone (bounded selected-chain walk).
            let anticone_blues =
                self.candidate_anticone_blues(selected_parent, &cur_mergeset_blues, &candidate);

            // Constraint (a): |anticone(candidate) ∩ blue_set| ≤ k.
            if anticone_blues.len() > self.k {
                mergeset_reds.push(candidate);
                continue;
            }
            // Constraint (b): colouring the candidate blue must not push any blue
            // it lands in the anticone of over k (re-seeded count, absent = 0).
            let violates_b = anticone_blues
                .iter()
                .any(|b| *cur_blues_anticone_sizes.get(b).unwrap_or(&0) + 1 > self.k);
            if violates_b {
                mergeset_reds.push(candidate);
                continue;
            }

            // Blue: record its own count and bump every blue in its anticone.
            cur_mergeset_blues.push(candidate);
            cur_blues_anticone_sizes.insert(candidate, anticone_blues.len());
            for b in &anticone_blues {
                *cur_blues_anticone_sizes.entry(*b).or_insert(0) += 1;
            }
        }

        let mergeset_blues: Vec<BlockHash> =
            cur_mergeset_blues.into_iter().filter(|b| b != selected_parent).collect();
        (mergeset_blues, mergeset_reds, cur_blues_anticone_sizes)
    }

    /// Collect every blue in the candidate's anticone via a BOUNDED selected-chain
    /// walk. Phase 0 scans the block-under-construction's own blues
    /// (`selected_parent` + mergeset candidates already coloured blue). Phase 1
    /// walks `selected_parent` and up, stopping the instant a chain block is an
    /// ancestor of the candidate — everything deeper is in the candidate's past,
    /// never its anticone. Each block belongs to exactly one mergeset, so there
    /// are no duplicates. This replaces the old O(depth) `past_blue_set_unbounded`
    /// seed + full-set scan while producing the identical anticone set.
    ///
    /// Audit DAG-7, two output-preserving shortcuts (pre-activation rule):
    /// - k + 1 early exit: the caller colours the candidate red as soon as the
    ///   list holds more than k blues, so the walk stops there. The returned list
    ///   is then a (k + 1)-prefix of the full one, which leads to the same red
    ///   decision and to no anticone-size update (only blues update sizes).
    /// - skip pointers (`merge_skip`): chain blocks with an empty
    ///   `mergeset_blues` add nothing to the list, so the walk jumps from one
    ///   merging chain block to the next. The stop condition is unaffected: if
    ///   a skipped block is an ancestor of the candidate, the next merging block
    ///   below it is one too (ancestry is transitive), so the walk still stops
    ///   before processing anything the original walk would not have processed.
    fn candidate_anticone_blues(
        &self,
        selected_parent: &BlockHash,
        cur_mergeset_blues: &[BlockHash],
        candidate: &BlockHash,
    ) -> Vec<BlockHash> {
        let mut out: Vec<BlockHash> = Vec::new();

        // Phase 0 — the under-construction block's own accumulated blues.
        for &blue in cur_mergeset_blues {
            if !self.reach.is_dag_ancestor(&blue, candidate)
                && !self.reach.is_dag_ancestor(candidate, &blue)
            {
                out.push(blue);
                if out.len() > self.k {
                    return out;
                }
            }
        }

        // Phase 1 — selected_parent and up, until an ancestor of the candidate.
        let mut chain = self.next_merging_chain_block(selected_parent);
        while let Some(h) = chain {
            if self.reach.is_dag_ancestor(&h, candidate) {
                break;
            }
            let d = match self.store.get(&h) {
                Some(d) => d,
                None => break, // missing ancestor (shouldn't happen) — stop
            };
            for &blue in &d.mergeset_blues {
                if !self.reach.is_dag_ancestor(&blue, candidate)
                    && !self.reach.is_dag_ancestor(candidate, &blue)
                {
                    out.push(blue);
                    if out.len() > self.k {
                        return out;
                    }
                }
            }
            chain = d.selected_parent.and_then(|p| self.next_merging_chain_block(&p));
        }

        out
    }

    /// First block at or below `from` on its selected chain whose
    /// `mergeset_blues` is non-empty, from the `merge_skip` cache. Without a
    /// cache entry this is `Some(from)`: the walk then visits `from` itself,
    /// exactly like the original one-step walk.
    fn next_merging_chain_block(&self, from: &BlockHash) -> Option<BlockHash> {
        match self.merge_skip.get(from) {
            Some(v) => *v,
            None => Some(*from),
        }
    }

    /// Fill the `merge_skip` cache for `from` and every block below it on its
    /// selected chain (amortised O(1) per block; a DAG loaded from disk pays
    /// one walk the first time). If the store lacks a chain block the cache
    /// ends above it, which the original walk would also stop at.
    fn ensure_merge_skip(&mut self, from: &BlockHash) {
        let mut path: Vec<(BlockHash, bool)> = Vec::new();
        let mut below: Option<BlockHash> = None;
        let mut cur = Some(*from);
        while let Some(h) = cur {
            if let Some(v) = self.merge_skip.get(&h) {
                below = *v;
                break;
            }
            let d = match self.store.get(&h) {
                Some(d) => d,
                None => break,
            };
            path.push((h, !d.mergeset_blues.is_empty()));
            cur = d.selected_parent;
        }
        let mut acc = below;
        for (h, merging) in path.into_iter().rev() {
            if merging {
                acc = Some(h);
            }
            self.merge_skip.insert(h, acc);
        }
    }

    // ── Hardening (audit DAG-3 / DAG-4 / DAG-7) ─────────────────────────────

    /// Whether ancestry queries for a block with these parents can use the
    /// reachability index. The index is filled in topological order (or loaded
    /// whole and self-checked at boot), so indexed parents imply an indexed
    /// past. Otherwise the callers fall back to unbounded graph walks, which
    /// give the same answers more slowly.
    fn ancestry_index_ready(&self, parents: &[BlockHash], selected_parent: &BlockHash) -> bool {
        self.maintains_reachability_index()
            && self.reach.has(selected_parent)
            && parents.iter().all(|p| self.reach.has(p))
    }

    /// Exact, unbounded `a ∈ past(b)` (strict). Never the bounded legacy
    /// `is_ancestor`.
    fn dag_ancestor(&self, a: &BlockHash, b: &BlockHash, use_index: bool) -> bool {
        if use_index {
            self.reach.is_dag_ancestor(a, b)
        } else {
            reachability::brute_force_is_ancestor(&self.store, a, b)
        }
    }

    /// The mergeset of a block with these parents, from the reachability index
    /// in O(|mergeset| · parents · log): a backward walk from the non-selected
    /// parents that stops at `past(selected_parent) ∪ {selected_parent}`.
    ///
    /// Same output as [`compute_mergeset`]: both collect exactly the blocks
    /// reachable from a non-selected parent without passing through
    /// `past(selected_parent) ∪ {selected_parent}` (any path to a mergeset
    /// block avoids that set, since it is closed under taking ancestors), and
    /// both order the set with the same deterministic `topological_sort`. The
    /// index answers `h ∈ past(selected_parent)` exactly where the old code
    /// looked `h` up in the materialised `compute_past(selected_parent)`.
    ///
    /// `limit` (blocks, selected parent excluded) aborts the walk with
    /// [`ConsensusError::MergesetTooLarge`] as soon as it is exceeded, so an
    /// oversized mergeset costs O(limit), not O(|mergeset|).
    fn compute_mergeset_bounded(
        &self,
        parents: &[BlockHash],
        selected_parent: &BlockHash,
        limit: Option<usize>,
    ) -> Result<Vec<BlockHash>, ConsensusError> {
        let mut set: HashSet<BlockHash> = HashSet::new();
        let mut queue: VecDeque<BlockHash> = parents
            .iter()
            .filter(|p| *p != selected_parent)
            .copied()
            .collect();
        while let Some(h) = queue.pop_front() {
            if h == *selected_parent || set.contains(&h) || self.reach.is_dag_ancestor(&h, selected_parent) {
                continue;
            }
            set.insert(h);
            if let Some(limit) = limit {
                if set.len() > limit {
                    return Err(ConsensusError::MergesetTooLarge { limit: MAX_MERGESET_SIZE });
                }
            }
            if let Some(d) = self.store.get(&h) {
                for p in &d.parents {
                    if !set.contains(p) {
                        queue.push_back(*p);
                    }
                }
            }
        }
        Ok(topological_sort(&self.store, set.into_iter().collect()))
    }

    /// Exact GHOSTDAG coloring (PHANTOM paper, Kaspa's algorithm) for blocks at
    /// or above the hardening activation (audit DAG-4).
    ///
    /// Candidates are taken in the deterministic mergeset order (ancestors
    /// first, hash tie-break). With `blue` = blue(selected_parent) ∪
    /// {selected_parent} ∪ the candidates already coloured blue, a candidate
    /// `c` is blue iff
    ///   (a) |anticone(c) ∩ blue| ≤ k, and
    ///   (b) every `x ∈ anticone(c) ∩ blue` has |anticone(x) ∩ blue| + 1 ≤ k.
    /// Both counts run over the FULL blue anticone, selected-chain blocks
    /// included: every chain block's selected parent is walked as a blue, which
    /// is what Kaspa gets from storing the selected parent as
    /// `mergeset_blues[0]` and what the pre-activation walk misses.
    ///
    /// Anticone sizes are computed from the DAG, never read from stored
    /// `blues_anticone_sizes` (those of pre-activation blocks are not exact),
    /// then kept current as blues are added. Every walk exits after k + 1
    /// blues, so a candidate costs O(k) chain blocks: each chain block visited
    /// that is not in the past of the walked block is itself in its blue
    /// anticone. Returns (blues without the selected parent, reds, the sizes of
    /// the selected parent, the new blues and every older blue whose size grew,
    /// each exact with respect to blue(B)).
    fn classify_mergeset_exact(
        &self,
        mergeset: &[BlockHash],
        selected_parent: &BlockHash,
        use_index: bool,
    ) -> (Vec<BlockHash>, Vec<BlockHash>, HashMap<BlockHash, usize>) {
        let k = self.k;
        let mut blues: Vec<BlockHash> = Vec::new();
        let mut reds: Vec<BlockHash> = Vec::new();
        // |anticone(x) ∩ blue| for every blue looked at so far, exact while < k
        // and stored as k once it reaches k (such an x turns every candidate in
        // its anticone red, so it never grows further).
        let mut sizes: HashMap<BlockHash, usize> = HashMap::new();
        let mut changed: HashSet<BlockHash> = HashSet::new();
        // blue(sp) ⊂ past(sp): the selected parent starts with an empty blue anticone.
        sizes.insert(*selected_parent, 0);
        changed.insert(*selected_parent);

        for &candidate in mergeset {
            let anticone = match self.exact_candidate_blue_anticone(selected_parent, &blues, &candidate, use_index) {
                Some(a) => a,
                None => {
                    reds.push(candidate); // (a): more than k blues in its anticone
                    continue;
                }
            };
            let mut fits = true;
            for x in &anticone {
                let s = match sizes.get(x) {
                    Some(s) => *s,
                    None => {
                        let s = self.exact_blue_anticone_size(x, selected_parent, &blues, use_index);
                        sizes.insert(*x, s);
                        s
                    }
                };
                if s + 1 > k {
                    fits = false; // (b): x would exceed k
                    break;
                }
            }
            if !fits {
                reds.push(candidate);
                continue;
            }
            for x in &anticone {
                if let Some(s) = sizes.get_mut(x) {
                    *s += 1;
                }
                changed.insert(*x);
            }
            sizes.insert(candidate, anticone.len());
            changed.insert(candidate);
            blues.push(candidate);
        }

        let anticone_sizes = changed
            .into_iter()
            .map(|h| {
                let s = sizes.get(&h).copied().unwrap_or(0);
                (h, s)
            })
            .collect();
        (blues, reds, anticone_sizes)
    }

    /// The blues in `candidate`'s anticone, or `None` as soon as there are more
    /// than k. The blue set is blue(sp) ∪ {sp} ∪ `blues`; it is enumerated as
    /// sp and `blues` (the block under construction), then, for each chain
    /// block d from sp down, sp(d) and d's mergeset blues. The walk stops after
    /// d once sp(d) is in the candidate's past: all remaining blues are below.
    ///
    /// A candidate is never in the past of a listed blue: candidates come in
    /// topological order and are not in past(sp), so only `y ∈ past(c)` needs a
    /// test.
    fn exact_candidate_blue_anticone(
        &self,
        selected_parent: &BlockHash,
        blues: &[BlockHash],
        candidate: &BlockHash,
        use_index: bool,
    ) -> Option<Vec<BlockHash>> {
        let k = self.k;
        let mut out: Vec<BlockHash> = Vec::with_capacity(k + 1);
        for y in std::iter::once(selected_parent).chain(blues.iter()) {
            if !self.dag_ancestor(y, candidate, use_index) {
                out.push(*y);
                if out.len() > k {
                    return None;
                }
            }
        }
        let mut d = *selected_parent;
        while let Some(dd) = self.store.get(&d) {
            let dsp = match dd.selected_parent {
                Some(p) => p,
                None => break, // genesis: blue(genesis) is empty
            };
            let dsp_in_past = self.dag_ancestor(&dsp, candidate, use_index);
            if !dsp_in_past {
                out.push(dsp);
                if out.len() > k {
                    return None;
                }
            }
            for y in &dd.mergeset_blues {
                if !self.dag_ancestor(y, candidate, use_index) {
                    out.push(*y);
                    if out.len() > k {
                        return None;
                    }
                }
            }
            if dsp_in_past {
                break;
            }
            d = dsp;
        }
        Some(out)
    }

    /// |anticone(x) ∩ blue| for a blue `x`, where blue = blue(sp) ∪ {sp} ∪
    /// `blues`, capped at k (the caller only needs to know whether it reached
    /// k). Same enumeration as [`exact_candidate_blue_anticone`], testing both
    /// directions of ancestry, and stopping once the chain reaches `x` or its
    /// past.
    fn exact_blue_anticone_size(
        &self,
        x: &BlockHash,
        selected_parent: &BlockHash,
        blues: &[BlockHash],
        use_index: bool,
    ) -> usize {
        let cap = self.k;
        let in_anticone = |y: &BlockHash| {
            y != x && !self.dag_ancestor(y, x, use_index) && !self.dag_ancestor(x, y, use_index)
        };
        let mut n = 0usize;
        for y in std::iter::once(selected_parent).chain(blues.iter()) {
            if in_anticone(y) {
                n += 1;
                if n >= cap {
                    return cap;
                }
            }
        }
        let mut d = *selected_parent;
        loop {
            if d == *x {
                break; // blue(x) ⊂ past(x)
            }
            let dd = match self.store.get(&d) {
                Some(dd) => dd,
                None => break,
            };
            let dsp = match dd.selected_parent {
                Some(p) => p,
                None => break,
            };
            for y in std::iter::once(&dsp).chain(dd.mergeset_blues.iter()) {
                if in_anticone(y) {
                    n += 1;
                    if n >= cap {
                        return cap;
                    }
                }
            }
            if dsp == *x || self.dag_ancestor(&dsp, x, use_index) {
                break;
            }
            d = dsp;
        }
        n
    }

    /// PoW work of a block (the `work` it was added with), for Kaspa blue work.
    ///
    /// Taken from the cache, or derived from stored `GhostdagData`: below the
    /// activation `blue_work = sp.blue_work + work`, at or above it
    /// `blue_work = sp.blue_work + Σ work(mergeset blues) + work`. Both invert
    /// exactly; the recursion only descends into mergeset blues (ancestors), so
    /// it terminates. Iterative, with results recorded in `memo`.
    fn work_of(&self, block: &BlockHash, memo: &mut HashMap<BlockHash, u128>) -> u128 {
        let known = |h: &BlockHash, memo: &HashMap<BlockHash, u128>| {
            self.block_work.get(h).or_else(|| memo.get(h)).copied()
        };
        if let Some(w) = known(block, memo) {
            return w;
        }
        let mut stack = vec![*block];
        while let Some(&h) = stack.last() {
            if known(&h, memo).is_some() {
                stack.pop();
                continue;
            }
            let d = match self.store.get(&h) {
                Some(d) => d,
                None => {
                    memo.insert(h, 0);
                    stack.pop();
                    continue;
                }
            };
            let sp_work = d
                .selected_parent
                .and_then(|p| self.store.get(&p))
                .map(|p| p.blue_work)
                .unwrap_or(0);
            let own_and_merged = d.blue_work.saturating_sub(sp_work);
            if d.selected_parent.is_none() || !self.is_hardened_at(d.height) {
                memo.insert(h, own_and_merged);
                stack.pop();
                continue;
            }
            let missing: Vec<BlockHash> = d
                .mergeset_blues
                .iter()
                .filter(|m| known(m, memo).is_none())
                .copied()
                .collect();
            if missing.is_empty() {
                let merged: u128 = d.mergeset_blues.iter().filter_map(|m| known(m, memo)).sum();
                memo.insert(h, own_and_merged.saturating_sub(merged));
                stack.pop();
            } else {
                stack.extend(missing);
            }
        }
        known(block, memo).unwrap_or(0)
    }

    /// The merge-depth root of a block with this selected parent and blue
    /// score: the highest block of the selected chain (from the selected parent
    /// down) whose blue_score is at most `blue_score - MERGE_DEPTH`; `None` while
    /// the chain is shallower than `MERGE_DEPTH`. At most `MERGE_DEPTH` steps,
    /// since blue_score strictly decreases down the chain.
    fn merge_depth_root(&self, selected_parent: &BlockHash, blue_score: u64) -> Option<BlockHash> {
        let required = blue_score.checked_sub(MERGE_DEPTH)?;
        let mut d = *selected_parent;
        loop {
            let dd = self.store.get(&d)?;
            if dd.blue_score <= required {
                return Some(d);
            }
            d = dd.selected_parent?;
        }
    }

    /// Bounded merge depth (audit DAG-7), as in Kaspa: every red of the
    /// mergeset must be in the future of the merge-depth root, or in the past
    /// of a mergeset blue that is ("kosherized").
    fn check_merge_depth(
        &self,
        selected_parent: &BlockHash,
        blue_score: u64,
        blues: &[BlockHash],
        reds: &[BlockHash],
        use_index: bool,
    ) -> Result<(), ConsensusError> {
        let root = match self.merge_depth_root(selected_parent, blue_score) {
            Some(r) => r,
            None => return Ok(()),
        };
        let above_root = |h: &BlockHash| *h == root || self.dag_ancestor(&root, h, use_index);
        let kosherizing: Vec<&BlockHash> = blues.iter().filter(|b| above_root(b)).collect();
        for red in reds {
            if above_root(red) {
                continue;
            }
            if kosherizing.iter().any(|b| self.dag_ancestor(red, b, use_index)) {
                continue;
            }
            return Err(ConsensusError::MergeDepthViolation { red: *red });
        }
        Ok(())
    }

    /// Parents for a block template (audit DAG-2 / DAG-7).
    ///
    /// Returns at most `max_parents` of `candidates` (normally the bodied tips)
    /// such that a block with exactly these parents, in this order, is accepted
    /// by [`add_block`](Self::add_block): the first entry is the block's
    /// selected parent (the heaviest candidate by blue work, blue score, hash —
    /// the same rule `add_block` applies), and the others follow by decreasing
    /// blue work.
    ///
    /// Below the hardening activation (judged at the template's height,
    /// `selected_parent.height + 1`) this is the heaviest `max_parents`
    /// candidates. At or above it, a candidate is added only while the
    /// mergeset stays within [`MAX_MERGESET_SIZE`], and parents that would make
    /// the block merge a red below the merge-depth root are then dropped, as
    /// Kaspa's virtual-parent selection does.
    ///
    /// Template code should call it as
    /// `dag.select_parents_for_template(&dag.bodied_tips(has_body), core::MAX_PARENTS)`
    /// and use the result as `header.parents` unchanged. Unknown candidates
    /// are ignored. With a single candidate the result is that candidate.
    pub fn select_parents_for_template(&self, candidates: &[BlockHash], max_parents: usize) -> Vec<BlockHash> {
        let key = |h: &BlockHash| {
            let d = self.store.get(h);
            (d.map(|d| d.blue_work).unwrap_or(0), d.map(|d| d.blue_score).unwrap_or(0), *h)
        };
        let mut cands: Vec<BlockHash> = candidates.iter().copied().filter(|h| self.store.has(h)).collect();
        cands.sort_by_key(|h| std::cmp::Reverse(key(h)));
        cands.dedup();
        if cands.is_empty() || max_parents == 0 {
            return Vec::new();
        }
        let sp = cands[0];
        let height = self.store.get(&sp).map(|d| d.height + 1).unwrap_or(1);
        if !self.is_hardened_at(height) {
            cands.truncate(max_parents);
            return cands;
        }

        let use_index = self.ancestry_index_ready(&cands, &sp);
        let budget = MAX_MERGESET_SIZE - 1;
        let mut chosen = vec![sp];
        let mut merged: HashSet<BlockHash> = HashSet::new();
        for c in cands.iter().skip(1) {
            if chosen.len() >= max_parents {
                break;
            }
            if merged.contains(c) || self.dag_ancestor(c, &sp, use_index) {
                continue; // adds nothing to the mergeset
            }
            // The blocks `c` would add to the mergeset, bounded by the budget.
            let mut added: Vec<BlockHash> = Vec::new();
            let mut seen: HashSet<BlockHash> = HashSet::new();
            let mut queue: VecDeque<BlockHash> = VecDeque::from([*c]);
            let mut over = false;
            while let Some(h) = queue.pop_front() {
                if h == sp || merged.contains(&h) || !seen.insert(h) || self.dag_ancestor(&h, &sp, use_index) {
                    continue;
                }
                added.push(h);
                if merged.len() + added.len() > budget {
                    over = true;
                    break;
                }
                if let Some(d) = self.store.get(&h) {
                    queue.extend(d.parents.iter().copied());
                }
            }
            if over {
                continue;
            }
            merged.extend(added);
            chosen.push(*c);
        }

        // Drop parents responsible for merge-depth violations, re-checking
        // with the consensus code until the template is valid. Each round
        // removes at least one parent; the selected parent alone always is.
        loop {
            match self.compute_block(&chosen, 0, 0) {
                Ok(_) => break,
                Err(ConsensusError::MergeDepthViolation { red }) => {
                    let before = chosen.len();
                    chosen.retain(|p| *p == sp || !(*p == red || self.dag_ancestor(&red, p, use_index)));
                    if chosen.len() == before {
                        chosen.truncate(1);
                    }
                }
                Err(_) => {
                    chosen.truncate(1);
                    break;
                }
            }
        }
        chosen
    }

    /// Compute |anticone(candidate) ∩ blue_set|
    fn anticone_size_in_set(&self, candidate: &BlockHash, blue_set: &HashSet<BlockHash>) -> usize {
        blue_set.iter()
            .filter(|&b| self.is_in_anticone(candidate, b))
            .count()
    }

    /// Check if `a` and `b` are in each other's anticone
    /// (neither is ancestor of the other)
    fn is_in_anticone(&self, a: &BlockHash, b: &BlockHash) -> bool {
        if a == b { return false; }
        !is_ancestor(&self.store, a, b) && !is_ancestor(&self.store, b, a)
    }

    /// Collect blue blocks in the past of `block` by walking the selected chain.
    ///
    /// Audit H-5 fix: previously bounded at `2*K = 20` selected-chain hops
    /// (with K=10), which under-counted the anticone when the DAG had
    /// branches extending beyond that window. A red block could then be
    /// classified blue, causing `blue_score` to diverge between nodes — a
    /// silent consensus split.
    ///
    /// The short-term mitigation here is to raise the bound to `K*100`
    /// (1000 hops with K=10) and log a warning whenever the bound is hit,
    /// so misclassifications become observable in production even before
    /// the long-term fix (Kaspa-style reachability tree) lands.
    ///
    /// A node that sees these warnings regularly should open a bug — it
    /// means the DAG has drift exceeding the bound and a reachability tree
    /// is now a critical upgrade for that deployment.
    fn past_blue_set(&self, block: &BlockHash) -> HashSet<BlockHash> {
        let mut blue = HashSet::new();
        let mut cur = Some(*block);
        let max_depth = self.k * 100;
        let mut depth = 0usize;
        while let Some(h) = cur {
            if depth >= max_depth {
                warn!(
                    "past_blue_set hit depth bound of {} (K*100) walking from block {} — \
                     classification may under-count anticone. If this repeats, a reachability \
                     tree upgrade is now required for correctness.",
                    max_depth,
                    hex::encode(block),
                );
                break;
            }
            if let Some(data) = self.store.get(&h) {
                for mb in &data.mergeset_blues {
                    blue.insert(*mb);
                }
                cur = data.selected_parent;
                depth += 1;
            } else {
                break;
            }
        }
        blue
    }

    // ── Public query API ────────────────────────────────────────────────────

    /// Best tip: highest blue_work, then blue_score, then hash
    pub fn selected_tip(&self) -> Option<BlockHash> {
        self.store.tips.iter()
            .max_by(|a, b| {
                let da = self.store.get(a);
                let db = self.store.get(b);
                let wa = da.map(|d| d.blue_work).unwrap_or(0);
                let wb = db.map(|d| d.blue_work).unwrap_or(0);
                let sa = da.map(|d| d.blue_score).unwrap_or(0);
                let sb = db.map(|d| d.blue_score).unwrap_or(0);
                wa.cmp(&wb).then(sa.cmp(&sb)).then(a.cmp(b))
            })
            .cloned()
    }

    pub fn tip_blue_score(&self) -> u64 {
        self.selected_tip()
            .and_then(|h| self.store.get(&h))
            .map(|d| d.blue_score)
            .unwrap_or(0)
    }

    pub fn tips(&self) -> Vec<BlockHash> {
        self.store.tips.iter().cloned().collect()
    }

    /// Best tip whose BODY is available, walking the selected-parent chain
    /// down from the highest-blue-work tip until a bodied block is found.
    ///
    /// A header-only tip — accepted via headers-first sync but whose body
    /// never arrived (e.g. an unreachable chain advertised by peers) — is
    /// UNMINEABLE: a block built on it cannot be validated by accept_block,
    /// so the internal miner and stratum silently stall on a phantom parent.
    /// This is exactly what wedged the founder at H=3737 behind a bodyless
    /// H=3738 header. `has_body(&hash)` must return true iff the full block
    /// body is present in block storage.
    pub fn best_bodied_tip<F: Fn(&BlockHash) -> bool>(&self, has_body: F) -> Option<BlockHash> {
        // Resolve EVERY tip to a bodied candidate — the tip itself when its
        // body is present, else its nearest bodied ancestor along the
        // selected-parent chain — then return the heaviest candidate under
        // GhostDAG's own tip ordering (blue_work, then blue_score, then hash).
        //
        // This deliberately EXCLUDES a header-only tip from selection. A
        // dominant-blue_work but BODILESS tip — e.g. a persisted N-way merge
        // header whose body never arrived — can never be extended, so the miner
        // must build on the heaviest tip we actually hold a body for. The prior
        // implementation walked selected_parent down from the single
        // highest-blue_work tip and so returned that phantom's bodied ANCESTOR,
        // leaving the miner producing sibling blocks that always lost the
        // blue_work race to the phantom → a persisted deadlock no restart could
        // clear (h3757/b3ee487b). Scanning all tips instead lets a freshly-mined
        // bodied tip win selection and the chain advance. Recomputed from the
        // store on every call — no persisted latch, so this is restart-safe.
        let mut best: Option<BlockHash> = None;
        for tip in self.store.tips.iter() {
            // Nearest bodied block at or below this tip.
            let mut cur = Some(*tip);
            let candidate = loop {
                match cur {
                    Some(h) if has_body(&h)  => break Some(h),
                    Some(h)                  => cur = self.store.get(&h).and_then(|d| d.selected_parent),
                    None                     => break None,
                }
            };
            if let Some(c) = candidate {
                best = Some(match best {
                    None => c,
                    Some(b) => {
                        let dc = self.store.get(&c);
                        let db = self.store.get(&b);
                        let wc = dc.map(|d| d.blue_work).unwrap_or(0);
                        let wb = db.map(|d| d.blue_work).unwrap_or(0);
                        let sc = dc.map(|d| d.blue_score).unwrap_or(0);
                        let sb = db.map(|d| d.blue_score).unwrap_or(0);
                        if wc.cmp(&wb).then(sc.cmp(&sb)).then(c.cmp(&b)).is_gt() { c } else { b }
                    }
                });
            }
        }
        best
    }

    /// Tips that are safe to mine on: those whose body is available. When
    /// every tip is header-only, falls back to the nearest bodied ancestor
    /// via [`best_bodied_tip`] so mining never stalls on a phantom parent.
    pub fn bodied_tips<F: Fn(&BlockHash) -> bool>(&self, has_body: F) -> Vec<BlockHash> {
        let bodied: Vec<BlockHash> = self.store.tips.iter()
            .filter(|h| has_body(h))
            .cloned()
            .collect();
        if !bodied.is_empty() {
            return bodied;
        }
        self.best_bodied_tip(has_body).into_iter().collect()
    }

    pub fn block_count(&self) -> usize {
        self.store.data.len()
    }

    pub fn has_block(&self, hash: &BlockHash) -> bool {
        self.store.has(hash)
    }

    pub fn get_block_data(&self, hash: &BlockHash) -> Option<&GhostdagData> {
        self.store.get(hash)
    }

    /// Selected parent chain from best tip (the "virtual selected chain")
    pub fn selected_chain(&self) -> Vec<BlockHash> {
        let mut chain = Vec::new();
        let mut cur = self.selected_tip();
        while let Some(h) = cur {
            chain.push(h);
            cur = self.store.get(&h).and_then(|d| d.selected_parent);
        }
        chain
    }

    /// Is `hash` in the blue set of the current DAG?
    /// Bounded check: walks selected chain up to 2*K depth.
    pub fn is_blue(&self, hash: &BlockHash) -> bool {
        if let Some(tip) = self.selected_tip() {
            let blue = self.past_blue_set(&tip);
            return blue.contains(hash);
        }
        false
    }

    /// Finality: a block is final if its blue_score is more than
    /// CHECKPOINT_DEPTH below the current tip.
    ///
    /// Audit H-6 fix: previously used a local `FINALITY_DEPTH = 86_400` (~10 days
    /// at 10s block time) which disagreed with `core::CHECKPOINT_DEPTH = 1_000`
    /// used by the finalization checkpoint in main.rs. RPC clients saw is_final
    /// return false for 10 days on blocks the node already treated as final.
    /// Now both sides use `core::CHECKPOINT_DEPTH` as single source of truth.
    pub fn is_final(&self, hash: &BlockHash) -> bool {
        let tip_score = self.tip_blue_score();
        if let Some(data) = self.store.get(hash) {
            tip_score.saturating_sub(data.blue_score) > crate::core::CHECKPOINT_DEPTH
        } else {
            false
        }
    }

    /// Ordered block hashes from blue_score `from` for IBD sync.
    ///
    /// H-R3-1: this used to `.collect()` every `GhostdagData` with
    /// `blue_score >= from_blue_score` into a `Vec`, `sort_by_key` the WHOLE
    /// thing, and only then `take(limit)` — an O(n log n) time, O(n) memory
    /// operation charged in full for every request regardless of `limit`
    /// (on the historical Genesis-3 datadir, n ~= 50,600). The directed-sync
    /// server (`network/mod.rs::serve_sync_request`) calls this inline on the
    /// swarm event loop with an attacker-supplied, unclamped `limit`, so an
    /// unbounded `limit` (e.g. `u32::MAX`) forced a full-DAG sort per 13-byte
    /// request on the very thread that also drives block propagation.
    ///
    /// INVARIANT (H-R3-1): this call is O(n) time — a HashMap keyed by hash
    /// gives no cheaper way to find "blue_score >= from" without an
    /// auxiliary index — but MUST be O(limit) memory, never O(n) memory. A
    /// max-heap bounded to capacity `limit` gives both: keep only the
    /// `limit` smallest qualifying blue_scores seen so far, evicting the
    /// current maximum whenever a smaller candidate arrives and the heap is
    /// already full. Ties break on hash for a deterministic result (the
    /// previous `sort_by_key` broke ties on HashMap iteration order, which is
    /// not consensus-critical but was needlessly nondeterministic).
    pub fn ordered_hashes_from(&self, from_blue_score: u64, limit: usize) -> Vec<BlockHash> {
        if limit == 0 {
            return Vec::new();
        }
        use std::collections::BinaryHeap;

        // `BinaryHeap` is a max-heap: `peek()`/`pop()` always return the
        // LARGEST retained entry — exactly the one to evict when a smaller
        // candidate shows up and the heap is already at `limit` capacity.
        let cap = limit.min(self.store.data.len().saturating_add(1));
        let mut heap: BinaryHeap<(u64, BlockHash)> = BinaryHeap::with_capacity(cap);
        for (h, d) in self.store.data.iter() {
            if d.blue_score < from_blue_score {
                continue;
            }
            if heap.len() < limit {
                heap.push((d.blue_score, *h));
            } else if let Some(&(max_score, max_hash)) = heap.peek() {
                if (d.blue_score, *h) < (max_score, max_hash) {
                    heap.pop();
                    heap.push((d.blue_score, *h));
                }
            }
        }
        let mut out: Vec<(u64, BlockHash)> = heap.into_vec();
        out.sort_unstable();
        out.into_iter().map(|(_, h)| h).collect()
    }

    pub fn get_node(&self, hash: &BlockHash) -> Option<&GhostdagData> {
        self.store.get(hash)
    }
}

// ── Errors ────────────────────────────────────────────────────────────────────

/// Errors returned by consensus operations.
///
/// Introduced by audit finding M-9 — previously `add_block` used `assert!`
/// for its preconditions and panicked the whole process when an invalid
/// block somehow reached the consensus layer. This enum lets callers
/// reject bad input cleanly.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ConsensusError {
    /// A block was submitted with an empty parents vector. Only the genesis
    /// block is allowed to have no parents, and genesis goes through
    /// `add_genesis`, not `add_block`.
    #[error("block has no parents — only genesis can have zero parents, and genesis uses add_genesis()")]
    NoParents,

    /// A block with this hash is already present in the DAG. The caller
    /// should treat this as a duplicate-announcement case rather than an
    /// error on the consensus layer.
    #[error("block already in DAG: {}", hex::encode(.0))]
    DuplicateBlock(BlockHash),

    /// The block's selected parent is not present in the DAG store. In the
    /// normal path this cannot happen — the sync/gossip layer buffers blocks
    /// with missing parents in the orphan pool and only calls `add_block`
    /// once every parent is known. This variant completes the Audit M-9
    /// hardening: if a block ever reaches `add_block` with an absent selected
    /// parent, reject it cleanly instead of panicking the node.
    #[error("selected parent not in DAG: {}", hex::encode(.0))]
    MissingSelectedParent(BlockHash),

    /// Audit DAG-7 (at or above the hardening activation): the block's
    /// mergeset, selected parent included, has more than `limit` blocks.
    #[error("mergeset exceeds {limit} blocks (selected parent included)")]
    MergesetTooLarge { limit: usize },

    /// Audit DAG-7 (at or above the hardening activation): the block merges a
    /// red block that is neither in the future of its merge-depth root nor in
    /// the past of a merged blue block that is.
    #[error("merges red block {} below the merge-depth root", hex::encode(.red))]
    MergeDepthViolation { red: BlockHash },
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hash(n: u8) -> BlockHash {
        let mut h = [0u8; 32];
        h[0] = n;
        h
    }

    /// WS-A: the corrected-coloring gate is armed to a FUTURE height. A Legacy
    /// (production) DAG stays Legacy below the gate — so all already-mined
    /// history keeps its coloring, no reorg / no balance recompute — and flips
    /// to the exact index-based `Fast` coloring at/above it. Arming the gate also
    /// turns on reachability-index maintenance from genesis so `Fast` is ready by
    /// the activation height.
    #[test]
    fn corrected_coloring_gate_is_armed_at_future_height() {
        assert_ne!(
            CORRECTED_COLORING_ACTIVATION_HEIGHT, u64::MAX,
            "WS-A: gate must be armed to a real future height, not disabled",
        );
        let dag = GhostDAG::with_default_k(); // Legacy constructor = production path
        assert!(
            dag.maintains_reachability_index(),
            "an armed gate must maintain the reachability index from genesis",
        );
        // GnB: exact coloring from genesis.
        assert_eq!(CORRECTED_COLORING_ACTIVATION_HEIGHT, 0);
        assert!(matches!(dag.effective_coloring(0), ColoringMode::Fast));
        assert!(matches!(dag.effective_coloring(1), ColoringMode::Fast));
    }

    #[test]
    fn genesis_blue_score_zero() {
        let mut dag = GhostDAG::with_k(3);
        dag.add_genesis(make_hash(0), 1000);
        assert_eq!(dag.tip_blue_score(), 0);
        assert_eq!(dag.block_count(), 1);
    }

    #[test]
    fn linear_chain_blue_scores() {
        let mut dag = GhostDAG::with_k(3);
        let g = make_hash(0);
        dag.add_genesis(g, 0);

        let b1 = make_hash(1);
        dag.add_block(b1, vec![g], 1, 1000).unwrap();
        assert_eq!(dag.store.get(&b1).unwrap().blue_score, 1);

        let b2 = make_hash(2);
        dag.add_block(b2, vec![b1], 2, 1000).unwrap();
        assert_eq!(dag.store.get(&b2).unwrap().blue_score, 2);

        let b3 = make_hash(3);
        dag.add_block(b3, vec![b2], 3, 1000).unwrap();
        assert_eq!(dag.store.get(&b3).unwrap().blue_score, 3);
    }

    /// H-R3-1 regression: `ordered_hashes_from` must return exactly the
    /// `limit` smallest qualifying blue_scores, in ascending order — the same
    /// observable result the old "collect everything, sort, take(limit)"
    /// implementation produced, but via the O(n)/O(limit) bounded-heap path.
    /// Reverting to a naive `.filter().collect()` without the `limit`
    /// respected before materialising would still pass this on correctness,
    /// but the point of the invariant is memory/CPU, not just the return
    /// value — see `ordered_hashes_from_never_returns_more_than_limit` below
    /// for the bound this test's sibling pins.
    #[test]
    fn ordered_hashes_from_ascending_and_correct() {
        let mut dag = GhostDAG::with_k(3);
        let g = make_hash(0);
        dag.add_genesis(g, 0);
        let mut prev = g;
        for i in 1..=10u8 {
            let b = make_hash(i);
            dag.add_block(b, vec![prev], i as u64, 1000u128 + i as u128).unwrap();
            prev = b;
        }
        // blue_scores present: 0..=10. Ask from 3, limit 4 -> expect the four
        // smallest qualifying scores: 3,4,5,6 (hashes 3,4,5,6), ascending.
        let got = dag.ordered_hashes_from(3, 4);
        assert_eq!(
            got,
            vec![make_hash(3), make_hash(4), make_hash(5), make_hash(6)],
            "must return the smallest `limit` qualifying blue_scores, ascending"
        );
    }

    /// H-R3-1 regression: `limit` bounds the OUTPUT (and, by construction of
    /// the fix, the heap's peak memory) regardless of how many blocks in the
    /// DAG satisfy `blue_score >= from_blue_score`. This is the property a
    /// naive revert-to-full-sort would still satisfy for correctness of the
    /// truncation itself, but pairs with the doc-invariant above: the fix is
    /// that the heap here never holds more than `limit` entries at any point
    /// during the scan, not merely that the final `Vec` is short.
    #[test]
    fn ordered_hashes_from_never_returns_more_than_limit() {
        let mut dag = GhostDAG::with_k(3);
        let g = make_hash(0);
        dag.add_genesis(g, 0);
        let mut prev = g;
        for i in 1..=50u8 {
            let b = make_hash(i);
            dag.add_block(b, vec![prev], i as u64, 1000u128 + i as u128).unwrap();
            prev = b;
        }
        let got = dag.ordered_hashes_from(0, 5);
        assert_eq!(got.len(), 5, "limit must bound the result even with 51 qualifying blocks");
        assert_eq!(got, vec![make_hash(0), make_hash(1), make_hash(2), make_hash(3), make_hash(4)]);

        // limit larger than the qualifying set returns everything, still ascending.
        let all = dag.ordered_hashes_from(48, 100);
        assert_eq!(all, vec![make_hash(48), make_hash(49), make_hash(50)]);

        // limit == 0 returns empty without touching the store.
        assert_eq!(dag.ordered_hashes_from(0, 0), Vec::<BlockHash>::new());
    }

    #[test]
    fn missing_selected_parent_is_rejected_not_panic() {
        // Audit M-9 completion: a block whose parent is unknown to the DAG
        // must return ConsensusError::MissingSelectedParent, never panic.
        let mut dag = GhostDAG::with_k(3);
        dag.add_genesis(make_hash(0), 0);

        let unknown_parent = make_hash(200);
        let child = make_hash(201);
        let err = dag.add_block(child, vec![unknown_parent], 1, 1000).unwrap_err();
        assert!(matches!(err, ConsensusError::MissingSelectedParent(p) if p == unknown_parent));
        // DAG must be unchanged — only genesis present.
        assert_eq!(dag.block_count(), 1);
        assert!(!dag.store.has(&child));
    }

    #[test]
    fn parallel_blocks_merged() {
        //  G ─ A
        //  └── B
        //      └── C (merges A and B)
        let mut dag = GhostDAG::with_k(3);
        let g = make_hash(0);
        let a = make_hash(1);
        let b = make_hash(2);
        let c = make_hash(3);

        dag.add_genesis(g, 0);
        dag.add_block(a, vec![g], 1, 1000).unwrap();
        dag.add_block(b, vec![g], 2, 1000).unwrap();
        // C references both A and B
        let data_c = dag.add_block(c, vec![a, b], 3, 1000).unwrap();

        // C should merge both A and B — both should be blue (k=3)
        assert!(!data_c.mergeset_blues.is_empty() || !data_c.mergeset_reds.is_empty());
        assert!(dag.block_count() == 4);
    }

    #[test]
    fn selected_parent_is_highest_blue_work() {
        let mut dag = GhostDAG::with_k(3);
        let g = make_hash(0);
        dag.add_genesis(g, 0);

        // Chain 1: g -> a -> b (blue_score 2)
        let a = make_hash(1);
        let b = make_hash(2);
        dag.add_block(a, vec![g], 1, 1000).unwrap();
        dag.add_block(b, vec![a], 2, 1000).unwrap();

        // Chain 2: g -> c (blue_score 1)
        let c = make_hash(3);
        dag.add_block(c, vec![g], 3, 1000).unwrap();

        // Block d merges b and c — selected parent should be b (higher blue_score)
        let d = make_hash(4);
        let data_d = dag.add_block(d, vec![b, c], 4, 1000).unwrap();
        assert_eq!(data_d.selected_parent, Some(b));
    }

    #[test]
    fn tips_updated_correctly() {
        let mut dag = GhostDAG::with_k(3);
        let g = make_hash(0);
        dag.add_genesis(g, 0);
        assert_eq!(dag.tips().len(), 1);

        let a = make_hash(1);
        dag.add_block(a, vec![g], 1, 1000).unwrap();
        // g is no longer a tip
        assert!(!dag.store.tips.contains(&g));
        assert!(dag.store.tips.contains(&a));

        // Two parallel blocks
        let b = make_hash(2);
        let cc = make_hash(3);
        dag.add_block(b, vec![a], 2, 1000).unwrap();
        dag.add_block(cc, vec![a], 3, 1000).unwrap();
        assert_eq!(dag.tips().len(), 2);

        // Merge them
        let d = make_hash(4);
        dag.add_block(d, vec![b, cc], 4, 1000).unwrap();
        assert_eq!(dag.tips().len(), 1);
    }

    #[test]
    fn selected_chain_is_consistent() {
        let mut dag = GhostDAG::with_k(3);
        let g = make_hash(0);
        dag.add_genesis(g, 0);
        for i in 1u8..=10 {
            let h = make_hash(i);
            dag.add_block(h, vec![make_hash(i-1)], i as u64, 1000).unwrap();
        }
        let chain = dag.selected_chain();
        assert_eq!(chain.len(), 11); // genesis + 10 blocks
        assert_eq!(chain[0], make_hash(10)); // tip first
        assert_eq!(*chain.last().unwrap(), g);
    }

    // ── M-9 regression tests ────────────────────────────────────────────────

    #[test]
    fn add_block_rejects_no_parents() {
        let mut dag = GhostDAG::with_k(3);
        let g = make_hash(0);
        dag.add_genesis(g, 0);

        // A block with no parents must not be accepted — only genesis is
        // allowed to have zero parents, and genesis uses add_genesis().
        let orphan = make_hash(99);
        let err = dag.add_block(orphan, vec![], 1, 1000).unwrap_err();
        assert_eq!(err, ConsensusError::NoParents);
        // Store must be untouched
        assert!(dag.store.get(&orphan).is_none());
        assert_eq!(dag.block_count(), 1);
    }

    #[test]
    fn add_block_rejects_duplicate_hash() {
        let mut dag = GhostDAG::with_k(3);
        let g = make_hash(0);
        dag.add_genesis(g, 0);

        let a = make_hash(1);
        dag.add_block(a, vec![g], 1, 1000).unwrap();

        // Second attempt with the same hash must fail without panicking.
        let err = dag.add_block(a, vec![g], 2, 1000).unwrap_err();
        assert_eq!(err, ConsensusError::DuplicateBlock(a));
        assert_eq!(dag.block_count(), 2); // g + a, not 3
    }

    #[test]
    fn add_block_errors_are_not_fatal_to_subsequent_blocks() {
        // Key property of the M-9 fix: a bad call no longer aborts the
        // process, so the DAG can keep accepting valid blocks after it.
        let mut dag = GhostDAG::with_k(3);
        let g = make_hash(0);
        dag.add_genesis(g, 0);

        let _ = dag.add_block(make_hash(50), vec![], 1, 1000); // bad: no parents
        let _ = dag.add_block(g, vec![g], 1, 1000);            // bad: duplicate

        // The DAG is still usable.
        let a = make_hash(1);
        dag.add_block(a, vec![g], 1, 1000).unwrap();
        assert_eq!(dag.store.get(&a).unwrap().blue_score, 1);
    }

    // ── H-5 regression tests ────────────────────────────────────────────────

    #[test]
    fn past_blue_set_walks_beyond_old_2k_bound() {
        // H-5 regression test.
        //
        // The previous bound was `self.k * 2` selected-chain hops (20 hops
        // when K=10). Any blue block deeper than 20 hops was silently
        // dropped from past_blue_set, under-counting the anticone — the
        // core symptom of audit H-5.
        //
        // We cannot exercise the bound with a linear chain because
        // `mergeset_blues` is empty at every linear position (no
        // sibling blocks merging in). So we build 30 iterations of
        //
        //     Left_i  = [prev]
        //     Right_i = [prev]          (sibling of Left_i)
        //     Merge_i = [Left_i, Right_i]
        //     prev = Merge_i
        //
        // Each Merge_i contributes exactly one block to its
        // `mergeset_blues` (the non-selected one of Left_i / Right_i),
        // so past_blue_set picks up 1 blue per Merge encountered on the
        // selected chain. K=100 is chosen large enough that every
        // mergeset block stays blue — the test is about the bound, not
        // PHANTOM classification logic.
        //
        // The selected chain from the tip is
        //     Merge_30 → SelectedSibling_30 → Merge_29 → SelectedSibling_29
        //              → ... → SelectedSibling_1 → G
        // — 61 hops total. With the old K*2=200 bound (K=100 here) we'd
        // walk all 61 hops anyway, so we pick K=10 to exercise the OLD
        // failure mode. But K=10 means PHANTOM's K-constraint kicks in
        // and some mergeset blocks go red. To sidestep that, we build
        // with K=100 and construct a chain ≥ 200 hops so the old bound
        // (2*K=200) would still truncate it.
        //
        // 80 iterations × (3 blocks per iteration) = 240 blocks.
        // Selected chain from tip: 2 hops per iteration × 80 + genesis = 161
        // hops. That's below the old 2*K=200 bound, so let's push further.
        // 110 iterations → 221 hops on the selected chain, and 110 blues in
        // mergeset_blues. Old bound (200) truncates at Merge_~10, giving
        // ~100 blues. New bound (K*100 = 10_000) walks everything.

        fn h(kind: u8, i: u16) -> BlockHash {
            let mut out = [0u8; 32];
            out[0] = kind;
            out[1] = (i >> 8) as u8;
            out[2] = (i & 0xff) as u8;
            out
        }

        let mut dag = GhostDAG::with_k(100);
        let g = make_hash(0);
        dag.add_genesis(g, 0);

        let iterations: u16 = 110;
        let mut prev = g;
        for i in 1..=iterations {
            let l = h(b'L', i);
            let r = h(b'R', i);
            let m = h(b'M', i);
            dag.add_block(l, vec![prev], (3 * i) as u64, 1000).unwrap();
            dag.add_block(r, vec![prev], (3 * i + 1) as u64, 1000).unwrap();
            dag.add_block(m, vec![l, r], (3 * i + 2) as u64, 1000).unwrap();
            prev = m;
        }

        let blues = dag.past_blue_set(&prev);

        // With K=100, old bound = 2*K = 200 selected-chain hops. We have 221
        // hops on the selected chain and 110 Merges contributing one blue
        // each. Old bound truncates at hop 200 (after ~100 Merges walked) →
        // ~100 blues. New bound (K*100 = 10_000) walks all 221 hops → 110
        // blues. Assert strictly > old maximum to prove we're past it.
        assert!(
            blues.len() > 100,
            "past_blue_set returned only {} blues from a {}-iteration \
             merging DAG (chain length ~{} hops). Old 2*K=200 bound would \
             give about 100; new K*100=10000 bound should give {}. \
             H-5 fix has regressed.",
            blues.len(),
            iterations,
            2 * iterations + 1,
            iterations,
        );
    }

    /// Property-only check: the `past_blue_set` code path must not panic or
    /// loop on a long linear chain. This is a weaker regression guard than
    /// the merging-DAG test above — linear chains have empty mergesets at
    /// every position, so this call returns {} by construction — but it
    /// pins the invariant that the bound-increase doesn't break the
    /// traversal shape.
    #[test]
    fn past_blue_set_long_linear_chain_does_not_panic() {
        let mut dag = GhostDAG::with_k(10);
        let g = make_hash(0);
        dag.add_genesis(g, 0);
        let mut prev = g;
        for i in 1u16..=200 {
            let mut hx = [0u8; 32];
            hx[0] = (i >> 8) as u8;
            hx[1] = (i & 0xff) as u8;
            hx[2] = 0xaa;
            dag.add_block(hx, vec![prev], i as u64, 1000).unwrap();
            prev = hx;
        }
        // Linear chain → empty mergesets at every position → {} result.
        // The assertion is merely that we completed without panicking.
        let blues = dag.past_blue_set(&prev);
        assert_eq!(
            blues.len(), 0,
            "linear chain has no merges, so past_blue_set must be empty; \
             got {} entries — this indicates a new code path was added \
             that the bound test must account for",
            blues.len(),
        );
    }
}

// ── Property-based GhostDAG invariants (security scanner lane) ───────────────
//
// GhostDAG ordering is consensus-critical: if two honest nodes colour the same
// DAG differently — because block/parent ingestion order leaked into the result,
// or because a `HashMap` iteration order made colouring nondeterministic — they
// disagree on `blue_score`, hence on the selected chain, hence they fork. These
// `proptest` cases build randomly-shaped DAGs and assert the ordering is a pure
// deterministic function of the DAG structure alone. Run with:
//   `cargo test -p bloch ghostdag_proptest`
#[cfg(test)]
mod ghostdag_proptest {
    use super::*;
    use proptest::prelude::*;

    fn idx_hash(i: usize) -> BlockHash {
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&(i as u64).to_le_bytes());
        h
    }

    /// Build a DAG from a structural description. `shape[i]` is the parent-index
    /// set of block `i` (block 0 is genesis, always empty). `reverse` flips each
    /// parent vector to probe parent-order independence; `k` is the GhostDAG
    /// anticone bound.
    fn build(shape: &[Vec<usize>], k: usize, reverse: bool) -> GhostDAG {
        let mut dag = GhostDAG::with_k(k);
        dag.add_genesis(idx_hash(0), 0);
        for (i, parents) in shape.iter().enumerate().skip(1) {
            let mut ph: Vec<BlockHash> = parents.iter().map(|&j| idx_hash(j)).collect();
            if reverse {
                ph.reverse();
            }
            dag.add_block(idx_hash(i), ph, i as u64, 1000)
                .expect("well-formed block must be accepted");
        }
        dag
    }

    /// Same as `build` with an explicit hardening activation height (0 = the
    /// corrected rules from genesis; a mid-DAG height mixes both regimes).
    fn build_at(shape: &[Vec<usize>], k: usize, reverse: bool, activation: u64) -> GhostDAG {
        let mut dag = GhostDAG::with_k_and_activation(k, activation);
        dag.add_genesis(idx_hash(0), 0);
        for (i, parents) in shape.iter().enumerate().skip(1) {
            let mut ph: Vec<BlockHash> = parents.iter().map(|&j| idx_hash(j)).collect();
            if reverse {
                ph.reverse();
            }
            // Vary the work so blue work (DAG-3) is exercised, deterministically.
            let work = 1 + (i as u128 * 7919) % 1000;
            dag.add_block(idx_hash(i), ph, i as u64, work)
                .expect("well-formed block must be accepted");
        }
        dag
    }

    /// Activation heights for the hardened proptests: from genesis, or inside
    /// the DAG so both regimes and the boundary are exercised.
    fn activation_height() -> impl Strategy<Value = u64> {
        prop_oneof![Just(0u64), 1u64..12]
    }

    /// A structurally valid DAG shape: block `i` (>0) has a non-empty parent set
    /// drawn from `{0..i}`, so parents always exist when added in index order.
    fn dag_shape() -> impl Strategy<Value = (Vec<Vec<usize>>, usize)> {
        (proptest::collection::vec(any::<u64>(), 1..18usize), 1usize..6)
            .prop_map(|(seeds, k)| {
                let n = seeds.len();
                let mut shape: Vec<Vec<usize>> = Vec::with_capacity(n);
                for (i, seed) in seeds.iter().enumerate() {
                    if i == 0 {
                        shape.push(vec![]);
                        continue;
                    }
                    let mut parents: Vec<usize> =
                        (0..i).filter(|j| (seed >> (j % 64)) & 1 == 1).collect();
                    if parents.is_empty() {
                        parents.push(i - 1);
                    }
                    shape.push(parents);
                }
                (shape, k)
            })
    }

    proptest! {
        // Determinism: colouring the identical DAG twice yields byte-identical
        // per-block data. Catches any nondeterminism (e.g. HashMap iteration
        // order) leaking into blue_score / blue_work / selected_parent.
        #[test]
        fn colouring_is_deterministic((shape, k) in dag_shape()) {
            let a = build(&shape, k, false);
            let b = build(&shape, k, false);
            for i in 0..shape.len() {
                let h = idx_hash(i);
                let da = a.get_block_data(&h).unwrap();
                let db = b.get_block_data(&h).unwrap();
                prop_assert_eq!(da.blue_score, db.blue_score);
                prop_assert_eq!(da.blue_work, db.blue_work);
                prop_assert_eq!(da.selected_parent, db.selected_parent);
                prop_assert_eq!(da.height, db.height);
            }
        }

        // Parent-order independence: reversing every parent vector (as gossip
        // reordering would) must not change any block's colouring. A failure
        // here is a consensus-split vulnerability.
        #[test]
        fn colouring_ignores_parent_order((shape, k) in dag_shape()) {
            let fwd = build(&shape, k, false);
            let rev = build(&shape, k, true);
            for i in 0..shape.len() {
                let h = idx_hash(i);
                let df = fwd.get_block_data(&h).unwrap();
                let dr = rev.get_block_data(&h).unwrap();
                prop_assert_eq!(df.blue_score, dr.blue_score, "blue_score depends on parent order at block {}", i);
                prop_assert_eq!(df.blue_work, dr.blue_work);
                prop_assert_eq!(df.selected_parent, dr.selected_parent);
                prop_assert_eq!(df.height, dr.height);
            }
        }

        // Monotonicity: every non-genesis block dominates its selected parent in
        // blue_score and blue_work, and strictly increases height. Genesis is 0.
        #[test]
        fn blue_score_monotone_over_selected_parent((shape, k) in dag_shape()) {
            let dag = build(&shape, k, false);
            prop_assert_eq!(dag.get_block_data(&idx_hash(0)).unwrap().blue_score, 0);
            for i in 1..shape.len() {
                let d = dag.get_block_data(&idx_hash(i)).unwrap();
                let sp = d.selected_parent.expect("non-genesis has a selected parent");
                let sd = dag.get_block_data(&sp).unwrap();
                prop_assert!(d.blue_score >= sd.blue_score, "blue_score regressed vs selected parent at block {}", i);
                prop_assert!(d.blue_work >= sd.blue_work, "blue_work regressed vs selected parent at block {}", i);
                prop_assert!(d.height >= sd.height + 1, "height did not increase over selected parent at block {}", i);
            }
        }

        // The selected chain (tip → genesis) has non-increasing blue_score.
        #[test]
        fn selected_chain_blue_score_non_increasing((shape, k) in dag_shape()) {
            let dag = build(&shape, k, false);
            let chain = dag.selected_chain();
            for w in chain.windows(2) {
                let child = dag.get_block_data(&w[0]).unwrap();
                let parent = dag.get_block_data(&w[1]).unwrap();
                prop_assert!(child.blue_score >= parent.blue_score);
            }
        }

        // topological_order is a valid, complete, deterministic linearisation:
        // it lists every block exactly once and always places a block after all
        // of its parents.
        #[test]
        fn topological_order_is_valid_and_deterministic((shape, k) in dag_shape()) {
            let dag = build(&shape, k, false);
            let ord = dag.topological_order().expect("topological order must exist for a DAG");
            prop_assert_eq!(ord.len(), dag.block_count());
            let pos: std::collections::HashMap<BlockHash, usize> =
                ord.iter().enumerate().map(|(p, h)| (*h, p)).collect();
            for i in 0..shape.len() {
                let h = idx_hash(i);
                let d = dag.get_block_data(&h).unwrap();
                for p in &d.parents {
                    prop_assert!(pos[p] < pos[&h], "parent ordered after child at block {}", i);
                }
            }
            // Determinism: recomputing on an independently-built DAG matches.
            let dag2 = build(&shape, k, false);
            prop_assert_eq!(ord, dag2.topological_order().unwrap());
        }

        // ── Hardened (post-activation and mixed) regimes ──────────────────

        // Determinism of the full canonical data, every field included.
        #[test]
        fn hardened_colouring_is_deterministic((shape, k) in dag_shape(), act in activation_height()) {
            let a = build_at(&shape, k, false, act);
            let b = build_at(&shape, k, false, act);
            for i in 0..shape.len() {
                let h = idx_hash(i);
                prop_assert_eq!(
                    canonical_encode(a.get_block_data(&h).unwrap()),
                    canonical_encode(b.get_block_data(&h).unwrap())
                );
            }
        }

        // Parent-order independence of the full canonical data (canonical
        // encoding sorts the parent list, everything else must match).
        #[test]
        fn hardened_colouring_ignores_parent_order((shape, k) in dag_shape(), act in activation_height()) {
            let fwd = build_at(&shape, k, false, act);
            let rev = build_at(&shape, k, true, act);
            for i in 0..shape.len() {
                let h = idx_hash(i);
                prop_assert_eq!(
                    canonical_encode(fwd.get_block_data(&h).unwrap()),
                    canonical_encode(rev.get_block_data(&h).unwrap()),
                    "block {} depends on parent order", i
                );
            }
            prop_assert_eq!(fwd.selected_tip(), rev.selected_tip());
        }

        // Monotonicity and DAG-3 blue work: a hardened block's blue work is its
        // selected parent's plus the work of its merged blues plus its own, so
        // it strictly exceeds the selected parent's; blue_score counts blues.
        #[test]
        fn hardened_blue_work_and_score((shape, k) in dag_shape(), act in activation_height()) {
            let dag = build_at(&shape, k, false, act);
            for i in 1..shape.len() {
                let d = dag.get_block_data(&idx_hash(i)).unwrap();
                let sp = d.selected_parent.expect("non-genesis has a selected parent");
                let sd = dag.get_block_data(&sp).unwrap();
                let own = 1 + (i as u128 * 7919) % 1000;
                let merged: u128 = d.mergeset_blues.iter()
                    .map(|m| {
                        let j = u64::from_le_bytes(m[..8].try_into().unwrap()) as u128;
                        1 + (j * 7919) % 1000
                    })
                    .sum();
                if dag.is_hardened_at(d.height) {
                    prop_assert_eq!(d.blue_work, sd.blue_work + merged + own);
                    // Exact coloring: at most k blues besides the selected parent.
                    prop_assert!(d.mergeset_blues.len() <= k);
                } else {
                    prop_assert_eq!(d.blue_work, sd.blue_work + own);
                }
                prop_assert_eq!(d.blue_score, sd.blue_score + d.mergeset_blues.len() as u64 + 1);
                prop_assert!(d.height == sd.height + 1);
            }
        }

        // Below the activation, the hardened DAG and a never-activating DAG
        // agree on every block whose whole past is below the activation.
        #[test]
        fn hardened_keeps_old_data_below_activation((shape, k) in dag_shape(), act in 1u64..12) {
            let mixed = build_at(&shape, k, false, act);
            let never = build_at(&shape, k, false, u64::MAX);
            let mut below = vec![false; shape.len()];
            below[0] = true;
            for i in 1..shape.len() {
                let d = never.get_block_data(&idx_hash(i)).unwrap();
                below[i] = d.height < act && shape[i].iter().all(|&j| below[j]);
                if below[i] {
                    prop_assert_eq!(
                        canonical_encode(mixed.get_block_data(&idx_hash(i)).unwrap()),
                        canonical_encode(d)
                    );
                }
            }
        }
    }
}

// ── Hardening unit tests (audit DAG-3 / DAG-4 / DAG-7) ───────────────────────

#[cfg(test)]
mod hardening_tests {
    use super::*;

    fn h(tag: u8, i: u64) -> BlockHash {
        let mut out = [0u8; 32];
        out[0] = tag;
        out[1..9].copy_from_slice(&i.to_be_bytes());
        out
    }

    #[test]
    fn default_constructors_follow_the_process_activation_height() {
        // Unit tests never set the chain id: mainnet schedule.
        assert_eq!(
            GhostDAG::with_default_k().hardening_activation_height(),
            activation::hardening_activation_height()
        );
        {
            let _g = activation::scoped_override(0);
            assert_eq!(GhostDAG::with_k(3).hardening_activation_height(), 0);
            assert_eq!(GhostDAG::with_k_fast(3).hardening_activation_height(), 0);
        }
        let dag = GhostDAG::with_k(3).with_hardening_activation(7);
        assert!(!dag.is_hardened_at(6));
        assert!(dag.is_hardened_at(7));
    }

    #[test]
    #[should_panic(expected = "before blocks are added")]
    fn activation_height_cannot_change_after_blocks_exist() {
        let mut dag = GhostDAG::with_k_and_activation(3, 0);
        dag.add_genesis(h(0, 0), 0);
        let _ = dag.with_hardening_activation(5);
    }

    /// `work_of` recovers the exact work of every block from stored data
    /// alone (as after a restart), in both regimes and across the boundary.
    #[test]
    fn work_is_recovered_from_stored_data() {
        let mut dag = GhostDAG::with_k_and_activation(3, 4);
        let g = h(0, 0);
        dag.add_genesis(g, 0);
        let mut works = HashMap::new();
        let mut tips = vec![g];
        for i in 1..=40u64 {
            let w = 1 + (i as u128 * 37) % 50;
            let mut parents = vec![tips[tips.len() - 1]];
            if i % 3 == 0 && tips.len() > 2 {
                parents.push(tips[tips.len() - 3]);
            }
            let b = h(1, i);
            dag.add_block(b, parents, i, w).unwrap();
            works.insert(b, w);
            tips.push(b);
        }
        let mut fresh = GhostDAG::with_k_and_activation(3, 4);
        fresh.load_persisted(dag.store.data.iter().map(|(k, v)| (*k, v.clone())).collect());
        let mut memo = HashMap::new();
        for (b, w) in &works {
            assert_eq!(fresh.work_of(b, &mut memo), *w, "work of {}", hex::encode(&b[..9]));
        }
        assert_eq!(fresh.work_of(&g, &mut memo), 0);
    }

    /// Removing a just-added block clears its cache entries; re-adding it
    /// gives the same data.
    #[test]
    fn remove_and_re_add_is_identical() {
        for act in [0u64, u64::MAX] {
            let mut dag = GhostDAG::with_k_and_activation(3, act);
            let g = h(0, 0);
            dag.add_genesis(g, 0);
            let a = h(1, 1);
            let b = h(1, 2);
            dag.add_block(a, vec![g], 1, 10).unwrap();
            dag.add_block(b, vec![g], 1, 20).unwrap();
            let m = h(1, 3);
            let first = dag.add_block(m, vec![a, b], 2, 30).unwrap();
            assert!(dag.remove_block(&m));
            assert!(!dag.block_work.contains_key(&m) && !dag.merge_skip.contains_key(&m));
            let again = dag.add_block(m, vec![a, b], 2, 30).unwrap();
            assert_eq!(canonical_encode(&first), canonical_encode(&again));
        }
    }

    /// The pre-activation skip pointers name the nearest merging block on the
    /// selected chain, and a DAG without them (fallback walk) agrees.
    #[test]
    fn merge_skip_pointers_are_correct() {
        let mut dag = GhostDAG::with_k_and_activation(5, u64::MAX);
        let g = h(0, 0);
        dag.add_genesis(g, 0);
        let mut prev = g;
        let mut merging = None;
        for i in 1..=30u64 {
            let b = h(1, i);
            let mut parents = vec![prev];
            if i % 7 == 0 {
                let s = h(2, i);
                dag.add_block(s, vec![prev], i, 1).unwrap();
                parents.push(s);
            }
            dag.add_block(b, parents, i, 1000).unwrap();
            if !dag.get_block_data(&b).unwrap().mergeset_blues.is_empty() {
                merging = Some(b);
            }
            assert_eq!(dag.merge_skip.get(&b).copied(), Some(merging), "block {i}");
            prev = b;
        }
        // Rebuilding the cache from scratch gives the same pointers.
        let cached = dag.merge_skip.clone();
        dag.merge_skip.clear();
        dag.ensure_merge_skip(&prev);
        for (k, v) in &dag.merge_skip {
            assert_eq!(cached.get(k), Some(v));
        }
    }

    /// The index-based mergeset equals the O(past) one, in content and order.
    #[test]
    fn bounded_mergeset_equals_compute_past_mergeset() {
        let mut dag = GhostDAG::with_k_and_activation(4, u64::MAX);
        let g = h(0, 0);
        dag.add_genesis(g, 0);
        let mut all = vec![g];
        let mut state = 0x1234_5678_9ABC_DEF1u64;
        for i in 1..=150u64 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let n = all.len();
            let mut parents = vec![all[n - 1 - (state as usize % n.min(5))]];
            for j in 0..(state % 4) as usize {
                let p = all[(state as usize >> (8 + j * 8)) % n];
                if !parents.contains(&p) {
                    parents.push(p);
                }
            }
            let sp = dag.select_parent(&parents);
            let a = compute_mergeset(&dag.store, &parents, &sp);
            let b = dag.compute_mergeset_bounded(&parents, &sp, None).unwrap();
            assert_eq!(a, b, "block {i}");
            let blk = h(1, i);
            dag.add_block(blk, parents, i, 1 + state as u128 % 100).unwrap();
            all.push(blk);
        }
    }
}
