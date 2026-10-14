//! Block-ingress policy for the message processor (audit fixes POW-2, NET-2,
//! POW-3, POW-4, POW-8, NET-6, DAG-7).
//!
//! `main.rs` is a binary that integration tests cannot link, so every decision
//! the processor makes about an inbound block — before any expensive work —
//! lives here as a small pure function or a self-contained data structure,
//! unit- and integration-tested in isolation.
//!
//! NONE of this changes consensus validity. A block valid on the chain stays
//! valid (it still goes through `accept_block`); these are relay, buffering,
//! ordering and anti-DoS policies of one node:
//!
//! * peer-supplied integers are compared with saturating arithmetic only
//!   (a `NewBlock { height: u64::MAX }` used to panic the processor — POW-2);
//! * cheap checks run before the 64 MiB proof of work, and an orphan (parents
//!   unknown, so its expected bits cannot be derived) must carry bits no
//!   easier than an anti-DoS floor derived from OUR selected tip and the wall
//!   clock before its PoW is even evaluated (NET-2 / POW-3 / POW-4);
//! * the orphan pool is bounded by bytes and per peer and evicts by ARRIVAL
//!   order, never by a self-declared height; the first copy of an id wins
//!   (POW-4 / POW-8);
//! * the IBD latch is set only by work-backed evidence (a full-difficulty
//!   orphan claiming to be well ahead of us), never by a tip claim (NET-6);
//! * POW-3 (node-local anti-DoS half): a block whose parents we hold is only
//!   stored and processed if its chain can come within
//!   [`ANTI_DOS_WINDOW_BLOCKS`] selected-chain blocks of work of our tip, or
//!   if a proof-of-work-verified orphan chain announced on top of it does
//!   (see [`work_admission`]). A chain that carries the work is always
//!   accepted, so the final outcome for honest data is unchanged.
//!
//! [`BlockIngress`] is the processor's per-block core (orphan pool,
//! missing-parent tracker, deep-insertion budget, the decisions above, the
//! call into `accept_block` and the iterative orphan drain). `main.rs` feeds
//! it decoded gossip / sync blocks and acts on the outcome (network requests,
//! frontier, IBD latch, gossip verdict); the integration tests drive the
//! same core.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use libp2p::PeerId;
use log::{debug, info, warn};
use parking_lot::RwLock;
use tokio::sync::broadcast;

use crate::coherence::ShieldedPool;
use crate::consensus::{BlockHash, GhostDAG};
use crate::core;
use crate::mempool::Mempool;
use crate::network::GossipVerdict;
use crate::rpc::NodeState;
use crate::storage::Storage;
use crate::sync::parent_fetch::ParentFetchTracker;
use crate::tip::TipChanged;

// ── POW-2: peer-supplied heights ─────────────────────────────────────────────

/// An UNSOLICITED (gossip) `NewBlock` claiming a height more than this far
/// above our selected tip is dropped before any decoding or arithmetic. A node
/// that far behind syncs by directed pulls; a gossiped block from the network
/// tip would only be an orphan waiting on a thousand-block parent chain.
pub const MAX_UNSOLICITED_HEIGHT_LOOKAHEAD: u64 = core::CHECKPOINT_DEPTH;

/// POW-2: `height > tip_h + lookahead`, overflow-free.
pub fn unsolicited_height_too_far_ahead(height: u64, tip_h: u64) -> bool {
    height > tip_h.saturating_add(MAX_UNSOLICITED_HEIGHT_LOOKAHEAD)
}

/// Outcome of the backfill-flood guard (see `main.rs`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackfillDecision {
    /// Not deep below the tip: continue.
    Pass,
    /// Deep below the tip and nobody asked for it: drop cheaply.
    DropUnsolicitedDeep,
    /// Deep below the tip but awaited as the parent of a buffered orphan:
    /// may continue, subject to the deep-backfill budget.
    AwaitedDeep,
}

/// The backfill-flood guard, overflow-free (POW-2: this expression used to be
/// `height + CHECKPOINT_DEPTH < tip_h`, which panicked on `height = u64::MAX`
/// under `overflow-checks = true`).
pub fn backfill_decision(height: u64, tip_h: u64, awaited: bool) -> BackfillDecision {
    let deep = tip_h > core::CHECKPOINT_DEPTH
        && height.saturating_add(core::CHECKPOINT_DEPTH) < tip_h;
    match (deep, awaited) {
        (false, _) => BackfillDecision::Pass,
        (true, false) => BackfillDecision::DropUnsolicitedDeep,
        (true, true) => BackfillDecision::AwaitedDeep,
    }
}

/// DAG-7 / POW-3: global budget of deep (more than `CHECKPOINT_DEPTH` below
/// the tip) MERGE-BACKED block insertions (see [`WorkAdmission::MergeBacked`]).
/// Inserting one deep block costs a reachability reindex under the DAG write
/// lock, and a single crafted orphan merging a deep block makes it needed, so
/// these insertions are rationed. A deep block backed by the work of its own
/// announced chain (`ChainBacked`, an honest deep fork) does not use it. An
/// honest node needs it almost never; a denied block is simply re-requested
/// by the orphan sweep.
pub struct DeepBackfillBudget {
    bucket: crate::network::ratelimit::TokenBuckets<()>,
}

/// Burst / refill (one per 30 s) of [`DeepBackfillBudget`].
pub const DEEP_BACKFILL_BURST: u32 = 4;
pub const DEEP_BACKFILL_REFILL_PER_SEC: f64 = 1.0 / 30.0;

impl Default for DeepBackfillBudget {
    fn default() -> Self {
        Self::new()
    }
}

impl DeepBackfillBudget {
    pub fn new() -> Self {
        Self {
            bucket: crate::network::ratelimit::TokenBuckets::new(
                DEEP_BACKFILL_BURST,
                DEEP_BACKFILL_REFILL_PER_SEC,
                1,
            ),
        }
    }

    pub fn allow_at(&mut self, now: Instant) -> bool {
        self.bucket.allow_at((), now)
    }
}

// ── NET-2 / POW-3 / POW-4: the orphan anti-DoS work floor ────────────────────

/// An orphan may claim a target at most `2^ORPHAN_WORK_FLOOR_SHIFT` times
/// easier than the reference target (≈ 4 ASERT half-lives ≈ 8 h, or ~960
/// blocks of depth on a chain running on schedule).
pub const ORPHAN_WORK_FLOOR_SHIFT: u32 = 4;

/// Reference target for "now": the target a child of our selected tip (height
/// `tip_h + 1`) would have if its parent were stamped `now_unix` — the EASIEST
/// target any honest block extending our chain can carry right now (honest
/// blocks further ahead, or with earlier parents, are harder). Falls back to
/// the pow limit (fail open: this is anti-DoS, never consensus).
pub fn reference_target(tip_h: u64, now_unix: u64) -> [u8; 32] {
    match core::expected_bits(now_unix, tip_h.saturating_add(1)) {
        Ok(bits) => {
            let t = core::bits_to_target(bits);
            if t == [0u8; 32] { core::bits_to_target(core::POW_LIMIT_BITS) } else { t }
        }
        Err(_) => core::bits_to_target(core::POW_LIMIT_BITS),
    }
}

/// `target × 2^shift`, saturating at the pow limit.
pub fn ease_target(target: &[u8; 32], shift: u32) -> [u8; 32] {
    use primitive_types::U256;
    let limit = U256::from_big_endian(&core::bits_to_target(core::POW_LIMIT_BITS));
    let t = U256::from_big_endian(target);
    if t.is_zero() {
        return limit.to_big_endian();
    }
    let eased = if t.leading_zeros() < shift { limit } else { (t << shift as usize).min(limit) };
    eased.to_big_endian()
}

/// The admission floor for orphans: [`reference_target`] eased by
/// [`ORPHAN_WORK_FLOOR_SHIFT`].
pub fn orphan_admission_floor(tip_h: u64, now_unix: u64) -> [u8; 32] {
    ease_target(&reference_target(tip_h, now_unix), ORPHAN_WORK_FLOOR_SHIFT)
}

/// `target(bits) <= floor`. Malformed bits never meet any floor. Cheap: no
/// proof-of-work evaluation.
pub fn bits_meet_floor(bits: u32, floor: &[u8; 32]) -> bool {
    match gnb_smh::difficulty::try_bits_to_target(bits) {
        Ok(t) => t.0 <= *floor,
        Err(_) => false,
    }
}

// ── NET-6: work-backed IBD evidence ──────────────────────────────────────────

/// A PoW-verified orphan counts as evidence that we are BEHIND (and may latch
/// the IBD latch) iff its bits are at least as hard as the un-eased
/// [`reference_target`] — i.e. it cost as much work as a real next block —
/// and it claims a height more than `IBD_EXIT_LAG` above our tip. Its height
/// is a claim, but a claim that cost a full block of work to make, and
/// `accept_block` verifies it the moment its parents arrive.
pub fn orphan_is_sync_evidence(bits: u32, claimed_height: u64, tip_h: u64, now_unix: u64) -> bool {
    claimed_height > tip_h.saturating_add(crate::sync::IBD_EXIT_LAG)
        && bits_meet_floor(bits, &reference_target(tip_h, now_unix))
}

/// NET-6: what the processor does with one (clamped) tip claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClaimAction {
    /// The claim clamped against our own verified score.
    pub clamped: u64,
    /// Send a directed GetHeaders / GetTips (rate-limited). Never latches IBD.
    pub pull: bool,
    /// Answer a BEHIND peer with a reciprocal Version (rate-limited).
    pub reciprocal: bool,
}

/// Minimum spacing between claim-triggered pulls.
pub const CLAIM_PULL_MIN_INTERVAL: Duration = Duration::from_secs(5);
/// Minimum spacing between reciprocal tip announcements.
pub const RECIPROCAL_MIN_INTERVAL: Duration = Duration::from_secs(15);

/// NET-6: tip claims (`PeerTip` / `Version`) are hints. A claim ahead of us
/// only triggers a rate-limited directed pull; it never sets `is_syncing`
/// (that requires work-backed evidence — see [`orphan_is_sync_evidence`]).
#[derive(Debug, Default)]
pub struct ClaimPolicy {
    last_pull: Option<Instant>,
    last_reciprocal: Option<Instant>,
}

impl ClaimPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn evaluate(&mut self, raw_claim: u64, our_score: u64, now: Instant) -> ClaimAction {
        let clamped = crate::network::clamp_announced_blue_score(raw_claim, our_score);
        let mut act = ClaimAction { clamped, pull: false, reciprocal: false };
        if clamped > our_score {
            if self.last_pull.is_none_or(|t| now.saturating_duration_since(t) >= CLAIM_PULL_MIN_INTERVAL) {
                self.last_pull = Some(now);
                act.pull = true;
            }
        } else if clamped < our_score
            && self.last_reciprocal.is_none_or(|t| now.saturating_duration_since(t) >= RECIPROCAL_MIN_INTERVAL)
        {
            self.last_reciprocal = Some(now);
            act.reciprocal = true;
        }
        act
    }
}

// ── POW-8: never trust wire metadata ─────────────────────────────────────────

/// POW-8: the `blue_score` carried on the wire is not committed by the block
/// id and was persisted and re-served verbatim. Before a block is stored it
/// is replaced by a value derived from VERIFIED parents — exactly what this
/// codebase's miner writes (`max(parent blue_score) + 1`). The authoritative
/// GhostDAG blue score lives in the DAG, not in the block body.
pub fn derived_blue_score<I: IntoIterator<Item = u64>>(parent_scores: I) -> u64 {
    parent_scores.into_iter().max().unwrap_or(0).saturating_add(1)
}

// ── NET-2: verdicts ──────────────────────────────────────────────────────────

/// Map an `accept_block` rejection to a gossip verdict. Only rejections that
/// are a pure function of the block and its (known) parents — wrong height,
/// wrong difficulty bits, invalid proof of work, timestamp before a parent,
/// coinbase over-claim — are `Reject` (penalized, never relayed: no honest
/// node can produce them). Anything that depends on local state or time
/// (duplicates, finality, reorg policy, storage, UTXO view, future
/// timestamps, shielded verifier) is `Ignore`.
pub fn verdict_for_accept_error(err: &str) -> GossipVerdict {
    const REJECT_PREFIXES: &[&str] = &[
        "invalid height",
        "invalid difficulty",
        "consensus rejection: invalid GnB-SMH proof of work",
        "consensus rejection: non-genesis block without parents",
        "timestamp rejected: timestamp before parent",
        "coinbase rejected",
    ];
    if REJECT_PREFIXES.iter().any(|p| err.starts_with(p)) {
        GossipVerdict::Reject
    } else {
        GossipVerdict::Ignore
    }
}

// ── POW-2: supervisor back-off ───────────────────────────────────────────────

/// A processor run that lasted at least this long counts as healthy: the next
/// panic restarts after the BASE back-off, not after the accumulated one.
pub const SUPERVISOR_HEALTHY_RESET: Duration = Duration::from_secs(60);

/// Exponential restart back-off for the supervised message processor, reset
/// after a healthy period (POW-2: it used to only ever grow, to its 30 s cap,
/// so one panic per 30 s kept block processing stopped).
#[derive(Debug, Clone)]
pub struct SupervisorBackoff {
    base: Duration,
    max: Duration,
    next: Duration,
}

impl SupervisorBackoff {
    pub fn new(base: Duration, max: Duration) -> Self {
        Self { base, max, next: base }
    }

    /// The processor panicked after running for `ran_for`: how long to wait
    /// before restarting it.
    pub fn on_panic(&mut self, ran_for: Duration) -> Duration {
        if ran_for >= SUPERVISOR_HEALTHY_RESET {
            self.next = self.base;
        }
        let wait = self.next;
        self.next = self.next.saturating_mul(2).min(self.max);
        wait
    }
}

// ── POW-4 / POW-8: the bounded orphan pool ───────────────────────────────────

/// Bounds of an [`OrphanPool`]. `bytes` are wire bytes of the block (the
/// parsed copy in memory is proportional; the raw bytes are not retained).
#[derive(Clone, Copy, Debug)]
pub struct OrphanLimits {
    pub max_entries:          usize,
    pub max_bytes:            usize,
    pub max_entries_per_peer: usize,
    pub max_bytes_per_peer:   usize,
}

impl Default for OrphanLimits {
    fn default() -> Self {
        Self {
            max_entries:          10_000,
            max_bytes:            64 * 1024 * 1024,
            max_entries_per_peer: 2_500,
            max_bytes_per_peer:   16 * 1024 * 1024,
        }
    }
}

/// One buffered orphan.
#[derive(Clone, Debug)]
pub struct OrphanEntry {
    pub block:  core::Block,
    /// Claimed (wire) height; verified by `accept_block` when parents arrive.
    pub height: u64,
    pub bytes:  usize,
    /// The peer that delivered it (`None` = local / unknown).
    pub peer:   Option<PeerId>,
    /// Counted as IBD evidence (see [`orphan_is_sync_evidence`]).
    pub evidence: bool,
    seq:        u64,
}

/// Result of [`OrphanPool::insert`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OrphanInsert {
    /// Buffered; `evicted` lists orphans dropped to make room (arrival order).
    Inserted { evicted: Vec<[u8; 32]> },
    /// Already buffered: the FIRST copy wins (POW-8 — a later copy with
    /// different wire metadata never overwrites a pending orphan).
    Duplicate,
    /// Larger than any quota could ever hold.
    TooLarge,
}

#[derive(Default, Debug)]
struct PeerUsage {
    bytes: usize,
    seqs:  BTreeSet<u64>,
}

/// POW-4 (audit): the orphan pool, bounded by entries AND bytes, globally and
/// per delivering peer. Eviction is by ARRIVAL order — first the delivering
/// peer's own oldest entries when it exceeds its quota, then the globally
/// oldest — never by the self-declared height (which used to let attacker
/// orphans claiming huge heights evict every honest orphan). Holds the
/// reverse index `parent -> waiting orphans`.
#[derive(Debug)]
pub struct OrphanPool {
    limits:      OrphanLimits,
    entries:     HashMap<[u8; 32], OrphanEntry>,
    order:       BTreeMap<u64, [u8; 32]>,
    waiting_for: HashMap<[u8; 32], HashSet<[u8; 32]>>,
    per_peer:    HashMap<Option<PeerId>, PeerUsage>,
    evidence:    BTreeMap<u64, usize>,
    total_bytes: usize,
    next_seq:    u64,
    /// POW-3: announced work remembered across evictions. For a missing
    /// parent `p`, the greatest proof-of-work-verified work of an orphan chain
    /// built on `p` that was evicted (see [`OrphanPool::announced_work_above`]).
    /// Lets a chain longer than the pool still prove its work when its bottom
    /// finally connects. Bounded by [`REMEMBERED_WORK_MAX`], oldest first.
    remembered:       HashMap<[u8; 32], u128>,
    remembered_order: VecDeque<[u8; 32]>,
}

/// Bound of the remembered announced-work map (POW-3). 48 bytes per entry.
pub const REMEMBERED_WORK_MAX: usize = 50_000;

/// Proof-of-work work a block's header claims (its bits; checked against the
/// proof before an orphan is buffered).
fn header_work(block: &core::Block) -> u128 {
    core::bits_to_work(block.header.bits)
}

impl Default for OrphanPool {
    fn default() -> Self {
        Self::new(OrphanLimits::default())
    }
}

impl OrphanPool {
    pub fn new(limits: OrphanLimits) -> Self {
        Self {
            limits,
            entries: HashMap::new(),
            order: BTreeMap::new(),
            waiting_for: HashMap::new(),
            per_peer: HashMap::new(),
            evidence: BTreeMap::new(),
            total_bytes: 0,
            next_seq: 0,
            remembered: HashMap::new(),
            remembered_order: VecDeque::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub fn contains(&self, h: &[u8; 32]) -> bool {
        self.entries.contains_key(h)
    }

    pub fn get(&self, h: &[u8; 32]) -> Option<&OrphanEntry> {
        self.entries.get(h)
    }

    /// `(entries, bytes)` buffered on behalf of `peer`.
    pub fn peer_usage(&self, peer: Option<PeerId>) -> (usize, usize) {
        self.per_peer.get(&peer).map(|u| (u.seqs.len(), u.bytes)).unwrap_or((0, 0))
    }

    /// True iff some buffered orphan waits for `h` as a parent.
    pub fn is_waited_on(&self, h: &[u8; 32]) -> bool {
        self.waiting_for.contains_key(h)
    }

    /// Every parent some orphan is waiting for.
    pub fn waiting_parents(&self) -> Vec<[u8; 32]> {
        self.waiting_for.keys().copied().collect()
    }

    /// NET-6: highest claimed height among orphans counted as IBD evidence.
    pub fn max_evidence_height(&self) -> Option<u64> {
        self.evidence.keys().next_back().copied()
    }

    /// Buffer an orphan waiting on `missing_parents`. See [`OrphanInsert`].
    #[allow(clippy::too_many_arguments)]
    pub fn insert(
        &mut self,
        hash: [u8; 32],
        block: core::Block,
        height: u64,
        bytes: usize,
        peer: Option<PeerId>,
        evidence: bool,
        missing_parents: &[[u8; 32]],
    ) -> OrphanInsert {
        if self.entries.contains_key(&hash) {
            return OrphanInsert::Duplicate;
        }
        if bytes > self.limits.max_bytes_per_peer || bytes > self.limits.max_bytes {
            return OrphanInsert::TooLarge;
        }
        let mut evicted = Vec::new();
        // Per-peer quota: the delivering peer pays with its OWN oldest orphans.
        loop {
            let (count, used) = self.peer_usage(peer);
            if count < self.limits.max_entries_per_peer
                && used.saturating_add(bytes) <= self.limits.max_bytes_per_peer
            {
                break;
            }
            let oldest = self.per_peer.get(&peer).and_then(|u| u.seqs.iter().next().copied());
            match oldest.and_then(|s| self.order.get(&s).copied()) {
                Some(h) => {
                    self.evict(&h);
                    evicted.push(h);
                }
                None => break,
            }
        }
        // Global bounds: oldest arrival first.
        while self.entries.len() >= self.limits.max_entries
            || self.total_bytes.saturating_add(bytes) > self.limits.max_bytes
        {
            match self.order.values().next().copied() {
                Some(h) => {
                    self.evict(&h);
                    evicted.push(h);
                }
                None => break,
            }
        }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        for mp in missing_parents {
            self.waiting_for.entry(*mp).or_default().insert(hash);
        }
        if evidence {
            *self.evidence.entry(height).or_insert(0) += 1;
        }
        let usage = self.per_peer.entry(peer).or_default();
        usage.bytes = usage.bytes.saturating_add(bytes);
        usage.seqs.insert(seq);
        self.total_bytes = self.total_bytes.saturating_add(bytes);
        self.order.insert(seq, hash);
        self.entries.insert(hash, OrphanEntry { block, height, bytes, peer, evidence, seq });
        OrphanInsert::Inserted { evicted }
    }

    /// Evict one orphan to make room, first remembering the work its chain
    /// announces for each of its parents (POW-3), then removing it.
    fn evict(&mut self, h: &[u8; 32]) {
        if let Some(e) = self.entries.get(h) {
            let above = header_work(&e.block).saturating_add(self.announced_work_above(h));
            let parents = e.block.header.parents.clone();
            for p in parents {
                self.remember(p, above);
            }
        }
        self.remove(h);
    }

    fn remember(&mut self, parent: [u8; 32], work: u128) {
        match self.remembered.get_mut(&parent) {
            Some(w) => *w = (*w).max(work),
            None => {
                if self.remembered_order.len() >= REMEMBERED_WORK_MAX {
                    if let Some(old) = self.remembered_order.pop_front() {
                        self.remembered.remove(&old);
                    }
                }
                self.remembered.insert(parent, work);
                self.remembered_order.push_back(parent);
            }
        }
    }

    /// True iff evicted orphans announced work above `h` (it was a missing
    /// parent of a chain we had buffered).
    pub fn remembers(&self, h: &[u8; 32]) -> bool {
        self.remembered.contains_key(h)
    }

    /// Drop the remembered work for `h` (the block is in the DAG now).
    pub fn forget(&mut self, h: &[u8; 32]) {
        if self.remembered.remove(h).is_some() {
            self.remembered_order.retain(|x| x != h);
        }
    }

    /// POW-3: the greatest work of an orphan chain announced ABOVE `root`
    /// (excluding `root` itself): the maximum, over the buffered orphans that
    /// wait on `root` directly or through other buffered orphans, of the
    /// summed header work along the waiting path, combined with the work
    /// remembered from evicted orphans. Every orphan's proof was verified
    /// against its bits before it was buffered, so this is work an announcer
    /// really spent. O(orphans above `root`).
    pub fn announced_work_above(&self, root: &[u8; 32]) -> u128 {
        // Depth-first, a node is computed once all its buffered waiters are;
        // `in_progress` guards against (impossible) cycles.
        let mut memo: HashMap<[u8; 32], u128> = HashMap::new();
        let mut in_progress: HashSet<[u8; 32]> = HashSet::new();
        let mut stack: Vec<[u8; 32]> = vec![*root];
        while let Some(&h) = stack.last() {
            if memo.contains_key(&h) {
                stack.pop();
                continue;
            }
            let waiters = self.waiting_for.get(&h);
            let pending: Vec<[u8; 32]> = waiters
                .map(|ws| ws.iter()
                    .filter(|w| self.entries.contains_key(*w) && !memo.contains_key(*w) && !in_progress.contains(*w))
                    .copied()
                    .collect())
                .unwrap_or_default();
            if pending.is_empty() || !in_progress.insert(h) {
                let mut best = self.remembered.get(&h).copied().unwrap_or(0);
                if let Some(ws) = waiters {
                    for w in ws {
                        if let Some(e) = self.entries.get(w) {
                            let above = memo.get(w).copied().unwrap_or(0);
                            best = best.max(header_work(&e.block).saturating_add(above));
                        }
                    }
                }
                memo.insert(h, best);
                in_progress.remove(&h);
                stack.pop();
            } else {
                stack.extend(pending);
            }
        }
        memo.get(root).copied().unwrap_or(0)
    }

    /// POW-3: the greatest lower bound on the blue work of any buffered
    /// orphan that (directly or through other buffered orphans) waits on
    /// `root`, assuming `root` connects with blue work at least `root_lb`.
    /// An orphan's bound is the largest bound of its parents — a DAG block's
    /// blue work, `root_lb` for `root`, a buffered orphan's own bound, 0 for
    /// anything else — plus its header work: a block's blue work is at least
    /// any parent's plus its own work, before and after the hardening
    /// activation. O(orphans above `root` and their buffered ancestors).
    pub fn best_waiter_lb(&self, root: &[u8; 32], root_lb: u128, dag: &crate::consensus::GhostDAG) -> u128 {
        // Orphans above `root`.
        let mut above: Vec<[u8; 32]> = Vec::new();
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        let mut queue: VecDeque<[u8; 32]> = VecDeque::new();
        queue.push_back(*root);
        while let Some(h) = queue.pop_front() {
            if let Some(ws) = self.waiting_for.get(&h) {
                for w in ws {
                    if self.entries.contains_key(w) && seen.insert(*w) {
                        above.push(*w);
                        queue.push_back(*w);
                    }
                }
            }
        }
        // Their lower bounds, parents first (iterative, memoized).
        let mut memo: HashMap<[u8; 32], u128> = HashMap::new();
        memo.insert(*root, root_lb);
        let mut best = 0u128;
        for start in above {
            // Depth-first, a node is computed once all its buffered parents
            // are; `in_progress` guards against (impossible) cycles.
            let mut stack: Vec<[u8; 32]> = vec![start];
            let mut in_progress: HashSet<[u8; 32]> = HashSet::new();
            while let Some(&h) = stack.last() {
                if memo.contains_key(&h) {
                    stack.pop();
                    continue;
                }
                let Some(e) = self.entries.get(&h) else {
                    memo.insert(h, dag.get_block_data(&h).map(|d| d.blue_work).unwrap_or(0));
                    stack.pop();
                    continue;
                };
                let pending: Vec<[u8; 32]> = e.block.header.parents.iter()
                    .filter(|p| !memo.contains_key(*p) && self.entries.contains_key(*p) && !in_progress.contains(*p))
                    .copied()
                    .collect();
                if pending.is_empty() || !in_progress.insert(h) {
                    let base = e.block.header.parents.iter().map(|p| {
                        memo.get(p).copied()
                            .or_else(|| dag.get_block_data(p).map(|d| d.blue_work))
                            .unwrap_or(0)
                    }).max().unwrap_or(0);
                    memo.insert(h, base.saturating_add(header_work(&e.block)));
                    in_progress.remove(&h);
                    stack.pop();
                } else {
                    stack.extend(pending);
                }
            }
            best = best.max(memo.get(&start).copied().unwrap_or(0));
        }
        best
    }

    /// Remove one orphan, detaching it from every parent it waited on.
    /// Orphans waiting on IT keep waiting (their parent is just not buffered).
    pub fn remove(&mut self, h: &[u8; 32]) -> Option<OrphanEntry> {
        let e = self.entries.remove(h)?;
        self.order.remove(&e.seq);
        if let Some(u) = self.per_peer.get_mut(&e.peer) {
            u.seqs.remove(&e.seq);
            u.bytes = u.bytes.saturating_sub(e.bytes);
            if u.seqs.is_empty() {
                self.per_peer.remove(&e.peer);
            }
        }
        if e.evidence {
            if let Some(n) = self.evidence.get_mut(&e.height) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    self.evidence.remove(&e.height);
                }
            }
        }
        self.total_bytes = self.total_bytes.saturating_sub(e.bytes);
        for p in &e.block.header.parents {
            if let Some(set) = self.waiting_for.get_mut(p) {
                set.remove(h);
                if set.is_empty() {
                    self.waiting_for.remove(p);
                }
            }
        }
        Some(e)
    }

    /// Detach and return the orphans waiting on `parent`, in arrival order.
    pub fn take_waiters(&mut self, parent: &[u8; 32]) -> Vec<[u8; 32]> {
        let mut v: Vec<[u8; 32]> = self.waiting_for.remove(parent).unwrap_or_default().into_iter().collect();
        v.sort_by_key(|h| self.entries.get(h).map(|e| e.seq).unwrap_or(u64::MAX));
        v
    }

    /// Remove every orphan transitively waiting on `root_parent`
    /// (iteratively — no recursion). Returns how many were dropped.
    pub fn drop_subtree(&mut self, root_parent: &[u8; 32]) -> usize {
        let mut dropped = 0usize;
        let mut stack: VecDeque<[u8; 32]> = self.take_waiters(root_parent).into();
        while let Some(h) = stack.pop_front() {
            if self.remove(&h).is_some() {
                dropped += 1;
                stack.extend(self.take_waiters(&h));
            }
        }
        dropped
    }
}

// ── POW-3: anti-DoS work rule for blocks whose parents are known ─────────────

/// The anti-DoS window, in selected-chain blocks (Bitcoin uses 144 blocks
/// of work below the tip for `GetAntiDoSWorkThreshold`). 360 = `MERGE_DEPTH`:
/// 3 hours at 30 s, the depth below which, after the hardening activation, a
/// red block can no longer be merged; and with a 2-hour ASERT half-life a
/// fork that branches this far back still pays at least 2^-1.5 ≈ 35% of the
/// tip's work per block.
pub const ANTI_DOS_WINDOW_BLOCKS: u64 = crate::consensus::MERGE_DEPTH;

/// The anti-DoS work threshold: the blue work of the selected-chain block
/// [`ANTI_DOS_WINDOW_BLOCKS`] below our selected tip (0 while the chain is
/// shorter), i.e. our tip's work minus the work of the last
/// `ANTI_DOS_WINDOW_BLOCKS` selected-chain blocks. O(window).
pub fn anti_dos_work_threshold(dag: &GhostDAG) -> u128 {
    let mut cur = dag.selected_tip();
    for _ in 0..ANTI_DOS_WINDOW_BLOCKS {
        match cur.and_then(|h| dag.get_block_data(&h)).and_then(|d| d.selected_parent) {
            Some(p) => cur = Some(p),
            None => return 0,
        }
    }
    cur.and_then(|h| dag.get_block_data(&h)).map(|d| d.blue_work).unwrap_or(0)
}

/// A lower bound on the blue work a block with these parents and `bits`
/// gets: the largest parent blue work plus its own work. Exact before the
/// hardening activation (the selected parent IS the parent of largest blue
/// work); after it the merged blues only add. `None` if a parent is unknown.
pub fn block_work_lower_bound(dag: &GhostDAG, parents: &[BlockHash], bits: u32) -> Option<u128> {
    let mut best = 0u128;
    for p in parents {
        best = best.max(dag.get_block_data(p)?.blue_work);
    }
    Some(best.saturating_add(core::bits_to_work(bits)))
}

/// Verdict of the POW-3 anti-DoS work rule on a block whose parents are all
/// known, evaluated BEFORE its proof of work, storage or DAG insertion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkAdmission {
    /// Its own work bound reaches the threshold (every honest block near the
    /// tip, fork-losers within the window).
    NearTip,
    /// A proof-of-work-verified orphan chain announced on top of it (buffered,
    /// or remembered after eviction) brings the chain through it to the
    /// threshold: a chain that carries the work, however deep it branches
    /// (Bitcoin: headers with enough work make the blocks requested).
    ChainBacked,
    /// A buffered orphan whose own bound reaches the threshold needs it as a
    /// parent (it merges a lower-work block); deep ones consume the
    /// [`DeepBackfillBudget`].
    MergeBacked,
    /// Nothing backs it: its chain cannot come within the window of our tip.
    /// Not stored, not processed, not penalized; if a heavier chain ever
    /// builds on it, that chain's orphans make it `ChainBacked` /
    /// `MergeBacked` and it is fetched again.
    LowWork,
}

/// The POW-3 decision from its inputs: `lb` = [`block_work_lower_bound`],
/// `threshold` = [`anti_dos_work_threshold`], `chain_above` =
/// [`OrphanPool::announced_work_above`], `merge_lb` =
/// [`OrphanPool::best_waiter_lb`].
pub fn work_admission(lb: u128, threshold: u128, chain_above: u128, merge_lb: u128) -> WorkAdmission {
    if lb >= threshold {
        WorkAdmission::NearTip
    } else if lb.saturating_add(chain_above) >= threshold {
        WorkAdmission::ChainBacked
    } else if merge_lb >= threshold {
        WorkAdmission::MergeBacked
    } else {
        WorkAdmission::LowWork
    }
}

// ── The processor's block-ingress core ───────────────────────────────────────

/// POW-8 (audit): the wire `blue_score` is not committed by the block id and
/// used to be persisted and re-served verbatim. Replace it with the value
/// derived from the block's VERIFIED parents before the block is stored.
/// (`height` needs no rewrite: `accept_block` rejects any block whose height
/// differs from max(parent height) + 1.)
pub fn normalize_wire_metadata(block: &mut core::Block, dag: &Arc<RwLock<GhostDAG>>) {
    let d = dag.read();
    block.blue_score = derived_blue_score(
        block.header.parents.iter().filter_map(|p| d.get_block_data(p).map(|x| x.blue_score)),
    );
}

/// After accepting a block, accept every buffered orphan that can now be
/// connected, transitively. Returns the hashes accepted, in order.
///
/// POW-3 / POW-4 (audit): ITERATIVE (a work queue), not recursive — an
/// attacker-built chain of thousands of orphans used to recurse once per
/// accepted orphan on a 2 MiB worker stack. Buffered orphans passed the
/// anti-DoS floor and their proof of work to enter the pool, so they are not
/// re-checked against the POW-3 work rule.
#[allow(clippy::too_many_arguments)]
pub fn process_orphans(
    accepted_hash: [u8; 32],
    orphans:       &mut OrphanPool,
    dag:           &Arc<RwLock<GhostDAG>>,
    store:         &Arc<Storage>,
    mempool:       &Arc<Mempool>,
    node_state:    &Arc<RwLock<NodeState>>,
    tip_tx:        Option<&broadcast::Sender<TipChanged>>,
    shielded:      &Arc<RwLock<ShieldedPool>>,
) -> Vec<[u8; 32]> {
    let mut accepted = Vec::new();
    let mut queue: VecDeque<[u8; 32]> = VecDeque::new();
    queue.push_back(accepted_hash);
    while let Some(parent) = queue.pop_front() {
        for orphan_hash in orphans.take_waiters(&parent) {
            let all_parents_present = orphans.get(&orphan_hash)
                .map(|e| {
                    let d = dag.read();
                    e.block.header.parents.iter().all(|p| d.has_block(p))
                })
                .unwrap_or(false);
            // Still waiting on another parent: it stays registered under that
            // parent and is retried when it arrives.
            if !all_parents_present { continue; }

            if let Some(entry) = orphans.remove(&orphan_hash) {
                let height = entry.height;
                let mut block = entry.block;
                normalize_wire_metadata(&mut block, dag);
                match crate::accept::accept_block(&block, orphan_hash, height, dag, store, mempool,
                                                  node_state, tip_tx, shielded) {
                    Ok(hash) => {
                        info!("✓ orphan h={} accepted (pool={})", height, orphans.len());
                        orphans.forget(&hash);
                        accepted.push(hash);
                        queue.push_back(hash);
                    }
                    Err(e) => {
                        warn!("orphan h={} rejected: {}", height, e);
                    }
                }
            }
        }
    }
    accepted
}

/// What the acceptance pipeline needs (the arguments `accept_block` takes
/// besides the block).
pub struct AcceptCtx<'a> {
    pub dag:        &'a Arc<RwLock<GhostDAG>>,
    pub store:      &'a Arc<Storage>,
    pub mempool:    &'a Arc<Mempool>,
    pub node_state: &'a Arc<RwLock<NodeState>>,
    pub tip_tx:     Option<&'a broadcast::Sender<TipChanged>>,
    pub shielded:   &'a Arc<RwLock<ShieldedPool>>,
}

/// Why [`BlockIngress::handle_block`] dropped a block before evaluating its
/// proof of work. None of these is a protocol violation (gossip verdict
/// `Ignore`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropReason {
    /// An orphan far below our tip that nobody asked for (backfill-flood
    /// guard: backfill is pulled, never pushed).
    UnsolicitedDeepOrphan,
    /// An orphan whose bits are easier than the anti-DoS floor.
    OrphanBelowFloor,
    /// POW-3: a block whose chain cannot reach the anti-DoS work threshold.
    LowWork,
    /// POW-3 / DAG-7: a deep merge-backed block while the deep-insertion
    /// budget is exhausted (the orphan sweep re-requests it).
    DeepBudgetExhausted,
}

/// At most this many missing bodies are requested per failed connect
/// (`accept::missing_bodies_below`); a later attempt asks for the next ones.
pub const MAX_BODY_REFETCH: usize = 4_096;

/// What [`BlockIngress::handle_block`] did with one block.
#[derive(Debug)]
pub enum BlockOutcome {
    /// Already in the DAG (with its body) or buffered.
    Known,
    /// DAG-6, pruned nodes: the block was in the DAG without a body (pruned,
    /// then reorganized away from); the re-fetched body was verified and
    /// stored, so a chain through it can be connected again.
    BodyRestored,
    /// Dropped before any proof-of-work evaluation.
    Dropped(DropReason),
    /// Context-free invalid (structure, or an orphan's proof of work).
    Invalid(String),
    /// Buffered as an orphan; `request` = missing parents to fetch now.
    Buffered { request: Vec<[u8; 32]>, evidence: bool, evicted: usize },
    /// The orphan pool refused it (an earlier copy is buffered, or too large).
    PoolRefused,
    /// Its parents are known and it passed the POW-3 work rule (`admission`):
    /// `accept_block` ran (`result`) and, on success, the orphans waiting on
    /// it were drained (`drained`). If the connect failed because blocks it
    /// had to apply have no body (`reorg::ERR_MISSING_BODIES`),
    /// `missing_bodies` lists those to re-fetch (then the block again).
    Processed {
        admission:      WorkAdmission,
        result:         Result<[u8; 32], String>,
        drained:        Vec<[u8; 32]>,
        missing_bodies: Vec<[u8; 32]>,
    },
}

/// The message processor's per-block core: everything it decides about an
/// inbound block (decoded and bound to its id and height by the caller)
/// before and around `accept_block`.
pub struct BlockIngress {
    pub orphans:      OrphanPool,
    pub parent_fetch: ParentFetchTracker,
    pub deep_budget:  DeepBackfillBudget,
    /// `(selected tip, anti_dos_work_threshold)` of the last work check: the
    /// threshold only changes when the selected tip does.
    threshold_cache:  Option<(BlockHash, u128)>,
}

impl Default for BlockIngress {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockIngress {
    pub fn new() -> Self {
        Self::with_limits(OrphanLimits::default())
    }

    pub fn with_limits(limits: OrphanLimits) -> Self {
        Self {
            orphans: OrphanPool::new(limits),
            parent_fetch: ParentFetchTracker::new(),
            deep_budget: DeepBackfillBudget::new(),
            threshold_cache: None,
        }
    }

    /// True iff some buffered orphan, an outstanding parent request or a
    /// remembered evicted orphan chain waits for `hash`.
    pub fn is_awaited(&self, hash: &[u8; 32]) -> bool {
        self.orphans.is_waited_on(hash) || self.parent_fetch.is_awaited(hash) || self.orphans.remembers(hash)
    }

    /// The POW-3 work rule for a block whose parents are all known (cheap:
    /// DAG lookups and the orphan pool, no proof of work).
    pub fn work_check(
        &mut self,
        block: &core::Block,
        hash: &[u8; 32],
        tip_h: u64,
        now: Instant,
        dag: &GhostDAG,
    ) -> Result<WorkAdmission, DropReason> {
        let threshold = match (dag.selected_tip(), self.threshold_cache) {
            (Some(tip), Some((cached_tip, t))) if tip == cached_tip => t,
            (tip, _) => {
                let t = anti_dos_work_threshold(dag);
                self.threshold_cache = tip.map(|h| (h, t));
                t
            }
        };
        let lb = block_work_lower_bound(dag, &block.header.parents, block.header.bits).unwrap_or(0);
        let (chain_above, merge_lb) = if lb >= threshold {
            (0, 0)
        } else {
            (self.orphans.announced_work_above(hash), self.orphans.best_waiter_lb(hash, lb, dag))
        };
        match work_admission(lb, threshold, chain_above, merge_lb) {
            WorkAdmission::LowWork => Err(DropReason::LowWork),
            WorkAdmission::MergeBacked => {
                if backfill_decision(block.height, tip_h, true) == BackfillDecision::AwaitedDeep
                    && !self.deep_budget.allow_at(now)
                {
                    Err(DropReason::DeepBudgetExhausted)
                } else {
                    Ok(WorkAdmission::MergeBacked)
                }
            }
            ok => Ok(ok),
        }
    }

    /// Handle one inbound block. Cheapest checks first; the proof of work of
    /// an orphan is evaluated only after its floor check, and that of a block
    /// with known parents only inside `accept_block` (after height, expected
    /// bits, timestamp), and only if the POW-3 work rule admitted it.
    #[allow(clippy::too_many_arguments)]
    pub fn handle_block(
        &mut self,
        mut block: core::Block,
        hash: [u8; 32],
        wire_bytes: usize,
        peer: Option<PeerId>,
        now: Instant,
        now_unix: u64,
        ctx: &AcceptCtx,
    ) -> BlockOutcome {
        if ctx.dag.read().has_block(&hash) {
            // DAG-6, pruned nodes: a DAG block whose body is missing (pruned,
            // then reorganized away from) gets its re-fetched body back,
            // after the same structure and proof checks as any block.
            if ctx.store.has_block_body(&hash).unwrap_or(true) {
                return BlockOutcome::Known;
            }
            if let Err(reason) = block.validate_structure_without_pow() {
                return BlockOutcome::Invalid(reason.to_string());
            }
            if !block.validate_pow() {
                return BlockOutcome::Invalid("invalid PoW".into());
            }
            return match ctx.store.put_block_body(&block) {
                Ok(()) => BlockOutcome::BodyRestored,
                Err(e) => BlockOutcome::Invalid(format!("body not stored: {e}")),
            };
        }
        if self.orphans.contains(&hash) {
            return BlockOutcome::Known;
        }
        let tip_h = {
            let d = ctx.dag.read();
            d.selected_tip().and_then(|t| d.get_block_data(&t).map(|x| x.height)).unwrap_or(0)
        };
        // Cheap structural validation (merkle, coinbase format, duplicates,
        // dust, size, parent count) — NO PoW yet.
        if let Err(reason) = block.validate_structure_without_pow() {
            return BlockOutcome::Invalid(reason.to_string());
        }
        let missing: Vec<[u8; 32]> = {
            let d = ctx.dag.read();
            block.header.parents.iter().filter(|p| !d.has_block(p)).copied().collect()
        };

        if !missing.is_empty() {
            // Orphan. Backfill-flood guard: a far-below-tip orphan nobody
            // asked for is dropped (backfill is pulled). An awaited one is
            // buffered — the expensive step, inserting it, happens only when
            // its chain connects and passes the POW-3 work rule there.
            if backfill_decision(block.height, tip_h, self.is_awaited(&hash))
                == BackfillDecision::DropUnsolicitedDeep
            {
                return BlockOutcome::Dropped(DropReason::UnsolicitedDeepOrphan);
            }
            // NET-2 / POW-4: bits no easier than the anti-DoS floor BEFORE
            // the proof is evaluated.
            let floor = orphan_admission_floor(tip_h, now_unix);
            if !bits_meet_floor(block.header.bits, &floor) {
                return BlockOutcome::Dropped(DropReason::OrphanBelowFloor);
            }
            if !block.validate_pow() {
                return BlockOutcome::Invalid("invalid PoW".into());
            }
            let evidence = orphan_is_sync_evidence(block.header.bits, block.height, tip_h, now_unix);
            // Request each missing parent that nobody is waiting for and that
            // is not itself buffered (a deep gap fans out one level at a time).
            let fresh: Vec<[u8; 32]> = missing.iter()
                .filter(|mp| !self.orphans.is_waited_on(mp) && !self.orphans.contains(mp))
                .copied()
                .collect();
            let height = block.height;
            match self.orphans.insert(hash, block, height, wire_bytes, peer, evidence, &missing) {
                OrphanInsert::Inserted { evicted } => {
                    for mp in &fresh {
                        self.parent_fetch.note_requested(*mp, now);
                    }
                    debug!("orphan block h={} (missing {} parents), buffered (pool={} / {} bytes)",
                        height, missing.len(), self.orphans.len(), self.orphans.total_bytes());
                    BlockOutcome::Buffered { request: fresh, evidence, evicted: evicted.len() }
                }
                OrphanInsert::Duplicate | OrphanInsert::TooLarge => BlockOutcome::PoolRefused,
            }
        } else {
            // All parents known: POW-3 work rule before any expensive step.
            let admission = {
                let d = ctx.dag.read();
                // `work_check` takes the read guard's target; the budget is
                // updated under it (no DAG write happens here).
                match self.work_check(&block, &hash, tip_h, now, &d) {
                    Ok(a) => a,
                    Err(r) => return BlockOutcome::Dropped(r),
                }
            };
            normalize_wire_metadata(&mut block, ctx.dag);
            let height = block.height;
            let result = crate::accept::accept_block(
                &block, hash, height, ctx.dag, ctx.store, ctx.mempool, ctx.node_state,
                ctx.tip_tx, ctx.shielded,
            );
            let (drained, missing_bodies) = match &result {
                Ok(h) => {
                    self.orphans.forget(h);
                    (self.drain_orphans(*h, ctx), Vec::new())
                }
                Err(e) if e.contains(crate::reorg::ERR_MISSING_BODIES) => (
                    Vec::new(),
                    crate::accept::missing_bodies_below(ctx.dag, ctx.store, &block.header.parents, MAX_BODY_REFETCH),
                ),
                Err(_) => (Vec::new(), Vec::new()),
            };
            BlockOutcome::Processed { admission, result, drained, missing_bodies }
        }
    }

    /// [`process_orphans`] on this core's pool.
    pub fn drain_orphans(&mut self, accepted: [u8; 32], ctx: &AcceptCtx) -> Vec<[u8; 32]> {
        process_orphans(accepted, &mut self.orphans, ctx.dag, ctx.store, ctx.mempool,
                        ctx.node_state, ctx.tip_tx, ctx.shielded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blk(parents: Vec<[u8; 32]>, tag: u64) -> core::Block {
        core::Block {
            header: core::BlockHeader {
                version: 1,
                parents,
                merkle_root: core::MerkleRoot::ZERO,
                timestamp: tag,
                bits: core::POW_LIMIT_BITS,
                nonce: tag,
            },
            transactions: vec![],
            blue_score: 0,
            height: 0,
            shielded_transactions: vec![],
        }
    }

    fn h(i: u64) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&i.to_le_bytes());
        b
    }

    #[test]
    fn height_checks_never_overflow() {
        assert!(unsolicited_height_too_far_ahead(u64::MAX, 40_000));
        assert!(!unsolicited_height_too_far_ahead(40_500, 40_000));
        assert!(!unsolicited_height_too_far_ahead(u64::MAX, u64::MAX));
        assert_eq!(backfill_decision(u64::MAX, 40_000, false), BackfillDecision::Pass);
        assert_eq!(backfill_decision(1, 40_000, false), BackfillDecision::DropUnsolicitedDeep);
        assert_eq!(backfill_decision(1, 40_000, true), BackfillDecision::AwaitedDeep);
        assert_eq!(backfill_decision(1, 500, false), BackfillDecision::Pass);
    }

    #[test]
    fn supervisor_backoff_resets_after_healthy_run() {
        let mut b = SupervisorBackoff::new(Duration::from_millis(100), Duration::from_secs(30));
        assert_eq!(b.on_panic(Duration::ZERO), Duration::from_millis(100));
        assert_eq!(b.on_panic(Duration::ZERO), Duration::from_millis(200));
        for _ in 0..20 { b.on_panic(Duration::ZERO); }
        assert_eq!(b.on_panic(Duration::ZERO), Duration::from_secs(30), "capped");
        assert_eq!(b.on_panic(SUPERVISOR_HEALTHY_RESET), Duration::from_millis(100), "reset after a healthy run");
    }

    #[test]
    fn verdict_mapping() {
        assert_eq!(verdict_for_accept_error("consensus rejection: invalid GnB-SMH proof of work"), GossipVerdict::Reject);
        assert_eq!(verdict_for_accept_error("invalid difficulty: block bits 0x1 != expected 0x2"), GossipVerdict::Reject);
        assert_eq!(verdict_for_accept_error("invalid height: block claims h=9 but expected h=2"), GossipVerdict::Reject);
        assert_eq!(verdict_for_accept_error("consensus rejection: block already in DAG: ab"), GossipVerdict::Ignore);
        assert_eq!(verdict_for_accept_error("timestamp rejected: timestamp too far in the future"), GossipVerdict::Ignore);
        assert_eq!(verdict_for_accept_error("finality: block h=3 may not become the selected tip"), GossipVerdict::Ignore);
    }

    #[test]
    fn ease_target_saturates_at_pow_limit() {
        let limit = core::bits_to_target(core::POW_LIMIT_BITS);
        assert_eq!(ease_target(&limit, 4), limit);
        let g = core::bits_to_target(core::GENESIS_BITS);
        let eased = ease_target(&g, 4);
        assert!(eased > g && eased <= limit);
        assert!(bits_meet_floor(core::GENESIS_BITS, &eased));
        assert!(!bits_meet_floor(core::POW_LIMIT_BITS, &eased), "pow-limit bits are easier than the floor");
        assert!(!bits_meet_floor(0x0480_0001, &limit), "malformed bits never meet a floor");
    }

    #[test]
    fn derived_blue_score_ignores_wire_value() {
        assert_eq!(derived_blue_score([5u64, 9, 7]), 10);
        assert_eq!(derived_blue_score(std::iter::empty()), 1);
        assert_eq!(derived_blue_score([u64::MAX]), u64::MAX);
    }

    #[test]
    fn claims_never_latch_and_are_rate_limited() {
        let mut p = ClaimPolicy::new();
        let t0 = Instant::now();
        let a = p.evaluate(u64::MAX, 100, t0);
        assert_eq!(a.clamped, 100 + crate::network::MAX_ANNOUNCED_LOOKAHEAD);
        assert!(a.pull);
        assert!(!p.evaluate(u64::MAX, 100, t0 + Duration::from_secs(1)).pull, "rate-limited");
        assert!(p.evaluate(u64::MAX, 100, t0 + CLAIM_PULL_MIN_INTERVAL).pull);
        let b = p.evaluate(5, 100, t0);
        assert!(b.reciprocal && !b.pull);
    }

    #[test]
    fn orphan_pool_first_copy_wins_and_fifo_eviction() {
        let limits = OrphanLimits { max_entries: 3, max_bytes: 1_000, max_entries_per_peer: 3, max_bytes_per_peer: 1_000 };
        let mut pool = OrphanPool::new(limits);
        for i in 0..3 {
            assert!(matches!(pool.insert(h(i), blk(vec![h(100 + i)], i), 10, 10, None, false, &[h(100 + i)]), OrphanInsert::Inserted { .. }));
        }
        assert_eq!(pool.insert(h(0), blk(vec![h(100)], 0), u64::MAX, 10, None, false, &[h(100)]), OrphanInsert::Duplicate);
        assert_eq!(pool.get(&h(0)).unwrap().height, 10, "the first copy is kept");
        // A 4th entry evicts the OLDEST arrival (h0), regardless of heights.
        match pool.insert(h(3), blk(vec![h(103)], 3), 0, 10, None, false, &[h(103)]) {
            OrphanInsert::Inserted { evicted } => assert_eq!(evicted, vec![h(0)]),
            other => panic!("{other:?}"),
        }
        assert!(!pool.is_waited_on(&h(100)), "evicted orphan detached from its parent");
    }

    #[test]
    fn orphan_pool_drop_subtree_is_iterative() {
        let mut pool = OrphanPool::new(OrphanLimits {
            max_entries: 10_000, max_bytes: 1 << 20, max_entries_per_peer: 10_000, max_bytes_per_peer: 1 << 20,
        });
        // chain: h1 waits on h0 (missing), h2 waits on h1, ... 5_000 deep
        for i in 1..=5_000u64 {
            pool.insert(h(i), blk(vec![h(i - 1)], i), i, 1, None, false, &[h(i - 1)]);
        }
        assert_eq!(pool.drop_subtree(&h(0)), 5_000);
        assert!(pool.is_empty());
        assert_eq!(pool.total_bytes(), 0);
    }

    #[test]
    fn evidence_height_tracks_pool() {
        let mut pool = OrphanPool::default();
        pool.insert(h(1), blk(vec![h(9)], 1), 500, 1, None, true, &[h(9)]);
        pool.insert(h(2), blk(vec![h(9)], 2), 900, 1, None, true, &[h(9)]);
        pool.insert(h(3), blk(vec![h(9)], 3), 5_000, 1, None, false, &[h(9)]);
        assert_eq!(pool.max_evidence_height(), Some(900));
        pool.remove(&h(2));
        assert_eq!(pool.max_evidence_height(), Some(500));
        pool.drop_subtree(&h(9));
        assert_eq!(pool.max_evidence_height(), None);
    }

    // ── POW-3 work rule ────────────────────────────────────────────────────

    #[test]
    fn work_admission_decision_table() {
        use WorkAdmission::*;
        assert_eq!(work_admission(100, 100, 0, 0), NearTip);
        assert_eq!(work_admission(99, 100, 1, 0), ChainBacked);
        assert_eq!(work_admission(99, 100, 0, 100), MergeBacked);
        assert_eq!(work_admission(10, 100, 89, 99), LowWork);
        assert_eq!(work_admission(u128::MAX, 0, u128::MAX, u128::MAX), NearTip, "no overflow");
        assert_eq!(work_admission(1, u128::MAX, u128::MAX, 0), ChainBacked, "saturating");
    }

    fn chain_dag(n: u64, work: u128) -> (crate::consensus::GhostDAG, Vec<[u8; 32]>) {
        let mut dag = crate::consensus::GhostDAG::with_default_k();
        dag.add_genesis(h(0), 0);
        let mut chain = vec![h(0)];
        for i in 1..=n {
            dag.add_block(h(i), vec![h(i - 1)], i, work).unwrap();
            chain.push(h(i));
        }
        (dag, chain)
    }

    #[test]
    fn threshold_is_the_work_of_the_selected_chain_block_a_window_below_the_tip() {
        let (dag, _) = chain_dag(ANTI_DOS_WINDOW_BLOCKS - 1, 10);
        assert_eq!(anti_dos_work_threshold(&dag), 0, "chain shorter than the window");
        let (dag, chain) = chain_dag(ANTI_DOS_WINDOW_BLOCKS + 40, 10);
        assert_eq!(anti_dos_work_threshold(&dag), 400, "block 40 carries 40 x 10");
        assert_eq!(block_work_lower_bound(&dag, &[chain[40], chain[7]], core::POW_LIMIT_BITS),
            Some(400 + core::bits_to_work(core::POW_LIMIT_BITS)));
        assert_eq!(block_work_lower_bound(&dag, &[[0xEE; 32]], core::POW_LIMIT_BITS), None);
    }

    #[test]
    fn announced_work_survives_eviction() {
        // A chain o1 <- o2 <- ... <- o6 announced on top of the missing x,
        // fetched tip-first (o6 arrives first) into a pool of 3 entries.
        let limits = OrphanLimits { max_entries: 3, max_bytes: 1 << 20, max_entries_per_peer: 3, max_bytes_per_peer: 1 << 20 };
        let mut pool = OrphanPool::new(limits);
        let x = h(1000);
        let o = |i: u64| h(2000 + i);
        let w = core::bits_to_work(core::POW_LIMIT_BITS);
        for i in (1..=6u64).rev() {
            let parent = if i == 1 { x } else { o(i - 1) };
            pool.insert(o(i), blk(vec![parent], i), i, 1, None, false, &[parent]);
        }
        assert_eq!(pool.len(), 3, "o6, o5, o4 were evicted");
        assert!(pool.remembers(&o(3)), "o4's eviction remembered the work above o3");
        assert_eq!(pool.announced_work_above(&x), 6 * w, "the whole announced chain, buffered + remembered");
        assert_eq!(pool.announced_work_above(&o(2)), 4 * w);
        pool.forget(&o(3));
        assert!(!pool.remembers(&o(3)));
        assert_eq!(pool.announced_work_above(&x), 3 * w, "only the buffered o1..o3 are left");
    }

    #[test]
    fn best_waiter_lb_counts_known_parents_and_diamonds() {
        let (dag, chain) = chain_dag(50, 10);
        let w = core::bits_to_work(core::POW_LIMIT_BITS);
        let x = h(1000);
        let mut pool = OrphanPool::default();
        // a waits on x; b waits on x; c merges a, b and the known chain[50].
        pool.insert(h(1001), blk(vec![x], 1), 1, 1, None, false, &[x]);
        pool.insert(h(1002), blk(vec![x], 2), 1, 1, None, false, &[x]);
        pool.insert(h(1003), blk(vec![h(1001), h(1002), chain[50]], 3), 2, 1, None, false, &[h(1001), h(1002)]);
        assert_eq!(pool.announced_work_above(&x), 2 * w, "longest waiting path x <- a <- c");
        // Merge-backed: c's bound comes from the known chain[50] (500).
        assert_eq!(pool.best_waiter_lb(&x, 7, &dag), 500 + w);
        // With x's own bound high, the path through x dominates.
        assert_eq!(pool.best_waiter_lb(&x, 10_000, &dag), 10_000 + 2 * w);
        assert_eq!(pool.best_waiter_lb(&h(4242), 1, &dag), 0, "nobody waits on it");
    }
}
