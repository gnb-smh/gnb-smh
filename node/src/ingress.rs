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
//!   orphan claiming to be well ahead of us), never by a tip claim (NET-6).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use libp2p::PeerId;

use crate::core;
use crate::network::GossipVerdict;

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

/// DAG-7 / POW-3: global budget of deep (below-finality) block insertions that
/// the "awaited" exemption may grant. Inserting one deep block costs seconds
/// under the DAG write lock; an orphan can make its deep parents "awaited", so
/// the exemption is rationed instead of unconditional. An honest node needs it
/// almost never; a denied block is simply re-requested by the orphan sweep.
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

/// Gossip verdict for a `NewTransaction` frame once the mempool decided
/// (audit follow-up to OPS-2): relayed (`Accept`) only if it was admitted.
/// Every refusal — undecodable, non-standard, missing or spent inputs, low
/// fee, bad signature, already known — is `Ignore`: not relayed and never
/// penalized, because most refusals depend on local state and older nodes
/// still relay transactions on decode.
pub fn verdict_for_tx_admission(admitted: bool) -> GossipVerdict {
    if admitted { GossipVerdict::Accept } else { GossipVerdict::Ignore }
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
                    self.remove(&h);
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
                    self.remove(&h);
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

    /// Transactions are relayed only once the mempool admitted them; a
    /// refusal is never a penalty.
    #[test]
    fn tx_verdict_follows_mempool_admission() {
        assert_eq!(verdict_for_tx_admission(true), GossipVerdict::Accept);
        assert_eq!(verdict_for_tx_admission(false), GossipVerdict::Ignore);
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
}
