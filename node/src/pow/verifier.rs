//! NET-2 residual (Phase 4): proof-of-work evaluations OFF the message
//! processor, under budgets.
//!
//! A GnB-SMH evaluation costs 64 MiB and most of a second of CPU. The audit
//! found it still ran inline on the single message-processor task, so a
//! block that costs its sender nothing (our tip as parent with the expected
//! bits and a junk nonce, or an orphan whose bits meet the floor) forced an
//! evaluation at every directly connected node and stalled everything queued
//! behind it — honest blocks, tip claims, pull answers. Bitcoin Core never
//! has this problem (its proof is one SHA-256d); the closest defences are its
//! per-peer accounting (misbehaviour leads to disconnection and address
//! discouragement) and its bounded per-peer work queues. Here:
//!
//! * the message processor runs every cheap check first and then hands the
//!   block to this scheduler instead of evaluating it; evaluations run on
//!   the blocking thread pool, at most [`PowLimits::workers`] at a time
//!   (the global concurrency budget), and the processor resumes the block
//!   when the result arrives;
//! * the queue is bounded globally ([`PowLimits::max_queued`]), per
//!   delivering peer and per network group, and answers to this node's own
//!   pulls go first;
//! * every GOSSIP evaluation is charged to the delivering peer's budget AND
//!   to its network group's budget (`network::discourage::NetGroup`: /16,
//!   /32 — fresh identities and addresses inside one range share it) and
//!   refunded when the proof is valid, so only failed proofs (and
//!   floor-failing orphans, [`PowScheduler::charge`]) consume it: an honest
//!   relay's valid blocks never do. An answer to this node's own pull is not
//!   charged up front (an IBD batch from one peer has up to 16 pulls in
//!   flight, answered faster than proofs are evaluated: charging them would
//!   drop most of them, review finding); it is charged only when its proof
//!   turns out invalid;
//! * a gossip job still queued when its frame left gossipsub's cache
//!   ([`PowLimits::verdict_ttl`]) is dropped unevaluated with an explicit
//!   `Ignore` (`StartNext::Expired`): every queued gossip frame gets exactly
//!   one verdict, the result's or that one;
//! * results are remembered (bounded) by block id AND header height, so a
//!   resubmitted block never costs a second evaluation. The height is part
//!   of the key because `Block::validate_pow` judges the target against the
//!   pow limit of the block's height, which the block id does not commit: a
//!   copy re-framed with another height must not poison the honest block's
//!   result (review finding; `gnb_crypto`'s own proof cache keeps only
//!   successes for the same reason).

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use libp2p::PeerId;

use crate::network::discourage::NetGroup;
use crate::network::ratelimit::TokenBuckets;

/// Bounds of a [`PowScheduler`].
#[derive(Clone, Copy, Debug)]
pub struct PowLimits {
    /// Evaluations running at once (each holds 64 MiB).
    pub workers:              usize,
    /// Gossip jobs queued (not running), in total.
    pub max_queued:           usize,
    /// Gossip jobs queued per delivering peer.
    pub max_queued_per_peer:  usize,
    /// Gossip jobs queued per network group.
    pub max_queued_per_group: usize,
    /// Answers to this node's own pulls queued (not running): no per-peer
    /// bound (an IBD batch comes from one peer); the pull pipeline bounds
    /// how many are outstanding, and this bounds the memory they hold (the
    /// frame, at most 4 MiB, typically one block of at most 1 MB).
    pub max_queued_solicited: usize,
    /// Per-peer budget of unrefunded evaluations: burst and refill.
    pub peer_burst:           u32,
    pub peer_refill_per_sec:  f64,
    /// Per-network-group budget: burst and refill.
    pub group_burst:          u32,
    pub group_refill_per_sec: f64,
    /// A gossip job older than this when a worker frees up is dropped with
    /// an explicit `Ignore` (gossipsub has dropped its frame meanwhile).
    pub verdict_ttl:          Duration,
    /// Results remembered (by block id).
    pub results_cap:          usize,
}

impl Default for PowLimits {
    fn default() -> Self {
        Self {
            workers: default_workers(),
            max_queued: 64,
            max_queued_solicited: 1_024,
            max_queued_per_peer: 4,
            max_queued_per_group: 8,
            peer_burst: 4,
            peer_refill_per_sec: 1.0 / 60.0,
            group_burst: 8,
            group_refill_per_sec: 1.0 / 30.0,
            verdict_ttl: crate::mempool::relay::DEFERRED_VERDICT_TTL,
            results_cap: 4_096,
        }
    }
}

/// Half the logical CPUs, at least 1 and at most 4 (each evaluation holds a
/// 64 MiB scratchpad; the miner and the rest of the node need the others).
pub fn default_workers() -> usize {
    std::thread::available_parallelism().map(|n| n.get() / 2).unwrap_or(1).clamp(1, 4)
}

/// Bound on tracked budget keys (far above the connection limit).
const BUDGET_TRACK_CAP: usize = 4_096;

/// Who an evaluation is charged to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PowSource {
    /// The delivering peer (`None`: local).
    pub peer:  Option<PeerId>,
    /// Its network group, when known.
    pub group: Option<NetGroup>,
}

/// Why a job was not queued (the block is not evaluated; its frame is
/// answered `Ignore`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PowRefusal {
    PeerBudget,
    GroupBudget,
    PeerQueue,
    GroupQueue,
    QueueFull,
    /// The same block id is already queued or running.
    AlreadyQueued,
}

/// A queued evaluation.
#[derive(Debug)]
pub struct PowJob<T> {
    pub id:          [u8; 32],
    /// The block's header height (not committed by `id`; part of the result
    /// key).
    pub height:      u64,
    pub source:      PowSource,
    /// The answer to one of this node's pulls (no gossip verdict owed;
    /// never expires, goes first).
    pub solicited:   bool,
    /// When the network loop received the frame.
    pub received_at: Instant,
    pub payload:     T,
}

impl<T> PowJob<T> {
    /// The result of evaluating this job, for [`PowScheduler::complete`].
    pub fn outcome(&self, valid: bool) -> PowOutcome {
        PowOutcome { id: self.id, height: self.height, source: self.source, solicited: self.solicited, valid }
    }
}

/// The result of a started job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PowOutcome {
    pub id:        [u8; 32],
    pub height:    u64,
    pub source:    PowSource,
    pub solicited: bool,
    pub valid:     bool,
}

/// What [`PowScheduler::start_next`] hands out.
#[derive(Debug)]
pub enum StartNext<T> {
    /// Evaluate this job now (a worker slot was taken; call
    /// [`PowScheduler::complete`] with its result).
    Start(PowJob<T>),
    /// This gossip job waited too long: answer its frame `Ignore`, do not
    /// evaluate it (its budget charge is refunded).
    Expired(PowJob<T>),
    /// Nothing to start (no free worker, or an empty queue).
    Idle,
}

/// Counters (metrics, tests).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PowStats {
    pub queued:    u64,
    pub started:   u64,
    pub valid:     u64,
    pub invalid:   u64,
    pub refused:   u64,
    pub expired:   u64,
}

/// The bounded, budgeted proof-of-work queue of the message processor.
pub struct PowScheduler<T> {
    limits:       PowLimits,
    peer_budget:  TokenBuckets<PeerId>,
    group_budget: TokenBuckets<NetGroup>,
    solicited:    VecDeque<PowJob<T>>,
    gossip:       VecDeque<PowJob<T>>,
    ids:          HashSet<[u8; 32]>,
    per_peer:     HashMap<PeerId, usize>,
    per_group:    HashMap<NetGroup, usize>,
    in_flight:    usize,
    results:      HashMap<([u8; 32], u64), bool>,
    result_order: VecDeque<([u8; 32], u64)>,
    stats:        PowStats,
}

impl<T> PowScheduler<T> {
    pub fn new(limits: PowLimits) -> Self {
        Self {
            limits,
            peer_budget: TokenBuckets::new(limits.peer_burst, limits.peer_refill_per_sec, BUDGET_TRACK_CAP),
            group_budget: TokenBuckets::new(limits.group_burst, limits.group_refill_per_sec, BUDGET_TRACK_CAP),
            solicited: VecDeque::new(),
            gossip: VecDeque::new(),
            ids: HashSet::new(),
            per_peer: HashMap::new(),
            per_group: HashMap::new(),
            in_flight: 0,
            results: HashMap::new(),
            result_order: VecDeque::new(),
            stats: PowStats::default(),
        }
    }

    /// Counters since start.
    #[allow(dead_code)] // tests only; the node binary compiles this module too
    pub fn stats(&self) -> PowStats {
        self.stats
    }

    /// Evaluations running.
    #[allow(dead_code)] // tests only; the node binary compiles this module too
    pub fn in_flight(&self) -> usize {
        self.in_flight
    }

    /// Jobs waiting for a worker.
    #[allow(dead_code)] // tests only; the node binary compiles this module too
    pub fn queued(&self) -> usize {
        self.solicited.len() + self.gossip.len()
    }

    /// The result of an earlier evaluation of block `id` framed at header
    /// height `height`, if remembered.
    pub fn known(&self, id: &[u8; 32], height: u64) -> Option<bool> {
        self.results.get(&(*id, height)).copied()
    }

    /// Take one budget token from the peer and from its group (all or
    /// nothing).
    fn take(&mut self, source: &PowSource, now: Instant) -> Result<(), PowRefusal> {
        if let Some(p) = source.peer {
            if !self.peer_budget.try_take_n_at(p, 1, now) {
                return Err(PowRefusal::PeerBudget);
            }
        }
        if let Some(g) = source.group {
            if !self.group_budget.try_take_n_at(g, 1, now) {
                if let Some(p) = source.peer {
                    self.peer_budget.refund_n(p, 1);
                }
                return Err(PowRefusal::GroupBudget);
            }
        }
        Ok(())
    }

    fn refund(&mut self, source: &PowSource) {
        if let Some(p) = source.peer {
            self.peer_budget.refund_n(p, 1);
        }
        if let Some(g) = source.group {
            self.group_budget.refund_n(g, 1);
        }
    }

    /// Charge `source` one evaluation without queuing anything (a penalty:
    /// an orphan whose bits fail the floor cost its decoding and hashing and
    /// proves its sender is not honest). Returns `false` when the budget was
    /// already spent.
    pub fn charge(&mut self, source: &PowSource, now: Instant) -> bool {
        self.take(source, now).is_ok()
    }

    /// Queue `job`, charging one evaluation to its source (a gossip job
    /// only: an answer to our own pull is charged when its proof fails). On
    /// refusal the job is handed back with the reason.
    #[allow(clippy::result_large_err)] // the refused job is handed back (moved), not copied
    pub fn submit(&mut self, job: PowJob<T>, now: Instant) -> Result<(), (PowRefusal, PowJob<T>)> {
        let refuse = |s: &mut Self, r: PowRefusal, job: PowJob<T>| {
            s.stats.refused += 1;
            Err((r, job))
        };
        if self.ids.contains(&job.id) {
            return refuse(self, PowRefusal::AlreadyQueued, job);
        }
        if job.solicited {
            // Answers to this node's own pulls: as many as it asked for (the
            // pull pipeline bounds them; an IBD batch from one peer must not
            // be refused per peer), within their own bound.
            if self.solicited.len() >= self.limits.max_queued_solicited {
                return refuse(self, PowRefusal::QueueFull, job);
            }
        } else {
            if self.gossip.len() >= self.limits.max_queued {
                return refuse(self, PowRefusal::QueueFull, job);
            }
            if let Some(p) = job.source.peer {
                if self.per_peer.get(&p).copied().unwrap_or(0) >= self.limits.max_queued_per_peer {
                    return refuse(self, PowRefusal::PeerQueue, job);
                }
            }
            if let Some(g) = job.source.group {
                if self.per_group.get(&g).copied().unwrap_or(0) >= self.limits.max_queued_per_group {
                    return refuse(self, PowRefusal::GroupQueue, job);
                }
            }
        }
        if !job.solicited {
            if let Err(r) = self.take(&job.source, now) {
                return refuse(self, r, job);
            }
        }
        if !job.solicited {
            if let Some(p) = job.source.peer {
                *self.per_peer.entry(p).or_insert(0) += 1;
            }
            if let Some(g) = job.source.group {
                *self.per_group.entry(g).or_insert(0) += 1;
            }
        }
        self.ids.insert(job.id);
        self.stats.queued += 1;
        if job.solicited {
            self.solicited.push_back(job);
        } else {
            self.gossip.push_back(job);
        }
        Ok(())
    }

    fn dequeued(&mut self, job: &PowJob<T>) {
        if job.solicited {
            return;
        }
        if let Some(p) = job.source.peer {
            if let Some(n) = self.per_peer.get_mut(&p) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    self.per_peer.remove(&p);
                }
            }
        }
        if let Some(g) = job.source.group {
            if let Some(n) = self.per_group.get_mut(&g) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    self.per_group.remove(&g);
                }
            }
        }
    }

    /// The next job to evaluate, if a worker is free: answers to this node's
    /// pulls first, then gossip in arrival order. A gossip job older than
    /// [`PowLimits::verdict_ttl`] is returned as [`StartNext::Expired`]
    /// instead (call again for the next one).
    pub fn start_next(&mut self, now: Instant) -> StartNext<T> {
        if self.in_flight >= self.limits.workers.max(1) {
            return StartNext::Idle;
        }
        let job = match self.solicited.pop_front() {
            Some(j) => j,
            None => match self.gossip.pop_front() {
                Some(j) => j,
                None => return StartNext::Idle,
            },
        };
        self.dequeued(&job);
        if !job.solicited && now.saturating_duration_since(job.received_at) >= self.limits.verdict_ttl {
            self.ids.remove(&job.id);
            self.refund(&job.source);
            self.stats.expired += 1;
            return StartNext::Expired(job);
        }
        self.in_flight += 1;
        self.stats.started += 1;
        StartNext::Start(job)
    }

    /// Record the result of a started job: frees its worker slot, remembers
    /// the result, refunds a gossip job's budget charge when the proof is
    /// valid, and charges an answer to our own pull whose proof is invalid.
    pub fn complete(&mut self, done: PowOutcome, now: Instant) {
        self.in_flight = self.in_flight.saturating_sub(1);
        self.ids.remove(&done.id);
        if done.valid {
            self.stats.valid += 1;
            if !done.solicited {
                self.refund(&done.source);
            }
        } else {
            self.stats.invalid += 1;
            if done.solicited {
                let _ = self.take(&done.source, now);
            }
        }
        let key = (done.id, done.height);
        if self.results.insert(key, done.valid).is_none() {
            self.result_order.push_back(key);
            while self.result_order.len() > self.limits.results_cap.max(1) {
                if let Some(old) = self.result_order.pop_front() {
                    self.results.remove(&old);
                }
            }
        }
    }

    /// Housekeeping of the budget maps.
    pub fn gc_at(&mut self, now: Instant) {
        self.peer_budget.gc_at(now, Duration::from_secs(3_600));
        self.group_budget.gc_at(now, Duration::from_secs(3_600));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src(peer: Option<PeerId>, g: u8) -> PowSource {
        let ip: std::net::IpAddr = format!("45.{g}.1.2").parse().unwrap();
        PowSource { peer, group: Some(crate::network::discourage::net_group(ip)) }
    }

    fn job(i: u8, source: PowSource, solicited: bool, at: Instant) -> PowJob<u8> {
        PowJob { id: [i; 32], height: 7, source, solicited, received_at: at, payload: i }
    }

    fn limits() -> PowLimits {
        PowLimits {
            workers: 1, max_queued: 8, max_queued_per_peer: 2, max_queued_per_group: 3, max_queued_solicited: 4,
            peer_burst: 2, peer_refill_per_sec: 0.0, group_burst: 3, group_refill_per_sec: 0.0,
            verdict_ttl: Duration::from_secs(10), results_cap: 4,
        }
    }

    /// Failed proofs consume the peer's and the group's budget; valid ones
    /// are refunded; fresh identities in one group share the group budget.
    #[test]
    fn budgets_charge_failures_and_refund_valid_proofs() {
        let t0 = Instant::now();
        let mut s: PowScheduler<u8> = PowScheduler::new(limits());
        let a = Some(PeerId::random());
        // Two failures exhaust A's budget of 2.
        for i in 0..2u8 {
            s.submit(job(i, src(a, 1), false, t0), t0).unwrap();
            let StartNext::Start(j) = s.start_next(t0) else { panic!() };
            s.complete(j.outcome(false), t0);
        }
        assert_eq!(s.submit(job(9, src(a, 1), false, t0), t0).unwrap_err().0, PowRefusal::PeerBudget);
        // A third identity in the same /16 spends the last group token; a
        // fourth is refused by the GROUP budget although its own is full.
        let b = Some(PeerId::random());
        s.submit(job(10, src(b, 1), false, t0), t0).unwrap();
        let StartNext::Start(j) = s.start_next(t0) else { panic!() };
        s.complete(j.outcome(false), t0);
        let c = Some(PeerId::random());
        assert_eq!(s.submit(job(11, src(c, 1), false, t0), t0).unwrap_err().0, PowRefusal::GroupBudget);
        // Another group is unaffected; its valid proofs never consume.
        let d = Some(PeerId::random());
        for i in 20..30u8 {
            s.submit(job(i, src(d, 2), false, t0), t0).unwrap();
            let StartNext::Start(j) = s.start_next(t0) else { panic!() };
            s.complete(j.outcome(true), t0);
        }
        assert_eq!(s.known(&[20; 32], 7), None, "results are bounded (cap 4)");
        assert_eq!(s.known(&[29; 32], 7), Some(true));
        assert_eq!(s.stats().invalid, 3);
    }

    /// One worker; solicited jobs first; per-peer / per-group / global queue
    /// bounds; a stale gossip job is expired (explicit Ignore) and refunded.
    #[test]
    fn queue_is_bounded_ordered_and_expires_gossip() {
        let t0 = Instant::now();
        let mut lim = limits();
        lim.peer_burst = 100;
        lim.group_burst = 100;
        let mut s: PowScheduler<u8> = PowScheduler::new(lim);
        let a = Some(PeerId::random());
        s.submit(job(1, src(a, 1), false, t0), t0).unwrap();
        s.submit(job(2, src(a, 1), false, t0), t0).unwrap();
        assert_eq!(s.submit(job(3, src(a, 1), false, t0), t0).unwrap_err().0, PowRefusal::PeerQueue);
        assert_eq!(s.submit(job(1, src(None, 9), true, t0), t0).unwrap_err().0, PowRefusal::AlreadyQueued);
        let b = Some(PeerId::random());
        s.submit(job(4, src(b, 1), false, t0), t0).unwrap();
        assert_eq!(s.submit(job(5, src(b, 1), false, t0), t0).unwrap_err().0, PowRefusal::GroupQueue);
        s.submit(job(6, src(None, 7), true, t0), t0).unwrap();
        let StartNext::Start(first) = s.start_next(t0) else { panic!() };
        assert_eq!(first.payload, 6, "our own pull's answer goes first");
        assert!(matches!(s.start_next(t0), StartNext::Idle), "one worker");
        s.complete(first.outcome(true), t0);
        // 11 s later the queued gossip jobs are stale.
        let late = t0 + Duration::from_secs(11);
        let mut expired = Vec::new();
        loop {
            match s.start_next(late) {
                StartNext::Expired(j) => expired.push(j.payload),
                StartNext::Start(_) => panic!("stale gossip must not be evaluated"),
                StartNext::Idle => break,
            }
        }
        assert_eq!(expired, vec![1, 2, 4]);
        assert_eq!(s.queued(), 0);
        assert_eq!(s.stats().expired, 3);
        // Global bound.
        let mut lim = limits();
        lim.max_queued = 2;
        lim.peer_burst = 100;
        lim.group_burst = 100;
        let mut s: PowScheduler<u8> = PowScheduler::new(lim);
        s.submit(job(1, src(Some(PeerId::random()), 1), false, t0), t0).unwrap();
        s.submit(job(2, src(Some(PeerId::random()), 2), false, t0), t0).unwrap();
        assert_eq!(s.submit(job(3, src(Some(PeerId::random()), 3), false, t0), t0).unwrap_err().0, PowRefusal::QueueFull);
    }

    /// Answers to this node's own pulls (an IBD batch comes from one peer)
    /// are bounded by their own queue, not per peer or group, not charged to
    /// the budgets (here 2 per peer, 3 per group), and never expire (no
    /// gossip verdict is owed for them).
    #[test]
    fn answers_to_our_pulls_are_bounded_on_their_own() {
        let t0 = Instant::now();
        let mut lim = limits();
        lim.max_queued_solicited = 6;
        let mut s: PowScheduler<u8> = PowScheduler::new(lim);
        let a = Some(PeerId::random());
        for i in 0..6u8 {
            s.submit(job(i, src(a, 1), true, t0), t0).expect("no per-peer bound for our own pulls");
        }
        assert_eq!(s.submit(job(7, src(a, 1), true, t0), t0).unwrap_err().0, PowRefusal::QueueFull);
        s.submit(job(8, src(a, 1), false, t0), t0).expect("gossip has its own bounds and budget");
        let late = t0 + Duration::from_secs(60);
        let StartNext::Start(j) = s.start_next(late) else { panic!("an old pull answer is still evaluated") };
        assert!(j.solicited);
    }

    #[test]
    fn charge_is_a_budget_penalty() {
        let t0 = Instant::now();
        let mut s: PowScheduler<u8> = PowScheduler::new(limits());
        let a = Some(PeerId::random());
        assert!(s.charge(&src(a, 1), t0));
        assert!(s.charge(&src(a, 1), t0));
        assert!(!s.charge(&src(a, 1), t0), "spent");
        assert_eq!(s.submit(job(1, src(a, 1), false, t0), t0).unwrap_err().0, PowRefusal::PeerBudget);
    }

    /// Review finding (NET-2): with the DEFAULT limits (4 per peer, 8 per
    /// group), 16 answers to our own pulls from one peer — what sync keeps
    /// in flight per peer — are all queued and evaluated; only an invalid
    /// answer is charged. Pre-fix answers 5 and up were refused
    /// (`PeerBudget`) and silently dropped.
    #[test]
    fn pull_answers_are_not_charged_until_their_proof_fails() {
        let t0 = Instant::now();
        let mut s: PowScheduler<u8> = PowScheduler::new(PowLimits { workers: 1, ..PowLimits::default() });
        let a = Some(PeerId::random());
        for i in 0..16u8 {
            s.submit(job(i, src(a, 1), true, t0), t0).expect("an answer to our own pull is not budgeted");
        }
        for _ in 0..16 {
            let StartNext::Start(j) = s.start_next(t0) else { panic!() };
            s.complete(j.outcome(true), t0);
        }
        // Valid answers cost nothing: A's gossip budget is whole.
        for i in 0..4u8 {
            s.submit(job(100 + i, src(a, 1), false, t0), t0).expect("budget untouched by valid answers");
            let StartNext::Start(j) = s.start_next(t0) else { panic!() };
            s.complete(j.outcome(true), t0);
        }
        // Invalid answers are charged: after 4, A's gossip is refused.
        for i in 0..4u8 {
            s.submit(job(50 + i, src(a, 1), true, t0), t0).unwrap();
            let StartNext::Start(j) = s.start_next(t0) else { panic!() };
            s.complete(j.outcome(false), t0);
        }
        assert_eq!(s.submit(job(60, src(a, 1), false, t0), t0).unwrap_err().0, PowRefusal::PeerBudget);
    }

    /// Review finding (NET-2): the result is remembered per (id, height): an
    /// invalid result for a copy re-framed with another height (the pow
    /// limit `validate_pow` applies depends on it) says nothing about the
    /// honest copy.
    #[test]
    fn results_are_keyed_by_id_and_height() {
        let t0 = Instant::now();
        let mut s: PowScheduler<u8> = PowScheduler::new(limits());
        let mut fake = job(1, src(Some(PeerId::random()), 1), false, t0);
        fake.height = 110_000;
        s.submit(fake, t0).unwrap();
        let StartNext::Start(j) = s.start_next(t0) else { panic!() };
        s.complete(j.outcome(false), t0);
        assert_eq!(s.known(&[1; 32], 110_000), Some(false));
        assert_eq!(s.known(&[1; 32], 7), None, "the honest height is not poisoned");
    }
}
