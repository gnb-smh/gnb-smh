//! Directed-pull scheduling: the CLIENT side of `/gnb/sync/1`, swarm-free.
//!
//! The network loop (`network/mod.rs`) owns one [`PullScheduler`]: it
//! enqueues the processor's pulls (GetBlock / GetHeaders / GetTips /
//! GetPeers), sends what [`PullScheduler::drain`] picks, and reports every
//! answer and failure back. Everything that decides who is asked, when, how
//! often and what an answer is worth lives here, so it is tested directly
//! (`node/tests/fix_net_directed_sync.rs`, including a discrete-event model
//! of fast attackers against rate-limiting honest servers).
//!
//! Audit NET-5 / NET-9 and re-audit B1-T2 / B1-T6 / NET-10 (Bitcoin Core's
//! block download logic is the model: `mapBlocksInFlight`, at most 16 blocks
//! in flight per peer, blocks fetched from a peer that announced them, a
//! stalling peer moved away from):
//!
//! * Every answer is bound to its request (`sync_rr::check_response`): any
//!   other answer is a protocol violation — not delivered, the pull not
//!   completed, the peer put on cooldown, and the caller penalizes it.
//! * A pull prefers the peers that announced the block (its hints), is never
//!   sent twice to the same peer, is retried with a growing delay (the first
//!   retry at once), is dropped after [`MAX_PULL_ATTEMPTS`] peers, when no
//!   connected peer is left to ask, or after [`MAX_PULL_AGE`]. Busy is
//!   back-pressure: it neither uses an attempt nor excludes the peer.
//! * NotFound counts against the answering peer (it ranks down), and is
//!   refunded if the pull is dropped (then nobody had the block: the answer
//!   was true). Only a NotFound from a peer we dialed is delivered (it may
//!   count toward abandoning a frontier tip: free inbound identities cannot
//!   abandon one).
//! * One source's answers cannot fill the shared queue: pulls attributed to
//!   the peer whose answer announced them are capped per source
//!   ([`MAX_PENDING_PER_SOURCE`]), and the node's own pulls are always
//!   admitted (they evict an attributed one when the queue is full). The same
//!   block is pulled once however many answers name it.

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;
use std::time::{Duration, Instant};

use libp2p::PeerId;
use log::debug;

use super::sync_rr::{self, PullPeerSelector, SyncRequest, SyncResponse};

/// Max queued pulls waiting for an eligible peer.
pub const MAX_PENDING_PULLS: usize = 4096;
/// B1-T2: max queued or in-flight pulls attributed to ONE source (the peer
/// whose Headers or Tips answer announced them).
pub const MAX_PENDING_PER_SOURCE: usize = MAX_PENDING_PULLS / 4;
/// A pull is sent to at most this many different peers (the processor's own
/// retry paths — frontier expiry, orphan sweep, the 30 s nudge — re-issue
/// anything still needed after that). B1-T6: was 3, with no spacing and
/// with the same peer allowed again.
pub const MAX_PULL_ATTEMPTS: u8 = 8;
/// A queued pull older than this is dropped.
pub const MAX_PULL_AGE: Duration = Duration::from_secs(600);
/// First spaced retry (the 2nd); each later one doubles, up to
/// [`MAX_RETRY_BACKOFF`]. The first retry goes to another peer at once.
pub const RETRY_BACKOFF: Duration = Duration::from_millis(250);
/// Longest delay between two attempts of one pull.
pub const MAX_RETRY_BACKOFF: Duration = Duration::from_secs(4);
/// Max peers a pull remembers as having its block.
pub const MAX_HINTS: usize = 4;
/// Queue entries examined per [`PullScheduler::drain`]; entries examined
/// but not sent move to the back, so the next drain sees the next ones.
const DRAIN_SCAN_LIMIT: usize = 512;
/// How often [`PullScheduler::drain`] expires old pulls.
const EXPIRY_PERIOD: Duration = Duration::from_secs(1);

/// What [`PullScheduler::enqueue`] did with a pull.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enqueued {
    Queued,
    /// The same block is already queued or in flight.
    Duplicate,
    /// Queue full, or its source is over [`MAX_PENDING_PER_SOURCE`].
    Refused,
}

/// Why a request ended without an answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureKind {
    /// Timeout, reset, unsupported protocol: counts toward a stall.
    Transport,
    /// The connection closed: no verdict on the peer.
    Closed,
    /// The answer broke the wire rules (`sync_rr::is_sync_protocol_violation`):
    /// a stall; the caller also penalizes the peer.
    Violation,
    /// The answer was refused, but an honest older release can send it
    /// (B2-T7: a Tips answer over the wire bound): a useless answer.
    Refused,
}

/// What the caller does with an answer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResponseAction {
    /// Hand the answer to the processor (or to peer-exchange ingest).
    pub deliver: bool,
    /// The peer broke the request/response contract
    /// (`sync_rr::check_response`): the caller penalizes it.
    pub violation: Option<&'static str>,
}

#[derive(Clone, Debug)]
struct PendingPull {
    req: SyncRequest,
    /// The peer whose answer announced it (charged against its quota).
    source: Option<PeerId>,
    /// Peers believed to have it (preferred).
    hints: Vec<PeerId>,
    /// A pull about one peer's own state, sent to it alone, never retried.
    pinned: bool,
    /// Peers that answered or failed it: never asked again.
    tried: Vec<PeerId>,
    /// Peers that answered NotFound (refunded if the pull is dropped).
    not_found: Vec<PeerId>,
    attempts: u8,
    not_before: Instant,
    created: Instant,
}

impl PendingPull {
    fn block_hash(&self) -> Option<[u8; 32]> {
        match self.req {
            SyncRequest::GetBlock { block_hash } => Some(block_hash),
            _ => None,
        }
    }
}

/// Spacing before attempt `attempts + 1`: none for the first retry, then
/// [`RETRY_BACKOFF`] doubling, capped.
fn retry_delay(attempts: u8) -> Duration {
    if attempts < 2 {
        return Duration::ZERO;
    }
    let shift = u32::from(attempts - 2).min(16);
    RETRY_BACKOFF.saturating_mul(1u32 << shift).min(MAX_RETRY_BACKOFF)
}

/// The directed-pull queue, in-flight table and peer selector. `I` is the
/// request id the transport assigns (libp2p's `OutboundRequestId`; a
/// counter in tests).
pub struct PullScheduler<I> {
    selector: PullPeerSelector,
    pending: VecDeque<PendingPull>,
    inflight: HashMap<I, (PendingPull, PeerId)>,
    /// Blocks queued or in flight (one pull per block).
    wanted: HashSet<[u8; 32]>,
    /// Queued or in-flight pulls per source.
    per_source: HashMap<PeerId, usize>,
    dropped: u64,
    last_expiry: Option<Instant>,
}

impl<I: Copy + Eq + Hash> PullScheduler<I> {
    pub fn new(explicit: HashSet<PeerId>) -> Self {
        Self {
            selector: PullPeerSelector::new(explicit),
            pending: VecDeque::new(),
            inflight: HashMap::new(),
            wanted: HashSet::new(),
            per_source: HashMap::new(),
            dropped: 0,
            last_expiry: None,
        }
    }

    /// A connection to `peer` was established; `outbound` = we dialed it.
    pub fn on_connect(&mut self, peer: PeerId, outbound: bool, now: Instant) {
        self.selector.on_connect_with(peer, outbound, now);
    }

    /// The last connection to `peer` closed: its in-flight pulls go back to
    /// the queue for other peers (the transport's later failure reports for
    /// them are ignored), and its selector state is kept.
    pub fn on_disconnect(&mut self, peer: &PeerId, now: Instant) {
        self.selector.on_disconnect_at(peer, now);
        let ids: Vec<I> = self.inflight.iter().filter(|(_, (_, to))| to == peer).map(|(id, _)| *id).collect();
        for id in ids {
            if let Some((p, _)) = self.inflight.remove(&id) {
                self.retry_after(p, *peer, false, now);
            }
        }
    }

    /// `peer` misbehaved (found by the caller: a violation on any
    /// protocol): it is not asked while on cooldown.
    pub fn on_misbehaving(&mut self, peer: &PeerId, now: Instant) {
        self.selector.on_misbehaving(peer, now);
    }

    /// Whether a NotFound from `peer` may count toward abandoning a frontier
    /// tip: only from a peer we dialed (NET-9 residual: two free inbound
    /// identities used to abandon any tip for an hour).
    pub fn counts_for_abandonment(&self, peer: &PeerId) -> bool {
        self.selector.is_outbound(peer)
    }

    /// Queue a pull. `source`: the peer whose answer announced it (charged
    /// against [`MAX_PENDING_PER_SOURCE`]; `None` for the node's own pulls).
    /// `hints`: peers believed to have it, asked first.
    pub fn enqueue(&mut self, req: SyncRequest, source: Option<PeerId>, hints: &[PeerId], now: Instant) -> Enqueued {
        if matches!(req, SyncRequest::Malformed) {
            return Enqueued::Refused;
        }
        if let SyncRequest::GetBlock { block_hash } = req {
            if self.wanted.contains(&block_hash) {
                return Enqueued::Duplicate;
            }
        }
        if let Some(s) = source {
            if self.per_source.get(&s).copied().unwrap_or(0) >= MAX_PENDING_PER_SOURCE {
                return Enqueued::Refused;
            }
        }
        if self.pending.len() >= MAX_PENDING_PULLS && !(source.is_none() && self.evict_one_attributed(now)) {
            return Enqueued::Refused;
        }
        let mut h: Vec<PeerId> = hints.iter().copied().take(MAX_HINTS).collect();
        h.dedup();
        let p = PendingPull {
            req,
            source,
            hints: h,
            pinned: false,
            tried: Vec::new(),
            not_found: Vec::new(),
            attempts: 0,
            not_before: now,
            created: now,
        };
        self.admit(&p);
        self.pending.push_back(p);
        Enqueued::Queued
    }

    fn admit(&mut self, p: &PendingPull) {
        if let Some(h) = p.block_hash() {
            self.wanted.insert(h);
        }
        if let Some(s) = p.source {
            *self.per_source.entry(s).or_insert(0) += 1;
        }
    }

    fn release(&mut self, p: &PendingPull) {
        if let Some(h) = p.block_hash() {
            self.wanted.remove(&h);
        }
        if let Some(s) = p.source {
            if let Some(n) = self.per_source.get_mut(&s) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    self.per_source.remove(&s);
                }
            }
        }
    }

    /// Drop a pull for good: its NotFound answers were true (refund them).
    fn drop_pull(&mut self, p: PendingPull, now: Instant, why: &str) {
        debug!("directed pull [{}] dropped ({why}) after {} attempt(s)", p.req.kind_name(), p.attempts);
        for peer in &p.not_found {
            self.selector.refund_useless(peer, now, 1.0);
        }
        self.release(&p);
        self.dropped += 1;
    }

    /// Make room for one of the node's own pulls: remove the most recently
    /// queued pull of the source with the most pulls charged.
    fn evict_one_attributed(&mut self, now: Instant) -> bool {
        let heaviest = self
            .pending
            .iter()
            .filter_map(|p| p.source)
            .max_by_key(|s| (self.per_source.get(s).copied().unwrap_or(0), s.to_bytes()));
        let Some(s) = heaviest else { return false };
        let Some(i) = self.pending.iter().rposition(|p| p.source == Some(s)) else { return false };
        let Some(p) = self.pending.remove(i) else { return false };
        self.drop_pull(p, now, "evicted for a local pull");
        true
    }

    /// Send `req` to `peer` itself, bypassing the queue: a request about THAT
    /// peer's state (its frontier on connect or when it claims to be ahead,
    /// its peers on connect). Never retried on another peer.
    pub fn send_pinned(&mut self, peer: PeerId, req: SyncRequest, now: Instant, send: impl FnOnce(PeerId, &SyncRequest) -> I) {
        let id = send(peer, &req);
        self.selector.on_sent(peer, now);
        let p = PendingPull {
            req,
            source: None,
            hints: vec![peer],
            pinned: true,
            tried: vec![peer],
            not_found: Vec::new(),
            attempts: 0,
            not_before: now,
            created: now,
        };
        self.inflight.insert(id, (p, peer));
    }

    /// Send queued pulls to eligible peers (`send` transmits one request
    /// and returns its id). Returns how many were sent.
    pub fn drain(&mut self, now: Instant, mut send: impl FnMut(PeerId, &SyncRequest) -> I) -> usize {
        self.expire(now);
        let mut sent = 0;
        let budget = self.pending.len().min(DRAIN_SCAN_LIMIT);
        for _ in 0..budget {
            if !self.selector.any_eligible(now) {
                break;
            }
            let Some(p) = self.pending.pop_front() else { break };
            if !p.tried.is_empty() && !self.selector.has_untried(&p.tried) {
                self.drop_pull(p, now, "no connected peer left to ask");
                continue;
            }
            if p.not_before > now {
                self.pending.push_back(p);
                continue;
            }
            match self.selector.select_for(now, &p.tried, &p.hints) {
                Some(peer) => {
                    let id = send(peer, &p.req);
                    debug!("→ directed pull [{}] to {}", p.req.kind_name(), peer);
                    self.selector.on_sent(peer, now);
                    self.inflight.insert(id, (p, peer));
                    sent += 1;
                }
                None => self.pending.push_back(p),
            }
        }
        sent
    }

    fn expire(&mut self, now: Instant) {
        if self.last_expiry.is_some_and(|t| now.saturating_duration_since(t) < EXPIRY_PERIOD) {
            return;
        }
        self.last_expiry = Some(now);
        let mut keep = VecDeque::with_capacity(self.pending.len());
        while let Some(p) = self.pending.pop_front() {
            if now.saturating_duration_since(p.created) >= MAX_PULL_AGE {
                self.drop_pull(p, now, "too old");
            } else {
                keep.push_back(p);
            }
        }
        self.pending = keep;
    }

    /// Put `p` back in the queue after `failed_on` answered or failed it,
    /// unless it is pinned or used up.
    fn retry(&mut self, p: PendingPull, failed_on: PeerId, now: Instant) {
        self.retry_after(p, failed_on, true, now);
    }

    /// [`Self::retry`]; `answered` = false when the request ended only
    /// because the connection closed: the peer is not excluded from the pull
    /// (it said nothing about it, and may serve it once reconnected).
    fn retry_after(&mut self, mut p: PendingPull, failed_on: PeerId, answered: bool, now: Instant) {
        if p.pinned {
            self.release(&p);
            return;
        }
        if answered && !p.tried.contains(&failed_on) {
            p.tried.push(failed_on);
        }
        p.attempts = p.attempts.saturating_add(1);
        if p.attempts >= MAX_PULL_ATTEMPTS {
            self.drop_pull(p, now, "attempts used up");
            return;
        }
        p.not_before = now + retry_delay(p.attempts);
        self.pending.push_back(p);
    }

    /// The answer `resp` from `peer` to request `id`.
    pub fn on_response(&mut self, id: I, peer: PeerId, resp: &SyncResponse, now: Instant) -> ResponseAction {
        let Some((mut p, _)) = self.inflight.remove(&id) else {
            // Every request is sent through this scheduler, and libp2p only
            // reports answers to requests it sent: nothing to bind it to (its
            // pull already went elsewhere), nothing to deliver.
            debug!("answer from {peer} to no outstanding pull; ignored");
            return ResponseAction::default();
        };
        if matches!(resp, SyncResponse::Busy) {
            // NET-5: back-pressure, not an offence; no attempt used, and the
            // peer may be asked again after its short back-off.
            self.selector.on_busy(&peer, now);
            if p.pinned {
                self.release(&p);
            } else {
                self.pending.push_back(p);
            }
            return ResponseAction::default();
        }
        if let Err(why) = sync_rr::check_response(&p.req, resp) {
            self.selector.on_closed(&peer);
            self.selector.on_misbehaving(&peer, now);
            self.retry(p, peer, now);
            return ResponseAction { deliver: false, violation: Some(why) };
        }
        match resp {
            SyncResponse::BlockNotFound { .. } => {
                self.selector.on_useless(&peer, now, 1.0);
                p.not_found.push(peer);
                let deliver = self.counts_for_abandonment(&peer);
                self.retry(p, peer, now);
                ResponseAction { deliver, violation: None }
            }
            SyncResponse::Headers { entries } if entries.is_empty() && p.hints.contains(&peer) => {
                // It claimed to be ahead of `from` and has nothing above it.
                self.selector.on_useless(&peer, now, 1.0);
                self.release(&p);
                ResponseAction { deliver: true, violation: None }
            }
            _ => {
                self.selector.on_success(&peer);
                self.release(&p);
                ResponseAction { deliver: true, violation: None }
            }
        }
    }

    /// Request `id` to `peer` ended without an answer.
    pub fn on_failure(&mut self, id: I, peer: PeerId, kind: FailureKind, now: Instant) {
        let Some((p, _)) = self.inflight.remove(&id) else { return };
        if kind == FailureKind::Closed {
            self.selector.on_closed(&peer);
            self.retry_after(p, peer, false, now);
            return;
        }
        match kind {
            FailureKind::Closed => {}
            FailureKind::Transport => self.selector.on_failure(&peer, now),
            FailureKind::Violation => {
                self.selector.on_closed(&peer);
                self.selector.on_misbehaving(&peer, now);
            }
            FailureKind::Refused => self.selector.on_useless(&peer, now, 1.0),
        }
        self.retry(p, peer, now);
    }

    /// Pulls waiting for a peer.
    #[allow(dead_code)] // library API and tests; the node binary compiles this module too
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Requests sent and not yet answered.
    #[allow(dead_code)] // library API and tests; the node binary compiles this module too
    pub fn in_flight_len(&self) -> usize {
        self.inflight.len()
    }

    /// Pulls dropped so far (attempts used up, no peer left, too old, or
    /// evicted).
    #[allow(dead_code)] // library API and tests; the node binary compiles this module too
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    #[allow(dead_code)] // library API and tests; the node binary compiles this module too
    pub fn selector(&self) -> &PullPeerSelector {
        &self.selector
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_delay_grows_and_is_capped() {
        assert_eq!(retry_delay(0), Duration::ZERO);
        assert_eq!(retry_delay(1), Duration::ZERO);
        assert_eq!(retry_delay(2), RETRY_BACKOFF);
        assert_eq!(retry_delay(3), RETRY_BACKOFF * 2);
        assert_eq!(retry_delay(7), MAX_RETRY_BACKOFF);
        assert_eq!(retry_delay(u8::MAX), MAX_RETRY_BACKOFF);
    }

    /// A pull every connected peer has answered is dropped (and its
    /// NotFound charges refunded: nobody had the block) instead of waiting.
    #[test]
    fn a_pull_nobody_has_is_dropped_and_refunded() {
        let t0 = Instant::now();
        let (a, b) = (PeerId::random(), PeerId::random());
        let mut s: PullScheduler<u64> = PullScheduler::new(HashSet::new());
        s.on_connect(a, true, t0);
        s.on_connect(b, true, t0);
        let hash = [3u8; 32];
        s.enqueue(SyncRequest::GetBlock { block_hash: hash }, None, &[], t0);
        let mut id = 0u64;
        for _ in 0..2 {
            let mut to = None;
            s.drain(t0, |p, _| {
                id += 1;
                to = Some(p);
                id
            });
            let p = to.expect("sent");
            s.on_response(id, p, &SyncResponse::BlockNotFound { block_hash: hash }, t0);
        }
        assert!(s.selector().penalty(&a, t0) > 0.0 || s.selector().penalty(&b, t0) > 0.0 || s.dropped() == 1);
        s.drain(t0, |_, _| unreachable!("nobody is left to ask"));
        assert_eq!(s.dropped(), 1);
        assert_eq!(s.pending_len(), 0);
        assert_eq!(s.selector().penalty(&a, t0), 0.0, "true NotFound refunded");
        assert_eq!(s.selector().penalty(&b, t0), 0.0);
        // The block may be pulled again later.
        assert_eq!(s.enqueue(SyncRequest::GetBlock { block_hash: hash }, None, &[], t0), Enqueued::Queued);
    }

    /// A disconnect sends the peer's in-flight pulls to the queue at once.
    #[test]
    fn disconnect_requeues_in_flight_pulls() {
        let t0 = Instant::now();
        let (a, b) = (PeerId::random(), PeerId::random());
        let mut s: PullScheduler<u64> = PullScheduler::new(HashSet::new());
        s.on_connect(a, true, t0);
        s.on_connect(b, true, t0);
        s.enqueue(SyncRequest::GetBlock { block_hash: [1; 32] }, None, &[a], t0);
        s.drain(t0, |p, _| {
            assert_eq!(p, a);
            7
        });
        s.on_disconnect(&a, t0);
        assert_eq!((s.in_flight_len(), s.pending_len()), (0, 1));
        // The transport's late failure report for it is ignored.
        s.on_failure(7, a, FailureKind::Closed, t0);
        assert_eq!(s.pending_len(), 1);
        let mut to = None;
        s.drain(t0, |p, _| {
            to = Some(p);
            8
        });
        assert_eq!(to, Some(b));
    }
}
