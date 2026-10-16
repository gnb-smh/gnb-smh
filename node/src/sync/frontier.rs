use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// Give up fetching an advertised tip after this many timed-out re-requests and
/// mark it unreachable (`abandoned`). ~8 × TIP_REQUEST_TIMEOUT(30s) ≈ 4 min —
/// well past the 90s mine-through valve, so a tip that no reachable peer serves
/// (a fork we cannot reach, a partitioned holder, or a lying peer) stops
/// blocking `reconciled` instead of pinning the node in `is_syncing` forever.
pub const MAX_TIP_ATTEMPTS: u32 = 8;

/// Attempt-count jump applied on an EXPLICIT `BlockNotFound` (vs a silent
/// timeout, which adds 1). A tip a peer definitively cannot serve should be
/// abandoned in seconds, not after 4 min of timeouts: two NotFounds (2×4 past
/// the initial attempt of 1) cross `MAX_TIP_ATTEMPTS`. This is the H=3413
/// unstick — the orphan header chain whose bodies are gone network-wide gets
/// abandoned promptly so `maybe_release_ibd` can release `is_syncing`.
pub const NOT_FOUND_PENALTY: u32 = 4;

/// NET-10 (audit): global bound on tips simultaneously in flight. Each one is
/// a GetBlock we issued; 2,000 unsolicited Tips frames used to create 512,000
/// entries and as many pulls. Honest frontiers are a handful of tips wide.
pub const MAX_FRONTIER_IN_FLIGHT: usize = 512;
/// NET-10: bound on the abandoned set (oldest entries are forgotten first).
pub const MAX_FRONTIER_ABANDONED: usize = 4096;
/// NET-10: an abandoned tip is forgotten after this long, so the set cannot
/// grow with stale entries and a long-gone phantom stops influencing release.
pub const ABANDONED_TTL: Duration = Duration::from_secs(3600);
/// NET-10: max new tips taken from ONE Tips response (per-peer bound).
pub const MAX_NEW_TIPS_PER_RESPONSE: usize = 64;

/// Pure: tips we should advertise, bounded to MAX_ADVERTISED_TIPS. Input is
/// `consensus::GhostDAG::tips()`. Deterministic order (sorted) for testability.
pub fn advertise_tips(dag_tips: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut t = dag_tips.to_vec();
    t.sort_unstable();
    t.truncate(crate::sync::MAX_ADVERTISED_TIPS);
    t
}

/// Pure: which advertised tips we lack. `has_block` is the DAG membership oracle
/// (`consensus::GhostDAG::has_block`). Result is deduped, order-preserving.
pub fn diff_missing<F: Fn(&[u8; 32]) -> bool>(
    advertised: &[[u8; 32]],
    has_block: F,
) -> Vec<[u8; 32]> {
    let mut seen = std::collections::HashSet::new();
    advertised
        .iter()
        .filter(|h| !has_block(h) && seen.insert(**h))
        .copied()
        .collect()
}

/// Pure sync-completion predicate. True iff every advertised tip is either
/// present (`has_block`) OR abandoned-as-unreachable (`is_abandoned`), and
/// nothing is in flight. An abandoned tip counts as "resolved" so a single
/// unreachable/phantom tip cannot pin the node in IBD forever — the blue_work
/// gate in maybe_release_ibd still guarantees we only release once our own
/// selected chain is at least the best VERIFIED reachable work.
pub fn reconciled<F: Fn(&[u8; 32]) -> bool, G: Fn(&[u8; 32]) -> bool>(
    advertised: &[[u8; 32]],
    has_block: F,
    outstanding: usize,
    is_abandoned: G,
) -> bool {
    outstanding == 0 && advertised.iter().all(|h| has_block(h) || is_abandoned(h))
}

/// In-flight tip-request tracker. Shared as Arc<Mutex<FrontierState>>.
#[derive(Default)]
pub struct FrontierState {
    /// tip hash -> (time we last (re)requested it via GetBlock, attempt count).
    /// Bounded by [`MAX_FRONTIER_IN_FLIGHT`].
    in_flight: HashMap<[u8; 32], (Instant, u32)>,
    /// tips given up on after MAX_TIP_ATTEMPTS timed-out re-requests. They no
    /// longer count as outstanding and `reconciled` treats them as resolved.
    /// A tip leaves this set the instant its block actually arrives
    /// (`note_received`), so a fork that later becomes reachable heals.
    /// Value = when it was abandoned. Bounded by [`MAX_FRONTIER_ABANDONED`]
    /// and [`ABANDONED_TTL`].
    abandoned: HashMap<[u8; 32], Instant>,
    /// NET-9: distinct peers that answered NotFound for an in-flight tip. A
    /// single peer repeating NotFound counts once, so one peer can no longer
    /// abandon a tip on its own.
    not_found_by: HashMap<[u8; 32], HashSet<libp2p::PeerId>>,
    /// NET-6: highest claimed height among buffered, work-backed orphans
    /// (`ingress::orphan_is_sync_evidence`). Set by the message processor;
    /// read by the IBD release gate. `None` = no evidence pending.
    orphan_evidence: Option<u64>,
}

impl FrontierState {
    pub fn new() -> Self {
        Self::default()
    }

    /// NET-6: record the highest claimed height among pending work-backed
    /// orphans (`None` when there are none).
    pub fn set_orphan_evidence(&mut self, height: Option<u64>) {
        self.orphan_evidence = height;
    }

    /// NET-6: see [`Self::set_orphan_evidence`].
    pub fn orphan_evidence_height(&self) -> Option<u64> {
        self.orphan_evidence
    }

    /// Abandoned tips currently remembered (observability / tests).
    pub fn abandoned_len(&self) -> usize {
        self.abandoned.len()
    }

    fn abandon(&mut self, h: [u8; 32], now: Instant) {
        self.in_flight.remove(&h);
        self.not_found_by.remove(&h);
        self.abandoned.insert(h, now);
        self.prune_abandoned(now);
    }

    /// NET-10: drop abandoned entries older than [`ABANDONED_TTL`] and, if
    /// still over [`MAX_FRONTIER_ABANDONED`], the oldest ones.
    pub fn prune_abandoned(&mut self, now: Instant) {
        self.abandoned.retain(|_, t| now.saturating_duration_since(*t) < ABANDONED_TTL);
        if self.abandoned.len() > MAX_FRONTIER_ABANDONED {
            let mut v: Vec<([u8; 32], Instant)> = self.abandoned.iter().map(|(h, t)| (*h, *t)).collect();
            v.sort_by_key(|(_, t)| *t);
            let excess = v.len() - MAX_FRONTIER_ABANDONED;
            for (h, _) in v.into_iter().take(excess) {
                self.abandoned.remove(&h);
            }
        }
    }

    /// In-flight tip GetBlocks awaiting delivery (excludes abandoned). Gates IBD.
    pub fn outstanding(&self) -> usize {
        self.in_flight.len()
    }

    /// True if we gave up fetching this tip (declared it unreachable).
    pub fn is_abandoned(&self, hash: &[u8; 32]) -> bool {
        self.abandoned.contains_key(hash)
    }

    /// Newly-missing tips to GetBlock: diff_missing MINUS in-flight MINUS
    /// abandoned; records returned ones as in-flight at `now`.
    pub fn to_request<F: Fn(&[u8; 32]) -> bool>(
        &mut self,
        advertised: &[[u8; 32]],
        has_block: F,
        now: Instant,
    ) -> Vec<[u8; 32]> {
        self.to_request_capped(advertised, has_block, now, usize::MAX)
    }

    /// NET-10: [`Self::to_request`] taking at most `max_new` new tips, and
    /// never letting the in-flight set exceed [`MAX_FRONTIER_IN_FLIGHT`].
    pub fn to_request_capped<F: Fn(&[u8; 32]) -> bool>(
        &mut self,
        advertised: &[[u8; 32]],
        has_block: F,
        now: Instant,
        max_new: usize,
    ) -> Vec<[u8; 32]> {
        let missing = diff_missing(advertised, has_block);
        let mut out = Vec::new();
        for h in missing {
            if out.len() >= max_new || self.in_flight.len() >= MAX_FRONTIER_IN_FLIGHT {
                break;
            }
            if !self.in_flight.contains_key(&h) && !self.abandoned.contains_key(&h) {
                self.in_flight.insert(h, (now, 1));
                out.push(h);
            }
        }
        out
    }

    /// Clear a tip once its block is accepted. Also un-abandons it so a fork tip
    /// that finally arrives heals. No-op if neither in flight nor abandoned.
    pub fn note_received(&mut self, hash: &[u8; 32]) {
        self.in_flight.remove(hash);
        self.abandoned.remove(hash);
        self.not_found_by.remove(hash);
    }

    /// A peer answered GetBlock with an explicit `BlockNotFound` — a DEFINITIVE
    /// "I don't hold this body" (pruned/unknown), unlike a silent timeout. Count
    /// it toward abandonment AGGRESSIVELY: an unreachable tip that peers NotFound
    /// must not pin the node in IBD for 8×30s of timeouts (which was the H=3413
    /// symptom — the orphan header chain's bodies are gone network-wide, every
    /// peer NotFounds them, yet the node kept `is_syncing=true` forever). Adds
    /// `NOT_FOUND_PENALTY` to the attempt count; at `MAX_TIP_ATTEMPTS` the tip is
    /// abandoned (treated as resolved by `reconciled`, releasing IBD). No-op for
    /// a hash we are not currently chasing.
    pub fn note_not_found(&mut self, hash: &[u8; 32], now: Instant) {
        let attempts = match self.in_flight.get(hash) {
            Some((_, a)) => a.saturating_add(NOT_FOUND_PENALTY),
            None => return,
        };
        if attempts >= MAX_TIP_ATTEMPTS {
            self.abandon(*hash, now);
        } else {
            self.in_flight.insert(*hash, (now, attempts));
        }
    }

    /// NET-9 (audit): [`Self::note_not_found`] attributed to the answering
    /// `peer`. Only the FIRST NotFound from each distinct peer counts, so a
    /// single (possibly malicious) peer can no longer abandon a tip by itself
    /// — abandonment via NotFound now needs two different peers to say so
    /// (or the ordinary timeout path). Returns `true` if the NotFound counted.
    pub fn note_not_found_from(&mut self, hash: &[u8; 32], peer: libp2p::PeerId, now: Instant) -> bool {
        if !self.in_flight.contains_key(hash) {
            return false;
        }
        let reporters = self.not_found_by.entry(*hash).or_default();
        if !reporters.insert(peer) {
            return false;
        }
        self.note_not_found(hash, now);
        true
    }

    /// Timed-out in-flight tips for re-request. Each increments its attempt
    /// count; at MAX_TIP_ATTEMPTS it is moved to `abandoned` (dropped from
    /// in-flight, NOT returned). Otherwise its timestamp refreshes and it is
    /// returned so P5 re-sends GetBlock.
    pub fn expired(&mut self, timeout: Duration, now: Instant) -> Vec<[u8; 32]> {
        let stale: Vec<[u8; 32]> = self
            .in_flight
            .iter()
            .filter(|(_, (t, _))| now.duration_since(*t) >= timeout)
            .map(|(h, _)| *h)
            .collect();
        let mut retry = Vec::new();
        for h in stale {
            let attempts = self.in_flight.get(&h).map(|(_, a)| *a).unwrap_or(0).saturating_add(1);
            if attempts >= MAX_TIP_ATTEMPTS {
                self.abandon(h, now);
            } else {
                self.in_flight.insert(h, (now, attempts));
                retry.push(h);
            }
        }
        retry
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hh(i: u32) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[..4].copy_from_slice(&i.to_le_bytes());
        b
    }

    /// NET-10 regression: thousands of 256-tip frames cannot grow the
    /// in-flight set (or the GetBlocks it issues) past the global cap.
    #[test]
    fn in_flight_is_globally_bounded() {
        let mut fr = FrontierState::new();
        let now = Instant::now();
        let mut issued = 0usize;
        for frame in 0u32..2000 {
            let tips: Vec<[u8; 32]> = (0u32..256).map(|i| hh(frame * 256 + i)).collect();
            issued += fr.to_request(&tips, |_| false, now).len();
        }
        assert_eq!(fr.outstanding(), MAX_FRONTIER_IN_FLIGHT);
        assert_eq!(issued, MAX_FRONTIER_IN_FLIGHT);
    }

    #[test]
    fn per_response_cap_is_honoured() {
        let mut fr = FrontierState::new();
        let tips: Vec<[u8; 32]> = (0u32..256).map(hh).collect();
        let got = fr.to_request_capped(&tips, |_| false, Instant::now(), MAX_NEW_TIPS_PER_RESPONSE);
        assert_eq!(got.len(), MAX_NEW_TIPS_PER_RESPONSE);
    }

    /// NET-9 regression: one peer repeating NotFound cannot abandon a tip;
    /// two distinct peers can.
    #[test]
    fn not_found_needs_distinct_peers() {
        let mut fr = FrontierState::new();
        let now = Instant::now();
        let tip = hh(7);
        fr.to_request(&[tip], |_| false, now);
        let liar = libp2p::PeerId::random();
        for _ in 0..10 {
            fr.note_not_found_from(&tip, liar, now);
        }
        assert!(!fr.is_abandoned(&tip), "a single peer must not abandon a tip");
        assert_eq!(fr.outstanding(), 1);
        assert!(fr.note_not_found_from(&tip, libp2p::PeerId::random(), now));
        assert!(fr.is_abandoned(&tip), "two distinct NotFounds abandon it");
    }

    /// NET-10 regression: the abandoned set is bounded and expires.
    #[test]
    fn abandoned_set_is_bounded_and_expires() {
        let mut fr = FrontierState::new();
        let t0 = Instant::now();
        for i in 0..(MAX_FRONTIER_ABANDONED as u32 + 100) {
            fr.abandon(hh(i), t0 + Duration::from_millis(u64::from(i)));
        }
        assert_eq!(fr.abandoned_len(), MAX_FRONTIER_ABANDONED);
        fr.prune_abandoned(t0 + ABANDONED_TTL + Duration::from_secs(3600));
        assert_eq!(fr.abandoned_len(), 0);
    }
}
