//! Per-peer chain-state table for the drop-in Kaspa sync-negotiation layer.
//!
//! Announced hints (`announced_blue_score` / `announced_height`) are UNTRUSTED
//! wire data and never gate the IBD latch; `advertised_tips` drive frontier
//! reconciliation; verified `blue_work` is resolved on demand against the local
//! DAG (see [`PeerStateTable::servable_blue_work`]).

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// NET-6 (audit): an announced tip claim stops counting this long after the
/// peer last made it. Claims used to be a monotonic max that lived as long as
/// the connection, so one inflated frame pinned `best_announced` forever.
pub const CLAIM_TTL: Duration = Duration::from_secs(600);

use libp2p::PeerId;
use parking_lot::RwLock;

/// Per-peer chain-state. `announced_*` are UNTRUSTED wire hints (never gate the
/// latch); `advertised_tips` drive frontier reconciliation; verified blue_work is
/// resolved on demand against the local DAG (see `servable_blue_work`).
#[derive(Clone, Debug)]
pub struct PeerChainState {
    pub announced_blue_score: u64,
    pub announced_height:     u64,
    pub advertised_tips:      Vec<[u8; 32]>,
    pub last_seen:            Instant,
    pub connected:            bool,
    /// When the peer last made a tip claim (`None` = never). Claims older
    /// than [`CLAIM_TTL`] are ignored by [`PeerStateTable::best_announced_blue_score`].
    pub claimed_at:           Option<Instant>,
}

/// Thread-safe `PeerId -> PeerChainState` table + servable-frontier query.
/// Shared as `Arc<PeerStateTable>`. Locking is internal (single `RwLock`).
pub struct PeerStateTable {
    inner: RwLock<HashMap<PeerId, PeerChainState>>,
    /// Per-node secret keys ordering [`Self::claiming_above`] (B1-T6
    /// review: ties used to be broken by PeerId bytes, which anyone can grind).
    hint_order: std::collections::hash_map::RandomState,
}

impl PeerStateTable {
    pub fn new() -> Self {
        Self { inner: RwLock::new(HashMap::new()), hint_order: std::collections::hash_map::RandomState::new() }
    }

    /// P4: on `SwarmEvent::ConnectionEstablished`.
    pub fn on_connect(&self, peer: PeerId, now: Instant) {
        let mut g = self.inner.write();
        let e = g.entry(peer).or_insert_with(|| PeerChainState {
            announced_blue_score: 0,
            announced_height: 0,
            advertised_tips: Vec::new(),
            last_seen: now,
            connected: true,
            claimed_at: None,
        });
        e.connected = true;
        e.last_seen = now;
    }

    /// P4: on `SwarmEvent::ConnectionClosed`.
    ///
    /// M-3 (audit): this used to RETAIN the row (only flip `connected =
    /// false`), so the table grew by one entry per distinct `PeerId` ever
    /// seen and NEVER shrank. A libp2p identity is a freshly generated
    /// keypair — free to an attacker — so "connect, send one `Tips` frame
    /// (up to `MAX_ADVERTISED_TIPS` = 256 hashes, ~8 KB), disconnect, repeat
    /// with a new identity" grew this table without bound (unlike
    /// `WirePenaltyTracker`, which the same module comparison in the audit
    /// notes was explicitly capped for exactly this threat and this map was
    /// not).
    ///
    /// INVARIANT (M-3): a disconnected peer contributes NOTHING to this
    /// table's steady-state size. The state kept here is a cache serving
    /// `servable_blue_work` / `best_announced_blue_score` /
    /// `connected_advertised_tips`, all of which already filter on
    /// `connected` — dropping the row outright removes no behavior a
    /// currently-connected-peer query could observe, and a peer that
    /// reconnects re-announces its tips/blue_score immediately via
    /// `observe`/`on_connect`, which reinserts a fresh row. Table size is
    /// therefore bounded by however many connections libp2p's own
    /// connection-limits behaviour (`max_established_incoming`, wired in
    /// `network::mod::run`) currently allows, not by every identity ever seen.
    pub fn on_disconnect(&self, peer: &PeerId) {
        self.inner.write().remove(peer);
    }

    /// P4: on decode of `Tips` / `PeerTip` / `Version`. For `PeerTip`/`Version`
    /// pass `tips = &[]` (they carry no tip hashes); for `Tips` pass the entry
    /// hashes. Updates hints + `last_seen` and (re)marks the peer connected.
    ///
    /// NET-6 (audit): the hints are the peer's LATEST claim, not a monotonic
    /// max — a peer that once announced an inflated score no longer keeps it
    /// forever; it is replaced by the next claim and expires after
    /// [`CLAIM_TTL`]. Callers must pass the claim's AUTHOR (the peer that made
    /// it), never the relay it arrived through.
    pub fn observe(
        &self,
        peer: PeerId,
        announced_blue_score: u64,
        announced_height: u64,
        tips: &[[u8; 32]],
        now: Instant,
    ) {
        let mut g = self.inner.write();
        let e = g.entry(peer).or_insert_with(|| PeerChainState {
            announced_blue_score: 0,
            announced_height: 0,
            advertised_tips: Vec::new(),
            last_seen: now,
            connected: true,
            claimed_at: None,
        });
        e.connected = true;
        e.last_seen = now;
        e.announced_blue_score = announced_blue_score;
        e.announced_height = announced_height;
        e.claimed_at = Some(now);
        if !tips.is_empty() {
            e.advertised_tips = tips.to_vec();
            e.advertised_tips.truncate(crate::sync::MAX_ADVERTISED_TIPS);
        }
    }

    /// NET-6 (audit): record a gossip tip claim (`PeerTip` / `Version`) made
    /// by `author` — ONLY if `author` is a currently connected peer (it has a
    /// row from [`Self::on_connect`]). Claims by authors we are not connected
    /// to (relayed through someone else) are never stored: the table cannot be
    /// grown by minted identities, and a relay is never charged for a claim it
    /// merely forwarded. Returns `true` if the claim was recorded.
    pub fn observe_claim(
        &self,
        author: PeerId,
        announced_blue_score: u64,
        announced_height: u64,
        now: Instant,
    ) -> bool {
        let mut g = self.inner.write();
        match g.get_mut(&author) {
            Some(e) if e.connected => {
                e.last_seen = now;
                e.announced_blue_score = announced_blue_score;
                e.announced_height = announced_height;
                e.claimed_at = Some(now);
                true
            }
            _ => false,
        }
    }

    /// Union (deduped) of advertised tips over CONNECTED peers. P5 feeds this to
    /// `frontier::reconciled` and `frontier::to_request`.
    pub fn connected_advertised_tips(&self) -> Vec<[u8; 32]> {
        let g = self.inner.read();
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for s in g.values().filter(|s| s.connected) {
            for h in &s.advertised_tips {
                if seen.insert(*h) {
                    out.push(*h);
                }
            }
        }
        out
    }

    /// Servable frontier: the greatest LOCALLY-VERIFIED blue_work reachable from
    /// a connected peer. `resolve(tip)` returns the tip's blue_work IFF it is in
    /// our DAG (P5 passes `|h| dag.get_node(h).map(|n| n.blue_work)`), else None.
    /// Tips we cannot verify contribute 0 — announced work is never trusted.
    pub fn servable_blue_work<F: Fn(&[u8; 32]) -> Option<u128>>(&self, resolve: F) -> u128 {
        let g = self.inner.read();
        let mut best = 0u128;
        for s in g.values().filter(|s| s.connected) {
            for h in &s.advertised_tips {
                if let Some(w) = resolve(h) {
                    best = best.max(w);
                }
            }
        }
        best
    }

    /// Highest FRESH announced blue_score among connected peers (claims made
    /// within [`CLAIM_TTL`]) — a hint used only to RELEASE the IBD latch
    /// early (never to set it), and for RPC.
    pub fn best_announced_blue_score(&self) -> u64 {
        self.best_announced_blue_score_at(Instant::now())
    }

    /// [`Self::best_announced_blue_score`] with an explicit clock.
    pub fn best_announced_blue_score_at(&self, now: Instant) -> u64 {
        self.inner
            .read()
            .values()
            .filter(|s| s.connected)
            .filter(|s| s.claimed_at.is_some_and(|t| now.saturating_duration_since(t) < CLAIM_TTL))
            .map(|s| s.announced_blue_score)
            .max()
            .unwrap_or(0)
    }

    /// B1-T6: up to `max` connected peers whose fresh claim (within
    /// [`CLAIM_TTL`]) is above `score`: the peers a GetHeaders from `score`
    /// is best sent to. Claims are clamped, unverified announcements, so the
    /// size of a claim never ranks a peer (B1-T6 review: highest claim first
    /// and ties by PeerId bytes let a few ground identities that claim the
    /// clamp's maximum take every hint slot): the claimers are taken in an
    /// order keyed by a per-node secret. The pull scheduler then puts the
    /// peers we dialed first (`network::pull::PullScheduler::enqueue`).
    pub fn claiming_above(&self, score: u64, now: Instant, max: usize) -> Vec<PeerId> {
        use std::hash::BuildHasher;
        let g = self.inner.read();
        let mut v: Vec<(u64, PeerId)> = g
            .iter()
            .filter(|(_, s)| s.connected && s.announced_blue_score > score)
            .filter(|(_, s)| s.claimed_at.is_some_and(|t| now.saturating_duration_since(t) < CLAIM_TTL))
            .map(|(p, _)| (self.hint_order.hash_one(p.to_bytes()), *p))
            .collect();
        v.sort_unstable_by_key(|(k, _)| *k);
        v.into_iter().take(max).map(|(_, p)| p).collect()
    }

    pub fn connected_count(&self) -> usize {
        self.inner.read().values().filter(|s| s.connected).count()
    }

    /// Debug/RPC snapshot.
    pub fn snapshot(&self) -> Vec<(PeerId, PeerChainState)> {
        self.inner.read().iter().map(|(k, v)| (*k, v.clone())).collect()
    }
}

impl Default for PeerStateTable {
    fn default() -> Self {
        Self::new()
    }
}
