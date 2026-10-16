//! B1-T9 / NET-11 (a)-(d): connection management — Bitcoin Core's `CConnman`
//! slot accounting, inbound eviction, feelers and anchors, for libp2p.
//!
//! * **Outbound slots are separate from inbound** (B1-T9). The node keeps
//!   [`OUTBOUND_FULL_RELAY_TARGET`] full-relay and [`BLOCK_RELAY_ONLY_TARGET`]
//!   block-relay-only outbound connections (Core: 8 + 2) and dials from its
//!   address tables whenever it is below them, whatever the inbound count.
//!   Inbound connections take at most `max_peers` slots of their own, so an
//!   attacker opening inbound connections can neither stop outbound dialing
//!   nor consume outbound slots. Configured `--peer` / `--dns-seed`
//!   connections are "manual" (Core's `-addnode`): they never count against
//!   the automatic slots.
//! * **Outbound netgroup diversity**: at most one automatic outbound
//!   (full-relay or block-relay-only) peer per netgroup (Core's
//!   `setConnected` rule in `ThreadOpenConnections`).
//! * **Inbound eviction** (NET-11 a): when a new inbound connection finds the
//!   inbound slots full, an existing inbound peer is evicted by
//!   [`select_node_to_evict`] (Core's `SelectNodeToEvict`): peers in a few
//!   keyed netgroups, the lowest-latency peers, the peers that most recently
//!   delivered novel transactions and blocks, and the longest-connected half
//!   of the rest are protected; the youngest peer of the most represented
//!   netgroup is evicted. With nobody evictable the newcomer is refused.
//! * **Feelers** (NET-11 c): once the outbound slots are full, a short-lived
//!   connection tests one address roughly every [`FEELER_INTERVAL`]
//!   (exponentially distributed, Core's `FEELER_INTERVAL`): a queued tried
//!   collision first (test-before-evict), else an address from the new
//!   table, which moves to the tried table on success. Feelers carry no
//!   gossip and none of our requests, and are closed after
//!   [`FEELER_LINGER`].
//! * **Block-relay-only connections and anchors** (NET-11 b/d): see
//!   `network::gossip_gate` for how such a connection carries no gossip, and
//!   [`read_anchors`] / [`write_anchors`] for Core's `anchors.dat`.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

use libp2p::swarm::ConnectionId;
use libp2p::{Multiaddr, PeerId};
use log::warn;

use super::addrbook::{keyed_u64, AddrKey};
use super::pex_validator::{is_valid_public_multiaddr, netgroup_of};

/// Core's `MAX_OUTBOUND_FULL_RELAY_CONNECTIONS`.
pub const OUTBOUND_FULL_RELAY_TARGET: usize = 8;
/// Core's `MAX_BLOCK_RELAY_ONLY_CONNECTIONS`.
pub const BLOCK_RELAY_ONLY_TARGET: usize = 2;
/// Core's `MAX_BLOCK_RELAY_ONLY_ANCHORS`.
pub const MAX_ANCHORS: usize = 2;
/// Core's `FEELER_INTERVAL` (the mean of the exponential delay).
pub const FEELER_INTERVAL: Duration = Duration::from_secs(120);
/// How long an established feeler connection stays open before it is closed
/// (Core closes a feeler once the version handshake is done; closing the
/// instant our side is established cuts the remote's connection setup short).
pub const FEELER_LINGER: Duration = Duration::from_secs(1);
/// How often the frontier of each block-relay-only peer is polled with a
/// directed `GetTips` (blocks reach us over such a connection this way: it
/// carries no gossip).
pub const BLOCK_RELAY_POLL_INTERVAL: Duration = Duration::from_secs(30);
/// Name of the anchors file in the data directory (Core's `anchors.dat`).
pub const ANCHORS_FILE: &str = "anchors.json";
/// Connection headroom above `max_peers` (inbound) for every outbound kind
/// (8 full-relay + 2 block-relay-only + 1 feeler + manual peers), so the
/// swarm-wide connection cap can never be reached by inbound connections.
pub const OUTBOUND_CONNECTION_HEADROOM: usize = 32;

/// Core's eviction protection sizes (`SelectNodeToEvict`).
pub const EVICT_PROTECT_NETGROUP: usize = 4;
pub const EVICT_PROTECT_PING: usize = 8;
pub const EVICT_PROTECT_TX: usize = 4;
pub const EVICT_PROTECT_BLOCK: usize = 4;

/// What a connection is for (Core's `ConnectionType`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConnKind {
    Inbound,
    /// Automatic outbound connection that relays everything.
    OutboundFullRelay,
    /// Automatic outbound connection that relays blocks only: no gossip at
    /// all (no transactions, no addresses), blocks by directed pulls.
    BlockRelayOnly,
    /// Short-lived outbound test of an address; closed after `FEELER_LINGER`.
    Feeler,
    /// Operator-configured (`--peer`, `--dns-seed`), mDNS, or not dialed by
    /// the connection manager. Not counted against the automatic slots.
    Manual,
}

impl ConnKind {
    pub fn is_outbound(self) -> bool {
        !matches!(self, ConnKind::Inbound)
    }

    /// We ask this peer for addresses (Core sends `getaddr` to outbound
    /// full-relay and manual peers only).
    pub fn sends_getaddr(self) -> bool {
        matches!(self, ConnKind::OutboundFullRelay | ConnKind::Manual)
    }

    /// We answer this peer's address requests (Core answers `getaddr` only
    /// from INBOUND peers: an outbound peer asking us is a fingerprinting
    /// probe — it could plant addresses in our table and ask for them back).
    pub fn answers_getaddr(self) -> bool {
        matches!(self, ConnKind::Inbound)
    }

    /// Strength of a role when a peer has several connections.
    fn rank(self) -> u8 {
        match self {
            ConnKind::Feeler => 0,
            ConnKind::Inbound => 1,
            ConnKind::BlockRelayOnly => 2,
            ConnKind::OutboundFullRelay => 3,
            ConnKind::Manual => 4,
        }
    }
}

/// Why a dial was made: recorded before dialing, keyed by the dial's
/// connection id, so the established connection gets its kind.
#[derive(Clone, Debug)]
pub struct DialIntent {
    pub kind: ConnKind,
    /// The table address dialed (canonical `/…/p2p/<id>` form), if any.
    pub addr: Option<String>,
    /// The peer id dialed, if known.
    pub peer: Option<PeerId>,
    /// Netgroup of the dialed address (outbound diversity).
    pub group: Option<String>,
    /// For a feeler that tests a tried-table collision: the newcomer waiting
    /// for the occupant `addr`'s test.
    pub collision_newcomer: Option<String>,
}

impl DialIntent {
    pub fn manual() -> Self {
        Self { kind: ConnKind::Manual, addr: None, peer: None, group: None, collision_newcomer: None }
    }
}

/// One connected peer.
#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub role: ConnKind,
    pub connected_at: Instant,
    pub netgroup: String,
    /// The table address we dialed (outbound), for anchors.
    pub dialed_addr: Option<String>,
    pub min_ping: Option<Duration>,
    pub last_block: Option<Instant>,
    pub last_tx: Option<Instant>,
    pub getaddr_answered: bool,
    conns: Vec<(ConnectionId, ConnKind)>,
}

/// What [`ConnManager::on_established`] learned about a new connection.
#[derive(Clone, Debug)]
pub struct Established {
    pub kind: ConnKind,
    /// The peer was not connected before (its first non-feeler connection).
    pub new_peer: bool,
    pub intent: Option<DialIntent>,
}

/// What [`ConnManager::on_closed`] learned about a closed connection.
#[derive(Clone, Debug)]
pub struct Closed {
    pub kind: Option<ConnKind>,
    /// The peer's last (non-feeler) connection closed.
    pub peer_gone: Option<PeerInfo>,
}

/// Connection bookkeeping of the network loop.
pub struct ConnManager {
    key: AddrKey,
    max_inbound: usize,
    full_target: usize,
    block_relay_target: usize,
    pending: HashMap<ConnectionId, DialIntent>,
    conns: HashMap<ConnectionId, (PeerId, ConnKind, bool)>,
    peers: HashMap<PeerId, PeerInfo>,
}

impl ConnManager {
    /// `max_inbound` = `--max-peers` (inbound slots).
    pub fn new(key: AddrKey, max_inbound: usize) -> Self {
        Self {
            key,
            max_inbound,
            full_target: OUTBOUND_FULL_RELAY_TARGET,
            block_relay_target: BLOCK_RELAY_ONLY_TARGET,
            pending: HashMap::new(),
            conns: HashMap::new(),
            peers: HashMap::new(),
        }
    }

    /// Override the automatic outbound targets (tests).
    pub fn set_targets(&mut self, full_relay: usize, block_relay_only: usize) {
        self.full_target = full_relay;
        self.block_relay_target = block_relay_only;
    }

    pub fn max_inbound(&self) -> usize {
        self.max_inbound
    }

    pub fn full_relay_target(&self) -> usize {
        self.full_target
    }

    pub fn block_relay_target(&self) -> usize {
        self.block_relay_target
    }

    /// Record a dial about to be made.
    pub fn register_dial(&mut self, conn: ConnectionId, intent: DialIntent) {
        self.pending.insert(conn, intent);
    }

    /// A dial failed (or was refused before connecting).
    pub fn on_dial_failed(&mut self, conn: ConnectionId) -> Option<DialIntent> {
        self.pending.remove(&conn)
    }

    /// A connection was established. `dialer`: we dialed it.
    pub fn on_established(
        &mut self,
        conn: ConnectionId,
        peer: PeerId,
        dialer: bool,
        remote: &Multiaddr,
        now: Instant,
    ) -> Established {
        let intent = if dialer { self.pending.remove(&conn) } else { None };
        let kind = if dialer { intent.as_ref().map(|i| i.kind).unwrap_or(ConnKind::Manual) } else { ConnKind::Inbound };
        self.conns.insert(conn, (peer, kind, !dialer));
        if kind == ConnKind::Feeler {
            return Established { kind, new_peer: false, intent };
        }
        let group = netgroup_of(remote).unwrap_or_else(|| "?".into());
        let mut new_peer = false;
        let info = self.peers.entry(peer).or_insert_with(|| {
            new_peer = true;
            PeerInfo {
                role: kind,
                connected_at: now,
                netgroup: group,
                dialed_addr: None,
                min_ping: None,
                last_block: None,
                last_tx: None,
                getaddr_answered: false,
                conns: Vec::new(),
            }
        });
        info.conns.push((conn, kind));
        if kind.rank() > info.role.rank() || new_peer {
            info.role = kind;
            if let Some(a) = intent.as_ref().and_then(|i| i.addr.clone()) {
                info.dialed_addr = Some(a);
            }
        }
        Established { kind, new_peer, intent }
    }

    /// A connection closed.
    pub fn on_closed(&mut self, conn: ConnectionId, peer: PeerId) -> Closed {
        let kind = self.conns.remove(&conn).map(|(_, k, _)| k);
        let mut gone = None;
        if let Some(info) = self.peers.get_mut(&peer) {
            info.conns.retain(|(c, _)| *c != conn);
            if info.conns.is_empty() {
                gone = self.peers.remove(&peer);
            } else if let Some(best) = info.conns.iter().map(|(_, k)| *k).max_by_key(|k| k.rank()) {
                info.role = best;
            }
        }
        Closed { kind, peer_gone: gone }
    }

    /// The kind of a live connection.
    pub fn conn_kind(&self, conn: &ConnectionId) -> Option<ConnKind> {
        self.conns.get(conn).map(|(_, k, _)| *k)
    }

    /// The role of a connected peer.
    pub fn role(&self, peer: &PeerId) -> Option<ConnKind> {
        self.peers.get(peer).map(|i| i.role)
    }

    pub fn peer(&self, peer: &PeerId) -> Option<&PeerInfo> {
        self.peers.get(peer)
    }

    /// Distinct connected peers (feeler-only peers excluded).
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Peers whose role is `kind`.
    pub fn count(&self, kind: ConnKind) -> usize {
        self.peers.values().filter(|i| i.role == kind).count()
    }

    /// Dials of `kind` still pending.
    pub fn pending_count(&self, kind: ConnKind) -> usize {
        self.pending.values().filter(|i| i.kind == kind).count()
    }

    /// Whether a dial to `peer` is pending.
    pub fn is_dialing(&self, peer: &PeerId) -> bool {
        self.pending.values().any(|i| i.peer.as_ref() == Some(peer))
    }

    /// Inbound CONNECTIONS (what libp2p's incoming limit counts).
    pub fn inbound_connections(&self) -> usize {
        self.conns.values().filter(|(_, _, inbound)| *inbound).count()
    }

    /// Whether the inbound slots are over-full (an eviction is due).
    pub fn inbound_over_capacity(&self) -> bool {
        self.inbound_connections() > self.max_inbound
    }

    /// Netgroups of the automatic outbound peers and pending automatic dials:
    /// a new automatic outbound dial must be outside all of them.
    pub fn outbound_groups(&self) -> std::collections::HashSet<String> {
        let mut g: std::collections::HashSet<String> = self
            .peers
            .values()
            .filter(|i| matches!(i.role, ConnKind::OutboundFullRelay | ConnKind::BlockRelayOnly))
            .map(|i| i.netgroup.clone())
            .collect();
        for i in self.pending.values() {
            if matches!(i.kind, ConnKind::OutboundFullRelay | ConnKind::BlockRelayOnly) {
                if let Some(gr) = &i.group {
                    g.insert(gr.clone());
                }
            }
        }
        g
    }

    /// Full-relay outbound peers, established + pending.
    pub fn full_relay_slots_used(&self) -> usize {
        self.count(ConnKind::OutboundFullRelay) + self.pending_count(ConnKind::OutboundFullRelay)
    }

    /// Block-relay-only outbound peers, established + pending.
    pub fn block_relay_slots_used(&self) -> usize {
        self.count(ConnKind::BlockRelayOnly) + self.pending_count(ConnKind::BlockRelayOnly)
    }

    /// The addresses of the block-relay-only peers: the anchors to persist.
    pub fn anchors(&self) -> Vec<String> {
        let mut v: Vec<(Instant, String)> = self
            .peers
            .values()
            .filter(|i| i.role == ConnKind::BlockRelayOnly)
            .filter_map(|i| i.dialed_addr.clone().map(|a| (i.connected_at, a)))
            .collect();
        v.sort();
        v.into_iter().map(|(_, a)| a).take(MAX_ANCHORS).collect()
    }

    /// Block-relay-only peers (for the frontier polls).
    pub fn block_relay_peers(&self) -> Vec<PeerId> {
        self.peers.iter().filter(|(_, i)| i.role == ConnKind::BlockRelayOnly).map(|(p, _)| *p).collect()
    }

    /// Whether to answer `peer`'s address request: inbound peers only, once
    /// per connection (Core's `m_getaddr_recvd`).
    pub fn take_getaddr_answer(&mut self, peer: &PeerId) -> bool {
        match self.peers.get_mut(peer) {
            Some(i) if i.role.answers_getaddr() && !i.getaddr_answered => {
                i.getaddr_answered = true;
                true
            }
            _ => false,
        }
    }

    pub fn on_ping(&mut self, peer: &PeerId, rtt: Duration) {
        if let Some(i) = self.peers.get_mut(peer) {
            i.min_ping = Some(i.min_ping.map_or(rtt, |m| m.min(rtt)));
        }
    }

    /// `peer` delivered a block we accepted (novel and valid).
    pub fn on_novel_block(&mut self, peer: &PeerId, now: Instant) {
        if let Some(i) = self.peers.get_mut(peer) {
            i.last_block = Some(now);
        }
    }

    /// `peer` delivered a transaction our mempool admitted.
    pub fn on_novel_tx(&mut self, peer: &PeerId, now: Instant) {
        if let Some(i) = self.peers.get_mut(peer) {
            i.last_tx = Some(now);
        }
    }

    /// Keyed netgroup value of a peer (Core's `nKeyedNetGroup`): the order of
    /// the netgroup protection is secret, so an attacker cannot pick a
    /// netgroup that will be protected.
    pub fn keyed_netgroup(&self, group: &str) -> u64 {
        keyed_u64(&self.key, b"evict-netgroup", &[group.as_bytes()])
    }

    /// The inbound peer to evict to make room for a new inbound connection
    /// from `newcomer` (never a candidate), or `None` if every inbound peer is
    /// protected (then the newcomer is refused).
    pub fn eviction_victim(&self, newcomer: &PeerId) -> Option<PeerId> {
        let candidates: Vec<EvictionCandidate<PeerId>> = self
            .peers
            .iter()
            .filter(|(p, i)| *p != newcomer && i.role == ConnKind::Inbound)
            .map(|(p, i)| EvictionCandidate {
                id: *p,
                connected_at: i.connected_at,
                min_ping: i.min_ping,
                last_block: i.last_block,
                last_tx: i.last_tx,
                keyed_netgroup: self.keyed_netgroup(&i.netgroup),
            })
            .collect();
        select_node_to_evict(candidates)
    }
}

// ── Inbound eviction (Core's SelectNodeToEvict) ──────────────────────────────

/// One inbound peer considered for eviction (Core's `NodeEvictionCandidate`).
#[derive(Clone, Debug)]
pub struct EvictionCandidate<Id> {
    pub id: Id,
    pub connected_at: Instant,
    /// Lowest ping round trip seen (`None`: never measured — worst).
    pub min_ping: Option<Duration>,
    /// Last novel block / transaction it delivered (`None`: never).
    pub last_block: Option<Instant>,
    pub last_tx: Option<Instant>,
    pub keyed_netgroup: u64,
}

/// Sort with `cmp` and drop (protect) the last `k` elements.
fn protect_last_k<T>(v: &mut Vec<T>, cmp: impl FnMut(&T, &T) -> Ordering, k: usize) {
    v.sort_by(cmp);
    let keep = v.len().saturating_sub(k);
    v.truncate(keep);
}

/// Bitcoin Core's `SelectNodeToEvict` (src/node/eviction.cpp), step by step:
///
/// 1. protect [`EVICT_PROTECT_NETGROUP`] peers with the highest KEYED
///    netgroup value (an attacker cannot know which netgroups win);
/// 2. protect the [`EVICT_PROTECT_PING`] lowest-latency peers;
/// 3. protect the [`EVICT_PROTECT_TX`] peers that most recently delivered a
///    novel transaction;
/// 4. protect the [`EVICT_PROTECT_BLOCK`] peers that most recently delivered
///    a novel block (ties in 3 and 4: the longer-connected peer wins);
/// 5. protect the longest-connected half of the rest;
/// 6. evict the most recently connected peer of the netgroup with the most
///    remaining peers (a tie goes to the group with the youngest member).
///
/// `None` when every candidate is protected. Core's extra categories for
/// block-relay-only inbound peers and for disadvantaged networks (Tor, I2P,
/// CJDNS) do not apply here and are left out.
pub fn select_node_to_evict<Id: Clone>(mut c: Vec<EvictionCandidate<Id>>) -> Option<Id> {
    let ping = |e: &EvictionCandidate<Id>| e.min_ping.unwrap_or(Duration::MAX);
    protect_last_k(&mut c, |a, b| a.keyed_netgroup.cmp(&b.keyed_netgroup), EVICT_PROTECT_NETGROUP);
    protect_last_k(&mut c, |a, b| ping(b).cmp(&ping(a)), EVICT_PROTECT_PING);
    protect_last_k(&mut c, |a, b| a.last_tx.cmp(&b.last_tx).then(b.connected_at.cmp(&a.connected_at)), EVICT_PROTECT_TX);
    protect_last_k(
        &mut c,
        |a, b| a.last_block.cmp(&b.last_block).then(b.connected_at.cmp(&a.connected_at)),
        EVICT_PROTECT_BLOCK,
    );
    let half = c.len() / 2;
    // Youngest first: the oldest half is at the end and protected.
    protect_last_k(&mut c, |a, b| b.connected_at.cmp(&a.connected_at), half);
    if c.is_empty() {
        return None;
    }
    // `c` is sorted youngest first, so a group's first member is its youngest.
    let mut groups: HashMap<u64, (usize, Instant, usize)> = HashMap::new(); // group -> (size, youngest time, index of youngest)
    let mut best: Option<(u64, usize, Instant)> = None;
    for (idx, n) in c.iter().enumerate() {
        let g = groups.entry(n.keyed_netgroup).or_insert((0, n.connected_at, idx));
        g.0 += 1;
        let (size, time) = (g.0, g.1);
        let better = match best {
            None => true,
            Some((_, bsize, btime)) => size > bsize || (size == bsize && time > btime),
        };
        if better {
            best = Some((n.keyed_netgroup, size, time));
        }
    }
    let (group, _, _) = best?;
    let idx = groups.get(&group)?.2;
    Some(c[idx].id.clone())
}

// ── Outbound decisions (Core's ThreadOpenConnections) ────────────────────────

/// The next automatic outbound connection to open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutboundAction {
    /// Re-dial a persisted anchor as block-relay-only.
    Anchor,
    FullRelay,
    BlockRelay,
    Feeler,
    Idle,
}

/// Core's order in `ThreadOpenConnections`: anchors first (while
/// block-relay-only slots are free), then full-relay slots, then
/// block-relay-only slots, then — only with every slot full — a feeler when
/// one is due. `feeler_due` is consulted (and so advances the feeler timer)
/// only in that last case. Inbound connections play no part (B1-T9).
pub fn next_outbound_action(
    full_used: usize,
    full_target: usize,
    block_relay_used: usize,
    block_relay_target: usize,
    have_anchor: bool,
    feeler_due: impl FnOnce() -> bool,
) -> OutboundAction {
    if have_anchor && block_relay_used < block_relay_target {
        OutboundAction::Anchor
    } else if full_used < full_target {
        OutboundAction::FullRelay
    } else if block_relay_used < block_relay_target {
        OutboundAction::BlockRelay
    } else if feeler_due() {
        OutboundAction::Feeler
    } else {
        OutboundAction::Idle
    }
}

/// An exponentially distributed delay with the given mean from a uniform
/// `u` in `[0, 1)` (Core's `GetExponentialRand`), capped at 20 means.
pub fn exponential_delay(mean: Duration, u: f64) -> Duration {
    let u = u.clamp(0.0, 1.0 - f64::EPSILON);
    mean.mul_f64((-(1.0 - u).ln()).min(20.0))
}

/// Feeler cadence: due at exponentially distributed intervals with mean
/// [`FEELER_INTERVAL`] (Core: `next_feeler = GetExponentialRand(now,
/// FEELER_INTERVAL)`), checked only when every outbound slot is full.
#[derive(Clone, Debug)]
pub struct FeelerSchedule {
    next: Instant,
    mean: Duration,
}

impl FeelerSchedule {
    pub fn new(now: Instant, mean: Duration, u: f64) -> Self {
        Self { next: now + exponential_delay(mean, u), mean }
    }

    pub fn next_due(&self) -> Instant {
        self.next
    }

    /// Whether a feeler is due at `now`; if so, schedules the next one after
    /// a fresh exponential delay drawn from `u`.
    pub fn poll(&mut self, now: Instant, u: f64) -> bool {
        if now < self.next {
            return false;
        }
        self.next = now + exponential_delay(self.mean, u);
        true
    }
}

// ── Anchors (Core's anchors.dat) ─────────────────────────────────────────────

/// Read the anchors persisted by the previous run and DELETE the file (Core:
/// anchors are used once per start-up; a node that keeps crashing does not
/// keep re-dialing the same anchors). Invalid entries are dropped; at most
/// [`MAX_ANCHORS`] are returned.
pub fn read_anchors(path: &Path, allow_private: bool) -> Vec<String> {
    let anchors: Vec<String> = std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    if path.exists() {
        if let Err(e) = std::fs::remove_file(path) {
            warn!("removing {} failed: {}", path.display(), e);
        }
    }
    let mut out: Vec<String> = Vec::new();
    for a in anchors {
        if is_valid_public_multiaddr(&a, allow_private) && !out.contains(&a) {
            out.push(a);
        }
        if out.len() == MAX_ANCHORS {
            break;
        }
    }
    out
}

/// Persist the current block-relay-only peers as anchors (atomically). The
/// network loop writes the file whenever that set changes; Core writes it at
/// shutdown only, which this node has no orderly hook for.
pub fn write_anchors(path: &Path, anchors: &[String]) {
    let list: Vec<&String> = anchors.iter().take(MAX_ANCHORS).collect();
    match serde_json::to_string(&list) {
        Ok(json) => {
            if let Err(e) = super::write_file_atomic(path, json.as_bytes(), false) {
                warn!("saving {} failed: {}", path.display(), e);
            }
        }
        Err(e) => warn!("encoding anchors failed: {}", e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::addrbook::random_key;

    fn cand(id: u32, age_secs: u64, group: u64, now: Instant) -> EvictionCandidate<u32> {
        EvictionCandidate {
            id,
            connected_at: now - Duration::from_secs(age_secs),
            min_ping: None,
            last_block: None,
            last_tx: None,
            keyed_netgroup: group,
        }
    }

    /// Core: with too few candidates every one is protected — nobody is
    /// evicted and the newcomer is refused.
    #[test]
    fn small_inbound_sets_are_fully_protected() {
        let now = Instant::now() + Duration::from_secs(1_000_000);
        for n in 0..=20u32 {
            let c: Vec<_> = (0..n).map(|i| cand(i, 1000 + i as u64, i as u64, now)).collect();
            assert_eq!(select_node_to_evict(c), None, "{n} candidates are all protected");
        }
        let c: Vec<_> = (0..21u32).map(|i| cand(i, 1000 + i as u64, i as u64, now)).collect();
        assert!(select_node_to_evict(c).is_some(), "21 candidates leave one evictable");
    }

    /// The victim comes from the most represented netgroup, and is its
    /// youngest member.
    #[test]
    fn evicts_the_youngest_of_the_largest_netgroup() {
        let now = Instant::now() + Duration::from_secs(1_000_000);
        // 20 honest peers in distinct groups, connected long ago.
        let mut c: Vec<_> = (0..20u32).map(|i| cand(i, 10_000 + i as u64, 1000 + i as u64, now)).collect();
        // 20 attacker peers in ONE group, connected recently.
        c.extend((100..120u32).map(|i| cand(i, 100 + (i - 100) as u64, 7, now)));
        let victim = select_node_to_evict(c).unwrap();
        assert!((100..120).contains(&victim), "the attacker netgroup is evicted from, got {victim}");
        assert_eq!(victim, 100, "its youngest member (connected 100 s ago)");
    }

    /// Low latency, novel transactions, novel blocks and long uptime each
    /// protect a peer that would otherwise be the victim.
    #[test]
    fn each_protection_category_shields_a_useful_peer() {
        let now = Instant::now() + Duration::from_secs(1_000_000);
        // 30 peers in one netgroup; peer 0 is the youngest, so it is the
        // victim when nothing protects it.
        let base = || -> Vec<EvictionCandidate<u32>> { (0..30u32).map(|i| cand(i, 10 + i as u64, 5, now)).collect() };
        assert_eq!(select_node_to_evict(base()), Some(0));

        let mut c = base();
        c[0].min_ping = Some(Duration::from_millis(5));
        for x in c.iter_mut().skip(1) {
            x.min_ping = Some(Duration::from_millis(200));
        }
        assert_ne!(select_node_to_evict(c), Some(0), "lowest ping protects");

        let mut c = base();
        c[0].last_tx = Some(now);
        assert_ne!(select_node_to_evict(c), Some(0), "a recent novel transaction protects");

        let mut c = base();
        c[0].last_block = Some(now);
        assert_ne!(select_node_to_evict(c), Some(0), "a recent novel block protects");

        // Uptime: the oldest peers survive whatever the attacker does.
        let c = base();
        let victim = select_node_to_evict(c).unwrap();
        assert!(victim < 15, "only the younger half can be evicted, got {victim}");
    }

    /// The netgroup protection order is keyed: two nodes protect different
    /// netgroups, so an attacker cannot choose a netgroup that is protected.
    #[test]
    fn netgroup_protection_is_keyed_per_node() {
        let groups: Vec<String> = (0..64u32).map(|i| format!("ip4:{}.{}", 20 + i, i)).collect();
        let top = |m: &ConnManager| {
            let mut v: Vec<(u64, &String)> = groups.iter().map(|g| (m.keyed_netgroup(g), g)).collect();
            v.sort();
            v.iter().rev().take(EVICT_PROTECT_NETGROUP).map(|(_, g)| (*g).clone()).collect::<Vec<_>>()
        };
        let (a, b) = (ConnManager::new(random_key(), 50), ConnManager::new(random_key(), 50));
        assert_ne!(top(&a), top(&b));
    }

    fn ip_addr(s: &str) -> Multiaddr {
        format!("/ip4/{s}/tcp/17110").parse().unwrap()
    }

    /// B1-T9 at the decision level: a full inbound side never stops outbound
    /// dialing, and inbound peers never use outbound slots.
    #[test]
    fn inbound_connections_never_consume_or_freeze_outbound_slots() {
        let now = Instant::now();
        let mut m = ConnManager::new(random_key(), 50);
        for i in 0..60u32 {
            let ip = format!("{}.{}.1.1", 20 + i / 200, i % 200);
            m.on_established(ConnectionId::new_unchecked(i as usize), PeerId::random(), false, &ip_addr(&ip), now);
        }
        assert_eq!(m.count(ConnKind::Inbound), 60);
        assert_eq!(m.full_relay_slots_used(), 0);
        let action = next_outbound_action(
            m.full_relay_slots_used(), m.full_relay_target(),
            m.block_relay_slots_used(), m.block_relay_target(), false, || false);
        assert_eq!(action, OutboundAction::FullRelay, "inbound peers do not stop outbound dialing");
        // Manual (configured) peers do not use automatic slots either.
        let c = ConnectionId::new_unchecked(1000);
        m.register_dial(c, DialIntent::manual());
        m.on_established(c, PeerId::random(), true, &ip_addr("80.1.1.1"), now);
        assert_eq!(m.full_relay_slots_used(), 0);
    }

    /// Core's order: anchors, full-relay, block-relay-only, feeler; the feeler
    /// timer is only consulted once every slot is full.
    #[test]
    fn outbound_action_order_follows_core() {
        use OutboundAction::*;
        let never = || -> bool { panic!("feeler timer consulted with free slots") };
        assert_eq!(next_outbound_action(0, 8, 0, 2, true, never), Anchor);
        assert_eq!(next_outbound_action(0, 8, 2, 2, true, never), FullRelay);
        assert_eq!(next_outbound_action(3, 8, 0, 2, false, never), FullRelay);
        assert_eq!(next_outbound_action(8, 8, 1, 2, false, never), BlockRelay);
        assert_eq!(next_outbound_action(8, 8, 2, 2, false, || true), Feeler);
        assert_eq!(next_outbound_action(8, 8, 2, 2, false, || false), Idle);
    }

    /// NET-11 (c): feeler cadence — exponentially distributed with mean
    /// FEELER_INTERVAL, never more than one per due time, and the clock only
    /// advances when polled.
    #[test]
    fn feeler_cadence_is_exponential_with_core_mean() {
        let t0 = Instant::now();
        let mut s = FeelerSchedule::new(t0, FEELER_INTERVAL, 0.5);
        assert!(!s.poll(t0, 0.5), "not due at start");
        // Deterministic uniform stream (SplitMix64, 53-bit mantissa).
        let mut state = 0x1234_5678_9abc_def0u64;
        let mut next_u = || {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            ((z ^ (z >> 31)) >> 11) as f64 / (1u64 << 53) as f64
        };
        let mut now = t0;
        let mut fired = Vec::new();
        let end = t0 + Duration::from_secs(3600 * 20);
        while now < end {
            now += Duration::from_secs(1);
            if s.poll(now, next_u()) {
                fired.push(now);
                assert!(!s.poll(now, next_u()), "at most one feeler per due time");
            }
        }
        let n = fired.len() as f64;
        let mean_gap = (fired.last().unwrap().duration_since(fired[0]).as_secs_f64()) / (n - 1.0);
        assert!((100.0..=140.0).contains(&mean_gap), "mean interval {mean_gap:.1} s, expected about 120 s");
        let short = fired.windows(2).filter(|w| w[1].duration_since(w[0]) < Duration::from_secs(30)).count();
        assert!(short > 0, "the delay is exponential (some short gaps), not fixed");
        assert_eq!(exponential_delay(FEELER_INTERVAL, 0.0), Duration::ZERO);
        assert!(exponential_delay(FEELER_INTERVAL, 0.999_999_999) <= FEELER_INTERVAL * 20);
    }

    /// NET-11 (a): an inbound flood from one netgroup, connection after
    /// connection (1,000 of them), displaces at most 1 + EVICT_PROTECT_NETGROUP
    /// of 50 diverse honest inbound peers: once the attacker holds a slot,
    /// each new attacker connection evicts an attacker one (largest netgroup,
    /// youngest member); only the secret netgroup protection can shield up to
    /// four attacker peers, and only if the attacker's netgroup happens to win
    /// it (Core accepts the same bound).
    #[test]
    fn inbound_flood_from_one_netgroup_cannot_displace_diverse_peers() {
        let t0 = Instant::now();
        let mut m = ConnManager::new(random_key(), 50);
        let mut honest = Vec::new();
        let mut id = 0usize;
        for i in 0..50u32 {
            let p = PeerId::random();
            m.on_established(ConnectionId::new_unchecked(id), p, false, &ip_addr(&format!("{}.{}.1.1", 30 + i, i)), t0);
            m.on_ping(&p, Duration::from_millis(40 + i as u64));
            id += 1;
            honest.push((p, id - 1));
        }
        let mut conn_of: HashMap<PeerId, usize> = honest.iter().cloned().collect();
        for k in 0..1000u64 {
            let now = t0 + Duration::from_secs(60 + k);
            let p = PeerId::random();
            let c = id;
            id += 1;
            m.on_established(ConnectionId::new_unchecked(c), p, false, &ip_addr(&format!("66.66.{}.{}", k / 250, k % 250 + 1)), now);
            conn_of.insert(p, c);
            assert!(m.inbound_over_capacity());
            match m.eviction_victim(&p) {
                Some(v) => {
                    let vc = conn_of[&v];
                    m.on_closed(ConnectionId::new_unchecked(vc), v);
                }
                None => {
                    m.on_closed(ConnectionId::new_unchecked(c), p);
                }
            }
            assert!(!m.inbound_over_capacity());
        }
        let kept = honest.iter().filter(|(p, _)| m.role(p).is_some()).count();
        assert!(kept >= 50 - 1 - EVICT_PROTECT_NETGROUP, "honest diverse peers kept: {kept}/50");
        assert_eq!(m.count(ConnKind::Inbound), 50);
    }

    /// Address relay asymmetry (Core): only inbound peers are answered, once
    /// per connection; we ask only outbound full-relay and manual peers.
    #[test]
    fn getaddr_is_answered_once_and_only_for_inbound_peers() {
        let now = Instant::now();
        let mut m = ConnManager::new(random_key(), 8);
        let (inb, out, bro) = (PeerId::random(), PeerId::random(), PeerId::random());
        m.on_established(ConnectionId::new_unchecked(1), inb, false, &ip_addr("80.1.1.1"), now);
        let c2 = ConnectionId::new_unchecked(2);
        m.register_dial(c2, DialIntent { kind: ConnKind::OutboundFullRelay, ..DialIntent::manual() });
        m.on_established(c2, out, true, &ip_addr("80.2.1.1"), now);
        let c3 = ConnectionId::new_unchecked(3);
        m.register_dial(c3, DialIntent { kind: ConnKind::BlockRelayOnly, ..DialIntent::manual() });
        m.on_established(c3, bro, true, &ip_addr("80.3.1.1"), now);
        assert!(m.take_getaddr_answer(&inb));
        assert!(!m.take_getaddr_answer(&inb), "once per connection");
        assert!(!m.take_getaddr_answer(&out), "never to an outbound peer");
        assert!(!m.take_getaddr_answer(&bro), "never on a block-relay-only connection");
        assert!(ConnKind::OutboundFullRelay.sends_getaddr() && ConnKind::Manual.sends_getaddr());
        assert!(!ConnKind::BlockRelayOnly.sends_getaddr() && !ConnKind::Inbound.sends_getaddr());
        assert!(!ConnKind::Feeler.sends_getaddr());
    }

    /// NET-11 (b): anchors round-trip, are read once (the file is deleted on
    /// read) and are validated and capped on load.
    #[test]
    fn anchors_are_persisted_read_once_and_validated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(ANCHORS_FILE);
        let a = format!("/ip4/80.1.1.1/tcp/17110/p2p/{}", PeerId::random());
        let b = format!("/ip4/81.1.1.1/tcp/17110/p2p/{}", PeerId::random());
        write_anchors(&path, &[a.clone(), b.clone()]);
        assert_eq!(read_anchors(&path, false), vec![a.clone(), b.clone()]);
        assert!(!path.exists(), "anchors are used once per start-up");
        assert!(read_anchors(&path, false).is_empty());
        // Invalid entries are dropped; at most MAX_ANCHORS kept.
        let junk = vec![
            "/dns4/evil.example/tcp/1/p2p/x".to_string(),
            format!("/ip4/127.0.0.1/tcp/1/p2p/{}", PeerId::random()),
            a.clone(),
            b.clone(),
            format!("/ip4/82.1.1.1/tcp/17110/p2p/{}", PeerId::random()),
        ];
        std::fs::write(&path, serde_json::to_string(&junk).unwrap()).unwrap();
        assert_eq!(read_anchors(&path, false), vec![a, b]);
    }

    /// Anchors are the block-relay-only peers' dialed addresses.
    #[test]
    fn anchors_are_the_block_relay_only_peers() {
        let now = Instant::now();
        let mut m = ConnManager::new(random_key(), 8);
        let addr = format!("/ip4/80.3.1.1/tcp/17110/p2p/{}", PeerId::random());
        let c = ConnectionId::new_unchecked(3);
        m.register_dial(c, DialIntent { kind: ConnKind::BlockRelayOnly, addr: Some(addr.clone()), ..DialIntent::manual() });
        let p = PeerId::random();
        m.on_established(c, p, true, &ip_addr("80.3.1.1"), now);
        let c2 = ConnectionId::new_unchecked(4);
        m.register_dial(c2, DialIntent { kind: ConnKind::OutboundFullRelay, addr: Some("/ip4/80.4.1.1/tcp/1/p2p/x".into()), ..DialIntent::manual() });
        m.on_established(c2, PeerId::random(), true, &ip_addr("80.4.1.1"), now);
        assert_eq!(m.anchors(), vec![addr]);
        assert_eq!(m.block_relay_peers(), vec![p]);
        m.on_closed(c, p);
        assert!(m.anchors().is_empty());
    }

    /// Distinct peers are counted, not connections; feelers are not peers.
    #[test]
    fn peer_count_counts_distinct_peers_and_ignores_feelers() {
        let now = Instant::now();
        let mut m = ConnManager::new(random_key(), 8);
        let (p, q) = (PeerId::random(), PeerId::random());
        m.on_established(ConnectionId::new_unchecked(1), p, false, &ip_addr("80.1.1.1"), now);
        m.on_established(ConnectionId::new_unchecked(2), p, false, &ip_addr("80.1.1.1"), now);
        m.on_established(ConnectionId::new_unchecked(3), q, false, &ip_addr("80.2.1.1"), now);
        assert_eq!(m.peer_count(), 2);
        let f = ConnectionId::new_unchecked(4);
        m.register_dial(f, DialIntent { kind: ConnKind::Feeler, ..DialIntent::manual() });
        let e = m.on_established(f, PeerId::random(), true, &ip_addr("80.9.1.1"), now);
        assert!(!e.new_peer && e.kind == ConnKind::Feeler);
        assert_eq!(m.peer_count(), 2, "a feeler is not a peer");
        assert!(m.on_closed(ConnectionId::new_unchecked(1), p).peer_gone.is_none(), "P still has a connection");
        assert!(m.on_closed(ConnectionId::new_unchecked(2), p).peer_gone.is_some());
        assert_eq!(m.peer_count(), 1);
    }
}
