//! Proof-of-work admission at the network edge, with peer accountability.
//!
//! GnB-SMH costs ~0.5 s and 64 MiB to verify — as much as one mining
//! attempt — so a block whose proof is invalid is the cheapest way to burn a
//! node's CPU. Every block received from a peer passes this gate before its
//! proof is evaluated, and the peer answers for the result:
//!
//! 1. **Banned peers** are ignored for [`BAN_DURATION`].
//! 2. **Context-free precheck** ([`pow_precheck`], microseconds): structure,
//!    timestamp bound, and `bits` no easier than the easiest difficulty any
//!    valid block at that height and time can have.
//! 3. **Contextual precheck** ([`contextual_precheck`]) when every parent is
//!    already in the DAG: height and `bits` must be exactly what block
//!    acceptance will require, so a block that would be refused anyway never
//!    costs a proof evaluation.
//! 4. **Per-source budget** for UNSOLICITED blocks: a token bucket of
//!    [`BUDGET_BURST`] evaluations refilled at [`BUDGET_REFILL_PER_SEC`],
//!    keyed by the peer's IP address when known (new identities from the same
//!    address share it). A block with an unknown parent cannot be checked in
//!    context and costs [`ORPHAN_COST`]. Blocks this node requested (directed
//!    pulls) are not budgeted — the node controls that rate — but are still
//!    verified and still accountable.
//! 5. The proof is evaluated off the event loop, on a bounded worker pool
//!    (in parallel across cores — this is also what speeds up sync). Queued
//!    evaluations of a peer banned meanwhile are dropped unevaluated.
//! 6. **Invalid proof ⇒ ban** of the peer and of its IP address. Gossip is
//!    validated before it is relayed (`validate_messages`), so an honest peer
//!    never forwards an unverified block: the peer that delivered an invalid
//!    proof is the one at fault.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use libp2p::{Multiaddr, PeerId};
use parking_lot::RwLock;

use crate::core::{self, Block};

/// Burst of unsolicited proof evaluations a source may trigger (about 4 s of
/// one core). Honest gossip is one block every ~30 s.
pub const BUDGET_BURST: f64 = 8.0;
/// Budget cost of a block whose parents are not all known: it skips the
/// contextual precheck, so it is charged as several evaluations.
pub const ORPHAN_COST: f64 = 4.0;
/// Sustained unsolicited evaluations per second per peer (30 per minute,
/// about 15 s of CPU per minute at 0.5 s each). Honest gossip is one block
/// every ~30 s.
pub const BUDGET_REFILL_PER_SEC: f64 = 0.5;
/// How long a peer that delivered an invalid proof is banned.
pub const BAN_DURATION: Duration = Duration::from_secs(24 * 60 * 60);
/// Bound on tracked peers (budgets), so the map itself is not a DoS target.
const MAX_TRACKED: usize = 4096;

/// Who a budget belongs to: the peer's IP address when known, else the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Source {
    Ip(IpAddr),
    Peer(PeerId),
}

/// Per-source budgets, and bans of peers and of their addresses.
#[derive(Default)]
pub struct PowGate {
    budgets: HashMap<Source, (f64, Instant)>,
    bans: HashMap<PeerId, Instant>,
    ip_bans: HashMap<IpAddr, Instant>,
    peer_ips: HashMap<PeerId, IpAddr>,
    /// Peers banned right now, shared with queued evaluations so they can be
    /// dropped without running.
    banned: Arc<RwLock<HashSet<PeerId>>>,
}

/// The IP address of a multiaddr, if it has one.
pub fn multiaddr_ip(addr: &Multiaddr) -> Option<IpAddr> {
    addr.iter().find_map(|p| match p {
        libp2p::multiaddr::Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
        libp2p::multiaddr::Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
        _ => None,
    })
}

impl PowGate {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the address a peer connected from (keys its budget and bans).
    pub fn note_peer_ip(&mut self, peer: PeerId, ip: IpAddr) {
        if !self.peer_ips.contains_key(&peer) && self.peer_ips.len() >= MAX_TRACKED {
            if let Some(any) = self.peer_ips.keys().next().copied() {
                self.peer_ips.remove(&any);
            }
        }
        self.peer_ips.insert(peer, ip);
    }

    fn source(&self, peer: &PeerId) -> Source {
        self.peer_ips.get(peer).map_or(Source::Peer(*peer), |ip| Source::Ip(*ip))
    }

    /// Banned itself, or connected from a banned address.
    pub fn is_banned(&self, peer: &PeerId, now: Instant) -> bool {
        self.bans.get(peer).is_some_and(|until| now < *until)
            || self.peer_ips.get(peer).is_some_and(|ip| self.is_ip_banned(ip, now))
    }

    pub fn is_ip_banned(&self, ip: &IpAddr, now: Instant) -> bool {
        self.ip_bans.get(ip).is_some_and(|until| now < *until)
    }

    /// Shared view of the currently banned peers, for queued evaluations.
    pub fn banned_handle(&self) -> Arc<RwLock<HashSet<PeerId>>> {
        self.banned.clone()
    }

    /// Take `cost` evaluations from `peer`'s source budget; `false` when
    /// exhausted.
    pub fn take(&mut self, peer: &PeerId, cost: f64, now: Instant) -> bool {
        let key = self.source(peer);
        if !self.budgets.contains_key(&key) && self.budgets.len() >= MAX_TRACKED {
            // Forget the stalest budget; a forgotten source restarts full,
            // which only matters for sources idle long enough to be stalest.
            if let Some(oldest) = self.budgets.iter().min_by_key(|(_, (_, t))| *t).map(|(k, _)| *k) {
                self.budgets.remove(&oldest);
            }
        }
        let (tokens, last) = self.budgets.entry(key).or_insert((BUDGET_BURST, now));
        let refill = now.saturating_duration_since(*last).as_secs_f64() * BUDGET_REFILL_PER_SEC;
        *tokens = (*tokens + refill).min(BUDGET_BURST);
        *last = now;
        if *tokens >= cost {
            *tokens -= cost;
            true
        } else {
            false
        }
    }

    /// Ban `peer` and the address it connected from.
    pub fn ban(&mut self, peer: &PeerId, now: Instant) {
        self.bans.insert(*peer, now + BAN_DURATION);
        let key = self.source(peer);
        self.budgets.remove(&key);
        if let Source::Ip(ip) = key {
            self.ip_bans.insert(ip, now + BAN_DURATION);
        }
        self.banned.write().insert(*peer);
    }

    /// Remove and return peer bans that have expired (to lift transport-level
    /// blacklists); expired address bans are dropped too.
    pub fn expire_bans(&mut self, now: Instant) -> Vec<PeerId> {
        let expired: Vec<PeerId> = self.bans.iter()
            .filter(|(_, until)| now >= **until)
            .map(|(p, _)| *p)
            .collect();
        let mut banned = self.banned.write();
        for p in &expired {
            self.bans.remove(p);
            banned.remove(p);
        }
        self.ip_bans.retain(|_, until| now < *until);
        expired
    }
}

/// Checks that need the parents: `parents` holds `(height, timestamp)` of
/// every parent when all are in the DAG. Height and `bits` must equal what
/// block acceptance requires (max parent height + 1; the ASERT schedule from
/// the latest parent timestamp), so a block refused there never costs a
/// proof evaluation here. Microseconds; never evaluates GnB-SMH.
pub fn contextual_precheck(block: &Block, parents: &[(u64, u64)]) -> Result<(), String> {
    let height = parents.iter().map(|(h, _)| *h).max().unwrap_or(0) + 1;
    if block.height != height {
        return Err(format!("height {} != {} from its parents", block.height, height));
    }
    let parent_ts = core::difficulty_parent_timestamp(parents.iter().map(|(_, t)| *t));
    let bits = crate::pow::expected_bits(parent_ts, height)?;
    if block.header.bits != bits {
        return Err(format!("bits 0x{:08x} != expected 0x{:08x}", block.header.bits, bits));
    }
    Ok(())
}

/// Context-free checks a block must pass before its proof is evaluated.
/// Microseconds; never evaluates GnB-SMH.
///
/// The difficulty floor is exact: ASERT eases monotonically with the parent
/// timestamp and no parent is later than its child, so
/// `expected_bits(block.timestamp, height)` is the easiest difficulty ANY
/// valid block at that height can carry. A valid block never fails it.
pub fn pow_precheck(block: &Block) -> Result<(), String> {
    block.validate_structure_cheap().map_err(|e| e.to_string())?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    if block.header.timestamp > now.saturating_add(core::MAX_FUTURE_SECS) {
        return Err("timestamp too far in the future".into());
    }
    if block.height == 0 {
        return Err("genesis is never relayed".into());
    }
    let target = gnb_smh::difficulty::try_bits_to_target(block.header.bits)
        .map_err(|e| format!("malformed bits: {:?}", e))?;
    let floor_bits = core::expected_bits(block.header.timestamp, block.height)
        .map_err(|e| format!("difficulty floor: {}", e))?;
    let floor = gnb_smh::difficulty::try_bits_to_target(floor_bits)
        .map_err(|e| format!("difficulty floor: {:?}", e))?;
    if target > floor {
        return Err(format!("bits 0x{:08x} easier than the consensus floor 0x{:08x}",
            block.header.bits, floor_bits));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_allows_a_burst_then_refills_slowly() {
        let mut g = PowGate::new();
        let p = PeerId::random();
        let t0 = Instant::now();
        for _ in 0..BUDGET_BURST as usize {
            assert!(g.take(&p, 1.0, t0));
        }
        assert!(!g.take(&p, 1.0, t0), "burst exhausted");
        assert!(!g.take(&p, 1.0, t0 + Duration::from_millis(1500)), "not yet a full token");
        assert!(g.take(&p, 1.0, t0 + Duration::from_secs(2)), "one token after 2 s");
        assert!(!g.take(&p, 1.0, t0 + Duration::from_secs(2)));
    }

    #[test]
    fn budgets_are_per_peer() {
        let mut g = PowGate::new();
        let (a, b) = (PeerId::random(), PeerId::random());
        let t0 = Instant::now();
        for _ in 0..BUDGET_BURST as usize { g.take(&a, 1.0, t0); }
        assert!(!g.take(&a, 1.0, t0));
        assert!(g.take(&b, 1.0, t0), "another peer is unaffected");
    }

    #[test]
    fn bans_hold_for_the_ban_duration_then_expire() {
        let mut g = PowGate::new();
        let p = PeerId::random();
        let t0 = Instant::now();
        g.ban(&p, t0);
        assert!(g.is_banned(&p, t0));
        assert!(g.is_banned(&p, t0 + BAN_DURATION - Duration::from_secs(1)));
        assert!(g.expire_bans(t0 + Duration::from_secs(60)).is_empty());
        assert_eq!(g.expire_bans(t0 + BAN_DURATION), vec![p]);
        assert!(!g.is_banned(&p, t0 + BAN_DURATION));
    }

    #[test]
    fn tracked_budgets_are_bounded() {
        let mut g = PowGate::new();
        let t0 = Instant::now();
        for i in 0..(MAX_TRACKED + 100) {
            g.take(&PeerId::random(), 1.0, t0 + Duration::from_millis(i as u64));
        }
        assert!(g.budgets.len() <= MAX_TRACKED);
    }

    #[test]
    fn identities_from_one_address_share_a_budget_and_a_ban() {
        let mut g = PowGate::new();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let (a, b, c) = (PeerId::random(), PeerId::random(), PeerId::random());
        g.note_peer_ip(a, ip);
        g.note_peer_ip(b, ip);
        let t0 = Instant::now();
        for _ in 0..BUDGET_BURST as usize { assert!(g.take(&a, 1.0, t0)); }
        assert!(!g.take(&b, 1.0, t0), "a new identity on the same address gets no fresh budget");
        g.ban(&a, t0);
        assert!(g.banned_handle().read().contains(&a));
        g.note_peer_ip(c, ip);
        assert!(g.is_banned(&c, t0), "the address is banned, whatever the identity");
        assert!(g.is_ip_banned(&ip, t0));
        g.expire_bans(t0 + BAN_DURATION);
        assert!(!g.is_banned(&c, t0 + BAN_DURATION) && !g.banned_handle().read().contains(&a));
    }

    #[test]
    fn orphans_cost_more_budget() {
        let mut g = PowGate::new();
        let p = PeerId::random();
        let t0 = Instant::now();
        let n = (0..10).take_while(|_| g.take(&p, ORPHAN_COST, t0)).count();
        assert_eq!(n, (BUDGET_BURST / ORPHAN_COST) as usize);
    }

    #[test]
    fn contextual_precheck_requires_the_exact_height_and_bits() {
        let parents = [(9u64, core::GENESIS_TIMESTAMP + 300), (7, core::GENESIS_TIMESTAMP + 200)];
        let mut b = core::genesis_block();
        b.height = 10;
        b.header.bits = crate::pow::expected_bits(core::GENESIS_TIMESTAMP + 300, 10).unwrap();
        assert_eq!(contextual_precheck(&b, &parents), Ok(()));
        b.height = 11;
        assert!(contextual_precheck(&b, &parents).unwrap_err().contains("height"));
        b.height = 10;
        b.header.bits ^= 1;
        assert!(contextual_precheck(&b, &parents).unwrap_err().contains("bits"));
    }

    #[test]
    fn precheck_rejects_future_and_genesis_blocks() {
        let mut b = core::genesis_block();
        assert!(pow_precheck(&b).unwrap_err().contains("genesis"));
        b.height = 5;
        b.header.timestamp = u64::MAX / 2;
        assert!(pow_precheck(&b).unwrap_err().contains("future"));
    }
}
