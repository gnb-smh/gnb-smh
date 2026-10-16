//! NET-2 residual (Phase 4): address-based discouragement and network
//! groups, after Bitcoin Core's `BanMan::Discourage` (`m_discouraged`, a
//! rolling bloom filter of addresses) and its netgroups.
//!
//! The audit measured that about three zero-cost invalid blocks per libp2p
//! identity forced a 64 MiB proof-of-work evaluation each before gossipsub's
//! invalid-message penalty graylisted the sender, and identities are free: a
//! new key is a new allowance. Core keys misbehaviour to the ADDRESS: a peer
//! that sends invalid data is disconnected and its address discouraged, and a
//! new connection from a discouraged address is not accepted (while inbound
//! slots are scarce; here: always, except for operator-configured peers). A
//! fresh identity from the same address therefore buys nothing.
//!
//! * An IPv4 address is discouraged as such; an IPv6 address by its /64 (one
//!   host's allocation: rotating within it is free).
//! * Local addresses (loopback, unspecified) are never discouraged, only
//!   disconnected — as Core does: every local connection would be refused.
//! * The set is bounded ([`DISCOURAGED_CAP`], Core's filter holds 50,000) and
//!   entries expire after [`DISCOURAGE_FOR`]; it is not persisted (Core's
//!   filter is not either).
//!
//! [`NetGroup`] (/16 IPv4, /32 IPv6, Core's `GetGroup` granularity) keys the
//! per-network-group proof-of-work budget (`pow::verifier`): identities and
//! addresses inside one provider's range share one budget.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use parking_lot::RwLock;

/// Bound of the discouraged-address set (Bitcoin Core's rolling filter
/// holds 50,000 addresses).
pub const DISCOURAGED_CAP: usize = 50_000;
/// How long an address stays discouraged.
pub const DISCOURAGE_FOR: Duration = Duration::from_secs(24 * 60 * 60);

/// Key of a discouraged address: an IPv4 address, or an IPv6 /64.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AddrKey([u8; 9]);

/// A network group: an IPv4 /16 or an IPv6 /32 (with IPv4-mapped IPv6
/// addresses mapped to their IPv4 group).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NetGroup([u8; 5]);

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

/// The discouragement key of `ip`.
pub fn addr_key(ip: IpAddr) -> AddrKey {
    let mut k = [0u8; 9];
    match canonical(ip) {
        IpAddr::V4(v4) => {
            k[0] = 4;
            k[1..5].copy_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            k[0] = 6;
            k[1..9].copy_from_slice(&v6.octets()[..8]);
        }
    }
    AddrKey(k)
}

/// The network group of `ip`.
pub fn net_group(ip: IpAddr) -> NetGroup {
    let mut g = [0u8; 5];
    match canonical(ip) {
        IpAddr::V4(v4) => {
            g[0] = 4;
            g[1..3].copy_from_slice(&v4.octets()[..2]);
        }
        IpAddr::V6(v6) => {
            g[0] = 6;
            g[1..5].copy_from_slice(&v6.octets()[..4]);
        }
    }
    NetGroup(g)
}

/// The IP address of a multiaddr (`/ip4/..` or `/ip6/..`), if it has one.
pub fn ip_of(addr: &Multiaddr) -> Option<IpAddr> {
    addr.iter().find_map(|p| match p {
        Protocol::Ip4(v4) => Some(IpAddr::V4(v4)),
        Protocol::Ip6(v6) => Some(IpAddr::V6(v6)),
        _ => None,
    })
}

/// Bitcoin Core's `IsLocal` (loopback, unspecified): such peers are
/// disconnected but never discouraged.
pub fn is_local(ip: IpAddr) -> bool {
    let ip = canonical(ip);
    ip.is_loopback() || ip.is_unspecified()
}

/// The bounded, expiring set of discouraged addresses.
#[derive(Debug, Default)]
pub struct Discouraged {
    until: HashMap<AddrKey, Instant>,
    order: VecDeque<(Instant, AddrKey)>,
}

impl Discouraged {
    pub fn new() -> Self {
        Self::default()
    }

    /// Discourage `ip` from `now` for [`DISCOURAGE_FOR`]. Returns `false`
    /// (nothing recorded) for a local address.
    pub fn discourage(&mut self, ip: IpAddr, now: Instant) -> bool {
        if is_local(ip) {
            return false;
        }
        let key = addr_key(ip);
        let until = now + DISCOURAGE_FOR;
        self.until.insert(key, until);
        self.order.push_back((until, key));
        while self.until.len() > DISCOURAGED_CAP || self.order.len() > 2 * DISCOURAGED_CAP {
            match self.order.pop_front() {
                Some((u, k)) => {
                    if self.until.get(&k) == Some(&u) {
                        self.until.remove(&k);
                    }
                }
                None => break,
            }
        }
        true
    }

    /// True iff `ip` is discouraged at `now`.
    pub fn is_discouraged(&self, ip: IpAddr, now: Instant) -> bool {
        !is_local(ip) && self.until.get(&addr_key(ip)).is_some_and(|u| now < *u)
    }

    /// Drop expired entries.
    pub fn gc_at(&mut self, now: Instant) {
        while let Some((u, k)) = self.order.front().copied() {
            if u > now {
                break;
            }
            self.order.pop_front();
            if self.until.get(&k) == Some(&u) {
                self.until.remove(&k);
            }
        }
    }

    #[allow(dead_code)] // tests only; the node binary compiles this module too
    pub fn len(&self) -> usize {
        self.until.len()
    }

    #[allow(dead_code)] // tests only; the node binary compiles this module too
    pub fn is_empty(&self) -> bool {
        self.until.is_empty()
    }
}

/// The remote IP address of every connected peer (its first connection),
/// maintained by the network loop and read by the message processor (the
/// proof-of-work budget of a peer's network group).
#[derive(Clone, Debug, Default)]
pub struct PeerAddrs(Arc<RwLock<HashMap<PeerId, IpAddr>>>);

impl PeerAddrs {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, peer: &PeerId) -> Option<IpAddr> {
        self.0.read().get(peer).copied()
    }

    /// The network group of `peer`, if connected.
    pub fn group(&self, peer: &PeerId) -> Option<NetGroup> {
        self.get(peer).map(net_group)
    }

    pub fn insert(&self, peer: PeerId, ip: IpAddr) {
        self.0.write().entry(peer).or_insert(ip);
    }

    pub fn remove(&self, peer: &PeerId) {
        self.0.write().remove(peer);
    }

    #[allow(dead_code)] // tests only; the node binary compiles this module too
    pub fn len(&self) -> usize {
        self.0.read().len()
    }

    #[allow(dead_code)] // tests only; the node binary compiles this module too
    pub fn is_empty(&self) -> bool {
        self.0.read().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn keys_and_groups() {
        let a: IpAddr = "45.77.1.2".parse().unwrap();
        let b: IpAddr = "45.77.200.9".parse().unwrap();
        assert_ne!(addr_key(a), addr_key(b), "IPv4: one address");
        assert_eq!(net_group(a), net_group(b), "IPv4: /16");
        let v6a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let v6b: IpAddr = "2001:db8:1:2:ffff::9".parse().unwrap();
        let v6c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(addr_key(v6a), addr_key(v6b), "IPv6: one /64");
        assert_ne!(addr_key(v6a), addr_key(v6c));
        assert_eq!(net_group(v6a), net_group(v6c), "IPv6: /32");
        let mapped = IpAddr::V6(Ipv4Addr::new(45, 77, 1, 2).to_ipv6_mapped());
        assert_eq!(addr_key(mapped), addr_key(a), "IPv4-mapped IPv6 is the IPv4 address");
        let ma: Multiaddr = "/ip4/45.77.1.2/tcp/17110".parse().unwrap();
        assert_eq!(ip_of(&ma), Some(a));
        assert!(is_local(IpAddr::V4(Ipv4Addr::LOCALHOST)) && is_local(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn discouragement_is_by_address_bounded_and_expires() {
        let mut d = Discouraged::new();
        let t0 = Instant::now();
        let a: IpAddr = "45.77.1.2".parse().unwrap();
        assert!(d.discourage(a, t0));
        assert!(d.is_discouraged(a, t0), "any identity from this address");
        assert!(!d.is_discouraged("45.77.1.3".parse().unwrap(), t0));
        assert!(!d.discourage(IpAddr::V4(Ipv4Addr::LOCALHOST), t0), "local peers are never discouraged");
        assert!(!d.is_discouraged(IpAddr::V4(Ipv4Addr::LOCALHOST), t0));
        assert!(!d.is_discouraged(a, t0 + DISCOURAGE_FOR), "expires");
        d.gc_at(t0 + DISCOURAGE_FOR);
        assert!(d.is_empty());
        for i in 0..(DISCOURAGED_CAP as u32 + 10) {
            d.discourage(IpAddr::V4(Ipv4Addr::from(0x0A00_0000 + i)), t0);
        }
        assert_eq!(d.len(), DISCOURAGED_CAP, "bounded");
        assert!(!d.is_discouraged(IpAddr::V4(Ipv4Addr::from(0x0A00_0000)), t0), "oldest out first");
    }
}
