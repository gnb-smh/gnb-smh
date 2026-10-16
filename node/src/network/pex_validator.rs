//! Sprint P — PEX Protocol Hardening
//!
//! Validates and rate-limits Peer Exchange (PEX) messages to prevent
//! amplification attacks and private-network pivoting.
//!
//! ## Attacks this module prevents
//!
//! 1. **Amplification scan:** peer sends 10,000 arbitrary IPs, victim dials all
//!    of them. Sprint P caps per-message batch at 20.
//!
//! 2. **Sustained flooding:** peer sends PEX repeatedly to bypass batch limit.
//!    Sprint P applies a sliding rate limit of 100 addresses per 5 min per peer_id.
//!
//! 3. **Local-network pivoting:** peer sends 127.0.0.1, 10.x.x.x, 192.168.x.x,
//!    169.254.x.x. Sprint P rejects unless `--allow-private-peers` is set.
//!
//! 4. **known_peers.json pollution:** bad addresses persist forever. Sprint P
//!    filters on-load and caps at 1000 entries with FIFO eviction.
//!
//! 5. **Reflection / eclipse via PEX (audit NET-11):** received addresses are
//!    NEVER dialed directly from the message that carried them. They go into
//!    a bounded, keyed, netgroup-bucketed "new" table ([`AddrBook`],
//!    `network::addrbook`); the connection manager dials from the tables to
//!    keep its OUTBOUND slots full (never limited by inbound connections,
//!    B1-T9), one outbound peer per netgroup. Rate limits are keyed by the
//!    AUTHOR of the message, and a successful outbound connection moves the
//!    address to the persisted, keyed "tried" table ([`TriedTable`]).
//!
//! 6. **Host-name and re-spelled-IP bypass (re-audit B1-T8):** PEX carries
//!    IP literals only (no `/dns*` names) and every IPv6 literal that embeds
//!    an IPv4 is judged — routability and netgroup — on that IPv4
//!    ([`classify_ip`], [`netgroup`]).

use libp2p::{Multiaddr, PeerId, multiaddr::Protocol};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

pub use super::addrbook::{AddrBook, TriedInsert, TriedTable};

// ── Tunables ─────────────────────────────────────────────────────────────────

/// Max addresses processed per single PeerExchange message.
pub const PEX_BATCH_LIMIT: usize = 20;

/// Sliding window for PEX rate limit (per peer_id).
pub const PEX_RATE_WINDOW: Duration = Duration::from_secs(300);

/// Max addresses from a single peer within the sliding window.
pub const PEX_MAX_PER_WINDOW: usize = 100;

/// Max entries in known_peers.json.
pub const KNOWN_PEERS_CAP: usize = 1000;

/// How often aggregated stats are logged (see PexStats).
pub const PEX_STATS_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// NET-11: bound on the number of authors the PEX rate limiter tracks.
pub const PEX_LIMITER_TRACK_CAP: usize = 4096;

/// NET-11: capacity of the in-memory "new" (unverified) address table
/// (`addrbook::NEW_BUCKET_COUNT` × `addrbook::BUCKET_SIZE`).
pub const NEW_TABLE_CAP: usize = 1024;
/// NET-11: at most this many "new" addresses per netgroup (see [`netgroup`]).
pub const NEW_PER_NETGROUP: usize = 8;
/// NET-11: at most this many persisted ("tried") known peers per netgroup:
/// a netgroup maps to `addrbook::TRIED_BUCKETS_PER_GROUP` tried buckets of
/// `addrbook::BUCKET_SIZE` slots.
pub const TRIED_PER_NETGROUP: usize = 16;

// ── Address validation ───────────────────────────────────────────────────────

/// Checks whether a string multiaddr is acceptable as a PEX suggestion, a
/// known-peers ("tried") entry, an anchor, or an address we advertise.
///
/// Rules (B1-T8, modelled on Bitcoin Core's addrman, which stores only IP
/// addresses and screens them with `CNetAddr::IsRoutable`):
/// - exactly `/ip4|ip6/<ip>/tcp/<port ≠ 0>[/ws|/wss]/p2p/<peer id>`: one
///   IP literal first, TCP, an optional websocket layer, and exactly ONE
///   trailing `/p2p/<peer_id>` (we must know who we dial; the canonical form
///   has the id LAST, once);
/// - NO host names (`/dns`, `/dns4`, `/dns6`): a name is not an address — it
///   resolves to whatever its owner wants at dial time (a loopback or private
///   IP included), and every attacker sub-domain used to be its own netgroup,
///   which defeated every per-netgroup cap. Operator-configured names
///   (`--peer`, `--dns-seed`) are resolved by the node, never learned;
/// - the IP must be routable ([`classify_ip`]), judged on the IPv4 an IPv6
///   literal embeds (IPv4-mapped / -compatible, SIIT, NAT64, 6to4, Teredo),
///   so `::ffff:127.0.0.1` is refused like `127.0.0.1`;
/// - loopback / private / CGNAT / ULA / link-local-v6 only with
///   `allow_private` (dev/test mode);
/// - must fit MAX_WIRE_ADDR_LEN (an entry the wire bound forbids can never
///   be exchanged, and carrying it in a PeerExchange graylists the sender).
///
/// PROPAGAÇÃO-CHURN fix (2026-08-09): the single-final-P2p and length rules
/// are what let `prune_invalid` self-heal a poisoned known_peers.json at
/// startup. The old check ("contains a P2p somewhere") accepted the
/// `/p2p/<id>/p2p/<id>/…` chains the ConnectionEstablished handler used to
/// build, so the poison round-tripped load → PEX → penalty forever.
pub fn is_valid_public_multiaddr(addr: &str, allow_private: bool) -> bool {
    if addr.len() > super::MAX_WIRE_ADDR_LEN {
        return false;
    }
    let ma: Multiaddr = match addr.parse() {
        Ok(m) => m,
        Err(_) => return false,
    };
    let parts: Vec<Protocol<'_>> = ma.iter().collect();
    let ip_ok = match parts.first() {
        Some(Protocol::Ip4(ip)) => is_acceptable_ip(IpAddr::V4(*ip), allow_private),
        Some(Protocol::Ip6(ip)) => is_acceptable_ip(IpAddr::V6(*ip), allow_private),
        // Host names and anything else are refused.
        _ => false,
    };
    if !ip_ok {
        return false;
    }
    match parts.get(1) {
        Some(Protocol::Tcp(port)) if *port != 0 => {}
        _ => return false,
    }
    matches!(&parts[2..], [Protocol::P2p(_)] | [Protocol::Ws(_) | Protocol::Wss(_), Protocol::P2p(_)])
}

/// Routability class of an IP address (B1-T8; Bitcoin Core's
/// `CNetAddr::IsRoutable` and friends). An IPv6 literal that embeds an IPv4
/// address is classified by that IPv4 ([`embedded_ipv4`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpClass {
    /// A globally routable unicast address.
    Public,
    /// Loopback, RFC 1918, CGNAT (100.64/10), ULA (fc00::/7), site-local or
    /// link-local IPv6: reachable only on a local network; accepted only with
    /// `--allow-private-peers` (dev/test mode).
    Private,
    /// Never a peer: unspecified, broadcast, multicast, reserved,
    /// documentation, benchmarking, IPv4 link-local (cloud metadata lives at
    /// 169.254.169.254), ORCHID, discard-only, NAT64 local-use.
    Invalid,
}

/// The IPv4 address an IPv6 literal embeds, for the transition formats whose
/// traffic ends up at that IPv4 address (Bitcoin Core's `CNetAddr` handles
/// the same set: RFC 4291 IPv4-mapped and IPv4-compatible, RFC 6145 SIIT,
/// RFC 6052 NAT64 well-known prefix, RFC 3964 6to4, RFC 4380 Teredo).
/// `None` for a native IPv6 address (and for `::` / `::1`).
pub fn embedded_ipv4(ip: &Ipv6Addr) -> Option<Ipv4Addr> {
    let s = ip.segments();
    let tail = Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8);
    // ::ffff:a.b.c.d (IPv4-mapped)
    if s[..5] == [0, 0, 0, 0, 0] && s[5] == 0xffff {
        return Some(tail);
    }
    // ::ffff:0:a.b.c.d (SIIT, RFC 6145)
    if s[..4] == [0, 0, 0, 0] && s[4] == 0xffff && s[5] == 0 {
        return Some(tail);
    }
    // ::a.b.c.d (IPv4-compatible, deprecated) — not :: or ::1.
    if s[..6] == [0, 0, 0, 0, 0, 0] && (s[6] != 0 || s[7] > 1) {
        return Some(tail);
    }
    // 64:ff9b::a.b.c.d (NAT64 well-known prefix, RFC 6052)
    if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return Some(tail);
    }
    // 2002:AABB:CCDD::/48 (6to4, RFC 3964)
    if s[0] == 0x2002 {
        return Some(Ipv4Addr::new((s[1] >> 8) as u8, s[1] as u8, (s[2] >> 8) as u8, s[2] as u8));
    }
    // 2001:0::/32 (Teredo, RFC 4380): the client's IPv4 is the bit-inverted
    // last 32 bits.
    if s[0] == 0x2001 && s[1] == 0 {
        let x = !(((s[6] as u32) << 16) | s[7] as u32);
        return Some(Ipv4Addr::from(x));
    }
    None
}

fn classify_ipv4(ip: &Ipv4Addr) -> IpClass {
    let o = ip.octets();
    if o[0] == 0                       // 0.0.0.0/8 "this network"
        || ip.is_broadcast()           // 255.255.255.255
        || ip.is_multicast()           // 224.0.0.0/4
        || o[0] >= 240                 // 240.0.0.0/4 reserved
        || ip.is_documentation()       // 192.0.2/24, 198.51.100/24, 203.0.113/24
        || ip.is_link_local()          // 169.254.0.0/16 (cloud metadata)
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18.0.0/15 benchmarking (RFC 2544)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24 IETF protocol assignments
    {
        return IpClass::Invalid;
    }
    if ip.is_loopback()                // 127.0.0.0/8
        || ip.is_private()             // 10/8, 172.16/12, 192.168/16
        || (o[0] == 100 && (o[1] & 0xc0) == 0x40) // 100.64.0.0/10 CGNAT
    {
        return IpClass::Private;
    }
    IpClass::Public
}

fn classify_ipv6(ip: &Ipv6Addr) -> IpClass {
    let s = ip.segments();
    if ip.is_unspecified() || ip.is_multicast() {
        return IpClass::Invalid;
    }
    if ip.is_loopback() {
        return IpClass::Private;
    }
    let special_2001 = s[0] == 0x2001
        && (s[1] == 0x0db8                         // 2001:db8::/32 documentation (RFC 3849)
            || (s[1] & 0xfff0) == 0x10             // 2001:10::/28 ORCHID (RFC 4843)
            || (s[1] & 0xfff0) == 0x20             // 2001:20::/28 ORCHIDv2 (RFC 7343)
            || (s[1] == 0x0002 && s[2] == 0));     // 2001:2::/48 benchmarking (RFC 5180)
    if special_2001
        || (s[0] == 0x0100 && s[1..4] == [0, 0, 0])   // 100::/64 discard-only (RFC 6666)
        || (s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0x0001) // 64:ff9b:1::/48 NAT64 local-use
    {
        return IpClass::Invalid;
    }
    if let Some(v4) = embedded_ipv4(ip) {
        return classify_ipv4(&v4);
    }
    if (s[0] & 0xfe00) == 0xfc00                     // fc00::/7 ULA
        || (s[0] & 0xffc0) == 0xfe80                 // fe80::/10 link-local
        || (s[0] & 0xffc0) == 0xfec0                 // fec0::/10 site-local (deprecated)
    {
        return IpClass::Private;
    }
    IpClass::Public
}

/// B1-T8: routability class of `ip` (see [`IpClass`]).
pub fn classify_ip(ip: IpAddr) -> IpClass {
    match ip {
        IpAddr::V4(v4) => classify_ipv4(&v4),
        IpAddr::V6(v6) => classify_ipv6(&v6),
    }
}

/// B1-T8: whether `ip` may be dialed / stored: public, or private with
/// `allow_private` (dev/test mode). Never the [`IpClass::Invalid`] classes.
pub fn is_acceptable_ip(ip: IpAddr, allow_private: bool) -> bool {
    match classify_ip(ip) {
        IpClass::Public => true,
        IpClass::Private => allow_private,
        IpClass::Invalid => false,
    }
}

/// B1-T8: the canonical spelling of a peer address: an IPv4-mapped or
/// IPv4-compatible IPv6 literal (which denotes the IPv4 host itself) is
/// rewritten as `/ip4/…`, so the same host can never sit in the tables twice
/// under two spellings. Other addresses are returned unchanged. `None` for an
/// unparseable string.
pub fn normalize_peer_addr(addr: &str) -> Option<String> {
    let ma: Multiaddr = addr.parse().ok()?;
    let mut changed = false;
    let out: Multiaddr = ma
        .iter()
        .map(|p| match p {
            Protocol::Ip6(ip6) => {
                let s = ip6.segments();
                let mapped_or_compat = s[..5] == [0, 0, 0, 0, 0] && (s[5] == 0xffff || (s[5] == 0 && (s[6] != 0 || s[7] > 1)));
                match embedded_ipv4(&ip6) {
                    Some(v4) if mapped_or_compat => {
                        changed = true;
                        Protocol::Ip4(v4)
                    }
                    _ => Protocol::Ip6(ip6),
                }
            }
            other => other,
        })
        .collect();
    Some(if changed { out.to_string() } else { addr.to_string() })
}

/// Whether a multiaddr points at a LAN (private / loopback / link-local) IP.
/// mDNS auto-dial must accept ONLY LAN targets: an mDNS record that names a
/// public IP is a reflection / SSRF attempt (a rogue LAN responder making us
/// dial an arbitrary internet host), and must never be dialed.
pub fn is_lan_multiaddr(addr: &Multiaddr) -> bool {
    for proto in addr.iter() {
        match proto {
            Protocol::Ip4(ip) => {
                return ip.is_private() || ip.is_loopback() || ip.is_link_local();
            }
            Protocol::Ip6(ip) => {
                let seg = ip.segments();
                return ip.is_loopback()
                    || (seg[0] & 0xffc0) == 0xfe80   // link-local fe80::/10
                    || (seg[0] & 0xfe00) == 0xfc00;  // ULA fc00::/7
            }
            _ => {}
        }
    }
    false
}

// ── Rate limiter ─────────────────────────────────────────────────────────────

/// Sliding-window rate limiter keyed by peer_id.
///
/// Each peer is allowed PEX_MAX_PER_WINDOW address suggestions per
/// PEX_RATE_WINDOW seconds. When a window expires, it resets.
#[derive(Default)]
pub struct PexRateLimiter {
    state: HashMap<PeerId, WindowState>,
}

#[derive(Clone, Copy)]
struct WindowState {
    window_start: Instant,
    count: usize,
}

impl PexRateLimiter {
    pub fn new() -> Self {
        Self { state: HashMap::new() }
    }

    /// Try to admit `n_addresses` from `sender`. Returns the number actually
    /// accepted after rate and batch limits. Rejected = n_addresses - accepted.
    pub fn admit(&mut self, sender: PeerId, n_addresses: usize) -> usize {
        // Apply batch limit first (independent of rate window).
        let capped_batch = n_addresses.min(PEX_BATCH_LIMIT);

        let now = Instant::now();
        // NET-11: bounded. A full map is first garbage-collected; if it is
        // still full, an unknown sender is refused (PEX is optional, so
        // failing closed costs nothing but a few addresses).
        if !self.state.contains_key(&sender) && self.state.len() >= PEX_LIMITER_TRACK_CAP {
            self.gc();
            if self.state.len() >= PEX_LIMITER_TRACK_CAP {
                return 0;
            }
        }
        let state = self.state.entry(sender).or_insert(WindowState {
            window_start: now,
            count: 0,
        });

        // If current window expired, reset
        if now.duration_since(state.window_start) >= PEX_RATE_WINDOW {
            state.window_start = now;
            state.count = 0;
        }

        // How much room left in the window
        let room = PEX_MAX_PER_WINDOW.saturating_sub(state.count);
        let admitted = capped_batch.min(room);
        state.count += admitted;
        admitted
    }

    /// Remove entries whose window has long expired (housekeeping).
    /// Call periodically to prevent unbounded growth.
    pub fn gc(&mut self) {
        let now = Instant::now();
        self.state.retain(|_, st| {
            now.duration_since(st.window_start) < PEX_RATE_WINDOW.saturating_mul(2)
        });
    }

    pub fn tracked_peer_count(&self) -> usize {
        self.state.len()
    }
}

// ── Aggregated stats (for logging) ───────────────────────────────────────────

/// Accumulates rejection/accept counts between periodic log emissions.
pub struct PexStats {
    last_log: Instant,
    accepted: usize,
    rejected_invalid: usize,
    rejected_batch:   usize,
    rejected_rate:    usize,
    rejected_private: usize,
    distinct_peers:   usize,
}

impl PexStats {
    pub fn new() -> Self {
        Self {
            last_log: Instant::now(),
            accepted: 0,
            rejected_invalid: 0,
            rejected_batch:   0,
            rejected_rate:    0,
            rejected_private: 0,
            distinct_peers:   0,
        }
    }

    pub fn record_accept(&mut self, n: usize) { self.accepted += n; }
    pub fn record_invalid(&mut self, n: usize) { self.rejected_invalid += n; }
    pub fn record_batch(&mut self, n: usize) { self.rejected_batch += n; }
    pub fn record_rate(&mut self, n: usize) { self.rejected_rate += n; }
    pub fn record_private(&mut self, n: usize) { self.rejected_private += n; }

    pub fn set_distinct_peers(&mut self, n: usize) { self.distinct_peers = n; }

    /// Returns a summary line if enough time has passed since the last log,
    /// resetting counters. Otherwise returns None.
    pub fn tick(&mut self) -> Option<String> {
        let now = Instant::now();
        if now.duration_since(self.last_log) < PEX_STATS_LOG_INTERVAL {
            return None;
        }
        let total_rej = self.rejected_invalid + self.rejected_batch
                      + self.rejected_rate + self.rejected_private;
        if self.accepted == 0 && total_rej == 0 {
            self.last_log = now;
            return None; // nothing to report
        }
        let msg = format!(
            "PEX stats: accepted {} | rejected {} (invalid {}, batch-limit {}, rate-limit {}, private {}) | tracked peers {}",
            self.accepted, total_rej,
            self.rejected_invalid, self.rejected_batch,
            self.rejected_rate, self.rejected_private,
            self.distinct_peers
        );
        // Reset
        self.last_log = now;
        self.accepted = 0;
        self.rejected_invalid = 0;
        self.rejected_batch = 0;
        self.rejected_rate = 0;
        self.rejected_private = 0;
        Some(msg)
    }
}

impl Default for PexStats {
    fn default() -> Self { Self::new() }
}

// ── known_peers.json hygiene ─────────────────────────────────────────────────

/// Apply the known_peers cap. NET-11: eviction is netgroup-aware — entries
/// are removed from the MOST represented netgroup first, so a flood of
/// addresses from one /16 can never push out a diverse set of peers.
/// Returns how many entries were removed.
pub fn enforce_cap(peers: &mut std::collections::HashSet<String>) -> usize {
    let initial = peers.len();
    if initial <= KNOWN_PEERS_CAP {
        return 0;
    }
    let mut to_remove = initial - KNOWN_PEERS_CAP;
    let mut groups: HashMap<String, Vec<String>> = HashMap::new();
    for a in peers.iter() {
        groups.entry(netgroup(a).unwrap_or_default()).or_default().push(a.clone());
    }
    while to_remove > 0 {
        let Some(victim) = groups
            .values_mut()
            .max_by_key(|v| v.len())
            .and_then(|v| v.pop())
        else {
            break;
        };
        peers.remove(&victim);
        to_remove -= 1;
    }
    initial - peers.len()
}

/// NET-11 / B1-T8: the "netgroup" of an address string (with or without a
/// `/p2p/` suffix) — the bucket used for every diversity rule: address-table
/// bucketing, the per-netgroup caps, outbound diversity and inbound eviction
/// (Bitcoin Core's `NetGroupManager::GetGroup`).
///
/// * public IPv4: the /16 (`ip4:a.b`);
/// * an IPv6 literal that embeds an IPv4 ([`embedded_ipv4`]): the /16 of that
///   IPv4, so re-spelling one /16 as `::ffff:…`, 6to4, NAT64 or Teredo lands
///   in the same group;
/// * other public IPv6: the /32 (`ip6:xxxx:xxxx`);
/// * loopback / private / link-local (only ever accepted with
///   `--allow-private-peers`, or seen as the source of an inbound
///   connection): the full IP (`local:<ip>`) — these ranges have no
///   meaningful routing prefix (Core lumps them into one "unroutable" group;
///   one group per IP keeps a LAN or proxy source as ONE group without
///   collapsing a whole LAN into one);
/// * host names and unparseable strings: `None` (a name has no netgroup —
///   that was the B1-T8 bypass — and no table accepts it).
pub fn netgroup(addr: &str) -> Option<String> {
    let ma: Multiaddr = addr.parse().ok()?;
    netgroup_of(&ma)
}

/// [`netgroup`] of a parsed multiaddr (its FIRST component must be the IP).
pub fn netgroup_of(ma: &Multiaddr) -> Option<String> {
    match ma.iter().next()? {
        Protocol::Ip4(ip) => Some(ipv4_group(&ip)),
        Protocol::Ip6(ip) => Some(match embedded_ipv4(&ip) {
            Some(v4) => ipv4_group(&v4),
            None if classify_ipv6(&ip) == IpClass::Public => {
                let s = ip.segments();
                format!("ip6:{:x}:{:x}", s[0], s[1])
            }
            None => format!("local:{ip}"),
        }),
        _ => None,
    }
}

fn ipv4_group(ip: &Ipv4Addr) -> String {
    if classify_ipv4(ip) == IpClass::Public {
        let o = ip.octets();
        format!("ip4:{}.{}", o[0], o[1])
    } else {
        format!("local:{ip}")
    }
}

/// The `/p2p/<peer id>` of an address string, if any.
pub fn addr_peer_id(addr: &str) -> Option<PeerId> {
    let ma: Multiaddr = addr.parse().ok()?;
    ma.iter().find_map(|p| match p {
        Protocol::P2p(id) => Some(id),
        _ => None,
    })
}

/// One-time cleanup at startup: drop entries that fail the new validator.
/// Returns number of entries removed.
pub fn prune_invalid(
    peers: &mut std::collections::HashSet<String>,
    allow_private: bool,
) -> usize {
    let before = peers.len();
    peers.retain(|addr| is_valid_public_multiaddr(addr, allow_private));
    before - peers.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(ip: &str) -> String {
        format!("/ip4/{}/tcp/17110/p2p/{}", ip, PeerId::random())
    }

    #[test]
    fn netgroup_buckets_by_slash16() {
        assert_eq!(netgroup(&addr("45.77.1.2")), netgroup(&addr("45.77.200.9")));
        assert_ne!(netgroup(&addr("45.77.1.2")), netgroup(&addr("45.78.1.2")));
        assert_eq!(netgroup("garbage"), None);
    }

    /// NET-11: one /16 can fill at most NEW_PER_NETGROUP slots of the new table.
    #[test]
    fn addr_book_limits_each_netgroup() {
        let mut book = AddrBook::new();
        let mut inserted = 0;
        for i in 0..100u8 {
            if book.add(&addr(&format!("45.77.{}.1", i))) {
                inserted += 1;
            }
        }
        assert_eq!(inserted, NEW_PER_NETGROUP);
        assert!(book.add(&addr("80.1.1.1")), "another netgroup still has room");
    }

    /// NET-11: the table is bounded and dial batches are netgroup-diverse.
    #[test]
    fn addr_book_is_bounded_and_dials_diverse_batches() {
        let mut book = AddrBook::new();
        for a in 0..=255u8 {
            for b in 0..8u8 {
                book.add(&addr(&format!("{}.{}.1.{}", 20 + (a % 200), a, b + 1)));
            }
        }
        assert!(book.len() <= NEW_TABLE_CAP);
        let batch = book.take_dial_candidates(10, |_| false);
        assert_eq!(batch.len(), 10);
        let groups: std::collections::HashSet<_> = batch.iter().map(|a| netgroup(a)).collect();
        assert_eq!(groups.len(), 10, "one address per netgroup per batch");
        for a in &batch {
            assert!(!book.contains(a), "dialed candidates leave the new table");
        }
    }

    /// NET-11: tried table keeps at most TRIED_PER_NETGROUP per /16 (now the
    /// keyed TriedTable: a netgroup reaches TRIED_BUCKETS_PER_GROUP buckets).
    #[test]
    fn tried_table_netgroup_cap() {
        let now = Instant::now();
        let mut tried = TriedTable::with_key(super::super::addrbook::random_key());
        for i in 0..50u8 {
            tried.insert(&addr(&format!("45.77.{}.1", i)), now);
        }
        assert!(tried.len() <= TRIED_PER_NETGROUP);
        let before = tried.len();
        assert!((0..4u8).any(|i| tried.insert(&addr(&format!("{}.1.1.1", 80 + i)), now) == TriedInsert::Inserted));
        assert_eq!(tried.len(), before + 1);
    }

    /// B1-T8: routability is judged on the IPv4 an IPv6 literal embeds, and
    /// mapped / compatible forms are canonicalised to `/ip4/`.
    #[test]
    fn embedded_ipv4_classification_and_normalisation() {
        let v6 = |s: &str| s.parse::<Ipv6Addr>().unwrap();
        assert_eq!(embedded_ipv4(&v6("::ffff:10.0.0.1")), Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(embedded_ipv4(&v6("::10.0.0.1")), Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(embedded_ipv4(&v6("::ffff:0:10.0.0.1")), Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(embedded_ipv4(&v6("64:ff9b::a00:1")), Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(embedded_ipv4(&v6("2002:a00:1::")), Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(embedded_ipv4(&v6("2001:0:4136:e378:8000:63bf:f5ff:fffe")), Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(embedded_ipv4(&v6("::1")), None);
        assert_eq!(embedded_ipv4(&v6("::")), None);
        assert_eq!(embedded_ipv4(&v6("2606:4700:4700::1111")), None);
        for (ip, class) in [
            ("8.8.8.8", IpClass::Public),
            ("10.1.2.3", IpClass::Private),
            ("100.100.1.1", IpClass::Private),
            ("127.0.0.1", IpClass::Private),
            ("169.254.169.254", IpClass::Invalid),
            ("0.1.2.3", IpClass::Invalid),
            ("240.0.0.1", IpClass::Invalid),
            ("198.18.0.1", IpClass::Invalid),
            ("192.0.0.8", IpClass::Invalid),
            ("::ffff:169.254.169.254", IpClass::Invalid),
            ("::ffff:8.8.8.8", IpClass::Public),
            ("::ffff:127.0.0.1", IpClass::Private),
            ("fd00::1", IpClass::Private),
            ("fec0::1", IpClass::Private),
            ("100::1", IpClass::Invalid),
            ("2001:db8::1", IpClass::Invalid),
            ("64:ff9b:1::1", IpClass::Invalid),
            ("2606:4700:4700::1111", IpClass::Public),
        ] {
            assert_eq!(classify_ip(ip.parse().unwrap()), class, "{ip}");
        }
        let id = PeerId::random();
        assert_eq!(
            normalize_peer_addr(&format!("/ip6/::ffff:45.77.1.2/tcp/1/p2p/{id}")),
            Some(format!("/ip4/45.77.1.2/tcp/1/p2p/{id}"))
        );
        let native = format!("/ip6/2606:4700:4700::1111/tcp/1/p2p/{id}");
        assert_eq!(normalize_peer_addr(&native), Some(native.clone()));
        assert_eq!(normalize_peer_addr("garbage"), None);
    }

    /// NET-11: cap enforcement evicts from the most represented netgroup.
    #[test]
    fn enforce_cap_preserves_diversity() {
        let mut peers = std::collections::HashSet::new();
        for i in 0..KNOWN_PEERS_CAP {
            peers.insert(addr(&format!("45.77.{}.{}", i / 250, i % 250 + 1)));
        }
        let lone = addr("80.1.1.1");
        peers.insert(lone.clone());
        assert_eq!(enforce_cap(&mut peers), 1);
        assert!(peers.contains(&lone), "the only member of its netgroup survives");
    }

    #[test]
    fn lan_filter_accepts_lan_rejects_public() {
        let lan = |s: &str| is_lan_multiaddr(&s.parse::<Multiaddr>().unwrap());
        // LAN / loopback / link-local — mDNS may auto-dial these.
        assert!(lan("/ip4/192.168.1.10/tcp/17110"));
        assert!(lan("/ip4/10.0.0.5/tcp/17110"));
        assert!(lan("/ip4/172.16.3.4/tcp/17110"));
        assert!(lan("/ip4/127.0.0.1/tcp/17110"));
        assert!(lan("/ip4/169.254.1.1/tcp/17110"));
        assert!(lan("/ip6/::1/tcp/17110"));
        assert!(lan("/ip6/fe80::1/tcp/17110"));
        // Public IPs — an mDNS record naming these is a reflection/SSRF attempt.
        assert!(!lan("/ip4/8.8.8.8/tcp/17110"));
        assert!(!lan("/ip4/1.1.1.1/tcp/443"));
        assert!(!lan("/ip6/2606:4700:4700::1111/tcp/443"));
    }
}
