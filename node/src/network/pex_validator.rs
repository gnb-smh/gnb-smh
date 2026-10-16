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
//!    a bounded, netgroup-diverse "new" table ([`AddrBook`]); the network loop
//!    dials a few of them per tick, one per /16 at most, only while it is
//!    below its peer target. Rate limits are keyed by the AUTHOR of the
//!    message, and the persisted known-peers ("tried") table keeps at most
//!    [`TRIED_PER_NETGROUP`] entries per /16.

use libp2p::{Multiaddr, PeerId, multiaddr::Protocol};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

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

/// NET-11: capacity of the in-memory "new" (unverified) address table.
pub const NEW_TABLE_CAP: usize = 1024;
/// NET-11: at most this many "new" addresses per netgroup (/16, /32 v6, DNS name).
pub const NEW_PER_NETGROUP: usize = 8;
/// NET-11: at most this many persisted ("tried") known peers per netgroup.
pub const TRIED_PER_NETGROUP: usize = 16;

// ── Address validation ───────────────────────────────────────────────────────

/// Checks whether a string multiaddr is acceptable as a PEX suggestion
/// or a known_peers entry.
///
/// Rules:
/// - Must parse as a valid libp2p Multiaddr
/// - Must contain /tcp/ (we don't PEX QUIC/WebTransport yet)
/// - Must end in exactly ONE /p2p/<peer_id> component (need to know who
///   we're dialing — and the canonical form has the peer id LAST, once)
/// - Must fit MAX_WIRE_ADDR_LEN (an entry the wire bound forbids can never
///   be exchanged, and carrying it in a PeerExchange graylists the sender)
/// - IP must not be loopback, link-local, or unspecified
/// - When `allow_private=false`: rejects RFC1918 (private networks)
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

    let mut has_tcp = false;
    let mut p2p_count = 0usize;
    let mut last_is_p2p = false;
    let mut ip_ok = false;

    for proto in ma.iter() {
        last_is_p2p = matches!(proto, Protocol::P2p(_));
        match proto {
            Protocol::Ip4(ip) => {
                ip_ok = is_acceptable_ipv4(&ip, allow_private);
                if !ip_ok { return false; }
            }
            Protocol::Ip6(ip) => {
                ip_ok = is_acceptable_ipv6(&ip, allow_private);
                if !ip_ok { return false; }
            }
            Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_) => {
                // DNS names are opaque here — accept as IP-proxy.
                // Worst case, resolution fails at dial time.
                ip_ok = true;
            }
            Protocol::Tcp(_) => has_tcp = true,
            Protocol::P2p(_) => p2p_count += 1,
            _ => {}
        }
    }

    ip_ok && has_tcp && p2p_count == 1 && last_is_p2p
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

fn is_acceptable_ipv4(ip: &Ipv4Addr, allow_private: bool) -> bool {
    // Always reject these, regardless of allow_private
    if ip.is_unspecified()      { return false; } // 0.0.0.0
    if ip.is_broadcast()        { return false; } // 255.255.255.255
    if ip.is_multicast()        { return false; } // 224.0.0.0/4
    if ip.is_documentation()    { return false; } // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
    if ip.is_link_local()       { return false; } // 169.254.0.0/16

    // Reject private networks unless explicitly allowed (dev/test mode)
    if !allow_private {
        if ip.is_loopback()     { return false; } // 127.0.0.0/8
        if ip.is_private()      { return false; } // 10.x, 172.16-31.x, 192.168.x
        // 100.64.0.0/10 (CGNAT) — stdlib doesn't have this
        let o = ip.octets();
        if o[0] == 100 && (o[1] & 0xc0) == 0x40 { return false; }
    }
    true
}

fn is_acceptable_ipv6(ip: &Ipv6Addr, allow_private: bool) -> bool {
    if ip.is_unspecified()   { return false; } // ::
    if ip.is_multicast()     { return false; } // ff00::/8

    if !allow_private {
        if ip.is_loopback()  { return false; } // ::1
        // ULA (Unique Local Address) fc00::/7
        let seg = ip.segments();
        if (seg[0] & 0xfe00) == 0xfc00 { return false; }
        // Link-local fe80::/10
        if (seg[0] & 0xffc0) == 0xfe80 { return false; }
    }
    true
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

/// NET-11: insert a CONFIRMED (dialed and connected) address into the
/// persisted known-peers table, keeping at most [`TRIED_PER_NETGROUP`]
/// entries per netgroup (an older entry of the same group makes room) and the
/// global [`KNOWN_PEERS_CAP`]. Returns `true` if the address is now present.
pub fn add_tried(peers: &mut std::collections::HashSet<String>, addr: String) -> bool {
    if peers.contains(&addr) {
        return true;
    }
    let group = netgroup(&addr).unwrap_or_default();
    let same: Vec<String> = peers
        .iter()
        .filter(|a| netgroup(a).unwrap_or_default() == group)
        .cloned()
        .collect();
    if same.len() >= TRIED_PER_NETGROUP {
        if let Some(v) = same.into_iter().min() {
            peers.remove(&v);
        }
    }
    peers.insert(addr.clone());
    enforce_cap(peers);
    peers.contains(&addr)
}

/// NET-11: the "netgroup" of an address string — the bucket used for
/// diversity limits. IPv4: the /16; IPv6: the /32; DNS: the host name.
/// `None` for unparseable strings.
pub fn netgroup(addr: &str) -> Option<String> {
    let ma: Multiaddr = addr.parse().ok()?;
    for proto in ma.iter() {
        match proto {
            Protocol::Ip4(ip) => {
                let o = ip.octets();
                return Some(format!("ip4:{}.{}", o[0], o[1]));
            }
            Protocol::Ip6(ip) => {
                let s = ip.segments();
                return Some(format!("ip6:{:x}:{:x}", s[0], s[1]));
            }
            Protocol::Dns(h) | Protocol::Dns4(h) | Protocol::Dns6(h) => {
                return Some(format!("dns:{}", h.to_ascii_lowercase()));
            }
            _ => {}
        }
    }
    None
}

/// The `/p2p/<peer id>` of an address string, if any.
pub fn addr_peer_id(addr: &str) -> Option<PeerId> {
    let ma: Multiaddr = addr.parse().ok()?;
    ma.iter().find_map(|p| match p {
        Protocol::P2p(id) => Some(id),
        _ => None,
    })
}

/// NET-11: the bounded, netgroup-diverse table of UNVERIFIED addresses learned
/// from peer exchange. Nothing here is persisted and nothing is dialed on
/// receipt: the network loop pulls a few candidates per tick with
/// [`AddrBook::take_dial_candidates`] (at most one per netgroup per batch).
/// A successful outbound connection promotes the address to the persisted
/// "tried" table ([`add_tried`]).
#[derive(Default, Debug)]
pub struct AddrBook {
    /// address -> (netgroup, insertion sequence)
    entries: HashMap<String, (String, u64)>,
    per_group: HashMap<String, usize>,
    seq: u64,
}

impl AddrBook {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn contains(&self, addr: &str) -> bool {
        self.entries.contains_key(addr)
    }

    /// Add one validated candidate. Returns `true` if it was inserted. A full
    /// netgroup refuses the newcomer; a full table evicts its OLDEST entry
    /// from the largest netgroup.
    pub fn add(&mut self, addr: &str) -> bool {
        if self.entries.contains_key(addr) {
            return false;
        }
        let Some(group) = netgroup(addr) else { return false };
        if self.per_group.get(&group).copied().unwrap_or(0) >= NEW_PER_NETGROUP {
            return false;
        }
        if self.entries.len() >= NEW_TABLE_CAP {
            let biggest = self.per_group.iter().max_by_key(|(_, n)| **n).map(|(g, _)| g.clone());
            let victim = biggest.and_then(|g| {
                self.entries
                    .iter()
                    .filter(|(_, (eg, _))| *eg == g)
                    .min_by_key(|(_, (_, seq))| *seq)
                    .map(|(a, _)| a.clone())
            });
            match victim {
                Some(v) => self.remove(&v),
                None => return false,
            }
        }
        self.seq = self.seq.wrapping_add(1);
        *self.per_group.entry(group.clone()).or_insert(0) += 1;
        self.entries.insert(addr.to_string(), (group, self.seq));
        true
    }

    pub fn remove(&mut self, addr: &str) {
        if let Some((g, _)) = self.entries.remove(addr) {
            if let Some(n) = self.per_group.get_mut(&g) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    self.per_group.remove(&g);
                }
            }
        }
    }

    /// Remove and return up to `n` dial candidates, oldest first, at most one
    /// per netgroup. Entries for which `skip` returns true (already connected,
    /// already known, ourselves) are dropped from the table as well — there is
    /// no reason to dial them later either.
    pub fn take_dial_candidates<F: Fn(&str) -> bool>(&mut self, n: usize, skip: F) -> Vec<String> {
        let mut ordered: Vec<(&String, &(String, u64))> = self.entries.iter().collect();
        ordered.sort_by_key(|(_, (_, seq))| *seq);
        let mut groups_used = std::collections::HashSet::new();
        let mut out = Vec::new();
        let mut stale = Vec::new();
        for (addr, (group, _)) in ordered {
            if out.len() >= n {
                break;
            }
            if skip(addr) {
                stale.push(addr.clone());
                continue;
            }
            if !groups_used.insert(group.clone()) {
                continue;
            }
            out.push(addr.clone());
        }
        for a in out.iter().chain(stale.iter()) {
            self.remove(a);
        }
        out
    }
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

    /// NET-11: tried table keeps at most TRIED_PER_NETGROUP per /16.
    #[test]
    fn tried_table_netgroup_cap() {
        let mut tried = std::collections::HashSet::new();
        for i in 0..50u8 {
            add_tried(&mut tried, addr(&format!("45.77.{}.1", i)));
        }
        assert_eq!(tried.len(), TRIED_PER_NETGROUP);
        assert!(add_tried(&mut tried, addr("80.1.1.1")));
        assert_eq!(tried.len(), TRIED_PER_NETGROUP + 1);
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
