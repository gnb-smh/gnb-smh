//! NET-11 (e): keyed, netgroup-bucketed address tables — Bitcoin Core's
//! `addrman` (src/addrman_impl.h, src/addrman.cpp), scaled to this node.
//!
//! Two tables, as in Core:
//!
//! * the **new** table ([`AddrBook`], in memory) holds UNVERIFIED addresses
//!   learned from peer exchange;
//! * the **tried** table ([`TriedTable`], persisted as `known_peers.json`)
//!   holds addresses this node has connected to OUTBOUND.
//!
//! Each table is split into buckets of fixed-size slots, and where an address
//! goes is decided by a keyed hash ([`AddrKey`], a per-node secret: Core's
//! `nKey`). Placement follows Core:
//!
//! * new: `h1 = H(key, group(addr), group(source)) mod NEW_BUCKETS_PER_SOURCE_GROUP`,
//!   `bucket = H(key, group(source), h1) mod NEW_BUCKET_COUNT` — every
//!   address a peer sends us lands in one of only
//!   [`NEW_BUCKETS_PER_SOURCE_GROUP`] buckets chosen by the SENDER's
//!   netgroup, so one source netgroup can fill at most 1/16 of the table,
//!   however many addresses it sends;
//! * tried: `h1 = H(key, addr) mod TRIED_BUCKETS_PER_GROUP`,
//!   `bucket = H(key, group(addr), h1) mod TRIED_BUCKET_COUNT` — one
//!   netgroup holds at most [`TRIED_BUCKETS_PER_GROUP`] ×
//!   [`TRIED_BUCKET_SIZE`] tried entries;
//! * slot: `H(key, table, bucket, addr) mod bucket size`.
//!
//! Without the secret an attacker cannot predict which bucket or slot its
//! addresses take, so it cannot aim them at the slots of the honest entries
//! it wants to push out. Two deliberate deviations, both documented in
//! docs/RUNNING.md: an occupied keyed slot probes forward to the next free
//! slot of the SAME bucket (the per-source and per-netgroup bucket bounds are
//! unchanged; it only avoids losing addresses to birthday collisions at this
//! small scale), and the new table is not persisted.
//!
//! An occupied tried slot is never overwritten on the spot: as in Core's
//! test-before-evict, the newcomer waits in a small collision queue and a
//! feeler connection tests the current occupant first; only an unreachable
//! occupant is replaced ([`TriedTable::pending_collision`],
//! [`TriedTable::resolve_collision`]).

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use rand::Rng;
use sha2::{Digest, Sha256};

use super::pex_validator::{netgroup, KNOWN_PEERS_CAP, NEW_PER_NETGROUP, NEW_TABLE_CAP, TRIED_PER_NETGROUP};

/// The per-node secret that keys bucket placement and the eviction netgroup
/// order (Core's `nKey` / `nKeyedNetGroup` seed).
pub type AddrKey = [u8; 32];

/// Slots per new-table bucket.
pub const NEW_BUCKET_SIZE: usize = 16;
/// New-table buckets (Core: 1024 × 64).
pub const NEW_BUCKET_COUNT: usize = 64;
/// New-table buckets one SOURCE netgroup can reach (Core: 64 of 1024, i.e. 1/16).
pub const NEW_BUCKETS_PER_SOURCE_GROUP: u64 = 4;
/// Slots per tried-table bucket.
pub const TRIED_BUCKET_SIZE: usize = 8;
/// Tried-table buckets (Core: 256 × 64).
pub const TRIED_BUCKET_COUNT: usize = 125;
/// Tried-table buckets one netgroup can reach (Core: 8).
pub const TRIED_BUCKETS_PER_GROUP: u64 = 2;
/// Core's `ADDRMAN_SET_TRIED_COLLISION_SIZE`.
pub const TRIED_COLLISION_QUEUE: usize = 10;
/// Core's `ADDRMAN_TEST_WINDOW`: a collision whose test never finished is
/// dropped after this long (the occupant stays).
pub const TRIED_COLLISION_TTL: Duration = Duration::from_secs(40 * 60);
/// Core's `ThreadOpenConnections` rule: an address tried less than this long
/// ago is not selected again.
pub const RETRY_INTERVAL: Duration = Duration::from_secs(10 * 60);
/// Core's `ADDRMAN_REPLACEMENT`: a tried occupant that connected
/// successfully less than this long ago is never replaced by a collision
/// newcomer, even if its test-before-evict feeler fails (it may be
/// restarting, briefly unreachable, or DoSed by the attacker who wants its
/// slot).
pub const ADDRMAN_REPLACEMENT: Duration = Duration::from_secs(4 * 60 * 60);

const _: () = assert!(NEW_BUCKET_COUNT * NEW_BUCKET_SIZE == NEW_TABLE_CAP);
const _: () = assert!(TRIED_BUCKET_COUNT * TRIED_BUCKET_SIZE == KNOWN_PEERS_CAP);
const _: () = assert!(TRIED_BUCKETS_PER_GROUP as usize * TRIED_BUCKET_SIZE == TRIED_PER_NETGROUP);

/// A fresh random key (tests; production derives the key from the node's
/// identity with [`derive_key`]).
pub fn random_key() -> AddrKey {
    let mut k = [0u8; 32];
    rand::rng().fill(&mut k);
    k
}

/// The node's address-table key, derived from its secret identity key bytes:
/// stable across restarts (so the persisted tried table keeps its layout),
/// different on every node, and never sent anywhere.
pub fn derive_key(secret: &[u8]) -> AddrKey {
    let mut h = Sha256::new();
    h.update(b"gnb/addrman-key/v1");
    h.update(secret);
    h.finalize().into()
}

/// `H(key, tag, parts…)` truncated to 64 bits (length-prefixed parts).
pub fn keyed_u64(key: &AddrKey, tag: &[u8], parts: &[&[u8]]) -> u64 {
    let mut h = Sha256::new();
    h.update(key);
    h.update((tag.len() as u32).to_le_bytes());
    h.update(tag);
    for p in parts {
        h.update((p.len() as u32).to_le_bytes());
        h.update(p);
    }
    let d = h.finalize();
    u64::from_le_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]])
}

/// New-table bucket of an address of netgroup `addr_group` learned from a
/// peer of netgroup `source_group`.
pub fn new_bucket(key: &AddrKey, addr_group: &str, source_group: &str) -> usize {
    let h1 = keyed_u64(key, b"new1", &[addr_group.as_bytes(), source_group.as_bytes()]) % NEW_BUCKETS_PER_SOURCE_GROUP;
    (keyed_u64(key, b"new2", &[source_group.as_bytes(), &h1.to_le_bytes()]) % NEW_BUCKET_COUNT as u64) as usize
}

/// Tried-table bucket of `addr` (netgroup `addr_group`).
pub fn tried_bucket(key: &AddrKey, addr: &str, addr_group: &str) -> usize {
    let h1 = keyed_u64(key, b"tried1", &[addr.as_bytes()]) % TRIED_BUCKETS_PER_GROUP;
    (keyed_u64(key, b"tried2", &[addr_group.as_bytes(), &h1.to_le_bytes()]) % TRIED_BUCKET_COUNT as u64) as usize
}

/// The keyed slot of `addr` inside `bucket` of a table (`b'N'` new, `b'K'`
/// tried) whose buckets have `size` slots.
pub fn bucket_position(key: &AddrKey, table: u8, bucket: usize, addr: &str, size: usize) -> usize {
    (keyed_u64(key, b"pos", &[&[table], &(bucket as u64).to_le_bytes(), addr.as_bytes()]) % size as u64) as usize
}

/// First free slot of `bucket` starting at the keyed position, or `Err(pos)`
/// with the keyed position when the bucket is full.
fn free_slot(slots: &[Option<String>], bucket: usize, size: usize, pos: usize) -> Result<usize, usize> {
    for i in 0..size {
        let s = bucket * size + (pos + i) % size;
        if slots[s].is_none() {
            return Ok(s);
        }
    }
    Err(bucket * size + pos)
}

/// Uniformly random element of `items` accepted by `accept` (reservoir
/// sampling, one pass).
fn pick<'a, R: Rng + ?Sized, I: Iterator<Item = &'a String>>(
    rng: &mut R,
    items: I,
    accept: impl Fn(&str) -> bool,
) -> Option<String> {
    let mut chosen: Option<&String> = None;
    let mut seen = 0u64;
    for a in items {
        if !accept(a) {
            continue;
        }
        seen += 1;
        if rng.random_range(0..seen) == 0 {
            chosen = Some(a);
        }
    }
    chosen.cloned()
}

// ── New table ────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct NewEntry {
    slot: usize,
    group: String,
}

/// NET-11: the keyed, bucketed table of UNVERIFIED addresses learned from
/// peer exchange (Core's "new" table). Nothing here is persisted and nothing
/// is dialed on receipt: the connection manager selects from it at random
/// ([`AddrBook::select`]), feelers test it, and a successful outbound
/// connection moves an address to the [`TriedTable`]. A full slot range keeps
/// its current entries (Core keeps an occupant that is not "terrible").
#[derive(Debug)]
pub struct AddrBook {
    key: AddrKey,
    slots: Vec<Option<String>>,
    entries: HashMap<String, NewEntry>,
    per_group: HashMap<String, usize>,
}

impl Default for AddrBook {
    fn default() -> Self {
        Self::new()
    }
}

impl AddrBook {
    /// A table with a fresh random key.
    pub fn new() -> Self {
        Self::with_key(random_key())
    }

    /// A table keyed with `key` (the node's [`derive_key`]).
    pub fn with_key(key: AddrKey) -> Self {
        Self { key, slots: vec![None; NEW_BUCKET_COUNT * NEW_BUCKET_SIZE], entries: HashMap::new(), per_group: HashMap::new() }
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

    /// Add `addr` as announced by itself (source = its own netgroup).
    pub fn add(&mut self, addr: &str) -> bool {
        let Some(g) = netgroup(addr) else { return false };
        self.add_from(addr, &g)
    }

    /// Add one validated candidate learned from a peer of netgroup
    /// `source_group`. Returns `true` if it was inserted. Refused: a known
    /// address, an address without a netgroup (host names), a netgroup that
    /// already holds [`NEW_PER_NETGROUP`] entries, and a full bucket.
    pub fn add_from(&mut self, addr: &str, source_group: &str) -> bool {
        if self.entries.contains_key(addr) {
            return false;
        }
        let Some(group) = netgroup(addr) else { return false };
        if self.per_group.get(&group).copied().unwrap_or(0) >= NEW_PER_NETGROUP {
            return false;
        }
        let bucket = new_bucket(&self.key, &group, source_group);
        let pos = bucket_position(&self.key, b'N', bucket, addr, NEW_BUCKET_SIZE);
        let Ok(slot) = free_slot(&self.slots, bucket, NEW_BUCKET_SIZE, pos) else { return false };
        self.slots[slot] = Some(addr.to_string());
        *self.per_group.entry(group.clone()).or_insert(0) += 1;
        self.entries.insert(addr.to_string(), NewEntry { slot, group });
        true
    }

    /// The bucket `addr` occupies, if present.
    pub fn bucket_of(&self, addr: &str) -> Option<usize> {
        self.entries.get(addr).map(|e| e.slot / NEW_BUCKET_SIZE)
    }

    pub fn remove(&mut self, addr: &str) {
        if let Some(e) = self.entries.remove(addr) {
            self.slots[e.slot] = None;
            if let Some(n) = self.per_group.get_mut(&e.group) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    self.per_group.remove(&e.group);
                }
            }
        }
    }

    /// A uniformly random entry accepted by `accept` (Core's `Select`).
    pub fn select<R: Rng + ?Sized>(&self, rng: &mut R, accept: impl Fn(&str) -> bool) -> Option<String> {
        pick(rng, self.entries.keys(), accept)
    }
}

// ── Tried table ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct TriedEntry {
    slot: usize,
    last_try: Option<Instant>,
    /// Last successful outbound connection (Core's `nLastSuccess`).
    last_success: Option<Instant>,
}

/// Result of [`TriedTable::insert`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TriedInsert {
    /// Already in the table.
    Present,
    /// Inserted.
    Inserted,
    /// The address's bucket is full; `existing` (the occupant of its keyed
    /// slot) must be tested before it can be replaced. The pair is queued
    /// (test-before-evict).
    Collision { existing: String },
    /// Not insertable (no netgroup: host name or unparseable).
    Refused,
}

/// NET-11: the keyed, bucketed table of addresses this node has connected to
/// outbound (Core's "tried" table), persisted as `known_peers.json` (a JSON
/// array of address strings, the pre-existing format; the layout is
/// recomputed from the key on load).
#[derive(Debug)]
pub struct TriedTable {
    key: AddrKey,
    slots: Vec<Option<String>>,
    index: HashMap<String, TriedEntry>,
    /// (newcomer, occupant, queued at) — Core's `m_tried_collisions`.
    collisions: VecDeque<(String, String, Instant)>,
}

impl TriedTable {
    pub fn with_key(key: AddrKey) -> Self {
        Self {
            key,
            slots: vec![None; TRIED_BUCKET_COUNT * TRIED_BUCKET_SIZE],
            index: HashMap::new(),
            collisions: VecDeque::new(),
        }
    }

    /// Load persisted entries: each is placed by the key; entries whose
    /// bucket is already full are dropped (as Core does when it re-buckets).
    ///
    /// The persisted form (`known_peers.json`, a plain address list) carries
    /// no success time; every loaded entry did connect successfully in an
    /// earlier run, and counts as having succeeded at load time, so for
    /// [`ADDRMAN_REPLACEMENT`] after a restart no collision can displace it.
    pub fn load<I: IntoIterator<Item = String>>(key: AddrKey, addrs: I) -> Self {
        let mut t = Self::with_key(key);
        let mut sorted: Vec<String> = addrs.into_iter().collect();
        sorted.sort();
        let now = Instant::now();
        for a in sorted {
            let _ = t.place(&a, now);
        }
        t
    }

    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    pub fn contains(&self, addr: &str) -> bool {
        self.index.contains_key(addr)
    }

    /// Every address, sorted (the persisted form).
    pub fn addresses(&self) -> Vec<String> {
        let mut v: Vec<String> = self.index.keys().cloned().collect();
        v.sort();
        v
    }

    /// The persisted form as a set.
    pub fn to_set(&self) -> HashSet<String> {
        self.index.keys().cloned().collect()
    }

    /// The bucket `addr` occupies, if present.
    pub fn bucket_of(&self, addr: &str) -> Option<usize> {
        self.index.get(addr).map(|e| e.slot / TRIED_BUCKET_SIZE)
    }

    /// Place without queuing a collision (load path). `Err(Some(occupant))`
    /// for a full bucket, `Err(None)` for an address with no netgroup.
    fn place(&mut self, addr: &str, success: Instant) -> Result<bool, Option<String>> {
        if let Some(e) = self.index.get_mut(addr) {
            e.last_success = Some(e.last_success.map_or(success, |t| t.max(success)));
            return Ok(false);
        }
        let Some(group) = netgroup(addr) else { return Err(None) };
        let bucket = tried_bucket(&self.key, addr, &group);
        let pos = bucket_position(&self.key, b'K', bucket, addr, TRIED_BUCKET_SIZE);
        match free_slot(&self.slots, bucket, TRIED_BUCKET_SIZE, pos) {
            Ok(slot) => {
                self.slots[slot] = Some(addr.to_string());
                self.index.insert(addr.to_string(), TriedEntry { slot, last_try: None, last_success: Some(success) });
                Ok(true)
            }
            Err(keyed) => Err(self.slots[keyed].clone()),
        }
    }

    /// Insert an address we just connected to outbound (Core's `Good`). A
    /// full bucket never evicts on the spot: the pair is queued for a feeler
    /// test of the occupant ([`TriedInsert::Collision`]).
    pub fn insert(&mut self, addr: &str, now: Instant) -> TriedInsert {
        match self.place(addr, now) {
            Ok(false) => TriedInsert::Present,
            Ok(true) => TriedInsert::Inserted,
            Err(None) => TriedInsert::Refused,
            Err(Some(existing)) => {
                self.expire_collisions(now);
                if !self.collisions.iter().any(|(n, _, _)| n == addr) && self.collisions.len() < TRIED_COLLISION_QUEUE {
                    self.collisions.push_back((addr.to_string(), existing.clone(), now));
                }
                TriedInsert::Collision { existing }
            }
        }
    }

    pub fn remove(&mut self, addr: &str) -> bool {
        match self.index.remove(addr) {
            Some(e) => {
                self.slots[e.slot] = None;
                true
            }
            None => false,
        }
    }

    fn expire_collisions(&mut self, now: Instant) {
        self.collisions.retain(|(_, _, t)| now.saturating_duration_since(*t) < TRIED_COLLISION_TTL);
    }

    /// The oldest queued collision whose occupant should be tested by a
    /// feeler: `(newcomer, occupant)` (Core's `SelectTriedCollision`).
    pub fn pending_collision(&mut self, now: Instant) -> Option<(String, String)> {
        self.expire_collisions(now);
        while let Some((n, e, _)) = self.collisions.front() {
            if self.index.contains_key(e) && !self.index.contains_key(n) {
                return Some((n.clone(), e.clone()));
            }
            self.collisions.pop_front();
        }
        None
    }

    /// Outcome of the feeler test of `occupant` for `newcomer` (Core's
    /// `ResolveCollisions`): a reachable occupant stays and the newcomer is
    /// dropped. An unreachable occupant is replaced by the newcomer (it takes
    /// the occupant's slot — same bucket by construction) only if it has not
    /// connected successfully in the last [`ADDRMAN_REPLACEMENT`]; a recently
    /// good occupant stays and the newcomer is dropped (one failed dial —
    /// a restart, or a DoS timed by the attacker — must not hand its slot
    /// over).
    pub fn resolve_collision(&mut self, newcomer: &str, occupant: &str, occupant_reachable: bool, now: Instant) {
        self.collisions.retain(|(n, e, _)| !(n == newcomer && e == occupant));
        if occupant_reachable || self.index.contains_key(newcomer) {
            return;
        }
        let Some(entry) = self.index.get(occupant) else { return };
        if entry.last_success.is_some_and(|t| now.saturating_duration_since(t) < ADDRMAN_REPLACEMENT) {
            return;
        }
        self.remove(occupant);
        let _ = self.place(newcomer, now);
    }

    /// Queued collisions (tests / diagnostics).
    pub fn collision_count(&self) -> usize {
        self.collisions.len()
    }

    /// Record a connection attempt to `addr` (Core's `Attempt`).
    pub fn mark_attempt(&mut self, addr: &str, now: Instant) {
        if let Some(e) = self.index.get_mut(addr) {
            e.last_try = Some(now);
        }
    }

    /// Whether `addr` was tried less than [`RETRY_INTERVAL`] ago.
    pub fn recently_tried(&self, addr: &str, now: Instant) -> bool {
        self.index
            .get(addr)
            .and_then(|e| e.last_try)
            .is_some_and(|t| now.saturating_duration_since(t) < RETRY_INTERVAL)
    }

    /// A uniformly random entry accepted by `accept` (Core's `Select`).
    pub fn select<R: Rng + ?Sized>(&self, rng: &mut R, accept: impl Fn(&str) -> bool) -> Option<String> {
        pick(rng, self.index.keys(), accept)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::PeerId;

    fn addr(ip: &str) -> String {
        format!("/ip4/{}/tcp/17110/p2p/{}", ip, PeerId::random())
    }

    /// NET-11 (e): bucket placement is keyed — the same addresses land in
    /// different buckets on two nodes, so an attacker cannot predict (and aim
    /// at) the slots of the entries it wants to displace.
    #[test]
    fn bucket_keying_differs_per_node_key() {
        let (k1, k2) = (random_key(), random_key());
        let addrs: Vec<String> = (0..200u8).map(|i| addr(&format!("{}.{}.1.1", 20 + (i % 100), i))).collect();
        let src = "ip4:9.9";
        let differ_new = addrs
            .iter()
            .filter(|a| {
                let g = netgroup(a).unwrap();
                new_bucket(&k1, &g, src) != new_bucket(&k2, &g, src)
            })
            .count();
        let differ_tried = addrs
            .iter()
            .filter(|a| {
                let g = netgroup(a).unwrap();
                tried_bucket(&k1, a, &g) != tried_bucket(&k2, a, &g)
            })
            .count();
        assert!(differ_new > 150, "new-table placement must depend on the key ({differ_new}/200 differ)");
        assert!(differ_tried > 150, "tried-table placement must depend on the key ({differ_tried}/200 differ)");
        // Same key, same placement (the layout survives a restart).
        for a in &addrs {
            let g = netgroup(a).unwrap();
            assert_eq!(new_bucket(&k1, &g, src), new_bucket(&k1, &g, src));
            assert_eq!(tried_bucket(&k1, a, &g), tried_bucket(&k1, a, &g));
        }
        // The key is a secret derived from the identity: different identities,
        // different keys; same identity, same key.
        assert_ne!(derive_key(b"node-a secret"), derive_key(b"node-b secret"));
        assert_eq!(derive_key(b"node-a secret"), derive_key(b"node-a secret"));
    }

    /// NET-11 (e): one SOURCE netgroup can reach only
    /// NEW_BUCKETS_PER_SOURCE_GROUP buckets of the new table (1/16), however
    /// many distinct netgroups its addresses claim: a flood from one peer (or
    /// one /16 of peers) cannot take over the table.
    #[test]
    fn one_source_netgroup_fills_at_most_a_sixteenth_of_the_new_table() {
        let key = random_key();
        let mut book = AddrBook::with_key(key);
        let attacker_source = "ip4:66.66";
        let mut buckets = HashSet::new();
        for a in 0..=255u8 {
            for b in 0..8u8 {
                let ad = addr(&format!("{}.{}.{}.1", 11 + (a % 200), a, b));
                if book.add_from(&ad, attacker_source) {
                    buckets.insert(book.bucket_of(&ad).unwrap());
                }
            }
        }
        assert!(buckets.len() as u64 <= NEW_BUCKETS_PER_SOURCE_GROUP);
        assert!(book.len() <= NEW_BUCKETS_PER_SOURCE_GROUP as usize * NEW_BUCKET_SIZE);
        // Honest addresses from other sources still find room: every one whose
        // keyed bucket is not one of the attacker's few buckets is inserted.
        let mut outside = 0;
        for i in 0..64u8 {
            let src = format!("ip4:{}.1", 100 + i);
            let a = addr(&format!("{}.7.7.7", 30 + i));
            let inserted = book.add_from(&a, &src);
            if !buckets.contains(&new_bucket(&key, &netgroup(&a).unwrap(), &src)) {
                outside += 1;
                assert!(inserted, "an honest address outside the attacker's buckets is never refused");
            }
        }
        assert!(outside >= 40, "most honest sources map outside the attacker's buckets ({outside}/64)");
    }

    /// The tried table bounds each netgroup to TRIED_PER_NETGROUP entries and
    /// never evicts on a full bucket: the collision is queued for a feeler
    /// test of the occupant (test-before-evict).
    #[test]
    fn tried_table_netgroup_cap_and_test_before_evict() {
        let now = Instant::now();
        let mut t = TriedTable::with_key(random_key());
        let mut collisions = 0;
        for i in 0..50u8 {
            match t.insert(&addr(&format!("45.77.{}.1", i)), now) {
                TriedInsert::Collision { .. } => collisions += 1,
                TriedInsert::Inserted => {}
                other => panic!("unexpected {other:?}"),
            }
        }
        assert!(t.len() <= TRIED_PER_NETGROUP, "one /16 holds at most {TRIED_PER_NETGROUP} tried entries");
        assert!(t.len() >= TRIED_BUCKET_SIZE, "a /16 reaches at least one full bucket");
        assert_eq!(collisions, 50 - t.len());
        assert_eq!(t.collision_count(), TRIED_COLLISION_QUEUE, "the collision queue is bounded");
        assert!(
            (0..4u8).any(|i| matches!(t.insert(&addr(&format!("{}.1.1.1", 80 + i)), now), TriedInsert::Inserted)),
            "other netgroups still have room"
        );

        // Test-before-evict: a reachable occupant stays...
        let (newcomer, occupant) = t.pending_collision(now).unwrap();
        t.resolve_collision(&newcomer, &occupant, true, now);
        assert!(t.contains(&occupant) && !t.contains(&newcomer));
        // ...an unreachable one that has not succeeded for ADDRMAN_REPLACEMENT
        // is replaced.
        let (newcomer, occupant) = t.pending_collision(now).unwrap();
        t.resolve_collision(&newcomer, &occupant, false, now + ADDRMAN_REPLACEMENT);
        assert!(!t.contains(&occupant) && t.contains(&newcomer));
        // Stale collisions expire (the occupant stays).
        assert!(t.pending_collision(now + TRIED_COLLISION_TTL).is_none());
    }

    /// Core's `ADDRMAN_REPLACEMENT`: a tried occupant that connected
    /// successfully within the last 4 hours survives a failed
    /// test-before-evict feeler (the newcomer is dropped); one whose last
    /// success is older is replaced. Before the fix ONE failed dial handed
    /// the occupant's slot to the newcomer.
    #[test]
    fn recently_good_occupant_survives_a_failed_feeler() {
        let t0 = Instant::now();
        // A full bucket with one queued (newcomer, occupant) collision.
        let setup = || {
            let mut t = TriedTable::with_key(random_key());
            for i in 0..50u8 {
                t.insert(&addr(&format!("45.77.{}.1", i)), t0);
            }
            let (newcomer, occupant) = t.pending_collision(t0).unwrap();
            (t, newcomer, occupant)
        };
        // The occupant connected again 3 h later; its feeler fails 1 h after.
        let (mut t, newcomer, occupant) = setup();
        let later = t0 + Duration::from_secs(3 * 3600);
        assert_eq!(t.insert(&occupant, later), TriedInsert::Present);
        t.resolve_collision(&newcomer, &occupant, false, later + Duration::from_secs(3600));
        assert!(t.contains(&occupant), "a recently good occupant stays");
        assert!(!t.contains(&newcomer), "the newcomer is dropped");
        // Within ADDRMAN_REPLACEMENT of its last success: kept.
        let (mut t, newcomer, occupant) = setup();
        t.resolve_collision(&newcomer, &occupant, false, t0 + ADDRMAN_REPLACEMENT - Duration::from_secs(1));
        assert!(t.contains(&occupant) && !t.contains(&newcomer), "still within the grace period");
        // Past it: a failed test replaces the occupant.
        let (mut t, newcomer, occupant) = setup();
        t.resolve_collision(&newcomer, &occupant, false, t0 + ADDRMAN_REPLACEMENT);
        assert!(!t.contains(&occupant) && t.contains(&newcomer), "a stale occupant is replaced");
        // Entries loaded from disk count as good at load time.
        let mut loaded = TriedTable::load(random_key(), [addr("80.1.1.1")]);
        let a = loaded.addresses()[0].clone();
        loaded.resolve_collision(&addr("80.1.2.2"), &a, false, Instant::now());
        assert!(loaded.contains(&a), "a persisted entry is not displaced right after a restart");
    }

    /// The persisted tried table reloads into the same layout with the same
    /// key; host names are never loaded.
    #[test]
    fn tried_table_round_trips_through_its_persisted_form() {
        let key = random_key();
        let now = Instant::now();
        let mut t = TriedTable::with_key(key);
        for i in 0..100u8 {
            t.insert(&addr(&format!("{}.{}.3.4", 20 + i, i)), now);
        }
        let mut persisted = t.addresses();
        persisted.push(format!("/dns4/evil.example/tcp/1/p2p/{}", PeerId::random()));
        let back = TriedTable::load(key, persisted);
        assert_eq!(back.addresses(), t.addresses());
        for a in t.addresses() {
            assert_eq!(back.bucket_of(&a), t.bucket_of(&a));
        }
    }

    /// Core's retry spacing: an address tried less than RETRY_INTERVAL ago is
    /// not selected again.
    #[test]
    fn recently_tried_addresses_are_not_reselected() {
        let now = Instant::now();
        let mut t = TriedTable::with_key(random_key());
        let a = addr("80.1.1.1");
        t.insert(&a, now);
        t.mark_attempt(&a, now);
        let mut rng = rand::rng();
        assert_eq!(t.select(&mut rng, |x| !t.recently_tried(x, now + Duration::from_secs(60))), None);
        assert_eq!(t.select(&mut rng, |x| !t.recently_tried(x, now + RETRY_INTERVAL)), Some(a));
    }

    /// Selection is uniform over accepted entries (not oldest-first, which an
    /// attacker could predict).
    #[test]
    fn selection_is_random_over_accepted_entries() {
        let mut book = AddrBook::with_key(random_key());
        let addrs: Vec<String> = (0..40u8).map(|i| addr(&format!("{}.5.5.5", 20 + i))).collect();
        for a in &addrs {
            assert!(book.add(a));
        }
        let mut rng = rand::rng();
        let mut seen = HashSet::new();
        for _ in 0..2000 {
            seen.insert(book.select(&mut rng, |_| true).unwrap());
        }
        assert_eq!(seen.len(), addrs.len(), "every entry is selectable");
        assert_eq!(book.select(&mut rng, |_| false), None);
    }
}
