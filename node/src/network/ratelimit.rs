//! Bounded, decaying per-key token buckets (audit NET-8 / NET-11).
//!
//! Every per-peer limiter in the network layer used to be a `HashMap` that
//! either never evicted (`SyncRequestLimiter`: after 1,024 identities every
//! newcomer was refused forever) or evicted nothing and kept late offenders
//! un-tracked (`WirePenaltyTracker`). This is the shared building block that
//! replaces them: a token bucket per key, a hard cap on the number of tracked
//! keys, and eviction that prefers idle keys (bucket full again) and then the
//! least-recently-used one. Time is always passed in, so behaviour is
//! deterministic in tests.
//!
//! Evicting a key can only ever GRANT that key a fresh full bucket; it never
//! refuses a key it has not seen. Identity cycling therefore buys an attacker
//! nothing it could not get by opening a new connection, which libp2p's
//! connection limits already bound.

use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug)]
struct Bucket {
    tokens: f64,
    last_refill: Instant,
    last_used: Instant,
}

/// Per-key token buckets with a bounded key set.
#[derive(Debug)]
pub struct TokenBuckets<K: Hash + Eq + Copy> {
    capacity: f64,
    refill_per_sec: f64,
    max_tracked: usize,
    buckets: HashMap<K, Bucket>,
}

impl<K: Hash + Eq + Copy> TokenBuckets<K> {
    /// `capacity` = burst, `refill_per_sec` = sustained rate, `max_tracked` =
    /// hard bound on the number of keys held in memory (>= 1).
    pub fn new(capacity: u32, refill_per_sec: f64, max_tracked: usize) -> Self {
        Self {
            capacity: f64::from(capacity.max(1)),
            refill_per_sec: if refill_per_sec.is_finite() && refill_per_sec > 0.0 { refill_per_sec } else { 0.0 },
            max_tracked: max_tracked.max(1),
            buckets: HashMap::new(),
        }
    }

    /// Consume one token for `key` at `now`. Returns `false` when the key's
    /// bucket is empty. Never refuses a key merely because the map is full.
    pub fn allow_at(&mut self, key: K, now: Instant) -> bool {
        self.allow_n_at(key, 1, now) == 1
    }

    /// Consume up to `n` tokens for `key` at `now`; returns how many were
    /// granted (0..=n).
    pub fn allow_n_at(&mut self, key: K, n: usize, now: Instant) -> usize {
        if !self.buckets.contains_key(&key) && self.buckets.len() >= self.max_tracked {
            self.evict_one(now);
        }
        let cap = self.capacity;
        let rate = self.refill_per_sec;
        let b = self.buckets.entry(key).or_insert(Bucket { tokens: cap, last_refill: now, last_used: now });
        let elapsed = now.saturating_duration_since(b.last_refill).as_secs_f64();
        if elapsed > 0.0 {
            b.tokens = (b.tokens + elapsed * rate).min(cap);
            b.last_refill = now;
        }
        b.last_used = now;
        let avail = b.tokens.floor().max(0.0);
        let granted = (n as f64).min(avail);
        b.tokens -= granted;
        granted as usize
    }

    /// Consume exactly `n` tokens for `key` at `now`, or none at all.
    /// Returns `true` iff all `n` were available (MEM-5: a transaction's
    /// signature checks are charged as one unit — a partial grant would let
    /// the work run while charging less than its cost).
    pub fn try_take_n_at(&mut self, key: K, n: usize, now: Instant) -> bool {
        if !self.buckets.contains_key(&key) && self.buckets.len() >= self.max_tracked {
            self.evict_one(now);
        }
        let cap = self.capacity;
        let rate = self.refill_per_sec;
        let b = self.buckets.entry(key).or_insert(Bucket { tokens: cap, last_refill: now, last_used: now });
        let elapsed = now.saturating_duration_since(b.last_refill).as_secs_f64();
        if elapsed > 0.0 {
            b.tokens = (b.tokens + elapsed * rate).min(cap);
            b.last_refill = now;
        }
        b.last_used = now;
        let need = n as f64;
        if b.tokens.floor() >= need {
            b.tokens -= need;
            true
        } else {
            false
        }
    }

    /// Drop keys whose bucket has refilled completely (they carry no state a
    /// fresh bucket would not) or that have been idle for `idle_ttl`.
    pub fn gc_at(&mut self, now: Instant, idle_ttl: Duration) {
        let cap = self.capacity;
        let rate = self.refill_per_sec;
        self.buckets.retain(|_, b| {
            let elapsed = now.saturating_duration_since(b.last_refill).as_secs_f64();
            let full = b.tokens + elapsed * rate >= cap;
            !full && now.saturating_duration_since(b.last_used) < idle_ttl
        });
    }

    /// Number of keys currently tracked.
    pub fn tracked(&self) -> usize {
        self.buckets.len()
    }

    /// Make room for one key: prefer a key whose bucket is full again (idle),
    /// else the least-recently-used key.
    fn evict_one(&mut self, now: Instant) {
        let cap = self.capacity;
        let rate = self.refill_per_sec;
        let idle = self.buckets.iter().find(|(_, b)| {
            let elapsed = now.saturating_duration_since(b.last_refill).as_secs_f64();
            b.tokens + elapsed * rate >= cap
        }).map(|(k, _)| *k);
        let victim = idle.or_else(|| {
            self.buckets.iter().min_by_key(|(_, b)| b.last_used).map(|(k, _)| *k)
        });
        if let Some(k) = victim {
            self.buckets.remove(&k);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_then_refill() {
        let t0 = Instant::now();
        let mut tb: TokenBuckets<u32> = TokenBuckets::new(3, 1.0, 16);
        assert!(tb.allow_at(1, t0));
        assert!(tb.allow_at(1, t0));
        assert!(tb.allow_at(1, t0));
        assert!(!tb.allow_at(1, t0), "burst exhausted");
        assert!(tb.allow_at(1, t0 + Duration::from_secs(1)), "one token refilled after 1s");
        assert!(!tb.allow_at(1, t0 + Duration::from_secs(1)));
    }

    #[test]
    fn full_map_never_locks_out_a_newcomer() {
        let t0 = Instant::now();
        let mut tb: TokenBuckets<u32> = TokenBuckets::new(2, 0.0, 4);
        for k in 0..4 {
            assert!(tb.allow_at(k, t0));
            assert!(tb.allow_at(k, t0)); // exhaust: no refill at rate 0
        }
        assert_eq!(tb.tracked(), 4);
        // Newcomer is served (LRU eviction), map stays bounded.
        assert!(tb.allow_at(99, t0 + Duration::from_millis(1)));
        assert_eq!(tb.tracked(), 4);
    }

    #[test]
    fn eviction_prefers_idle_keys() {
        let t0 = Instant::now();
        let mut tb: TokenBuckets<u32> = TokenBuckets::new(2, 1.0, 2);
        assert!(tb.allow_at(1, t0)); // key 1 used once, refills in 1s
        assert!(tb.allow_at(2, t0 + Duration::from_secs(5)));
        assert!(tb.allow_at(2, t0 + Duration::from_secs(5))); // key 2 exhausted
        // At t0+5s key 1 is full again (idle): it is evicted, key 2 keeps its empty bucket.
        assert!(tb.allow_at(3, t0 + Duration::from_secs(5)));
        assert!(!tb.allow_at(2, t0 + Duration::from_secs(5)), "key 2 state survived eviction");
    }

    #[test]
    fn try_take_n_is_all_or_nothing() {
        let t0 = Instant::now();
        let mut tb: TokenBuckets<u32> = TokenBuckets::new(10, 1.0, 16);
        assert!(tb.try_take_n_at(1, 7, t0));
        assert!(!tb.try_take_n_at(1, 4, t0), "only 3 left: nothing is taken");
        assert!(tb.try_take_n_at(1, 3, t0), "the refused request consumed nothing");
        assert!(!tb.try_take_n_at(1, 1, t0));
        assert!(tb.try_take_n_at(1, 2, t0 + Duration::from_secs(2)));
        assert!(!tb.try_take_n_at(2, 11, t0), "more than the burst never passes");
    }

    #[test]
    fn gc_drops_refilled_and_idle_keys() {
        let t0 = Instant::now();
        let mut tb: TokenBuckets<u32> = TokenBuckets::new(4, 1.0, 16);
        tb.allow_at(1, t0);
        tb.allow_n_at(2, 4, t0);
        tb.gc_at(t0 + Duration::from_secs(2), Duration::from_secs(600));
        assert_eq!(tb.tracked(), 1, "key 1 refilled, key 2 still owes tokens");
        tb.gc_at(t0 + Duration::from_secs(700), Duration::from_secs(600));
        assert_eq!(tb.tracked(), 0);
    }
}
