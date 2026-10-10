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
//! 3. **Per-peer budget** for UNSOLICITED blocks: a token bucket of
//!    [`BUDGET_BURST`] evaluations refilled at [`BUDGET_REFILL_PER_SEC`].
//!    Blocks this node requested (directed pulls) are not budgeted — the node
//!    controls that rate — but are still verified and still accountable.
//! 4. The proof is evaluated off the event loop, on a bounded worker pool
//!    (in parallel across cores — this is also what speeds up sync).
//! 5. **Invalid proof ⇒ ban.** Gossip is validated before it is relayed
//!    (`validate_messages`), so an honest peer never forwards an unverified
//!    block: the peer that delivered an invalid proof is the one at fault.

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use libp2p::PeerId;

use crate::core::{self, Block};

/// Burst of unsolicited proof evaluations a peer may trigger.
pub const BUDGET_BURST: f64 = 32.0;
/// Sustained unsolicited evaluations per second per peer (30 per minute,
/// about 15 s of CPU per minute at 0.5 s each). Honest gossip is one block
/// every ~30 s.
pub const BUDGET_REFILL_PER_SEC: f64 = 0.5;
/// How long a peer that delivered an invalid proof is banned.
pub const BAN_DURATION: Duration = Duration::from_secs(24 * 60 * 60);
/// Bound on tracked peers (budgets), so the map itself is not a DoS target.
const MAX_TRACKED: usize = 4096;

/// Per-peer budgets and bans.
#[derive(Default)]
pub struct PowGate {
    budgets: HashMap<PeerId, (f64, Instant)>,
    bans: HashMap<PeerId, Instant>,
}

impl PowGate {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_banned(&self, peer: &PeerId, now: Instant) -> bool {
        self.bans.get(peer).is_some_and(|until| now < *until)
    }

    /// Take one evaluation from `peer`'s budget; `false` when exhausted.
    pub fn take(&mut self, peer: &PeerId, now: Instant) -> bool {
        if !self.budgets.contains_key(peer) && self.budgets.len() >= MAX_TRACKED {
            // Forget the stalest budget; a forgotten peer restarts full,
            // which only matters for peers idle long enough to be stalest.
            if let Some(oldest) = self.budgets.iter().min_by_key(|(_, (_, t))| *t).map(|(p, _)| *p) {
                self.budgets.remove(&oldest);
            }
        }
        let (tokens, last) = self.budgets.entry(*peer).or_insert((BUDGET_BURST, now));
        let refill = now.saturating_duration_since(*last).as_secs_f64() * BUDGET_REFILL_PER_SEC;
        *tokens = (*tokens + refill).min(BUDGET_BURST);
        *last = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }

    pub fn ban(&mut self, peer: &PeerId, now: Instant) {
        self.bans.insert(*peer, now + BAN_DURATION);
        self.budgets.remove(peer);
    }

    /// Remove and return bans that have expired (to lift transport-level
    /// blacklists).
    pub fn expire_bans(&mut self, now: Instant) -> Vec<PeerId> {
        let expired: Vec<PeerId> = self.bans.iter()
            .filter(|(_, until)| now >= **until)
            .map(|(p, _)| *p)
            .collect();
        for p in &expired {
            self.bans.remove(p);
        }
        expired
    }
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
            assert!(g.take(&p, t0));
        }
        assert!(!g.take(&p, t0), "burst exhausted");
        assert!(!g.take(&p, t0 + Duration::from_millis(1500)), "not yet a full token");
        assert!(g.take(&p, t0 + Duration::from_secs(2)), "one token after 2 s");
        assert!(!g.take(&p, t0 + Duration::from_secs(2)));
    }

    #[test]
    fn budgets_are_per_peer() {
        let mut g = PowGate::new();
        let (a, b) = (PeerId::random(), PeerId::random());
        let t0 = Instant::now();
        for _ in 0..BUDGET_BURST as usize { g.take(&a, t0); }
        assert!(!g.take(&a, t0));
        assert!(g.take(&b, t0), "another peer is unaffected");
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
            g.take(&PeerId::random(), t0 + Duration::from_millis(i as u64));
        }
        assert!(g.budgets.len() <= MAX_TRACKED);
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
