//! Disconnecting and discouraging misbehaving peers (re-audit B1-T2).
//!
//! The node keeps ONE misbehaviour score per peer: the decaying application
//! score of [`super::WirePenaltyTracker`], which every offence feeds — gossip
//! wire violations, a gossip frame the processor judged `Reject` (gossipsub's
//! invalid-delivery penalty applies too), a `/gnb/sync/1` answer that breaks
//! the request/response contract or the wire bounds, a malformed request,
//! an invalid block sent as the answer to our own pull, an invalid orphan
//! transaction (MEM-6). Before, that score only ever moved gossipsub's
//! application score: nothing closed a connection, and the directed-sync
//! client did not look at it, so a graylisted peer kept answering pulls.
//!
//! Bitcoin Core's model (`Misbehaving` → `fShouldDiscourage` →
//! `MaybeDiscourageAndDisconnect`, `BanMan::Discourage`): a peer that
//! crosses the threshold is disconnected and discouraged. Here a peer whose
//! score reaches [`MISBEHAVIOUR_DISCONNECT_SCORE`] (gossipsub's graylist
//! threshold: four offences within the score's decay) is disconnected and
//! its identity refused on reconnect for [`DISCOURAGE_TTL`]. Identities are
//! free, so this costs an attacker a new identity and handshake per four
//! offences; address-based discouragement (Core's rolling filter of
//! discouraged addresses) is the connection-management layer's (package
//! R2b/R3) to add on top of [`Discouraged`].

use std::collections::HashMap;
use std::time::{Duration, Instant};

use libp2p::PeerId;

/// A peer whose cumulative misbehaviour score is at or below this is
/// disconnected and discouraged. Equal to gossipsub's `graylist_threshold`
/// (`network::run_inner`), so a peer is graylisted and disconnected at the
/// same point.
pub const MISBEHAVIOUR_DISCONNECT_SCORE: f64 = -400.0;
/// How long a discouraged identity is refused.
pub const DISCOURAGE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// Max discouraged identities remembered (oldest forgotten first).
pub const MAX_DISCOURAGED: usize = 4096;

/// Whether a misbehaviour score warrants disconnecting the peer.
pub fn should_disconnect(score: f64) -> bool {
    score <= MISBEHAVIOUR_DISCONNECT_SCORE
}

/// Discouraged peer identities, bounded by [`MAX_DISCOURAGED`] and
/// [`DISCOURAGE_TTL`].
#[derive(Debug, Default)]
pub struct Discouraged {
    since: HashMap<PeerId, Instant>,
}

impl Discouraged {
    pub fn new() -> Self {
        Self::default()
    }

    /// Discourage `peer` from `now`. Returns the identities forgotten to make
    /// room (expired first, then the oldest), which the caller unblocks.
    pub fn insert(&mut self, peer: PeerId, now: Instant) -> Vec<PeerId> {
        let mut forgotten = Vec::new();
        if !self.since.contains_key(&peer) && self.since.len() >= MAX_DISCOURAGED {
            forgotten = self.expire(now);
            if self.since.len() >= MAX_DISCOURAGED {
                if let Some(oldest) = self.since.iter().min_by_key(|(p, t)| (**t, p.to_bytes())).map(|(p, _)| *p) {
                    self.since.remove(&oldest);
                    forgotten.push(oldest);
                }
            }
        }
        self.since.insert(peer, now);
        forgotten
    }

    /// Forget identities discouraged [`DISCOURAGE_TTL`] ago or longer;
    /// returns them (the caller unblocks them).
    pub fn expire(&mut self, now: Instant) -> Vec<PeerId> {
        let gone: Vec<PeerId> = self
            .since
            .iter()
            .filter(|(_, t)| now.saturating_duration_since(**t) >= DISCOURAGE_TTL)
            .map(|(p, _)| *p)
            .collect();
        for p in &gone {
            self.since.remove(p);
        }
        gone
    }

    /// Whether `peer` is discouraged at `now`.
    pub fn contains(&self, peer: &PeerId, now: Instant) -> bool {
        self.since.get(peer).is_some_and(|t| now.saturating_duration_since(*t) < DISCOURAGE_TTL)
    }

    /// Identities remembered.
    #[allow(dead_code)] // library API and tests; the node binary compiles this module too
    pub fn len(&self) -> usize {
        self.since.len()
    }

    #[allow(dead_code)] // library API and tests; the node binary compiles this module too
    pub fn is_empty(&self) -> bool {
        self.since.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threshold_is_four_offences() {
        let mut t = super::super::WirePenaltyTracker::new();
        let p = PeerId::random();
        let now = Instant::now();
        let scores: Vec<f64> = (0..4).map(|_| t.record_violation_at(p, now)).collect();
        assert!(!scores[..3].iter().any(|s| should_disconnect(*s)));
        assert!(should_disconnect(scores[3]));
    }

    #[test]
    fn discouragement_expires_and_is_bounded() {
        let mut d = Discouraged::new();
        let t0 = Instant::now();
        let p = PeerId::random();
        assert!(d.insert(p, t0).is_empty());
        assert!(d.contains(&p, t0 + DISCOURAGE_TTL - Duration::from_secs(1)));
        assert!(!d.contains(&p, t0 + DISCOURAGE_TTL));
        let mut forgotten = Vec::new();
        for i in 0..(MAX_DISCOURAGED + 10) {
            forgotten.extend(d.insert(PeerId::random(), t0 + Duration::from_millis(i as u64 + 1)));
        }
        assert_eq!(d.len(), MAX_DISCOURAGED);
        assert_eq!(forgotten.len(), 11);
        assert_eq!(forgotten[0], p, "the oldest entry was forgotten first");
        assert!(!d.contains(&p, t0));
        let expired = d.expire(t0 + DISCOURAGE_TTL + Duration::from_secs(10));
        assert_eq!(expired.len(), MAX_DISCOURAGED);
        assert!(d.is_empty());
    }
}
