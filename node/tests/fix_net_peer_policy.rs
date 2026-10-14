//! Regression tests for the P2P peer-policy fixes (audit NET-5, NET-7, NET-8,
//! NET-9, NET-10, NET-11). Each asserts the FIXED behaviour; the matching
//! proofs of concept in `audit/poc/node/tests/audit_poc_net.rs` asserted the
//! original bugs.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use gnb::network::pex_validator::{netgroup, AddrBook, PexRateLimiter, PexStats, NEW_PER_NETGROUP, PEX_BATCH_LIMIT};
use gnb::network::sync_rr::{
    check_nonempty_frame, decode_response, encode_frame, is_sync_protocol_violation, select_pull_peer,
    PeerSync, PullPeerSelector, SyncRequestLimiter, SyncResponse, MAX_INFLIGHT_PER_PEER,
};
use gnb::network::{
    decode_wire_message, gossip_disposition, ingest_pex_addresses, GossipDisposition, GossipVerdict,
    NetworkMessage, WireDecodeError, WirePenaltyTracker, WireReaction, MAX_WIRE_BYTES,
    WIRE_PENALTY_TRACK_CAP,
};
use gnb::sync::frontier::{FrontierState, MAX_FRONTIER_IN_FLIGHT};
use libp2p::PeerId;

fn enc(m: &NetworkMessage) -> Vec<u8> {
    bincode::serde::encode_to_vec(m, bincode::config::standard()).unwrap()
}

// ── NET-7 ────────────────────────────────────────────────────────────────────

/// NET-7: trailing bytes are rejected, so a request can no longer be made
/// byte-unique to defeat gossipsub de-duplication.
#[test]
fn trailing_bytes_are_rejected() {
    for base in [NetworkMessage::PeerRequest, NetworkMessage::GetTips] {
        let clean = enc(&base);
        for i in 0u32..100 {
            let mut f = clean.clone();
            f.extend_from_slice(&i.to_le_bytes());
            match decode_wire_message(&f) {
                Err(WireDecodeError::TrailingBytes(4)) => {}
                other => panic!("trailing bytes must be rejected, got {:?}", other.map(|m| m.kind_name())),
            }
        }
    }
}

/// NET-7: gossip pulls are never delivered (so never answered with a
/// mesh-wide broadcast) and never relayed.
#[test]
fn gossip_pulls_are_not_served() {
    for m in [
        NetworkMessage::GetTips,
        NetworkMessage::PeerRequest,
        NetworkMessage::GetHeaders { from_blue_score: 0, limit: 2_000, nonce: 9 },
        NetworkMessage::GetBlock { block_hash: [1u8; 32], nonce: 9 },
    ] {
        assert_eq!(gossip_disposition(&m, true, true), GossipDisposition::Drop(GossipVerdict::Ignore));
    }
}

// ── NET-5 ────────────────────────────────────────────────────────────────────

/// NET-5: a rate-limited server answers `Busy`, which is a well-formed answer —
/// the requester decodes it and does not treat it as a protocol violation —
/// and a server that closes the stream without answering (empty frame) is a
/// transport failure, not a violation.
#[test]
fn rate_limited_server_is_not_penalized() {
    let mut lim = SyncRequestLimiter::new();
    let requester = PeerId::random();
    let t0 = Instant::now();
    let mut refused = 0;
    for _ in 0..200 {
        if !lim.allow_at(requester, t0) {
            refused += 1;
        }
    }
    assert!(refused > 0, "an IBD-sized burst does hit the server's limiter");
    // What the server now sends instead of dropping the channel:
    let busy = encode_frame(&SyncResponse::Busy).unwrap();
    assert_eq!(decode_response(&busy).expect("Busy decodes"), SyncResponse::Busy);
    // And the old failure mode (no answer at all) is not a violation either.
    let eof = check_nonempty_frame(Vec::new()).unwrap_err();
    assert!(!is_sync_protocol_violation(&eof));
    // A Busy answer puts the server on a short back-off, not a stall penalty.
    let server = PeerId::random();
    let mut sel = PullPeerSelector::new(HashSet::new());
    sel.on_connect(server);
    sel.on_sent(server, t0);
    sel.on_busy(&server, t0);
    assert!(sel.is_cooling_down(&server, t0));
    assert!(!sel.is_cooling_down(&server, t0 + Duration::from_secs(3)));
}

/// NET-5: the client caps in-flight requests per peer, spreading a burst.
#[test]
fn client_caps_in_flight_per_peer() {
    let (a, b) = (PeerId::random(), PeerId::random());
    let mut sel = PullPeerSelector::new(HashSet::new());
    sel.on_connect(a);
    sel.on_connect(b);
    let now = Instant::now();
    let mut sent = 0;
    while let Some(p) = sel.select(now, &[]) {
        sel.on_sent(p, now);
        sent += 1;
    }
    assert_eq!(sent, 2 * MAX_INFLIGHT_PER_PEER as usize);
    assert_eq!(sel.in_flight(&a), MAX_INFLIGHT_PER_PEER);
    assert_eq!(sel.in_flight(&b), MAX_INFLIGHT_PER_PEER);
}

// ── NET-8 ────────────────────────────────────────────────────────────────────

/// NET-8: after 1,024 free identities, a fresh honest peer is still served.
#[test]
fn sync_limiter_never_locks_out_newcomers() {
    let mut lim = SyncRequestLimiter::new();
    let t0 = Instant::now();
    for i in 0..1024u64 {
        assert!(lim.allow_at(PeerId::random(), t0 + Duration::from_micros(i)));
    }
    // The PoC waited 1.5 s and the newcomer was still refused forever. Now it
    // is served once the (global, aggregate) budget has refilled.
    let honest_newcomer = PeerId::random();
    for i in 0..10u64 {
        assert!(lim.allow_at(honest_newcomer, t0 + Duration::from_millis(1_500 + i)), "new honest peer must be served");
    }
    assert!(lim.tracked_peers() <= 1024);
}

/// NET-8: after the penalty tracker saturates, a new offender still
/// accumulates to the graylist (it used to stay at −100 forever).
#[test]
fn penalty_tracker_saturation_does_not_shield_offenders() {
    let mut t = WirePenaltyTracker::new();
    let bad = vec![0u8; MAX_WIRE_BYTES + 1];
    for _ in 0..WIRE_PENALTY_TRACK_CAP {
        t.classify(PeerId::random(), &bad);
    }
    let offender = PeerId::random();
    let mut worst = 0.0f64;
    for _ in 0..10 {
        if let WireReaction::Penalize { score, .. } = t.classify(offender, &bad) {
            worst = worst.min(score);
        }
    }
    assert!(worst <= -400.0, "offender must cross graylist (−400), got {worst}");
    assert_eq!(t.tracked_peers(), WIRE_PENALTY_TRACK_CAP);
}

// ── NET-9 ────────────────────────────────────────────────────────────────────

/// NET-9: a peer that self-declares "archival" and announces a huge score no
/// longer captures every pull.
#[test]
fn self_declared_archival_does_not_capture_pulls() {
    let honest = PeerId::random();
    let attacker = PeerId::random();
    let mut peers = HashMap::new();
    peers.insert(honest, PeerSync { blue_score: 50_010, archival: Some(true) });
    peers.insert(attacker, PeerSync { blue_score: 1_050_000, archival: Some(true) });
    let explicit = HashSet::from([honest]);
    assert_eq!(select_pull_peer(&peers, &explicit), Some(honest));

    // The live selector rotates regardless of anything a peer claims.
    let mut sel = PullPeerSelector::new(HashSet::new());
    sel.on_connect(honest);
    sel.on_connect(attacker);
    let t0 = Instant::now();
    let mut to_attacker = 0;
    for i in 0..1000u64 {
        let now = t0 + Duration::from_millis(i);
        let p = sel.select(now, &[]).unwrap();
        sel.on_sent(p, now);
        sel.on_success(&p);
        if p == attacker {
            to_attacker += 1;
        }
    }
    assert_eq!(to_attacker, 500, "pulls are shared, not captured");
}

/// NET-9: a stalling peer (timeouts) is detected and rotated away from.
#[test]
fn stalling_peer_is_rotated_out() {
    let staller = PeerId::random();
    let good = PeerId::random();
    let mut sel = PullPeerSelector::new(HashSet::new());
    sel.on_connect(staller);
    sel.on_connect(good);
    let t0 = Instant::now();
    for _ in 0..gnb::network::sync_rr::STALL_FAILURES {
        sel.on_sent(staller, t0);
        sel.on_failure(&staller, t0);
    }
    for i in 0..20u64 {
        let now = t0 + Duration::from_millis(i);
        assert_eq!(sel.select(now, &[]), Some(good));
        sel.on_sent(good, now);
        sel.on_success(&good);
    }
}

/// NET-9: one peer answering NotFound repeatedly cannot abandon a tip.
#[test]
fn single_peer_not_found_cannot_abandon_tip() {
    let mut fr = FrontierState::new();
    let tip = [7u8; 32];
    let now = Instant::now();
    fr.to_request(&[tip], |_| false, now);
    let liar = PeerId::random();
    for _ in 0..50 {
        fr.note_not_found_from(&tip, liar, now);
    }
    assert!(!fr.is_abandoned(&tip));
}

// ── NET-10 ───────────────────────────────────────────────────────────────────

/// NET-10: 2,000 frames of 256 fake tips cannot create more than the global
/// cap of in-flight entries (and GetBlocks).
#[test]
fn frontier_state_is_bounded() {
    let mut fr = FrontierState::new();
    let now = Instant::now();
    let mut getblocks = 0usize;
    for frame in 0u32..2000 {
        let tips: Vec<[u8; 32]> = (0u32..256)
            .map(|i| {
                let mut h = [0u8; 32];
                h[..4].copy_from_slice(&frame.to_le_bytes());
                h[4..8].copy_from_slice(&i.to_le_bytes());
                h
            })
            .collect();
        getblocks += fr.to_request(&tips, |_| false, now).len();
    }
    assert_eq!(fr.outstanding(), MAX_FRONTIER_IN_FLIGHT);
    assert_eq!(getblocks, MAX_FRONTIER_IN_FLIGHT);
}

// ── NET-11 ───────────────────────────────────────────────────────────────────

/// NET-11: peer-exchange addresses only ever enter the bounded address table
/// (nothing here can dial), capped per message, per author and per /16.
#[test]
fn pex_addresses_go_to_a_diverse_bounded_table() {
    let mut book = AddrBook::new();
    let mut lim = PexRateLimiter::new();
    let mut stats = PexStats::new();
    let me = PeerId::random();
    let author = PeerId::random();
    // 20 addresses, all in ONE /16 (an eclipse attempt).
    let same_group: Vec<String> = (0..20u8)
        .map(|i| format!("/ip4/45.77.{}.1/tcp/17110/p2p/{}", i, PeerId::random()))
        .collect();
    let added = ingest_pex_addresses(&mut book, &mut lim, &mut stats, author, &same_group, false, &me, &HashSet::new());
    assert_eq!(added, NEW_PER_NETGROUP, "one /16 fills at most NEW_PER_NETGROUP slots");
    // A dial batch takes at most one address per netgroup.
    let batch = book.take_dial_candidates(4, |_| false);
    assert_eq!(batch.len(), 1);
    assert_eq!(netgroup(&batch[0]), netgroup(&same_group[0]));
    // Oversized message: batch-capped.
    let many: Vec<String> = (0..100u8)
        .map(|i| format!("/ip4/{}.9.1.1/tcp/17110/p2p/{}", 20 + i, PeerId::random()))
        .collect();
    let other_author = PeerId::random();
    let added = ingest_pex_addresses(&mut book, &mut lim, &mut stats, other_author, &many, false, &me, &HashSet::new());
    assert_eq!(added, PEX_BATCH_LIMIT);
}
