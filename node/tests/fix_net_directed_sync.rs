//! Phase 4 (package R2a) regressions for the directed-sync CLIENT
//! (`/gnb/sync/1`): re-audit items B1-T2, B1-T6, NET-9 and NET-10.
//!
//! * Every answer is bound to the request it answers (variant, block hash,
//!   header count and range); anything else is a protocol violation that is
//!   neither delivered nor allowed to complete the pull.
//! * Pull selection prefers the peer that announced a block, never sends a
//!   pull back to a peer that already answered it, counts NotFound and wrong
//!   answers against the peer, spaces retries, keeps cooldowns across
//!   reconnects and does not let one peer's answers fill the shared queue.
//! * A discrete-event model with network latency (the earlier tests had
//!   none): a fast attacker (NotFound, wrong-variant answers, stalls,
//!   several identities) against honest servers that rate-limit with the
//!   node's own `SyncRequestLimiter` — every honest pull must complete.
//! * The frontier tracker: one peer cannot fill the in-flight set, inbound
//!   identities cannot abandon a tip, and abandoned tips expire at their TTL.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::time::{Duration, Instant};

use gnb::network::pull::{
    Enqueued, FailureKind, PullScheduler, MAX_PENDING_INBOUND_ATTRIBUTED, MAX_PENDING_PER_SOURCE, MAX_PENDING_PULLS,
};
use gnb::network::sync_rr::{
    SyncRequest, SyncRequestLimiter, SyncResponse, MAX_INFLIGHT_PER_PEER, STALL_FAILURES,
};
use gnb::network::SyncEntry;
use gnb::sync::peer_state::PeerStateTable;
use gnb::sync::frontier::{FrontierState, ABANDONED_TTL, MAX_FRONTIER_IN_FLIGHT, MAX_NEW_TIPS_PER_RESPONSE};
use libp2p::PeerId;

fn h(i: u32) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[..4].copy_from_slice(&i.to_be_bytes());
    b[31] = 0xB1;
    b
}

fn get_block(i: u32) -> SyncRequest {
    SyncRequest::GetBlock { block_hash: h(i) }
}

fn block(i: u32) -> SyncResponse {
    SyncResponse::Block { block_hash: h(i), blue_score: 1, height: 1, block_data: vec![1] }
}

fn entry(i: u32) -> SyncEntry {
    SyncEntry { hash: h(i), blue_score: 100 + u64::from(i), height: 1 }
}

/// A scheduler with `n` outbound peers connected at `t0`.
fn scheduler(n: usize, t0: Instant) -> (PullScheduler<u64>, Vec<PeerId>) {
    let mut s = PullScheduler::new(HashSet::new());
    let peers: Vec<PeerId> = (0..n).map(|_| PeerId::random()).collect();
    for p in &peers {
        s.on_connect(*p, true, t0);
    }
    (s, peers)
}

/// Drain once; returns the (peer, request id) pairs sent.
fn drain(s: &mut PullScheduler<u64>, now: Instant, next_id: &mut u64) -> Vec<(PeerId, u64, SyncRequest)> {
    let mut sent = Vec::new();
    s.drain(now, |p, req| {
        *next_id += 1;
        sent.push((p, *next_id, req.clone()));
        *next_id
    });
    sent
}

// ── B1-T2 / NET-10: answers are bound to their request ─────────────────────

/// Each request kind against every answer shape: only an answer an honest
/// server can give to THAT request is accepted. A wrong answer is a
/// violation, is not delivered, and does not complete the pull (it goes to
/// another peer). Before, any well-formed answer completed any pull and was
/// handed to the processor as solicited data: a GetPeers or GetTips answered
/// with 2,000 made-up headers produced 2,000 GetBlocks.
#[test]
fn answers_are_bound_to_their_request() {
    let headers = |n: u32| SyncResponse::Headers { entries: (0..n).map(entry).collect() };
    let tips = SyncResponse::Tips { tips: vec![entry(1)], locator: vec![] };
    let peers = SyncResponse::Peers { peers: vec![] };
    let get_headers = SyncRequest::GetHeaders { from_blue_score: 100, limit: 500 };
    let cases: Vec<(SyncRequest, SyncResponse, bool)> = vec![
        (get_block(1), block(1), true),
        (get_block(1), SyncResponse::BlockNotFound { block_hash: h(1) }, true),
        (get_block(1), block(2), false),
        (get_block(1), SyncResponse::BlockNotFound { block_hash: h(2) }, false),
        (get_block(1), headers(0), false),
        (get_block(1), headers(2_000), false),
        (get_block(1), tips.clone(), false),
        (get_block(1), peers.clone(), false),
        (get_headers.clone(), headers(500), true),
        (get_headers.clone(), headers(0), true),
        (get_headers.clone(), headers(501), false),
        (SyncRequest::GetHeaders { from_blue_score: 101, limit: 500 }, headers(10), false),
        (get_headers.clone(), tips.clone(), false),
        (get_headers.clone(), block(1), false),
        (get_headers.clone(), peers.clone(), false),
        (SyncRequest::GetTips, tips.clone(), true),
        (SyncRequest::GetTips, headers(2_000), false),
        (SyncRequest::GetTips, peers.clone(), false),
        (SyncRequest::GetTips, block(1), false),
        (SyncRequest::GetPeers, peers.clone(), true),
        (SyncRequest::GetPeers, headers(2_000), false),
        (SyncRequest::GetPeers, tips.clone(), false),
        (SyncRequest::GetPeers, SyncResponse::BlockNotFound { block_hash: h(1) }, false),
    ];
    for (req, resp, valid) in cases {
        let t0 = Instant::now();
        let (mut s, _) = scheduler(2, t0);
        let mut id = 0;
        assert_eq!(s.enqueue(req.clone(), None, &[], t0), Enqueued::Queued);
        let sent = drain(&mut s, t0, &mut id);
        assert_eq!(sent.len(), 1);
        let (peer, rid, _) = sent[0];
        let act = s.on_response(rid, peer, &resp, t0);
        if valid {
            assert!(act.violation.is_none(), "{req:?} / {resp:?}: honest answer flagged");
            assert!(act.deliver, "{req:?} / {resp:?}: honest answer not delivered");
        } else {
            assert!(act.violation.is_some(), "{req:?} / {resp:?}: wrong answer accepted");
            assert!(!act.deliver, "{req:?} / {resp:?}: wrong answer delivered to the processor");
            // The pull is not completed by it: it goes to the other peer.
            let again = drain(&mut s, t0, &mut id);
            assert_eq!(again.len(), 1, "{req:?} / {resp:?}: a wrong answer completed the pull");
            assert_ne!(again[0].0, peer, "the retry went back to the offender");
            assert_eq!(again[0].2, req);
        }
    }
}

/// Busy is a valid answer to every request: not delivered, not a violation.
#[test]
fn busy_is_back_pressure_for_every_request() {
    for req in [get_block(1), SyncRequest::GetHeaders { from_blue_score: 0, limit: 500 }, SyncRequest::GetTips, SyncRequest::GetPeers] {
        let t0 = Instant::now();
        let (mut s, _) = scheduler(1, t0);
        let mut id = 0;
        s.enqueue(req.clone(), None, &[], t0);
        let (peer, rid, _) = drain(&mut s, t0, &mut id)[0].clone();
        let act = s.on_response(rid, peer, &SyncResponse::Busy, t0);
        assert_eq!((act.deliver, act.violation), (false, None), "{req:?}");
        assert!(s.selector().is_cooling_down(&peer, t0));
    }
}

// ── B1-T6 / NET-9: pull selection ──────────────────────────────────────────

/// A pull goes first to the peer that announced the block (its hint), even
/// when another peer is less loaded.
#[test]
fn pulls_prefer_the_announcing_peer() {
    let t0 = Instant::now();
    let (mut s, p) = scheduler(3, t0);
    let mut id = 0;
    // p[1] already has a pull in flight: least-loaded selection avoids it.
    s.send_pinned(p[1], SyncRequest::GetTips, t0, |_, _| {
        id += 1;
        id
    });
    assert_eq!(s.enqueue(get_block(1), None, &[p[1]], t0), Enqueued::Queued);
    let sent = drain(&mut s, t0, &mut id);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, p[1], "the pull must go to the peer that announced the block");
}

/// A peer that answered a pull (here NotFound) never gets the same pull
/// again, even when it is the only peer with a free slot: the pull waits for
/// another peer. Before, the drain fell back to the same NotFound peer and
/// spent the pull's attempts on it.
#[test]
fn a_pull_never_returns_to_a_peer_that_already_answered_it() {
    let t0 = Instant::now();
    let (mut s, p) = scheduler(2, t0);
    let (a, b) = (p[0], p[1]);
    let mut id = 0;
    // b is saturated by pinned pulls.
    for _ in 0..MAX_INFLIGHT_PER_PEER {
        s.send_pinned(b, SyncRequest::GetTips, t0, |_, _| {
            id += 1;
            id
        });
    }
    let saturated_until = id;
    s.enqueue(get_block(7), None, &[], t0);
    let sent = drain(&mut s, t0, &mut id);
    assert_eq!(sent.iter().map(|x| x.0).collect::<Vec<_>>(), vec![a]);
    s.on_response(sent[0].1, a, &SyncResponse::BlockNotFound { block_hash: h(7) }, t0);
    for later in [t0, t0 + Duration::from_secs(1), t0 + Duration::from_secs(5)] {
        let again = drain(&mut s, later, &mut id);
        assert!(again.is_empty(), "the pull was sent back to the peer that said NotFound: {again:?}");
    }
    // A slot frees up on b: the pull goes there.
    let t1 = t0 + Duration::from_secs(5);
    s.on_response(saturated_until, b, &SyncResponse::Tips { tips: vec![], locator: vec![] }, t1);
    let again = drain(&mut s, t1, &mut id);
    assert_eq!(again.iter().map(|x| (x.0, x.2.clone())).collect::<Vec<_>>(), vec![(b, get_block(7))]);
}

/// A block only the fifth peer has is still fetched: a pull is not dropped
/// after three NotFounds while untried peers remain.
#[test]
fn a_pull_outlives_more_than_three_not_found() {
    let t0 = Instant::now();
    let (mut s, p) = scheduler(5, t0);
    let mut id = 0;
    s.enqueue(get_block(9), None, &[], t0);
    let mut now = t0;
    let mut asked = Vec::new();
    loop {
        let sent = drain(&mut s, now, &mut id);
        if let Some((peer, rid, _)) = sent.first().cloned() {
            asked.push(peer);
            if asked.len() == 5 {
                let act = s.on_response(rid, peer, &block(9), now);
                assert!(act.deliver);
                break;
            }
            s.on_response(rid, peer, &SyncResponse::BlockNotFound { block_hash: h(9) }, now);
        }
        now += Duration::from_millis(250);
        assert!(now < t0 + Duration::from_secs(60), "the pull was dropped after {} NotFound(s)", asked.len());
    }
    let distinct: HashSet<PeerId> = asked.iter().copied().collect();
    assert_eq!(distinct.len(), 5, "every attempt went to a different peer");
    assert_eq!(distinct, p.iter().copied().collect());
}

/// Retries are spaced in time: after two failed attempts the third is not
/// sent before the back-off.
#[test]
fn retries_are_spaced_in_time() {
    let t0 = Instant::now();
    let (mut s, _) = scheduler(4, t0);
    let mut id = 0;
    s.enqueue(get_block(3), None, &[], t0);
    for _ in 0..2 {
        let (peer, rid, _) = drain(&mut s, t0, &mut id)[0].clone();
        s.on_failure(rid, peer, FailureKind::Transport, t0);
    }
    assert!(drain(&mut s, t0, &mut id).is_empty(), "third attempt sent at once");
    assert!(drain(&mut s, t0 + Duration::from_millis(100), &mut id).is_empty());
    assert_eq!(drain(&mut s, t0 + Duration::from_secs(5), &mut id).len(), 1, "but it is sent after the back-off");
}

/// NotFound counts against the answering peer: a peer that keeps saying
/// NotFound ranks below one that serves, even when it is less loaded (a fast
/// liar always has the fewest pulls in flight).
#[test]
fn not_found_answers_rank_a_peer_down() {
    let t0 = Instant::now();
    let (mut s, p) = scheduler(2, t0);
    let (liar, honest) = (p[0], p[1]);
    let mut id = 0;
    for i in 0..3 {
        s.enqueue(get_block(100 + i), None, &[liar], t0);
        let (peer, rid, _) = drain(&mut s, t0, &mut id)[0].clone();
        assert_eq!(peer, liar);
        s.on_response(rid, liar, &SyncResponse::BlockNotFound { block_hash: h(100 + i) }, t0);
        let (peer, rid, _) = drain(&mut s, t0, &mut id)[0].clone();
        assert_eq!(peer, honest);
        s.on_response(rid, honest, &block(100 + i), t0);
    }
    // honest now carries one pinned pull; the liar has none.
    s.send_pinned(honest, SyncRequest::GetTips, t0, |_, _| {
        id += 1;
        id
    });
    s.enqueue(get_block(200), None, &[], t0);
    let sent = drain(&mut s, t0, &mut id);
    assert_eq!(sent[0].0, honest, "the NotFound peer must rank below the serving one");
}

/// A stalled peer's cooldown survives a reconnect, and its rotation slot
/// is not reset to "never selected".
#[test]
fn cooldown_survives_reconnect() {
    let t0 = Instant::now();
    let (mut s, p) = scheduler(2, t0);
    let (staller, good) = (p[0], p[1]);
    let mut id = 0;
    for _ in 0..STALL_FAILURES {
        s.send_pinned(staller, SyncRequest::GetTips, t0, |_, _| {
            id += 1;
            id
        });
        s.on_failure(id, staller, FailureKind::Transport, t0);
    }
    assert!(s.selector().is_cooling_down(&staller, t0));
    s.on_disconnect(&staller, t0);
    s.on_connect(staller, true, t0 + Duration::from_secs(1));
    assert!(s.selector().is_cooling_down(&staller, t0 + Duration::from_secs(1)), "a reconnect cleared the cooldown");
    s.enqueue(get_block(1), None, &[], t0 + Duration::from_secs(1));
    let sent = drain(&mut s, t0 + Duration::from_secs(1), &mut id);
    assert_eq!(sent[0].0, good);
}

/// A misbehaving peer (a violation found by the network loop) is not
/// selected while it is on cooldown.
#[test]
fn misbehaving_peer_is_not_selected() {
    let t0 = Instant::now();
    let (mut s, p) = scheduler(2, t0);
    let mut id = 0;
    s.send_pinned(p[1], SyncRequest::GetTips, t0, |_, _| {
        id += 1;
        id
    });
    s.on_misbehaving(&p[0], t0);
    s.enqueue(get_block(1), None, &[p[0]], t0);
    let sent = drain(&mut s, t0, &mut id);
    assert_eq!(sent[0].0, p[1]);
}

/// One peer's answers cannot fill the shared pull queue: pulls attributed to
/// one source are capped, and the node's own pulls (orphan parents, nudges)
/// are still admitted when the queue is full.
#[test]
fn one_source_cannot_fill_the_pull_queue() {
    let t0 = Instant::now();
    let (mut s, p) = scheduler(2, t0);
    let attacker = p[0];
    let admitted = (0..MAX_PENDING_PULLS as u32)
        .filter(|i| s.enqueue(get_block(*i), Some(attacker), &[attacker], t0) == Enqueued::Queued)
        .count();
    assert!(admitted <= MAX_PENDING_PULLS / 4, "one source queued {admitted} pulls");
    // Other sources and local pulls still get in, even with the queue full.
    let others = (0..3u32)
        .flat_map(|k| (0..MAX_PENDING_PULLS as u32).map(move |i| (k, i)))
        .filter(|(k, i)| s.enqueue(get_block(100_000 * (k + 1) + i), Some(PeerId::random()), &[], t0) == Enqueued::Queued)
        .count();
    assert!(others > 0);
    assert!(s.pending_len() <= MAX_PENDING_PULLS);
    assert_eq!(s.enqueue(get_block(9_999_999), None, &[], t0), Enqueued::Queued, "a local pull was refused");
}

/// The same block is pulled once, however many answers announce it.
#[test]
fn duplicate_block_pulls_are_coalesced() {
    let t0 = Instant::now();
    let (mut s, p) = scheduler(2, t0);
    assert_eq!(s.enqueue(get_block(5), Some(p[0]), &[p[0]], t0), Enqueued::Queued);
    assert_eq!(s.enqueue(get_block(5), Some(p[1]), &[p[1]], t0), Enqueued::Duplicate);
    assert_eq!(s.enqueue(get_block(5), None, &[], t0), Enqueued::Duplicate);
    assert_eq!(s.pending_len(), 1);
}

/// Review of B1-T2: free inbound identities, each under its own quota,
/// together hold at most half the queue; a pull announced by a peer we
/// dialed is still admitted when the queue is full (it evicts one an inbound
/// source announced), and so is the node's own. Before, five identities
/// filled the queue and every honest peer's announced pull was refused.
#[test]
fn inbound_identities_cannot_fill_the_pull_queue() {
    let t0 = Instant::now();
    let mut s: PullScheduler<u64> = PullScheduler::new(HashSet::new());
    let honest = PeerId::random();
    s.on_connect(honest, true, t0);
    let sybils: Vec<PeerId> = (0..6).map(|_| PeerId::random()).collect();
    let mut next = 0u32;
    let mut queued = 0usize;
    for sy in &sybils {
        s.on_connect(*sy, false, t0);
        for _ in 0..MAX_PENDING_PER_SOURCE {
            next += 1;
            if s.enqueue(get_block(next), Some(*sy), &[*sy], t0) == Enqueued::Queued {
                queued += 1;
            }
        }
    }
    assert_eq!(queued, MAX_PENDING_INBOUND_ATTRIBUTED, "inbound identities together queued {queued}");
    // The node's own pulls fill the rest of the queue.
    while s.pending_len() < MAX_PENDING_PULLS {
        next += 1;
        assert_eq!(s.enqueue(get_block(next), None, &[], t0), Enqueued::Queued);
    }
    // Full queue: a pull a dialed peer announced still gets in.
    for i in 0..64 {
        assert_eq!(
            s.enqueue(get_block(5_000_000 + i), Some(honest), &[honest], t0),
            Enqueued::Queued,
            "an honest peer's announced pull was refused"
        );
    }
    assert_eq!(s.pending_len(), MAX_PENDING_PULLS);
    assert_eq!(s.enqueue(get_block(6_000_000), None, &[], t0), Enqueued::Queued, "a local pull was refused");
    // An inbound identity evicts nothing.
    let late = PeerId::random();
    s.on_connect(late, false, t0);
    assert_eq!(s.enqueue(get_block(7_000_000), Some(late), &[late], t0), Enqueued::Refused);
}

/// Review of B1-T6: a NotFound for a block an identity that connected to
/// us announced (free, unverified: it may be made up) costs the answering
/// peer nothing for now; the announcer pays one useless answer when it
/// cannot serve the block itself. For a block a peer we dialed announced,
/// the NotFounds count at once and are refunded when nobody had it (the
/// announcer's own NotFound included). Before, an attacker's made-up
/// announcements were answered NotFound by every honest peer, and each
/// answer ranked that honest peer down until all of them were poor peers.
#[test]
fn not_found_for_a_block_another_peer_announced_is_charged_to_the_announcer() {
    for announcer_dialed in [false, true] {
        let t0 = Instant::now();
        let mut s: PullScheduler<u64> = PullScheduler::new(HashSet::new());
        let announcer = PeerId::random();
        let others = [PeerId::random(), PeerId::random()];
        s.on_connect(announcer, announcer_dialed, t0);
        for o in &others {
            s.on_connect(*o, true, t0);
        }
        let mut id = 0;
        s.on_misbehaving(&announcer, t0); // on cooldown: the pull goes to the others
        s.enqueue(get_block(42), Some(announcer), &[announcer], t0);
        let mut now = t0;
        for _ in 0..2 {
            let sent = drain(&mut s, now, &mut id);
            let (peer, rid, _) = sent[0].clone();
            assert_ne!(peer, announcer);
            s.on_response(rid, peer, &SyncResponse::BlockNotFound { block_hash: h(42) }, now);
            let charged = s.selector().penalty(&peer, now);
            if announcer_dialed {
                assert!((charged - 1.0).abs() < 1e-9, "a NotFound for a dialed peer's announcement counts at once: {charged}");
            } else {
                assert_eq!(charged, 0.0, "a true NotFound for an inbound identity's announcement was charged");
            }
            now += Duration::from_millis(10);
        }
        // Then the announcer itself says NotFound: it pays, and the pull is dropped.
        let mut rid = None;
        for step in 0..40 {
            let t = t0 + Duration::from_secs(61 + 15 * step);
            if let Some((peer, r, _)) = drain(&mut s, t, &mut id).first().cloned() {
                assert_eq!(peer, announcer);
                rid = Some((r, t));
                break;
            }
        }
        let (r, t) = rid.expect("the pull went back to its announcer once its cooldown ended");
        let before = s.selector().penalty(&announcer, t);
        s.on_response(r, announcer, &SyncResponse::BlockNotFound { block_hash: h(42) }, t);
        drain(&mut s, t, &mut id);
        assert_eq!(s.dropped(), 1);
        let paid = s.selector().penalty(&announcer, t) - before;
        assert!((paid - 1.0).abs() < 1e-9, "the announcer paid {paid} for its unservable announcement (one useless answer)");
        for other in &others {
            assert_eq!(s.selector().penalty(other, t), 0.0, "a true NotFound stayed charged (dialed announcer: {announcer_dialed})");
        }
    }
}

/// Review of B1-T6 (follow-up): a NotFound for a block an identity that
/// connected to us announced is not free either. It is held against the
/// answering peer once a peer we dialed serves the block (it existed: the
/// answer was useless), never when only the announcing identity "serves"
/// it (it may have announced a made-up block and answer with a made-up
/// body). Never charging such NotFounds (nor those for a dialed peer's
/// announcement, which count at once) let eight free NotFound identities use
/// up the attempts of most pulls an honest peer announced
/// (`announced_pulls_resist_fast_not_found_liars`).
#[test]
fn not_found_to_an_announced_block_counts_once_a_dialed_peer_serves_it() {
    let t0 = Instant::now();
    let mut id = 0;
    let serve = |s: &mut PullScheduler<u64>, sent: Vec<(PeerId, u64, SyncRequest)>| {
        for (peer, rid, req) in sent {
            let SyncRequest::GetBlock { block_hash } = req else { panic!("{req:?}") };
            s.on_response(rid, peer, &SyncResponse::Block { block_hash, blue_score: 1, height: 1, block_data: vec![1] }, t0);
        }
    };

    // A block an inbound identity announced, then served by a peer we dialed.
    let mut s: PullScheduler<u64> = PullScheduler::new(HashSet::new());
    let (announcer, liar, dialed) = (PeerId::random(), PeerId::random(), PeerId::random());
    s.on_connect(announcer, false, t0);
    s.on_connect(liar, false, t0);
    s.on_connect(dialed, true, t0);
    s.on_misbehaving(&announcer, t0); // backing off: not asked for a while
    // The dialed peer is busy with the node's own pulls.
    for i in 0..MAX_INFLIGHT_PER_PEER {
        s.enqueue(get_block(1_000 + i), None, &[dialed], t0);
    }
    let busy = drain(&mut s, t0, &mut id);
    assert_eq!(busy.len(), MAX_INFLIGHT_PER_PEER as usize);
    assert!(busy.iter().all(|(p, _, _)| *p == dialed));
    s.enqueue(get_block(42), Some(announcer), &[announcer], t0);
    let (to, rid, _) = drain(&mut s, t0, &mut id)[0].clone();
    assert_eq!(to, liar);
    s.on_response(rid, liar, &SyncResponse::BlockNotFound { block_hash: h(42) }, t0);
    assert_eq!(s.selector().penalty(&liar, t0), 0.0, "not charged before the block turns out to exist");
    assert!(drain(&mut s, t0, &mut id).is_empty(), "nobody free to ask");
    serve(&mut s, busy);
    let (to, rid, _) = drain(&mut s, t0, &mut id)[0].clone();
    assert_eq!(to, dialed);
    s.on_response(rid, dialed, &block(42), t0);
    assert!((s.selector().penalty(&liar, t0) - 1.0).abs() < 1e-9, "the NotFound was not held against the liar");
    assert_eq!(s.selector().penalty(&dialed, t0), 0.0);

    // A block an inbound identity announced and "serves" itself.
    let mut s: PullScheduler<u64> = PullScheduler::new(HashSet::new());
    let (attacker, honest) = (PeerId::random(), PeerId::random());
    s.on_connect(attacker, false, t0);
    s.on_connect(honest, true, t0);
    s.enqueue(get_block(43), Some(attacker), &[attacker], t0);
    let (to, rid, _) = drain(&mut s, t0, &mut id)[0].clone();
    assert_eq!(to, attacker, "the announcer is asked first");
    s.on_response(rid, attacker, &SyncResponse::Busy, t0);
    let (to, rid, _) = drain(&mut s, t0, &mut id)[0].clone();
    assert_eq!(to, honest, "the announcer is backing off: the other peer is asked");
    s.on_response(rid, honest, &SyncResponse::BlockNotFound { block_hash: h(43) }, t0);
    let t = t0 + Duration::from_secs(3);
    let (to, rid, _) = drain(&mut s, t, &mut id)[0].clone();
    assert_eq!(to, attacker);
    s.on_response(rid, attacker, &block(43), t);
    assert_eq!(s.selector().penalty(&honest, t), 0.0, "a made-up announcement got an honest NotFound charged");
}

/// Review of B1-T6: a NotFound charge on the node's own pull is refunded
/// only when every peer asked answered NotFound; a pull that also timed out
/// on a peer (the block may exist there) refunds nothing.
#[test]
fn not_found_is_refunded_only_when_every_peer_asked_said_not_found() {
    let t0 = Instant::now();
    let (mut s, p) = scheduler(2, t0);
    let mut id = 0;
    s.enqueue(get_block(77), None, &[p[0]], t0);
    let (peer, rid, _) = drain(&mut s, t0, &mut id)[0].clone();
    assert_eq!(peer, p[0]);
    s.on_response(rid, peer, &SyncResponse::BlockNotFound { block_hash: h(77) }, t0);
    let (peer, rid, _) = drain(&mut s, t0, &mut id)[0].clone();
    assert_eq!(peer, p[1]);
    s.on_failure(rid, peer, FailureKind::Transport, t0);
    drain(&mut s, t0, &mut id);
    assert_eq!(s.dropped(), 1, "nobody is left to ask");
    assert!(s.selector().penalty(&p[0], t0) > 0.0, "the NotFound was refunded although another peer timed out");
}

/// Review of B1-T6: a GetHeaders that a peer which claimed to be ahead
/// answers short (nothing, or fewer entries than asked) is delivered and also
/// sent to the next such peer: one claimer cannot hold header sync back.
/// Before, a short or empty answer completed the pull.
#[test]
fn short_headers_answer_goes_to_the_next_claimer() {
    for short in [0u32, 7] {
        let t0 = Instant::now();
        let (mut s, p) = scheduler(3, t0);
        let mut id = 0;
        let req = SyncRequest::GetHeaders { from_blue_score: 100, limit: 500 };
        s.enqueue(req.clone(), None, &[p[0], p[1]], t0);
        let (peer, rid, _) = drain(&mut s, t0, &mut id)[0].clone();
        let act = s.on_response(rid, peer, &SyncResponse::Headers { entries: (0..short).map(entry).collect() }, t0);
        assert!(act.deliver && act.violation.is_none());
        let again = drain(&mut s, t0, &mut id);
        assert_eq!(again.len(), 1, "a short answer ({short}) completed the GetHeaders");
        let (next, rid, _) = again[0].clone();
        assert!(next != peer && [p[0], p[1]].contains(&next), "the retry went to {next}, not the other claimer");
        // A full answer completes it.
        let act = s.on_response(rid, next, &SyncResponse::Headers { entries: (0..500).map(entry).collect() }, t0);
        assert!(act.deliver);
        assert!(drain(&mut s, t0, &mut id).is_empty());
        assert_eq!((s.pending_len(), s.in_flight_len()), (0, 0));
    }
}

/// Review of B1-T6: hints are not ranked by grindable PeerId bytes or by the
/// size of an unverified claim: equal claims are taken in a per-node secret
/// order, and the scheduler puts the peers we dialed first.
#[test]
fn header_hints_are_not_grindable_and_prefer_dialed_peers() {
    let now = Instant::now();
    let peers: Vec<PeerId> = (0..64).map(|_| PeerId::random()).collect();
    let mut by_bytes = peers.clone();
    by_bytes.sort_by_key(|p| p.to_bytes());
    let lowest: HashSet<PeerId> = by_bytes[..4].iter().copied().collect();
    let mut differs = false;
    for _ in 0..4 {
        let table = PeerStateTable::new();
        for (i, p) in peers.iter().enumerate() {
            table.on_connect(*p, now);
            // The lowest-byte identities claim the most.
            let claim = if lowest.contains(p) { 1_000_000 } else { 200 + i as u64 };
            table.observe(*p, claim, claim, &[], now);
        }
        let got: HashSet<PeerId> = table.claiming_above(100, now, 4).into_iter().collect();
        assert_eq!(got.len(), 4);
        differs |= got != lowest;
    }
    assert!(differs, "the lowest-byte, highest-claim identities always took every hint slot");
    // Dialed peers first among the hints.
    let t0 = Instant::now();
    let mut s: PullScheduler<u64> = PullScheduler::new(HashSet::new());
    let inbound: Vec<PeerId> = (0..4).map(|_| PeerId::random()).collect();
    let outbound = PeerId::random();
    for p in &inbound {
        s.on_connect(*p, false, t0);
    }
    s.on_connect(outbound, true, t0);
    let mut hints = inbound.clone();
    hints.push(outbound);
    s.enqueue(SyncRequest::GetHeaders { from_blue_score: 1, limit: 500 }, None, &hints, t0);
    let mut id = 0;
    assert_eq!(drain(&mut s, t0, &mut id)[0].0, outbound, "the dialed claimer must be asked first");
}

/// NET-9 residual: a NotFound from a peer that connected to US (an identity
/// that costs nothing) never counts toward abandoning a frontier tip; one
/// from a peer we dialed does.
#[test]
fn not_found_from_inbound_identities_never_abandons_a_tip() {
    let t0 = Instant::now();
    let mut s: PullScheduler<u64> = PullScheduler::new(HashSet::new());
    let (inbound, outbound) = (PeerId::random(), PeerId::random());
    s.on_connect(inbound, false, t0);
    s.on_connect(outbound, true, t0);
    assert!(!s.counts_for_abandonment(&inbound));
    assert!(s.counts_for_abandonment(&outbound));
    // And so the network loop does not deliver an inbound peer's NotFound.
    let mut id = 0;
    s.enqueue(get_block(1), None, &[inbound], t0);
    let (peer, rid, _) = drain(&mut s, t0, &mut id)[0].clone();
    assert_eq!(peer, inbound);
    let act = s.on_response(rid, inbound, &SyncResponse::BlockNotFound { block_hash: h(1) }, t0);
    assert!(!act.deliver && act.violation.is_none());
}

// ── Discrete-event model: fast attackers vs honest, rate-limiting servers ──

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Role {
    Honest,
    /// Answers every GetBlock with BlockNotFound.
    NotFoundLiar,
    /// Answers every request with a Headers frame (a wrong variant).
    WrongVariant,
    /// Never answers (the request times out after 30 s).
    Staller,
    /// Connects to us, announces 64 made-up blocks (a pinned GetTips answer)
    /// every 30 s, and answers every request Busy.
    BusyForever,
}

struct SimPeer {
    id: PeerId,
    role: Role,
    latency: Duration,
    limiter: SyncRequestLimiter,
    connected: bool,
    violations: u32,
}

enum Ev {
    Answer { id: u64, peer: usize, resp: SyncResponse },
    Timeout { id: u64, peer: usize },
}

#[derive(Debug)]
struct Outcome {
    completed: usize,
    dropped: u64,
    to_attackers: usize,
    sent: usize,
    finished_after: Duration,
    /// Answered requests (Busy excepted) that went to a peer which had
    /// already answered the same pull.
    repeated: usize,
    /// Made-up blocks announced (`Role::BusyForever`).
    phantoms: u64,
}

/// How the simulated node's pulls are queued.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Feed {
    /// The node's own pulls, no hint.
    Local,
    /// The node's own pulls, each naming an honest server as having it.
    Hinted,
    /// Pulls announced by an honest server's Headers answer (headers-first
    /// IBD: `NetworkControl::Fetch`), attributed to it and hinted to it.
    Announced,
}

/// `n` GetBlock pulls of blocks every honest server has, from a node
/// connected (outbound) to `honest` honest servers (latency
/// `honest_latency`, the node's own per-requester rate limit: 64 burst, then
/// 8/s, answered Busy beyond it) and to `attackers`. With `hinted`, each pull
/// names an honest server that announced it. A violator is disconnected at
/// its 4th violation (the network loop's misbehaviour threshold). Runs until
/// every pull completed, nothing is left, or `limit` simulated time.
fn simulate(n: u32, honest: usize, honest_latency: Duration, attackers: &[(Role, Duration)], hinted: bool) -> Outcome {
    simulate_feed(n, honest, honest_latency, attackers, if hinted { Feed::Hinted } else { Feed::Local })
}

/// [`simulate`] with the pulls queued as `feed` says.
fn simulate_feed(n: u32, honest: usize, honest_latency: Duration, attackers: &[(Role, Duration)], feed: Feed) -> Outcome {
    let limit = Duration::from_secs(600);
    let t0 = Instant::now();
    let me = PeerId::random();
    let mut peers: Vec<SimPeer> = (0..honest)
        .map(|_| (Role::Honest, honest_latency))
        .chain(attackers.iter().copied())
        .map(|(role, latency)| SimPeer { id: PeerId::random(), role, latency, limiter: SyncRequestLimiter::new(), connected: true, violations: 0 })
        .collect();
    let index: HashMap<PeerId, usize> = peers.iter().enumerate().map(|(i, p)| (p.id, i)).collect();
    let mut s: PullScheduler<u64> = PullScheduler::new(HashSet::new());
    // Attackers connect first (the order of a node's connections is theirs to
    // choose); a Busy-only announcer connects to us.
    for p in peers.iter().rev() {
        s.on_connect(p.id, p.role != Role::BusyForever, t0);
    }
    let wanted: HashMap<[u8; 32], u32> = (0..n).map(|i| (h(i), i)).collect();
    let mut answered: HashSet<([u8; 32], usize)> = HashSet::new();
    let mut repeated = 0usize;
    let mut phantoms = 0u64;
    let mut next_feed = Duration::ZERO;
    for i in 0..n {
        let announcer = peers[i as usize % honest].id;
        let (source, hints) = match feed {
            Feed::Local => (None, vec![]),
            Feed::Hinted => (None, vec![announcer]),
            Feed::Announced => (Some(announcer), vec![announcer]),
        };
        assert_eq!(s.enqueue(get_block(i), source, &hints, t0), Enqueued::Queued);
    }
    let mut queue: BinaryHeap<Reverse<(Duration, u64)>> = BinaryHeap::new();
    let mut events: HashMap<u64, Ev> = HashMap::new();
    let mut inflight: HashMap<u64, usize> = HashMap::new();
    // Request id → the block it pulls.
    let mut pulled: HashMap<u64, [u8; 32]> = HashMap::new();
    let (mut seq, mut next_id) = (0u64, 0u64);
    let mut completed: HashSet<u32> = HashSet::new();
    let (mut to_attackers, mut sent) = (0usize, 0usize);
    let mut at = Duration::ZERO;
    let tick = Duration::from_millis(250);
    loop {
        let now = t0 + at;
        if at >= next_feed {
            next_feed = at + Duration::from_secs(30);
            for p in peers.iter().filter(|p| p.role == Role::BusyForever && p.connected) {
                for _ in 0..64 {
                    phantoms += 1;
                    let fake = h(50_000_000 + phantoms as u32);
                    s.enqueue(SyncRequest::GetBlock { block_hash: fake }, Some(p.id), &[p.id], now);
                }
            }
        }
        s.drain(now, |peer, req| {
            next_id += 1;
            let pi = index[&peer];
            let p = &mut peers[pi];
            sent += 1;
            if p.role != Role::Honest {
                to_attackers += 1;
            }
            let hash = match req {
                SyncRequest::GetBlock { block_hash } => *block_hash,
                _ => [0u8; 32],
            };
            let (delay, ev) = match p.role {
                Role::Honest => {
                    let resp = if !p.limiter.allow_at(me, now) {
                        SyncResponse::Busy
                    } else if wanted.contains_key(&hash) {
                        SyncResponse::Block { block_hash: hash, blue_score: 1, height: 1, block_data: vec![1] }
                    } else {
                        SyncResponse::BlockNotFound { block_hash: hash }
                    };
                    (p.latency, Ev::Answer { id: next_id, peer: pi, resp })
                }
                Role::BusyForever => (p.latency, Ev::Answer { id: next_id, peer: pi, resp: SyncResponse::Busy }),
                Role::NotFoundLiar => (p.latency, Ev::Answer { id: next_id, peer: pi, resp: SyncResponse::BlockNotFound { block_hash: hash } }),
                Role::WrongVariant => (
                    p.latency,
                    Ev::Answer { id: next_id, peer: pi, resp: SyncResponse::Headers { entries: (0..50).map(|i| entry(1_000_000 + i)).collect() } },
                ),
                Role::Staller => (Duration::from_secs(30), Ev::Timeout { id: next_id, peer: pi }),
            };
            seq += 1;
            queue.push(Reverse((at + delay, seq)));
            events.insert(seq, ev);
            inflight.insert(next_id, pi);
            pulled.insert(next_id, hash);
            next_id
        });
        if completed.len() == n as usize {
            break;
        }
        let next = match queue.peek() {
            Some(Reverse((t, _))) if *t <= at + tick => *t,
            _ if queue.is_empty() && s.pending_len() == 0 => break,
            _ => at + tick,
        };
        if next > limit {
            break;
        }
        at = next;
        let now = t0 + at;
        while let Some(Reverse((t, sq))) = queue.peek().copied() {
            if t > at {
                break;
            }
            queue.pop();
            match events.remove(&sq).expect("event") {
                Ev::Answer { id, peer: pi, resp } => {
                    if inflight.remove(&id).is_none() {
                        continue; // its connection was closed meanwhile
                    }
                    let pid = peers[pi].id;
                    if !matches!(resp, SyncResponse::Busy) && !answered.insert((pulled[&id], pi)) {
                        repeated += 1;
                    }
                    let act = s.on_response(id, pid, &resp, now);
                    if act.violation.is_some() {
                        // (The scheduler already put the peer on cooldown;
                        // the network loop adds the shared misbehaviour
                        // score, modelled here by the violation count.)
                        peers[pi].violations += 1;
                        if peers[pi].violations >= 4 && peers[pi].connected {
                            peers[pi].connected = false;
                            s.on_disconnect(&pid, now);
                            let ids: Vec<u64> = inflight.iter().filter(|(_, p)| **p == pi).map(|(i, _)| *i).collect();
                            for i in ids {
                                inflight.remove(&i);
                                s.on_failure(i, pid, FailureKind::Transport, now);
                            }
                        }
                    }
                    if let (true, SyncResponse::Block { block_hash, .. }) = (act.deliver, &resp) {
                        if let Some(i) = wanted.get(block_hash) {
                            completed.insert(*i);
                        }
                    }
                }
                Ev::Timeout { id, peer: pi } => {
                    if inflight.remove(&id).is_some() {
                        if !answered.insert((pulled[&id], pi)) {
                            repeated += 1;
                        }
                        s.on_failure(id, peers[pi].id, FailureKind::Transport, now);
                    }
                }
            }
        }
    }
    Outcome { completed: completed.len(), dropped: s.dropped(), to_attackers, sent, finished_after: at, repeated, phantoms }
}

fn assert_all_honest_pulls_complete(o: &Outcome, n: u32, _attackers: usize) {
    eprintln!("{o:?}");
    assert_eq!(o.completed, n as usize, "honest pulls did not all complete: {o:?}");
    assert_eq!(o.dropped, 0, "pulls were dropped: {o:?}");
    assert_eq!(o.repeated, 0, "a pull went back to a peer that had already answered it: {o:?}");
    assert!(o.finished_after < Duration::from_secs(300), "too slow: {o:?}");
}

const FAST: Duration = Duration::from_millis(5);
const HONEST: Duration = Duration::from_millis(200);

/// Latency-aware (honest 200 ms, attacker 5 ms): one fast NotFound liar.
/// The re-audit's model of the old selector dropped 1,488 of 2,000 pulls
/// with 4 honest peers.
#[test]
fn fast_not_found_liar_cannot_drop_honest_pulls() {
    let o = simulate(2_000, 4, HONEST, &[(Role::NotFoundLiar, FAST)], false);
    assert_all_honest_pulls_complete(&o, 2_000, 1);
}

/// Three NotFound identities against four honest servers.
#[test]
fn not_found_sybils_cannot_drop_honest_pulls() {
    let o = simulate(2_000, 4, HONEST, &[(Role::NotFoundLiar, FAST), (Role::NotFoundLiar, FAST), (Role::NotFoundLiar, FAST)], false);
    assert_all_honest_pulls_complete(&o, 2_000, 3);
}

/// A fast peer answering with useless frames of the wrong variant (which
/// used to complete the pull and reset its failure count, so it captured
/// most pulls: 97 % with one honest peer, 81 % with eight) completes
/// nothing and is disconnected.
#[test]
fn fast_wrong_variant_peer_cannot_complete_pulls() {
    for honest in [1u32, 4] {
        let n = 500 * honest;
        let o = simulate(n, honest as usize, HONEST, &[(Role::WrongVariant, FAST)], false);
        assert_all_honest_pulls_complete(&o, n, 1);
        assert!(o.to_attackers <= 16, "the violator kept getting pulls: {o:?}");
    }
}

/// A staller (never answers) and a NotFound liar together, one honest
/// server, pulls hinted with the honest announcer.
#[test]
fn staller_and_liar_with_one_honest_server() {
    let o = simulate(1_000, 1, HONEST, &[(Role::Staller, FAST), (Role::NotFoundLiar, FAST)], true);
    assert_all_honest_pulls_complete(&o, 1_000, 2);
}

/// With hints, pulls go to the announcing honest servers: the fast liar
/// sees almost none of them.
#[test]
fn hinted_pulls_bypass_the_fast_liar() {
    let o = simulate(2_000, 4, HONEST, &[(Role::NotFoundLiar, FAST)], true);
    assert_all_honest_pulls_complete(&o, 2_000, 1);
    assert!(o.to_attackers * 10 < o.sent, "the liar received {} of {} requests", o.to_attackers, o.sent);
}

/// Pulls announced by honest servers (headers-first IBD: each attributed to
/// the server whose Headers answer named it) against fast NotFound liars:
/// a liar's NotFound for a block another peer announced must still rank the
/// liar down once the block turns out to exist (another peer serves it), or
/// enough free identities use up every pull's attempts while the announcer
/// is busy, and the honest announcer is blamed for the drops.
#[test]
fn announced_pulls_resist_fast_not_found_liars() {
    let runs: Vec<(usize, usize, u32, Outcome)> = [(4usize, 3usize), (4, 8), (1, 8)]
        .into_iter()
        .map(|(honest, liars)| {
            let n = 500 * honest as u32;
            let attackers = vec![(Role::NotFoundLiar, FAST); liars];
            let o = simulate_feed(n, honest, HONEST, &attackers, Feed::Announced);
            eprintln!("{honest} honest, {liars} liars: {o:?}");
            (honest, liars, n, o)
        })
        .collect();
    for (honest, liars, n, o) in &runs {
        assert_all_honest_pulls_complete(o, *n, *liars);
        assert!(o.to_attackers <= 16 * liars, "the liars kept getting pulls ({honest} honest, {liars} liars): {o:?}");
    }
}

/// Review of B1-T6: one free identity announces 64 made-up blocks every
/// 30 s and answers everything Busy. Before, the honest peers' true
/// NotFounds for the made-up blocks made all of them poor peers, while the
/// Busy-only peer, which cost nothing, stayed the "better peer" every pull
/// waited for: directed sync stalled for minutes per feed. The made-up
/// announcements now cost the announcer (not the honest peers), and a peer
/// that answers only Busy ranks down.
#[test]
fn busy_only_announcer_cannot_stall_honest_pulls() {
    let o = simulate(2_000, 4, HONEST, &[(Role::BusyForever, FAST)], false);
    eprintln!("{o:?}");
    assert!(o.phantoms >= 64);
    assert_eq!(o.completed, 2_000, "honest pulls did not all complete: {o:?}");
    assert_eq!(o.repeated, 0, "{o:?}");
    assert!(o.finished_after < Duration::from_secs(120), "directed sync stalled: {o:?}");
}

/// The same with one honest server (the node's only source of blocks).
#[test]
fn busy_only_announcer_with_one_honest_server() {
    let o = simulate(1_000, 1, HONEST, &[(Role::BusyForever, FAST)], true);
    eprintln!("{o:?}");
    assert_eq!(o.completed, 1_000, "honest pulls did not all complete: {o:?}");
    assert_eq!(o.repeated, 0, "{o:?}");
    assert!(o.finished_after < Duration::from_secs(240), "directed sync stalled: {o:?}");
}

// ── NET-10 / NET-9 residuals: the frontier tracker ─────────────────────────

/// One peer's Tips answers cannot fill the global in-flight set: another
/// peer's tips are still fetched.
#[test]
fn one_peer_cannot_fill_the_frontier() {
    let mut fr = FrontierState::new();
    let now = Instant::now();
    let (attacker, honest) = (PeerId::random(), PeerId::random());
    let mut from_attacker = 0usize;
    for frame in 0u32..100 {
        let tips: Vec<[u8; 32]> = (0u32..256).map(|i| h(frame * 1_000 + i)).collect();
        from_attacker += fr.request_from(attacker, &tips, |_| false, now, MAX_NEW_TIPS_PER_RESPONSE).len();
    }
    assert!(from_attacker <= MAX_FRONTIER_IN_FLIGHT / 4, "one peer has {from_attacker} tips in flight");
    let honest_tips: Vec<[u8; 32]> = (0u32..4).map(|i| h(9_000_000 + i)).collect();
    let got = fr.request_from(honest, &honest_tips, |_| false, now, MAX_NEW_TIPS_PER_RESPONSE);
    assert_eq!(got, honest_tips, "an honest peer's frontier was crowded out");
    // Its slots come back as its tips arrive.
    for t in &honest_tips {
        fr.note_received(t);
    }
    assert_eq!(fr.outstanding(), from_attacker);
}

/// An abandoned tip is forgotten at its TTL, whether or not anything else
/// is abandoned later (pruning used to run only inside `abandon`).
#[test]
fn abandoned_tip_expires_at_its_ttl() {
    let mut fr = FrontierState::new();
    let t0 = Instant::now();
    let tip = h(1);
    fr.to_request(&[tip], |_| false, t0);
    for p in [PeerId::random(), PeerId::random()] {
        fr.note_not_found_from(&tip, p, t0);
    }
    assert!(fr.is_abandoned_at(&tip, t0));
    assert!(fr.is_abandoned_at(&tip, t0 + ABANDONED_TTL - Duration::from_secs(1)));
    assert!(!fr.is_abandoned_at(&tip, t0 + ABANDONED_TTL), "abandoned tip outlived its TTL");
    // And it can be requested again once expired.
    let again = fr.to_request(&[tip], |_| false, t0 + ABANDONED_TTL);
    assert_eq!(again, vec![tip]);
}
