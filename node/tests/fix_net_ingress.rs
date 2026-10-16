//! Regression tests for the block-ingress fixes (audit POW-2, NET-2, POW-3,
//! POW-4, POW-8, NET-6, DAG-7). Each test asserts the FIXED behaviour, the
//! inverse of the audit's proof of concept for the same finding.
//!
//! Note: node test builds enable gnb-crypto's `test-pow-limit` feature, which
//! pins `expected_bits` to the pow limit. Floors are therefore exercised with
//! explicit reference targets (`ease_target`) rather than the clock-derived
//! `reference_target`.

use std::time::{Duration, Instant};

use gnb::core::{self, Block, BlockHeader, Transaction, TxInput, TxOutput};
use gnb::ingress::{
    backfill_decision, bits_meet_floor, derived_blue_score, ease_target, orphan_is_sync_evidence,
    unsolicited_height_too_far_ahead, verdict_for_accept_error, verdict_for_block_decode_error, BackfillDecision, ClaimPolicy,
    DeepBackfillBudget, OrphanInsert, OrphanLimits, OrphanPool, SupervisorBackoff,
    DEEP_BACKFILL_BURST, ORPHAN_WORK_FLOOR_SHIFT, SUPERVISOR_HEALTHY_RESET,
};
use gnb::network::{decode_wire_message, GossipVerdict, NetworkMessage};
use gnb::sync::peer_state::{PeerStateTable, CLAIM_TTL};
use libp2p::PeerId;

fn enc(m: &NetworkMessage) -> Vec<u8> {
    bincode::serde::encode_to_vec(m, bincode::config::standard()).unwrap()
}

fn coinbase(tag: u64, n_big_outputs: usize) -> Transaction {
    let mut outputs = vec![TxOutput { value: 1, script_pubkey: vec![1u8; 20] }];
    for _ in 0..n_big_outputs {
        outputs.push(TxOutput { value: 0, script_pubkey: vec![0xAB; 10_000] });
    }
    Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid: [0u8; 32],
            prev_index: u32::MAX,
            script_sig: format!("fix:{tag}").into_bytes(),
            sequence: u32::MAX,
        }],
        outputs,
        locktime: 0,
    }
}

fn block_with(parents: Vec<[u8; 32]>, bits: u32, nonce: u64, tag: u64, big: usize) -> Block {
    let txs = vec![coinbase(tag, big)];
    let mut b = Block {
        header: BlockHeader {
            version: 1,
            parents,
            merkle_root: Transaction::merkle_root(&txs),
            timestamp: 1_800_000_000,
            bits,
            nonce,
        },
        transactions: txs,
        blue_score: 1,
        height: 1,
        shielded_transactions: vec![],
        powit: Default::default(),
    };
    b.header.merkle_root = b.body_merkle_root();
    b
}

fn h(i: u64) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&i.to_le_bytes());
    b
}

// ── POW-2 ────────────────────────────────────────────────────────────────────

/// POW-2: `NewBlock { height: u64::MAX }` passes every wire pre-check, and the
/// processor's height checks must handle it without panicking (the binary is
/// built with `overflow-checks = true`, and so are these tests in dev).
#[test]
fn u64_max_height_does_not_panic_the_guard() {
    let mut blk = block_with(vec![[0x33; 32]], core::GENESIS_BITS, 7, 7, 0);
    blk.height = u64::MAX;
    let frame = enc(&NetworkMessage::NewBlock {
        block_hash: blk.block_hash(),
        blue_score: 0,
        height: u64::MAX,
        block_data: blk.to_wire_bytes(),
    });
    let NetworkMessage::NewBlock { height, .. } = decode_wire_message(&frame).expect("wire accept") else {
        unreachable!()
    };
    let tip_h: u64 = 40_000;
    let r = std::panic::catch_unwind(|| {
        let height = std::hint::black_box(height);
        (
            unsolicited_height_too_far_ahead(height, tip_h),
            backfill_decision(height, tip_h, false),
            backfill_decision(height, u64::MAX, true),
        )
    });
    let (too_far, d1, _) = r.expect("guard must not panic on u64::MAX");
    assert!(too_far, "an unsolicited u64::MAX height is rejected before any arithmetic");
    assert_eq!(d1, BackfillDecision::Pass);
}

/// POW-2: one panic per 30 s used to keep processing stopped because the
/// supervisor back-off never reset; it now resets after a healthy run.
#[test]
fn supervisor_backoff_resets_after_healthy_period() {
    let mut b = SupervisorBackoff::new(Duration::from_millis(100), Duration::from_secs(30));
    for _ in 0..30 {
        b.on_panic(Duration::from_millis(5));
    }
    assert_eq!(b.on_panic(Duration::ZERO), Duration::from_secs(30));
    assert_eq!(b.on_panic(SUPERVISOR_HEALTHY_RESET), Duration::from_millis(100));
}

// ── NET-2 / POW-3 / POW-4 ────────────────────────────────────────────────────

/// NET-2: the structural gate no longer runs the 64 MiB PoW; a hard-target
/// block with a failing nonce passes the cheap half (and still fails the full
/// `validate_structure`, so every ingress path keeps verifying the proof).
#[test]
fn cheap_structure_check_runs_no_pow() {
    let mut b = block_with(vec![[0x11; 32]], core::GENESIS_BITS, 0, 1, 0);
    while b.validate_pow() {
        b.header.nonce += 1;
    }
    assert_eq!(b.validate_structure_without_pow(), Ok(()));
    assert_eq!(b.validate_structure(), Err("invalid PoW"));
}

/// NET-2 / POW-3 / POW-4: an orphan (unknown parents) at the pow limit — the
/// free-orphan of the PoC — is refused by the anti-DoS floor BEFORE its PoW
/// is evaluated whenever the reference difficulty is real; honest bits pass.
#[test]
fn pow_limit_orphan_is_refused_by_the_floor() {
    let reference = core::bits_to_target(core::GENESIS_BITS);
    // Capped at the pow limit of the height (`pow_limit_bits_at`, POW-3).
    let floor = ease_target(&reference, ORPHAN_WORK_FLOOR_SHIFT, 1);
    assert!(!bits_meet_floor(core::POW_LIMIT_BITS, &floor), "free pow-limit orphan refused");
    assert!(bits_meet_floor(core::GENESIS_BITS, &floor), "honest-difficulty orphan admitted");
    // Up to 2^SHIFT easier than the reference is still admitted.
    let eased_bits = core::target_to_bits(&ease_target(&reference, ORPHAN_WORK_FLOOR_SHIFT, 1));
    assert!(bits_meet_floor(eased_bits, &floor));
    // Malformed bits never meet any floor (and cost no evaluation).
    assert!(!bits_meet_floor(0x0480_0001, &core::bits_to_target(core::POW_LIMIT_BITS)));
}

/// POW-4: the orphan pool respects its byte caps globally and per peer; a
/// single peer flooding ~1 MB orphans can only churn its OWN quota.
#[test]
fn orphan_pool_respects_byte_caps() {
    let limits = OrphanLimits {
        max_entries: 10_000,
        max_bytes: 8 * 1024 * 1024,
        max_entries_per_peer: 2_500,
        max_bytes_per_peer: 2 * 1024 * 1024,
    };
    let mut pool = OrphanPool::new(limits);
    let honest = PeerId::random();
    let attacker = PeerId::random();
    // An honest orphan with a modest claimed height.
    assert!(matches!(
        pool.insert(h(1), block_with(vec![h(1_000)], core::GENESIS_BITS, 0, 1, 0), 10, 2_000, Some(honest), false, &[h(1_000)]),
        OrphanInsert::Inserted { .. }
    ));
    // The attacker floods 200 × ~950 KB orphans claiming huge heights.
    let big = 950_000usize;
    for i in 0..200u64 {
        let b = block_with(vec![h(2_000 + i)], core::GENESIS_BITS, i, 100 + i, 0);
        pool.insert(h(10 + i), b, u64::MAX - i, big, Some(attacker), false, &[h(2_000 + i)]);
        assert!(pool.total_bytes() <= limits.max_bytes, "global byte cap");
        assert!(pool.peer_usage(Some(attacker)).1 <= limits.max_bytes_per_peer, "per-peer byte cap");
    }
    assert!(pool.contains(&h(1)), "honest orphan is never evicted by another peer's flood");
    assert_eq!(pool.peer_usage(Some(attacker)).0, limits.max_bytes_per_peer / big);
}

/// POW-4: eviction is by arrival order, never by the claimed height.
#[test]
fn orphan_eviction_ignores_claimed_height() {
    let limits = OrphanLimits { max_entries: 2, max_bytes: 1 << 20, max_entries_per_peer: 2, max_bytes_per_peer: 1 << 20 };
    let mut pool = OrphanPool::new(limits);
    pool.insert(h(1), block_with(vec![h(9)], core::GENESIS_BITS, 1, 1, 0), u64::MAX, 10, None, false, &[h(9)]);
    pool.insert(h(2), block_with(vec![h(9)], core::GENESIS_BITS, 2, 2, 0), 5, 10, None, false, &[h(9)]);
    match pool.insert(h(3), block_with(vec![h(9)], core::GENESIS_BITS, 3, 3, 0), 6, 10, None, false, &[h(9)]) {
        OrphanInsert::Inserted { evicted } => assert_eq!(evicted, vec![h(1)], "oldest arrival goes first, whatever its height"),
        other => panic!("{other:?}"),
    }
}

/// POW-8: a later copy with the same block id (different wire metadata) never
/// overwrites a pending orphan.
#[test]
fn later_copy_does_not_overwrite_pending_orphan() {
    let mut pool = OrphanPool::default();
    let b = block_with(vec![h(9)], core::GENESIS_BITS, 1, 1, 0);
    let id = b.block_hash();
    pool.insert(id, b.clone(), 7, 100, None, false, &[h(9)]);
    let mut forged = b;
    forged.blue_score = u64::MAX;
    forged.height = u64::MAX;
    assert_eq!(pool.insert(id, forged, u64::MAX, 100, None, false, &[h(9)]), OrphanInsert::Duplicate);
    let kept = pool.get(&id).unwrap();
    assert_eq!((kept.height, kept.block.blue_score), (7, 1));
}

/// POW-8: the persisted blue_score is derived from verified parents.
#[test]
fn wire_blue_score_is_replaced_by_derived_value() {
    assert_eq!(derived_blue_score([41u64, 40, 12]), 42);
    assert_eq!(derived_blue_score([u64::MAX]), u64::MAX);
}

/// POW-3 / POW-4: a long orphan chain is dropped (and drained) iteratively —
/// no recursion, no stack exhaustion.
#[test]
fn deep_orphan_chain_is_handled_iteratively() {
    let mut pool = OrphanPool::new(OrphanLimits {
        max_entries: 50_000,
        max_bytes: 1 << 30,
        max_entries_per_peer: 50_000,
        max_bytes_per_peer: 1 << 30,
    });
    for i in 1..=20_000u64 {
        let b = block_with(vec![h(i - 1)], core::GENESIS_BITS, i, i, 0);
        pool.insert(h(i), b, i, 1, None, false, &[h(i - 1)]);
    }
    // Run on a small stack: recursion over 20k levels would overflow it.
    let handle = std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(move || pool.drop_subtree(&h(0)))
        .unwrap();
    assert_eq!(handle.join().expect("no stack overflow"), 20_000);
}

/// DAG-7 / POW-3: the awaited-parent exemption for deep blocks is rationed.
#[test]
fn deep_backfill_exemption_is_rationed() {
    assert_eq!(backfill_decision(1, 40_000, false), BackfillDecision::DropUnsolicitedDeep);
    assert_eq!(backfill_decision(1, 40_000, true), BackfillDecision::AwaitedDeep);
    let mut budget = DeepBackfillBudget::new();
    let t0 = Instant::now();
    for _ in 0..DEEP_BACKFILL_BURST {
        assert!(budget.allow_at(t0));
    }
    assert!(!budget.allow_at(t0), "a flood of awaited deep blocks is cut off");
    assert!(budget.allow_at(t0 + Duration::from_secs(31)), "and slowly refilled");
}

/// NET-2: verdict classification of accept_block errors.
#[test]
fn only_context_free_failures_are_rejected() {
    assert_eq!(verdict_for_accept_error("consensus rejection: invalid GnB-SMH proof of work"), GossipVerdict::Reject);
    assert_eq!(verdict_for_accept_error("invalid difficulty: block bits 0x2100ffff != expected 0x1f0e9036"), GossipVerdict::Reject);
    assert_eq!(verdict_for_accept_error("timestamp rejected: timestamp before parent"), GossipVerdict::Reject);
    assert_eq!(verdict_for_accept_error("timestamp rejected: timestamp too far in the future"), GossipVerdict::Ignore);
    assert_eq!(verdict_for_accept_error("U.4: execute_reorg failed: reorg depth exceeds maximum"), GossipVerdict::Ignore);
    assert_eq!(verdict_for_accept_error("tx double-spend: outpoint already spent"), GossipVerdict::Ignore);
}

/// Mixed-version rollout of the minimal-varint rule (H-fuzz, docs/CONSENSUS.md
/// "Wire encoding"): a `NewBlock` whose `block_data` is a valid block with a
/// widened varint (accepted and relayed verbatim by releases before the rule)
/// is answered `Ignore`, never `Reject`, so the gossipsub P4 penalty cannot be
/// steered onto honest older relays (three such frames within a couple of
/// minutes graylisted one). Every other malformed body stays `Reject`.
#[test]
fn widened_block_varints_are_ignored_and_other_malformed_bodies_rejected() {
    // The coinbase's locktime ends `FD 00`: with its script_sig length widened
    // the pre-fix decoder (framing at the re-encoded length) read the
    // shielded count as `FD 00 00` and accepted the bytes as this block.
    let mut blk = block_with(vec![[0x33; 32]], core::GENESIS_BITS, 7, 7, 0);
    blk.transactions[0].locktime = u32::from_le_bytes([0x11, 0x22, 0xFD, 0x00]);
    blk.header.merkle_root = blk.body_merkle_root();
    let w = blk.to_wire_bytes();
    assert!(Block::from_wire_bytes(&w).is_ok());
    let hdr = blk.header.to_wire_bytes(blk.blue_score, blk.height).len();
    let widen = |at: usize, form: &[u8]| -> Vec<u8> {
        assert!(w[at] < 0xFD, "a one-byte varint at {at}");
        let mut v = w[..at].to_vec();
        v.extend_from_slice(form);
        v[at + 1] = w[at];
        v.extend_from_slice(&w[at + 1..]);
        v
    };
    let ss_len_at = hdr + 1 + 4 + 1 + 36; // tx count, version, input count, outpoint
    assert_eq!(usize::from(w[ss_len_at]), blk.transactions[0].inputs[0].script_sig.len());
    let widened = [
        ("parent count", widen(4, &[0xFD, 0, 0])),
        ("tx count", widen(hdr, &[0xFD, 0, 0])),
        ("tx count, 9-byte form", widen(hdr, &[0xFF, 0, 0, 0, 0, 0, 0, 0, 0])),
        ("script_sig length", widen(ss_len_at, &[0xFD, 0, 0])),
        ("shielded count", widen(w.len() - 1, &[0xFE, 0, 0, 0, 0])),
    ];
    for (what, bytes) in &widened {
        let e = Block::from_wire_bytes(bytes).expect_err(what);
        assert!(core::is_non_minimal_varint_error(&e), "{what}: {e}");
        assert_eq!(verdict_for_block_decode_error(&e), GossipVerdict::Ignore, "{what}: {e}");
        // The frame itself is canonical bincode: it reaches the block decoder.
        let frame = enc(&NetworkMessage::NewBlock { block_hash: blk.block_hash(), blue_score: 1, height: 1, block_data: bytes.clone() });
        assert!(decode_wire_message(&frame).is_ok(), "{what}");
    }
    let mut trailing = w.clone();
    trailing.push(0);
    let mut truncated = w.clone();
    truncated.pop();
    let mut cut_tx = w[..hdr + 1].to_vec(); // header and a tx count of 1, no transaction
    cut_tx.push(0);
    let mut too_many = w.clone();
    too_many[hdr] = 2; // two transactions announced, one present
    for (what, bytes) in [("trailing byte", trailing), ("truncated", truncated), ("missing tx", cut_tx), ("tx count 2", too_many), ("empty", vec![])] {
        let e = Block::from_wire_bytes(&bytes).expect_err(what);
        assert!(!core::is_non_minimal_varint_error(&e), "{what}: {e}");
        assert_eq!(verdict_for_block_decode_error(&e), GossipVerdict::Reject, "{what}: {e}");
    }
}

// ── NET-6 ────────────────────────────────────────────────────────────────────

/// NET-6: a tip claim never latches IBD; it only triggers a rate-limited pull.
/// The latch needs a work-backed orphan that claims to be well ahead.
#[test]
fn claims_only_pull_and_latch_needs_work_backed_evidence() {
    let mut policy = ClaimPolicy::new();
    let t0 = Instant::now();
    let a = policy.evaluate(u64::MAX, 1_000, t0);
    assert!(a.pull && !a.reciprocal);
    for i in 1..50u64 {
        assert!(!policy.evaluate(u64::MAX, 1_000, t0 + Duration::from_millis(i)).pull, "rate-limited");
    }
    let tip_h = 1_000;
    assert!(!orphan_is_sync_evidence(core::POW_LIMIT_BITS, tip_h + gnb::sync::IBD_EXIT_LAG, tip_h, 0));
    assert!(!orphan_is_sync_evidence(0x0480_0001, u64::MAX, tip_h, 0), "malformed bits are never evidence");
}

/// NET-6: claims are attributed to connected authors only, are latest-wins
/// (not a monotonic max) and expire.
#[test]
fn claims_are_author_attributed_latest_and_expiring() {
    let t = PeerStateTable::new();
    let now = Instant::now();
    let relay = PeerId::random();
    let stranger = PeerId::random();
    t.on_connect(relay, now);
    // A claim made by an author we are not connected to is not stored —
    // neither against the author nor against the relay.
    assert!(!t.observe_claim(stranger, u64::MAX, u64::MAX, now));
    assert_eq!(t.best_announced_blue_score_at(now), 0);
    // A connected author's claim counts, latest wins, and it expires.
    assert!(t.observe_claim(relay, 5_000, 10, now));
    assert!(t.observe_claim(relay, 100, 10, now));
    assert_eq!(t.best_announced_blue_score_at(now), 100);
    assert_eq!(t.best_announced_blue_score_at(now + CLAIM_TTL), 0, "stale claims stop counting");
}
