//! Audit PoC tests for the PoW / difficulty paths in gnb-crypto (PoW reviewer).
//!
//! Must run WITHOUT `test-pow-limit` (plain `-p gnb-crypto` does not enable it).
//! Every test is expected to PASS; tests named `finding_*` pass because they
//! demonstrate the reported weakness.
//!
//! Run: cargo test --release --locked -p gnb-crypto --test audit_poc_pow -- --nocapture

use gnb_crypto::core::{
    self, Block, BlockHeader, MerkleRoot, Transaction, TxInput, TxOutput, CHECKPOINT_DEPTH,
    GENESIS_TIMESTAMP, POW_LIMIT_BITS,
};

fn coinbase(tag: u64, value: u64) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid: [0u8; 32],
            prev_index: u32::MAX,
            script_sig: format!("audit-poc:{tag}").into_bytes(),
            sequence: u32::MAX,
        }],
        outputs: vec![TxOutput { value, script_pubkey: vec![7u8; 20] }],
        locktime: 0,
    }
}

fn block(parents: Vec<[u8; 32]>, ts: u64, bits: u32, height: u64, tag: u64) -> Block {
    let txs = vec![coinbase(tag, 0)];
    Block {
        header: BlockHeader {
            version: 1,
            parents,
            merkle_root: Transaction::merkle_root(&txs),
            timestamp: ts,
            bits,
            nonce: 0,
        },
        transactions: txs,
        blue_score: 0,
        height,
        shielded_transactions: vec![],
    }
}

/// POW-free-blocks: a side chain forked from any block >~24 h behind schedule
/// (e.g. genesis, 6 days ago) carries a current timestamp; from its second
/// block on, `expected_bits` is the pow limit and almost every nonce is a
/// valid proof. Every sibling here is a distinct, PoW-valid block whose bits
/// equal the consensus-expected bits, found with ONE evaluation each.
#[test]
fn finding_deep_fork_blocks_are_free_after_one() {
    let now = GENESIS_TIMESTAMP + 6 * 86_400; // a node clock 6 days after genesis
    // S1: parent = genesis, height 1, needs real work at GENESIS_BITS (not mined here).
    assert_eq!(core::expected_bits(GENESIS_TIMESTAMP, 1).unwrap(), core::GENESIS_BITS);
    // S2..: parent S1 has timestamp `now` (allowed: >= parent ts, <= now + 600).
    let s1 = [0x51u8; 32];
    let bits = core::expected_bits(now, 2).unwrap();
    assert_eq!(bits, POW_LIMIT_BITS, "deep-fork child is at the pow limit");
    assert_eq!(core::bits_to_work(bits), 1);
    let mut evaluations = 0;
    for tag in 0..6u64 {
        let mut b = block(vec![s1], now, bits, 2, tag);
        loop {
            evaluations += 1;
            if b.validate_pow() {
                break;
            }
            b.header.nonce += 1;
        }
        assert!(b.validate_structure().is_ok());
    }
    eprintln!("6 distinct pow-limit sibling blocks: {evaluations} evaluations total");
    assert!(evaluations <= 7);
    // The chain stays at the pow limit while it is >= ~24.3 h behind schedule:
    // from a genesis fork 6 days late, ~14,300 consecutive heights are free.
    let mut free_heights = 0u64;
    for h in 2..30_000u64 {
        if core::expected_bits(now, h).unwrap() == POW_LIMIT_BITS {
            free_heights += 1;
        } else {
            break;
        }
    }
    eprintln!("consecutive free heights on a genesis fork at +6 days: {free_heights}");
    assert!(free_heights > 10_000);
}

/// POW-1: `validate_structure()` (run on every ingress path BEFORE
/// `accept_block`'s cheap contextual checks) evaluates the full 64 MiB proof
/// against the header's OWN, attacker-chosen `bits`. A block with unknown
/// parents and bits that match no schedule costs the node one evaluation; at
/// pow-limit bits it even passes and is inserted in the 16,384-entry PoW cache.
#[test]
fn finding_structure_check_runs_pow_on_self_declared_bits() {
    // passes: parents are random, height/timestamp absurd, bits = pow limit
    let junk_parent = [0xAAu8; 32];
    let b = block(vec![junk_parent], 0, POW_LIMIT_BITS, 9_999_999, 1);
    let t0 = std::time::Instant::now();
    assert!(b.validate_structure().is_ok());
    let first = t0.elapsed();
    let t1 = std::time::Instant::now();
    assert!(b.validate_structure().is_ok()); // now a PoW-cache hit
    let cached = t1.elapsed();
    eprintln!("pow-limit junk block: first validate_structure {:?}, cached {:?}", first, cached);
    assert!(cached * 10 < first);

    // fails, but only after a full evaluation; each new nonce is a new id, so
    // the negative result is never cached and every message costs the same.
    let mut cost = std::time::Duration::ZERO;
    for nonce in 0..3u64 {
        let mut hard = block(vec![junk_parent], 0, 0x1D00_FFFF, 1, 2);
        hard.header.nonce = nonce;
        let t = std::time::Instant::now();
        assert_eq!(hard.validate_structure(), Err("invalid PoW"));
        cost += t.elapsed();
    }
    eprintln!("invalid-PoW junk block: {:?} per rejection", cost / 3);
    assert!(cost / 3 > first / 4);
}

/// POW-2 (input side): `height` and `blue_score` are carried on the wire but
/// are not covered by `block_hash()` or the PoW preimage, and `u64::MAX`
/// survives the strict wire decoder. The NewBlock arm in node/src/main.rs then
/// evaluates `height + core::CHECKPOINT_DEPTH`, which panics under the
/// workspace's `overflow-checks = true`.
#[test]
fn finding_wire_height_is_unauthenticated_and_overflows_guard() {
    let mut b = block(vec![[1u8; 32]], GENESIS_TIMESTAMP, POW_LIMIT_BITS, 5, 3);
    let id = b.block_hash();
    let pre = b.header.pow_preimage();
    b.height = u64::MAX;
    b.blue_score = u64::MAX;
    assert_eq!(b.block_hash(), id, "height/blue_score are not committed by the id");
    assert_eq!(b.header.pow_preimage(), pre, "nor by the PoW preimage");
    let wire = b.to_wire_bytes();
    let back = Block::from_wire_bytes(&wire).expect("u64::MAX height decodes");
    assert_eq!(back.height, u64::MAX);
    assert_eq!(back.block_hash(), id);

    // The expression at node/src/main.rs:1120, with the decoded value.
    let height = std::hint::black_box(back.height);
    let r = std::panic::catch_unwind(|| height + CHECKPOINT_DEPTH < std::hint::black_box(20_000u64));
    assert!(r.is_err(), "u64 overflow must panic with overflow-checks = true");
}

/// Difficulty input of a multi-parent block: max(timestamp) over ALL parents
/// (order independent), not the selected parent as node/src/pow/mod.rs:6-7 says.
#[test]
fn difficulty_parent_timestamp_is_max_over_all_parents() {
    assert_eq!(core::difficulty_parent_timestamp([5u64, 9, 7]), 9);
    assert_eq!(core::difficulty_parent_timestamp([9u64, 7, 5]), 9);
    assert_eq!(core::difficulty_parent_timestamp(std::iter::empty()), GENESIS_TIMESTAMP);
    // out-of-range timestamps fail closed (no panic)
    assert!(core::expected_bits(u64::MAX, 1).is_err());
    assert!(core::expected_bits(GENESIS_TIMESTAMP, 0).is_err());
}

/// Timestamp rule: only `ts >= max parent ts` and `ts <= now + 600`; no
/// median-time-past. Shown here: equal to parent passes, one below fails.
#[test]
fn timestamp_rule_is_monotone_not_mtp() {
    let b = block(vec![[2u8; 32]], 1_000, POW_LIMIT_BITS, 1, 4);
    assert!(b.validate_timestamp(1_000).is_ok());
    assert_eq!(b.validate_timestamp(1_001), Err("timestamp before parent"));
    let far = block(vec![[2u8; 32]], u64::MAX, POW_LIMIT_BITS, 1, 5);
    assert_eq!(far.validate_timestamp(0), Err("timestamp too far in the future"));
    let _ = MerkleRoot::ZERO;
}
