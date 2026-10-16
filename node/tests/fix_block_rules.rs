//! Regression tests for the block-validity fixes of the hardening activation
//! (package P1): VAL-2 (BIP34 height + parents commitment, BIP30
//! no-overwrite, undo convergence), VAL-3 (no same-block coinbase spend),
//! VAL-10 (tagged Merkle root, 64-byte transactions), CRY-1 (witness
//! commitment), VAL-12 (wire-size block limit), POW-3 (pow limit).
//!
//! Every block goes through the REAL pipeline (`validate_structure` +
//! `gnb::accept::accept_block`, see `fix_common::accept`). Each rule is
//! exercised in both regimes with `activation::scoped_override` (a per-thread
//! override; every call below runs on the test thread): `NEVER` reproduces
//! the old rules, `0` (or a small height) applies the new ones. The GhostDAG
//! of `fix_common::node_with` reads the same value at construction. The
//! transaction rules of the same activation (package P2: version 3, sighash
//! v3, canonical witnesses) apply in the new regime too, so spends that must
//! be valid there are signed with `fix_common::signed_spend_at` (version 1 /
//! sighash v2 below the activation, version 3 / sighash v3 from it).

mod fix_common;
use fix_common::*;

use gnb::consensus::BlockHash;
use gnb::core::{self, activation, block_rules, Block, BlockHeader, MerkleRoot, Transaction, TxInput, TxOutput};
use gnb::mempool::admission::{self, AdmissionError, AdmissionPolicy};
use gnb::reorg::{self, ConnectError, ConnectHooks, ReorgPlan, UtxoView};
use gnb::storage::Storage;
use gnb::{accept as pipeline, pow, template};

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Write the coinbase commitment (when the rules of the block's height
/// require it; the coinbase's current `script_sig` becomes the miner's extra
/// bytes) and the header root of the block's height.
fn commit(b: &mut Block) {
    if block_rules::rules_active(b.height) {
        let c = block_rules::expected_coinbase_commitment(b);
        let extra = std::mem::take(&mut b.transactions[0].inputs[0].script_sig);
        b.transactions[0].inputs[0].script_sig = block_rules::coinbase_script_sig(&c, &extra);
    }
    b.header.merkle_root = b.body_merkle_root();
}

/// Mine `b` as-is (header unchanged otherwise).
fn mine(mut b: Block, pred: impl Fn(&BlockHash) -> bool) -> Block {
    loop {
        if pred(&b.block_hash()) && b.validate_pow() {
            return b;
        }
        b.header.nonce += 1;
    }
}

/// An unsealed block on `parents` carrying `txs` with the consensus height,
/// bits and timestamp.
fn raw_block(n: &Node, parents: Vec<BlockHash>, txs: Vec<Transaction>) -> Block {
    let (height, parent_ts) = {
        let d = n.dag.read();
        let h = parents.iter().map(|p| d.get_block_data(p).expect("parent known").height).max().unwrap() + 1;
        let ts = parents.iter().map(|p| d.get_block_data(p).unwrap().timestamp).max().unwrap();
        (h, ts)
    };
    Block {
        header: BlockHeader {
            version: 1,
            parents,
            merkle_root: MerkleRoot::ZERO,
            timestamp: parent_ts + 1,
            bits: pow::expected_bits(parent_ts, height).unwrap(),
            nonce: 0,
        },
        transactions: txs,
        blue_score: height,
        height,
        shielded_transactions: Vec::new(),
    }
}

/// A valid block for the rules of its height (commitment, header root, PoW).
fn build_where(n: &Node, parents: Vec<BlockHash>, txs: Vec<Transaction>, pred: impl Fn(&BlockHash) -> bool) -> Block {
    let mut b = raw_block(n, parents, txs);
    commit(&mut b);
    mine(b, pred)
}

fn build(n: &Node, parents: Vec<BlockHash>, txs: Vec<Transaction>) -> Block {
    build_where(n, parents, txs, |_| true)
}

fn subsidy(h: u64) -> u64 {
    core::tokenomics::block_subsidy_sat(h)
}

/// Accept through `accept_block` only (no `validate_structure` gate), as an
/// in-process caller could.
fn accept_direct(n: &Node, b: &Block) -> Result<BlockHash, String> {
    pipeline::accept_block(b, b.block_hash(), b.height, &n.dag, &n.store, &n.mempool, &n.node_state,
        Some(&n.tip_tx), &n.shielded)
}

/// NET-12 (merge P1 x P4): the explorer aggregates kept in the UTXO write
/// batches equal a full recomputation, and the start-up check finds them
/// describing the connected chain (no rebuild needed).
fn assert_aggregates_consistent(store: &Storage, what: &str) {
    let stored = store.aggregate_snapshot().unwrap();
    let full = store.recompute_aggregates(&std::sync::atomic::AtomicBool::new(false)).unwrap();
    assert_eq!(stored, full, "{what}: incremental aggregates != full recomputation");
    assert!(store.aggregates_match_connected_chain().unwrap(), "{what}: the start-up rebuild check would fire");
}

/// The block left no trace: not in the DAG, no body, no invalid mark.
fn assert_not_stored(n: &Node, b: &Block) {
    let id = b.block_hash();
    assert!(!n.dag.read().has_block(&id), "block must not be in the DAG");
    assert!(n.store.get_block(&id).unwrap().is_none(), "block body must not be stored");
    assert!(n.store.invalid_block_reason(&id).unwrap().is_none(), "no invalid mark for the block id");
}

// ── VAL-2: duplicate coinbase (BIP34) ────────────────────────────────────────

/// The finding's attack: a miner repeats a coinbase (same script, value and
/// address within one halving epoch), so two blocks share one coinbase txid.
/// Before the activation the second block is accepted and overwrites the coin
/// (old behaviour, unchanged). From the activation the copied coinbase
/// commits to the wrong height (and parents) and the block is refused before
/// it is stored; the first coin keeps its coinbase-height row.
#[test]
fn val2_duplicate_coinbase_accepted_before_activation_rejected_after() {
    for hardened in [false, true] {
        let _g = activation::scoped_override(if hardened { 0 } else { activation::NEVER });
        let genesis = mk_genesis(unix_now() - 10_000);
        let gh = genesis.block_hash();
        let n = node_with(&genesis, &[]);
        assert_eq!(subsidy(1), subsidy(2), "one halving epoch: same coinbase value");

        let b1 = build(&n, vec![gh], vec![coinbase("same coinbase twice", subsidy(1), vec![0xD0; 20])]);
        accept(&n, &b1).unwrap();
        let cb = b1.transactions[0].clone();
        let c = cb.txid();

        // B2 carries B1's coinbase byte for byte.
        let mut b2 = raw_block(&n, vec![b1.block_hash()], vec![cb.clone()]);
        b2.header.merkle_root = b2.body_merkle_root();
        let b2 = mine(b2, |_| true);
        assert_eq!(b2.transactions[0].txid(), c, "same coinbase txid");
        if hardened {
            let err = accept(&n, &b2).unwrap_err();
            assert!(err.contains("bad-cb-height"), "{err}");
            let err = accept_direct(&n, &b2).unwrap_err();
            assert!(err.contains("bad-cb-height"), "{err}");
            assert_not_stored(&n, &b2);
            assert_eq!(n.store.get_coinbase_height(&c).unwrap(), Some(1));
            assert_eq!(applied_tip(&n), Some(b1.block_hash()));
        } else {
            accept(&n, &b2).expect("old rules: a duplicate coinbase is valid");
            assert_eq!(applied_tip(&n), Some(b2.block_hash()));
            assert_eq!(n.store.get_coinbase_height(&c).unwrap(), Some(2), "the coin was overwritten");
        }
    }
}

/// Two coinbases of one selected chain can never coincide after the
/// activation, even when their HEADER heights are equal (the header height
/// is max(parent DAG heights) + 1 and is not monotone along a selected chain,
/// DAG-8): the commitment also covers the parent list, and a block's parent
/// set never equals an ancestor's.
#[test]
fn val2_commitment_differs_for_equal_heights_with_different_parents() {
    let parents_a = vec![[1u8; 32]];
    let parents_b = vec![[1u8; 32], [2u8; 32]];
    let wr = block_rules::witness_root(&[coinbase("x", 1, vec![1; 20])]);
    assert_ne!(
        block_rules::coinbase_commitment(7, &parents_a, &wr),
        block_rules::coinbase_commitment(7, &parents_b, &wr),
    );
}

// ── VAL-2: BIP30 no-overwrite (connect-time, the shared rule) ───────────────

/// A block whose output would overwrite an UNSPENT coin is invalid from the
/// activation, in `validate_block_in_view` — the function behind the
/// extension, reorg and re-validation paths. Before the activation the same
/// block is valid (old behaviour: it overwrites).
#[test]
fn val2_bip30_overwrite_of_an_unspent_coin_is_invalid_after_activation() {
    for hardened in [false, true] {
        let _g = activation::scoped_override(if hardened { 0 } else { activation::NEVER });
        let genesis = mk_genesis(unix_now() - 10_000);
        let gh = genesis.block_hash();
        let k = key();
        let fund = ([0x30u8; 32], 0u32, out(2_000_000, &k.spk));
        let n = node_with(&genesis, std::slice::from_ref(&fund));
        let spend = signed_spend(&k, &[(fund.0, 0)], vec![out(1_900_000, &[0x31; 20])]);
        let b = build(&n, vec![gh], vec![coinbase("bip30", subsidy(1) + 100_000, vec![0xB3; 20]), spend.clone()]);

        // An unspent coin already sits at the coinbase's and at the spend's
        // first outpoint (models a coin created before the activation).
        let stale = out(777, &[0x77; 20]);
        n.store.put_utxo(&b.transactions[0].txid(), 0, &stale).unwrap();
        n.store.put_utxo(&spend.txid(), 0, &stale).unwrap();

        let view: &Storage = &n.store;
        let shared = pipeline::validate_block_in_view(view as &dyn UtxoView, &b);
        if hardened {
            let err = shared.unwrap_err();
            assert!(err.starts_with("BIP30"), "{err}");
            let err = accept(&n, &b).unwrap_err();
            assert!(err.contains("BIP30"), "{err}");
            assert_eq!(applied_tip(&n), Some(gh), "nothing connected");
            assert_eq!(n.store.get_utxo(&b.transactions[0].txid(), 0).unwrap().unwrap().value, 777);
            // Without the colliding coins the same block connects.
            assert!(pipeline::validate_block_in_view_at(view, &b, activation::NEVER).is_ok());
        } else {
            shared.expect("old rules: overwriting is allowed");
            accept(&n, &b).expect("old rules");
            assert_eq!(n.store.get_utxo(&spend.txid(), 0).unwrap().unwrap().value, 1_900_000, "overwritten");
        }
    }
}

// ── VAL-2: undo restores an overwritten coin (all heights) ──────────────────

/// Node A applies B2, whose coinbase repeats B1's (old rules), then reorgs
/// it away; node B never sees B2. Both must end with the same UTXO set and
/// the same coinbase-height and tx-index rows. Before the undo fix A's
/// rollback deleted B1's coin and its coinbase row: a later spend of it was
/// valid on B and invalid on A (chain split).
#[test]
fn val2_overwrite_then_rollback_converges_with_a_node_that_never_applied_it() {
    let _g = activation::scoped_override(activation::NEVER);
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let a = node_with(&genesis, &[]);
    let b = node_with(&genesis, &[]);

    let dup = coinbase("repeated coinbase", subsidy(1), vec![0xD1; 20]);
    let c = dup.txid();
    let b1 = build(&a, vec![gh], vec![dup.clone()]);
    accept(&a, &b1).unwrap();
    accept(&b, &b1).unwrap();
    let b2 = build(&a, vec![b1.block_hash()], vec![dup.clone()]);
    accept(&a, &b2).unwrap();
    assert_eq!(applied_tip(&a), Some(b2.block_hash()));
    assert_aggregates_consistent(&a.store, "B2 overwrote B1's coin");
    let undo = a.store.get_undo_data(&b2.block_hash()).unwrap().unwrap();
    assert_eq!(undo.overwritten.utxos.len(), 1, "the replaced coin is in the undo record");
    assert_eq!(undo.overwritten.coinbase_heights, vec![(c, 1)]);
    assert_eq!(undo.overwritten.tx_index, vec![(c, b1.block_hash(), 1)]);

    // A heavier fork that does not contain B2 (f2 loses the first tie).
    let f2 = build_where(&a, vec![b1.block_hash()], vec![coinbase("f2", subsidy(2), vec![0xF2; 20])],
        |h| *h < b2.block_hash());
    accept(&a, &f2).unwrap();
    assert_eq!(applied_tip(&a), Some(b2.block_hash()), "B2 still applied");
    let f3 = build(&a, vec![f2.block_hash()], vec![coinbase("f3", subsidy(3), vec![0xF3; 20])]);
    accept(&a, &f3).expect("reorg away from B2");
    assert_eq!(applied_tip(&a), Some(f3.block_hash()));
    for blk in [&f2, &f3] {
        accept(&b, blk).unwrap();
    }
    assert_eq!(applied_tip(&b), Some(f3.block_hash()));

    assert!(a.store.get_utxo(&c, 0).unwrap().is_some(), "B1's coin survives B2's rollback");
    assert_eq!(a.store.iter_utxos_sorted().unwrap(), b.store.iter_utxos_sorted().unwrap(), "same UTXO set");
    assert_eq!(a.store.get_coinbase_height(&c).unwrap(), Some(1));
    assert_eq!(a.store.get_coinbase_height(&c).unwrap(), b.store.get_coinbase_height(&c).unwrap());
    assert_eq!(a.store.get_tx_location(&c).unwrap(), b.store.get_tx_location(&c).unwrap());
    // The explorer aggregates converge too (merge P1 x P4).
    assert_aggregates_consistent(&a.store, "B2 rolled back");
    assert_eq!(a.store.aggregate_snapshot().unwrap(), b.store.aggregate_snapshot().unwrap(), "same aggregates");
}

/// The same convergence on the standalone storage primitives
/// (`reorg::apply_block_utxo_mutations` / `Storage::rollback_block`).
#[test]
fn val2_storage_rollback_restores_the_overwritten_rows() {
    let tmp = tempfile::TempDir::new().unwrap();
    let store = Storage::open(&tmp.path().join("db")).unwrap();
    let dup = coinbase("dup", 5_000, vec![0xD2; 20]);
    let c = dup.txid();
    let mk = |height: u64, nonce: u64| Block {
        header: BlockHeader { version: 1, parents: vec![], merkle_root: MerkleRoot::ZERO, timestamp: 1, bits: 0, nonce },
        transactions: vec![dup.clone()],
        blue_score: height,
        height,
        shielded_transactions: vec![],
    };
    let (b1, b2) = (mk(1, 1), mk(2, 2));
    store.put_block(&b1).unwrap();
    reorg::apply_block_utxo_mutations(&store, &b1).unwrap();
    let before = store.iter_utxos_sorted().unwrap();
    let aggregates_before = store.aggregate_snapshot().unwrap();
    store.put_block(&b2).unwrap();
    reorg::apply_block_utxo_mutations(&store, &b2).unwrap();
    assert_eq!(store.get_coinbase_height(&c).unwrap(), Some(2));
    assert_aggregates_consistent(&store, "standalone overwrite");
    store.rollback_block(&b2.block_hash()).unwrap();
    assert_eq!(store.iter_utxos_sorted().unwrap(), before);
    assert_aggregates_consistent(&store, "standalone rollback");
    assert_eq!(store.aggregate_snapshot().unwrap().holders, aggregates_before.holders);
    assert_eq!(store.get_coinbase_height(&c).unwrap(), Some(1));
    assert_eq!(store.get_tx_location(&c).unwrap(), Some((b1.block_hash(), 1)));
}

/// Merge P1 x P4 (NET-12): the coin a block overwrites belongs to ANOTHER
/// holder with another value (the BIP30 case: a coin already sits at the
/// outpoint of a later transaction's output, valid before the activation).
/// Connecting the block moves the balance to the new owner; disconnecting it
/// — through a reorg (`reorg::connect_plan`, one batch) and through the
/// standalone primitives (`Storage::rollback_block`) — restores the old
/// owner's coin from `UndoData.overwritten`, and the holder aggregates,
/// supply tiers and rich list follow every step (equal to a full
/// recomputation; the start-up check needs no rebuild; a rebuild changes
/// nothing).
#[test]
fn val2_overwritten_coin_restore_keeps_the_explorer_aggregates() {
    use std::sync::atomic::AtomicBool;
    let _g = activation::scoped_override(activation::NEVER);
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0x3Au8; 32], 0u32, out(2_000_000, &k.spk));
    let n = node_with(&genesis, std::slice::from_ref(&fund));
    let spend = signed_spend(&k, &[(fund.0, 0)], vec![out(1_900_000, &[0x3B; 20])]);
    let (old_owner, new_owner) = ([0x77u8; 20], [0x3Bu8; 20]);
    let holder = |st: &Storage, a: &[u8; 20]| st.holder(a).unwrap().map(|h| (h.balance, h.utxos));

    // (a) Through the acceptance pipeline and a reorg.
    n.store.put_utxo(&spend.txid(), 0, &out(777, &old_owner)).unwrap();
    assert_aggregates_consistent(&n.store, "stale coin placed");
    assert_eq!(holder(&n.store, &old_owner), Some((777, 1)));
    let b = build(&n, vec![gh], vec![coinbase("ow", subsidy(1) + 100_000, vec![0xB4; 20]), spend.clone()]);
    accept(&n, &b).expect("old rules: overwriting is allowed");
    assert_eq!(applied_tip(&n), Some(b.block_hash()));
    assert_eq!(n.store.get_undo_data(&b.block_hash()).unwrap().unwrap().overwritten.utxos.len(), 1);
    assert_aggregates_consistent(&n.store, "overwrite connected");
    assert_eq!(holder(&n.store, &old_owner), None, "the old owner's coin was overwritten");
    assert_eq!(holder(&n.store, &new_owner), Some((1_900_000, 1)));
    let f1 = build_where(&n, vec![gh], vec![coinbase("f1", subsidy(1), vec![0xF1; 20])], |h| *h < b.block_hash());
    accept(&n, &f1).unwrap();
    let f2 = build(&n, vec![f1.block_hash()], vec![coinbase("f2", subsidy(2), vec![0xF2; 20])]);
    accept(&n, &f2).expect("reorg away from the overwriting block");
    assert_eq!(applied_tip(&n), Some(f2.block_hash()));
    assert_eq!(n.store.get_utxo(&spend.txid(), 0).unwrap().map(|o| o.value), Some(777), "restored");
    assert_aggregates_consistent(&n.store, "overwrite rolled back by a reorg");
    assert_eq!(holder(&n.store, &old_owner), Some((777, 1)), "the old owner's balance is back");
    assert_eq!(holder(&n.store, &new_owner), None);
    assert!(!n.store.ensure_aggregates().unwrap(), "no start-up rebuild needed");
    let snap = n.store.aggregate_snapshot().unwrap();
    assert_eq!(n.store.rebuild_aggregates(&AtomicBool::new(false)).unwrap(), snap, "a rebuild changes nothing");

    // (b) The standalone primitives.
    let tmp = tempfile::TempDir::new().unwrap();
    let store = Storage::open(&tmp.path().join("db")).unwrap();
    let mk = |height: u64, txs: Vec<Transaction>| Block {
        header: BlockHeader { version: 1, parents: vec![], merkle_root: MerkleRoot::ZERO, timestamp: 1, bits: 0, nonce: height },
        transactions: txs,
        blue_score: height,
        height,
        shielded_transactions: vec![],
    };
    store.put_utxo(&fund.0, 0, &fund.2).unwrap();
    store.put_utxo(&spend.txid(), 0, &out(777, &old_owner)).unwrap();
    let b1 = mk(1, vec![coinbase("sb", 5_000, vec![0xB5; 20]), spend.clone()]);
    store.put_block(&b1).unwrap();
    reorg::apply_block_utxo_mutations(&store, &b1).unwrap();
    assert_aggregates_consistent(&store, "standalone overwrite");
    assert_eq!(holder(&store, &old_owner), None);
    store.rollback_block(&b1.block_hash()).unwrap();
    assert_aggregates_consistent(&store, "standalone rollback");
    assert_eq!(holder(&store, &old_owner), Some((777, 1)));
    assert_eq!(holder(&store, &new_owner), None);
    assert_eq!(store.chain_totals().unwrap().blocks, 0);
}

// ── VAL-3: no spend of the same block's coinbase ─────────────────────────────

/// `[coinbase paying k, tx spending that coinbase]` at height 1.
fn same_block_coinbase_spend(n: &Node, k: &Key, parent: BlockHash, coinbase_extra: Vec<u8>) -> Block {
    let fee = 100_000;
    let mut cb = coinbase("cb", subsidy(1) + fee, k.spk.clone());
    cb.inputs[0].script_sig = coinbase_extra;
    let spend = signed_spend(k, &[(cb.txid(), 0)], vec![out(subsidy(1), &[0x33; 20])]);
    let mut b = raw_block(n, vec![parent], vec![cb, spend]);
    b.header.merkle_root = b.body_merkle_root();
    b
}

/// Extension (accept) and connect paths. Before the activation the spend is
/// valid (old behaviour). From it, the shared connect rule rejects it; on the
/// acceptance path such a block cannot even carry a valid coinbase commitment
/// (the commitment covers the spend's wtxid, which covers the coinbase txid,
/// which covers the commitment), so it is refused before being stored.
#[test]
fn val3_same_block_coinbase_spend_on_the_extension_and_connect_paths() {
    let k = key();
    // Connect path, both regimes, one block.
    {
        let genesis = mk_genesis(unix_now() - 10_000);
        let n = node_with(&genesis, &[]);
        let x = same_block_coinbase_spend(&n, &k, genesis.block_hash(), b"legacy".to_vec());
        let view: &Storage = &n.store;
        pipeline::validate_block_in_view_at(view, &x, activation::NEVER).expect("old rules: valid");
        let err = pipeline::validate_block_in_view_at(view, &x, 0).unwrap_err();
        assert!(err.contains("spends the coinbase of its own block"), "{err}");
        let err = pipeline::validate_block_in_view_at(view, &x, 1).unwrap_err();
        assert!(err.contains("spends the coinbase of its own block"), "height 1 >= activation 1: {err}");
        pipeline::validate_block_in_view_at(view, &x, 2).expect("height 1 < activation 2");
    }
    // Acceptance (extension) path.
    for hardened in [false, true] {
        let _g = activation::scoped_override(if hardened { 0 } else { activation::NEVER });
        let genesis = mk_genesis(unix_now() - 10_000);
        let gh = genesis.block_hash();
        let n = node_with(&genesis, &[]);
        let mut extra = b"legacy".to_vec();
        if hardened {
            // Best effort: a commitment for the block as it stood before the
            // spend was signed (any commitment is stale once it is).
            let probe = same_block_coinbase_spend(&n, &k, gh, vec![]);
            let mut ss = block_rules::expected_coinbase_commitment(&probe).to_vec();
            ss.extend_from_slice(b"x");
            extra = ss;
        }
        let x = mine(same_block_coinbase_spend(&n, &k, gh, extra), |_| true);
        let spend_txid = x.transactions[1].txid();
        if hardened {
            let err = accept(&n, &x).unwrap_err();
            assert!(err.contains("witness commitment"), "{err}");
            assert_not_stored(&n, &x);
        } else {
            accept(&n, &x).expect("old rules: same-block coinbase spend is valid");
            assert_eq!(applied_tip(&n), Some(x.block_hash()));
            assert!(n.store.get_utxo(&x.transactions[0].txid(), 0).unwrap().is_none(), "spent in its block");
            assert!(n.store.get_utxo(&spend_txid, 0).unwrap().is_some());
        }
    }
}

/// Reorg path: the block first arrives as a fork-loser (stored without
/// validation) and is connected when its branch becomes heavier. Before the
/// activation it is connected (old behaviour, the pipeline uses the shared
/// rule for reorgs too); from it, the reorg connect of the same block with
/// the pipeline's validator fails and nothing is committed.
#[test]
fn val3_same_block_coinbase_spend_on_the_reorg_path() {
    let k = key();
    // Old rules, through the whole pipeline.
    {
        let _g = activation::scoped_override(activation::NEVER);
        let genesis = mk_genesis(unix_now() - 10_000);
        let gh = genesis.block_hash();
        let n = node_with(&genesis, &[]);
        let m1 = build(&n, vec![gh], vec![coinbase("m1", subsidy(1), vec![0x01; 20])]);
        accept(&n, &m1).unwrap();
        let x = mine(same_block_coinbase_spend(&n, &k, gh, b"fork".to_vec()), |h| *h < m1.block_hash());
        accept(&n, &x).expect("fork-loser: stored, not evaluated");
        assert_eq!(applied_tip(&n), Some(m1.block_hash()));
        let x2 = build(&n, vec![x.block_hash()], vec![coinbase("x2", subsidy(2), vec![0x02; 20])]);
        accept(&n, &x2).expect("reorg onto the branch with the same-block coinbase spend");
        assert_eq!(applied_tip(&n), Some(x2.block_hash()));
        assert!(n.store.get_utxo(&x.transactions[1].txid(), 0).unwrap().is_some());
    }
    // New rules: the reorg connect (`reorg::connect_plan` with the
    // pipeline's validator) refuses the same block and commits nothing. (The
    // pipeline itself never stores such a block after the activation.)
    for (act, ok) in [(activation::NEVER, true), (0, false)] {
        let _g = activation::scoped_override(act);
        let genesis = mk_genesis(unix_now() - 10_000);
        let gh = genesis.block_hash();
        let n = node_with(&genesis, &[]);
        let m1 = build(&n, vec![gh], vec![coinbase("m1", subsidy(1), vec![0x01; 20])]);
        accept(&n, &m1).unwrap();
        let x = mine(same_block_coinbase_spend(&n, &k, gh, b"fork".to_vec()), |_| true);
        n.store.put_block(&x).unwrap();
        let plan = ReorgPlan { lca: gh, to_rollback: vec![m1.block_hash()], to_apply: vec![x.block_hash()] };
        let validate = |v: &dyn UtxoView, b: &Block| pipeline::validate_block_in_view(v, b).map_err(reorg::ValidationFailure::Invalid);
        let none = |_: &Storage, _: &mut rocksdb::WriteBatch| -> Result<(), String> { Ok(()) };
        let res = reorg::connect_plan(&n.store, &plan, &ConnectHooks { validate: &validate, stage_extra: &none });
        if ok {
            res.expect("old rules: the fork block connects");
        } else {
            match res {
                Err(ConnectError::Invalid { block, reason, .. }) => {
                    assert_eq!(block, x.block_hash());
                    assert!(reason.contains("spends the coinbase of its own block"), "{reason}");
                }
                other => panic!("expected an invalid fork block, got {other:?}"),
            }
            assert!(n.store.get_utxo(&m1.transactions[0].txid(), 0).unwrap().is_some(), "m1 still applied");
        }
    }
}

/// Mempool path: a coinbase output can only be referenced once its block is
/// connected, and then it is immature (1 confirmation): admission refuses the
/// spend, and a pool that holds one anyway never puts it into a template.
#[test]
fn val3_mempool_and_template_never_spend_a_fresh_coinbase() {
    for hardened in [false, true] {
        let _g = activation::scoped_override(if hardened { 0 } else { activation::NEVER });
        let genesis = mk_genesis(unix_now() - 10_000);
        let gh = genesis.block_hash();
        let k = key();
        let n = node_with(&genesis, &[]);
        let b1 = build(&n, vec![gh], vec![coinbase("b1", subsidy(1), k.spk.clone())]);
        accept(&n, &b1).unwrap();
        let policy = AdmissionPolicy::relay(admission::next_block_height(&n.dag.read()));
        // Valid for the next block's version rule (P2), so admission reaches
        // the maturity check.
        let spend = signed_spend_at(&k, &[(b1.transactions[0].txid(), 0)], &b1.transactions[0].outputs,
            vec![out(subsidy(1) - 100_000, &[0x34; 20])], policy.next_block_height);
        match admission::admit(&n.store, &n.mempool, spend.clone(), &policy) {
            Err(AdmissionError::Immature(_)) => {}
            other => panic!("expected Immature, got {other:?}"),
        }
        n.mempool.add(spend.clone(), 100_000).unwrap();
        let tmpl = template::build_block_template(&n.dag, &n.store, &n.mempool, template::EXTERNAL_COINBASE_RESERVE).unwrap();
        assert!(tmpl.transactions.is_empty(), "the immature spend is not mined");
        assert_eq!(tmpl.evicted, 1);
        assert_eq!(tmpl.hardened, hardened);
    }
}

// ── CRY-1: witness commitment ────────────────────────────────────────────────

/// The PoC: a relay pads a witness (bytes after the public key, which the
/// verifier ignores) or substitutes another valid signature. Block id, txids
/// and header root are unchanged. From the activation the altered copy fails
/// the witness commitment and is refused WITHOUT being stored or marked
/// invalid, so the honest copy with the same id is accepted afterwards.
/// Before the activation the altered copy is accepted (old behaviour).
#[test]
fn cry1_witness_padding_and_swap_rejected_without_storing_the_block() {
    for hardened in [false, true] {
        let _g = activation::scoped_override(if hardened { 0 } else { activation::NEVER });
        let genesis = mk_genesis(unix_now() - 10_000);
        let gh = genesis.block_hash();
        let k = key();
        let fund = ([0x41u8; 32], 0u32, out(3_000_000, &k.spk));
        let n = node_with(&genesis, std::slice::from_ref(&fund));
        let tx = signed_spend_at(&k, &[(fund.0, 0)], std::slice::from_ref(&fund.2), vec![out(2_900_000, &[0x42; 20])], 1);
        let honest = build(&n, vec![gh], vec![coinbase("cry1", subsidy(1) + 100_000, vec![0xC1; 20]), tx.clone()]);

        let mut padded = honest.clone();
        padded.transactions[1].inputs[0].script_sig.extend_from_slice(&[0u8; 1_000]);
        assert_eq!(padded.block_hash(), honest.block_hash(), "same block id");
        assert_eq!(padded.transactions[1].txid(), tx.txid(), "same txid");
        assert!(padded.wire_size() > honest.wire_size());

        if hardened {
            let err = accept(&n, &padded).unwrap_err();
            assert!(err.contains("witness commitment"), "{err}");
            let err = accept_direct(&n, &padded).unwrap_err();
            assert!(err.contains("witness commitment"), "{err}");
            assert_not_stored(&n, &padded);

            // A re-signed witness (another valid signature, same txid).
            let resigned = signed_spend_at(&k, &[(fund.0, 0)], std::slice::from_ref(&fund.2), vec![out(2_900_000, &[0x42; 20])], 1);
            if resigned.inputs[0].script_sig != tx.inputs[0].script_sig {
                let mut swapped = honest.clone();
                swapped.transactions[1] = resigned;
                assert_eq!(swapped.block_hash(), honest.block_hash());
                let err = accept_direct(&n, &swapped).unwrap_err();
                assert!(err.contains("witness commitment"), "{err}");
                assert_not_stored(&n, &swapped);
            }

            accept(&n, &honest).expect("the honest copy of the same id is still accepted");
            assert_eq!(applied_tip(&n), Some(honest.block_hash()));
        } else {
            accept(&n, &padded).expect("old rules: nothing commits to witnesses");
            assert_eq!(applied_tip(&n), Some(padded.block_hash()));
        }
    }
}

// ── VAL-10: 64-byte transactions, Merkle mutation ───────────────────────────

/// A signed one-input, one-output transaction paying a 5-byte script has a
/// 64-byte txid preimage. Valid before the activation (block and mempool);
/// rejected from it, by the structural gate, by `accept_block` itself, by
/// admission, and evicted by the template.
#[test]
fn val10_64_byte_transaction_is_rejected_after_activation() {
    for hardened in [false, true] {
        let _g = activation::scoped_override(if hardened { 0 } else { activation::NEVER });
        let genesis = mk_genesis(unix_now() - 10_000);
        let gh = genesis.block_hash();
        let k = key();
        let funds = [([0x51u8; 32], 0u32, out(2_000_000, &k.spk)), ([0x52u8; 32], 0u32, out(2_000_000, &k.spk))];
        let n = node_with(&genesis, &funds);
        let tx64 = signed_spend_at(&k, &[(funds[0].0, 0)], std::slice::from_ref(&funds[0].2), vec![out(1_900_000, &[0x05; 5])], 1);
        assert_eq!(tx64.to_wire_bytes(false).len(), 64);

        let policy = AdmissionPolicy::relay(admission::next_block_height(&n.dag.read()));
        let b = build(&n, vec![gh], vec![coinbase("v10", subsidy(1) + 100_000, vec![0xA1; 20]), tx64.clone()]);
        if hardened {
            let err = admission::admit(&n.store, &n.mempool, tx64.clone(), &policy).unwrap_err();
            assert!(err.to_string().contains("64-byte"), "{err}");
            let err = accept(&n, &b).unwrap_err();
            assert!(err.contains("64-byte"), "{err}");
            let err = accept_direct(&n, &b).unwrap_err();
            assert!(err.contains("64-byte"), "{err}");
            assert_not_stored(&n, &b);
            // Pooled before the activation (simulated): the template evicts it.
            n.mempool.add(tx64.clone(), 100_000).unwrap();
            let ok = signed_spend_at(&k, &[(funds[1].0, 0)], std::slice::from_ref(&funds[1].2), vec![out(1_900_000, &[0x06; 20])], 1);
            n.mempool.add(ok.clone(), 100_000).unwrap();
            let tmpl = template::build_block_template(&n.dag, &n.store, &n.mempool, template::EXTERNAL_COINBASE_RESERVE).unwrap();
            assert_eq!(tmpl.evicted, 1);
            assert_eq!(tmpl.transactions.len(), 1);
            assert_eq!(tmpl.transactions[0].0.txid(), ok.txid());
        } else {
            admission::admit(&n.store, &n.mempool, tx64.clone(), &policy).expect("old rules: admitted");
            accept(&n, &b).expect("old rules: a 64-byte transaction is valid");
            assert_eq!(applied_tip(&n), Some(b.block_hash()));
        }
    }
}

/// P1 x P2: the 64-byte rule is one of the next-block height rules
/// (`admission::check_tx_for_next_block`, together with the version rule), so
/// admission, the re-check under the acceptance lock, post-connect eviction
/// (`accept::evict_version_invalid`), `accept::revalidate_mempool` and the
/// template self-check apply it at the same height as the version rule.
#[test]
fn the_64_byte_rule_is_a_next_block_height_rule() {
    const H: u64 = 3;
    let _g = activation::scoped_override(H);
    let k = key();
    let fund = |tag: u8| ([tag; 32], 0u32, out(2_000_000, &k.spk));
    let (f1, f2, f3) = (fund(0x81), fund(0x82), fund(0x83));
    let spend = |f: &([u8; 32], u32, TxOutput), spk: &[u8], height: u64| {
        signed_spend_at(&k, &[(f.0, f.1)], std::slice::from_ref(&f.2), vec![out(1_900_000, spk)], height)
    };
    let tx64_v1 = spend(&f1, &[0x05; 5], H - 1);
    let tx64_v3 = spend(&f2, &[0x05; 5], H);
    let ok_v3 = spend(&f3, &[0x06; 20], H);
    assert_eq!((tx64_v1.version, tx64_v3.version), (1, 3));
    assert_eq!(tx64_v1.to_wire_bytes(false).len(), 64);
    assert_eq!(tx64_v3.to_wire_bytes(false).len(), 64);
    admission::check_tx_for_next_block(&tx64_v1, H - 1).expect("below the activation: valid and standard");
    let e = admission::check_tx_for_next_block(&tx64_v3, H).unwrap_err();
    assert!(e.contains("64-byte"), "{e}");
    admission::check_tx_for_next_block(&ok_v3, H).expect("an ordinary version-3 spend");
    let e = admission::check_tx_for_next_block(&tx64_v1, H).unwrap_err();
    assert!(e.contains("bad-txns-version"), "the version rule is checked first: {e}");

    // Post-connect eviction at the new next height drops exactly the
    // transaction the 64-byte rule forbids there.
    let pool = gnb::mempool::Mempool::new();
    pool.add(tx64_v3.clone(), 100_000).unwrap();
    pool.add(ok_v3.clone(), 100_000).unwrap();
    assert_eq!(pipeline::evict_version_invalid(&pool, H), 1);
    assert!(pool.contains(&ok_v3.txid()) && !pool.contains(&tx64_v3.txid()));
}

/// CVE-2012-2459 shape: `[cb, A, B]` and `[cb, A, B, B]` share the legacy
/// root, so before the activation only the duplicate-transaction rule stops
/// the mutated copy. From the activation the tagged root differs: the
/// mutated copy no longer matches the header at all.
#[test]
fn val10_duplicated_last_transaction_changes_the_tagged_root() {
    for hardened in [false, true] {
        let _g = activation::scoped_override(if hardened { 0 } else { activation::NEVER });
        let genesis = mk_genesis(unix_now() - 10_000);
        let gh = genesis.block_hash();
        let k = key();
        let funds = [([0x61u8; 32], 0u32, out(2_000_000, &k.spk)), ([0x62u8; 32], 0u32, out(2_000_000, &k.spk))];
        let n = node_with(&genesis, &funds);
        let a = signed_spend_at(&k, &[(funds[0].0, 0)], std::slice::from_ref(&funds[0].2), vec![out(1_900_000, &[0x07; 20])], 1);
        let b = signed_spend_at(&k, &[(funds[1].0, 0)], std::slice::from_ref(&funds[1].2), vec![out(1_900_000, &[0x08; 20])], 1);
        let honest = build(&n, vec![gh], vec![coinbase("v10m", subsidy(1) + 200_000, vec![0xA2; 20]), a, b.clone()]);
        let mut mutated = honest.clone();
        mutated.transactions.push(b);
        assert_eq!(mutated.block_hash(), honest.block_hash(), "the header is untouched");
        let legacy_same = core::Transaction::merkle_root(&mutated.transactions)
            == core::Transaction::merkle_root(&honest.transactions);
        assert!(legacy_same, "the legacy tree cannot tell them apart");
        let err = accept(&n, &mutated).unwrap_err();
        if hardened {
            assert!(err.contains("invalid merkle root"), "{err}");
            assert_ne!(mutated.body_merkle_root(), honest.header.merkle_root);
        } else {
            assert!(err.contains("duplicate transaction"), "{err}");
            assert_eq!(mutated.body_merkle_root(), honest.header.merkle_root);
        }
        assert_not_stored(&n, &mutated);
        accept(&n, &honest).expect("the honest block");
    }
}

// ── VAL-12: wire-size block limit ────────────────────────────────────────────

/// Zero-value outputs with empty scripts cost 2 bytes in bincode and 9 on
/// the wire: a block of ~1.17 MB on the wire is ~0.26 MB in bincode. Valid
/// size before the activation (bincode measure, unchanged); too large from it.
#[test]
fn val12_block_size_is_measured_on_the_wire_after_activation() {
    let many_outputs = |tag: u8, n: usize| Transaction {
        version: 1,
        inputs: vec![TxInput { prev_txid: [tag; 32], prev_index: 0, script_sig: vec![tag; 10], sequence: u32::MAX }],
        outputs: vec![TxOutput { value: 0, script_pubkey: vec![] }; n],
        locktime: 0,
    };
    for hardened in [false, true] {
        let _g = activation::scoped_override(if hardened { 0 } else { activation::NEVER });
        let genesis = mk_genesis(unix_now() - 10_000);
        let gh = genesis.block_hash();
        let n = node_with(&genesis, &[]);
        let b = build(&n, vec![gh], vec![
            coinbase("v12", subsidy(1), vec![0xA3; 20]), many_outputs(1, 65_000), many_outputs(2, 65_000),
        ]);
        assert!(b.size_bytes() < core::MAX_BLOCK_SIZE, "bincode {}", b.size_bytes());
        assert!(b.wire_size() > core::MAX_BLOCK_SIZE, "wire {}", b.wire_size());
        assert_eq!(b.wire_size(), b.to_wire_bytes().len());
        if hardened {
            assert_eq!(b.validate_structure_without_pow(), Err("block too large"));
            let err = accept_direct(&n, &b).unwrap_err();
            assert!(err.contains("block too large"), "{err}");
            assert_not_stored(&n, &b);
        } else {
            assert_eq!(b.validate_structure_without_pow(), Ok(()), "bincode measure: within the limit");
        }
    }
}

/// The template budgets with the measure of its height: from the activation
/// the assembled block stays under MAX_BLOCK_SIZE on the WIRE even when the
/// pool holds more than a block of transactions.
#[test]
fn val12_template_budgets_with_the_wire_measure_after_activation() {
    let _g = activation::scoped_override(0);
    let genesis = mk_genesis(unix_now() - 10_000);
    let n = node_with(&genesis, &[]);
    let script_sig_len = 8 + core::SIG_SIZE + core::PUBKEY_SIZE;
    for i in 0..200u32 {
        let mut prev = [0u8; 32];
        prev[..4].copy_from_slice(&i.to_le_bytes());
        prev[31] = 0xEF;
        n.store.put_utxo(&prev, 0, &out(1_000_000, &[0x55; 20])).unwrap();
        let tx = Transaction {
            // The version the template height requires (P2 version rule).
            version: core::sighash::TX_VERSION_V3,
            inputs: vec![TxInput { prev_txid: prev, prev_index: 0, script_sig: vec![0xA5; script_sig_len], sequence: u32::MAX }],
            outputs: vec![TxOutput { value: 1_000_000 - 20_000 - i as u64, script_pubkey: vec![0x12; 20] }],
            locktime: 0,
        };
        n.mempool.add(tx, 20_000 + i as u64).unwrap();
    }
    let tmpl = template::build_block_template_with(&n.dag, &n.store, &n.mempool, &template::TemplateOptions {
        coinbase_reserve: template::miner_coinbase_reserve(&[0xCB; 20]), verify_scripts: false,
    }).unwrap();
    assert!(tmpl.hardened);
    assert!(!tmpl.transactions.is_empty() && tmpl.transactions.len() < 200);
    let cb = template::miner_coinbase(tmpl.height, tmpl.subsidy + tmpl.total_fees, vec![0xCB; 20]);
    let block = template::assemble_block(&tmpl, cb, unix_now()).expect("self-check passes");
    assert!(block.wire_size() <= core::MAX_BLOCK_SIZE, "wire {}", block.wire_size());
    assert_eq!(block.validate_structure_without_pow(), Ok(()));
}

/// Review finding (getblocktemplate): the template leaves only
/// `EXTERNAL_COINBASE_RESERVE` bytes for an external coinbase, so the
/// advertised `max_coinbase_extra_bytes` must fit in it. With a mempool larger
/// than a block, a coinbase carrying exactly `max_coinbase_extra_bytes` miner
/// bytes and a `max_coinbase_script_pubkey_bytes` script keeps the block
/// within `MAX_BLOCK_SIZE` in the template's size measure on both sides of
/// the activation; the value advertised before the fix (the script_sig cap,
/// 9,920 / 10,000 bytes) made the same block too large.
#[test]
fn getblocktemplate_max_coinbase_extra_fits_a_full_template() {
    for hardened in [false, true] {
        let act = if hardened { 0 } else { activation::NEVER };
        let _g = activation::scoped_override(act);
        let genesis = mk_genesis(unix_now() - 10_000);
        let n = node_with(&genesis, &[]);
        // ~1.3 MB of ~330-byte transactions: more than one block.
        for i in 0..4_000u32 {
            let mut prev = [0u8; 32];
            prev[..4].copy_from_slice(&i.to_le_bytes());
            prev[31] = 0xBD;
            n.store.put_utxo(&prev, 0, &out(1_000_000, &[0x55; 20])).unwrap();
            let fee = 50_000 + i as u64;
            let tx = Transaction {
                // The version the template height requires (P2 version rule).
                version: core::sighash::tx_version_for_height(1, act),
                inputs: vec![TxInput { prev_txid: prev, prev_index: 0, script_sig: vec![0xA6; 250 + (i % 7) as usize], sequence: u32::MAX }],
                outputs: vec![TxOutput { value: 1_000_000 - fee, script_pubkey: vec![0x13; 20] }],
                locktime: 0,
            };
            n.mempool.add(tx, fee).unwrap();
        }
        let tmpl = template::build_block_template_with(&n.dag, &n.store, &n.mempool, &template::TemplateOptions {
            coinbase_reserve: template::EXTERNAL_COINBASE_RESERVE, verify_scripts: false,
        }).unwrap();
        assert_eq!(tmpl.hardened, hardened);
        assert!(tmpl.transactions.len() < 4_000, "the mempool holds more than one block");
        let prefix: Vec<u8> = tmpl.coinbase_commitment().map(|c| c.to_vec()).unwrap_or_default();
        let max_extra = template::external_coinbase_max_extra(prefix.len(), hardened, template::EXTERNAL_COINBASE_RESERVE);

        // Assemble the block as an external miner does from the RPC fields.
        let external = |extra: usize| -> Block {
            let mut script_sig = prefix.clone();
            script_sig.extend(std::iter::repeat_n(0xE7u8, extra));
            let cb = Transaction {
                version: 1,
                inputs: vec![TxInput { prev_txid: [0; 32], prev_index: u32::MAX, script_sig, sequence: u32::MAX }],
                outputs: vec![TxOutput {
                    value: tmpl.subsidy + tmpl.total_fees,
                    script_pubkey: vec![0x44; template::EXTERNAL_COINBASE_MAX_SPK],
                }],
                locktime: 0,
            };
            let root = block_rules::merkle_root_from_coinbase_branch(&cb.txid(), &tmpl.coinbase_merkle_branch(), hardened);
            Block {
                header: BlockHeader {
                    version: 1, parents: tmpl.parents.clone(), merkle_root: root,
                    timestamp: tmpl.parent_timestamp + 1, bits: tmpl.bits, nonce: 0,
                },
                transactions: std::iter::once(cb).chain(tmpl.transactions.iter().map(|(t, _)| t.clone())).collect(),
                blue_score: tmpl.blue_score,
                height: tmpl.height,
                shielded_transactions: vec![],
            }
        };
        let ok = external(max_extra);
        let size = block_rules::block_size_for_rules(&ok, hardened);
        assert!(size <= core::MAX_BLOCK_SIZE, "size {size}");
        assert!(size > core::MAX_BLOCK_SIZE - 2_000, "the template is full: {size}");
        assert_eq!(ok.validate_structure_without_pow_at(act), Ok(()));
        assert_eq!(block_rules::check_block_hardened_at(&ok, act), Ok(()));
        assert_eq!(template::check_template_block_at(&ok, tmpl.total_fees, act), Ok(()));

        // The pre-fix advertisement: the consensus script_sig cap.
        let old = external(core::limits::MAX_SCRIPT_SIG_SIZE - prefix.len());
        assert_eq!(old.validate_structure_without_pow_at(act), Err("block too large"));
    }
}

// ── POW-3: pow limit ─────────────────────────────────────────────────────────

/// The real ASERT path (`expected_bits_at`, never pinned by the dev-only
/// `test-pow-limit` feature this test binary is built with): a chain one year
/// behind schedule eases to POW_LIMIT_BITS one block below the activation
/// and is clamped to the genesis target at it. `validate_pow`'s own limit
/// check is exercised without the feature in gnb-crypto
/// (`core::hardening_core_tests::validate_pow_enforces_the_height_pow_limit`).
#[test]
fn pow3_pow_limit_clamp_at_the_activation_boundary() {
    let late = core::GENESIS_TIMESTAMP + 365 * 86_400;
    for act in [2u64, 1_000, activation::MAINNET_HARDENING_ACTIVATION_HEIGHT] {
        let below = core::expected_bits_at(late, act - 1, act).unwrap();
        let at = core::expected_bits_at(late, act, act).unwrap();
        assert_eq!(below, core::target_to_bits(&core::bits_to_target(core::POW_LIMIT_BITS)), "act {act}");
        assert_eq!(at, core::GENESIS_BITS, "act {act}");
        assert_eq!(core::bits_to_work(at), 4_500, "the cheapest block from the activation costs ~4,500 evaluations");
        assert_eq!(core::bits_to_work(below), 1);
        let limit = core::bits_to_target(core::POW_LIMIT_BITS);
        assert!(Block::target_within_pow_limit_at(&limit, act - 1, act));
        assert!(!Block::target_within_pow_limit_at(&limit, act, act));
    }
}

// ── Producers: templates at H-1 and H ────────────────────────────────────────

/// With the activation at H = 2, the template for height 1 (H - 1) is built
/// under the old rules and the template for height 2 (H) under the new ones;
/// both are mined and accepted by the real pipeline, each carrying a signed
/// mempool transaction. A height-H block built with the old encodings and a
/// height-(H-1) block built with the new root are refused.
#[test]
fn templates_at_h_minus_1_and_h_are_accepted_by_the_real_pipeline() {
    const H: u64 = 2;
    let _g = activation::scoped_override(H);
    let genesis = mk_genesis(unix_now() - 10_000);
    let k = key();
    let funds = [([0x71u8; 32], 0u32, out(3_000_000, &k.spk)), ([0x72u8; 32], 0u32, out(3_000_000, &k.spk))];
    let n = node_with(&genesis, &funds);
    let miner_spk = vec![0xCB; 20];

    for (i, height) in [(0usize, H - 1), (1, H)] {
        let policy = AdmissionPolicy::relay(admission::next_block_height(&n.dag.read()));
        assert_eq!(policy.next_block_height, height);
        // Version 1 / sighash v2 for H-1, version 3 / sighash v3 for H (P2).
        let tx = signed_spend_at(&k, &[(funds[i].0, 0)], std::slice::from_ref(&funds[i].2),
            vec![out(2_900_000, &[0x73; 20])], height);
        assert_eq!(tx.version, if height >= H { 3 } else { 1 });
        admission::admit(&n.store, &n.mempool, tx.clone(), &policy).expect("admitted");

        let tmpl = template::build_block_template(&n.dag, &n.store, &n.mempool, template::miner_coinbase_reserve(&miner_spk)).unwrap();
        assert_eq!(tmpl.height, height);
        assert_eq!(tmpl.hardened, height >= H);
        assert_eq!(tmpl.transactions.len(), 1);
        let cb = template::miner_coinbase(tmpl.height, tmpl.subsidy + tmpl.total_fees, miner_spk.clone());
        let block = template::assemble_block(&tmpl, cb, unix_now()).expect("self-check");
        let ss = &block.transactions[0].inputs[0].script_sig;
        if tmpl.hardened {
            assert_eq!(&ss[..80], &tmpl.coinbase_commitment().unwrap()[..]);
            assert!(ss[80..].starts_with(format!("gnb:h{height}:").as_bytes()), "the miner tag is the extra");
            assert_ne!(block.header.merkle_root, core::Transaction::merkle_root(&block.transactions));
        } else {
            assert!(tmpl.coinbase_commitment().is_none());
            assert!(ss.starts_with(format!("gnb:h{height}:").as_bytes()), "legacy coinbase unchanged");
            assert_eq!(block.header.merkle_root, core::Transaction::merkle_root(&block.transactions));
        }
        // The root an external miner folds from the template's branch.
        assert_eq!(
            block_rules::merkle_root_from_coinbase_branch(&block.transactions[0].txid(), &tmpl.coinbase_merkle_branch(), tmpl.hardened),
            block.header.merkle_root,
        );
        let block = mine(block, |_| true);

        // The wrong regime's encoding is refused at this height.
        let mut wrong = block.clone();
        if tmpl.hardened {
            wrong.transactions[0].inputs[0].script_sig = format!("gnb:h{height}:legacy").into_bytes();
            wrong.header.merkle_root = core::Transaction::merkle_root(&wrong.transactions);
        } else {
            wrong.header.merkle_root = block_rules::tx_merkle_root(&wrong.transactions, true);
        }
        let wrong = mine(wrong, |_| true);
        assert!(accept(&n, &wrong).is_err(), "height {height}: the other regime's block is invalid");

        accept(&n, &block).unwrap_or_else(|e| panic!("template block at height {height}: {e}"));
        assert_eq!(applied_tip(&n), Some(block.block_hash()));
        assert!(n.store.get_utxo(&tx.txid(), 0).unwrap().is_some());
        assert_eq!(n.mempool.size(), 0);
    }
}

// ── Pre-activation witness mutation must not poison the block id ────────────
//
// Below the activation the block id commits to txids, which exclude
// non-coinbase `script_sig`s, so a relay can change those bytes without
// changing the id. A connect-time failure caused by such bytes (script parse,
// pubkey hash, signature, the size-based minimum fee) must not disqualify the
// id: the body is dropped, nothing is persisted, and a later copy of the same
// id with a different body replaces it and is re-evaluated.

/// One signed spend of `fund` paying `fee`, and the honest block carrying it.
fn witness_fixture(n: &Node, k: &Key, fund: &([u8; 32], u32, TxOutput), fee: u64, parent: BlockHash,
    pred: impl Fn(&BlockHash) -> bool) -> Block
{
    let tx = signed_spend(k, &[(fund.0, fund.1)], vec![out(fund.2.value - fee, &[0x9A; 20])]);
    let h = n.dag.read().get_block_data(&parent).unwrap().height + 1;
    build_where(n, vec![parent], vec![coinbase("witness", subsidy(h) + fee, vec![0x9B; 20]), tx], pred)
}

/// The block left waiting for another body: in the DAG, body dropped, no
/// persisted mark, not offered as known to the ingress paths.
fn assert_waits_for_body(n: &Node, id: &BlockHash) {
    let d = n.dag.read();
    assert!(d.has_block(id), "the id stays known to the DAG");
    assert!(d.is_body_pending(id), "waiting for another body");
    assert!(d.is_invalid(id), "never selected while waiting");
    assert!(!d.is_invalid_persistently(id), "not disqualified");
    drop(d);
    assert!(n.store.get_block(id).unwrap().is_none(), "the rejected body is dropped (never served)");
    assert!(n.store.invalid_block_reason(id).unwrap().is_none(), "no persisted invalid mark");
    assert!(n.store.load_invalid_blocks().unwrap().is_empty());
    assert!(pipeline::awaits_body(&n.dag, &n.store, id));
    assert!(!pipeline::is_known_block(&n.dag, &n.store, id), "gossip/pull/RPC dedup lets a new copy in");
}

/// The finding's attack, for every witness-dependent rule: a node first
/// receives a copy whose non-coinbase `script_sig` was altered in transit
/// (same block id), then the honest copy. It ends on the honest block, and a
/// child of it connects. The same corrupted body is refused cheaply when
/// re-delivered.
#[test]
fn witness_corrupted_copy_then_honest_copy_ends_on_the_honest_block() {
    let _g = activation::scoped_override(activation::NEVER);
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0xA1u8; 32], 0u32, out(5_000_000, &k.spk));
    // A fee just above the consensus minimum of the honest size, so padding
    // the witness drops it below the minimum.
    let probe = signed_spend(&k, &[(fund.0, 0)], vec![out(4_000_000, &[0x9A; 20])]);
    let honest_size = probe.to_wire_bytes(true).len();
    let fee = core::tokenomics::min_tx_fee_sat(honest_size) + 500;
    assert!(fee < core::tokenomics::min_tx_fee_sat(honest_size + 1_000));

    type Corrupt = fn(&mut Vec<u8>);
    let corruptions: [(&str, Corrupt, &str); 4] = [
        ("signature byte flipped", |ss| ss[100] ^= 0x01, "invalid signature"),
        ("public key byte flipped", |ss| { let i = ss.len() - 10; ss[i] ^= 0x01 }, "pubkey mismatch"),
        ("script_sig truncated", |ss| ss.truncate(6), "malformed script_sig"),
        ("witness padded past the minimum fee", |ss| ss.extend_from_slice(&[0u8; 1_000]), "below consensus minimum"),
    ];
    for (what, corrupt, expect) in corruptions {
        let n = node_with(&genesis, std::slice::from_ref(&fund));
        let honest = witness_fixture(&n, &k, &fund, fee, gh, |_| true);
        let id = honest.block_hash();
        let mut bad = honest.clone();
        corrupt(&mut bad.transactions[1].inputs[0].script_sig);
        assert_eq!(bad.block_hash(), id, "{what}: same block id");
        assert_ne!(block_rules::witness_root(&bad.transactions), block_rules::witness_root(&honest.transactions));

        let err = accept(&n, &bad).expect_err(what);
        assert!(err.contains("body rejected") && err.contains(expect), "{what}: {err}");
        assert_waits_for_body(&n, &id);
        assert_eq!(sel_tip(&n), Some(gh));
        assert_eq!(applied_tip(&n), Some(gh));
        assert!(n.store.get_utxo(&fund.0, 0).unwrap().is_some(), "{what}: no UTXO effect");

        let again = accept(&n, &bad).expect_err("the same rejected body again");
        assert!(again.contains("already rejected"), "{what}: {again}");

        accept(&n, &honest).unwrap_or_else(|e| panic!("{what}: the honest copy: {e}"));
        assert_eq!(sel_tip(&n), Some(id), "{what}");
        assert_eq!(applied_tip(&n), Some(id), "{what}");
        assert!(!n.dag.read().is_invalid(&id) && !n.dag.read().is_body_pending(&id));
        assert_eq!(n.store.get_block(&id).unwrap().map(|b| b.to_wire_bytes()), Some(honest.to_wire_bytes()),
            "{what}: the honest body is stored");
        assert!(n.store.get_utxo(&honest.transactions[1].txid(), 0).unwrap().is_some());
        assert!(n.store.get_utxo(&fund.0, 0).unwrap().is_none());
        assert!(n.store.load_invalid_blocks().unwrap().is_empty(), "{what}: nothing was ever persisted");
        let again = accept(&n, &honest).expect_err("now a plain duplicate");
        assert!(again.contains("already in DAG"), "{again}");

        let child = empty_child(&n, id, "after-honest");
        accept(&n, &child).expect("a child of the honest block connects");
        assert_eq!(applied_tip(&n), Some(child.block_hash()));
    }
}

/// The same attack across restarts: the corrupted copy arrives, the node
/// restarts (nothing was persisted, the dropped body is found missing and the
/// block waits again), the honest copy is accepted, and after another
/// restart the node is still on the honest block.
#[test]
fn witness_corrupted_copy_then_restart_then_honest_copy() {
    let _g = activation::scoped_override(activation::NEVER);
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0xA2u8; 32], 0u32, out(5_000_000, &k.spk));
    let mut n = node_with(&genesis, std::slice::from_ref(&fund));
    let honest = witness_fixture(&n, &k, &fund, 100_000, gh, |_| true);
    let id = honest.block_hash();
    let mut bad = honest.clone();
    bad.transactions[1].inputs[0].script_sig[200] ^= 0x80;
    assert_eq!(bad.block_hash(), id);
    accept(&n, &bad).expect_err("signature-corrupted copy");
    assert_waits_for_body(&n, &id);

    restart(&mut n);
    assert!(n.dag.read().has_block(&id), "the DAG record survives");
    assert_eq!(sel_tip(&n), Some(gh), "a block without a body is never selected");
    assert_eq!(applied_tip(&n), Some(gh));
    assert!(n.dag.read().is_body_pending(&id), "start-up found the body missing: waits again");
    assert!(pipeline::awaits_body(&n.dag, &n.store, &id));
    assert!(!pipeline::is_known_block(&n.dag, &n.store, &id));
    assert!(n.store.load_invalid_blocks().unwrap().is_empty());

    accept(&n, &honest).expect("the honest copy after the restart");
    assert_eq!(applied_tip(&n), Some(id));
    assert!(n.store.get_utxo(&honest.transactions[1].txid(), 0).unwrap().is_some());

    restart(&mut n);
    assert_eq!(sel_tip(&n), Some(id));
    assert_eq!(applied_tip(&n), Some(id));
    assert!(!n.dag.read().is_invalid(&id));
    let child = empty_child(&n, id, "after-restart");
    accept(&n, &child).expect("the chain grows on the honest block");
    assert_eq!(applied_tip(&n), Some(child.block_hash()));
}

/// The corrupted copy arrives as a fork-loser (stored, not evaluated); a
/// child makes its branch the heaviest, the corrupted body fails, and the
/// branch WAITS instead of being disqualified: the child is accepted into
/// the DAG, the old tip stays applied, nothing is persisted. A second child
/// arriving meanwhile also waits. When the honest body arrives the branch is
/// re-evaluated and connected by reorg, also after a restart.
#[test]
fn witness_corrupted_fork_loser_waits_and_reorgs_once_the_honest_body_arrives() {
    let _g = activation::scoped_override(activation::NEVER);
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0xA3u8; 32], 0u32, out(5_000_000, &k.spk));
    let mut n = node_with(&genesis, std::slice::from_ref(&fund));
    let m1 = empty_child(&n, gh, "main-1");
    accept(&n, &m1).unwrap();
    let honest = witness_fixture(&n, &k, &fund, 100_000, gh, |h| *h < m1.block_hash());
    let f = honest.block_hash();
    let mut bad = honest.clone();
    bad.transactions[1].inputs[0].script_sig[300] ^= 0x04;
    accept(&n, &bad).expect("a fork-loser is stored without evaluation");
    assert_eq!(applied_tip(&n), Some(m1.block_hash()));

    let g = empty_child(&n, f, "fork-child");
    accept(&n, &g).expect("the child waits for its ancestor's body; it is not disqualified");
    assert_waits_for_body(&n, &f);
    assert!(n.dag.read().is_invalid(&g.block_hash()) && !n.dag.read().is_invalid_persistently(&g.block_hash()));
    assert_eq!(sel_tip(&n), Some(m1.block_hash()));
    assert_eq!(applied_tip(&n), Some(m1.block_hash()), "the old tip stays applied");
    assert!(n.store.get_utxo(&fund.0, 0).unwrap().is_some());

    let g2 = empty_child(&n, g.block_hash(), "fork-grandchild");
    accept(&n, &g2).expect("a later descendant waits too");
    assert!(n.store.load_invalid_blocks().unwrap().is_empty(), "nothing persisted for the waiting branch");

    restart(&mut n);
    assert_eq!(applied_tip(&n), Some(m1.block_hash()));
    assert!(n.dag.read().is_body_pending(&f), "re-derived at start-up from the missing body");

    accept(&n, &honest).expect("the honest body of F");
    assert_eq!(sel_tip(&n), Some(g2.block_hash()));
    assert_eq!(applied_tip(&n), Some(g2.block_hash()), "reorg onto the honest branch");
    assert!(n.store.get_utxo(&fund.0, 0).unwrap().is_none());
    assert!(n.store.get_utxo(&honest.transactions[1].txid(), 0).unwrap().is_some());
    assert!(n.store.get_utxo(&m1.transactions[0].txid(), 0).unwrap().is_none(), "main-1 rolled back");
    restart(&mut n);
    assert_eq!(applied_tip(&n), Some(g2.block_hash()));
}

/// Failures the block id commits to stay persisted exactly as before: below
/// the activation a spend of a missing coin; at/after it, an invalid
/// signature too, because the witness commitment (checked before the block
/// is stored) fixes every byte of the body.
#[test]
fn id_committed_failures_are_still_persisted_on_both_sides_of_the_activation() {
    // Below: a spend of a coin that does not exist (txid-committed).
    {
        let _g = activation::scoped_override(activation::NEVER);
        let genesis = mk_genesis(unix_now() - 10_000);
        let gh = genesis.block_hash();
        let k = key();
        let n = node_with(&genesis, &[]);
        let ghost = signed_spend(&k, &[([0xEEu8; 32], 0)], vec![out(1_000_000, &[0x01; 20])]);
        let b = build(&n, vec![gh], vec![coinbase("ghost", subsidy(1), vec![0x9C; 20]), ghost]);
        let err = accept(&n, &b).unwrap_err();
        assert!(err.contains("not found") && err.contains("invalid in its own chain context"), "{err}");
        assert!(n.dag.read().is_invalid_persistently(&b.block_hash()));
        assert!(!n.dag.read().is_body_pending(&b.block_hash()));
        assert!(n.store.invalid_block_reason(&b.block_hash()).unwrap().is_some(), "persisted as before");
        assert!(n.store.get_block(&b.block_hash()).unwrap().is_some(), "body kept as before");
    }
    // At/after: a block whose own miner committed to a bad signature.
    {
        let _g = activation::scoped_override(0);
        let genesis = mk_genesis(unix_now() - 10_000);
        let gh = genesis.block_hash();
        let k = key();
        let fund = ([0xA4u8; 32], 0u32, out(5_000_000, &k.spk));
        let n = node_with(&genesis, std::slice::from_ref(&fund));
        let mut tx = signed_spend_at(&k, &[(fund.0, 0)], std::slice::from_ref(&fund.2), vec![out(4_900_000, &[0x9A; 20])], 1);
        assert_eq!(tx.version, 3);
        tx.inputs[0].script_sig[100] ^= 0x01;
        let b = build(&n, vec![gh], vec![coinbase("committed-bad-sig", subsidy(1) + 100_000, vec![0x9D; 20]), tx]);
        assert_eq!(block_rules::check_block_hardened_at(&b, 0), Ok(()), "the commitment covers the bad witness");
        let err = accept(&n, &b).unwrap_err();
        assert!(err.contains("invalid signature") && err.contains("invalid in its own chain context"), "{err}");
        assert!(n.dag.read().is_invalid_persistently(&b.block_hash()));
        assert!(!n.dag.read().is_body_pending(&b.block_hash()));
        assert!(n.store.invalid_block_reason(&b.block_hash()).unwrap().is_some());
        let again = accept(&n, &b).unwrap_err();
        assert!(again.contains("already in DAG"), "{again}");
    }
}

/// The verdict of a classified connect failure (a read failure of the view
/// is no verdict: re-audit B1-T12).
fn verdict_of(r: Result<(), pipeline::ConnectFailure>) -> pipeline::BlockInvalidity {
    match r.expect_err("a verdict") {
        pipeline::ConnectFailure::Invalid(b) => b,
        pipeline::ConnectFailure::Storage(m) => panic!("no verdict (storage): {m}"),
    }
}

/// The classification behind the pipeline, on `validate_block_in_view`'s
/// own terms: the same signature failure is witness-dependent below the
/// activation and id-committed at/after it; the verdict is unchanged.
#[test]
fn connect_failures_are_classified_by_what_the_block_id_commits_to() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0xA5u8; 32], 0u32, out(5_000_000, &k.spk));
    let n = node_with(&genesis, std::slice::from_ref(&fund));
    // A version-3 (sighash v3) spend, valid by version on both sides: below
    // the activation it is verified with sighash v2 (P2), and either way the
    // flipped byte breaks the signature.
    let mut tx = {
        let _g = activation::scoped_override(1);
        signed_spend_at(&k, &[(fund.0, 0)], std::slice::from_ref(&fund.2), vec![out(4_900_000, &[0x9A; 20])], 1)
    };
    assert_eq!(tx.version, 3);
    tx.inputs[0].script_sig[100] ^= 0x01;
    let txs = vec![coinbase("classify", subsidy(1) + 100_000, vec![0x9E; 20]), tx];
    let mut b = raw_block(&n, vec![gh], txs);
    b.header.merkle_root = b.body_merkle_root_at(activation::NEVER);
    let view: &Storage = &n.store;
    let below = verdict_of(pipeline::validate_block_in_view_classified_at(view, &b, activation::NEVER));
    assert!(below.witness_dependent && below.reason.contains("invalid signature"), "{below:?}");
    let at = verdict_of(pipeline::validate_block_in_view_classified_at(view, &b, 1));
    assert!(!at.witness_dependent && at.reason.contains("invalid signature"), "{at:?}");
    assert_eq!(pipeline::validate_block_in_view_at(view, &b, activation::NEVER).unwrap_err(), below.reason);
    // An over-claiming coinbase is id-committed on both sides.
    let mut over = raw_block(&n, vec![gh], vec![coinbase("over", subsidy(1) + 1, vec![0x9F; 20])]);
    over.header.merkle_root = over.body_merkle_root_at(activation::NEVER);
    let e = verdict_of(pipeline::validate_block_in_view_classified_at(view, &over, activation::NEVER));
    assert!(!e.witness_dependent, "{e:?}");
}

/// P1 x P2: every failure the transaction rules of package P2 can produce is
/// classified by what the block id commits to. Below the activation P2's
/// consensus rule is the old one (every version, sighash v2, the lenient
/// witness framing), so the witness-dependent set is exactly a malformed
/// `script_sig`, a public key that does not hash to the prevout, an invalid
/// signature (a version-3 transaction included: it is verified with sighash
/// v2 there) and the size-based minimum fee above the floor no witness can
/// lower (re-audit B1-T13: a fee below that floor, here 0, is id-committed).
/// At/after the activation every failure (the version rule, a non-canonical
/// witness, a sighash-v3 signature, the minimum fee) is id-committed. The
/// verdict is `validate_block_in_view_at`'s on both sides.
#[test]
fn transaction_rule_failures_are_classified_on_both_sides_of_the_activation() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let k = key();
    let other = key();
    let fund = ([0xA7u8; 32], 0u32, out(5_000_000, &k.spk));
    let n = node_with(&genesis, std::slice::from_ref(&fund));
    let view: &Storage = &n.store;
    let ins = [(fund.0, 0u32)];
    let spent = std::slice::from_ref(&fund.2);
    let pay = |v: u64| vec![out(v, &[0x9A; 20])];
    let v1 = signed_spend(&k, &ins, pay(4_900_000));
    let (v3, v3_no_fee) = {
        let _g = activation::scoped_override(1);
        (signed_spend_at(&k, &ins, spent, pay(4_900_000), 1), signed_spend_at(&k, &ins, spent, pay(5_000_000), 1))
    };
    assert_eq!((v1.version, v3.version, v3_no_fee.version), (1, 3, 3));
    let mutate = |tx: &Transaction, f: &dyn Fn(&mut Vec<u8>)| {
        let mut t = tx.clone();
        f(&mut t.inputs[0].script_sig);
        assert_eq!(t.txid(), tx.txid(), "a witness mutation keeps the txid");
        t
    };
    const BELOW: u64 = activation::NEVER;
    let cases: Vec<(&str, Transaction, u64, &str, bool)> = vec![
        ("malformed script_sig", mutate(&v1, &|ss| ss.truncate(3)), BELOW, "malformed script_sig", true),
        ("another key's witness", signed_spend(&other, &ins, pay(4_900_000)), BELOW, "pubkey mismatch", true),
        ("v1 signature byte flipped", mutate(&v1, &|ss| ss[100] ^= 1), BELOW, "invalid signature", true),
        ("version 3 below the activation", v3.clone(), BELOW, "invalid signature", true),
        ("v1 fee above the floor, below the size-based minimum", signed_spend(&k, &ins, pay(4_988_000)), BELOW,
         "below consensus minimum", true),
        ("v1 fee of 0, below the floor", signed_spend(&k, &ins, pay(5_000_000)), BELOW, "below consensus minimum", false),
        ("version 1 at the activation", v1.clone(), 1, "bad-txns-version", false),
        ("non-canonical witness", mutate(&v3, &|ss| ss.extend_from_slice(&[0, 1, 2])), 1, "non-canonical", false),
        ("v3 signature byte flipped", mutate(&v3, &|ss| ss[100] ^= 1), 1, "invalid signature", false),
        ("v3 fee below the minimum", v3_no_fee, 1, "below consensus minimum", false),
    ];
    // The same transaction set is valid on its own side of the boundary.
    for (tx, act) in [(v1.clone(), BELOW), (v3.clone(), 1)] {
        let mut b = raw_block(&n, vec![gh], vec![coinbase("p1p2-ok", subsidy(1) + 100_000, vec![0x9E; 20]), tx]);
        b.header.merkle_root = b.body_merkle_root_at(act);
        pipeline::validate_block_in_view_classified_at(view, &b, act).expect("valid on its side");
    }
    for (label, tx, act, fragment, witness_dependent) in cases {
        // The coinbase claims the subsidy alone (valid whatever the fee), so
        // the transaction's failure is the block's.
        let mut b = raw_block(&n, vec![gh], vec![coinbase("p1p2", subsidy(1), vec![0x9E; 20]), tx]);
        b.header.merkle_root = b.body_merkle_root_at(act);
        let e = verdict_of(pipeline::validate_block_in_view_classified_at(view, &b, act));
        assert!(e.reason.contains(fragment), "{label}: {e:?}");
        assert_eq!(e.witness_dependent, witness_dependent, "{label}: {e:?}");
        assert_eq!(pipeline::validate_block_in_view_at(view, &b, act).unwrap_err(), e.reason, "{label}");
    }
}

/// GhostDAG bookkeeping behind the fix: a body-pending root disqualifies its
/// selected-chain descendants in memory only; clearing it re-derives the set
/// from the remaining roots (a persistent mark below is kept), and a block
/// arriving under a waiting parent waits too.
#[test]
fn body_pending_marks_are_in_memory_roots_that_clear_cleanly() {
    let mut dag = gnb::consensus::GhostDAG::with_default_k();
    let g = [0x01u8; 32];
    dag.add_genesis(g, 1_000);
    let a = [0x0Au8; 32];
    let b = [0x0Bu8; 32];
    let c = [0x0Cu8; 32];
    let x = [0x0Du8; 32];
    dag.add_block(a, vec![g], 1_001, 1).unwrap();
    dag.add_block(b, vec![a], 1_002, 1).unwrap();
    dag.add_block(x, vec![g], 1_001, 1).unwrap();
    let marked = dag.mark_body_pending(a, Some([0x77; 32]));
    assert_eq!(marked.len(), 2, "a and its selected child b");
    assert!(dag.is_invalid(&b) && !dag.is_invalid_persistently(&b));
    assert!(dag.body_rejected_before(&a, &[0x77; 32]) && !dag.body_rejected_before(&a, &[0x78; 32]));
    dag.add_block(c, vec![b], 1_003, 1).unwrap();
    assert!(dag.is_invalid(&c) && !dag.is_invalid_persistently(&c), "a later arrival waits too");
    dag.mark_invalid(x);
    assert!(dag.is_invalid_persistently(&x));
    assert!(dag.clear_body_pending(&a));
    assert!(!dag.is_invalid(&a) && !dag.is_invalid(&b) && !dag.is_invalid(&c));
    assert!(dag.is_invalid(&x), "persistent marks survive the recompute");
    assert!(!dag.clear_body_pending(&a), "nothing left to clear");
    assert_eq!(dag.selected_tip().map(|t| t == c), Some(true));
}

// ── Blocks stored by a pre-upgrade binary (review finding) ──────────────────

/// A node runs the OLD binary past the activation height A: it stores (and
/// applies) a legacy-format block P at header height A and a child of it.
/// After the upgrade the start-up recheck disqualifies P and every block that
/// descends from it, rolls the applied chain back, and never offers them as
/// template parents: the template is built on the honest tip, at height A,
/// in the new format, and is accepted by a node that never stored P. A later
/// block that merges P as a NON-selected parent is disqualified on arrival,
/// and the marks survive another restart.
#[test]
fn stored_blocks_failing_the_hardening_rules_are_disqualified_at_startup() {
    const A: u64 = 3;
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let miner_spk = vec![0xCB; 20];
    let (mut n, m1, m2, p, pc) = {
        let _old = activation::scoped_override(activation::NEVER);
        let n = node_with(&genesis, &[]);
        let m1 = build(&n, vec![gh], vec![coinbase("m1", subsidy(1), vec![0xE1; 20])]);
        accept(&n, &m1).unwrap();
        let m2 = build(&n, vec![m1.block_hash()], vec![coinbase("m2", subsidy(2), vec![0xE2; 20])]);
        accept(&n, &m2).unwrap();
        let p = build(&n, vec![m2.block_hash()], vec![coinbase("legacy-P", subsidy(3), vec![0xE3; 20])]);
        accept(&n, &p).expect("old binary: a legacy block at height A is valid");
        let pc = build(&n, vec![p.block_hash()], vec![coinbase("legacy-PC", subsidy(4), vec![0xE4; 20])]);
        accept(&n, &pc).unwrap();
        assert_eq!(applied_tip(&n), Some(pc.block_hash()));
        (n, m1, m2, p, pc)
    };
    let _new = activation::scoped_override(A);
    assert_eq!(block_rules::check_block_hardened_at(&p, A), Err("invalid merkle root"));
    assert!(matches!(pipeline::classify_stored_block(&p, A), pipeline::StoredBlockCheck::IdCommitted(_)));

    restart(&mut n);
    for (b, what) in [(&p, "P"), (&pc, "P's child")] {
        let d = n.dag.read();
        assert!(d.is_invalid(&b.block_hash()) && d.is_invalid_all_edges(&b.block_hash()), "{what}");
    }
    let reason = n.store.invalid_block_reason(&p.block_hash()).unwrap().unwrap();
    assert!(reason.starts_with(pipeline::HARDENING_RECHECK_REASON), "{reason}");
    assert_eq!(n.store.get_meta(pipeline::HARDENING_RECHECK_META).unwrap(), Some(A.to_le_bytes().to_vec()));
    assert_eq!(sel_tip(&n), Some(m2.block_hash()));
    assert_eq!(applied_tip(&n), Some(m2.block_hash()), "the applied chain left the legacy branch");
    // COH-2: the rollback-only plan moved the shielded state with the chain,
    // in memory and in the same committed batch.
    assert_eq!(n.shielded.read().tip(), Some(m2.block_hash()));
    assert_eq!(gnb::coherence::ShieldedPool::load(&n.store).unwrap().tip(), Some(m2.block_hash()));
    assert!(n.store.get_utxo(&p.transactions[0].txid(), 0).unwrap().is_none());
    assert!(n.store.get_utxo(&m2.transactions[0].txid(), 0).unwrap().is_some());

    // Merge P1 x P3 (operator overrides, audit DAG-6): `reconsiderblock`
    // re-validates a hardening-recheck mark instead of lifting it — P's
    // stored body still fails the rules, so nothing changes — and
    // `invalidateblock` never turns it into an operator mark.
    let r = pipeline::reconsider_block(p.block_hash(), &n.dag, &n.store, &n.mempool, &n.node_state,
        Some(&n.tip_tx), &n.shielded).expect("reconsiderblock");
    assert_eq!((r.tip, r.rolled_back, r.connected), (m2.block_hash(), 0, 0));
    let r = pipeline::invalidate_block(p.block_hash(), &n.dag, &n.store, &n.mempool, &n.node_state,
        Some(&n.tip_tx), &n.shielded).expect("invalidateblock on a disqualified block is a no-op");
    assert_eq!((r.tip, r.rolled_back, r.connected, r.affected), (m2.block_hash(), 0, 0, 0));
    assert_eq!(n.store.invalid_block_reason(&p.block_hash()).unwrap().as_deref(), Some(reason.as_str()));
    for b in [&p, &pc] {
        assert!(n.dag.read().is_invalid_all_edges(&b.block_hash()));
    }
    assert_eq!(applied_tip(&n), Some(m2.block_hash()));

    let has_body = |h: &BlockHash| n.store.get_block(h).ok().flatten().is_some();
    let parents = n.dag.read().template_parents(core::MAX_PARENTS, has_body);
    assert_eq!(parents, vec![m2.block_hash()]);
    let tmpl = template::build_block_template(&n.dag, &n.store, &n.mempool, template::miner_coinbase_reserve(&miner_spk)).unwrap();
    assert_eq!(tmpl.height, A);
    assert!(tmpl.hardened);
    let cb = template::miner_coinbase(tmpl.height, tmpl.subsidy + tmpl.total_fees, miner_spk.clone());
    let blk = mine(template::assemble_block(&tmpl, cb, unix_now()).expect("self-check"), |_| true);
    accept(&n, &blk).expect("the template block");
    assert_eq!(applied_tip(&n), Some(blk.block_hash()));

    // A node that never stored P accepts the same chain and refuses P.
    let fresh = node_with(&genesis, &[]);
    for b in [&m1, &m2, &blk] {
        accept(&fresh, b).expect("the upgraded node accepts the honest chain");
    }
    assert!(accept(&fresh, &p).unwrap_err().contains("invalid merkle root"));

    // A block that merges P as a non-selected parent.
    let blk2 = build(&n, vec![blk.block_hash()], vec![coinbase("honest-4", subsidy(4), vec![0xE5; 20])]);
    accept(&n, &blk2).unwrap();
    let h5 = n.dag.read().get_block_data(&blk2.block_hash()).unwrap().height + 1;
    let y = build(&n, vec![blk2.block_hash(), p.block_hash()], vec![coinbase("merges-P", subsidy(h5), vec![0xE6; 20])]);
    assert_eq!(block_rules::check_block_hardened_at(&y, A), Ok(()), "Y itself is well-formed");
    let err = accept(&n, &y).unwrap_err();
    assert!(err.contains(pipeline::HARDENING_RECHECK_REASON), "{err}");
    assert_eq!(n.dag.read().get_block_data(&y.block_hash()).unwrap().selected_parent, Some(blk2.block_hash()),
        "P is a merged (non-selected) parent of Y");
    assert!(n.dag.read().is_invalid(&y.block_hash()));
    assert_eq!(applied_tip(&n), Some(blk2.block_hash()));
    let parents = n.dag.read().template_parents(core::MAX_PARENTS, has_body);
    assert_eq!(parents, vec![blk2.block_hash()]);

    restart(&mut n);
    for b in [&p, &pc, &y] {
        assert!(n.dag.read().is_invalid_all_edges(&b.block_hash()));
    }
    assert_eq!(applied_tip(&n), Some(blk2.block_hash()));
    let tmpl = template::build_block_template(&n.dag, &n.store, &n.mempool, template::miner_coinbase_reserve(&miner_spk)).unwrap();
    assert_eq!(tmpl.parents, vec![blk2.block_hash()]);
}

/// P1 x P2: the template's parent predicate (a stored body must pass the
/// hardening block rules of its height, defense in depth behind the start-up
/// recheck) lives in `template::template_parents_and_height`, the ONE source
/// of the node's next block height (P2). A legacy-format tip that the recheck
/// has not seen yet (no restart) is skipped by the template AND by the next
/// height the mempool and wallets use, so the two never disagree.
#[test]
fn next_block_height_and_template_skip_the_same_legacy_tip() {
    const A: u64 = 3;
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let (n, m2, p) = {
        let _old = activation::scoped_override(activation::NEVER);
        let n = node_with(&genesis, &[]);
        let m1 = build(&n, vec![gh], vec![coinbase("nh-m1", subsidy(1), vec![0xE1; 20])]);
        accept(&n, &m1).unwrap();
        let m2 = build(&n, vec![m1.block_hash()], vec![coinbase("nh-m2", subsidy(2), vec![0xE2; 20])]);
        accept(&n, &m2).unwrap();
        let p = build(&n, vec![m2.block_hash()], vec![coinbase("nh-legacy-P", subsidy(3), vec![0xE3; 20])]);
        accept(&n, &p).expect("old binary: a legacy block at height A");
        (n, m2, p)
    };
    let _new = activation::scoped_override(A);
    assert_eq!(block_rules::check_block_hardened_at(&p, A), Err("invalid merkle root"));
    assert!(!n.dag.read().is_invalid(&p.block_hash()), "not rechecked yet (no restart)");
    let (parents, height) = template::template_parents_and_height(&n.dag.read(), &n.store);
    assert_eq!(parents, vec![m2.block_hash()], "the legacy tip is not a template parent");
    assert_eq!(height, A);
    assert_eq!(template::next_template_height(&n.dag.read(), &n.store), A, "not P's height + 1");
    let synced = pipeline::sync_mempool_next_height(&n.dag, &n.store, &n.mempool);
    assert_eq!(synced, A);
    assert_eq!(admission::pool_next_height(&n.dag.read(), &n.store, &n.mempool), A);
    let tmpl = template::build_block_template(&n.dag, &n.store, &n.mempool, template::EXTERNAL_COINBASE_RESERVE).unwrap();
    assert_eq!((tmpl.parents.clone(), tmpl.height, tmpl.hardened), (vec![m2.block_hash()], A, true));
}

/// Merge review (P1 x DAG-11 x COH-2): a pre-upgrade binary ran past the
/// activation A, stored and applied a legacy block P at height A (spending a
/// funded output) and its child PC, then crashed while committing X, a child
/// of PC: X's UTXO effects and undo record are on disk, its DAG record is not
/// (the pre-fix extension commit), with the tip pointer written or not.
/// After the upgrade the hardening recheck disqualifies P and PC, so the DAG's
/// best valid block is M2. Start-up reconciliation used to roll back only X
/// and point the tip and the shielded tip at that best block, leaving P's
/// and PC's effects applied under a tip that excludes them (P's input spent,
/// their coinbases present), with nothing to repair it. Step 2 now rolls X
/// back onto PC, the heaviest DAG block holding an undo record (the block
/// the UTXO set sits on), and step 3 disconnects PC and P: the
/// UTXO set, the tip pointer and the shielded tip all describe M2, exactly
/// like a node that never stored P, and a hardened block spending P's input
/// is accepted on both.
#[test]
fn startup_rolls_an_unrecorded_block_back_onto_its_disqualified_parent() {
    const A: u64 = 3;
    for tip_written in [false, true] {
        let genesis = mk_genesis(unix_now() - 10_000);
        let gh = genesis.block_hash();
        let k = key();
        let fund = ([0xA7u8; 32], 0u32, out(3_000_000, &k.spk));
        let (mut n, m1, m2, p, pc, x, t, tx) = {
            let _old = activation::scoped_override(activation::NEVER);
            let n = node_with(&genesis, std::slice::from_ref(&fund));
            let m1 = build(&n, vec![gh], vec![coinbase("rx-m1", subsidy(1), vec![0xE1; 20])]);
            accept(&n, &m1).unwrap();
            let m2 = build(&n, vec![m1.block_hash()], vec![coinbase("rx-m2", subsidy(2), vec![0xE2; 20])]);
            accept(&n, &m2).unwrap();
            let t = signed_spend(&k, &[(fund.0, 0)], vec![out(2_900_000, &k.spk)]);
            let p = build(&n, vec![m2.block_hash()],
                vec![coinbase("rx-legacy-P", subsidy(3), vec![0xE3; 20]), t.clone()]);
            accept(&n, &p).expect("old binary: a legacy block at height A is valid");
            let pc = build(&n, vec![p.block_hash()], vec![coinbase("rx-legacy-PC", subsidy(4), vec![0xE4; 20])]);
            accept(&n, &pc).unwrap();
            let tx = signed_spend(&k, &[(t.txid(), 0)], vec![out(2_800_000, &[0x9C; 20])]);
            let x = build(&n, vec![pc.block_hash()],
                vec![coinbase("rx-legacy-X", subsidy(5), vec![0xE5; 20]), tx.clone()]);
            // The pre-fix extension commit, up to the crash point.
            n.store.put_block(&x).unwrap();
            reorg::apply_block_utxo_mutations(&n.store, &x).unwrap();
            if tip_written {
                n.store.put_meta("tip_hash", &x.block_hash()).unwrap();
            }
            assert!(n.store.get_dag_data(&x.block_hash()).unwrap().is_none());
            (n, m1, m2, p, pc, x, t, tx)
        };
        let _new = activation::scoped_override(A);
        let what = if tip_written { "tip pointer at X" } else { "tip pointer at PC" };

        restart(&mut n);
        assert!(n.dag.read().is_invalid(&p.block_hash()) && n.dag.read().is_invalid(&pc.block_hash()), "{what}");
        assert_eq!(sel_tip(&n), Some(m2.block_hash()), "{what}");
        assert_eq!(applied_tip(&n), Some(m2.block_hash()), "{what}");
        assert_eq!(n.shielded.read().tip(), Some(m2.block_hash()), "{what}");
        assert_eq!(gnb::coherence::ShieldedPool::load(&n.store).unwrap().tip(), Some(m2.block_hash()), "{what}");
        for b in [&p, &pc, &x] {
            assert!(n.store.get_undo_data(&b.block_hash()).unwrap().is_none(), "{what}: undo record left");
        }

        // The UTXO set equals that of a node that only ever connected M1, M2.
        let reference = node_with(&genesis, std::slice::from_ref(&fund));
        for b in [&m1, &m2] {
            accept(&reference, b).unwrap();
        }
        let mut outpoints = vec![(fund.0, 0u32), (t.txid(), 0), (tx.txid(), 0)];
        for b in [&m1, &m2, &p, &pc, &x] {
            outpoints.push((b.transactions[0].txid(), 0));
        }
        assert_eq!(utxo_snapshot(&n, &outpoints), utxo_snapshot(&reference, &outpoints), "{what}");
        assert!(n.store.get_utxo(&fund.0, 0).unwrap().is_some(), "{what}: P's input is unspent again");
        assert_aggregates_consistent(&n.store, what);

        // Both nodes accept the same hardened block at height A spending P's input.
        let spend = signed_spend_at(&k, &[(fund.0, 0)], std::slice::from_ref(&fund.2),
            vec![out(2_900_000, &[0x9D; 20])], A);
        let blk = build(&n, vec![m2.block_hash()], vec![coinbase("rx-honest", subsidy(A), vec![0xE6; 20]), spend]);
        accept(&n, &blk).expect("the input P spent is spendable on the honest chain");
        accept(&reference, &blk).expect("the reference node agrees");
        assert_eq!(applied_tip(&n), Some(blk.block_hash()));
        assert_eq!(utxo_snapshot(&n, &outpoints), utxo_snapshot(&reference, &outpoints), "{what}");
    }
}

/// The recheck's classification: a legacy block at/after the activation
/// fails for every body (id-committed); a block whose only problem is its
/// witnesses fails only for this body; a valid one and one below the
/// activation pass.
#[test]
fn classify_stored_block_separates_id_committed_from_body_only_failures() {
    let _g = activation::scoped_override(1);
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0xA6u8; 32], 0u32, out(5_000_000, &k.spk));
    let n = node_with(&genesis, std::slice::from_ref(&fund));
    let tx = signed_spend(&k, &[(fund.0, 0)], vec![out(4_900_000, &[0x9A; 20])]);
    let good = build(&n, vec![gh], vec![coinbase("cls", subsidy(1) + 100_000, vec![0x9B; 20]), tx]);
    assert_eq!(pipeline::classify_stored_block(&good, 1), pipeline::StoredBlockCheck::Valid);

    let mut witness = good.clone();
    witness.transactions[1].inputs[0].script_sig[100] ^= 1;
    assert_eq!(witness.block_hash(), good.block_hash());
    assert!(matches!(pipeline::classify_stored_block(&witness, 1), pipeline::StoredBlockCheck::BodyOnly(_)));

    let mut legacy = good.clone();
    legacy.transactions[0].inputs[0].script_sig = b"no commitment".to_vec();
    legacy.header.merkle_root = legacy.body_merkle_root_at(activation::NEVER);
    assert!(matches!(pipeline::classify_stored_block(&legacy, 1), pipeline::StoredBlockCheck::IdCommitted(_)));
    assert_eq!(pipeline::classify_stored_block(&legacy, 2), pipeline::StoredBlockCheck::Valid, "below the activation");

    let mut wrong_height = good.clone();
    wrong_height.transactions[0].inputs[0].script_sig[8] ^= 1;
    wrong_height.header.merkle_root = wrong_height.body_merkle_root_at(1);
    assert!(matches!(pipeline::classify_stored_block(&wrong_height, 1), pipeline::StoredBlockCheck::IdCommitted(_)));
}

// ── Merge review (P1 x P2) ───────────────────────────────────────────────────

/// A block at `height` carrying a coinbase and `spend` (header unchecked: the
/// in-block helpers and the connect rule read only the body and the height).
fn unsealed_block_at(height: u64, spend: &Transaction, fee: u64) -> Block {
    Block {
        header: BlockHeader {
            version: 1, parents: vec![], merkle_root: MerkleRoot::ZERO,
            timestamp: 0, bits: core::GENESIS_BITS, nonce: 0,
        },
        transactions: vec![coinbase("in-block", subsidy(height) + fee, vec![0xC1; 20]), spend.clone()],
        blue_score: height,
        height,
        shielded_transactions: Vec::new(),
    }
}

/// Review finding: `validate_tx_in_block_with_maturity` gated VAL-3 on
/// `block.height` but evaluated the transaction rules (version, sighash
/// regime) at its `current_height` argument, which `validate_tx_in_block`
/// passes as 0. With the mainnet activation, a valid version-3 / sighash-v3
/// spend in a block at 110,001 was rejected ("invalid signature") and an
/// invalid version-1 spend accepted. Every rule is now evaluated at
/// `block.height` (`current_height` only drives coinbase maturity), so both
/// helpers and the connect rule (`validate_block_in_view_at`) give the same
/// verdict on both sides of the activation.
#[test]
fn in_block_helpers_evaluate_transaction_rules_at_the_block_height() {
    const A: u64 = core::activation::MAINNET_HARDENING_ACTIVATION_HEIGHT;
    let _g = activation::scoped_override(A);
    let genesis = mk_genesis(unix_now() - 10_000);
    let k = key();
    let fund = ([0x91u8; 32], 0u32, out(2_000_000, &k.spk));
    let n = node_with(&genesis, std::slice::from_ref(&fund));
    let spend_for = |h: u64| {
        signed_spend_at(&k, &[(fund.0, fund.1)], std::slice::from_ref(&fund.2), vec![out(1_900_000, &[0x07; 20])], h)
    };
    let v1 = spend_for(A - 1);
    let v3 = spend_for(A + 1);
    assert_eq!((v1.version, v3.version), (1, 3));
    let cases = [
        (A + 1, &v3, None),
        (A + 1, &v1, Some("bad-txns-version")),
        (A, &v3, None),
        (A, &v1, Some("bad-txns-version")),
        (A - 1, &v1, None),
        (A - 1, &v3, Some("")), // a v3-digest signature checked under sighash v2
    ];
    for (height, tx, want_err) in cases {
        let b = unsealed_block_at(height, tx, 100_000);
        let helper = pipeline::validate_tx_in_block(&b, tx, &n.store, &mut std::collections::HashSet::new());
        let with_maturity = pipeline::validate_tx_in_block_with_maturity(
            &b, tx, &n.store, &mut std::collections::HashSet::new(), height,
        );
        let connect = pipeline::validate_block_in_view_at(&*n.store, &b, A);
        match want_err {
            None => {
                helper.unwrap_or_else(|e| panic!("h={height} v{}: {e}", tx.version));
                assert_eq!(with_maturity, Ok(100_000), "h={height} v{}", tx.version);
                connect.unwrap_or_else(|e| panic!("connect h={height} v{}: {e}", tx.version));
            }
            Some(what) => {
                let errs: Vec<String> = [("helper", helper), ("with_maturity", with_maturity.map(|_| ())), ("connect", connect)]
                    .into_iter()
                    .map(|(path, r)| r.expect_err(&format!("{path}: h={height} v{} must be rejected", tx.version)))
                    .collect();
                assert!(errs[0].contains(what), "h={height} v{}: {}", tx.version, errs[0]);
                assert!(errs.iter().all(|e| e == &errs[0]), "one rule, one reason: {errs:?}");
            }
        }
    }
}

/// Review finding: the in-block helper applied VAL-3 but not BIP30 (VAL-2)
/// for the transaction it validates. From the activation, a transaction whose
/// output would overwrite an unspent coin is rejected by the helper exactly as
/// by the connect rule (one function, `check_no_unspent_overwrite`); below it
/// both accept, as before.
#[test]
fn in_block_helper_applies_bip30_to_its_transaction() {
    for hardened in [false, true] {
        let act = if hardened { 1 } else { activation::NEVER };
        let _g = activation::scoped_override(act);
        let genesis = mk_genesis(unix_now() - 10_000);
        let k = key();
        let fund = ([0x92u8; 32], 0u32, out(2_000_000, &k.spk));
        let n = node_with(&genesis, std::slice::from_ref(&fund));
        let tx = signed_spend_at(&k, &[(fund.0, 0)], std::slice::from_ref(&fund.2), vec![out(1_900_000, &[0x08; 20])], 5);
        n.store.put_utxo(&tx.txid(), 0, &out(1_000, &[0x09; 20])).unwrap();
        let b = unsealed_block_at(5, &tx, 100_000);
        let helper = pipeline::validate_tx_in_block(&b, &tx, &n.store, &mut std::collections::HashSet::new());
        let connect = pipeline::validate_block_in_view_at(&*n.store, &b, act);
        if hardened {
            assert!(helper.unwrap_err().contains("BIP30"));
            assert!(connect.unwrap_err().contains("BIP30"));
        } else {
            helper.expect("old rules: no BIP30");
            connect.expect("old rules: no BIP30");
        }
    }
}

/// Review finding: the block rules use `h >= 1 && h >= activation`, the
/// transaction rules `h >= activation` (pinned by the version-rule vectors).
/// The two agree at every height a validated block or a next block can have
/// (>= 1); `check_tx_for_next_block` gates its two rules with ONE predicate,
/// so even at the height-0 convention of callers without a height context
/// (`validate_tx_standalone(.., 0)`) the version rule and the 64-byte rule
/// switch together (before, with activation 0, the version rule applied
/// there and the 64-byte rule did not).
#[test]
fn block_and_transaction_rule_predicates_agree_at_every_next_block_height() {
    for act in [0, 1, 2, 7, 109_999, 110_000, activation::NEVER] {
        for h in [1, 2, 6, 7, 8, 109_998, 109_999, 110_000, 110_001, u64::MAX] {
            assert_eq!(block_rules::rules_active_at(h, act), activation::is_active_at(h, act), "h={h} act={act}");
        }
    }
    assert!(!block_rules::rules_active_at(0, 0), "the genesis is never subject to the block rules");
    assert!(activation::is_active_at(0, 0), "sighash_vectors.json: version_rule (v1, h 0, act 0) is invalid");

    let _g = activation::scoped_override(0);
    let genesis = mk_genesis(unix_now() - 10_000);
    let k = key();
    let f1 = ([0x93u8; 32], 0u32, out(2_000_000, &k.spk));
    let f2 = ([0x94u8; 32], 0u32, out(2_000_000, &k.spk));
    let n = node_with(&genesis, &[f1.clone(), f2.clone()]);
    assert!(template::next_template_height(&n.dag.read(), &n.store) >= 1);
    let tx64_v3 = signed_spend_at(&k, &[(f1.0, 0)], std::slice::from_ref(&f1.2), vec![out(1_900_000, &[0x05; 5])], 1);
    assert_eq!((tx64_v3.version, tx64_v3.to_wire_bytes(false).len()), (3, 64));
    let tx_v1 = signed_spend(&k, &[(f2.0, 0)], vec![out(1_900_000, &[0x06; 20])]);
    for h in [0, 1] {
        let e = admission::check_tx_for_next_block(&tx64_v3, h).unwrap_err();
        assert!(e.contains("64-byte"), "h={h}: {e}");
        let e = admission::check_tx_for_next_block(&tx_v1, h).unwrap_err();
        assert!(e.contains("bad-txns-version"), "h={h}: {e}");
    }
    let e = pipeline::validate_tx_standalone(&tx64_v3, &n.store, 0).unwrap_err();
    assert!(e.contains("64-byte"), "{e}");
}

/// Review finding: the template's parent predicate (stored body passes
/// `check_block_hardened_at`) runs on every valid tip at every acceptance
/// (`next_template_height`). Its verdict is memoized per block hash: repeated
/// calls decode and hash no body, a body rewrite (the body-pending
/// replacement) is re-judged once, and a deleted body is never eligible.
#[test]
fn template_parent_predicate_judges_each_stored_body_once() {
    const A: u64 = 1;
    let _g = activation::scoped_override(A);
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0x95u8; 32], 0u32, out(5_000_000, &k.spk));
    let n = node_with(&genesis, std::slice::from_ref(&fund));
    let tx = signed_spend_at(&k, &[(fund.0, 0)], std::slice::from_ref(&fund.2), vec![out(4_900_000, &[0x9C; 20])], 1);
    let t0 = build(&n, vec![gh], vec![coinbase("memo-0", subsidy(1) + 100_000, vec![0xD0; 20]), tx]);
    let t1 = build(&n, vec![gh], vec![coinbase("memo-1", subsidy(1), vec![0xD1; 20])]);
    let t2 = build(&n, vec![gh], vec![coinbase("memo-2", subsidy(1), vec![0xD2; 20])]);
    for t in [&t0, &t1, &t2] {
        accept(&n, t).unwrap();
    }
    let ids = |v: &[&Block]| {
        let mut v: Vec<BlockHash> = v.iter().map(|b| b.block_hash()).collect();
        v.sort();
        v
    };
    let parents = || {
        let mut p = template::template_parents_and_height(&n.dag.read(), &n.store).0;
        p.sort();
        p
    };
    assert_eq!(parents(), ids(&[&t0, &t1, &t2]));
    let computed = n.store.body_verdicts_computed();
    for _ in 0..20 {
        assert_eq!(parents(), ids(&[&t0, &t1, &t2]));
        assert_eq!(template::next_template_height(&n.dag.read(), &n.store), 2);
    }
    assert_eq!(n.store.body_verdicts_computed(), computed, "no tip body is decoded or hashed again");

    // A witness-mutated body under the same id (what a body-pending
    // replacement writes) is re-judged once, fails, and stays excluded
    // without being judged (or logged) again.
    let mut mutated = t0.clone();
    mutated.transactions[1].inputs[0].script_sig[100] ^= 1;
    assert_eq!(mutated.block_hash(), t0.block_hash());
    assert!(block_rules::check_block_hardened_at(&mutated, A).is_err());
    n.store.put_block_body(&mutated).unwrap();
    assert_eq!(parents(), ids(&[&t1, &t2]));
    assert_eq!(n.store.body_verdicts_computed(), computed + 1);
    for _ in 0..5 {
        assert_eq!(parents(), ids(&[&t1, &t2]));
    }
    assert_eq!(n.store.body_verdicts_computed(), computed + 1);
    // The honest body back: eligible again.
    n.store.put_block_body(&t0).unwrap();
    assert_eq!(parents(), ids(&[&t0, &t1, &t2]));
    assert_eq!(n.store.body_verdicts_computed(), computed + 2);

    // A deleted body is never eligible, whatever the memo held.
    n.store.delete_block_body(&t1.block_hash()).unwrap();
    assert_eq!(parents(), ids(&[&t0, &t2]));
    // Another activation height is judged afresh (one memo slot per hash).
    assert!(template::template_parents_and_height_at(&n.dag.read(), &n.store, activation::NEVER).0.len() == 2);
}

/// `Storage::body_verdict`: memoized per (hash, key), re-judged after every
/// body write, `None` for a deleted or pruned body.
#[test]
fn storage_body_verdict_memo_follows_every_body_write() {
    let tmp = tempfile::TempDir::new().unwrap();
    let store = Storage::open(&tmp.path().join("db")).unwrap();
    let k = key();
    let spend = signed_spend(&k, &[([0x96; 32], 0)], vec![out(1_000, &[0x0A; 20])]);
    let b = unsealed_block_at(3, &spend, 0);
    let h = b.block_hash();
    let honest = b.transactions[1].inputs[0].script_sig[100];
    let calls = std::cell::Cell::new(0u32);
    // The verdict "byte 100 of the spend's witness is the honest one".
    let judge = |key: u64| store.body_verdict(&h, key, |body| {
        calls.set(calls.get() + 1);
        body.transactions[1].inputs[0].script_sig[100] == honest
    }).unwrap();
    assert_eq!(judge(7), None, "no body stored");
    store.put_block_body(&b).unwrap();
    assert_eq!(judge(7), Some(true));
    assert_eq!(judge(7), Some(true));
    assert_eq!(calls.get(), 1, "memoized");
    assert_eq!(judge(8), Some(true));
    assert_eq!(calls.get(), 2, "another key is judged afresh");
    let mut other = b.clone();
    other.transactions[1].inputs[0].script_sig[100] ^= 1;
    assert_eq!(other.block_hash(), h);
    store.put_block_body(&other).unwrap();
    assert_eq!(judge(8), Some(false), "a rewritten body is judged afresh");
    assert_eq!(calls.get(), 3);
    store.delete_block_body(&h).unwrap();
    assert_eq!(judge(8), None);
    store.put_block(&b).unwrap();
    assert_eq!(judge(8), Some(true));
    assert_eq!(calls.get(), 4);
    assert_eq!(store.prune_blocks_below(4).unwrap(), 1);
    assert_eq!(judge(8), None, "a pruned body is never reported");
}
