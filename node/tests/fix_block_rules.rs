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
//! of `fix_common::node_with` reads the same value at construction.

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
        let n = node_with(&genesis, &[fund.clone()]);
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
    store.put_block(&b2).unwrap();
    reorg::apply_block_utxo_mutations(&store, &b2).unwrap();
    assert_eq!(store.get_coinbase_height(&c).unwrap(), Some(2));
    store.rollback_block(&b2.block_hash()).unwrap();
    assert_eq!(store.iter_utxos_sorted().unwrap(), before);
    assert_eq!(store.get_coinbase_height(&c).unwrap(), Some(1));
    assert_eq!(store.get_tx_location(&c).unwrap(), Some((b1.block_hash(), 1)));
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
        let validate = |v: &dyn UtxoView, b: &Block| pipeline::validate_block_in_view(v, b);
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
        let spend = signed_spend(&k, &[(b1.transactions[0].txid(), 0)], vec![out(subsidy(1) - 100_000, &[0x34; 20])]);
        let policy = AdmissionPolicy::relay(admission::next_block_height(&n.dag.read()));
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
        let n = node_with(&genesis, &[fund.clone()]);
        let tx = signed_spend(&k, &[(fund.0, 0)], vec![out(2_900_000, &[0x42; 20])]);
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
            let resigned = signed_spend(&k, &[(fund.0, 0)], vec![out(2_900_000, &[0x42; 20])]);
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
        let tx64 = signed_spend(&k, &[(funds[0].0, 0)], vec![out(1_900_000, &[0x05; 5])]);
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
            let ok = signed_spend(&k, &[(funds[1].0, 0)], vec![out(1_900_000, &[0x06; 20])]);
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
        let a = signed_spend(&k, &[(funds[0].0, 0)], vec![out(1_900_000, &[0x07; 20])]);
        let b = signed_spend(&k, &[(funds[1].0, 0)], vec![out(1_900_000, &[0x08; 20])]);
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
            version: 1,
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
        let tx = signed_spend(&k, &[(funds[i].0, 0)], vec![out(2_900_000, &[0x73; 20])]);
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
