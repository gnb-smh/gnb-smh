//! Re-audit package R1a (phase 4): value and connect-time block rules.
//!
//! * B1-T1: the VAL-11 remediation added a block-wide output-total
//!   MoneyRange rule. Chained in-block spends move the same coins once per
//!   hop, so a valid block (and a valid template of a valid mempool chain)
//!   could exceed it; it applied at every height (changing pre-activation
//!   verdicts) and templates ignored it. Removed: Bitcoin Core bounds each
//!   transaction's output total and the accumulated fees, never the sum of
//!   all outputs of a block.
//!
//! Every block goes through the real acceptance pipeline
//! (`gnb::accept::accept_block`, after `validate_structure`); proofs of work
//! are recorded as verified (`Block::test_only_assume_pow_valid`, dev-only
//! `test-pow-limit`).

mod fix_common;
use fix_common::*;

use gnb::core::{self, activation, Transaction, TxOutput};
use gnb::mempool::admission::{self, AdmissionPolicy};
use gnb::template;

/// 4,000,000 GNB: three hops of it sum above `MAX_SUPPLY_SAT` (10,000,000 GNB).
const BIG: u64 = 4_000_000 * core::tokenomics::SAT_PER_GNB;
const HOP_FEE: u64 = 100_000;

/// A chain of `keys.len() - 1` signed spends: hop i moves the previous
/// output (locked to `keys[i]`) to `keys[i + 1]`, paying `HOP_FEE`. Signed
/// for a block at `height` under the calling thread's activation height.
fn hop_chain(keys: &[Key], fund: &([u8; 32], u32, TxOutput), height: u64) -> Vec<Transaction> {
    let mut prev = (fund.0, fund.1, fund.2.clone());
    let mut out_txs = Vec::new();
    for i in 0..keys.len() - 1 {
        let next = out(prev.2.value - HOP_FEE, &keys[i + 1].spk);
        let tx = signed_spend_at(&keys[i], &[(prev.0, prev.1)], std::slice::from_ref(&prev.2), vec![next.clone()], height);
        prev = (tx.txid(), 0, next);
        out_txs.push(tx);
    }
    out_txs
}

/// B1-T1: on both sides of the activation, a mempool chain of three hops of
/// 4,000,000 GNB (each transaction in range, outputs summing to about
/// 12,000,000 GNB) is admitted, templated, assembled (the template
/// self-check) and accepted and connected by the real pipeline. Before the
/// fix `assemble_block` refused it ("block output total ... exceeds
/// MAX_SUPPLY_SAT") and so did `accept_block`: the miner retried the same
/// poisoned template every second while the chain stayed pooled.
#[test]
fn chained_spends_whose_outputs_sum_above_the_supply_are_valid_and_templated() {
    for act in [activation::NEVER, 0] {
        let _g = activation::scoped_override(act);
        let genesis = mk_genesis(unix_now() - 10_000);
        let keys: Vec<Key> = (0..4).map(|_| key()).collect();
        let fund = ([0xB1u8; 32], 0u32, out(BIG, &keys[0].spk));
        let n = node_with(&genesis, std::slice::from_ref(&fund));
        let height = admission::next_block_height(&n.dag.read());
        let chain = hop_chain(&keys, &fund, height);
        let total: u128 = chain.iter().flat_map(|t| &t.outputs).map(|o| u128::from(o.value)).sum();
        assert!(total > u128::from(core::tokenomics::MAX_SUPPLY_SAT), "outputs sum above the supply: {total}");
        for t in &chain {
            assert!(core::limits::check_tx_money_range(t).is_ok(), "each transaction is in range");
            admission::admit(&n.store, &n.mempool, t.clone(), &AdmissionPolicy::relay(height))
                .unwrap_or_else(|e| panic!("act {act}: hop admitted: {e}"));
        }

        let miner = vec![0xCB; 20];
        let tmpl = template::build_block_template(&n.dag, &n.store, &n.mempool, template::miner_coinbase_reserve(&miner)).unwrap();
        assert_eq!(tmpl.transactions.len(), 3, "act {act}: the whole chain, parents first");
        assert_eq!(tmpl.total_fees, 3 * HOP_FEE);
        let cb = template::miner_coinbase(tmpl.height, tmpl.subsidy + tmpl.total_fees, miner.clone());
        let block = template::assemble_block(&tmpl, cb, unix_now())
            .unwrap_or_else(|e| panic!("act {act}: the template self-check refused a valid block: {e}"));
        assert_eq!(core::limits::check_block_context_free(&block), Ok(()));
        block.test_only_assume_pow_valid();
        accept(&n, &block).unwrap_or_else(|e| panic!("act {act}: accept_block: {e}"));
        assert_eq!(applied_tip(&n), Some(block.block_hash()), "act {act}: connected");
        assert!(n.store.get_utxo(&chain[2].txid(), 0).unwrap().is_some());
        assert!(n.store.get_utxo(&fund.0, 0).unwrap().is_none());
        assert_eq!(n.mempool.size(), 0);
    }
}

// ── B1-T12: storage read failures are never consensus verdicts ─────────────

/// Overwrite one row of a column family with bytes that do not decode
/// (a corrupted record, as after a checksum or decode failure).
fn corrupt_row(n: &Node, cf: &str, key: &[u8], bytes: &[u8]) {
    let db = n.store.db();
    db.put_cf(db.cf_handle(cf).expect("column family"), key, bytes).unwrap();
}

fn utxo_row_key(txid: &[u8; 32], index: u32) -> Vec<u8> {
    let mut k = txid.to_vec();
    k.extend_from_slice(&index.to_le_bytes());
    k
}

/// Nothing about `id` was persisted or remembered as a verdict.
fn assert_no_verdict(n: &Node, id: &gnb::consensus::BlockHash, what: &str) {
    assert!(n.store.invalid_block_reason(id).unwrap().is_none(), "{what}: no persisted invalid mark");
    assert!(n.store.load_invalid_blocks().unwrap().is_empty(), "{what}");
    assert!(!n.dag.read().is_invalid_persistently(id), "{what}: not disqualified");
}

/// B1-T12: a UTXO row that cannot be read while a block is connected (I/O
/// error, corruption) must not become a consensus verdict. Before the fix the
/// read error went through `From<String> for TxFailure` as an id-committed
/// failure: the honest block was disqualified and `invalid_block/<id>` was
/// persisted (it survived restarts). Now nothing is committed, nothing is
/// remembered, and the block connects once the row reads again. The same for
/// the BIP30 read of the block's own outpoints (at/after the activation).
#[test]
fn utxo_read_failure_while_connecting_is_not_a_verdict() {
    // Below the activation: the input lookup.
    {
        let genesis = mk_genesis(unix_now() - 10_000);
        let gh = genesis.block_hash();
        let k = key();
        let fund = ([0xC1u8; 32], 0u32, out(5_000_000, &k.spk));
        let n = node_with(&genesis, std::slice::from_ref(&fund));
        let tx = signed_spend(&k, &[(fund.0, 0)], vec![out(4_900_000, &[0x9A; 20])]);
        let b = mk_block(&n, vec![gh], vec![coinbase("t12", core::tokenomics::block_subsidy_sat(1) + 100_000, vec![0x9B; 20]), tx]);
        let id = b.block_hash();
        corrupt_row(&n, "utxo", &utxo_row_key(&fund.0, 0), &[0xFF, 0xFF, 0xFF]);
        let err = accept(&n, &b).expect_err("cannot be validated while the row is unreadable");
        assert!(!err.contains("invalid in its own chain context"), "not a verdict: {err}");
        assert_no_verdict(&n, &id, "input lookup");
        assert_eq!(applied_tip(&n), Some(gh));
        let db = n.store.db();
        db.delete_cf(db.cf_handle("utxo").unwrap(), utxo_row_key(&fund.0, 0)).unwrap();
        n.store.put_utxo(&fund.0, 0, &fund.2).unwrap();
        accept(&n, &b).expect("the same block once the row reads again");
        assert_eq!(applied_tip(&n), Some(id));
    }
    // At/after the activation: BIP30 reads every outpoint the block creates.
    {
        let _g = activation::scoped_override(0);
        let genesis = mk_genesis(unix_now() - 10_000);
        let gh = genesis.block_hash();
        let n = node_with(&genesis, &[]);
        let b = mk_block(&n, vec![gh], vec![coinbase("t12-bip30", core::tokenomics::block_subsidy_sat(1), vec![0x9C; 20])]);
        let id = b.block_hash();
        let cb = b.transactions[0].txid();
        corrupt_row(&n, "utxo", &utxo_row_key(&cb, 0), &[0xFF, 0xFF, 0xFF]);
        let err = accept(&n, &b).expect_err("BIP30 cannot be evaluated");
        assert!(!err.contains("invalid in its own chain context"), "not a verdict: {err}");
        assert_no_verdict(&n, &id, "BIP30 lookup");
        let db = n.store.db();
        db.delete_cf(db.cf_handle("utxo").unwrap(), utxo_row_key(&cb, 0)).unwrap();
        accept(&n, &b).expect("the same block once the row is gone");
        assert_eq!(applied_tip(&n), Some(id));
    }
}

/// B1-T12 (reorg.rs:819): the connect batch captures each spent coin for the
/// undo record before deleting it, with a validator that reads nothing. The
/// capture used to skip a failed read (`if let Ok(Some(..))`); the deletion
/// right after it re-reads the same row and already failed closed, so that
/// skip was not reachable on its own (a mutation restoring it passes this
/// test). The capture now propagates the error itself. Guarded property: an
/// unreadable spent coin fails the connect as a storage failure and no undo
/// record is written.
#[test]
fn undo_capture_read_failure_fails_the_connect() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0xC2u8; 32], 0u32, out(5_000_000, &k.spk));
    let n = node_with(&genesis, std::slice::from_ref(&fund));
    let tx = signed_spend(&k, &[(fund.0, 0)], vec![out(4_900_000, &[0x9A; 20])]);
    let b = mk_block(&n, vec![gh], vec![coinbase("t12-undo", core::tokenomics::block_subsidy_sat(1) + 100_000, vec![0x9B; 20]), tx]);
    n.store.put_block_body(&b).unwrap();
    corrupt_row(&n, "utxo", &utxo_row_key(&fund.0, 0), &[0xFF, 0xFF, 0xFF]);
    let plan = gnb::reorg::ReorgPlan { lca: gh, to_rollback: vec![], to_apply: vec![b.block_hash()] };
    // A validator that does not read the view (the batch's own reads remain).
    let validate = |_: &dyn gnb::reorg::UtxoView, _: &core::Block| -> Result<(), gnb::reorg::ValidationFailure> { Ok(()) };
    let none = |_: &gnb::storage::Storage, _: &mut rocksdb::WriteBatch| -> Result<(), String> { Ok(()) };
    let r = gnb::reorg::connect_plan(&n.store, &plan, &gnb::reorg::ConnectHooks { validate: &validate, stage_extra: &none });
    match r {
        Err(gnb::reorg::ConnectError::Failed(m)) => assert!(m.contains("get_utxo"), "{m}"),
        other => panic!("the apply must fail on the unreadable coin: {:?}", other.map(|o| o.connected.len())),
    }
    assert!(n.store.get_undo_data(&b.block_hash()).unwrap().is_none(), "no undo record written");
}

/// B1-T12: a coinbase-height row that cannot be read must never look like
/// "not a coinbase". Before the fix (`.ok().flatten()`, and a row of the
/// wrong length read as absent) the maturity check was skipped and a block
/// spending a 1-block-old coinbase was accepted and applied, a block every
/// other node rejects. Now nothing is committed; once the row reads again
/// the block is rejected for its immature spend, as everywhere else.
#[test]
fn coinbase_height_read_failure_never_skips_maturity() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let k = key();
    let n = node_with(&genesis, &[]);
    let b1 = mk_block(&n, vec![gh], vec![coinbase("t12-cb", core::tokenomics::block_subsidy_sat(1), k.spk.clone())]);
    accept(&n, &b1).unwrap();
    let cb = b1.transactions[0].txid();
    assert_eq!(n.store.get_coinbase_height(&cb).unwrap(), Some(1));
    let spend = signed_spend(&k, &[(cb, 0)], vec![out(core::tokenomics::block_subsidy_sat(1) - 100_000, &[0x9D; 20])]);
    let b2 = mk_block(&n, vec![b1.block_hash()],
        vec![coinbase("t12-spend", core::tokenomics::block_subsidy_sat(2) + 100_000, vec![0x9E; 20]), spend]);
    let id = b2.block_hash();
    corrupt_row(&n, "coinbase", &cb, &[0x01, 0x02, 0x03]);
    let err = accept(&n, &b2).expect_err("an immature spend is never accepted");
    assert!(!err.contains("invalid in its own chain context"), "not a verdict while unreadable: {err}");
    assert_no_verdict(&n, &id, "coinbase height lookup");
    assert_eq!(applied_tip(&n), Some(b1.block_hash()), "not applied");
    n.store.put_coinbase_info(&cb, 1).unwrap();
    let err = accept(&n, &b2).expect_err("immature");
    assert!(err.contains("coinbase maturity"), "{err}");
    assert!(n.store.invalid_block_reason(&id).unwrap().is_some(), "now a genuine verdict, persisted");
}

// ── B1-T13: classify witness-dependent failures by curability ──────────────

fn subsidy(h: u64) -> u64 {
    core::tokenomics::block_subsidy_sat(h)
}

/// A block on genesis carrying `txs`, its coinbase claiming the subsidy plus
/// `fees`.
fn block_with_txs(n: &Node, gh: gnb::consensus::BlockHash, tag: &str, fees: u64, txs: Vec<Transaction>) -> core::Block {
    let mut all = vec![coinbase(tag, subsidy(1) + fees, vec![0xC3; 20])];
    all.extend(txs);
    mk_block(n, vec![gh], all)
}

/// The connect-time verdict of `b` on `n`'s state (below the activation).
fn classify_below(n: &Node, b: &core::Block) -> gnb::accept::BlockInvalidity {
    let view: &gnb::storage::Storage = &n.store;
    match gnb::accept::validate_block_in_view_classified_at(view, b, activation::NEVER) {
        Err(gnb::accept::ConnectFailure::Invalid(e)) => e,
        other => panic!("expected a verdict, got {other:?}"),
    }
}

/// B1-T13: below the activation a failure that NO body with the same block
/// id can cure is id-committed: the block is disqualified and the mark
/// persisted, like any other consensus failure. Before the fix every script
/// and minimum-fee failure was "witness-dependent", so such a block (and its
/// descendants) waited for another body forever and every re-malleated copy
/// was re-validated. Incurable here: a fee below the size-independent floor
/// (MIN_TX_FEE_SAT), a transaction without inputs (its fee is 0), a spend of
/// a coin whose script is not 20 bytes (no public key hashes to it), and a
/// block whose first failure is a bad signature but which also spends more
/// than it has in a later transaction (id-committed checks of the whole
/// block run before any witness check).
#[test]
fn incurable_failures_below_the_activation_are_id_committed() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0xD1u8; 32], 0u32, out(5_000_000, &k.spk));
    let fund2 = ([0xD2u8; 32], 0u32, out(5_000_000, &k.spk));
    let odd = ([0xD3u8; 32], 0u32, out(5_000_000, &[0x55; 5]));
    let funds = [fund.clone(), fund2.clone(), odd.clone()];
    let pay = |v: u64| vec![out(v, &[0x9A; 20])];

    let mut bad_sig = signed_spend(&k, &[(fund.0, 0)], pay(4_900_000));
    bad_sig.inputs[0].script_sig[100] ^= 0x01;
    let overspend = signed_spend(&k, &[(fund2.0, 0)], pay(5_000_001));
    let cases: Vec<(&str, Vec<Transaction>, u64, &str)> = vec![
        ("fee of 1 below the 10,000 floor", vec![signed_spend(&k, &[(fund.0, 0)], pay(4_999_999))], 1, "below consensus minimum"),
        ("transaction without inputs", vec![Transaction { version: 1, inputs: vec![], outputs: vec![], locktime: 0 }], 0, "below consensus minimum"),
        ("coin locked to a 5-byte script", vec![signed_spend(&k, &[(odd.0, 0)], pay(4_900_000))], 100_000, "pubkey mismatch"),
        ("bad signature, then an overspend", vec![bad_sig, overspend], 100_000, "inputs"),
    ];
    for (what, txs, fees, fragment) in cases {
        let n = node_with(&genesis, &funds);
        let b = block_with_txs(&n, gh, what, fees, txs);
        let e = classify_below(&n, &b);
        assert!(e.reason.contains(fragment), "{what}: {e:?}");
        assert!(!e.witness_dependent, "{what}: no body with this id can be valid: {e:?}");
        let err = accept(&n, &b).expect_err(what);
        assert!(err.contains("invalid in its own chain context"), "{what}: {err}");
        assert!(n.dag.read().is_invalid_persistently(&b.block_hash()), "{what}: disqualified");
        assert!(!n.dag.read().is_body_pending(&b.block_hash()), "{what}: not waiting for a body");
        assert!(n.store.invalid_block_reason(&b.block_hash()).unwrap().is_some(), "{what}: persisted");
    }
}

/// The curable failures stay witness-dependent below the activation (another
/// body with the same id can be valid): a bad signature alone, and a fee at
/// or above the floor but below the size-based minimum of this body (a body
/// with shorter witnesses can meet it).
#[test]
fn curable_failures_below_the_activation_stay_witness_dependent() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0xD4u8; 32], 0u32, out(5_000_000, &k.spk));
    let pay = |v: u64| vec![out(v, &[0x9A; 20])];
    let mut bad_sig = signed_spend(&k, &[(fund.0, 0)], pay(4_900_000));
    bad_sig.inputs[0].script_sig[100] ^= 0x01;
    let low_fee = signed_spend(&k, &[(fund.0, 0)], pay(5_000_000 - 12_000));
    assert!(core::tokenomics::min_tx_fee_sat(low_fee.to_wire_bytes(true).len()) > 12_000);
    for (what, tx, fees, fragment) in [
        ("bad signature", bad_sig, 100_000, "invalid signature"),
        ("fee above the floor, below this body's minimum", low_fee, 12_000, "below consensus minimum"),
    ] {
        let n = node_with(&genesis, std::slice::from_ref(&fund));
        let b = block_with_txs(&n, gh, what, fees, vec![tx]);
        let e = classify_below(&n, &b);
        assert!(e.reason.contains(fragment) && e.witness_dependent, "{what}: {e:?}");
        accept(&n, &b).expect_err(what);
        assert!(n.dag.read().is_body_pending(&b.block_hash()), "{what}: waits for another body");
        assert!(n.store.invalid_block_reason(&b.block_hash()).unwrap().is_none(), "{what}: nothing persisted");
    }
}

/// B1-T13: a block whose body was rejected for a witness-dependent reason
/// waits for another body, but its body is WANTED (requested and chased from
/// peers) only while the chain through it can become the best one: a tip on
/// it is heavier than the selected tip (Bitcoin Core downloads blocks of the
/// best header chain only). Before the fix it was chased forever, so each
/// such block (one block of proof of work) held a body-pull slot and every
/// re-malleated answer re-validated it, however far the honest chain moved
/// on. Once the honest chain is heavier the pulls stop; if the waiting branch
/// grows heavier again they resume.
#[test]
fn wanted_bodies_are_bounded_by_the_best_chain() {
    use gnb::ingress::{awaited_bodies_to_chase, awaited_bodies_to_request};
    use gnb::sync::parent_fetch::ParentFetchTracker;
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0xD5u8; 32], 0u32, out(5_000_000, &k.spk));
    let n = node_with(&genesis, std::slice::from_ref(&fund));
    let m1 = empty_child(&n, gh, "main-1");
    accept(&n, &m1).unwrap();
    let mut bad = signed_spend(&k, &[(fund.0, 0)], vec![out(4_900_000, &[0x9A; 20])]);
    bad.inputs[0].script_sig[100] ^= 0x01;
    let f = block_with_txs(&n, gh, "fork", 100_000, vec![bad]);
    // Equal weight to m1: stored unevaluated as a fork-loser, or (when it
    // wins the hash tie-break) evaluated and its body rejected right away.
    let _ = accept(&n, &f);
    let g = empty_child(&n, f.block_hash(), "fork-child");
    let _ = accept(&n, &g); // stored; the branch is evaluated and waits for F's body
    assert!(n.dag.read().is_body_pending(&f.block_hash()));
    let tracker = ParentFetchTracker::new();
    let wanted = |n: &Node| awaited_bodies_to_request(&n.dag.read(), &tracker, 64);
    let chased = |n: &Node| awaited_bodies_to_chase(&n.dag.read(), &tracker, 64);
    assert_eq!(wanted(&n), vec![f.block_hash()], "the waiting branch is the heaviest");
    assert_eq!(chased(&n), vec![f.block_hash()]);

    // The honest chain moves on: three blocks against the branch's two.
    let m2 = empty_child(&n, m1.block_hash(), "main-2");
    accept(&n, &m2).unwrap();
    let m3 = empty_child(&n, m2.block_hash(), "main-3");
    accept(&n, &m3).unwrap();
    assert!(n.dag.read().is_body_pending(&f.block_hash()), "still waiting (in memory, never persisted)");
    assert!(wanted(&n).is_empty(), "no longer requested: the honest chain is heavier");
    assert!(chased(&n).is_empty(), "no longer chased");
    // ... and a copy that arrives anyway is known (an unrequested low-work
    // block in Bitcoin Core): it is not validated again.
    assert!(!gnb::accept::awaits_body(&n.dag, &n.store, &f.block_hash()));
    let err = accept(&n, &f).expect_err("known");
    assert!(err.contains("already in DAG"), "{err}");

    // The waiting branch grows heavier again: its body is wanted again.
    let g2 = empty_child(&n, g.block_hash(), "fork-2");
    accept(&n, &g2).unwrap();
    let g3 = empty_child(&n, g2.block_hash(), "fork-3");
    accept(&n, &g3).unwrap();
    assert_eq!(wanted(&n), vec![f.block_hash()]);
    assert!(gnb::accept::awaits_body(&n.dag, &n.store, &f.block_hash()));
}
