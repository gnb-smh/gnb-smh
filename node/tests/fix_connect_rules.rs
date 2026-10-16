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
