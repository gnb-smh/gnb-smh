//! Audit DAG-10 (serialized acceptance), DAG-11 (atomic connect + start-up
//! reconciliation) and DAG-12 (height index only for selected-chain blocks)
//! regression tests, on the REAL acceptance path.

mod fix_common;
use fix_common::*;

use std::sync::Arc;

use gnb::core::{self, Block};
use gnb::reorg;

/// DAG-10: many threads accept conflicting sibling blocks (all spending the
/// same outpoint) and their children concurrently into ONE node. With the
/// acceptance mutex the result equals a sequential reference node: one
/// selected chain, the shared outpoint spent exactly once, exactly the
/// selected chain's coinbases applied. Pre-fix interleavings could apply two
/// siblings (supply inflation) or validate a child before its parent applied.
#[test]
fn concurrent_acceptance_equals_sequential_acceptance() {
    let g_ts = unix_now() - 10_000;
    let genesis = mk_genesis(g_ts);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0x31u8; 32], 0u32, out(3_000_000, &k.spk));
    let t = signed_spend(&k, &[(fund.0, 0)], vec![out(2_900_000, &[0x12; 20])]);
    let sub1 = core::tokenomics::block_subsidy_sat(1);

    let reference = node_with(&genesis, &[fund.clone()]);
    let concurrent = Arc::new(node_with(&genesis, &[fund.clone()]));

    // 6 siblings at h1 sharing T, each with one child at h2.
    let mut blocks: Vec<Block> = Vec::new();
    let mut parents_first: Vec<Block> = Vec::new();
    for i in 0..6u8 {
        let s = mk_block(&reference, vec![gh],
            vec![coinbase(&format!("sib-{i}"), sub1 + 100_000, vec![0x40 + i; 20]), t.clone()]);
        parents_first.push(s.clone());
        blocks.push(s);
    }
    for s in &parents_first {
        accept(&reference, s).unwrap();
    }
    let mut children = Vec::new();
    for (i, s) in parents_first.iter().enumerate() {
        let c = empty_child(&reference, s.block_hash(), &format!("child-{i}"));
        accept(&reference, &c).unwrap();
        children.push(c);
    }

    // Concurrent node: siblings from 6 threads at once, then children.
    for wave in [parents_first.clone(), children.clone()] {
        let handles: Vec<_> = wave.into_iter().map(|b| {
            let n = concurrent.clone();
            std::thread::spawn(move || accept(&n, &b))
        }).collect();
        for h in handles {
            h.join().unwrap().expect("every block is valid");
        }
    }

    assert_eq!(sel_tip(&reference), sel_tip(&concurrent));
    assert_eq!(applied_tip(&reference), applied_tip(&concurrent));
    let mut outpoints = vec![(fund.0, 0u32), (t.txid(), 0)];
    for b in parents_first.iter().chain(children.iter()) {
        outpoints.push((b.transactions[0].txid(), 0));
    }
    assert_eq!(utxo_snapshot(&reference, &outpoints), utxo_snapshot(&concurrent, &outpoints));
    let applied_coinbases = parents_first.iter().chain(children.iter())
        .filter(|b| concurrent.store.get_utxo(&b.transactions[0].txid(), 0).unwrap().is_some())
        .count();
    assert_eq!(applied_coinbases, 2, "exactly the selected chain (one sibling + its child) is applied");
    assert!(concurrent.store.get_utxo(&fund.0, 0).unwrap().is_none());
    let _ = blocks;
}

/// DAG-11 (atomicity): if anything in the connect batch fails, NOTHING lands —
/// not the UTXO effects, not the undo record, not the DAG record, not the tip
/// pointer. Here the DAG-record staging fails (the parent's integrity record
/// was lost); pre-fix the UTXO effects were written first and the DAG/tip
/// writes were `.ok()`-ignored, leaving applied effects for a block the DAG
/// does not know.
#[test]
fn failed_connect_batch_leaves_no_partial_state() {
    let g_ts = unix_now() - 10_000;
    let genesis = mk_genesis(g_ts);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0x32u8; 32], 0u32, out(3_000_000, &k.spk));
    let n = node_with(&genesis, &[fund.clone()]);

    let b1 = empty_child(&n, gh, "b1");
    accept(&n, &b1).unwrap();
    // Lose b1's integrity record (what the old `.ok()` writes could do).
    {
        let db = n.store.db();
        let cf = db.cf_handle("dag_integrity").unwrap();
        db.delete_cf(&cf, b1.block_hash()).unwrap();
    }
    let t = signed_spend(&k, &[(fund.0, 0)], vec![out(2_900_000, &[0x13; 20])]);
    let sub2 = core::tokenomics::block_subsidy_sat(2);
    let b2 = mk_block(&n, vec![b1.block_hash()], vec![coinbase("b2", sub2 + 100_000, vec![0xB2; 20]), t.clone()]);
    let err = accept(&n, &b2).expect_err("the connect batch cannot be built");
    assert!(err.contains("integrity"), "{err}");

    assert!(n.store.get_utxo(&fund.0, 0).unwrap().is_some(), "input NOT spent");
    assert!(n.store.get_utxo(&t.txid(), 0).unwrap().is_none(), "no output created");
    assert!(n.store.get_utxo(&b2.transactions[0].txid(), 0).unwrap().is_none());
    assert!(n.store.get_undo_data(&b2.block_hash()).unwrap().is_none(), "no undo record");
    assert!(n.store.get_dag_data(&b2.block_hash()).unwrap().is_none(), "no DAG record");
    assert!(!n.dag.read().has_block(&b2.block_hash()), "in-memory insertion rolled back");
    assert_eq!(applied_tip(&n), Some(b1.block_hash()), "tip pointer unchanged");
    assert_eq!(n.store.get_block_hash_at_height(2).unwrap(), None, "no chain index row");
}

/// DAG-11 (extension commit is one batch): after a successful extension the
/// UTXO effects, undo record, DAG + integrity record and tip pointer are all
/// present, and a restart (reload + verify the integrity chain) is clean.
#[test]
fn extension_commits_everything_and_restart_is_clean() {
    let g_ts = unix_now() - 10_000;
    let genesis = mk_genesis(g_ts);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0x33u8; 32], 0u32, out(3_000_000, &k.spk));
    let mut n = node_with(&genesis, &[fund.clone()]);
    let t = signed_spend(&k, &[(fund.0, 0)], vec![out(2_900_000, &[0x14; 20])]);
    let sub1 = core::tokenomics::block_subsidy_sat(1);
    let b1 = mk_block(&n, vec![gh], vec![coinbase("b1", sub1 + 100_000, vec![0xB1; 20]), t.clone()]);
    accept(&n, &b1).unwrap();
    let h = b1.block_hash();
    assert!(n.store.get_undo_data(&h).unwrap().is_some());
    assert!(n.store.get_dag_data(&h).unwrap().is_some());
    assert!(n.store.get_integrity_hash(&h).unwrap().is_some());
    assert_eq!(applied_tip(&n), Some(h));
    assert!(n.store.get_utxo(&t.txid(), 0).unwrap().is_some());
    restart(&mut n);
    assert_eq!(sel_tip(&n), Some(h));
    assert_eq!(applied_tip(&n), Some(h));
}

/// DAG-11 (start-up reconciliation): the exact crash state of the pre-fix,
/// non-atomic extension commit (audit PoC VAL-4): UTXO effects + undo record
/// written, process dies before the CF_DAG write. Pre-fix the block was
/// rejected forever on re-receipt ('UTXO not found': its inputs read as
/// spent). Reconciliation rolls the orphaned effects back; the block is then
/// accepted normally.
#[test]
fn reconciliation_repairs_a_pre_fix_crash_between_utxo_apply_and_dag_write() {
    let g_ts = unix_now() - 10_000;
    let genesis = mk_genesis(g_ts);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0x34u8; 32], 0u32, out(3_000_000, &k.spk));
    let mut n = node_with(&genesis, &[fund.clone()]);
    let t = signed_spend(&k, &[(fund.0, 0)], vec![out(2_900_000, &[0x15; 20])]);
    let sub1 = core::tokenomics::block_subsidy_sat(1);
    let x = mk_block(&n, vec![gh], vec![coinbase("x", sub1 + 100_000, vec![0xAB; 20]), t.clone()]);

    // The pre-fix extension path, up to the crash point.
    n.store.put_block(&x).unwrap();
    reorg::apply_block_utxo_mutations(&n.store, &x).unwrap();
    assert!(n.store.get_utxo(&fund.0, 0).unwrap().is_none(), "crash state: input spent");

    restart(&mut n); // reload + reconcile_on_startup
    assert!(n.store.get_utxo(&fund.0, 0).unwrap().is_some(), "orphaned effects rolled back");
    assert!(n.store.get_undo_data(&x.block_hash()).unwrap().is_none());

    accept(&n, &x).expect("re-receipt now succeeds (pre-fix: rejected forever)");
    assert_eq!(sel_tip(&n), Some(x.block_hash()));
    assert!(n.store.get_utxo(&fund.0, 0).unwrap().is_none());
    assert!(n.store.get_utxo(&t.txid(), 0).unwrap().is_some());
}

/// DAG-12: a fork-loser (or a refused block) no longer overwrites the
/// height → hash index; the index follows the selected chain through reorgs.
#[test]
fn height_index_tracks_the_selected_chain_only() {
    let g_ts = unix_now() - 10_000;
    let genesis = mk_genesis(g_ts);
    let gh = genesis.block_hash();
    let n = node_with(&genesis, &[]);

    let m1 = empty_child(&n, gh, "m1");
    accept(&n, &m1).unwrap();
    assert_eq!(n.store.get_block_hash_at_height(1).unwrap(), Some(m1.block_hash()));

    let sub1 = core::tokenomics::block_subsidy_sat(1);
    let f1 = mk_block_where(&n, vec![gh], vec![coinbase("f1", sub1, vec![0xF1; 20])],
        |h| *h < m1.block_hash());
    accept(&n, &f1).unwrap();
    assert_eq!(n.store.get_block_hash_at_height(1).unwrap(), Some(m1.block_hash()),
        "fork-loser must not overwrite height 1 (pre-fix: it did)");

    // f-chain overtakes: the index follows the new selected chain.
    let f2 = empty_child(&n, f1.block_hash(), "f2");
    accept(&n, &f2).unwrap();
    assert_eq!(sel_tip(&n), Some(f2.block_hash()));
    assert_eq!(n.store.get_block_hash_at_height(1).unwrap(), Some(f1.block_hash()));
    assert_eq!(n.store.get_block_hash_at_height(2).unwrap(), Some(f2.block_hash()));

    // Back to the m-chain, which becomes heavier: heights re-point.
    let m2 = mk_block_where(&n, vec![m1.block_hash()],
        vec![coinbase("m2", core::tokenomics::block_subsidy_sat(2), vec![0xA2; 20])],
        |h| *h < f2.block_hash());
    accept(&n, &m2).unwrap();
    assert_eq!(n.store.get_block_hash_at_height(2).unwrap(), Some(f2.block_hash()), "m2 is a fork-loser");
    let m3 = empty_child(&n, m2.block_hash(), "m3");
    accept(&n, &m3).unwrap();
    assert_eq!(sel_tip(&n), Some(m3.block_hash()));
    for (h, b) in [(1u64, &m1), (2, &m2), (3, &m3)] {
        assert_eq!(n.store.get_block_hash_at_height(h).unwrap(), Some(b.block_hash()), "height {h}");
    }
}
