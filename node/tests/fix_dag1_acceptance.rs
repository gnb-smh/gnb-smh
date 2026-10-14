//! Audit DAG-1 regression tests: acceptance is separated from connection, so
//! the outcome no longer depends on block arrival order.
//!
//! Every test drives the REAL `gnb::accept::accept_block` with sealed blocks.

mod fix_common;
use fix_common::*;

use gnb::core::{self, TxOutput};

/// Two miners on the same tip include the same mempool transaction T in
/// sibling blocks a1 and b1. Node X sees a1 first, node Y sees b1 first.
/// Pre-fix, each node rejected the other's sibling ("UTXO not found": T's
/// input was already spent in its tip state) and the network split forever.
/// Now both nodes keep both siblings, select the same one, apply the same UTXO
/// set, and keep converging when the other branch later grows heavier.
#[test]
fn sibling_blocks_sharing_a_tx_converge_in_either_arrival_order() {
    let g_ts = unix_now() - 10_000;
    let genesis = mk_genesis(g_ts);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0x5Au8; 32], 0u32, out(1_000_000, &k.spk));

    let t = signed_spend(&k, &[(fund.0, fund.1)], vec![out(900_000, &[0x11; 20])]);
    let fee = 100_000;
    let sub = core::tokenomics::block_subsidy_sat(1);

    let x = node_with(&genesis, &[fund.clone()]);
    let y = node_with(&genesis, &[fund.clone()]);

    let a1 = mk_block(&x, vec![gh], vec![coinbase("miner-A", sub + fee, vec![0xAA; 20]), t.clone()]);
    let b1 = mk_block(&x, vec![gh], vec![coinbase("miner-B", sub + fee, vec![0xBB; 20]), t.clone()]);
    let (a1h, b1h) = (a1.block_hash(), b1.block_hash());
    // Equal work: GhostDAG breaks the tie by hash (larger wins).
    let (winner, loser) = if a1h > b1h { (&a1, &b1) } else { (&b1, &a1) };

    // X: a1 then b1. Y: b1 then a1. Every block is accepted on both nodes.
    accept(&x, &a1).expect("a1 on X");
    accept(&x, &b1).expect("b1 on X — pre-fix: 'UTXO not found'");
    accept(&y, &b1).expect("b1 on Y");
    accept(&y, &a1).expect("a1 on Y — pre-fix: 'UTXO not found'");

    let outpoints = vec![
        (fund.0, fund.1),
        (t.txid(), 0),
        (a1.transactions[0].txid(), 0),
        (b1.transactions[0].txid(), 0),
    ];
    for n in [&x, &y] {
        assert_eq!(sel_tip(n), Some(winner.block_hash()), "same selected tip on both nodes");
        assert_eq!(applied_tip(n), Some(winner.block_hash()), "applied tip pointer agrees");
        assert!(n.store.get_utxo(&fund.0, 0).unwrap().is_none(), "T's input spent once");
        assert!(n.store.get_utxo(&t.txid(), 0).unwrap().is_some(), "T's output exists");
        assert!(n.store.get_utxo(&winner.transactions[0].txid(), 0).unwrap().is_some());
        assert!(n.store.get_utxo(&loser.transactions[0].txid(), 0).unwrap().is_none(),
            "the fork-loser's coinbase is not applied");
    }
    assert_eq!(utxo_snapshot(&x, &outpoints), utxo_snapshot(&y, &outpoints));

    // The LOSER's branch grows: both nodes must follow it (one by reorg) and
    // stay identical. Pre-fix, the node that rejected the loser could never
    // connect its child ('unknown parent', then re-rejection forever).
    let c2 = empty_child(&x, loser.block_hash(), "miner-C");
    accept(&x, &c2).expect("c2 on X");
    accept(&y, &c2).expect("c2 on Y");
    let outpoints2 = [outpoints.clone(), vec![(c2.transactions[0].txid(), 0)]].concat();
    for n in [&x, &y] {
        assert_eq!(sel_tip(n), Some(c2.block_hash()));
        assert_eq!(applied_tip(n), Some(c2.block_hash()));
        assert!(n.store.get_utxo(&loser.transactions[0].txid(), 0).unwrap().is_some());
        assert!(n.store.get_utxo(&winner.transactions[0].txid(), 0).unwrap().is_none());
        assert!(n.store.get_utxo(&t.txid(), 0).unwrap().is_some(), "T re-applied in the loser's context");
        assert!(n.store.get_utxo(&fund.0, 0).unwrap().is_none());
    }
    assert_eq!(utxo_snapshot(&x, &outpoints2), utxo_snapshot(&y, &outpoints2));
}

/// A fork block spending an output created EARLIER ON ITS OWN FORK is valid in
/// its own context. Pre-fix it was rejected at acceptance (the output does not
/// exist in the tip's UTXO set), so the heavier fork could never be adopted.
#[test]
fn fork_block_spending_its_own_forks_output_is_connected_by_reorg() {
    let g_ts = unix_now() - 10_000;
    let genesis = mk_genesis(g_ts);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0x6Bu8; 32], 0u32, out(5_000_000, &k.spk));
    let n = node_with(&genesis, &[fund.clone()]);

    // Main chain: m1 -> m2 (coinbase only).
    let m1 = empty_child(&n, gh, "m1");
    accept(&n, &m1).unwrap();
    let m2 = empty_child(&n, m1.block_hash(), "m2");
    accept(&n, &m2).unwrap();

    // Fork: f1 spends `fund` to k (tx1); f2 spends tx1's output (tx2); f3.
    let sub1 = core::tokenomics::block_subsidy_sat(1);
    let tx1 = signed_spend(&k, &[(fund.0, 0)], vec![out(4_900_000, &k.spk)]);
    let f1 = mk_block_where(&n, vec![gh], vec![coinbase("f1", sub1 + 100_000, vec![0xF1; 20]), tx1.clone()],
        |h| *h < m1.block_hash());
    assert!(accept(&n, &f1).is_ok(), "f1 is a fork-loser, stored without tip-state validation");
    let tx2 = signed_spend(&k, &[(tx1.txid(), 0)], vec![out(4_800_000, &[0x22; 20])]);
    let sub2 = core::tokenomics::block_subsidy_sat(2);
    let f2 = mk_block_where(&n, vec![f1.block_hash()], vec![coinbase("f2", sub2 + 100_000, vec![0xF2; 20]), tx2.clone()],
        |h| *h < m2.block_hash());
    assert!(accept(&n, &f2).is_ok(),
        "f2 spends f1's output: pre-fix rejected with 'UTXO not found' against the tip state");
    assert_eq!(sel_tip(&n), Some(m2.block_hash()), "m-chain still selected (tie lost by hash)");

    let f3 = empty_child(&n, f2.block_hash(), "f3");
    accept(&n, &f3).expect("f3 makes the fork heavier: reorg, each fork block validated in its own context");
    assert_eq!(sel_tip(&n), Some(f3.block_hash()));
    assert_eq!(applied_tip(&n), Some(f3.block_hash()));
    assert!(n.store.get_utxo(&fund.0, 0).unwrap().is_none());
    assert!(n.store.get_utxo(&tx1.txid(), 0).unwrap().is_none(), "spent by tx2");
    assert!(n.store.get_utxo(&tx2.txid(), 0).unwrap().is_some());
    assert!(n.store.get_utxo(&m1.transactions[0].txid(), 0).unwrap().is_none(), "m-chain rolled back");
}

/// A block that is invalid in its own context is disqualified — never
/// selected, never applied — together with its selected-chain descendants,
/// and the marks survive a restart. A block that MERGES it as a non-selected
/// parent is still accepted, on a node that evaluated it (X) and on one that
/// never did (Y): this is why disqualified blocks stay in the DAG instead of
/// being deleted — deleting them would make Y's honest merging block
/// unacceptable to X forever.
#[test]
fn invalid_block_is_disqualified_deterministically_and_mergers_converge() {
    let g_ts = unix_now() - 10_000;
    let genesis = mk_genesis(g_ts);
    let gh = genesis.block_hash();
    let sub = core::tokenomics::block_subsidy_sat(1);

    let mut x = node_with(&genesis, &[]);
    let y = node_with(&genesis, &[]);

    // Honest h1 block Y1 and an invalid sibling BAD (coinbase over-claims the
    // subsidy by 1 sat — only detectable at connect time) whose hash loses
    // the tie-break against Y1 but which is evaluated first on X.
    let y1 = empty_child(&x, gh, "honest-y1");
    let bad = mk_block_where(&x, vec![gh], vec![coinbase("bad", sub + 1, vec![0xBA; 20])],
        |h| *h < y1.block_hash());

    // X: BAD first — it extends the tip, is connected, fails, is disqualified.
    let err = accept(&x, &bad).expect_err("BAD must be rejected");
    assert!(err.contains("coinbase"), "{err}");
    assert!(x.dag.read().is_invalid(&bad.block_hash()));
    assert!(x.dag.read().has_block(&bad.block_hash()), "kept in the DAG as disqualified");
    assert_eq!(sel_tip(&x), Some(gh), "old tip kept");
    assert!(x.store.get_utxo(&bad.transactions[0].txid(), 0).unwrap().is_none(), "no UTXO effect");
    accept(&x, &y1).expect("Y1 on X");

    // Y: Y1 first, then BAD as an unevaluated fork-loser.
    accept(&y, &y1).expect("Y1 on Y");
    accept(&y, &bad).expect("BAD is a fork-loser on Y: stored, not evaluated");
    assert!(!y.dag.read().is_invalid(&bad.block_hash()));

    // A child of BAD is disqualified on arrival on X (its selected parent is
    // invalid), and refused.
    let bad_child = empty_child(&x, bad.block_hash(), "bad-child");
    let e2 = accept(&x, &bad_child).expect_err("selected parent invalid");
    assert!(e2.contains("invalid"), "{e2}");
    assert!(x.dag.read().is_invalid(&bad_child.block_hash()));

    // Y's miner merges BAD as a NON-selected parent (Y1 has the higher key).
    let d = mk_block(&y, vec![y1.block_hash(), bad.block_hash()],
        vec![coinbase("merger", core::tokenomics::block_subsidy_sat(2), vec![0xD0; 20])]);
    accept(&y, &d).expect("D on Y");
    accept(&x, &d).expect("D on X: valid — merged blocks never affect validity");
    let outpoints = vec![
        (y1.transactions[0].txid(), 0),
        (bad.transactions[0].txid(), 0),
        (d.transactions[0].txid(), 0),
    ];
    for n in [&x, &y] {
        assert_eq!(sel_tip(n), Some(d.block_hash()));
        assert_eq!(applied_tip(n), Some(d.block_hash()));
    }
    assert_eq!(utxo_snapshot(&x, &outpoints), utxo_snapshot(&y, &outpoints));

    // The disqualification is persisted and survives a restart.
    restart(&mut x);
    assert!(x.dag.read().is_invalid(&bad.block_hash()));
    assert!(x.dag.read().is_invalid(&bad_child.block_hash()), "descendant re-derived on reload");
    assert_eq!(sel_tip(&x), Some(d.block_hash()));
    let again = accept(&x, &bad).expect_err("re-delivery is a cheap dedup");
    assert!(again.contains("already in DAG"), "{again}");
    // Disqualified blocks are never template parents.
    let parents = x.dag.read().template_parents(core::MAX_PARENTS, |h| x.store.get_block(h).ok().flatten().is_some());
    assert!(!parents.contains(&bad.block_hash()) && !parents.contains(&bad_child.block_hash()));
}

/// A double-spending extension (two txs spending one outpoint) is disqualified
/// and leaves the UTXO set untouched; the honest sibling is then connected.
#[test]
fn double_spending_block_is_disqualified_and_state_untouched() {
    let g_ts = unix_now() - 10_000;
    let genesis = mk_genesis(g_ts);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0x7Cu8; 32], 0u32, out(2_000_000, &k.spk));
    let n = node_with(&genesis, &[fund.clone()]);
    let sub = core::tokenomics::block_subsidy_sat(1);

    let s1 = signed_spend(&k, &[(fund.0, 0)], vec![out(1_900_000, &[0x01; 20])]);
    let s2 = signed_spend(&k, &[(fund.0, 0)], vec![out(1_800_000, &[0x02; 20])]);
    let ds = mk_block(&n, vec![gh], vec![coinbase("ds", sub, vec![0xDD; 20]), s1.clone(), s2]);
    let err = accept(&n, &ds).expect_err("double spend");
    assert!(err.contains("double-spend"), "{err}");
    assert!(n.store.get_utxo(&fund.0, 0).unwrap().is_some(), "UTXO untouched");
    assert_eq!(applied_tip(&n), Some(gh));

    let ok = mk_block(&n, vec![gh], vec![coinbase("ok", sub + 100_000, vec![0xEE; 20]), s1.clone()]);
    accept(&n, &ok).expect("honest sibling connects");
    assert_eq!(sel_tip(&n), Some(ok.block_hash()));
    assert!(n.store.get_utxo(&s1.txid(), 0).unwrap().is_some());
    let _ = TxOutput { value: 0, script_pubkey: vec![] };
}
