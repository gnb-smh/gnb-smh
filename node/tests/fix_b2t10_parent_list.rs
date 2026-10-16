//! Audit B2-T10 + DAG-12 item (4): the header parent list
//! (docs/CONSENSUS.md, "Parent list"), on the REAL acceptance path.
//!
//! * A parent listed twice is valid below the hardening activation (exactly
//!   as before: the DAG treats the list as a set) and invalid at/after it
//!   (`block_rules::check_parents_distinct`), as in Kaspa. The coinbase
//!   commitment hashes the list as written, so the tests commit to the
//!   duplicated list: the repeated parent is the only fault.
//! * A parent in the past of another parent stays valid at every height; it
//!   counts in the header height.
//! * Every producer emits distinct parents on both sides of the boundary
//!   (templates at H - 1 and H, mined and accepted).

mod fix_common;
use fix_common::*;

use gnb::consensus::BlockHash;
use gnb::core::{self, activation, Block};
use gnb::template;

fn assert_not_stored(n: &Node, b: &Block) {
    let h = b.block_hash();
    assert!(!n.dag.read().has_block(&h), "not in the DAG");
    assert!(!n.store.has_block_body(&h).unwrap(), "no body stored");
    assert!(n.store.get_dag_data(&h).unwrap().is_none(), "no DAG record");
}

fn child(n: &Node, parents: Vec<BlockHash>, tag: &str) -> Block {
    let h = {
        let d = n.dag.read();
        parents.iter().map(|p| d.get_block_data(p).unwrap().height).max().unwrap() + 1
    };
    mk_block(n, parents, vec![coinbase(tag, core::tokenomics::block_subsidy_sat(h), vec![0xC0; 20])])
}

/// Below the activation a repeated parent is accepted exactly as before, and
/// the GhostDAG data equal those of the same parents listed once.
#[test]
fn duplicate_parent_below_the_activation_is_accepted_as_before() {
    let _g = activation::scoped_override(100);
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let n = node_with(&genesis, &[]);
    let a = child(&n, vec![gh], "a");
    let c = child(&n, vec![gh], "c");
    accept(&n, &a).unwrap();
    accept(&n, &c).unwrap();
    let dup = child(&n, vec![a.block_hash(), c.block_hash(), c.block_hash()], "dup");
    let dup_sp = child(&n, vec![a.block_hash(), c.block_hash(), a.block_hash()], "dup-sp");
    let plain = child(&n, vec![a.block_hash(), c.block_hash()], "plain");
    assert_eq!(dup.height, 2);
    assert!(dup.validate_structure().is_ok());
    for b in [&dup, &dup_sp, &plain] {
        accept(&n, b).unwrap_or_else(|e| panic!("below the activation: {e}"));
    }
    let d = n.dag.read();
    let p = d.get_block_data(&plain.block_hash()).unwrap().clone();
    for b in [&dup, &dup_sp] {
        let x = d.get_block_data(&b.block_hash()).unwrap();
        assert_eq!(
            (x.selected_parent, x.height, x.blue_score, x.blue_work, &x.mergeset_blues, &x.mergeset_reds),
            (p.selected_parent, p.height, p.blue_score, p.blue_work, &p.mergeset_blues, &p.mergeset_reds),
            "a repeated parent changes no GhostDAG data"
        );
    }
}

/// From the activation a repeated parent is invalid: refused before the
/// block is stored, on every ingress path (the structural check) and in
/// `accept_block`; the same block with distinct parents is valid. Checked at
/// the boundary: activation 2, so the parents (height 1) are pre-activation.
#[test]
fn duplicate_parent_from_the_activation_is_rejected() {
    let _g = activation::scoped_override(2);
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let n = node_with(&genesis, &[]);
    let a = child(&n, vec![gh], "a");
    let c = child(&n, vec![gh], "c");
    accept(&n, &a).unwrap();
    accept(&n, &c).unwrap();
    for parents in [
        vec![a.block_hash(), c.block_hash(), c.block_hash()],
        vec![a.block_hash(), a.block_hash()],
        vec![c.block_hash(), a.block_hash(), c.block_hash()],
    ] {
        let dup = child(&n, parents, "dup");
        assert_eq!(dup.height, 2);
        assert_eq!(dup.validate_structure_without_pow(), Err("duplicate parent"));
        assert_eq!(core::block_rules::check_block_hardened_at(&dup, 2), Err("duplicate parent"));
        assert_eq!(core::block_rules::check_block_hardened_at(&dup, 3), Ok(()), "one height later it would be legacy");
        let err = gnb::accept::accept_block(
            &dup, dup.block_hash(), dup.height, &n.dag, &n.store, &n.mempool, &n.node_state, None, &n.shielded,
        ).unwrap_err();
        assert!(err.contains("duplicate parent"), "{err}");
        assert_not_stored(&n, &dup);
        assert!(matches!(
            gnb::accept::classify_stored_block(&dup, 2),
            gnb::accept::StoredBlockCheck::IdCommitted(_)
        ), "a stored copy (pre-upgrade binary) is disqualified with its id");
    }
    let plain = child(&n, vec![a.block_hash(), c.block_hash()], "plain");
    accept(&n, &plain).expect("distinct parents");
}

/// A parent in the past of another parent is valid in both regimes; it is
/// never the selected parent, adds nothing to the mergeset, and counts in
/// the header height.
#[test]
fn redundant_ancestor_parent_is_valid_in_both_regimes() {
    for act in [activation::NEVER, 1] {
        let _g = activation::scoped_override(act);
        let genesis = mk_genesis(unix_now() - 10_000);
        let gh = genesis.block_hash();
        let n = node_with(&genesis, &[]);
        let a = child(&n, vec![gh], "a");
        accept(&n, &a).unwrap();
        let a2 = child(&n, vec![a.block_hash()], "a2");
        accept(&n, &a2).unwrap();
        let r = child(&n, vec![a2.block_hash(), a.block_hash()], "r");
        accept(&n, &r).unwrap_or_else(|e| panic!("activation {act}: {e}"));
        let d = n.dag.read();
        let x = d.get_block_data(&r.block_hash()).unwrap();
        assert_eq!(x.selected_parent, Some(a2.block_hash()));
        assert!(x.mergeset_blues.is_empty() && x.mergeset_reds.is_empty());
        assert_eq!((r.height, x.height), (3, 3));
    }
}

/// Every producer emits distinct parents on both sides of the boundary: the
/// template at H - 1 and at H (built on two tips, so it lists two parents)
/// is mined and accepted.
#[test]
fn templates_list_each_parent_once_on_both_sides_of_the_activation() {
    const H: u64 = 3;
    let _g = activation::scoped_override(H);
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let n = node_with(&genesis, &[]);
    for tag in ["t1", "t2"] {
        accept(&n, &child(&n, vec![gh], tag)).unwrap();
    }
    for want in [H - 1, H] {
        let tmpl = template::build_block_template(&n.dag, &n.store, &n.mempool, template::EXTERNAL_COINBASE_RESERVE).unwrap();
        assert_eq!(tmpl.height, want);
        assert_eq!(tmpl.parents.len(), 2, "two tips");
        assert_eq!(core::block_rules::check_parents_distinct(&tmpl.parents), Ok(()));
        let cb = template::miner_coinbase(tmpl.height, tmpl.subsidy + tmpl.total_fees, vec![0xCB; 20]);
        let mut block = template::assemble_block(&tmpl, cb, unix_now()).expect("self-check");
        while !block.validate_pow() {
            block.header.nonce += 1;
        }
        accept(&n, &block).unwrap_or_else(|e| panic!("template at {want}: {e}"));
        // A sibling tip so the next template has two parents again.
        if want == H - 1 {
            let tip = block.block_hash();
            let parent = tmpl.parents[0];
            let sib = child(&n, vec![parent], "sib");
            accept(&n, &sib).unwrap();
            assert!(n.dag.read().tips().contains(&tip));
        }
    }
}
