//! GhostDAG-level regression tests: DAG-5 (topological reload), DAG-8
//! (legacy `is_ancestor` height shortcut), and the DAG-1 invalid-set
//! selection rules (best VALID block, valid tips, template parents).

use std::collections::HashSet;

use gnb::consensus::{is_ancestor, BlockHash, GhostDAG};

fn hx(tag: u8, i: u64) -> BlockHash {
    let mut h = [0u8; 32];
    h[0] = tag;
    h[1..9].copy_from_slice(&i.to_be_bytes());
    h
}

/// The audit PoC shape: a merged (non-selected) parent Q10 carries a larger
/// blue_score than its child B. Pre-fix the blue_score-ordered reload
/// inserted Q10 after B and resurrected it as a tip.
fn dag5_shape() -> (GhostDAG, BlockHash, BlockHash) {
    let g = hx(0xEE, 0);
    let mut dag = GhostDAG::with_k(1);
    dag.add_genesis(g, 0);
    let s1 = hx(1, 1);
    dag.add_block(s1, vec![g], 1, 1_000).unwrap(); // heavy single block
    let mut q = g;
    for i in 1..=10u64 {
        let h = hx(2, i);
        dag.add_block(h, vec![q], i, 1).unwrap(); // light long chain
        q = h;
    }
    let b = hx(3, 1);
    dag.add_block(b, vec![s1, q], 11, 1).unwrap();
    assert!(dag.get_block_data(&q).unwrap().blue_score > dag.get_block_data(&b).unwrap().blue_score);
    (dag, q, b)
}

#[test]
fn dag5_reload_keeps_the_tip_set() {
    let (dag, q, _b) = dag5_shape();
    let before: HashSet<BlockHash> = dag.tips().into_iter().collect();
    let entries: Vec<_> = dag.store.data.iter().map(|(h, d)| (*h, d.clone())).collect();

    let mut reloaded = GhostDAG::with_k(1);
    reloaded.load_persisted(entries.clone());
    let after: HashSet<BlockHash> = reloaded.tips().into_iter().collect();
    assert_eq!(before, after, "pre-fix: Q10 came back as a tip");
    assert!(!after.contains(&q));
    assert_eq!(reloaded.selected_tip(), dag.selected_tip());

    // Same for the integrity-verified loader (self-heal path: no records).
    let mut verified = GhostDAG::with_k(1);
    verified.load_persisted_validated(entries, Default::default()).unwrap();
    let after_v: HashSet<BlockHash> = verified.tips().into_iter().collect();
    assert_eq!(before, after_v);
}

/// DAG-8: a merged parent can have a GREATER DAG height than its child
/// (`GhostdagData::height` follows the selected parent). The legacy
/// `is_ancestor` returned false for it via the height shortcut.
#[test]
fn dag8_is_ancestor_finds_a_merged_parent_with_greater_height() {
    let g = hx(0xEE, 0);
    let mut dag = GhostDAG::with_default_k();
    dag.add_genesis(g, 0);
    let heavy = hx(1, 1);
    dag.add_block(heavy, vec![g], 1, 1_000_000).unwrap();
    let mut light = g;
    for i in 1..=5u64 {
        let h = hx(2, i);
        dag.add_block(h, vec![light], i, 1).unwrap();
        light = h;
    }
    let b = hx(3, 1);
    let d = dag.add_block(b, vec![heavy, light], 10, 1).unwrap();
    assert_eq!(d.height, 2, "DAG height follows the selected (heavy) parent");
    assert_eq!(dag.get_block_data(&light).unwrap().height, 5);
    assert!(is_ancestor(&dag.store, &light, &b), "merged parent IS an ancestor (pre-fix: false)");
    assert!(is_ancestor(&dag.store, &hx(2, 1), &b), "and so are its ancestors");
    assert!(is_ancestor(&dag.store, &heavy, &b));
    assert!(!is_ancestor(&dag.store, &b, &light));
    assert!(!is_ancestor(&dag.store, &heavy, &light), "siblings are not ancestors");
    // Agrees with the unbounded oracle on every pair.
    let all: Vec<BlockHash> = dag.store.data.keys().copied().collect();
    for a in &all {
        for c in &all {
            assert_eq!(
                is_ancestor(&dag.store, a, c),
                gnb::consensus::reachability::brute_force_is_ancestor(&dag.store, a, c),
            );
        }
    }
}

/// DAG-1 selection rules: the selected tip is the best NON-disqualified
/// block, even when it is no longer a DAG tip; disqualification propagates to
/// selected-chain descendants (including later arrivals) but not to blocks
/// that merely merge a disqualified block; valid tips / template parents skip
/// disqualified blocks.
#[test]
fn invalid_blocks_are_never_selected_and_propagate_along_selected_chains() {
    let g = hx(0xEE, 0);
    let mut dag = GhostDAG::with_default_k();
    dag.add_genesis(g, 0);
    let a = hx(1, 1);
    dag.add_block(a, vec![g], 1, 10).unwrap();
    let x = hx(2, 1); // child of a: will be disqualified
    dag.add_block(x, vec![a], 2, 10).unwrap();
    let x2 = hx(2, 2);
    dag.add_block(x2, vec![x], 3, 10).unwrap();
    assert_eq!(dag.selected_tip(), Some(x2));

    let marked = dag.mark_invalid(x);
    assert_eq!(marked.len(), 2, "x and its selected-chain child x2");
    assert_eq!(dag.selected_tip(), Some(a), "falls back to the best valid block (not a DAG tip)");
    assert_eq!(dag.valid_tips(), vec![a]);

    // Later arrival extending a disqualified block inherits the mark.
    let x3 = hx(2, 3);
    dag.add_block(x3, vec![x2], 4, 10).unwrap();
    assert!(dag.is_invalid(&x3));
    assert_eq!(dag.selected_tip(), Some(a));

    // A sibling y of x, and a merger m = [y, x] whose selected parent is y:
    // m is NOT disqualified (merged blocks do not affect validity).
    let y = hx(3, 1);
    dag.add_block(y, vec![a], 2, 20).unwrap();
    let m = hx(3, 2);
    dag.add_block(m, vec![y, x], 3, 10).unwrap();
    assert_eq!(dag.get_block_data(&m).unwrap().selected_parent, Some(y));
    assert!(!dag.is_invalid(&m));
    assert_eq!(dag.selected_tip(), Some(m));

    let has_body = |_: &BlockHash| true;
    let parents = dag.template_parents(gnb::core::MAX_PARENTS, has_body);
    assert_eq!(parents, vec![m]);

    // Reload: the persisted roots re-derive every mark.
    let entries: Vec<_> = dag.store.data.iter().map(|(h, d)| (*h, d.clone())).collect();
    let mut re = GhostDAG::with_default_k();
    re.load_persisted(entries);
    re.load_invalid(vec![x]);
    for h in [x, x2, x3] {
        assert!(re.is_invalid(&h));
    }
    assert!(!re.is_invalid(&m));
    assert_eq!(re.selected_tip(), Some(m));
}
