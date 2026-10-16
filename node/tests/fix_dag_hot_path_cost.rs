//! Phase-4 package R4: per-block DAG costs that must not grow with the DAG.
//!
//! * B1-T15 — after the hardening activation, a valid tip whose whole branch
//!   lies below the merge-depth root of the template's selected parent can
//!   never be merged again; it used to cost one full GhostDAG
//!   `compute_block` (and a stored-body lookup) per tip at EVERY template
//!   computation, forever. Each candidate is now tested against the
//!   merge-depth root first (an O(log) reachability query); one final
//!   `compute_block` checks the result.
//! * DAG-7 residual — the reachability reindex of a deep side block or a
//!   genesis sibling re-laid out the whole subtree under its parent, under
//!   the DAG write lock: O(DAG) per such block. The index now follows Kaspa's
//!   reindex-root scheme (slack reserved along the selected chain, reindexing
//!   only inside a bounded window), so such a block costs O(window).
//!
//! Costs are counted (`consensus::compute_block_calls`,
//! `ReachabilityStore::reindex_work`), not timed.

use gnb::consensus::{self, BlockHash, GhostDAG, MERGE_DEPTH};
use gnb::core::activation::NEVER;
use gnb::core::GHOSTDAG_K;

fn hx(tag: u8, i: u64) -> BlockHash {
    let mut h = [0u8; 32];
    h[0] = tag;
    h[1..9].copy_from_slice(&i.to_be_bytes());
    h
}

/// A hardened (activation 0) chain of `n` blocks on genesis `hx(0xEE, 0)`.
fn hardened_chain(n: u64) -> (GhostDAG, Vec<BlockHash>) {
    let g = hx(0xEE, 0);
    let mut dag = GhostDAG::with_k_and_activation(GHOSTDAG_K, 0);
    dag.add_genesis(g, 0);
    let mut chain = vec![g];
    for i in 1..=n {
        dag.add_block(hx(1, i), vec![chain[(i - 1) as usize]], i, 1_000).unwrap();
        chain.push(hx(1, i));
    }
    (dag, chain)
}

// ═════════════════════════════════════════════════════════════════════════════
// B1-T15: unmergeable tips cost O(1) each per template, not a compute_block
// ═════════════════════════════════════════════════════════════════════════════

/// The audit's probe: 178 single-block tips planted under distinct deep chain
/// blocks (far below the merge-depth root), one mergeable side tip near the
/// top. Pre-fix every template computation ran ~178 full `compute_block`s
/// (one repair round per unmergeable tip) and looked up the stored body of
/// every tip. Now: one `compute_block` (the final check), and the unmergeable
/// tips are dropped before their bodies are looked at.
#[test]
fn b1_t15_unmergeable_tips_cost_no_compute_block() {
    const N: u64 = 1_000;
    const { assert!(N > 2 * MERGE_DEPTH, "the deep tips are below the merge-depth root") };
    let (mut dag, chain) = hardened_chain(N);
    for j in 1..=178u64 {
        dag.add_block(hx(2, j), vec![chain[j as usize]], N + j, 1_000).unwrap();
    }
    let side = hx(3, 0);
    dag.add_block(side, vec![chain[(N - 3) as usize]], N + 500, 1_000).unwrap();
    let tip = chain[N as usize];

    let looked_up = std::cell::Cell::new(0usize);
    let has_body = |_: &BlockHash| {
        looked_up.set(looked_up.get() + 1);
        true
    };
    let before = consensus::compute_block_calls();
    let parents = dag.template_parents(gnb::core::MAX_PARENTS, has_body);
    let runs = consensus::compute_block_calls() - before;
    assert_eq!(parents, vec![tip, side], "the selected parent and the one mergeable tip");
    assert!(runs <= 1, "{runs} compute_block runs for one template (the final check only)");
    assert!(looked_up.get() <= 2, "{} stored-body lookups: the unmergeable tips cost none", looked_up.get());

    // The result is what consensus accepts: a block on these parents is valid.
    dag.add_block(hx(4, 0), parents, N + 600, 1_000).expect("the template's parents are valid");

    // Below the activation nothing changes: the plain heaviest-first list.
    let g = hx(0xEE, 0);
    let mut legacy = GhostDAG::with_k_and_activation(GHOSTDAG_K, NEVER);
    legacy.add_genesis(g, 0);
    let mut prev = g;
    for i in 1..=50 {
        legacy.add_block(hx(1, i), vec![prev], i, 1_000).unwrap();
        prev = hx(1, i);
    }
    legacy.add_block(hx(2, 1), vec![hx(1, 1)], 60, 1_000).unwrap();
    let p = legacy.template_parents(gnb::core::MAX_PARENTS, |_| true);
    assert_eq!(p, vec![hx(1, 50), hx(2, 1)], "pre-activation templates still merge every tip");
}

// ═════════════════════════════════════════════════════════════════════════════
// DAG-7 residual: a deep side block costs O(window), not O(DAG)
// ═════════════════════════════════════════════════════════════════════════════

/// Reindex work (nodes counted or re-laid out) of every insertion after an
/// `n`-block chain: deep side blocks under three chain blocks, genesis
/// siblings, more side blocks under the same parent, and a 40-block side
/// chain grown under a deep block. Returns (largest single insertion, total
/// over all of them, work of building the chain itself).
fn deep_insertion_work(n: u64) -> (u64, u64, u64) {
    let g = hx(0xEE, 0);
    let mut dag = GhostDAG::with_k_and_activation(GHOSTDAG_K, NEVER);
    dag.add_genesis(g, 0);
    let mut chain = vec![g];
    for i in 1..=n {
        dag.add_block(hx(1, i), vec![chain[(i - 1) as usize]], i, 1_000).unwrap();
        chain.push(hx(1, i));
    }
    let build = dag.reachability().reindex_work();
    let mut worst = 0u64;
    let mut total = 0u64;
    let mut insert = |dag: &mut GhostDAG, h: BlockHash, parent: BlockHash| {
        let before = dag.reachability().reindex_work();
        dag.add_block(h, vec![parent], 1, 1).unwrap();
        let w = dag.reachability().reindex_work() - before;
        worst = worst.max(w);
        total += w;
    };
    for (j, d) in [n / 2, n / 4, n / 3].iter().enumerate() {
        insert(&mut dag, hx(3, j as u64), chain[*d as usize]);
    }
    for j in 0..20 {
        insert(&mut dag, hx(4, j), g);
    }
    for j in 0..20 {
        insert(&mut dag, hx(5, j), chain[(n / 2) as usize]);
    }
    let mut p = chain[(n / 3) as usize];
    for j in 0..40 {
        insert(&mut dag, hx(6, j), p);
        p = hx(6, j);
    }
    // The tip keeps extending past the deep blocks.
    let mut tip = chain[n as usize];
    for i in 1..=300 {
        let h = hx(7, i);
        let before = dag.reachability().reindex_work();
        dag.add_block(h, vec![tip], n + i, 1_000).unwrap();
        total += dag.reachability().reindex_work() - before;
        tip = h;
    }
    dag.reach_self_check_sample(2_000, 0x0DA6_0007).expect("the index answers exactly");
    (worst, total, build)
}

/// Pre-fix the deep side block under the middle of an n-block chain re-laid
/// out the whole subtree under its parent (about n/2 nodes) and the first
/// genesis sibling the whole DAG. Now no single insertion costs more than a
/// bounded window, the same at 2,000 and 8,000 blocks, and building the chain
/// costs O(1) per block.
#[test]
fn dag7_deep_side_blocks_cost_a_bounded_reindex() {
    let (worst_s, total_s, build_s) = deep_insertion_work(2_000);
    let (worst_l, total_l, build_l) = deep_insertion_work(8_000);
    println!("DAG-7 reindex work: n=2000 worst {worst_s} total {total_s} build {build_s}; \
              n=8000 worst {worst_l} total {total_l} build {build_l}");
    assert!(worst_l <= 1_000, "one deep insertion re-laid out {worst_l} nodes of an 8,000-block DAG");
    assert!(total_l <= 2 * total_s + 1_000,
        "the deep insertions cost {total_l} at 8,000 blocks vs {total_s} at 2,000: the cost grows with the DAG");
    // Tip extensions stay amortized O(1): the reindex root advances in jumps
    // of REINDEX_DEPTH, re-laying out its window once per jump.
    assert!(build_l <= 16 * 8_000, "building the chain cost {build_l} reindex steps");
}
