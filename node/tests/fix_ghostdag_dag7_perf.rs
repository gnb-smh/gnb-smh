//! Audit DAG-7 cost profile: the timing scenario of the audit PoC
//! (`dag7_dos_cost_profile`), run in both regimes and printed. Sizes default to
//! a CI-friendly scale; the audit's scale is
//!   GNB_DAG7_N=12000 GNB_DAG7_SIBLINGS=80 GNB_DAG7_SIDE=1000 \
//!     cargo test -p gnb --test fix_ghostdag_dag7_perf -- --nocapture
//!
//! Timings are printed, not asserted (they depend on the host). The asserts
//! check the behaviour that bounds the cost: before the activation every block
//! is still accepted exactly as before (the speedups there are
//! output-preserving), after it a 1,000-block mergeset is rejected by the size
//! limit and a maximal accepted mergeset is colored with the k + 1 exit.

use std::time::{Duration, Instant};

use gnb::consensus::{BlockHash, ConsensusError, GhostDAG, MERGESET_SIZE_LIMIT};
use gnb::core::activation::NEVER;
use gnb::core::GHOSTDAG_K;

fn hx(tag: u8, i: u64) -> BlockHash {
    let mut h = [0u8; 32];
    h[0] = tag;
    h[1..9].copy_from_slice(&i.to_be_bytes());
    h
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn profile(label: &str, activation: u64) {
    let n = env_u64("GNB_DAG7_N", 3_000);
    let siblings = env_u64("GNB_DAG7_SIBLINGS", 80);
    let side = env_u64("GNB_DAG7_SIDE", 1_000);
    let hardened = activation == 0;
    let g = hx(0xEE, 0);
    let mut dag = GhostDAG::with_k_and_activation(GHOSTDAG_K, activation);
    dag.add_genesis(g, 0);

    let mut chain = vec![g];
    let t_build = Instant::now();
    let mut ext_small = Duration::ZERO;
    for i in 1..=n {
        let h = hx(1, i);
        let t = Instant::now();
        dag.add_block(h, vec![chain[(i - 1) as usize]], i, 1).unwrap();
        if i == 1_000.min(n) { ext_small = t.elapsed(); }
        chain.push(h);
    }
    let build = t_build.elapsed();

    let t = Instant::now();
    dag.add_block(hx(2, 0), vec![chain[n as usize]], n + 1, 1).unwrap();
    let ext_big = t.elapsed();
    assert!(dag.remove_block(&hx(2, 0)));

    let mut deep = vec![];
    for (j, depth) in [n / 2, n / 4].iter().enumerate() {
        let t = Instant::now();
        dag.add_block(hx(3, j as u64), vec![chain[*depth as usize]], 1, 1).unwrap();
        deep.push(t.elapsed());
    }

    let mut worst = Duration::ZERO;
    let mut total = Duration::ZERO;
    for j in 0..siblings {
        let t = Instant::now();
        dag.add_block(hx(4, j), vec![g], 1, 1).unwrap();
        let e = t.elapsed();
        total += e;
        worst = worst.max(e);
    }

    // The audit's merge: a side chain forked at genesis.
    let mut sc = g;
    for j in 0..side {
        let h = hx(5, j);
        dag.add_block(h, vec![sc], 1, 1).unwrap();
        sc = h;
    }
    let t = Instant::now();
    let res = dag.add_block(hx(6, 0), vec![chain[n as usize], sc], n + 1, 1);
    let merge = t.elapsed();
    let merge_desc = match &res {
        Ok(d) => format!("accepted, mergeset {} (blues {}, reds {})",
            d.mergeset_blues.len() + d.mergeset_reds.len(), d.mergeset_blues.len(), d.mergeset_reds.len()),
        Err(e) => format!("rejected: {e}"),
    };
    // This chain's mergeset limit (64, selected parent excluded) holds on
    // both sides of the activation.
    if side as usize > MERGESET_SIZE_LIMIT {
        assert_eq!(res.unwrap_err(), ConsensusError::MergesetTooLarge { limit: MERGESET_SIZE_LIMIT });
    } else if hardened {
        if n >= gnb::consensus::MERGE_DEPTH {
            // Forked at genesis, below the merge-depth root.
            assert!(matches!(res, Err(ConsensusError::MergeDepthViolation { .. })));
        }
    } else {
        let d = res.expect("pre-activation: within the mergeset limit");
        assert_eq!(d.mergeset_blues.len() + d.mergeset_reds.len(), side as usize);
    }

    // Largest accepted mergeset after activation: 179 blocks forked within
    // the merge depth, all red (each is colored with the k + 1 early exit).
    let mut max_merge = String::from("n/a");
    if hardened && n > 400 {
        let mut sc = chain[(n - 200) as usize];
        for j in 0..(MERGESET_SIZE_LIMIT as u64) {
            let h = hx(7, j);
            dag.add_block(h, vec![sc], 1, 1).unwrap();
            sc = h;
        }
        let t = Instant::now();
        let d = dag.add_block(hx(8, 0), vec![chain[n as usize], sc], n + 1, 1).expect("maximal mergeset accepted");
        max_merge = format!("{:.2?} (blues {}, reds {})", t.elapsed(), d.mergeset_blues.len(), d.mergeset_reds.len());
        assert_eq!(d.mergeset_blues.len() + d.mergeset_reds.len(), MERGESET_SIZE_LIMIT);
    }

    println!(
        "DAG7 [{label}] n={n}: build {build:.2?}; tip ext h={} {ext_small:.2?}, h={n} {ext_big:.2?}; \
         deep side {deep:.2?}; {siblings} genesis siblings total {total:.2?} worst {worst:.2?}; \
         merge of {side}-block side chain: {merge_desc} in {merge:.2?}; max accepted mergeset: {max_merge}",
        1_000.min(n)
    );
}

#[test]
fn dag7_profile_pre_activation() {
    profile("pre-activation", NEVER);
}

#[test]
fn dag7_profile_post_activation() {
    profile("post-activation", 0);
}

/// DAG-7 residual (package P3). After the earlier fixes, inserting a genesis
/// sibling still costs a reachability reindex proportional to the whole DAG,
/// and a deep side block one proportional to the subtree under its parent.
/// The bound is the POW-3 anti-DoS work rule
/// (`gnb::ingress::BlockIngress::work_check`, run on every block whose
/// parents are known before its proof of work, storage or insertion): a
/// block whose selected parent is so deep that its chain cannot come within
/// `ANTI_DOS_WINDOW_BLOCKS` of the tip's work is not inserted unless a
/// proof-of-work-verified chain built on it carries that work (honest deep
/// forks), or a buffered orphan merges it — and then deep insertions are
/// rationed by `DeepBackfillBudget`. Outcome-neutral: a block any heavier
/// chain needs is fetched again through that chain's orphans
/// (`node/tests/fix_chain_selection.rs`, pow3_*).
///
/// Measured: the same flood of genesis siblings and deep side blocks
/// inserted into GhostDAG (what reached `accept_block` before) versus
/// decided by the work rule (after). The honest DAG's GhostDAG data and its
/// reachability index are byte-identical with and without the refused flood.
/// The honest chain carries real per-block work (1,000); flood blocks carry
/// the pow-limit work, as the audit's near-free deep-fork blocks do.
#[test]
fn dag7_residual_deep_inserts_are_bounded_by_the_work_rule() {
    use gnb::consensus::canonical_encode;
    use gnb::core::{Block, BlockHeader, MerkleRoot, POW_LIMIT_BITS};
    use gnb::ingress::{BlockIngress, DropReason};

    let n = env_u64("GNB_DAG7_N", 3_000);
    let siblings = env_u64("GNB_DAG7_SIBLINGS", 80);
    let g = hx(0xEE, 0);
    let build = || {
        let mut dag = GhostDAG::with_k_and_activation(GHOSTDAG_K, NEVER);
        dag.add_genesis(g, 0);
        for i in 1..=n {
            dag.add_block(hx(1, i), vec![if i == 1 { g } else { hx(1, i - 1) }], i, 1_000).unwrap();
        }
        dag
    };
    let flood: Vec<(BlockHash, Block)> = (0..siblings)
        .map(|j| {
            // Genesis siblings, and side blocks under n/2 and n/4.
            let parent = match j % 3 { 0 => g, 1 => hx(1, n / 2), _ => hx(1, n / 4) };
            let b = Block {
                header: BlockHeader {
                    version: 1, parents: vec![parent], merkle_root: MerkleRoot::ZERO,
                    timestamp: j, bits: POW_LIMIT_BITS, nonce: j,
                },
                transactions: vec![], blue_score: 0, height: 1, shielded_transactions: vec![],
                powit: Default::default(),
            };
            (b.block_hash(), b)
        })
        .collect();

    // Before: every flood block reached GhostDAG.
    let mut before = build();
    let (mut total_b, mut worst_b) = (Duration::ZERO, Duration::ZERO);
    for (h, b) in &flood {
        let t = Instant::now();
        before.add_block(*h, b.header.parents.clone(), b.header.timestamp, 1).unwrap();
        let e = t.elapsed();
        total_b += e;
        worst_b = worst_b.max(e);
    }

    // After: the work rule decides first; nothing is inserted.
    let after = build();
    let mut core = BlockIngress::new();
    let (mut total_a, mut worst_a) = (Duration::ZERO, Duration::ZERO);
    for (h, b) in &flood {
        let t = Instant::now();
        let verdict = core.work_check(b, h, n, Instant::now(), &after);
        let e = t.elapsed();
        total_a += e;
        worst_a = worst_a.max(e);
        assert_eq!(verdict, Err(DropReason::LowWork));
    }
    let reference = build();
    let snapshot = |d: &GhostDAG| -> Vec<Vec<u8>> {
        (1..=n).map(|i| canonical_encode(d.get_block_data(&hx(1, i)).unwrap())).collect()
    };
    assert_eq!(snapshot(&after), snapshot(&reference), "GhostDAG outputs unchanged");
    assert_eq!(after.reach_export_all(), reference.reach_export_all(), "reachability index unchanged");
    assert_eq!(after.block_count(), reference.block_count());
    assert_eq!(snapshot(&before), snapshot(&reference), "insertions never change existing blocks' data");
    // The work rule still admits the honest tip's children.
    let child = Block {
        header: BlockHeader {
            version: 1, parents: vec![hx(1, n)], merkle_root: MerkleRoot::ZERO,
            timestamp: n + 1, bits: POW_LIMIT_BITS, nonce: 0,
        },
        transactions: vec![], blue_score: 0, height: n + 1, shielded_transactions: vec![],
        powit: Default::default(),
    };
    assert!(core.work_check(&child, &child.block_hash(), n, Instant::now(), &after).is_ok());

    println!(
        "DAG7 residual n={n}: {siblings} low-work deep blocks (genesis siblings + side blocks at n/2, n/4): \
         inserted (before) total {total_b:.2?} worst {worst_b:.2?}; work rule (after) total {total_a:.2?} \
         worst {worst_a:.2?}, none inserted"
    );
}
