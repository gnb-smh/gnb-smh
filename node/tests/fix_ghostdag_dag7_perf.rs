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

use gnb::consensus::{BlockHash, ConsensusError, GhostDAG, MAX_MERGESET_SIZE};
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
    if hardened {
        if side as usize >= MAX_MERGESET_SIZE {
            assert_eq!(res.unwrap_err(), ConsensusError::MergesetTooLarge { limit: MAX_MERGESET_SIZE });
        } else if n >= gnb::consensus::MERGE_DEPTH {
            // Forked at genesis, below the merge-depth root.
            assert!(matches!(res, Err(ConsensusError::MergeDepthViolation { .. })));
        }
    } else {
        let d = res.expect("pre-activation: no mergeset limit");
        assert_eq!(d.mergeset_blues.len() + d.mergeset_reds.len(), side as usize);
    }

    // Largest accepted mergeset after activation: 179 blocks forked within
    // the merge depth, all red (each is colored with the k + 1 early exit).
    let mut max_merge = String::from("n/a");
    if hardened && n > 400 {
        let mut sc = chain[(n - 200) as usize];
        for j in 0..(MAX_MERGESET_SIZE as u64 - 1) {
            let h = hx(7, j);
            dag.add_block(h, vec![sc], 1, 1).unwrap();
            sc = h;
        }
        let t = Instant::now();
        let d = dag.add_block(hx(8, 0), vec![chain[n as usize], sc], n + 1, 1).expect("maximal mergeset accepted");
        max_merge = format!("{:.2?} (blues {}, reds {})", t.elapsed(), d.mergeset_blues.len(), d.mergeset_reds.len());
        assert_eq!(1 + d.mergeset_blues.len() + d.mergeset_reds.len(), MAX_MERGESET_SIZE);
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
