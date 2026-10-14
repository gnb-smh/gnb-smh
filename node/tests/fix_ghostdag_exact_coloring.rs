//! Hardening activation, post-activation rules (audit DAG-3, DAG-4, DAG-7,
//! DAG-2 consensus side).
//!
//! * `exact_coloring_matches_reference_on_random_dags`: every block at or above
//!   the activation is compared with a reference GHOSTDAG written here from the
//!   paper's definition — brute-force pasts, the k-cluster test over the FULL
//!   blue anticone, the same selected-parent rule and the same deterministic
//!   candidate order — on random DAGs, from genesis (activation 0) and with the
//!   activation in the middle of the DAG.
//! * The DAG-3 and DAG-4 PoC shapes of the audit, before and after activation.
//! * Mergeset-size limit, merge-depth bound (with Kaspa's kosherizing rule) and
//!   the template parent helper.

use std::collections::{HashMap, HashSet, VecDeque};

use gnb::consensus::{
    canonical_encode, BlockHash, ConsensusError, GhostDAG, GhostdagData, MAX_MERGESET_SIZE, MERGE_DEPTH,
};
use gnb::core::activation::NEVER;
use gnb::core::{GHOSTDAG_K, MAX_PARENTS};

// ── helpers ──────────────────────────────────────────────────────────────────

struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self { Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1) }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next_u64() % n as u64) as usize }
    }
}

fn hx(tag: u8, i: u64) -> BlockHash {
    let mut h = [0u8; 32];
    h[0] = tag;
    h[1..9].copy_from_slice(&i.to_be_bytes());
    h
}

/// Hash with a pseudo-random prefix so hash tie-breaks are exercised.
fn rh(tag: u8, i: u64) -> BlockHash {
    let mut z = ((tag as u64) << 40) ^ i ^ 0xD1B5_4A32_D192_ED03;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(&(z ^ (z >> 31)).to_le_bytes());
    h[8] = tag;
    h[9..17].copy_from_slice(&i.to_be_bytes());
    h
}

type Spec = (BlockHash, Vec<BlockHash>, u64, u128);

fn random_specs(tag: u8, n: u64, maxpar: usize, window: usize, deep_one_in: usize, max_work: usize, seed: u64)
    -> (BlockHash, Vec<Spec>)
{
    let mut rng = Rng::new(seed);
    let g = rh(tag, 0);
    let mut pool = vec![g];
    let mut specs = Vec::new();
    for i in 1..=n {
        let np = 1 + rng.below(maxpar);
        let mut parents = Vec::new();
        for _ in 0..np {
            let p = if deep_one_in > 0 && rng.below(deep_one_in) == 0 {
                pool[rng.below(pool.len())]
            } else {
                let w = pool.len().min(window);
                pool[pool.len() - w + rng.below(w)]
            };
            if !parents.contains(&p) { parents.push(p); }
        }
        let h = rh(tag, i);
        specs.push((h, parents, i, 1 + rng.below(max_work) as u128));
        pool.push(h);
    }
    (g, specs)
}

fn build(k: usize, activation: u64, g: BlockHash, specs: &[Spec]) -> GhostDAG {
    let mut dag = GhostDAG::with_k_and_activation(k, activation);
    dag.add_genesis(g, 0);
    for (h, p, ts, w) in specs {
        dag.add_block(*h, p.clone(), *ts, *w)
            .unwrap_or_else(|e| panic!("add_block {}: {e}", hex::encode(&h[..4])));
    }
    dag
}

/// blue(B) from stored data: blue(sp) ∪ {sp} ∪ mergeset_blues(B).
fn stored_blue_set(dag: &GhostDAG, b: &BlockHash, memo: &mut HashMap<BlockHash, HashSet<BlockHash>>) -> HashSet<BlockHash> {
    if let Some(s) = memo.get(b) { return s.clone(); }
    let d = dag.get_block_data(b).unwrap().clone();
    let mut s = match d.selected_parent {
        None => HashSet::new(),
        Some(sp) => { let mut s = stored_blue_set(dag, &sp, memo); s.insert(sp); s }
    };
    s.extend(d.mergeset_blues.iter().copied());
    memo.insert(*b, s.clone());
    s
}

// ── reference GHOSTDAG (definition, brute force) ─────────────────────────────

/// Same tie-broken Kahn order as `consensus::topological_sort` (ancestors
/// first, hash order among ready blocks): the deterministic candidate order.
fn topo(parents_of: &HashMap<BlockHash, Vec<BlockHash>>, blocks: &HashSet<BlockHash>) -> Vec<BlockHash> {
    let mut indeg: HashMap<BlockHash, usize> = HashMap::new();
    let mut rev: HashMap<BlockHash, Vec<BlockHash>> = HashMap::new();
    for &b in blocks {
        indeg.entry(b).or_insert(0);
        for p in &parents_of[&b] {
            if blocks.contains(p) {
                *indeg.entry(b).or_insert(0) += 1;
                rev.entry(*p).or_default().push(b);
            }
        }
    }
    let mut start: Vec<BlockHash> = indeg.iter().filter(|(_, &d)| d == 0).map(|(h, _)| *h).collect();
    start.sort_unstable();
    let mut q: VecDeque<BlockHash> = start.into();
    let mut out = Vec::new();
    while let Some(b) = q.pop_front() {
        out.push(b);
        if let Some(ch) = rev.get(&b) {
            let mut nx = Vec::new();
            for c in ch {
                let d = indeg.get_mut(c).unwrap();
                *d -= 1;
                if *d == 0 { nx.push(*c); }
            }
            nx.sort_unstable();
            q.extend(nx);
        }
    }
    out
}

struct RefBlock {
    sp: BlockHash,
    height: u64,
    blues: Vec<BlockHash>,
    reds: Vec<BlockHash>,
    blue_set: HashSet<BlockHash>,
    blue_score: u64,
    blue_work: u128,
}

/// Checks every block at or above `activation` against the reference.
/// Blocks below it are taken as stored (their bit-identity with the old code is
/// proven in `fix_ghostdag_preactivation_identity.rs`). Returns the number of
/// blocks checked.
fn check_against_reference(dag: &GhostDAG, k: usize, activation: u64, g: BlockHash, specs: &[Spec], label: &str) -> usize {
    let mut parents_of: HashMap<BlockHash, Vec<BlockHash>> = HashMap::new();
    let mut work: HashMap<BlockHash, u128> = HashMap::new();
    let mut past: HashMap<BlockHash, HashSet<BlockHash>> = HashMap::new();
    parents_of.insert(g, vec![]);
    work.insert(g, 0);
    past.insert(g, HashSet::new());
    // reference (or, below activation, stored) values per block
    let mut bw: HashMap<BlockHash, u128> = HashMap::from([(g, 0)]);
    let mut bs: HashMap<BlockHash, u64> = HashMap::from([(g, 0)]);
    let mut height: HashMap<BlockHash, u64> = HashMap::from([(g, 0)]);
    let mut blue: HashMap<BlockHash, HashSet<BlockHash>> = HashMap::from([(g, HashSet::new())]);
    let mut stored_memo = HashMap::new();
    let mut checked = 0;

    for (h, ps, _, w) in specs {
        parents_of.insert(*h, ps.clone());
        work.insert(*h, *w);
        let mut p: HashSet<BlockHash> = HashSet::new();
        for x in ps { p.insert(*x); p.extend(past[x].iter().copied()); }
        past.insert(*h, p);
        let anti = |a: &BlockHash, b: &BlockHash, past: &HashMap<BlockHash, HashSet<BlockHash>>| {
            a != b && !past[b].contains(a) && !past[a].contains(b)
        };

        let sp = *ps.iter().max_by(|a, b| bw[*a].cmp(&bw[*b]).then(bs[*a].cmp(&bs[*b])).then(a.cmp(b))).unwrap();
        let hgt = height[&sp] + 1;
        let d = dag.get_block_data(h).unwrap();
        if hgt < activation {
            assert_eq!(d.height, hgt, "[{label}] height");
            bw.insert(*h, d.blue_work);
            bs.insert(*h, d.blue_score);
            height.insert(*h, d.height);
            blue.insert(*h, stored_blue_set(dag, h, &mut stored_memo));
            continue;
        }

        let mergeset: HashSet<BlockHash> = past[h].iter()
            .filter(|x| **x != sp && !past[&sp].contains(*x)).copied().collect();
        let mut bset = blue[&sp].clone();
        bset.insert(sp);
        let (mut blues, mut reds) = (Vec::new(), Vec::new());
        for c in topo(&parents_of, &mergeset) {
            let ac: Vec<BlockHash> = bset.iter().filter(|x| anti(&c, x, &past)).copied().collect();
            let fits = ac.len() <= k
                && ac.iter().all(|x| bset.iter().filter(|y| anti(x, y, &past)).count() < k);
            if fits { bset.insert(c); blues.push(c); } else { reds.push(c); }
        }
        let r = RefBlock {
            sp,
            height: hgt,
            blue_work: bw[&sp] + blues.iter().map(|b| work[b]).sum::<u128>() + w,
            blue_score: bset.len() as u64,
            blues,
            reds,
            blue_set: bset,
        };

        let hx4 = hex::encode(&h[..4]);
        assert_eq!(d.selected_parent, Some(r.sp), "[{label}] {hx4} selected parent");
        assert_eq!(d.height, r.height, "[{label}] {hx4} height");
        assert_eq!(d.mergeset_blues, r.blues, "[{label}] {hx4} mergeset blues");
        assert_eq!(d.mergeset_reds, r.reds, "[{label}] {hx4} mergeset reds");
        assert_eq!(d.blue_score, r.blue_score, "[{label}] {hx4} blue score");
        assert_eq!(d.blue_work, r.blue_work, "[{label}] {hx4} blue work");
        assert_eq!(stored_blue_set(dag, h, &mut stored_memo), r.blue_set, "[{label}] {hx4} blue set");
        // Every recorded anticone size is exact w.r.t. blue(B), and the map
        // covers the selected parent and the new blues.
        for (x, s) in &d.blues_anticone_sizes {
            let exact = r.blue_set.iter().filter(|y| anti(x, y, &past)).count();
            assert_eq!(*s, exact, "[{label}] {hx4} anticone size of {}", hex::encode(&x[..4]));
        }
        assert!(d.blues_anticone_sizes.contains_key(&r.sp));
        for b in &r.blues { assert!(d.blues_anticone_sizes.contains_key(b)); }
        if activation == 0 {
            // From genesis: blue(B) is a k-cluster, and blue work is the work of
            // blue(B) ∪ {B} (GnB's blue_work includes the block's own work).
            for x in &r.blue_set {
                let n = r.blue_set.iter().filter(|y| anti(x, y, &past)).count();
                assert!(n <= k, "[{label}] {hx4}: blue {} has {n} > k blues in its anticone", hex::encode(&x[..4]));
            }
            let total: u128 = r.blue_set.iter().map(|x| work[x]).sum::<u128>() + w;
            assert_eq!(d.blue_work, total, "[{label}] {hx4} blue work = work(blue(B) ∪ {{B}})");
        }
        bw.insert(*h, r.blue_work);
        bs.insert(*h, r.blue_score);
        height.insert(*h, r.height);
        blue.insert(*h, r.blue_set);
        checked += 1;
    }
    checked
}

#[test]
fn exact_coloring_matches_reference_on_random_dags() {
    let mut total = 0;
    let mut reds = 0;
    for s in 0..60u64 {
        let k = [1usize, 2, 3, 4, 10][s as usize % 5];
        let (g, specs) = random_specs(0x40, 70 + s % 30, 1 + s as usize % 4, 4 + s as usize % 9,
                                      [0, 10, 30][s as usize % 3], [1, 50, 3000][s as usize % 3], s);
        let dag = build(k, 0, g, &specs);
        total += check_against_reference(&dag, k, 0, g, &specs, &format!("from-genesis seed {s} k {k}"));
        reds += specs.iter().map(|(h, ..)| dag.get_block_data(h).unwrap().mergeset_reds.len()).sum::<usize>();
    }
    assert!(total > 4_000 && reds > 200, "reference comparison exercised ({total} blocks, {reds} reds)");
}

#[test]
fn exact_coloring_matches_reference_with_mid_dag_activation() {
    let mut total = 0;
    for s in 0..30u64 {
        let k = [2usize, 3, 10][s as usize % 3];
        let (g, specs) = random_specs(0x50, 90, 3, 8, 15, 400, 100 + s);
        let activation = 10 + s % 25;
        let dag = build(k, activation, g, &specs);
        total += check_against_reference(&dag, k, activation, g, &specs, &format!("mid seed {s} k {k} activation {activation}"));
    }
    println!("mid-DAG activation: {total} hardened blocks checked");
    assert!(total > 500, "hardened blocks checked: {total}");
}

/// Post-activation coloring and blue work do not depend on the order of the
/// parent list or on the order in which (topologically valid) blocks arrive.
#[test]
fn post_activation_is_parent_and_arrival_order_independent() {
    for s in 0..20u64 {
        let k = [2usize, 3, 10][s as usize % 3];
        let (g, specs) = random_specs(0x60, 100, 4, 10, 12, 500, 300 + s);
        let a = build(k, 0, g, &specs);
        let reversed: Vec<Spec> = specs.iter().map(|(h, p, t, w)| {
            let mut p = p.clone();
            p.reverse();
            (*h, p, *t, *w)
        }).collect();
        let b = build(k, 0, g, &reversed);
        // A different valid arrival order: delay every third block until just
        // before its first child.
        let mut order: Vec<Spec> = Vec::new();
        let mut held: Vec<Spec> = Vec::new();
        for (i, sp) in specs.iter().enumerate() {
            let needs: Vec<BlockHash> = sp.1.clone();
            let mut j = 0;
            while j < held.len() {
                if needs.contains(&held[j].0) { order.push(held.remove(j)); } else { j += 1; }
            }
            if i % 3 == 0 { held.push(sp.clone()); } else { order.push(sp.clone()); }
        }
        order.extend(held);
        let c = build(k, 0, g, &order);
        for (h, ..) in &specs {
            let da = canonical_encode(a.get_block_data(h).unwrap());
            assert_eq!(da, canonical_encode(b.get_block_data(h).unwrap()), "seed {s}: parent order changed a block");
            let dc = c.get_block_data(h).unwrap();
            // the parents vector is stored as given; compare everything else
            let mut dc = dc.clone();
            dc.parents = a.get_block_data(h).unwrap().parents.clone();
            assert_eq!(da, canonical_encode(&dc), "seed {s}: arrival order changed a block");
        }
        assert_eq!(a.selected_tip(), b.selected_tip());
        assert_eq!(a.selected_tip(), c.selected_tip());
    }
}

// ── audit PoC shapes ─────────────────────────────────────────────────────────

fn dag3_shape(dag: &mut GhostDAG) -> (BlockHash, BlockHash) {
    let g = hx(0xEE, 0);
    dag.add_genesis(g, 0);
    let mut prev = g;
    for i in 1..=5u64 {
        let (l, r, m) = (hx(0x10, i), hx(0x11, i), hx(0x12, i));
        dag.add_block(l, vec![prev], i, 1).unwrap();
        dag.add_block(r, vec![prev], i, 1).unwrap();
        let d = dag.add_block(m, vec![l, r], i, 1).unwrap();
        assert_eq!(d.mergeset_blues.len(), 1, "sibling merged as blue");
        prev = m;
    }
    let mut c = g;
    for i in 1..=11u64 {
        let h = hx(0x20, i);
        dag.add_block(h, vec![c], i, 1).unwrap();
        c = h;
    }
    (prev, c)
}

/// DAG-3: after activation the merged blue blocks count, so the honest DAG
/// (15 blocks) outweighs the bare 11-block chain; before activation the old
/// fork choice (10 vs 11) is kept.
#[test]
fn dag3_merged_blue_work_counts_after_activation() {
    let mut post = GhostDAG::with_k_and_activation(GHOSTDAG_K, 0);
    let (honest, bare) = dag3_shape(&mut post);
    assert_eq!(post.get_block_data(&honest).unwrap().blue_work, 15);
    assert_eq!(post.get_block_data(&bare).unwrap().blue_work, 11);
    assert_eq!(post.selected_tip(), Some(honest), "heaviest blue DAG wins");

    let mut pre = GhostDAG::with_k_and_activation(GHOSTDAG_K, NEVER);
    let (honest, bare) = dag3_shape(&mut pre);
    assert_eq!(pre.get_block_data(&honest).unwrap().blue_work, 10);
    assert_eq!(pre.get_block_data(&bare).unwrap().blue_work, 11);
    assert_eq!(pre.selected_tip(), Some(bare), "pre-activation fork choice unchanged");
}

/// Below the activation blue work is the old formula; the first hardened block
/// adds its merged blues on top of the stored value, with no gap.
#[test]
fn dag3_blue_work_across_the_activation_boundary() {
    let mut dag = GhostDAG::with_k_and_activation(GHOSTDAG_K, 3);
    let g = hx(0xEE, 0);
    dag.add_genesis(g, 0);
    let a1 = hx(1, 1);
    let b1 = hx(2, 1);
    dag.add_block(a1, vec![g], 1, 100).unwrap(); // height 1
    dag.add_block(b1, vec![g], 1, 7).unwrap(); // height 1
    let m2 = dag.add_block(hx(3, 2), vec![a1, b1], 2, 100).unwrap(); // height 2: old rule
    assert_eq!(m2.mergeset_blues, vec![b1]);
    assert_eq!(m2.blue_work, 200, "pre-activation: sp.blue_work + own work");
    let b2 = hx(2, 2);
    dag.add_block(b2, vec![a1], 2, 5).unwrap(); // height 2
    let m3 = dag.add_block(hx(3, 3), vec![hx(3, 2), b2], 3, 100).unwrap(); // height 3: hardened
    assert_eq!(m3.mergeset_blues, vec![b2]);
    assert_eq!(m3.blue_work, 200 + 5 + 100, "hardened: sp.blue_work + merged blue + own");
}

fn dag4_shape(dag: &mut GhostDAG) -> (BlockHash, GhostdagData) {
    let g = hx(0xEE, 0);
    dag.add_genesis(g, 0);
    let mut prev = g;
    for i in 1..=30u64 {
        let h = hx(1, i);
        dag.add_block(h, vec![prev], i, 1_000).unwrap();
        prev = h;
    }
    let side = hx(9, 1);
    dag.add_block(side, vec![g], 1, 1_000).unwrap();
    let d = dag.add_block(hx(9, 2), vec![prev, side], 31, 1_000).unwrap();
    (side, d)
}

/// DAG-4: a side block forked under a 30-block chain has 30 > k blues in its
/// anticone. Exact coloring makes it red; the old coloring (kept below the
/// activation) made it blue.
#[test]
fn dag4_deep_side_block_is_red_after_activation() {
    let mut post = GhostDAG::with_k_and_activation(GHOSTDAG_K, 0);
    let (side, d) = dag4_shape(&mut post);
    assert_eq!(d.mergeset_reds, vec![side]);
    assert!(d.mergeset_blues.is_empty());
    assert_eq!(d.blue_score, 31);

    let mut pre = GhostDAG::with_k_and_activation(GHOSTDAG_K, NEVER);
    let (side, d) = dag4_shape(&mut pre);
    assert_eq!(d.mergeset_blues, vec![side], "pre-activation keeps the old (buggy) coloring");
}

// ── DAG-7 limits ─────────────────────────────────────────────────────────────

fn chain(dag: &mut GhostDAG, tag: u8, from: BlockHash, len: u64, work: u128) -> Vec<BlockHash> {
    let mut out = vec![from];
    for i in 1..=len {
        let h = hx(tag, i);
        dag.add_block(h, vec![out[(i - 1) as usize]], i, work).unwrap();
        out.push(h);
    }
    out
}

#[test]
fn mergeset_size_limit_after_activation() {
    for (activation, side_len, ok) in [
        (0, MAX_MERGESET_SIZE as u64 - 1, true),  // 179 + selected parent = 180
        (0, MAX_MERGESET_SIZE as u64, false),     // 181
        (0, 1_000, false),
        (NEVER, 1_000, true),                     // no limit before activation
    ] {
        let mut dag = GhostDAG::with_k_and_activation(GHOSTDAG_K, activation);
        let g = hx(0xEE, 0);
        dag.add_genesis(g, 0);
        // Main chain shorter than MERGE_DEPTH, so only the size limit applies.
        let main = chain(&mut dag, 1, g, 300, 1_000);
        let side = chain(&mut dag, 2, g, side_len, 1);
        let tips_before: HashSet<BlockHash> = dag.tips().into_iter().collect();
        let count_before = dag.block_count();
        let merge = hx(3, 0);
        let res = dag.add_block(merge, vec![*main.last().unwrap(), *side.last().unwrap()], 0, 1_000);
        if ok {
            let d = res.expect("within the limit");
            assert_eq!(d.mergeset_blues.len() + d.mergeset_reds.len(), side_len as usize);
        } else {
            assert_eq!(res.unwrap_err(), ConsensusError::MergesetTooLarge { limit: MAX_MERGESET_SIZE });
            assert_eq!(dag.block_count(), count_before, "rejected block not inserted");
            assert_eq!(dag.tips().into_iter().collect::<HashSet<_>>(), tips_before);
            assert!(!dag.has_block(&merge));
            // A valid block still goes in afterwards.
            dag.add_block(hx(4, 0), vec![*main.last().unwrap()], 0, 1_000).unwrap();
        }
    }
}

#[test]
fn merge_depth_bound_after_activation() {
    assert_eq!(MERGE_DEPTH, 360);
    let mut dag = GhostDAG::with_k_and_activation(GHOSTDAG_K, 0);
    let g = hx(0xEE, 0);
    dag.add_genesis(g, 0);
    let c = chain(&mut dag, 1, g, 401, 1_000); // linear: blue_score(C_i) = i
    let red_deep = hx(5, 1);
    dag.add_block(red_deep, vec![c[41]], 0, 1).unwrap(); // forked at C_41
    let red_ok = hx(5, 2);
    dag.add_block(red_ok, vec![c[80]], 0, 1).unwrap(); // forked at C_80

    // B' = [C_401, red_deep]: blue_score 402, root C_42; red_deep is below it.
    let err = dag.add_block(hx(6, 1), vec![c[401], red_deep], 0, 1_000).unwrap_err();
    assert_eq!(err, ConsensusError::MergeDepthViolation { red: red_deep });
    // A red forked above the root is fine.
    let d = dag.add_block(hx(6, 2), vec![c[401], red_ok], 0, 1_000).unwrap();
    assert_eq!(d.mergeset_reds, vec![red_ok]);

    // Kosherizing: X = [C_400, red_deep] is valid (root C_41, red_deep is in its
    // future); B = [C_401, X] merges X as blue, and red_deep is below B's root
    // (C_43) but in X's past, so B is valid too.
    let x = hx(7, 1);
    let dx = dag.add_block(x, vec![c[400], red_deep], 0, 1).unwrap();
    assert_eq!(dx.mergeset_reds, vec![red_deep]);
    let db = dag.add_block(hx(7, 2), vec![c[401], x], 0, 1_000).unwrap();
    assert_eq!(db.mergeset_blues, vec![x]);
    assert_eq!(db.mergeset_reds, vec![red_deep]);

    // Below the activation none of this applies.
    let mut pre = GhostDAG::with_k_and_activation(GHOSTDAG_K, NEVER);
    pre.add_genesis(g, 0);
    let c = chain(&mut pre, 1, g, 401, 1_000);
    pre.add_block(red_deep, vec![c[41]], 0, 1).unwrap();
    pre.add_block(hx(6, 1), vec![c[401], red_deep], 0, 1_000).unwrap();
}

/// The audit's DAG-7 merge (a 1,000-block side chain forked at genesis): after
/// activation it is rejected by the mergeset limit before any coloring work.
#[test]
fn dag7_large_side_chain_merge_rejected_after_activation() {
    let mut dag = GhostDAG::with_k_and_activation(GHOSTDAG_K, 0);
    let g = hx(0xEE, 0);
    dag.add_genesis(g, 0);
    let main = chain(&mut dag, 1, g, 2_000, 1);
    let side = chain(&mut dag, 5, g, 1_000, 1);
    let t = std::time::Instant::now();
    let err = dag.add_block(hx(6, 0), vec![main[2_000], side[1_000]], 0, 1).unwrap_err();
    println!("1,000-block mergeset rejected in {:.2?}", t.elapsed());
    assert_eq!(err, ConsensusError::MergesetTooLarge { limit: MAX_MERGESET_SIZE });
}

// ── template helper (DAG-2 consensus side) ───────────────────────────────────

fn template_hash(i: u64) -> BlockHash { hx(0x77, i) }

#[test]
fn template_parents_respect_mergeset_limit() {
    // DAG-2 shape: 300 leaf children of an anchor deep in history.
    let mut dag = GhostDAG::with_k_and_activation(GHOSTDAG_K, 0);
    let g = hx(0xEE, 0);
    dag.add_genesis(g, 0);
    let main = chain(&mut dag, 1, g, 20, 1_000);
    let anchor = hx(2, 0);
    dag.add_block(anchor, vec![main[3]], 100, 1).unwrap();
    for i in 0..300u64 {
        dag.add_block(hx(3, i), vec![anchor], 101, 1).unwrap();
    }
    let tips = dag.bodied_tips(|_| true);
    assert_eq!(tips.len(), 301);
    let parents = dag.select_parents_for_template(&tips, MAX_PARENTS);
    assert_eq!(parents[0], main[20], "selected parent first");
    assert!(parents.len() <= MAX_PARENTS);
    assert!(parents.len() > 100, "the helper still merges what fits ({})", parents.len());
    let d = dag.add_block(template_hash(1), parents.clone(), 200, 1_000).expect("template is valid");
    assert_eq!(d.selected_parent, Some(main[20]));
    assert!(1 + d.mergeset_blues.len() + d.mergeset_reds.len() <= MAX_MERGESET_SIZE);
    // Deterministic, and independent of the candidate order.
    let mut rev = tips.clone();
    rev.reverse();
    assert_eq!(dag.select_parents_for_template(&rev, MAX_PARENTS), parents);
}

#[test]
fn template_parents_drop_merge_depth_violations() {
    let mut dag = GhostDAG::with_k_and_activation(GHOSTDAG_K, 0);
    let g = hx(0xEE, 0);
    dag.add_genesis(g, 0);
    let c = chain(&mut dag, 1, g, 401, 1_000);
    let deep = hx(5, 1);
    dag.add_block(deep, vec![c[41]], 0, 1).unwrap();
    let near = hx(5, 2);
    dag.add_block(near, vec![c[399]], 0, 1).unwrap();
    let tips = dag.tips();
    assert_eq!(tips.len(), 3);
    let parents = dag.select_parents_for_template(&tips, MAX_PARENTS);
    assert_eq!(parents, vec![c[401], near], "deep tip dropped, near tip kept");
    dag.add_block(template_hash(2), parents, 0, 1_000).expect("template is valid");
}

#[test]
fn template_parents_before_activation_are_heaviest_tips() {
    let mut dag = GhostDAG::with_k_and_activation(GHOSTDAG_K, NEVER);
    let g = hx(0xEE, 0);
    dag.add_genesis(g, 0);
    let main = chain(&mut dag, 1, g, 20, 1_000);
    for i in 0..300u64 {
        dag.add_block(hx(3, i), vec![main[5]], 0, 1 + i as u128).unwrap();
    }
    let tips = dag.tips();
    let parents = dag.select_parents_for_template(&tips, MAX_PARENTS);
    assert_eq!(parents.len(), MAX_PARENTS);
    assert_eq!(parents[0], main[20]);
    let w = |h: &BlockHash| dag.get_block_data(h).unwrap().blue_work;
    assert!(parents.windows(2).all(|p| w(&p[0]) >= w(&p[1])), "ordered by blue work");
    assert_eq!(dag.select_parents_for_template(&tips, 1), vec![main[20]]);
    assert!(dag.select_parents_for_template(&tips, 0).is_empty());
    assert!(dag.select_parents_for_template(&[hx(0x99, 9)], 4).is_empty(), "unknown candidates ignored");
}
