//! Hardening activation (audit DAG-3 / DAG-4 / DAG-7): below the activation
//! height the GhostDAG output must be BIT-IDENTICAL to the code that produced
//! the existing chain — blue sets, blue_score, blue_work, selected parent,
//! mergeset order and `blues_anticone_sizes` — so every stored `GhostdagData`
//! (and its integrity hash) stays valid.
//!
//! Two independent proofs:
//!
//! 1. `snapshot_matches_pre_change_code`: digests of every block's
//!    `canonical_encode` over 45 DAGs, captured by running this file's
//!    generators against the consensus code of commit 125e9e5 (before the
//!    change), are reproduced with the activation at `NEVER` and with the
//!    default (mainnet, `MAINNET_HARDENING_ACTIVATION_HEIGHT`) activation.
//! 2. `frozen_old_algorithm_matches_on_random_dags`: a verbatim copy of the old
//!    `add_block` path (O(past) mergeset, the old fast coloring without the
//!    k + 1 exit or skip pointers, old blue work) is compared block by block on
//!    hundreds of further random DAGs.
//!
//! Plus: a DAG reloaded from its stored data continues identically (the new
//! caches are rebuilt lazily), and with the activation in the middle of a DAG
//! every block whose whole past lies below it keeps its old data.

use std::collections::{HashMap, HashSet};

use gnb::consensus::{
    canonical_encode, BlockHash, GhostDAG, CORRECTED_COLORING_ACTIVATION_HEIGHT,
};
use gnb::core::activation::{self, NEVER};
use sha2::{Digest, Sha256};

// ── deterministic generators (DO NOT CHANGE: the snapshot depends on them) ──

struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self { Rng(seed ^ 0x9E37_79B9_7F4A_7C15 | 1) }
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

fn mix(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Hash whose lexicographic order is unrelated to insertion order, so hash
/// tie-breaks (selected parent, topological order) are exercised.
fn bh(tag: u8, i: u32) -> BlockHash {
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(&mix(((tag as u64) << 32) | i as u64).to_le_bytes());
    h[8..12].copy_from_slice(&i.to_be_bytes());
    h[12] = tag;
    h
}

type Spec = (BlockHash, Vec<BlockHash>, u64, u128);

struct Scenario {
    label: String,
    k: usize,
    genesis: BlockHash,
    specs: Vec<Spec>,
}

fn random_dag(tag: u8, n: u32, maxpar: usize, window: usize, deep_one_in: usize,
              max_work: u64, seed: u64) -> (BlockHash, Vec<Spec>) {
    let mut rng = Rng::new(seed);
    let g = bh(tag, 0);
    let mut pool = vec![g];
    let mut specs = Vec::new();
    for i in 1..=n {
        let np = 1 + rng.below(maxpar);
        let mut parents: Vec<BlockHash> = Vec::new();
        for _ in 0..np {
            let p = if deep_one_in > 0 && rng.below(deep_one_in) == 0 {
                pool[rng.below(pool.len())]
            } else {
                let w = pool.len().min(window);
                pool[pool.len() - w + rng.below(w)]
            };
            if !parents.contains(&p) { parents.push(p); }
        }
        let work = if max_work <= 1 { 1 } else { 1 + rng.below(max_work as usize) as u128 };
        let h = bh(tag, i);
        specs.push((h, parents, i as u64, work));
        pool.push(h);
    }
    (g, specs)
}

/// A selected chain of `len` blocks plus side chains forked at the given
/// depths, each merged back into the main chain a few blocks later.
fn side_chains(tag: u8, len: u32, forks: &[(u32, u32, u32)]) -> (BlockHash, Vec<Spec>) {
    let g = bh(tag, 0);
    let mut chain = vec![g];
    let mut specs = Vec::new();
    let mut id = 1u32;
    let mut pending: Vec<(u32, BlockHash)> = Vec::new(); // (merge_at, side_tip)
    for i in 1..=len {
        for &(fork_at, side_len, merge_after) in forks {
            if fork_at == i {
                let mut prev = chain[(fork_at - 1) as usize];
                for _ in 0..side_len {
                    let h = bh(tag.wrapping_add(1), id); id += 1;
                    specs.push((h, vec![prev], id as u64, 1000));
                    prev = h;
                }
                pending.push((i + merge_after, prev));
            }
        }
        let mut parents = vec![*chain.last().unwrap()];
        pending.retain(|(at, tip)| if *at == i { parents.push(*tip); false } else { true });
        let h = bh(tag, i);
        specs.push((h, parents, 10_000 + i as u64, 1000));
        chain.push(h);
    }
    (g, specs)
}

fn wide_layers(tag: u8, layers: u32, width: u32) -> (BlockHash, Vec<Spec>) {
    let g = bh(tag, 0);
    let mut prev = g;
    let mut specs = Vec::new();
    let mut id = 1u32;
    for _ in 0..layers {
        let mut sibs = Vec::new();
        for _ in 0..width {
            let s = bh(tag, id); id += 1;
            specs.push((s, vec![prev], id as u64, 1000));
            sibs.push(s);
        }
        let m = bh(tag, id); id += 1;
        specs.push((m, sibs, id as u64, 1000));
        prev = m;
    }
    (g, specs)
}

/// DAG-3 PoC shape: 5 diamonds vs an 11-block bare chain.
fn dag3_shape(tag: u8) -> (BlockHash, Vec<Spec>) {
    let g = bh(tag, 0);
    let mut specs = Vec::new();
    let mut prev = g;
    for i in 1..=5u32 {
        let (l, r, m) = (bh(tag, 100 + i), bh(tag, 200 + i), bh(tag, 300 + i));
        specs.push((l, vec![prev], i as u64, 1));
        specs.push((r, vec![prev], i as u64, 1));
        specs.push((m, vec![l, r], i as u64, 1));
        prev = m;
    }
    let mut c = g;
    for i in 1..=11u32 {
        let h = bh(tag, 400 + i);
        specs.push((h, vec![c], i as u64, 1));
        c = h;
    }
    (g, specs)
}

/// DAG-4 PoC shape: a side block under a 30-block chain, then merged.
fn dag4_shape(tag: u8) -> (BlockHash, Vec<Spec>) {
    let g = bh(tag, 0);
    let mut specs = Vec::new();
    let mut prev = g;
    for i in 1..=30u32 {
        let h = bh(tag, i);
        specs.push((h, vec![prev], i as u64, 1000));
        prev = h;
    }
    let side = bh(tag, 1000);
    specs.push((side, vec![g], 1, 1000));
    specs.push((bh(tag, 1001), vec![prev, side], 31, 1000));
    (g, specs)
}

fn scenarios() -> Vec<Scenario> {
    let mut out = Vec::new();
    let ks = [2usize, 3, 10];
    for s in 0..24u64 {
        let (g, specs) = random_dag(0x10 + s as u8, 160, 3, 16, 30, 4000, s);
        out.push(Scenario { label: format!("random-a-{s}"), k: ks[s as usize % 3], genesis: g, specs });
    }
    for s in 0..10u64 {
        let (g, specs) = random_dag(0x40 + s as u8, 120, 5, 8, 0, 1, 1000 + s);
        out.push(Scenario { label: format!("random-dense-{s}"), k: 10, genesis: g, specs });
    }
    for s in 0..6u64 {
        let (g, specs) = random_dag(0x60 + s as u8, 200, 2, 40, 12, 50, 2000 + s);
        out.push(Scenario { label: format!("random-deep-{s}"), k: 4, genesis: g, specs });
    }
    let (g, specs) = side_chains(0x80, 150, &[(10, 20, 25), (70, 35, 5), (140, 3, 2), (100, 12, 30)]);
    out.push(Scenario { label: "side-chains-k10".into(), k: 10, genesis: g, specs: specs.clone() });
    out.push(Scenario { label: "side-chains-k3".into(), k: 3, genesis: g, specs });
    let (g, specs) = wide_layers(0x90, 10, 15);
    out.push(Scenario { label: "wide-layers".into(), k: 10, genesis: g, specs });
    let (g, specs) = dag3_shape(0xA0);
    out.push(Scenario { label: "dag3".into(), k: 10, genesis: g, specs });
    let (g, specs) = dag4_shape(0xB0);
    out.push(Scenario { label: "dag4".into(), k: 10, genesis: g, specs });
    out
}

fn digest(dag: &GhostDAG, sc: &Scenario) -> String {
    let mut h = Sha256::new();
    let mut order = vec![sc.genesis];
    order.extend(sc.specs.iter().map(|s| s.0));
    for b in &order {
        h.update(b);
        h.update(canonical_encode(dag.get_block_data(b).expect("block present")));
    }
    h.update(dag.selected_tip().unwrap());
    hex::encode(h.finalize())
}

fn build(dag: &mut GhostDAG, genesis: BlockHash, specs: &[Spec]) {
    dag.add_genesis(genesis, 0);
    for (h, p, ts, w) in specs {
        dag.add_block(*h, p.clone(), *ts, *w)
            .unwrap_or_else(|e| panic!("add_block {}: {e}", hex::encode(&h[..4])));
    }
}

/// Captured from commit 125e9e5 (pre-change consensus code), `GhostDAG::with_k`.
const SNAPSHOT: &[(&str, &str)] = &[
    ("random-a-0", "82d16c4717658dfef1fbf99f20f9e0b4dd367c81a51d838ec291c1a6dddea77c"),
    ("random-a-1", "191b182d030d3e2f54031c582f0b7276147dc014f1ed843429495b24f3216513"),
    ("random-a-2", "4fe2d85f7d6d6835386a673c1a4d233158326c7cf4044ef1b8fb94f1ed12623b"),
    ("random-a-3", "20a31942243caa87e1802ccc57183388683cdf24dd2ed90279c583b749e795ae"),
    ("random-a-4", "e81cca524bba8ecefefec2dcd9dff501c7e826a65fc3af31acc5da0ef442007f"),
    ("random-a-5", "b2f1ea38189bab0fc20bd14d87879d02d6e115631c6f8eaa08b790c60bb4fc5f"),
    ("random-a-6", "c476b872abf6bda90e8312e774d5c267ae2ac2b05dfb644eb3bca340679fa40a"),
    ("random-a-7", "ab211c7bcc4370ca58ff41382ab0d247b022be5c8b462b6f8bbdeff87d1945d1"),
    ("random-a-8", "fda4a171f837d41a771df08f7d6267e6787e798fdb02a6dad57a4fdc72a3fa90"),
    ("random-a-9", "a0597649b639ba12036f98eeda72332abf2675fffd30690c79ed191c22b66c69"),
    ("random-a-10", "5c3c6d1593f79cb4c1cf80559930a674a224cae6f2acae92fe311fba32d2000b"),
    ("random-a-11", "f76544f8ebaaa040d0f8a14ed2466386f722b9b12bb088c336c49c144ec163bf"),
    ("random-a-12", "e73a3368c8d8a3af148793284211e955c1d91de2fbdc96526e2a5d9fc82b3c17"),
    ("random-a-13", "ac2bad4aedb1dd8d456963e3028e20d28fbd271d3d9d7c8e8d9fd75861eed503"),
    ("random-a-14", "95d7d8674c30df18f8a406482f702941f9dbf997582fdd64b35e0459aabcb603"),
    ("random-a-15", "322bcb87b23f3b5b82b0c07fa434407778f3478d85b1ba3ac1a22d246849366c"),
    ("random-a-16", "758832d2e430391e9c09d84e708358c22b2dc304b406d471b57d85759fba27e5"),
    ("random-a-17", "20f6095cc9af46f27933ea4d989935077e1143257b951910e5385702b7f13175"),
    ("random-a-18", "7329d602bef0b8990d164ecf23ed3dd901fb05afcb184ef8ac431f1fbd4773d2"),
    ("random-a-19", "ddb2555fc75fbaa135c354f9c896d458c7010b6e63c152fda6d8b365d701969e"),
    ("random-a-20", "34c7b8eba555bca8717233d7697c8f611904a121897eb065b9cc462f0ad4e958"),
    ("random-a-21", "0b9b3eaf11dcbde4d54b7cf5a869c4a155db60cbbddc0fe840174225048046a9"),
    ("random-a-22", "1ccb3de4ac60b8a32af758fc952615ec4eb727abcb424a37aa0a232c72dc6679"),
    ("random-a-23", "994f12f5c5fc8e233ce9d281a336b5a7ed32c852f2b159ed6f752511439c76a4"),
    ("random-dense-0", "8f61a499bf50a3fc781009206c98214c12623ba37bf320fc80912640dc639101"),
    ("random-dense-1", "ed122dd8140afa40ce88e6fd316e6e247df989a4e8d14eeb1ba2d0f38cb94854"),
    ("random-dense-2", "b40a3ba3177269903cc131cccace4dc9884cfd9d7aac8ca604121562269522e1"),
    ("random-dense-3", "29036157859104462e637545a9b0a25fb8bc7e3c229235beaad36f1f1555748b"),
    ("random-dense-4", "86ab8de03068b5f38fedc0b2942b446e1798ba1c92078ee968868f6628104ae0"),
    ("random-dense-5", "75ab5f2cfda8b0ca8a1bae4032272e738828a8b5d9cd2eb9670c4fc15db713c7"),
    ("random-dense-6", "58198ced8d130c44ee904323a7078e5b78a068918fa05763b1514aa6bb42ba60"),
    ("random-dense-7", "dde31f1e305077e7be027bc47e9ec42dc8f7d84c8e4f8adef67d9be319894789"),
    ("random-dense-8", "b1535b7cab844a662f73d1cc532e6d35966fe872d9ed5c0231397b6f86cfff3e"),
    ("random-dense-9", "fe368493138dd56061520b4961900de0b60db00dc083364b121ba2bbe388acd5"),
    ("random-deep-0", "2689ecc0e92d1f90218639d5f92159143033f2415c30eef507866ee87ec272bf"),
    ("random-deep-1", "8d653eeb1818b53a846a22d727dacdde9e8b0ce33a2fc64d5c5b934b55563ac8"),
    ("random-deep-2", "195a65762ef65e7c2d16f4aad494ed312699b8a71fcc3a2eab43a5e1a69e714a"),
    ("random-deep-3", "9a48eec64b1886f09cda1f5d9ec1f241b0a7870d022e261129b4b384fdf28417"),
    ("random-deep-4", "92b894a0983acc063f469f635fdc830c05b30383c4c8f816aa6536f2a51ac875"),
    ("random-deep-5", "999c6d10eb04aab879b1da805806d67e410ecbcbf5b25a7cad4fe80ba084bec7"),
    ("side-chains-k10", "e33336225236ada54a10f6806fd80cc8bd7193420b326f24ddb1ef9658f48524"),
    ("side-chains-k3", "f0865197c339d4a1b318d796016f7ad675af962aea0c0d8f7a16ff1098554b1c"),
    ("wide-layers", "b23dc62f84bd7f497ddde9a747c1e8667fd858bcb0de044d3b212cf8a9192883"),
    ("dag3", "fa5fa81912c52e927808fb21925af7fc2b35cd73fce214248874acd950d2bf7c"),
    ("dag4", "b7df8ba80f5696da3db5a84a079af1a77b2b47364a7e15d51f9717bf01d2147c"),
];

#[test]
fn snapshot_matches_pre_change_code() {
    let expected: HashMap<&str, &str> = SNAPSHOT.iter().copied().collect();
    let scenarios = scenarios();
    assert_eq!(scenarios.len(), SNAPSHOT.len());
    for sc in &scenarios {
        let want = expected[sc.label.as_str()];

        let mut never = GhostDAG::with_k_and_activation(sc.k, NEVER);
        build(&mut never, sc.genesis, &sc.specs);
        assert_eq!(digest(&never, sc), want, "[{}] activation = NEVER differs from the pre-change code", sc.label);

        // The default constructor (no chain id set in tests => mainnet height)
        // is the pre-activation regime for every height these DAGs reach.
        let mut default = GhostDAG::with_k(sc.k);
        assert_eq!(default.hardening_activation_height(), activation::MAINNET_HARDENING_ACTIVATION_HEIGHT);
        build(&mut default, sc.genesis, &sc.specs);
        assert_eq!(digest(&default, sc), want, "[{}] default constructor differs from the pre-change code", sc.label);
    }
}

// ── frozen copy of the pre-change add_block path ────────────────────────────

/// Verbatim port of the consensus code of commit 125e9e5, restricted to the
/// path every GnB block took (`CORRECTED_COLORING_ACTIVATION_HEIGHT = 0`, so
/// `effective_coloring` was always `Fast`). Uses its own reachability index,
/// exactly like the old `GhostDAG`.
mod frozen {
    use std::collections::{HashMap, HashSet, VecDeque};

    use gnb::consensus::reachability::ReachabilityStore;
    use gnb::consensus::{BlockHash, DagStore, GhostdagData};

    pub struct OldDag {
        pub k: usize,
        pub store: DagStore,
        reach: ReachabilityStore,
    }

    fn compute_past(store: &DagStore, b: &BlockHash) -> HashSet<BlockHash> {
        let mut past = HashSet::new();
        let mut queue = VecDeque::new();
        if let Some(data) = store.get(b) {
            for p in &data.parents { queue.push_back(*p); }
        }
        while let Some(h) = queue.pop_front() {
            if past.insert(h) {
                if let Some(data) = store.get(&h) {
                    for p in &data.parents {
                        if !past.contains(p) { queue.push_back(*p); }
                    }
                }
            }
        }
        past
    }

    fn compute_mergeset(store: &DagStore, b_parents: &[BlockHash], selected_parent: &BlockHash) -> Vec<BlockHash> {
        let sp_past = compute_past(store, selected_parent);
        let mut mergeset_set: HashSet<BlockHash> = HashSet::new();
        for parent in b_parents {
            if parent == selected_parent { continue; }
            let mut queue = VecDeque::new();
            queue.push_back(*parent);
            while let Some(h) = queue.pop_front() {
                if !sp_past.contains(&h) && h != *selected_parent && mergeset_set.insert(h) {
                    if let Some(data) = store.get(&h) {
                        for p in &data.parents {
                            if !sp_past.contains(p) && p != selected_parent { queue.push_back(*p); }
                        }
                    }
                }
            }
        }
        topological_sort(store, mergeset_set.into_iter().collect())
    }

    fn topological_sort(store: &DagStore, blocks: Vec<BlockHash>) -> Vec<BlockHash> {
        let set: HashSet<BlockHash> = blocks.iter().cloned().collect();
        let mut in_degree: HashMap<BlockHash, usize> = HashMap::new();
        let mut reverse_deps: HashMap<BlockHash, Vec<BlockHash>> = HashMap::new();
        for &b in &blocks {
            in_degree.entry(b).or_insert(0);
            if let Some(data) = store.get(&b) {
                for p in &data.parents {
                    if set.contains(p) {
                        *in_degree.entry(b).or_insert(0) += 1;
                        reverse_deps.entry(*p).or_default().push(b);
                    }
                }
            }
        }
        let mut result = Vec::with_capacity(blocks.len());
        let mut queue: VecDeque<BlockHash> = in_degree.iter().filter(|(_, &d)| d == 0).map(|(&h, _)| h).collect();
        let mut sorted_start: Vec<BlockHash> = queue.drain(..).collect();
        sorted_start.sort_unstable();
        queue.extend(sorted_start);
        while let Some(b) = queue.pop_front() {
            result.push(b);
            if let Some(children) = reverse_deps.get(&b) {
                let mut next: Vec<BlockHash> = children.iter()
                    .filter_map(|c| {
                        let deg = in_degree.get_mut(c)?;
                        *deg -= 1;
                        if *deg == 0 { Some(*c) } else { None }
                    })
                    .collect();
                next.sort_unstable();
                queue.extend(next);
            }
        }
        result
    }

    impl OldDag {
        pub fn new(k: usize) -> Self {
            OldDag { k, store: DagStore::new(), reach: ReachabilityStore::new() }
        }

        pub fn add_genesis(&mut self, hash: BlockHash, timestamp: u64) {
            let mut data = GhostdagData::genesis();
            data.timestamp = timestamp;
            self.store.genesis = Some(hash);
            self.reach.add_genesis(hash);
            self.store.insert(hash, data);
        }

        pub fn add_block(&mut self, hash: BlockHash, parents: Vec<BlockHash>, timestamp: u64, work: u128) {
            let selected_parent = self.select_parent(&parents);
            let sp_data = self.store.get(&selected_parent).cloned().expect("selected parent present");
            let height = sp_data.height + 1;
            let mergeset = compute_mergeset(&self.store, &parents, &selected_parent);
            let (mergeset_blues, mergeset_reds, blues_anticone_sizes) =
                self.classify_mergeset_fast(&mergeset, &selected_parent);
            let blue_score = sp_data.blue_score + mergeset_blues.len() as u64 + 1;
            let blue_work = sp_data.blue_work + work;
            let data = GhostdagData {
                blue_score,
                blue_work,
                selected_parent: Some(selected_parent),
                mergeset_blues,
                mergeset_reds,
                blues_anticone_sizes,
                parents,
                height,
                timestamp,
            };
            self.reach.add_block(hash, &selected_parent, &mergeset);
            self.store.insert(hash, data);
        }

        fn select_parent(&self, parents: &[BlockHash]) -> BlockHash {
            *parents.iter().max_by(|a, b| {
                let da = self.store.get(*a);
                let db = self.store.get(*b);
                let work_a = da.map(|d| d.blue_work).unwrap_or(0);
                let work_b = db.map(|d| d.blue_work).unwrap_or(0);
                let score_a = da.map(|d| d.blue_score).unwrap_or(0);
                let score_b = db.map(|d| d.blue_score).unwrap_or(0);
                work_a.cmp(&work_b).then(score_a.cmp(&score_b)).then(a.cmp(b))
            }).expect("parents non-empty")
        }

        fn classify_mergeset_fast(
            &self,
            mergeset: &[BlockHash],
            selected_parent: &BlockHash,
        ) -> (Vec<BlockHash>, Vec<BlockHash>, HashMap<BlockHash, usize>) {
            let mut cur_mergeset_blues: Vec<BlockHash> = Vec::with_capacity(mergeset.len() + 1);
            let mut cur_blues_anticone_sizes: HashMap<BlockHash, usize> = HashMap::new();
            cur_mergeset_blues.push(*selected_parent);
            cur_blues_anticone_sizes.insert(*selected_parent, 0);
            let mut mergeset_reds: Vec<BlockHash> = Vec::new();
            for &candidate in mergeset {
                let anticone_blues =
                    self.candidate_anticone_blues(selected_parent, &cur_mergeset_blues, &candidate);
                if anticone_blues.len() > self.k {
                    mergeset_reds.push(candidate);
                    continue;
                }
                let violates_b = anticone_blues
                    .iter()
                    .any(|b| *cur_blues_anticone_sizes.get(b).unwrap_or(&0) + 1 > self.k);
                if violates_b {
                    mergeset_reds.push(candidate);
                    continue;
                }
                cur_mergeset_blues.push(candidate);
                cur_blues_anticone_sizes.insert(candidate, anticone_blues.len());
                for b in &anticone_blues {
                    *cur_blues_anticone_sizes.entry(*b).or_insert(0) += 1;
                }
            }
            let mergeset_blues: Vec<BlockHash> =
                cur_mergeset_blues.into_iter().filter(|b| b != selected_parent).collect();
            (mergeset_blues, mergeset_reds, cur_blues_anticone_sizes)
        }

        fn candidate_anticone_blues(
            &self,
            selected_parent: &BlockHash,
            cur_mergeset_blues: &[BlockHash],
            candidate: &BlockHash,
        ) -> Vec<BlockHash> {
            let mut out: Vec<BlockHash> = Vec::new();
            for &blue in cur_mergeset_blues {
                if !self.reach.is_dag_ancestor(&blue, candidate) && !self.reach.is_dag_ancestor(candidate, &blue) {
                    out.push(blue);
                }
            }
            let mut chain = Some(*selected_parent);
            while let Some(h) = chain {
                if self.reach.is_dag_ancestor(&h, candidate) { break; }
                let d = match self.store.get(&h) { Some(d) => d, None => break };
                for &blue in &d.mergeset_blues {
                    if !self.reach.is_dag_ancestor(&blue, candidate) && !self.reach.is_dag_ancestor(candidate, &blue) {
                        out.push(blue);
                    }
                }
                chain = d.selected_parent;
            }
            out
        }
    }
}

#[test]
fn frozen_old_algorithm_matches_on_random_dags() {
    // The frozen copy reproduces the old live path only while the old
    // corrected-coloring gate stayed at 0 (Fast coloring for every height).
    assert_eq!(CORRECTED_COLORING_ACTIVATION_HEIGHT, 0);
    let mut cases: Vec<(String, usize, BlockHash, Vec<Spec>)> = Vec::new();
    for s in 0..60u64 {
        let k = [1usize, 2, 3, 5, 10][s as usize % 5];
        let (g, specs) = random_dag(0xC0, 140, 1 + (s as usize % 4), 6 + (s as usize % 20), [0, 8, 25][s as usize % 3], [1, 7, 5000][s as usize % 3], 7_000 + s);
        cases.push((format!("frozen-random-{s}"), k, g, specs));
    }
    for s in 0..8u64 {
        let (g, specs) = random_dag(0xD0, 400, 3, 30, 15, 100, 9_000 + s);
        cases.push((format!("frozen-large-{s}"), 10, g, specs));
    }
    let (g, specs) = side_chains(0xE0, 300, &[(5, 40, 50), (60, 60, 3), (200, 10, 80), (250, 25, 1)]);
    cases.push(("frozen-side-chains".into(), 10, g, specs));

    for (label, k, g, specs) in &cases {
        let mut old = frozen::OldDag::new(*k);
        old.add_genesis(*g, 0);
        let mut new = GhostDAG::with_k_and_activation(*k, NEVER);
        new.add_genesis(*g, 0);
        for (h, p, ts, w) in specs {
            old.add_block(*h, p.clone(), *ts, *w);
            let got = new.add_block(*h, p.clone(), *ts, *w).expect("pre-activation accepts every block");
            let want = old.store.get(h).unwrap();
            assert_eq!(
                canonical_encode(&got), canonical_encode(want),
                "[{label}] block {} differs from the frozen pre-change algorithm",
                hex::encode(&h[..4])
            );
        }
        let old_tip = old.store.tips.iter().max_by(|a, b| {
            let (da, db) = (old.store.get(a).unwrap(), old.store.get(b).unwrap());
            da.blue_work.cmp(&db.blue_work).then(da.blue_score.cmp(&db.blue_score)).then(a.cmp(b))
        }).copied();
        assert_eq!(new.selected_tip(), old_tip, "[{label}] selected tip differs");
    }
}

/// The non-consensus caches (`merge_skip`, `block_work`) start empty after a
/// reload from stored data; continuing the DAG must give the same data as an
/// uninterrupted run, in both regimes.
#[test]
fn reload_from_stored_data_continues_identically() {
    for (activation_height, k) in [(NEVER, 3usize), (0, 3), (NEVER, 10), (0, 10), (60, 4)] {
        let (g, specs) = random_dag(0xF0, 200, 3, 12, 20, 300, 31 + k as u64);
        let (first, rest) = specs.split_at(120);
        let mut full = GhostDAG::with_k_and_activation(k, activation_height);
        build(&mut full, g, &specs);

        let mut part = GhostDAG::with_k_and_activation(k, activation_height);
        build(&mut part, g, first);
        let entries: Vec<_> = part.store.data.iter().map(|(h, d)| (*h, d.clone())).collect();
        let mut reloaded = GhostDAG::with_k_and_activation(k, activation_height);
        reloaded.load_persisted(entries);
        reloaded.rebuild_reachability_from_store().expect("rebuild index");
        for (h, p, ts, w) in rest {
            let got = reloaded.add_block(*h, p.clone(), *ts, *w).expect("block accepted after reload");
            assert_eq!(
                canonical_encode(&got),
                canonical_encode(full.get_block_data(h).unwrap()),
                "activation {activation_height}, k {k}: block {} differs after reload",
                hex::encode(&h[..4])
            );
        }
    }
}

/// With the activation in the middle of a DAG, every block whose whole past
/// (itself included) is below the activation height keeps its old data.
#[test]
fn blocks_below_activation_keep_old_data_in_a_mixed_dag() {
    for s in 0..12u64 {
        let k = [2usize, 3, 10][s as usize % 3];
        let (g, specs) = random_dag(0xF8, 160, 3, 10, 25, 900, 500 + s);
        let mut never = GhostDAG::with_k_and_activation(k, NEVER);
        build(&mut never, g, &specs);
        // Somewhere between 2/7 and 5/7 of the DAG's height range.
        let max_height = specs.iter().map(|(h, ..)| never.get_block_data(h).unwrap().height).max().unwrap();
        let activation_height = (max_height * (2 + s % 4) / 7).max(1);
        let mut mixed = GhostDAG::with_k_and_activation(k, activation_height);
        build(&mut mixed, g, &specs);

        let mut all_below: HashSet<BlockHash> = HashSet::from([g]);
        let (mut same, mut post) = (0, 0);
        for (h, p, ..) in &specs {
            let d = never.get_block_data(h).unwrap();
            if d.height < activation_height && p.iter().all(|x| all_below.contains(x)) {
                all_below.insert(*h);
                assert_eq!(
                    canonical_encode(mixed.get_block_data(h).unwrap()),
                    canonical_encode(d),
                    "seed {s}: block {} below activation changed",
                    hex::encode(&h[..4])
                );
                same += 1;
            } else {
                post += 1;
            }
        }
        assert!(same > 10 && post > 10, "seed {s}: both regimes exercised ({same} / {post})");
    }
}
