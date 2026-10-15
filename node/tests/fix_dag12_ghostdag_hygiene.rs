//! Audit DAG-12 (1)-(3) residuals: `GhostDAG::is_blue` answers exactly
//! "is this block in the blue set of the selected tip" (the selected chain
//! and every mergeset blue on it, at any depth), and the dead `is_final`
//! (a blue-score gap compared with a height constant) is gone.

use std::collections::HashSet;

use gnb::consensus::{BlockHash, GhostDAG};
use gnb::core::activation::NEVER;

fn hx(tag: u8, i: u64) -> BlockHash {
    let mut h = [0u8; 32];
    h[0] = tag;
    h[1..9].copy_from_slice(&i.to_be_bytes());
    h
}

/// blue(B) ∪ {B} by definition from the stored data:
/// blue(B) = blue(sp) ∪ {sp} ∪ mergeset_blues(B).
fn blue_closure(dag: &GhostDAG, tip: &BlockHash) -> HashSet<BlockHash> {
    let mut out = HashSet::new();
    let mut cur = Some(*tip);
    while let Some(h) = cur {
        out.insert(h);
        let d = dag.get_block_data(&h).unwrap();
        out.extend(d.mergeset_blues.iter().copied());
        cur = d.selected_parent;
    }
    out
}

struct Rng(u64);
impl Rng {
    fn below(&mut self, n: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 % n as u64) as usize
    }
}

#[test]
fn is_blue_is_the_blue_set_of_the_selected_tip_on_random_dags() {
    for (seed, act) in [(1u64, 0u64), (2, NEVER), (3, 0), (4, 40)] {
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let mut dag = GhostDAG::with_k_and_activation(4, act);
        let g = hx(0xEE, 0);
        dag.add_genesis(g, 0);
        let mut pool = vec![g];
        for i in 1..=160u64 {
            let mut parents = Vec::new();
            for _ in 0..1 + rng.below(4) {
                let w = pool.len().min(12);
                let p = pool[pool.len() - w + rng.below(w)];
                if !parents.contains(&p) {
                    parents.push(p);
                }
            }
            let h = hx(0xA0, i);
            if dag.add_block(h, parents, i, 1 + rng.below(5) as u128).is_ok() {
                pool.push(h);
            }
        }
        let tip = dag.selected_tip().unwrap();
        let blue = blue_closure(&dag, &tip);
        assert!(blue.len() > dag.selected_chain().len(), "seed {seed}: the DAG merges blues");
        assert!(blue.len() < pool.len(), "seed {seed}: the DAG has reds or unmerged tips");
        for h in &pool {
            assert_eq!(dag.is_blue(h), blue.contains(h), "seed {seed}: is_blue({})", hex::encode(&h[..9]));
        }
        assert!(!dag.is_blue(&hx(0xFF, 1)), "unknown block");
    }
}

/// The old `is_blue` walked at most k * 100 = 1,000 selected-chain blocks
/// (the legacy `past_blue_set` bound) and never counted the selected chain
/// itself: a selected-chain block and a blue merged more than 1,000 chain
/// blocks below the tip both read as not blue.
#[test]
fn is_blue_reaches_any_depth_and_counts_the_selected_chain() {
    let mut dag = GhostDAG::with_k_and_activation(10, 0);
    let g = hx(0xEE, 0);
    dag.add_genesis(g, 0);
    let side = hx(0x5E, 1);
    dag.add_block(hx(0xC0, 1), vec![g], 1, 1).unwrap();
    dag.add_block(side, vec![g], 1, 1).unwrap();
    let mut prev = hx(0xC0, 1);
    for i in 2..=1_100u64 {
        let h = hx(0xC0, i);
        let parents = if i == 2 { vec![prev, side] } else { vec![prev] };
        dag.add_block(h, parents, i, 1).unwrap();
        prev = h;
    }
    assert_eq!(dag.selected_tip(), Some(prev));
    let d2 = dag.get_block_data(&hx(0xC0, 2)).unwrap();
    assert_eq!(d2.mergeset_blues, vec![side], "the side block is merged blue at chain depth 1,098");
    assert!(dag.is_blue(&side), "a blue merged 1,098 chain blocks below the tip");
    assert!(dag.is_blue(&hx(0xC0, 500)), "a selected-chain block is blue");
    assert!(dag.is_blue(&prev), "the selected tip is in the blue set");
    assert!(dag.is_blue(&g), "the genesis is on the selected chain");
}
