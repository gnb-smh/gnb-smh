//! The incremental commitment tree (audit COH-2: no `O(n)` root per append)
//! must produce exactly the roots and paths of the original full
//! recomputation, which is reproduced here as the reference.

use coherence_core::{verify_path, CommitmentTree, TREE_DEPTH};
use proptest::prelude::*;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

const DOM_MT: &[u8] = b"gnb:coherence:mt:v1";

fn shake(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Shake256::default();
    for p in parts {
        h.update(p);
    }
    let mut out = [0u8; 32];
    h.finalize_xof().read(&mut out);
    out
}

fn parent(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    shake(&[DOM_MT, l, r])
}

fn empty_roots() -> Vec<[u8; 32]> {
    let mut e = vec![shake(&[DOM_MT, b"empty-leaf"])];
    for d in 1..=TREE_DEPTH {
        let prev = e[d - 1];
        e.push(parent(&prev, &prev));
    }
    e
}

/// The pre-COH-2 implementation: rehash every level from the leaves.
fn naive_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    let empty = empty_roots();
    let mut level = leaves.to_vec();
    for d in 0..TREE_DEPTH {
        let mut next: Vec<[u8; 32]> =
            level.chunks(2).map(|p| parent(&p[0], p.get(1).unwrap_or(&empty[d]))).collect();
        if next.is_empty() {
            next.push(empty[d + 1]);
        }
        level = next;
    }
    level[0]
}

fn naive_path(leaves: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
    let empty = empty_roots();
    let mut level = leaves.to_vec();
    let mut idx = index;
    let mut path = Vec::new();
    for d in 0..TREE_DEPTH {
        path.push(*level.get(idx ^ 1).unwrap_or(&empty[d]));
        let mut next: Vec<[u8; 32]> =
            level.chunks(2).map(|p| parent(&p[0], p.get(1).unwrap_or(&empty[d]))).collect();
        if next.is_empty() {
            next.push(empty[d + 1]);
        }
        level = next;
        idx /= 2;
    }
    path
}

#[test]
fn empty_tree_matches_reference() {
    assert_eq!(CommitmentTree::new().root(), naive_root(&[]));
    assert_eq!(CommitmentTree::from_leaves(vec![]).root(), naive_root(&[]));
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, .. ProptestConfig::default() })]

    /// Every prefix root, every path, and the bulk rebuild agree with the
    /// reference.
    #[test]
    fn incremental_matches_reference(leaves in proptest::collection::vec(any::<[u8; 32]>(), 0..40)) {
        let mut t = CommitmentTree::new();
        for (i, cm) in leaves.iter().enumerate() {
            prop_assert_eq!(t.append(*cm), i as u64);
            prop_assert_eq!(t.root(), naive_root(&leaves[..=i]));
        }
        prop_assert_eq!(t.leaves(), leaves.as_slice());
        prop_assert_eq!(&CommitmentTree::from_leaves(leaves.clone()), &t);
        for i in 0..leaves.len() {
            let path = t.path(i as u64).unwrap();
            prop_assert_eq!(&path, &naive_path(&leaves, i));
            prop_assert!(verify_path(&leaves[i], i as u64, &path, &t.root()));
        }
        prop_assert!(t.path(leaves.len() as u64).is_none());
    }

    /// Truncation restores the exact earlier tree (reorg undo), and appending
    /// again afterwards is indistinguishable from never having truncated.
    #[test]
    fn truncate_is_an_exact_inverse(
        leaves in proptest::collection::vec(any::<[u8; 32]>(), 1..40),
        cut in 0usize..40,
        extra in proptest::collection::vec(any::<[u8; 32]>(), 0..10),
    ) {
        let cut = cut.min(leaves.len());
        let mut t = CommitmentTree::from_leaves(leaves.clone());
        t.truncate(cut);
        prop_assert_eq!(&t, &CommitmentTree::from_leaves(leaves[..cut].to_vec()));
        prop_assert_eq!(t.root(), naive_root(&leaves[..cut]));
        for cm in &extra {
            t.append(*cm);
        }
        let mut all = leaves[..cut].to_vec();
        all.extend_from_slice(&extra);
        prop_assert_eq!(&t, &CommitmentTree::from_leaves(all.clone()));
        prop_assert_eq!(t.root(), naive_root(&all));
    }
}
