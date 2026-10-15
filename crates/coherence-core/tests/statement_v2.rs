//! Spend statement v2 (audit COH-1): golden vectors for the byte-exact rules
//! in `docs/CONSENSUS.md` ("Shielded spend statement v2"), and property tests
//! of spending authority and nullifier uniqueness.

use coherence_core::{
    check_spend, derive_ak, derive_nk, derive_pk_d, pk_d_from_sk, CommitmentTree, Note,
    SpendError, SpendInput, SpendPublic, SpendWitness, TREE_DEPTH,
};
use proptest::prelude::*;

fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ── Golden vectors ───────────────────────────────────────────────────────────

/// `sk = 00 01 02 … 1f`, note `v = 1000`, `rho = 0x11 × 32`,
/// `psi = 0x22 × 32`, `pk_d` derived from `sk`, at position 5.
#[test]
fn golden_vectors_v2() {
    let sk: [u8; 32] = core::array::from_fn(|i| i as u8);
    let ak = derive_ak(&sk);
    let nk = derive_nk(&sk);
    let pk_d = derive_pk_d(&ak, &nk);
    assert_eq!(pk_d, pk_d_from_sk(&sk));
    let note = Note { v: 1000, pk_d, rho: [0x11; 32], psi: [0x22; 32] };
    let cm = note.commitment();
    let nf = note.nullifier(&nk, 5);

    assert_eq!(hex32(&ak), GOLDEN_AK, "ak");
    assert_eq!(hex32(&nk), GOLDEN_NK, "nk");
    assert_eq!(hex32(&pk_d), GOLDEN_PK_D, "pk_d");
    assert_eq!(hex32(&cm), GOLDEN_CM, "cm");
    assert_eq!(hex32(&nf), GOLDEN_NF, "nf");
    // Empty commitment-tree root (the genesis anchor).
    assert_eq!(hex32(&CommitmentTree::new().root()), GOLDEN_EMPTY_ROOT, "empty root");
}

const GOLDEN_AK: &str = "1d64f855d802d8d73b185b6c3c8666fce5ed176d3d2e1b480fa5f8620d981223";
const GOLDEN_NK: &str = "0004a2dfbb1a21b7ef2584349aa057e6980430a6bac9a0124159aa2f6ffa738d";
const GOLDEN_PK_D: &str = "d9a13fe370b6169dd975132432296e614e31902be55d0c542b606c3aaa20b551";
const GOLDEN_CM: &str = "ca6218f92e0f20ffb2e285a05af2e33efcc5f576e48989dd6cec2dd707a70a6f";
const GOLDEN_NF: &str = "f7c0d16ea5c3034bbf561e57da5a31da7080309bb1a922072106af8a6abc51ce";
const GOLDEN_EMPTY_ROOT: &str = "91225423fd45e8d61ce70c068f075176eacdcebf5d0df94fdb80a1b4aa5d251a";

// ── Properties ───────────────────────────────────────────────────────────────

/// A small tree with `filler` random leaves around the spent note at `pos`.
fn tree_with(note: &Note, pos: usize, filler: &[[u8; 32]]) -> (CommitmentTree, u64) {
    let mut t = CommitmentTree::new();
    for f in &filler[..pos.min(filler.len())] {
        t.append(*f);
    }
    let p = t.append(note.commitment());
    for f in &filler[pos.min(filler.len())..] {
        t.append(*f);
    }
    (t, p)
}

fn spend_with(
    tree: &CommitmentTree,
    note: &Note,
    pos: u64,
    witness_sk: [u8; 32],
    public_nf: [u8; 32],
    out_v: u64,
    fee: u64,
) -> (SpendPublic, SpendWitness) {
    let out = Note { v: out_v, pk_d: [0xee; 32], rho: [1; 32], psi: [2; 32] };
    (
        SpendPublic { anchor: tree.root(), nullifiers: vec![public_nf], out_commitments: vec![out.commitment()], fee },
        SpendWitness {
            inputs: vec![SpendInput { note: note.clone(), position: pos, path: tree.path(pos).unwrap(), sk: witness_sk }],
            outputs: vec![out],
        },
    )
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, .. ProptestConfig::default() })]

    /// The owner's spend verifies and publishes exactly the derived nullifier.
    #[test]
    fn owner_spend_verifies(
        sk in any::<[u8; 32]>(), v in 0u64..=u64::MAX / 2, rho in any::<[u8; 32]>(),
        psi in any::<[u8; 32]>(), filler in proptest::collection::vec(any::<[u8; 32]>(), 0..6),
        pos in 0usize..6, fee_part in 0u64..=1000,
    ) {
        let note = Note { v, pk_d: pk_d_from_sk(&sk), rho, psi };
        let (tree, p) = tree_with(&note, pos, &filler);
        let fee = fee_part.min(v);
        let nf = note.nullifier(&derive_nk(&sk), p);
        let (public, witness) = spend_with(&tree, &note, p, sk, nf, v - fee, fee);
        prop_assert_eq!(check_spend(&public, &witness), Ok(()));
    }

    /// Any other witness key is refused, whatever nullifier it publishes —
    /// in particular the v1 attack (a free key and its own nullifier).
    #[test]
    fn any_other_key_is_unauthorized(
        sk in any::<[u8; 32]>(), other in any::<[u8; 32]>(), rho in any::<[u8; 32]>(),
        use_own_nf in any::<bool>(),
    ) {
        prop_assume!(sk != other);
        let note = Note { v: 1000, pk_d: pk_d_from_sk(&sk), rho, psi: [9; 32] };
        let (tree, p) = tree_with(&note, 0, &[]);
        let nf = if use_own_nf { note.nullifier(&derive_nk(&other), p) } else { note.nullifier(&derive_nk(&sk), p) };
        let (public, witness) = spend_with(&tree, &note, p, other, nf, 1000, 0);
        prop_assert_eq!(check_spend(&public, &witness), Err(SpendError::Unauthorized(0)));
    }

    /// One note, one nullifier: among a set of candidate witness keys, every
    /// accepted spend of the same leaf publishes the same nullifier, and only
    /// the owner's key is accepted.
    #[test]
    fn accepted_spends_of_one_leaf_share_one_nullifier(
        sk in any::<[u8; 32]>(), candidates in proptest::collection::vec(any::<[u8; 32]>(), 1..6),
        pos in 0usize..4,
    ) {
        let note = Note { v: 77, pk_d: pk_d_from_sk(&sk), rho: [3; 32], psi: [4; 32] };
        let filler: Vec<[u8; 32]> = (0..4u8).map(|i| [i; 32]).collect();
        let (tree, p) = tree_with(&note, pos, &filler);
        let mut keys = candidates.clone();
        keys.push(sk);
        let mut accepted = Vec::new();
        for k in keys {
            let nf = note.nullifier(&derive_nk(&k), p);
            let (public, witness) = spend_with(&tree, &note, p, k, nf, 77, 0);
            if check_spend(&public, &witness).is_ok() {
                prop_assert_eq!(k, sk);
                accepted.push(nf);
            }
        }
        prop_assert!(!accepted.is_empty());
        prop_assert!(accepted.iter().all(|nf| *nf == accepted[0]));
    }

    /// Nullifiers are distinct across positions and across notes, and differ
    /// from the commitment (domain separation).
    #[test]
    fn nullifiers_bind_position_and_note(
        sk in any::<[u8; 32]>(), a in 0u64..(1 << TREE_DEPTH), b in 0u64..(1 << TREE_DEPTH),
        rho1 in any::<[u8; 32]>(), rho2 in any::<[u8; 32]>(),
    ) {
        let nk = derive_nk(&sk);
        let n1 = Note { v: 1, pk_d: pk_d_from_sk(&sk), rho: rho1, psi: [0; 32] };
        let n2 = Note { v: 1, pk_d: pk_d_from_sk(&sk), rho: rho2, psi: [0; 32] };
        if a != b { prop_assert_ne!(n1.nullifier(&nk, a), n1.nullifier(&nk, b)); }
        if rho1 != rho2 { prop_assert_ne!(n1.nullifier(&nk, a), n2.nullifier(&nk, a)); }
        prop_assert_ne!(n1.nullifier(&nk, a), n1.commitment());
    }
}
