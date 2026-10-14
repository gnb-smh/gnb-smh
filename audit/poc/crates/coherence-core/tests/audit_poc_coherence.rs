//! AUDIT PoC (coherence-core). A passing test == the documented property holds.

use coherence_core::{
    check_spend, CommitmentTree, Note, NullifierSet, ShieldedTx, SpendError, SpendInput, SpendPublic,
    SpendWitness,
};

fn note(v: u64, tag: u8) -> Note {
    Note { v, pk_d: [tag; 32], rho: [tag ^ 0x11; 32], psi: [tag ^ 0x22; 32] }
}

/// COH-1 quantified: under the v1 statement ONE funded leaf of value V can be
/// spent K times in K separate transactions (witness-chosen `nk`), every spend
/// passes `check_spend`, and every nullifier is fresh for the nullifier set, so
/// K*V of value is created from V. Only `RejectAll` stands between this and
/// shielded inflation.
#[test]
fn poc_one_note_spent_k_times_creates_k_times_value() {
    const V: u64 = 1_000;
    const K: u8 = 8;
    let input = note(V, 7);
    let mut tree = CommitmentTree::new();
    let pos = tree.append(input.commitment());
    let anchor = tree.root();
    let path = tree.path(pos).unwrap();

    let mut spent = NullifierSet::new();
    let mut value_out: u128 = 0;
    for k in 0..K {
        let nk = [0xA0 ^ k; 32];
        let out = note(V, 0x80 | k);
        let public = SpendPublic {
            anchor,
            nullifiers: vec![input.nullifier(&nk, pos)],
            out_commitments: vec![out.commitment()],
            fee: 0,
        };
        let w = SpendWitness {
            inputs: vec![SpendInput { note: input.clone(), position: pos, path: path.clone(), nk }],
            outputs: vec![out],
        };
        assert_eq!(check_spend(&public, &w), Ok(()), "spend #{k} accepted");
        assert!(spent.insert(public.nullifiers[0]), "spend #{k}: nullifier is fresh");
        value_out += V as u128;
    }
    assert_eq!(value_out, V as u128 * K as u128);
}

/// Info: the statement has no transparent<->shielded value bridge. With no
/// inputs, only zero-value outputs balance, so the pool cannot be funded (and
/// `fee` cannot be paid out of nothing) under check_spend.
#[test]
fn poc_no_value_bridge_zero_input_spends_only_mint_zero() {
    let anchor = CommitmentTree::new().root();
    let zero = note(0, 1);
    let p = SpendPublic { anchor, nullifiers: vec![], out_commitments: vec![zero.commitment()], fee: 0 };
    let w = SpendWitness { inputs: vec![], outputs: vec![zero] };
    assert_eq!(check_spend(&p, &w), Ok(()));

    let one = note(1, 2);
    let p = SpendPublic { anchor, nullifiers: vec![], out_commitments: vec![one.commitment()], fee: 0 };
    let w = SpendWitness { inputs: vec![], outputs: vec![one] };
    assert!(matches!(check_spend(&p, &w), Err(SpendError::Unbalanced { .. })));
}

/// Info: `binding_sig` (and `proof`) are not part of `SpendPublic`, so nothing
/// the verifier checks covers `binding_sig`: it is unauthenticated, malleable
/// payload (committed only by the block merkle root once mined).
#[test]
fn poc_binding_sig_is_not_bound_by_public_inputs() {
    let a = ShieldedTx { anchor: [1; 32], nullifiers: vec![[2; 32]], outputs: vec![[3; 32]], fee: 4, proof: vec![5], binding_sig: vec![6] };
    let mut b = a.clone();
    b.binding_sig = vec![0xff; 64];
    let (pa, pb) = (a.public(), b.public());
    assert_eq!(pa.anchor, pb.anchor);
    assert_eq!(pa.nullifiers, pb.nullifiers);
    assert_eq!(pa.out_commitments, pb.out_commitments);
    assert_eq!(pa.fee, pb.fee);
}
