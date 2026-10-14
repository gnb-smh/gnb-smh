//! Regression tests for audit COH-1 (internal CR-01): the spend statement must
//! bind spending authority.
//!
//! Under statement v1 the nullifier key was a free witness, so whoever held a
//! note's plaintext could spend it, and ONE funded leaf of value V verified as
//! K separate spends with K fresh nullifiers (the audit's proof of concept:
//! 8 spends of one 1,000-value note, 8,000 value out of 1,000 in). Statement
//! v2 (`coherence_core::SPEND_STATEMENT_VERSION`) derives `pk_d` and the
//! nullifier key from the witness spending key, so these tests now assert
//! that the attack FAILS.

use coherence_core::{
    check_spend, derive_ak, derive_nk, derive_pk_d, pk_d_from_sk, statement_binds_authority,
    CommitmentTree, Note, NullifierSet, SpendError, SpendInput, SpendPublic, SpendWitness,
    SPEND_STATEMENT_VERSION,
};

const OWNER_SK: [u8; 32] = [0x5a; 32];

/// A note owned by `sk` (its `pk_d` derives from `sk`).
fn owned_note(value: u64, sk: &[u8; 32], tag: u8) -> Note {
    Note { v: value, pk_d: pk_d_from_sk(sk), rho: [tag; 32], psi: [tag ^ 0x22; 32] }
}

/// One funded leaf and its anchor/path.
fn funded(input: &Note) -> (CommitmentTree, u64, Vec<[u8; 32]>) {
    let mut tree = CommitmentTree::new();
    let position = tree.append(input.commitment());
    let path = tree.path(position).unwrap();
    (tree, position, path)
}

/// A one-input, one-output spend of `input` with witness key `sk`, publishing
/// the nullifier derived under `nk_for_public`.
fn spend(
    tree: &CommitmentTree,
    input: &Note,
    position: u64,
    path: &[[u8; 32]],
    sk: [u8; 32],
    nk_for_public: [u8; 32],
    output: Note,
) -> (SpendPublic, SpendWitness) {
    let public = SpendPublic {
        anchor: tree.root(),
        nullifiers: vec![input.nullifier(&nk_for_public, position)],
        out_commitments: vec![output.commitment()],
        fee: 0,
    };
    let witness = SpendWitness {
        inputs: vec![SpendInput { note: input.clone(), position, path: path.to_vec(), sk }],
        outputs: vec![output],
    };
    (public, witness)
}

#[test]
fn statement_version_binds_authority() {
    assert_eq!(SPEND_STATEMENT_VERSION, 2);
    assert!(statement_binds_authority(SPEND_STATEMENT_VERSION));
    assert!(!statement_binds_authority(1), "v1 never binds authority");
}

/// THE audit PoC, replayed: one funded 1,000-value leaf, 8 attempted spends
/// under 8 attacker-chosen keys. Every one is refused, nothing enters the
/// nullifier set, and no value is created.
#[test]
fn attack_eight_spends_of_one_note_now_fails() {
    const V: u64 = 1_000;
    const K: u8 = 8;
    let input = owned_note(V, &OWNER_SK, 7);
    let (tree, pos, path) = funded(&input);

    let mut spent = NullifierSet::new();
    let mut value_out: u128 = 0;
    for k in 0..K {
        let attacker_sk = [0xA0 ^ k; 32];
        assert_ne!(attacker_sk, OWNER_SK);
        // The v1 attack: publish a nullifier under a freely chosen key.
        let (public, witness) =
            spend(&tree, &input, pos, &path, attacker_sk, derive_nk(&attacker_sk), owned_note(V, &[0x80 | k; 32], 0x80 | k));
        let verdict = check_spend(&public, &witness);
        assert_eq!(verdict, Err(SpendError::Unauthorized(0)), "spend #{k} must be refused");
        if verdict.is_ok() {
            assert!(spent.insert(public.nullifiers[0]));
            value_out += V as u128;
        }
    }
    assert_eq!(value_out, 0, "no value is created from the note");
    assert!(spent.is_empty());

    // The owner spends it exactly once: a second owner spend (different
    // outputs) derives the SAME nullifier, which the nullifier set refuses.
    let (first, w1) = spend(&tree, &input, pos, &path, OWNER_SK, derive_nk(&OWNER_SK), owned_note(V, &[1; 32], 1));
    let (second, w2) = spend(&tree, &input, pos, &path, OWNER_SK, derive_nk(&OWNER_SK), owned_note(V, &[2; 32], 2));
    assert_eq!(check_spend(&first, &w1), Ok(()));
    assert_eq!(check_spend(&second, &w2), Ok(()));
    assert_eq!(first.nullifiers, second.nullifiers, "one note, one nullifier");
    assert!(spent.insert(first.nullifiers[0]));
    assert!(!spent.insert(second.nullifiers[0]), "the second spend is a double spend");
}

/// The sender who created a note knows its full opening but not the
/// recipient's spending key: it can no longer spend the note.
#[test]
fn plaintext_holder_without_the_key_cannot_spend() {
    let recipient_note = owned_note(1_000, &OWNER_SK, 7);
    let (tree, pos, path) = funded(&recipient_note);
    let sender_sk = [0xa1; 32];
    let (public, witness) =
        spend(&tree, &recipient_note, pos, &path, sender_sk, derive_nk(&sender_sk), owned_note(1_000, &sender_sk, 9));
    assert_eq!(check_spend(&public, &witness), Err(SpendError::Unauthorized(0)));
}

/// The owner cannot publish a second nullifier for the same note either: the
/// nullifier must be the one derived from the key that derives `pk_d`.
#[test]
fn owner_cannot_choose_a_different_nullifier_key() {
    let input = owned_note(1_000, &OWNER_SK, 7);
    let (tree, pos, path) = funded(&input);
    for other_nk in [[0u8; 32], [0xb2; 32], derive_ak(&OWNER_SK), derive_nk(&[0x5b; 32])] {
        let (public, witness) = spend(&tree, &input, pos, &path, OWNER_SK, other_nk, owned_note(1_000, &[3; 32], 3));
        assert_eq!(check_spend(&public, &witness), Err(SpendError::Nullifier(0)));
    }
}

/// A viewing key `(ak, nk)` recognises the note and computes its nullifier,
/// but the statement takes the spending key: the viewing key itself (used as
/// a witness key) does not authorize a spend.
#[test]
fn viewing_key_does_not_spend() {
    let input = owned_note(1_000, &OWNER_SK, 7);
    let (ak, nk) = (derive_ak(&OWNER_SK), derive_nk(&OWNER_SK));
    assert_eq!(derive_pk_d(&ak, &nk), input.pk_d, "the viewing key recognises the note");
    let (tree, pos, path) = funded(&input);
    for witness_key in [ak, nk] {
        let (public, witness) = spend(&tree, &input, pos, &path, witness_key, nk, owned_note(1_000, &[3; 32], 3));
        assert_eq!(check_spend(&public, &witness), Err(SpendError::Unauthorized(0)));
    }
}

/// Defense in depth kept from v1: one leaf is never counted twice in one
/// witness, even by its owner.
#[test]
fn repeated_position_cannot_double_value() {
    let input = owned_note(1_000, &OWNER_SK, 7);
    let (tree, pos, path) = funded(&input);
    let nf = input.nullifier(&derive_nk(&OWNER_SK), pos);
    let output = owned_note(2_000, &[0xee; 32], 0xee);
    let public = SpendPublic {
        anchor: tree.root(),
        nullifiers: vec![nf, nf],
        out_commitments: vec![output.commitment()],
        fee: 0,
    };
    let witness = SpendWitness {
        inputs: (0..2).map(|_| SpendInput { note: input.clone(), position: pos, path: path.clone(), sk: OWNER_SK }).collect(),
        outputs: vec![output],
    };
    assert_eq!(check_spend(&public, &witness), Err(SpendError::DuplicateInputPosition(1)));
}

/// Two separately funded leaves with identical commitments are two notes:
/// both are spendable, with distinct nullifiers (the position is bound in).
#[test]
fn separately_funded_positions_remain_spendable_even_with_identical_commitments() {
    let input = owned_note(1_000, &OWNER_SK, 7);
    let mut tree = CommitmentTree::new();
    tree.append(input.commitment());
    tree.append(input.commitment());
    let output = owned_note(2_000, &[0xee; 32], 0xee);
    let nk = derive_nk(&OWNER_SK);
    let public = SpendPublic {
        anchor: tree.root(),
        nullifiers: (0..2).map(|position| input.nullifier(&nk, position)).collect(),
        out_commitments: vec![output.commitment()],
        fee: 0,
    };
    assert_ne!(public.nullifiers[0], public.nullifiers[1]);
    let witness = SpendWitness {
        inputs: (0..2)
            .map(|position| SpendInput { note: input.clone(), position, path: tree.path(position).unwrap(), sk: OWNER_SK })
            .collect(),
        outputs: vec![output],
    };
    assert_eq!(check_spend(&public, &witness), Ok(()));
}

/// The spending key never appears in a witness's debug output.
#[test]
fn witness_debug_redacts_the_spending_key() {
    let input = owned_note(1_000, &OWNER_SK, 7);
    let w = SpendInput { note: input, position: 0, path: vec![], sk: OWNER_SK };
    let shown = format!("{w:?}");
    assert!(shown.contains("<redacted>"));
    assert!(!shown.contains("90, 90, 90"), "sk bytes (0x5a = 90) leaked: {shown}");
}
