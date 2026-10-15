//! The hardening block rules of `core::block_rules` (audit VAL-2, VAL-10,
//! VAL-12, CRY-1) against independent implementations written from the
//! specification (`common`), on two kinds of input selected by the first byte:
//!
//! * an id list: the tagged Merkle root equals an RFC 6962-style recursive
//!   reference, the legacy root equals Bitcoin's in-place `ComputeMerkleRoot`,
//!   the coinbase branch folds back to the root in both regimes and does not
//!   depend on position 0, and appending a copy of the last id (CVE-2012-2459)
//!   changes the tagged root (it keeps the legacy root for odd lists);
//! * a block decoded from untrusted wire bytes (the attacker's path): wire
//!   size, txids, wtxids, header roots, witness root, parents commitment and
//!   the 80-byte coinbase commitment equal the references; the 64-byte rule
//!   fires exactly on a 64-byte txid preimage; the coinbase-commitment verdict
//!   equals a reference parser of the commitment; no check panics. Then the
//!   block is REPAIRED with the references (coinbase shape, commitment, root)
//!   so the library must accept it unless a transaction is 64 bytes, and one
//!   input-chosen field the commitment covers is altered: the library must
//!   reject it (and must keep accepting when only the miner's extra bytes
//!   change with the root recomputed).
#![no_main]

mod common;

use common::*;
use gnb_crypto::core::{activation, block_rules as br, Block, Transaction, TxInput, MAX_BLOCK_SIZE};
use libfuzzer_sys::fuzz_target;
use sha3::{Digest, Sha3_256};

fuzz_target!(|data: &[u8]| {
    let mut inp = Input::new(data);
    if inp.u8() & 1 == 0 {
        check_id_list(&mut inp);
    } else {
        let ctl = inp.arr::<8>();
        if let Ok(block) = Block::from_wire_bytes(inp.rest()) {
            check_block(&block);
            check_repaired(&block, &mut Input::new(&ctl));
        }
    }
});

fn check_id_list(inp: &mut Input) {
    let n = inp.below(80);
    let mut ids: Vec<[u8; 32]> = Vec::with_capacity(n);
    for i in 0..n {
        // Repeated ids are allowed and frequent: duplicates are the
        // interesting shape for Merkle malleability.
        if i > 0 && inp.u8().is_multiple_of(4) {
            let j = inp.below(i);
            ids.push(ids[j]);
        } else {
            ids.push(inp.arr());
        }
    }
    let tagged = br::tagged_merkle_root(&ids);
    let legacy = br::legacy_merkle_root(&ids);
    assert_eq!(tagged.0, ref_tagged_root(&ids), "tagged root differs from the reference");
    assert_eq!(legacy.0, ref_legacy_root(&ids), "legacy root differs from the reference");
    if let Some(first) = ids.first() {
        assert_eq!(br::merkle_leaf(first), ref_tagged(b"GnB/merkle/leaf", first));
    }
    for (hardened, root) in [(true, tagged), (false, legacy)] {
        let branch = br::coinbase_merkle_branch(&ids, hardened);
        if let Some(first) = ids.first() {
            assert_eq!(br::merkle_root_from_coinbase_branch(first, &branch, hardened), root, "branch fold (hardened={hardened})");
            let mut other = ids.clone();
            other[0] = [0xEE; 32];
            assert_eq!(br::coinbase_merkle_branch(&other, hardened), branch, "branch depends on position 0");
        } else {
            assert!(branch.is_empty());
        }
    }
    if let Some(last) = ids.last().copied() {
        let mut dup = ids.clone();
        dup.push(last);
        assert_ne!(br::tagged_merkle_root(&dup), tagged, "duplicating the last id kept the tagged root");
        if ids.len() % 2 == 1 && ids.len() > 1 {
            assert_eq!(br::legacy_merkle_root(&dup), legacy, "legacy duplicate-last ambiguity");
        }
    }
}

/// The reference header root of `b` in the regime `hardened`.
fn ref_body_root(b: &Block, hardened: bool) -> [u8; 32] {
    let ids: Vec<[u8; 32]> = b.transactions.iter().map(ref_txid).collect();
    let tx_root = if hardened { ref_tagged_root(&ids) } else { ref_legacy_root(&ids) };
    if b.shielded_transactions.is_empty() {
        return tx_root;
    }
    let mut sh = Sha3_256::new();
    sh.update(b"gnb:block:shielded:v1");
    for s in &b.shielded_transactions {
        // The shielded encoding is the block wire encoding of one entry:
        // re-encode a block holding only it and cut the fixed prefix.
        let lone = Block {
            header: b.header.clone(),
            transactions: vec![],
            blue_score: 0,
            height: 0,
            shielded_transactions: vec![s.clone()],
        };
        let enc = ref_block_wire(&lone);
        let prefix = ref_header_wire(&lone.header, 0, 0).len() + 1 + 1; // tx count 0, shielded count 1
        sh.update(sha3(&enc[prefix..]));
    }
    let sh_root: [u8; 32] = sh.finalize().into();
    let mut c = Sha3_256::new();
    c.update(b"gnb:block:body:v1");
    c.update(tx_root);
    c.update(sh_root);
    c.finalize().into()
}

/// Reference verdict of `check_coinbase_commitment`: which field (if any)
/// of the first input's `script_sig` disagrees, in the specified order.
fn ref_commitment_verdict(b: &Block) -> Result<(), &'static str> {
    let ss = match b.transactions.first().and_then(|t| t.inputs.first()) {
        Some(i) => &i.script_sig,
        None => return Err("format"),
    };
    if ss.len() < 80 {
        return Err("short");
    }
    let want = ref_commitment(b.height, &b.header.parents, &b.transactions);
    if ss[..8] != want[..8] {
        return Err("tag");
    }
    if ss[8..16] != want[8..16] {
        return Err("height");
    }
    if ss[16..48] != want[16..48] {
        return Err("parents");
    }
    if ss[48..80] != want[48..80] {
        return Err("witness");
    }
    Ok(())
}

fn lib_commitment_kind(r: Result<(), &'static str>) -> Result<(), &'static str> {
    r.map_err(|e| {
        if e.contains("invalid coinbase format") {
            "format"
        } else if e.contains("shorter than 80") {
            "short"
        } else if e.contains("tag") {
            "tag"
        } else if e.starts_with("bad-cb-height") {
            "height"
        } else if e.contains("parents") {
            "parents"
        } else if e.contains("witness") {
            "witness"
        } else {
            panic!("unexpected commitment error {e:?}")
        }
    })
}

/// The activation predicate as specified (`activation::is_active_at`, and
/// never at the genesis height): `height >= activation`. `NEVER` is u64::MAX,
/// so the rules are active under it at the one height u64::MAX: no block can
/// reach that height (its parents would be at u64::MAX - 1), but a decoded
/// block can claim it.
fn ref_active(height: u64, activation: u64) -> bool {
    height >= 1 && height >= activation
}

fn check_block(b: &Block) {
    // Encodings and sizes.
    let wire = b.to_wire_bytes();
    assert_eq!(wire, ref_block_wire(b), "block encoding differs from the reference");
    assert_eq!(b.wire_size(), wire.len(), "wire_size differs from the encoding length");
    for tx in &b.transactions {
        assert_eq!(tx.is_coinbase(), ref_is_coinbase(tx));
        assert_eq!(tx.txid(), ref_txid(tx), "txid");
        assert_eq!(tx.wtxid(), ref_wtxid(tx), "wtxid");
        for with in [false, true] {
            assert_eq!(tx.wire_size(with), ref_tx_wire(tx, with).len(), "tx wire_size");
        }
        // VAL-10: the 64-byte rule fires exactly on a 64-byte txid preimage.
        let pre = ref_tx_wire(tx, ref_is_coinbase(tx)).len();
        assert_eq!(br::txid_preimage_len(tx), pre);
        assert_eq!(br::check_tx_not_64_bytes(tx).is_err(), pre == 64, "64-byte rule");
    }

    // Roots and commitments.
    assert_eq!(b.body_merkle_root_at(0).0, ref_body_root(b, ref_active(b.height, 0)), "hardened body root");
    assert_eq!(
        b.body_merkle_root_at(activation::NEVER).0,
        ref_body_root(b, ref_active(b.height, activation::NEVER)),
        "legacy body root"
    );
    assert_eq!(br::witness_root(&b.transactions).0, ref_witness_root(&b.transactions), "witness root");
    assert_eq!(br::parents_commitment(&b.header.parents), ref_parents_commitment(&b.header.parents));
    assert_eq!(
        br::expected_coinbase_commitment(b),
        ref_commitment(b.height, &b.header.parents, &b.transactions),
        "expected coinbase commitment"
    );
    assert_eq!(lib_commitment_kind(br::check_coinbase_commitment(b)), ref_commitment_verdict(b), "commitment verdict");

    // The full context-free checks never panic; below the activation they are
    // a no-op, and the genesis height is never subject to them.
    let _ = br::check_block_hardened_at(b, 0);
    let _ = br::check_hardened_body(b);
    let _ = b.validate_structure_without_pow_at(0);
    let _ = b.validate_structure_without_pow_at(activation::NEVER);
    if !ref_active(b.height, activation::NEVER) {
        assert_eq!(br::check_block_hardened_at(b, activation::NEVER), Ok(()));
    }
    if b.height == 0 {
        assert_eq!(br::check_block_hardened_at(b, 0), Ok(()));
    }
    assert_eq!(br::block_size_for_rules(b, true), wire.len());
}

/// Make `b` satisfy every hardening rule with the references (coinbase shape,
/// height >= 1, commitment, header root), check the library agrees, then alter
/// one committed field and check it is rejected.
fn check_repaired(b: &Block, ctl: &mut Input) {
    let mut r = b.clone();
    if r.transactions.is_empty() {
        return;
    }
    let extra = r.transactions[0].inputs.first().map(|i| i.script_sig.clone()).unwrap_or_default();
    let extra = extra[..extra.len().min(40)].to_vec();
    r.transactions[0].inputs = vec![TxInput { prev_txid: [0; 32], prev_index: u32::MAX, script_sig: vec![], sequence: u32::MAX }];
    for tx in r.transactions.iter_mut().skip(1) {
        if ref_is_coinbase(tx) {
            tx.inputs[0].prev_index = 0;
        }
    }
    r.height = r.height.max(1);
    let commit = |r: &mut Block, extra: &[u8]| {
        let mut ss = ref_commitment(r.height, &r.header.parents, &r.transactions).to_vec();
        ss.extend_from_slice(extra);
        r.transactions[0].inputs[0].script_sig = ss;
        r.header.merkle_root.0 = ref_body_root(r, true);
    };
    commit(&mut r, &extra);

    let has_64 = r.transactions.iter().any(|t| ref_tx_wire(t, ref_is_coinbase(t)).len() == 64);
    let too_big = ref_block_wire(&r).len() > MAX_BLOCK_SIZE;
    let got = br::check_block_hardened_at(&r, 0);
    match (has_64, too_big) {
        (false, false) => assert_eq!(got, Ok(()), "a block repaired to the specification is rejected"),
        (_, true) => assert_eq!(got, Err("block too large")),
        (true, false) => assert!(got.unwrap_err().starts_with("64-byte"), "64-byte transaction accepted"),
    }
    if got.is_err() {
        return;
    }
    assert_eq!(br::check_hardened_body(&r), Ok(()));

    // Changing only the miner's extra bytes (root recomputed) stays valid.
    let mut e = r.clone();
    let mut extra2 = extra.clone();
    extra2.push(ctl.u8());
    commit(&mut e, &extra2);
    assert_eq!(br::check_block_hardened_at(&e, 0), Ok(()), "extra nonce bytes are free");

    // One committed field altered: always rejected.
    let mut m = r.clone();
    let what = ctl.u8() % 6;
    match what {
        0 => {
            // Any byte of the 80-byte commitment, root recomputed (so only
            // the commitment check can catch it).
            let i = ctl.below(80);
            m.transactions[0].inputs[0].script_sig[i] ^= 1 | ctl.u8();
            m.header.merkle_root.0 = ref_body_root(&m, true);
        }
        1 => {
            // The header height (the commitment keeps the old one).
            m.height = m.height.wrapping_add(1 + ctl.below(3) as u64).max(1);
            if m.height == r.height {
                m.height += 1;
            }
        }
        2 => {
            // The parent list (add, drop or change one parent).
            if m.header.parents.is_empty() || ctl.bool() {
                m.header.parents.push(ctl.arr());
            } else {
                let i = ctl.below(m.header.parents.len());
                m.header.parents[i][ctl.below(32)] ^= 0x80;
            }
        }
        3 => {
            // A non-coinbase witness: changes its wtxid, not its txid.
            if m.transactions.len() < 2 || m.transactions[1].inputs.is_empty() {
                return;
            }
            m.transactions[1].inputs[0].script_sig.push(ctl.u8());
            assert_eq!(m.transactions[1].txid(), r.transactions[1].txid());
        }
        4 => {
            // The commitment cut short.
            let keep = ctl.below(80);
            m.transactions[0].inputs[0].script_sig.truncate(keep);
            m.header.merkle_root.0 = ref_body_root(&m, true);
        }
        _ => {
            // A transaction appended without updating the root.
            let mut t: Transaction = r.transactions.last().unwrap().clone();
            if ref_is_coinbase(&t) {
                return;
            }
            t.locktime ^= 1;
            m.transactions.push(t);
        }
    }
    assert!(br::check_block_hardened_at(&m, 0).is_err(), "mutation {what} of a committed field was accepted");
}
