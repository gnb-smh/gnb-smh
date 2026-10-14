//! AUDIT PoC (consensus cryptography). Each test documents one audited property.
//! Tests named `poc_*_malleab*`/`*_accepted` PASS when the reported weakness is
//! PRESENT (they assert the current behaviour), so a passing run confirms the
//! finding. Positive-control tests pass when the property holds.

use gnb_crypto::address::{Address, Network};
use gnb_crypto::core::{Block, BlockHeader, ChainId, MerkleRoot, Transaction, TxInput, TxOutput};
use gnb_crypto::crypto::{self, MLDSA_SIG_LEN, SUITE_HEADER_LEN};
use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};
use sha3::{Digest, Sha3_256};

const SUITE_MAGIC: [u8; 2] = [0xB1, 0x0C];

fn pk_hash20(pk: &[u8]) -> Vec<u8> {
    Sha3_256::digest(pk)[..20].to_vec()
}

/// Exact replica of node/src/main.rs validate_tx_inputs per-input auth steps
/// (parse_script_sig -> SHA3(pk)[..20] == script_pubkey -> crypto::verify).
fn consensus_input_ok(tx: &Transaction, i: usize, spk: &[u8], chain: ChainId) -> bool {
    let Some((sig, pk)) = Transaction::parse_script_sig(&tx.inputs[i].script_sig) else {
        return false;
    };
    if pk_hash20(&pk) != spk {
        return false;
    }
    crypto::verify(&pk, &tx.sighash(i, chain), &sig)
}

fn spend_tx() -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput { prev_txid: [0x5a; 32], prev_index: 3, script_sig: vec![], sequence: u32::MAX }],
        outputs: vec![TxOutput { value: 50_000, script_pubkey: vec![0x11; 20] }],
        locktime: 0,
    }
}

fn coinbase() -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput { prev_txid: [0; 32], prev_index: u32::MAX, script_sig: b"height:7".to_vec(), sequence: u32::MAX }],
        outputs: vec![TxOutput { value: 1, script_pubkey: vec![0; 20] }],
        locktime: 0,
    }
}

fn block_with(tx: Transaction) -> Block {
    let mut b = Block {
        header: BlockHeader { version: 1, parents: vec![[9; 32]], merkle_root: MerkleRoot::ZERO, timestamp: 1, bits: 0x2100_FFFF, nonce: 0 },
        transactions: vec![coinbase(), tx],
        blue_score: 1,
        height: 7,
        shielded_transactions: vec![],
    };
    b.header.merkle_root = b.body_merkle_root();
    b
}

/// Sign until the produced hybrid signature is "ordinary": raw body does not
/// start with the envelope magic and the compact Falcon half leaves room for
/// the 1280-byte padded form (true for the overwhelming majority of sigs).
fn sign_ordinary(sk: &[u8], msg: &[u8]) -> Vec<u8> {
    for _ in 0..64 {
        let sig = crypto::sign(sk, msg).unwrap();
        let body = &sig[SUITE_HEADER_LEN..];
        let falcon_len = body.len() - MLDSA_SIG_LEN;
        if body[..2] != SUITE_MAGIC && falcon_len < crypto::falcon::padded_signature_len() {
            return sig;
        }
    }
    panic!("could not obtain an ordinary signature");
}

// ── Positive control: hybrid is AND, not OR ──────────────────────────────────
#[test]
fn control_hybrid_requires_both_halves() {
    let (pk, sk) = crypto::generate_keypair();
    let msg = [7u8; 32];
    let sig = crypto::sign(&sk, &msg).unwrap();
    assert!(crypto::verify(&pk, &msg, &sig));
    let f_off = SUITE_HEADER_LEN + MLDSA_SIG_LEN;
    // valid ML-DSA + corrupted Falcon -> reject
    let mut bad_f = sig.clone();
    bad_f[f_off + 50] ^= 0x40;
    assert!(!crypto::verify(&pk, &msg, &bad_f));
    // corrupted ML-DSA + valid Falcon -> reject
    let mut bad_m = sig.clone();
    bad_m[SUITE_HEADER_LEN + 100] ^= 0x01;
    assert!(!crypto::verify(&pk, &msg, &bad_m));
    // Falcon half alone under the hybrid key -> reject; ML-DSA half alone -> reject
    let mut falcon_only = sig[..SUITE_HEADER_LEN].to_vec();
    falcon_only.extend_from_slice(&sig[f_off..]);
    assert!(!crypto::verify(&pk, &msg, &falcon_only));
    assert!(!crypto::verify(&pk, &msg, &sig[..f_off]));
    // swapping in another key's Falcon half (same ML-DSA half) changes the address
    let (pk2, _) = crypto::generate_keypair();
    let mut swapped = pk.clone();
    swapped[SUITE_HEADER_LEN + crypto::MLDSA_PUBKEY_LEN..]
        .copy_from_slice(&pk2[SUITE_HEADER_LEN + crypto::MLDSA_PUBKEY_LEN..]);
    assert_ne!(pk_hash20(&swapped), pk_hash20(&pk), "address commits to both halves");
}

// ── CRY-1: third-party witness malleability accepted by consensus verify ────
#[test]
fn poc_witness_malleability_accepted_with_same_txid_and_block_id() {
    let (pk, sk) = crypto::generate_keypair();
    let spk = pk_hash20(&pk);
    let mut tx = spend_tx();
    let sighash = tx.sighash(0, ChainId::Mainnet);
    let sig = sign_ordinary(&sk, &sighash);
    tx.inputs[0].script_sig = Transaction::build_script_sig(&sig, &pk);
    assert!(consensus_input_ok(&tx, 0, &spk, ChainId::Mainnet));

    // (a) third party strips the 4-byte suite envelope from the signature
    let stripped = sig[SUITE_HEADER_LEN..].to_vec();
    // (b) third party zero-pads the Falcon half to PQClean's 1280-byte padded form
    let mut padded = sig.clone();
    padded.resize(SUITE_HEADER_LEN + MLDSA_SIG_LEN + crypto::falcon::padded_signature_len(), 0);
    // (c) third party appends junk after the pubkey inside script_sig
    let mut junk = Transaction::build_script_sig(&sig, &pk);
    junk.extend_from_slice(&[0xEE; 900]);
    // (d) all combined
    let mut stripped_padded = stripped.clone();
    stripped_padded.resize(MLDSA_SIG_LEN + crypto::falcon::padded_signature_len(), 0);
    let mut combo = Transaction::build_script_sig(&stripped_padded, &pk);
    combo.extend_from_slice(&[0u8; 500]);

    let variants: Vec<(&str, Vec<u8>)> = vec![
        ("envelope-stripped", Transaction::build_script_sig(&stripped, &pk)),
        ("falcon-zero-padded", Transaction::build_script_sig(&padded, &pk)),
        ("trailing-junk", junk),
        ("combined", combo),
    ];

    let blk = block_with(tx.clone());
    for (name, ss) in variants {
        let mut m = tx.clone();
        m.inputs[0].script_sig = ss;
        assert!(consensus_input_ok(&m, 0, &spk, ChainId::Mainnet), "{name}: consensus must (currently) accept");
        assert_ne!(m.inputs[0].script_sig, tx.inputs[0].script_sig, "{name}: witness bytes differ");
        assert_eq!(m.txid(), tx.txid(), "{name}: txid unchanged");
        assert_ne!(m.to_wire_bytes(true), tx.to_wire_bytes(true), "{name}: wire bytes differ");
        let mb = block_with(m.clone());
        assert_eq!(mb.header.merkle_root, blk.header.merkle_root, "{name}: merkle root does not commit to script_sig");
        assert_eq!(mb.block_hash(), blk.block_hash(), "{name}: same block id");
        assert_ne!(mb.size_bytes(), blk.size_bytes(), "{name}: different consensus size for same block id");
        eprintln!("{name}: tx wire {} -> {} bytes, block size {} -> {}",
            tx.to_wire_bytes(true).len(), m.to_wire_bytes(true).len(), blk.size_bytes(), mb.size_bytes());
    }

    // The repository already contains a canonical verifier that would reject (a)/(b).
    assert!(crypto::verify_enveloped_canonical(&pk, &sighash, &sig));
    assert!(!crypto::verify_enveloped_canonical(&pk, &sighash, &stripped));
    assert!(!crypto::verify_enveloped_canonical(&pk, &sighash, &padded));
}

// ── CRY-1 corollary: a body mutation can flip size-dependent validity ────────
#[test]
fn poc_mutated_body_flips_size_rule_under_same_block_id() {
    let (pk, sk) = crypto::generate_keypair();
    let mut tx = spend_tx();
    let sig = sign_ordinary(&sk, &tx.sighash(0, ChainId::Mainnet));
    tx.inputs[0].script_sig = Transaction::build_script_sig(&sig, &pk);
    let honest = block_with(tx.clone());
    let mut m = tx.clone();
    // wire parser caps script_sig at 10_000 bytes; pad up to that
    let room = 10_000 - m.inputs[0].script_sig.len();
    m.inputs[0].script_sig.extend(std::iter::repeat(0u8).take(room));
    assert!(consensus_input_ok(&m, 0, &pk_hash20(&pk), ChainId::Mainnet));
    let mutated = block_with(m);
    assert_eq!(honest.block_hash(), mutated.block_hash());
    // Round-trips through the strict wire codec, so a peer can relay it.
    let wire = mutated.to_wire_bytes();
    let back = Block::from_wire_bytes(&wire).expect("mutated body is wire-valid");
    assert_eq!(back.block_hash(), honest.block_hash());
    eprintln!("same block id; honest size {} vs mutated size {} (+{} bytes per input)",
        honest.size_bytes(), back.size_bytes(), back.size_bytes() - honest.size_bytes());
}

// ── CRY-3: hybrid is separable; suite 0x0002 accepted by consensus verify ───
#[test]
fn poc_mldsa_only_suite_accepted_and_hybrid_signature_strippable() {
    let (pk, sk) = crypto::generate_keypair();
    let msg = [3u8; 32];
    let sig = crypto::sign(&sk, &msg).unwrap();
    // Strip the Falcon half from a victim's hybrid signature and relabel as 0x0002.
    let mut mldsa_only_pk = vec![0xB1, 0x0C, 0x02, 0x00];
    mldsa_only_pk.extend_from_slice(&pk[SUITE_HEADER_LEN..SUITE_HEADER_LEN + crypto::MLDSA_PUBKEY_LEN]);
    let mut mldsa_only_sig = vec![0xB1, 0x0C, 0x02, 0x00];
    mldsa_only_sig.extend_from_slice(&sig[SUITE_HEADER_LEN..SUITE_HEADER_LEN + MLDSA_SIG_LEN]);
    assert!(crypto::verify(&mldsa_only_pk, &msg, &mldsa_only_sig),
        "stripped ML-DSA half verifies as a suite-0x0002 signature (suite not bound into message)");
    // Mitigation: the address commits to the suite envelope, so the victim's
    // hybrid address does not accept it.
    assert_ne!(pk_hash20(&mldsa_only_pk), pk_hash20(&pk));
    assert!(!crypto::is_hybrid_public_key(&mldsa_only_pk));

    // A user-created ML-DSA-only output is spendable through the consensus path
    // today (no activation gate; is_hybrid_public_key has no caller).
    let (mpk, msk) = mldsa65::keypair();
    let mut pk2 = vec![0xB1, 0x0C, 0x02, 0x00];
    pk2.extend_from_slice(mpk.as_bytes());
    let mut sk2 = vec![0xB1, 0x0C, 0x02, 0x00];
    sk2.extend_from_slice(msk.as_bytes());
    let mut tx = spend_tx();
    let s = crypto::sign(&sk2, &tx.sighash(0, ChainId::Mainnet)).unwrap();
    tx.inputs[0].script_sig = Transaction::build_script_sig(&s, &pk2);
    assert!(consensus_input_ok(&tx, 0, &pk_hash20(&pk2), ChainId::Mainnet),
        "single-algorithm (ML-DSA-only) spend accepted by consensus verification");
}

// ── CRY-6: Falcon signer error code ignored -> Ok(sig) that never verifies ──
#[test]
fn poc_corrupt_falcon_secret_key_signs_ok_but_emits_unverifiable_sig() {
    let (pk, mut sk) = crypto::generate_keypair();
    // Falcon-1024 sk header byte must be 0x5A; corrupt it (length unchanged).
    sk[SUITE_HEADER_LEN + crypto::MLDSA_SECRET_LEN] ^= 0xFF;
    let sig = crypto::sign(&sk, b"m").expect("sign() reports success");
    assert_eq!(sig.len(), SUITE_HEADER_LEN + MLDSA_SIG_LEN, "Falcon half silently empty");
    assert!(!crypto::verify(&pk, b"m", &sig));
}

// ── CRY-8: address string checksum excludes the network; case-insensitive ──
#[test]
fn poc_address_checksum_not_network_bound_and_case_malleable() {
    let a = Address::from_hash([0x42; 20], Network::Mainnet).to_string();
    let swapped = a.replacen("gnb1q", "gnb1t", 1);
    let p = Address::parse(&swapped).expect("prefix swap passes checksum");
    assert!(p.is_testnet());
    assert_eq!(p.hash(), &[0x42; 20]);
    let upper = format!("gnb1q{}", a["gnb1q".len()..].to_uppercase());
    assert_ne!(upper, a);
    assert_eq!(Address::parse(&upper).unwrap().hash(), &[0x42; 20], "mixed/upper case accepted");
}

// ── Positive control: seeded RNG override does not leak ─────────────────────
#[test]
fn control_seeded_override_scoped_to_thread_and_closure() {
    let seed = [0x33u8; 32];
    let (pk_a, _) = crypto::generate_keypair_from_seed(&seed).unwrap();
    let (pk_b, sk_b) = crypto::generate_keypair_from_seed(&seed).unwrap();
    assert_eq!(pk_a, pk_b);
    // After the scope: signing is hedged.
    assert_ne!(crypto::sign(&sk_b, b"x").unwrap(), crypto::sign(&sk_b, b"x").unwrap());
    // While a scope is active on this thread, other threads use OS entropy.
    let (t1, t2) = pqcrypto_internals::with_seeded_rng_scope(&seed, || {
        let h1 = std::thread::spawn(crypto::generate_keypair);
        let h2 = std::thread::spawn(crypto::generate_keypair);
        (h1.join().unwrap().0, h2.join().unwrap().0)
    });
    assert_ne!(t1, t2);
    // Unwind inside the scope restores OS entropy.
    let r = std::panic::catch_unwind(|| {
        pqcrypto_internals::with_seeded_rng_scope(&seed, || panic!("boom"))
    });
    assert!(r.is_err());
    assert_ne!(crypto::generate_keypair().0, crypto::generate_keypair().0);
    // Misuse hazard (documented): signing INSIDE a scope is deterministic.
    let s1 = pqcrypto_internals::with_seeded_rng_scope(&seed, || crypto::sign(&sk_b, b"x").unwrap());
    let s2 = pqcrypto_internals::with_seeded_rng_scope(&seed, || crypto::sign(&sk_b, b"x").unwrap());
    assert_eq!(s1, s2);
}

// ── Positive control: only the clean Falcon variant is linked (tripwire) ────
#[test]
fn control_falcon_native_fp_variants_not_linked_in_this_binary() {
    let bytes = std::fs::read(std::env::current_exe().unwrap()).unwrap();
    let has = |n: &str| bytes.windows(n.len()).any(|w| w == n.as_bytes());
    let sym = |v: &str| format!("PQCLEAN_{}{}_{}_crypto_sign", "FALCON", "1024", v);
    assert!(has(&sym("CLEAN")), "control: clean symbols must be observable");
    assert!(!has(&sym("AVX2")));
    assert!(!has(&sym("AARCH64")));
}

// ── Positive control: pinned clean-variant Falcon KAT reproduces on this host
#[test]
fn control_falcon_clean_kat_reproduces_cross_platform() {
    let (pk, sig) = pqcrypto_internals::with_seeded_rng_scope(&[0xB1; 32], || {
        let (pk, sk) = crypto::falcon::keypair();
        let sig = crypto::falcon::sign(&sk, b"bloch-pos-falcon-clean-kat-v1").unwrap();
        (pk, sig)
    });
    assert_eq!(sig.len(), 1271);
    assert_eq!(hex::encode(Sha3_256::digest(&pk)), "afc79ea102992a5081b8172b55fb7c14e01ff2a74501a8577d1fe4df094c2375");
    assert_eq!(hex::encode(Sha3_256::digest(&sig)), "645bf4db96650515c016aa1f615b78ad4dac5985363abdfbb8a3e0fc4a5d2e24");
}

// ── CRY-4: sighash preimage is bincode-2 (library-defined) — pin it by an
// independent hand encoder so the exact consensus bytes are documented.
fn bincode_varint(out: &mut Vec<u8>, v: u64) {
    if v < 251 { out.push(v as u8) }
    else if v <= u16::MAX as u64 { out.push(251); out.extend_from_slice(&(v as u16).to_le_bytes()) }
    else if v <= u32::MAX as u64 { out.push(252); out.extend_from_slice(&(v as u32).to_le_bytes()) }
    else { out.push(253); out.extend_from_slice(&v.to_le_bytes()) }
}

#[test]
fn control_sighash_preimage_matches_independent_encoder() {
    let mut tx = spend_tx();
    tx.inputs.push(TxInput { prev_txid: [0x77; 32], prev_index: 300, script_sig: vec![1, 2, 3], sequence: 7 });
    tx.inputs[0].script_sig = vec![9; 40]; // must be ignored
    for idx in 0..2usize {
        let mut body = Vec::new();
        bincode_varint(&mut body, tx.version as u64);
        bincode_varint(&mut body, tx.inputs.len() as u64);
        for (i, inp) in tx.inputs.iter().enumerate() {
            body.extend_from_slice(&inp.prev_txid);
            bincode_varint(&mut body, inp.prev_index as u64);
            let ss: &[u8] = if i == idx { b"GNB_SIGHASH" } else { b"" };
            bincode_varint(&mut body, ss.len() as u64);
            body.extend_from_slice(ss);
            bincode_varint(&mut body, inp.sequence as u64);
        }
        bincode_varint(&mut body, tx.outputs.len() as u64);
        for o in &tx.outputs {
            bincode_varint(&mut body, o.value);
            bincode_varint(&mut body, o.script_pubkey.len() as u64);
            body.extend_from_slice(&o.script_pubkey);
        }
        bincode_varint(&mut body, tx.locktime as u64);
        let mut h = Sha3_256::new();
        h.update(b"GNB-SIGHASH-v1\0\0");
        h.update([1u8]);
        h.update(0x474E_0001u32.to_le_bytes());
        h.update(&body);
        let expect: [u8; 32] = h.finalize().into();
        assert_eq!(tx.sighash(idx, ChainId::Mainnet), expect, "input {idx}");
    }
    // Out-of-range index: no marker at all; every out-of-range index collides.
    assert_eq!(tx.sighash(2, ChainId::Mainnet), tx.sighash(99, ChainId::Mainnet));
}

// ── Positive control: sighash is chain-bound; mainnet sig fails on testnet ──
#[test]
fn control_cross_chain_replay_rejected_end_to_end() {
    let (pk, sk) = crypto::generate_keypair();
    let mut tx = spend_tx();
    let sig = crypto::sign(&sk, &tx.sighash(0, ChainId::Mainnet)).unwrap();
    tx.inputs[0].script_sig = Transaction::build_script_sig(&sig, &pk);
    assert!(consensus_input_ok(&tx, 0, &pk_hash20(&pk), ChainId::Mainnet));
    assert!(!consensus_input_ok(&tx, 0, &pk_hash20(&pk), ChainId::Testnet));
    // signature over the same tx under a different input index is rejected
    let mut two = tx.clone();
    two.inputs.push(TxInput { prev_txid: [1; 32], prev_index: 0, script_sig: vec![], sequence: u32::MAX });
    two.inputs[1].script_sig = two.inputs[0].script_sig.clone();
    assert!(!consensus_input_ok(&two, 1, &pk_hash20(&pk), ChainId::Mainnet));
    // ML-DSA private key type is Copy (cannot be zeroized by the caller)
    fn is_copy<T: Copy>() {}
    is_copy::<mldsa65::SecretKey>();
    let _ = mldsa65::SecretKey::from_bytes(&[0u8; 4032]).unwrap().as_bytes().len();
}
