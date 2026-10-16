//! Third-party Wycheproof ML-DSA-65 verification vectors (C2SP/wycheproof).
//! See vectors/WYCHEPROOF-MLDSA-PROVENANCE.md for source, commit and scope.
use gnb_crypto::crypto;
use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
use serde_json::Value;
use sha2::{Digest, Sha256};

const FIXTURE: &[u8] = include_bytes!("vectors/wycheproof-mldsa65-verify.json");

/// `(tcId, publicKey, msg, ctx, sig, valid)` for every test.
fn cases() -> Vec<(u64, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, bool)> {
    assert_eq!(hex::encode(Sha256::digest(FIXTURE)),
        "49ac366d76115eab56b7116f10d06e288e6f23fe6cfb90b26bfb2d731a8d1e02");
    let f: Value = serde_json::from_slice(FIXTURE).unwrap();
    assert_eq!(f["algorithm"], "ML-DSA-65");
    let hexf = |v: &Value| hex::decode(v.as_str().unwrap_or("")).unwrap();
    let mut out = Vec::new();
    for g in f["testGroups"].as_array().unwrap() {
        let pk = hexf(&g["publicKey"]);
        for t in g["tests"].as_array().unwrap() {
            let valid = match t["result"].as_str().unwrap() {
                "valid" => true,
                "invalid" => false,
                other => panic!("unexpected result {other}"),
            };
            out.push((t["tcId"].as_u64().unwrap(), pk.clone(), hexf(&t["msg"]), hexf(&t["ctx"]),
                      hexf(&t["sig"]), valid));
        }
    }
    assert_eq!(out.len(), 210);
    out
}

fn envelope(body: &[u8]) -> Vec<u8> {
    // Suite envelope: magic B1 0C, suite id u16 LE (0x0002 = ML-DSA-65 only).
    let mut v = vec![0xB1, 0x0C];
    v.extend_from_slice(&crypto::SUITE_MLDSA65_ONLY.to_le_bytes());
    v.extend_from_slice(body);
    v
}

/// Where the linked library (pqcrypto-mldsa 0.1.2, PQClean) disagrees with
/// Wycheproof: 41 invalid signatures whose z violates the FIPS 204 infinity
/// norm are ACCEPTED, and tcId 161 (a valid signature under an all-zero public
/// key, `use_hint(1, 0)`) is REFUSED. Consensus closes the first gap itself
/// (`crypto::mldsa65_z_within_bound`); the second only refuses a key no honest
/// wallet generates. Pinned so a library change is noticed.
const LIBRARY_DISAGREES: &[u64] = &[84, 85, 86, 87, 88, 90, 91, 92, 93, 94, 95, 97, 98, 99, 102, 103, 104, 106, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 120, 121, 122, 124, 125, 126, 127, 128, 129, 130, 131, 132, 139, 161];
const VALID_REFUSED_BY_LIBRARY: u64 = 161;

fn library_verify(pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    match (mldsa65::PublicKey::from_bytes(pk), mldsa65::DetachedSignature::from_bytes(sig)) {
        (Ok(pk), Ok(sig)) => mldsa65::verify_detached_signature_ctx(&sig, msg, ctx, &pk).is_ok(),
        _ => false,
    }
}

/// The library's disagreements with Wycheproof are exactly the known set.
#[test]
fn library_disagreements_are_exactly_the_known_ones() {
    let found: Vec<u64> = cases().into_iter()
        .filter(|(_, pk, msg, ctx, sig, valid)| library_verify(pk, msg, ctx, sig) != *valid)
        .map(|c| c.0)
        .collect();
    assert_eq!(found, LIBRARY_DISAGREES);
}

/// Every empty-context case through the consensus wrapper (`crypto::verify`
/// and `crypto::verify_canonical`, ML-DSA-65-only suite): it matches
/// Wycheproof on every case, including all 41 norm violations the library
/// alone would accept, except tcId 161 (refused, conservatively).
#[test]
fn consensus_wrapper_matches_wycheproof() {
    let mut checked = 0;
    for (id, pk, msg, ctx, sig, valid) in cases() {
        if !ctx.is_empty() {
            continue; // GnB signs with the empty context only
        }
        let expected = valid && id != VALID_REFUSED_BY_LIBRARY;
        let (pk, sig) = (envelope(&pk), envelope(&sig));
        assert_eq!(crypto::verify(&pk, &msg, &sig), expected, "Wycheproof tcId {id} (verify)");
        assert_eq!(crypto::verify_canonical(&pk, &msg, &sig), expected, "Wycheproof tcId {id} (canonical)");
        checked += 1;
    }
    assert_eq!(checked, 203);
}
