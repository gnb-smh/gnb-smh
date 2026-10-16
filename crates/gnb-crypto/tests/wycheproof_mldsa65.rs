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

/// The cases PQClean's AVX2 ML-DSA-65 got wrong: it ACCEPTED the 41 invalid
/// signatures whose z violates the FIPS 204 infinity norm (no ‖z‖∞ check)
/// and REFUSED tcId 161, a valid signature under an all-zero public key whose
/// hint sits where r0 = 0 (its UseHint moves r1 up there; FIPS 204 Algorithm
/// 40 moves it down). pqcrypto-mldsa's default features dispatch to that code
/// on AVX2 CPUs only, so the consensus verdict depended on the CPU (tcId 161:
/// refused on AVX2 x86_64, accepted on i686, on x86_64 without AVX2 and in the
/// wasm wallet). Every build now links the clean implementation alone
/// (crates/gnb-crypto/Cargo.toml, `crypto::mldsa_one_verdict`), which agrees
/// with Wycheproof everywhere; the list documents what the tests below guard.
const AVX2_VARIANT_DISAGREED: &[u64] = &[84, 85, 86, 87, 88, 90, 91, 92, 93, 94, 95, 97, 98, 99, 102, 103, 104, 106, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 120, 121, 122, 124, 125, 126, 127, 128, 129, 130, 131, 132, 139, 161];
const AVX2_VARIANT_REFUSED_VALID: u64 = 161;

fn library_verify(pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    match (mldsa65::PublicKey::from_bytes(pk), mldsa65::DetachedSignature::from_bytes(sig)) {
        (Ok(pk), Ok(sig)) => mldsa65::verify_detached_signature_ctx(&sig, msg, ctx, &pk).is_ok(),
        _ => false,
    }
}

/// The linked library agrees with Wycheproof on all 210 cases (with their
/// contexts) on every target and CPU: x86_64 with and without AVX2 (CI also
/// runs this binary on qemu's Nehalem), i686, aarch64.
#[test]
fn linked_library_matches_wycheproof_on_every_case() {
    let found: Vec<u64> = cases().into_iter()
        .filter(|(_, pk, msg, ctx, sig, valid)| library_verify(pk, msg, ctx, sig) != *valid)
        .map(|c| c.0)
        .collect();
    assert_eq!(found, Vec::<u64>::new(), "tcIds where the library differs from Wycheproof");
}

/// Every empty-context case through the consensus wrapper (`crypto::verify`
/// and `crypto::verify_canonical`, ML-DSA-65-only suite) matches Wycheproof,
/// the 42 cases the AVX2 implementation got wrong included: the 41 norm
/// violations are refused and tcId 161 is accepted, on every platform.
#[test]
fn consensus_wrapper_matches_wycheproof() {
    let mut checked = 0;
    let mut avx2_cases = 0;
    for (id, pk, msg, ctx, sig, valid) in cases() {
        if !ctx.is_empty() {
            continue; // GnB signs with the empty context only
        }
        if AVX2_VARIANT_DISAGREED.contains(&id) {
            assert_eq!(valid, id == AVX2_VARIANT_REFUSED_VALID, "Wycheproof tcId {id}");
            avx2_cases += 1;
        }
        let (pk, sig) = (envelope(&pk), envelope(&sig));
        assert_eq!(crypto::verify(&pk, &msg, &sig), valid, "Wycheproof tcId {id} (verify)");
        assert_eq!(crypto::verify_canonical(&pk, &msg, &sig), valid, "Wycheproof tcId {id} (canonical)");
        checked += 1;
    }
    assert_eq!((checked, avx2_cases), (203, AVX2_VARIANT_DISAGREED.len()));
}
