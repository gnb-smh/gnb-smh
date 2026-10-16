//! Cross-implementation check of the v3 draft against its Python reference vectors.

use gnb_smh::v3::{trace_with, Scratchpad};

const VECTORS: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/reference/test_vectors_v3.json"));

/// Under Miri only the smallest vectors run: one step is two Keccak-f[1600]
/// permutations and one permutation takes ~0.4 s there
/// (docs/testing/SANITIZERS.md). The log2_n = 15 vectors are 2^16 steps each
/// (about 15 hours apiece). log2_n = 4 with one pass (15 steps) runs the seed,
/// `enc` lengths, the u64le nonce, pass 0 with its data-dependent index and
/// the final digest; the first log2_n = 4 vector with three passes (47 steps)
/// adds the later passes and their wrap-around predecessor. So `miri-cross`
/// checks every byte-order site against the Python reference on s390x and
/// i686. Natively all run.
const MIRI_MAX_LOG2_N: u32 = 4;
/// Vectors with more passes than this run under Miri only up to
/// `MIRI_MULTI_PASS_VECTORS` of them.
const MIRI_MAX_FREE_PASSES: u8 = 1;
const MIRI_MULTI_PASS_VECTORS: usize = 1;
/// The five one-pass vectors and one three-pass vector (reference/gnb_smh_v3.py).
const MIRI_MIN_VECTORS: usize = 6;

#[test]
fn v3_matches_python_reference() {
    let doc: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let vectors = doc["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 15);
    let (mut checked, mut multi_pass) = (0, 0);
    for v in vectors {
        let log2_n = v["log2_n"].as_u64().unwrap() as u32;
        let passes = v["passes"].as_u64().unwrap() as u8;
        if cfg!(miri) {
            if log2_n > MIRI_MAX_LOG2_N {
                continue;
            }
            if passes > MIRI_MAX_FREE_PASSES {
                if multi_pass == MIRI_MULTI_PASS_VECTORS {
                    continue;
                }
                multi_pass += 1;
            }
        }
        let header = hex::decode(v["header_hex"].as_str().unwrap()).unwrap();
        let nonce: u64 = v["nonce"].as_str().unwrap().parse().unwrap();
        let t = trace_with(&mut Scratchpad::new(log2_n), passes, &header, nonce);
        let ctx = format!("log2_n={log2_n} passes={passes} nonce={nonce}");
        assert_eq!(hex::encode(t.seed), v["seed_hex"].as_str().unwrap(), "seed {ctx}");
        assert_eq!(hex::encode(t.after_pass0), v["after_pass0_hex"].as_str().unwrap(), "pass0 {ctx}");
        assert_eq!(hex::encode(t.last), v["last_hex"].as_str().unwrap(), "last {ctx}");
        assert_eq!(hex::encode(t.out), v["out_hex"].as_str().unwrap(), "out {ctx}");
        checked += 1;
    }
    let want = if cfg!(miri) { MIRI_MIN_VECTORS } else { vectors.len() };
    assert!(checked >= want, "only {checked} of {} vectors checked (want >= {want})", vectors.len());
}
