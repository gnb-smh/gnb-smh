//! Cross-implementation check of the v2 draft against its Python reference vectors.

use gnb_smh::v2::{trace_with, Scratchpad};

const VECTORS: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/reference/test_vectors_v2.json"));

/// Under Miri only the vectors up to this size run: log2_n = 4 is 32
/// single-block SHA-256 compressions plus the seed and final digests, and one
/// compression takes ~0.2 s there (docs/testing/SANITIZERS.md); the five
/// log2_n = 13 vectors are 16,384 compressions each (about an hour apiece).
/// The small ones run the whole pipeline (seed, fill, data-dependent mix,
/// final digest), so `miri-cross` checks every byte-order site against the
/// Python reference on s390x and i686. Natively all run.
const MIRI_MAX_LOG2_N: u32 = 4;
/// log2_n = 4, five (header, nonce) cases (reference/gen_vectors_v2.py).
const MIRI_MIN_VECTORS: usize = 5;

#[test]
fn v2_matches_python_reference() {
    let doc: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let vectors = doc["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 10);
    let mut checked = 0;
    for v in vectors {
        let log2_n = v["log2_n"].as_u64().unwrap() as u32;
        if cfg!(miri) && log2_n > MIRI_MAX_LOG2_N {
            continue;
        }
        let header = hex::decode(v["header_hex"].as_str().unwrap()).unwrap();
        let nonce: u64 = v["nonce"].as_str().unwrap().parse().unwrap();
        let mut sp = Scratchpad::new(log2_n);
        let t = trace_with(&mut sp, &header, nonce);
        assert_eq!(hex::encode(t.seed), v["seed_hex"].as_str().unwrap(), "seed log2_n={log2_n} nonce={nonce}");
        assert_eq!(hex::encode(t.x_after_fill), v["x_after_fill_hex"].as_str().unwrap(), "fill log2_n={log2_n} nonce={nonce}");
        assert_eq!(hex::encode(t.x_after_mix), v["x_after_mix_hex"].as_str().unwrap(), "mix log2_n={log2_n} nonce={nonce}");
        assert_eq!(hex::encode(t.out), v["out_hex"].as_str().unwrap(), "out log2_n={log2_n} nonce={nonce}");
        checked += 1;
    }
    let want = if cfg!(miri) { MIRI_MIN_VECTORS } else { vectors.len() };
    assert!(checked >= want, "only {checked} of {} vectors checked (want >= {want})", vectors.len());
}
