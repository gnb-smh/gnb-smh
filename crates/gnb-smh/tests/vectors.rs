//! Cross-implementation check against the Python reference vectors.

use gnb_smh::{trace_with, Scratchpad};

const VECTORS: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/reference/test_vectors.json"));

/// Under Miri only the vectors up to this size run: log2_n = 2 is eight inner
/// Keccak-f[1600] permutations plus the seed and final digests, and one
/// permutation takes ~0.4 s there (docs/testing/SANITIZERS.md). They cover the
/// whole pipeline (seed with `enc` lengths and the u64le nonce, bytes to lanes,
/// fill, the data-dependent mix index, lanes to bytes, final digest), so the
/// `miri-cross` run checks every byte-order site against the Python reference
/// on a big-endian (s390x) and a 32-bit (i686) target. Natively all run.
const MIRI_MAX_LOG2_N: u32 = 2;
/// log2_n = 1 and 2, five (header, nonce) cases each (reference/gen_vectors.py).
const MIRI_MIN_VECTORS: usize = 10;

#[test]
fn matches_python_reference() {
    let doc: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let vectors = doc["vectors"].as_array().unwrap();
    assert!(!vectors.is_empty());
    let mut checked = 0;
    for v in vectors {
        let log2_n = v["log2_n"].as_u64().unwrap() as u32;
        if cfg!(miri) && log2_n > MIRI_MAX_LOG2_N {
            continue; // 2^10 and 2^19 blocks: hours to days under Miri
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
