//! Cross-implementation check of the v2 draft against its Python reference vectors.

use gnb_smh::v2::{trace_with, Scratchpad};

const VECTORS: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/reference/test_vectors_v2.json"));

#[test]
fn v2_matches_python_reference() {
    let doc: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let vectors = doc["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 10);
    for v in vectors {
        let log2_n = v["log2_n"].as_u64().unwrap() as u32;
        let header = hex::decode(v["header_hex"].as_str().unwrap()).unwrap();
        let nonce: u64 = v["nonce"].as_str().unwrap().parse().unwrap();
        let mut sp = Scratchpad::new(log2_n);
        let t = trace_with(&mut sp, &header, nonce);
        assert_eq!(hex::encode(t.seed), v["seed_hex"].as_str().unwrap(), "seed log2_n={log2_n} nonce={nonce}");
        assert_eq!(hex::encode(t.x_after_fill), v["x_after_fill_hex"].as_str().unwrap(), "fill log2_n={log2_n} nonce={nonce}");
        assert_eq!(hex::encode(t.x_after_mix), v["x_after_mix_hex"].as_str().unwrap(), "mix log2_n={log2_n} nonce={nonce}");
        assert_eq!(hex::encode(t.out), v["out_hex"].as_str().unwrap(), "out log2_n={log2_n} nonce={nonce}");
    }
}
