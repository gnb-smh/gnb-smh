//! Cross-implementation check of the v3 draft against its Python reference vectors.

use gnb_smh::v3::{trace_with, Scratchpad};

const VECTORS: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/reference/test_vectors_v3.json"));

#[test]
fn v3_matches_python_reference() {
    let doc: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let vectors = doc["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 15);
    for v in vectors {
        let log2_n = v["log2_n"].as_u64().unwrap() as u32;
        let passes = v["passes"].as_u64().unwrap() as u8;
        let header = hex::decode(v["header_hex"].as_str().unwrap()).unwrap();
        let nonce: u64 = v["nonce"].as_str().unwrap().parse().unwrap();
        let t = trace_with(&mut Scratchpad::new(log2_n), passes, &header, nonce);
        let ctx = format!("log2_n={log2_n} passes={passes} nonce={nonce}");
        assert_eq!(hex::encode(t.seed), v["seed_hex"].as_str().unwrap(), "seed {ctx}");
        assert_eq!(hex::encode(t.after_pass0), v["after_pass0_hex"].as_str().unwrap(), "pass0 {ctx}");
        assert_eq!(hex::encode(t.last), v["last_hex"].as_str().unwrap(), "last {ctx}");
        assert_eq!(hex::encode(t.out), v["out_hex"].as_str().unwrap(), "out {ctx}");
    }
}
