//! Cross-implementation check against `reference/ledger_vectors.json`.

use gnb_smh::ledger::{self, Context, Hash, State};

const VECTORS: &str = include_str!("../../reference/ledger_vectors.json");

fn doc() -> serde_json::Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn h32(v: &serde_json::Value) -> Hash {
    hex::decode(v.as_str().unwrap()).unwrap().try_into().unwrap()
}

fn state(v: &serde_json::Value) -> State {
    State { utxo_root: h32(&v["utxo_root"]), nullifier_root: h32(&v["nullifier_root"]) }
}

fn ctx(v: &serde_json::Value) -> Context {
    Context {
        height: v["height"].as_u64().unwrap(),
        subsidy: v["subsidy"].as_u64().unwrap(),
        coinbase_maturity: v["coinbase_maturity"].as_u64().unwrap(),
        auth: ledger::test_preimage_auth,
        // validate_block sets it from the header.
        parents_root: ledger::EMPTY,
    }
}

fn run(v: &serde_json::Value) -> Result<(State, Vec<bool>), ledger::InvalidBlock> {
    let wires: Vec<Vec<u8>> =
        v["txs_hex"].as_array().unwrap().iter().map(|t| hex::decode(t.as_str().unwrap()).unwrap()).collect();
    let header = hex::decode(v["header_hex"].as_str().unwrap()).unwrap();
    let witness = hex::decode(v["witness_hex"].as_str().unwrap()).unwrap();
    let nonce: u64 = v["nonce"].as_str().unwrap().parse().unwrap();
    let mut sp = gnb_smh::Scratchpad::new(v["log2_n"].as_u64().unwrap() as u32);
    ledger::validate_block_any_size(&state(&v["pre"]), &header, nonce, &wires, &witness, &ctx(v), &mut sp, &[0xff; 32])
}

#[test]
fn smt_vectors() {
    let d = doc();
    let smt = &d["smt"];
    let defaults = ledger::defaults();
    assert_eq!(defaults[1], h32(&smt["default_1"]));
    assert_eq!(defaults[255], h32(&smt["default_255"]));
    assert_eq!(ledger::empty_root(), h32(&smt["empty_root"]));
    assert_eq!(State::genesis().commitment(), h32(&smt["genesis_state_commitment"]));

    let mut tree = ledger::SparseMerkleTree::new();
    let mut values = std::collections::HashMap::new();
    for step in smt["steps"].as_array().unwrap() {
        let k = h32(&step["key"]);
        if step["op"] == "insert" {
            let v = h32(&step["value"]);
            values.insert(k, v);
            tree.set(&k, &ledger::leaf_hash(&k, &v));
        } else {
            values.remove(&k);
            tree.set(&k, &ledger::EMPTY);
        }
        assert_eq!(tree.root(), h32(&step["root"]));
    }
    let root = h32(&smt["final_root"]);
    for p in smt["proofs"].as_array().unwrap() {
        let k = h32(&p["key"]);
        let bytes = hex::decode(p["proof"].as_str().unwrap()).unwrap();
        assert_eq!(tree.proof(&k), bytes, "Rust tree must emit the same proof bytes");
        let (sibs, end) = ledger::decode_proof(&bytes, 0).unwrap();
        assert_eq!(end, bytes.len());
        let leaf = if p["present"].as_bool().unwrap() { ledger::leaf_hash(&k, &values[&k]) } else { ledger::EMPTY };
        assert_eq!(ledger::root_from(&k, &leaf, &sibs), root);
    }
    let bad = hex::decode(smt["noncanonical_proof"].as_str().unwrap()).unwrap();
    assert_eq!(ledger::decode_proof(&bad, 0).unwrap_err().code, ledger::ErrorCode::NoncanonicalProof);
}

#[test]
fn valid_blocks() {
    let d = doc();
    let blocks: Vec<&serde_json::Value> =
        d["chain"].as_array().unwrap().iter().chain(d["synthetic"].as_array().unwrap()).collect();
    assert_eq!(blocks.len(), 5);
    for v in blocks {
        let name = v["name"].as_str().unwrap();
        let (post, accepted) = run(v).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(post, state(&v["post"]), "{name}");
        let expected: Vec<bool> = v["accepted"].as_array().unwrap().iter().map(|b| b.as_bool().unwrap()).collect();
        assert_eq!(accepted, expected, "{name}");
        let ids = v["txids"].as_array().unwrap().iter().zip(v["wtxids"].as_array().unwrap());
        for (tx_hex, (id, wid)) in v["txs_hex"].as_array().unwrap().iter().zip(ids) {
            let bytes = hex::decode(tx_hex.as_str().unwrap()).unwrap();
            let tx = ledger::decode_tx_wire(&bytes).unwrap();
            assert_eq!(ledger::tx_wire(&tx), bytes, "{name}: wire round trip");
            assert_eq!(ledger::txid(&tx), h32(id), "{name}: txid");
            assert_eq!(ledger::wtxid(&bytes), h32(wid), "{name}: wtxid");
        }
    }
}

#[test]
fn invalid_blocks_raise_the_same_error_codes() {
    let d = doc();
    let cases = d["invalid"].as_array().unwrap();
    assert!(cases.len() >= 15);
    for v in cases {
        let name = v["name"].as_str().unwrap();
        let expected = v["expected_error"].as_str().unwrap();
        match run(v) {
            Ok(_) => panic!("{name}: accepted, expected {expected}"),
            Err(e) => {
                assert_eq!(e.code.as_str(), expected, "{name}: {e}");
                assert_eq!(e.code.is_permanent(), v["permanent"].as_bool().unwrap(), "{name}: permanence");
            }
        }
    }
}
