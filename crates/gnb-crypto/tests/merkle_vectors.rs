//! The hardening block rules against the normative Python reference
//! (`reference/gnb_merkle.py` -> `reference/merkle_vectors.json`, written by
//! `reference/gen_merkle_vectors.py`): tagged and legacy Merkle roots,
//! coinbase branches, transaction encodings and ids, the 64-byte rule, and
//! the 80-byte coinbase commitment (audit VAL-2, VAL-10, CRY-1).

use gnb_crypto::core::{self, activation, block_rules, Block, BlockHeader, MerkleRoot, Transaction, TxInput, TxOutput};
use serde_json::Value;

const VECTORS: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../reference/merkle_vectors.json"));

fn doc() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn h32(v: &Value) -> [u8; 32] {
    hex::decode(v.as_str().unwrap()).unwrap().try_into().unwrap()
}

fn h32s(v: &Value) -> Vec<[u8; 32]> {
    v.as_array().unwrap().iter().map(h32).collect()
}

fn tx_from(v: &Value) -> Transaction {
    Transaction {
        version: v["version"].as_u64().unwrap() as u32,
        inputs: v["inputs"].as_array().unwrap().iter().map(|i| TxInput {
            prev_txid: h32(&i["prev_txid"]),
            prev_index: i["prev_index"].as_u64().unwrap() as u32,
            script_sig: hex::decode(i["script_sig"].as_str().unwrap()).unwrap(),
            sequence: i["sequence"].as_u64().unwrap() as u32,
        }).collect(),
        outputs: v["outputs"].as_array().unwrap().iter().map(|o| TxOutput {
            value: o["value"].as_u64().unwrap(),
            script_pubkey: hex::decode(o["script_pubkey"].as_str().unwrap()).unwrap(),
        }).collect(),
        locktime: v["locktime"].as_u64().unwrap() as u32,
    }
}

#[test]
fn constants_match_the_reference() {
    let d = doc();
    let c = &d["constants"];
    assert_eq!(c["merkle_leaf_tag"].as_str().unwrap().as_bytes(), block_rules::MERKLE_LEAF_TAG);
    assert_eq!(c["merkle_node_tag"].as_str().unwrap().as_bytes(), block_rules::MERKLE_NODE_TAG);
    assert_eq!(c["parents_tag"].as_str().unwrap().as_bytes(), block_rules::PARENTS_TAG);
    assert_eq!(c["coinbase_commitment_tag"].as_str().unwrap().as_bytes(), &block_rules::COINBASE_COMMITMENT_TAG);
    assert_eq!(c["coinbase_commitment_len"].as_u64().unwrap() as usize, block_rules::COINBASE_COMMITMENT_LEN);
    assert_eq!(h32(&c["coinbase_wtxid"]), block_rules::COINBASE_WTXID);
    assert_eq!(c["forbidden_txid_preimage_len"].as_u64().unwrap() as usize, block_rules::FORBIDDEN_TXID_PREIMAGE_LEN);
    assert_eq!(c["mainnet_hardening_activation_height"].as_u64().unwrap(), activation::MAINNET_HARDENING_ACTIVATION_HEIGHT);
}

#[test]
fn merkle_roots_and_branches_match() {
    let d = doc();
    let cases = d["merkle"].as_array().unwrap();
    assert!(cases.len() >= 10);
    for v in cases {
        let ids = h32s(&v["ids"]);
        assert_eq!(block_rules::legacy_merkle_root(&ids).0, h32(&v["legacy_root"]), "{v}");
        assert_eq!(block_rules::tagged_merkle_root(&ids).0, h32(&v["tagged_root"]), "{v}");
        assert_eq!(block_rules::coinbase_merkle_branch(&ids, false), h32s(&v["legacy_coinbase_branch"]));
        assert_eq!(block_rules::coinbase_merkle_branch(&ids, true), h32s(&v["tagged_coinbase_branch"]));
    }
}

/// VAL-10: the duplicated-tail mutations keep the legacy root and change the
/// tagged one.
#[test]
fn mutation_vectors_match() {
    let d = doc();
    for v in d["mutation"].as_array().unwrap() {
        let ids = h32s(&v["ids"]);
        let mutated = h32s(&v["mutated_ids"]);
        assert_eq!(block_rules::legacy_merkle_root(&ids), block_rules::legacy_merkle_root(&mutated));
        assert_eq!(block_rules::tagged_merkle_root(&ids).0, h32(&v["tagged_root"]));
        assert_eq!(block_rules::tagged_merkle_root(&mutated).0, h32(&v["mutated_tagged_root"]));
        assert_ne!(v["tagged_root"], v["mutated_tagged_root"]);
    }
}

#[test]
fn transaction_encodings_ids_and_the_64_byte_rule_match() {
    let d = doc();
    let cases = d["transactions"].as_array().unwrap();
    assert!(cases.iter().any(|v| v["forbidden_64"] == true));
    for v in cases {
        let tx = tx_from(&v["tx"]);
        assert_eq!(hex::encode(tx.to_wire_bytes(true)), v["wire_hex"].as_str().unwrap(), "{}", v["note"]);
        assert_eq!(tx.wire_size(true), tx.to_wire_bytes(true).len());
        assert_eq!(block_rules::txid_preimage_len(&tx) as u64, v["txid_preimage_len"].as_u64().unwrap());
        assert_eq!(tx.txid(), h32(&v["txid"]), "{}", v["note"]);
        assert_eq!(tx.wtxid(), h32(&v["wtxid"]), "{}", v["note"]);
        let forbidden = v["forbidden_64"].as_bool().unwrap();
        assert_eq!(block_rules::check_tx_not_64_bytes(&tx).is_err(), forbidden, "{}", v["note"]);
    }
}

/// Blocks built by the reference: the Rust commitment, witness root and
/// header roots agree, the block passes the context-free hardening checks
/// at/after the activation, and its header root under the legacy rule is the
/// legacy root.
#[test]
fn block_commitments_match() {
    let d = doc();
    let cases = d["blocks"].as_array().unwrap();
    assert!(cases.len() >= 3);
    for v in cases {
        let height = v["height"].as_u64().unwrap();
        let parents = h32s(&v["parents"]);
        let txs: Vec<Transaction> = v["transactions"].as_array().unwrap().iter().map(tx_from).collect();
        assert_eq!(block_rules::parents_commitment(&parents), h32(&v["parents_commitment"]));
        assert_eq!(block_rules::witness_root(&txs).0, h32(&v["witness_root"]));
        let mut block = Block {
            header: BlockHeader { version: 1, parents, merkle_root: MerkleRoot::ZERO, timestamp: 0, bits: 0, nonce: 0 },
            transactions: txs,
            blue_score: height,
            height,
            shielded_transactions: vec![],
            powit: Default::default(),
        };
        assert_eq!(hex::encode(block_rules::expected_coinbase_commitment(&block)), v["coinbase_commitment"].as_str().unwrap());
        assert_eq!(block.body_merkle_root_at(0).0, h32(&v["tagged_header_root"]));
        assert_eq!(block.body_merkle_root_at(activation::NEVER).0, h32(&v["legacy_header_root"]));
        assert_eq!(block.body_merkle_root_at(height + 1).0, h32(&v["legacy_header_root"]), "one below activation");
        block.header.merkle_root = MerkleRoot(h32(&v["tagged_header_root"]));
        assert_eq!(block_rules::check_block_hardened_at(&block, height), Ok(()));
        assert_eq!(block.validate_structure_without_pow_at(height), Ok(()));
        // Every other activation height at or below the block's height agrees.
        assert_eq!(block_rules::check_block_hardened_at(&block, 0), Ok(()));
        assert!(core::limits::check_block_context_free(&block).is_ok());
    }
}
