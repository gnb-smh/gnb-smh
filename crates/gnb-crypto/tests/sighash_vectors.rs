//! Sighash v2 and v3 against the normative Python reference
//! (`reference/gnb_sighash.py` -> `reference/sighash_vectors.json`), audit
//! CRY-3: the v3 digest (every intermediate hash and the 195-byte preimage),
//! its error cases, the v3 component messages (CRY-2), and the historical v2
//! digest, which must never change (the reference re-derives its bincode body
//! byte by byte, so the digest no longer depends on a serialization library).

use gnb_crypto::core::sighash::{SighashError, SighashV3Precomputed};
use gnb_crypto::core::{ChainId, Transaction, TxOutput};
use gnb_crypto::crypto;
use serde_json::Value;

const VECTORS: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../reference/sighash_vectors.json"));

fn doc() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn chain(v: &Value) -> ChainId {
    match v["chain_id"].as_u64().unwrap() {
        0x474E_0001 => ChainId::Mainnet,
        0x474E_0002 => ChainId::Testnet,
        other => panic!("unknown chain id {other:#x}"),
    }
}

fn tx(d: &Value, v: &Value) -> Transaction {
    let hex_tx = d["transactions"][v["tx"].as_str().unwrap()].as_str().unwrap();
    let bytes = hex::decode(hex_tx).unwrap();
    let tx = Transaction::from_wire_bytes(&bytes).unwrap();
    assert_eq!(tx.to_wire_bytes(true), bytes, "vector transaction must round-trip");
    tx
}

fn spent(d: &Value, v: &Value) -> Vec<TxOutput> {
    d["spent_outputs"][v["spent"].as_str().unwrap()].as_array().unwrap().iter().map(|o| TxOutput {
        value: o["value"].as_str().unwrap().parse().unwrap(),
        script_pubkey: hex::decode(o["script_pubkey"].as_str().unwrap()).unwrap(),
    }).collect()
}

fn idx(v: &Value) -> usize {
    v["input_index"].as_u64().unwrap() as usize
}

#[test]
fn reference_uses_the_chain_and_digest_constants() {
    let d = doc();
    let c = &d["constants"];
    assert_eq!(c["chain_mainnet"].as_u64().unwrap(), u64::from(ChainId::Mainnet.to_u32()));
    assert_eq!(c["chain_testnet"].as_u64().unwrap(), u64::from(ChainId::Testnet.to_u32()));
    assert_eq!(c["sighash_v2_domain"].as_str().unwrap(), hex::encode(gnb_crypto::core::SIGHASH_DOMAIN));
    assert_eq!(c["sighash_v3_domain"].as_str().unwrap(), hex::encode(gnb_crypto::core::sighash::SIGHASH_V3_DOMAIN));
    assert_eq!(c["sighash_v3_preimage_len"].as_u64().unwrap() as usize, SIGHASH_V3_PREIMAGE_LEN);
    use gnb_crypto::core::sighash::*;
    let tags = &c["tags"];
    for (k, t) in [("prevouts", TAG_PREVOUTS), ("sequences", TAG_SEQUENCES), ("amounts", TAG_AMOUNTS),
                   ("scripts", TAG_SCRIPTS), ("outputs", TAG_OUTPUTS)] {
        assert_eq!(tags[k].as_str().unwrap().as_bytes(), t);
    }
    assert_eq!(c["component_domain"].as_str().unwrap().as_bytes(), &crypto::TX_SIG_COMPONENT_DOMAIN);
}

#[test]
fn sighash_v2_matches_reference() {
    let d = doc();
    let vs = d["v2"].as_array().unwrap();
    assert!(vs.len() >= 20);
    for v in vs {
        let t = tx(&d, v);
        let got = t.sighash(idx(v), chain(v));
        assert_eq!(hex::encode(got), v["sighash"].as_str().unwrap(), "v2 vector {:?}", v["name"]);
    }
}

/// Belt and braces: two v2 digests hard-coded here, so the v2 digest cannot
/// change even if the vector file were regenerated from a modified reference.
#[test]
fn sighash_v2_pinned_digests() {
    use gnb_crypto::core::{TxInput, TxOutput as Out};
    let one = Transaction {
        version: 1,
        inputs: vec![TxInput { prev_txid: [0x11; 32], prev_index: 0, script_sig: vec![1, 2], sequence: u32::MAX }],
        outputs: vec![Out { value: 100_000_000, script_pubkey: vec![0x22; 20] }],
        locktime: 0,
    };
    assert_eq!(hex::encode(one.sighash(0, ChainId::Mainnet)), PINNED_V2_ONE_MAINNET);
    let two = Transaction {
        version: 1,
        inputs: vec![
            TxInput { prev_txid: [0x01; 32], prev_index: 7, script_sig: b"sig-a".to_vec(), sequence: 1 },
            TxInput { prev_txid: [0x02; 32], prev_index: 0xFFFF, script_sig: b"sig-b".to_vec(), sequence: 0xFFFF_FFFE },
        ],
        outputs: vec![Out { value: 5_000, script_pubkey: vec![0x0A; 20] }, Out { value: 546, script_pubkey: vec![0x0B; 20] }],
        locktime: 12345,
    };
    assert_eq!(hex::encode(two.sighash(1, ChainId::Testnet)), PINNED_V2_TWO_TESTNET_INPUT1);
}

const PINNED_V2_ONE_MAINNET: &str = "211c6d375f6e50a58e09c9f3b914a3ea1fa38698d524ecabc745492e0141babf";
const PINNED_V2_TWO_TESTNET_INPUT1: &str = "9861067cd575299db06a15ee93c68bedcf2e4c8de2d544dc1c586ac7d3813657";

#[test]
fn sighash_v3_matches_reference() {
    let d = doc();
    let vs = d["v3"].as_array().unwrap();
    assert!(vs.len() >= 20);
    for v in vs {
        let name = v["name"].as_str().unwrap();
        let t = tx(&d, v);
        let s = spent(&d, v);
        let pre = SighashV3Precomputed::new(&t, &s).unwrap();
        for (k, h) in [("hash_prevouts", pre.hash_prevouts), ("hash_sequences", pre.hash_sequences),
                       ("hash_amounts", pre.hash_amounts), ("hash_scripts", pre.hash_scripts),
                       ("hash_outputs", pre.hash_outputs)] {
            assert_eq!(hex::encode(h), v[k].as_str().unwrap(), "{k} of {name}");
        }
        let suite = v["suite"].as_u64().unwrap() as u16;
        let p = pre.preimage(idx(v), suite, chain(v)).unwrap();
        assert_eq!(hex::encode(p), v["preimage"].as_str().unwrap(), "preimage of {name}");
        let digest = pre.digest(idx(v), suite, chain(v)).unwrap();
        assert_eq!(hex::encode(digest), v["sighash"].as_str().unwrap(), "sighash of {name}");
        assert_eq!(t.sighash_v3(&s, idx(v), suite, chain(v)).unwrap(), digest);
    }
    // Every suite id, including reserved ones, gives a distinct digest.
    let suites: std::collections::BTreeSet<u64> = vs.iter().map(|v| v["suite"].as_u64().unwrap()).collect();
    assert_eq!(suites.into_iter().collect::<Vec<_>>(), vec![0x0000, 0x0001, 0x0002, 0xFFFF]);
}

#[test]
fn sighash_v3_errors_match_reference() {
    let d = doc();
    for v in d["v3_errors"].as_array().unwrap() {
        let t = tx(&d, v);
        let s = spent(&d, v);
        let suite = v["suite"].as_u64().unwrap() as u16;
        let err = SighashV3Precomputed::new(&t, &s).and_then(|p| p.digest(idx(v), suite, chain(v))).unwrap_err();
        let kind = match err {
            SighashError::InputIndexOutOfRange { .. } => "InputIndexOutOfRange",
            SighashError::SpentOutputCount { .. } => "SpentOutputCount",
            SighashError::TooLarge(_) => "TooLarge",
        };
        assert_eq!(kind, v["error"].as_str().unwrap(), "{:?}", v["name"]);
    }
}

#[test]
fn component_messages_match_reference() {
    let d = doc();
    let ms = d["component_messages"].as_array().unwrap();
    assert_eq!(ms.len(), 4);
    for m in ms {
        let digest: [u8; 32] = hex::decode(m["digest"].as_str().unwrap()).unwrap().try_into().unwrap();
        let got = crypto::bound_component_message(
            m["suite"].as_u64().unwrap() as u16, m["component"].as_u64().unwrap() as u8, &digest);
        assert_eq!(hex::encode(got), m["message"].as_str().unwrap());
    }
}
