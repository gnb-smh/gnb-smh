use super::*;
use gnb::address::Network;
use gnb::core::{Transaction, TxInput, TxOutput};
use gnb::wallet::policy_spend::PolicySpend;
use serde_json::{json, Value};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

struct Fixture {
    spend: PolicySpend,
    keys: Vec<gnb::wallet::Keypair>,
    replies: BTreeMap<String, Value>,
    calls: RefCell<Vec<String>>,
}

impl Fixture {
    fn new(height: u64, after: u32, older: u32) -> Self {
        let keys: Vec<_> = (0..3)
            .map(|_| gnb::wallet::generate_keypair(false))
            .collect();
        let policy = gnb::core::policy::SpendPolicy::new(
            2,
            keys.iter().map(|k| k.public_key.clone()).collect(),
            after,
            older,
        )
        .unwrap();
        let previous = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: [3; 32],
                prev_index: 0,
                script_sig: Vec::new(),
                sequence: u32::MAX,
            }],
            outputs: vec![TxOutput {
                value: 10_000_000,
                script_pubkey: policy.script_pubkey(),
            }],
            locktime: 0,
        };
        let txid = hex::encode(previous.txid());
        let mut spend = PolicySpend::new(
            Network::Mainnet,
            policy,
            &[(previous.txid(), 0, 10_000_000)],
            vec![8; 20],
            1_000_000,
            50_000,
            after,
        )
        .unwrap();
        spend.target_height(height).unwrap();
        let replies = [
            ("getnetworkinfo", json!({"network":"mainnet", "hardening_activation_height":17500})),
            ("getdaginfo", json!({"next_block_height":height,"tip":hex::encode([5;32])})),
            ("getutxos", json!({"truncated":false,"next_block_height":height,"tip":hex::encode([5;32]), "utxos":[{
                "txid":txid, "index":0, "value":"10000000", "script_pubkey":hex::encode(spend.locking_script()),
                "spent_in_mempool":false,"confirmations_at_next_block":height-100
            }]})),
            ("getrawtransaction", json!({"txid":txid, "hex":hex::encode(previous.to_wire_bytes(true)), "in_mempool":false})),
            ("gettransaction", json!({"txid":txid, "block_height":100, "block_hash":hex::encode([4;32])})),
        ].into_iter().map(|(k,v)| (k.to_owned(),v)).collect();
        Self {
            spend,
            keys,
            replies,
            calls: RefCell::new(Vec::new()),
        }
    }

    fn rpc(&self, method: &str, params: &Value) -> Result<Value, String> {
        match method {
            "getnetworkinfo" | "getdaginfo" => assert_eq!(params, &Value::Null),
            "getutxos" => {
                let address = gnb::address::PolicyAddress::from_script(
                    &self.spend.locking_script(),
                    self.spend.network,
                )
                .unwrap();
                let selected: Vec<_> = self.spend.tx.inputs.iter().map(|input|
                    json!({"txid":hex::encode(input.prev_txid),"index":input.prev_index})).collect();
                assert_eq!(
                    params,
                    &json!([
                        address.to_string(),
                        gnb::wallet::send::GETUTXOS_MAX_ROWS,
                        selected
                    ]),
                    "UTXO proof must request the document's address and selected outpoints"
                );
            }
            "getrawtransaction" | "gettransaction" => {
                let arguments = params.as_array().expect("transaction query arguments");
                assert_eq!(arguments.len(), 1);
                assert!(
                    self.spend
                        .tx
                        .inputs
                        .iter()
                        .any(|input| arguments[0] == hex::encode(input.prev_txid)),
                    "previous-transaction proof must request a selected input's transaction"
                );
            }
            _ => panic!("unexpected fixture RPC {method}"),
        }
        self.calls.borrow_mut().push(method.to_owned());
        self.replies
            .get(method)
            .cloned()
            .ok_or_else(|| format!("unexpected method {method}"))
    }

    fn text(&self) -> String {
        self.spend.to_json().unwrap()
    }

    fn refused_before_signer(&self) -> String {
        let opened = Cell::new(0);
        let result = with_policy_preflight(
            &self.text(),
            None,
            2_000_000,
            &|m, p| self.rpc(m, p),
            |_, _, _| {
                opened.set(opened.get() + 1);
                Ok(0)
            },
        );
        assert_eq!(
            opened.get(),
            0,
            "an invalid request reached the key-access callback"
        );
        match result {
            Err(e) => e,
            Ok(_) => panic!("invalid fixture was accepted"),
        }
    }
}

#[test]
fn online_policy_preflight_roundtrip_two_of_three_and_exact_preview() {
    let fixture = Fixture::new(17_499, 0, 0);
    let mut text = fixture.text();
    for key in fixture.keys.iter().take(2) {
        let (document, legacy, _) = with_policy_preflight(
            &text,
            None,
            2_000_000,
            &|m, p| fixture.rpc(m, p),
            |doc, ctx, review| {
                let preview = policy_review_lines(doc, ctx, review).join("\n");
                assert!(preview.contains("Input 0:"));
                assert!(preview.contains("10000000 base units"));
                assert!(preview.contains("Fee:"));
                assert!(preview.contains("Change:"));
                doc.sign(ctx, &key.public_key, |d, v| key.sign_tx_digest(d, v))
            },
        )
        .unwrap();
        assert!(legacy);
        text = document.spend.to_json().unwrap();
    }
    let final_spend = PolicySpend::from_json(&text).unwrap();
    assert_eq!(final_spend.tx.version, 1);
    assert_eq!(final_spend.signers().len(), 2);
    final_spend.finalize().unwrap();
    assert!(fixture
        .calls
        .borrow()
        .iter()
        .any(|m| m == "getrawtransaction"));
    assert_eq!(
        format_base_units(u64::MAX),
        "184467440737.09551615 GNB (18446744073709551615 base units)"
    );
}

#[test]
fn online_policy_preflight_rejects_unavailable_changed_or_malformed_inputs_before_keys() {
    let mut fixture = Fixture::new(17_500, 0, 0);
    let valid = fixture.replies.clone();
    let invalid = [
        (
            "getnetworkinfo",
            json!({"network":"testnet", "hardening_activation_height":0}),
        ),
        (
            "getnetworkinfo",
            json!({"network":"mainnet", "hardening_activation_height":17501}),
        ),
        ("getnetworkinfo", json!({"error":"node unavailable"})),
        ("getdaginfo", json!({"next_block_height":"17500"})),
        ("getdaginfo", json!({"next_block_height":0})),
        ("getdaginfo", json!({"tip_height":u64::MAX})),
        (
            "getutxos",
            json!({"next_block_height":17500,"tip":hex::encode([5;32]),"truncated":true,"utxos":[]}),
        ),
        (
            "getutxos",
            json!({"next_block_height":17500,"tip":hex::encode([5;32]),"truncated":false,"utxos":[]}),
        ),
        ("getutxos", json!({"error":"database unavailable"})),
        (
            "getutxos",
            json!({"next_block_height":17500,"tip":hex::encode([5;32]),"truncated":false,"utxos":"bad"}),
        ),
    ];
    for (method, value) in invalid {
        fixture.replies = valid.clone();
        fixture.replies.insert(method.to_owned(), value);
        fixture.refused_before_signer();
    }
    for (field, value) in [
        ("value", json!("10000001")),
        ("value", json!("18446744073709551616")),
        ("value", json!("-1")),
        ("script_pubkey", json!(hex::encode([8; 20]))),
        ("txid", json!(hex::encode([2; 32]))),
        ("index", json!(u64::MAX)),
        ("coinbase_height", json!(17500)),
        ("coinbase_height", json!(17501)),
        ("coinbase_height", json!("unknown")),
        ("spent_in_mempool", json!(true)),
        ("spent_in_mempool", json!("false")),
    ] {
        fixture.replies = valid.clone();
        fixture.replies.get_mut("getutxos").unwrap()["utxos"][0][field] = value;
        fixture.refused_before_signer();
    }
    fixture.replies = valid;
    let row = fixture.replies["getutxos"]["utxos"][0].clone();
    fixture.replies.get_mut("getutxos").unwrap()["utxos"]
        .as_array_mut()
        .unwrap()
        .push(row);
    fixture.refused_before_signer();
}

#[test]
fn online_policy_preflight_checks_h_minus_one_h_and_never_changes_a_signed_version() {
    let mut fixture = Fixture::new(17_499, 0, 0);
    let k = &fixture.keys[0];
    fixture
        .spend
        .sign_digest(&k.public_key, |d, v| k.sign_tx_digest(d, v))
        .unwrap();
    let original = fixture.spend.tx.to_wire_bytes(true);
    let calls = Cell::new(0);
    with_policy_preflight(
        &fixture.text(),
        None,
        2_000_000,
        &|m, p| fixture.rpc(m, p),
        |_, _, _| {
            calls.set(1);
            Ok(0)
        },
    )
    .unwrap();
    assert_eq!(calls.get(), 1);
    fixture.replies.get_mut("getdaginfo").unwrap()["next_block_height"] = json!(17500);
    fixture.replies.get_mut("getutxos").unwrap()["next_block_height"] = json!(17500);
    fixture.replies.get_mut("getutxos").unwrap()["utxos"][0]["confirmations_at_next_block"] =
        json!(17400);
    let refusal = fixture.refused_before_signer();
    assert!(refusal.starts_with("bad-txns-version:"), "{refusal}");
    assert!(
        refusal.contains("version 1 is invalid at height 17500"),
        "{refusal}"
    );
    assert_eq!(fixture.spend.tx.to_wire_bytes(true), original);
}

#[test]
fn online_policy_preflight_requires_full_hash_checked_previous_transaction_for_v1() {
    let mut fixture = Fixture::new(17_499, 0, 0);
    for response in [
        json!({"error":"pruned"}),
        json!({"hex":"00"}),
        json!({"hex":""}),
    ] {
        fixture.replies.insert("getrawtransaction".into(), response);
        fixture.refused_before_signer();
    }
}

#[test]
fn online_policy_preflight_fee_ceiling_and_override_precede_key_access() {
    let mut fixture = Fixture::new(17_500, 0, 0);
    let locking_script = fixture.spend.locking_script();
    fixture
        .spend
        .tx
        .outputs
        .retain(|o| o.script_pubkey != locking_script);
    assert!(fixture
        .refused_before_signer()
        .to_lowercase()
        .contains("fee"));
    let opened = Cell::new(false);
    with_policy_preflight(
        &fixture.text(),
        None,
        9_000_000,
        &|m, p| fixture.rpc(m, p),
        |_, _, review| {
            opened.set(true);
            assert_eq!(review.fee, 9_000_000);
            Ok(0)
        },
    )
    .unwrap();
    assert!(opened.get());
}

#[test]
fn online_policy_preflight_coinbase_and_relative_locks_fail_closed() {
    let mut fixture = Fixture::new(17_500, 0, 20);
    fixture.replies.get_mut("getutxos").unwrap()["utxos"][0]["confirmations_at_next_block"] =
        json!(19);
    fixture.refused_before_signer();
    fixture.replies.get_mut("getutxos").unwrap()["utxos"][0]["confirmations_at_next_block"] =
        json!(20);
    with_policy_preflight(
        &fixture.text(),
        None,
        2_000_000,
        &|m, p| fixture.rpc(m, p),
        |_, _, _| Ok(0),
    )
    .unwrap();
    fixture.replies.get_mut("getutxos").unwrap()["utxos"][0]["confirmations_at_next_block"] =
        Value::Null;
    fixture.refused_before_signer();
    let mut fixture = Fixture::new(17_500, 0, 0);
    fixture.replies.get_mut("getutxos").unwrap()["utxos"][0]["coinbase_height"] = json!(17400);
    with_policy_preflight(
        &fixture.text(),
        None,
        2_000_000,
        &|m, p| fixture.rpc(m, p),
        |_, _, _| Ok(0),
    )
    .unwrap();
    fixture.replies.get_mut("getutxos").unwrap()["utxos"][0]["coinbase_height"] = json!(17401);
    fixture.refused_before_signer();
}

#[test]
fn online_policy_preflight_refuses_height_changes_and_rpc_transport_errors() {
    let fixture = Fixture::new(17_500, 0, 0);
    let reads = Cell::new(0);
    let result = with_policy_preflight(
        &fixture.text(),
        None,
        2_000_000,
        &|m, p| {
            if m == "getdaginfo" {
                reads.set(reads.get() + 1);
                return Ok(
                    json!({"next_block_height":17500+reads.get()-1,"tip":hex::encode([5;32])}),
                );
            }
            fixture.rpc(m, p)
        },
        |_, _, _| panic!("keys must stay closed across a changed snapshot"),
    );
    assert!(result.is_err());
    let result = with_policy_preflight(
        &fixture.text(),
        None,
        2_000_000,
        &|_, _| Err("connection refused".into()),
        |_, _, _| panic!("keys must stay closed after an RPC transport error"),
    );
    assert!(result.is_err());
}

#[test]
fn online_policy_preflight_refuses_a_reorg_at_the_same_height() {
    let fixture = Fixture::new(17_500, 0, 0);
    let reads = Cell::new(0);
    let result = with_policy_preflight(
        &fixture.text(),
        None,
        2_000_000,
        &|m, p| {
            if m == "getdaginfo" {
                reads.set(reads.get() + 1);
                return Ok(
                    json!({"next_block_height":17500,"tip":hex::encode([reads.get() as u8 + 4;32])}),
                );
            }
            fixture.rpc(m, p)
        },
        |_, _, _| panic!("same-height reorganization must keep keys closed"),
    );
    assert!(result.is_err());
}

#[test]
fn online_policy_preflight_pq_document_preserves_version_and_rejects_duplicate_fields() {
    let fixture = Fixture::new(17_500, 0, 0);
    let document = gnb::wallet::pqpsbt::PqPsbt::from_legacy_json(&fixture.text()).unwrap();
    let original = document.to_json().unwrap();
    let (signed, legacy, _) = with_policy_preflight(
        &original,
        None,
        2_000_000,
        &|m, p| fixture.rpc(m, p),
        |doc, ctx, _| {
            let key = &fixture.keys[0];
            doc.sign(ctx, &key.public_key, |d, v| key.sign_tx_digest(d, v))
        },
    )
    .unwrap();
    assert!(!legacy);
    assert_eq!(signed.spend.tx.version, 3);
    assert_eq!(signed.spend.signers().len(), 1);
    let duplicate = original.replacen("\"format\":", "\"format\":\"gnb-pqpsbt\",\"format\":", 1);
    assert!(with_policy_preflight(
        &duplicate,
        None,
        2_000_000,
        &|_, _| panic!("document parse precedes RPC"),
        |_, _, _| panic!("duplicate fields precede key access")
    )
    .is_err());
    assert!(with_policy_preflight(
        &original,
        Some(Network::Testnet),
        2_000_000,
        &|_, _| panic!("stated network precedes RPC"),
        |_, _, _| panic!("network mismatch precedes keys")
    )
    .is_err());
}

#[test]
fn online_policy_preflight_rejects_valid_bytes_for_the_wrong_previous_transaction() {
    let mut fixture = Fixture::new(17_499, 0, 0);
    let encoded = fixture.replies["getrawtransaction"]["hex"]
        .as_str()
        .unwrap();
    let (mut previous, _) = Transaction::read_wire_bytes(&hex::decode(encoded).unwrap()).unwrap();
    previous.locktime += 1;
    fixture.replies.get_mut("getrawtransaction").unwrap()["hex"] =
        json!(hex::encode(previous.to_wire_bytes(true)));
    fixture.refused_before_signer();
}

#[test]
fn online_policy_preflight_rejects_v3_before_activation_and_unreached_absolute_lock() {
    let mut fixture = Fixture::new(17_499, 0, 0);
    fixture.spend.tx.version = 3;
    assert!(fixture
        .refused_before_signer()
        .contains("non-standard-version"));
    let mut fixture = Fixture::new(17_500, 0, 0);
    fixture.spend.tx.locktime = 17_501;
    assert!(fixture.refused_before_signer().contains("locktime"));
}
