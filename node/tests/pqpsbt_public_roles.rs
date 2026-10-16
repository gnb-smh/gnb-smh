//! Public CLI roles share the strict core and never require an RPC node or wallet.
use gnb::wallet::pqpsbt::{PqPsbt, SignContext};
use serde_json::{json, Value};

fn role(request: Value) -> Value {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("request.json");
    std::fs::write(&file, serde_json::to_vec(&request).unwrap()).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_gnb-cli"))
        .args([
            "--rpc-url",
            "http://127.0.0.1:1",
            "pqpsbt",
            file.to_str().unwrap(),
        ])
        .env_remove("GNB_RPC_API_KEY")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn pqpsbt_public_cli_two_of_three_create_update_combine_finalize_extract() {
    let keys: Vec<_> = (0..3)
        .map(|_| gnb::wallet::generate_keypair(false))
        .collect();
    let policy = gnb::core::policy::SpendPolicy::new(
        2,
        keys.iter().map(|k| k.public_key.clone()).collect(),
        0,
        0,
    )
    .unwrap();
    let mut spend = gnb::wallet::policy_spend::PolicySpend::new(
        gnb::address::Network::Mainnet,
        policy,
        &[([7; 32], 0, 10_000_000)],
        vec![9; 20],
        1_000_000,
        50_000,
        0,
    )
    .unwrap();
    spend.target_height(17500).unwrap();
    let created = role(json!({"action":"create","spend_json":spend.to_json().unwrap()}));
    let decoded = role(json!({"action":"decode","hex":created["hex"]}));
    let encoded = role(json!({"action":"encode","json":decoded["json"]}));
    assert_eq!(created, encoded);
    let document_json: Value = serde_json::from_str(decoded["json"].as_str().unwrap()).unwrap();
    let updated = role(json!({"action":"update","hex":created["hex"],"index":0,
        "input_json":document_json["inputs"][0].to_string()}));
    assert_eq!(created, updated);
    let original =
        PqPsbt::from_bytes(&hex::decode(created["hex"].as_str().unwrap()).unwrap()).unwrap();
    let context = SignContext {
        network: gnb::address::Network::Mainnet,
        next_height: 17500,
        max_fee: 2_000_000,
    };
    let mut a = original.clone();
    let mut b = original.clone();
    a.sign(&context, &keys[0].public_key, |d, v| {
        keys[0].sign_tx_digest(d, v)
    })
    .unwrap();
    b.sign(&context, &keys[1].public_key, |d, v| {
        keys[1].sign_tx_digest(d, v)
    })
    .unwrap();
    let combined = role(
        json!({"action":"combine","hex":hex::encode(a.to_bytes().unwrap()),"other_hex":hex::encode(b.to_bytes().unwrap())}),
    );
    let context_request = |action| json!({"action":action,"hex":combined["hex"],"network":"mainnet","next_height":"17500","max_fee":"2000000"});
    let review = role(context_request("review"));
    let actual_fee = original.spend.amounts.iter().sum::<u64>()
        - original
            .spend
            .tx
            .outputs
            .iter()
            .map(|o| o.value)
            .sum::<u64>();
    assert_eq!(review["review"]["fee"], actual_fee.to_string());
    let finalized = role(context_request("finalize"));
    let extracted = role(context_request("extract"));
    assert_eq!(finalized, extracted);
    let bytes = hex::decode(extracted["hex"].as_str().unwrap()).unwrap();
    let (tx, consumed) = gnb::core::Transaction::read_wire_bytes(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(tx.version, 3);
    assert_eq!(hex::encode(tx.txid()), extracted["txid"]);
}
