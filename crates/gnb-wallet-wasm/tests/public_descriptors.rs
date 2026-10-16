use gnb_wallet_wasm::handle;
use serde_json::json;

// Public shape fixture accepted by the existing policy predicate; no secret
// key or claim of spendability is associated with these deterministic bytes.
fn key(byte: u8) -> String {
    hex::encode(vec![byte; 3749])
}

#[test]
fn legacy_normalize_control_without_a_session() {
    let address = gnb_crypto::address::Address::from_hash([0; 20],
        gnb_crypto::address::Network::Mainnet).to_string();
    assert_eq!(handle(&json!({"op":"normalize", "address":address})).unwrap(),
        json!({"address":address}));
}

#[test]
fn public_descriptor_creation_preserves_existing_script_without_a_session() {
    for network in ["mainnet", "testnet"] {
        let public_key = key(7);
        let result = handle(&json!({"op":"descriptor", "action":"create", "network":network,
            "body":format!("gnbd1({network},pkh({public_key}))")}));
        assert!(result.is_ok(), "public descriptor creation failed: {result:?}");
        let result = result.unwrap();
        assert_eq!(result["kind"], "pkh");
        assert_eq!(result["network"], network);
        let net = if network == "mainnet" {gnb_crypto::address::Network::Mainnet} else {gnb_crypto::address::Network::Testnet};
        let address = gnb_crypto::address::Address::from_pubkey(&hex::decode(public_key).unwrap(), net);
        assert_eq!(result["address"], address.to_string());
        assert_eq!(result["script_pubkey"], hex::encode(address.hash()));
        assert_eq!(result["bech32m"], address.to_bech32m());
        assert_eq!(result["requires_policy_tree_activation"], false);
    }
}

#[test]
fn public_descriptor_pool_restores_public_identities_without_a_session() {
    let result = handle(&json!({"op":"descriptor", "action":"pool", "network":"testnet",
        "public_keys":[key(1), key(2)]}));
    assert!(result.is_ok(), "public descriptor pool failed: {result:?}");
    let pool = result.unwrap();
    assert_eq!(pool["count"], 2);
    let restored = handle(&json!({"op":"descriptor", "action":"import", "network":"testnet", "bundle":pool["bundle"]})).unwrap();
    assert_eq!(restored, pool);
}
