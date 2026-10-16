// Bounded address fixtures for the RPC boundary; no network traffic is sent.
// Literal v2 vectors were generated independently by the Python reference.
const ADDRESS_V2_MAIN_42: &str = "gnb1zq9g4z52329g4z52329g4z52329g4z5232lk8szw";
const ADDRESS_V2_TEST_42: &str = "tgnb1zq9g4z52329g4z52329g4z52329g4z5232ed3tuc";
const POLICY_V2_MAIN_44: &str = "gnb1zp9skzctpv9skzctpv9skzctpv9skzctpv9skzctpv9skzctpv9skqamypv7";
const POLICY_V2_TEST_44: &str = "tgnb1zp9skzctpv9skzctpv9skzctpv9skzctpv9skzctpv9skzctpv9skqzctyfu";

fn address_frontends_state() -> (TempDir, AppState) {
    let (tmp, state) = state_with_chain(1);
    state.store.ensure_aggregates().unwrap();
    (tmp, state)
}

#[tokio::test]
async fn address_frontends_queries_reject_wrong_network_before_storage() {
    use crate::address::{Address, Network, PolicyAddress};
    let (_tmp, state) = address_frontends_state();
    let main = Address::from_hash([42; 20], Network::Mainnet).to_string();
    let other = Address::from_hash([42; 20], Network::Testnet).to_string();
    state.store.put_utxo(&[43; 32], 0, &TxOutput { value: 12_345, script_pubkey: vec![42; 20] }).unwrap();
    let mut failures = Vec::new();
    for method in ["getbalance", "getutxos", "getaddressinfo", "getaddresshistory", "listtransactions", "getaddressbalance_at_height"] {
        let positive = dispatch(method, Some(&json!([main])), &state).await;
        assert!(positive.get("error").is_none(), "positive {method}: {positive}");
        let before = state.store.storage_reads();
        let rejected = dispatch(method, Some(&json!([other])), &state).await;
        let reads = state.store.storage_reads() - before;
        if rejected["error"] != "address is for Testnet, expected Mainnet" || reads != 0 {
            failures.push(format!("{method}: {rejected}; storage reads {reads}"));
        }
    }
    let script = [vec![crate::core::policy::POLICY_TAG], vec![44; 32]].concat();
    let policy_main = PolicyAddress::from_script(&script, Network::Mainnet).unwrap().to_string();
    let policy_other = PolicyAddress::from_script(&script, Network::Testnet).unwrap().to_string();
    state.store.put_utxo(&[45; 32], 0, &TxOutput { value: 23_456, script_pubkey: script }).unwrap();
    assert_eq!(dispatch("getutxos", Some(&json!([policy_main])), &state).await["satoshis"], "23456");
    let before = state.store.storage_reads();
    let rejected = dispatch("getutxos", Some(&json!([policy_other])), &state).await;
    let reads = state.store.storage_reads() - before;
    if rejected["error"] != "address is for Testnet, expected Mainnet" || reads != 0 {
        failures.push(format!("policy getutxos: {rejected}; storage reads {reads}"));
    }
    state.store.put_meta("tip_hash", &[1; 32]).unwrap();
    state.store.put_tx_index(&[43; 32], &[1; 32], 1).unwrap();
    let selected = json!([{"txid": hex::encode([43; 32]), "index": 0}]);
    let positive = dispatch("getutxos", Some(&json!([main, 1, selected])), &state).await;
    assert_eq!(positive["utxos"][0]["value"], "12345", "selected positive: {positive}");
    let before = state.store.storage_reads();
    let rejected = dispatch("getutxos", Some(&json!([other, 1, selected])), &state).await;
    let reads = state.store.storage_reads() - before;
    if rejected["error"] != "address is for Testnet, expected Mainnet" || reads != 0 {
        failures.push(format!("selected getutxos: {rejected}; storage reads {reads}"));
    }
    assert!(failures.is_empty(), "wrong-network queries were accepted:\n{}", failures.join("\n"));
}

#[tokio::test]
async fn address_frontends_validators_refuse_wrong_network() {
    use crate::address::{Address, Network};
    let (_tmp, state) = address_frontends_state();
    let main = Address::from_hash([42; 20], Network::Mainnet).to_string();
    let other = Address::from_hash([42; 20], Network::Testnet).to_string();
    let mut failures = Vec::new();
    for (method, field) in [("validateaddress", "isvalid"), ("validateaddressverbose", "valid")] {
        assert_eq!(dispatch(method, Some(&json!([main])), &state).await[field], true);
        let result = dispatch(method, Some(&json!([other])), &state).await;
        if result[field] != false || result["reason"] != "address is for Testnet, expected Mainnet" {
            failures.push(format!("{method}: {result}"));
        }
    }
    assert!(failures.is_empty(), "wrong-network validation:\n{}", failures.join("\n"));
}

#[tokio::test]
async fn address_frontends_legacy_aliases_keep_one_index_identity() {
    use crate::address::{Address, Network};
    let (_tmp, state) = address_frontends_state();
    let address = Address::from_hash([42; 20], Network::Mainnet).to_string();
    let bloch = address.replacen("gnb1q", "bloch1q", 1);
    state.store.put_utxo(&[43; 32], 0, &TxOutput { value: 12_345, script_pubkey: vec![42; 20] }).unwrap();
    for alias in [&address, &bloch] {
        let balance = dispatch("getbalance", Some(&json!([alias])), &state).await;
        assert_eq!(balance["satoshis"], "12345");
        assert_eq!(balance["utxo_count"], 1);
        let utxos = dispatch("getutxos", Some(&json!([alias])), &state).await;
        assert_eq!(utxos["returned"], 1);
        assert_eq!(utxos["utxos"][0]["txid"], hex::encode([43; 32]));
    }
    assert_eq!(dispatch("getaddresscount", None, &state).await["addresses_with_balance"], 1);
}

#[tokio::test]
async fn address_frontends_validators_share_legacy_alias_parser() {
    use crate::address::{Address, Network};
    let (_tmp, state) = address_frontends_state();
    let main = Address::from_hash([42; 20], Network::Mainnet).to_string();
    let bloch = main.replacen("gnb1q", "bloch1q", 1);
    assert!(Address::parse(&bloch).is_ok());
    for (method, field) in [("validateaddress", "isvalid"), ("validateaddressverbose", "valid")] {
        assert_eq!(dispatch(method, Some(&json!([main])), &state).await[field], true);
        assert_eq!(dispatch(method, Some(&json!([bloch])), &state).await[field], true, "{method} must use the already accepted alias parser");
    }
}

#[tokio::test]
async fn address_frontends_v2_aliases_keep_existing_index_identity() {
    use crate::address::{Address, Network, PolicyAddress};
    let (_tmp, state) = address_frontends_state();
    let legacy = Address::from_hash([42; 20], Network::Mainnet).to_string();
    state.store.put_utxo(&[43; 32], 0, &TxOutput { value: 12_345, script_pubkey: vec![42; 20] }).unwrap();
    let tx = Transaction { version: 1, inputs: vec![],
        outputs: vec![TxOutput { value: 12_345, script_pubkey: vec![42; 20] }], locktime: 0 };
    state.store.index_tx_addresses(&tx, 0, 0).unwrap();
    for method in ["getbalance", "getutxos", "getaddressinfo", "getaddresshistory", "listtransactions", "getaddressbalance_at_height"] {
        let mut old = dispatch(method, Some(&json!([legacy])), &state).await;
        assert!(old.get("error").is_none(), "legacy positive {method}: {old}");
        let mut new = dispatch(method, Some(&json!([ADDRESS_V2_MAIN_42])), &state).await;
        assert!(new.get("error").is_none(), "v2 {method}: {new}");
        old.as_object_mut().unwrap().remove("address");
        new.as_object_mut().unwrap().remove("address");
        assert_eq!(old, new, "{method}: aliases must query the same index identity");
    }
    assert_eq!(dispatch("getaddresscount", None, &state).await["addresses_with_balance"], 1);
    let script = [vec![crate::core::policy::POLICY_TAG], vec![44; 32]].concat();
    let policy = PolicyAddress::from_script(&script, Network::Mainnet).unwrap();
    state.store.put_utxo(&[45; 32], 0, &TxOutput { value: 23_456, script_pubkey: script }).unwrap();
    let old = dispatch("getutxos", Some(&json!([policy.to_string()])), &state).await;
    let new = dispatch("getutxos", Some(&json!([POLICY_V2_MAIN_44])), &state).await;
    assert_eq!(new["satoshis"], "23456", "{new}");
    assert_eq!(old["utxos"], new["utxos"]);
    assert_eq!(old["returned"], new["returned"]);
    // The existing holder/history APIs are single-key only. A policy alias
    // must not be truncated into a 20-byte identity by accepting v2.
    for method in ["getbalance", "getaddressinfo", "getaddresshistory", "listtransactions", "getaddressbalance_at_height"] {
        for input in [policy.to_string().as_str(), POLICY_V2_MAIN_44] {
            let before = state.store.storage_reads();
            assert_eq!(dispatch(method, Some(&json!([input])), &state).await["error"], "invalid address");
            assert_eq!(state.store.storage_reads() - before, 0);
        }
    }
    for other in [ADDRESS_V2_TEST_42, POLICY_V2_TEST_44] {
        let before = state.store.storage_reads();
        assert_eq!(dispatch("getutxos", Some(&json!([other])), &state).await["error"],
            "address is for Testnet, expected Mainnet");
        assert_eq!(state.store.storage_reads() - before, 0);
    }
}

#[tokio::test]
async fn address_frontends_explicit_v2_conversion_preserves_legacy_default() {
    use crate::address::{Address, Network, PolicyAddress};
    let (_tmp, state) = address_frontends_state();
    let single = Address::from_hash([42; 20], Network::Mainnet).to_string();
    let script = [vec![crate::core::policy::POLICY_TAG], vec![44; 32]].concat();
    let policy = PolicyAddress::from_script(&script, Network::Mainnet).unwrap().to_string();
    for (legacy, v2) in [(&single, ADDRESS_V2_MAIN_42), (&policy, POLICY_V2_MAIN_44)] {
        for (method, field) in [("validateaddress", "isvalid"), ("validateaddressverbose", "valid")] {
            for input in [legacy.as_str(), v2] {
                let response = dispatch(method, Some(&json!([input])), &state).await;
                assert_eq!(response[field], true, "{method}: {response}");
                assert_eq!(response["address"], input);
                assert_eq!(response["canonical_address"], *legacy);
                assert_eq!(response["bech32m"], v2, "{method}: {response}");
                assert_eq!(response["network"], "mainnet");
            }
        }
    }
}

#[tokio::test]
async fn address_frontends_malformed_inputs_remain_invalid() {
    use crate::address::{Address, Network};
    let (_tmp, state) = address_frontends_state();
    let mut bad_checksum = Address::from_hash([42; 20], Network::Mainnet).to_string();
    let replacement = if bad_checksum.ends_with('0') { "1" } else { "0" };
    bad_checksum.replace_range(bad_checksum.len() - 1.., replacement);
    for input in ["", "gnb1q00", bad_checksum.as_str()] {
        for method in ["getbalance", "getutxos", "getaddressinfo", "getaddresshistory", "listtransactions", "getaddressbalance_at_height"] {
            assert_eq!(dispatch(method, Some(&json!([input])), &state).await["error"], "invalid address", "{method}");
        }
        for (method, field) in [("validateaddress", "isvalid"), ("validateaddressverbose", "valid")] {
            let response = dispatch(method, Some(&json!([input])), &state).await;
            assert_eq!(response[field], false);
            assert!(response.get("bech32m").is_none());
        }
    }
}

// Chain ID is process-global and immutable. Run the testnet matrix in its
// own test-harness process instead of changing other tests' consensus context.
#[test]
fn address_frontends_testnet_rpc_isolated() {
    const CHILD_ENV: &str = "GNB_R4_ADDRESS_TESTNET_CHILD";
    if std::env::var_os(CHILD_ENV).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "rpc::audit_2026_10_rpc_tests::address_frontends_testnet_rpc_isolated", "--nocapture"])
            .env(CHILD_ENV, "1")
            .output().expect("run isolated testnet test");
        assert!(output.status.success(), "testnet child failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        return;
    }
    crate::core::set_node_chain_id(crate::core::ChainId::Testnet).unwrap();
    assert_eq!(crate::core::node_chain_id(), crate::core::ChainId::Testnet);
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        use crate::address::{Address, Network};
        let (_tmp, state) = address_frontends_state();
        let address = Address::from_hash([42; 20], Network::Testnet).to_string();
        let other = Address::from_hash([42; 20], Network::Mainnet).to_string();
        state.store.put_utxo(&[43; 32], 0, &TxOutput { value: 12_345, script_pubkey: vec![42; 20] }).unwrap();
        let mut failures = Vec::new();
        for method in ["getbalance", "getutxos", "getaddressinfo", "getaddresshistory", "listtransactions", "getaddressbalance_at_height"] {
            let positive = dispatch(method, Some(&json!([address])), &state).await;
            assert!(positive.get("error").is_none(), "testnet positive {method}: {positive}");
            let before = state.store.storage_reads();
            let result = dispatch(method, Some(&json!([other])), &state).await;
            let reads = state.store.storage_reads() - before;
            if result["error"] != "address is for Mainnet, expected Testnet" || reads != 0 {
                failures.push(format!("{method}: {result}; storage reads {reads}"));
            }
        }
        for (method, field) in [("validateaddress", "isvalid"), ("validateaddressverbose", "valid")] {
            assert_eq!(dispatch(method, Some(&json!([address])), &state).await[field], true);
            let result = dispatch(method, Some(&json!([other])), &state).await;
            if result[field] != false || result["reason"] != "address is for Mainnet, expected Testnet" {
                failures.push(format!("{method}: {result}"));
            }
        }
        assert!(failures.is_empty(), "testnet matrix:\n{}", failures.join("\n"));
    });
}
