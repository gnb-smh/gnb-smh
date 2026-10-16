// Fixed BIP380 checksums supplied by the independent Python implementation.
// These synthetic public bytes test format identity, not private-key ownership.
fn descriptor_rpc_fixtures(network: &str) -> Vec<(&'static str, String)> {
    let key = "42".repeat(3745);
    let policy = format!("policy(1,0,0,{key})");
    let expressions = [format!("pkh({key})"), policy.clone(), format!("tree({policy},policy(1,1,0,{key}))")];
    let sums = if network == "mainnet" { ["mmmqtmd0", "fczqcm2g", "m77axt4v"] } else { ["n29qfpyk", "slrf030f", "5j236sxv"] };
    ["pkh", "policy", "tree"].into_iter().zip(expressions).zip(sums)
        .map(|((kind, expression), sum)| (kind, format!("gnbd1({network},{expression})#{sum}"))).collect()
}

async fn descriptor_rpc_matrix(network: &str) {
    let (_tmp, state) = state_with_chain(1);
    assert_eq!(dispatch("getnetworkinfo", None, &state).await["network"], network,
        "existing node-network RPC positive control");
    for (kind, descriptor) in descriptor_rpc_fixtures(network) {
        let before = state.store.storage_reads();
        let info = dispatch("getdescriptorinfo", Some(&json!([descriptor])), &state).await;
        assert_eq!(info["kind"], kind, "missing inspect: {info}");
        assert_eq!(info["descriptor"], descriptor);
        assert_eq!(info["network"], network);
        assert_eq!(info["requires_policy_tree_activation"], kind == "tree");
        let script = hex::decode(info["script_pubkey"].as_str().unwrap()).unwrap();
        assert_eq!(crate::address::parse_destination(info["address"].as_str().unwrap()).unwrap().1, script);
        assert_eq!(crate::address::parse_destination(info["bech32m"].as_str().unwrap()).unwrap().1, script);
        assert_eq!(dispatch("deriveaddresses", Some(&json!([descriptor])), &state).await, json!([info["address"]]));
        assert_eq!(state.store.storage_reads() - before, 0, "public descriptors must not query storage");
    }
    let other = if network == "mainnet" { "testnet" } else { "mainnet" };
    for (_, descriptor) in descriptor_rpc_fixtures(other) {
        for method in ["getdescriptorinfo", "deriveaddresses"] {
            let before = state.store.storage_reads();
            let result = dispatch(method, Some(&json!([descriptor])), &state).await;
            assert!(result["error"].as_str().unwrap_or("").contains("network"), "{method}: {result}");
            assert_eq!(state.store.storage_reads() - before, 0);
        }
    }
}

#[tokio::test]
async fn descriptor_rpc_mainnet_static_kinds_and_aliases() {
    descriptor_rpc_matrix("mainnet").await;
}

#[tokio::test]
async fn descriptor_rpc_rejects_argument_and_checksum_variants() {
    let (_tmp, state) = state_with_chain(1);
    let descriptor = &descriptor_rpc_fixtures("mainnet")[0].1;
    assert_eq!(dispatch("getdescriptorinfo", Some(&json!([descriptor])), &state).await["kind"], "pkh");
    let invalid = [Value::Null, json!([]), json!([descriptor, 0]), json!([0]), json!({"descriptor":descriptor}), json!([format!("{descriptor}! ")]), json!([descriptor.split('#').next().unwrap()])];
    for method in ["getdescriptorinfo", "deriveaddresses"] {
        assert!(dispatch(method, None, &state).await.get("error").is_some());
        for params in &invalid {
            let before = state.store.storage_reads();
            assert!(dispatch(method, Some(params), &state).await.get("error").is_some(), "{method}: {params}");
            assert_eq!(state.store.storage_reads() - before, 0);
        }
    }
}

#[test]
fn descriptor_rpc_testnet_isolated() {
    const CHILD: &str = "GNB_R5_DESCRIPTOR_TESTNET_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "rpc::audit_2026_10_rpc_tests::descriptor_rpc_testnet_isolated", "--nocapture"])
            .env(CHILD, "1").output().unwrap();
        assert!(out.status.success(), "isolated testnet failed:\n{}\n{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(String::from_utf8_lossy(&out.stdout).contains("1 passed"));
        return;
    }
    crate::core::set_node_chain_id(crate::core::ChainId::Testnet).unwrap();
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
        .block_on(descriptor_rpc_matrix("testnet"));
}

#[tokio::test]
async fn descriptor_rpc_existing_validation_positive_control() {
    let (_tmp, state) = state_with_chain(1);
    let address = crate::address::Address::from_hash([42;20], crate::address::Network::Mainnet).to_string();
    assert_eq!(dispatch("validateaddress", Some(&json!([address])), &state).await["isvalid"], true);
}
