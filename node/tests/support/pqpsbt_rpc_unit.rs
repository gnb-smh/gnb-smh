// Included inside rpc::audit_2026_10_rpc_tests so the production router and
// its normal blocking dispatch, authentication and body reader are exercised.
fn pqpsbt_fixture(inputs: usize, keys: usize, signed: usize) -> gnb_crypto::wallet::pqpsbt::PqPsbt {
    let wallets: Vec<_> = (0..keys)
        .map(|_| gnb_crypto::wallet::generate_keypair(false))
        .collect();
    let policy = crate::core::policy::SpendPolicy::new(
        keys as u8,
        wallets.iter().map(|k| k.public_key.clone()).collect(),
        0,
        0,
    )
    .unwrap();
    let outpoints: Vec<_> = (0..inputs)
        .map(|i| ([i as u8 + 50; 32], 0, 10_000_000))
        .collect();
    let mut spend = gnb_crypto::wallet::policy_spend::PolicySpend::new(
        crate::address::Network::Mainnet,
        policy,
        &outpoints,
        vec![90; 20],
        1_000_000,
        50_000,
        0,
    )
    .unwrap();
    spend.target_height(17500).unwrap();
    for key in wallets.iter().take(signed) {
        spend
            .sign_digest(&key.public_key, |d, v| key.sign_tx_digest(d, v))
            .unwrap();
    }
    gnb_crypto::wallet::pqpsbt::PqPsbt::from_policy_spend(spend).unwrap()
}

#[tokio::test]
async fn pqpsbt_rpc_requires_a_key_even_for_trusted_loopback_and_private_peers() {
    let (_tmp, mut state) = state_with_chain(1);
    state.trust_loopback = true;
    state.trust_private_ranges = true;
    let (status, _) = post_raw(
        &state,
        "127.0.0.1:5000",
        &[],
        rpc_body("getblockcount", json!([])),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "ordinary reads preserve their policy"
    );
    let request = json!({"action":"decode","hex":"00"});
    for key in [None, Some("operator-key".to_owned())] {
        state.api_key = key;
        for peer in [
            "127.0.0.1:5000",
            "[::1]:5000",
            "[::ffff:127.0.0.1]:5000",
            "10.0.0.2:5000",
        ] {
            let (status, _) =
                post_raw(&state, peer, &[], rpc_body("pqpsbt", request.clone())).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{peer}");
        }
    }
    let (status, _) = post_raw(
        &state,
        "127.0.0.1:5000",
        &[("x-forwarded-for", "203.0.113.9")],
        rpc_body("pqpsbt", request.clone()),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "proxy trust does not bypass explicit key authentication"
    );
    let (status, result) = post_raw(
        &state,
        "127.0.0.1:5000",
        &[("x-api-key", "operator-key")],
        rpc_body("pqpsbt", request),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert!(
        result["result"]["error"].is_string(),
        "authorized request reaches strict parser: {result}"
    );
    assert_eq!(
        state.pqpsbt_gate.available_permits(),
        1,
        "parse failure releases gate"
    );
}

#[tokio::test]
async fn pqpsbt_rpc_public_roles_preserve_documents_and_reject_secret_operations() {
    let (_tmp, mut state) = state_with_chain(1);
    state.api_key = Some("operator-key".into());
    let headers = [("x-api-key", "operator-key")];
    let document = pqpsbt_fixture(1, 2, 0);
    let legacy = document.spend.to_json().unwrap();
    let (_, created) = post_raw(
        &state,
        "127.0.0.1:5000",
        &headers,
        rpc_body("pqpsbt", json!({"action":"create","spend_json":legacy})),
    )
    .await;
    let encoded = created["result"]["hex"]
        .as_str()
        .expect("created public document");
    let (_, decoded) = post_raw(
        &state,
        "127.0.0.1:5000",
        &headers,
        rpc_body("pqpsbt", json!({"action":"decode","hex":encoded})),
    )
    .await;
    let json_doc = decoded["result"]["json"]
        .as_str()
        .expect("JSON document remains a string");
    assert_eq!(
        gnb_crypto::wallet::pqpsbt::PqPsbt::from_json(json_doc)
            .unwrap()
            .to_bytes()
            .unwrap(),
        document.to_bytes().unwrap()
    );
    let duplicate = json_doc.replacen("\"format\":", "\"format\":\"gnb-pqpsbt\",\"format\":", 1);
    for request in [
        json!({"action":"sign","hex":encoded}),
        json!({"action":"importprivatekey","private_key":"synthetic"}),
        json!({"action":"decode","hex":encoded,"private_key":"synthetic"}),
        json!({"action":"encode","json":serde_json::from_str::<Value>(json_doc).unwrap()}),
        json!({"action":"encode","json":duplicate}),
    ] {
        let (_, response) = post_raw(
            &state,
            "127.0.0.1:5000",
            &headers,
            rpc_body("pqpsbt", request),
        )
        .await;
        assert!(response["result"]["error"].is_string(), "{response}");
        assert_eq!(state.pqpsbt_gate.available_permits(), 1);
    }
}

#[tokio::test]
async fn pqpsbt_rpc_finalization_budget_singleflight_and_body_limit() {
    let (_tmp, mut state) = state_with_chain(1);
    state.api_key = Some("operator-key".into());
    let headers = [("x-api-key", "operator-key")];
    let full = pqpsbt_fixture(4, 4, 4);
    let request = |p: &gnb_crypto::wallet::pqpsbt::PqPsbt| {
        json!({"action":"finalize","hex":hex::encode(p.to_bytes().unwrap()),
        "network":"mainnet","next_height":"17500","max_fee":"2000000"})
    };
    let permit = state.pqpsbt_gate.try_acquire().unwrap();
    let (_, busy) = post_raw(
        &state,
        "127.0.0.1:5000",
        &headers,
        rpc_body("pqpsbt", request(&full)),
    )
    .await;
    assert!(
        busy["result"]["error"].as_str().unwrap().contains("busy"),
        "{busy}"
    );
    drop(permit);
    // A held unrelated global lock must not prevent this public-data work.
    let dag_lock = state.dag.write();
    let node_lock = state.node_state.write();
    let start = std::time::Instant::now();
    let (status, result) = post_raw(
        &state,
        "127.0.0.1:5000",
        &headers,
        rpc_body("pqpsbt", request(&full)),
    )
    .await;
    let elapsed = start.elapsed();
    drop(node_lock);
    drop(dag_lock);
    assert_eq!(status, StatusCode::OK, "{result}");
    assert!(result["result"]["hex"].is_string(), "{result}");
    let actual_fee = full.spend.amounts.iter().sum::<u64>()
        - full.spend.tx.outputs.iter().map(|o| o.value).sum::<u64>();
    assert_eq!(result["result"]["review"]["fee"], actual_fee.to_string());
    eprintln!("PQ-PSBT RPC budget positive: 4 inputs, 16 partials, core measured 48 verifier calls; router elapsed {elapsed:?}");
    let mut wrong_digest = full.clone();
    wrong_digest.spend.tx.outputs[0].value += 1;
    let (_, rejected) = post_raw(
        &state,
        "127.0.0.1:5000",
        &headers,
        rpc_body("pqpsbt", request(&wrong_digest)),
    )
    .await;
    assert!(rejected["result"]["error"].is_string(), "{rejected}");
    assert_eq!(
        state.pqpsbt_gate.available_permits(),
        1,
        "signature failure releases gate"
    );
    // Input and partial counts are tested independently. The core counter
    // suite measures zero actual verifications when either cap is exceeded.
    for oversized in [pqpsbt_fixture(5, 1, 0), pqpsbt_fixture(4, 5, 5)] {
        let (_, response) = post_raw(
            &state,
            "127.0.0.1:5000",
            &headers,
            rpc_body("pqpsbt", request(&oversized)),
        )
        .await;
        assert!(
            response["result"]["error"]
                .as_str()
                .unwrap()
                .contains("budget"),
            "{response}"
        );
        assert_eq!(state.pqpsbt_gate.available_permits(), 1);
    }
    let huge = rpc_body(
        "pqpsbt",
        json!({"action":"decode","hex":"0".repeat(RPC_MAX_BODY_BYTES)}),
    );
    let (status, _) = post_raw(&state, "127.0.0.1:5000", &headers, huge).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn pqpsbt_getutxos_metadata_cost_is_bounded_to_selected_inputs() {
    let (_tmp, state) = state_with_chain(5);
    state.store.put_meta("tip_hash", &[5; 32]).unwrap();
    let address = crate::address::Address::from_hash([41; 20], crate::address::Network::Mainnet);
    for index in 0..80 {
        state
            .store
            .put_utxo(
                &[42; 32],
                index,
                &TxOutput {
                    value: 1000,
                    script_pubkey: vec![41; 20],
                },
            )
            .unwrap();
    }
    state.store.put_tx_index(&[42; 32], &[2; 32], 2).unwrap();
    let selected: Vec<_> = (0..64u32)
        .map(|index| json!({"txid":hex::encode([42;32]),"index":index}))
        .collect();
    let before = state.store.storage_reads();
    let plain = dispatch("getutxos", Some(&json!([address.to_string(), 80])), &state).await;
    let plain_reads = state.store.storage_reads() - before;
    let before = state.store.storage_reads();
    let result = dispatch(
        "getutxos",
        Some(&json!([address.to_string(), 80, selected])),
        &state,
    )
    .await;
    let reads = state.store.storage_reads() - before;
    assert_eq!(result["utxo_count"], 80, "{result}");
    assert_eq!(
        result["utxos"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r.get("spent_in_mempool").is_some())
            .count(),
        64
    );
    assert!(plain["utxos"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r.get("spent_in_mempool").is_none()));
    assert!(
        reads <= plain_reads + 64 + 16,
        "{reads} vs default {plain_reads}"
    );
    eprintln!("PQ-PSBT metadata storage reads: default={plain_reads}, selected64={reads}");
    let _activation = crate::core::activation::scoped_override(0);
    for hash in [[2; 32], [5; 32]] {
        let data = state.dag.read().get_block_data(&hash).unwrap().clone();
        state.store.put_dag_data(&hash, &data).unwrap();
    }
    let before = state.store.storage_reads();
    let plain = dispatch("getutxos", Some(&json!([address.to_string(), 80])), &state).await;
    let active_plain_reads = state.store.storage_reads() - before;
    let selected: Vec<_> = (0..64u32)
        .map(|index| json!({"txid":hex::encode([42;32]),"index":index}))
        .collect();
    let before = state.store.storage_reads();
    let result = dispatch(
        "getutxos",
        Some(&json!([address.to_string(), 80, selected])),
        &state,
    )
    .await;
    let active_reads = state.store.storage_reads() - before;
    assert_eq!(plain["utxo_count"], 80);
    assert_eq!(
        result["utxos"][0]["confirmations_at_next_block"], 4,
        "{result}"
    );
    assert!(
        active_reads <= active_plain_reads + 64 * 4 + 16,
        "{active_reads} vs post-activation default {active_plain_reads}"
    );
    eprintln!("PQ-PSBT metadata post-activation reads: default={active_plain_reads}, selected64={active_reads}");
    for selected in [
        json!([{"txid":"00","index":0}]),
        json!([{"txid":hex::encode([42;32]),"index":u64::MAX}]),
        json!([{"txid":hex::encode([42;32]),"index":0},{"txid":hex::encode([42;32]),"index":0}]),
    ] {
        let before = state.store.storage_reads();
        let result = dispatch(
            "getutxos",
            Some(&json!([address.to_string(), 1, selected])),
            &state,
        )
        .await;
        assert!(result["error"].is_string());
        assert_eq!(state.store.storage_reads() - before, 0);
    }
}

#[tokio::test]
async fn pqpsbt_getutxos_metadata_uses_consensus_depth_and_detects_pool_spends() {
    let _activation = crate::core::activation::scoped_override(0);
    let (_tmp, state) = state_with_chain(5);
    state.store.put_meta("tip_hash", &[5; 32]).unwrap();
    for hash in [[2; 32], [5; 32]] {
        let data = state.dag.read().get_block_data(&hash).unwrap().clone();
        state.store.put_dag_data(&hash, &data).unwrap();
    }
    let address = crate::address::Address::from_hash([41; 20], crate::address::Network::Mainnet);
    state
        .store
        .put_utxo(
            &[42; 32],
            0,
            &TxOutput {
                value: 1000,
                script_pubkey: vec![41; 20],
            },
        )
        .unwrap();
    // Header height deliberately disagrees with selected depth: subtraction
    // from the reported next height would give zero, but consensus gives 4.
    state
        .store
        .put_tx_index(&[42; 32], &[2; 32], 50_000)
        .unwrap();
    let selected = json!([{"txid":hex::encode([42;32]),"index":0}]);
    let params = json!([address.to_string(), 1, selected]);
    let result = dispatch("getutxos", Some(&params), &state).await;
    assert_eq!(
        result["utxos"][0]["confirmations_at_next_block"], 4,
        "{result}"
    );
    assert_eq!(result["utxos"][0]["spent_in_mempool"], false);
    state
        .mempool
        .add(
            Transaction {
                version: 3,
                inputs: vec![TxInput {
                    prev_txid: [42; 32],
                    prev_index: 0,
                    script_sig: vec![],
                    sequence: u32::MAX,
                }],
                outputs: vec![TxOutput {
                    value: 1,
                    script_pubkey: vec![8; 20],
                }],
                locktime: 0,
            },
            50_000,
        )
        .unwrap();
    let result = dispatch("getutxos", Some(&params), &state).await;
    assert_eq!(result["utxos"][0]["spent_in_mempool"], true, "{result}");
    state.store.put_meta("tip_hash", &[4; 32]).unwrap();
    assert!(dispatch("getutxos", Some(&params), &state).await["error"].is_string());
}
