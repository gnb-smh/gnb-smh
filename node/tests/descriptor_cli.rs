//! Runtime tests through the actual CLI binary, with no node or secret keys.
use serde_json::{json, Value};
use std::process::{Command, Output, Stdio};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_gnb-cli"))
        .args(args).env_remove("GNB_RPC_API_KEY").stdin(Stdio::null())
        .output().expect("run offline CLI")
}

fn ok(out: Output) -> Value {
    assert!(out.status.success(), "CLI failed: {}", String::from_utf8_lossy(&out.stderr));
    serde_json::from_slice(&out.stdout).expect("JSON result")
}

fn body(network: &str) -> String {
    format!("gnbd1({network},pkh({}))", "42".repeat(3745))
}

#[test]
fn descriptor_cli_existing_help_positive_control() {
    let out = run(&["--help"]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("policyaddress"));
}

#[test]
fn descriptor_cli_create_and_inspect_are_offline_and_network_bound() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("body.txt");
    let descriptor = tmp.path().join("descriptor.txt");
    for (network, flag, other) in [("mainnet", "--mainnet", "--testnet"), ("testnet", "--testnet", "--mainnet")] {
        std::fs::write(&input, body(network)).unwrap();
        let created = ok(run(&["descriptor", "create", input.to_str().unwrap(), flag]));
        assert_eq!(created["network"], network);
        assert_eq!(created["kind"], "pkh");
        assert_eq!(created["requires_policy_tree_activation"], false);
        std::fs::write(&descriptor, created["descriptor"].as_str().unwrap()).unwrap();
        assert_eq!(ok(run(&["descriptor", "inspect", descriptor.to_str().unwrap(), flag])), created);
        let rejected = run(&["descriptor", "inspect", descriptor.to_str().unwrap(), other]);
        assert!(!rejected.status.success());
        assert!(String::from_utf8_lossy(&rejected.stderr).contains("network"));
    }
}

#[test]
fn descriptor_cli_public_pool_roundtrip_preserves_order_and_never_overwrites() {
    let tmp = tempfile::tempdir().unwrap();
    let keys = tmp.path().join("keys.json");
    let pool = tmp.path().join("public-pool.json");
    let list = tmp.path().join("descriptors.json");
    let copy = tmp.path().join("copy.json");
    std::fs::write(&keys, json!(["42".repeat(3745), "43".repeat(3745)]).to_string()).unwrap();
    let created = ok(run(&["descriptor", "pool", keys.to_str().unwrap(), pool.to_str().unwrap(), "--mainnet"]));
    assert_eq!(created["count"], 2);
    let saved = std::fs::read_to_string(&pool).unwrap();
    assert_eq!(created["bundle"], saved);
    assert_eq!(ok(run(&["descriptor", "import", pool.to_str().unwrap(), "--mainnet"])), created);
    let descriptors: Vec<_> = created["entries"].as_array().unwrap().iter().map(|e| e["descriptor"].clone()).collect();
    std::fs::write(&list, json!(descriptors).to_string()).unwrap();
    assert_eq!(ok(run(&["descriptor", "export", list.to_str().unwrap(), copy.to_str().unwrap(), "--mainnet"])), created);
    assert_eq!(std::fs::read_to_string(&copy).unwrap(), saved);
    let refused = run(&["descriptor", "pool", keys.to_str().unwrap(), pool.to_str().unwrap(), "--mainnet"]);
    assert!(!refused.status.success());
    assert_eq!(std::fs::read_to_string(&pool).unwrap(), saved);
}
