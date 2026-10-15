//! The data-driven consensus vectors (`reference/tx_vectors.json`,
//! `reference/block_vectors.json`; format and coverage in
//! docs/testing/VECTORS.md) through the node's own validation functions.
//!
//! Transactions: every case is decoded with the gossip/RPC decoder
//! (`admission::decode_tx_strict`), put in its wrapper block
//! `[coinbase, tx]` at the case height, checked with the per-transaction
//! context-free block rules (`Block::validate_coinbase_format`, the 64-byte
//! rule, `Block::validate_dust`, `limits::check_block_context_free`), which
//! must reject exactly the context-free classes (`context_free_expectation`),
//! and then connected with `accept::validate_block_in_view_classified`, the
//! function the acceptance pipeline calls for an extension and every block
//! of a reorg, against a RocksDB store holding exactly the case's prevouts.
//! Mempool admission (`admission::check_transaction`, relay policy,
//! signatures on) runs on the same store at the case height and must accept,
//! or refuse with the recorded class of the first admission rule that
//! refuses, carried by the `AdmissionError` variant that class must come with
//! (`admission_variant`: `Rejected` for a consensus refusal, which the relay
//! may penalise, `NonStandard` for relay policy; a storage or pool error fails
//! the case).
//!
//! Blocks: `Block::from_wire_bytes`, the ingress structure check
//! `Block::validate_structure_without_pow`, `block_rules::check_block_hardened_at`,
//! the pow limit, `Block::validate_pow` for `pow: full`,
//! `limits::check_block_context_free` (together: exactly the context-free
//! class), then `accept::validate_block_in_view_classified` on a store holding
//! the case's prevouts (scope `connect`: decode and the last step only).
//!
//! Activation: an `explicit` case installs its height with
//! `activation::scoped_override`; a `schedule` case installs nothing, so every
//! rule runs under the process-wide height of the node's chain id (mainnet
//! 110,000 here, testnet 0 in the testnet child), which the case thereby pins.
//! The node's chain id is process-wide (`core::set_node_chain_id`, a
//! `OnceLock`), so the testnet cases run in a child process of this test
//! binary (`tx_vectors_testnet`).

#[path = "../../crates/gnb-crypto/tests/consensus_vectors_common/mod.rs"]
mod common;

use common::*;
use gnb::accept;
use gnb::core::{self, activation, block_rules, limits, Block, ChainId};
use gnb::mempool::admission::{self, AdmissionError, AdmissionPolicy};
use gnb::storage::Storage;

/// A RocksDB store holding exactly the `utxo` prevouts, the coinbase height
/// of every coinbase prevout, and a transaction-index row for every prevout
/// txid: a node applies every coin together with its creating transaction's
/// index row (`reorg::apply_block_utxo_mutations`: `put_tx_index` before
/// `put_utxo`), which mempool admission reads ("already confirmed").
fn store_with(prevouts: &[Prevout]) -> (tempfile::TempDir, Storage) {
    let tmp = tempfile::TempDir::new().unwrap();
    let store = Storage::open(&tmp.path().join("db")).unwrap();
    for p in prevouts.iter().filter(|p| !p.block_coinbase) {
        store.put_tx_index(&p.txid, &[0xB0; 32], p.coinbase_height.unwrap_or(0)).unwrap();
        store.put_utxo(&p.txid, p.vout, &p.out()).unwrap();
        if let Some(h) = p.coinbase_height {
            store.put_coinbase_info(&p.txid, h).unwrap();
        }
    }
    (tmp, store)
}

/// The activation height the case's rules run under: its own (installed for
/// the returned guard's lifetime) or, for a `schedule` case, the node's
/// process-wide schedule.
fn activation_for(schedule: bool, recorded: u64) -> (Option<activation::OverrideGuard>, u64) {
    let guard = (!schedule).then(|| activation::scoped_override(recorded));
    (guard, activation::hardening_activation_height())
}

/// The vector class of an admission refusal. The relay-policy refusals are
/// [`AdmissionError::NonStandard`], the consensus ones
/// [`AdmissionError::Rejected`] (MEM-5 verdicts); [`admission_variant`] pins
/// which variant each class must come with.
fn policy_class(e: &AdmissionError) -> String {
    match e {
        AdmissionError::MissingInputs(_) => "missing-input".into(),
        AdmissionError::Immature(_) => "immature-coinbase".into(),
        AdmissionError::LowFee(_) => "low-relay-fee".into(),
        AdmissionError::Duplicate(m) if m == "transaction already confirmed" => "already-confirmed".into(),
        // Never a recorded class: pool-relative refusals cannot happen
        // without a pool, and a storage or pool failure is not a verdict.
        AdmissionError::Duplicate(m)
        | AdmissionError::Conflict(m)
        | AdmissionError::Replacement(m)
        | AdmissionError::ChainLimit(m)
        | AdmissionError::RateLimited(m) => format!("pool: {m}"),
        AdmissionError::Pool(m) => format!("storage/pool error: {m}"),
        AdmissionError::NonStandard(m) => {
            if m.starts_with("non-standard-version") {
                "non-standard-version".into()
            } else if m.contains("single-algorithm signature suite (non-standard") {
                "non-standard-suite".into()
            } else if m.contains("non-canonical") && m.contains("(non-standard)") {
                "non-standard-witness".into()
            } else if m.contains("has zero value (non-standard)") {
                "non-standard-zero-value".into()
            } else if m == "no outputs" {
                "non-standard-no-outputs".into()
            } else if m.starts_with("transaction too large") {
                "non-standard-size".into()
            } else {
                // The version rule and the 64-byte rule for the next block
                // (`admission::check_tx_for_next_block`).
                classify(m).into()
            }
        }
        AdmissionError::Rejected(m) => {
            if m == "no inputs" {
                // Admission's own consensus rule (a zero fee is below the
                // consensus minimum): `Rejected`, not relay policy.
                "no-inputs".into()
            } else if m == "coinbase not accepted" {
                "coinbase-format".into()
            } else if m.contains("bad-witness: the canonical witness is a consensus rule") {
                // `admission::check_witnesses_for_next_block`: version 3 at/after
                // the activation, where the canonical witness is consensus (CRY-1).
                "witness-non-canonical".into()
            } else {
                classify(m).into()
            }
        }
    }
}

/// The [`AdmissionError`] variant a refusal of each policy class must carry
/// (MEM-5 verdicts, `relay::TxRelay`): `Rejected` (consensus-invalid for this
/// exact transaction: the relay reports `Reject` and may penalise the peer)
/// or a policy variant (`Ignore`). The version rule and the 64-byte rule
/// depend on the node's next height, so they are `NonStandard` even where the
/// transaction is consensus-invalid at the case height.
fn admission_variant(class: &str) -> &'static str {
    match class {
        "non-standard-no-outputs" | "non-standard-size" | "non-standard-zero-value" | "non-standard-witness"
        | "non-standard-suite" | "non-standard-version" | "bad-version" | "tx-64-bytes" => "NonStandard",
        "missing-input" => "MissingInputs",
        "immature-coinbase" => "Immature",
        "low-relay-fee" => "LowFee",
        "already-confirmed" => "Duplicate",
        _ => "Rejected",
    }
}

fn variant_name(e: &AdmissionError) -> &'static str {
    match e {
        AdmissionError::Rejected(_) => "Rejected",
        AdmissionError::NonStandard(_) => "NonStandard",
        AdmissionError::MissingInputs(_) => "MissingInputs",
        AdmissionError::Conflict(_) => "Conflict",
        AdmissionError::Replacement(_) => "Replacement",
        AdmissionError::ChainLimit(_) => "ChainLimit",
        AdmissionError::Immature(_) => "Immature",
        AdmissionError::LowFee(_) => "LowFee",
        AdmissionError::Duplicate(_) => "Duplicate",
        AdmissionError::RateLimited(_) => "RateLimited",
        AdmissionError::Pool(_) => "Pool",
    }
}

fn run_tx_vectors(network: &str) -> usize {
    assert_eq!(core::node_chain_id(), chain_of(network), "the process chain id must be the cases' network");
    let v = load_tx_vectors();
    let max_supply = max_supply_sat(&v.constants);
    let mut rep = Report::default();
    let mut n = 0;
    for c in v.cases.iter().filter(|c| c.network == network) {
        n += 1;
        let (_g, act) = activation_for(c.schedule, c.activation);
        let (_tmp, store) = store_with(&c.prevouts);
        let tx = match admission::decode_tx_strict(&c.bytes) {
            Ok(tx) => tx,
            Err(_) => {
                rep.expect(&c.id, "consensus", &want(&c.error), "decode");
                rep.expect(&c.id, "policy class", c.policy_class.as_deref().unwrap_or("accept"), "decode");
                continue;
            }
        };

        // Consensus: the context-free per-transaction rules (exactly the
        // context-free classes), then connect.
        let expected = want(&c.error);
        let block = wrapper_block(&tx, c.height, &c.prevouts);
        let cf = tx_context_free(&block, act).map_err(|e| classify(&e).to_string());
        rep.expect(&c.id, "context-free rules", &context_free_expectation(&expected, &block, max_supply), &verdict(&cf));
        let got = cf.and_then(|()| {
            accept::validate_block_in_view_classified(&store, &block).map_err(|e| classify(&e.reason).to_string())
        });
        rep.expect(&c.id, "consensus", &expected, &verdict(&got));

        // Mempool admission for a block at the case height.
        let adm = admission::check_transaction(&store, None, &tx, &AdmissionPolicy::relay(c.height));
        match &adm {
            Ok(_) => rep.expect(&c.id, "policy", &c.policy, "accept"),
            Err(AdmissionError::Pool(m)) => rep.expect(&c.id, "admission", "a verdict", &format!("storage/pool error: {m}")),
            Err(e) => {
                let class = policy_class(e);
                rep.expect(&c.id, "policy class", c.policy_class.as_deref().unwrap_or("accept"), &class);
                rep.expect(&c.id, "admission verdict", admission_variant(&class), variant_name(e));
                assert_eq!(e.is_consensus_invalid(), variant_name(e) == "Rejected");
            }
        }
    }
    rep.finish(&format!("tx vectors on {network} (node)"));
    n
}

#[test]
fn tx_vectors_mainnet() {
    let n = run_tx_vectors("mainnet");
    assert!(n >= 150, "{n} mainnet cases");
}

/// Re-runs this binary for [`tx_vectors_testnet_child`] with the testnet
/// chain id set in the child process only.
#[test]
fn tx_vectors_testnet() {
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "tx_vectors_testnet_child", "--ignored", "--nocapture", "--test-threads=1"])
        .env("GNB_VECTORS_CHILD", "testnet")
        .output()
        .expect("spawn the test binary");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "testnet child failed:\n{stdout}\n{stderr}");
    assert!(stdout.contains("test result: ok. 1 passed"), "the testnet child did not run:\n{stdout}\n{stderr}");
    eprint!("{stderr}");
}

#[test]
#[ignore = "run by tx_vectors_testnet in a child process (the node chain id is process-wide)"]
fn tx_vectors_testnet_child() {
    if std::env::var("GNB_VECTORS_CHILD").as_deref() != Ok("testnet") {
        eprintln!("skipped: only meaningful in the child process tx_vectors_testnet starts");
        return;
    }
    core::set_node_chain_id(ChainId::Testnet).expect("fresh process");
    let n = run_tx_vectors("testnet");
    assert!(n >= 5, "{n} testnet cases");
}

#[test]
fn block_vectors() {
    let b = load_block_vectors();
    let max_supply = max_supply_sat(&b.constants);
    assert!(b.cases.len() >= 60);
    let mut rep = Report::default();
    for c in &b.cases {
        let (_g, act) = activation_for(c.schedule, c.activation);
        let expected = want(&c.error);
        let block = match Block::from_wire_bytes(&c.bytes) {
            Ok(b) => b,
            Err(_) => {
                rep.expect(&c.id, "block", &expected, "decode");
                continue;
            }
        };
        if c.scope == "full" {
            let cf = (|| -> Result<(), String> {
                block.validate_structure_without_pow().map_err(|e| classify(e).to_string())?;
                block_rules::check_block_hardened_at(&block, act).map_err(|e| classify(e).to_string())?;
                if c.pow != "skip" {
                    pow_limit(&block, act).map_err(str::to_string)?;
                    // `validate_pow` itself: the dev feature `test-pow-limit`
                    // pins this build's limit to 0x2100ffff, so only the
                    // `pow: full` cases (all within it) are evaluated here; the
                    // gnb-crypto runner evaluates the pow-limit cases with
                    // the real limit.
                    if c.pow == "full" && !block.validate_pow() {
                        return Err("bad-pow".into());
                    }
                }
                limits::check_block_context_free(&block).map_err(|e| classify(&e).to_string())
            })();
            rep.expect(&c.id, "context-free block rules", &context_free_expectation(&expected, &block, max_supply), &verdict(&cf));
            if let Err(class) = cf {
                rep.expect(&c.id, "block", &expected, &class);
                continue;
            }
        } else {
            assert_eq!(c.scope, "connect", "{}", c.id);
        }
        let (_tmp, store) = store_with(&c.prevouts);
        let got = accept::validate_block_in_view_classified(&store, &block).map_err(|e| classify(&e.reason).to_string());
        rep.expect(&c.id, "block", &expected, &verdict(&got));
    }
    rep.finish("block vectors (node)");
}
