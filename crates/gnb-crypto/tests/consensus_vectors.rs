//! The data-driven consensus vectors (`reference/tx_vectors.json`,
//! `reference/block_vectors.json`; docs/testing/VECTORS.md) against
//! gnb-crypto's consensus functions, in this crate's own invocation (the real
//! pow limit: the node's dev feature `test-pow-limit` is off here).
//!
//! What this runner checks (the node runner, `node/tests/consensus_vectors.rs`,
//! adds the connect-time rules and mempool admission):
//!
//! * every recorded derived value (txid, wtxid, sizes, sighash v2/v3 digests,
//!   Merkle and witness roots, parent commitment, subsidy, block id) is what
//!   the code computes;
//! * transactions: strict decoding, the context-free per-transaction rules of
//!   a block, and the input-script rule `core::sighash::verify_tx_scripts`
//!   with the case's chain id (testnet cases included) wherever the expected
//!   verdict depends on it;
//! * blocks: decoding, `Block::validate_structure_without_pow_at`,
//!   `block_rules::check_block_hardened_at`, the pow limit (with
//!   `Block::validate_pow` under the case's activation height where it fails
//!   fast or the case is mined) and `limits::check_block_context_free`.

#[path = "consensus_vectors_common/mod.rs"]
mod common;

use common::*;
use gnb_crypto::core::sighash::SighashV3Precomputed;
use gnb_crypto::core::{self, activation, block_rules, limits, Block, Transaction, TxOutput};
use gnb_crypto::crypto;

fn hexs(b: &[u8]) -> String {
    hex::encode(b)
}

/// Classes decided before the input scripts in the node's order.
const BEFORE_SCRIPTS: &[&str] = &[
    "decode", "coinbase-format", "tx-64-bytes", "dust", "value-out-of-range", "canonical-limit", "bip30",
    "same-block-coinbase", "immature-coinbase", "double-spend", "missing-input",
];

#[test]
fn tx_vectors_core() {
    let v = load_tx_vectors();
    assert!(v.cases.len() >= 150, "{} tx cases", v.cases.len());
    assert_eq!(v.constants["wrapper_coinbase_script_sig"], hexs(WRAPPER_COINBASE_SCRIPT_SIG));
    let mut rep = Report::default();
    let mut ids = std::collections::HashSet::new();
    for c in &v.cases {
        assert!(ids.insert(c.id.clone()), "duplicate id {}", c.id);
        let chain = chain_of(&c.network);
        let Some(tx) = decode_tx(&c.bytes) else {
            rep.expect(&c.id, "strict decode", &want(&c.error), "decode");
            assert!(c.derived.is_null(), "{}: no derived values for undecodable bytes", c.id);
            continue;
        };
        // Derived values.
        let d = &c.derived;
        rep.expect(&c.id, "txid", d["txid"].as_str().unwrap(), &hexs(&tx.txid()));
        rep.expect(&c.id, "wtxid", d["wtxid"].as_str().unwrap(), &hexs(&tx.wtxid()));
        rep.expect(&c.id, "wire_size", &d["wire_size"].to_string(), &tx.wire_size(true).to_string());
        rep.expect(&c.id, "txid_preimage_size", &d["txid_preimage_size"].to_string(),
            &block_rules::txid_preimage_len(&tx).to_string());
        let spent: Option<Vec<TxOutput>> = tx.inputs.iter().map(|i| {
            c.prevouts.iter().find(|p| p.txid == i.prev_txid && p.vout == i.prev_index).map(Prevout::out)
        }).collect();
        let digests = d["digests"].as_array().unwrap();
        assert_eq!(digests.len(), tx.inputs.len(), "{}", c.id);
        for (i, dg) in digests.iter().enumerate() {
            rep.expect(&c.id, &format!("sighash_v2[{i}]"), dg["sighash_v2"].as_str().unwrap(), &hexs(&tx.sighash(i, chain)));
            let suite = dg["sighash_v3_suite"].as_u64().unwrap() as u16;
            let got = spent.as_ref()
                .map(|s| hexs(&SighashV3Precomputed::new(&tx, s).unwrap().digest(i, suite, chain).unwrap()))
                .unwrap_or_else(|| "null".into());
            rep.expect(&c.id, &format!("sighash_v3[{i}]"), dg["sighash_v3"].as_str().unwrap_or("null"), &got);
        }

        // Context-free per-transaction rules.
        let block = wrapper_block(&tx, c.height, &c.prevouts);
        let cf = tx_context_free(&block, c.activation).map_err(|e| classify(&e).to_string());
        let expected = want(&c.error);
        match &cf {
            Err(_) => rep.expect(&c.id, "context-free rules", &expected, &verdict(&cf)),
            Ok(()) => {
                if CONTEXT_FREE_CLASSES.contains(&expected.as_str()) {
                    rep.expect(&c.id, "context-free rules", &expected, "valid");
                }
            }
        }

        // The input-script rule, wherever the expected verdict depends on it.
        if cf.is_ok() && !BEFORE_SCRIPTS.contains(&expected.as_str()) {
            let spent = spent.clone().expect("every input resolves when the scripts decide");
            let got = core::sighash::verify_tx_scripts(&tx, &spent, chain, c.height, c.activation)
                .map(|_| ())
                .map_err(|e| classify(&e).to_string());
            let want_scripts = if SCRIPT_CLASSES.contains(&expected.as_str()) { expected.clone() } else { "valid".into() };
            rep.expect(&c.id, "verify_tx_scripts", &want_scripts, &verdict(&got));
        }
    }
    rep.finish("tx vectors (gnb-crypto)");
}

#[test]
fn block_vectors_core() {
    let cases = load_block_vectors();
    assert!(cases.len() >= 60, "{} block cases", cases.len());
    let mut rep = Report::default();
    for c in &cases {
        let block = match Block::from_wire_bytes(&c.bytes) {
            Ok(b) => b,
            Err(_) => {
                rep.expect(&c.id, "decode", &want(&c.error), "decode");
                continue;
            }
        };
        assert_eq!(block.height, c.height, "{}", c.id);
        assert_eq!(block.to_wire_bytes(), c.bytes, "{}: canonical encoding", c.id);
        let d = &c.derived;
        let ids: Vec<[u8; 32]> = block.transactions.iter().map(Transaction::txid).collect();
        rep.expect(&c.id, "block_hash", d["block_hash"].as_str().unwrap(), &hexs(&block.block_hash()));
        let txids: Vec<String> = d["txids"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect();
        rep.expect(&c.id, "txids", &txids.join(","), &ids.iter().map(|i| hexs(i)).collect::<Vec<_>>().join(","));
        rep.expect(&c.id, "legacy_merkle_root", d["legacy_merkle_root"].as_str().unwrap(), &hexs(&Transaction::merkle_root(&block.transactions).0));
        rep.expect(&c.id, "tagged_merkle_root", d["tagged_merkle_root"].as_str().unwrap(), &hexs(&block_rules::tx_merkle_root(&block.transactions, true).0));
        rep.expect(&c.id, "witness_root", d["witness_root"].as_str().unwrap(), &hexs(&block_rules::witness_root(&block.transactions).0));
        rep.expect(&c.id, "parents_commitment", d["parents_commitment"].as_str().unwrap(), &hexs(&block_rules::parents_commitment(&block.header.parents)));
        rep.expect(&c.id, "subsidy", d["subsidy"].as_str().unwrap(), &core::tokenomics::block_subsidy_sat(block.height).to_string());
        rep.expect(&c.id, "wire_size", &d["wire_size"].to_string(), &block.wire_size().to_string());
        rep.expect(&c.id, "bincode_size", &d["bincode_size"].to_string(), &block.size_bytes().to_string());

        if c.scope == "connect" {
            continue; // connect-time rules only: node runner
        }
        let expected = want(&c.error);
        let got = (|| -> Result<(), String> {
            block.validate_structure_without_pow_at(c.activation).map_err(|e| classify(e).to_string())?;
            block_rules::check_block_hardened_at(&block, c.activation).map_err(|e| classify(e).to_string())?;
            if c.pow != "skip" {
                let limit = pow_limit(&block, c.activation);
                // `validate_pow` under the case's activation height: it must
                // agree, without an evaluation, wherever the limit fails. A
                // workspace-wide build unifies the node's dev feature
                // `test-pow-limit`, which pins `validate_pow`'s limit to
                // 0x2100ffff: there only the mined case is evaluated.
                if core::TEST_POW_LIMIT {
                    if c.pow == "full" && !block.validate_pow() {
                        return Err("bad-pow".into());
                    }
                } else if limit.is_err() || c.pow == "full" {
                    let _g = activation::scoped_override(c.activation);
                    let t = std::time::Instant::now();
                    let ok = block.validate_pow();
                    if limit.is_err() {
                        assert!(!ok, "{}: validate_pow accepted bits the pow-limit rule refuses", c.id);
                        assert!(t.elapsed() < std::time::Duration::from_millis(200), "{}: refused without an evaluation", c.id);
                    } else if !ok {
                        return Err("bad-pow".into());
                    }
                }
                limit.map_err(str::to_string)?;
            }
            limits::check_block_context_free(&block).map_err(|e| classify(&e).to_string())
        })();
        match &got {
            Err(_) => rep.expect(&c.id, "context-free block rules", &expected, &verdict(&got)),
            Ok(()) => {
                if CONTEXT_FREE_CLASSES.contains(&expected.as_str()) {
                    rep.expect(&c.id, "context-free block rules", &expected, "valid");
                }
            }
        }
    }
    rep.finish("block vectors (gnb-crypto)");
}

/// The two files cover what docs/testing/VECTORS.md promises: both regimes,
/// every error class, both networks, and every version x regime.
#[test]
fn vector_coverage() {
    let v = load_tx_vectors();
    let has = |f: &dyn Fn(&TxVector) -> bool| v.cases.iter().any(f);
    for class in [
        "decode", "coinbase-format", "tx-64-bytes", "dust", "value-out-of-range", "bip30", "same-block-coinbase",
        "immature-coinbase", "double-spend", "missing-input", "bad-version", "witness-malformed",
        "witness-non-canonical", "pubkey-mismatch", "bad-signature", "inputs-below-outputs", "min-fee",
    ] {
        assert!(has(&|c| c.error.as_deref() == Some(class)), "tx class {class} not covered");
    }
    for policy in ["non-standard-witness", "non-standard-version", "non-standard-suite", "non-standard-zero-value", "non-standard-no-outputs"] {
        assert!(has(&|c| c.policy_class.as_deref() == Some(policy)), "policy {policy} not covered");
    }
    for net in ["mainnet", "testnet"] {
        for post in [false, true] {
            assert!(has(&|c| c.network == net && (c.height >= c.activation) == post), "{net} post={post}");
        }
    }
    for version in [0u32, 1, 2, 3, 4, u32::MAX] {
        for post in [false, true] {
            assert!(has(&|c| decode_tx(&c.bytes).is_some_and(|t| t.version == version) && (c.height >= c.activation) == post),
                "version {version} post={post}");
        }
    }
    // Raw carry-over keys and the 0x0002 suite appear in valid spends.
    let pk_len = |c: &TxVector| decode_tx(&c.bytes)
        .and_then(|t| Transaction::parse_script_sig(&t.inputs.first()?.script_sig).map(|(_, pk)| pk.len()));
    assert!(has(&|c| c.error.is_none() && pk_len(c) == Some(crypto::MLDSA_PUBKEY_LEN + crypto::falcon::pubkey_len())));
    assert!(has(&|c| c.error.is_none() && pk_len(c) == Some(4 + crypto::MLDSA_PUBKEY_LEN)));

    let b = load_block_vectors();
    for class in [
        "decode", "bad-merkle-root", "coinbase-format", "tx-64-bytes", "cb-commitment-missing", "cb-commitment-tag",
        "cb-height", "cb-parents", "witness-commitment", "duplicate-tx", "block-size", "pow-limit", "bad-bits",
        "bip30", "coinbase-value", "coinbase-output-count", "same-block-coinbase",
    ] {
        assert!(b.iter().any(|c| c.error.as_deref() == Some(class)), "block class {class} not covered");
    }
    for post in [false, true] {
        assert!(b.iter().filter(|c| (c.height >= c.activation) == post && c.error.is_none()).count() >= 10);
    }
}
