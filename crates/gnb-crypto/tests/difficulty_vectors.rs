//! GnB's difficulty rule against the normative Python reference
//! (`reference/gnb_difficulty.py` -> `reference/difficulty_vectors.json`):
//! the chain constants, multi-parent difficulty inputs (latest parent
//! timestamp, max parent height + 1) under the real ASERT, and chain work.
//!
//! Run this crate in its OWN cargo invocation (`cargo test -p gnb-crypto`):
//! in a workspace-wide invocation the node's dev-dependency feature
//! `test-pow-limit` is unified into gnb-crypto and pins `expected_bits` to
//! the pow limit. Under that feature this test still checks the real ASERT
//! through `asert_params()`/`asert_anchor()` and asserts the pinned value
//! for `expected_bits`, so it never silently passes on the wrong path.

use gnb_crypto::core;
use serde_json::Value;

const VECTORS: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../reference/difficulty_vectors.json"));

fn doc() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

#[test]
fn reference_uses_the_chain_constants() {
    let d = doc();
    let g = &d["gnb"];
    assert_eq!(g["target_spacing"].as_u64().unwrap(), core::TARGET_BLOCK_TIME);
    assert_eq!(g["halflife"].as_i64().unwrap(), core::ASERT_HALFLIFE_SECS);
    assert_eq!(g["pow_limit_bits"].as_u64().unwrap(), u64::from(core::POW_LIMIT_BITS));
    assert_eq!(g["genesis_bits"].as_u64().unwrap(), u64::from(core::GENESIS_BITS));
    assert_eq!(g["genesis_timestamp"].as_u64().unwrap(), core::GENESIS_TIMESTAMP);
    assert_eq!(g["genesis_height"].as_u64().unwrap(), core::asert_anchor().height);
    assert_eq!(core::asert_anchor().bits, core::GENESIS_BITS);
    assert_eq!(core::asert_anchor().timestamp, core::GENESIS_TIMESTAMP as i64);
}

#[test]
fn multi_parent_expected_bits_match_reference() {
    let d = doc();
    let cases = d["gnb_expected_bits"].as_array().unwrap();
    assert!(cases.len() >= 8);
    for v in cases {
        let parents: Vec<(u64, u64)> = v["parents"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| (p["height"].as_u64().unwrap(), p["timestamp"].as_u64().unwrap()))
            .collect();
        // The difficulty input: latest timestamp over ALL parents, and
        // max(parent heights) + 1, independent of parent order.
        let parent_ts = core::difficulty_parent_timestamp(parents.iter().map(|&(_, t)| t));
        let height = parents.iter().map(|&(h, _)| h).max().unwrap() + 1;
        assert_eq!(parent_ts, v["parent_time"].as_u64().unwrap(), "{v}");
        assert_eq!(height, v["height"].as_u64().unwrap(), "{v}");
        let reversed = core::difficulty_parent_timestamp(parents.iter().rev().map(|&(_, t)| t));
        assert_eq!(parent_ts, reversed);

        let got = core::expected_bits(parent_ts, height);
        match v.get("bits") {
            Some(bits) => {
                let want = u32::try_from(bits.as_u64().unwrap()).unwrap();
                // The real rule, always: ASERT through the chain's parameters.
                let asert = gnb_smh::difficulty::asert_next_bits(
                    &core::asert_params(),
                    &core::asert_anchor(),
                    i64::try_from(parent_ts).unwrap(),
                    height,
                )
                .unwrap();
                assert_eq!(asert, want, "{v}");
                if core::TEST_POW_LIMIT {
                    assert_eq!(got.unwrap(), core::target_to_bits(&core::bits_to_target(core::POW_LIMIT_BITS)));
                } else {
                    assert_eq!(got.unwrap(), want, "{v}");
                }
            }
            None => {
                assert_eq!(v["error"], "ParentTimestampOutOfRange");
                if !core::TEST_POW_LIMIT {
                    assert!(got.is_err(), "{v}");
                }
            }
        }
    }
}

/// POW-3: the pow limit around the hardening activation height, on the real
/// ASERT path (`expected_bits_at` is never pinned by `test-pow-limit`).
#[test]
fn hardening_pow_limit_matches_reference() {
    let d = doc();
    let g = &d["gnb"];
    assert_eq!(
        g["hardened_pow_limit_bits"].as_u64().unwrap(),
        u64::from(core::block_rules::HARDENED_POW_LIMIT_BITS)
    );
    assert_eq!(core::block_rules::HARDENED_POW_LIMIT_BITS, core::GENESIS_BITS);
    assert_eq!(
        g["mainnet_hardening_activation_height"].as_u64().unwrap(),
        core::activation::MAINNET_HARDENING_ACTIVATION_HEIGHT
    );
    let cases = d["hardening_pow_limit"].as_array().unwrap();
    assert!(cases.len() >= 24);
    let pow_limit_bits = core::target_to_bits(&core::bits_to_target(core::POW_LIMIT_BITS));
    let mut clamped_below = 0;
    let mut clamped_at = 0;
    for v in cases {
        let act = v["activation_height"].as_u64().unwrap();
        let height = v["height"].as_u64().unwrap();
        let parent_time = v["parent_time"].as_u64().unwrap();
        let limit = u32::try_from(v["pow_limit_bits"].as_u64().unwrap()).unwrap();
        let want = u32::try_from(v["bits"].as_u64().unwrap()).unwrap();
        assert_eq!(core::block_rules::pow_limit_bits_at(height, act), limit, "{v}");
        assert_eq!(core::expected_bits_at(parent_time, height, act).unwrap(), want, "{v}");
        let target = core::bits_to_target(want);
        assert!(core::Block::target_within_pow_limit_at(&target, height, act), "{v}");
        if want == pow_limit_bits {
            clamped_below += 1;
            assert!(height < act, "{v}");
        }
        if limit == core::GENESIS_BITS && want == core::GENESIS_BITS && v["note"] != "on schedule" {
            clamped_at += 1;
        }
    }
    assert!(clamped_below > 0 && clamped_at > 0, "both sides of the boundary are exercised");
}

#[test]
fn chain_work_matches_reference() {
    let d = doc();
    for v in d["compact"].as_array().unwrap() {
        let bits = u32::try_from(v["bits"].as_u64().unwrap()).unwrap();
        let want: u128 = v["work"].as_str().unwrap().parse().unwrap();
        assert_eq!(core::bits_to_work(bits), want, "bits {bits:#010x}");
    }
}
