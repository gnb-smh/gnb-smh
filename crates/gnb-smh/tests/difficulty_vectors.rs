//! Cross-implementation check of `gnb_smh::difficulty` against the normative
//! Python reference `reference/gnb_difficulty.py`, through the vectors it
//! generates (`reference/difficulty_vectors.json`): compact bits, target
//! encoding, chain work and ASERT, including generic anchors near the pow
//! limit (audit fix AUD-1) and the floor rounding of the exponent.

use gnb_smh::difficulty::{
    asert_next_bits, asert_next_target, bits_to_target, target_to_bits, try_bits_to_target, work,
    work_from_bits, AsertAnchor, AsertError, AsertParams, BitsError, Target,
};
use serde_json::Value;

const VECTORS: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../reference/difficulty_vectors.json"));

fn doc() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn u32_of(v: &Value) -> u32 {
    u32::try_from(v.as_u64().unwrap()).unwrap()
}

fn target_of(v: &Value) -> Target {
    Target(hex::decode(v.as_str().unwrap()).unwrap().try_into().unwrap())
}

fn work_of(v: &Value) -> u128 {
    v.as_str().unwrap().parse().unwrap()
}

fn bits_error_name(e: BitsError) -> &'static str {
    match e {
        BitsError::NegativeFlag => "NegativeFlag",
        BitsError::ZeroMantissa => "ZeroMantissa",
        BitsError::ExponentOutOfRange { .. } => "ExponentOutOfRange",
        BitsError::MantissaOverflow => "MantissaOverflow",
        BitsError::ZeroTarget => "ZeroTarget",
    }
}

fn asert_error_name(e: AsertError) -> &'static str {
    match e {
        AsertError::HeightNotAboveAnchor => "HeightNotAboveAnchor",
        AsertError::InvalidAnchor(_) => "InvalidAnchor",
        AsertError::ArithmeticOverflow => "ArithmeticOverflow",
    }
}

#[test]
fn compact_decoding_and_work_from_bits() {
    let d = doc();
    let cases = d["compact"].as_array().unwrap();
    assert!(cases.len() >= 60);
    for v in cases {
        let bits = u32_of(&v["bits"]);
        match try_bits_to_target(bits) {
            Ok(t) => {
                assert_eq!(t, target_of(&v["target_hex"]), "bits {bits:#010x}");
                assert_eq!(target_to_bits(&t), u32_of(&v["reencoded_bits"]), "bits {bits:#010x}");
            }
            Err(e) => {
                assert_eq!(bits_error_name(e), v["error"].as_str().unwrap(), "bits {bits:#010x}");
                assert_eq!(bits_to_target(bits), Target::ZERO);
            }
        }
        assert_eq!(work_from_bits(bits), work_of(&v["work"]), "work of bits {bits:#010x}");
    }
}

#[test]
fn target_encoding_and_chain_work() {
    let d = doc();
    let cases = d["targets"].as_array().unwrap();
    assert!(cases.len() >= 60);
    for v in cases {
        let t = target_of(&v["target_hex"]);
        assert_eq!(target_to_bits(&t), u32_of(&v["bits"]), "target {}", v["target_hex"]);
        assert_eq!(work(&t), work_of(&v["work"]), "work of target {}", v["target_hex"]);
    }
}

#[test]
fn asert_matches_reference() {
    let d = doc();
    let cases = d["asert"].as_array().unwrap();
    assert!(cases.len() >= 200);
    for v in cases {
        let p = &v["params"];
        let params = AsertParams {
            target_spacing: p["target_spacing"].as_i64().unwrap(),
            halflife: p["halflife"].as_i64().unwrap(),
            pow_limit: bits_to_target(u32_of(&p["pow_limit_bits"])),
        };
        let a = &v["anchor"];
        let anchor = AsertAnchor {
            height: a["height"].as_u64().unwrap(),
            bits: u32_of(&a["bits"]),
            timestamp: a["timestamp"].as_i64().unwrap(),
        };
        let parent_time = v["parent_time"].as_i64().unwrap();
        let height = v["height"].as_u64().unwrap();
        let got = asert_next_target(&params, &anchor, parent_time, height);
        match v.get("error") {
            Some(err) => {
                assert_eq!(asert_error_name(got.unwrap_err()), err.as_str().unwrap(), "{v}");
            }
            None => {
                assert_eq!(got.unwrap(), target_of(&v["target_hex"]), "{v}");
                assert_eq!(
                    asert_next_bits(&params, &anchor, parent_time, height).unwrap(),
                    u32_of(&v["bits"]),
                    "{v}"
                );
            }
        }
    }
}

#[test]
fn reference_constants_are_gnbs() {
    // The GnB constants the reference uses; gnb-crypto's own test checks them
    // against `gnb_crypto::core`.
    let d = doc();
    let g = &d["gnb"];
    assert_eq!(g["target_spacing"], 30);
    assert_eq!(g["halflife"], 7_200);
    assert_eq!(u32_of(&g["pow_limit_bits"]), 0x2100_FFFF);
    assert_eq!(g["genesis_height"], 0);
}
