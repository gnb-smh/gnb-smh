//! Bounded public descriptor JSON. Accepted outputs must survive inspection and
//! public pool restoration; changing the requested network must be refused.
//! Script/checksum equality with an independent implementation is checked by
//! reference/descriptor_differential.py in CI, not inferred from round trips.
#![no_main]

use gnb_crypto::wallet::descriptor::{public_request, request_from_json};
use libfuzzer_sys::fuzz_target;
use serde_json::{json, Value};

fn check_info(info: &Value) {
    let network = info["network"].as_str().unwrap();
    let other = match network {
        "mainnet" => "testnet",
        "testnet" => "mainnet",
        _ => panic!("accepted descriptor has an unknown network"),
    };
    let descriptor = info["descriptor"].as_str().unwrap();
    assert_eq!(
        public_request(&json!({"action":"inspect","network":network,"descriptor":descriptor})).unwrap(),
        *info
    );
    assert!(public_request(&json!({"action":"inspect","network":other,"descriptor":descriptor})).is_err());
}

fuzz_target!(|data: &[u8]| {
    let Ok(request) = request_from_json(data) else { return };
    let Ok(result) = public_request(&request) else { return };
    if result.get("descriptor").is_some() {
        check_info(&result);
    } else {
        let entries = result["entries"].as_array().unwrap();
        assert_eq!(result["count"].as_u64().unwrap(), entries.len() as u64);
        for info in entries {
            check_info(info);
        }
        assert_eq!(
            public_request(&json!({"action":"import","network":request["network"],"bundle":result["bundle"]})).unwrap(),
            result
        );
    }
});
