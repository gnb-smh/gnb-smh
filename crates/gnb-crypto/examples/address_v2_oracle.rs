//! JSONL adapter for the independent Python address-v2 reference.
//! Uses the real unified destination parser with no extra syntax gate. Legacy
//! behavior has separate golden tests; the shared differential corpus is v2.
use gnb_crypto::address::{destination_script, Address, Network, PolicyAddress};
use serde_json::{json, Value};
use std::io::{self, BufRead};

fn network(value: &Value) -> Option<Network> {
    match value.as_str()? {
        "mainnet" => Some(Network::Mainnet),
        "testnet" => Some(Network::Testnet),
        _ => None,
    }
}

fn response(net: Network, script: &[u8]) -> Option<Value> {
    let (kind, hash, address) = if script.len() == 20 {
        let hash: [u8; 20] = script.try_into().ok()?;
        (
            "single-key",
            script,
            Address::from_hash(hash, net).to_bech32m(),
        )
    } else {
        let policy = PolicyAddress::from_script(script, net)?;
        ("policy", &script[1..], policy.to_bech32m())
    };
    Some(json!({"ok": true, "address": address,
        "network": if net == Network::Mainnet { "mainnet" } else { "testnet" },
        "kind": kind, "hash_hex": hex::encode(hash), "script_hex": hex::encode(script)}))
}

fn run(request: &Value) -> Option<Value> {
    let fields = request.as_object()?;
    match request.get("op")?.as_str()? {
        "decode" => {
            if fields.keys().any(|key| !["op", "address", "expected_network"].contains(&key.as_str())) {
                return None;
            }
            let (net, script) = destination_script(request.get("address")?.as_str()?).ok()?;
            // Match the Python envelope contract: null and absence both mean
            // no expected-network constraint; other values must name a network.
            if let Some(expected) = request.get("expected_network").filter(|value| !value.is_null()) {
                if network(expected)? != net {
                    return None;
                }
            }
            response(net, &script)
        }
        "encode" => {
            if fields.keys().any(|key| !["op", "network", "kind", "hash_hex"].contains(&key.as_str())) {
                return None;
            }
            let net = network(request.get("network")?)?;
            let encoded = request.get("hash_hex")?.as_str()?;
            if encoded
                .bytes()
                .any(|c| !c.is_ascii_digit() && !(b'a'..=b'f').contains(&c))
            {
                return None;
            }
            let hash = hex::decode(encoded).ok()?;
            let mut script = Vec::new();
            match request.get("kind")?.as_str()? {
                "single-key" if hash.len() == 20 => (),
                "policy" if hash.len() == 32 => script.push(2),
                _ => return None,
            }
            script.extend_from_slice(&hash);
            response(net, &script)
        }
        _ => None,
    }
}

fn main() -> io::Result<()> {
    for line in io::stdin().lock().lines() {
        let value = serde_json::from_str::<Value>(&line?)
            .ok()
            .and_then(|request| run(&request));
        println!("{}", value.unwrap_or_else(|| json!({"ok": false})));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const ADDRESS: &str = "gnb1zqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdaq6uw";

    fn decode_request() -> Value {
        json!({"op": "decode", "address": ADDRESS})
    }

    fn encode_request() -> Value {
        json!({"op": "encode", "network": "mainnet", "kind": "single-key", "hash_hex": "00".repeat(20)})
    }

    #[test]
    fn oracle_valid_decode_and_encode_remain_equivalent() {
        let decoded = run(&decode_request()).expect("valid address control");
        assert_eq!(decoded["address"], ADDRESS);
        assert_eq!(run(&encode_request()), Some(decoded));
    }

    #[test]
    fn oracle_null_expected_network_means_absent() {
        let mut request = decode_request();
        request["expected_network"] = Value::Null;
        assert_eq!(run(&request), run(&decode_request()));
    }

    #[test]
    fn oracle_unknown_decode_field_is_rejected() {
        let mut request = decode_request();
        request["unknown"] = json!(1);
        assert!(run(&request).is_none());
    }

    #[test]
    fn oracle_unknown_encode_field_is_rejected() {
        let mut request = encode_request();
        request["unknown"] = json!(1);
        assert!(run(&request).is_none());
    }

    #[test]
    fn oracle_missing_fields_and_invalid_types_are_rejected() {
        for request in [Value::Null, json!([]), json!("decode"), json!({}), json!({"op": null})] {
            assert!(run(&request).is_none());
        }
        for field in ["op", "address"] {
            let mut request = decode_request();
            request.as_object_mut().unwrap().remove(field);
            assert!(run(&request).is_none());
        }
        for field in ["op", "network", "kind", "hash_hex"] {
            let mut request = encode_request();
            request.as_object_mut().unwrap().remove(field);
            assert!(run(&request).is_none());
        }
        for invalid in [Value::Null, json!(false), json!(7), json!([]), json!({})] {
            let mut request = decode_request();
            request["address"] = invalid.clone();
            assert!(run(&request).is_none());
            for field in ["network", "kind", "hash_hex"] {
                let mut request = encode_request();
                request[field] = invalid.clone();
                assert!(run(&request).is_none());
            }
            if !invalid.is_null() {
                let mut request = decode_request();
                request["expected_network"] = invalid;
                assert!(run(&request).is_none());
            }
        }
    }
}
