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
    match request.get("op")?.as_str()? {
        "decode" => {
            let (net, script) = destination_script(request.get("address")?.as_str()?).ok()?;
            if let Some(expected) = request.get("expected_network") {
                if network(expected)? != net {
                    return None;
                }
            }
            response(net, &script)
        }
        "encode" => {
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
