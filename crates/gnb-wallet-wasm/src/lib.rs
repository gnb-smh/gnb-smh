//! GnB browser wallet core, built for `wasm32-wasip1`.
//!
//! One entry point, JSON in and JSON out:
//!
//! ```text
//! gnb_alloc(len) -> ptr            gnb_free(ptr, len)
//! gnb_call(ptr, len) -> u64        (result_ptr << 32) | result_len; free with gnb_free
//! ```
//!
//! Requests: `{"op": ...}` with
//!
//! ```text
//! open {json, password}       unlock a keystore (v3/v2, `bloch1q…` accepted for v2; then v1)
//! create {mnemonic?}          new mainnet key from the WASI CSPRNG (browser crypto).
//!                             By default (`mnemonic` absent or true) the key is
//!                             derived from a fresh 24-word phrase, returned ONCE as
//!                             `words` for the user to write down (WAL-7);
//!                             `mnemonic: false` makes a random key with no phrase.
//! restore {words}             unlock the key of a 24-word phrase
//! export {password}           encrypted keystore v3 JSON of the unlocked key
//! plan {utxos, to, amount, fee, next_height}
//!                             the transaction `version` a payment targeting block
//!                             `next_height` (the node's getdaginfo tip_height + 1)
//!                             gets, and, for version 1 only, the txids whose creating
//!                             transactions the page should fetch (WAL-1). A version-3
//!                             signature commits to every spent value and script, so
//!                             `prev_txids` is empty from the hardening activation on.
//! pay {utxos, to, amount, fee, next_height, prevtxs?, max_fee?, require_verified?}
//!                             build and sign a payment (amounts in base units) as
//!                             version 3 / sighash v3 at/after the activation, version
//!                             1 / sighash v2 below it. `prevtxs` maps txid -> raw
//!                             transaction hex; each is hashed against its txid and
//!                             the claimed UTXO values are checked against it before
//!                             anything is signed. The response reports the ACTUAL
//!                             fee, dust added to the fee, change, verified/unverified
//!                             inputs, `version` and `amounts_committed`.
//! address {} · wipe {} · normalize {address} · minfee {size}
//! ```
//!
//! The secret key never crosses the boundary: responses carry addresses,
//! public keys, signed transactions, encrypted keystores and — only from
//! `create` — the new recovery phrase. Request buffers are wiped by the
//! loader (`core.js`) and the password copies made here are wiped on drop.

use gnb_crypto::address::{Address, Network};
use gnb_crypto::core::{tokenomics, ChainId, TxOutput};
use gnb_crypto::wallet::payment::amounts_committed_at;
use gnb_crypto::wallet::{
    generate_keypair, generate_mnemonic_keypair, keypair_from_mnemonic, FeeChoice, FeePolicy,
    Keypair, PaymentOptions, PrevTxs, TxBuilder, Utxo, Wallet,
};
use serde_json::{json, Value};
use std::sync::Mutex;
use zeroize::{Zeroize, Zeroizing};

static SESSION: Mutex<Option<Keypair>> = Mutex::new(None);

fn set_session(kp: Keypair) {
    let mut s = SESSION.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(old) = s.as_mut() {
        old.private_key.zeroize();
    }
    *s = Some(kp);
}

fn with_session<R>(f: impl FnOnce(&Keypair) -> Result<R, String>) -> Result<R, String> {
    let s = SESSION.lock().unwrap_or_else(|e| e.into_inner());
    s.as_ref().ok_or_else(|| "wallet is locked".to_string()).and_then(f)
}

fn s<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> {
    v.get(k).and_then(Value::as_str).ok_or_else(|| format!("missing string field `{k}`"))
}

/// A secret string field, copied into wiping storage (CRY-4).
fn secret(v: &Value, k: &str) -> Result<Zeroizing<String>, String> {
    s(v, k).map(|x| Zeroizing::new(x.to_owned()))
}

/// Overwrite every secret string field of a request in place, so the parsed
/// `serde_json::Value` does not keep the password or phrase after dispatch.
fn wipe_secret_fields(req: &mut Value) {
    if let Some(obj) = req.as_object_mut() {
        for key in ["password", "words"] {
            if let Some(Value::String(text)) = obj.get_mut(key) {
                text.zeroize();
            }
        }
    }
}

/// Dispatch one request and wipe its secret fields (CRY-4).
pub fn handle_owned(mut req: Value) -> Result<Value, String> {
    let out = handle(&req);
    wipe_secret_fields(&mut req);
    out
}

/// Dispatch one request. Pure Rust, testable on the host.
pub fn handle(req: &Value) -> Result<Value, String> {
    match s(req, "op")? {
        "open" => {
            let raw = s(req, "json")?.as_bytes();
            let pw = secret(req, "password")?;
            let kp = match Keypair::from_encrypted_bytes(raw, &pw) {
                Ok(kp) => kp,
                Err(e2) => match Wallet::from_encrypted_bytes(raw, &pw) {
                    Ok(w) => w.into_keypair(),
                    Err(e1) => return Err(format!("could not open the wallet: {e2} / {e1}")),
                },
            };
            let out = json!({ "address": kp.address, "public_key": hex::encode(&kp.public_key) });
            set_session(kp);
            Ok(out)
        }
        "create" => {
            let with_phrase = req.get("mnemonic").and_then(Value::as_bool).unwrap_or(true);
            if with_phrase {
                let (kp, phrase) = generate_mnemonic_keypair(Network::Mainnet).map_err(|e| e.to_string())?;
                let words = Zeroizing::new(phrase.words().join(" "));
                let out = json!({
                    "address": kp.address, "public_key": hex::encode(&kp.public_key),
                    "words": words.as_str(),
                });
                set_session(kp);
                Ok(out)
            } else {
                let kp = generate_keypair(false);
                let out = json!({ "address": kp.address, "public_key": hex::encode(&kp.public_key) });
                set_session(kp);
                Ok(out)
            }
        }
        "restore" => {
            let words = secret(req, "words")?;
            let kp = keypair_from_mnemonic(&words, Network::Mainnet).map_err(|e| e.to_string())?;
            let out = json!({ "address": kp.address, "public_key": hex::encode(&kp.public_key) });
            set_session(kp);
            Ok(out)
        }
        "address" => with_session(|kp| Ok(json!({ "address": kp.address }))),
        "export" => {
            let pw = secret(req, "password")?;
            with_session(|kp| kp.to_encrypted_json(&pw).map(|j| json!({ "keystore": j })))
        }
        "plan" => {
            let utxos = parse_utxos(req.get("utxos").ok_or("missing `utxos`")?)?;
            let amount = parse_amount(req, "amount")?;
            let fee = FeeChoice::AtLeast(parse_amount(req, "fee")?);
            let next_height = parse_height(req)?;
            with_session(|kp| {
                let chain = ChainId::for_network(kp.network()?);
                let opts = PaymentOptions { next_block_height: Some(next_height), ..PaymentOptions::default() };
                let version = opts.tx_version(chain)?;
                if amounts_committed_at(next_height, chain) {
                    return Ok(json!({ "prev_txids": [], "version": version }));
                }
                let outpoints = TxBuilder::plan_inputs(kp, &utxos, amount, fee)?;
                let mut txids: Vec<String> = outpoints.iter().map(|(t, _)| hex::encode(t)).collect();
                txids.dedup();
                Ok(json!({ "prev_txids": txids, "version": version }))
            })
        }
        "pay" => {
            let utxos = parse_utxos(req.get("utxos").ok_or("missing `utxos`")?)?;
            let amount = parse_amount(req, "amount")?;
            let fee = parse_amount(req, "fee")?;
            let next_height = parse_height(req)?;
            let to = s(req, "to")?;
            let mut prevs = PrevTxs::new();
            if let Some(map) = req.get("prevtxs").and_then(Value::as_object) {
                for (txid, raw) in map {
                    prevs.insert_hex(txid, raw.as_str().ok_or("prevtxs values must be hex strings")?)?;
                }
            }
            let fee_policy = match req.get("max_fee").and_then(Value::as_str) {
                Some(cap) => FeePolicy::with_max_fee(cap.parse().map_err(|_| "invalid max_fee")?),
                None => FeePolicy::DEFAULT,
            };
            let opts = PaymentOptions {
                fee: FeeChoice::AtLeast(fee),
                fee_policy,
                prev_txs: Some(&prevs),
                require_verified_inputs: req.get("require_verified").and_then(Value::as_bool).unwrap_or(false),
                next_block_height: Some(next_height),
                ..PaymentOptions::default()
            };
            with_session(|kp| pay(kp, &utxos, to, amount, &opts))
        }
        "wipe" => {
            let mut s = SESSION.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(kp) = s.as_mut() {
                kp.private_key.zeroize();
            }
            *s = None;
            Ok(json!({ "locked": true }))
        }
        "normalize" => Address::parse(s(req, "address")?.trim())
            .map(|a| json!({ "address": a.to_string() }))
            .map_err(|e| format!("invalid address: {e:?}")),
        "minfee" => {
            let size = req.get("size").and_then(Value::as_u64).ok_or("missing `size`")? as usize;
            Ok(json!({ "fee": tokenomics::min_tx_fee_sat(size).to_string() }))
        }
        other => Err(format!("unknown op `{other}`")),
    }
}

fn parse_amount(req: &Value, k: &str) -> Result<u64, String> {
    s(req, k)?.parse().map_err(|_| format!("invalid {k}"))
}

/// `next_height`: height of the block the payment targets (decimal string or
/// JSON number). Required: it selects the transaction version, and a guess
/// would sign a transaction the network rejects.
fn parse_height(req: &Value) -> Result<u64, String> {
    match req.get("next_height") {
        Some(Value::String(v)) => v.trim().parse().map_err(|_| "invalid next_height".to_string()),
        Some(Value::Number(n)) => n.as_u64().ok_or_else(|| "invalid next_height".to_string()),
        _ => Err("missing `next_height` (the node's getdaginfo tip_height + 1)".into()),
    }
}

fn pay(kp: &Keypair, utxos: &[Utxo], to: &str, amount: u64, opts: &PaymentOptions<'_>) -> Result<Value, String> {
    if amount == 0 {
        return Err("amount must be positive".into());
    }
    let dest = Address::parse(to.trim()).map_err(|e| format!("invalid destination: {e:?}"))?;
    let mine = Address::parse(&kp.address).map_err(|e| format!("{e:?}"))?;
    if dest.network() != mine.network() {
        return Err("destination is on another network".into());
    }
    let paid = TxBuilder::build_payment(kp, utxos, &dest, amount, opts)?;
    let raw = paid.tx.to_wire_bytes(true);
    Ok(json!({
        "raw": hex::encode(&raw), "txid": hex::encode(paid.tx.txid()), "size": paid.size,
        // WAL-1/WAL-6: the ACTUAL fee (inputs − outputs), including sub-dust change.
        "fee": paid.fee.to_string(), "dust_to_fee": paid.dust_to_fee.to_string(),
        "inputs": paid.tx.inputs.len(), "amount": amount.to_string(),
        "change": paid.change.to_string(), "inputs_total": paid.inputs_total.to_string(),
        "verified_inputs": paid.verified_inputs, "unverified_inputs": paid.unverified_inputs,
        // WAL-1 full fix: version 3 (sighash v3) commits every spent value.
        "version": paid.tx.version, "amounts_committed": paid.amounts_committed,
    }))
}

fn parse_utxos(rows: &Value) -> Result<Vec<Utxo>, String> {
    let rows = rows.as_array().ok_or("`utxos` must be an array")?;
    rows.iter().map(|row| {
        let txid: [u8; 32] = hex::decode(s(row, "txid")?).map_err(|e| e.to_string())?
            .try_into().map_err(|_| "UTXO txid must be 32 bytes".to_string())?;
        let index = row["index"].as_u64().and_then(|v| u32::try_from(v).ok()).ok_or("bad UTXO index")?;
        let value = match &row["value"] {
            Value::String(v) => v.parse().map_err(|_| "bad UTXO value")?,
            Value::Number(n) => n.as_u64().ok_or("bad UTXO value")?,
            _ => return Err("bad UTXO value".into()),
        };
        let script_pubkey = hex::decode(s(row, "script_pubkey")?).map_err(|e| e.to_string())?;
        Ok(Utxo { txid, index, output: TxOutput { value, script_pubkey } })
    }).collect()
}

// ── C ABI ────────────────────────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn gnb_alloc(len: usize) -> *mut u8 {
    let mut v = Vec::<u8>::with_capacity(len.max(1));
    let p = v.as_mut_ptr();
    std::mem::forget(v);
    p
}

/// # Safety
/// `ptr`/`len` must come from `gnb_alloc` or a `gnb_call` result.
#[no_mangle]
pub unsafe extern "C" fn gnb_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        let mut v = Vec::from_raw_parts(ptr, len, len.max(1));
        v.zeroize();
    }
}

/// # Safety
/// `ptr`/`len` must describe a readable UTF-8 JSON buffer from `gnb_alloc`.
#[no_mangle]
pub unsafe extern "C" fn gnb_call(ptr: *const u8, len: usize) -> u64 {
    let input = std::slice::from_raw_parts(ptr, len);
    let out = match serde_json::from_slice::<Value>(input) {
        Ok(req) => match handle_owned(req) {
            Ok(v) => json!({ "ok": v }),
            Err(e) => json!({ "error": e }),
        },
        Err(e) => json!({ "error": format!("bad request: {e}") }),
    };
    let bytes = out.to_string().into_bytes().into_boxed_slice();
    let n = bytes.len();
    let p = Box::into_raw(bytes) as *mut u8;
    ((p as u64) << 32) | n as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use gnb_crypto::core::{Transaction, TxInput};

    // The session is process-global: keep every flow in one test.
    #[test]
    fn create_export_open_roundtrip_and_pay() {
        let created = handle(&json!({"op": "create"})).unwrap();
        let addr = created["address"].as_str().unwrap().to_string();
        // WAL-7: phrase-backed by default, and the phrase restores the key.
        let words = created["words"].as_str().unwrap().to_string();
        assert_eq!(words.split_whitespace().count(), 24);
        let ks = handle(&json!({"op": "export", "password": "Correct-Horse-9-battery"})).unwrap();
        let ks = ks["keystore"].as_str().unwrap().to_string();
        assert!(ks.contains("\"version\": 3"), "exports keystore v3");
        handle(&json!({"op": "wipe"})).unwrap();
        assert!(handle(&json!({"op": "address"})).is_err());
        let restored = handle(&json!({"op": "restore", "words": words})).unwrap();
        assert_eq!(restored["address"], addr);
        handle(&json!({"op": "wipe"})).unwrap();
        let opened = handle(&json!({"op": "open", "json": ks, "password": "Correct-Horse-9-battery"})).unwrap();
        assert_eq!(opened["address"], addr);

        // Pay 3 GNB from two 2 GNB outputs owned by this key.
        let spk = Address::parse(&addr).unwrap().hash().to_vec();
        let utxos = json!([
            {"txid": "11".repeat(32), "index": 0, "value": "200000000", "script_pubkey": hex::encode(&spk)},
            {"txid": "22".repeat(32), "index": 1, "value": "200000000", "script_pubkey": hex::encode(&spk)},
        ]);
        let to = Address::from_hash([7u8; 20], Network::Mainnet).to_string();
        // Without the next block's height the core refuses to sign.
        let err = handle(&json!({"op": "pay", "utxos": utxos, "to": to, "amount": "300000000", "fee": "0"})).unwrap_err();
        assert!(err.contains("next_height"), "{err}");
        // Mainnet, far below the activation height: version 1 / sighash v2.
        let r = handle(&json!({"op": "pay", "utxos": utxos, "to": to, "amount": "300000000", "fee": "0",
            "next_height": "11"})).unwrap();
        assert_eq!(r["version"], 1);
        assert_eq!(r["amounts_committed"], false);
        let size = r["size"].as_u64().unwrap() as usize;
        assert_eq!(r["inputs"], 2);
        let fee: u64 = r["fee"].as_str().unwrap().parse().unwrap();
        assert!(fee >= tokenomics::min_tx_fee_sat(size));
        // The reported fee is the actual one: inputs − amount − change.
        let change: u64 = r["change"].as_str().unwrap().parse().unwrap();
        assert_eq!(400_000_000 - 300_000_000 - change, fee);
        assert_eq!(r["unverified_inputs"], 2);
        let raw = hex::decode(r["raw"].as_str().unwrap()).unwrap();
        let tx = Transaction::from_wire_bytes(&raw).unwrap();
        assert_eq!(hex::encode(tx.txid()), r["txid"].as_str().unwrap());
        // Every input carries a signature that verifies under the GnB sighash.
        for (i, inp) in tx.inputs.iter().enumerate() {
            let (sig, pk) = Transaction::parse_script_sig(&inp.script_sig).unwrap();
            let h = tx.sighash(i, gnb_crypto::core::ChainId::Mainnet);
            assert!(gnb_crypto::crypto::verify(&pk, &h, &sig));
        }
        // Bloch-prefixed destinations are the same owner.
        let bloch = format!("bloch1q{}", &to[5..]);
        assert_eq!(handle(&json!({"op": "normalize", "address": bloch})).unwrap()["address"], to);

        // ── WAL-1: a lied UTXO value is detected through `prevtxs` ─────────
        let prev = Transaction {
            version: 1,
            inputs: vec![TxInput { prev_txid: [9; 32], prev_index: 0, script_sig: vec![], sequence: u32::MAX }],
            outputs: vec![TxOutput { value: 10_000_000_000, script_pubkey: spk.clone() }],
            locktime: 0,
        };
        let txid = hex::encode(prev.txid());
        let lied = json!([{"txid": txid, "index": 0, "value": "100050000", "script_pubkey": hex::encode(&spk)}]);
        let plan = handle(&json!({"op": "plan", "utxos": lied, "to": to, "amount": "100000000", "fee": "0",
            "next_height": 11})).unwrap();
        assert_eq!(plan["prev_txids"], json!([txid]));
        assert_eq!(plan["version"], 1);
        let prevtxs = json!({ txid.clone(): hex::encode(prev.to_wire_bytes(true)) });
        let err = handle(&json!({"op": "pay", "utxos": lied, "to": to, "amount": "100000000", "fee": "0",
            "next_height": "11", "prevtxs": prevtxs})).unwrap_err();
        assert!(err.contains("refusing to sign"), "{err}");
        let honest = json!([{"txid": txid, "index": 0, "value": "10000000000", "script_pubkey": hex::encode(&spk)}]);
        let r = handle(&json!({"op": "pay", "utxos": honest, "to": to, "amount": "100000000", "fee": "0",
            "next_height": "11", "prevtxs": prevtxs, "require_verified": true})).unwrap();
        assert_eq!(r["verified_inputs"], 1);
        // The maximum-fee guard cannot be bypassed through `fee`.
        let err = handle(&json!({"op": "pay", "utxos": honest, "to": to, "amount": "1", "fee": "9900000000",
            "next_height": "11"})).unwrap_err();
        assert!(err.contains("guard"), "{err}");

        // ── WAL-1 full fix: from the mainnet activation height, version 3 ──
        let act = gnb_crypto::core::activation::MAINNET_HARDENING_ACTIVATION_HEIGHT;
        let plan = handle(&json!({"op": "plan", "utxos": lied, "to": to, "amount": "100000000", "fee": "0",
            "next_height": act.to_string()})).unwrap();
        assert_eq!(plan["prev_txids"], json!([]), "nothing to fetch: the signature commits the values");
        assert_eq!(plan["version"], 3);
        let r = handle(&json!({"op": "pay", "utxos": lied, "to": to, "amount": "100000000", "fee": "0",
            "next_height": act.to_string(), "require_verified": true})).unwrap();
        assert_eq!(r["version"], 3);
        assert_eq!(r["amounts_committed"], true);
        assert_eq!(r["unverified_inputs"], 0);
        let tx = Transaction::from_wire_bytes(&hex::decode(r["raw"].as_str().unwrap()).unwrap()).unwrap();
        let claimed = TxOutput { value: 100_050_000, script_pubkey: spk.clone() };
        let real = prev.outputs[0].clone();
        let verify = |spent: &TxOutput| gnb_crypto::core::sighash::verify_tx_scripts(
            &tx, std::slice::from_ref(spent), gnb_crypto::core::ChainId::Mainnet, act, act);
        assert!(verify(&claimed).is_ok(), "valid for the value it was signed over");
        assert!(verify(&real).is_err(), "the lie invalidates it against the real coin");
        handle(&json!({"op": "wipe"})).unwrap();
    }

    #[test]
    fn secret_request_fields_are_wiped_after_dispatch() {
        let mut req = json!({"op": "minfee", "size": 10, "password": "hunter2-hunter2", "words": "a b c"});
        wipe_secret_fields(&mut req);
        assert_eq!(req["password"], "");
        assert_eq!(req["words"], "");
        assert!(handle_owned(json!({"op": "minfee", "size": 10, "password": "x"})).is_ok());
    }
}
