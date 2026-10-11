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
//! - `open {json, password}`      unlock a keystore (v2, `bloch1q…` accepted; then v1)
//! - `create {}`                  new mainnet keypair from the WASI CSPRNG (browser crypto)
//! - `export {password}`          encrypted keystore v2 JSON of the unlocked key
//! - `pay {utxos, to, amount, fee}` build and sign a payment (amounts in base units)
//! - `address {}` · `wipe {}` · `normalize {address}` · `minfee {size}`
//!
//! The secret key never crosses the boundary: responses carry addresses,
//! public keys, signed transactions and encrypted keystores only.

use gnb_crypto::core::{tokenomics, Transaction, TxOutput};
use gnb_crypto::wallet::{generate_keypair, Keypair, TxBuilder, Wallet};
use serde_json::{json, Value};
use std::sync::Mutex;
use zeroize::Zeroize;

const MAX_TX_BYTES: usize = 400 * 1024;

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

/// Dispatch one request. Pure Rust, testable on the host.
pub fn handle(req: &Value) -> Result<Value, String> {
    match s(req, "op")? {
        "open" => {
            let raw = s(req, "json")?.as_bytes();
            let pw = s(req, "password")?;
            let kp = match Keypair::from_encrypted_bytes(raw, pw) {
                Ok(kp) => kp,
                Err(e2) => match Wallet::from_encrypted_bytes(raw, pw) {
                    Ok(w) => w.into_keypair(),
                    Err(e1) => return Err(format!("could not open the wallet: {e2} / {e1}")),
                },
            };
            let out = json!({ "address": kp.address, "public_key": hex::encode(&kp.public_key) });
            set_session(kp);
            Ok(out)
        }
        "create" => {
            let kp = generate_keypair(false);
            let out = json!({ "address": kp.address, "public_key": hex::encode(&kp.public_key) });
            set_session(kp);
            Ok(out)
        }
        "address" => with_session(|kp| Ok(json!({ "address": kp.address }))),
        "export" => {
            let pw = s(req, "password")?;
            with_session(|kp| kp.to_encrypted_json(pw).map(|j| json!({ "keystore": j })))
        }
        "pay" => {
            let utxos = parse_utxos(req.get("utxos").ok_or("missing `utxos`")?)?;
            let amount: u64 = s(req, "amount")?.parse().map_err(|_| "invalid amount")?;
            let fee: u64 = s(req, "fee")?.parse().map_err(|_| "invalid fee")?;
            let to = s(req, "to")?;
            with_session(|kp| pay(kp, &utxos, to, amount, fee))
        }
        "wipe" => {
            let mut s = SESSION.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(kp) = s.as_mut() {
                kp.private_key.zeroize();
            }
            *s = None;
            Ok(json!({ "locked": true }))
        }
        "normalize" => gnb_crypto::address::Address::parse(s(req, "address")?.trim())
            .map(|a| json!({ "address": a.to_string() }))
            .map_err(|e| format!("invalid address: {e:?}")),
        "minfee" => {
            let size = req.get("size").and_then(Value::as_u64).ok_or("missing `size`")? as usize;
            Ok(json!({ "fee": tokenomics::min_tx_fee_sat(size).to_string() }))
        }
        other => Err(format!("unknown op `{other}`")),
    }
}

fn pay(kp: &Keypair, utxos: &[(Vec<u8>, u32, TxOutput)], to: &str, amount: u64, mut fee: u64) -> Result<Value, String> {
    if amount == 0 {
        return Err("amount must be positive".into());
    }
    let dest = gnb_crypto::address::Address::parse(to.trim()).map_err(|e| format!("invalid destination: {e:?}"))?;
    let mine = gnb_crypto::address::Address::parse(&kp.address).map_err(|e| format!("{e:?}"))?;
    if dest.network() != mine.network() {
        return Err("destination is on another network".into());
    }
    let to_hex = hex::encode(dest.hash());
    // Falcon signatures vary in length, so each rebuild can come out a few
    // bytes larger or smaller. The fee only ever rises (to the largest minimum
    // seen), so this settles as soon as one build is not the largest yet.
    let mut tx: Option<Transaction> = None;
    for _ in 0..16 {
        let built = TxBuilder::build(kp, utxos, &to_hex, amount, fee)?;
        let min = tokenomics::min_tx_fee_sat(built.to_wire_bytes(true).len());
        if fee >= min {
            tx = Some(built);
            break;
        }
        fee = fee.max(min);
    }
    let tx = tx.ok_or("could not settle the fee")?;
    let raw = tx.to_wire_bytes(true);
    if raw.len() > MAX_TX_BYTES {
        return Err(format!(
            "this payment needs {} inputs ({} bytes), above the 400 kB limit; send a smaller amount and repeat",
            tx.inputs.len(), raw.len()));
    }
    let change: u64 = tx.outputs.iter().skip(1).map(|o| o.value).sum();
    Ok(json!({
        "raw": hex::encode(&raw), "txid": hex::encode(tx.txid()), "size": raw.len(),
        "fee": fee.to_string(), "inputs": tx.inputs.len(), "amount": amount.to_string(),
        "change": change.to_string(),
    }))
}

fn parse_utxos(rows: &Value) -> Result<Vec<(Vec<u8>, u32, TxOutput)>, String> {
    let rows = rows.as_array().ok_or("`utxos` must be an array")?;
    rows.iter().map(|row| {
        let txid = hex::decode(s(row, "txid")?).map_err(|e| e.to_string())?;
        if txid.len() != 32 {
            return Err("UTXO txid must be 32 bytes".into());
        }
        let index = row["index"].as_u64().and_then(|v| u32::try_from(v).ok()).ok_or("bad UTXO index")?;
        let value = match &row["value"] {
            Value::String(v) => v.parse().map_err(|_| "bad UTXO value")?,
            Value::Number(n) => n.as_u64().ok_or("bad UTXO value")?,
            _ => return Err("bad UTXO value".into()),
        };
        let script_pubkey = hex::decode(s(row, "script_pubkey")?).map_err(|e| e.to_string())?;
        Ok((txid, index, TxOutput { value, script_pubkey }))
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
        Ok(req) => match handle(&req) {
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

    #[test]
    fn create_export_open_roundtrip_and_pay() {
        let created = handle(&json!({"op": "create"})).unwrap();
        let addr = created["address"].as_str().unwrap().to_string();
        let ks = handle(&json!({"op": "export", "password": "Correct-Horse-9-battery"})).unwrap();
        let ks = ks["keystore"].as_str().unwrap().to_string();
        handle(&json!({"op": "wipe"})).unwrap();
        assert!(handle(&json!({"op": "address"})).is_err());
        let opened = handle(&json!({"op": "open", "json": ks, "password": "Correct-Horse-9-battery"})).unwrap();
        assert_eq!(opened["address"], addr);

        // Pay 3 GNB from two 2 GNB outputs owned by this key.
        let spk = gnb_crypto::address::Address::parse(&addr).unwrap().hash().to_vec();
        let utxos = json!([
            {"txid": "11".repeat(32), "index": 0, "value": "200000000", "script_pubkey": hex::encode(&spk)},
            {"txid": "22".repeat(32), "index": 1, "value": "200000000", "script_pubkey": hex::encode(&spk)},
        ]);
        let to = gnb_crypto::address::Address::from_hash([7u8; 20], gnb_crypto::address::Network::Mainnet).to_string();
        let r = handle(&json!({"op": "pay", "utxos": utxos, "to": to, "amount": "300000000", "fee": "0"})).unwrap();
        let size = r["size"].as_u64().unwrap() as usize;
        assert_eq!(r["inputs"], 2);
        assert!(r["fee"].as_str().unwrap().parse::<u64>().unwrap() >= tokenomics::min_tx_fee_sat(size));
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
    }
}
