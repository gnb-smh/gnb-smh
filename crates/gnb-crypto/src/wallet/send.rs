//! Synchronous "send" flow shared by `gnb-cli send` and `gnb-wallet send`
//! (WAL-1, WAL-6, WAL-7). Transport-agnostic: the caller passes a JSON-RPC
//! closure, so the flow is unit-tested without a node.
//!
//! 1. `getutxos` (bounded by a limit);
//! 2. coin selection on the claimed values;
//! 3. `getrawtransaction` for every selected outpoint, hashed against its
//!    txid: a lying server is detected before anything is signed;
//! 4. build and sign with the size-aware fee and the maximum-fee guard;
//! 5. the caller shows [`PreparedSend::summary`] (actual fee, change,
//!    verified/unverified inputs) and asks for confirmation;
//! 6. [`broadcast`].

use super::payment::{BuiltPayment, FeeChoice, FeePolicy, PaymentOptions, PrevTxs};
use super::{Keypair, TxBuilder, Utxo};
use crate::address::Address;
use crate::core::TxOutput;
use serde_json::{json, Value};

/// JSON-RPC call: `(method, params) -> result`.
pub type RpcFn<'a> = dyn Fn(&str, &Value) -> Result<Value, String> + 'a;

/// What to send.
pub struct SendRequest<'a> {
    pub keypair: &'a Keypair,
    pub to: &'a Address,
    pub amount: u64,
    pub fee: FeeChoice,
    pub fee_policy: FeePolicy,
    /// Refuse inputs whose value could not be verified.
    pub require_verified_inputs: bool,
    /// Maximum UTXOs requested from the node.
    pub utxo_limit: u64,
}

/// A signed payment ready for confirmation and broadcast.
pub struct PreparedSend {
    pub payment: BuiltPayment,
    /// UTXOs and value the node reported.
    pub utxos_seen: usize,
    pub value_seen: u64,
}

fn gnb(sat: u64) -> String {
    format!("{}.{:08} GNB", sat / 100_000_000, sat % 100_000_000)
}

impl PreparedSend {
    /// Lines for the confirmation screen: everything the signature commits
    /// to, plus the ACTUAL fee and the verification status of the inputs.
    pub fn summary(&self, from: &str, to: &str) -> Vec<(String, String)> {
        let p = &self.payment;
        let mut lines = vec![
            ("from".into(), from.to_string()),
            ("to".into(), to.to_string()),
            ("amount".into(), format!("{} ({} sat)", gnb(p.amount), p.amount)),
            ("network fee".into(), format!("{} ({} sat){}", gnb(p.fee), p.fee,
                if p.dust_to_fee > 0 { format!(", incl. {} sat dust change", p.dust_to_fee) } else { String::new() })),
            ("change".into(), gnb(p.change)),
            ("total leaving".into(), gnb(p.amount.saturating_add(p.fee))),
            ("inputs".into(), format!("{} ({} verified, {} unverified) · {} bytes",
                p.tx.inputs.len(), p.verified_inputs, p.unverified_inputs, p.size)),
            ("txid".into(), hex::encode(p.tx.txid())),
        ];
        if p.unverified_inputs > 0 {
            lines.push(("warning".into(), format!(
                "{} input value(s) come only from the node (carryover or pruned history) and \
                 could not be checked against their transaction",
                p.unverified_inputs
            )));
        }
        lines
    }

    pub fn raw_hex(&self) -> String {
        hex::encode(self.payment.tx.to_wire_bytes(true))
    }
}

/// A `{"error": ...}` object returned as an RPC *result* (this node's style).
fn result_error(v: &Value) -> Option<String> {
    v.get("error").filter(|e| !e.is_null()).map(|e| match e.as_str() {
        Some(s) => s.to_string(),
        None => e.to_string(),
    })
}

/// Parse `getutxos` rows. Malformed rows are refused, never filtered.
pub fn parse_utxo_rows(result: &Value) -> Result<Vec<Utxo>, String> {
    let rows = result.get("utxos").and_then(Value::as_array).ok_or("RPC response missing UTXO array")?;
    rows.iter().map(|row| {
        let txid: [u8; 32] = row.get("txid").and_then(Value::as_str)
            .and_then(|s| hex::decode(s).ok()).and_then(|b| b.try_into().ok())
            .ok_or("UTXO transaction ID must be 32 bytes of hex")?;
        let index = row.get("index").and_then(Value::as_u64).and_then(|v| u32::try_from(v).ok())
            .ok_or("UTXO index must fit u32")?;
        let value = row.get("value").and_then(super::sat_u64).ok_or("invalid UTXO value")?;
        let script_pubkey = row.get("script_pubkey").and_then(Value::as_str)
            .and_then(|s| hex::decode(s).ok()).ok_or("invalid UTXO script")?;
        Ok(Utxo { txid, index, output: TxOutput { value, script_pubkey } })
    }).collect()
}

/// Steps 1–4: fetch, select, verify, build and sign. Nothing is broadcast.
pub fn prepare_send(rpc: &RpcFn<'_>, req: &SendRequest<'_>) -> Result<PreparedSend, String> {
    let result = rpc("getutxos", &json!([req.keypair.address, req.utxo_limit]))?;
    if let Some(e) = result_error(&result) {
        return Err(format!("getutxos: {e}"));
    }
    let utxos = parse_utxo_rows(&result)?;
    if utxos.is_empty() {
        return Err(format!("no UTXOs found for {}", req.keypair.address));
    }
    let value_seen = utxos.iter().try_fold(0u64, |t, u| t.checked_add(u.output.value))
        .ok_or("UTXO value total exceeds u64")?;

    let planned = TxBuilder::plan_inputs(req.keypair, &utxos, req.amount, req.fee)?;
    let mut prevs = PrevTxs::new();
    let mut seen = std::collections::BTreeSet::new();
    for (txid, _) in &planned {
        if !seen.insert(*txid) { continue; }
        let txid_hex = hex::encode(txid);
        // A node without the method, or without the body (carryover,
        // pruned), leaves the input unverified; a forged body is an error.
        if let Ok(v) = rpc("getrawtransaction", &json!([txid_hex])) {
            if let Some(raw) = v.get("hex").and_then(Value::as_str) {
                prevs.insert_hex(&txid_hex, raw)?;
            }
        }
    }

    let opts = PaymentOptions {
        fee: req.fee,
        fee_policy: req.fee_policy,
        prev_txs: Some(&prevs),
        require_verified_inputs: req.require_verified_inputs,
        ..PaymentOptions::default()
    };
    let payment = TxBuilder::build_payment(req.keypair, &utxos, req.to, req.amount, &opts)?;
    Ok(PreparedSend { payment, utxos_seen: utxos.len(), value_seen })
}

/// Step 6: broadcast and check the node echoes the right txid.
pub fn broadcast(rpc: &RpcFn<'_>, prepared: &PreparedSend) -> Result<String, String> {
    let result = rpc("sendrawtransaction", &json!([prepared.raw_hex()]))?;
    if let Some(e) = result_error(&result) {
        return Err(format!("broadcast rejected: {e}"));
    }
    let txid = hex::encode(prepared.payment.tx.txid());
    match result.get("txid").and_then(Value::as_str) {
        Some(t) if t == txid => Ok(txid),
        Some(t) => Err(format!("node reported txid {t}, expected {txid}")),
        None => Err("broadcast response missing txid".into()),
    }
}

/// Ask `question` on stderr and read a yes/no answer from stdin (default no).
pub fn confirm(question: &str) -> bool {
    use std::io::Write;
    eprint!("{question} [y/N] ");
    let _ = std::io::stderr().flush();
    let mut answer = String::new();
    if std::io::stdin().read_line(&mut answer).is_err() {
        return false;
    }
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// Parse a CLI fee argument: `auto` (or empty) = consensus minimum for the
/// actual size; otherwise a GNB amount used as a floor (raised to the
/// minimum when lower).
pub fn parse_fee_arg(value: &str) -> Result<FeeChoice, &'static str> {
    let value = value.trim();
    if value.is_empty() || value.eq_ignore_ascii_case("auto") {
        return Ok(FeeChoice::AUTO);
    }
    Ok(FeeChoice::AtLeast(super::parse_bloch_satoshis(value)?))
}

/// Parse a CLI `--max-fee` argument (GNB) into an explicit guard override.
pub fn parse_max_fee_arg(value: Option<&str>) -> Result<FeePolicy, &'static str> {
    match value {
        None => Ok(FeePolicy::DEFAULT),
        Some(v) => Ok(FeePolicy::with_max_fee(super::parse_bloch_satoshis(v)?)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Network;
    use crate::core::{Transaction, TxInput};
    use std::cell::RefCell;

    const SAT: u64 = 100_000_000;

    fn prev_paying(kp: &Keypair, value: u64) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxInput { prev_txid: [4; 32], prev_index: 0, script_sig: vec![], sequence: u32::MAX }],
            outputs: vec![TxOutput { value, script_pubkey: kp.address_bytes() }],
            locktime: 0,
        }
    }

    fn mock<'a>(
        claimed: u64,
        prev: &'a Transaction,
        serve_prev: bool,
        calls: &'a RefCell<Vec<String>>,
    ) -> impl Fn(&str, &Value) -> Result<Value, String> + 'a {
        move |method, _params| {
            calls.borrow_mut().push(method.to_string());
            let txid = hex::encode(prev.txid());
            Ok(match method {
                "getutxos" => json!({"utxos": [{"txid": txid, "index": 0, "value": claimed.to_string(),
                    "script_pubkey": hex::encode(&prev.outputs[0].script_pubkey)}]}),
                "getrawtransaction" if serve_prev => json!({"txid": txid, "hex": hex::encode(prev.to_wire_bytes(true))}),
                "getrawtransaction" => json!({"error": "transaction body not available"}),
                "sendrawtransaction" => json!({"txid": "00"}),
                _ => json!({"error": "unknown method"}),
            })
        }
    }

    fn request<'a>(kp: &'a Keypair, to: &'a Address) -> SendRequest<'a> {
        SendRequest { keypair: kp, to, amount: SAT, fee: FeeChoice::AUTO, fee_policy: FeePolicy::DEFAULT,
            require_verified_inputs: false, utxo_limit: 50 }
    }

    /// WAL-1 regression for both CLIs: a lied value is detected and the
    /// flow never reaches broadcast.
    #[test]
    fn cli_send_detects_a_lied_utxo_value() {
        let kp = super::super::generate_keypair(false);
        let to = Address::from_hash([7; 20], Network::Mainnet);
        let prev = prev_paying(&kp, 100 * SAT);
        let calls = RefCell::new(Vec::new());
        let rpc = mock(SAT + 50_000, &prev, true, &calls);
        let err = prepare_send(&rpc, &request(&kp, &to)).err().unwrap();
        assert!(err.contains("refusing to sign"), "{err}");
        assert!(!calls.borrow().iter().any(|m| m == "sendrawtransaction"));
    }

    #[test]
    fn cli_send_reports_actual_fee_and_verification() {
        let kp = super::super::generate_keypair(false);
        let to = Address::from_hash([7; 20], Network::Mainnet);
        let prev = prev_paying(&kp, 100 * SAT);
        let calls = RefCell::new(Vec::new());
        let rpc = mock(100 * SAT, &prev, true, &calls);
        let prepared = prepare_send(&rpc, &request(&kp, &to)).unwrap();
        assert_eq!(prepared.payment.verified_inputs, 1);
        let summary = prepared.summary(&kp.address, &to.to_string());
        let fee_line = &summary.iter().find(|(k, _)| k == "network fee").unwrap().1;
        assert!(fee_line.contains(&format!("({} sat)", prepared.payment.fee)));
        assert!(!summary.iter().any(|(k, _)| k == "warning"));
        // The mock echoes a wrong txid: broadcast refuses to report success.
        assert!(broadcast(&rpc, &prepared).is_err());

        // Unserved previous transaction: allowed but flagged, or refused.
        let rpc = mock(100 * SAT, &prev, false, &calls);
        let prepared = prepare_send(&rpc, &request(&kp, &to)).unwrap();
        assert_eq!(prepared.payment.unverified_inputs, 1);
        assert!(prepared.summary(&kp.address, &to.to_string()).iter().any(|(k, _)| k == "warning"));
        let strict = SendRequest { require_verified_inputs: true, ..request(&kp, &to) };
        assert!(prepare_send(&rpc, &strict).is_err());
    }

    #[test]
    fn fee_arguments_parse() {
        assert_eq!(parse_fee_arg("auto"), Ok(FeeChoice::AUTO));
        assert_eq!(parse_fee_arg("0.0005"), Ok(FeeChoice::AtLeast(50_000)));
        assert!(parse_fee_arg("-1").is_err());
        assert_eq!(parse_max_fee_arg(None), Ok(FeePolicy::DEFAULT));
        assert_eq!(parse_max_fee_arg(Some("1")).unwrap().max_fee_sat, SAT);
    }
}
