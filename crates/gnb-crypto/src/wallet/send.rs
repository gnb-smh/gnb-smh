//! Synchronous "send" flow shared by `gnb-cli send` and `gnb-wallet send`
//! (WAL-1, WAL-6, WAL-7). Transport-agnostic: the caller passes a JSON-RPC
//! closure, so the flow is unit-tested without a node.
//!
//! 1. `getutxos` (bounded by a limit; a truncated window that cannot pay is
//!    asked again with the node's whole window, `GETUTXOS_MAX_ROWS`) and
//!    `getdaginfo` (the next block's height = `next_block_height`, or
//!    `tip_height` + 1 from an older node; it selects the transaction
//!    version: 3 with sighash v3 at/after the hardening activation, 1 below
//!    it);
//! 2. coin selection on the claimed values, among the outputs spendable in
//!    the next block (a coinbase output, `coinbase_height` in its row, only
//!    from `COINBASE_MATURITY` blocks after its coinbase);
//! 3. version 1 only: `getrawtransaction` for every selected outpoint, hashed
//!    against its txid, so a lying server is detected before anything is
//!    signed. A version-3 signature commits to every spent value and script,
//!    so a lie only produces a transaction the network rejects; nothing is
//!    fetched;
//! 4. build and sign with the size-aware fee and the maximum-fee guard;
//! 5. the caller shows [`PreparedSend::summary`] (actual fee, change,
//!    verified/unverified inputs) and asks for confirmation;
//! 6. [`broadcast`].

use super::payment::{self, BuiltPayment, FeeChoice, FeePolicy, PaymentOptions, PrevTxs};
use super::{Keypair, TxBuilder, Utxo};
use crate::address::Address;
use crate::core::{ChainId, TxOutput};
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
            ("inputs".into(), if p.amounts_committed {
                format!("{} (values committed by the version-3 signature) · {} bytes", p.tx.inputs.len(), p.size)
            } else {
                format!("{} ({} verified, {} unverified) · {} bytes",
                    p.tx.inputs.len(), p.verified_inputs, p.unverified_inputs, p.size)
            }),
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

/// Whether the `getutxos` row `row` is spendable in the block at
/// `next_block_height`: a row carrying `coinbase_height` (an output of a
/// coinbase) only from `coinbase_height + COINBASE_MATURITY` on
/// (`core::check_coinbase_maturity`); a row without the field (an older node,
/// or not a coinbase) is. A malformed field is refused. The one rule every
/// wallet path selects coins by: `gnb-cli` / `gnb-wallet` (`prepare_send`),
/// `WalletClient::send_payment` and the browser wallet core
/// (crates/gnb-wallet-wasm). Selecting an immature output produced a
/// transaction every node refuses (test/functional/wallet_coinbase_maturity.py).
pub fn utxo_row_spendable_at(row: &Value, next_block_height: u64) -> Result<bool, String> {
    match row.get("coinbase_height") {
        None | Some(Value::Null) => Ok(true),
        Some(v) => {
            let h = v.as_u64().ok_or("UTXO coinbase_height must be an integer")?;
            Ok(next_block_height.saturating_sub(h) >= crate::core::COINBASE_MATURITY)
        }
    }
}

/// Why a payment cannot be built when every coin of `address` is an immature
/// coinbase output (`immature` of them) at `next_block_height`.
pub fn all_immature_message(address: &str, immature: usize, next_block_height: u64) -> String {
    format!("no spendable UTXOs for {address}: {immature} coinbase output(s) still immature at height \
        {next_block_height} (coinbase outputs mature after {} blocks)", crate::core::COINBASE_MATURITY)
}

/// `getutxos` rows spendable in the block at `next_block_height`
/// ([`utxo_row_spendable_at`]), and how many were left out. A malformed row
/// is refused, like every other malformed row.
pub fn spendable_utxo_rows(result: &Value, next_block_height: u64) -> Result<(Vec<Utxo>, usize), String> {
    let utxos = parse_utxo_rows(result)?;
    let rows = result.get("utxos").and_then(Value::as_array).ok_or("RPC response missing UTXO array")?;
    let mut spendable = Vec::with_capacity(utxos.len());
    let mut immature = 0;
    for (utxo, row) in utxos.into_iter().zip(rows) {
        if utxo_row_spendable_at(row, next_block_height)? { spendable.push(utxo) } else { immature += 1 }
    }
    Ok((spendable, immature))
}

/// The height of the next block from a `getdaginfo` result: its
/// `next_block_height` (the height the node's mempool admission and block
/// template check a transaction against; it can exceed `tip_height` + 1 when
/// the template merges a tip with a greater DAG height), or, from a node that
/// predates that field, the selected tip's height + 1.
pub fn next_block_height_from_daginfo(result: &Value) -> Result<u64, String> {
    if let Some(e) = result_error(result) {
        return Err(format!("getdaginfo: {e}"));
    }
    match result.get("next_block_height") {
        None | Some(Value::Null) => result.get("tip_height").and_then(Value::as_u64)
            .and_then(|h| h.checked_add(1))
            .ok_or_else(|| "getdaginfo: missing or invalid tip_height".to_string()),
        Some(v) => v.as_u64().filter(|&h| h >= 1)
            .ok_or_else(|| "getdaginfo: invalid next_block_height".to_string()),
    }
}

/// The most `getutxos` rows the node returns in one call (its `GETUTXOS_MAX`
/// in node/src/rpc/mod.rs; a larger limit is capped to it).
pub const GETUTXOS_MAX_ROWS: u64 = 10_000;

/// Whether a `getutxos` result says the node stopped listing at the limit.
fn utxos_truncated(result: &Value) -> bool {
    result.get("truncated").and_then(Value::as_bool).unwrap_or(false)
}

/// Steps 1–4: fetch, select, verify, build and sign. Nothing is broadcast.
///
/// The node lists an address's unspent outputs in index order up to
/// `req.utxo_limit` (`truncated` when it stopped there), so the window can
/// miss the coins a payment needs: immature coinbase outputs, which are
/// never selected, can fill most or all of it, or what it holds is too
/// little. When a truncated window fails, the flow asks once more for the
/// node's whole window ([`GETUTXOS_MAX_ROWS`], what `WalletClient` asks for);
/// an error from a window that is still truncated says so, instead of
/// claiming that the address has no spendable coins.
pub fn prepare_send(rpc: &RpcFn<'_>, req: &SendRequest<'_>) -> Result<PreparedSend, String> {
    let result = fetch_utxos(rpc, req, req.utxo_limit)?;
    let next_block_height = next_block_height_from_daginfo(&rpc("getdaginfo", &json!([]))?)?;
    match prepare_from_rows(rpc, req, &result, next_block_height) {
        Err(_) if utxos_truncated(&result) && req.utxo_limit < GETUTXOS_MAX_ROWS => {
            let wide = fetch_utxos(rpc, req, GETUTXOS_MAX_ROWS)?;
            prepare_from_rows(rpc, req, &wide, next_block_height)
                .map_err(|e| with_truncation_note(e, &wide, &req.keypair.address))
        }
        Err(e) => Err(with_truncation_note(e, &result, &req.keypair.address)),
        ok => ok,
    }
}

/// Step 1: `getutxos` of the sender's address, at most `limit` rows.
fn fetch_utxos(rpc: &RpcFn<'_>, req: &SendRequest<'_>, limit: u64) -> Result<Value, String> {
    let result = rpc("getutxos", &json!([req.keypair.address, limit]))?;
    if let Some(e) = result_error(&result) {
        return Err(format!("getutxos: {e}"));
    }
    Ok(result)
}

/// `error`, and when `result` (a `getutxos` answer) was truncated, that the
/// node listed only part of `address`'s unspent outputs.
fn with_truncation_note(error: String, result: &Value, address: &str) -> String {
    if !utxos_truncated(result) {
        return error;
    }
    let listed = result.get("utxos").and_then(Value::as_array).map_or(0, Vec::len);
    format!("{error} (the node listed only the first {listed} unspent outputs of {address}: \
        getutxos truncated; spendable coins may exist beyond them)")
}

/// Steps 2–4 on one `getutxos` result.
fn prepare_from_rows(rpc: &RpcFn<'_>, req: &SendRequest<'_>, result: &Value, next_block_height: u64)
    -> Result<PreparedSend, String>
{
    let all = parse_utxo_rows(result)?;
    if all.is_empty() {
        return Err(format!("no UTXOs found for {}", req.keypair.address));
    }
    let value_seen = all.iter().try_fold(0u64, |t, u| t.checked_add(u.output.value))
        .ok_or("UTXO value total exceeds u64")?;
    // Coinbase outputs not yet mature at the next block are never selected.
    let (utxos, immature) = spendable_utxo_rows(result, next_block_height)?;
    if utxos.is_empty() {
        return Err(all_immature_message(&req.keypair.address, immature, next_block_height));
    }
    let chain_id = ChainId::for_network(req.keypair.network()?);

    let mut prevs = PrevTxs::new();
    if !payment::amounts_committed_at(next_block_height, chain_id) {
        let planned = TxBuilder::plan_inputs(req.keypair, &utxos, req.amount, req.fee)?;
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
    }

    let opts = PaymentOptions {
        fee: req.fee,
        fee_policy: req.fee_policy,
        prev_txs: Some(&prevs),
        require_verified_inputs: req.require_verified_inputs,
        next_block_height: Some(next_block_height),
        ..PaymentOptions::default()
    };
    let payment = TxBuilder::build_payment(req.keypair, &utxos, req.to, req.amount, &opts)?;
    Ok(PreparedSend { payment, utxos_seen: all.len(), value_seen })
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
        // Mainnet tip far below the activation: version-1 payments.
        mock_at(claimed, prev, serve_prev, calls, 10)
    }

    fn mock_at<'a>(
        claimed: u64,
        prev: &'a Transaction,
        serve_prev: bool,
        calls: &'a RefCell<Vec<String>>,
        tip_height: u64,
    ) -> impl Fn(&str, &Value) -> Result<Value, String> + 'a {
        move |method, _params| {
            calls.borrow_mut().push(method.to_string());
            let txid = hex::encode(prev.txid());
            Ok(match method {
                "getdaginfo" => json!({"tip_height": tip_height, "tip_blue_score": tip_height}),
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

    /// WAL-1 full fix through the CLI flow: at the activation height the
    /// payment is version 3, no previous transaction is fetched, and a lied
    /// value yields a signature that is invalid for the real UTXO.
    #[test]
    fn cli_send_signs_version_3_from_the_activation_height() {
        use crate::core::{activation, sighash};
        let kp = super::super::generate_keypair(false);
        let to = Address::from_hash([7; 20], Network::Mainnet);
        let prev = prev_paying(&kp, 100 * SAT);
        let act = activation::MAINNET_HARDENING_ACTIVATION_HEIGHT;

        // Next block = act - 1: version 1, previous transaction fetched.
        let calls = RefCell::new(Vec::new());
        let rpc = mock_at(100 * SAT, &prev, true, &calls, act - 2);
        let v1 = prepare_send(&rpc, &request(&kp, &to)).unwrap();
        assert_eq!(v1.payment.tx.version, 1);
        assert!(calls.borrow().iter().any(|m| m == "getrawtransaction"));

        // Next block = act: version 3, nothing fetched, values committed.
        let calls = RefCell::new(Vec::new());
        let rpc = mock_at(SAT + 50_000, &prev, true, &calls, act - 1);
        let strict = SendRequest { require_verified_inputs: true, ..request(&kp, &to) };
        let v3 = prepare_send(&rpc, &strict).unwrap();
        assert_eq!(v3.payment.tx.version, 3);
        assert!(v3.payment.amounts_committed);
        assert!(!calls.borrow().iter().any(|m| m == "getrawtransaction"));
        assert!(!v3.summary(&kp.address, &to.to_string()).iter().any(|(k, _)| k == "warning"));
        // The lie (claimed 1.0005 GNB for a 100 GNB coin) makes the signature
        // invalid against the real coin: the network rejects it, nothing is lost.
        let real = prev.outputs[0].clone();
        let claimed = TxOutput { value: SAT + 50_000, ..real.clone() };
        let verify = |spent: &TxOutput| sighash::verify_tx_scripts(&v3.payment.tx, std::slice::from_ref(spent),
            crate::core::ChainId::Mainnet, act, act);
        assert!(verify(&claimed).is_ok());
        assert!(verify(&real).unwrap_err().contains("invalid signature"));
    }

    /// Rows for `spendable_utxo_rows` / `prepare_send`: (value, coinbase_height).
    fn rows(kp: &Keypair, coins: &[(u64, Option<u64>)]) -> Value {
        let list: Vec<Value> = coins.iter().enumerate().map(|(i, (value, cb))| {
            let mut row = json!({"txid": hex::encode([i as u8 + 1; 32]), "index": 0,
                "value": value.to_string(), "script_pubkey": hex::encode(kp.address_bytes())});
            if let Some(h) = cb { row["coinbase_height"] = json!(h); }
            row
        }).collect();
        json!({ "utxos": list })
    }

    /// Coinbase outputs are spendable from `coinbase_height +
    /// COINBASE_MATURITY` on: one below that is left out, at it kept; rows
    /// without the field are kept; a malformed field is refused.
    #[test]
    fn immature_coinbase_rows_are_not_spendable() {
        use crate::core::COINBASE_MATURITY as M;
        let kp = super::super::generate_keypair(false);
        let r = rows(&kp, &[(SAT, None), (2 * SAT, Some(500)), (3 * SAT, Some(500 - M))]);
        let (ok, immature) = spendable_utxo_rows(&r, 500 + M - 1).unwrap();
        assert_eq!((ok.iter().map(|u| u.output.value).collect::<Vec<_>>(), immature), (vec![SAT, 3 * SAT], 1));
        let (ok, immature) = spendable_utxo_rows(&r, 500 + M).unwrap();
        assert_eq!((ok.len(), immature), (3, 0));
        let mut bad = r.clone();
        bad["utxos"][1]["coinbase_height"] = json!("500");
        assert!(spendable_utxo_rows(&bad, 1_000).is_err());
    }

    /// The send flow never selects an immature coinbase output, even when it
    /// is the only coin that covers the payment alone (the old selection
    /// picked it and the node refused the broadcast), and says why when only
    /// immature coins are left.
    #[test]
    fn cli_send_skips_immature_coinbase_outputs() {
        let kp = super::super::generate_keypair(false);
        let to = Address::from_hash([7; 20], Network::Mainnet);
        let tip = 1_000u64;
        let utxos = rows(&kp, &[(100 * SAT, Some(tip)), (2 * SAT, Some(tip - 200)), (2 * SAT, None)]);
        let rpc = |method: &str, _p: &Value| -> Result<Value, String> {
            Ok(match method {
                "getdaginfo" => json!({"tip_height": tip, "next_block_height": tip + 1}),
                "getutxos" => utxos.clone(),
                _ => json!({"error": "unknown method"}),
            })
        };
        let req = SendRequest { amount: 3 * SAT, ..request(&kp, &to) };
        let prepared = prepare_send(&rpc, &req).unwrap();
        let spent: Vec<[u8; 32]> = prepared.payment.tx.inputs.iter().map(|i| i.prev_txid).collect();
        assert_eq!(spent.len(), 2);
        assert!(!spent.contains(&[1u8; 32]), "the immature 100 GNB coinbase output was selected");
        assert_eq!(prepared.utxos_seen, 3);

        let only_immature = rows(&kp, &[(100 * SAT, Some(tip))]);
        let rpc = |method: &str, _p: &Value| -> Result<Value, String> {
            Ok(match method {
                "getdaginfo" => json!({"tip_height": tip}),
                "getutxos" => only_immature.clone(),
                _ => json!({"error": "unknown method"}),
            })
        };
        let err = prepare_send(&rpc, &request(&kp, &to)).err().unwrap();
        assert!(err.contains("immature"), "{err}");
    }

    /// The txid of the `i`-th coin of [`window_mock`]: `i` + 1, big-endian.
    fn window_txid(i: usize) -> [u8; 32] {
        let mut t = [0u8; 32];
        t[..4].copy_from_slice(&(i as u32 + 1).to_be_bytes());
        t
    }

    /// A `getutxos` mock of a node listing `coins` (value, coinbase_height)
    /// in order up to the requested limit, `truncated` when it stops there,
    /// as the node does; records each call's method and limit.
    fn window_mock<'a>(kp: &'a Keypair, coins: &'a [(u64, Option<u64>)], tip: u64,
        calls: &'a RefCell<Vec<(String, Option<u64>)>>)
        -> impl Fn(&str, &Value) -> Result<Value, String> + 'a
    {
        move |method, params| {
            let limit = params.get(1).and_then(Value::as_u64);
            calls.borrow_mut().push((method.to_string(), limit));
            Ok(match method {
                "getdaginfo" => json!({"tip_height": tip, "next_block_height": tip + 1}),
                "getutxos" => {
                    let limit = limit.unwrap_or(GETUTXOS_MAX_ROWS).min(GETUTXOS_MAX_ROWS) as usize;
                    let list: Vec<Value> = coins.iter().take(limit).enumerate().map(|(i, (value, cb))| {
                        let mut row = json!({"txid": hex::encode(window_txid(i)), "index": 0,
                            "value": value.to_string(), "script_pubkey": hex::encode(kp.address_bytes())});
                        if let Some(h) = cb { row["coinbase_height"] = json!(h); }
                        row
                    }).collect();
                    json!({"utxos": list, "truncated": coins.len() > limit})
                }
                _ => json!({"error": "unknown method"}),
            })
        }
    }

    /// `gnb-cli send` asks for a 50-row window. When immature coinbase
    /// outputs fill it (a miner's address) and the mature coins come after
    /// them in the node's order, the send used to fail with "no spendable
    /// UTXOs ... still immature" although the address could pay; it now
    /// asks again for the node's whole window and pays from the mature
    /// coins. A window that could pay is not asked again, and a failure on a
    /// window that is still truncated says the list was truncated.
    #[test]
    fn a_truncated_window_of_immature_coinbase_outputs_is_widened() {
        let kp = super::super::generate_keypair(false);
        let to = Address::from_hash([7; 20], Network::Mainnet);
        let tip = 1_000u64;
        let mut coins: Vec<(u64, Option<u64>)> = vec![(10 * SAT, Some(tip)); 55];
        coins.extend([(2 * SAT, None); 5]);
        let calls = RefCell::new(Vec::new());
        let rpc = window_mock(&kp, &coins, tip, &calls);
        let req = SendRequest { amount: 3 * SAT, ..request(&kp, &to) };
        let prepared = prepare_send(&rpc, &req).unwrap();
        let spent: Vec<[u8; 32]> = prepared.payment.tx.inputs.iter().map(|i| i.prev_txid).collect();
        assert_eq!(spent.len(), 2);
        assert!(spent.iter().all(|t| (55..60).any(|i| *t == window_txid(i))),
            "an immature coinbase output was selected: {spent:?}");
        let windows: Vec<Option<u64>> = calls.borrow().iter()
            .filter(|(m, _)| m == "getutxos").map(|(_, l)| *l).collect();
        assert_eq!(windows, vec![Some(50), Some(GETUTXOS_MAX_ROWS)]);
        assert_eq!(prepared.utxos_seen, 60);

        // Mature coins inside the first window: one call, as before.
        let mut coins: Vec<(u64, Option<u64>)> = vec![(2 * SAT, None); 5];
        coins.extend(vec![(10 * SAT, Some(tip)); 55]);
        let calls = RefCell::new(Vec::new());
        let rpc = window_mock(&kp, &coins, tip, &calls);
        prepare_send(&rpc, &req).unwrap();
        assert_eq!(calls.borrow().iter().filter(|(m, _)| m == "getutxos").count(), 1);

        // Still truncated at the node's cap: the error says so.
        let coins: Vec<(u64, Option<u64>)> = vec![(10 * SAT, Some(tip)); GETUTXOS_MAX_ROWS as usize + 1];
        let calls = RefCell::new(Vec::new());
        let rpc = window_mock(&kp, &coins, tip, &calls);
        let err = prepare_send(&rpc, &req).err().unwrap();
        assert!(err.contains("immature") && err.contains("truncated"), "{err}");
        assert!(err.contains(&format!("first {GETUTXOS_MAX_ROWS} unspent outputs")), "{err}");
        // A caller already asking for the whole window: asked once, same note.
        let calls = RefCell::new(Vec::new());
        let rpc = window_mock(&kp, &coins, tip, &calls);
        let whole = SendRequest { utxo_limit: GETUTXOS_MAX_ROWS, ..req };
        let err = prepare_send(&rpc, &whole).err().unwrap();
        assert!(err.contains("immature") && err.contains("truncated"), "{err}");
        assert_eq!(calls.borrow().iter().filter(|(m, _)| m == "getutxos").count(), 1);

        // Not truncated: the plain message, one call.
        let coins = vec![(10 * SAT, Some(tip)); 3];
        let calls = RefCell::new(Vec::new());
        let rpc = window_mock(&kp, &coins, tip, &calls);
        let err = prepare_send(&rpc, &req).err().unwrap();
        assert!(err.contains("immature") && !err.contains("truncated"), "{err}");
        assert_eq!(calls.borrow().iter().filter(|(m, _)| m == "getutxos").count(), 1);
    }

    #[test]
    fn daginfo_height_parsing() {
        assert_eq!(next_block_height_from_daginfo(&json!({"tip_height": 41})), Ok(42));
        // The node's own next height wins (a template merging a tip with a
        // greater DAG height sits above tip_height + 1).
        assert_eq!(next_block_height_from_daginfo(&json!({"tip_height": 41, "next_block_height": 43})), Ok(43));
        assert_eq!(next_block_height_from_daginfo(&json!({"tip_height": 41, "next_block_height": null})), Ok(42));
        assert!(next_block_height_from_daginfo(&json!({"tip_height": 41, "next_block_height": 0})).is_err());
        assert!(next_block_height_from_daginfo(&json!({"tip_height": 41, "next_block_height": "43"})).is_err());
        assert!(next_block_height_from_daginfo(&json!({})).is_err());
        assert!(next_block_height_from_daginfo(&json!({"error": "x"})).is_err());
        assert!(next_block_height_from_daginfo(&json!({"tip_height": u64::MAX})).is_err());
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
