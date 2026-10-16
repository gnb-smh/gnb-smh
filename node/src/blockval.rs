//! This chain's transaction rules that the shared pipeline
//! (`accept::validate_block_in_view_classified_at`, `mempool::admission`,
//! `template::self_check`) adds to the audit rule set.
//!
//! Every block of the current chain was validated with these rules at every
//! height (they predate the 2026-10-14 chain reset), so they are not gated by
//! the hardening activation:
//!
//! * `locktime` is a block height: a transaction is final, and so includable,
//!   only in a block at height ≥ `locktime` (`0` is always final);
//! * every output, the coinbase's included, is one of the two defined kinds
//!   (`core::policy::output_kind`: a 20-byte key hash or a 33-byte spend
//!   policy); anything else would be an unspendable, unaccountable burn;
//! * no output below the dust threshold;
//! * a policy spend (multisig / timelocks, docs/MULTISIG.md) satisfies its
//!   timelocks — absolute `after` against `locktime`, relative `older`
//!   against the spent output's confirmation height — and a policy-tree
//!   spend (one revealed branch) is valid only from `core::powit_height()`.
//!   The policy's keys and signatures are checked with every other input
//!   script (`core::sighash::verify_input_signatures`);
//! * BIP30: no transaction may create an outpoint that is still unspent, and
//!   no transaction may spend its own block's coinbase (both also hardening
//!   rules of the audit, VAL-2 / VAL-3, and both on this chain from genesis).

use crate::core::{self, policy, Transaction, TxOutput};

/// Confirmation-height reader for a txid's outputs (the tx index):
/// `Ok(None)` when unknown, `Err` when the index could not be read.
pub type ConfirmHeightLookup<'a> = dyn Fn(&[u8; 32]) -> Result<Option<u64>, String> + 'a;

/// Marks an error caused by missing local index data, never by the block.
pub const STORAGE_ERR: &str = "storage: ";

/// Rules that need only the transaction and the height of the block it is
/// (or would be) in: finality, output kinds, dust.
pub fn check_tx_context_free(tx: &Transaction, height: u64) -> Result<(), String> {
    if u64::from(tx.locktime) > height {
        return Err(format!("non-final: locktime {} > block height {}", tx.locktime, height));
    }
    for (j, out) in tx.outputs.iter().enumerate() {
        if policy::output_kind(&out.script_pubkey).is_none() {
            return Err(format!("output {}: unsupported script_pubkey ({} bytes)", j, out.script_pubkey.len()));
        }
    }
    if !tx.is_coinbase() {
        tx.validate_dust().map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// The policy-spend rules that depend on the chain, for a non-coinbase `tx`
/// spending `prevouts` (one per input, in order) in a block at `height`.
/// `confirm_height` resolves the block height a spent output was confirmed
/// at; its read failures are reported with the [`STORAGE_ERR`] prefix.
pub fn check_policy_spends(
    tx: &Transaction,
    prevouts: &[TxOutput],
    height: u64,
    confirm_height: &ConfirmHeightLookup<'_>,
) -> Result<(), String> {
    for (i, (inp, prev)) in tx.inputs.iter().zip(prevouts).enumerate() {
        if policy::output_kind(&prev.script_pubkey) != Some(policy::OutputKind::Policy) {
            continue;
        }
        let w = policy::AnyPolicyWitness::decode(&inp.script_sig)
            .map_err(|e| format!("malformed policy witness at input {}: {}", i, e))?;
        if w.is_branch() && !core::powit_active(height) {
            return Err(format!("policy-tree spend before activation at input {}", i));
        }
        let pol = w.policy();
        if pol.after != 0 && tx.locktime < pol.after {
            return Err(format!("input {}: absolute timelock: locktime {} < {}", i, tx.locktime, pol.after));
        }
        if pol.older != 0 {
            let confirmed = confirm_height(&inp.prev_txid)
                .map_err(|e| format!("{}{}", STORAGE_ERR, e))?
                .ok_or_else(|| format!("{}confirmation height of input {} unknown", STORAGE_ERR, i))?;
            let age = height.saturating_sub(confirmed);
            if age < u64::from(pol.older) {
                return Err(format!("input {}: relative timelock: {} confirmations < {}", i, age, pol.older));
            }
        }
    }
    Ok(())
}

/// Every rule of this module for a non-coinbase transaction.
pub fn check_tx_chain_rules(
    tx: &Transaction,
    prevouts: &[TxOutput],
    height: u64,
    confirm_height: &ConfirmHeightLookup<'_>,
) -> Result<(), String> {
    check_tx_context_free(tx, height)?;
    check_policy_spends(tx, prevouts, height, confirm_height)
}

/// Where a transaction is being validated: the height of the block it is (or
/// would be) in, and how to find when a spent output was confirmed.
pub struct SpendContext<'a> {
    pub height: u64,
    pub confirm_height: &'a ConfirmHeightLookup<'a>,
}

/// UTXO reader for the state a transaction or block is validated against.
pub type UtxoLookup<'a> = dyn Fn(&[u8; 32], u32) -> Result<Option<TxOutput>, String> + 'a;

/// Every rule a non-coinbase transaction must pass in a block at
/// `ctx.height` (no coinbase maturity, no in-block context): inputs exist and
/// are not spent twice (`spent_set` tracks spends across the caller's
/// transactions), this module's rules, the input scripts under the version /
/// sighash rule of that height (`core::sighash::verify_tx_scripts`, policy
/// spends included), value conservation and the consensus minimum fee.
/// Returns the fee. The block pipeline (`accept`) runs the same rules.
pub fn validate_tx_inputs(
    tx: &Transaction,
    utxo_lookup: &UtxoLookup<'_>,
    mut spent_set: Option<&mut std::collections::HashSet<([u8; 32], u32)>>,
    ctx: &SpendContext<'_>,
) -> Result<u64, String> {
    let mut local: std::collections::HashSet<([u8; 32], u32)> = std::collections::HashSet::new();
    let mut prevouts = Vec::with_capacity(tx.inputs.len());
    let mut total_in = 0u64;
    for inp in &tx.inputs {
        let op = (inp.prev_txid, inp.prev_index);
        if spent_set.as_ref().is_some_and(|s| s.contains(&op)) || !local.insert(op) {
            return Err(format!("double-spend: {}:{} already consumed", hex::encode(&op.0[..8]), op.1));
        }
        let out = utxo_lookup(&op.0, op.1)?
            .ok_or_else(|| format!("UTXO {}:{} not found", hex::encode(&op.0[..8]), op.1))?;
        total_in = core::limits::money_add(total_in, out.value).map_err(|e| format!("input overflow: {}", e))?;
        prevouts.push(out);
    }
    check_tx_chain_rules(tx, &prevouts, ctx.height, ctx.confirm_height)?;
    core::sighash::verify_tx_scripts(tx, &prevouts, core::node_chain_id(), ctx.height,
                                     core::activation::hardening_activation_height())?;
    if let Some(s) = spent_set.as_mut() {
        s.extend(local);
    }
    let total_out = core::limits::check_tx_money_range(tx).map_err(|e| format!("output sum overflow: {}", e))?;
    if total_in < total_out {
        return Err(format!("inputs {} < outputs {}", total_in, total_out));
    }
    let fee = total_in - total_out;
    core::check_min_fee(tx, fee)?;
    Ok(fee)
}

/// Why a block's transactions were not accepted (see
/// `accept::BlockInvalidity`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockTxError {
    /// A rule over data the block id commits to: permanent.
    Invalid(String),
    /// A rule over witness bytes the block id does not commit to.
    InvalidWitness(String),
    /// The state could not be read.
    Storage(String),
}

impl std::fmt::Display for BlockTxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockTxError::Invalid(e) | BlockTxError::InvalidWitness(e) => write!(f, "{}", e),
            BlockTxError::Storage(e) => write!(f, "storage error during validation: {}", e),
        }
    }
}

/// Validate every transaction of `block` against the state the lookups
/// describe (its selected parent's), exactly as the acceptance pipeline does
/// (`accept::validate_block_in_view_classified`), and return the total fee.
#[cfg(feature = "node")]
pub fn validate_block_transactions(
    block: &core::Block,
    utxo_lookup: &UtxoLookup<'_>,
    coinbase_height: &dyn Fn(&[u8; 32]) -> Result<Option<u64>, String>,
    confirm_height: &ConfirmHeightLookup<'_>,
) -> Result<u64, BlockTxError> {
    struct View<'a> {
        utxo: &'a UtxoLookup<'a>,
        coinbase: &'a dyn Fn(&[u8; 32]) -> Result<Option<u64>, String>,
        confirm: &'a ConfirmHeightLookup<'a>,
        error: std::cell::RefCell<Option<String>>,
    }
    impl View<'_> {
        fn note<T>(&self, r: Result<T, String>) -> Result<T, String> {
            r.inspect_err(|e| { self.error.borrow_mut().get_or_insert_with(|| e.clone()); })
        }
    }
    impl crate::reorg::UtxoView for View<'_> {
        fn view_utxo(&self, t: &[u8; 32], i: u32) -> Result<Option<TxOutput>, String> { self.note((self.utxo)(t, i)) }
        fn view_coinbase_height(&self, t: &[u8; 32]) -> Result<Option<u64>, String> { self.note((self.coinbase)(t)) }
        fn view_tx_height(&self, t: &[u8; 32]) -> Result<Option<u64>, String> { self.note((self.confirm)(t)) }
    }
    let view = View { utxo: utxo_lookup, coinbase: coinbase_height, confirm: confirm_height, error: Default::default() };
    let verdict = crate::accept::validate_block_in_view_classified(&view, block);
    if let Some(e) = view.error.into_inner() {
        return Err(BlockTxError::Storage(e));
    }
    verdict.map_err(|e| if e.witness_dependent {
        BlockTxError::InvalidWitness(e.reason)
    } else {
        BlockTxError::Invalid(e.reason)
    })?;
    // The fee total the coinbase may claim (the verdict already checked it).
    let mut created: std::collections::HashMap<([u8; 32], u32), u64> = std::collections::HashMap::new();
    let mut fees = 0u64;
    for (i, tx) in block.transactions.iter().enumerate() {
        if i > 0 {
            let mut inp = 0u64;
            for x in &tx.inputs {
                inp += match created.get(&(x.prev_txid, x.prev_index)) {
                    Some(v) => *v,
                    None => utxo_lookup(&x.prev_txid, x.prev_index).ok().flatten().map(|o| o.value).unwrap_or(0),
                };
            }
            fees += inp.saturating_sub(tx.outputs.iter().map(|o| o.value).sum::<u64>());
        }
        let txid = tx.txid();
        for (j, o) in tx.outputs.iter().enumerate() {
            created.insert((txid, j as u32), o.value);
        }
    }
    Ok(fees)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::TxInput;

    fn tx(locktime: u32, spk: Vec<u8>, value: u64) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxInput { prev_txid: [1; 32], prev_index: 0, script_sig: vec![], sequence: u32::MAX }],
            outputs: vec![TxOutput { value, script_pubkey: spk }],
            locktime,
        }
    }

    #[test]
    fn locktime_is_a_block_height() {
        assert!(check_tx_context_free(&tx(10, vec![0; 20], 10_000), 10).is_ok());
        assert!(check_tx_context_free(&tx(11, vec![0; 20], 10_000), 10).unwrap_err().contains("non-final"));
        assert!(check_tx_context_free(&tx(0, vec![0; 20], 10_000), 0).is_ok());
    }

    #[test]
    fn only_the_defined_output_kinds_and_no_dust() {
        assert!(check_tx_context_free(&tx(0, vec![0; 21], 10_000), 5).unwrap_err().contains("unsupported"));
        assert!(check_tx_context_free(&tx(0, vec![0; 20], 1), 5).is_err());
    }
}
