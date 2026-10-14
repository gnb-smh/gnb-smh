//! Shared transaction standardness + admission (audit MEM-1, MEM-4, MEM-5,
//! MEM-6, MEM-7).
//!
//! Before this module the node had three admission paths with different
//! rules: gossip (`validate_tx_standalone`: no dust check, maturity against
//! the DAG block COUNT), RPC `sendrawtransaction` (dust check, tip height) and
//! reorg re-injection (UTXO presence only). A single gossiped dust transaction
//! was therefore admitted from any peer and made every block template
//! consensus-invalid (MEM-1). Every ingress path now calls [`admit`] (or
//! [`check_transaction`] when only the verdict is needed), whose rules are a
//! superset of the block rules a pooled transaction must satisfy to be mined.
//!
//! Checks run cheapest first (MEM-5), so the expensive, size-dependent
//! signature work only ever runs on a transaction that passed everything else:
//!
//!  1. structure: not a coinbase, has inputs and outputs;
//!  2. size: canonical wire size and bincode size within `MAX_TX_SIZE` — this
//!     bounds the quadratic `Transaction::sighash` cost before any signature
//!     is checked (the sighash itself is consensus and is NOT changed);
//!  3. known: already pooled, already confirmed, or recently rejected (a
//!     replay costs one size-bounded hash);
//!  4. standardness: canonical-encoding limits (VAL-12), MoneyRange (VAL-11),
//!     no dust output (the consensus `Block::validate_dust` rule), no
//!     zero-value output (policy: UTXO-set bloat, VAL-11 note);
//!  5. conflicts: an input already spent by a pooled tx (first-seen wins —
//!     the explicit replacement rule is "no replacement", MEM-6);
//!  6. duplicate inputs within the tx (C-R3-2);
//!  7. UTXO presence (no unconfirmed parents: package relay is not supported);
//!  8. coinbase maturity at the height of the NEXT block (selected-tip DAG
//!     height + 1, never `dag.block_count()`, MEM-4);
//!  9. value: inputs ≥ outputs, MoneyRange of the input sum, consensus
//!     minimum fee, relay fee rate, rolling minimum fee (MEM-6);
//! 10. scripts: pubkey hash then the hybrid signatures, LAST, with a bounded
//!     verified-signature cache shared with block validation.
//!
//! Rejections other than "missing inputs" are remembered in the mempool's
//! bounded recent-rejects filter until the selected tip changes, so a peer
//! replaying the same invalid transaction costs a hash lookup (MEM-5).

use std::collections::HashSet;

use crate::core::{self, Transaction, TxOutput};
use crate::mempool::{Mempool, MempoolError, MAX_TX_SIZE, MIN_RELAY_FEE_RATE};
use crate::storage::Storage;

/// Which checks an admission runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmissionPolicy {
    /// Header height of the block the transaction would be mined in (for
    /// coinbase maturity). `0` skips the maturity check (genesis-only node).
    pub next_block_height: u64,
    /// Verify the hybrid signatures. `false` ONLY for re-injection of
    /// transactions from disconnected blocks, whose signatures were verified
    /// when the block was connected (signatures do not depend on chain state).
    pub check_signatures: bool,
    /// Consult and update the recent-rejects filter.
    pub use_reject_filter: bool,
}

impl AdmissionPolicy {
    /// Gossip and RPC relay admission.
    pub fn relay(next_block_height: u64) -> Self {
        Self { next_block_height, check_signatures: true, use_reject_filter: true }
    }

    /// Re-injection of transactions from blocks a reorg disconnected (MEM-7).
    pub fn reinjection(next_block_height: u64) -> Self {
        Self { next_block_height, check_signatures: false, use_reject_filter: false }
    }
}

/// Why a transaction was not admitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionError {
    /// Permanently invalid or non-standard for this exact transaction.
    Rejected(String),
    /// An input is not in the UTXO set (unknown parent, or already spent by
    /// a confirmed transaction). Not cached: it may become valid later.
    MissingInputs(String),
    /// Conflicts with a pooled transaction (first-seen wins).
    Conflict(String),
    /// Coinbase input not yet mature at the next block height.
    Immature(String),
    /// Fee below the relay or rolling minimum (pool policy).
    LowFee(String),
    /// Already pooled / already confirmed.
    Duplicate(String),
    /// The pool refused it (full, or another mempool-level rule).
    Pool(String),
}

impl AdmissionError {
    /// Whether the rejection belongs in the recent-rejects filter.
    pub fn is_cacheable(&self) -> bool {
        !matches!(self, AdmissionError::MissingInputs(_) | AdmissionError::Duplicate(_))
    }
}

impl std::fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdmissionError::Rejected(m)
            | AdmissionError::MissingInputs(m)
            | AdmissionError::Conflict(m)
            | AdmissionError::Immature(m)
            | AdmissionError::LowFee(m)
            | AdmissionError::Duplicate(m)
            | AdmissionError::Pool(m) => write!(f, "{}", m),
        }
    }
}

/// Witness-inclusive transaction id: SHA3-256 over the full canonical wire
/// encoding INCLUDING script_sigs. Two encodings of the same txid with
/// different signatures get different wtxids (reject filter, sig cache).
pub fn wtxid(tx: &Transaction) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(b"gnb-wtxid-v1");
    h.update(tx.to_wire_bytes(true));
    h.finalize().into()
}

/// Strict gossip/RPC decode (MEM-5): `Transaction::from_wire_bytes` ignores
/// trailing bytes, so one transaction had unboundedly many byte-distinct
/// encodings (each a fresh gossipsub message id costing a full validation).
/// Only the exact canonical encoding is accepted here.
pub fn decode_tx_strict(bytes: &[u8]) -> Result<Transaction, String> {
    if bytes.len() > MAX_TX_SIZE {
        return Err(format!("transaction of {} bytes exceeds MAX_TX_SIZE {}", bytes.len(), MAX_TX_SIZE));
    }
    let tx = Transaction::from_wire_bytes(bytes)?;
    let canonical_len = tx.to_wire_bytes(true).len();
    if canonical_len != bytes.len() {
        return Err(format!(
            "non-canonical transaction encoding: {} trailing byte(s)",
            bytes.len().saturating_sub(canonical_len)
        ));
    }
    Ok(tx)
}

/// Header height of the next block on top of the selected tip: the tip's DAG
/// height + 1. This is the smallest height any child of the tip can declare
/// (`max(parent DAG heights) + 1`), so a transaction admitted at this height
/// is mature in every possible next block. Never `dag.block_count()` (MEM-4:
/// the DAG block count includes merged/red blocks and exceeded the chain
/// height by >10k on the Bloch chain, making every immature coinbase look
/// mature).
pub fn next_block_height(dag: &crate::consensus::GhostDAG) -> u64 {
    dag.selected_tip()
        .and_then(|t| dag.get_block_data(&t).map(|d| d.height))
        .unwrap_or(0)
        .saturating_add(1)
}

// ── Verified-signature cache (shared with block validation) ─────────────────

const SIG_CACHE_CAPACITY: usize = 100_000;

fn sig_cache() -> &'static parking_lot::Mutex<(HashSet<[u8; 32]>, std::collections::VecDeque<[u8; 32]>)> {
    static CACHE: std::sync::OnceLock<
        parking_lot::Mutex<(HashSet<[u8; 32]>, std::collections::VecDeque<[u8; 32]>)>,
    > = std::sync::OnceLock::new();
    CACHE.get_or_init(|| parking_lot::Mutex::new((HashSet::new(), std::collections::VecDeque::new())))
}

fn sig_cache_key(tx: &Transaction) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(b"gnb-sigcache-v1");
    h.update(core::node_chain_id().to_le_bytes());
    h.update(wtxid(tx));
    h.finalize().into()
}

/// Verify every input's script against its prevout: the script_sig must parse
/// as (sig, pubkey), the pubkey hash must equal the prevout's script_pubkey,
/// and the hybrid signature must verify over the input's sighash.
///
/// The (expensive) signature results are cached per (chain id, wtxid): the
/// wtxid commits to the whole transaction including every script_sig, so the
/// sighash, the signature and the public key of every input are fixed by it —
/// a cache hit is exactly as good as re-verifying. The pubkey-hash binding to
/// the prevout is re-checked on every call (it depends on the prevout, i.e. on
/// the chain context). Only successes are cached.
pub fn verify_input_scripts(tx: &Transaction, prevouts: &[TxOutput]) -> Result<(), String> {
    use sha3::{Digest, Sha3_256};
    if prevouts.len() != tx.inputs.len() {
        return Err(format!("{} prevouts for {} inputs", prevouts.len(), tx.inputs.len()));
    }
    let mut parsed: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(tx.inputs.len());
    for (i, (inp, prev)) in tx.inputs.iter().zip(prevouts).enumerate() {
        let (sig, pk) = Transaction::parse_script_sig(&inp.script_sig)
            .ok_or_else(|| format!("malformed script_sig at input {}", i))?;
        let pk_hash = Sha3_256::digest(&pk)[..20].to_vec();
        if pk_hash != prev.script_pubkey {
            return Err(format!("pubkey mismatch at input {}", i));
        }
        parsed.push((sig, pk));
    }
    let key = sig_cache_key(tx);
    if sig_cache().lock().0.contains(&key) {
        return Ok(());
    }
    for (i, (sig, pk)) in parsed.iter().enumerate() {
        let sighash = tx.sighash(i, core::node_chain_id());
        if !crate::crypto::verify(pk, &sighash, sig) {
            return Err(format!("invalid signature at input {}", i));
        }
    }
    let mut g = sig_cache().lock();
    let (set, order) = &mut *g;
    if set.insert(key) {
        order.push_back(key);
        while order.len() > SIG_CACHE_CAPACITY {
            if let Some(old) = order.pop_front() {
                set.remove(&old);
            }
        }
    }
    Ok(())
}

/// Standardness rules that need no chain state (steps 1–3).
pub fn check_standard(tx: &Transaction) -> Result<(), AdmissionError> {
    check_structure_and_size(tx)?;
    check_policy(tx)
}

/// Steps 1–2: structure and size. Run before anything that hashes or walks
/// the whole transaction, so their cost is bounded by `MAX_TX_SIZE`.
fn check_structure_and_size(tx: &Transaction) -> Result<(), AdmissionError> {
    if tx.is_coinbase() {
        return Err(AdmissionError::Rejected("coinbase not accepted".into()));
    }
    if tx.inputs.is_empty() {
        return Err(AdmissionError::Rejected("no inputs".into()));
    }
    if tx.outputs.is_empty() {
        return Err(AdmissionError::Rejected("no outputs".into()));
    }
    let wire = tx.to_wire_bytes(true).len();
    if wire > MAX_TX_SIZE {
        return Err(AdmissionError::Rejected(format!(
            "transaction too large: {} bytes (max {})", wire, MAX_TX_SIZE)));
    }
    let size = tx.actual_size();
    if size > MAX_TX_SIZE {
        return Err(AdmissionError::Rejected(format!(
            "transaction too large: {} bytes (max {})", size, MAX_TX_SIZE)));
    }
    Ok(())
}

/// Step 3: canonical limits, MoneyRange, dust, zero-value outputs.
fn check_policy(tx: &Transaction) -> Result<(), AdmissionError> {
    core::limits::check_tx_canonical_limits(tx).map_err(AdmissionError::Rejected)?;
    core::limits::check_tx_money_range(tx).map_err(AdmissionError::Rejected)?;
    for (i, o) in tx.outputs.iter().enumerate() {
        if o.value > 0 && o.value < core::DUST_THRESHOLD {
            return Err(AdmissionError::Rejected(format!(
                "output {} below dust threshold ({} < {} sats)", i, o.value, core::DUST_THRESHOLD)));
        }
        if o.value == 0 {
            return Err(AdmissionError::Rejected(format!(
                "output {} has zero value (non-standard)", i)));
        }
    }
    Ok(())
}

/// Run every admission check (steps 1–10) WITHOUT inserting. Returns the fee.
/// `mempool = None` skips the pool-relative checks (known/conflict/rolling
/// fee), which is what block-independent callers such as
/// `validate_tx_standalone` want.
pub fn check_transaction(
    store: &Storage,
    mempool: Option<&Mempool>,
    tx: &Transaction,
    policy: &AdmissionPolicy,
) -> Result<u64, AdmissionError> {
    check_structure_and_size(tx)?;

    // Known: pooled, recently rejected (a replay costs one bounded hash), or
    // already confirmed.
    let txid = tx.txid();
    if let Some(mp) = mempool {
        if mp.contains(&txid) {
            return Err(AdmissionError::Duplicate("duplicate transaction".into()));
        }
        if policy.use_reject_filter && mp.is_recently_rejected(&wtxid(tx)) {
            return Err(AdmissionError::Duplicate("recently rejected".into()));
        }
    }
    if let Ok(Some(_)) = store.get_tx_location(&txid) {
        return Err(AdmissionError::Duplicate("transaction already confirmed".into()));
    }

    check_policy(tx)?;

    // Conflicts with the pool and duplicate inputs (cheap, no I/O).
    let mut seen: HashSet<([u8; 32], u32)> = HashSet::with_capacity(tx.inputs.len());
    for inp in &tx.inputs {
        let op = (inp.prev_txid, inp.prev_index);
        if !seen.insert(op) {
            return Err(AdmissionError::Rejected(format!(
                "double-spend: {}:{} already consumed", hex::encode(&inp.prev_txid[..8]), inp.prev_index)));
        }
        if let Some(mp) = mempool {
            if mp.spends_outpoint(&op) {
                return Err(AdmissionError::Conflict(format!(
                    "conflicts with a mempool tx: outpoint {}:{} already spent",
                    hex::encode(&inp.prev_txid[..8]), inp.prev_index)));
            }
        }
    }

    // UTXO presence + input sum.
    let mut prevouts: Vec<TxOutput> = Vec::with_capacity(tx.inputs.len());
    let mut total_in: u64 = 0;
    for inp in &tx.inputs {
        let out = store.get_utxo(&inp.prev_txid, inp.prev_index)
            .map_err(|e| AdmissionError::Pool(format!("storage: {}", e)))?
            .ok_or_else(|| AdmissionError::MissingInputs(format!(
                "UTXO {}:{} not found", hex::encode(&inp.prev_txid[..8]), inp.prev_index)))?;
        total_in = core::limits::money_add(total_in, out.value)
            .map_err(|e| AdmissionError::Rejected(format!("input total: {}", e)))?;
        prevouts.push(out);
    }

    // Coinbase maturity at the next block's height (MEM-4).
    core::check_coinbase_maturity(tx, policy.next_block_height, |t| {
        store.get_coinbase_height(t).ok().flatten()
    }).map_err(AdmissionError::Immature)?;

    // Value + fees.
    let total_out = core::limits::check_tx_money_range(tx).map_err(AdmissionError::Rejected)?;
    if total_in < total_out {
        return Err(AdmissionError::Rejected(format!("inputs {} < outputs {}", total_in, total_out)));
    }
    let fee = total_in - total_out;
    core::check_min_fee(tx, fee).map_err(AdmissionError::Rejected)?;
    let size = tx.actual_size();
    if fee < (size as u64).saturating_mul(MIN_RELAY_FEE_RATE) {
        return Err(AdmissionError::LowFee(format!(
            "fee {} below minimum relay rate ({} sat/byte for {} bytes)", fee, MIN_RELAY_FEE_RATE, size)));
    }
    if let Some(mp) = mempool {
        if !mp.meets_rolling_min(fee, size) {
            return Err(AdmissionError::LowFee(format!(
                "fee {} below the mempool's rolling minimum ({} sat/byte)", fee, mp.rolling_min_fee_rate())));
        }
    }

    // Signatures last (the only step whose cost grows with size²).
    if policy.check_signatures {
        verify_input_scripts(tx, &prevouts).map_err(AdmissionError::Rejected)?;
    }
    Ok(fee)
}

/// Check and insert `tx` into `mempool`. On success returns the txid.
///
/// The final insert runs under the store's acceptance lock with a re-check
/// that every input is still unspent, so it cannot race a block connect that
/// spends an input and sweeps conflicts (MEM-3) between the check and the
/// insert.
pub fn admit(
    store: &Storage,
    mempool: &Mempool,
    tx: Transaction,
    policy: &AdmissionPolicy,
) -> Result<[u8; 32], AdmissionError> {
    let fee = match check_transaction(store, Some(mempool), &tx, policy) {
        Ok(fee) => fee,
        Err(e) => {
            if policy.use_reject_filter && e.is_cacheable() {
                mempool.note_rejected(wtxid(&tx));
            }
            return Err(e);
        }
    };
    let _guard = store.acceptance_lock();
    for inp in &tx.inputs {
        match store.get_utxo(&inp.prev_txid, inp.prev_index) {
            Ok(Some(_)) => {}
            _ => return Err(AdmissionError::MissingInputs(format!(
                "UTXO {}:{} spent while admitting", hex::encode(&inp.prev_txid[..8]), inp.prev_index))),
        }
    }
    mempool.add(tx, fee).map_err(|e| match e {
        MempoolError::Duplicate => AdmissionError::Duplicate(e.to_string()),
        MempoolError::Conflict { .. } => AdmissionError::Conflict(e.to_string()),
        other => AdmissionError::Pool(other.to_string()),
    })
}
