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
//!  5. duplicate inputs within the tx (C-R3-2);
//!  6. inputs: each one in the UTXO set OR an output of a pooled transaction
//!     (MEM-6: chains of unconfirmed transactions); otherwise "missing
//!     inputs" (the gossip relay buffers it in the orphanage);
//!  7. coinbase maturity at the height of the NEXT block (selected-tip DAG
//!     height + 1, never `dag.block_count()`, MEM-4);
//!  8. value: inputs ≥ outputs, MoneyRange of the input sum, consensus
//!     minimum fee, relay fee rate, rolling minimum fee (MEM-6);
//!  9. pool policy (MEM-6): a conflict with pooled transactions is resolved
//!     by the full-RBF replacement rules (BIP125 rules 2-6, see the
//!     `mempool` module docs) and the ancestor / descendant limits must hold
//!     (`Mempool::preflight`);
//! 10. scripts: pubkey hash then the hybrid signatures, LAST, with a bounded
//!     verified-signature cache shared with block validation. A caller may
//!     put a gate in front of this step (`admit_gated`): the gossip relay
//!     charges the delivering connection's signature budget there (MEM-5).
//!
//! Every error says whether the transaction is consensus-INVALID
//! ([`AdmissionError::Rejected`]: no honest node relays it, so the gossip
//! relay penalises its author) or merely refused by local policy (every
//! other variant). Rejections other than "missing inputs", duplicates and
//! rate limiting are remembered in the mempool's bounded recent-rejects
//! filter until the selected tip changes, so a peer replaying the same
//! invalid transaction costs a hash lookup (MEM-5).

use std::collections::HashSet;

use crate::core::{self, Transaction, TxOutput};
use crate::mempool::{AddOutcome, Mempool, MempoolError, MAX_TX_SIZE, MIN_RELAY_FEE_RATE};
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
    /// Consensus-INVALID for this exact transaction: it can never be mined
    /// in any block (bad signature, inputs < outputs, below the consensus
    /// minimum fee, dust, MoneyRange, canonical limits, duplicate inputs, no
    /// inputs, a coinbase outside a block). The gossip relay reports
    /// `Reject` and the author is penalised.
    Rejected(String),
    /// Refused by local relay policy only (size above `MAX_TX_SIZE`, no
    /// outputs, a zero-value output). The relay reports `Ignore`.
    NonStandard(String),
    /// An input is neither in the UTXO set nor an output of a pooled
    /// transaction (unknown parent, or already spent by a confirmed
    /// transaction). Not cached: it may become valid later.
    MissingInputs(String),
    /// Conflicts with a pooled transaction and replacement was not possible.
    Conflict(String),
    /// MEM-6: conflicts with pooled transactions and fails the full-RBF
    /// replacement rules.
    Replacement(String),
    /// MEM-6: would exceed the ancestor / descendant limits.
    ChainLimit(String),
    /// Coinbase input not yet mature at the next block height.
    Immature(String),
    /// Fee below the relay or rolling minimum (pool policy).
    LowFee(String),
    /// Already pooled / already confirmed / recently rejected.
    Duplicate(String),
    /// MEM-5: the delivering connection's signature-verification budget is
    /// spent. Not cached: the transaction may be perfectly valid.
    RateLimited(String),
    /// The pool refused it (full, or another mempool-level rule).
    Pool(String),
}

impl AdmissionError {
    /// Whether the rejection belongs in the recent-rejects filter.
    pub fn is_cacheable(&self) -> bool {
        !matches!(
            self,
            AdmissionError::MissingInputs(_) | AdmissionError::Duplicate(_) | AdmissionError::RateLimited(_)
        )
    }

    /// True iff the transaction is consensus-invalid (see [`Self::Rejected`]).
    pub fn is_consensus_invalid(&self) -> bool {
        matches!(self, AdmissionError::Rejected(_))
    }
}

impl std::fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdmissionError::Rejected(m)
            | AdmissionError::NonStandard(m)
            | AdmissionError::MissingInputs(m)
            | AdmissionError::Conflict(m)
            | AdmissionError::Replacement(m)
            | AdmissionError::ChainLimit(m)
            | AdmissionError::Immature(m)
            | AdmissionError::LowFee(m)
            | AdmissionError::Duplicate(m)
            | AdmissionError::RateLimited(m)
            | AdmissionError::Pool(m) => write!(f, "{}", m),
        }
    }
}

/// Map a mempool insertion error onto the admission error space.
fn from_mempool_error(e: MempoolError) -> AdmissionError {
    match e {
        MempoolError::Duplicate => AdmissionError::Duplicate(e.to_string()),
        MempoolError::Conflict { .. } => AdmissionError::Conflict(e.to_string()),
        MempoolError::Replacement(_) => AdmissionError::Replacement(e.to_string()),
        MempoolError::ChainLimit(_) => AdmissionError::ChainLimit(e.to_string()),
        other => AdmissionError::Pool(other.to_string()),
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

/// True iff the hybrid signatures of `tx` are in the verified-signature
/// cache, i.e. [`verify_input_scripts`] would skip the expensive step. The
/// gossip relay charges a peer's signature budget only on a miss (MEM-5).
pub fn signatures_cached(tx: &Transaction) -> bool {
    let key = sig_cache_key(tx);
    sig_cache().lock().0.contains(&key)
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
    // Consensus: a coinbase is only valid as the first transaction of a
    // block, and a transaction without inputs pays a zero fee (below the
    // consensus minimum) — neither can ever be mined.
    if tx.is_coinbase() {
        return Err(AdmissionError::Rejected("coinbase not accepted".into()));
    }
    if tx.inputs.is_empty() {
        return Err(AdmissionError::Rejected("no inputs".into()));
    }
    // Policy (MEM-5 verdicts): an output-less transaction or one above
    // MAX_TX_SIZE can be consensus-valid inside a block; refusing to RELAY
    // it is local policy, never grounds for penalising the sender.
    if tx.outputs.is_empty() {
        return Err(AdmissionError::NonStandard("no outputs".into()));
    }
    let wire = tx.to_wire_bytes(true).len();
    if wire > MAX_TX_SIZE {
        return Err(AdmissionError::NonStandard(format!(
            "transaction too large: {} bytes (max {})", wire, MAX_TX_SIZE)));
    }
    let size = tx.actual_size();
    if size > MAX_TX_SIZE {
        return Err(AdmissionError::NonStandard(format!(
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
            return Err(AdmissionError::NonStandard(format!(
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
    check_transaction_gated(store, mempool, tx, policy, &mut |_| Ok(()))
}

/// The gate type of [`check_transaction_gated`] / [`admit_gated`]: called
/// once, right before the signatures are verified, and only when they are
/// not already in the verified-signature cache. An `Err` aborts the
/// admission with that error.
pub type SignatureGate<'a> = dyn FnMut(&Transaction) -> Result<(), AdmissionError> + 'a;

/// [`check_transaction`] with a [`SignatureGate`] in front of step 10.
pub fn check_transaction_gated(
    store: &Storage,
    mempool: Option<&Mempool>,
    tx: &Transaction,
    policy: &AdmissionPolicy,
    gate: &mut SignatureGate<'_>,
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

    // Duplicate inputs (cheap, no I/O). Conflicts with the pool are NOT an
    // early exit any more: they are resolved by the replacement rules in
    // step 9 (MEM-6, full-RBF).
    let mut seen: HashSet<([u8; 32], u32)> = HashSet::with_capacity(tx.inputs.len());
    for inp in &tx.inputs {
        let op = (inp.prev_txid, inp.prev_index);
        if !seen.insert(op) {
            return Err(AdmissionError::Rejected(format!(
                "double-spend: {}:{} already consumed", hex::encode(&inp.prev_txid[..8]), inp.prev_index)));
        }
    }

    // Input presence + input sum: the UTXO set, else (MEM-6) an output of a
    // pooled transaction.
    let mut prevouts: Vec<TxOutput> = Vec::with_capacity(tx.inputs.len());
    let mut total_in: u64 = 0;
    for inp in &tx.inputs {
        let confirmed = store.get_utxo(&inp.prev_txid, inp.prev_index)
            .map_err(|e| AdmissionError::Pool(format!("storage: {}", e)))?;
        let out = match confirmed {
            Some(o) => o,
            None => mempool
                .and_then(|mp| mp.pool_output(&inp.prev_txid, inp.prev_index))
                .ok_or_else(|| AdmissionError::MissingInputs(format!(
                    "UTXO {}:{} not found", hex::encode(&inp.prev_txid[..8]), inp.prev_index)))?,
        };
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
        // MEM-6: replacement rules (when it conflicts) and chain limits,
        // still before any signature work.
        mp.preflight(tx, fee).map_err(from_mempool_error)?;
    }

    // Signatures last (the only step whose cost grows with size²), behind
    // the caller's gate (MEM-5: the relay's per-connection budget).
    if policy.check_signatures {
        if !signatures_cached(tx) {
            gate(tx)?;
        }
        verify_input_scripts(tx, &prevouts).map_err(AdmissionError::Rejected)?;
    }
    Ok(fee)
}

/// Check and insert `tx` into `mempool`. On success returns the txid.
///
/// The final insert runs under the store's acceptance lock with a re-check
/// that every input is still available (unspent in the UTXO set, or an
/// output of a pooled transaction), so it cannot race a block connect that
/// spends an input and sweeps conflicts (MEM-3) between the check and the
/// insert. Conflicting pooled transactions are replaced when the full-RBF
/// rules hold (MEM-6).
pub fn admit(
    store: &Storage,
    mempool: &Mempool,
    tx: Transaction,
    policy: &AdmissionPolicy,
) -> Result<[u8; 32], AdmissionError> {
    admit_gated(store, mempool, tx, policy, &mut |_| Ok(())).map(|o| o.txid)
}

/// [`admit`] with a [`SignatureGate`]; returns what the insertion did
/// (including any replaced transactions).
pub fn admit_gated(
    store: &Storage,
    mempool: &Mempool,
    tx: Transaction,
    policy: &AdmissionPolicy,
    gate: &mut SignatureGate<'_>,
) -> Result<AddOutcome, AdmissionError> {
    let fee = match check_transaction_gated(store, Some(mempool), &tx, policy, gate) {
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
        let confirmed = matches!(store.get_utxo(&inp.prev_txid, inp.prev_index), Ok(Some(_)));
        if !confirmed && mempool.pool_output(&inp.prev_txid, inp.prev_index).is_none() {
            return Err(AdmissionError::MissingInputs(format!(
                "UTXO {}:{} spent while admitting", hex::encode(&inp.prev_txid[..8]), inp.prev_index)));
        }
    }
    mempool.add_with_replacement(tx, fee).map_err(from_mempool_error)
}

/// Parent txids of `tx` that are neither confirmed (an unspent output in
/// the UTXO set) nor pooled — what an orphan is waiting for (MEM-6).
pub fn missing_parents(store: &Storage, mempool: &Mempool, tx: &Transaction) -> std::collections::BTreeSet<[u8; 32]> {
    tx.inputs.iter()
        .filter(|i| {
            !matches!(store.get_utxo(&i.prev_txid, i.prev_index), Ok(Some(_)))
                && mempool.pool_output(&i.prev_txid, i.prev_index).is_none()
        })
        .map(|i| i.prev_txid)
        .collect()
}

/// True iff some input of `tx` is neither confirmed nor pooled. Stops at the
/// first missing input — use it wherever only emptiness of
/// [`missing_parents`] matters (the orphan re-try path, review finding).
pub fn has_missing_input(store: &Storage, mempool: &Mempool, tx: &Transaction) -> bool {
    tx.inputs.iter().any(|i| {
        !matches!(store.get_utxo(&i.prev_txid, i.prev_index), Ok(Some(_)))
            && mempool.pool_output(&i.prev_txid, i.prev_index).is_none()
    })
}

/// True iff the transaction `txid` is pooled or confirmed: one lookup per
/// recorded missing parent is the cheap pre-filter of the periodic orphan
/// sweep (a parent that is neither cannot have made its child admissible).
pub fn parent_available(store: &Storage, mempool: &Mempool, txid: &[u8; 32]) -> bool {
    mempool.contains(txid) || matches!(store.get_tx_location(txid), Ok(Some(_)))
}
