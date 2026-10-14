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
//!     bounds the quadratic sighash-v2 cost before any signature is checked
//!     (sighash v3, the only digest valid at/after the hardening activation,
//!     is linear: MEM-5 residual closed by CRY-3);
//!  3. known: already pooled, already confirmed, or recently rejected (a
//!     replay costs one size-bounded hash);
//!  4. standardness: canonical-encoding limits (VAL-12), MoneyRange (VAL-11),
//!     no dust output (the consensus `Block::validate_dust` rule), no
//!     zero-value output (policy: UTXO-set bloat, VAL-11 note), canonical
//!     witnesses at EVERY height and the hybrid signature suite only
//!     ([`check_standard_witnesses`], CRY-1/CRY-2 policy);
//!  5. version: valid AND standard for the next block's height
//!     (`core::sighash::check_tx_version_standard`: version 3 from the
//!     hardening activation height; below it version >= 3 is non-standard
//!     although consensus-valid with sighash v2);
//!  6. conflicts: an input already spent by a pooled tx (first-seen wins —
//!     the explicit replacement rule is "no replacement", MEM-6);
//!  7. duplicate inputs within the tx (C-R3-2);
//!  8. UTXO presence (no unconfirmed parents: package relay is not supported);
//!  9. coinbase maturity at the height of the NEXT block (selected-tip DAG
//!     height + 1, never `dag.block_count()`, MEM-4);
//! 10. value: inputs ≥ outputs, MoneyRange of the input sum, consensus
//!     minimum fee, relay fee rate, rolling minimum fee (MEM-6);
//! 11. scripts: the consensus input-script rule at the next block's height
//!     ([`verify_input_scripts`]: witnesses, pubkey hash, signatures under
//!     the digest the version selects), LAST, with a bounded
//!     verified-signature cache shared with block validation.
//!
//! Rejections other than "missing inputs" are remembered in the mempool's
//! bounded recent-rejects filter until the selected tip changes, so a peer
//! replaying the same invalid transaction costs a hash lookup (MEM-5).

use std::collections::HashSet;

use crate::core::sighash::SighashVersion;
use crate::core::{self, Transaction, TxOutput};
use crate::mempool::{Mempool, MempoolError, MAX_TX_SIZE, MIN_RELAY_FEE_RATE};
use crate::storage::Storage;

/// Which checks an admission runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmissionPolicy {
    /// Header height of the block the transaction would be mined in (for
    /// coinbase maturity). `0` skips the maturity check (genesis-only node).
    pub next_block_height: u64,
    /// Verify the witnesses (standardness: canonical witness, hybrid suite)
    /// and the signatures. `false` ONLY for re-injection of transactions from
    /// disconnected blocks, whose witnesses and signatures were accepted when
    /// the block was connected: standardness is then skipped, and so are the
    /// signatures below the activation (every version is sighash v2 there, as
    /// when the block was mined); at/after it the input scripts are verified
    /// anyway, since the block may have been mined below it under v2. The
    /// version rule and policy at `next_block_height` apply either way.
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

/// Cache key of a verified transaction: EVERYTHING the cached verdict
/// depends on, so a "valid" entry can never answer for another digest
/// version, prevout set or height regime (mandated with CRY-3):
///
/// * the chain id (every digest commits to it);
/// * the digest / witness regime (`SighashVersion`: v2 + lenient witness, or
///   v3 + canonical witness + bound signatures) and whether the hardening
///   activation is in force at the block height (the regime is a function of
///   both, so a version-3 transaction verified under v2 below the activation
///   never hits at/after it, and vice versa);
/// * the wtxid (every input's outpoint, sequence, script_sig, every output,
///   version and locktime);
/// * every spent output (value and `script_pubkey`, in input order): sighash
///   v3 commits to them, and the witness check hashes the public key against
///   the spent script. Included for v2 too, so the key never depends on the
///   regime-specific reasoning above.
fn sig_cache_key(tx: &Transaction, version: SighashVersion, active: bool, prevouts: &[TxOutput]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(b"gnb-sigcache-v4");
    h.update(core::node_chain_id().to_le_bytes());
    h.update([match version { SighashVersion::V2 => 2u8, SighashVersion::V3 => 3u8 }, u8::from(active)]);
    h.update(wtxid(tx));
    h.update((prevouts.len() as u64).to_le_bytes());
    for p in prevouts {
        h.update(p.value.to_le_bytes());
        h.update((p.script_pubkey.len() as u64).to_le_bytes());
        h.update(&p.script_pubkey);
    }
    h.finalize().into()
}

/// The hardening activation height the transaction rules are evaluated
/// under (process-wide; a `scoped_override` on the calling thread in tests).
fn activation_height() -> u64 {
    core::activation::hardening_activation_height()
}

/// The consensus input-script rule of a non-coinbase transaction in a block
/// at header height `block_height` — the ONE function block acceptance and
/// connect (`accept::validate_tx_inputs`), reorg connect, template self-check
/// and mempool admission (at the next block's height) all call:
///
/// 1. version: `core::sighash::check_tx_version` (below the hardening
///    activation every version, 3 included, is valid with sighash v2 — the
///    pre-upgrade rule exactly; at/after it only version 3 is valid, with
///    sighash v3);
/// 2. witnesses (`core::sighash::check_input_witnesses`): below the
///    activation the historical lenient `script_sig` framing; from it the
///    canonical witness (exact framing, enveloped canonical signature,
///    CRY-1); the public key must hash to the spent `script_pubkey`
///    (`prevouts[i]`);
/// 3. signatures (`core::sighash::verify_input_signatures`): sighash v2 with
///    the historical verifier, or sighash v3 (spent amounts and scripts, the
///    suite and the input index committed; linear cost) with component-bound
///    signatures (CRY-2, CRY-3).
///
/// Steps 1–2 run on every call (they depend on the height and the prevouts).
/// The expensive signature results are cached under a key that covers the
/// regime, the activation state at `block_height` and the prevouts (see
/// [`sig_cache_key`]); only successes are cached. Relay policy (version >= 3
/// non-standard below the activation) is NOT part of this rule: see
/// [`check_version_for_next_block`].
pub fn verify_input_scripts(tx: &Transaction, prevouts: &[TxOutput], block_height: u64) -> Result<(), String> {
    let act = activation_height();
    let version = core::sighash::check_tx_version(tx.version, block_height, act)?;
    let witnesses = core::sighash::check_input_witnesses(tx, prevouts, version)?;
    let key = sig_cache_key(tx, version, core::activation::is_active_at(block_height, act), prevouts);
    if sig_cache().lock().0.contains(&key) {
        return Ok(());
    }
    core::sighash::verify_input_signatures(tx, prevouts, &witnesses, version, core::node_chain_id())?;
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

/// Step 3: canonical limits, MoneyRange, dust, zero-value outputs. (The
/// witness standardness of step 4 runs in [`check_transaction`] together with
/// the signature policy.)
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

/// Witness standardness (relay policy at EVERY height; no signature math):
///
/// * CRY-1: every `script_sig` must be the canonical witness
///   (`core::sighash::canonical_witness`: exactly
///   `[u32 sig_len][sig][u32 pk_len][pk]`, enveloped canonical signature —
///   compact Falcon half, exact ML-DSA length). Consensus requires it only
///   for version 3 (at/after the activation); below it a non-canonical
///   witness is still consensus-valid but is not relayed or mined from the
///   pool, so third parties cannot malleate pooled transactions. Wallets
///   always emit canonical witnesses.
/// * CRY-2: the public key must name the hybrid suite
///   (`crypto::is_hybrid_public_key`: suite 0x0001, or the raw legacy hybrid
///   key of a carry-over address). Single-algorithm suite 0x0002 stays
///   consensus-valid (outputs that may already be locked to such keys are not
///   frozen) but is non-standard: no new 0x0002 spend enters the pool.
pub fn check_standard_witnesses(tx: &Transaction) -> Result<(), String> {
    for (i, inp) in tx.inputs.iter().enumerate() {
        let (_sig, pk) = core::sighash::canonical_witness(&inp.script_sig)
            .map_err(|e| format!("input {i}: {e} (non-standard)"))?;
        if !crate::crypto::is_hybrid_public_key(pk) {
            return Err(format!(
                "input {i}: single-algorithm signature suite (non-standard; only the hybrid \
                 ML-DSA-65 + Falcon-1024 suite 0x0001 is relayed)"
            ));
        }
    }
    Ok(())
}

/// Step 5: the version rule AND policy at the next block's height
/// (`core::sighash::check_tx_version_standard`): consensus (only version 3
/// at/after the hardening activation) plus relay policy (version >= 3 is
/// non-standard below it, although consensus-valid there with sighash v2).
/// Cheap; runs even when signatures are not checked (reorg re-injection), in
/// post-connect eviction, in `accept::revalidate_mempool` and in the
/// template self-check, so the pool never holds a version-1 transaction for a
/// block at/after the activation, nor a version >= 3 one for a block below it.
///
/// Whatever passes this check at two heights uses the same digest at both, so
/// a pooled transaction's verified signatures stay valid while the next
/// height moves (only a move across the activation changes the regime, and
/// then no version passes on both sides).
pub fn check_version_for_next_block(tx: &Transaction, next_block_height: u64) -> Result<(), String> {
    core::sighash::check_tx_version_standard(tx.version, next_block_height, activation_height()).map(|_| ())
}

/// Run every admission check (steps 1–11) WITHOUT inserting. Returns the fee.
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
    if policy.check_signatures {
        // Witness standardness travels with the signature policy: a
        // re-injected transaction was already mined (its witness accepted by
        // consensus), relayed ones must be standard.
        check_standard_witnesses(tx).map_err(AdmissionError::Rejected)?;
    }
    check_version_for_next_block(tx, policy.next_block_height).map_err(AdmissionError::Rejected)?;

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

    // Signatures last (the most expensive step). Re-injection skips them only
    // where the digest regime cannot have changed since the transaction was
    // mined: below the activation every version is verified with sighash v2
    // at every height. From the activation the scripts are verified again (a
    // verified-signature cache hit when the disconnected block was itself at
    // or after it): a version-3 transaction mined BELOW the activation was
    // checked against the v2 digest, which says nothing about v3.
    let regime_may_have_changed = !policy.check_signatures
        && core::activation::is_active_at(policy.next_block_height, activation_height());
    if policy.check_signatures || regime_may_have_changed {
        verify_input_scripts(tx, &prevouts, policy.next_block_height).map_err(AdmissionError::Rejected)?;
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
