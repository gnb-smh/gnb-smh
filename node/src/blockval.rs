//! Block transaction validation — ONE implementation for every consensus path.
//!
//! SECURITY: a block's transactions used to be checked by two different
//! routines. The accept-time path (`accept_block`, main chain) verified
//! signatures, pubkey binding, minimum fee and the coinbase value, but read
//! every input from the CURRENT TIP's UTXO set — so a block on a competing
//! branch was judged against the wrong state and rejected, and a transaction
//! could spend its own block's coinbase without the 100-block maturity (the
//! store does not know a coinbase that is not applied yet). The reorg path
//! (`reorg::validate_fork_block_state`) used the right state but skipped the
//! signature/pubkey binding, the minimum fee and the coinbase value.
//!
//! `validate_block_transactions` is now the only rule set. Callers differ only
//! in WHICH state they pass in (the selected parent's UTXO view), never in
//! which rules run.

use std::collections::{HashMap, HashSet};

use crate::core::{self, Block, TxOutput};
use crate::crypto;

/// Why a block's transactions were not accepted.
///
/// The distinction is security-relevant: only `Invalid` may be recorded as
/// a permanent consensus verdict. A `Storage` failure (I/O error, corrupt
/// read) says nothing about the block; marking it invalid would make a node
/// reject a valid chain forever.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockTxError {
    /// The block breaks a consensus rule over data its hash commits to.
    /// This verdict is permanent and may be recorded.
    Invalid(String),
    /// The block failed a rule that depends on its script_sigs (signature,
    /// pubkey binding, size-based minimum fee). The txid — and so the merkle
    /// root and block hash — does NOT commit to script_sigs, so a peer can
    /// relay a corrupted copy of a VALID block under the same hash. Reject
    /// this copy, but NEVER record the hash as invalid: the honest copy must
    /// still be accepted when it arrives.
    InvalidWitness(String),
    /// The UTXO state could not be read; the block's validity is unknown.
    Storage(String),
    /// The block's branch forks deeper than the finality window below THIS
    /// node's tip. That is a statement about the local tip, not the block, so
    /// it is never recorded: a node that was eclipsed onto a wrong chain must
    /// still be able to recover onto the honest one (after an operator
    /// rollback or restart), which a recorded verdict would forbid forever.
    BeyondFinality(String),
}

impl std::fmt::Display for BlockTxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockTxError::Invalid(e) | BlockTxError::InvalidWitness(e) => write!(f, "{}", e),
            BlockTxError::Storage(e) => write!(f, "storage error during validation: {}", e),
            BlockTxError::BeyondFinality(e) => write!(f, "{}", e),
        }
    }
}

/// `(txid, output index)`.
pub type Outpoint = ([u8; 32], u32);

/// UTXO reader for the state a block is validated against.
pub type UtxoLookup<'a> = dyn Fn(&[u8; 32], u32) -> Result<Option<TxOutput>, String> + 'a;

/// Coinbase-height reader: `Ok(None)` for a txid that is not a known
/// coinbase, `Err` when the index could not be read.
pub type CoinbaseHeightLookup<'a> = dyn Fn(&[u8; 32]) -> Result<Option<u64>, String> + 'a;

// ── Unified TX validation ────────────────────────────────────────────────────
// FIX #10: Single validation core used by all code paths.

/// Core input validation logic shared by all TX validation paths.
/// Resolves each input's UTXO, checks pubkey hash match, verifies ML-DSA-65
/// signature, and accumulates total input value.
pub fn validate_tx_inputs(
    tx:           &core::Transaction,
    utxo_lookup:  &dyn Fn(&[u8; 32], u32) -> Result<Option<core::TxOutput>, String>,
    mut spent_set: Option<&mut HashSet<([u8; 32], u32)>>,
) -> Result<u64, String> {
    let mut total_in = 0u64;

    // C-R3-2: the intra-tx duplicate-outpoint check is UNCONDITIONAL. The
    // standalone (gossip-relay) path passes `spent_set = None`, and the old
    // Some-gated check let a tx list the SAME outpoint N times — its value
    // was counted N times below, so a doubled-fee double-spend was admitted
    // to the mempool. `local_spent` catches duplicates within THIS tx on
    // every path; the caller's `spent_set` (when provided) still tracks
    // cross-tx conflicts inside a block.
    let mut local_spent: HashSet<([u8; 32], u32)> = HashSet::new();

    for (i, inp) in tx.inputs.iter().enumerate() {
        let outpoint = (inp.prev_txid, inp.prev_index);

        // FIX #9 + C-R3-2: double-spend within the same validation context —
        // cross-tx via the caller's set (when present), intra-tx ALWAYS via
        // the local insert-as-check.
        let cross_tx_dup = spent_set.as_ref().is_some_and(|s| s.contains(&outpoint));
        if cross_tx_dup || !local_spent.insert(outpoint) {
            return Err(format!("double-spend: {}:{} already consumed",
                hex::encode(&inp.prev_txid[..8]), inp.prev_index));
        }

        // Resolve UTXO
        let utxo = utxo_lookup(&inp.prev_txid, inp.prev_index)?
            .ok_or_else(|| format!("UTXO {}:{} not found",
                hex::encode(&inp.prev_txid[..8]), inp.prev_index))?;

        total_in = total_in.checked_add(utxo.value).ok_or("input overflow")?;

        // Parse and verify script_sig
        let (sig, pk) = core::Transaction::parse_script_sig(&inp.script_sig)
            .ok_or_else(|| format!("{}malformed script_sig at input {}", WITNESS_ERR, i))?;

        // Verify pubkey hash matches UTXO script_pubkey
        let pk_hash = {
            use sha3::{Sha3_256, Digest};
            Sha3_256::digest(&pk)[..20].to_vec()
        };
        if pk_hash != utxo.script_pubkey {
            return Err(format!("{}pubkey mismatch at input {}", WITNESS_ERR, i));
        }

        // Verify hybrid ML-DSA-65 ‖ Falcon-1024 signature. Chain-id (Roadmap #8)
        // is the node-level single source of truth — miner and validator share it
        // (see core::node_chain_id / set_node_chain_id).
        let sighash = tx.sighash(i, core::node_chain_id());
        if !crypto::verify(&pk, &sighash, &sig) {
            return Err(format!("{}invalid signature at input {}", WITNESS_ERR, i));
        }

        // Mark outpoint as spent
        if let Some(spent) = spent_set.as_mut() {
            spent.insert(outpoint);
        }
    }

    let total_out: u64 = tx.outputs.iter()
        .try_fold(0u64, |acc, o| acc.checked_add(o.value))
        .ok_or("output sum overflow")?;
    if total_in < total_out {
        return Err(format!("inputs {} < outputs {}", total_in, total_out));
    }
    let fee = total_in - total_out;
    // The size (and so the minimum fee) includes the script_sigs, which the
    // txid does not commit: a fee shortfall is witness-dependent too.
    core::check_min_fee(tx, fee).map_err(|e| format!("{}{}", WITNESS_ERR, e))?;
    Ok(fee)
}

/// Validate every transaction of `block` against the UTXO state of its
/// selected parent and return the total fee.
///
/// Rules, in block order:
/// * each non-coinbase tx passes `validate_tx_inputs` (existence, no
///   double-spend inside the tx or the block, pubkey-hash binding, hybrid
///   signature, value conservation with checked arithmetic, minimum fee);
/// * a tx may spend outputs of EARLIER transactions of the same block, never
///   its own or a later one's;
/// * no input may reference an immature coinbase — including this block's
///   own coinbase, which is immature by definition;
/// * the coinbase pays at most subsidy + fees (`validate_coinbase_value`).
pub fn validate_block_transactions(
    block: &Block,
    utxo_lookup: &UtxoLookup<'_>,
    coinbase_height: &CoinbaseHeightLookup<'_>,
) -> Result<u64, BlockTxError> {
    // Record any read failure so it is never reported as a rule violation.
    let storage_error: std::cell::RefCell<Option<String>> = std::cell::RefCell::new(None);
    let checked_lookup = |t: &[u8; 32], i: u32| -> Result<Option<TxOutput>, String> {
        utxo_lookup(t, i).map_err(|e| {
            storage_error.borrow_mut().get_or_insert_with(|| e.clone());
            e
        })
    };
    // A failed coinbase-index read must never look like "not a coinbase"
    // (that would skip the maturity rule): report it as the block's own
    // height, which fails maturity, and surface the storage error below.
    let checked_coinbase = |t: &[u8; 32]| -> Option<u64> {
        match coinbase_height(t) {
            Ok(h) => h,
            Err(e) => {
                storage_error.borrow_mut().get_or_insert(e);
                Some(block.height)
            }
        }
    };
    let res = validate_block_transactions_inner(block, &checked_lookup, &checked_coinbase);
    if let Some(e) = storage_error.into_inner() {
        return Err(BlockTxError::Storage(e));
    }
    res.map_err(|e| {
        if e.contains(WITNESS_ERR) { BlockTxError::InvalidWitness(e) } else { BlockTxError::Invalid(e) }
    })
}

/// Marks an error that depends on script_sig content (see
/// `BlockTxError::InvalidWitness`).
const WITNESS_ERR: &str = "witness: ";

fn validate_block_transactions_inner(
    block: &Block,
    utxo_lookup: &UtxoLookup<'_>,
    coinbase_height: &dyn Fn(&[u8; 32]) -> Option<u64>,
) -> Result<u64, String> {
    let coinbase_txid = block.transactions.first().map(|t| t.txid());
    let mut created: HashMap<Outpoint, TxOutput> = HashMap::new();
    let mut spent: HashSet<Outpoint> = HashSet::new();
    let mut total_fees: u64 = 0;

    for (i, tx) in block.transactions.iter().enumerate() {
        let txid = tx.txid();
        if i > 0 {
            if let Some(cb) = coinbase_txid {
                if let Some(pos) = tx.inputs.iter().position(|inp| inp.prev_txid == cb) {
                    return Err(format!(
                        "coinbase maturity: input {} spends this block's own coinbase", pos));
                }
            }
            core::check_coinbase_maturity(tx, block.height, coinbase_height)?;

            let lookup = |t: &[u8; 32], idx: u32| -> Result<Option<TxOutput>, String> {
                if let Some(out) = created.get(&(*t, idx)) {
                    return Ok(Some(out.clone()));
                }
                utxo_lookup(t, idx)
            };
            let fee = validate_tx_inputs(tx, &lookup, Some(&mut spent))
                .map_err(|e| format!("tx {} ({}): {}", i, hex::encode(&txid[..8]), e))?;
            total_fees = total_fees.checked_add(fee).ok_or("block fee sum overflow")?;
        }
        for (j, out) in tx.outputs.iter().enumerate() {
            created.insert((txid, j as u32), out.clone());
        }
    }

    block.validate_coinbase_value(total_fees)
        .map_err(|e| format!("coinbase rejected: {}", e))?;
    Ok(total_fees)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{BlockHeader, MerkleRoot, Transaction, TxInput};
    use sha3::{Digest as _, Sha3_256};

    fn key() -> &'static (Vec<u8>, Vec<u8>) {
        static K: std::sync::OnceLock<(Vec<u8>, Vec<u8>)> = std::sync::OnceLock::new();
        K.get_or_init(crypto::generate_keypair)
    }
    fn owner() -> Vec<u8> { Sha3_256::digest(&key().0)[..20].to_vec() }

    fn coinbase(value: u64) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxInput { prev_txid: [0u8; 32], prev_index: u32::MAX,
                                   script_sig: b"cb".to_vec(), sequence: u32::MAX }],
            outputs: vec![TxOutput { value, script_pubkey: owner() }],
            locktime: 0,
        }
    }

    fn spend(prev: Outpoint, value: u64) -> Transaction {
        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxInput { prev_txid: prev.0, prev_index: prev.1,
                                   script_sig: vec![], sequence: u32::MAX }],
            outputs: vec![TxOutput { value, script_pubkey: owner() }],
            locktime: 0,
        };
        let sig = crypto::sign(&key().1, &tx.sighash(0, core::node_chain_id())).expect("sign");
        tx.inputs[0].script_sig = Transaction::build_script_sig(&sig, &key().0);
        tx
    }

    fn block(txs: Vec<Transaction>) -> Block {
        Block {
            header: BlockHeader { version: 1, parents: vec![], merkle_root: MerkleRoot::ZERO,
                                  timestamp: 0, bits: core::GENESIS_BITS, nonce: 0 },
            transactions: txs, blue_score: 1, height: 200,
            shielded_transactions: Vec::new(),
        }
    }

    const U: Outpoint = ([0x55u8; 32], 0);

    fn utxo_u(t: &[u8; 32], i: u32) -> Result<Option<TxOutput>, String> {
        Ok(((*t, i) == U).then(|| TxOutput { value: 1_000_000, script_pubkey: owner() }))
    }
    fn no_coinbase(_: &[u8; 32]) -> Result<Option<u64>, String> { Ok(None) }

    #[test]
    fn valid_block_passes_and_returns_fees() {
        let b = block(vec![coinbase(1_000), spend(U, 900_000)]);
        assert_eq!(validate_block_transactions(&b, &utxo_u, &no_coinbase), Ok(100_000));
    }

    #[test]
    fn spending_this_blocks_own_coinbase_is_invalid() {
        let cb = coinbase(1_000);
        let b = block(vec![cb.clone(), spend((cb.txid(), 0), 500)]);
        match validate_block_transactions(&b, &utxo_u, &no_coinbase) {
            Err(BlockTxError::Invalid(m)) => assert!(m.contains("own coinbase"), "{m}"),
            other => panic!("expected Invalid own-coinbase, got {other:?}"),
        }
    }

    #[test]
    fn coinbase_claiming_more_than_subsidy_plus_fees_is_invalid() {
        let fees = 100_000;
        let over = core::tokenomics::block_subsidy_sat(200) + fees + 1;
        let b = block(vec![coinbase(over), spend(U, 900_000)]);
        assert!(matches!(validate_block_transactions(&b, &utxo_u, &no_coinbase),
                         Err(BlockTxError::Invalid(m)) if m.contains("coinbase")));
    }

    #[test]
    fn double_spend_across_transactions_is_invalid() {
        let b = block(vec![coinbase(1_000), spend(U, 900_000), spend(U, 800_000)]);
        assert!(matches!(validate_block_transactions(&b, &utxo_u, &no_coinbase),
                         Err(BlockTxError::Invalid(m)) if m.contains("double-spend")));
    }

    #[test]
    fn bad_signature_is_a_witness_failure_never_a_recordable_verdict() {
        let mut tx = spend(U, 900_000);
        let n = tx.inputs[0].script_sig.len();
        tx.inputs[0].script_sig[n / 3] ^= 0x01; // corrupt; txid is unchanged
        assert_eq!(tx.txid(), spend(U, 900_000).txid(), "txid must not commit script_sig");
        let b = block(vec![coinbase(1_000), tx]);
        assert!(matches!(validate_block_transactions(&b, &utxo_u, &no_coinbase),
                         Err(BlockTxError::InvalidWitness(_))));
    }

    #[test]
    fn utxo_read_failure_is_storage_not_invalid() {
        let failing = |_: &[u8; 32], _: u32| -> Result<Option<TxOutput>, String> { Err("io".into()) };
        let b = block(vec![coinbase(1_000), spend(U, 900_000)]);
        assert_eq!(validate_block_transactions(&b, &failing, &no_coinbase),
                   Err(BlockTxError::Storage("io".into())));
    }

    #[test]
    fn coinbase_index_read_failure_fails_closed() {
        let failing = |_: &[u8; 32]| -> Result<Option<u64>, String> { Err("io".into()) };
        let b = block(vec![coinbase(1_000), spend(U, 900_000)]);
        assert!(matches!(validate_block_transactions(&b, &utxo_u, &failing),
                         Err(BlockTxError::Storage(_))));
    }

    #[test]
    fn immature_coinbase_input_is_invalid() {
        let cb_height = |t: &[u8; 32]| -> Result<Option<u64>, String> {
            Ok((*t == U.0).then_some(150)) // only 50 confirmations at h=200
        };
        let b = block(vec![coinbase(1_000), spend(U, 900_000)]);
        assert!(matches!(validate_block_transactions(&b, &utxo_u, &cb_height),
                         Err(BlockTxError::Invalid(m)) if m.contains("maturity")));
    }
}
