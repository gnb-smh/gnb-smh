//! Block-template construction shared by the internal miner and the
//! `getblocktemplate` RPC (audit MEM-2, DAG-2, MEM-1/MEM-3 template side).
//!
//! * Parents: at most `core::MAX_PARENTS` bodied, non-disqualified tips,
//!   highest blue work first (`GhostDAG::template_parents`) — the stock code
//!   used EVERY tip, so more than 256 tips made every template invalid
//!   (`too many parents`) with nobody able to merge them (DAG-2).
//! * Transactions: highest fee rate first under a BYTE budget measured exactly
//!   as the consensus rule measures AT THE TEMPLATE'S HEIGHT (bincode
//!   `Block::size_bytes` below the hardening activation, the canonical wire
//!   encoding `Block::wire_size` at/after it, audit VAL-12): the budget is
//!   `MAX_BLOCK_SIZE` minus an upper bound of the header and block framing
//!   (every varint at its maximum width) minus a coinbase reserve. A
//!   count-only cap let ~116 ordinary transactions push every template past
//!   `MAX_BLOCK_SIZE` (MEM-2).
//! * Hardening rules (docs/CONSENSUS.md, "Block rules at the hardening
//!   activation"): a template at/after the activation height gets the
//!   tagged Merkle root and a coinbase whose `script_sig` starts with the
//!   80-byte commitment (height, parents, witness root) —
//!   [`assemble_block`] writes it — and never contains a 64-byte
//!   transaction or a spend of its own coinbase (inputs must be in the UTXO
//!   set). A template below the height is built exactly as before.
//! * Self-check: every selected transaction is re-validated against the
//!   current UTXO set (standardness, inputs present and not already used by
//!   the template, coinbase maturity at the template height, MoneyRange,
//!   consensus minimum fee, input scripts — normally verified-signature cache
//!   hits). A transaction that fails is EVICTED from the mempool instead of
//!   making every template invalid (MEM-1, MEM-3). The fees the coinbase may
//!   claim are recomputed from the UTXO set, never taken from the pool.
//!
//! The template is built under the store's acceptance lock, so the DAG and
//! UTXO snapshot it reads are consistent with each other.

use std::collections::HashSet;
use std::sync::Arc;

use parking_lot::RwLock;

use crate::consensus::{BlockHash, GhostDAG};
use crate::core::{self, Block, BlockHeader, MerkleRoot, Transaction, TxInput, TxOutput};
use crate::mempool::{admission, Mempool};
use crate::storage::Storage;

/// Bytes reserved for a coinbase the template builder does not construct
/// itself (`getblocktemplate` consumers build their own coinbase). Far above
/// the node's own coinbase (~80 bytes).
pub const EXTERNAL_COINBASE_RESERVE: usize = 1_000;

/// A block template: everything needed to assemble a candidate block.
#[derive(Clone, Debug)]
pub struct BlockTemplate {
    /// Parents, the selected parent first.
    pub parents: Vec<BlockHash>,
    /// Header height: max parent DAG height + 1 (the `accept_block` rule).
    pub height: u64,
    /// Informational blue score (max parent blue score + 1).
    pub blue_score: u64,
    /// Expected ASERT bits for these parents.
    pub bits: u32,
    /// Latest parent timestamp (the minimum block timestamp).
    pub parent_timestamp: u64,
    /// Non-coinbase transactions in block order, with their recomputed fees.
    pub transactions: Vec<(Transaction, u64)>,
    /// Sum of the fees of `transactions`.
    pub total_fees: u64,
    /// Block subsidy at `height`.
    pub subsidy: u64,
    /// Transactions evicted from the mempool by the self-check.
    pub evicted: usize,
    /// The byte budget the transactions were selected under.
    pub tx_byte_budget: usize,
    /// The hardening activation height the template was built under.
    pub activation_height: u64,
    /// Whether the hardening block rules apply at `height`.
    pub hardened: bool,
}

impl BlockTemplate {
    /// The 80-byte coinbase commitment a block built from this template must
    /// carry at the start of its coinbase `script_sig` (`None` below the
    /// activation, where the `script_sig` is free-form).
    pub fn coinbase_commitment(&self) -> Option<[u8; core::block_rules::COINBASE_COMMITMENT_LEN]> {
        if !self.hardened {
            return None;
        }
        // The witness root ignores position 0 (the coinbase).
        let placeholder = Transaction { version: 0, inputs: vec![], outputs: vec![], locktime: 0 };
        let txs: Vec<Transaction> = std::iter::once(placeholder)
            .chain(self.transactions.iter().map(|(t, _)| t.clone()))
            .collect();
        Some(core::block_rules::coinbase_commitment(
            self.height, &self.parents, &core::block_rules::witness_root(&txs)))
    }

    /// The sibling hashes from the coinbase leaf to the header Merkle root,
    /// under the rule of the template's height.
    pub fn coinbase_merkle_branch(&self) -> Vec<[u8; 32]> {
        let ids: Vec<[u8; 32]> = std::iter::once([0u8; 32])
            .chain(self.transactions.iter().map(|(t, _)| t.txid()))
            .collect();
        core::block_rules::coinbase_merkle_branch(&ids, self.hardened)
    }
}

/// Upper bound of the size of a block with these parents and NO
/// transactions, in the measure of the regime (wire when `hardened`,
/// bincode otherwise): every variable-width integer at its widest encoding.
fn framing_upper_bound(parents: &[BlockHash], hardened: bool) -> usize {
    if hardened {
        // header (fixed fields + parents varint + parents) + tx-count varint
        // (at most 9) + shielded-count varint (1: templates carry none).
        return 4 + 9 + 32 * parents.len() + 32 + 8 + 4 + 8 + 8 + 8 + 9 + 1;
    }
    let empty = Block {
        header: BlockHeader {
            version: u32::MAX,
            parents: parents.to_vec(),
            merkle_root: MerkleRoot::ZERO,
            timestamp: u64::MAX,
            bits: u32::MAX,
            nonce: u64::MAX,
        },
        transactions: Vec::new(),
        blue_score: u64::MAX,
        height: u64::MAX,
        shielded_transactions: Vec::new(),
    };
    // + 9: the transaction-count varint grows from 1 byte (empty) to at most 9.
    empty.size_bytes().saturating_add(9)
}

/// The node's own coinbase for `height` paying `value` to `script_pubkey`.
/// Height plus a random tag: two blocks at the same height (common in a DAG)
/// must never share a coinbase txid. At/after the hardening activation
/// [`assemble_block`] prefixes this `script_sig` with the 80-byte commitment
/// (the tag stays as the miner's extra bytes).
pub fn miner_coinbase(height: u64, value: u64, script_pubkey: Vec<u8>) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid:  [0u8; 32],
            prev_index: u32::MAX,
            script_sig: format!("gnb:h{}:{:016x}", height, rand::random::<u64>()).into_bytes(),
            sequence:   u32::MAX,
        }],
        outputs: vec![TxOutput { value, script_pubkey }],
        locktime: 0,
    }
}

/// Bytes the miner reserves for its own coinbase: the widest coinbase it can
/// build (maximal value and tag, plus the 80-byte hardening commitment) in
/// the larger of the two size measures, so the reserve holds on both sides of
/// the activation.
pub fn miner_coinbase_reserve(script_pubkey: &[u8]) -> usize {
    let mut cb = miner_coinbase(u64::MAX, u64::MAX, script_pubkey.to_vec());
    let mut ss = vec![0xFF; core::block_rules::COINBASE_COMMITMENT_LEN];
    ss.extend_from_slice(&cb.inputs[0].script_sig);
    cb.inputs[0].script_sig = ss;
    cb.actual_size().max(cb.wire_size(true))
}

/// Build a template on the current DAG / UTXO / mempool state.
///
/// `coinbase_reserve` is the number of bytes kept free for the coinbase
/// (`EXTERNAL_COINBASE_RESERVE` for `getblocktemplate`; the miner passes the
/// size of its own coinbase with a maximal value).
pub fn build_block_template(
    dag: &Arc<RwLock<GhostDAG>>,
    store: &Storage,
    mempool: &Mempool,
    coinbase_reserve: usize,
) -> Result<BlockTemplate, String> {
    build_block_template_with(dag, store, mempool, &TemplateOptions { coinbase_reserve, verify_scripts: true })
}

/// Template-building knobs.
#[derive(Clone, Copy, Debug)]
pub struct TemplateOptions {
    /// Bytes kept free for the coinbase.
    pub coinbase_reserve: usize,
    /// Verify each selected transaction's input scripts (signatures). On by
    /// default; normally served from the verified-signature cache. Tests with
    /// synthetic unsigned transactions turn it off.
    pub verify_scripts: bool,
}

/// [`build_block_template`] with explicit options.
pub fn build_block_template_with(
    dag: &Arc<RwLock<GhostDAG>>,
    store: &Storage,
    mempool: &Mempool,
    options: &TemplateOptions,
) -> Result<BlockTemplate, String> {
    let coinbase_reserve = options.coinbase_reserve;
    let _guard = store.acceptance_lock();

    let (parents, height, blue_score, parent_ts) = {
        let d = dag.read();
        let parents = d.template_parents(core::MAX_PARENTS, |h| {
            store.get_block(h).ok().flatten().is_some()
        });
        if parents.is_empty() {
            return Err("node has no bodied tip yet (still syncing genesis?)".into());
        }
        let height = parents.iter()
            .filter_map(|t| d.get_block_data(t))
            .map(|x| x.height)
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        let blue_score = parents.iter()
            .filter_map(|t| d.get_block_data(t))
            .map(|x| x.blue_score)
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        let parent_ts = core::difficulty_parent_timestamp(
            parents.iter().filter_map(|t| d.get_block_data(t)).map(|x| x.timestamp));
        (parents, height, blue_score, parent_ts)
    };
    let bits = crate::pow::expected_bits(parent_ts, height)
        .map_err(|e| format!("expected bits not derivable: {}", e))?;
    // The rules of the template's height (header height, as accept_block
    // will judge the block).
    let activation_height = core::activation::hardening_activation_height();
    let hardened = core::block_rules::rules_active_at(height, activation_height);

    let budget = core::MAX_BLOCK_SIZE
        .saturating_sub(framing_upper_bound(&parents, hardened))
        .saturating_sub(coinbase_reserve);

    // Fee-rate order, byte budget, self-check, eviction.
    let mut used = 0usize;
    let mut spent_by_template: HashSet<([u8; 32], u32)> = HashSet::new();
    let mut selected: Vec<(Transaction, u64)> = Vec::new();
    let mut total_fees: u64 = 0;
    let mut evict: HashSet<[u8; 32]> = HashSet::new();
    for (tx, _pool_fee, pool_size) in mempool.entries_by_fee_rate() {
        // The pool records bincode sizes; the consensus measure at/after the
        // activation is the wire encoding (VAL-12).
        let size = if hardened { tx.wire_size(true) } else { pool_size };
        if used.saturating_add(size) > budget {
            continue; // a smaller, lower-rate tx may still fit
        }
        match self_check(store, &tx, height, &spent_by_template, options.verify_scripts, hardened) {
            Ok(fee) => {
                let new_total = match core::limits::money_add(total_fees, fee) {
                    Ok(t) => t,
                    Err(_) => continue,
                };
                for inp in &tx.inputs {
                    spent_by_template.insert((inp.prev_txid, inp.prev_index));
                }
                used = used.saturating_add(size);
                total_fees = new_total;
                selected.push((tx, fee));
            }
            Err(TemplateReject::Evict(reason)) => {
                log::info!("template: evicting tx {} from the mempool: {}",
                    hex::encode(&tx.txid()[..8]), reason);
                evict.insert(tx.txid());
            }
            Err(TemplateReject::Skip) => {}
        }
    }
    let evicted = evict.len();
    if evicted > 0 {
        mempool.retain_valid(|e| !evict.contains(&e.tx.txid()));
    }

    Ok(BlockTemplate {
        parents,
        height,
        blue_score,
        bits,
        parent_timestamp: parent_ts,
        transactions: selected,
        total_fees,
        subsidy: core::tokenomics::block_subsidy_sat(height),
        evicted,
        tx_byte_budget: budget,
        activation_height,
        hardened,
    })
}

enum TemplateReject {
    /// The transaction can never be mined on this chain: drop it from the pool.
    Evict(String),
    /// Not includable in THIS template (its input is used by an earlier
    /// template transaction); keep it pooled.
    Skip,
}

/// Signature-free in-context check of one candidate (see the module docs).
fn self_check(
    store: &Storage,
    tx: &Transaction,
    height: u64,
    spent_by_template: &HashSet<([u8; 32], u32)>,
    verify_scripts: bool,
    hardened: bool,
) -> Result<u64, TemplateReject> {
    admission::check_standard(tx).map_err(|e| TemplateReject::Evict(e.to_string()))?;
    if hardened {
        // Pooled before the activation, unminable from it (VAL-10).
        core::block_rules::check_tx_not_64_bytes(tx)
            .map_err(|e| TemplateReject::Evict(e.to_string()))?;
    }
    let mut seen: HashSet<([u8; 32], u32)> = HashSet::new();
    let mut total_in: u64 = 0;
    let mut prevouts: Vec<TxOutput> = Vec::with_capacity(tx.inputs.len());
    for inp in &tx.inputs {
        let op = (inp.prev_txid, inp.prev_index);
        if !seen.insert(op) {
            return Err(TemplateReject::Evict("duplicate input".into()));
        }
        if spent_by_template.contains(&op) {
            return Err(TemplateReject::Skip);
        }
        let out = match store.get_utxo(&inp.prev_txid, inp.prev_index) {
            Ok(Some(o)) => o,
            Ok(None) => return Err(TemplateReject::Evict(format!(
                "input {}:{} is not in the UTXO set", hex::encode(&inp.prev_txid[..8]), inp.prev_index))),
            Err(_) => return Err(TemplateReject::Skip),
        };
        total_in = core::limits::money_add(total_in, out.value)
            .map_err(TemplateReject::Evict)?;
        prevouts.push(out);
    }
    core::check_coinbase_maturity(tx, height, |t| store.get_coinbase_height(t).ok().flatten())
        .map_err(TemplateReject::Evict)?;
    let total_out = core::limits::check_tx_money_range(tx).map_err(TemplateReject::Evict)?;
    if total_in < total_out {
        return Err(TemplateReject::Evict(format!("inputs {} < outputs {}", total_in, total_out)));
    }
    let fee = total_in - total_out;
    core::check_min_fee(tx, fee).map_err(TemplateReject::Evict)?;
    if verify_scripts {
        // Normally a verified-signature cache hit: pooled transactions were
        // verified at admission, re-injected ones when their block connected.
        admission::verify_input_scripts(tx, &prevouts).map_err(TemplateReject::Evict)?;
    }
    Ok(fee)
}

/// Assemble the candidate block for `template` with the given coinbase, and
/// run the context-free consensus checks a mined block must pass (size,
/// parents, dust, duplicates, canonical limits, MoneyRange, coinbase value,
/// and at/after the activation the hardening rules). The returned block
/// still needs a nonce.
///
/// At/after the hardening activation the coinbase's `script_sig` is
/// rewritten to `commitment || extra`, where `extra` is the caller's
/// `script_sig` (with a leading commitment, if the caller already wrote one,
/// removed): every in-process producer that goes through this function emits
/// a valid coinbase on both sides of the boundary. The header Merkle root
/// follows the rule of the template's height.
pub fn assemble_block(template: &BlockTemplate, coinbase: Transaction, timestamp: u64) -> Result<Block, String> {
    let all: Vec<Transaction> = std::iter::once(coinbase)
        .chain(template.transactions.iter().map(|(t, _)| t.clone()))
        .collect();
    let mut block = Block {
        header: BlockHeader {
            version: 1,
            parents: template.parents.clone(),
            merkle_root: MerkleRoot::ZERO,
            timestamp: timestamp.max(template.parent_timestamp),
            bits: template.bits,
            nonce: 0,
        },
        transactions: all,
        blue_score: template.blue_score,
        height: template.height,
        shielded_transactions: Vec::new(),
    };
    if template.hardened {
        let commitment = core::block_rules::expected_coinbase_commitment(&block);
        if let Some(input) = block.transactions[0].inputs.first_mut() {
            let tag = &core::block_rules::COINBASE_COMMITMENT_TAG;
            let extra = if input.script_sig.len() >= core::block_rules::COINBASE_COMMITMENT_LEN
                && input.script_sig.starts_with(tag)
            {
                input.script_sig[core::block_rules::COINBASE_COMMITMENT_LEN..].to_vec()
            } else {
                std::mem::take(&mut input.script_sig)
            };
            input.script_sig = core::block_rules::coinbase_script_sig(&commitment, &extra);
        }
    }
    block.header.merkle_root = block.body_merkle_root_at(template.activation_height);
    check_template_block_at(&block, template.total_fees, template.activation_height)?;
    Ok(block)
}

/// The template self-check on an assembled (not yet mined) block: every
/// structural rule of `validate_structure` except the proof of work, plus
/// the coinbase value, under the process-wide activation height.
pub fn check_template_block(block: &Block, total_fees: u64) -> Result<(), String> {
    check_template_block_at(block, total_fees, core::activation::hardening_activation_height())
}

/// [`check_template_block`] for an explicit activation height.
pub fn check_template_block_at(block: &Block, total_fees: u64, activation_height: u64) -> Result<(), String> {
    let hardened = core::block_rules::rules_active_at(block.height, activation_height);
    let size = core::block_rules::block_size_for_rules(block, hardened);
    if size > core::MAX_BLOCK_SIZE {
        return Err(format!(
            "block too large: {} > {} ({} encoding)",
            size, core::MAX_BLOCK_SIZE, if hardened { "wire" } else { "bincode" }
        ));
    }
    block.validate_structure_without_pow_at(activation_height).map_err(|e| e.to_string())?;
    core::limits::check_block_context_free(block)?;
    block.validate_coinbase_value(total_fees).map_err(|e| e.to_string())?;
    Ok(())
}
