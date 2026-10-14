//! Block-template construction shared by the internal miner and the
//! `getblocktemplate` RPC (audit MEM-2, DAG-2, MEM-1/MEM-3 template side).
//!
//! * Parents: at most `core::MAX_PARENTS` bodied, non-disqualified tips,
//!   highest blue work first (`GhostDAG::template_parents`) — the stock code
//!   used EVERY tip, so more than 256 tips made every template invalid
//!   (`too many parents`) with nobody able to merge them (DAG-2).
//! * Transactions: highest fee rate first under a BYTE budget measured exactly
//!   as the consensus rule measures (`Block::size_bytes`, bincode): the
//!   budget is `MAX_BLOCK_SIZE` minus an upper bound of the header and block
//!   framing (every varint at its maximum width) minus a coinbase reserve. A
//!   count-only cap let ~116 ordinary transactions push every template past
//!   `MAX_BLOCK_SIZE` (MEM-2).
//! * Self-check: every selected transaction is re-validated against the
//!   current UTXO set (standardness, inputs present and not already used by
//!   the template, coinbase maturity at the template height, the
//!   transaction-version rule and policy at the template height (CRY-3
//!   activation), MoneyRange, consensus minimum fee, input scripts — normally
//!   verified-signature cache hits). A transaction that fails is EVICTED from
//!   the mempool instead of making every template invalid (MEM-1, MEM-3) —
//!   except a transaction that fails ONLY the version rule at the template
//!   height while it is valid at the pool's own next height
//!   (`Mempool::next_height`), which is skipped, never evicted. The fees the
//!   coinbase may claim are recomputed from the UTXO set, never taken from
//!   the pool.
//! * Height: [`template_parents_and_height`] — the ONE "next block height"
//!   of the node. Mempool admission, post-connect eviction, re-injection and
//!   wallets (`getdaginfo.next_block_height`) use the same value
//!   ([`next_template_height`], cached in `Mempool::next_height`), so they
//!   can never sit on opposite sides of the hardening activation (the header
//!   height of a block that merges a tip with a greater DAG height than its
//!   selected parent exceeds the selected tip's DAG height + 1, DAG-8).
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
}

/// Upper bound of the bincode size of a block with these parents and NO
/// transactions: every variable-width integer at its widest encoding.
fn framing_upper_bound(parents: &[BlockHash]) -> usize {
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
/// must never share a coinbase txid.
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

/// The parents a template on the current DAG would use (at most
/// `core::MAX_PARENTS` bodied, non-disqualified tips, `GhostDAG::template_parents`)
/// and the template's header height: the largest parent DAG height + 1 (the
/// `accept_block` rule). With no bodied tip, no parents and the selected
/// tip's DAG height + 1 (`admission::next_block_height`).
pub fn template_parents_and_height(d: &GhostDAG, store: &Storage) -> (Vec<BlockHash>, u64) {
    let parents = d.template_parents(core::MAX_PARENTS, |h| {
        store.get_block(h).ok().flatten().is_some()
    });
    if parents.is_empty() {
        return (parents, admission::next_block_height(d));
    }
    let height = parents.iter()
        .filter_map(|t| d.get_block_data(t))
        .map(|x| x.height)
        .max()
        .unwrap_or(0)
        .saturating_add(1);
    (parents, height)
}

/// Header height of the node's next template (see
/// [`template_parents_and_height`]): the height the mempool, the template
/// self-check and the wallets evaluate the height-dependent transaction rules
/// (version / sighash, coinbase maturity) at. Never smaller than 1.
pub fn next_template_height(d: &GhostDAG, store: &Storage) -> u64 {
    template_parents_and_height(d, store).1.max(1)
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
        let (parents, height) = template_parents_and_height(&d, store);
        if parents.is_empty() {
            return Err("node has no bodied tip yet (still syncing genesis?)".into());
        }
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

    let budget = core::MAX_BLOCK_SIZE
        .saturating_sub(framing_upper_bound(&parents))
        .saturating_sub(coinbase_reserve);

    // Fee-rate order, byte budget, self-check, eviction.
    let mut used = 0usize;
    let mut spent_by_template: HashSet<([u8; 32], u32)> = HashSet::new();
    let mut selected: Vec<(Transaction, u64)> = Vec::new();
    let mut total_fees: u64 = 0;
    let mut evict: HashSet<[u8; 32]> = HashSet::new();
    // The pool's own next height. Equal to `height` whenever the cache is
    // current (both come from `template_parents_and_height` on the same DAG
    // under the acceptance lock); 0 (unknown) means "the template height".
    let pool_height = match mempool.next_height() {
        0 => height,
        h => h,
    };
    for (tx, _pool_fee, size) in mempool.entries_by_fee_rate() {
        if used.saturating_add(size) > budget {
            continue; // a smaller, lower-rate tx may still fit
        }
        match self_check(store, &tx, height, pool_height, &spent_by_template, options.verify_scripts) {
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
    })
}

enum TemplateReject {
    /// The transaction can never be mined on this chain: drop it from the pool.
    Evict(String),
    /// Not includable in THIS template (its input is used by an earlier
    /// template transaction, or its version is valid at the pool's next
    /// height but not at this template's height); keep it pooled.
    Skip,
}

/// In-context check of one candidate (see the module docs). `pool_height` is
/// the mempool's next height (normally equal to `height`).
fn self_check(
    store: &Storage,
    tx: &Transaction,
    height: u64,
    pool_height: u64,
    spent_by_template: &HashSet<([u8; 32], u32)>,
    verify_scripts: bool,
) -> Result<u64, TemplateReject> {
    admission::check_standard(tx).map_err(|e| TemplateReject::Evict(e.to_string()))?;
    // CRY-3 activation: the version must be valid (and standard) at the
    // TEMPLATE height (version 3 from the hardening activation, version < 3
    // below it); checked even when scripts are not verified. A transaction
    // that fails only because this template's height differs from the pool's
    // next height is still minable in the block the pool targets: skip it,
    // never evict it.
    if let Err(e) = admission::check_version_for_next_block(tx, height) {
        if pool_height != height && admission::check_version_for_next_block(tx, pool_height).is_ok() {
            return Err(TemplateReject::Skip);
        }
        return Err(TemplateReject::Evict(e));
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
        admission::verify_input_scripts(tx, &prevouts, height).map_err(TemplateReject::Evict)?;
    }
    Ok(fee)
}

/// Assemble the candidate block for `template` with the given coinbase, and
/// run the context-free consensus checks a mined block must pass (size,
/// parents, dust, duplicates, canonical limits, MoneyRange, coinbase value).
/// The returned block still needs a nonce.
pub fn assemble_block(template: &BlockTemplate, coinbase: Transaction, timestamp: u64) -> Result<Block, String> {
    let all: Vec<Transaction> = std::iter::once(coinbase)
        .chain(template.transactions.iter().map(|(t, _)| t.clone()))
        .collect();
    let merkle = Transaction::merkle_root(&all);
    let block = Block {
        header: BlockHeader {
            version: 1,
            parents: template.parents.clone(),
            merkle_root: merkle,
            timestamp: timestamp.max(template.parent_timestamp),
            bits: template.bits,
            nonce: 0,
        },
        transactions: all,
        blue_score: template.blue_score,
        height: template.height,
        shielded_transactions: Vec::new(),
    };
    check_template_block(&block, template.total_fees)?;
    Ok(block)
}

/// The template self-check on an assembled (not yet mined) block: every
/// structural rule of `validate_structure` except the proof of work, plus
/// the coinbase value.
pub fn check_template_block(block: &Block, total_fees: u64) -> Result<(), String> {
    if block.header.parents.len() > core::MAX_PARENTS {
        return Err("too many parents".into());
    }
    let size = block.size_bytes();
    if size > core::MAX_BLOCK_SIZE {
        return Err(format!("block too large: {} > {}", size, core::MAX_BLOCK_SIZE));
    }
    if !block.validate_merkle() {
        return Err("invalid merkle root".into());
    }
    if !block.validate_coinbase_format() {
        return Err("invalid coinbase format".into());
    }
    block.validate_no_duplicate_txs().map_err(|e| e.to_string())?;
    block.validate_dust().map_err(|e| e.to_string())?;
    core::limits::check_block_context_free(block)?;
    block.validate_coinbase_value(total_fees).map_err(|e| e.to_string())?;
    Ok(())
}
