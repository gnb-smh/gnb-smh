//! Block-template construction shared by the internal miner and the
//! `getblocktemplate` RPC (audit MEM-2, DAG-2, MEM-1/MEM-3 template side).
//!
//! * Parents: at most `core::MAX_PARENTS` bodied, non-disqualified tips,
//!   highest blue work first (`GhostDAG::template_parents`) — the stock code
//!   used EVERY tip, so more than 256 tips made every template invalid
//!   (`too many parents`) with nobody able to merge them (DAG-2).
//! * Transactions: whole ANCESTOR PACKAGES by package fee rate, parents
//!   before children (child-pays-for-parent, audit MEM-6 —
//!   `mempool::select_packages`), under a BYTE budget measured exactly as the
//!   consensus rule measures (`Block::size_bytes`, bincode): the budget is
//!   `MAX_BLOCK_SIZE` minus an upper bound of the header and block framing
//!   (every varint at its maximum width) minus a coinbase reserve. A
//!   count-only cap let ~116 ordinary transactions push every template past
//!   `MAX_BLOCK_SIZE` (MEM-2). Without in-pool chains this is highest fee
//!   rate first.
//! * Self-check: every selected transaction is re-validated against the
//!   current UTXO set plus the outputs of the transactions placed before it
//!   in the template (standardness, inputs present and not already used by
//!   the template, coinbase maturity at the template height, MoneyRange,
//!   consensus minimum fee, input scripts — normally verified-signature cache
//!   hits). A transaction that fails is EVICTED from the mempool together
//!   with its in-pool descendants instead of making every template invalid
//!   (MEM-1, MEM-3, MEM-6); a package is included all-or-nothing. The fees
//!   the coinbase may claim are recomputed from those inputs, never taken
//!   from the pool.
//!
//! The template is built under the store's acceptance lock, so the DAG and
//! UTXO snapshot it reads are consistent with each other.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use parking_lot::RwLock;

use crate::consensus::{BlockHash, GhostDAG};
use crate::core::{self, Block, BlockHeader, MerkleRoot, Transaction, TxInput, TxOutput};
use crate::mempool::{self, admission, Mempool};
use crate::storage::Storage;

/// `(txid, output index)`.
type Outpoint = ([u8; 32], u32);

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

    let budget = core::MAX_BLOCK_SIZE
        .saturating_sub(framing_upper_bound(&parents))
        .saturating_sub(coinbase_reserve);

    // Ancestor packages by package fee rate (CPFP), byte budget, self-check
    // of every package member in block order, eviction.
    let mut spent_by_template: HashSet<([u8; 32], u32)> = HashSet::new();
    let mut created_by_template: HashMap<([u8; 32], u32), TxOutput> = HashMap::new();
    let mut selected: Vec<(Transaction, u64)> = Vec::new();
    let mut total_fees: u64 = 0;
    let mut evict: HashSet<[u8; 32]> = HashSet::new();
    let candidates = mempool.package_candidates();
    mempool::select_packages(&candidates, budget, usize::MAX, |package| {
        // Dry-run the whole package against the template state; commit only
        // if every member passes (all-or-nothing).
        let mut local_spent: HashSet<([u8; 32], u32)> = HashSet::new();
        let mut local_created: HashMap<([u8; 32], u32), TxOutput> = HashMap::new();
        let mut local_fees = total_fees;
        let mut staged: Vec<(Transaction, u64)> = Vec::with_capacity(package.len());
        for txid in package {
            let Some(tx) = mempool.get_tx(txid) else { return Err(*txid) };
            let is_spent = |op: &([u8; 32], u32)| spent_by_template.contains(op) || local_spent.contains(op);
            let created = |op: &([u8; 32], u32)| {
                local_created.get(op).or_else(|| created_by_template.get(op)).cloned()
            };
            match self_check(store, &tx, height, &is_spent, &created, options.verify_scripts) {
                Ok(fee) => {
                    local_fees = match core::limits::money_add(local_fees, fee) {
                        Ok(t) => t,
                        Err(_) => return Err(*txid),
                    };
                    for inp in &tx.inputs {
                        local_spent.insert((inp.prev_txid, inp.prev_index));
                    }
                    for (j, o) in tx.outputs.iter().enumerate() {
                        local_created.insert((*txid, j as u32), o.clone());
                    }
                    staged.push((tx, fee));
                }
                Err(TemplateReject::Evict(reason)) => {
                    log::info!("template: evicting tx {} (and its descendants) from the mempool: {}",
                        hex::encode(&txid[..8]), reason);
                    evict.insert(*txid);
                    return Err(*txid);
                }
                Err(TemplateReject::Skip) => return Err(*txid),
            }
        }
        spent_by_template.extend(local_spent);
        created_by_template.extend(local_created);
        total_fees = local_fees;
        selected.extend(staged);
        Ok(())
    });
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
    /// template transaction); keep it pooled.
    Skip,
}

/// In-context check of one candidate (see the module docs): its inputs come
/// from `created` (outputs of transactions placed earlier in the template —
/// MEM-6 package parents) or the UTXO set.
fn self_check(
    store: &Storage,
    tx: &Transaction,
    height: u64,
    spent_by_template: &dyn Fn(&Outpoint) -> bool,
    created: &dyn Fn(&Outpoint) -> Option<TxOutput>,
    verify_scripts: bool,
) -> Result<u64, TemplateReject> {
    admission::check_standard(tx).map_err(|e| TemplateReject::Evict(e.to_string()))?;
    let mut seen: HashSet<([u8; 32], u32)> = HashSet::new();
    let mut total_in: u64 = 0;
    let mut prevouts: Vec<TxOutput> = Vec::with_capacity(tx.inputs.len());
    for inp in &tx.inputs {
        let op = (inp.prev_txid, inp.prev_index);
        if !seen.insert(op) {
            return Err(TemplateReject::Evict("duplicate input".into()));
        }
        if spent_by_template(&op) {
            return Err(TemplateReject::Skip);
        }
        let out = match created(&op) {
            Some(o) => o,
            None => match store.get_utxo(&inp.prev_txid, inp.prev_index) {
                Ok(Some(o)) => o,
                Ok(None) => return Err(TemplateReject::Evict(format!(
                    "input {}:{} is neither in the UTXO set nor created earlier in the template",
                    hex::encode(&inp.prev_txid[..8]), inp.prev_index))),
                Err(_) => return Err(TemplateReject::Skip),
            },
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
