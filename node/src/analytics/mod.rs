//! Bloch-SIS Protocol — Chain Analytics
//!
//! Sprint B: aggregated data primitives for node ops and explorer use.
//! All functions here are read-only, derived from storage + mempool state.
//! None of them affect consensus; safe to add/remove without hard fork.
//!
//! # Bounded cost (audit NET-12)
//!
//! The explorer statistics used to decode EVERY stored block body
//! (`chain_stats`, `supply_distribution`, `difficulty_history`,
//! `block_time_percentiles`) or walk the whole UTXO set (rich list) on each
//! call. Every function here now does work independent of the chain length:
//!
//! * totals come from aggregates maintained in the UTXO write batches
//!   (`storage::aggregates`): O(1) reads;
//! * windows (last 24 h, last 50 blocks) walk the in-memory selected chain
//!   for at most [`STATS_WINDOW_MAX_BLOCKS`] blocks, checking a cancellation
//!   flag, and read the per-block cumulative totals at the two ends only;
//! * the rich list reads at most `offset + limit` index entries, with
//!   `offset ≤` [`MAX_RICHLIST_OFFSET`] and `limit ≤` [`MAX_RICHLIST_PAGE`].
//!
//! Errors are typed ([`StatsError`]): the RPC layer answers a storage
//! failure with the sanitised `STORAGE_ERROR` response (audit L-5) and never
//! with the storage detail (paths, RocksDB internals).

use std::sync::atomic::{AtomicBool, Ordering};

use parking_lot::RwLock;

use crate::consensus::GhostDAG;
use crate::storage::aggregates::{HolderEntry, TierTotals};
use crate::storage::{Storage, StorageError};
use crate::mempool::Mempool;
use crate::core::TARGET_BLOCK_TIME;

/// NET-12: upper bound on selected-chain blocks walked for the 24 h window
/// (≈ 7× the 2,880 blocks a day at the 30 s target).
pub const STATS_WINDOW_MAX_BLOCKS: usize = 20_000;
/// NET-12: selected-chain blocks sampled for the average block time.
pub const BLOCK_TIME_SAMPLE: usize = 50;
/// NET-12: largest accepted rich-list offset.
pub const MAX_RICHLIST_OFFSET: usize = 10_000;
/// NET-12: largest rich-list page.
pub const MAX_RICHLIST_PAGE: usize = 100;

const NOT_READY: &str = "explorer aggregates are not built yet (they are rebuilt at node start-up)";

/// Why an explorer statistic could not be computed.
#[derive(Debug)]
pub enum StatsError {
    /// The aggregates are not built yet (start-up rebuild pending).
    NotReady,
    /// The request's cancellation flag was set (dispatch timeout).
    Cancelled,
    /// The DAG has no selected tip yet.
    NoTip,
    /// A storage failure. Its detail is for the node's log only: the RPC
    /// layer answers with the sanitised `STORAGE_ERROR` response (audit L-5).
    Storage(StorageError),
}

impl std::fmt::Display for StatsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StatsError::NotReady => write!(f, "{}", NOT_READY),
            StatsError::Cancelled => write!(f, "cancelled"),
            StatsError::NoTip => write!(f, "no selected tip yet"),
            StatsError::Storage(_) => write!(f, "internal storage error"),
        }
    }
}

impl std::error::Error for StatsError {}

/// A storage error seen by a cancellable computation: `aggregates::cancelled`
/// is itself a `StorageError`, so a set flag means the request was
/// cancelled, not that storage failed.
fn storage(cancel: &AtomicBool, e: StorageError) -> StatsError {
    if cancel.load(Ordering::Relaxed) { StatsError::Cancelled } else { StatsError::Storage(e) }
}

fn cancelled(cancel: &AtomicBool) -> Result<(), StatsError> {
    if cancel.load(Ordering::Relaxed) { Err(StatsError::Cancelled) } else { Ok(()) }
}

// ─────────────────────────────────────────────────────────────────────────────
// Chain stats (bounded)
// ─────────────────────────────────────────────────────────────────────────────

/// `getchainstats` / `gethashrate`.
#[derive(Clone, Debug, PartialEq)]
pub struct ChainStats {
    /// Blocks in the DAG (in memory; merged and red blocks included).
    pub total_blocks:        u64,
    /// Blocks of the applied selected chain, genesis included.
    pub chain_blocks:        u64,
    /// Transactions connected on the selected chain (the ledger), genesis
    /// excluded.
    pub total_txs:           u64,
    pub avg_txs_per_block:   f64,
    /// Selected-chain blocks stamped within the last 24 h.
    pub blocks_last_24h:     u64,
    /// Their transactions (None if a cumulative record is missing).
    pub txs_last_24h:        Option<u64>,
    /// The 24 h window hit [`STATS_WINDOW_MAX_BLOCKS`].
    pub window_capped:       bool,
    /// Average interval between SELECTED-CHAIN blocks over the last
    /// [`BLOCK_TIME_SAMPLE`] chain blocks.
    pub avg_block_time:      f64,
    /// Average interval between DAG blocks over the same span: the chain
    /// blocks plus every block they merged (blue and red). Each of them cost
    /// a block's worth of work.
    pub avg_dag_block_interval: f64,
    pub current_difficulty:  u32,
    /// Network hashrate: hashes per block / [`Self::avg_dag_block_interval`]
    /// (every DAG block counts, merged blue and red included).
    pub hashrate_estimate:   f64,
}

/// NET-12: chain statistics in O(window) in-memory DAG steps and a constant
/// number of storage reads (tip pointer, chain totals, two cumulative
/// records, the tip header), whatever the chain length.
pub fn chain_stats_bounded(
    store: &Storage,
    dag: &RwLock<GhostDAG>,
    now_unix: u64,
    cancel: &AtomicBool,
) -> Result<ChainStats, StatsError> {
    if !store.aggregates_ready() {
        return Err(StatsError::NotReady);
    }
    let applied_tip = store.get_meta("tip_hash").ok().flatten()
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok());
    let cutoff = now_unix.saturating_sub(86_400);

    // In-memory walks under the DAG read lock; no storage access here.
    struct Walk {
        tip: [u8; 32], dag_blocks: u64, in_window: u64, boundary: Option<([u8; 32], bool)>, capped: bool,
        sample: Vec<u64>,
        /// DAG blocks mined after the oldest sampled chain block.
        dag_in_sample: u64,
    }
    let w = {
        let d = dag.read();
        let tip = applied_tip.filter(|t| d.has_block(t)).or_else(|| d.selected_tip())
            .ok_or(StatsError::NoTip)?;
        // Each chain block stands for itself plus its mergeset (the merged
        // blue and red blocks, the selected parent excluded): summed over
        // the newest n-1 sampled chain blocks, exactly the DAG blocks mined
        // after the oldest one.
        let mut sample = Vec::with_capacity(BLOCK_TIME_SAMPLE);
        let mut merged: Vec<u64> = Vec::with_capacity(BLOCK_TIME_SAMPLE);
        let mut cur = Some(tip);
        while let Some(h) = cur {
            if sample.len() >= BLOCK_TIME_SAMPLE { break; }
            let Some(data) = d.get_block_data(&h) else { break };
            sample.push(data.timestamp);
            merged.push(1 + data.mergeset_blues.len() as u64 + data.mergeset_reds.len() as u64);
            cur = data.selected_parent;
        }
        let dag_in_sample: u64 = if sample.len() >= 2 { merged[..sample.len() - 1].iter().sum() } else { 0 };
        let (mut in_window, mut boundary, mut capped) = (0u64, None, false);
        let mut cur = Some(tip);
        while let Some(h) = cur {
            if in_window % 256 == 0 {
                cancelled(cancel)?;
            }
            let Some(data) = d.get_block_data(&h) else { break };
            let is_genesis = data.selected_parent.is_none();
            if data.timestamp < cutoff {
                boundary = Some((h, is_genesis));
                break;
            }
            if in_window as usize >= STATS_WINDOW_MAX_BLOCKS {
                capped = true;
                boundary = Some((h, is_genesis));
                break;
            }
            in_window += 1;
            cur = data.selected_parent;
        }
        Walk { tip, dag_blocks: d.block_count() as u64, in_window, boundary, capped, sample, dag_in_sample }
    };

    let totals = store.chain_totals().map_err(|e| storage(cancel, e))?;
    let at = |h: &[u8; 32], genesis: bool| -> Option<u64> {
        match store.chain_cumulative(h) {
            Ok(Some(t)) => Some(t.txs),
            Ok(None) if genesis => Some(0),
            _ => None,
        }
    };
    let tip_is_genesis = totals.blocks == 0;
    let tip_txs = at(&w.tip, tip_is_genesis);
    let base_txs = match w.boundary {
        Some((h, genesis)) => at(&h, genesis),
        None => Some(0), // walked back through the genesis: the whole chain
    };
    let txs_last_24h = match (tip_txs, base_txs) {
        (Some(t), Some(b)) => Some(t.saturating_sub(b)),
        _ => None,
    };

    let (avg_block_time, avg_dag_block_interval) = if w.sample.len() >= 2 {
        let span = w.sample[0].saturating_sub(*w.sample.last().unwrap_or(&w.sample[0]));
        let chain = span as f64 / (w.sample.len() - 1) as f64;
        let dag = if w.dag_in_sample > 0 { span as f64 / w.dag_in_sample as f64 } else { chain };
        (chain, dag)
    } else {
        (TARGET_BLOCK_TIME as f64, TARGET_BLOCK_TIME as f64)
    };
    let bits = store.get_block(&w.tip).ok().flatten().map(|b| b.header.bits)
        .unwrap_or(crate::core::GENESIS_BITS);
    let chain_blocks = totals.blocks.saturating_add(1);
    Ok(ChainStats {
        total_blocks: w.dag_blocks,
        chain_blocks,
        total_txs: totals.txs,
        avg_txs_per_block: if totals.blocks > 0 { totals.txs as f64 / totals.blocks as f64 } else { 0.0 },
        blocks_last_24h: w.in_window,
        txs_last_24h,
        window_capped: w.capped,
        avg_block_time,
        avg_dag_block_interval,
        current_difficulty: bits,
        hashrate_estimate: estimate_hashrate(bits, avg_dag_block_interval),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Holders (bounded)
// ─────────────────────────────────────────────────────────────────────────────

/// One page of the rich list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RichListPage {
    /// Number of holders (20-byte script_pubkeys with ≥ 1 UTXO).
    pub holders:      u64,
    /// Σ of their balances.
    pub total_supply: u64,
    /// The (clamped) offset served.
    pub offset:       usize,
    pub items:        Vec<([u8; 20], HolderEntry)>,
}

/// NET-12: `limit` (1..=[`MAX_RICHLIST_PAGE`]) holders from rank `offset`
/// (clamped to [`MAX_RICHLIST_OFFSET`]): one read of the tier totals plus
/// at most `offset + limit` index entries.
pub fn rich_list_bounded(store: &Storage, offset: usize, limit: usize, cancel: &AtomicBool) -> Result<RichListPage, StatsError> {
    if !store.aggregates_ready() {
        return Err(StatsError::NotReady);
    }
    let offset = offset.min(MAX_RICHLIST_OFFSET);
    let limit = limit.clamp(1, MAX_RICHLIST_PAGE);
    let tiers = store.tier_totals().map_err(|e| storage(cancel, e))?;
    let items = store.rich_list_page(offset, limit, cancel).map_err(|e| storage(cancel, e))?;
    Ok(RichListPage {
        holders: tiers.iter().map(|t| t.holders).sum(),
        total_supply: tiers.iter().fold(0u64, |a, t| a.saturating_add(t.sats)),
        offset,
        items,
    })
}

/// NET-12: the supply distribution — one read.
pub fn supply_distribution_bounded(store: &Storage) -> Result<Vec<TierTotals>, StatsError> {
    if !store.aggregates_ready() {
        return Err(StatsError::NotReady);
    }
    store.tier_totals().map_err(StatsError::Storage)
}

/// NET-12: `(holders, their UTXOs)` — one read (was a scan of the whole
/// address index).
pub fn address_count_bounded(store: &Storage) -> Result<(u64, u64), StatsError> {
    let tiers = supply_distribution_bounded(store)?;
    Ok((tiers.iter().map(|t| t.holders).sum(), tiers.iter().map(|t| t.utxos).sum()))
}

// ─────────────────────────────────────────────────────────────────────────────
// Hashrate estimate
// ─────────────────────────────────────────────────────────────────────────────

/// Estimate network hashrate in hashes per second from difficulty and block time.
///
/// Formula: target = bits_to_target(bits), expected_hashes_per_block = 2^256 / target
/// hashrate = expected_hashes_per_block / avg_block_time_seconds
pub fn estimate_hashrate(bits: u32, avg_block_time_secs: f64) -> f64 {
    if avg_block_time_secs <= 0.0 { return 0.0; }

    // Compute target from bits
    let exponent = ((bits >> 24) & 0xff) as i32;
    let mantissa = (bits & 0x00ffffff) as f64;

    // target = mantissa * 256^(exponent - 3)
    let target = mantissa * 256f64.powi(exponent - 3);
    if target <= 0.0 { return 0.0; }

    // 2^256 = max_target
    let max_target = 2f64.powi(256);

    // Expected hashes per block = max_target / target
    let hashes_per_block = max_target / target;

    hashes_per_block / avg_block_time_secs
}

// ─────────────────────────────────────────────────────────────────────────────
// Mempool stats (beyond getmempoolinfo)
// ─────────────────────────────────────────────────────────────────────────────

pub struct MempoolStats {
    pub size:        usize,
    pub total_fees:  u64,
    pub min_fee:     u64,
    pub max_fee:     u64,
    pub median_fee:  u64,
    pub avg_fee:     f64,
    pub buckets:     Vec<MempoolFeeBucket>,
}

pub struct MempoolFeeBucket {
    pub range:       String,
    pub tx_count:    usize,
}

pub fn mempool_stats(mempool: &Mempool) -> MempoolStats {
    let entries = mempool.entries();
    let size = entries.len();

    if size == 0 {
        return MempoolStats {
            size: 0,
            total_fees: 0,
            min_fee: 0, max_fee: 0, median_fee: 0,
            avg_fee: 0.0,
            buckets: Vec::new(),
        };
    }

    let mut fees: Vec<u64> = entries.iter().map(|(_, fee, _)| *fee).collect();
    fees.sort();

    let total_fees: u64 = fees.iter().sum();
    let avg_fee = total_fees as f64 / size as f64;
    let median_fee = fees[size / 2];

    // Fee rate buckets (sats)
    let bucket_bounds: &[(u64, &str)] = &[
        (100,       "0-100"),
        (1_000,     "100-1k"),
        (10_000,    "1k-10k"),
        (100_000,   "10k-100k"),
        (u64::MAX,  ">100k"),
    ];

    let mut buckets = Vec::new();
    let mut last_bound = 0u64;
    for (bound, label) in bucket_bounds {
        let count = fees.iter().filter(|&&f| f >= last_bound && f < *bound).count();
        buckets.push(MempoolFeeBucket {
            range:    label.to_string(),
            tx_count: count,
        });
        last_bound = *bound;
    }

    MempoolStats {
        size,
        total_fees,
        min_fee:    *fees.first().unwrap(),
        max_fee:    *fees.last().unwrap(),
        median_fee,
        avg_fee,
        buckets,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Address info (aggregate view)
// ─────────────────────────────────────────────────────────────────────────────

pub struct AddressInfo {
    pub address:           String,
    pub balance_sats:      u64,
    pub balance_gnb:      f64,
    pub utxo_count:        usize,
    pub pending_incoming:  u64,
    pub pending_outgoing:  u64,
    pub pool_role:         Option<String>,
}

pub fn address_info(
    storage: &Storage,
    mempool: &Mempool,
    addr_str: &str,
    addr_hash: &[u8; 20],
) -> Result<AddressInfo, String> {
    let (balance_sats, utxo_count) = storage.get_balance(addr_hash).map_err(|e| e.to_string())?;

    // Pending balance from mempool
    let utxo_lookup = |txid: &[u8; 32], index: u32| -> Option<crate::core::TxOutput> {
        storage.get_utxo(txid.as_slice(), index).ok().flatten()
    };
    let (pending_incoming, pending_outgoing) = mempool.pending_balance_for(
        addr_hash,
        Some(&utxo_lookup),
    );

    // Fair launch: no protocol pools or founder addresses exist.
    let pool_role: Option<String> = None;

    Ok(AddressInfo {
        address:          addr_str.to_string(),
        balance_sats,
        balance_gnb:     balance_sats as f64 / 1e8,
        utxo_count,
        pending_incoming,
        pending_outgoing,
        pool_role,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Fee estimation (advanced)
// ─────────────────────────────────────────────────────────────────────────────

/// `estimatefeeadvanced`: absolute fees for one transaction of `tx_bytes`
/// wire bytes, in satoshis, every one at least the consensus minimum for that
/// size and the mempool's rolling minimum (B1-T21 / MEM-6).
pub struct FeeEstimate {
    /// Wire size the fees are computed for.
    pub tx_bytes:         usize,
    /// The fee rates (sat per 1,000 wire bytes) behind the three tiers.
    pub floor_rate_per_kb: u64,
    pub next_block_rate_per_kb: u64,
    pub medium_rate_per_kb: u64,
    pub next_block_sats:  u64,
    pub medium_priority:  u64,
    pub slow_priority:    u64,
    /// The median pooled fee rate applied to `tx_bytes` (equals
    /// `medium_priority`; kept for older clients).
    pub mempool_median:   u64,
    pub mempool_size:     usize,
}

/// Largest input / output count `estimatefeeadvanced` prices (far beyond any
/// standard transaction; keeps the size arithmetic exact).
pub const FEE_ESTIMATE_MAX_IO: u64 = 10_000;

/// B1-T21 / MEM-6: the advanced estimate is derived from fee RATES, like
/// `estimatefee`, and from the size of the transaction being priced
/// (`tx_bytes`). The floor rate is the consensus minimum rate or the
/// mempool's rolling minimum, whichever is higher
/// (`Mempool::estimate_fee_rate_per_kb`'s floor); `slow` pays the floor,
/// `medium` the median pooled rate, `next_block` the 75th-percentile pooled
/// rate, none below the floor. Each tier's fee is
/// `max(min_tx_fee_sat(tx_bytes), ceil(tx_bytes × rate / 1000))`, so no field
/// is ever below the consensus minimum for that size. (The previous estimate
/// returned raw ABSOLUTE-fee percentiles that ignored the size, and on a
/// quiet pool 5,000 and 1,000 sat against the 10,000-sat minimum.) Bitcoin
/// Core's `estimatesmartfee` likewise never returns a rate below
/// max(minrelaytxfee, mempoolminfee).
pub fn estimate_fee_advanced(mempool: &Mempool, tx_bytes: usize) -> FeeEstimate {
    let floor = crate::core::tokenomics::MIN_FEE_RATE_SAT_PER_KB
        .max(mempool.rolling_min_fee_rate().saturating_mul(1000));
    let rates = mempool.fee_rates_per_kb();
    let pct = |p: usize| -> u64 {
        if rates.is_empty() { 0 } else { rates[((rates.len() - 1) * p / 100).min(rates.len() - 1)] }
    };
    let medium_rate = pct(50).max(floor);
    let next_rate = pct(75).max(medium_rate);
    let fee_at = |rate: u64| -> u64 {
        crate::core::tokenomics::min_tx_fee_sat(tx_bytes)
            .max((tx_bytes as u64).saturating_mul(rate).div_ceil(1000))
    };
    let medium = fee_at(medium_rate);
    FeeEstimate {
        tx_bytes,
        floor_rate_per_kb: floor,
        next_block_rate_per_kb: next_rate,
        medium_rate_per_kb: medium_rate,
        next_block_sats: fee_at(next_rate),
        medium_priority: medium,
        slow_priority: fee_at(floor),
        mempool_median: medium,
        mempool_size: rates.len(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashrate_nonzero_for_valid_bits() {
        let h = estimate_hashrate(0x1d00ffff, 10.0);
        assert!(h > 0.0, "hashrate should be positive");
    }

    #[test]
    fn hashrate_zero_if_block_time_zero() {
        let h = estimate_hashrate(0x1d00ffff, 0.0);
        assert_eq!(h, 0.0);
    }

    #[test]
    fn hashrate_higher_difficulty_means_more_hashrate() {
        // 0x1d00ffff is easier than 0x1c00ffff (lower exponent = smaller target = more work)
        let easy = estimate_hashrate(0x1d00ffff, 10.0);
        let hard = estimate_hashrate(0x1c00ffff, 10.0);
        assert!(hard > easy, "harder target should imply higher hashrate for same block time");
    }

    #[test]
    fn supply_tier_bounds_are_monotonic() {
        // NET-12: the tiers now live with the incremental aggregates.
        let tiers = crate::storage::aggregates::TIERS;
        for i in 1..tiers.len() {
            assert!(tiers[i].0 > tiers[i-1].0);
        }
    }
}
