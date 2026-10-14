//! Read-only explorer RPCs: DAG-aware block, chain, address and holder views.
//!
//! The height index in storage is last-write-wins (any block at a height), so
//! these methods never use it for chain membership. They walk the GhostDAG
//! instead: the selected chain is the selected-parent chain from the selected
//! tip, cached and extended incrementally as the tip moves.

use super::*;
use crate::consensus::GhostdagData;
use std::collections::{HashMap, HashSet};

const MAX_PAGE: usize = 100;
const MAX_DAG_WINDOW: usize = 300;

/// Selected chain from genesis (index 0) to the selected tip.
struct ChainCache {
    tip: [u8; 32],
    chain: Vec<[u8; 32]>,
    pos: HashMap<[u8; 32], usize>,
}

fn chain_cache() -> &'static parking_lot::Mutex<Option<ChainCache>> {
    static C: std::sync::OnceLock<parking_lot::Mutex<Option<ChainCache>>> = std::sync::OnceLock::new();
    C.get_or_init(|| parking_lot::Mutex::new(None))
}

/// Run `f` with an up-to-date selected-chain cache.
///
/// NET-15: `f` runs while the DAG read lock is held, so it must only read
/// DAG data (copying what it needs). Every storage (RocksDB) access happens
/// after `with_chain` returns, so a slow disk read can no longer hold the
/// lock that `accept_block` needs to write.
fn with_chain<R>(state: &AppState, f: impl FnOnce(&ChainCache, &GhostDAG) -> R) -> Option<R> {
    let dag = state.dag.read();
    let tip = dag.selected_tip()?;
    let mut guard = chain_cache().lock();
    let fresh = match guard.as_ref() {
        Some(c) if c.tip == tip => None,
        Some(c) => {
            // Walk back from the new tip until we meet the cached chain.
            let mut tail = Vec::new();
            let mut cur = Some(tip);
            let mut meet = None;
            while let Some(h) = cur {
                if let Some(&p) = c.pos.get(&h) { meet = Some(p); break; }
                tail.push(h);
                cur = dag.get_block_data(&h).and_then(|d| d.selected_parent);
            }
            let mut chain = match meet {
                Some(p) => c.chain[..=p].to_vec(),
                None => Vec::new(),
            };
            tail.reverse();
            chain.extend(tail);
            Some(chain)
        }
        None => {
            let mut chain = dag.selected_chain();
            chain.reverse();
            Some(chain)
        }
    };
    if let Some(chain) = fresh {
        let pos = chain.iter().enumerate().map(|(i, h)| (*h, i)).collect();
        *guard = Some(ChainCache { tip, chain, pos });
    }
    guard.as_ref().map(|c| f(c, &dag))
}

fn hex32(h: &[u8; 32]) -> String { hex::encode(h) }

fn parse_hash(v: Option<&Value>) -> Option<[u8; 32]> {
    v.and_then(|v| v.as_str())
        .and_then(|s| hex::decode(s).ok())
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
}

fn spk_address(spk: &[u8]) -> Option<String> {
    <[u8; 20]>::try_from(spk).ok()
        .map(|h| crate::crypto::address_from_hash(&h, crate::core::node_chain_id() == crate::core::ChainId::Testnet))
}

/// Previous output of an input: from storage (UTXO set or the creating tx).
/// Carryover outputs that are already spent are not in any block; they come
/// back as `None` and the caller reports the input without a value.
fn resolve_prevout(state: &AppState, txid: &[u8; 32], index: u32) -> Option<crate::core::TxOutput> {
    state.store.get_utxo_including_spent(txid, index).ok().flatten()
}

fn tx_json(state: &AppState, tx: &crate::core::Transaction) -> Value {
    let coinbase = tx.is_coinbase();
    let mut total_in: Option<u64> = if coinbase { None } else { Some(0) };
    let inputs: Vec<Value> = tx.inputs.iter().map(|inp| {
        if coinbase {
            return json!({ "coinbase": String::from_utf8_lossy(&inp.script_sig).to_string() });
        }
        let prev = resolve_prevout(state, &inp.prev_txid, inp.prev_index);
        match (&prev, total_in.as_mut()) {
            (Some(p), Some(t)) => *t = t.saturating_add(p.value),
            (None, _) => total_in = None,
            _ => {}
        }
        json!({
            "prev_txid":  hex::encode(inp.prev_txid),
            "prev_index": inp.prev_index,
            "value":      prev.as_ref().map(|p| p.value.to_string()),
            "address":    prev.as_ref().and_then(|p| spk_address(&p.script_pubkey)),
        })
    }).collect();
    let total_out: u64 = tx.outputs.iter().map(|o| o.value).sum();
    json!({
        "txid":      hex::encode(tx.txid()),
        "coinbase":  coinbase,
        "size":      tx.to_wire_bytes(true).len(),
        "inputs":    inputs,
        "outputs":   tx.outputs.iter().enumerate().map(|(i, o)| json!({
            "index":   i,
            "value":   o.value.to_string(),
            "address": spk_address(&o.script_pubkey),
            "spent":   state.store.get_utxo(&tx.txid(), i as u32).ok().flatten().is_none(),
        })).collect::<Vec<_>>(),
        "total_out": total_out.to_string(),
        "fee":       total_in.map(|i| i.saturating_sub(total_out).to_string()),
        "locktime":  tx.locktime,
    })
}

/// Colour of `hash` relative to the selected chain: "chain", "blue", "red",
/// or "pending" (not yet merged by a chain block).
fn colour_of(c: &ChainCache, dag: &GhostDAG, hash: &[u8; 32], data: &GhostdagData) -> (&'static str, Option<[u8; 32]>) {
    if c.pos.contains_key(hash) {
        return ("chain", None);
    }
    // The merging chain block is the first chain block whose blue score is
    // above this block's and whose mergeset lists it. Search a bounded window.
    let start = c.chain.partition_point(|h| {
        dag.get_block_data(h).map(|d| d.blue_score <= data.blue_score).unwrap_or(true)
    });
    for h in c.chain.iter().skip(start).take(512) {
        if let Some(d) = dag.get_block_data(h) {
            if d.mergeset_blues.contains(hash) { return ("blue", Some(*h)); }
            if d.mergeset_reds.contains(hash) { return ("red", Some(*h)); }
        }
    }
    ("pending", None)
}

/// The DAG facts a block summary shows, copied out under the DAG lock.
#[derive(Clone, Copy)]
struct DagFacts { height: u64, blue_score: u64, timestamp: u64, parents: usize, merged: usize, reds: usize }

fn dag_facts(dag: &GhostDAG, hash: &[u8; 32]) -> Option<DagFacts> {
    dag.get_block_data(hash).map(|d| DagFacts {
        height: d.height,
        blue_score: d.blue_score,
        timestamp: d.timestamp,
        parents: d.parents.len(),
        merged: d.mergeset_blues.len() + d.mergeset_reds.len(),
        reds: d.mergeset_reds.len(),
    })
}

/// Storage half of a block summary; call without the DAG lock (NET-15).
fn block_summary(state: &AppState, hash: &[u8; 32], d: Option<DagFacts>) -> Value {
    let b = state.store.get_block(hash).ok().flatten();
    let cb = b.as_ref().and_then(|b| b.transactions.first());
    json!({
        "hash":       hex32(hash),
        "height":     d.map(|d| d.height),
        "blue_score": d.map(|d| d.blue_score),
        "timestamp":  d.map(|d| d.timestamp),
        "parents":    d.map(|d| d.parents),
        "merged":     d.map(|d| d.merged),
        "reds":       d.map(|d| d.reds),
        "tx_count":   b.as_ref().map(|b| b.transactions.len()),
        "size":       b.as_ref().map(|b| b.size_bytes()),
        "bits":       b.as_ref().map(|b| format!("0x{:08x}", b.header.bits)),
        "difficulty": b.as_ref().map(|b| crate::core::difficulty_from_bits(b.header.bits)),
        "miner":      cb.and_then(|t| t.outputs.first()).and_then(|o| spk_address(&o.script_pubkey)),
        "reward":     cb.map(|t| t.outputs.iter().map(|o| o.value).sum::<u64>().to_string()),
    })
}

/// `getselectedchain [offset_from_tip=0, count=25]` — newest first.
pub(super) fn get_selected_chain(params: Option<&Value>, state: &AppState) -> Value {
    let offset = params.and_then(|p| p.get(0)).and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    let count = (params.and_then(|p| p.get(1)).and_then(|v| v.as_u64()).unwrap_or(25) as usize).clamp(1, MAX_PAGE);
    // NET-15: copy the page's DAG facts under the lock, read storage after.
    let Some((len, page)) = with_chain(state, |c, dag| {
        let page: Vec<([u8; 32], Option<DagFacts>)> = c.chain.iter().rev().skip(offset).take(count)
            .map(|h| (*h, dag_facts(dag, h))).collect();
        (c.chain.len(), page)
    }) else {
        return json!({ "error": "no selected tip yet" });
    };
    let blocks: Vec<Value> = page.iter().map(|(h, d)| block_summary(state, h, *d)).collect();
    json!({ "chain_length": len, "offset": offset, "blocks": blocks })
}

/// `getblockdag [hash]` — header, GhostDAG data, colour and full transactions.
pub(super) fn get_block_dag(params: Option<&Value>, state: &AppState) -> Value {
    let Some(hash) = parse_hash(params.and_then(|p| p.get(0))) else {
        return json!({ "error": "invalid block hash" });
    };
    // NET-15: DAG facts are copied under the lock; the block body and every
    // per-input storage lookup in `tx_json` run after it is released.
    let facts = with_chain(state, |c, dag| {
        let d = dag.get_block_data(&hash)?;
        let (colour, merged_by) = colour_of(c, dag, &hash, d);
        let tip_score = c.chain.last().and_then(|t| dag.get_block_data(t)).map(|t| t.blue_score).unwrap_or(0);
        let next_chain = c.pos.get(&hash).and_then(|&p| c.chain.get(p + 1)).map(hex32);
        Some((d.clone(), colour, merged_by, tip_score, next_chain))
    });
    let (d, colour, merged_by, tip_score, next_chain) = match facts {
        None => return json!({ "error": "no selected tip yet" }),
        Some(None) => return json!({ "error": "block not found" }),
        Some(Some(f)) => f,
    };
    let block = state.store.get_block(&hash).ok().flatten();
    {
        json!({
            "hash":            hex32(&hash),
            "height":          d.height,
            "blue_score":      d.blue_score,
            "blue_work":       d.blue_work.to_string(),
            "timestamp":       d.timestamp,
            "parents":         d.parents.iter().map(hex32).collect::<Vec<_>>(),
            "selected_parent": d.selected_parent.as_ref().map(hex32),
            "mergeset_blues":  d.mergeset_blues.iter().map(hex32).collect::<Vec<_>>(),
            "mergeset_reds":   d.mergeset_reds.iter().map(hex32).collect::<Vec<_>>(),
            "colour":          colour,
            "merged_by":       merged_by.as_ref().map(hex32),
            "next_chain_block": next_chain,
            "confirmations":   tip_score.saturating_sub(d.blue_score),
            "body":            block.is_some(),
            "version":         block.as_ref().map(|b| b.header.version),
            "bits":            block.as_ref().map(|b| format!("0x{:08x}", b.header.bits)),
            "difficulty":      block.as_ref().map(|b| crate::core::difficulty_from_bits(b.header.bits)),
            "nonce":           block.as_ref().map(|b| b.header.nonce.to_string()),
            "merkle_root":     block.as_ref().map(|b| hex::encode(b.header.merkle_root)),
            "size":            block.as_ref().map(|b| b.size_bytes()),
            "transactions":    block.as_ref().map(|b| b.transactions.iter().map(|t| tx_json(state, t)).collect::<Vec<_>>()),
        })
    }
}

/// Selected-chain blocks from the tip backwards, at most `n`, as
/// `(hash, height, timestamp)`. An O(n) walk of selected parents under a
/// short DAG read lock; no storage access (NET-12/NET-15).
///
/// `None` = the request was cancelled (also while it waited for the lock) —
/// never a partial tail: callers answer `{"error": "cancelled"}`, which
/// HeavyGate never caches. Returning a truncated tail as a success let a
/// cancelled request cache zero block-time percentiles and an empty
/// difficulty history for 30 s (review finding).
fn chain_tail(state: &AppState, n: usize) -> Option<Vec<([u8; 32], u64, u64)>> {
    use std::sync::atomic::Ordering::Relaxed;
    let dag = state.dag.read();
    if state.cancel.load(Relaxed) {
        return None;
    }
    let mut out = Vec::with_capacity(n.min(4096));
    let mut cur = dag.selected_tip();
    while let Some(h) = cur {
        if out.len() >= n { break; }
        if state.cancel.load(Relaxed) {
            return None;
        }
        let Some(d) = dag.get_block_data(&h) else { break };
        out.push((h, d.height, d.timestamp));
        cur = d.selected_parent;
    }
    Some(out)
}

/// Upper bound on blocks read by `getdifficultyhistory`, per point asked.
const DIFFICULTY_SCAN_PER_POINT: usize = 4;

/// `getdifficultyhistory [limit=20]` — the last `limit` (≤ 100) changes of
/// `bits` along the selected chain, newest first.
///
/// NET-12: reads at most `4 × limit` chain blocks (was: every stored block
/// body, decoded and sorted on every call).
pub(super) fn get_difficulty_history(params: Option<&Value>, state: &AppState) -> Value {
    let limit = (params.and_then(|p| p.get(0)).and_then(|v| v.as_u64()).unwrap_or(20) as usize).clamp(1, 100);
    let Some(tail) = chain_tail(state, limit * DIFFICULTY_SCAN_PER_POINT) else {
        return json!({ "error": "cancelled" });
    };
    let mut items: Vec<Value> = Vec::new();
    let mut last_bits: Option<u32> = None;
    for (hash, height, timestamp) in tail {
        if state.cancel.load(std::sync::atomic::Ordering::Relaxed) {
            return json!({ "error": "cancelled" });
        }
        let Ok(Some(block)) = state.store.get_block(&hash) else { continue };
        let bits = block.header.bits;
        if last_bits != Some(bits) {
            items.push(json!({
                "height":     height,
                "bits":       bits,
                "bits_hex":   format!("0x{:08x}", bits),
                "timestamp":  timestamp,
                "target_hex": hex::encode(crate::core::bits_to_target(bits)),
            }));
            last_bits = Some(bits);
            if items.len() >= limit { break; }
        }
    }
    json!({ "count": items.len(), "points": items })
}

/// `getblocktimepercentiles [window=100]` — block-interval statistics over
/// the last `window` (10..=1000) selected-chain blocks.
///
/// NET-12: an O(window) walk of in-memory DAG data (was: every stored block
/// body, decoded and sorted on every call).
pub(super) fn get_block_time_percentiles(params: Option<&Value>, state: &AppState) -> Value {
    let window = (params.and_then(|p| p.get(0)).and_then(|v| v.as_u64()).unwrap_or(100) as usize).clamp(10, 1000);
    let Some(tail) = chain_tail(state, window + 1) else {
        return json!({ "error": "cancelled" });
    };
    let mut deltas: Vec<u64> = tail.windows(2).map(|w| w[0].2.saturating_sub(w[1].2)).collect();
    deltas.sort_unstable();
    let n = deltas.len();
    let (min, p50, p90, p99, max, avg) = if n == 0 {
        (0, 0, 0, 0, 0, 0.0)
    } else {
        let p = |pct: f64| deltas[(((n - 1) as f64 * pct).round() as usize).min(n - 1)];
        let sum: u64 = deltas.iter().fold(0u64, |a, d| a.saturating_add(*d));
        (deltas[0], p(0.50), p(0.90), p(0.99), deltas[n - 1], sum as f64 / n as f64)
    };
    json!({
        "sample_size":  n,
        "window":       window,
        "min_secs":     min,
        "p50_secs":     p50,
        "p90_secs":     p90,
        "p99_secs":     p99,
        "max_secs":     max,
        "avg_secs":     avg,
        "target_secs":  crate::core::TARGET_BLOCK_TIME,
    })
}

/// `gettransactionfull [txid]` — transaction with resolved inputs and its block.
pub(super) fn get_transaction_full(params: Option<&Value>, state: &AppState) -> Value {
    let Some(txid) = parse_hash(params.and_then(|p| p.get(0))) else {
        return json!({ "error": "invalid txid" });
    };
    let Ok(Some((block_hash, height))) = state.store.get_tx_location(&txid) else {
        // Mempool?
        if let Some(e) = state.mempool.get_entry(&txid) {
            return json!({ "status": "mempool", "fee_paid": e.fee.to_string(), "transaction": tx_json(state, &e.tx) });
        }
        return json!({ "error": "transaction not found" });
    };
    let Ok(Some(block)) = state.store.get_block(&block_hash) else {
        return json!({ "error": "block not found" });
    };
    let Some(tx) = block.transactions.iter().find(|t| t.txid() == txid) else {
        return json!({ "error": "transaction index is stale" });
    };
    let colour = with_chain(state, |c, dag| {
        dag.get_block_data(&block_hash).map(|d| colour_of(c, dag, &block_hash, d).0).unwrap_or("unknown")
    }).unwrap_or("unknown");
    json!({
        "status":       "confirmed",
        "block_hash":   hex32(&block_hash),
        "block_height": height,
        "block_colour": colour,
        "timestamp":    block.header.timestamp,
        "transaction":  tx_json(state, tx),
    })
}

/// `getdagwindow [count=120]` — the newest blocks with parents and colour.
pub(super) fn get_dag_window(params: Option<&Value>, state: &AppState) -> Value {
    let count = (params.and_then(|p| p.get(0)).and_then(|v| v.as_u64()).unwrap_or(120) as usize).clamp(1, MAX_DAG_WINDOW);
    with_chain(state, |c, dag| {
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        let mut nodes = Vec::new();
        let mut push = |h: [u8; 32], colour: &str, nodes: &mut Vec<Value>| {
            if !seen.insert(h) { return; }
            if let Some(d) = dag.get_block_data(&h) {
                nodes.push(json!({
                    "hash": hex32(&h), "height": d.height, "blue_score": d.blue_score,
                    "timestamp": d.timestamp, "colour": colour,
                    "parents": d.parents.iter().map(hex32).collect::<Vec<_>>(),
                    "selected_parent": d.selected_parent.as_ref().map(hex32),
                }));
            }
        };
        for tip in dag.tips() {
            if !c.pos.contains_key(&tip) { push(tip, "pending", &mut nodes); }
        }
        for h in c.chain.iter().rev() {
            if nodes.len() >= count { break; }
            push(*h, "chain", &mut nodes);
            if let Some(d) = dag.get_block_data(h) {
                for b in &d.mergeset_blues { if Some(*b) != d.selected_parent { push(*b, "blue", &mut nodes); } }
                for r in &d.mergeset_reds { push(*r, "red", &mut nodes); }
            }
        }
        json!({ "k": dag.k, "nodes": nodes })
    }).unwrap_or_else(|| json!({ "error": "no selected tip yet" }))
}

/// `getaddresshistory [address, limit=25, offset=0]` — newest first.
pub(super) fn get_address_history(params: Option<&Value>, state: &AppState) -> Value {
    let addr = params.and_then(|p| p.get(0)).and_then(|v| v.as_str()).unwrap_or("");
    let Some(hash) = parse_address(addr).and_then(|b| <[u8; 20]>::try_from(b).ok()) else {
        return json!({ "error": "invalid address" });
    };
    let limit = (params.and_then(|p| p.get(1)).and_then(|v| v.as_u64()).unwrap_or(25) as usize).clamp(1, MAX_PAGE);
    let offset = params.and_then(|p| p.get(2)).and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    let total = match state.store.count_address_history(&hash, 0, u64::MAX) {
        Ok(n) => n as usize,
        Err(e) => return storage_err_response(&e),
    };
    // The index is ascending; page from the end for newest-first.
    let end = total.saturating_sub(offset);
    let start = end.saturating_sub(limit);
    let entries = match state.store.query_address_history(&hash, 0, u64::MAX, end - start, start) {
        Ok(e) => e,
        Err(e) => return storage_err_response(&e),
    };
    let items: Vec<Value> = entries.iter().rev().map(|e| json!({
        "txid":      hex32(&e.txid),
        "height":    e.height,
        "direction": e.direction_str(),
        "amount":    e.amount.to_string(),
    })).collect();
    let (balance, utxos) = state.store.get_balance(&hash).unwrap_or((0, 0));
    json!({
        "address": addr, "balance": balance.to_string(), "utxo_count": utxos,
        "total": total, "offset": offset, "items": items,
    })
}

/// `getrichlist [limit=50, offset=0]` — holders by balance.
///
/// NET-12: served from the incremental holder index (`storage::aggregates`,
/// updated in the same batch as every UTXO change): one read of the tier
/// totals plus at most `offset + limit` index entries, `offset` capped at
/// `analytics::MAX_RICHLIST_OFFSET`. Was a scan of the whole UTXO set.
pub(super) fn get_rich_list(params: Option<&Value>, state: &AppState) -> Value {
    let limit = (params.and_then(|p| p.get(0)).and_then(|v| v.as_u64()).unwrap_or(50) as usize).clamp(1, MAX_PAGE);
    let offset = params.and_then(|p| p.get(1)).and_then(|v| v.as_u64()).unwrap_or(0)
        .min(crate::analytics::MAX_RICHLIST_OFFSET as u64) as usize;
    let testnet = crate::core::node_chain_id() == crate::core::ChainId::Testnet;
    match crate::analytics::rich_list_bounded(&state.store, offset, limit, &state.cancel) {
        Ok(page) => json!({
            "holders":      page.holders,
            "total_supply": page.total_supply.to_string(),
            "offset":       page.offset,
            "max_offset":   crate::analytics::MAX_RICHLIST_OFFSET,
            "items":        page.items.iter().enumerate().map(|(i, (h, e))| json!({
                "rank":    page.offset + i + 1,
                "address": crate::crypto::address_from_hash(h, testnet),
                "balance": e.balance.to_string(),
                "utxos":   e.utxos,
                "share":   if page.total_supply > 0 { e.balance as f64 / page.total_supply as f64 } else { 0.0 },
            })).collect::<Vec<_>>(),
        }),
        Err(e) => super::stats_err_response(&e),
    }
}

/// `getsupplydistribution` — holders bucketed by balance, from the UTXO set
/// (carryover included). NET-12: one read of the incremental tier totals.
pub(super) fn get_supply_distribution(state: &AppState) -> Value {
    use crate::storage::aggregates::TIERS;
    match crate::analytics::supply_distribution_bounded(&state.store) {
        Ok(tiers) => {
            let total: u64 = tiers.iter().fold(0u64, |a, t| a.saturating_add(t.sats));
            let holders: u64 = tiers.iter().map(|t| t.holders).sum();
            json!({
                "total_supply": total.to_string(),
                "holders": holders,
                "tiers": TIERS.iter().zip(tiers.iter()).map(|((_, label), t)| json!({
                    "label": label, "address_count": t.holders, "total_sats": t.sats.to_string(),
                    "pct_of_supply": if total > 0 { t.sats as f64 * 100.0 / total as f64 } else { 0.0 },
                })).collect::<Vec<_>>(),
            })
        }
        Err(e) => super::stats_err_response(&e),
    }
}
