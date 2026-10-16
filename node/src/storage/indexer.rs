//! Bloch-SIS Protocol — Address Transaction History Indexer (Sprint F)
//!
//! Appends entries to `CF_ADDR_TX_HISTORY` for each (address, tx) touch —
//! whether as output recipient or as input spender. Chronologically ordered
//! by height, enabling O(log n + k) queries instead of O(n) full chain scans.
//!
//! Key schema:   [20B addr_hash][8B height BE][4B tx_index BE][4B out_or_in_idx BE]
//! Value schema: [32B txid][1B direction: 0=in, 1=out][8B amount_sats LE]
//!
//! `height` is the block's position on the selected chain, its DAG height
//! (audit DAG-8; `Storage::stage_chain_index`), not its header height.
//!
//! Properties:
//! - Written when a block joins the selected chain and deleted when it
//!   leaves it, in the same atomic batch as the UTXO changes.
//! - Height in BE so prefix-iteration returns chronological order.
//! - Key is unique per (addr, position, tx, vout/vin): positions are unique
//!   along the selected chain (header heights were not: DAG-8).
//! - Prefix extractor of 20 bytes enables efficient address-scoped range scans.

use rocksdb::{IteratorMode, ReadOptions};
use crate::storage::{Storage, StorageError};
use crate::core::Transaction;

pub const CF_ADDR_TX_HISTORY: &str = "addr_tx_history";

/// B1-T11: largest offset an address-history page may skip (one index step
/// per skipped entry). Deeper pages use the opaque cursor a page returns
/// (`next_cursor`), which costs nothing to resume from. The explorer API
/// (deploy/explorer-api: HISTORY_OFFSET) accepts exactly this range.
pub const MAX_HISTORY_OFFSET: usize = 10_000;

/// B1-T11: length of an address-history cursor: the key suffix after the
/// address (height BE ‖ tx_index BE ‖ io_index BE) of the last entry a page
/// returned. The next page starts strictly before it.
pub const HISTORY_CURSOR_LEN: usize = 16;

/// One newest-first page of an address's history.
#[derive(Debug, Clone, Default)]
pub struct HistoryPage {
    pub entries:     Vec<AddrHistoryEntry>,
    /// Cursor of the next (older) page; None when this page is the last.
    pub next_cursor: Option<[u8; HISTORY_CURSOR_LEN]>,
}

// Entry size: 32 (txid) + 1 (direction) + 8 (amount) = 41 bytes
pub const ENTRY_SIZE: usize = 41;
pub const DIR_IN: u8 = 0;
pub const DIR_OUT: u8 = 1;

/// Parsed history entry.
#[derive(Debug, Clone)]
pub struct AddrHistoryEntry {
    pub addr_hash: [u8; 20],
    pub height:    u64,
    pub tx_index:  u32,
    pub io_index:  u32,
    pub txid:      [u8; 32],
    pub direction: u8,      // 0 = in (spent), 1 = out (received)
    pub amount:    u64,
}

#[allow(dead_code)] // library API (the RPC streams balances since NET-12)
impl AddrHistoryEntry {
    pub fn is_incoming(&self) -> bool { self.direction == DIR_OUT }
    pub fn is_outgoing(&self) -> bool { self.direction == DIR_IN }
    pub fn direction_str(&self) -> &'static str {
        if self.direction == DIR_OUT { "in" } else { "out" }
    }
}

/// Compose the key bytes for a history entry.
pub fn make_key(addr_hash: &[u8; 20], height: u64, tx_index: u32, io_index: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(36);
    key.extend_from_slice(addr_hash);
    key.extend_from_slice(&height.to_be_bytes());
    key.extend_from_slice(&tx_index.to_be_bytes());
    key.extend_from_slice(&io_index.to_be_bytes());
    key
}

/// Every CF_ADDR_TX_HISTORY key that connecting `block` to the selected chain
/// writes (`Storage::stage_chain_index`): one row per output whose script
/// carries a 20-byte address, and one per non-coinbase input whose spent
/// output — resolved through `spent`, the block's undo capture — does.
///
/// Single definition used to un-index a block on rollback and to record the
/// keys when its body is pruned, so a reorg of any depth can still un-index a
/// pruned block exactly (audit DAG-6).
pub fn addr_history_keys(
    block: &crate::core::Block,
    position: u64,
    spent: &std::collections::HashMap<([u8; 32], u32), crate::core::TxOutput>,
) -> Vec<Vec<u8>> {
    let mut keys = Vec::new();
    for (tx_idx, tx) in block.transactions.iter().enumerate() {
        for (vout, out) in tx.outputs.iter().enumerate() {
            if out.script_pubkey.len() >= 20 {
                let mut addr = [0u8; 20];
                addr.copy_from_slice(&out.script_pubkey[..20]);
                keys.push(make_key(&addr, position, tx_idx as u32, vout as u32));
            }
        }
        if !tx.is_coinbase() {
            for (vin, inp) in tx.inputs.iter().enumerate() {
                if let Some(prev) = spent.get(&(inp.prev_txid, inp.prev_index)) {
                    if prev.script_pubkey.len() >= 20 {
                        let mut addr = [0u8; 20];
                        addr.copy_from_slice(&prev.script_pubkey[..20]);
                        keys.push(make_key(&addr, position, tx_idx as u32, 0x8000_0000 | vin as u32));
                    }
                }
            }
        }
    }
    keys
}

/// `key` with its height field replaced by `position` (the chain-index
/// migration of audit DAG-8). A malformed key is returned unchanged.
pub fn with_position(key: &[u8], position: u64) -> Vec<u8> {
    let mut k = key.to_vec();
    if k.len() == 36 {
        k[20..28].copy_from_slice(&position.to_be_bytes());
    }
    k
}

/// Compose the value bytes for a history entry.
pub fn make_value(txid: &[u8; 32], direction: u8, amount: u64) -> Vec<u8> {
    let mut val = Vec::with_capacity(ENTRY_SIZE);
    val.extend_from_slice(txid);
    val.push(direction);
    val.extend_from_slice(&amount.to_le_bytes());
    val
}

/// Parse a key into (addr_hash, height, tx_index, io_index).
pub fn parse_key(key: &[u8]) -> Option<([u8; 20], u64, u32, u32)> {
    if key.len() != 36 { return None; }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&key[..20]);
    let height = u64::from_be_bytes(key[20..28].try_into().ok()?);
    let tx_index = u32::from_be_bytes(key[28..32].try_into().ok()?);
    let io_index = u32::from_be_bytes(key[32..36].try_into().ok()?);
    Some((addr, height, tx_index, io_index))
}

/// Parse a value into (txid, direction, amount).
pub fn parse_value(val: &[u8]) -> Option<([u8; 32], u8, u64)> {
    if val.len() != ENTRY_SIZE { return None; }
    let mut txid = [0u8; 32];
    txid.copy_from_slice(&val[..32]);
    let direction = val[32];
    let amount = u64::from_le_bytes(val[33..41].try_into().ok()?);
    Some((txid, direction, amount))
}

// ─────────────────────────────────────────────────────────────────────────────
// Indexing API (called by Storage::put_block)
// ─────────────────────────────────────────────────────────────────────────────

impl Storage {
    /// Extract the 20-byte address hash from a script_pubkey.
    /// Our script_pubkey format is simply the 20-byte SHA3-256(pubkey)[..20].
    fn script_pubkey_to_addr_hash(script_pubkey: &[u8]) -> Option<[u8; 20]> {
        if script_pubkey.len() < 20 { return None; }
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&script_pubkey[..20]);
        Some(addr)
    }

    /// Compute the (key, value) `CF_ADDR_TX_HISTORY` writes for one transaction
    /// WITHOUT touching the DB. Shared by `index_tx_addresses` (direct write)
    /// and `put_block`'s atomic `WriteBatch` path so both produce byte-identical
    /// entries. Kept private to the crate; the keys/values are an internal index.
    pub(crate) fn addr_index_entries(
        &self,
        tx: &Transaction,
        height: u64,
        tx_index: u32,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        let txid = tx.txid();
        let mut entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

        // Index outputs (DIR_OUT — address RECEIVED funds)
        for (vout_idx, output) in tx.outputs.iter().enumerate() {
            if let Some(addr) = Self::script_pubkey_to_addr_hash(&output.script_pubkey) {
                entries.push((
                    make_key(&addr, height, tx_index, vout_idx as u32),
                    make_value(&txid, DIR_OUT, output.value),
                ));
            }
        }

        // Index inputs (DIR_IN — address SPENT funds)
        // Coinbase has no real inputs — skip.
        if !tx.is_coinbase() {
            for (vin_idx, input) in tx.inputs.iter().enumerate() {
                // Look up the previous output to find which address was spent
                if let Ok(Some(prev_output)) = self.get_utxo_including_spent(&input.prev_txid, input.prev_index) {
                    if let Some(addr) = Self::script_pubkey_to_addr_hash(&prev_output.script_pubkey) {
                        // Use a high bit offset for io_index to avoid collision with vout indices
                        // (a tx cannot have 2^31 outputs, so bit 31 marks "this is an input entry")
                        entries.push((
                            make_key(&addr, height, tx_index, 0x80000000 | vin_idx as u32),
                            make_value(&txid, DIR_IN, prev_output.value),
                        ));
                    }
                }
                // If prev_output can't be found (shouldn't happen on valid chain),
                // skip silently — we prefer partial index to indexing failure.
            }
        }

        Ok(entries)
    }

    /// Index one transaction's address touches.
    /// Called during put_block for each tx. For inputs, looks up the previous
    /// output to find which address was spent.
    pub fn index_tx_addresses(&self, tx: &Transaction, height: u64, tx_index: u32) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_ADDR_TX_HISTORY)
            .ok_or_else(|| StorageError::CfNotFound(CF_ADDR_TX_HISTORY.into()))?;
        // B1-T11: the rows and the per-address history counters in one batch.
        let _agg = self.agg_lock();
        let mut batch = rocksdb::WriteBatch::default();
        let mut deltas = super::aggregates::HistoryDeltas::default();
        for (key, val) in self.addr_index_entries(tx, height, tx_index)? {
            deltas.put(&key);
            batch.put_cf(&cf, &key, &val);
        }
        self.stage_history_deltas(&mut batch, &deltas)?;
        self.write_batch(batch)
    }

    /// Sprint U.2 — Inverse of `index_tx_addresses`. Called by `rollback_block`
    /// to un-record address touches when a block is being reverted out of the
    /// selected chain.
    ///
    /// For inputs we use `spent_lookup` (sourced from UndoData.spent_utxos)
    /// rather than `get_utxo_including_spent`. The latter could fail after
    /// UTXO restoration re-inserts spent outputs, and could also succeed with
    /// stale data for intra-block chains if rollback order changes. Using the
    /// lookup captured at accept-time is deterministic.
    ///
    /// Silently skips entries whose address can't be resolved — matches the
    /// best-effort semantics of `index_tx_addresses`, so any key that wasn't
    /// created in the first place isn't attempted for delete.
    pub fn unindex_tx_addresses(
        &self,
        tx: &Transaction,
        height: u64,
        tx_index: u32,
        spent_lookup: &std::collections::HashMap<([u8; 32], u32), crate::core::TxOutput>,
    ) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_ADDR_TX_HISTORY)
            .ok_or_else(|| StorageError::CfNotFound(CF_ADDR_TX_HISTORY.into()))?;
        // B1-T11: the deletions and the per-address history counters in one
        // batch.
        let _agg = self.agg_lock();
        let mut batch = rocksdb::WriteBatch::default();
        let mut deltas = super::aggregates::HistoryDeltas::default();

        // Unindex outputs (DIR_OUT entries created by index_tx_addresses)
        for (vout_idx, output) in tx.outputs.iter().enumerate() {
            if let Some(addr) = Self::script_pubkey_to_addr_hash(&output.script_pubkey) {
                let key = make_key(&addr, height, tx_index, vout_idx as u32);
                deltas.delete(&key);
                batch.delete_cf(&cf, &key);
            }
        }

        // Unindex inputs (DIR_IN entries — only exist for non-coinbase txs)
        if !tx.is_coinbase() {
            for (vin_idx, input) in tx.inputs.iter().enumerate() {
                if let Some(prev_output) = spent_lookup.get(&(input.prev_txid, input.prev_index)) {
                    if let Some(addr) = Self::script_pubkey_to_addr_hash(&prev_output.script_pubkey) {
                        // Mirror index_tx_addresses's bit-31 IN marker.
                        let key = make_key(&addr, height, tx_index, 0x80000000 | vin_idx as u32);
                        deltas.delete(&key);
                        batch.delete_cf(&cf, &key);
                    }
                }
                // If not in spent_lookup (e.g. intra-block chain that was never
                // successfully indexed), there's nothing to delete — skip.
            }
        }

        self.stage_history_deltas(&mut batch, &deltas)?;
        self.write_batch(batch)
    }
    pub fn get_utxo_including_spent(&self, prev_txid: &[u8; 32], prev_index: u32)
        -> Result<Option<crate::core::TxOutput>, StorageError>
    {
        // Try UTXO set first (fast path for unspent outputs)
        if let Some(utxo) = self.get_utxo(prev_txid, prev_index)? {
            return Ok(Some(utxo));
        }
        // Fallback: look up the tx location, load the block, find the output
        match self.get_tx_location(prev_txid)? {
            Some((block_hash, _height)) => {
                if let Some(block) = self.get_block(&block_hash)? {
                    for tx in &block.transactions {
                        if &tx.txid() == prev_txid {
                            if let Some(out) = tx.outputs.get(prev_index as usize) {
                                return Ok(Some(out.clone()));
                            }
                        }
                    }
                }
                Ok(None)
            }
            None => Ok(None),
        }
    }

    /// Query address history by range. Returns entries sorted by height ascending.
    pub fn query_address_history(
        &self,
        addr_hash: &[u8; 20],
        start_height: u64,
        end_height: u64,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<AddrHistoryEntry>, StorageError> {
        let cf = self.db.cf_handle(CF_ADDR_TX_HISTORY)
            .ok_or_else(|| StorageError::CfNotFound(CF_ADDR_TX_HISTORY.into()))?;

        let mut lower = Vec::with_capacity(36);
        lower.extend_from_slice(addr_hash);
        lower.extend_from_slice(&start_height.to_be_bytes());
        lower.extend_from_slice(&[0u8; 8]); // tx_index + io_index = 0

        let mut upper = Vec::with_capacity(36);
        upper.extend_from_slice(addr_hash);
        upper.extend_from_slice(&end_height.saturating_add(1).to_be_bytes());
        upper.extend_from_slice(&[0u8; 8]);

        let mut read_opts = ReadOptions::default();
        read_opts.set_iterate_upper_bound(upper);

        let iter = self.db.iterator_cf_opt(&cf, read_opts, IteratorMode::From(&lower, rocksdb::Direction::Forward));

        let mut results = Vec::new();
        let mut skipped = 0;
        for item in iter {
            let (key, value) = item.map_err(|e| StorageError::ReadFailed(e.to_string()))?;
            // Verify prefix still matches our address (paranoia)
            if key.len() < 20 || &key[..20] != addr_hash {
                break;
            }
            if skipped < offset {
                skipped += 1;
                continue;
            }
            if results.len() >= limit {
                break;
            }
            if let (Some((a, h, ti, ii)), Some((txid, dir, amt))) = (parse_key(&key), parse_value(&value)) {
                results.push(AddrHistoryEntry {
                    addr_hash: a,
                    height:    h,
                    tx_index:  ti,
                    io_index:  ii,
                    txid,
                    direction: dir,
                    amount:    amt,
                });
            }
        }
        Ok(results)
    }

    /// Count total entries for an address within a height range (for pagination).
    pub fn count_address_history(
        &self,
        addr_hash: &[u8; 20],
        start_height: u64,
        end_height: u64,
    ) -> Result<u64, StorageError> {
        let cf = self.db.cf_handle(CF_ADDR_TX_HISTORY)
            .ok_or_else(|| StorageError::CfNotFound(CF_ADDR_TX_HISTORY.into()))?;

        let mut lower = Vec::with_capacity(36);
        lower.extend_from_slice(addr_hash);
        lower.extend_from_slice(&start_height.to_be_bytes());
        lower.extend_from_slice(&[0u8; 8]);

        let mut upper = Vec::with_capacity(36);
        upper.extend_from_slice(addr_hash);
        upper.extend_from_slice(&end_height.saturating_add(1).to_be_bytes());
        upper.extend_from_slice(&[0u8; 8]);

        let mut read_opts = ReadOptions::default();
        read_opts.set_iterate_upper_bound(upper);

        let iter = self.db.iterator_cf_opt(&cf, read_opts, IteratorMode::From(&lower, rocksdb::Direction::Forward));

        let mut count = 0u64;
        for item in iter {
            let (key, _) = item.map_err(|e| StorageError::ReadFailed(e.to_string()))?;
            if key.len() < 20 || &key[..20] != addr_hash { break; }
            count += 1;
        }
        Ok(count)
    }

    /// [`Self::count_address_history`] that checks `cancel` on every entry
    /// (B1-T11: the RPC callers of a range count).
    pub fn count_address_history_cancellable(
        &self,
        addr_hash: &[u8; 20],
        start_height: u64,
        end_height: u64,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<u64, StorageError> {
        self.count_address_history_capped(addr_hash, start_height, end_height, u64::MAX, cancel)
    }

    /// [`Self::count_address_history_cancellable`] that stops at `cap`
    /// entries (returns `cap` when there are at least that many): at most
    /// `cap` index steps whatever the address's history (B1-T11 review:
    /// `listtransactions` over a height range).
    pub fn count_address_history_capped(
        &self,
        addr_hash: &[u8; 20],
        start_height: u64,
        end_height: u64,
        cap: u64,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<u64, StorageError> {
        let cf = self.db.cf_handle(CF_ADDR_TX_HISTORY)
            .ok_or_else(|| StorageError::CfNotFound(CF_ADDR_TX_HISTORY.into()))?;
        let mut lower = Vec::with_capacity(36);
        lower.extend_from_slice(addr_hash);
        lower.extend_from_slice(&start_height.to_be_bytes());
        lower.extend_from_slice(&[0u8; 8]);
        let mut upper = Vec::with_capacity(36);
        upper.extend_from_slice(addr_hash);
        upper.extend_from_slice(&end_height.saturating_add(1).to_be_bytes());
        upper.extend_from_slice(&[0u8; 8]);
        let mut read_opts = ReadOptions::default();
        read_opts.set_iterate_upper_bound(upper);
        let iter = self.db.iterator_cf_opt(&cf, read_opts, IteratorMode::From(&lower, rocksdb::Direction::Forward));
        let mut count = 0u64;
        for item in iter {
            if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(super::aggregates::cancelled());
            }
            if count >= cap {
                break;
            }
            self.note_reads(1);
            let (key, _) = item.map_err(|e| StorageError::ReadFailed(e.to_string()))?;
            if key.len() < 20 || &key[..20] != addr_hash { break; }
            count += 1;
        }
        Ok(count)
    }

    /// B1-T11: one newest-first page of `addr_hash`'s history: the entries
    /// strictly older than `before` (a cursor a previous page returned; None
    /// = from the newest), skipping `offset` (capped at
    /// [`MAX_HISTORY_OFFSET`]) and returning at most `limit`.
    ///
    /// A reverse iterator from the end of the address's key range: the cost
    /// is `offset + limit + 1` index steps, whatever the length of the
    /// history (the previous form counted every entry and skipped forward
    /// from the oldest one). `cancel` is checked on every step. Modelled on
    /// the electrs/esplora address APIs (last-seen cursor, hard limits).
    pub fn address_history_page(
        &self,
        addr_hash: &[u8; 20],
        before: Option<&[u8; HISTORY_CURSOR_LEN]>,
        offset: usize,
        limit: usize,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<HistoryPage, StorageError> {
        let cf = self.db.cf_handle(CF_ADDR_TX_HISTORY)
            .ok_or_else(|| StorageError::CfNotFound(CF_ADDR_TX_HISTORY.into()))?;
        let offset = offset.min(MAX_HISTORY_OFFSET);
        let mut read_opts = ReadOptions::default();
        read_opts.set_iterate_lower_bound(addr_hash.to_vec());
        // Total order: the reverse walk must not depend on the prefix
        // extractor's seek mode.
        read_opts.set_total_order_seek(true);
        let mut it = self.db.raw_iterator_cf_opt(&cf, read_opts);
        let mut target = Vec::with_capacity(20 + HISTORY_CURSOR_LEN + 1);
        target.extend_from_slice(addr_hash);
        match before {
            Some(c) => target.extend_from_slice(c),
            // Greater than every 36-byte key of the address.
            None => target.extend_from_slice(&[0xFF; HISTORY_CURSOR_LEN + 1]),
        }
        it.seek_for_prev(&target);
        if before.is_some() && it.key() == Some(target.as_slice()) {
            it.prev();
        }
        let mut page = HistoryPage::default();
        let mut skipped = 0usize;
        let mut more = false;
        while let (Some(key), Some(value)) = (it.key(), it.value()) {
            if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(super::aggregates::cancelled());
            }
            self.note_reads(1);
            if key.len() < 20 || &key[..20] != addr_hash { break; }
            if skipped < offset {
                skipped += 1;
            } else if page.entries.len() >= limit {
                more = true;
                break;
            } else if let (Some((a, h, ti, ii)), Some((txid, dir, amt))) = (parse_key(key), parse_value(value)) {
                page.entries.push(AddrHistoryEntry {
                    addr_hash: a, height: h, tx_index: ti, io_index: ii, txid, direction: dir, amount: amt,
                });
            }
            it.prev();
        }
        it.status().map_err(|e| StorageError::ReadFailed(e.to_string()))?;
        if more {
            page.next_cursor = page.entries.last().map(|e| {
                let mut c = [0u8; HISTORY_CURSOR_LEN];
                c[..8].copy_from_slice(&e.height.to_be_bytes());
                c[8..12].copy_from_slice(&e.tx_index.to_be_bytes());
                c[12..].copy_from_slice(&e.io_index.to_be_bytes());
                c
            });
        }
        Ok(page)
    }

    /// B1-T11: balance and UTXO count of `addr` — one read of the holder
    /// aggregate (`storage::aggregates`, updated in the same batch as every
    /// UTXO change). While the aggregates are being rebuilt (start-up after
    /// an upgrade) it falls back to the walk of the address's UTXOs, which
    /// checks `cancel`.
    pub fn address_balance(
        &self,
        addr: &[u8; 20],
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<(u64, u64), StorageError> {
        if self.aggregates_ready() {
            return Ok(self.holder(addr)?.map(|h| (h.balance, h.utxos)).unwrap_or((0, 0)));
        }
        self.get_balance_cancellable(addr, cancel).map(|(b, n)| (b, n as u64))
    }

    /// Compute balance at a specific height by replaying the address history.
    /// balance(height) = sum(received up to height) - sum(spent up to height)
    #[allow(dead_code)] // library API; the RPC uses the cancellable form
    pub fn balance_at_height(&self, addr_hash: &[u8; 20], height: u64) -> Result<u64, StorageError> {
        self.balance_at_height_cancellable(addr_hash, height, &std::sync::atomic::AtomicBool::new(false))
            .map(|(b, _)| b)
    }

    /// NET-12: [`Self::balance_at_height`] that streams the history (no
    /// collected vector) and checks `cancel` on every entry, so an aborted
    /// heavy RPC stops instead of finishing a long walk in the background.
    /// Returns `(balance, entries replayed)`.
    pub fn balance_at_height_cancellable(
        &self,
        addr_hash: &[u8; 20],
        height: u64,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<(u64, u64), StorageError> {
        let cf = self.db.cf_handle(CF_ADDR_TX_HISTORY)
            .ok_or_else(|| StorageError::CfNotFound(CF_ADDR_TX_HISTORY.into()))?;
        let mut lower = Vec::with_capacity(36);
        lower.extend_from_slice(addr_hash);
        lower.extend_from_slice(&0u64.to_be_bytes());
        lower.extend_from_slice(&[0u8; 8]);
        let mut upper = Vec::with_capacity(36);
        upper.extend_from_slice(addr_hash);
        upper.extend_from_slice(&height.saturating_add(1).to_be_bytes());
        upper.extend_from_slice(&[0u8; 8]);
        let mut read_opts = ReadOptions::default();
        read_opts.set_iterate_upper_bound(upper);
        let iter = self.db.iterator_cf_opt(&cf, read_opts, IteratorMode::From(&lower, rocksdb::Direction::Forward));
        let mut balance: i128 = 0;
        let mut entries = 0u64;
        for item in iter {
            if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(super::aggregates::cancelled());
            }
            self.note_reads(1);
            let (key, value) = item.map_err(|e| StorageError::ReadFailed(e.to_string()))?;
            if key.len() < 20 || &key[..20] != addr_hash { break; }
            if let (Some(_), Some((_, dir, amt))) = (parse_key(&key), parse_value(&value)) {
                entries += 1;
                if dir == DIR_OUT {
                    balance += amt as i128;
                } else {
                    balance -= amt as i128;
                }
            }
        }
        Ok((balance.clamp(0, u64::MAX as i128) as u64, entries))
    }
}
