//! Explorer aggregates maintained incrementally (audit NET-12).
//!
//! `getchainstats`, `gethashrate`, `getrichlist` and `getsupplydistribution`
//! used to decode every stored block body or walk the whole UTXO set on each
//! call. Their inputs are now kept as aggregates in `CF_META`, updated on
//! every UTXO-set mutation IN THE SAME `WriteBatch` as the mutation itself
//! (`reorg::connect_plan` for chain moves, `put_utxo` / `delete_utxo` /
//! `ingest_carryover` for direct writes), so they can never disagree with the
//! UTXO set, across reorgs and crashes alike:
//!
//! | key | value |
//! |---|---|
//! | `agg/version` | `u32 LE` = [`AGG_VERSION`]: the aggregates are complete |
//! | `agg/chain` | connected selected-chain blocks `u64 LE` ‖ their transactions `u64 LE` (genesis excluded) |
//! | `agg/conn` | XOR of the hashes of those connected blocks (32 bytes): the fingerprint of the connected set |
//! | `agg/cum/<32-byte block hash>` | the same two totals through that connected block |
//! | `agg/bal/<20-byte address>` | balance `u64 LE` ‖ UTXO count `u64 LE` (present iff count > 0) |
//! | `agg/rich/<u64 BE (u64::MAX − balance)><20-byte address>` | UTXO count `u64 LE` — iterates highest balance first, ties by address |
//! | `agg/tiers` | per [`TIERS`] entry: holders `u64 LE` ‖ sats `u64 LE` ‖ UTXOs `u64 LE` |
//! | `agg/hist/<20-byte address>` | number of `CF_ADDR_TX_HISTORY` rows of the address `u64 LE` (present iff > 0; audit B1-T11, layout version 2) |
//!
//! A holder is a 20-byte `script_pubkey` with at least one UTXO (exactly what
//! the previous full-scan rich list counted). The chain totals count the
//! blocks that currently have an undo record — the connected selected chain
//! — and their transactions; [`Storage::recompute_aggregates`] derives every
//! value from scratch (UTXO set + undo records) and is used both to build the
//! aggregates of a pre-existing database at start-up and, in tests, to prove
//! that the incremental values equal a full recomputation.
//!
//! The version marker alone does not prove the aggregates current: a binary
//! that does not know them moves the chain without touching `agg/*`, and the
//! marker survives. At start-up [`Storage::ensure_aggregates`] therefore also
//! compares the stored block count and connected-set fingerprint
//! (`agg/chain`, `agg/conn`) with one pass over the undo-record keys, and
//! rebuilds on any mismatch (review finding: a downgrade and re-upgrade
//! served a stale rich list, tiers and chain totals indefinitely). RocksDB
//! refuses the read-write open of every release that predates the `shielded`
//! column family (audit COH-2) on a data directory that has it
//! (docs/RUNNING.md, "Upgrading and downgrading"), so once this release has
//! opened a data directory no downgrade can move its chain. The check still
//! covers a data directory an older release moved before this upgrade (a
//! downgrade from a NET-12 build that predates COH-2), one edited outside the
//! node and one restored in part.
//!
//! These are node-local indexes: no consensus rule reads them.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};

use rocksdb::{IteratorMode, WriteBatch};

use super::{decode, Storage, StorageError, CF_ADDR_TX_HISTORY, CF_DAG, CF_META, CF_UNDO, CF_UTXO};
use crate::core::TxOutput;
use crate::consensus::GhostdagData;

/// Layout version of the aggregate keys. Version 2 (audit B1-T11) adds the
/// per-address history counters (`agg/hist/`); a data directory written with
/// version 1 has its aggregates rebuilt once at start-up
/// ([`Storage::ensure_aggregates`]).
pub const AGG_VERSION: u32 = 2;

const K_VERSION: &[u8] = b"agg/version";
const K_CHAIN: &[u8] = b"agg/chain";
const K_CONN: &[u8] = b"agg/conn";
const K_TIERS: &[u8] = b"agg/tiers";
const P_CUM: &[u8] = b"agg/cum/";
const P_BAL: &[u8] = b"agg/bal/";
const P_RICH: &[u8] = b"agg/rich/";
const P_HIST: &[u8] = b"agg/hist/";

/// Balance tiers of the supply distribution: (exclusive upper bound in sat,
/// label).
pub const TIERS: &[(u64, &str)] = &[
    (100_000_000, "< 1 GNB"),
    (1_000_000_000, "1 – 10 GNB"),
    (10_000_000_000, "10 – 100 GNB"),
    (100_000_000_000, "100 – 1k GNB"),
    (1_000_000_000_000, "1k – 10k GNB"),
    (10_000_000_000_000, "10k – 100k GNB"),
    (u64::MAX, "≥ 100k GNB"),
];

/// Tier index of a balance.
pub fn tier_of(balance: u64) -> usize {
    TIERS.iter().position(|(cap, _)| balance < *cap).unwrap_or(TIERS.len() - 1)
}

/// Connected-chain totals.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChainTotals {
    pub blocks: u64,
    pub txs:    u64,
}

/// One holder.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HolderEntry {
    pub balance: u64,
    pub utxos:   u64,
}

/// One supply-distribution tier.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TierTotals {
    pub holders: u64,
    pub sats:    u64,
    pub utxos:   u64,
}

/// XOR of the hashes of a set of blocks (order-free fingerprint; adding or
/// removing a block toggles its hash in).
pub fn xor_into(acc: &mut [u8; 32], hash: &[u8; 32]) {
    for (a, h) in acc.iter_mut().zip(hash) {
        *a ^= h;
    }
}

/// Every stored aggregate, or a from-scratch recomputation of them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AggregateSnapshot {
    pub chain:      ChainTotals,
    /// XOR of the hashes of the connected blocks (`agg/conn`).
    pub conn:       [u8; 32],
    pub cumulative: BTreeMap<[u8; 32], ChainTotals>,
    pub holders:    BTreeMap<[u8; 20], HolderEntry>,
    /// Holders in rich-list order (balance descending, address ascending).
    pub rich_order: Vec<([u8; 20], HolderEntry)>,
    pub tiers:      Vec<TierTotals>,
    /// B1-T11: address-history rows per address (`agg/hist/`).
    pub history:    BTreeMap<[u8; 20], u64>,
}

/// Net holder changes accumulated while staging UTXO mutations.
#[derive(Clone, Debug, Default)]
pub struct HolderDeltas {
    map: HashMap<[u8; 20], (i128, i64)>,
}

impl HolderDeltas {
    /// A UTXO paying `out` was created.
    pub fn add(&mut self, out: &TxOutput) {
        if let Ok(a) = <[u8; 20]>::try_from(out.script_pubkey.as_slice()) {
            let e = self.map.entry(a).or_default();
            e.0 += out.value as i128;
            e.1 += 1;
        }
    }

    /// A UTXO paying `out` was spent / removed.
    pub fn remove(&mut self, out: &TxOutput) {
        if let Ok(a) = <[u8; 20]>::try_from(out.script_pubkey.as_slice()) {
            let e = self.map.entry(a).or_default();
            e.0 -= out.value as i128;
            e.1 -= 1;
        }
    }

    pub fn is_empty(&self) -> bool {
        self.map.values().all(|(b, c)| *b == 0 && *c == 0)
    }
}

/// B1-T11: the address-history rows (`CF_ADDR_TX_HISTORY` keys) a batch
/// puts and deletes, last operation per key winning. When the batch is
/// staged, [`Storage::stage_history_deltas`] compares each key's final state
/// with its presence on disk, so the per-address counters equal the number
/// of rows exactly: a key written twice (two parallel DAG blocks at one
/// height paying one address from the same position) or deleted and written
/// again in one reorg counts once.
#[derive(Clone, Debug, Default)]
pub struct HistoryDeltas {
    keys: HashMap<Vec<u8>, bool>,
}

impl HistoryDeltas {
    /// The batch writes history row `key`.
    pub fn put(&mut self, key: &[u8]) {
        self.keys.insert(key.to_vec(), true);
    }

    /// The batch deletes history row `key`.
    pub fn delete(&mut self, key: &[u8]) {
        self.keys.insert(key.to_vec(), false);
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Error a cancelled long-running computation returns.
pub fn cancelled() -> StorageError {
    StorageError::ReadFailed("cancelled".into())
}

#[inline]
fn check_cancel(cancel: &AtomicBool) -> Result<(), StorageError> {
    if cancel.load(Ordering::Relaxed) { Err(cancelled()) } else { Ok(()) }
}

fn key(prefix: &[u8], id: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(prefix.len() + id.len());
    k.extend_from_slice(prefix);
    k.extend_from_slice(id);
    k
}

fn rich_key(balance: u64, addr: &[u8; 20]) -> Vec<u8> {
    let mut k = Vec::with_capacity(P_RICH.len() + 28);
    k.extend_from_slice(P_RICH);
    k.extend_from_slice(&(u64::MAX - balance).to_be_bytes());
    k.extend_from_slice(addr);
    k
}

fn enc2(a: u64, b: u64) -> [u8; 16] {
    let mut v = [0u8; 16];
    v[..8].copy_from_slice(&a.to_le_bytes());
    v[8..].copy_from_slice(&b.to_le_bytes());
    v
}

fn dec2(v: &[u8]) -> Option<(u64, u64)> {
    if v.len() != 16 {
        return None;
    }
    Some((u64::from_le_bytes(v[..8].try_into().ok()?), u64::from_le_bytes(v[8..].try_into().ok()?)))
}

fn enc_tiers(t: &[TierTotals]) -> Vec<u8> {
    let mut v = Vec::with_capacity(t.len() * 24);
    for x in t {
        v.extend_from_slice(&x.holders.to_le_bytes());
        v.extend_from_slice(&x.sats.to_le_bytes());
        v.extend_from_slice(&x.utxos.to_le_bytes());
    }
    v
}

fn dec_tiers(v: &[u8]) -> Option<Vec<TierTotals>> {
    if v.len() != TIERS.len() * 24 {
        return None;
    }
    Some(v.chunks_exact(24).map(|c| TierTotals {
        holders: u64::from_le_bytes(c[..8].try_into().unwrap_or_default()),
        sats:    u64::from_le_bytes(c[8..16].try_into().unwrap_or_default()),
        utxos:   u64::from_le_bytes(c[16..].try_into().unwrap_or_default()),
    }).collect())
}

fn tiers_from_holders<'a, I: IntoIterator<Item = &'a HolderEntry>>(holders: I) -> Vec<TierTotals> {
    let mut t = vec![TierTotals::default(); TIERS.len()];
    for h in holders {
        let x = &mut t[tier_of(h.balance)];
        x.holders += 1;
        x.sats = x.sats.saturating_add(h.balance);
        x.utxos += h.utxos;
    }
    t
}

impl Storage {
    fn meta_cf(&self) -> Result<&rocksdb::ColumnFamily, StorageError> {
        self.db.cf_handle(CF_META).ok_or(StorageError::CfNotFound(CF_META.into()))
    }

    fn meta_get_raw(&self, k: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.note_reads(1);
        let cf = self.meta_cf()?;
        self.db.get_cf(cf, k).map_err(|e| StorageError::ReadFailed(e.to_string()))
    }

    /// Serialises every read-modify-write of the aggregates.
    pub(crate) fn agg_lock(&self) -> parking_lot::MutexGuard<'_, ()> {
        self.agg_lock.lock()
    }

    /// True iff the aggregates are complete (established on an empty
    /// database, or rebuilt since). Cached: no storage read.
    pub fn aggregates_ready(&self) -> bool {
        self.agg_ready.load(Ordering::Acquire)
    }

    /// At open: a database without the version marker is marked complete
    /// iff it holds no UTXO and no connected block yet (every later mutation
    /// is then tracked); otherwise it needs [`Self::ensure_aggregates`].
    pub(crate) fn init_aggregates_marker(&self) -> Result<(), StorageError> {
        let ready = match self.meta_get_raw(K_VERSION)? {
            Some(v) => v.as_slice() == AGG_VERSION.to_le_bytes(),
            None => {
                let empty_cf = |name: &str| -> Result<bool, StorageError> {
                    let cf = self.db.cf_handle(name).ok_or(StorageError::CfNotFound(name.into()))?;
                    Ok(self.db.iterator_cf(cf, IteratorMode::Start).next().is_none())
                };
                if empty_cf(CF_UTXO)? && empty_cf(CF_UNDO)? {
                    let cf = self.meta_cf()?;
                    let mut batch = WriteBatch::default();
                    batch.put_cf(cf, K_CONN, [0u8; 32]);
                    batch.put_cf(cf, K_VERSION, AGG_VERSION.to_le_bytes());
                    self.write_batch(batch)?;
                    true
                } else {
                    false
                }
            }
        };
        self.agg_ready.store(ready, Ordering::Release);
        Ok(())
    }

    /// Rebuild the aggregates from scratch if they are not complete (a
    /// database written before NET-12) or do not describe the connected
    /// chain on disk (another binary moved the chain since they were
    /// written: [`Self::aggregates_match_connected_chain`]). At start-up
    /// only: one pass over the undo-record keys, plus one full scan when a
    /// rebuild is needed. Returns whether a rebuild ran.
    pub fn ensure_aggregates(&self) -> Result<bool, StorageError> {
        if self.aggregates_ready() {
            if self.aggregates_match_connected_chain()? {
                return Ok(false);
            }
            log::warn!("NET-12: the explorer aggregates do not describe the connected chain on disk \
                        (moved by another binary, or restored in part?); rebuilding them");
            self.agg_ready.store(false, Ordering::Release);
        }
        self.rebuild_aggregates(&AtomicBool::new(false))?;
        Ok(true)
    }

    /// `(blocks, XOR of their hashes)` of the connected chain on disk: the
    /// blocks with an undo record (one pass over the CF_UNDO keys).
    pub fn connected_fingerprint_from_undo(&self) -> Result<(u64, [u8; 32]), StorageError> {
        let cf_undo = self.db.cf_handle(CF_UNDO).ok_or(StorageError::CfNotFound(CF_UNDO.into()))?;
        let (mut count, mut xor) = (0u64, [0u8; 32]);
        let mut it = self.db.raw_iterator_cf(cf_undo);
        it.seek_to_first();
        while let Some(k) = it.key() {
            if let Ok(h) = <[u8; 32]>::try_from(k) {
                count += 1;
                xor_into(&mut xor, &h);
            }
            it.next();
        }
        it.status().map_err(|e| StorageError::ReadFailed(e.to_string()))?;
        Ok((count, xor))
    }

    /// True iff the stored block count (`agg/chain`) and connected-set
    /// fingerprint (`agg/conn`, required) match the undo records on disk.
    pub fn aggregates_match_connected_chain(&self) -> Result<bool, StorageError> {
        let (count, xor) = self.connected_fingerprint_from_undo()?;
        Ok(self.chain_totals()?.blocks == count && self.conn_fingerprint()? == Some(xor))
    }

    /// The stored connected-set fingerprint (`agg/conn`), if any.
    pub fn conn_fingerprint(&self) -> Result<Option<[u8; 32]>, StorageError> {
        Ok(self.meta_get_raw(K_CONN)?.and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok()))
    }

    /// Connected-chain totals.
    pub fn chain_totals(&self) -> Result<ChainTotals, StorageError> {
        Ok(self.meta_get_raw(K_CHAIN)?
            .and_then(|v| dec2(&v))
            .map(|(blocks, txs)| ChainTotals { blocks, txs })
            .unwrap_or_default())
    }

    /// Totals through the connected block `hash` (None: not connected, or
    /// the genesis).
    pub fn chain_cumulative(&self, hash: &[u8; 32]) -> Result<Option<ChainTotals>, StorageError> {
        Ok(self.meta_get_raw(&key(P_CUM, hash))?
            .and_then(|v| dec2(&v))
            .map(|(blocks, txs)| ChainTotals { blocks, txs }))
    }

    /// One holder's aggregate.
    pub fn holder(&self, addr: &[u8; 20]) -> Result<Option<HolderEntry>, StorageError> {
        Ok(self.meta_get_raw(&key(P_BAL, addr))?
            .and_then(|v| dec2(&v))
            .map(|(balance, utxos)| HolderEntry { balance, utxos }))
    }

    /// B1-T11: number of address-history rows of `addr` (one read), or None
    /// while the aggregates are incomplete (being rebuilt).
    pub fn address_history_count(&self, addr: &[u8; 20]) -> Result<Option<u64>, StorageError> {
        if !self.aggregates_ready() {
            return Ok(None);
        }
        Ok(Some(self.meta_get_raw(&key(P_HIST, addr))?
            .and_then(|v| <[u8; 8]>::try_from(v.as_slice()).ok())
            .map(u64::from_le_bytes)
            .unwrap_or(0)))
    }

    /// B1-T11: stage the effect of `deltas` on the per-address history
    /// counters into `batch`: one presence read per touched row, one counter
    /// read per touched address. The caller holds [`Self::agg_lock`] until
    /// the batch is written. No-op while the aggregates are incomplete.
    pub(crate) fn stage_history_deltas(&self, batch: &mut WriteBatch, deltas: &HistoryDeltas) -> Result<(), StorageError> {
        if !self.aggregates_ready() || deltas.is_empty() {
            return Ok(());
        }
        let cf_hist = self.db.cf_handle(CF_ADDR_TX_HISTORY)
            .ok_or(StorageError::CfNotFound(CF_ADDR_TX_HISTORY.into()))?;
        let mut per_addr: BTreeMap<[u8; 20], i64> = BTreeMap::new();
        for (k, present) in &deltas.keys {
            let Ok(addr) = <[u8; 20]>::try_from(&k[..k.len().min(20)]) else { continue };
            self.note_reads(1);
            let existed = self.db.get_pinned_cf(cf_hist, k)
                .map_err(|e| StorageError::ReadFailed(e.to_string()))?
                .is_some();
            let d = i64::from(*present) - i64::from(existed);
            if d != 0 {
                *per_addr.entry(addr).or_default() += d;
            }
        }
        let cf = self.meta_cf()?;
        let mut drift = false;
        for (addr, d) in per_addr {
            if d == 0 {
                continue;
            }
            let old = self.address_history_count(&addr)?.unwrap_or(0) as i128;
            let new = old + d as i128;
            if new < 0 {
                drift = true;
            }
            let new = new.clamp(0, u64::MAX as i128) as u64;
            if new > 0 {
                batch.put_cf(cf, key(P_HIST, &addr), new.to_le_bytes());
            } else {
                batch.delete_cf(cf, key(P_HIST, &addr));
            }
        }
        if drift {
            log::error!("B1-T11 history counters drifted (underflow); marked for rebuild");
            batch.delete_cf(cf, K_VERSION);
            self.agg_ready.store(false, Ordering::Release);
        }
        Ok(())
    }

    /// The supply-distribution tiers (one read).
    pub fn tier_totals(&self) -> Result<Vec<TierTotals>, StorageError> {
        Ok(self.meta_get_raw(K_TIERS)?
            .and_then(|v| dec_tiers(&v))
            .unwrap_or_else(|| vec![TierTotals::default(); TIERS.len()]))
    }

    /// `limit` holders from rank `offset` (0-based) in rich-list order.
    /// Reads `offset + limit` index entries at most.
    pub fn rich_list_page(
        &self,
        offset: usize,
        limit: usize,
        cancel: &AtomicBool,
    ) -> Result<Vec<([u8; 20], HolderEntry)>, StorageError> {
        let cf = self.meta_cf()?;
        let mut out = Vec::with_capacity(limit.min(1024));
        let mut skipped = 0usize;
        for item in self.db.iterator_cf(cf, IteratorMode::From(P_RICH, rocksdb::Direction::Forward)) {
            check_cancel(cancel)?;
            self.note_reads(1);
            let (k, v) = item.map_err(|e| StorageError::ReadFailed(e.to_string()))?;
            if !k.starts_with(P_RICH) || out.len() >= limit {
                break;
            }
            if skipped < offset {
                skipped += 1;
                continue;
            }
            let body = &k[P_RICH.len()..];
            if body.len() != 28 || v.len() != 8 {
                continue;
            }
            let balance = u64::MAX - u64::from_be_bytes(body[..8].try_into().unwrap_or_default());
            let mut addr = [0u8; 20];
            addr.copy_from_slice(&body[8..]);
            let utxos = u64::from_le_bytes(v[..8].try_into().unwrap_or_default());
            out.push((addr, HolderEntry { balance, utxos }));
        }
        Ok(out)
    }

    /// Stage the net effect of `deltas` on the holder aggregates into
    /// `batch`. The caller holds [`Self::agg_lock`] until the batch is
    /// written. No-op while the aggregates are incomplete (they are rebuilt
    /// from scratch instead).
    pub(crate) fn stage_holder_deltas(&self, batch: &mut WriteBatch, deltas: &HolderDeltas) -> Result<(), StorageError> {
        if !self.aggregates_ready() || deltas.is_empty() {
            return Ok(());
        }
        let cf = self.meta_cf()?;
        let mut tiers = self.tier_totals()?;
        let mut drift = false;
        let mut addrs: Vec<&[u8; 20]> = deltas.map.keys().collect();
        addrs.sort();
        for addr in addrs {
            let (db, dc) = deltas.map[addr];
            if db == 0 && dc == 0 {
                continue;
            }
            let old = self.holder(addr)?.unwrap_or_default();
            let nb = old.balance as i128 + db;
            let nc = old.utxos as i128 + dc as i128;
            if nb < 0 || nc < 0 || nb > u64::MAX as i128 || (nc == 0 && nb != 0) {
                drift = true;
            }
            let new = HolderEntry {
                balance: nb.clamp(0, u64::MAX as i128) as u64,
                utxos: nc.clamp(0, u64::MAX as i128) as u64,
            };
            if old.utxos > 0 {
                batch.delete_cf(cf, rich_key(old.balance, addr));
                let t = &mut tiers[tier_of(old.balance)];
                t.holders = t.holders.saturating_sub(1);
                t.sats = t.sats.saturating_sub(old.balance);
                t.utxos = t.utxos.saturating_sub(old.utxos);
            }
            if new.utxos > 0 {
                batch.put_cf(cf, key(P_BAL, addr), enc2(new.balance, new.utxos));
                batch.put_cf(cf, rich_key(new.balance, addr), new.utxos.to_le_bytes());
                let t = &mut tiers[tier_of(new.balance)];
                t.holders += 1;
                t.sats = t.sats.saturating_add(new.balance);
                t.utxos += new.utxos;
            } else {
                batch.delete_cf(cf, key(P_BAL, addr));
            }
        }
        batch.put_cf(cf, K_TIERS, enc_tiers(&tiers));
        if drift {
            // Never fail a chain-state commit over a diagnostics index: mark
            // the aggregates incomplete; the next start-up rebuilds them.
            log::error!("NET-12 aggregates drifted (underflow); marked for rebuild");
            batch.delete_cf(cf, K_VERSION);
            self.agg_ready.store(false, Ordering::Release);
        }
        Ok(())
    }

    /// Chain-state rebuild (audit DAG-11): mark the aggregates incomplete
    /// (version marker deleted in `batch`, in-memory flag cleared now) BEFORE
    /// the chain state is cleared, so the reconnect that follows stages no
    /// incremental change on top of values describing the old state. The
    /// rebuild recomputes them from scratch at its end
    /// ([`Self::rebuild_aggregates`]); a crash in between leaves the marker
    /// absent, and the next start-up rebuilds them ([`Self::ensure_aggregates`]).
    pub fn stage_aggregates_incomplete(&self, batch: &mut WriteBatch) -> Result<(), StorageError> {
        let _g = self.agg_lock();
        batch.delete_cf(self.meta_cf()?, K_VERSION);
        self.agg_ready.store(false, Ordering::Release);
        Ok(())
    }

    /// Stage the connected-chain totals and the connected-set fingerprint.
    pub(crate) fn stage_chain_totals(&self, batch: &mut WriteBatch, t: ChainTotals, conn: &[u8; 32]) -> Result<(), StorageError> {
        if !self.aggregates_ready() {
            return Ok(());
        }
        let cf = self.meta_cf()?;
        batch.put_cf(cf, K_CHAIN, enc2(t.blocks, t.txs));
        batch.put_cf(cf, K_CONN, conn);
        Ok(())
    }

    /// Stage (Some) or remove (None) the cumulative record of `hash`.
    pub(crate) fn stage_chain_cumulative(
        &self,
        batch: &mut WriteBatch,
        hash: &[u8; 32],
        t: Option<ChainTotals>,
    ) -> Result<(), StorageError> {
        if !self.aggregates_ready() {
            return Ok(());
        }
        let cf = self.meta_cf()?;
        match t {
            Some(t) => batch.put_cf(cf, key(P_CUM, hash), enc2(t.blocks, t.txs)),
            None => batch.delete_cf(cf, key(P_CUM, hash)),
        }
        Ok(())
    }

    /// Direct (non-batched) connect of one block outside `connect_plan`
    /// (`reorg::apply_block_utxo_mutations`): bump the chain totals.
    #[allow(dead_code)] // the node binary only connects through `connect_plan`
    pub(crate) fn note_block_connected(&self, hash: &[u8; 32], txs: u64) -> Result<(), StorageError> {
        let _g = self.agg_lock();
        let mut t = self.chain_totals()?;
        t.blocks += 1;
        t.txs = t.txs.saturating_add(txs);
        let mut conn = self.conn_fingerprint()?.unwrap_or_default();
        xor_into(&mut conn, hash);
        let mut batch = WriteBatch::default();
        self.stage_chain_totals(&mut batch, t, &conn)?;
        self.stage_chain_cumulative(&mut batch, hash, Some(t))?;
        self.write_batch(batch)
    }

    /// Direct (non-batched) rollback of one block (`Storage::rollback_block`).
    #[allow(dead_code)] // the node binary only disconnects through `connect_plan`
    pub(crate) fn note_block_disconnected(&self, hash: &[u8; 32], txs: u64) -> Result<(), StorageError> {
        let _g = self.agg_lock();
        let mut t = self.chain_totals()?;
        t.blocks = t.blocks.saturating_sub(1);
        t.txs = t.txs.saturating_sub(txs);
        let mut conn = self.conn_fingerprint()?.unwrap_or_default();
        xor_into(&mut conn, hash);
        let mut batch = WriteBatch::default();
        self.stage_chain_totals(&mut batch, t, &conn)?;
        self.stage_chain_cumulative(&mut batch, hash, None)?;
        self.write_batch(batch)
    }

    /// Every stored aggregate (prefix scans; tests and diagnostics only).
    #[allow(dead_code)] // library API (tests, diagnostics)
    pub fn aggregate_snapshot(&self) -> Result<AggregateSnapshot, StorageError> {
        let cf = self.meta_cf()?;
        let mut snap = AggregateSnapshot {
            chain: self.chain_totals()?,
            conn: self.conn_fingerprint()?.unwrap_or_default(),
            tiers: self.tier_totals()?,
            ..Default::default()
        };
        for item in self.db.iterator_cf(cf, IteratorMode::From(P_CUM, rocksdb::Direction::Forward)) {
            let (k, v) = item.map_err(|e| StorageError::ReadFailed(e.to_string()))?;
            if !k.starts_with(P_CUM) { break; }
            if let (Ok(h), Some((blocks, txs))) = (<[u8; 32]>::try_from(&k[P_CUM.len()..]), dec2(&v)) {
                snap.cumulative.insert(h, ChainTotals { blocks, txs });
            }
        }
        for item in self.db.iterator_cf(cf, IteratorMode::From(P_BAL, rocksdb::Direction::Forward)) {
            let (k, v) = item.map_err(|e| StorageError::ReadFailed(e.to_string()))?;
            if !k.starts_with(P_BAL) { break; }
            if let (Ok(a), Some((balance, utxos))) = (<[u8; 20]>::try_from(&k[P_BAL.len()..]), dec2(&v)) {
                snap.holders.insert(a, HolderEntry { balance, utxos });
            }
        }
        for item in self.db.iterator_cf(cf, IteratorMode::From(P_HIST, rocksdb::Direction::Forward)) {
            let (k, v) = item.map_err(|e| StorageError::ReadFailed(e.to_string()))?;
            if !k.starts_with(P_HIST) { break; }
            if let (Ok(a), Ok(n)) = (<[u8; 20]>::try_from(&k[P_HIST.len()..]), <[u8; 8]>::try_from(v.as_ref())) {
                snap.history.insert(a, u64::from_le_bytes(n));
            }
        }
        snap.rich_order = self.rich_list_page(0, usize::MAX, &AtomicBool::new(false))?;
        Ok(snap)
    }

    /// Recompute every aggregate from scratch: the holders from the UTXO set,
    /// the chain totals from the undo records (one per connected block),
    /// ordered by DAG height (header height when the block has no DAG
    /// record). O(UTXO set + connected chain); cancellable.
    pub fn recompute_aggregates(&self, cancel: &AtomicBool) -> Result<AggregateSnapshot, StorageError> {
        let cf_utxo = self.db.cf_handle(CF_UTXO).ok_or(StorageError::CfNotFound(CF_UTXO.into()))?;
        let mut holders: BTreeMap<[u8; 20], HolderEntry> = BTreeMap::new();
        for item in self.db.iterator_cf(cf_utxo, IteratorMode::Start) {
            check_cancel(cancel)?;
            let (_k, v) = item.map_err(|e| StorageError::ReadFailed(e.to_string()))?;
            let out: TxOutput = decode(&v)?;
            if let Ok(a) = <[u8; 20]>::try_from(out.script_pubkey.as_slice()) {
                let h = holders.entry(a).or_default();
                h.balance = h.balance.saturating_add(out.value);
                h.utxos += 1;
            }
        }
        let mut rich_order: Vec<([u8; 20], HolderEntry)> = holders.iter().map(|(a, h)| (*a, *h)).collect();
        rich_order.sort_by(|a, b| b.1.balance.cmp(&a.1.balance).then(a.0.cmp(&b.0)));
        let tiers = tiers_from_holders(holders.values());

        let cf_undo = self.db.cf_handle(CF_UNDO).ok_or(StorageError::CfNotFound(CF_UNDO.into()))?;
        let cf_dag = self.db.cf_handle(CF_DAG).ok_or(StorageError::CfNotFound(CF_DAG.into()))?;
        let mut connected: Vec<(u64, [u8; 32], u64)> = Vec::new();
        for item in self.db.iterator_cf(cf_undo, IteratorMode::Start) {
            check_cancel(cancel)?;
            let (k, v) = item.map_err(|e| StorageError::ReadFailed(e.to_string()))?;
            let Ok(hash) = <[u8; 32]>::try_from(k.as_ref()) else { continue };
            // The stored encoding (legacy record, or with the VAL-2
            // overwritten-rows extension): `UndoData::from_bytes`, exactly as
            // `Storage::get_undo_data` reads it.
            let undo = crate::core::UndoData::from_bytes(&v).map_err(StorageError::DeserializeFailed)?;
            let order_height = self.db.get_cf(cf_dag, hash)
                .map_err(|e| StorageError::ReadFailed(e.to_string()))?
                .and_then(|d| decode::<GhostdagData>(&d).ok())
                .map(|d| d.height)
                .unwrap_or(undo.block_height);
            connected.push((order_height, hash, undo.tx_index_keys.len() as u64));
        }
        connected.sort();
        let mut running = ChainTotals::default();
        let mut cumulative = BTreeMap::new();
        let mut conn = [0u8; 32];
        for (_, hash, txs) in connected {
            running.blocks += 1;
            running.txs = running.txs.saturating_add(txs);
            cumulative.insert(hash, running);
            xor_into(&mut conn, &hash);
        }
        // B1-T11: history rows per address, one pass over the index keys.
        let cf_hist = self.db.cf_handle(CF_ADDR_TX_HISTORY)
            .ok_or(StorageError::CfNotFound(CF_ADDR_TX_HISTORY.into()))?;
        let mut history: BTreeMap<[u8; 20], u64> = BTreeMap::new();
        let mut it = self.db.raw_iterator_cf(cf_hist);
        it.seek_to_first();
        while let Some(k) = it.key() {
            check_cancel(cancel)?;
            if let Ok(a) = <[u8; 20]>::try_from(&k[..k.len().min(20)]) {
                *history.entry(a).or_default() += 1;
            }
            it.next();
        }
        it.status().map_err(|e| StorageError::ReadFailed(e.to_string()))?;
        Ok(AggregateSnapshot { chain: running, conn, cumulative, holders, rich_order, tiers, history })
    }

    /// Replace the stored aggregates by a full recomputation, atomically,
    /// and mark them complete. Holds the aggregate lock for the duration.
    pub fn rebuild_aggregates(&self, cancel: &AtomicBool) -> Result<AggregateSnapshot, StorageError> {
        let _g = self.agg_lock();
        let snap = self.recompute_aggregates(cancel)?;
        let cf = self.meta_cf()?;
        let mut batch = WriteBatch::default();
        for prefix in [P_CUM, P_BAL, P_RICH, P_HIST] {
            for item in self.db.iterator_cf(cf, IteratorMode::From(prefix, rocksdb::Direction::Forward)) {
                let (k, _) = item.map_err(|e| StorageError::ReadFailed(e.to_string()))?;
                if !k.starts_with(prefix) { break; }
                batch.delete_cf(cf, k);
            }
        }
        batch.put_cf(cf, K_CHAIN, enc2(snap.chain.blocks, snap.chain.txs));
        batch.put_cf(cf, K_CONN, snap.conn);
        for (h, t) in &snap.cumulative {
            batch.put_cf(cf, key(P_CUM, h), enc2(t.blocks, t.txs));
        }
        for (a, h) in &snap.holders {
            batch.put_cf(cf, key(P_BAL, a), enc2(h.balance, h.utxos));
            batch.put_cf(cf, rich_key(h.balance, a), h.utxos.to_le_bytes());
        }
        for (a, n) in &snap.history {
            batch.put_cf(cf, key(P_HIST, a), n.to_le_bytes());
        }
        batch.put_cf(cf, K_TIERS, enc_tiers(&snap.tiers));
        batch.put_cf(cf, K_VERSION, AGG_VERSION.to_le_bytes());
        self.write_batch(batch)?;
        self.agg_ready.store(true, Ordering::Release);
        Ok(snap)
    }
}
