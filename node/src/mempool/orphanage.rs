//! Bounded orphan-transaction pool (audit MEM-6), after Bitcoin Core's
//! `TxOrphanage`.
//!
//! A gossiped transaction whose inputs reference outputs that are neither in
//! the UTXO set nor in the mempool ("missing inputs") used to be dropped: a
//! child that overtook its parent on the wire was lost for good. It is now
//! kept here — bounded — and re-tried when a parent arrives:
//!
//! * bounded by entry count and bytes globally ([`MAX_ORPHAN_TXS`],
//!   [`MAX_ORPHAN_BYTES`]) and per delivering peer
//!   ([`MAX_ORPHANS_PER_PEER`], [`MAX_ORPHAN_BYTES_PER_PEER`]); a peer over
//!   its quota pays with its OWN oldest orphans, and the global bound evicts
//!   the oldest orphan of the peer holding the most, so one flooding peer
//!   cannot flush everyone else's orphans;
//! * expired after [`ORPHAN_EXPIRY_SECS`] (Core: 20 minutes);
//! * indexed by missing parent txid, so the arrival of a parent finds its
//!   waiting children in O(children) ([`TxOrphanage::waiting_on`]);
//! * indexed by spent outpoint, so a connected block erases the orphans it
//!   conflicts with ([`TxOrphanage::erase_conflicts`]).
//!
//! Only transactions that passed every context-free check (structure, size,
//! standardness — see `admission::check_transaction`) reach the orphanage;
//! signatures are verified when the orphan is re-tried with its parents.
//! Generic over the peer key so it carries no networking dependency.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::hash::Hash;

use crate::core::Transaction;

/// Global entry cap (Bitcoin Core `DEFAULT_MAX_ORPHAN_TRANSACTIONS`).
pub const MAX_ORPHAN_TXS: usize = 100;
/// Global byte cap (wire bytes).
pub const MAX_ORPHAN_BYTES: usize = 10 * 1024 * 1024;
/// Per delivering peer entry quota.
pub const MAX_ORPHANS_PER_PEER: usize = 25;
/// Per delivering peer byte quota.
pub const MAX_ORPHAN_BYTES_PER_PEER: usize = 2 * 1024 * 1024;
/// Orphans older than this are dropped (Bitcoin Core `ORPHAN_TX_EXPIRE_TIME`).
pub const ORPHAN_EXPIRY_SECS: u64 = 20 * 60;

/// Bounds of a [`TxOrphanage`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrphanLimits {
    pub max_entries:          usize,
    pub max_bytes:            usize,
    pub max_entries_per_peer: usize,
    pub max_bytes_per_peer:   usize,
    pub expiry_secs:          u64,
}

impl Default for OrphanLimits {
    fn default() -> Self {
        Self {
            max_entries:          MAX_ORPHAN_TXS,
            max_bytes:            MAX_ORPHAN_BYTES,
            max_entries_per_peer: MAX_ORPHANS_PER_PEER,
            max_bytes_per_peer:   MAX_ORPHAN_BYTES_PER_PEER,
            expiry_secs:          ORPHAN_EXPIRY_SECS,
        }
    }
}

/// One buffered orphan.
#[derive(Clone, Debug)]
pub struct OrphanTx<P> {
    pub tx:              Transaction,
    pub txid:            [u8; 32],
    /// Wire bytes of the transaction.
    pub bytes:           usize,
    /// The peer that delivered it (`None` = unknown / local).
    pub peer:            Option<P>,
    /// Unix seconds after which it is dropped.
    pub expires_at:      u64,
    /// Parent txids that were missing when it was buffered.
    pub missing_parents: BTreeSet<[u8; 32]>,
    seq:                 u64,
}

/// Result of [`TxOrphanage::add`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OrphanAdd {
    /// Buffered; `evicted` lists orphans dropped to make room.
    Inserted { evicted: Vec<[u8; 32]> },
    /// Already buffered (the first copy is kept).
    Duplicate,
    /// Larger than a quota could ever hold.
    TooLarge,
}

#[derive(Debug)]
struct PeerUsage {
    bytes: usize,
    seqs:  BTreeSet<u64>,
}

/// The orphan pool. See the module documentation.
#[derive(Debug)]
pub struct TxOrphanage<P: Hash + Eq + Copy> {
    limits:      OrphanLimits,
    entries:     HashMap<[u8; 32], OrphanTx<P>>,
    order:       BTreeMap<u64, [u8; 32]>,
    by_parent:   HashMap<[u8; 32], BTreeSet<[u8; 32]>>,
    by_outpoint: HashMap<([u8; 32], u32), BTreeSet<[u8; 32]>>,
    per_peer:    HashMap<Option<P>, PeerUsage>,
    total_bytes: usize,
    next_seq:    u64,
}

impl<P: Hash + Eq + Copy> Default for TxOrphanage<P> {
    fn default() -> Self {
        Self::new(OrphanLimits::default())
    }
}

impl<P: Hash + Eq + Copy> TxOrphanage<P> {
    pub fn new(limits: OrphanLimits) -> Self {
        Self {
            limits,
            entries: HashMap::new(),
            order: BTreeMap::new(),
            by_parent: HashMap::new(),
            by_outpoint: HashMap::new(),
            per_peer: HashMap::new(),
            total_bytes: 0,
            next_seq: 0,
        }
    }

    pub fn limits(&self) -> OrphanLimits {
        self.limits
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub fn contains(&self, txid: &[u8; 32]) -> bool {
        self.entries.contains_key(txid)
    }

    pub fn get(&self, txid: &[u8; 32]) -> Option<&OrphanTx<P>> {
        self.entries.get(txid)
    }

    /// `(entries, bytes)` buffered on behalf of `peer`.
    pub fn peer_usage(&self, peer: Option<P>) -> (usize, usize) {
        self.per_peer.get(&peer).map(|u| (u.seqs.len(), u.bytes)).unwrap_or((0, 0))
    }

    /// Every buffered txid, oldest first.
    pub fn txids_by_age(&self) -> Vec<[u8; 32]> {
        self.order.values().copied().collect()
    }

    /// Buffer `tx` (whose wire size is `bytes`, delivered by `peer`) waiting
    /// on `missing_parents`, expiring at `now_unix + expiry`.
    pub fn add(
        &mut self,
        tx: Transaction,
        bytes: usize,
        peer: Option<P>,
        missing_parents: BTreeSet<[u8; 32]>,
        now_unix: u64,
    ) -> OrphanAdd {
        let expires_at = now_unix.saturating_add(self.limits.expiry_secs);
        self.add_with_expiry(tx, bytes, peer, missing_parents, expires_at)
    }

    /// [`Self::add`] with an explicit expiry (re-buffering an orphan that is
    /// still missing a parent keeps its original deadline).
    pub fn add_with_expiry(
        &mut self,
        tx: Transaction,
        bytes: usize,
        peer: Option<P>,
        missing_parents: BTreeSet<[u8; 32]>,
        expires_at: u64,
    ) -> OrphanAdd {
        let txid = tx.txid();
        if self.entries.contains_key(&txid) {
            return OrphanAdd::Duplicate;
        }
        if bytes > self.limits.max_bytes_per_peer || bytes > self.limits.max_bytes
            || self.limits.max_entries == 0 || self.limits.max_entries_per_peer == 0
        {
            return OrphanAdd::TooLarge;
        }
        let mut evicted = Vec::new();
        // Per-peer quota: the delivering peer pays with its own oldest.
        loop {
            let (count, used) = self.peer_usage(peer);
            if count < self.limits.max_entries_per_peer
                && used.saturating_add(bytes) <= self.limits.max_bytes_per_peer
            {
                break;
            }
            match self.oldest_of(peer) {
                Some(h) => {
                    self.remove(&h);
                    evicted.push(h);
                }
                None => break,
            }
        }
        // Global bounds: the oldest orphan of the peer holding the most.
        while self.entries.len() >= self.limits.max_entries
            || self.total_bytes.saturating_add(bytes) > self.limits.max_bytes
        {
            // Most entries, then most bytes, then the oldest orphan (seqs are
            // unique, so the choice is deterministic).
            let heaviest = self.per_peer.iter()
                .max_by_key(|(_, u)| {
                    (u.seqs.len(), u.bytes, std::cmp::Reverse(u.seqs.iter().next().copied().unwrap_or(u64::MAX)))
                })
                .map(|(p, _)| *p);
            match heaviest.and_then(|p| self.oldest_of(p)) {
                Some(h) => {
                    self.remove(&h);
                    evicted.push(h);
                }
                None => break,
            }
        }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        for p in &missing_parents {
            self.by_parent.entry(*p).or_default().insert(txid);
        }
        for inp in &tx.inputs {
            self.by_outpoint.entry((inp.prev_txid, inp.prev_index)).or_default().insert(txid);
        }
        let usage = self.per_peer.entry(peer).or_insert_with(|| PeerUsage { bytes: 0, seqs: BTreeSet::new() });
        usage.bytes = usage.bytes.saturating_add(bytes);
        usage.seqs.insert(seq);
        self.total_bytes = self.total_bytes.saturating_add(bytes);
        self.order.insert(seq, txid);
        self.entries.insert(txid, OrphanTx { tx, txid, bytes, peer, expires_at, missing_parents, seq });
        OrphanAdd::Inserted { evicted }
    }

    fn oldest_of(&self, peer: Option<P>) -> Option<[u8; 32]> {
        self.per_peer.get(&peer)
            .and_then(|u| u.seqs.iter().next().copied())
            .and_then(|s| self.order.get(&s).copied())
    }

    /// Remove one orphan and every index entry pointing at it.
    pub fn remove(&mut self, txid: &[u8; 32]) -> Option<OrphanTx<P>> {
        let e = self.entries.remove(txid)?;
        self.order.remove(&e.seq);
        if let Some(u) = self.per_peer.get_mut(&e.peer) {
            u.seqs.remove(&e.seq);
            u.bytes = u.bytes.saturating_sub(e.bytes);
            if u.seqs.is_empty() {
                self.per_peer.remove(&e.peer);
            }
        }
        self.total_bytes = self.total_bytes.saturating_sub(e.bytes);
        for p in &e.missing_parents {
            if let Some(s) = self.by_parent.get_mut(p) {
                s.remove(txid);
                if s.is_empty() {
                    self.by_parent.remove(p);
                }
            }
        }
        for inp in &e.tx.inputs {
            let op = (inp.prev_txid, inp.prev_index);
            if let Some(s) = self.by_outpoint.get_mut(&op) {
                s.remove(txid);
                if s.is_empty() {
                    self.by_outpoint.remove(&op);
                }
            }
        }
        Some(e)
    }

    /// Orphans that were waiting on `parent`, oldest first (not removed).
    pub fn waiting_on(&self, parent: &[u8; 32]) -> Vec<[u8; 32]> {
        let mut v: Vec<[u8; 32]> = self.by_parent.get(parent).map(|s| s.iter().copied().collect()).unwrap_or_default();
        v.sort_by_key(|t| self.entries.get(t).map(|e| e.seq).unwrap_or(u64::MAX));
        v
    }

    /// Drop every orphan whose deadline passed. Returns the dropped txids.
    pub fn expire(&mut self, now_unix: u64) -> Vec<[u8; 32]> {
        let doomed: Vec<[u8; 32]> = self.entries.values()
            .filter(|e| e.expires_at <= now_unix)
            .map(|e| e.txid)
            .collect();
        for t in &doomed {
            self.remove(t);
        }
        doomed
    }

    /// Drop every orphan spending one of `outpoints` (just consumed by a
    /// connected block — the orphan can never be mined) or listed in
    /// `confirmed` (it was mined itself). Returns the dropped txids.
    pub fn erase_for_block(&mut self, outpoints: &[([u8; 32], u32)], confirmed: &[[u8; 32]]) -> Vec<[u8; 32]> {
        let mut doomed: BTreeSet<[u8; 32]> = confirmed.iter().filter(|t| self.entries.contains_key(*t)).copied().collect();
        for op in outpoints {
            if let Some(s) = self.by_outpoint.get(op) {
                doomed.extend(s.iter().copied());
            }
        }
        for t in &doomed {
            self.remove(t);
        }
        doomed.into_iter().collect()
    }

    /// Drop every orphan delivered by `peer`. Returns how many.
    pub fn erase_peer(&mut self, peer: Option<P>) -> usize {
        let doomed: Vec<[u8; 32]> = self.per_peer.get(&peer)
            .map(|u| u.seqs.iter().filter_map(|s| self.order.get(s).copied()).collect())
            .unwrap_or_default();
        for t in &doomed {
            self.remove(t);
        }
        doomed.len()
    }

    /// Internal consistency (tests / fuzzing).
    pub fn debug_check_invariants(&self) -> Result<(), String> {
        if self.entries.len() > self.limits.max_entries {
            return Err(format!("{} entries > cap {}", self.entries.len(), self.limits.max_entries));
        }
        if self.total_bytes > self.limits.max_bytes {
            return Err(format!("{} bytes > cap {}", self.total_bytes, self.limits.max_bytes));
        }
        let sum: usize = self.entries.values().map(|e| e.bytes).sum();
        if sum != self.total_bytes {
            return Err("byte counter drifted".into());
        }
        if self.order.len() != self.entries.len() {
            return Err("order index drifted".into());
        }
        let mut per_peer_count = 0usize;
        for (p, u) in &self.per_peer {
            if u.seqs.len() > self.limits.max_entries_per_peer || u.bytes > self.limits.max_bytes_per_peer {
                return Err("per-peer quota exceeded".into());
            }
            let bytes: usize = u.seqs.iter()
                .filter_map(|s| self.order.get(s))
                .filter_map(|t| self.entries.get(t))
                .filter(|e| e.peer == *p)
                .map(|e| e.bytes)
                .sum();
            if bytes != u.bytes {
                return Err("per-peer bytes drifted".into());
            }
            per_peer_count += u.seqs.len();
        }
        if per_peer_count != self.entries.len() {
            return Err("per-peer index drifted".into());
        }
        for (parent, kids) in &self.by_parent {
            for k in kids {
                if !self.entries.get(k).is_some_and(|e| e.missing_parents.contains(parent)) {
                    return Err("by_parent drifted".into());
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{TxInput, TxOutput};

    fn orphan(parent: u8, tag: u8, pad: usize) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxInput { prev_txid: [parent; 32], prev_index: 0, script_sig: vec![tag; pad.max(1)], sequence: u32::MAX }],
            outputs: vec![TxOutput { value: 10_000, script_pubkey: vec![tag; 20] }],
            locktime: 0,
        }
    }

    fn parents(p: u8) -> BTreeSet<[u8; 32]> {
        std::iter::once([p; 32]).collect()
    }

    #[test]
    fn per_peer_quota_charges_the_flooder_only() {
        let limits = OrphanLimits { max_entries: 10, max_bytes: 1 << 20, max_entries_per_peer: 3, max_bytes_per_peer: 1 << 20, expiry_secs: 60 };
        let mut o: TxOrphanage<u8> = TxOrphanage::new(limits);
        let honest = orphan(1, 1, 10);
        assert!(matches!(o.add(honest.clone(), 100, Some(1), parents(1), 0), OrphanAdd::Inserted { .. }));
        for i in 0..10u8 {
            o.add(orphan(2, 10 + i, 10), 100, Some(2), parents(2), 0);
            o.debug_check_invariants().unwrap();
        }
        assert_eq!(o.peer_usage(Some(2)).0, 3, "the flooder keeps only its quota");
        assert!(o.contains(&honest.txid()), "the honest peer's orphan survives");
    }

    #[test]
    fn global_cap_evicts_from_the_heaviest_peer() {
        let limits = OrphanLimits { max_entries: 4, max_bytes: 1 << 20, max_entries_per_peer: 3, max_bytes_per_peer: 1 << 20, expiry_secs: 60 };
        let mut o: TxOrphanage<u8> = TxOrphanage::new(limits);
        let a = orphan(1, 1, 10);
        o.add(a.clone(), 10, Some(1), parents(1), 0);
        for i in 0..3u8 {
            o.add(orphan(2, 20 + i, 10), 10, Some(2), parents(2), 0);
        }
        // Global cap reached: a newcomer evicts peer 2's oldest, not peer 1's.
        o.add(orphan(3, 30, 10), 10, Some(3), parents(3), 0);
        assert!(o.contains(&a.txid()));
        assert_eq!(o.len(), 4);
        assert_eq!(o.peer_usage(Some(2)).0, 2);
        o.debug_check_invariants().unwrap();
    }

    #[test]
    fn byte_caps_and_too_large() {
        let limits = OrphanLimits { max_entries: 100, max_bytes: 1_000, max_entries_per_peer: 100, max_bytes_per_peer: 600, expiry_secs: 60 };
        let mut o: TxOrphanage<u8> = TxOrphanage::new(limits);
        assert_eq!(o.add(orphan(1, 1, 10), 601, Some(1), parents(1), 0), OrphanAdd::TooLarge);
        o.add(orphan(1, 2, 10), 400, Some(1), parents(1), 0);
        o.add(orphan(1, 3, 10), 400, Some(1), parents(1), 0); // per-peer bytes: evicts the first
        assert_eq!(o.peer_usage(Some(1)), (1, 400));
        o.add(orphan(2, 4, 10), 400, Some(2), parents(2), 0);
        o.add(orphan(3, 5, 10), 400, Some(3), parents(3), 0); // global bytes
        assert!(o.total_bytes() <= 1_000);
        o.debug_check_invariants().unwrap();
    }

    #[test]
    fn expiry_waiters_and_block_erase() {
        let mut o: TxOrphanage<u8> = TxOrphanage::default();
        let a = orphan(7, 1, 10);
        let b = orphan(7, 2, 10);
        let c = orphan(8, 3, 10);
        o.add(a.clone(), 10, Some(1), parents(7), 100);
        o.add(b.clone(), 10, Some(1), parents(7), 200);
        o.add(c.clone(), 10, None, parents(8), 300);
        assert_eq!(o.waiting_on(&[7; 32]), vec![a.txid(), b.txid()], "arrival order");
        let gone = o.expire(100 + ORPHAN_EXPIRY_SECS);
        assert_eq!(gone, vec![a.txid()]);
        assert_eq!(o.erase_for_block(&[([8; 32], 0)], &[]), vec![c.txid()], "conflicts with a confirmed spend");
        assert_eq!(o.erase_for_block(&[], &[b.txid()]), vec![b.txid()], "itself confirmed");
        assert!(o.is_empty());
        o.debug_check_invariants().unwrap();
    }
}
