//! Validated gossip relay of transactions (audit MEM-5 residual, NET-2 and
//! NET-4 on the transaction side; MEM-6 orphan handling).
//!
//! Blocks were already validated before gossipsub forwarded them
//! (`NetworkNode::run_validated` + a verdict channel), but `NewTransaction`
//! frames were still relayed on decode: an invalid transaction reached every
//! node at zero cost to its author, every honest relay forwarded it, and a
//! neighbour that judged it invalid could only blame the honest relay
//! (NET-4). The network loop now DEFERS the verdict on every gossiped
//! transaction to the message processor, which calls [`TxRelay::on_gossip_tx`]:
//!
//! * the frame's `tx_data` is decoded strictly (exact canonical bytes) and its
//!   claimed txid must match;
//! * the transaction goes through the SHARED admission function
//!   (`admission::admit_gated`, the same rules as RPC and reorg
//!   re-injection), cheapest checks first;
//! * the signature step — the only expensive one — runs LAST and is charged
//!   to the gossip AUTHOR's token bucket ([`SIG_BUDGET_BURST`] input
//!   signatures, refilled at [`SIG_BUDGET_REFILL_PER_SEC`]); an author out of
//!   budget is answered `Ignore` without any signature work;
//! * the verdict is `Accept` (relayed by gossipsub) only for a transaction
//!   that entered the pool; `Reject` (not relayed, the delivering peer takes
//!   gossipsub's invalid-message penalty — the author, since honest relays no
//!   longer forward invalid frames) for a malformed frame or a
//!   consensus-invalid transaction; `Ignore` (not relayed, not penalised) for
//!   policy refusals, duplicates, recently rejected ids, missing inputs and
//!   rate limiting;
//! * a transaction with missing inputs is kept in the bounded orphanage
//!   ([`super::orphanage`]) and re-tried when a parent enters the pool or a
//!   block confirms one. The caller withholds the verdict of the orphan's
//!   frame ([`DeferredVerdicts`]) and reports `Accept` when the orphan is
//!   admitted, so gossipsub relays the original frame; an orphan admitted
//!   after that frame left gossipsub's cache is re-announced by the node.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::time::{Duration, Instant};

use libp2p::PeerId;

use crate::core::Transaction;
use crate::mempool::admission::{self, AdmissionError, AdmissionPolicy};
use crate::mempool::orphanage::{OrphanAdd, OrphanLimits, TxOrphanage};
use crate::mempool::{Mempool, MAX_TX_SIZE};
use crate::network::ratelimit::TokenBuckets;
use crate::network::GossipVerdict;
use crate::storage::Storage;

/// Per-author burst of input-signature verifications (a hybrid
/// ML-DSA-65 + Falcon-1024 check per input).
pub const SIG_BUDGET_BURST: u32 = 400;
/// Per-author sustained input-signature verifications per second.
pub const SIG_BUDGET_REFILL_PER_SEC: f64 = 20.0;
/// Bound on the number of authors whose budget is tracked.
pub const SIG_BUDGET_TRACK_CAP: usize = 4096;
/// At most this many orphans are re-tried per triggering event; the rest
/// wait for the next event or the periodic sweep.
pub const MAX_ORPHANS_PER_EVENT: usize = 25;

/// How long a deferred orphan verdict stays useful: gossipsub keeps an
/// unvalidated frame for `history_length` (12) heartbeats of 1 s.
pub const DEFERRED_VERDICT_TTL: Duration = Duration::from_secs(12);
/// Delay before the node re-announces an orphan it admitted too late to
/// release the original frame: longer than gossipsub's 30 s duplicate cache
/// (an earlier publish of the same bytes is refused as a duplicate).
pub const REANNOUNCE_DELAY: Duration = Duration::from_secs(35);
/// Bound on deferred verdicts and scheduled re-announcements.
pub const MAX_DEFERRED: usize = 1024;

/// Gossip verdict for an admission error: `Reject` only for
/// consensus-invalid transactions (no honest node can relay them, so the
/// penalty lands on the author), `Ignore` for everything that is local
/// policy or state (duplicates, recent rejects, missing inputs, fees,
/// replacement and chain limits, rate limits, a full pool).
pub fn verdict_for_admission_error(e: &AdmissionError) -> GossipVerdict {
    if e.is_consensus_invalid() {
        GossipVerdict::Reject
    } else {
        GossipVerdict::Ignore
    }
}

/// What the processor must do after one gossiped transaction.
#[derive(Debug, Clone)]
pub struct GossipTxOutcome {
    /// The verdict to report for the gossip frame.
    pub verdict: GossipVerdict,
    /// Human-readable reason (logs).
    pub detail: String,
    /// The frame's transaction was buffered as an orphan: the caller should
    /// DEFER the verdict ([`DeferredVerdicts::defer`]) instead of reporting
    /// `verdict` (`Ignore`), so the frame can still be relayed when the
    /// orphan is admitted.
    pub orphaned: bool,
    /// OTHER transactions that entered the pool as a consequence (orphans
    /// whose parents arrived), parents first. The caller announces them.
    pub newly_admitted: Vec<Transaction>,
}

impl GossipTxOutcome {
    fn verdict(verdict: GossipVerdict, detail: impl Into<String>) -> Self {
        Self { verdict, detail: detail.into(), orphaned: false, newly_admitted: Vec::new() }
    }
}

/// MEM-6: verdicts withheld for gossiped orphans, so the ORIGINAL frame can
/// be relayed (`Accept`) once the orphan enters the pool — gossipsub would
/// refuse a re-publish of the same bytes as a duplicate. An orphan admitted
/// after its frame expired from gossipsub's cache is re-announced by the
/// node after [`REANNOUNCE_DELAY`]. Bounded by [`MAX_DEFERRED`]; `O` is the
/// frame's origin (the network's `InboundOrigin` in the node).
#[derive(Debug)]
pub struct DeferredVerdicts<O> {
    pending: HashMap<[u8; 32], (O, Instant)>,
    reannounce: VecDeque<(Instant, [u8; 32])>,
}

impl<O> Default for DeferredVerdicts<O> {
    fn default() -> Self {
        Self { pending: HashMap::new(), reannounce: VecDeque::new() }
    }
}

impl<O> DeferredVerdicts<O> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Withhold the verdict of the frame that carried orphan `txid`.
    pub fn defer(&mut self, txid: [u8; 32], origin: O, now: Instant) {
        if self.pending.len() >= MAX_DEFERRED {
            self.pending.retain(|_, (_, at)| now.saturating_duration_since(*at) < DEFERRED_VERDICT_TTL);
        }
        if self.pending.len() < MAX_DEFERRED {
            self.pending.entry(txid).or_insert((origin, now));
        }
    }

    /// `txids` entered the pool: returns the origins whose frames must now
    /// be reported `Accept` (still within gossipsub's cache window), and
    /// schedules a re-announcement for every other one.
    pub fn on_admitted(&mut self, txids: &[[u8; 32]], now: Instant) -> Vec<O> {
        let mut release = Vec::new();
        for t in txids {
            match self.pending.remove(t) {
                Some((o, at)) if now.saturating_duration_since(at) < DEFERRED_VERDICT_TTL => release.push(o),
                _ => {
                    if self.reannounce.len() < MAX_DEFERRED {
                        self.reannounce.push_back((now + REANNOUNCE_DELAY, *t));
                    }
                }
            }
        }
        release
    }

    /// Transactions whose re-announcement is due.
    pub fn due_reannouncements(&mut self, now: Instant) -> Vec<[u8; 32]> {
        let mut due = Vec::new();
        while let Some((at, _)) = self.reannounce.front() {
            if *at > now {
                break;
            }
            if let Some((_, t)) = self.reannounce.pop_front() {
                due.push(t);
            }
        }
        due
    }

    /// Forget deferred verdicts whose frame expired or whose orphan left
    /// the orphanage (expired / evicted / erased).
    pub fn prune(&mut self, still_orphan: impl Fn(&[u8; 32]) -> bool, now: Instant) {
        self.pending.retain(|t, (_, at)| {
            now.saturating_duration_since(*at) < DEFERRED_VERDICT_TTL && still_orphan(t)
        });
    }

    /// Number of withheld verdicts.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

/// Per-node transaction-relay state: per-author signature budgets and the
/// orphanage. Owned by the message processor.
pub struct TxRelay {
    budget: TokenBuckets<Option<PeerId>>,
    orphans: TxOrphanage<PeerId>,
}

impl Default for TxRelay {
    fn default() -> Self {
        Self::new()
    }
}

impl TxRelay {
    pub fn new() -> Self {
        Self::with_limits(SIG_BUDGET_BURST, SIG_BUDGET_REFILL_PER_SEC, OrphanLimits::default())
    }

    /// Explicit budget / orphanage bounds (tests).
    pub fn with_limits(burst: u32, refill_per_sec: f64, orphan_limits: OrphanLimits) -> Self {
        Self {
            budget: TokenBuckets::new(burst, refill_per_sec, SIG_BUDGET_TRACK_CAP),
            orphans: TxOrphanage::new(orphan_limits),
        }
    }

    /// The orphanage (read-only).
    pub fn orphans(&self) -> &TxOrphanage<PeerId> {
        &self.orphans
    }

    /// Judge one gossiped `NewTransaction { txid: claimed_txid, tx_data }`
    /// authored by `author`. `next_block_height` is the height of the next
    /// block (`admission::next_block_height`).
    #[allow(clippy::too_many_arguments)]
    pub fn on_gossip_tx(
        &mut self,
        store: &Storage,
        mempool: &Mempool,
        next_block_height: u64,
        claimed_txid: &[u8; 32],
        tx_data: &[u8],
        author: Option<PeerId>,
        now: Instant,
        now_unix: u64,
    ) -> GossipTxOutcome {
        self.orphans.expire(now_unix);
        // Policy, not invalidity: a > MAX_TX_SIZE transaction can be valid
        // in a block. Refused before decoding it.
        if tx_data.len() > MAX_TX_SIZE {
            return GossipTxOutcome::verdict(GossipVerdict::Ignore,
                format!("transaction of {} bytes exceeds the relay limit {}", tx_data.len(), MAX_TX_SIZE));
        }
        let tx = match admission::decode_tx_strict(tx_data) {
            Ok(t) => t,
            Err(e) => return GossipTxOutcome::verdict(GossipVerdict::Reject, format!("malformed transaction: {}", e)),
        };
        let txid = tx.txid();
        if txid != *claimed_txid {
            return GossipTxOutcome::verdict(GossipVerdict::Reject,
                format!("frame claims txid {} but the transaction hashes to {}",
                    hex::encode(&claimed_txid[..8]), hex::encode(&txid[..8])));
        }
        if self.orphans.contains(&txid) {
            return GossipTxOutcome::verdict(GossipVerdict::Ignore, "already buffered as an orphan");
        }
        let policy = AdmissionPolicy::relay(next_block_height);
        match self.admit_charged(store, mempool, tx.clone(), &policy, author, now) {
            Ok(()) => {
                let newly_admitted = self.resolve_orphans(store, mempool, &policy, vec![txid], now);
                GossipTxOutcome { verdict: GossipVerdict::Accept, detail: "admitted".into(), orphaned: false, newly_admitted }
            }
            Err(AdmissionError::MissingInputs(m)) => {
                let missing = admission::missing_parents(store, mempool, &tx);
                let orphaned = matches!(
                    self.orphans.add(tx, tx_data.len(), author, missing, now_unix),
                    OrphanAdd::Inserted { .. }
                );
                GossipTxOutcome { verdict: GossipVerdict::Ignore, detail: format!("orphan: {}", m), orphaned, newly_admitted: Vec::new() }
            }
            Err(e) => GossipTxOutcome::verdict(verdict_for_admission_error(&e), e.to_string()),
        }
    }

    /// After a block connected: drop orphans it confirmed or conflicts with,
    /// then re-try every orphan whose parents are now all available.
    /// Returns the transactions that entered the pool (to announce).
    #[allow(clippy::too_many_arguments)]
    pub fn on_block_connected(
        &mut self,
        store: &Storage,
        mempool: &Mempool,
        next_block_height: u64,
        block_txs: &[Transaction],
        now: Instant,
        now_unix: u64,
    ) -> Vec<Transaction> {
        let confirmed: Vec<[u8; 32]> = block_txs.iter().map(|t| t.txid()).collect();
        let spent: Vec<([u8; 32], u32)> = block_txs.iter()
            .filter(|t| !t.is_coinbase())
            .flat_map(|t| t.inputs.iter().map(|i| (i.prev_txid, i.prev_index)))
            .collect();
        self.orphans.erase_for_block(&spent, &confirmed);
        self.retry_orphans(store, mempool, next_block_height, now, now_unix)
    }

    /// Expire stale orphans and re-try every orphan whose parents are now
    /// available (periodic sweep / after blocks). Bounded by the orphanage
    /// size. Returns the transactions that entered the pool.
    pub fn retry_orphans(
        &mut self,
        store: &Storage,
        mempool: &Mempool,
        next_block_height: u64,
        now: Instant,
        now_unix: u64,
    ) -> Vec<Transaction> {
        self.orphans.expire(now_unix);
        let policy = AdmissionPolicy::relay(next_block_height);
        let ready: Vec<[u8; 32]> = self.orphans.txids_by_age().into_iter()
            .filter(|t| self.orphans.get(t).is_some_and(|o| admission::missing_parents(store, mempool, &o.tx).is_empty()))
            .take(MAX_ORPHANS_PER_EVENT)
            .collect();
        let mut out = Vec::new();
        let mut admitted = Vec::new();
        for t in ready {
            if let Some(tx) = self.try_orphan(store, mempool, &policy, &t, now) {
                admitted.push(t);
                out.push(tx);
            }
        }
        out.extend(self.resolve_orphans(store, mempool, &policy, admitted, now));
        out
    }

    /// Admission with the author's signature budget as the gate.
    fn admit_charged(
        &mut self,
        store: &Storage,
        mempool: &Mempool,
        tx: Transaction,
        policy: &AdmissionPolicy,
        author: Option<PeerId>,
        now: Instant,
    ) -> Result<(), AdmissionError> {
        let budget = &mut self.budget;
        let mut gate = |t: &Transaction| -> Result<(), AdmissionError> {
            let cost = t.inputs.len().max(1);
            if budget.try_take_n_at(author, cost, now) {
                Ok(())
            } else {
                Err(AdmissionError::RateLimited(format!(
                    "signature budget of {} exhausted ({} input signature(s) asked)",
                    author.map(|p| p.to_string()).unwrap_or_else(|| "unknown author".into()), cost)))
            }
        };
        admission::admit_gated(store, mempool, tx, policy, &mut gate).map(|_| ())
    }

    /// Re-try the orphan `txid` if all its inputs are now available. Returns
    /// the transaction when it entered the pool. An orphan still missing a
    /// parent, or whose author is out of budget, is kept (same deadline).
    fn try_orphan(
        &mut self,
        store: &Storage,
        mempool: &Mempool,
        policy: &AdmissionPolicy,
        txid: &[u8; 32],
        now: Instant,
    ) -> Option<Transaction> {
        let o = self.orphans.get(txid)?;
        if !admission::missing_parents(store, mempool, &o.tx).is_empty() {
            return None;
        }
        let o = self.orphans.remove(txid)?;
        match self.admit_charged(store, mempool, o.tx.clone(), policy, o.peer, now) {
            Ok(()) => Some(o.tx),
            Err(AdmissionError::MissingInputs(_)) | Err(AdmissionError::RateLimited(_)) => {
                let missing = admission::missing_parents(store, mempool, &o.tx);
                let missing = if missing.is_empty() { o.missing_parents.clone() } else { missing };
                self.orphans.add_with_expiry(o.tx, o.bytes, o.peer, missing, o.expires_at);
                None
            }
            Err(e) => {
                log::debug!("orphan {} dropped on re-try: {}", hex::encode(&txid[..8]), e);
                None
            }
        }
    }

    /// Breadth-first: for every txid that just entered the pool, re-try the
    /// orphans waiting on it (at most [`MAX_ORPHANS_PER_EVENT`] in total).
    fn resolve_orphans(
        &mut self,
        store: &Storage,
        mempool: &Mempool,
        policy: &AdmissionPolicy,
        roots: Vec<[u8; 32]>,
        now: Instant,
    ) -> Vec<Transaction> {
        let mut queue: VecDeque<[u8; 32]> = roots.into();
        let mut tried: BTreeSet<[u8; 32]> = BTreeSet::new();
        let mut out = Vec::new();
        while let Some(parent) = queue.pop_front() {
            for child in self.orphans.waiting_on(&parent) {
                if tried.len() >= MAX_ORPHANS_PER_EVENT {
                    return out;
                }
                if !tried.insert(child) {
                    continue;
                }
                if let Some(tx) = self.try_orphan(store, mempool, policy, &child, now) {
                    queue.push_back(child);
                    out.push(tx);
                }
            }
        }
        out
    }
}
