//! Serving `/gnb/sync/1` requests: the SERVER side, off the swarm task.
//!
//! Re-audit B1-T3 / B2-T5: requests used to be answered inline in the swarm
//! event loop, under the DAG read lock, and GetTips walked the whole
//! selected chain (for a locator nobody reads) while GetHeaders scanned every
//! stored block — O(chain) per 1-byte request on the thread that drives all
//! gossip and relay. Now each answer is O(log n + limit) (indexed DAG reads:
//! `GhostDAG::ordered_hashes_from`, `GhostDAG::tips_for_peers`; stored block
//! bytes), computed on the blocking pool by at most [`MAX_SERVE_WORKERS`]
//! workers that hold the DAG read lock only to copy at most `limit` entries;
//! requests wait in a bounded queue, taken round-robin across peers (Bitcoin
//! Core processes one message per peer per pass of its message handler).
//!
//! Re-audit B1-T18 / B2-T6: nothing used to track how many bytes of answers
//! a peer had not read yet, so a peer that never reads made the node hold
//! about 64 answers of up to a block each per burst, for 30 s at a time.
//! Each peer is now charged for the bytes of its answers until libp2p
//! reports them written (`ResponseSent`) or failed; a request from a peer at
//! [`PER_PEER_SEND_BUDGET`], or while all peers together are at
//! [`GLOBAL_SEND_BUDGET`], is answered `Busy` without being computed (Bitcoin
//! Core stops processing a peer's `getdata` while its send buffer is over
//! `-maxsendbuffer`, `fPauseSend`). Answers to a peer that does not read are
//! given up after `sync_rr::RESPONSE_WRITE_TIMEOUT`, and a block is sent as
//! its stored bytes (no decode and re-encode, no second copy). The last
//! [`PROTECTED_SEND_RESERVE`] of the global budget is kept for peers we
//! dialed and `--peer` peers, so identities that connect to us and never read
//! cannot get every peer answered Busy (Bitcoin Core exempts peers with the
//! download permission from its upload limit).

use std::collections::HashSet;

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use libp2p::PeerId;
use parking_lot::RwLock;

use super::sync_rr::{self, SyncRequest, SyncResponse};
use super::{SyncEntry, MAX_WIRE_GETHEADERS_LIMIT, MAX_WIRE_TIPS};

/// Bytes of unwritten answers one peer may have before its requests are
/// answered Busy. Room for a full block (`MAX_BLOCK_SIZE`, 1 MB) and a
/// maximal GetHeaders answer several times over; Bitcoin Core's default
/// `-maxsendbuffer` is 1000 kB.
pub const PER_PEER_SEND_BUDGET: usize = 4 * 1024 * 1024;
/// Bytes of unwritten answers all peers together may have.
pub const GLOBAL_SEND_BUDGET: usize = 64 * 1024 * 1024;
/// The part of [`GLOBAL_SEND_BUDGET`] only protected peers (dialed by us, or
/// `--peer`) may use: the others together stop at the rest.
pub const PROTECTED_SEND_RESERVE: usize = 16 * 1024 * 1024;
/// Requests computed at once (blocking-pool tasks).
pub const MAX_SERVE_WORKERS: usize = 2;
/// Requests of one peer waiting for a worker (above: Busy). An honest client
/// keeps at most `sync_rr::MAX_INFLIGHT_PER_PEER` (16) pulls in flight to one
/// peer, plus a few directed GetTips / GetPeers.
pub const MAX_QUEUED_PER_PEER: usize = 32;
/// Requests of all peers waiting for a worker (above: Busy).
pub const MAX_QUEUED_TOTAL: usize = 512;

/// Bytes of answers handed to libp2p and not yet written, over every network
/// loop of the process (observability, and the live regression test).
static OUTSTANDING: AtomicU64 = AtomicU64::new(0);

/// See [`OUTSTANDING`].
#[allow(dead_code)] // library API and tests; the node binary compiles this module too
pub fn send_bytes_outstanding() -> u64 {
    OUTSTANDING.load(Ordering::Relaxed)
}

/// One request waiting for (or given to) a worker. `C` is the channel the
/// answer goes back on (libp2p's `ResponseChannel`; anything in tests).
#[derive(Debug)]
pub struct Job<R, C> {
    pub peer: PeerId,
    pub id: R,
    pub req: SyncRequest,
    pub channel: C,
}

/// What [`ServeQueue::next_job`] wants done with the next job.
#[derive(Debug)]
pub enum Next<R, C> {
    /// Compute the answer on a worker; report it with [`ServeQueue::computed`].
    Compute(Job<R, C>),
    /// Answer Busy at once: the peer reached its send budget (or all peers
    /// together did) while the job waited.
    Busy(Job<R, C>),
}

#[derive(Debug, Default)]
struct PeerServe {
    /// Bytes of this peer's answers not yet written.
    unwritten: usize,
    computing: usize,
}

/// The bounded serving queue and send budgets (pure bookkeeping; the network
/// loop spawns the workers and talks to libp2p).
#[derive(Debug)]
pub struct ServeQueue<R, C> {
    queues: HashMap<PeerId, VecDeque<Job<R, C>>>,
    /// Peers with queued jobs, in round-robin order.
    rr: VecDeque<PeerId>,
    queued: usize,
    peers: HashMap<PeerId, PeerServe>,
    /// Unwritten answer bytes per request (and whether its peer was
    /// protected when charged).
    charged: HashMap<R, (PeerId, usize, bool)>,
    total_unwritten: usize,
    /// Of `total_unwritten`, the bytes of unprotected peers.
    unprotected_unwritten: usize,
    /// Connected peers we dialed or named with `--peer`.
    protected: HashSet<PeerId>,
    computing: usize,
}

impl<R: Copy + Eq + Hash, C> Default for ServeQueue<R, C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: Copy + Eq + Hash, C> ServeQueue<R, C> {
    pub fn new() -> Self {
        Self {
            queues: HashMap::new(),
            rr: VecDeque::new(),
            queued: 0,
            peers: HashMap::new(),
            charged: HashMap::new(),
            total_unwritten: 0,
            unprotected_unwritten: 0,
            protected: HashSet::new(),
            computing: 0,
        }
    }

    /// `peer` connected (`protected`: we dialed it, or it is a `--peer`), or
    /// disconnected (`false`).
    pub fn set_protected(&mut self, peer: PeerId, protected: bool) {
        if protected {
            self.protected.insert(peer);
        } else {
            self.protected.remove(&peer);
        }
    }

    /// Whether `peer` may be sent another answer now: its unwritten bytes
    /// and everyone's are under budget, and, for an unprotected peer, the
    /// unprotected peers' bytes leave [`PROTECTED_SEND_RESERVE`] free.
    pub fn has_send_budget(&self, peer: &PeerId) -> bool {
        self.total_unwritten < GLOBAL_SEND_BUDGET
            && self.peers.get(peer).map_or(0, |p| p.unwritten) < PER_PEER_SEND_BUDGET
            && (self.protected.contains(peer)
                || self.unprotected_unwritten < GLOBAL_SEND_BUDGET - PROTECTED_SEND_RESERVE)
    }

    /// Queue a request for a worker. `Err(job)`: answer it Busy now (queue
    /// full, or the peer is at its send budget).
    pub fn submit(&mut self, job: Job<R, C>) -> Result<(), Job<R, C>> {
        let q_len = self.queues.get(&job.peer).map_or(0, |q| q.len());
        if !self.has_send_budget(&job.peer) || q_len >= MAX_QUEUED_PER_PEER || self.queued >= MAX_QUEUED_TOTAL {
            return Err(job);
        }
        let peer = job.peer;
        let q = self.queues.entry(peer).or_default();
        if q.is_empty() {
            self.rr.push_back(peer);
        }
        q.push_back(job);
        self.queued += 1;
        Ok(())
    }

    /// The next job to start, round-robin across peers, if a worker is free.
    pub fn next_job(&mut self) -> Option<Next<R, C>> {
        if self.computing >= MAX_SERVE_WORKERS {
            return None;
        }
        let peer = self.rr.pop_front()?;
        let q = self.queues.get_mut(&peer)?;
        let job = q.pop_front()?;
        if q.is_empty() {
            self.queues.remove(&peer);
        } else {
            self.rr.push_back(peer);
        }
        self.queued -= 1;
        if !self.has_send_budget(&peer) {
            return Some(Next::Busy(job));
        }
        self.computing += 1;
        self.peers.entry(peer).or_default().computing += 1;
        Some(Next::Compute(job))
    }

    /// A worker finished `peer`'s job.
    pub fn computed(&mut self, peer: &PeerId) {
        self.computing = self.computing.saturating_sub(1);
        if let Some(p) = self.peers.get_mut(peer) {
            p.computing = p.computing.saturating_sub(1);
        }
        self.gc_peer(peer);
    }

    /// An answer of `bytes` to request `id` was handed to libp2p.
    pub fn charge(&mut self, peer: PeerId, id: R, bytes: usize) {
        if bytes == 0 {
            return;
        }
        self.peers.entry(peer).or_default().unwritten += bytes;
        self.total_unwritten += bytes;
        let protected = self.protected.contains(&peer);
        if !protected {
            self.unprotected_unwritten += bytes;
        }
        self.charged.insert(id, (peer, bytes, protected));
        OUTSTANDING.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// The answer to request `id` was written, or failed: its bytes are free.
    pub fn release(&mut self, id: &R) {
        let Some((peer, bytes, protected)) = self.charged.remove(id) else { return };
        if let Some(p) = self.peers.get_mut(&peer) {
            p.unwritten = p.unwritten.saturating_sub(bytes);
        }
        self.total_unwritten = self.total_unwritten.saturating_sub(bytes);
        if !protected {
            self.unprotected_unwritten = self.unprotected_unwritten.saturating_sub(bytes);
        }
        OUTSTANDING.fetch_sub(bytes as u64, Ordering::Relaxed);
        self.gc_peer(&peer);
    }

    fn gc_peer(&mut self, peer: &PeerId) {
        if self.peers.get(peer).is_some_and(|p| p.unwritten == 0 && p.computing == 0) {
            self.peers.remove(peer);
        }
    }

    /// The peer disconnected: its queued jobs are dropped (their channels
    /// with them; libp2p reports the requests as failed).
    pub fn forget_queued(&mut self, peer: &PeerId) -> usize {
        let n = self.queues.remove(peer).map_or(0, |q| q.len());
        self.queued -= n;
        self.rr.retain(|p| p != peer);
        n
    }

    /// Bytes of `peer`'s answers not yet written.
    #[allow(dead_code)] // library API and tests; the node binary compiles this module too
    pub fn unwritten(&self, peer: &PeerId) -> usize {
        self.peers.get(peer).map_or(0, |p| p.unwritten)
    }

    /// Bytes of all answers not yet written.
    #[allow(dead_code)] // library API and tests; the node binary compiles this module too
    pub fn total_unwritten(&self) -> usize {
        self.total_unwritten
    }

    /// Jobs waiting for a worker.
    #[allow(dead_code)] // library API and tests; the node binary compiles this module too
    pub fn queued(&self) -> usize {
        self.queued
    }

    /// Jobs being computed.
    #[allow(dead_code)] // library API and tests; the node binary compiles this module too
    pub fn computing(&self) -> usize {
        self.computing
    }
}

impl<R, C> Drop for ServeQueue<R, C> {
    fn drop(&mut self) {
        // Keep the process-wide gauge exact when a network loop ends.
        OUTSTANDING.fetch_sub(self.total_unwritten as u64, Ordering::Relaxed);
    }
}

/// Answer an inbound directed `SyncRequest` from the DAG and the block store
/// (blocking: run it on a worker). Block bodies live in the store, headers
/// and tips in the DAG. Every answer costs O(log n + limit):
///
/// * GetBlock: the stored bytes as they are (the canonical
///   `Block::to_wire_bytes` encoding every write path stores; Bitcoin Core
///   likewise sends a stored block's raw bytes), with `blue_score` / `height`
///   read from its header; `BlockNotFound` when pruned or unknown (the
///   requester tries another peer).
/// * GetHeaders: at most `min(limit, MAX_WIRE_GETHEADERS_LIMIT)` entries
///   from the (blue_score, hash) index, with the DAG read lock held only to
///   copy them.
/// * GetTips: `GhostDAG::tips_for_peers(MAX_WIRE_TIPS)` — the selected tip
///   and the best valid tips by blue work, never a chain-disqualified one
///   (B2-T7: every leaf used to be sent, and requesters refused more than
///   MAX_WIRE_TIPS). The locator is empty: no release reads it, and building
///   it walked the whole selected chain.
///
/// `GetPeers` is answered by the network loop (it needs the peer table);
/// here it gets an empty answer, and `Malformed` is never served.
pub fn serve_sync_request(
    dag: &Arc<RwLock<crate::consensus::GhostDAG>>,
    store: &Arc<crate::storage::Storage>,
    req: &SyncRequest,
) -> SyncResponse {
    match req {
        SyncRequest::GetPeers => SyncResponse::Peers { peers: Vec::new() },
        SyncRequest::Malformed => SyncResponse::Busy,
        SyncRequest::GetBlock { block_hash } => match store.get_block_wire_bytes(block_hash) {
            Ok(Some(bytes)) => match crate::core::BlockHeader::read_wire_bytes(&bytes) {
                Ok((_, blue_score, height, _)) => {
                    SyncResponse::Block { block_hash: *block_hash, blue_score, height, block_data: bytes }
                }
                Err(_) => SyncResponse::BlockNotFound { block_hash: *block_hash },
            },
            _ => SyncResponse::BlockNotFound { block_hash: *block_hash },
        },
        SyncRequest::GetHeaders { from_blue_score, limit } => {
            // H-R3-1: bound the work here too, whatever the decoder let in.
            let limit = (*limit as usize).min(MAX_WIRE_GETHEADERS_LIMIT as usize);
            let d = dag.read();
            let entries: Vec<SyncEntry> = d
                .ordered_hashes_from(*from_blue_score, limit)
                .iter()
                .filter_map(|h| d.get_node(h).map(|n| SyncEntry { hash: *h, blue_score: n.blue_score, height: n.height }))
                .collect();
            SyncResponse::Headers { entries }
        }
        SyncRequest::GetTips => {
            let d = dag.read();
            let tips: Vec<SyncEntry> = d
                .tips_for_peers(MAX_WIRE_TIPS)
                .iter()
                .filter_map(|h| d.get_node(h).map(|n| SyncEntry { hash: *h, blue_score: n.blue_score, height: n.height }))
                .collect();
            SyncResponse::Tips { tips, locator: Vec::new() }
        }
    }
}

/// A computed answer, back from a worker.
pub struct Served<R, C> {
    pub peer: PeerId,
    pub id: R,
    pub channel: C,
    pub response: SyncResponse,
}

/// Compute `job` on the blocking pool and send the answer to `done`. A panic
/// while serving answers Busy (the queue's worker count stays exact).
pub fn spawn_worker<R, C>(
    job: Job<R, C>,
    dag: Arc<RwLock<crate::consensus::GhostDAG>>,
    store: Arc<crate::storage::Storage>,
    done: tokio::sync::mpsc::Sender<Served<R, C>>,
) where
    R: Send + 'static,
    C: Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let Job { peer, id, req, channel } = job;
        let response = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| serve_sync_request(&dag, &store, &req)))
            .unwrap_or(SyncResponse::Busy);
        let _ = done.blocking_send(Served { peer, id, channel, response });
    });
}

/// Bytes an answer is charged while it waits to be written.
pub fn charge_for(resp: &SyncResponse) -> usize {
    if matches!(resp, SyncResponse::Busy) {
        0
    } else {
        sync_rr::response_wire_len(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(peer: PeerId, id: u32) -> Job<u32, ()> {
        Job { peer, id, req: SyncRequest::GetBlock { block_hash: [0; 32] }, channel: () }
    }

    /// A peer that never reads: once its unwritten answers reach the budget,
    /// its next requests are answered Busy without being computed, both at
    /// submission and when a queued one comes up; other peers are served.
    #[test]
    fn a_peer_at_its_send_budget_gets_busy() {
        let mut q: ServeQueue<u32, ()> = ServeQueue::new();
        let (slow, other) = (PeerId::random(), PeerId::random());
        for i in 0..8 {
            q.submit(job(slow, i)).unwrap();
        }
        // Each answer is a 2 MiB block nobody reads: after two, the peer is
        // at its budget and the six queued requests come up Busy.
        let (mut computed, mut busy) = (0, 0);
        while let Some(n) = q.next_job() {
            match n {
                Next::Compute(j) => {
                    q.computed(&j.peer);
                    q.charge(j.peer, j.id, 2 << 20);
                    computed += 1;
                }
                Next::Busy(_) => busy += 1,
            }
        }
        assert_eq!((computed, busy), (2, 6));
        assert_eq!(q.unwritten(&slow), PER_PEER_SEND_BUDGET);
        assert!(q.submit(job(slow, 99)).is_err(), "over budget: Busy at once");
        q.submit(job(other, 100)).expect("another peer is still served");
        assert!(matches!(q.next_job(), Some(Next::Compute(j)) if j.peer == other));
        // Written answers free the budget.
        for i in 0..8 {
            q.release(&i);
        }
        assert_eq!(q.unwritten(&slow), 0);
        assert!(q.submit(job(slow, 200)).is_ok());
    }

    /// Review of B1-T18: identities that connected to us and never read
    /// fill only the unprotected part of the global budget; a peer we dialed
    /// (or a `--peer`) is still served. Before, 16 such identities got every
    /// peer answered Busy.
    #[test]
    fn non_reading_inbound_identities_cannot_starve_protected_peers() {
        let mut q: ServeQueue<u32, ()> = ServeQueue::new();
        let outbound = PeerId::random();
        q.set_protected(outbound, true);
        let mut id = 0u32;
        let mut filled = 0usize;
        // Inbound identities each take their full per-peer budget and never read.
        for _ in 0..(GLOBAL_SEND_BUDGET / PER_PEER_SEND_BUDGET) {
            let p = PeerId::random();
            if !q.has_send_budget(&p) {
                break;
            }
            id += 1;
            q.charge(p, id, PER_PEER_SEND_BUDGET);
            filled += 1;
        }
        assert_eq!(filled * PER_PEER_SEND_BUDGET, GLOBAL_SEND_BUDGET - PROTECTED_SEND_RESERVE);
        assert!(!q.has_send_budget(&PeerId::random()), "another inbound identity is refused");
        assert!(q.has_send_budget(&outbound), "a peer we dialed is still served");
        q.submit(job(outbound, 9_999)).expect("its request is queued, not Busy");
        // The protected peers' own use is bounded by the global budget.
        q.set_protected(outbound, false);
        assert!(!q.has_send_budget(&outbound), "unprotected once disconnected");
    }

    /// Workers are bounded and peers are served round-robin.
    #[test]
    fn workers_are_bounded_and_round_robin() {
        let mut q: ServeQueue<u32, ()> = ServeQueue::new();
        let (a, b) = (PeerId::random(), PeerId::random());
        for i in 0..10 {
            q.submit(job(a, i)).unwrap();
        }
        q.submit(job(b, 100)).unwrap();
        let first: Vec<PeerId> = std::iter::from_fn(|| match q.next_job() {
            Some(Next::Compute(j)) => Some(j.peer),
            _ => None,
        })
        .collect();
        assert_eq!(first.len(), MAX_SERVE_WORKERS, "never more than the worker count at once");
        assert!(first.contains(&b), "b is not starved behind a's ten requests");
        assert_eq!(q.queued(), 9);
        // The per-peer and total queue caps answer Busy.
        for i in 0..MAX_QUEUED_PER_PEER as u32 {
            let _ = q.submit(job(a, 1000 + i));
        }
        assert!(q.submit(job(a, 5000)).is_err());
        assert_eq!(q.forget_queued(&a), MAX_QUEUED_PER_PEER);
        assert_eq!(q.queued(), 0);
    }
}
