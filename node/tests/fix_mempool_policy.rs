//! Regression tests for audit package P4 (mempool and RPC):
//!
//! * MEM-5 residual (+ NET-2 / NET-4, transaction side): gossiped
//!   transactions are judged by the shared admission function before relay;
//!   Reject only for consensus-invalid ones, Ignore for policy / duplicates /
//!   recent rejects; signatures last and budgeted per delivering connection.
//! * MEM-6 residual: bounded orphan pool; chains of unconfirmed transactions
//!   with ancestor/descendant limits, CPFP templates, descendant-consistent
//!   removal; full-RBF with BIP125 rules 2-6.
//! * NET-12 residual: explorer statistics from incremental aggregates kept in
//!   the UTXO write batches — equal to a full recomputation after random
//!   connect/disconnect sequences, bounded storage reads, cancellable work.
//!
//! The live (real swarm) tests are in `fix_mempool_live.rs`.

mod fix_common;
use fix_common::*;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use gnb::consensus::GhostDAG;
use gnb::core::{self, Block, BlockHeader, MerkleRoot, Transaction, TxInput, TxOutput};
use gnb::mempool::admission::{self, AdmissionError, AdmissionPolicy};
use gnb::mempool::orphanage::OrphanLimits;
use gnb::mempool::relay::{self, TxRelay};
use gnb::mempool::{self as mp, Clock, Mempool, MempoolError, PackageCandidate};
use gnb::network::{GossipVerdict, InboundOrigin};
use gnb::reorg::{self, ConnectHooks, ReorgPlan, UtxoView};
use gnb::storage::aggregates::{self, AggregateSnapshot, HolderEntry};
use gnb::storage::Storage;
use gnb::{analytics, template};
use libp2p::PeerId;
use parking_lot::RwLock;

// ── helpers ──────────────────────────────────────────────────────────────────

fn wire(tx: &Transaction) -> Vec<u8> {
    tx.to_wire_bytes(true)
}

/// An unsigned spend (mempool-level tests that never verify scripts).
fn syn(inputs: &[([u8; 32], u32)], outs: &[u64], tag: u8, pad: usize) -> Transaction {
    Transaction {
        version: 1,
        inputs: inputs.iter().map(|(t, i)| TxInput {
            prev_txid: *t, prev_index: *i, script_sig: vec![tag; pad.max(1)], sequence: u32::MAX,
        }).collect(),
        outputs: outs.iter().map(|v| TxOutput { value: *v, script_pubkey: vec![tag; 20] }).collect(),
        locktime: 0,
    }
}

fn ext(i: u64) -> [u8; 32] {
    let mut a = [0u8; 32];
    a[..8].copy_from_slice(&i.to_le_bytes());
    a[31] = 0xEE;
    a
}

struct TestClock(Arc<AtomicU64>);
impl Clock for TestClock {
    fn now_secs(&self) -> u64 { self.0.load(Ordering::SeqCst) }
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 { self.next() % n.max(1) }
}

// ── MEM-5: gossip verdicts ───────────────────────────────────────────────────

/// Every gossiped transaction goes through the shared admission function
/// BEFORE relay: Accept iff it entered the pool; Reject for malformed frames
/// and consensus-invalid transactions (bad signature, inputs < outputs, dust);
/// Ignore for policy refusals, duplicates, recently rejected ids and missing
/// inputs. Pre-fix every decodable frame was relayed (`Deliver(Accept)`).
#[test]
fn mem5_gossip_tx_verdicts_follow_admission() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let k = key();
    let funds: Vec<_> = (0..6u8).map(|i| ([0x50 + i; 32], 0u32, out(1_000_000, &k.spk))).collect();
    let n = node_with(&genesis, &funds);
    let next = admission::next_block_height(&n.dag.read());
    let mut relay = TxRelay::new();
    let author = Some(PeerId::random());
    let t0 = Instant::now();
    let mut go = |claim: &[u8; 32], bytes: &[u8]| relay.on_gossip_tx(&n.store, &n.mempool, next, claim, bytes, author, t0, unix_now());

    let good = signed_spend(&k, &[(funds[0].0, 0)], vec![out(900_000, &[0x01; 20])]);
    let o = go(&good.txid(), &wire(&good));
    assert_eq!(o.verdict, GossipVerdict::Accept, "{}", o.detail);
    assert!(n.mempool.contains(&good.txid()));
    assert_eq!(go(&good.txid(), &wire(&good)).verdict, GossipVerdict::Ignore, "duplicate");

    // Consensus-invalid → Reject; the replay is answered by the filter (Ignore).
    let mut bad_sig = signed_spend(&k, &[(funds[1].0, 0)], vec![out(900_000, &[0x02; 20])]);
    bad_sig.inputs[0].script_sig[10] ^= 0xFF;
    let o = go(&bad_sig.txid(), &wire(&bad_sig));
    assert_eq!(o.verdict, GossipVerdict::Reject, "{}", o.detail);
    let o = go(&bad_sig.txid(), &wire(&bad_sig));
    assert_eq!(o.verdict, GossipVerdict::Ignore);
    assert!(o.detail.contains("recently rejected"), "{}", o.detail);
    let overspend = signed_spend(&k, &[(funds[2].0, 0)], vec![out(2_000_000, &[0x03; 20])]);
    assert_eq!(go(&overspend.txid(), &wire(&overspend)).verdict, GossipVerdict::Reject, "inputs < outputs");
    let dust = signed_spend(&k, &[(funds[3].0, 0)], vec![out(1, &[0x04; 20]), out(900_000, &[0x05; 20])]);
    assert_eq!(go(&dust.txid(), &wire(&dust)).verdict, GossipVerdict::Reject, "dust is a consensus rule");

    // Malformed frames → Reject.
    let mut padded = wire(&good);
    padded.push(0);
    assert_eq!(go(&good.txid(), &padded).verdict, GossipVerdict::Reject, "trailing bytes");
    assert_eq!(go(&[7u8; 32], &[0xFF; 64]).verdict, GossipVerdict::Reject, "undecodable");
    let other = signed_spend(&k, &[(funds[4].0, 0)], vec![out(900_000, &[0x06; 20])]);
    assert_eq!(go(&[9u8; 32], &wire(&other)).verdict, GossipVerdict::Reject, "claimed txid mismatch");
    assert!(!n.mempool.contains(&other.txid()));

    // Policy refusals → Ignore (never a penalty).
    let zero = signed_spend(&k, &[(funds[4].0, 0)], vec![out(0, &[0x07; 20]), out(900_000, &[0x08; 20])]);
    let o = go(&zero.txid(), &wire(&zero));
    assert_eq!(o.verdict, GossipVerdict::Ignore, "zero-value output is non-standard, not invalid: {}", o.detail);
    let huge = vec![0u8; mp::MAX_TX_SIZE + 1];
    assert_eq!(go(&[1u8; 32], &huge).verdict, GossipVerdict::Ignore, "over the relay size limit");

    // Missing inputs → Ignore, buffered as an orphan.
    let orphan = signed_spend(&k, &[([0xAB; 32], 0)], vec![out(900_000, &[0x09; 20])]);
    let o = go(&orphan.txid(), &wire(&orphan));
    assert_eq!(o.verdict, GossipVerdict::Ignore);
    assert!(o.orphaned);
    n.mempool.debug_check_invariants().unwrap();
}

/// The verdict mapping is total: Reject exactly for consensus-invalid.
#[test]
fn mem5_verdict_mapping_rejects_only_consensus_invalid() {
    use AdmissionError::*;
    assert_eq!(relay::verdict_for_admission_error(&Rejected("x".into())), GossipVerdict::Reject);
    for e in [
        NonStandard("x".into()), MissingInputs("x".into()), Conflict("x".into()), Replacement("x".into()),
        ChainLimit("x".into()), Immature("x".into()), LowFee("x".into()), Duplicate("x".into()),
        RateLimited("x".into()), Pool("x".into()),
    ] {
        assert_eq!(relay::verdict_for_admission_error(&e), GossipVerdict::Ignore, "{e:?}");
    }
    assert!(!RateLimited("x".into()).is_cacheable(), "a rate-limited tx may be valid");
}

/// Signatures are verified LAST and charged to the delivering connection's
/// budget (one token per input, all-or-nothing): cheap failures cost
/// nothing; a connection out of budget is ignored without any signature
/// work and the transaction stays admissible from another connection.
/// Review finding: the tokens are REFUNDED when the transaction enters the
/// pool, so only verification that did not lead to admission is charged
/// (pre-fix an honest relay forwarding valid traffic spent its budget).
#[test]
fn mem5_signature_work_is_last_and_budgeted_per_connection() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let k = key();
    let funds: Vec<_> = (0..10u8).map(|i| ([0x70 + i; 32], 0u32, out(1_000_000, &k.spk))).collect();
    let n = node_with(&genesis, &funds);
    let next = admission::next_block_height(&n.dag.read());
    let mut relay = TxRelay::with_limits(3, 0.0, OrphanLimits::default());
    let (a, b) = (Some(PeerId::random()), Some(PeerId::random()));
    let t0 = Instant::now();
    let go = |relay: &mut TxRelay, tx: &Transaction, p: Option<PeerId>| {
        relay.on_gossip_tx(&n.store, &n.mempool, next, &tx.txid(), &wire(tx), p, t0, unix_now())
    };
    let bad_last = |inputs: &[([u8; 32], u32)], v: u64, tag: u8| {
        let mut t = signed_spend(&k, inputs, vec![out(v, &[tag; 20])]);
        let last = t.inputs.len() - 1;
        t.inputs[last].script_sig[10] ^= 0xFF;
        t
    };

    // Three transactions below the consensus minimum fee (fee 1 sat), each
    // also badly signed: refused at the fee step, signatures never touched.
    for i in 0..3u8 {
        let mut cheap = signed_spend(&k, &[(funds[0].0, 0)], vec![out(999_999 - i as u64, &[0x10 + i; 20])]);
        cheap.inputs[0].script_sig[10] ^= 0xFF;
        let o = go(&mut relay, &cheap, a);
        assert_eq!(o.verdict, GossipVerdict::Reject);
        assert!(o.detail.contains("below consensus minimum"), "the fee error, not the signature: {}", o.detail);
    }
    // A still has its full budget of 3: a 3-input transaction passes...
    let three = signed_spend(&k, &[(funds[1].0, 0), (funds[2].0, 0), (funds[3].0, 0)], vec![out(2_900_000, &[0x20; 20])]);
    assert_eq!(go(&mut relay, &three, a).verdict, GossipVerdict::Accept);
    // ... and, admitted, it was refunded: A still verifies another one.
    let one = signed_spend(&k, &[(funds[4].0, 0)], vec![out(900_000, &[0x21; 20])]);
    let o = go(&mut relay, &one, a);
    assert_eq!(o.verdict, GossipVerdict::Accept, "refunded on admission: {}", o.detail);
    // A consensus-invalid 3-input transaction is charged in full.
    let bad = bad_last(&[(funds[5].0, 0), (funds[6].0, 0), (funds[7].0, 0)], 2_900_000, 0x22);
    assert_eq!(go(&mut relay, &bad, a).verdict, GossipVerdict::Reject);
    // A's budget is now spent: the next transaction is ignored unverified.
    let next_one = signed_spend(&k, &[(funds[8].0, 0)], vec![out(900_000, &[0x23; 20])]);
    let o = go(&mut relay, &next_one, a);
    assert_eq!(o.verdict, GossipVerdict::Ignore);
    assert!(o.detail.contains("budget"), "{}", o.detail);
    assert!(!admission::signatures_cached(&next_one), "no signature was verified");
    assert!(!n.mempool.contains(&next_one.txid()));
    assert!(!n.mempool.is_recently_rejected(&admission::wtxid(&next_one)), "not cached: it may be valid");
    // Another connection is unaffected.
    assert_eq!(go(&mut relay, &next_one, b).verdict, GossipVerdict::Accept);
    // B pays for invalid signatures only: 1 + 2 tokens, then out of budget.
    let b1 = bad_last(&[(funds[9].0, 0)], 900_000, 0x24);
    assert_eq!(go(&mut relay, &b1, b).verdict, GossipVerdict::Reject);
    let b2 = bad_last(&[(funds[5].0, 0), (funds[6].0, 0)], 1_900_000, 0x25);
    assert_eq!(go(&mut relay, &b2, b).verdict, GossipVerdict::Reject);
    let b3 = bad_last(&[(funds[7].0, 0)], 880_000, 0x26);
    let o = go(&mut relay, &b3, b);
    assert_eq!(o.verdict, GossipVerdict::Ignore, "B spent 1 + 2 tokens: {}", o.detail);
    // A closed connection forgets its bucket (and its orphans).
    let tracked = relay.budgets_tracked();
    let ev = relay.on_peer_disconnected(a.unwrap());
    assert!(ev.is_empty());
    assert_eq!(relay.budgets_tracked(), tracked - 1);
}

// ── MEM-6 (a): orphan transactions ───────────────────────────────────────────

/// A child that overtakes its parent is buffered, and admitted (and returned
/// for announcement) the moment the parent enters the pool. Pre-fix it was
/// dropped as "UTXO not found".
#[test]
fn mem6_orphan_is_admitted_when_its_parent_arrives() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let k = key();
    let fund = ([0x31u8; 32], 0u32, out(1_000_000, &k.spk));
    let n = node_with(&genesis, std::slice::from_ref(&fund));
    let next = admission::next_block_height(&n.dag.read());
    let mut relay = TxRelay::new();
    let peer = Some(PeerId::random());
    let t0 = Instant::now();
    let parent = signed_spend(&k, &[(fund.0, 0)], vec![out(950_000, &k.spk)]);
    let child = signed_spend(&k, &[(parent.txid(), 0)], vec![out(900_000, &[0x44; 20])]);

    let o = relay.on_gossip_tx(&n.store, &n.mempool, next, &child.txid(), &wire(&child), peer, t0, unix_now());
    assert_eq!(o.verdict, GossipVerdict::Ignore, "an orphan is never relayed");
    assert!(o.orphaned);
    assert_eq!(relay.orphans().len(), 1);
    assert!(!n.mempool.contains(&child.txid()));

    let o = relay.on_gossip_tx(&n.store, &n.mempool, next, &parent.txid(), &wire(&parent), peer, t0, unix_now());
    assert_eq!(o.verdict, GossipVerdict::Accept, "{}", o.detail);
    assert_eq!(o.orphans.admitted.iter().map(|t| t.txid()).collect::<Vec<_>>(), vec![child.txid()]);
    assert!(relay.orphans().is_empty());
    let e = n.mempool.get_entry(&child.txid()).expect("child pooled");
    assert_eq!(e.parents.iter().copied().collect::<Vec<_>>(), vec![parent.txid()]);
    n.mempool.debug_check_invariants().unwrap();
}

/// An orphan's gossip verdict is withheld (keyed by the frame's wtxid) and
/// released as Accept when exactly those bytes are admitted within
/// gossipsub's cache window, timed from the frame's ARRIVAL; every admitted
/// orphan is re-announced after the duplicate window.
#[test]
fn mem6_orphan_verdicts_are_deferred_and_released() {
    use gnb::mempool::relay::{DeferredVerdicts, DEFERRED_VERDICT_TTL, REANNOUNCE_DELAY};
    let t0 = Instant::now();
    let mut d: DeferredVerdicts<&'static str> = DeferredVerdicts::new();
    assert!(d.defer([1; 32], "frame-1", t0, t0).is_none());
    assert!(d.defer([2; 32], "frame-2", t0, t0).is_none());
    assert_eq!(d.defer([2; 32], "frame-2b", t0, t0), Some("frame-2b"), "the same bytes are pending already");
    assert_eq!(d.on_admitted(&[([0x11; 32], [1; 32])], t0 + DEFERRED_VERDICT_TTL / 2), vec!["frame-1"], "released in time");
    assert!(d.on_admitted(&[([0x22; 32], [2; 32])], t0 + DEFERRED_VERDICT_TTL).is_empty(), "frame expired: not released");
    assert!(d.due_reannouncements(t0 + DEFERRED_VERDICT_TTL).is_empty());
    assert_eq!(d.due_reannouncements(t0 + DEFERRED_VERDICT_TTL + REANNOUNCE_DELAY), vec![[0x11; 32], [0x22; 32]],
        "every admitted orphan is re-announced later");
    assert!(d.defer([3; 32], "frame-3", t0, t0).is_none());
    assert_eq!(d.prune(|_| false, t0), vec!["frame-3"], "an orphan that left the orphanage: Ignore its frame");
    assert!(d.is_empty());
}

/// Review finding (deferred TTL): the window is measured from the frame's
/// arrival at the network loop — gossipsub cached it then and shifts it out
/// `GOSSIP_HISTORY_LENGTH` heartbeats later — with two heartbeats of margin.
/// Pre-fix the stamp was taken when the (possibly backlogged) processor got
/// to the frame and the window equalled the cache lifetime, so an orphan
/// released 11-12 s after receipt was "released" into a cache that no longer
/// held it and was never relayed nor re-announced.
#[test]
fn mem6_deferred_ttl_is_measured_from_frame_arrival() {
    use gnb::mempool::relay::{DeferredVerdicts, DEFERRED_VERDICT_TTL, REANNOUNCE_DELAY};
    use gnb::network::GOSSIP_HISTORY_LENGTH;
    use std::time::Duration;
    assert!(DEFERRED_VERDICT_TTL + Duration::from_secs(2) <= Duration::from_secs(GOSSIP_HISTORY_LENGTH as u64));
    let t0 = Instant::now();
    let mut d: DeferredVerdicts<&'static str> = DeferredVerdicts::new();
    // The processor gets to the frame 5 s after it arrived.
    assert!(d.defer([1; 32], "late-frame", t0, t0 + Duration::from_secs(5)).is_none());
    // Its parent arrives 11 s after receipt: past the window, not released...
    let at = t0 + Duration::from_secs(11);
    assert!(d.on_admitted(&[([0xA1; 32], [1; 32])], at).is_empty());
    // ... but re-announced after the duplicate window.
    assert!(d.due_reannouncements(at + REANNOUNCE_DELAY - Duration::from_millis(1)).is_empty());
    assert_eq!(d.due_reannouncements(at + REANNOUNCE_DELAY), vec![[0xA1; 32]]);
    // Within the window (from arrival) it is released.
    assert!(d.defer([2; 32], "frame", t0, t0 + Duration::from_secs(5)).is_none());
    assert_eq!(d.on_admitted(&[([0xA2; 32], [2; 32])], t0 + Duration::from_secs(9)), vec!["frame"]);
    // A frame that is already too old when the processor reaches it is not
    // withheld at all: the caller answers Ignore.
    assert_eq!(d.defer([3; 32], "stale", t0, t0 + DEFERRED_VERDICT_TTL), Some("stale"));
    assert!(d.is_empty());
}

/// The orphan pool is bounded per peer and globally, expires entries, and
/// drops orphans a connected block confirmed or conflicts with.
#[test]
fn mem6_orphan_pool_is_bounded_expires_and_follows_blocks() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let n = node_with(&genesis, &[]);
    let next = admission::next_block_height(&n.dag.read());
    let limits = OrphanLimits {
        max_entries: 4, max_bytes: 1 << 20, max_entries_per_peer: 2, max_bytes_per_peer: 1 << 20, expiry_secs: 60,
    };
    let mut relay = TxRelay::with_limits(400, 20.0, limits);
    let t0 = Instant::now();
    let now = unix_now();
    let (x, y, z) = (PeerId::random(), PeerId::random(), PeerId::random());
    let gossip = |relay: &mut TxRelay, tx: &Transaction, p: PeerId, at: u64| {
        relay.on_gossip_tx(&n.store, &n.mempool, next, &tx.txid(), &wire(tx), Some(p), t0, at)
    };
    // Unsigned orphans are fine here: missing inputs is decided before any
    // signature work.
    for i in 0..5u64 {
        assert!(gossip(&mut relay, &syn(&[(ext(100 + i), 0)], &[50_000], 0x30 + i as u8, 16), x, now).orphaned);
    }
    assert_eq!(relay.orphans().peer_usage(Some(x)).0, 2, "per-peer quota");
    for i in 0..2u64 {
        gossip(&mut relay, &syn(&[(ext(200 + i), 0)], &[50_000], 0x40 + i as u8, 16), y, now);
    }
    let zo = syn(&[(ext(300), 0)], &[50_000], 0x50, 16);
    gossip(&mut relay, &zo, z, now);
    assert_eq!(relay.orphans().len(), 4, "global cap");
    assert!(relay.orphans().contains(&admission::wtxid(&zo)));
    relay.orphans().debug_check_invariants().unwrap();

    // A block spending the outpoint an orphan spends erases it.
    let blocked = relay.on_block_connected(&n.store, &n.mempool, next,
        &[coinbase("cb", 0, vec![1; 20]), syn(&[(ext(300), 0)], &[40_000], 0x51, 16)], t0, now);
    assert!(blocked.admitted.is_empty());
    assert_eq!(blocked.dropped, vec![admission::wtxid(&zo)], "reported for its deferred frame");
    assert!(!relay.orphans().contains(&admission::wtxid(&zo)), "conflicts with a confirmed spend");
    // Everything else expires.
    relay.retry_orphans(&n.store, &n.mempool, next, t0, now + 61);
    assert!(relay.orphans().is_empty(), "expired after 60 s");
}

/// A gossip origin delivered by connection `conn` whose frame is signed by a
/// FRESH author key — what one connection can do for every frame.
fn fresh_author_origin(conn: PeerId) -> InboundOrigin {
    InboundOrigin::Gossip { propagation_source: conn, author: Some(PeerId::random()), pending: None, received_at: Instant::now() }
}

/// Review finding (author keying): the orphan quotas and the signature
/// budget are keyed by the DELIVERING CONNECTION (`InboundOrigin::peer`, the
/// gossip propagation_source — what main.rs passes), never by the signed
/// gossip author, which a sender can mint per frame. One connection sending
/// 100 orphans under 100 fresh author keys keeps only its own 25-orphan
/// quota and cannot evict another connection's (heavier) orphan; the
/// re-try signature work of its orphans is bounded by ONE bucket. Pre-fix
/// every fresh key got its own quota (the global tie-break then evicted the
/// honest ~8 KB orphan first) and a fresh 400-token bucket.
#[test]
fn mem5_orphan_quotas_and_budget_follow_the_connection_not_the_author() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let k = key();
    let fund = ([0x5Au8; 32], 0u32, out(10_000_000, &k.spk));
    let fund2 = ([0x5Bu8; 32], 0u32, out(10_000_000, &k.spk));
    let n = node_with(&genesis, &[fund.clone(), fund2.clone()]);
    let next = admission::next_block_height(&n.dag.read());
    let t0 = Instant::now();
    let (honest, attacker) = (PeerId::random(), PeerId::random());

    // (a) The orphan flush.
    let mut relay = TxRelay::new();
    let parent = signed_spend(&k, &[(fund2.0, 0)], vec![out(9_000_000, &k.spk)]);
    let honest_child = signed_spend(&k, &[(parent.txid(), 0)], vec![out(8_900_000, &[0x01; 20])]);
    let origin = fresh_author_origin(honest);
    let o = relay.on_gossip_tx(&n.store, &n.mempool, next, &honest_child.txid(), &wire(&honest_child), origin.peer(), t0, unix_now());
    assert!(o.orphaned, "{}", o.detail);
    for i in 0..100u64 {
        let origin = fresh_author_origin(attacker);
        assert_eq!(origin.peer(), Some(attacker), "the relay key is the connection, never the author");
        let t = syn(&[(ext(5_000 + i), 0)], &[50_000], i as u8, 8);
        relay.on_gossip_tx(&n.store, &n.mempool, next, &t.txid(), &wire(&t), origin.peer(), t0, unix_now());
    }
    assert_eq!(relay.orphans().peer_usage(Some(attacker)).0, gnb::mempool::orphanage::MAX_ORPHANS_PER_PEER);
    assert!(relay.orphans().contains(&admission::wtxid(&honest_child)), "another connection's orphan survives");
    assert_eq!(relay.orphans().len(), 1 + gnb::mempool::orphanage::MAX_ORPHANS_PER_PEER);
    relay.orphans().debug_check_invariants().unwrap();

    // (b) The re-try signature work: five 3-input orphans with bad scripts,
    // under five fresh authors, all waiting on one cheap parent. A bucket
    // of 10 verifies three of them (9 tokens); the other two wait.
    let mut relay = TxRelay::with_limits(10, 0.0, OrphanLimits::default());
    let p = signed_spend(&k, &[(fund.0, 0)], (0..15).map(|_| out(600_000, &k.spk)).collect());
    for j in 0..5u32 {
        let t = syn(&[(p.txid(), 3 * j), (p.txid(), 3 * j + 1), (p.txid(), 3 * j + 2)], &[1_700_000], 0x60 + j as u8, 64);
        let o = relay.on_gossip_tx(&n.store, &n.mempool, next, &t.txid(), &wire(&t), fresh_author_origin(attacker).peer(), t0, unix_now());
        assert!(o.orphaned, "{}", o.detail);
    }
    let o = relay.on_gossip_tx(&n.store, &n.mempool, next, &p.txid(), &wire(&p), fresh_author_origin(honest).peer(), t0, unix_now());
    assert_eq!(o.verdict, GossipVerdict::Accept, "{}", o.detail);
    assert_eq!(o.orphans.rejected.len(), 3, "one bucket: 3 × 3 input signatures, then out of budget");
    assert!(o.orphans.rejected.iter().all(|r| r.peer == Some(attacker)));
    assert_eq!(relay.orphans().peer_usage(Some(attacker)).0, 2, "the rest wait for the connection's budget");
    // The honest connection paid nothing for its admitted parent.
    let more = signed_spend(&k, &[(p.txid(), 14)], vec![out(580_000, &[0x02; 20])]);
    let honest_after = relay.on_gossip_tx(&n.store, &n.mempool, next, &more.txid(), &wire(&more), Some(honest), t0, unix_now());
    assert_eq!(honest_after.verdict, GossipVerdict::Accept, "{}", honest_after.detail);
    // When the attacker disconnects, its orphans go (Core's EraseForPeer).
    let ev = relay.on_peer_disconnected(attacker);
    assert_eq!(ev.dropped.len(), 2);
    assert!(relay.orphans().is_empty());
}

/// Review finding (orphan re-try verdict): an orphan whose re-try proves it
/// consensus-invalid is reported, so its withheld frame gets `Reject` (the
/// delivering connection takes gossipsub's P4 penalty) — or, once the frame
/// left gossipsub's cache, the connection is penalised through the
/// application score. A valid sibling is still released as `Accept`.
/// Pre-fix the failure was only logged and the deferred verdict silently
/// pruned: invalid transactions routed through the orphan pool were free.
#[test]
fn mem6_invalid_orphan_on_retry_is_rejected_or_penalised() {
    use gnb::mempool::relay::{DeferredVerdicts, DEFERRED_VERDICT_TTL};
    let genesis = mk_genesis(unix_now() - 10_000);
    let k = key();
    let fund = ([0x6Au8; 32], 0u32, out(10_000_000, &k.spk));
    let n = node_with(&genesis, std::slice::from_ref(&fund));
    let next = admission::next_block_height(&n.dag.read());
    let mut relay = TxRelay::new();
    let (x, y) = (PeerId::random(), PeerId::random());
    let t0 = Instant::now();
    let parent = signed_spend(&k, &[(fund.0, 0)], vec![out(4_000_000, &k.spk), out(4_000_000, &k.spk)]);
    let mut bad = signed_spend(&k, &[(parent.txid(), 0)], vec![out(3_900_000, &[0x0B; 20])]);
    bad.inputs[0].script_sig[10] ^= 0xFF;
    let good = signed_spend(&k, &[(parent.txid(), 1)], vec![out(3_900_000, &[0x0C; 20])]);
    let mut on_time: DeferredVerdicts<&'static str> = DeferredVerdicts::new();
    let mut late: DeferredVerdicts<&'static str> = DeferredVerdicts::new();
    for (tx, peer, frame) in [(&bad, x, "frame-bad"), (&good, y, "frame-good")] {
        let o = relay.on_gossip_tx(&n.store, &n.mempool, next, &tx.txid(), &wire(tx), Some(peer), t0, unix_now());
        assert!(o.orphaned, "{}", o.detail);
        assert!(on_time.defer(o.wtxid, frame, t0, t0).is_none());
        assert!(late.defer(o.wtxid, frame, t0, t0).is_none());
    }
    let o = relay.on_gossip_tx(&n.store, &n.mempool, next, &parent.txid(), &wire(&parent), Some(y), t0, unix_now());
    assert_eq!(o.verdict, GossipVerdict::Accept);
    assert_eq!(o.orphans.admitted.iter().map(|t| t.txid()).collect::<Vec<_>>(), vec![good.txid()]);
    assert_eq!(o.orphans.rejected.len(), 1);
    assert_eq!((o.orphans.rejected[0].wtxid, o.orphans.rejected[0].peer), (admission::wtxid(&bad), Some(x)));

    let s = on_time.settle(&o.orphans, t0 + std::time::Duration::from_secs(1));
    let mut v = s.verdicts.clone();
    v.sort_by_key(|(f, _)| *f);
    assert_eq!(v, vec![("frame-bad", GossipVerdict::Reject), ("frame-good", GossipVerdict::Accept)]);
    assert!(s.penalize.is_empty(), "the Reject verdict carries the penalty");
    // The parent arrived after the bad frame left gossipsub's cache: no
    // verdict can reach it any more, the connection is penalised instead.
    let s = late.settle(&o.orphans, t0 + DEFERRED_VERDICT_TTL);
    assert!(s.verdicts.is_empty(), "{:?}", s.verdicts);
    assert_eq!(s.penalize, vec![x]);
    assert!(late.is_empty() && on_time.is_empty());
}

/// Review findings (txid keying of the orphanage and of the deferred
/// verdicts). C1 is the child C with a junk signature: same txid, other
/// bytes. (1) A C1 that arrives first no longer shadows C: both are
/// buffered. (2) The exact attack: the attacker's C1 frame is deferred, C1
/// is evicted by the attacker's own quota, the valid C is deferred, then
/// the parent arrives — only C's frame is released as Accept; C1's frame
/// was answered Ignore when C1 left the orphanage. Pre-fix the verdict was
/// keyed by txid: C1's frame was released as Accept, the honest node
/// forwarded an invalid transaction and its neighbours penalised it.
/// (3) With both copies buffered, the junk one is Rejected and the genuine
/// one Accepted.
#[test]
fn mem6_junk_signature_copy_neither_shadows_nor_releases_the_genuine_child() {
    use gnb::mempool::relay::DeferredVerdicts;
    let genesis = mk_genesis(unix_now() - 10_000);
    let k = key();
    let funds: Vec<_> = (0..2u8).map(|i| ([0x7Au8 + i; 32], 0u32, out(10_000_000, &k.spk))).collect();
    let n = node_with(&genesis, &funds);
    let next = admission::next_block_height(&n.dag.read());
    let limits = OrphanLimits { max_entries_per_peer: 3, ..OrphanLimits::default() };
    let mut relay = TxRelay::with_limits(400, 20.0, limits);
    let (attacker, honest) = (PeerId::random(), PeerId::random());
    let t0 = Instant::now();
    let pair = |fund: &([u8; 32], u32, gnb::core::TxOutput), tag: u8| {
        let p = signed_spend(&k, &[(fund.0, 0)], vec![out(9_000_000, &k.spk)]);
        let c = signed_spend(&k, &[(p.txid(), 0)], vec![out(8_900_000, &[tag; 20])]);
        let mut c1 = c.clone();
        let sig = &mut c1.inputs[0].script_sig;
        let mid = sig.len() / 2;
        sig[mid] ^= 0xFF;
        (p, c, c1)
    };
    let mut d: DeferredVerdicts<&'static str> = DeferredVerdicts::new();
    let verdicts: std::cell::RefCell<Vec<(&'static str, GossipVerdict)>> = Default::default();
    let gossip = |relay: &mut TxRelay, d: &mut DeferredVerdicts<&'static str>, tx: &Transaction, peer: PeerId, frame: &'static str| {
        let o = relay.on_gossip_tx(&n.store, &n.mempool, next, &tx.txid(), &wire(tx), Some(peer), t0, unix_now());
        if o.orphaned {
            assert!(d.defer(o.wtxid, frame, t0, t0).is_none());
        } else {
            verdicts.borrow_mut().push((frame, o.verdict));
        }
        verdicts.borrow_mut().extend(d.settle(&o.orphans, t0).verdicts);
        o
    };

    // (1) + (2): the attack.
    let (p, c, c1) = pair(&funds[0], 0x91);
    assert_eq!(c.txid(), c1.txid());
    assert_ne!(admission::wtxid(&c), admission::wtxid(&c1));
    assert!(gossip(&mut relay, &mut d, &c1, attacker, "F1-junk").orphaned);
    let o = gossip(&mut relay, &mut d, &c, honest, "F2-valid");
    assert!(o.orphaned, "the genuine copy is not 'already buffered': {}", o.detail);
    assert_eq!(relay.orphans().wtxids_for_txid(&c.txid()).len(), 2);
    for i in 0..3u64 {
        gossip(&mut relay, &mut d, &syn(&[(ext(7_000 + i), 0)], &[50_000], 0xE0 + i as u8, 8), attacker, "tiny");
    }
    assert!(!relay.orphans().contains(&admission::wtxid(&c1)), "evicted by its own sender's quota");
    assert_eq!(*verdicts.borrow(), vec![("F1-junk", GossipVerdict::Ignore)], "answered Ignore the moment it left");
    verdicts.borrow_mut().clear();
    gossip(&mut relay, &mut d, &p, honest, "P");
    assert!(n.mempool.contains(&c.txid()), "the genuine child entered the pool");
    assert_eq!(*verdicts.borrow(), vec![("P", GossipVerdict::Accept), ("F2-valid", GossipVerdict::Accept)],
        "only the frame carrying the admitted bytes is released");
    verdicts.borrow_mut().clear();

    // (3) Both copies buffered when the parent arrives.
    let (p, c, c1) = pair(&funds[1], 0x92);
    assert!(gossip(&mut relay, &mut d, &c1, attacker, "G1-junk").orphaned);
    assert!(gossip(&mut relay, &mut d, &c, honest, "G2-valid").orphaned);
    gossip(&mut relay, &mut d, &p, honest, "Q");
    assert!(n.mempool.contains(&c.txid()));
    assert_eq!(n.mempool.get_tx(&c.txid()).map(|t| admission::wtxid(&t)), Some(admission::wtxid(&c)));
    verdicts.borrow_mut().sort_by_key(|(f, _)| *f);
    // ("tiny": the junk copy G1 made the attacker pay with its own oldest
    // tiny orphan, whose frame is answered Ignore.)
    assert_eq!(*verdicts.borrow(), vec![("G1-junk", GossipVerdict::Reject), ("G2-valid", GossipVerdict::Accept),
        ("Q", GossipVerdict::Accept), ("tiny", GossipVerdict::Ignore)]);
    assert_eq!(relay.orphans().len(), 2, "only the attacker's two tiny orphans are left");
    relay.orphans().debug_check_invariants().unwrap();
}

/// Review finding (orphan work on the block path): a connected block
/// re-tries only the orphans waiting on one of its transactions (Core's
/// work set) — no storage read at all for 100 unrelated orphans of 100
/// inputs each (pre-fix: one UTXO read per orphan input, 10,000) — and the
/// periodic sweep spends one lookup per orphan whose first recorded parent
/// is still missing, at most `MAX_SWEEP_LOOKUPS`. An orphan above
/// `MAX_ORPHAN_INPUTS` inputs is not buffered at all.
#[test]
fn mem6_orphan_work_per_block_and_sweep_is_bounded() {
    use gnb::mempool::orphanage::MAX_ORPHAN_INPUTS;
    let genesis = mk_genesis(unix_now() - 10_000);
    let n = node_with(&genesis, &[]);
    let next = admission::next_block_height(&n.dag.read());
    let mut relay = TxRelay::new();
    let t0 = Instant::now();
    let now = unix_now();
    let wide = |base: u64, n_in: usize, tag: u8| {
        syn(&(0..n_in as u64).map(|i| (ext(base + i), 0)).collect::<Vec<_>>(), &[50_000], tag, 8)
    };
    let too_wide = wide(10_000_000, MAX_ORPHAN_INPUTS + 1, 0x01);
    let o = relay.on_gossip_tx(&n.store, &n.mempool, next, &too_wide.txid(), &wire(&too_wide), Some(PeerId::random()), t0, now);
    assert!(!o.orphaned && o.detail.contains("not buffered"), "{}", o.detail);
    for c in 0..4u64 {
        let conn = Some(PeerId::random());
        for j in 0..25u64 {
            let t = wide(1_000_000 * (c + 1) + 1_000 * j, MAX_ORPHAN_INPUTS, (c * 25 + j) as u8);
            assert!(relay.on_gossip_tx(&n.store, &n.mempool, next, &t.txid(), &wire(&t), conn, t0, now).orphaned);
        }
    }
    assert_eq!(relay.orphans().len(), 100);

    let unrelated = [coinbase("cb", 0, vec![1; 20]), syn(&[(ext(99_999_999), 0)], &[40_000], 0x77, 8)];
    let r0 = n.store.storage_reads();
    let ev = relay.on_block_connected(&n.store, &n.mempool, next, &unrelated, t0, now);
    assert_eq!(n.store.storage_reads() - r0, 0, "no orphan waits on the block: nothing is read");
    assert!(ev.is_empty());
    assert_eq!(relay.orphans().len(), 100);

    let r0 = n.store.storage_reads();
    let ev = relay.retry_orphans(&n.store, &n.mempool, next, t0, now);
    let reads = n.store.storage_reads() - r0;
    assert!(ev.is_empty());
    assert!(reads <= 100 && reads <= relay::MAX_SWEEP_LOOKUPS as u64, "{reads} reads for 100 orphans");
}

/// Review finding (work set): an orphan whose parent is confirmed by a
/// connected block is admitted by `on_block_connected` (the block's txids
/// are the work set); an unrelated orphan is left alone.
#[test]
fn mem6_block_confirming_a_parent_admits_its_waiting_orphan() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0x8Eu8; 32], 0u32, out(5_000_000, &k.spk));
    let n = node_with(&genesis, std::slice::from_ref(&fund));
    let mut relay = TxRelay::new();
    let t0 = Instant::now();
    let tx1 = signed_spend(&k, &[(fund.0, 0)], vec![out(4_900_000, &k.spk)]);
    let child = signed_spend(&k, &[(tx1.txid(), 0)], vec![out(4_800_000, &[0x41; 20])]);
    let stranger = syn(&[(ext(4_242), 0)], &[50_000], 0x42, 8);
    let next = admission::next_block_height(&n.dag.read());
    for t in [&child, &stranger] {
        assert!(relay.on_gossip_tx(&n.store, &n.mempool, next, &t.txid(), &wire(t), Some(PeerId::random()), t0, unix_now()).orphaned);
    }
    let m1 = mk_block(&n, vec![gh], vec![coinbase("m1", core::tokenomics::block_subsidy_sat(1) + 100_000, vec![0xA1; 20]), tx1.clone()]);
    accept(&n, &m1).unwrap();
    let next = admission::next_block_height(&n.dag.read());
    let ev = relay.on_block_connected(&n.store, &n.mempool, next, &m1.transactions, t0, unix_now());
    assert_eq!(ev.admitted.iter().map(|t| t.txid()).collect::<Vec<_>>(), vec![child.txid()]);
    assert!(n.mempool.contains(&child.txid()));
    assert!(relay.orphans().contains(&admission::wtxid(&stranger)));
    assert_eq!(relay.orphans().len(), 1);
}

/// Review finding (per-event work): orphan re-tries triggered by ONE event
/// stop after `MAX_ORPHAN_RETRY_INPUTS_PER_EVENT` inputs (here six 60-input
/// orphans, from six connections so no per-connection budget interferes);
/// the periodic sweep picks up the rest.
#[test]
fn mem6_orphan_retry_work_per_event_is_bounded_by_inputs() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let k = key();
    let fund = ([0x9Eu8; 32], 0u32, out(10_000_000, &k.spk));
    let n = node_with(&genesis, std::slice::from_ref(&fund));
    let next = admission::next_block_height(&n.dag.read());
    let mut relay = TxRelay::new();
    let t0 = Instant::now();
    let p = signed_spend(&k, &[(fund.0, 0)], (0..600).map(|_| out(10_000, &k.spk)).collect());
    for j in 0..10u32 {
        let ins: Vec<_> = (0..60u32).map(|i| (p.txid(), 60 * j + i)).collect();
        let t = syn(&ins, &[570_000], 0xC0 + j as u8, 8);
        assert!(relay.on_gossip_tx(&n.store, &n.mempool, next, &t.txid(), &wire(&t), Some(PeerId::random()), t0, unix_now()).orphaned);
    }
    let o = relay.on_gossip_tx(&n.store, &n.mempool, next, &p.txid(), &wire(&p), Some(PeerId::random()), t0, unix_now());
    assert_eq!(o.verdict, GossipVerdict::Accept, "{}", o.detail);
    assert_eq!(relay::MAX_ORPHAN_RETRY_INPUTS_PER_EVENT, 400);
    assert_eq!(o.orphans.rejected.len(), 6, "6 × 60 inputs fit the per-event budget, a 7th does not");
    assert_eq!(relay.orphans().len(), 4);
    let ev = relay.retry_orphans(&n.store, &n.mempool, next, t0, unix_now());
    assert_eq!(ev.rejected.len(), 4, "the sweep re-tries the rest");
    assert!(relay.orphans().is_empty());
}

// ── MEM-6 (b): chains of unconfirmed transactions ────────────────────────────

/// CPFP: a low-fee parent with a high-fee child outranks a medium-fee
/// independent transaction; the template puts the parent before its child,
/// and the mined template block is valid. Pre-fix the child could not even
/// enter the pool (its input was not in the UTXO set).
#[test]
fn mem6_cpfp_template_orders_parents_first_and_is_valid() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let k = key();
    let fp = ([0x61u8; 32], 0u32, out(1_000_000, &k.spk));
    let fx = ([0x62u8; 32], 0u32, out(1_000_000, &k.spk));
    let n = node_with(&genesis, &[fp.clone(), fx.clone()]);
    let policy = AdmissionPolicy::relay(admission::next_block_height(&n.dag.read()));
    let parent = signed_spend(&k, &[(fp.0, 0)], vec![out(975_000, &k.spk)]); // fee 25,000
    let child = signed_spend(&k, &[(parent.txid(), 0)], vec![out(775_000, &[0x63; 20])]); // fee 200,000
    let indep = signed_spend(&k, &[(fx.0, 0)], vec![out(940_000, &[0x64; 20])]); // fee 60,000
    assert!(core::check_min_fee(&parent, 25_000).is_ok(), "the parent alone is valid");
    for t in [&parent, &indep, &child] {
        admission::admit(&n.store, &n.mempool, t.clone(), &policy).expect("admitted");
    }
    // By OWN fee rate the child comes first (and would be unminable alone).
    let own: Vec<_> = n.mempool.entries_by_fee_rate().iter().map(|(t, _, _)| t.txid()).collect();
    assert_eq!(own, vec![child.txid(), indep.txid(), parent.txid()]);

    let tmpl = template::build_block_template(&n.dag, &n.store, &n.mempool, template::EXTERNAL_COINBASE_RESERVE).unwrap();
    let ids: Vec<_> = tmpl.transactions.iter().map(|(t, _)| t.txid()).collect();
    assert_eq!(ids, vec![parent.txid(), child.txid(), indep.txid()], "package first, parent before child");
    assert_eq!(tmpl.total_fees, 285_000);
    assert_eq!(tmpl.evicted, 0);
    let cb = template::miner_coinbase(tmpl.height, tmpl.subsidy + tmpl.total_fees, vec![0xCB; 20]);
    let mut block = template::assemble_block(&tmpl, cb, unix_now()).unwrap();
    while !block.validate_pow() { block.header.nonce += 1; }
    accept(&n, &block).expect("a block with an in-block chain is valid");
    assert_eq!(n.mempool.size(), 0);
}

/// The package selection itself: packages by package fee rate, budget,
/// count limit, refusal of one member, parents-first order of a diamond.
#[test]
fn mem6_select_packages_is_cpfp_and_all_or_nothing() {
    let id = |b: u8| [b; 32];
    let c = |t: u8, fee: u64, parents: &[u8]| PackageCandidate {
        txid: id(t), fee, size: 100, parents: parents.iter().map(|p| id(*p)).collect(),
    };
    let cands = vec![c(1, 100, &[]), c(2, 10_000, &[1]), c(3, 5_000, &[]), c(4, 1, &[2])];
    assert_eq!(mp::select_packages(&cands, usize::MAX, usize::MAX, |_| Ok(())),
        vec![id(1), id(2), id(3), id(4)], "{{1,2}} rate 50.5 > 3's 50");
    assert_eq!(mp::select_packages(&cands, 250, usize::MAX, |_| Ok(())), vec![id(1), id(2)], "byte budget");
    assert_eq!(mp::select_packages(&cands, usize::MAX, usize::MAX, |p| if p.contains(&id(1)) { Err(id(1)) } else { Ok(()) }),
        vec![id(3)], "a refused parent takes its descendants with it");
    assert_eq!(mp::select_packages(&cands, usize::MAX, 1, |_| Ok(())), vec![id(3)], "count limit");
    // Diamond: 7 ← 8, {7,8} ← 9 — always 7, 8, 9.
    let diamond = vec![c(9, 90_000, &[7, 8]), c(8, 1, &[7]), c(7, 1, &[])];
    let mut seen = Vec::new();
    let order = mp::select_packages(&diamond, usize::MAX, usize::MAX, |p| { seen.push(p.to_vec()); Ok(()) });
    assert_eq!(order, vec![id(7), id(8), id(9)]);
    assert_eq!(seen, vec![vec![id(7), id(8), id(9)]], "one package, parents first");
}

/// Ancestor (25) / descendant (25) / package-size limits.
#[test]
fn mem6_chain_limits_are_enforced() {
    let pool = Mempool::new();
    let mut prev = (ext(1), 0u32);
    for i in 0..mp::MAX_ANCESTORS {
        let t = syn(&[prev], &[1_000_000 - i as u64 * 1_000], i as u8, 16);
        pool.add(t.clone(), 10_000).unwrap_or_else(|e| panic!("link {i}: {e}"));
        prev = (t.txid(), 0);
    }
    let too_deep = syn(&[prev], &[500_000], 0xFE, 16);
    assert!(matches!(pool.add(too_deep, 10_000), Err(MempoolError::ChainLimit(_))));
    pool.debug_check_invariants().unwrap();

    let pool = Mempool::new();
    let parent = syn(&[(ext(2), 0)], &[10_000; 30], 0x01, 16);
    pool.add(parent.clone(), 10_000).unwrap();
    for j in 0..(mp::MAX_DESCENDANTS - 1) as u32 {
        pool.add(syn(&[(parent.txid(), j)], &[9_000], 0x02, 16 + j as usize), 10_000).unwrap();
    }
    let one_more = syn(&[(parent.txid(), 29)], &[9_000], 0x03, 16);
    assert!(matches!(pool.add(one_more, 10_000), Err(MempoolError::ChainLimit(_))), "descendant limit");

    let pool = Mempool::new();
    let mut prev = (ext(3), 0u32);
    let mut refused = None;
    for i in 0..5u8 {
        let t = syn(&[prev], &[1_000_000], i, 150_000);
        match pool.add(t.clone(), 200_000) {
            Ok(_) => prev = (t.txid(), 0),
            Err(e) => { refused = Some((i, e)); break; }
        }
    }
    let (i, e) = refused.expect("a 500 kB package limit");
    assert_eq!(i, 3, "3 × 150 kB fit, the 4th does not");
    assert!(matches!(e, MempoolError::ChainLimit(_)), "{e}");
}

/// Removal is closed under descendants, except for confirmation (children
/// of a confirmed parent stay and are unlinked).
#[test]
fn mem6_removals_take_descendants_except_confirmation() {
    let now = Arc::new(AtomicU64::new(1_000_000));
    let build = |now: &Arc<AtomicU64>| {
        let pool = Mempool::with_clock(Box::new(TestClock(now.clone())));
        let p = syn(&[(ext(10), 0)], &[900_000], 0x01, 16);
        pool.add(p.clone(), 10_000).unwrap();
        now.fetch_add(100, Ordering::SeqCst);
        let c = syn(&[(p.txid(), 0)], &[800_000], 0x02, 16);
        pool.add(c.clone(), 10_000).unwrap();
        let g = syn(&[(c.txid(), 0)], &[700_000], 0x03, 16);
        pool.add(g.clone(), 10_000).unwrap();
        let x = syn(&[(ext(11), 0)], &[900_000], 0x04, 16);
        pool.add(x.clone(), 10_000).unwrap();
        (pool, p, c, g, x)
    };
    let ids = |v: &[&Transaction]| v.iter().map(|t| t.txid()).collect::<BTreeSet<_>>();

    let (pool, p, c, g, x) = build(&now);
    pool.remove_confirmed(&[p.txid()]);
    assert!(pool.contains(&c.txid()) && pool.contains(&g.txid()), "children of a confirmed parent stay");
    assert!(pool.get_entry(&c.txid()).unwrap().parents.is_empty());
    pool.debug_check_invariants().unwrap();

    let (pool, p, c, g, x2) = build(&now);
    let swept: BTreeSet<_> = pool.remove_conflicts(&[(ext(10), 0)]).into_iter().collect();
    assert_eq!(swept, ids(&[&p, &c, &g]), "conflict sweep takes the descendants");
    assert!(pool.contains(&x2.txid()));
    pool.debug_check_invariants().unwrap();

    let (pool, p, c, g, _) = build(&now);
    assert_eq!(pool.retain_valid(|e| e.tx.txid() != p.txid()), 3, "re-validation takes the descendants");
    assert!(!pool.contains(&c.txid()) && !pool.contains(&g.txid()));

    let (pool, p, c, g, _) = build(&now);
    assert!(pool.remove(&c.txid()));
    assert!(pool.contains(&p.txid()) && !pool.contains(&g.txid()), "remove takes the descendants only");

    // Expiry: only the parent is old, the whole chain goes.
    let (pool, p, c, g, x3) = build(&now);
    now.fetch_add(mp::MEMPOOL_EXPIRY_SECS, Ordering::SeqCst); // p is now 100 s older than the rest
    assert_eq!(pool.expire_older_than(mp::MEMPOOL_EXPIRY_SECS + 50), 3);
    assert!(!pool.contains(&p.txid()) && !pool.contains(&c.txid()) && !pool.contains(&g.txid()));
    assert!(pool.contains(&x3.txid()));
    pool.debug_check_invariants().unwrap();
    let _ = x;
}

/// A child whose parent existed only on the abandoned chain is dropped when
/// that parent cannot come back (its input is double-spent by the new chain);
/// the pool and the next template stay valid.
#[test]
fn mem6_reorg_drops_child_whose_parent_cannot_return() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0x8Fu8; 32], 0u32, out(5_000_000, &k.spk));
    let n = node_with(&genesis, std::slice::from_ref(&fund));
    let sub = core::tokenomics::block_subsidy_sat(1);
    let tx1 = signed_spend(&k, &[(fund.0, 0)], vec![out(4_900_000, &k.spk)]);
    let m1 = mk_block(&n, vec![gh], vec![coinbase("m1", sub + 100_000, vec![0xA1; 20]), tx1.clone()]);
    accept(&n, &m1).unwrap();
    let p = signed_spend(&k, &[(tx1.txid(), 0)], vec![out(4_800_000, &[0x31; 20])]);
    let policy = AdmissionPolicy::relay(admission::next_block_height(&n.dag.read()));
    admission::admit(&n.store, &n.mempool, p.clone(), &policy).unwrap();

    let tx1b = signed_spend(&k, &[(fund.0, 0)], vec![out(4_890_000, &[0xB1; 20])]);
    let f1 = mk_block_where(&n, vec![gh], vec![coinbase("f1", sub + 110_000, vec![0xF1; 20]), tx1b.clone()],
        |h| *h < m1.block_hash());
    accept(&n, &f1).unwrap();
    let f2 = empty_child(&n, f1.block_hash(), "f2");
    accept(&n, &f2).unwrap();
    assert_eq!(sel_tip(&n), Some(f2.block_hash()));
    assert!(!n.mempool.contains(&tx1.txid()), "tx1 conflicts with the new chain");
    assert!(!n.mempool.contains(&p.txid()), "its child left with it");
    n.mempool.debug_check_invariants().unwrap();
    let tmpl = template::build_block_template(&n.dag, &n.store, &n.mempool, template::EXTERNAL_COINBASE_RESERVE).unwrap();
    assert!(tmpl.transactions.is_empty());
}

/// After a reorg that re-injects a parent, the re-linked child is mined in
/// the next template, parent first, and the block is valid.
#[test]
fn mem6_reorg_relinks_child_and_template_mines_parent_first() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0x8Cu8; 32], 0u32, out(5_000_000, &k.spk));
    let n = node_with(&genesis, std::slice::from_ref(&fund));
    let sub = core::tokenomics::block_subsidy_sat(1);
    let tx1 = signed_spend(&k, &[(fund.0, 0)], vec![out(4_900_000, &k.spk)]);
    let m1 = mk_block(&n, vec![gh], vec![coinbase("m1", sub + 100_000, vec![0xA1; 20]), tx1.clone()]);
    accept(&n, &m1).unwrap();
    let p = signed_spend(&k, &[(tx1.txid(), 0)], vec![out(4_800_000, &[0x31; 20])]);
    let policy = AdmissionPolicy::relay(admission::next_block_height(&n.dag.read()));
    admission::admit(&n.store, &n.mempool, p.clone(), &policy).unwrap();
    let f1 = mk_block_where(&n, vec![gh], vec![coinbase("f1", sub, vec![0xF1; 20])], |h| *h < m1.block_hash());
    accept(&n, &f1).unwrap();
    let f2 = empty_child(&n, f1.block_hash(), "f2");
    accept(&n, &f2).unwrap();
    assert_eq!(n.mempool.ancestors_of(&p.txid()).into_iter().collect::<Vec<_>>(), vec![tx1.txid()]);

    let tmpl = template::build_block_template(&n.dag, &n.store, &n.mempool, template::EXTERNAL_COINBASE_RESERVE).unwrap();
    let ids: Vec<_> = tmpl.transactions.iter().map(|(t, _)| t.txid()).collect();
    assert_eq!(ids, vec![tx1.txid(), p.txid()]);
    let cb = template::miner_coinbase(tmpl.height, tmpl.subsidy + tmpl.total_fees, vec![0xCB; 20]);
    let mut block = template::assemble_block(&tmpl, cb, unix_now()).unwrap();
    while !block.validate_pow() { block.header.nonce += 1; }
    accept(&n, &block).expect("parent and child mined together");
    assert_eq!(n.mempool.size(), 0);
    // NET-12: the real acceptance pipeline (extensions and a reorg) kept the
    // explorer aggregates equal to a full recomputation.
    assert_eq!(n.store.aggregate_snapshot().unwrap(), n.store.recompute_aggregates(&AtomicBool::new(false)).unwrap());
    assert_eq!(n.store.chain_totals().unwrap().blocks, 3, "f1, f2 and the template block");
}

/// Review finding (reorg re-injection order): a reorg that disconnects TWO
/// blocks — the parent `tx1` confirmed in m1 and its child `p` confirmed in
/// m2 — re-admits both, parent first, as an in-pool chain; the next template
/// mines them in that order. Pre-fix the disconnected blocks were re-admitted
/// tip-first: `p` came first, failed with "missing inputs" (tx1 was neither
/// in the UTXO set nor pooled yet) and was lost.
#[test]
fn mem6_reorg_reinjects_a_cross_block_chain_parents_first() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0x8Du8; 32], 0u32, out(5_000_000, &k.spk));
    let n = node_with(&genesis, std::slice::from_ref(&fund));
    let tx1 = signed_spend(&k, &[(fund.0, 0)], vec![out(4_900_000, &k.spk)]);
    let m1 = mk_block(&n, vec![gh], vec![coinbase("m1", core::tokenomics::block_subsidy_sat(1) + 100_000, vec![0xA1; 20]), tx1.clone()]);
    accept(&n, &m1).unwrap();
    let p = signed_spend(&k, &[(tx1.txid(), 0)], vec![out(4_800_000, &[0x32; 20])]);
    let m2 = mk_block(&n, vec![m1.block_hash()], vec![coinbase("m2", core::tokenomics::block_subsidy_sat(2) + 100_000, vec![0xA2; 20]), p.clone()]);
    accept(&n, &m2).unwrap();
    assert_eq!(sel_tip(&n), Some(m2.block_hash()));
    assert_eq!(n.mempool.size(), 0);

    // A heavier fork from genesis that carries neither transaction.
    let f1 = empty_child(&n, gh, "f1");
    accept(&n, &f1).unwrap();
    let f2 = empty_child(&n, f1.block_hash(), "f2");
    accept(&n, &f2).unwrap();
    let f3 = empty_child(&n, f2.block_hash(), "f3");
    accept(&n, &f3).unwrap();
    assert_eq!(sel_tip(&n), Some(f3.block_hash()), "the fork won: m2 and m1 were disconnected");

    assert!(n.mempool.contains(&tx1.txid()), "the parent is back in the pool");
    assert!(n.mempool.contains(&p.txid()), "the child confirmed one block later is back too");
    assert_eq!(n.mempool.ancestors_of(&p.txid()).into_iter().collect::<Vec<_>>(), vec![tx1.txid()]);
    n.mempool.debug_check_invariants().unwrap();
    let tmpl = template::build_block_template(&n.dag, &n.store, &n.mempool, template::EXTERNAL_COINBASE_RESERVE).unwrap();
    let ids: Vec<_> = tmpl.transactions.iter().map(|(t, _)| t.txid()).collect();
    assert_eq!(ids, vec![tx1.txid(), p.txid()], "parent before child");
}

/// The re-injection order itself: oldest disconnected block first, block
/// order inside each block, coinbases skipped.
#[test]
fn mem6_disconnected_txs_are_ordered_oldest_block_first() {
    let mk = |tag: &str, txs: Vec<Transaction>| Block {
        header: BlockHeader { version: 1, parents: vec![[0; 32]], merkle_root: MerkleRoot::ZERO, timestamp: 0, bits: 0, nonce: 0 },
        transactions: std::iter::once(coinbase(tag, 1, vec![1; 20])).chain(txs).collect(),
        blue_score: 0, height: 0, shielded_transactions: vec![],
    };
    let (a, b, c, d) = (syn(&[(ext(1), 0)], &[9], 1, 4), syn(&[(ext(2), 0)], &[9], 2, 4), syn(&[(ext(3), 0)], &[9], 3, 4), syn(&[(ext(4), 0)], &[9], 4, 4));
    // `disconnected` is tip-first: [B2 (c, d), B1 (a, b)].
    let outcome = reorg::ConnectOutcome { disconnected: vec![mk("b2", vec![c.clone(), d.clone()]), mk("b1", vec![a.clone(), b.clone()])], connected: vec![] };
    let ids: Vec<_> = outcome.disconnected_txs_oldest_first().iter().map(|t| t.txid()).collect();
    assert_eq!(ids, vec![a.txid(), b.txid(), c.txid(), d.txid()]);
}

/// Eviction by DESCENDANT score: a low-fee parent whose child pays a lot is
/// protected (CPFP); the cheapest independent transaction is evicted. With
/// own-rate eviction the parent went first and orphaned its child in the pool.
#[test]
fn mem6_eviction_uses_descendant_score() {
    let pool = Mempool::new();
    let p = syn(&[(ext(1), 0)], &[900_000], 0x01, 16);
    let size = p.actual_size() as u64;
    pool.add(p.clone(), 2 * size).unwrap(); // own rate 2 sat/B
    let c = syn(&[(p.txid(), 0)], &[800_000], 0x02, 16);
    pool.add(c.clone(), 1_000 * size).unwrap(); // package rate ≈ 500 sat/B
    let mut cheapest = None;
    let mut i = 0u64;
    while pool.size() < 50_000 {
        let f = syn(&[(ext(1_000 + i), 0)], &[900_000], 0x03, 16);
        let fs = f.actual_size() as u64;
        if cheapest.is_none() { cheapest = Some(f.txid()); }
        pool.add(f, (10 + i % 50) * fs + i / 50).unwrap(); // 10..60 sat/B, first one cheapest
        i += 1;
    }
    let newcomer = syn(&[(ext(999_999), 0)], &[900_000], 0x04, 16);
    let ns = newcomer.actual_size() as u64;
    pool.add(newcomer.clone(), 100 * ns).unwrap();
    assert!(pool.contains(&p.txid()) && pool.contains(&c.txid()), "the CPFP-protected parent survives");
    assert!(!pool.contains(&cheapest.unwrap()), "the lowest descendant score was evicted");
    assert!(pool.contains(&newcomer.txid()));
    assert!(pool.rolling_min_fee_rate() >= 11, "rolling minimum raised to the evicted rate + 1");
    pool.debug_check_invariants().unwrap();
}

// ── MEM-6 (c): full-RBF ──────────────────────────────────────────────────────

/// BIP125 rules 2-6 at the mempool level (synthetic transactions).
#[test]
fn mem6_full_rbf_rules() {
    let setup = || {
        let pool = Mempool::new();
        let a = syn(&[(ext(1), 0)], &[900_000], 0x01, 16);
        pool.add(a.clone(), 10_000).unwrap();
        let a1 = syn(&[(a.txid(), 0)], &[800_000], 0x02, 16);
        pool.add(a1.clone(), 5_000).unwrap();
        (pool, a, a1)
    };
    let (pool, a, a1) = setup();
    // The raw add is first-seen.
    let r = syn(&[(ext(1), 0)], &[700_000], 0x03, 16);
    let rs = r.actual_size() as u64;
    assert!(matches!(pool.add(r.clone(), 1_000_000), Err(MempoolError::Conflict { .. })));
    // Rule 3: at least the 15,000 sat evicted.
    let e = pool.add_with_replacement(r.clone(), 14_999).unwrap_err().to_string();
    assert!(e.contains("below the 15000"), "{e}");
    // Rule 4: plus the incremental relay fee on its own size.
    let e = pool.add_with_replacement(r.clone(), 15_000 + rs - 1).unwrap_err().to_string();
    assert!(e.contains("incremental relay fee"), "{e}");
    pool.debug_check_invariants().unwrap();
    // Success: both the conflict and its descendant are evicted.
    let out = pool.add_with_replacement(r.clone(), 15_000 + rs).unwrap();
    assert_eq!(out.replaced.into_iter().collect::<BTreeSet<_>>(), [a.txid(), a1.txid()].into_iter().collect());
    assert!(pool.contains(&r.txid()) && !pool.contains(&a.txid()) && !pool.contains(&a1.txid()));
    pool.debug_check_invariants().unwrap();

    // Rule 6: a higher absolute fee but a LOWER fee rate is refused.
    let (pool, _, _) = setup();
    let fat = syn(&[(ext(1), 0)], &[700_000], 0x04, 100_000);
    let e = pool.add_with_replacement(fat, 150_000).unwrap_err().to_string();
    assert!(e.contains("fee rate does not exceed"), "{e}");

    // Rule 2: no new unconfirmed input.
    let (pool, _, _) = setup();
    let u = syn(&[(ext(2), 0)], &[900_000], 0x05, 16);
    pool.add(u.clone(), 10_000).unwrap();
    let r2 = syn(&[(ext(1), 0), (u.txid(), 0)], &[700_000], 0x06, 16);
    let e = pool.add_with_replacement(r2, 1_000_000).unwrap_err().to_string();
    assert!(e.contains("new unconfirmed input"), "{e}");

    // A replacement may not spend what it evicts.
    let (pool, a, _) = setup();
    let r3 = syn(&[(ext(1), 0), (a.txid(), 1)], &[700_000], 0x07, 16);
    let e = pool.add_with_replacement(r3, 1_000_000).unwrap_err().to_string();
    assert!(e.contains("which it would evict"), "{e}");

    // Rule 5: at most 100 evictions (5 roots × 25 = 125 here).
    let pool = Mempool::new();
    let mut roots = Vec::new();
    for r in 0..5u64 {
        let root = syn(&[(ext(100 + r), 0)], &[10_000; 30], r as u8, 16);
        pool.add(root.clone(), 10_000).unwrap();
        for j in 0..24u32 {
            pool.add(syn(&[(root.txid(), j)], &[9_000], 0x40 + r as u8, 16 + j as usize), 10_000).unwrap();
        }
        roots.push(ext(100 + r));
    }
    assert_eq!(pool.size(), 125);
    let big = syn(&roots.iter().map(|t| (*t, 0)).collect::<Vec<_>>(), &[1_000], 0x77, 16);
    let e = pool.add_with_replacement(big, 100_000_000).unwrap_err().to_string();
    assert!(e.contains("would evict 125"), "{e}");
    assert_eq!(pool.size(), 125, "nothing evicted");
    pool.debug_check_invariants().unwrap();
}

/// Full-RBF end to end through the shared admission function (and so RPC
/// `sendrawtransaction`); a failed replacement is relay policy (Ignore).
#[test]
fn mem6_full_rbf_through_admission_and_relay() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let k = key();
    let fund = ([0x91u8; 32], 0u32, out(1_000_000, &k.spk));
    let n = node_with(&genesis, std::slice::from_ref(&fund));
    let next = admission::next_block_height(&n.dag.read());
    let policy = AdmissionPolicy::relay(next);
    let a = signed_spend(&k, &[(fund.0, 0)], vec![out(970_000, &[0x01; 20])]); // fee 30,000
    admission::admit(&n.store, &n.mempool, a.clone(), &policy).unwrap();
    // Too small a bump: rule 4.
    let low = signed_spend(&k, &[(fund.0, 0)], vec![out(969_000, &[0x02; 20])]); // fee 31,000
    let err = admission::admit(&n.store, &n.mempool, low.clone(), &policy).unwrap_err();
    assert!(matches!(err, AdmissionError::Replacement(_)), "{err}");
    assert_eq!(relay::verdict_for_admission_error(&err), GossipVerdict::Ignore);
    assert!(n.mempool.contains(&a.txid()));
    // A proper bump replaces A.
    let b = signed_spend(&k, &[(fund.0, 0)], vec![out(940_000, &[0x03; 20])]); // fee 60,000
    let mut relay = TxRelay::new();
    let o = relay.on_gossip_tx(&n.store, &n.mempool, next, &b.txid(), &wire(&b), Some(PeerId::random()), Instant::now(), unix_now());
    assert_eq!(o.verdict, GossipVerdict::Accept, "{}", o.detail);
    assert!(n.mempool.contains(&b.txid()) && !n.mempool.contains(&a.txid()));
    n.mempool.debug_check_invariants().unwrap();
}

// ── NET-12: incremental aggregates ───────────────────────────────────────────

/// A UTXO set: outpoint → output.
type UtxoSet = BTreeMap<([u8; 32], u32), TxOutput>;
/// Blocks with the UTXO set after each.
type Branch = Vec<(Block, UtxoSet)>;

/// Model of a node's applied chain for the NET-12 property test.
struct Sim {
    _tmp: tempfile::TempDir,
    store: Arc<Storage>,
    base: UtxoSet,
    /// Connected blocks with the UTXO state after each.
    chain: Branch,
    /// A disconnected branch: (chain length it forks at, its blocks + states).
    alt: Option<(usize, Branch)>,
    rng: Rng,
    serial: u64,
    /// Plans that both disconnected and connected blocks.
    reorgs: usize,
}

const ADDRS: u8 = 9;

impl Sim {
    fn new(seed: u64) -> Self {
        let tmp = tempfile::TempDir::new().unwrap();
        let store = Arc::new(Storage::open(&tmp.path().join("db")).unwrap());
        assert!(store.aggregates_ready(), "a fresh database is complete from the start");
        let mut sim = Sim { _tmp: tmp, store, base: BTreeMap::new(), chain: Vec::new(), alt: None, rng: Rng(seed), serial: 0, reorgs: 0 };
        for i in 0..12u64 {
            let o = sim.random_output();
            sim.store.put_utxo(&ext(50_000 + i), 0, &o).unwrap();
            sim.base.insert((ext(50_000 + i), 0), o);
        }
        sim
    }

    fn random_output(&mut self) -> TxOutput {
        let a = self.rng.below(ADDRS as u64) as u8;
        // Some non-20-byte scripts: never holders.
        let spk = if a == ADDRS - 1 { vec![0xEE; 25] } else { vec![a; 20] };
        let value = match self.rng.below(4) {
            0 => 0,
            1 => self.rng.below(100_000_000),
            2 => 100_000_000 + self.rng.below(10_000_000_000),
            _ => self.rng.below(5_000_000_000_000),
        };
        TxOutput { value, script_pubkey: spk }
    }

    fn state(&self) -> &BTreeMap<([u8; 32], u32), TxOutput> {
        self.chain.last().map(|(_, s)| s).unwrap_or(&self.base)
    }

    fn tip_hash(&self) -> [u8; 32] {
        self.chain.last().map(|(b, _)| b.block_hash()).unwrap_or([0u8; 32])
    }

    /// A block on top of the current state: a coinbase and up to three
    /// spends of random current UTXOs.
    fn build(&mut self) -> (Block, BTreeMap<([u8; 32], u32), TxOutput>) {
        self.serial += 1;
        let height = self.chain.len() as u64 + 1;
        let mut state = self.state().clone();
        let mut txs = vec![Transaction {
            version: 1,
            inputs: vec![TxInput { prev_txid: [0; 32], prev_index: u32::MAX, script_sig: format!("sim{}", self.serial).into_bytes(), sequence: u32::MAX }],
            outputs: vec![self.random_output()],
            locktime: 0,
        }];
        for _ in 0..self.rng.below(4) {
            let keys: Vec<_> = state.keys().copied().collect();
            if keys.is_empty() { break; }
            let n_in = 1 + self.rng.below(2) as usize;
            let mut inputs = Vec::new();
            for _ in 0..n_in {
                let k = keys[self.rng.below(keys.len() as u64) as usize];
                if !inputs.contains(&k) { inputs.push(k); }
            }
            let outs: Vec<TxOutput> = (0..1 + self.rng.below(3)).map(|_| self.random_output()).collect();
            let tx = Transaction {
                version: 1,
                inputs: inputs.iter().map(|(t, i)| TxInput { prev_txid: *t, prev_index: *i, script_sig: vec![self.serial as u8; 8], sequence: u32::MAX }).collect(),
                outputs: outs,
                locktime: self.serial as u32,
            };
            for k in &inputs { state.remove(k); }
            txs.push(tx);
        }
        for t in &txs {
            let id = t.txid();
            for (j, o) in t.outputs.iter().enumerate() {
                state.insert((id, j as u32), o.clone());
            }
        }
        let block = Block {
            header: BlockHeader {
                version: 1, parents: vec![self.tip_hash()], merkle_root: MerkleRoot::ZERO,
                timestamp: 1_000 + height * 300, bits: core::POW_LIMIT_BITS, nonce: self.rng.next(),
            },
            transactions: txs,
            blue_score: height,
            height,
            shielded_transactions: vec![],
        };
        self.store.put_block_body(&block).unwrap();
        (block, state)
    }

    fn connect(&self, plan: &ReorgPlan, new_tip: [u8; 32]) {
        let validate = |_: &dyn UtxoView, _: &Block| -> Result<(), String> { Ok(()) };
        let stage = |st: &Storage, b: &mut rocksdb::WriteBatch| -> Result<(), String> {
            st.stage_meta(b, "tip_hash", &new_tip).map_err(|e| e.to_string())
        };
        reorg::connect_plan(&self.store, plan, &ConnectHooks { validate: &validate, stage_extra: &stage }).expect("connect");
    }

    fn extend(&mut self) {
        let (b, s) = self.build();
        let plan = ReorgPlan { lca: self.tip_hash(), to_rollback: vec![], to_apply: vec![b.block_hash()] };
        self.connect(&plan, b.block_hash());
        self.chain.push((b, s));
    }

    fn rollback(&mut self, k: usize) {
        let k = k.min(self.chain.len());
        if k == 0 { return; }
        let keep = self.chain.len() - k;
        let to_rollback: Vec<_> = self.chain[keep..].iter().rev().map(|(b, _)| b.block_hash()).collect();
        let gone: Vec<_> = self.chain.drain(keep..).collect();
        let plan = ReorgPlan { lca: self.tip_hash(), to_rollback, to_apply: vec![] };
        self.connect(&plan, self.tip_hash());
        self.alt = Some((keep, gone));
    }

    /// Reorg back onto the stored alternative branch.
    fn switch(&mut self) {
        let Some((fork, branch)) = self.alt.take() else { return };
        if fork > self.chain.len() { return; }
        let to_rollback: Vec<_> = self.chain[fork..].iter().rev().map(|(b, _)| b.block_hash()).collect();
        let to_apply: Vec<_> = branch.iter().map(|(b, _)| b.block_hash()).collect();
        let new_tip = branch.last().map(|(b, _)| b.block_hash());
        let gone: Vec<_> = self.chain.drain(fork..).collect();
        let lca = self.tip_hash();
        if !to_rollback.is_empty() && !to_apply.is_empty() {
            self.reorgs += 1;
        }
        self.connect(&ReorgPlan { lca, to_rollback, to_apply }, new_tip.unwrap_or(lca));
        self.chain.extend(branch);
        if !gone.is_empty() { self.alt = Some((fork, gone)); }
    }

    /// The aggregates the model predicts.
    fn expected_holders(&self) -> BTreeMap<[u8; 20], HolderEntry> {
        let mut m: BTreeMap<[u8; 20], HolderEntry> = BTreeMap::new();
        for o in self.state().values() {
            if let Ok(a) = <[u8; 20]>::try_from(o.script_pubkey.as_slice()) {
                let e = m.entry(a).or_default();
                e.balance += o.value;
                e.utxos += 1;
            }
        }
        m
    }

    fn check(&self, step: usize) {
        let stored: AggregateSnapshot = self.store.aggregate_snapshot().unwrap();
        let recomputed = self.store.recompute_aggregates(&AtomicBool::new(false)).unwrap();
        assert_eq!(stored, recomputed, "step {step}: incremental aggregates != full recomputation");
        assert_eq!(stored.holders, self.expected_holders(), "step {step}: holders != model");
        assert_eq!(stored.chain.blocks, self.chain.len() as u64, "step {step}");
        assert_eq!(stored.chain.txs, self.chain.iter().map(|(b, _)| b.transactions.len() as u64).sum::<u64>(), "step {step}");
        assert!(stored.rich_order.windows(2).all(|w| (w[0].1.balance, std::cmp::Reverse(w[0].0)) >= (w[1].1.balance, std::cmp::Reverse(w[1].0))));
    }
}

/// NET-12: after random sequences of connects, rollbacks and reorgs (all in
/// `reorg::connect_plan` batches), the incremental aggregates equal a full
/// recomputation from the UTXO set and the undo records — and the model.
#[test]
fn net12_incremental_aggregates_equal_full_recomputation_after_random_reorgs() {
    for seed in [1u64, 2, 3, 4] {
        let mut sim = Sim::new(0xA66 ^ seed);
        sim.check(0);
        for step in 1..=60 {
            match sim.rng.below(10) {
                0..=5 => sim.extend(),
                6 | 7 => { let k = 1 + sim.rng.below(3) as usize; sim.rollback(k) }
                _ => sim.switch(),
            }
            sim.check(step);
        }
        assert!(sim.reorgs >= 2, "seed {seed}: the sequence must include real reorgs ({})", sim.reorgs);
    }
}

/// NET-12: the direct (non-batched) mutation paths keep the aggregates
/// consistent too: `put_utxo` overwrites, `delete_utxo`, the legacy
/// `apply_block_utxo_mutations` / `rollback_block`, `clear_utxos`.
#[test]
fn net12_direct_paths_keep_aggregates_consistent() {
    let mut sim = Sim::new(77);
    let st = sim.store.clone();
    let check = |st: &Storage| {
        assert_eq!(st.aggregate_snapshot().unwrap(), st.recompute_aggregates(&AtomicBool::new(false)).unwrap());
    };
    st.put_utxo(&ext(50_000), 0, &TxOutput { value: 7, script_pubkey: vec![3; 20] }).unwrap(); // overwrite
    check(&st);
    st.delete_utxo(&ext(50_001), 0).unwrap();
    st.delete_utxo(&ext(1), 0).unwrap(); // absent: no-op
    check(&st);
    let (b, _) = sim.build();
    reorg::apply_block_utxo_mutations(&st, &b).unwrap();
    check(&st);
    assert_eq!(st.chain_totals().unwrap().blocks, 1);
    st.rollback_block(&b.block_hash()).unwrap();
    check(&st);
    assert_eq!(st.chain_totals().unwrap().blocks, 0);
    st.clear_utxos().unwrap();
    check(&st);
    assert!(st.aggregate_snapshot().unwrap().holders.is_empty());
}

/// A pre-NET-12 database (no version marker, aggregates missing) is not
/// served until rebuilt; the start-up rebuild makes it equal to a full
/// recomputation and every later connect keeps it so.
#[test]
fn net12_preexisting_database_is_rebuilt_at_startup() {
    let mut sim = Sim::new(5);
    for _ in 0..8 { sim.extend(); }
    let path = sim._tmp.path().join("db");
    // Simulate an old database: drop every aggregate key.
    {
        let db = sim.store.db();
        let cf = db.cf_handle("meta").unwrap();
        let keys: Vec<Vec<u8>> = db.iterator_cf(cf, rocksdb::IteratorMode::Start)
            .filter_map(|r| r.ok()).map(|(k, _)| k.to_vec()).filter(|k| k.starts_with(b"agg/")).collect();
        for k in keys { db.delete_cf(cf, k).unwrap(); }
    }
    let Sim { _tmp, store, chain, base, rng, serial, .. } = sim;
    drop(store);
    let store = Arc::new(Storage::open(&path).unwrap());
    assert!(!store.aggregates_ready(), "a non-empty database without the marker needs a rebuild");
    assert!(analytics::supply_distribution_bounded(&store).is_err(), "never served incomplete");
    assert!(store.ensure_aggregates().unwrap());
    assert!(store.aggregates_ready());
    let mut sim = Sim { _tmp, store, base, chain, alt: None, rng, serial, reorgs: 0 };
    sim.check(0);
    sim.extend();
    sim.rollback(2);
    sim.check(1);
}

/// Every `agg/*` key and value in CF_META (what a binary that does not know
/// the aggregates leaves untouched).
fn agg_keys(store: &Storage) -> Vec<(Vec<u8>, Vec<u8>)> {
    let db = store.db();
    let cf = db.cf_handle("meta").unwrap();
    db.iterator_cf(cf, rocksdb::IteratorMode::Start)
        .filter_map(|r| r.ok())
        .filter(|(k, _)| k.starts_with(b"agg/"))
        .map(|(k, v)| (k.to_vec(), v.to_vec()))
        .collect()
}

/// Put back `saved` as the only `agg/*` keys: the state a release without
/// the aggregates leaves after moving the chain.
fn restore_agg_keys(store: &Storage, saved: &[(Vec<u8>, Vec<u8>)]) {
    let db = store.db();
    let cf = db.cf_handle("meta").unwrap();
    for (k, _) in agg_keys(store) {
        db.delete_cf(cf, k).unwrap();
    }
    for (k, v) in saved {
        db.put_cf(cf, k, v).unwrap();
    }
}

/// Reopen the store of `sim` (a node restart).
fn reopen(sim: Sim) -> Sim {
    let path = sim._tmp.path().join("db");
    let Sim { _tmp, store, chain, base, rng, serial, .. } = sim;
    drop(store);
    let store = Arc::new(Storage::open(&path).unwrap());
    Sim { _tmp, store, base, chain, alt: None, rng, serial, reorgs: 0 }
}

/// Review finding (version marker only): the chain moved under aggregates
/// that a release without them left untouched — a downgrade then a
/// re-upgrade. The version marker survives, so pre-fix the stale rich list,
/// tiers and chain totals were served indefinitely. Start-up now compares
/// the stored block count and connected-set fingerprint with the undo
/// records and rebuilds on a mismatch — including a reorg that leaves the
/// block count unchanged, and a P4 database written before the fingerprint
/// existed. An untouched database is not rebuilt.
#[test]
fn net12_aggregates_left_stale_by_another_binary_are_rebuilt_at_startup() {
    let mut sim = Sim::new(21);
    for _ in 0..6 { sim.extend(); }
    sim.check(0);
    let mut sim = reopen(sim);
    assert!(!sim.store.ensure_aggregates().unwrap(), "current aggregates are not rebuilt");
    assert!(sim.store.aggregates_match_connected_chain().unwrap());

    // (a) The old binary connected three blocks and rolled one back.
    let saved = agg_keys(&sim.store);
    for _ in 0..3 { sim.extend(); }
    sim.rollback(1);
    restore_agg_keys(&sim.store, &saved);
    let mut sim = reopen(sim);
    assert!(sim.store.aggregates_ready(), "the marker survived: the bug's precondition");
    assert_ne!(sim.store.aggregate_snapshot().unwrap(), sim.store.recompute_aggregates(&AtomicBool::new(false)).unwrap(),
        "stale aggregates");
    assert!(!sim.store.aggregates_match_connected_chain().unwrap());
    assert!(sim.store.ensure_aggregates().unwrap(), "rebuilt at start-up");
    sim.check(1);
    sim.extend();
    sim.check(2);

    // (b) Same block count, different connected set (a one-block reorg).
    let saved = agg_keys(&sim.store);
    let blocks = sim.chain.len();
    sim.rollback(1);
    sim.extend();
    assert_eq!(sim.chain.len(), blocks);
    restore_agg_keys(&sim.store, &saved);
    let sim = reopen(sim);
    assert_eq!(sim.store.chain_totals().unwrap().blocks, blocks as u64, "the count alone matches");
    assert!(sim.store.ensure_aggregates().unwrap(), "the fingerprint does not");
    sim.check(3);

    // (c) A database written by the P4 binary before `agg/conn` existed.
    {
        let db = sim.store.db();
        let cf = db.cf_handle("meta").unwrap();
        db.delete_cf(cf, b"agg/conn").unwrap();
    }
    let sim = reopen(sim);
    assert!(sim.store.ensure_aggregates().unwrap());
    sim.check(4);
    assert_eq!(sim.store.conn_fingerprint().unwrap(), Some(sim.store.connected_fingerprint_from_undo().unwrap().1));
}

/// NET-12: bounded cost. The explorer statistics read a CONSTANT number of
/// storage entries whatever the chain length and the number of holders
/// (counted by the store, not timed); a full scan reads one per block.
#[test]
fn net12_explorer_statistics_read_a_bounded_number_of_entries() {
    let mut sim = Sim::new(9);
    // Blocks are 300 s apart: the 400-block chain spans 33 h, so the 24 h
    // window covers its last 288 blocks.
    let now = 1_000 + 400 * 300 + 10;
    let dag = Arc::new(RwLock::new(GhostDAG::with_default_k()));
    dag.write().add_genesis([0u8; 32], 1_000);
    let mut holders = 0u64;
    let mut measure = |sim: &mut Sim, blocks: usize, extra_holders: u64| {
        for _ in 0..blocks {
            sim.extend();
            let (b, _) = sim.chain.last().unwrap();
            let parent = b.header.parents[0];
            dag.write().add_block(b.block_hash(), vec![parent], b.header.timestamp, 1).unwrap();
        }
        for _ in 0..extra_holders {
            holders += 1;
            let mut spk = vec![0u8; 20];
            spk[..8].copy_from_slice(&holders.to_le_bytes());
            sim.store.put_utxo(&ext(900_000 + holders), 0, &TxOutput { value: holders * 1_000, script_pubkey: spk }).unwrap();
        }
        let st = &sim.store;
        let never = AtomicBool::new(false);
        let r0 = st.storage_reads();
        let stats = analytics::chain_stats_bounded(st, &dag, now, &never).unwrap();
        let chain_reads = st.storage_reads() - r0;
        let r0 = st.storage_reads();
        let page = analytics::rich_list_bounded(st, 0, 100, &never).unwrap();
        let rich_reads = st.storage_reads() - r0;
        let r0 = st.storage_reads();
        analytics::supply_distribution_bounded(st).unwrap();
        analytics::address_count_bounded(st).unwrap();
        let tier_reads = st.storage_reads() - r0;
        let r0 = st.storage_reads();
        let all = st.iter_all_blocks();
        let scan_reads = st.storage_reads() - r0;
        (stats, page, chain_reads, rich_reads, tier_reads, scan_reads, all.len())
    };

    let (s1, p1, c1, r1, t1, scan1, n1) = measure(&mut sim, 40, 150);
    let (s2, p2, c2, r2, t2, scan2, n2) = measure(&mut sim, 360, 1_500);
    assert!(c1 <= 5 && c2 <= 5, "chain stats: {c1}, {c2} reads");
    assert!(r1 <= 102 && r2 <= 102, "rich list page of 100: {r1}, {r2} reads");
    assert_eq!((t1, t2), (2, 2), "supply distribution + address count: one read each");
    assert!(scan1 >= n1 as u64 && scan2 >= n2 as u64 && scan2 > 5 * scan1, "a full scan grows with the chain");

    // And the answers are right.
    let model_txs: u64 = sim.chain.iter().map(|(b, _)| b.transactions.len() as u64).sum();
    assert_eq!(s2.total_txs, model_txs);
    assert_eq!(s2.chain_blocks, 401);
    let recent: Vec<&Block> = sim.chain.iter().map(|(b, _)| b).filter(|b| b.header.timestamp >= now - 86_400).collect();
    assert_eq!(s2.blocks_last_24h, recent.len() as u64);
    assert_eq!(s2.txs_last_24h, Some(recent.iter().map(|b| b.transactions.len() as u64).sum::<u64>()));
    assert!(!s2.window_capped);
    // The page equals the top of a full scan of the UTXO set (what the
    // pre-fix rich list computed on every call).
    let full = sim.store.recompute_aggregates(&AtomicBool::new(false)).unwrap();
    assert_eq!(p2.items, full.rich_order[..100].to_vec());
    assert_eq!(p2.holders, full.holders.len() as u64);
    assert_eq!(p2.total_supply, full.holders.values().map(|h| h.balance).sum::<u64>());
    assert!(s1.total_txs < s2.total_txs && p1.holders < p2.holders);
}

/// Review finding (hashrate): every DAG block — merged blue and red ones
/// included — cost a block's worth of work, so the hashrate is derived from
/// the interval between ALL DAG blocks over the sampled span, not between
/// selected-chain blocks. A "ladder" DAG with two blocks per level (each
/// chain block merges the other block of the level below) has twice the
/// chain-only hashrate. Pre-fix `hashrate_hs` counted chain blocks only and
/// reported half.
#[test]
fn net12_hashrate_counts_every_dag_block() {
    let tmp = tempfile::TempDir::new().unwrap();
    let store = Storage::open(&tmp.path().join("db")).unwrap();
    let dag = RwLock::new(GhostDAG::with_default_k());
    dag.write().add_genesis([0u8; 32], 1_000);
    let id = |lvl: u64, side: u8| {
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&lvl.to_le_bytes());
        h[8] = side;
        h[31] = 0x1A;
        h
    };
    let mut prev = vec![[0u8; 32]];
    for lvl in 1..=60u64 {
        for side in 0..2u8 {
            dag.write().add_block(id(lvl, side), prev.clone(), 1_000 + 30 * lvl, 1).unwrap();
        }
        prev = vec![id(lvl, 0), id(lvl, 1)];
    }
    let never = AtomicBool::new(false);
    let s = analytics::chain_stats_bounded(&store, &dag, 1_000 + 30 * 60 + 10, &never).unwrap();
    assert!((s.avg_block_time - 30.0).abs() < 1e-9, "chain interval {}", s.avg_block_time);
    assert!((s.avg_dag_block_interval - 15.0).abs() < 1e-9, "DAG interval {}", s.avg_dag_block_interval);
    let chain_only = analytics::estimate_hashrate(s.current_difficulty, s.avg_block_time);
    assert!((s.hashrate_estimate / chain_only - 2.0).abs() < 1e-9, "{} vs {}", s.hashrate_estimate, chain_only);

    // A plain chain: both intervals agree.
    let dag = RwLock::new(GhostDAG::with_default_k());
    dag.write().add_genesis([0u8; 32], 1_000);
    for lvl in 1..=60u64 {
        dag.write().add_block(id(lvl, 0), vec![if lvl == 1 { [0u8; 32] } else { id(lvl - 1, 0) }], 1_000 + 30 * lvl, 1).unwrap();
    }
    let s = analytics::chain_stats_bounded(&store, &dag, 1_000 + 30 * 60 + 10, &never).unwrap();
    assert!((s.avg_dag_block_interval - s.avg_block_time).abs() < 1e-9);
}

/// NET-12: long work checks a cancellation flag (the RPC sets it when its
/// dispatch timeout fires) and stops at once.
#[test]
fn net12_long_work_is_cancellable() {
    let mut sim = Sim::new(11);
    let dag = Arc::new(RwLock::new(GhostDAG::with_default_k()));
    dag.write().add_genesis([0u8; 32], 1_000);
    for _ in 0..5 {
        sim.extend();
        let (b, _) = sim.chain.last().unwrap();
        dag.write().add_block(b.block_hash(), b.header.parents.clone(), b.header.timestamp, 1).unwrap();
    }
    let cancel = AtomicBool::new(true);
    let st = &sim.store;
    let r0 = st.storage_reads();
    assert!(matches!(analytics::chain_stats_bounded(st, &dag, 5_000, &cancel), Err(analytics::StatsError::Cancelled)));
    // The cancellation surfaces inside the storage walk as a StorageError;
    // it is reported as Cancelled, never as a storage failure.
    assert!(matches!(analytics::rich_list_bounded(st, 0, 100, &cancel), Err(analytics::StatsError::Cancelled)));
    assert!(st.recompute_aggregates(&cancel).is_err());
    assert!(st.balance_at_height_cancellable(&[1; 20], u64::MAX, &cancel).is_err());
    assert!(st.storage_reads() - r0 <= 3, "nothing was walked after the flag was seen");
    let never = AtomicBool::new(false);
    assert!(analytics::chain_stats_bounded(st, &dag, 5_000, &never).is_ok());
    let _ = aggregates::TIERS;
}
