//! Audit DAG-11 residuals (the challenge of the re-audit), on the REAL
//! acceptance and start-up paths:
//!
//! 1. a database written by the pre-fix binary, whose lost DAG write left a
//!    missing or zero-filled parent integrity link, made the upgraded node
//!    exit before reconciliation with no repair but a resync;
//! 2. a failed reconciliation was log-and-continue, and `accept_block` took
//!    the DAG's in-memory selected tip as the applied tip, so every later
//!    connect was refused until a restart;
//! 3. the reachability delta was drained while the connect batch was being
//!    built, so a batch that failed lost it and left a reindex's stale
//!    intervals on disk.
//!
//! Faults are injected with `Storage::inject_batch_failures` (the next N
//! atomic batch commits fail and write nothing).

mod fix_common;
use fix_common::*;

use std::collections::HashMap;
use std::sync::Arc;

use gnb::accept;
use gnb::coherence::ShieldedPool;
use gnb::consensus::reachability::ReachabilityStore;
use gnb::consensus::{BlockHash, GhostDAG};
use gnb::core::Block;
use parking_lot::RwLock;

fn persisted_reach(n: &Node) -> HashMap<BlockHash, Vec<u8>> {
    n.store.load_all_reachability().unwrap().into_iter().collect()
}

fn memory_reach(n: &Node) -> HashMap<BlockHash, Vec<u8>> {
    n.dag.read().reach_export_all().into_iter().collect()
}

/// The chain depth at which inserting the next block makes the interval
/// index reindex (its parent's range is exhausted): the labeling depends on
/// the tree shape only, so a scratch index of a plain chain tells.
fn reindex_depth() -> u64 {
    let id = |i: u64| {
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&i.to_be_bytes());
        h
    };
    let mut r = ReachabilityStore::new();
    r.add_genesis(id(0));
    let _ = r.take_persist_delta();
    let mut prev = id(0);
    for d in 1..200u64 {
        r.add_block(id(d), &prev, &[]);
        let (ups, _) = r.take_persist_delta();
        if ups.len() > 2 {
            return d;
        }
        prev = id(d);
    }
    panic!("no reindex within 200 blocks");
}

fn raw_put(n: &Node, cf: &str, k: &[u8], v: &[u8]) {
    let db = n.store.db();
    db.put_cf(&db.cf_handle(cf).unwrap(), k, v).unwrap();
}

fn raw_delete(n: &Node, cf: &str, k: &[u8]) {
    let db = n.store.db();
    db.delete_cf(&db.cf_handle(cf).unwrap(), k).unwrap();
}

fn encoded(n: &Node) -> HashMap<BlockHash, Vec<u8>> {
    let d = n.dag.read();
    d.store.data.iter().map(|(h, x)| (*h, gnb::consensus::canonical_encode(x))).collect()
}

/// A chain c1..c5 on the genesis, accepted normally.
fn five_blocks() -> (Node, Vec<Block>) {
    let genesis = mk_genesis(unix_now() - 10_000);
    let n = node_with(&genesis, &[]);
    let mut tip = genesis.block_hash();
    let mut chain = Vec::new();
    for i in 1..=5 {
        let b = empty_child(&n, tip, &format!("c{i}"));
        accept(&n, &b).unwrap();
        tip = b.block_hash();
        chain.push(b);
    }
    (n, chain)
}

/// (1) The footprint of a pre-fix binary that lost one DAG write and kept
/// running: c2 has no CF_DAG record nor integrity link, c3 was written with
/// the zero-filled parent link, c4's integrity record is missing (the
/// self-heal of an older release wrote records one by one, errors ignored),
/// and c5's record was corrupted on disk. The integrity check fails, which
/// made the node exit before reconciliation with no remedy but a resync; it
/// is now repaired: c2 and c5 are recomputed from their stored headers, c3
/// and c4 relinked, nothing dropped, every block's data equals what the node
/// had, the next start verifies strictly and the node keeps accepting
/// blocks.
#[test]
fn a_pre_fix_lost_dag_write_is_repaired_at_start_up() {
    let (mut n, chain) = five_blocks();
    let original = encoded(&n);
    let id = |i: usize| chain[i - 1].block_hash();
    raw_delete(&n, "dag", &id(2));
    raw_delete(&n, "dag_integrity", &id(2));
    let d3 = n.dag.read().get_block_data(&id(3)).cloned().unwrap();
    raw_put(&n, "dag_integrity", &id(3), &gnb::consensus::compute_integrity_hash(&id(3), &d3, &[0u8; 32]));
    raw_delete(&n, "dag_integrity", &id(4));
    let mut d5 = n.dag.read().get_block_data(&id(5)).cloned().unwrap();
    d5.blue_score += 7;
    n.store.put_dag_data(&id(5), &d5).unwrap();

    // The start-up of the pre-fix binary (and of this one before the repair).
    let strict = GhostDAG::with_default_k()
        .load_persisted_validated(n.store.load_all_dag_data().unwrap(), n.store.load_all_integrity_hashes().unwrap());
    assert!(strict.is_err(), "the footprint fails the integrity chain");

    let dag = Arc::new(RwLock::new(GhostDAG::with_default_k()));
    let report = accept::load_dag(&dag, &n.store).expect("repaired");
    let rep = report.repair.expect("the repair ran");
    let mut recomputed: Vec<BlockHash> = rep.recomputed.iter().map(|(h, _)| *h).collect();
    recomputed.sort_unstable();
    let mut want = vec![id(2), id(5)];
    want.sort_unstable();
    assert_eq!(recomputed, want, "the lost and the corrupted record are recomputed");
    let mut relinked = rep.relinked.clone();
    relinked.sort_unstable();
    let mut want = vec![id(3), id(4)];
    want.sort_unstable();
    assert_eq!(relinked, want, "the zero-linked and the unlinked record are relinked");
    assert!(rep.dropped.is_empty());
    assert_eq!(report.blocks_loaded, 6);
    let repaired: HashMap<BlockHash, Vec<u8>> =
        dag.read().store.data.iter().map(|(h, x)| (*h, gnb::consensus::canonical_encode(x))).collect();
    assert_eq!(repaired, original, "every block's GhostDAG data is the one the node computed");
    assert_eq!(n.store.get_dag_data(&id(5)).unwrap().unwrap().blue_score, d5.blue_score - 7, "corruption repaired on disk");

    // The next start verifies strictly (fix_common::restart expects it) and
    // the node goes on.
    restart(&mut n);
    assert_eq!(sel_tip(&n), Some(id(5)));
    let c6 = empty_child(&n, id(5), "c6");
    accept(&n, &c6).unwrap();
    assert_eq!(applied_tip(&n), Some(c6.block_hash()));
}

/// (1) What cannot be recomputed is dropped with its descendants and fetched
/// again; but the UTXO set must not keep the effects of an applied block the
/// repaired DAG no longer has: with c2's record AND body gone (pruned), the
/// repair refuses and asks for a resync.
#[test]
fn a_repair_that_would_drop_applied_blocks_refuses() {
    let (n, chain) = five_blocks();
    let id = |i: usize| chain[i - 1].block_hash();
    raw_delete(&n, "dag", &id(2));
    raw_delete(&n, "dag_integrity", &id(2));
    n.store.delete_block_body(&id(2)).unwrap();
    let dag = Arc::new(RwLock::new(GhostDAG::with_default_k()));
    let err = accept::load_dag(&dag, &n.store).unwrap_err();
    assert!(err.contains("Resynchronize"), "{err}");
    assert!(n.store.get_dag_data(&id(3)).unwrap().is_some(), "nothing written");
}

/// (1) An unapplied side branch whose base lost its record and its body:
/// the blocks that descend from it cannot be loaded and are dropped (they
/// were never applied: the node fetches them again from its peers); the
/// applied chain is untouched and the node goes on.
#[test]
fn an_unrecoverable_side_branch_is_dropped() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let mut n = node_with(&genesis, &[]);
    let mut tip = gh;
    for i in 1..=3 {
        let b = empty_child(&n, tip, &format!("a{i}"));
        accept(&n, &b).unwrap();
        tip = b.block_hash();
    }
    let s1 = empty_child(&n, gh, "s1");
    accept(&n, &s1).unwrap();
    let t1 = empty_child(&n, s1.block_hash(), "t1");
    accept(&n, &t1).unwrap();
    assert_eq!(applied_tip(&n), Some(tip), "the side branch is lighter");
    raw_delete(&n, "dag", &s1.block_hash());
    raw_delete(&n, "dag_integrity", &s1.block_hash());
    n.store.delete_block_body(&s1.block_hash()).unwrap();

    let dag = Arc::new(RwLock::new(GhostDAG::with_default_k()));
    let rep = accept::load_dag(&dag, &n.store).expect("repaired").repair.expect("the repair ran");
    assert_eq!(rep.dropped, vec![t1.block_hash()]);
    assert!(rep.recomputed.is_empty() && rep.relinked.is_empty());
    assert!(n.store.get_dag_data(&t1.block_hash()).unwrap().is_none(), "dropped on disk");
    restart(&mut n);
    assert!(!n.dag.read().has_block(&t1.block_hash()));
    let a4 = empty_child(&n, tip, "a4");
    accept(&n, &a4).unwrap();
    assert_eq!(applied_tip(&n), Some(a4.block_hash()));
}

/// (3) The commit of the block whose insertion reindexed the interval index
/// fails; the in-memory insertion is rolled back and the block arrives
/// again. The index on disk must equal the one in memory afterwards (every
/// reindexed record rewritten), as it does on a node where nothing failed.
#[test]
fn a_failed_commit_keeps_the_reachability_delta_of_a_reindex() {
    let depth = reindex_depth();
    let genesis = mk_genesis(unix_now() - 100_000);
    let mut n = node_with(&genesis, &[]);
    let mut tip = genesis.block_hash();
    for i in 1..depth {
        let b = empty_child(&n, tip, &format!("r{i}"));
        accept(&n, &b).unwrap();
        tip = b.block_hash();
    }
    assert_eq!(persisted_reach(&n), memory_reach(&n), "consistent before the fault");
    let trigger = empty_child(&n, tip, "reindex");
    // The test proves something only if inserting the trigger reindexes the
    // NODE's index (a delta of more than the block and its parent): a dry
    // run on a copy loaded from disk, which equals the node's index (checked
    // just above), must reindex. If `reindex_depth` ever drifts from the
    // node's labelling, this fails instead of passing vacuously.
    {
        let mut probe = GhostDAG::with_default_k();
        probe.load_persisted_validated(n.store.load_all_dag_data().unwrap(), n.store.load_all_integrity_hashes().unwrap())
            .unwrap();
        probe.reach_load_records(&n.store.load_all_reachability().unwrap(), n.store.get_reachability_root().unwrap())
            .unwrap();
        let _ = probe.reach_take_delta(); // loading is not a change
        let work = gnb::pow::work_from_bits(trigger.header.bits);
        probe.add_block(trigger.block_hash(), trigger.header.parents.clone(), trigger.header.timestamp, work).unwrap();
        let ups = probe.reach_peek_delta().0.len();
        assert!(ups > 2, "inserting the trigger must reindex the node's index (delta of {ups} record(s))");
    }
    n.store.inject_batch_failures(1);
    let err = accept(&n, &trigger).unwrap_err();
    assert!(err.contains("injected batch failure"), "{err}");
    assert!(!n.dag.read().has_block(&trigger.block_hash()), "insertion rolled back");
    assert_eq!(applied_tip(&n), Some(tip));
    // The failed commit's reindex delta is still pending, not lost with the
    // batch: every record whose in-memory state differs from disk (the
    // removed leaf's parent and the records the reindex moved, which keep
    // their new intervals in memory) is in the pending delta. With the delta
    // drained while staging, only the parent (re-marked by the rollback)
    // was.
    {
        let (disk, mem) = (persisted_reach(&n), memory_reach(&n));
        let stale: std::collections::HashSet<BlockHash> =
            mem.iter().filter(|(h, r)| disk.get(*h) != Some(r)).map(|(h, _)| *h).collect();
        let pending: std::collections::HashSet<BlockHash> =
            n.dag.read().reach_peek_delta().0.into_iter().map(|(h, _)| h).collect();
        assert!(stale.len() >= 2, "the reindex moved a record besides the parent ({} stale)", stale.len());
        assert!(stale.is_subset(&pending),
            "{} of {} stale record(s) are no longer pending", stale.difference(&pending).count(), stale.len());
    }
    // The block arrives again and commits.
    accept(&n, &trigger).unwrap();
    assert_eq!(applied_tip(&n), Some(trigger.block_hash()));
    let (disk, mem) = (persisted_reach(&n), memory_reach(&n));
    let stale: Vec<String> = mem.iter()
        .filter(|(h, r)| disk.get(*h) != Some(r))
        .map(|(h, _)| hex::encode(&h[..4]))
        .collect();
    assert!(stale.is_empty(), "{} reachability record(s) on disk differ from memory: {:?}", stale.len(), stale);
    assert_eq!(disk.len(), mem.len());
    // And a restart loads the persisted index (fast path) and passes the
    // full self-check.
    restart(&mut n);
    assert_eq!(n.dag.read().reach_self_check_sample(5_000, 7).map(|c| c > 0), Ok(true));
}

/// (2) The node restarts with a recorded but unapplied heavier chain (the
/// applied tip pointer is A1, the DAG prefers F2) and start-up
/// reconciliation's reconnect fails (injected). `accept_block` must then
/// plan from the APPLIED tip on disk: the next block connects the best chain
/// (it used to plan from the in-memory selected tip F2, which the UTXO and
/// shielded state are not at, and every connect was refused until a
/// restart).
#[test]
fn accept_plans_from_the_applied_tip_after_a_failed_reconnect() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let mut n = node_with(&genesis, &[]);
    let a1 = empty_child(&n, gh, "a1");
    accept(&n, &a1).unwrap();
    let f1 = mk_block_where(&n, vec![gh],
        vec![coinbase("f1", gnb::core::tokenomics::block_subsidy_sat(1), vec![0xF1; 20])],
        |h| *h < a1.block_hash());
    accept(&n, &f1).unwrap();
    assert_eq!(applied_tip(&n), Some(a1.block_hash()), "F1 is a fork-loser");
    // F2's DAG record and body are on disk but it was never connected.
    let f2 = empty_child(&n, f1.block_hash(), "f2");
    {
        let work = gnb::pow::work_from_bits(f2.header.bits);
        n.dag.write().add_block(f2.block_hash(), f2.header.parents.clone(), f2.header.timestamp, work).unwrap();
        let data = n.dag.read().get_block_data(&f2.block_hash()).cloned().unwrap();
        n.store.put_block_body(&f2).unwrap();
        let mut batch = rocksdb::WriteBatch::default();
        n.store.stage_dag_record(&mut batch, &f2.block_hash(), &data, &[], &[], None).unwrap();
        n.store.write_batch(batch).unwrap();
    }
    // Restart: reconciliation's reconnect to F2 fails (storage fault).
    let mut d = GhostDAG::with_default_k();
    d.load_persisted_validated(n.store.load_all_dag_data().unwrap(), n.store.load_all_integrity_hashes().unwrap())
        .unwrap();
    d.rebuild_reachability_from_store().unwrap();
    n.dag = Arc::new(RwLock::new(d));
    n.shielded = Arc::new(RwLock::new(ShieldedPool::load(&n.store).unwrap()));
    // The writes reconciliation makes before its reconnect happen once per
    // data dir; make them now so the injected fault hits the reconnect.
    n.store.ensure_aggregates().unwrap();
    accept::migrate_chain_indexes(&n.dag, &n.store).unwrap();
    accept::recheck_stored_blocks_under_hardening(&n.dag, &n.store, gnb::core::activation::hardening_activation_height())
        .unwrap();
    n.store.inject_batch_failures(1);
    let err = accept::reconcile_on_startup(&n.dag, &n.store, &n.shielded).unwrap_err();
    assert!(err.contains("injected batch failure"), "{err}");
    assert_eq!(sel_tip(&n), Some(f2.block_hash()), "memory prefers F2");
    assert_eq!(applied_tip(&n), Some(a1.block_hash()), "disk is still at A1");
    // The next block extends the best chain and connects it from A1.
    let f3 = empty_child(&n, f2.block_hash(), "f3");
    accept(&n, &f3).expect("connects from the applied tip");
    assert_eq!(applied_tip(&n), Some(f3.block_hash()));
    assert_eq!(n.shielded.read().tip(), Some(f3.block_hash()));
    for b in [&f1, &f2, &f3] {
        assert!(n.store.get_utxo(&b.transactions[0].txid(), 0).unwrap().is_some(), "{} applied", hex::encode(&b.block_hash()[..4]));
    }
    assert!(n.store.get_utxo(&a1.transactions[0].txid(), 0).unwrap().is_none(), "A1 rolled back");
    let _: &Block = &f3;
}
