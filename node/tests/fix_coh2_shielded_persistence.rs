//! Audit COH-2 (residual): the shielded state is persisted in the same
//! RocksDB WriteBatch as the UTXO changes of each connect plan, with per-block
//! undo records, and reloaded at start-up; applying a block no longer clones
//! the tree or the nullifier set.
//!
//! The node's only compiled verifier is `RejectAll`, so the acceptance
//! pipeline never connects a block with shielded transactions. The storage
//! tests below therefore drive `ShieldedPool::stage_plan_with` (the exact
//! function the pipeline calls through `stage_plan`) with an accept-all test
//! closure, commit the writes through a RocksDB batch exactly like
//! `reorg::connect_plan`, and reload with `ShieldedPool::load` (what main()
//! does). The pipeline tests at the end use real `accept_block` calls.

mod fix_common;
use fix_common::*;

use gnb::coherence::{ShieldedPool, ShieldedSnapshot, ShieldedTx, SpendPublic};
use gnb::core::{Block, BlockHeader, Transaction, TxInput, TxOutput};
use gnb::reorg::{ConnectError, ReorgPlan};
use gnb::storage::Storage;
use tempfile::TempDir;

type Hash = [u8; 32];

fn ok(_: &SpendPublic, _: &[u8]) -> bool {
    true
}

fn coinbase(tag: u64) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid: [0u8; 32],
            prev_index: u32::MAX,
            script_sig: tag.to_le_bytes().to_vec(),
            sequence: u32::MAX,
        }],
        outputs: vec![TxOutput { value: 100, script_pubkey: vec![1u8; 20] }],
        locktime: 0,
    }
}

/// A block body on `parent` with the given shielded transactions, stored in
/// `store` (the pipeline stores every body before connecting it).
fn stored_block(store: &Storage, parent: Hash, height: u64, nonce: u64, shielded: Vec<ShieldedTx>) -> Hash {
    let cb = coinbase(nonce);
    let b = Block {
        header: BlockHeader {
            version: 1,
            parents: vec![parent],
            merkle_root: Transaction::merkle_root(std::slice::from_ref(&cb)),
            timestamp: 1_000 + height,
            bits: 0x2100ffff,
            nonce,
        },
        transactions: vec![cb],
        blue_score: height,
        height,
        shielded_transactions: shielded,
        powit: Default::default(),
    };
    store.put_block_body(&b).unwrap();
    b.block_hash()
}

fn stx(anchor: Hash, nullifiers: Vec<Hash>, outputs: Vec<Hash>) -> ShieldedTx {
    ShieldedTx { anchor, nullifiers, outputs, fee: 0, proof: vec![1], binding_sig: vec![] }
}

fn h(tag: u8, i: u64) -> Hash {
    let mut a = [tag; 32];
    a[..8].copy_from_slice(&i.to_le_bytes());
    a
}

/// Stage `plan`, commit the writes plus `meta/tip_hash` in ONE batch (as
/// `connect_plan` does), and commit the staged plan.
fn connect(store: &Storage, pool: &mut ShieldedPool, plan: &ReorgPlan) -> Result<(), ConnectError> {
    let staged = pool.stage_plan_with(store, plan, ok)?;
    let mut batch = rocksdb::WriteBatch::default();
    staged.stage_into(store, &mut batch).unwrap();
    let new_tip = plan.to_apply.last().copied().unwrap_or(plan.lca);
    store.stage_meta(&mut batch, "tip_hash", &new_tip).unwrap();
    store.write_batch(batch).unwrap();
    pool.commit_staged(staged);
    Ok(())
}

fn extend(from: Hash, blocks: &[Hash]) -> ReorgPlan {
    ReorgPlan { lca: from, to_rollback: vec![], to_apply: blocks.to_vec() }
}

fn snap(pool: &ShieldedPool) -> ShieldedSnapshot {
    pool.engine.snapshot()
}

fn reloaded(store: &Storage) -> ShieldedPool {
    ShieldedPool::load(store).expect("persisted shielded state loads")
}

struct Fixture {
    _tmp: TempDir,
    store: Storage,
    genesis: Hash,
}

fn fixture() -> Fixture {
    let tmp = TempDir::new().unwrap();
    let store = Storage::open(&tmp.path().join("db")).unwrap();
    let genesis = stored_block(&store, [0u8; 32], 0, 0, vec![]);
    store.put_meta("tip_hash", &genesis).unwrap();
    Fixture { _tmp: tmp, store, genesis }
}

/// A fresh (or pre-COH-2) data dir has no shielded records: it loads as the
/// empty genesis state at the UTXO tip.
#[test]
fn fresh_data_dir_loads_the_empty_state_at_the_utxo_tip() {
    let f = fixture();
    let pool = reloaded(&f.store);
    assert_eq!(pool.tip(), Some(f.genesis));
    assert_eq!(snap(&pool), ShieldedPool::new().engine.snapshot());
}

/// Restart consistency: after connecting shielded blocks, the reloaded state
/// equals the in-memory state (leaves, anchors, nullifiers, tip).
#[test]
fn restart_reloads_exactly_the_committed_state() {
    let f = fixture();
    let mut pool = reloaded(&f.store);
    let b1 = stored_block(&f.store, f.genesis, 1, 1, vec![stx(pool.anchor(), vec![h(1, 1)], vec![h(2, 1), h(2, 2)])]);
    connect(&f.store, &mut pool, &extend(f.genesis, &[b1])).unwrap();
    let a1 = pool.anchor();
    let b2 = stored_block(&f.store, b1, 2, 2, vec![
        stx(a1, vec![h(1, 2)], vec![h(2, 3)]),
        stx(a1, vec![h(1, 3), h(1, 4)], vec![]),
    ]);
    let b3 = stored_block(&f.store, b2, 3, 3, vec![]); // no shielded txs
    connect(&f.store, &mut pool, &extend(b1, &[b2, b3])).unwrap();

    let back = reloaded(&f.store);
    assert_eq!(back.tip(), Some(b3));
    assert_eq!(snap(&back), snap(&pool));
    assert_eq!(back.anchor(), pool.anchor());
    assert_eq!(snap(&pool).leaves.len(), 3);
    assert_eq!(snap(&pool).nullifiers.len(), 4);
    for i in 1..=4 {
        assert!(back.engine.is_spent(&h(1, i)), "nullifier {i} survives the restart");
    }
    // A double spend of a persisted nullifier is refused after the restart.
    let mut back = back;
    let b4 = stored_block(&f.store, b3, 4, 4, vec![stx(back.anchor(), vec![h(1, 2)], vec![])]);
    match back.stage_plan_with(&f.store, &extend(b3, &[b4]), ok) {
        Err(ConnectError::Invalid { block, .. }) => assert_eq!(block, b4),
        other => panic!("expected the double spend to be invalid, got {other:?}"),
    }
}

/// Reorg round trip: connect + disconnect returns to exactly the earlier
/// state, in memory and on disk (leaf, nullifier and undo rows removed).
#[test]
fn connect_then_disconnect_restores_the_previous_state() {
    let f = fixture();
    let mut pool = reloaded(&f.store);
    let b1 = stored_block(&f.store, f.genesis, 1, 1, vec![stx(pool.anchor(), vec![h(1, 1)], vec![h(2, 1)])]);
    connect(&f.store, &mut pool, &extend(f.genesis, &[b1])).unwrap();
    let before = snap(&pool);
    let before_disk = snap(&reloaded(&f.store));
    assert_eq!(before, before_disk);

    let b2 = stored_block(&f.store, b1, 2, 2, vec![stx(pool.anchor(), vec![h(1, 2)], vec![h(2, 2), h(2, 3)])]);
    connect(&f.store, &mut pool, &extend(b1, &[b2])).unwrap();
    assert_ne!(snap(&pool), before);
    assert!(gnb::coherence::persist::read_undo(&f.store, &b2).unwrap().is_some());

    // Disconnect b2 (tip-first) back to b1.
    let back_to_b1 = ReorgPlan { lca: b1, to_rollback: vec![b2], to_apply: vec![] };
    connect(&f.store, &mut pool, &back_to_b1).unwrap();
    assert_eq!(snap(&pool), before, "in-memory state after connect+disconnect");
    assert_eq!(pool.tip(), Some(b1));
    let disk = reloaded(&f.store);
    assert_eq!(snap(&disk), before, "persisted state after connect+disconnect");
    assert_eq!(disk.tip(), Some(b1));
    assert!(gnb::coherence::persist::read_undo(&f.store, &b2).unwrap().is_none(), "undo record deleted");
    assert!(!disk.engine.is_spent(&h(1, 2)));

    // A real reorg: b1 → {b2', b3'} replacing b2 after re-connecting it.
    connect(&f.store, &mut pool, &extend(b1, &[b2])).unwrap();
    let anchor_b1 = before.anchors.last().copied().unwrap();
    let b2x = stored_block(&f.store, b1, 2, 22, vec![stx(anchor_b1, vec![h(1, 2)], vec![h(3, 1)])]);
    let b3x = stored_block(&f.store, b2x, 3, 33, vec![]);
    connect(&f.store, &mut pool, &ReorgPlan { lca: b1, to_rollback: vec![b2], to_apply: vec![b2x, b3x] }).unwrap();
    assert_eq!(snap(&reloaded(&f.store)), snap(&pool));
    assert_eq!(pool.engine.snapshot().leaves, vec![h(2, 1), h(3, 1)]);
    // ...and back again.
    connect(&f.store, &mut pool, &ReorgPlan { lca: b1, to_rollback: vec![b3x, b2x], to_apply: vec![] }).unwrap();
    assert_eq!(snap(&pool), before);
    assert_eq!(snap(&reloaded(&f.store)), before);
}

/// Merge P3 x P5 (audit DAG-6: no reorg-depth limit, so a reorg disconnects
/// blocks whose body was pruned): the shielded side of a rollback through
/// pruned bodies takes "did the block carry shielded transactions" from the
/// record written when the body was pruned, or — a body pruned by an older
/// release, without a record — from the persisted shielded undo record
/// (never pruned), and disconnects exactly as with the body.
#[test]
fn disconnect_through_pruned_bodies_uses_the_pruned_record_and_the_undo() {
    let f = fixture();
    let mut pool = reloaded(&f.store);
    let empty = snap(&pool);
    let b1 = stored_block(&f.store, f.genesis, 1, 1, vec![stx(pool.anchor(), vec![h(1, 1)], vec![h(2, 1)])]);
    connect(&f.store, &mut pool, &extend(f.genesis, &[b1])).unwrap();
    let b2 = stored_block(&f.store, b1, 2, 2, vec![stx(pool.anchor(), vec![h(1, 2)], vec![h(2, 2)])]);
    let b3 = stored_block(&f.store, b2, 3, 3, vec![]);
    connect(&f.store, &mut pool, &extend(b1, &[b2, b3])).unwrap();
    // The node's selected-chain height index (what pruning walks).
    let mut batch = rocksdb::WriteBatch::default();
    for h in [f.genesis, b1, b2, b3] {
        let blk = f.store.get_block(&h).unwrap().unwrap();
        f.store.stage_chain_index(&mut batch, &blk, &std::collections::HashMap::new()).unwrap();
    }
    f.store.write_batch(batch).unwrap();
    assert_eq!(f.store.prune_blocks_below(3).unwrap(), 3, "genesis, b1 and b2 pruned");
    for h in [b1, b2] {
        assert!(f.store.get_block(&h).unwrap().is_none());
        assert!(f.store.get_pruned_body_record(&h).unwrap().unwrap().had_shielded);
    }
    // b1 as if pruned by an older release: no record.
    let mut batch = rocksdb::WriteBatch::default();
    f.store.stage_delete_pruned_body_record(&mut batch, &b1).unwrap();
    f.store.write_batch(batch).unwrap();

    let back = ReorgPlan { lca: f.genesis, to_rollback: vec![b3, b2, b1], to_apply: vec![] };
    connect(&f.store, &mut pool, &back).unwrap();
    assert_eq!(snap(&pool), empty, "in memory: back to the genesis state");
    assert_eq!(pool.tip(), Some(f.genesis));
    let disk = reloaded(&f.store);
    assert_eq!(snap(&disk), empty, "on disk too");
    for h in [b1, b2] {
        assert!(gnb::coherence::persist::read_undo(&f.store, &h).unwrap().is_none(), "undo consumed");
    }
}

/// A block whose shielded transactions are invalid in its context is
/// reported as `Invalid` (the pipeline disqualifies it) and the pool is
/// restored exactly, including the effects of earlier blocks of the plan.
#[test]
fn invalid_block_in_a_plan_restores_the_pool() {
    let f = fixture();
    let mut pool = reloaded(&f.store);
    let before = snap(&pool);
    let a0 = pool.anchor();
    let b1 = stored_block(&f.store, f.genesis, 1, 1, vec![stx(a0, vec![h(1, 1)], vec![h(2, 1)])]);
    // b2 double-spends b1's nullifier.
    let b2 = stored_block(&f.store, b1, 2, 2, vec![stx(a0, vec![h(1, 1)], vec![h(2, 2)])]);
    match pool.stage_plan_with(&f.store, &extend(f.genesis, &[b1, b2]), ok) {
        Err(ConnectError::Invalid { block, reason, .. }) => {
            assert_eq!(block, b2);
            assert!(reason.contains("DoubleSpend"), "{reason}");
        }
        other => panic!("expected Invalid, got {other:?}"),
    }
    assert_eq!(snap(&pool), before);
    assert_eq!(pool.tip(), Some(f.genesis));
    // A proof the verifier rejects is invalid too (RejectAll in the node).
    let reject = |_: &SpendPublic, _: &[u8]| false;
    assert!(matches!(
        pool.stage_plan_with(&f.store, &extend(f.genesis, &[b1]), reject),
        Err(ConnectError::Invalid { .. })
    ));
    assert_eq!(snap(&pool), before);
}

/// When the RocksDB batch is not committed (connect_plan failed after the
/// shielded staging), `revert_staged` restores the exact previous state and
/// nothing reached the disk.
#[test]
fn reverting_an_uncommitted_plan_restores_memory_and_leaves_disk_untouched() {
    let f = fixture();
    let mut pool = reloaded(&f.store);
    let b1 = stored_block(&f.store, f.genesis, 1, 1, vec![stx(pool.anchor(), vec![h(1, 1)], vec![h(2, 1)])]);
    connect(&f.store, &mut pool, &extend(f.genesis, &[b1])).unwrap();
    let before = snap(&pool);

    let b2 = stored_block(&f.store, b1, 2, 2, vec![stx(pool.anchor(), vec![h(1, 2)], vec![h(2, 2)])]);
    let staged = pool.stage_plan_with(&f.store, &extend(b1, &[b2]), ok).unwrap();
    assert_ne!(snap(&pool), before);
    pool.revert_staged(staged);
    assert_eq!(snap(&pool), before);
    assert_eq!(pool.tip(), Some(b1));
    assert_eq!(snap(&reloaded(&f.store)), before);

    // Same for a disconnect.
    let staged = pool.stage_plan_with(&f.store, &ReorgPlan { lca: f.genesis, to_rollback: vec![b1], to_apply: vec![] }, ok).unwrap();
    assert_ne!(snap(&pool), before);
    pool.revert_staged(staged);
    assert_eq!(snap(&pool), before);
}

/// The pool refuses a plan that does not start at its tip (it would apply
/// or undo the wrong blocks).
#[test]
fn plan_not_starting_at_the_shielded_tip_is_refused() {
    let f = fixture();
    let mut pool = reloaded(&f.store);
    let b1 = stored_block(&f.store, f.genesis, 1, 1, vec![]);
    let b2 = stored_block(&f.store, b1, 2, 2, vec![]);
    assert!(matches!(pool.stage_plan_with(&f.store, &extend(b1, &[b2]), ok), Err(ConnectError::Failed(_))));
    assert_eq!(pool.tip(), Some(f.genesis));
}

/// A corrupt persisted state is refused at start-up instead of running on a
/// wrong nullifier set or tree.
#[test]
fn corrupt_or_inconsistent_state_is_refused_at_load() {
    let f = fixture();
    let mut pool = reloaded(&f.store);
    let b1 = stored_block(&f.store, f.genesis, 1, 1, vec![stx(pool.anchor(), vec![h(1, 1)], vec![h(2, 1), h(2, 2)])]);
    connect(&f.store, &mut pool, &extend(f.genesis, &[b1])).unwrap();

    // The UTXO tip moved without the shielded state (non-empty state).
    f.store.put_meta("tip_hash", &f.genesis).unwrap();
    assert!(ShieldedPool::load(&f.store).unwrap_err().contains("refusing to start"));
    f.store.put_meta("tip_hash", &b1).unwrap();
    assert!(ShieldedPool::load(&f.store).is_ok());

    // A gap in the commitment tree.
    let mut batch = rocksdb::WriteBatch::default();
    let mut key = vec![b'L'];
    key.extend_from_slice(&0u64.to_be_bytes());
    f.store.stage_shielded_delete(&mut batch, &key).unwrap();
    f.store.write_batch(batch).unwrap();
    assert!(ShieldedPool::load(&f.store).unwrap_err().contains("gap"));
}

/// Randomized reorg round trips against an in-memory model: after every
/// committed plan the reloaded state equals the in-memory state, and every
/// disconnect returns to the snapshot taken when that height was the tip.
#[test]
fn randomized_reorg_round_trips_match_the_snapshots() {
    let f = fixture();
    let mut pool = reloaded(&f.store);
    // chain[i] = (block hash, snapshot after connecting it)
    let mut chain: Vec<(Hash, ShieldedSnapshot)> = vec![(f.genesis, snap(&pool))];
    let mut seed: u64 = 0x5eed_c0de;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut nonce = 100u64;
    let mut nf_counter = 0u64;
    for _ in 0..60 {
        let r = next();
        if r % 3 == 0 && chain.len() > 1 {
            // Disconnect 1..=3 blocks back to an earlier tip.
            let depth = 1 + (next() as usize % 3).min(chain.len() - 2);
            let target = chain.len() - 1 - depth;
            let to_rollback: Vec<Hash> = chain[target + 1..].iter().rev().map(|(b, _)| *b).collect();
            connect(&f.store, &mut pool, &ReorgPlan { lca: chain[target].0, to_rollback, to_apply: vec![] }).unwrap();
            chain.truncate(target + 1);
            assert_eq!(snap(&pool), chain[target].1, "disconnect restores the snapshot");
        } else {
            let (tip, _) = chain.last().cloned().unwrap();
            let n_tx = (next() % 3) as usize;
            let txs: Vec<ShieldedTx> = (0..n_tx)
                .map(|_| {
                    let nfs = (0..next() % 3).map(|_| { nf_counter += 1; h(9, nf_counter) }).collect();
                    let outs = (0..next() % 4).map(|_| h(8, next())).collect();
                    stx(pool.anchor(), nfs, outs)
                })
                .collect();
            nonce += 1;
            let b = stored_block(&f.store, tip, chain.len() as u64, nonce, txs);
            connect(&f.store, &mut pool, &extend(tip, &[b])).unwrap();
            chain.push((b, snap(&pool)));
        }
        let disk = reloaded(&f.store);
        assert_eq!(snap(&disk), snap(&pool), "restart consistency");
        assert_eq!(disk.tip(), Some(chain.last().unwrap().0));
    }
    assert!(chain.len() > 3, "the walk should grow the chain");
}

// ── The real acceptance pipeline ─────────────────────────────────────────────

/// accept_block persists the shielded tip with the UTXO tip in every connect
/// (extension and reorg), and a restart reloads it.
#[test]
fn pipeline_persists_the_shielded_tip_with_the_utxo_tip_and_restart_reloads_it() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let mut n = node_with(&genesis, &[]);
    let persisted = |n: &Node| ShieldedPool::load(&n.store).unwrap().tip();

    let m1 = empty_child(&n, gh, "m1");
    accept(&n, &m1).unwrap();
    let m2 = empty_child(&n, m1.block_hash(), "m2");
    accept(&n, &m2).unwrap();
    assert_eq!(persisted(&n), applied_tip(&n));
    assert_eq!(persisted(&n), Some(m2.block_hash()));

    // A heavier fork reorgs m1, m2 away.
    let f1 = empty_child(&n, gh, "f1");
    accept(&n, &f1).unwrap();
    let f2 = empty_child(&n, f1.block_hash(), "f2");
    accept(&n, &f2).unwrap();
    let f3 = empty_child(&n, f2.block_hash(), "f3");
    accept(&n, &f3).unwrap();
    assert_eq!(applied_tip(&n), Some(f3.block_hash()));
    assert_eq!(persisted(&n), applied_tip(&n));
    assert_eq!(n.shielded.read().tip(), applied_tip(&n));

    restart(&mut n);
    assert_eq!(n.shielded.read().tip(), Some(f3.block_hash()));
    let f4 = empty_child(&n, f3.block_hash(), "f4");
    accept(&n, &f4).unwrap();
    assert_eq!(persisted(&n), Some(f4.block_hash()));
}

/// A block carrying shielded transactions is still rejected context-free
/// (RejectAll), and leaves no shielded record behind.
#[test]
fn pipeline_rejects_shielded_blocks_under_reject_all() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let n = node_with(&genesis, &[]);
    let mut b = empty_child(&n, gh, "s1");
    b.shielded_transactions = vec![stx(n.shielded.read().anchor(), vec![h(1, 1)], vec![h(2, 1)])];
    b.header.merkle_root = b.body_merkle_root();
    while !b.validate_pow() {
        b.header.nonce += 1;
    }
    let err = accept(&n, &b).unwrap_err();
    assert!(err.contains("shielded consensus rejection"), "{err}");
    assert!(!n.dag.read().has_block(&b.block_hash()));
    assert_eq!(snap(&ShieldedPool::load(&n.store).unwrap()), ShieldedPool::new().engine.snapshot());
}
