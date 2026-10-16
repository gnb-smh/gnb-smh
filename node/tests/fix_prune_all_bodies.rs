//! Phase-4 package R4, B1-T17: pruning removes EVERY stored body below the
//! pruning height — selected-chain, merged, fork-loser and junk bodies alike
//! (Bitcoin Core prunes whole block files, stale blocks included) — and
//! writes the pruned-body rollback record only for blocks that are applied
//! (have an undo record).
//!
//! Pre-fix `Storage::prune_blocks_below` found the bodies to delete through
//! the selected-chain height index alone (one hash per height), so a merged
//! block, a fork-loser or an attacker's junk block was never pruned: the disk
//! use of a pruned node was not bounded by `PRUNING_DEPTH`.

mod fix_common;
use fix_common::*;

use gnb::consensus::{BlockHash, GhostDAG};
use gnb::core::{self, Block, BlockHeader, MerkleRoot, Transaction};
use gnb::pow;

struct Builder {
    dag: GhostDAG,
}

impl Builder {
    fn new(genesis: &Block) -> Self {
        let mut dag = GhostDAG::with_default_k();
        dag.add_genesis(genesis.block_hash(), genesis.header.timestamp);
        Builder { dag }
    }

    fn block(&mut self, parents: Vec<BlockHash>, tag: &str) -> Block {
        let height = parents.iter().map(|p| self.dag.get_block_data(p).unwrap().height).max().unwrap() + 1;
        let pts = parents.iter().map(|p| self.dag.get_block_data(p).unwrap().timestamp).max().unwrap();
        let bits = pow::expected_bits(pts, height).unwrap();
        let txs: Vec<Transaction> = vec![coinbase(tag, core::tokenomics::block_subsidy_sat(height), vec![0xC0; 20])];
        let mut b = Block {
            header: BlockHeader { version: 1, parents: parents.clone(), merkle_root: MerkleRoot::ZERO,
                timestamp: pts + 1, bits, nonce: 0 },
            transactions: txs, blue_score: height, height, shielded_transactions: Vec::new(),
            powit: Default::default(),
        };
        commit_block(&mut b);
        b.test_only_assume_pow_valid();
        self.dag.add_block(b.block_hash(), parents, b.header.timestamp, pow::work_from_bits(bits)).unwrap();
        b
    }
}

/// A chain of 30 blocks with, below the pruning height 20: a merged side
/// block (`s`, merged by the chain block at height 9), a lighter fork-loser
/// branch (`f1`, `f2` off height 5) and a deep "junk" block (a genesis
/// sibling). All four kinds of non-selected body are pruned with the chain's;
/// only applied blocks get a rollback record; the bodies above the pruning
/// height are kept.
#[test]
fn b1_t17_pruning_removes_merged_fork_loser_and_junk_bodies() {
    let genesis = mk_genesis(unix_now() - 100_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let mut n = node_with(&genesis, &[]);

    let mut chain: Vec<Block> = Vec::new();
    let mut tip = gh;
    let mut side: Option<Block> = None;
    for i in 1..=30u32 {
        let blk = if i == 9 {
            // Merge the side block `s` (a child of the chain block at height
            // 6, lighter than the selected parent at height 8).
            let s = side.clone().unwrap();
            accept(&n, &s).expect("side block stored");
            b.block(vec![tip, s.block_hash()], &format!("c{i}"))
        } else {
            b.block(vec![tip], &format!("c{i}"))
        };
        accept(&n, &blk).unwrap_or_else(|e| panic!("chain block {i}: {e}"));
        if i == 6 {
            side = Some(b.block(vec![blk.block_hash()], "s"));
        }
        tip = blk.block_hash();
        chain.push(blk);
    }
    let s_hash = side.unwrap().block_hash();
    assert_eq!(n.dag.read().get_block_data(&chain[8].block_hash()).unwrap().selected_parent,
        Some(chain[7].block_hash()), "the side block is merged, not selected");
    let f1 = b.block(vec![chain[4].block_hash()], "f1");
    let f2 = b.block(vec![f1.block_hash()], "f2");
    let junk = b.block(vec![gh], "junk");
    for x in [&f1, &f2, &junk] {
        accept(&n, x).expect("stored as a fork-loser");
    }
    assert_eq!(applied_tip(&n), Some(tip));
    for h in [s_hash, f1.block_hash(), f2.block_hash(), junk.block_hash()] {
        assert!(n.store.has_block_body(&h).unwrap());
        assert!(!n.store.has_undo_data(&h).unwrap(), "not applied");
    }

    n.store.prune_blocks_below(20).unwrap();

    for (what, h) in [("merged", s_hash), ("fork-loser", f1.block_hash()), ("fork-loser", f2.block_hash()),
                      ("junk", junk.block_hash())] {
        assert!(!n.store.has_block_body(&h).unwrap(), "{what} body below the pruning height is pruned");
        assert!(n.store.get_pruned_body_record(&h).unwrap().is_none(),
            "{what} block: no undo record, so no rollback record");
        assert!(!gnb::accept::awaits_body(&n.dag, &n.store, &h), "a pruned body is not wanted back");
    }
    for blk in &chain[..19] {
        assert!(!n.store.has_block_body(&blk.block_hash()).unwrap());
        assert!(n.store.get_pruned_body_record(&blk.block_hash()).unwrap().is_some(), "applied: record kept");
    }
    for blk in &chain[19..] {
        assert!(n.store.has_block_body(&blk.block_hash()).unwrap(), "bodies above the pruning height stay");
    }
    // The node keeps working: the chain extends, and a restart is clean.
    let next = b.block(vec![tip], "c31");
    accept(&n, &next).unwrap();
    assert_eq!(applied_tip(&n), Some(next.block_hash()));
    assert!(gnb::accept::check_chain_state(&n.dag, &n.store).unwrap().is_empty());
    restart(&mut n);
    assert_eq!(applied_tip(&n), Some(next.block_hash()));
    assert!(gnb::accept::check_chain_state(&n.dag, &n.store).unwrap().is_empty(),
        "start-up finds nothing to repair after the non-selected bodies were pruned");
    let next2 = b.block(vec![next.block_hash()], "c32");
    accept(&n, &next2).unwrap();
    assert_eq!(applied_tip(&n), Some(next2.block_hash()));
}

/// Review finding on B1-T17: a body that is deleted (a rejected body,
/// `accept::drop_body_and_wait`, or a rolled-back insertion) lost its body but
/// kept its body-index row, and a re-stored body got a second row. The stale
/// LOW row then pruned the re-stored body, which the node had indexed higher
/// to keep it until the chain through it connects. Every body now has
/// exactly one row: a write moves it, a deletion removes it, and pruning
/// ignores a row that is not the body's current one.
#[test]
fn b1_t17_a_re_stored_body_is_pruned_by_its_current_index_row_only() {
    let genesis = mk_genesis(unix_now() - 100_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let n = node_with(&genesis, &[]);
    let x = b.block(vec![gh], "x");
    let y = b.block(vec![gh], "y");
    let z = b.block(vec![gh], "z");
    let w = b.block(vec![gh], "w");
    let v = b.block(vec![gh], "v");
    let rows_of = |hashes: &[BlockHash]| {
        let db = n.store.db();
        let cf = db.cf_handle("meta").unwrap();
        db.prefix_iterator_cf(cf, b"body_h")
            .map(|kv| kv.unwrap().0.to_vec())
            .take_while(|k| k.starts_with(b"body_h"))
            .filter(|k| hashes.iter().any(|h| k.ends_with(h)))
            .count()
    };

    // A deletion removes the body's rows at once (forward and reverse).
    n.store.put_block_body_at(&w, 5).unwrap();
    assert_eq!(rows_of(&[w.block_hash()]), 2);
    n.store.delete_block_body(&w.block_hash()).unwrap();
    assert_eq!(rows_of(&[w.block_hash()]), 0, "no index row outlives a deleted body");
    // A stale forward row (none can be written any more; this models one
    // left at a lower height) is ignored by pruning: the current row decides.
    n.store.put_block_body_at(&v, 50).unwrap();
    {
        let db = n.store.db();
        let cf = db.cf_handle("meta").unwrap();
        let mut k = gnb::storage::BODY_INDEX_PREFIX.to_vec();
        k.extend_from_slice(&3u64.to_be_bytes());
        k.extend_from_slice(&v.block_hash());
        db.put_cf(cf, k, []).unwrap();
    }

    // Deleted, then re-stored higher: the old row goes with the deletion.
    n.store.put_block_body_at(&x, 5).unwrap();
    n.store.delete_block_body(&x.block_hash()).unwrap();
    n.store.put_block_body_at(&x, 50).unwrap();
    // Re-stored higher without a deletion: the write moves the row.
    n.store.put_block_body_at(&y, 5).unwrap();
    n.store.put_block_body_at(&y, 50).unwrap();
    assert_eq!(rows_of(&[y.block_hash()]), 2, "one forward row (moved to 50) and its reverse row");
    // Re-stored LOWER: the latest write decides.
    n.store.put_block_body_at(&z, 50).unwrap();
    n.store.put_block_body_at(&z, 5).unwrap();

    n.store.prune_blocks_below(6).unwrap();
    assert!(n.store.has_block_body(&v.block_hash()).unwrap(), "a stale row does not prune the body");
    assert_eq!(rows_of(&[v.block_hash()]), 2, "the stale row is dropped, the current one kept");
    assert!(n.store.has_block_body(&x.block_hash()).unwrap(), "no stale row prunes the re-stored body");
    assert!(n.store.has_block_body(&y.block_hash()).unwrap(), "the row moved with the second write");
    assert!(!n.store.has_block_body(&z.block_hash()).unwrap(), "indexed at 5 by its last write");
    n.store.prune_blocks_below(51).unwrap();
    for h in [x.block_hash(), y.block_hash(), v.block_hash()] {
        assert!(!n.store.has_block_body(&h).unwrap(), "pruned once the cursor passes its current row");
    }
    assert_eq!(rows_of(&[x.block_hash(), y.block_hash(), z.block_hash(), v.block_hash()]), 0,
        "no index row (forward or reverse) outlives its body");
}

/// Review finding on B1-T17, through the acceptance pipeline: a body the
/// node wants back (here: its stored body was deleted, as
/// `drop_body_and_wait` does, below the pruning cursor's next step) is
/// re-stored by the replacing path indexed at max(own DAG height, selected
/// tip height), so the next pruning step past its own height keeps it until
/// the cursor passes the tip it was stored at.
#[test]
fn b1_t17_a_body_fetched_back_is_kept_until_the_tip_it_was_stored_at() {
    let genesis = mk_genesis(unix_now() - 100_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let n = node_with(&genesis, &[]);
    let mut tip = gh;
    let mut chain = Vec::new();
    for i in 1..=30u32 {
        let blk = b.block(vec![tip], &format!("k{i}"));
        accept(&n, &blk).unwrap();
        tip = blk.block_hash();
        chain.push(blk);
    }
    let f = b.block(vec![chain[1].block_hash()], "f");
    let fh = f.block_hash();
    accept(&n, &f).expect("stored as a fork-loser");
    assert_eq!(n.dag.read().get_block_data(&fh).unwrap().height, 3);

    // Its body is dropped (a witness-dependent rejection deletes it); the
    // node wants a copy and takes the next one.
    n.store.delete_block_body(&fh).unwrap();
    assert!(gnb::accept::awaits_body(&n.dag, &n.store, &fh));
    accept(&n, &f).expect("the replacement body is taken");
    assert!(n.store.has_block_body(&fh).unwrap());
    assert!(!gnb::accept::awaits_body(&n.dag, &n.store, &fh));

    n.store.prune_blocks_below(4).unwrap();
    assert!(n.store.has_block_body(&fh).unwrap(),
        "indexed at the selected tip's height (30), not its own (3): kept past the next pruning step");
    assert!(!n.store.has_block_body(&chain[1].block_hash()).unwrap(), "the chain below 4 is pruned");
    n.store.prune_blocks_below(30).unwrap();
    assert!(n.store.has_block_body(&fh).unwrap());
    n.store.prune_blocks_below(31).unwrap();
    assert!(!n.store.has_block_body(&fh).unwrap(), "pruned once the cursor passes the tip height");
}

/// A database written before the body height index existed (no index rows,
/// no ready marker) is backfilled once, from the CF_DAG heights, the first
/// time it is pruned; bodies above the pruning height stay, and the pruning
/// call after that reads only the index.
#[test]
fn b1_t17_an_older_database_is_backfilled_then_pruned() {
    let genesis = mk_genesis(unix_now() - 100_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let n = node_with(&genesis, &[]);
    let mut tip = gh;
    let mut chain = Vec::new();
    for i in 1..=12u32 {
        let blk = b.block(vec![tip], &format!("o{i}"));
        accept(&n, &blk).unwrap();
        tip = blk.block_hash();
        chain.push(blk);
    }
    let loser = b.block(vec![chain[1].block_hash()], "loser");
    accept(&n, &loser).unwrap();

    // Make it look like an older release wrote it: drop every index row and
    // the ready marker.
    {
        let db = n.store.db();
        let cf = db.cf_handle("meta").unwrap();
        let keys: Vec<Vec<u8>> = db.prefix_iterator_cf(cf, gnb::storage::BODY_INDEX_PREFIX)
            .map(|kv| kv.unwrap().0.to_vec())
            .take_while(|k| k.starts_with(gnb::storage::BODY_INDEX_PREFIX))
            .collect();
        assert!(keys.len() >= 13, "every accepted body was indexed ({} rows)", keys.len());
        for k in keys {
            db.delete_cf(cf, k).unwrap();
        }
        // ...and the reverse rows (`body_hk/` ‖ hash).
        let reverse: Vec<Vec<u8>> = db.prefix_iterator_cf(cf, b"body_hk/")
            .map(|kv| kv.unwrap().0.to_vec())
            .take_while(|k| k.starts_with(b"body_hk/"))
            .collect();
        assert!(reverse.len() >= 13);
        for k in reverse {
            db.delete_cf(cf, k).unwrap();
        }
        db.delete_cf(cf, b"body_index_v1").unwrap();
    }

    assert_eq!(n.store.prune_blocks_below(8).unwrap(), 9, "genesis, 7 chain bodies and the fork-loser");
    assert!(!n.store.has_block_body(&loser.block_hash()).unwrap());
    assert!(n.store.has_block_body(&chain[7].block_hash()).unwrap(), "height 8 stays");
    assert_eq!(n.store.ensure_body_index().unwrap(), 0, "backfilled once");
    assert_eq!(n.store.prune_blocks_below(10).unwrap(), 2);
    assert_eq!(n.store.pruned_height(), 10);
}
