//! Audit DAG-8 + DAG-12 item (5): the selected-chain indexes (height ->
//! hash, height -> timestamp, the address history) were keyed by the HEADER
//! height, which repeats and decreases along the selected chain (a block
//! that merges a parent with a greater DAG height than its selected parent
//! has a header height above its chain position). Two selected-chain blocks
//! then shared a row: the later one overwrote the earlier one's, and
//! disconnecting it deleted the row of a block still on the chain, so
//! `getblockhash` / `getblock` by height and `prune_blocks_below` acted on
//! the wrong block or none. The indexes are now keyed by the selected-chain
//! position, the DAG height (`GhostdagData::height`), which is 0, 1, 2, ...
//! along the selected chain: unique, like Bitcoin Core's active-chain height.

mod fix_common;
use fix_common::*;

use gnb::accept;
use gnb::consensus::BlockHash;
use gnb::core::{activation, Block};
use gnb::reorg;

const ADDR: [u8; 20] = [0xC0; 20];

fn dag_height(n: &Node, h: &BlockHash) -> u64 {
    n.dag.read().get_block_data(h).unwrap().height
}

/// Every block of the applied selected chain is at its DAG height in the
/// height and timestamp indexes, and nothing else is.
fn assert_index_is_the_chain(n: &Node, what: &str) {
    let tip = applied_tip(n).unwrap();
    let mut chain = Vec::new();
    let mut cur = Some(tip);
    while let Some(h) = cur {
        chain.push(h);
        cur = n.dag.read().get_block_data(&h).and_then(|d| d.selected_parent);
    }
    chain.reverse();
    for (pos, h) in chain.iter().enumerate() {
        assert_eq!(dag_height(n, h), pos as u64);
        assert_eq!(n.store.get_block_hash_at_height(pos as u64).unwrap(), Some(*h), "{what}: position {pos}");
        let ts = n.dag.read().get_block_data(h).unwrap().timestamp;
        assert_eq!(n.store.get_timestamp_at_height(pos as u64).unwrap(), Some(ts), "{what}: timestamp {pos}");
    }
    assert_eq!(n.store.get_block_hash_at_height(chain.len() as u64).unwrap(), None, "{what}: nothing above the tip");
    assert_eq!(n.store.get_tip_height().unwrap(), chain.len() as u64 - 1, "{what}: tip height");
}

/// The coinbase txids the address history lists for `ADDR`, with the index
/// position of each row.
fn history(n: &Node) -> Vec<(u64, [u8; 32])> {
    n.store.query_address_history(&ADDR, 0, u64::MAX, 10_000, 0).unwrap()
        .into_iter().map(|e| (e.height, e.txid)).collect()
}

fn cb(b: &Block) -> [u8; 32] {
    b.transactions[0].txid()
}

/// The DAG-8 shape: four siblings merged by S (DAG height 2, the heaviest),
/// a lighter chain M1..M4 (DAG height 4), B merging M4 under S (DAG height
/// 3, header height 5), then C and D on B (header heights 4 and 5). `d_addr`
/// is the address D's coinbase pays.
fn dag8_shape(n: &Node, d_addr: [u8; 20]) -> (Block, Block, Block, Block, Vec<Block>) {
    let gh = n.dag.read().store.genesis.unwrap();
    let ps: Vec<Block> = (0..4).map(|i| empty_child(n, gh, &format!("p{i}"))).collect();
    for p in &ps {
        accept(n, p).unwrap();
    }
    let s = mk_block(n, ps.iter().map(|p| p.block_hash()).collect(),
        vec![coinbase("s", gnb::core::tokenomics::block_subsidy_sat(2), ADDR.to_vec())]);
    accept(n, &s).unwrap();
    let mut m = gh;
    let mut ms = Vec::new();
    for i in 0..4 {
        let b = empty_child(n, m, &format!("m{i}"));
        accept(n, &b).unwrap();
        m = b.block_hash();
        ms.push(b);
    }
    assert_eq!(applied_tip(n), Some(s.block_hash()), "the wide branch is heavier");
    let b = mk_block(n, vec![s.block_hash(), m],
        vec![coinbase("b", gnb::core::tokenomics::block_subsidy_sat(5), ADDR.to_vec())]);
    accept(n, &b).unwrap();
    let c = empty_child(n, b.block_hash(), "c");
    accept(n, &c).unwrap();
    let d = mk_block(n, vec![c.block_hash()],
        vec![coinbase("d", gnb::core::tokenomics::block_subsidy_sat(5), d_addr.to_vec())]);
    accept(n, &d).unwrap();
    assert_eq!(applied_tip(n), Some(d.block_hash()));
    assert_eq!((b.height, dag_height(n, &b.block_hash()), c.height, d.height), (5, 3, 4, 5));
    (s, b, c, d, ms)
}

/// A data dir of an earlier release (header-height keys, B's rows replaced by
/// D's, a pruned block's record naming header-height keys) is migrated once
/// at start-up: the indexes are the selected chain at its positions again,
/// the address history of bodied and pruned blocks is at their positions,
/// and a later rollback of the pruned block deletes its rows.
#[test]
fn an_old_layout_data_dir_is_migrated_at_start_up() {
    let _g = activation::scoped_override(0);
    let genesis = mk_genesis(unix_now() - 10_000);
    let mut n = node_with(&genesis, &[]);
    let (s, b, c, d, _ms) = dag8_shape(&n, [0xD0; 20]);
    assert_eq!(n.store.prune_blocks_below(4).unwrap(), 4, "G, a P, S and B pruned");

    // Rewrite the three indexes in the old layout, in connect order.
    let chain: Vec<BlockHash> = {
        let mut v = n.dag.read().selected_chain();
        v.reverse();
        v
    };
    {
        let db = n.store.db();
        for cf in ["height", "timestamps", "addr_tx_history"] {
            let h = db.cf_handle(cf).unwrap();
            let keys: Vec<Vec<u8>> = db.iterator_cf(&h, rocksdb::IteratorMode::Start).map(|r| r.unwrap().0.to_vec()).collect();
            for k in keys {
                db.delete_cf(&h, &k).unwrap();
            }
        }
    }
    for h in &chain {
        let data = n.dag.read().get_block_data(h).cloned().unwrap();
        match n.store.get_block(h).unwrap() {
            Some(body) => {
                let mut batch = rocksdb::WriteBatch::default();
                n.store.stage_chain_index(&mut batch, &body, body.height, &Default::default()).unwrap();
                n.store.write_batch(batch).unwrap();
            }
            None => {
                // Pruned: its header height is in its undo record.
                let header_height = n.store.get_undo_data(h).unwrap().map(|u| u.block_height).unwrap_or(0);
                let mut batch = rocksdb::WriteBatch::default();
                n.store.stage_chain_position(&mut batch, header_height, h, data.timestamp).unwrap();
                n.store.write_batch(batch).unwrap();
                let mut rec = n.store.get_pruned_body_record(h).unwrap().unwrap();
                rec.addr_history_keys = rec.addr_history_keys.iter()
                    .map(|k| gnb::storage::indexer::with_position(k, header_height)).collect();
                let db = n.store.db();
                let cf = db.cf_handle("addr_tx_history").unwrap();
                let blk_cb = if *h == b.block_hash() { cb(&b) } else if *h == s.block_hash() { cb(&s) } else {
                    // G and the P are coinbase-only blocks paying 0xC0 too.
                    [0u8; 32]
                };
                for k in &rec.addr_history_keys {
                    if blk_cb != [0u8; 32] {
                        db.put_cf(&cf, k, gnb::storage::indexer::make_value(&blk_cb, gnb::storage::indexer::DIR_OUT, 1)).unwrap();
                    }
                }
                db.put_cf(&db.cf_handle("undo").unwrap(), gnb::storage::pruned_body_key(h),
                    bincode::serde::encode_to_vec(&rec, bincode::config::standard()).unwrap()).unwrap();
            }
        }
    }
    {
        let db = n.store.db();
        db.delete_cf(&db.cf_handle("meta").unwrap(), gnb::storage::CHAIN_INDEX_VERSION_META).unwrap();
    }
    assert_eq!(n.store.chain_index_version().unwrap(), 1, "old layout");
    assert_eq!(n.store.get_block_hash_at_height(5).unwrap(), Some(d.block_hash()), "old layout: D replaced B's row");

    restart(&mut n); // reconcile_on_startup migrates first
    assert_eq!(n.store.chain_index_version().unwrap(), gnb::storage::CHAIN_INDEX_VERSION);
    assert_index_is_the_chain(&n, "migrated");
    let h = history(&n);
    assert!(h.iter().any(|(pos, t)| *t == cb(&b) && *pos == 3), "pruned B's row moved to its position");
    assert!(h.iter().any(|(pos, t)| *t == cb(&c) && *pos == 4), "bodied C's row at its position");
    assert!(!accept::migrate_chain_indexes(&n.dag, &n.store).unwrap(), "migrates once");

    // The migrated pruned-body records drive a later rollback correctly.
    accept::invalidate_block(s.block_hash(), &n.dag, &n.store, &n.mempool, &n.node_state, None, &n.shielded)
        .expect("invalidate S");
    assert_index_is_the_chain(&n, "after invalidating S");
    let h = history(&n);
    for x in [&s, &b, &c] {
        assert!(!h.iter().any(|(_, t)| *t == cb(x)), "rolled-back row of {} removed", hex::encode(&x.block_hash()[..4]));
    }
}

#[test]
fn chain_indexes_are_keyed_by_the_selected_chain_position() {
    let _g = activation::scoped_override(0); // Kaspa blue work: merged blues weigh
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let n = node_with(&genesis, &[]);
    // A wide, heavy branch: four siblings merged by S (DAG height 2, blue
    // work 5 blocks) ...
    let ps: Vec<Block> = (0..4).map(|i| empty_child(&n, gh, &format!("p{i}"))).collect();
    for p in &ps {
        accept(&n, p).unwrap();
    }
    let s = mk_block(&n, ps.iter().map(|p| p.block_hash()).collect(),
        vec![coinbase("s", gnb::core::tokenomics::block_subsidy_sat(2), ADDR.to_vec())]);
    accept(&n, &s).unwrap();
    // ... and a long, lighter one (DAG height 4, blue work 4 blocks).
    let mut m = gh;
    let mut ms = Vec::new();
    for i in 0..4 {
        let b = empty_child(&n, m, &format!("m{i}"));
        accept(&n, &b).unwrap();
        m = b.block_hash();
        ms.push(b);
    }
    assert_eq!(applied_tip(&n), Some(s.block_hash()), "the wide branch is heavier");
    // B merges the long branch under S: DAG height 3, header height 5.
    let b = mk_block(&n, vec![s.block_hash(), m],
        vec![coinbase("b", gnb::core::tokenomics::block_subsidy_sat(5), ADDR.to_vec())]);
    accept(&n, &b).unwrap();
    let c = empty_child(&n, b.block_hash(), "c");
    accept(&n, &c).unwrap();
    let d = empty_child(&n, c.block_hash(), "d");
    accept(&n, &d).unwrap();
    assert_eq!(applied_tip(&n), Some(d.block_hash()));
    assert_eq!((b.height, dag_height(&n, &b.block_hash())), (5, 3), "B's header height is above its position");
    assert_eq!((c.height, d.height), (4, 5), "header heights decrease, then repeat B's");
    assert_index_is_the_chain(&n, "after D");
    let h = history(&n);
    for x in [&s, &b, &c, &d] {
        assert_eq!(h.iter().filter(|(_, t)| *t == cb(x)).count(), 1, "one history row for each chain coinbase");
    }
    assert!(h.iter().any(|(pos, t)| *t == cb(&b) && *pos == 3), "B's row is at its position");

    // Disconnecting D (operator invalidateblock) keeps B's rows.
    accept::invalidate_block(d.block_hash(), &n.dag, &n.store, &n.mempool, &n.node_state, None, &n.shielded)
        .expect("invalidate D");
    assert_eq!(applied_tip(&n), Some(c.block_hash()));
    assert_index_is_the_chain(&n, "after invalidating D");
    let h = history(&n);
    assert!(h.iter().any(|(_, t)| *t == cb(&b)), "B's history row survives D's disconnect");
    assert!(!h.iter().any(|(_, t)| *t == cb(&d)));

    // Pruning below position 4 prunes every chain block below it, B included.
    assert_eq!(n.store.prune_blocks_below(4).unwrap(), 4, "G, a P, S and B");
    for x in [&s, &b] {
        assert!(!n.store.has_block_body(&x.block_hash()).unwrap(), "{} pruned", hex::encode(&x.block_hash()[..4]));
    }
    assert!(n.store.has_block_body(&c.block_hash()).unwrap());

    // A reorg through pruned blocks (invalidate S: C, B and S are rolled
    // back, B and S from their undo and pruned-body records) un-indexes
    // exactly their rows and the long branch is indexed at its positions.
    accept::invalidate_block(s.block_hash(), &n.dag, &n.store, &n.mempool, &n.node_state, None, &n.shielded)
        .expect("invalidate S");
    assert_eq!(applied_tip(&n), Some(m));
    assert_index_is_the_chain(&n, "after invalidating S");
    let h = history(&n);
    for x in [&s, &b, &c] {
        assert!(!h.iter().any(|(_, t)| *t == cb(x)), "rolled-back row of {} removed", hex::encode(&x.block_hash()[..4]));
    }
    for (i, x) in ms.iter().enumerate() {
        assert!(h.iter().any(|(pos, t)| *t == cb(x) && *pos == i as u64 + 1), "M{i} at position {}", i + 1);
    }
}

/// DAG-8 migration (review): a release before audit DAG-6 pruned bodies
/// without a pruned-body record and kept their address-history rows (keyed
/// by header height). The migration deleted every row and rebuilt only those
/// of bodied blocks and of blocks with a record, so the whole pruned range's
/// history was lost, silently. Such rows are now attributed to their block
/// through the transaction index, moved to its position, and a record
/// naming them is written, so a later rollback deletes them.
#[test]
fn an_old_layout_pruned_block_without_a_record_keeps_its_history() {
    let _g = activation::scoped_override(0);
    let genesis = mk_genesis(unix_now() - 10_000);
    let mut n = node_with(&genesis, &[]);
    let (s, b, c, d, ms) = dag8_shape(&n, [0xD0; 20]);
    let chain: Vec<BlockHash> = {
        let mut v = n.dag.read().selected_chain();
        v.reverse();
        v
    };
    let p = n.store.get_block(&chain[1]).unwrap().unwrap(); // the P S selects
    let bodies: Vec<Block> = chain.iter().map(|h| n.store.get_block(h).unwrap().unwrap()).collect();

    // The pre-DAG-6 prune: bodies gone, rows kept, no record.
    assert_eq!(n.store.prune_blocks_below(4).unwrap(), 4, "G, P, S and B pruned");
    {
        let db = n.store.db();
        for h in &chain[..4] {
            db.delete_cf(&db.cf_handle("undo").unwrap(), gnb::storage::pruned_body_key(h)).unwrap();
        }
        for cf in ["height", "timestamps", "addr_tx_history"] {
            let h = db.cf_handle(cf).unwrap();
            let keys: Vec<Vec<u8>> = db.iterator_cf(&h, rocksdb::IteratorMode::Start).map(|r| r.unwrap().0.to_vec()).collect();
            for k in keys {
                db.delete_cf(&h, &k).unwrap();
            }
        }
        db.delete_cf(&db.cf_handle("meta").unwrap(), gnb::storage::CHAIN_INDEX_VERSION_META).unwrap();
    }
    // The old layout, written by the connects in chain order (header-height
    // keys; D's height row replaces B's).
    for body in &bodies {
        let mut batch = rocksdb::WriteBatch::default();
        if body.header.parents.is_empty() {
            n.store.stage_chain_position(&mut batch, 0, &body.block_hash(), body.header.timestamp).unwrap();
        } else {
            n.store.stage_chain_index(&mut batch, body, body.height, &Default::default()).unwrap();
        }
        n.store.write_batch(batch).unwrap();
    }
    for x in [&p, &s, &b] {
        assert!(!n.store.has_block_body(&x.block_hash()).unwrap());
        assert!(n.store.get_pruned_body_record(&x.block_hash()).unwrap().is_none(), "no record (pre-DAG-6)");
    }
    assert_eq!(n.store.chain_index_version().unwrap(), 1, "old layout");
    assert!(history(&n).iter().any(|(pos, t)| *t == cb(&b) && *pos == 5), "old layout: B's row at its header height");

    restart(&mut n); // reconcile_on_startup migrates first
    assert_eq!(n.store.chain_index_version().unwrap(), gnb::storage::CHAIN_INDEX_VERSION);
    assert_index_is_the_chain(&n, "migrated");
    let h = history(&n);
    for (x, pos) in [(&p, 1u64), (&s, 2), (&b, 3), (&c, 4)] {
        assert_eq!(h.iter().filter(|(_, t)| *t == cb(x)).count(), 1, "one row of {}", hex::encode(&x.block_hash()[..4]));
        assert!(h.iter().any(|(q, t)| *t == cb(x) && *q == pos),
            "the row of {} is at its position {pos}: {h:?}", hex::encode(&x.block_hash()[..4]));
    }
    // A record naming the moved rows is written for each such block.
    for (x, pos) in [(&p, 1u64), (&s, 2), (&b, 3)] {
        let rec = n.store.get_pruned_body_record(&x.block_hash()).unwrap().expect("record written");
        assert_eq!(rec.height, x.height);
        assert_eq!(rec.addr_history_keys, vec![gnb::storage::indexer::make_key(&ADDR, pos, 0, 0)]);
    }

    // The records drive a later rollback: invalidating S rolls back D, C, B,
    // S and P (the M branch is the best chain then) and deletes their rows.
    accept::invalidate_block(s.block_hash(), &n.dag, &n.store, &n.mempool, &n.node_state, None, &n.shielded)
        .expect("invalidate S");
    assert_index_is_the_chain(&n, "after invalidating S");
    let h = history(&n);
    for x in [&p, &s, &b, &c] {
        assert!(!h.iter().any(|(_, t)| *t == cb(x)), "rolled-back row of {} removed", hex::encode(&x.block_hash()[..4]));
    }
    for (i, x) in ms.iter().enumerate() {
        assert!(h.iter().any(|(pos, t)| *t == cb(x) && *pos == i as u64 + 1), "M{i} at position {}", i + 1);
    }
    let _ = d;
}

/// DAG-8 migration (review): the migration ran before reconciliation's step
/// 2 and indexed the chain of meta `tip_hash`, while step 2 re-tips to the
/// block the UTXO set really sits on. Footprint of a pre-fix reorg that
/// crashed before its DAG and tip writes: the UTXO set moved from A1 to
/// B1 + B2, B2 has no DAG record, `tip_hash` still names A1. A1 is
/// disqualified (an operator mark of an earlier run), so the best chain
/// without B2 is B1's and step 4 does not move the chain. The migration
/// indexed A1 at position 1 (with A1's address history) and nothing ever
/// rewrote it; it now indexes the chain step 2 leaves applied, B1's.
#[test]
fn the_migration_indexes_the_chain_reconciliation_leaves_applied() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let mut n = node_with(&genesis, &[]);
    let sub1 = gnb::core::tokenomics::block_subsidy_sat(1);
    let a1 = mk_block(&n, vec![gh], vec![coinbase("a1", sub1, vec![0xA1; 20])]);
    let b1 = mk_block_where(&n, vec![gh], vec![coinbase("b1", sub1, vec![0xB1; 20])], |h| *h < a1.block_hash());
    accept(&n, &a1).unwrap();
    accept(&n, &b1).unwrap();
    assert_eq!(applied_tip(&n), Some(a1.block_hash()), "B1 is a fork-loser");
    let b2 = mk_block(&n, vec![b1.block_hash()],
        vec![coinbase("b2", gnb::core::tokenomics::block_subsidy_sat(2), vec![0xB2; 20])]);

    // The pre-fix reorg path, up to the crash point.
    n.store.put_block(&b2).unwrap();
    let plan = reorg::ReorgPlan {
        lca: gh, to_rollback: vec![a1.block_hash()], to_apply: vec![b1.block_hash(), b2.block_hash()],
    };
    let validate = |_: &dyn reorg::UtxoView, _: &Block| -> Result<(), String> { Ok(()) };
    let stage_extra = |_: &gnb::storage::Storage, _: &mut rocksdb::WriteBatch| -> Result<(), String> { Ok(()) };
    reorg::connect_plan(&n.store, &plan, &reorg::ConnectHooks { validate: &validate, stage_extra: &stage_extra })
        .unwrap();
    assert_eq!(applied_tip(&n), Some(a1.block_hash()), "crash state: tip pointer not rewritten");
    let mut batch = rocksdb::WriteBatch::default();
    n.store.stage_invalid_block(&mut batch, &a1.block_hash(), accept::OPERATOR_INVALIDATE_REASON).unwrap();
    n.store.write_batch(batch).unwrap();
    {
        let db = n.store.db();
        db.delete_cf(&db.cf_handle("meta").unwrap(), gnb::storage::CHAIN_INDEX_VERSION_META).unwrap();
    }
    assert_eq!(n.store.chain_index_version().unwrap(), 1, "a data dir of an earlier release");

    restart(&mut n);
    assert_eq!(n.store.chain_index_version().unwrap(), gnb::storage::CHAIN_INDEX_VERSION);
    assert_eq!(applied_tip(&n), Some(b1.block_hash()), "step 2 re-tipped to B1");
    assert_eq!(sel_tip(&n), Some(b1.block_hash()), "and B1 is the best block");
    assert_eq!(n.store.get_block_hash_at_height(1).unwrap(), Some(b1.block_hash()), "position 1 is B1, not A1");
    assert_index_is_the_chain(&n, "after reconciliation");
    let rows = |a: [u8; 20]| n.store.query_address_history(&a, 0, u64::MAX, 100, 0).unwrap();
    assert!(rows([0xA1; 20]).is_empty(), "no history of the unapplied A1");
    assert!(rows([0xB1; 20]).iter().any(|e| e.txid == cb(&b1) && e.height == 1), "B1's history at position 1");
    assert!(rows([0xB2; 20]).is_empty(), "B2 rolled back");
}

/// Every row of the three selected-chain index column families.
fn index_rows(n: &Node) -> Vec<(&'static str, Vec<u8>, Vec<u8>)> {
    let db = n.store.db();
    let mut out = Vec::new();
    for cf in ["height", "timestamps", "addr_tx_history"] {
        let h = db.cf_handle(cf).unwrap();
        for r in db.iterator_cf(&h, rocksdb::IteratorMode::Start) {
            let (k, v) = r.unwrap();
            out.push((cf, k.to_vec(), v.to_vec()));
        }
    }
    out
}

/// `--reindex-addresses` (main's d400bd0, "keep spends in the address
/// history across reorgs") is the DAG-8 rebuild, not a second layout: on a
/// chain with pruned blocks and a spend of a genesis-ledger output (an
/// outpoint no transaction creates), a history that lost its spend rows (the
/// reorg bug of earlier releases) and holds rows keyed by header height and
/// rows of a block off the chain is rebuilt to exactly what the connects
/// wrote, keyed by chain position, the spends resolved from the undo
/// records (no carryover snapshot), the pruned blocks' rows kept. Running it
/// again changes nothing.
#[test]
fn reindex_addresses_rebuilds_exactly_what_the_connects_wrote() {
    use gnb::storage::indexer::{make_key, make_value, parse_value, with_position, DIR_IN, DIR_OUT};
    let _g = activation::scoped_override(0);
    let genesis = mk_genesis(unix_now() - 10_000);
    let k = key();
    let fund = ([0x61; 32], 0u32, out(4_000_000, &k.spk));
    let n = node_with(&genesis, std::slice::from_ref(&fund));
    // As main() at first boot: the genesis coinbase is in the tx index (the
    // rebuild keeps a pruned block's row only if the row's txid is its own).
    for tx in &genesis.transactions {
        n.store.put_tx_index(&tx.txid(), &genesis.block_hash(), 0).unwrap();
    }
    let (s, b, _c, d, ms) = dag8_shape(&n, [0xD0; 20]);
    let spend = signed_spend_at(&k, &[(fund.0, fund.1)], std::slice::from_ref(&fund.2),
        vec![out(3_000_000, &ADDR), out(900_000, &k.spk)], 6);
    let e = mk_block(&n, vec![d.block_hash()],
        vec![coinbase("e", gnb::core::tokenomics::block_subsidy_sat(6) + 100_000, ADDR.to_vec()), spend.clone()]);
    accept(&n, &e).unwrap();
    assert_eq!(applied_tip(&n), Some(e.block_hash()));
    assert_eq!(n.store.prune_blocks_below(4).unwrap(), 4, "G, a P, S and B pruned");
    let k_addr: [u8; 20] = k.spk[..20].try_into().unwrap();
    let spent_row = make_key(&k_addr, dag_height(&n, &e.block_hash()), 1, 0x8000_0000);
    let connected = index_rows(&n);
    assert!(connected.iter().any(|(cf, key, v)| *cf == "addr_tx_history" && *key == spent_row
        && parse_value(v) == Some((spend.txid(), DIR_IN, 4_000_000))), "the connect wrote the genesis-ledger spend");

    // Damage, as earlier releases left it: every spend row gone, B's row
    // also at its header height (5), a row of M1 (off the chain).
    {
        let db = n.store.db();
        let cf = db.cf_handle("addr_tx_history").unwrap();
        for (_, key, v) in connected.iter().filter(|(c, _, _)| *c == "addr_tx_history") {
            if parse_value(v).map(|(_, dir, _)| dir) == Some(DIR_IN) {
                db.delete_cf(&cf, key).unwrap();
            }
        }
        let b_row = make_key(&ADDR, 3, 0, 0);
        db.put_cf(&cf, with_position(&b_row, b.height), make_value(&cb(&b), DIR_OUT, 1)).unwrap();
        db.put_cf(&cf, make_key(&[0xEE; 20], 1, 0, 0), make_value(&cb(&ms[0]), DIR_OUT, 1)).unwrap();
    }
    assert_ne!(index_rows(&n), connected);

    let r = accept::reindex_chain_indexes(&n.dag, &n.store).unwrap();
    assert_eq!((r.blocks, r.lost, r.unresolved), (7, 0, 0), "G, P, S, B, C, D, E; {r:?}");
    assert_eq!(index_rows(&n), connected, "exactly what the connects wrote");
    assert_eq!(n.store.chain_index_version().unwrap(), gnb::storage::CHAIN_INDEX_VERSION);
    assert_index_is_the_chain(&n, "reindexed");
    assert!(history(&n).iter().any(|(pos, t)| *t == cb(&s) && *pos == 2), "pruned S's row kept");
    assert_eq!(accept::reindex_chain_indexes(&n.dag, &n.store).unwrap(), r);
    assert_eq!(index_rows(&n), connected, "idempotent");
}
