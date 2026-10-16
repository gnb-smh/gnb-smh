//! Audit VAL-11 residual: the node had no way to audit its UTXO set against
//! the issuance — no counterpart of Bitcoin Core's `gettxoutsetinfo`, which
//! iterates the coins database over one snapshot and returns the number of
//! outputs, their total and a hash of the set, so an operator (or a monitor)
//! can see that the supply is what the issuance schedule allows and that two
//! nodes hold the same set. `Storage::utxo_set_audit` (RPC
//! `gettxoutsetinfo`) does that here, and also checks the scan against the
//! aggregates the node maintains with every UTXO change, so a row changed
//! outside the node is detected even when the total stays within the bound.

mod fix_common;
use fix_common::*;

use std::sync::atomic::AtomicBool;

use gnb::consensus::BlockHash;
use gnb::core::{activation, tokenomics, Block, TxOutput};
use gnb::storage::utxo_audit::{GenesisLedger, UtxoSetAudit};

fn subsidy(h: u64) -> u64 {
    tokenomics::block_subsidy_sat(h)
}

fn audit(n: &Node) -> UtxoSetAudit {
    audit_with(n, LEDGER)
}

fn audit_with(n: &Node, ledger: GenesisLedger) -> UtxoSetAudit {
    n.store.utxo_set_audit(ledger, &AtomicBool::new(false)).expect("audit")
}

fn height_of(n: &Node, h: &BlockHash) -> u64 {
    n.dag.read().get_block_data(h).unwrap().height
}

/// The genesis ledger of the fixture: two carryover-like outputs paying `k`
/// and the network's first locked tranche (a policy output with an absolute
/// timelock, `core::vesting`), as first boot writes them.
fn funds(k: &Key) -> Vec<([u8; 32], u32, TxOutput)> {
    let t = &gnb::core::vesting::genesis_tranches().unwrap()[0];
    vec![([0x51; 32], 0, out(3_000_000, &k.spk)), ([0x52; 32], 1, out(5_000_000, &k.spk)),
         (t.txid, t.vout, t.output.clone())]
}

const CARRY: u64 = 8_000_000;

/// Founder tranche 1 (`tokenomics::vesting_tranche_value`).
const LOCKED: u64 = tokenomics::FOUNDER_ALLOCATION_SAT / tokenomics::VESTING_TRANCHES as u64;

const LEDGER: GenesisLedger = GenesisLedger { carryover_sat: CARRY, locked_sat: LOCKED };

/// Outputs of `funds`.
const FUNDS: u64 = 3;

/// Every invariant a healthy node's audit satisfies, and the expected total.
fn assert_healthy(n: &Node, a: &UtxoSetAudit, tip: BlockHash, unclaimed: u128, what: &str) {
    assert_eq!(a.best_block, Some(tip), "{what}: best block");
    assert_eq!(a.height, height_of(n, &tip), "{what}: height");
    assert_eq!(a.applied_blocks, a.height, "{what}: one undo record per chain position");
    assert_eq!(a.undecodable, 0, "{what}");
    assert_eq!(a.unclaimed_sat(), Some(unclaimed), "{what}: unclaimed");
    assert_eq!(a.total_sat + unclaimed, LEDGER.total_sat() + a.subsidy_sat, "{what}: total + unclaimed = issuance");
    assert!(a.subsidy_sat <= a.schedule_issued_sat as u128, "{what}: within the schedule");
    assert_eq!(a.aggregates_ok(), Some(true), "{what}: scan == maintained aggregates");
    assert_eq!(a.hash_serialized, n.store.utxo_set_digest().unwrap(), "{what}: the set's digest");
    assert!(a.ok(), "{what}: {a:?}");
}

/// b1 (full subsidy), b2 (spends the first fund with a 100,000 sat fee, its
/// coinbase claims subsidy + fee), b3 (claims 777 sat less than its subsidy).
fn mine_three(n: &Node, k: &Key) -> Vec<Block> {
    let gh = n.dag.read().store.genesis.unwrap();
    let f = funds(k);
    let b1 = empty_child(n, gh, "b1");
    accept(n, &b1).unwrap();
    let spend = signed_spend_at(k, &[(f[0].0, f[0].1)], std::slice::from_ref(&f[0].2),
        vec![out(2_000_000, &[0x42; 20]), out(900_000, &k.spk)], 2);
    let b2 = mk_block(n, vec![b1.block_hash()], vec![coinbase("b2", subsidy(2) + 100_000, vec![0xC2; 20]), spend]);
    accept(n, &b2).unwrap();
    let b3 = mk_block(n, vec![b2.block_hash()], vec![coinbase("b3", subsidy(3) - 777, vec![0xC3; 20])]);
    accept(n, &b3).unwrap();
    assert_eq!(applied_tip(n), Some(b3.block_hash()));
    vec![b1, b2, b3]
}

/// On a mined chain, in both regimes: the set's total plus the unclaimed
/// reward is exactly carryover + Σ subsidy (fees move value, they issue
/// none), the count and hash describe the set, the hash is a function of the
/// set alone (a second node that connected the same blocks reports the same
/// one, also after a restart), and the scan agrees with the aggregates.
#[test]
fn the_utxo_set_agrees_with_the_issuance_on_a_mined_chain() {
    for hardened in [false, true] {
        let _g = activation::scoped_override(if hardened { 0 } else { activation::NEVER });
        let genesis = mk_genesis(unix_now() - 10_000);
        let gh = genesis.block_hash();
        let k = key();
        let mut n = node_with(&genesis, &funds(&k));
        n.store.ensure_aggregates().unwrap();

        let a0 = audit(&n);
        assert_eq!((a0.txouts, a0.total_sat, a0.subsidy_sat, a0.applied_blocks), (FUNDS, LEDGER.total_sat(), 0, 0));
        assert_healthy(&n, &a0, gh, 0, "genesis");

        let blocks = mine_three(&n, &k);
        let a = audit(&n);
        // 3 funds - 1 spent + 2 spend outputs + 3 coinbases.
        assert_eq!(a.txouts, FUNDS + 4, "hardened={hardened}");
        assert_eq!(a.subsidy_sat, (subsidy(1) + subsidy(2) + subsidy(3)) as u128);
        assert_eq!(a.total_sat, LEDGER.total_sat() + a.subsidy_sat - 777);
        assert_healthy(&n, &a, blocks[2].block_hash(), 777, "mined");
        assert_ne!(a.hash_serialized, a0.hash_serialized);

        // Another node that connected the same blocks holds the same set.
        let m = node_with(&genesis, &funds(&k));
        for b in &blocks {
            accept(&m, b).unwrap();
        }
        assert_eq!(audit(&m).hash_serialized, a.hash_serialized, "deterministic hash");

        // A restart (DAG reload + reconcile) changes nothing.
        restart(&mut n);
        assert_eq!(audit(&n), a, "hardened={hardened}");
    }
}

/// After a reorg that disconnects a spend and an under-claiming block, the
/// audit describes the new chain: the spent fund is back, the unclaimed
/// reward of the disconnected block is gone, and the hash equals that of a
/// node that only ever connected the new chain.
#[test]
fn the_audit_agrees_after_a_reorg() {
    let _g = activation::scoped_override(0);
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let k = key();
    let n = node_with(&genesis, &funds(&k));
    n.store.ensure_aggregates().unwrap();
    let old = mine_three(&n, &k);
    assert_healthy(&n, &audit(&n), old[2].block_hash(), 777, "before the reorg");

    // A heavier branch from the genesis: four coinbase-only blocks, the
    // third under-claiming by 5 sat.
    let mut side = Vec::new();
    let mut parent = gh;
    for i in 1..=4u64 {
        let claim = if i == 3 { subsidy(i) - 5 } else { subsidy(i) };
        let b = mk_block(&n, vec![parent], vec![coinbase(&format!("s{i}"), claim, vec![0xD0 + i as u8; 20])]);
        accept(&n, &b).unwrap();
        parent = b.block_hash();
        side.push(b);
    }
    assert_eq!(applied_tip(&n), Some(side[3].block_hash()), "the side branch is now the chain");

    let a = audit(&n);
    assert_eq!(a.txouts, FUNDS + 4, "the genesis ledger and the four side coinbases");
    assert_eq!(a.subsidy_sat, (1..=4).map(subsidy).sum::<u64>() as u128);
    assert_healthy(&n, &a, side[3].block_hash(), 5, "after the reorg");
    assert_eq!(n.store.get_utxo(&[0x51; 32], 0).unwrap().map(|o| o.value), Some(3_000_000), "spent fund restored");

    let fresh = node_with(&genesis, &funds(&k));
    for b in &side {
        accept(&fresh, b).unwrap();
    }
    assert_eq!(audit(&fresh).hash_serialized, a.hash_serialized, "same set as a node that never reorged");
}

/// Raw edits of CF_UTXO (what disk corruption or a hand-edited data dir
/// does) are detected: an inflated row breaks the supply bound and the
/// aggregates; a lowered row (total still within the bound) and a deleted row
/// break the aggregates; an undecodable row is counted and fails the audit;
/// every edit changes the hash. Restoring the rows restores the audit.
#[test]
fn a_corrupted_utxo_entry_is_detected() {
    let _g = activation::scoped_override(0);
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let k = key();
    let n = node_with(&genesis, &funds(&k));
    n.store.ensure_aggregates().unwrap();
    let b1 = empty_child(&n, gh, "b1");
    accept(&n, &b1).unwrap();
    let good = audit(&n);
    assert_healthy(&n, &good, b1.block_hash(), 0, "before");

    let cb = b1.transactions[0].txid();
    let mut key_bytes = cb.to_vec();
    key_bytes.extend_from_slice(&0u32.to_le_bytes());
    let db = n.store.db();
    let cf = db.cf_handle("utxo").unwrap();
    let original = db.get_cf(cf, &key_bytes).unwrap().expect("the coinbase output is unspent");
    let enc = |o: &TxOutput| bincode::serde::encode_to_vec(o, bincode::config::standard()).unwrap();
    let coin = n.store.get_utxo(&cb, 0).unwrap().unwrap();

    // Inflated by one sat.
    db.put_cf(cf, &key_bytes, enc(&TxOutput { value: coin.value + 1, ..coin.clone() })).unwrap();
    let a = audit(&n);
    assert_eq!(a.total_sat, good.total_sat + 1);
    assert!(!a.supply_ok(), "above the genesis ledger + issuance");
    assert_eq!(a.unclaimed_sat(), None);
    assert_eq!(a.aggregates_ok(), Some(false));
    assert!(!a.ok());
    assert_ne!(a.hash_serialized, good.hash_serialized);

    // Lowered: the supply bound still holds, the aggregates do not.
    db.put_cf(cf, &key_bytes, enc(&TxOutput { value: coin.value - 1, ..coin.clone() })).unwrap();
    let a = audit(&n);
    assert!(a.supply_ok());
    assert_eq!(a.aggregates_ok(), Some(false));
    assert!(!a.ok());

    // Undecodable.
    db.put_cf(cf, &key_bytes, [0xFFu8; 3]).unwrap();
    let a = audit(&n);
    assert_eq!(a.undecodable, 1);
    assert!(!a.supply_ok() && !a.ok());

    // Deleted.
    db.delete_cf(cf, &key_bytes).unwrap();
    let a = audit(&n);
    assert_eq!(a.txouts, good.txouts - 1);
    assert_eq!(a.aggregates_ok(), Some(false));
    assert!(!a.ok());

    // Restored.
    db.put_cf(cf, &key_bytes, &original).unwrap();
    assert_eq!(audit(&n), good);
}

/// A stale undo record (a block counted as applied that is not on the chain)
/// fails the chain check: issuance would be over-counted.
#[test]
fn an_undo_record_off_the_chain_fails_the_audit() {
    let _g = activation::scoped_override(0);
    let genesis = mk_genesis(unix_now() - 10_000);
    let k = key();
    let n = node_with(&genesis, &funds(&k));
    n.store.ensure_aggregates().unwrap();
    let blocks = mine_three(&n, &k);
    let db = n.store.db();
    let cf = db.cf_handle("undo").unwrap();
    let rec = db.get_cf(cf, blocks[2].block_hash()).unwrap().unwrap();
    db.put_cf(cf, [0xEE; 32], rec).unwrap();
    let a = audit(&n);
    assert_eq!(a.applied_blocks, 4);
    assert_eq!((a.undo_off_chain, a.chain_without_undo), (1, 0));
    assert!(!a.chain_ok() && !a.ok());
}

/// A stale undo record (a rolled-back block whose delete was lost) together
/// with a missing one (an applied block's record gone): the count still
/// equals the height, so a count check passed and the bound summed the
/// stale block's subsidy in place of the applied block's. The audit now
/// checks that the records are exactly the selected chain of the tip.
#[test]
fn a_stale_and_a_missing_undo_record_do_not_cancel_out() {
    let _g = activation::scoped_override(0);
    let genesis = mk_genesis(unix_now() - 10_000);
    let k = key();
    let n = node_with(&genesis, &funds(&k));
    n.store.ensure_aggregates().unwrap();
    let blocks = mine_three(&n, &k);
    let good = audit(&n);
    assert!(good.chain_ok() && good.ok(), "{good:?}");
    assert_eq!((good.undo_off_chain, good.chain_without_undo), (0, 0));
    let db = n.store.db();
    let cf = db.cf_handle("undo").unwrap();
    let rec = db.get_cf(cf, blocks[1].block_hash()).unwrap().unwrap();
    db.delete_cf(cf, blocks[1].block_hash()).unwrap();
    db.put_cf(cf, [0xEE; 32], rec).unwrap();
    let a = audit(&n);
    assert_eq!(a.applied_blocks, a.height, "the count alone cannot tell");
    assert_eq!((a.undo_off_chain, a.chain_without_undo), (1, 1));
    assert!(!a.chain_ok() && !a.ok(), "{a:?}");
}

/// The scan stops when its request is cancelled (the RPC deadline).
#[test]
fn a_cancelled_audit_stops() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let n = node_with(&genesis, &funds(&key()));
    let err = n.store.utxo_set_audit(LEDGER, &AtomicBool::new(true)).unwrap_err();
    assert!(err.to_string().contains("cancelled"), "{err}");
}

/// The genesis ledger counts the locked team and founder allocations
/// (`core::vesting`): the tranche is in the set and in the total, never in
/// the address aggregates (a policy output), and an audit whose ledger left
/// it out would read the set as inflation, by exactly its value.
#[test]
fn the_locked_allocations_are_part_of_the_genesis_ledger() {
    let _g = activation::scoped_override(0);
    let genesis = mk_genesis(unix_now() - 10_000);
    let k = key();
    let n = node_with(&genesis, &funds(&k));
    n.store.ensure_aggregates().unwrap();
    let blocks = mine_three(&n, &k);
    let a = audit(&n);
    assert_healthy(&n, &a, blocks[2].block_hash(), 777, "with the locked tranche");
    let t = &gnb::core::vesting::genesis_tranches().unwrap()[0];
    assert_eq!(t.output.value, LOCKED);
    let coin = n.store.get_utxo(&t.txid, t.vout).unwrap().expect("locked, unspent");
    assert_eq!((coin.value, coin.script_pubkey.len()), (LOCKED, t.output.script_pubkey.len()));
    assert_ne!(coin.script_pubkey.len(), 20, "a policy script");
    assert_eq!(a.total_sat - a.holder_total_sat, LOCKED as u128, "a policy output: not an address holding");
    let carryover_only = audit_with(&n, GenesisLedger { carryover_sat: CARRY, locked_sat: 0 });
    assert!(!carryover_only.supply_ok() && !carryover_only.ok());
    assert_eq!(carryover_only.total_sat - carryover_only.max_supply_sat(), (LOCKED - 777) as u128);
}
