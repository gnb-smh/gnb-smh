//! Regression tests for the mempool / block-production / context-free
//! validation fixes: MEM-1..MEM-7, DAG-2, VAL-11, VAL-12, COH-2.

mod fix_common;
use fix_common::*;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use gnb::consensus::GhostDAG;
use gnb::core::{self, Block, BlockHeader, MerkleRoot, Transaction, TxInput, TxOutput};
use gnb::mempool::admission::{self, AdmissionError, AdmissionPolicy};
use gnb::mempool::{Clock, Mempool, MEMPOOL_EXPIRY_SECS};
use gnb::{reorg, template};

fn fake_spend(prev: [u8; 32], value: u64, script_sig_len: usize) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput { prev_txid: prev, prev_index: 0, script_sig: vec![0xA5; script_sig_len], sequence: u32::MAX }],
        outputs: vec![TxOutput { value, script_pubkey: vec![0x12; 20] }],
        locktime: 0,
    }
}

// ── MEM-1 ────────────────────────────────────────────────────────────────────

/// A dust transaction gossiped by a peer is refused by the shared admission
/// function (pre-fix the gossip path had no dust rule and admitted it, after
/// which every template was consensus-invalid). The rejection is remembered.
#[test]
fn mem1_dust_tx_is_rejected_by_gossip_admission() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let k = key();
    let fund = ([0x9Eu8; 32], 0u32, out(1_000_000, &k.spk));
    let n = node_with(&genesis, &[fund.clone()]);
    let dust = signed_spend(&k, &[(fund.0, 0)], vec![out(1, &[0x03; 20]), out(899_999, &[0x04; 20])]);

    let policy = AdmissionPolicy::relay(admission::next_block_height(&n.dag.read()));
    let err = admission::admit(&n.store, &n.mempool, dust.clone(), &policy).unwrap_err();
    assert!(err.to_string().contains("dust"), "{err}");
    assert!(!n.mempool.contains(&dust.txid()));
    // The block-independent path used by tests / tools agrees.
    assert!(gnb::accept::validate_tx_standalone(&dust, &n.store, 1).unwrap_err().contains("dust"));
    // Replays are answered from the recent-rejects filter.
    let again = admission::admit(&n.store, &n.mempool, dust, &policy).unwrap_err();
    assert!(again.to_string().contains("recently rejected"), "{again}");
}

/// Template side of MEM-1/MEM-3: a transaction that cannot be mined (dust,
/// or an input already spent on chain) that is somehow in the pool is
/// EVICTED by the template self-check instead of poisoning every template.
#[test]
fn mem1_mem3_unminable_pool_tx_is_evicted_by_the_template() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let n = node_with(&genesis, &[
        ([0x01u8; 32], 0, out(1_000_000, &[0x55; 20])),
        ([0x02u8; 32], 0, out(1_000_000, &[0x55; 20])),
    ]);
    let mut dust = fake_spend([0x01; 32], 900_000, 10);
    dust.outputs.push(TxOutput { value: 1, script_pubkey: vec![0x13; 20] });
    let stale = fake_spend([0x77; 32], 900_000, 10); // input not in the UTXO set
    let good = fake_spend([0x02; 32], 900_000, 10);
    for t in [&dust, &stale, &good] {
        n.mempool.add(t.clone(), 100_000).unwrap(); // bypasses admission (pre-fix state)
    }
    let tmpl = template::build_block_template(&n.dag, &n.store, &n.mempool, template::EXTERNAL_COINBASE_RESERVE).unwrap();
    assert_eq!(tmpl.evicted, 2);
    assert_eq!(tmpl.transactions.len(), 1);
    assert_eq!(tmpl.transactions[0].0.txid(), good.txid());
    assert!(!n.mempool.contains(&dust.txid()) && !n.mempool.contains(&stale.txid()));
    let cb = template::miner_coinbase(tmpl.height, tmpl.subsidy + tmpl.total_fees, vec![0xCB; 20]);
    template::assemble_block(&tmpl, cb, unix_now()).expect("template passes its self-check");
}

// ── MEM-2 ────────────────────────────────────────────────────────────────────

/// 200 realistic (~8.6 kB hybrid-signature-sized) pending transactions: the
/// template is filled by fee rate under the byte budget and the assembled
/// block stays within MAX_BLOCK_SIZE as the consensus rule measures it.
/// Pre-fix `get_for_block(2000)` took all 200 (~1.7 MB) and every template
/// failed `validate_structure` with 'block too large'.
#[test]
fn mem2_template_stays_under_max_block_size_with_200_pending_txs() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let n = node_with(&genesis, &[]);
    let script_sig_len = 8 + core::SIG_SIZE + core::PUBKEY_SIZE;
    for i in 0..200u32 {
        let mut prev = [0u8; 32];
        prev[..4].copy_from_slice(&i.to_le_bytes());
        prev[31] = 0xEE;
        n.store.put_utxo(&prev, 0, &out(1_000_000, &[0x55; 20])).unwrap();
        n.mempool.add(fake_spend(prev, 1_000_000 - 20_000 - i as u64, script_sig_len), 20_000 + i as u64).unwrap();
    }
    let reserve = template::miner_coinbase(u64::MAX, u64::MAX, vec![0xCB; 20]).actual_size();
    let tmpl = template::build_block_template(&n.dag, &n.store, &n.mempool, reserve).unwrap();
    assert!(!tmpl.transactions.is_empty() && tmpl.transactions.len() < 200,
        "byte budget bounds the selection: {}", tmpl.transactions.len());
    // Highest fee rate first.
    let fees: Vec<u64> = tmpl.transactions.iter().map(|(_, f)| *f).collect();
    assert!(fees.windows(2).all(|w| w[0] >= w[1]));
    let cb = template::miner_coinbase(tmpl.height, tmpl.subsidy + tmpl.total_fees, vec![0xCB; 20]);
    let block = template::assemble_block(&tmpl, cb, unix_now()).expect("self-check passes");
    assert!(block.size_bytes() <= core::MAX_BLOCK_SIZE, "size {}", block.size_bytes());
    assert_eq!(block.clone().validate_structure_without_pow_for_test(), Ok(()));
}

/// End to end: a template built from real signed mempool transactions is
/// mined and accepted by the real acceptance path.
#[test]
fn mem2_template_block_is_accepted_by_the_real_pipeline() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let k = key();
    let funds: Vec<_> = (0..3u8).map(|i| ([0x60 + i; 32], 0u32, out(2_000_000, &k.spk))).collect();
    let n = node_with(&genesis, &funds);
    let policy = AdmissionPolicy::relay(admission::next_block_height(&n.dag.read()));
    for (i, f) in funds.iter().enumerate() {
        let t = signed_spend(&k, &[(f.0, 0)], vec![out(1_900_000 - i as u64 * 1_000, &[0x21; 20])]);
        admission::admit(&n.store, &n.mempool, t, &policy).expect("admitted");
    }
    let reserve = template::miner_coinbase(u64::MAX, u64::MAX, vec![0xCB; 20]).actual_size();
    let tmpl = template::build_block_template(&n.dag, &n.store, &n.mempool, reserve).unwrap();
    assert_eq!(tmpl.transactions.len(), 3);
    let cb = template::miner_coinbase(tmpl.height, tmpl.subsidy + tmpl.total_fees, vec![0xCB; 20]);
    let mut block = template::assemble_block(&tmpl, cb, unix_now()).unwrap();
    while !block.validate_pow() { block.header.nonce += 1; }
    accept(&n, &block).expect("the self-mined template block is valid");
    assert_eq!(n.mempool.size(), 0, "confirmed txs left the pool");
}

// ── DAG-2 ────────────────────────────────────────────────────────────────────

/// More than MAX_PARENTS tips: the template carries at most MAX_PARENTS
/// parents, highest blue work first (selected tip first), and its block is
/// within the parent cap. Pre-fix every bodied tip became a parent and the
/// template failed with 'too many parents' forever.
#[test]
fn dag2_template_parents_are_capped_at_max_parents() {
    let g_ts = unix_now() - 10_000;
    let genesis = mk_genesis(g_ts);
    let gh = genesis.block_hash();
    let n = node_with(&genesis, &[]);
    for i in 0..300u64 {
        let b = Block {
            header: BlockHeader {
                version: 1, parents: vec![gh], merkle_root: MerkleRoot::ZERO,
                timestamp: g_ts + 1, bits: core::POW_LIMIT_BITS, nonce: i,
            },
            transactions: vec![coinbase(&format!("tip-{i}"), 0, vec![0x01; 20])],
            blue_score: 1, height: 1, shielded_transactions: vec![],
        };
        let h = b.block_hash();
        // Varying work so the blue-work order is non-trivial.
        n.dag.write().add_block(h, vec![gh], g_ts + 1, 1_000 + (i % 7) as u128).unwrap();
        n.store.put_block_body(&b).unwrap();
    }
    assert_eq!(n.dag.read().tips().len(), 300);
    let tmpl = template::build_block_template(&n.dag, &n.store, &n.mempool, template::EXTERNAL_COINBASE_RESERVE).unwrap();
    assert_eq!(tmpl.parents.len(), core::MAX_PARENTS);
    assert_eq!(tmpl.parents[0], n.dag.read().selected_tip().unwrap(), "selected parent first");
    let works: Vec<u128> = tmpl.parents.iter()
        .map(|p| n.dag.read().get_block_data(p).unwrap().blue_work).collect();
    assert!(works.windows(2).all(|w| w[0] >= w[1]), "highest blue work first");
    let cb = template::miner_coinbase(tmpl.height, tmpl.subsidy, vec![0xCB; 20]);
    let block = template::assemble_block(&tmpl, cb, unix_now()).expect("within the parent cap");
    assert!(Block::from_wire_bytes(&block.to_wire_bytes()).is_ok(), "wire-decodable (decoder caps parents)");
}

// ── MEM-3 ────────────────────────────────────────────────────────────────────

/// A pooled tx whose input is spent by a DIFFERENT confirmed tx is swept when
/// that block connects. Pre-fix only txids in the block were removed and the
/// loser stayed in the pool forever, wedging the miner.
#[test]
fn mem3_conflicting_pool_tx_is_swept_on_connect() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0x8Du8; 32], 0u32, out(1_000_000, &k.spk));
    let n = node_with(&genesis, &[fund.clone()]);
    let a = signed_spend(&k, &[(fund.0, 0)], vec![out(900_000, &[0x01; 20])]);
    let policy = AdmissionPolicy::relay(admission::next_block_height(&n.dag.read()));
    admission::admit(&n.store, &n.mempool, a.clone(), &policy).unwrap();

    let a2 = signed_spend(&k, &[(fund.0, 0)], vec![out(880_000, &[0x02; 20])]);
    let sub = core::tokenomics::block_subsidy_sat(1);
    let x = mk_block(&n, vec![gh], vec![coinbase("other", sub + 120_000, vec![0xAA; 20]), a2]);
    accept(&n, &x).unwrap();
    assert!(!n.mempool.contains(&a.txid()), "conflict swept on connect");
}

/// After a reorg the pool is re-validated against the new UTXO set: a pooled
/// tx spending an output that only existed on the abandoned chain is dropped,
/// while the abandoned chain's own (still valid) tx is re-admitted.
#[test]
fn mem3_pool_is_revalidated_after_a_reorg() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0x8Eu8; 32], 0u32, out(5_000_000, &k.spk));
    let n = node_with(&genesis, &[fund.clone()]);
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
    assert_eq!(sel_tip(&n), Some(f2.block_hash()));
    assert!(!n.mempool.contains(&p.txid()), "P's input only existed on the abandoned chain");
    assert!(n.mempool.contains(&tx1.txid()), "tx1 re-admitted through the shared admission path");
}

struct TestClock(Arc<AtomicU64>);
impl Clock for TestClock {
    fn now_secs(&self) -> u64 { self.0.load(Ordering::SeqCst) }
}

/// Entries older than MEMPOOL_EXPIRY_SECS are dropped.
#[test]
fn mem3_pool_entries_expire() {
    let now = Arc::new(AtomicU64::new(1_000_000));
    let mp = Mempool::with_clock(Box::new(TestClock(now.clone())));
    let t = fake_spend([0x44; 32], 900_000, 10);
    mp.add(t.clone(), 100_000).unwrap();
    now.fetch_add(MEMPOOL_EXPIRY_SECS, Ordering::SeqCst);
    assert_eq!(mp.expire_older_than(MEMPOOL_EXPIRY_SECS), 0, "exactly at the limit: kept");
    now.fetch_add(1, Ordering::SeqCst);
    assert_eq!(mp.expire_older_than(MEMPOOL_EXPIRY_SECS), 1);
    assert!(!mp.contains(&t.txid()));
    mp.debug_check_invariants().unwrap();
}

// ── MEM-4 ────────────────────────────────────────────────────────────────────

/// Admission evaluates coinbase maturity at the NEXT block's height (tip DAG
/// height + 1), never at the DAG block count. Here 150 parallel blocks make
/// the block count 151 while the chain height is 1: pre-fix (gossip path)
/// the 1-confirmation coinbase spend looked 150 blocks deep and was admitted.
#[test]
fn mem4_admission_uses_tip_height_not_block_count() {
    let g_ts = unix_now() - 10_000;
    let genesis = mk_genesis(g_ts);
    let gh = genesis.block_hash();
    let k = key();
    let cb_txid = [0xCBu8; 32];
    let n = node_with(&genesis, &[(cb_txid, 0, out(1_000_000, &k.spk))]);
    n.store.put_coinbase_info(&cb_txid, 1).unwrap();
    for i in 0..150u64 {
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&i.to_le_bytes());
        h[31] = 0x99;
        n.dag.write().add_block(h, vec![gh], g_ts + 1, 1).unwrap();
    }
    assert_eq!(n.dag.read().block_count(), 151);
    let next = admission::next_block_height(&n.dag.read());
    assert_eq!(next, 2);
    let spend = signed_spend(&k, &[(cb_txid, 0)], vec![out(900_000, &[0x01; 20])]);
    let err = admission::admit(&n.store, &n.mempool, spend.clone(), &AdmissionPolicy::relay(next)).unwrap_err();
    assert!(matches!(err, AdmissionError::Immature(_)), "{err}");
    // Mature once the chain is deep enough (a deeper chain means the tip
    // moved, which clears the recent-rejects filter).
    n.mempool.clear_recent_rejects();
    admission::admit(&n.store, &n.mempool, spend, &AdmissionPolicy::relay(1 + core::COINBASE_MATURITY))
        .expect("mature at height 101");
}

// ── MEM-5 ────────────────────────────────────────────────────────────────────

/// Trailing bytes after a transaction are refused (pre-fix they were ignored,
/// giving one tx unboundedly many gossip message ids); an oversized tx is
/// refused by the size check BEFORE any signature work.
#[test]
fn mem5_strict_decode_and_size_before_signatures() {
    let t = fake_spend([0x45; 32], 900_000, 100);
    let mut bytes = t.to_wire_bytes(true);
    assert!(admission::decode_tx_strict(&bytes).is_ok());
    bytes.push(0);
    assert!(admission::decode_tx_strict(&bytes).unwrap_err().contains("trailing"));

    // 45 inputs × 10,000-byte (garbage) script_sigs ≈ 450 kB > MAX_TX_SIZE.
    let genesis = mk_genesis(unix_now() - 10_000);
    let n = node_with(&genesis, &[]);
    let big = Transaction {
        version: 1,
        inputs: (0..45u8).map(|i| TxInput {
            prev_txid: [i; 32], prev_index: 0, script_sig: vec![0x5A; 10_000], sequence: u32::MAX,
        }).collect(),
        outputs: vec![TxOutput { value: 1_000_000, script_pubkey: vec![0x01; 20] }],
        locktime: 0,
    };
    let err = admission::admit(&n.store, &n.mempool, big, &AdmissionPolicy::relay(1)).unwrap_err();
    assert!(err.to_string().contains("too large"), "size is checked first: {err}");
}

/// A transaction with a bad signature is rejected once, then answered from
/// the bounded recent-rejects filter until the tip changes.
#[test]
fn mem5_recent_rejects_filter() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let k = key();
    let fund = ([0x46u8; 32], 0u32, out(1_000_000, &k.spk));
    let n = node_with(&genesis, &[fund.clone()]);
    let mut t = signed_spend(&k, &[(fund.0, 0)], vec![out(900_000, &[0x01; 20])]);
    let last = t.inputs[0].script_sig.len() - 100;
    t.inputs[0].script_sig[last] ^= 0xFF; // corrupt the public key / signature bytes
    let policy = AdmissionPolicy::relay(1);
    let first = admission::admit(&n.store, &n.mempool, t.clone(), &policy).unwrap_err();
    assert!(!first.to_string().contains("recently rejected"));
    assert_eq!(n.mempool.recent_rejects_len(), 1);
    let second = admission::admit(&n.store, &n.mempool, t.clone(), &policy).unwrap_err();
    assert!(second.to_string().contains("recently rejected"));
    n.mempool.clear_recent_rejects(); // what a tip change does
    let third = admission::admit(&n.store, &n.mempool, t, &policy).unwrap_err();
    assert!(!third.to_string().contains("recently rejected"));
}

// ── MEM-6 ────────────────────────────────────────────────────────────────────

/// Evictions raise a rolling minimum fee rate; the fee estimate is never
/// below the consensus minimum rate.
#[test]
fn mem6_rolling_minimum_fee_and_estimate_floor() {
    let mp = Mempool::new();
    assert!(mp.estimate_fee_rate_per_kb() >= core::tokenomics::MIN_FEE_RATE_SAT_PER_KB,
        "empty pool: consensus minimum (pre-fix: 1,000 sat absolute)");
    assert_eq!(mp.rolling_min_fee_rate(), 0);
    // Fill the pool (count cap 50,000) with increasing fee rates, then one
    // more: the cheapest resident is evicted and the floor rises above it.
    let mut i: u64 = 0;
    loop {
        let mut prev = [0u8; 32];
        prev[..8].copy_from_slice(&i.to_le_bytes());
        let t = fake_spend(prev, 1_000, 10);
        mp.add(t, 1_000 + i).unwrap();
        i += 1;
        if mp.rolling_min_fee_rate() > 0 { break; }
        assert!(i <= 50_001, "eviction must happen at the count cap");
    }
    let floor = mp.rolling_min_fee_rate();
    assert!(floor > 0);
    let probe = fake_spend([0xFF; 32], 1_000, 10);
    let size = probe.actual_size();
    assert!(!mp.meets_rolling_min(1_000, size), "a tx at the evicted rate is now below the floor");
    assert!(mp.meets_rolling_min(floor.saturating_mul(size as u64) + size as u64, size));
    assert!(mp.estimate_fee_rate_per_kb() >= core::tokenomics::MIN_FEE_RATE_SAT_PER_KB);
    mp.debug_check_invariants().unwrap();
}

// ── MEM-7 ────────────────────────────────────────────────────────────────────

/// Re-injection after a reorg runs the shared admission checks: an immature
/// coinbase spend and a below-minimum-fee tx are discarded, a valid tx is
/// re-admitted. Pre-fix only input presence was checked.
#[test]
fn mem7_reinjection_runs_maturity_and_fee_checks() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let cb = [0xC1u8; 32];
    let plain = [0xC2u8; 32];
    let plain2 = [0xC3u8; 32];
    let n = node_with(&genesis, &[
        (cb, 0, out(1_000_000, &[0x55; 20])),
        (plain, 0, out(1_000_000, &[0x55; 20])),
        (plain2, 0, out(1_000_000, &[0x55; 20])),
    ]);
    n.store.put_coinbase_info(&cb, 50).unwrap();
    let immature = fake_spend(cb, 900_000, 10);
    let low_fee = fake_spend(plain, 999_000, 10); // fee 1,000 < 10,000 minimum
    let ok = fake_spend(plain2, 900_000, 10);
    let (re, dropped) = reorg::reinject_disconnected(
        &n.store, &n.mempool, vec![immature.clone(), low_fee.clone(), ok.clone()], 60);
    assert_eq!((re, dropped), (1, 2));
    assert!(n.mempool.contains(&ok.txid()));
    assert!(!n.mempool.contains(&immature.txid()) && !n.mempool.contains(&low_fee.txid()));
}

// ── VAL-11 / VAL-12 ──────────────────────────────────────────────────────────

/// VAL-12: an in-process block with a 12.6 kB script_sig passes
/// `validate_structure` but is refused by the acceptance path's canonical
/// limits and is NOT stored (pre-fix it was accepted, persisted, and then
/// could not be read back from disk).
#[test]
fn val12_oversized_script_block_is_refused_and_not_stored() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0x4Fu8; 32], 0u32, out(1_000_000, &k.spk));
    let n = node_with(&genesis, &[fund.clone()]);
    let mut t = signed_spend(&k, &[(fund.0, 0)], vec![out(900_000, &[0x11; 20])]);
    t.inputs[0].script_sig.extend_from_slice(&[0u8; 4096]);
    let sub = core::tokenomics::block_subsidy_sat(1);
    let x = mk_block(&n, vec![gh], vec![coinbase("x12", sub + 100_000, vec![0xAA; 20]), t]);
    let err = accept(&n, &x).expect_err("canonical limits");
    assert!(err.contains("script_sig"), "{err}");
    assert!(n.store.get_block(&x.block_hash()).unwrap().is_none(), "not stored");
    assert!(!n.dag.read().has_block(&x.block_hash()));
}

/// VAL-11: an output above MAX_SUPPLY_SAT is refused context-free.
#[test]
fn val11_money_range_is_enforced_on_acceptance() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let n = node_with(&genesis, &[]);
    let x = mk_block(&n, vec![gh], vec![coinbase("huge", core::tokenomics::MAX_SUPPLY_SAT + 1, vec![0xAA; 20])]);
    let err = accept(&n, &x).expect_err("MoneyRange");
    assert!(err.contains("MAX_SUPPLY_SAT"), "{err}");
    assert!(!n.dag.read().has_block(&x.block_hash()));
}

// ── COH-2 ────────────────────────────────────────────────────────────────────

/// The shielded engine is driven ONLY by selected-chain connects/disconnects:
/// a fork-loser leaves it untouched; a reorg disconnects and reconnects.
/// Pre-fix every accepted block (fork-losers included) pushed an undo record
/// in arrival order and reorgs never disconnected anything.
#[test]
fn coh2_shielded_state_follows_the_selected_chain_only() {
    let genesis = mk_genesis(unix_now() - 10_000);
    let gh = genesis.block_hash();
    let n = node_with(&genesis, &[]);
    let depth = |n: &Node| n.shielded.read().engine.undo_depth();

    let m1 = empty_child(&n, gh, "m1");
    accept(&n, &m1).unwrap();
    assert_eq!(depth(&n), 1, "connected block recorded");
    let sub = core::tokenomics::block_subsidy_sat(1);
    let f1 = mk_block_where(&n, vec![gh], vec![coinbase("f1", sub, vec![0xF1; 20])], |h| *h < m1.block_hash());
    accept(&n, &f1).unwrap();
    assert_eq!(depth(&n), 1, "fork-loser does not touch the shielded state");
    let f2 = empty_child(&n, f1.block_hash(), "f2");
    accept(&n, &f2).unwrap();
    assert_eq!(sel_tip(&n), Some(f2.block_hash()));
    assert_eq!(depth(&n), 2, "reorg: m1 disconnected, f1 + f2 connected");
}

#[allow(dead_code)]
fn _unused(_: GhostDAG) {}

trait StructureNoPow {
    fn validate_structure_without_pow_for_test(self) -> Result<(), &'static str>;
}
impl StructureNoPow for Block {
    /// `validate_structure` minus the proof of work (the template is not mined).
    fn validate_structure_without_pow_for_test(self) -> Result<(), &'static str> {
        if self.header.parents.len() > core::MAX_PARENTS { return Err("too many parents"); }
        if self.size_bytes() > core::MAX_BLOCK_SIZE { return Err("block too large"); }
        if !self.validate_merkle() { return Err("invalid merkle root"); }
        if !self.validate_coinbase_format() { return Err("invalid coinbase format"); }
        self.validate_no_duplicate_txs()?;
        self.validate_dust()
    }
}
