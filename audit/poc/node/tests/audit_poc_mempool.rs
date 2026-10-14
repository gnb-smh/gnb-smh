//! AUDIT PoC (mempool / block-template). Each test demonstrates that a tx the
//! mempool admits (and never expires) ends up in the template produced by
//! `Mempool::get_for_block(2000)` — the exact call the internal miner
//! (main.rs `mem_m.get_for_block(2000)`) and `getblocktemplate`
//! (rpc/mod.rs `state.mempool.get_for_block(2000)`) make — and that the
//! resulting block FAILS `Block::validate_structure()`, which
//! `commit_self_mined_block` and `submitblock` run before `accept_block`.
//!
//! A passing test here == the bug is present.

use gnb::core::{
    Block, BlockHeader, MerkleRoot, Transaction, TxInput, TxOutput, DUST_THRESHOLD, MAX_BLOCK_SIZE,
};
use gnb::mempool::Mempool;

/// Script-sig length of a real hybrid input: 4 + SIG_SIZE + 4 + PUBKEY_SIZE.
const HYBRID_SCRIPT_SIG: usize = 4 + gnb::core::SIG_SIZE + 4 + gnb::core::PUBKEY_SIZE;

fn tx(nonce: u64, script_sig_len: usize, out_value: u64) -> Transaction {
    let mut prev = [0x5au8; 32];
    prev[..8].copy_from_slice(&nonce.to_le_bytes());
    Transaction {
        version: 1,
        inputs: vec![TxInput { prev_txid: prev, prev_index: 0, script_sig: vec![7u8; script_sig_len], sequence: u32::MAX }],
        outputs: vec![
            TxOutput { value: out_value, script_pubkey: vec![1u8; 20] },
            TxOutput { value: 100_000, script_pubkey: vec![2u8; 20] },
        ],
        locktime: 0,
    }
}

fn coinbase() -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput { prev_txid: [0u8; 32], prev_index: u32::MAX, script_sig: b"gnb:h2:poc".to_vec(), sequence: u32::MAX }],
        outputs: vec![TxOutput { value: 1, script_pubkey: vec![3u8; 20] }],
        locktime: 0,
    }
}

/// Build the block the miner would build from a template (merkle bound, so
/// validate_structure gets past the merkle check to the rule under test).
fn block_from_template(txs: Vec<Transaction>) -> Block {
    let all: Vec<Transaction> = std::iter::once(coinbase()).chain(txs).collect();
    let mut b = Block {
        header: BlockHeader { version: 1, parents: vec![[1u8; 32]], merkle_root: MerkleRoot::ZERO, timestamp: 1, bits: 0x2100_ffff, nonce: 0 },
        transactions: all,
        blue_score: 2,
        height: 2,
        shielded_transactions: vec![],
    };
    b.header.merkle_root = b.body_merkle_root();
    b
}

/// MEM-2: no byte budget in template selection. ~116 ORDINARY 1-in/2-out
/// hybrid-signed transactions already exceed MAX_BLOCK_SIZE, so every block
/// the internal miner / getblocktemplate builds is rejected "block too large".
#[test]
fn poc_template_has_no_byte_budget_ordinary_load() {
    let mp = Mempool::new();
    let n = 120u64;
    for i in 0..n {
        let t = tx(i, HYBRID_SCRIPT_SIG, 1_000_000);
        let fee = 3 * t.actual_size() as u64; // well above both relay and consensus minimums
        mp.add(t, fee).expect("ordinary tx admitted");
    }
    let template = mp.get_for_block(2000);
    assert_eq!(template.len() as u64, n, "template takes every tx: no size budget");
    let b = block_from_template(template);
    eprintln!("template block size = {} bytes (MAX_BLOCK_SIZE = {})", b.size_bytes(), MAX_BLOCK_SIZE);
    assert!(b.size_bytes() > MAX_BLOCK_SIZE);
    assert_eq!(b.validate_structure(), Err("block too large"));
}

/// MEM-2 (adversarial form): three 390 KB transactions (each under the 400 KB
/// mempool cap) poison every template; they are never mined, so their fee is
/// never paid.
#[test]
fn poc_three_large_txs_poison_template() {
    let mp = Mempool::new();
    for i in 0..3u64 {
        let t = tx(1000 + i, 390 * 1024, 1_000_000);
        let fee = 2 * t.actual_size() as u64;
        mp.add(t, fee).expect("large tx admitted");
    }
    let b = block_from_template(mp.get_for_block(2000));
    assert_eq!(b.validate_structure(), Err("block too large"));
}

/// MEM-1: the mempool layer has no dust rule (and neither does the gossip
/// admission path `validate_tx_standalone` → `validate_tx_inputs`, see
/// report). A sub-dust output is admitted, selected first (highest fee rate),
/// and the template block fails `validate_dust` inside validate_structure.
#[test]
fn poc_dust_output_admitted_and_poisons_template() {
    let mp = Mempool::new();
    let dust = tx(7, HYBRID_SCRIPT_SIG, 1); // 1 sat < DUST_THRESHOLD
    assert!(1 < DUST_THRESHOLD);
    let fee = 50 * dust.actual_size() as u64; // high rate → template head
    mp.add(dust.clone(), fee).expect("dust tx admitted by mempool");
    for i in 0..5u64 {
        let t = tx(100 + i, HYBRID_SCRIPT_SIG, 1_000_000);
        let f = 3 * t.actual_size() as u64;
        mp.add(t, f).unwrap();
    }
    let template = mp.get_for_block(2000);
    assert_eq!(template[0].txid(), dust.txid(), "dust tx is the template head");
    let b = block_from_template(template);
    assert_eq!(b.validate_structure(), Err("output below dust threshold"));
}

/// MEM-4 cost model: `Transaction::sighash(i)` deep-clones the WHOLE tx and
/// re-encodes the stripped body for every input, so verifying N inputs costs
/// O(N * tx_size). Gossip admission runs this (validate_tx_inputs) BEFORE the
/// 400 KB MAX_TX_SIZE check in Mempool::add, on frames up to 4 MiB. Prints the
/// measured cost of the sighash loop alone (no signature verification).
#[test]
fn poc_sighash_loop_is_quadratic_in_tx_size() {
    fn big_tx(n_inputs: usize, output_bytes: usize) -> Transaction {
        let n_out = output_bytes / 10_000;
        Transaction {
            version: 1,
            inputs: (0..n_inputs)
                .map(|i| TxInput { prev_txid: [i as u8; 32], prev_index: i as u32, script_sig: vec![9u8; HYBRID_SCRIPT_SIG], sequence: u32::MAX })
                .collect(),
            outputs: (0..n_out).map(|_| TxOutput { value: 1_000, script_pubkey: vec![4u8; 10_000] }).collect(),
            locktime: 0,
        }
    }
    let chain = gnb::core::node_chain_id();
    let mut prev: Option<f64> = None;
    for (n, ob) in [(30usize, 250_000usize), (60, 500_000), (120, 1_000_000), (235, 2_000_000)] {
        let t = big_tx(n, ob);
        let wire = t.to_wire_bytes(true).len();
        let start = std::time::Instant::now();
        for i in 0..n {
            std::hint::black_box(t.sighash(i, chain));
        }
        let secs = start.elapsed().as_secs_f64();
        eprintln!("inputs={n:4} wire={:8} B  sighash loop = {:8.1} ms{}", wire, secs * 1e3,
            prev.map(|p| format!("  (x{:.1} vs previous)", secs / p)).unwrap_or_default());
        prev = Some(secs);
        assert!(wire <= 4 * 1024 * 1024, "fits one 4 MiB gossip frame");
    }
}

/// MEM-3: a mempool tx whose outpoint is consumed by a DIFFERENT confirmed
/// tx (double-spend mined elsewhere) is never removed: remove_confirmed() only
/// drops matching txids, there is no conflict sweep, no revalidation and no
/// expiry. The stale tx keeps being selected for every template (and every
/// self-mined block fails accept_block's UTXO lookup).
#[test]
fn poc_conflicting_confirmation_leaves_stale_tx_forever() {
    let mp = Mempool::new();
    let a = tx(42, HYBRID_SCRIPT_SIG, 1_000_000);
    let mut b = a.clone();
    b.outputs[0].value = 999_999; // same outpoint, different txid (the mined double-spend)
    assert_ne!(a.txid(), b.txid());
    let fa = 3 * a.actual_size() as u64;
    mp.add(a.clone(), fa).unwrap();

    // A block containing B (not A) is connected: accept_block calls
    // remove_confirmed(&block txids).
    mp.remove_confirmed(&[coinbase().txid(), b.txid()]);

    assert!(mp.contains(&a.txid()), "conflicting tx A survives B's confirmation");
    assert_eq!(mp.get_for_block(2000)[0].txid(), a.txid(), "A is still selected for templates");
    mp.debug_check_invariants().unwrap();
}
