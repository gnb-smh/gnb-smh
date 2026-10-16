//! Phase-4 package R4, B2-T0: the peak memory of a reorg does not grow with
//! its depth.
//!
//! Pre-fix, `resolve_best_chain` staged the whole move — every block body of
//! both branches, the UTXO overlay and the WriteBatch of every block — as one
//! in-memory plan, so the memory a reorg needed grew linearly with its depth
//! (the audit's day-long partition: gigabytes, an out-of-memory crash that
//! repeated at every start-up). Moves now commit in chunks of
//! `reorg::MAX_BLOCKS_PER_COMMIT` blocks and keep block hashes, not bodies, so
//! the peak is bounded by one chunk.
//!
//! The peak is measured with a counting global allocator, so this test lives
//! in its own test binary (one test, nothing running beside it).

mod fix_common;
use fix_common::*;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};

use gnb::consensus::{BlockHash, GhostDAG};
use gnb::core::{self, Block, BlockHeader, MerkleRoot, Transaction, TxInput, TxOutput};
use gnb::pow;

struct Counting;

static CURRENT: AtomicIsize = AtomicIsize::new(0);
static PEAK: AtomicIsize = AtomicIsize::new(0);

fn note(delta: isize) {
    let now = CURRENT.fetch_add(delta, Ordering::Relaxed) + delta;
    PEAK.fetch_max(now, Ordering::Relaxed);
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            note(layout.size() as isize);
        }
        p
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        note(-(layout.size() as isize));
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            note(new_size as isize - layout.size() as isize);
        }
        p
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// Heavy blocks: every coinbase carries a `PAD`-byte `script_sig` (the
/// consensus cap is `core::limits::MAX_SCRIPT_SIG_SIZE`), so each body is
/// about 10 KB.
const PAD: usize = 9_900;

struct Builder {
    dag: GhostDAG,
}

impl Builder {
    fn chain(&mut self, from: BlockHash, n: usize, tag: &str) -> Vec<Block> {
        let mut out = Vec::with_capacity(n);
        let mut p = from;
        for i in 0..n {
            let height = self.dag.get_block_data(&p).unwrap().height + 1;
            let pts = self.dag.get_block_data(&p).unwrap().timestamp;
            let bits = pow::expected_bits(pts, height).unwrap();
            let mut script_sig = format!("{tag}{i}").into_bytes();
            script_sig.resize(PAD, 0xA7);
            let cb = Transaction {
                version: 1,
                inputs: vec![TxInput { prev_txid: [0u8; 32], prev_index: u32::MAX, script_sig, sequence: u32::MAX }],
                outputs: vec![TxOutput {
                    value: core::tokenomics::block_subsidy_sat(height), script_pubkey: vec![0xC0; 20],
                }],
                locktime: 0,
            };
            let mut b = Block {
                header: BlockHeader {
                    version: 1, parents: vec![p], merkle_root: MerkleRoot::ZERO,
                    timestamp: pts + 1, bits, nonce: 0,
                },
                transactions: vec![cb],
                blue_score: height,
                height,
                shielded_transactions: Vec::new(),
                powit: Default::default(),
            };
            commit_block(&mut b);
            b.test_only_assume_pow_valid();
            self.dag.add_block(b.block_hash(), vec![p], b.header.timestamp, pow::work_from_bits(bits)).unwrap();
            p = b.block_hash();
            out.push(b);
        }
        out
    }
}

/// Peak extra heap (bytes) while a node on a `depth`-block chain receives a
/// heavier fork that branches at genesis (a `depth`-block reorg).
fn reorg_peak(depth: usize) -> isize {
    let genesis = mk_genesis(unix_now() - 100_000);
    let gh = genesis.block_hash();
    let mut dag = GhostDAG::with_default_k();
    dag.add_genesis(gh, genesis.header.timestamp);
    let mut b = Builder { dag };
    let a = b.chain(gh, depth, &format!("a{depth}:"));
    let fork = b.chain(gh, depth + 2, &format!("b{depth}:"));
    let n = node_with(&genesis, &[]);
    for blk in &a {
        accept(&n, blk).unwrap();
    }
    let mut worst = 0isize;
    for blk in &fork {
        let base = CURRENT.load(Ordering::Relaxed);
        PEAK.store(base, Ordering::Relaxed);
        accept(&n, blk).unwrap();
        worst = worst.max(PEAK.load(Ordering::Relaxed) - base);
    }
    assert_eq!(applied_tip(&n), Some(fork.last().unwrap().block_hash()), "the reorg happened");
    worst
}

#[test]
fn b2_t0_reorg_peak_memory_does_not_grow_with_its_depth() {
    let shallow = reorg_peak(32);
    let deep = reorg_peak(128);
    // Blocks moved: the old branch rolled back, the fork applied.
    let (moved_shallow, moved_deep) = (32 + 33, 128 + 129);
    let per_block = (deep - shallow) as f64 / (moved_deep - moved_shallow) as f64;
    println!("B2-T0 peak extra heap during the reorg: depth 32 -> {} KiB, depth 128 -> {} KiB \
              ({per_block:.0} bytes per moved block; bodies are {PAD} bytes)",
        shallow / 1024, deep / 1024);
    // What may still grow with the depth is the move's bookkeeping of block
    // HASHES (the plan, the net-move sets): a few hundred bytes per block.
    // Pre-fix every moved block's body stayed in memory until the single
    // commit (measured: ~11 KiB per moved block here, 691 KiB -> 2716 KiB).
    assert!(per_block < (PAD / 5) as f64,
        "the peak grows by {per_block:.0} bytes per moved block ({shallow} -> {deep} bytes): \
         block bodies are kept for the whole move");
}
