//! Phase-4 package R4 regressions: bounded chain moves.
//!
//! * B1-T16 — planning a chain move walks O(move) selected-parent steps,
//!   never the whole chain to genesis.
//! * B2-T0 — chain moves (acceptance, start-up reconciliation, chain-state
//!   rebuild) commit in bounded chunks, each one a consistent applied tip that
//!   start-up resumes from; a move larger than the memory available to one
//!   commit still completes.
//! * B1-T20 — reorg re-injection is capped by Bitcoin Core's 20 MB
//!   `DisconnectedBlockTransactions` budget and stops once the pool is full.
//!
//! Every block goes through the REAL acceptance pipeline
//! (`gnb::accept::accept_block`, after `validate_structure`), with the proof
//! of work marked verified (`Block::test_only_assume_pow_valid`, dev-only
//! `test-pow-limit`).

mod fix_common;
use fix_common::*;

use std::sync::Arc;

use gnb::accept;
use gnb::consensus::{BlockHash, GhostDAG};
use gnb::core::{self, Block, BlockHeader, MerkleRoot, Transaction, TxInput, TxOutput, GHOSTDAG_K};
use gnb::core::activation::NEVER;
use gnb::mempool::Mempool;
use gnb::pow;
use gnb::reorg;
use gnb::storage::Storage;
use parking_lot::RwLock;

// ── Fixtures ─────────────────────────────────────────────────────────────────

struct Builder {
    dag: GhostDAG,
}

impl Builder {
    fn new(genesis: &Block) -> Self {
        let mut dag = GhostDAG::with_default_k();
        dag.add_genesis(genesis.block_hash(), genesis.header.timestamp);
        Builder { dag }
    }

    fn block(&mut self, parents: Vec<BlockHash>, txs: Vec<Transaction>) -> Block {
        let height = parents.iter()
            .map(|p| self.dag.get_block_data(p).expect("parent built").height).max().unwrap() + 1;
        let pts = parents.iter().map(|p| self.dag.get_block_data(p).unwrap().timestamp).max().unwrap();
        let bits = pow::expected_bits(pts, height).unwrap();
        let mut b = Block {
            header: BlockHeader {
                version: 1, parents: parents.clone(), merkle_root: MerkleRoot::ZERO,
                timestamp: pts + 1, bits, nonce: 0,
            },
            transactions: txs,
            blue_score: height,
            height,
            shielded_transactions: Vec::new(),
        };
        commit_block(&mut b);
        b.test_only_assume_pow_valid();
        self.dag.add_block(b.block_hash(), parents, b.header.timestamp, pow::work_from_bits(bits))
            .expect("builder DAG accepts the block");
        b
    }

    fn height(&self, h: &BlockHash) -> u64 {
        self.dag.get_block_data(h).unwrap().height
    }

    /// A chain of `n` coinbase-only blocks on `from`.
    fn chain(&mut self, from: BlockHash, n: usize, tag: &str) -> Vec<Block> {
        let mut out = Vec::with_capacity(n);
        let mut p = from;
        for i in 0..n {
            let h = self.height(&p) + 1;
            let cb = coinbase(&format!("{tag}{i}"), core::tokenomics::block_subsidy_sat(h), vec![0xC0; 20]);
            let b = self.block(vec![p], vec![cb]);
            p = b.block_hash();
            out.push(b);
        }
        out
    }
}

fn digest(n: &Node) -> [u8; 32] {
    n.store.utxo_set_digest().unwrap()
}

/// Reload the DAG and the shielded state from disk exactly as main() does
/// after a restart (an in-memory state that was lost in a crash), WITHOUT the
/// reconciliation.
fn reload(n: &mut Node) {
    let mut d = GhostDAG::with_default_k();
    let entries = n.store.load_all_dag_data().unwrap();
    let im = n.store.load_all_integrity_hashes().unwrap();
    d.load_persisted_validated(entries, im).expect("integrity chain verifies");
    let records = n.store.load_all_reachability().unwrap();
    let root = n.store.get_reachability_root().unwrap();
    if records.len() == d.block_count() {
        d.reach_load_records(&records, root).unwrap();
    } else {
        d.rebuild_reachability_from_store().unwrap();
    }
    n.dag = Arc::new(RwLock::new(d));
    n.shielded = Arc::new(RwLock::new(gnb::coherence::ShieldedPool::load(&n.store).expect("shielded state loads")));
}

fn deliver_all(n: &Node, blocks: &[Block]) {
    for b in blocks {
        accept(n, b).unwrap_or_else(|e| panic!("block h={} refused: {e}", b.height));
    }
}

/// Clears the fault injection of this thread when dropped (also on panic).
struct NoFaults;
impl Drop for NoFaults {
    fn drop(&mut self) {
        reorg::fault_injection::set_max_blocks_per_commit(None);
        reorg::fault_injection::fail_after_commits(None);
    }
}

fn hx(tag: u8, i: u64) -> BlockHash {
    let mut h = [0u8; 32];
    h[0] = tag;
    h[1..9].copy_from_slice(&i.to_be_bytes());
    h
}

// ═════════════════════════════════════════════════════════════════════════════
// B1-T16: the LCA walk costs the move, not the chain
// ═════════════════════════════════════════════════════════════════════════════

/// Pre-fix `find_lca` inserted the applied tip's whole selected chain, back to
/// genesis, into a set on EVERY tip-moving acceptance, so a one-block
/// extension of an N-block chain cost N steps and initial sync cost Θ(N²).
/// The plan is now found by walking both selected chains down by DAG height
/// (it strictly decreases along selected-parent edges, Bitcoin Core's
/// `LastCommonAncestor` on heights): O(reorg depth + extension length).
#[test]
fn b1_t16_connect_plan_walks_the_move_not_the_chain() {
    const N: u64 = 20_000;
    let g = hx(0xEE, 0);
    let mut dag = GhostDAG::with_k_and_activation(GHOSTDAG_K, NEVER);
    dag.add_genesis(g, 0);
    let mut prev = g;
    for i in 1..=N {
        dag.add_block(hx(1, i), vec![prev], i, 1).unwrap();
        prev = hx(1, i);
    }
    // A 7-block fork from block N - 5 (a 5-block reorg).
    let mut fp = hx(1, N - 5);
    for j in 1..=7 {
        dag.add_block(hx(2, j), vec![fp], N + j, 1).unwrap();
        fp = hx(2, j);
    }

    // One-block extension: the fast path every honest block takes.
    let before = reorg::chain_walk_steps();
    let plan = reorg::compute_connect_plan(&dag, &hx(1, N - 1), &hx(1, N)).expect("extension plan");
    let steps = reorg::chain_walk_steps() - before;
    assert_eq!(plan.to_apply, vec![hx(1, N)]);
    assert!(plan.to_rollback.is_empty());
    assert!(steps <= 4, "a one-block extension walked {steps} selected-parent steps (chain of {N})");

    // A 5-block reorg onto the 7-block fork.
    let before = reorg::chain_walk_steps();
    let plan = reorg::compute_connect_plan(&dag, &hx(1, N), &hx(2, 7)).expect("reorg plan");
    let steps = reorg::chain_walk_steps() - before;
    assert_eq!(plan.lca, hx(1, N - 5));
    assert_eq!(plan.to_rollback.len(), 5);
    assert_eq!(plan.to_apply.len(), 7);
    assert!(steps <= 2 * (5 + 7) + 8, "a 5-block reorg walked {steps} steps (chain of {N})");
    let before = reorg::chain_walk_steps();
    assert_eq!(reorg::find_lca(&dag, &hx(2, 7), &hx(1, N)), Some(hx(1, N - 5)));
    assert!(reorg::chain_walk_steps() - before <= 2 * (5 + 7) + 4);

    // A backward move (operator invalidateblock) and the degenerate cases.
    let plan = reorg::compute_connect_plan(&dag, &hx(1, N), &hx(1, N - 3)).expect("backward plan");
    assert_eq!(plan.to_rollback, vec![hx(1, N), hx(1, N - 1), hx(1, N - 2)]);
    assert!(plan.to_apply.is_empty());
    assert!(reorg::compute_connect_plan(&dag, &hx(1, N), &hx(1, N)).is_none());
    assert_eq!(reorg::find_lca(&dag, &g, &hx(2, 7)), Some(g));
    assert_eq!(reorg::find_lca(&dag, &hx(9, 9), &hx(2, 7)), None, "unknown block: no common ancestor");
}

// ═════════════════════════════════════════════════════════════════════════════
// B2-T0: chain moves commit in bounded chunks
// ═════════════════════════════════════════════════════════════════════════════

/// The audit's out-of-memory scenario, with the memory limit simulated: a
/// commit that stages more than 40 blocks "runs out of memory" before it is
/// written. Pre-fix the 60-block reorg (rolling back 60 blocks and applying
/// 61) was staged as ONE plan, failed, and failed again for every later block
/// and at every start-up: the node never reached the best chain. The move now
/// commits in chunks of `reorg::MAX_BLOCKS_PER_COMMIT` and completes; a
/// restart under the same limit is clean.
#[test]
fn b2_t0_a_reorg_larger_than_one_commit_can_hold_still_completes() {
    let _guard = NoFaults;
    let genesis = mk_genesis(unix_now() - 100_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let a = b.chain(gh, 60, "a");
    let fork = b.chain(gh, 62, "b");

    let reference = node_with(&genesis, &[]);
    deliver_all(&reference, &a);
    deliver_all(&reference, &fork);
    let best = fork.last().unwrap().block_hash();
    assert_eq!(applied_tip(&reference), Some(best));

    let mut n = node_with(&genesis, &[]);
    deliver_all(&n, &a);
    reorg::fault_injection::set_max_blocks_per_commit(Some(40));
    for blk in &fork {
        let _ = accept(&n, blk);
    }
    assert_eq!(applied_tip(&n), Some(best), "the node follows the best chain whatever the move's size");
    assert_eq!(digest(&n), digest(&reference));
    assert!(accept::check_chain_state(&n.dag, &n.store).unwrap().is_empty());

    restart(&mut n);
    assert_eq!(applied_tip(&n), Some(best));
    assert_eq!(digest(&n), digest(&reference));
}

/// A crash between two chunks of a deep reorg (simulated: the fourth commit
/// fails before it is written, and the in-memory state is then discarded).
/// Every committed chunk is a consistent applied tip — tip pointer, UTXO set,
/// undo records, shielded tip and the arriving block's DAG record moved
/// together — so the start-up check finds nothing to repair and start-up
/// reconciliation resumes the move from where it stopped, ending with the
/// UTXO set of a node that never crashed. Pre-fix the move was one batch: no
/// progress survived a crash, and the same move was retried from scratch.
#[test]
fn b2_t0_a_crash_between_chunks_resumes_at_restart() {
    let _guard = NoFaults;
    let genesis = mk_genesis(unix_now() - 100_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let a = b.chain(gh, 60, "a");
    let fork = b.chain(gh, 64, "b");

    let reference = node_with(&genesis, &[]);
    deliver_all(&reference, &a);
    deliver_all(&reference, &fork);

    let mut n = node_with(&genesis, &[]);
    deliver_all(&n, &a);
    let a_tip = a.last().unwrap().block_hash();
    // B's first 59 blocks are lighter than A: stored as fork-losers.
    deliver_all(&n, &fork[..59]);
    assert_eq!(applied_tip(&n), Some(a_tip));

    // The reorg starts with B's 60th or 61st block; the fourth commit "crashes".
    reorg::fault_injection::fail_after_commits(Some(3));
    let mut switched_at = None;
    for (i, blk) in fork.iter().enumerate().skip(59).take(2) {
        let _ = accept(&n, blk);
        if applied_tip(&n) != Some(a_tip) && switched_at.is_none() {
            switched_at = Some(i);
        }
    }
    let switched_at = switched_at.expect("the reorg started and committed progress before the crash");
    let mid = applied_tip(&n).unwrap();
    assert_ne!(mid, a_tip);
    assert!(!fork.iter().any(|x| x.block_hash() == mid),
        "the crash interrupted the move: the applied tip is an intermediate block of the old chain");
    assert!(n.dag.read().is_on_selected_chain_of(&mid, &a_tip), "rolled back part of the old chain");
    assert!(accept::check_chain_state(&n.dag, &n.store).unwrap().is_empty(),
        "every intermediate state is a consistent applied tip");
    let shielded = gnb::coherence::ShieldedPool::load(&n.store).expect("shielded state loads");
    assert_eq!(shielded.tip(), Some(mid), "the shielded tip moved with the UTXO tip");

    // Crash: the in-memory state is lost; restart from disk.
    reorg::fault_injection::fail_after_commits(None);
    reload(&mut n);
    assert!(n.dag.read().has_block(&fork[switched_at].block_hash()),
        "the arriving block's DAG record was committed with the first chunk");
    accept::reconcile_on_startup(&n.dag, &n.store, &n.shielded).expect("reconcile resumes the move");
    assert_eq!(applied_tip(&n), Some(fork[switched_at].block_hash()));
    for blk in &fork[switched_at + 1..] {
        if !n.dag.read().has_block(&blk.block_hash()) {
            accept(&n, blk).expect("later blocks connect normally");
        }
    }
    assert_eq!(applied_tip(&n), Some(fork.last().unwrap().block_hash()));
    assert_eq!(digest(&n), digest(&reference), "same UTXO set as a node that never crashed");
    restart(&mut n);
    assert_eq!(digest(&n), digest(&reference));
}

fn genesis_seed(genesis: &Block)
    -> impl Fn(&Storage, &mut rocksdb::WriteBatch) -> Result<(), String>
{
    let gh = genesis.block_hash();
    let txids: Vec<[u8; 32]> = genesis.transactions.iter().map(|t| t.txid()).collect();
    move |st: &Storage, batch: &mut rocksdb::WriteBatch| {
        for t in &txids {
            st.stage_tx_index(batch, t, &gh, 0).map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

/// The chain-state rebuild (audit DAG-11) re-applies the chain from genesis
/// in bounded chunks: it completes under a memory limit no single commit of
/// the whole chain fits in, and an interrupted rebuild resumes from the last
/// committed chunk instead of starting over (pre-fix: one plan from genesis,
/// O(chain bytes) of memory, retried from scratch at every start).
#[test]
fn b2_t0_chain_state_rebuild_is_chunked_and_resumes() {
    let _guard = NoFaults;
    let genesis = mk_genesis(unix_now() - 100_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let chain = b.chain(gh, 70, "r");
    let mut n = node_with(&genesis, &[]);
    n.store.put_tx_index(&genesis.transactions[0].txid(), &gh, 0).unwrap();
    deliver_all(&n, &chain);
    let clean = digest(&n);
    let tip = chain.last().unwrap().block_hash();

    // Under a 40-block commit limit the whole rebuild still completes.
    reorg::fault_injection::set_max_blocks_per_commit(Some(40));
    let report = accept::rebuild_chain_state(&n.dag, &n.store, &n.shielded, &genesis_seed(&genesis))
        .expect("a chunked rebuild fits the memory limit");
    assert_eq!(report.connected_blocks, chain.len());
    assert_eq!(digest(&n), clean);
    reorg::fault_injection::set_max_blocks_per_commit(None);

    // A rebuild interrupted after two chunks keeps its progress...
    reorg::fault_injection::fail_after_commits(Some(2));
    let err = accept::rebuild_chain_state(&n.dag, &n.store, &n.shielded, &genesis_seed(&genesis));
    reorg::fault_injection::fail_after_commits(None);
    assert!(err.is_err(), "the interrupted rebuild reports the failure");
    let mid = applied_tip(&n).unwrap();
    assert_ne!(mid, gh, "progress was committed");
    assert_ne!(mid, tip);
    reload(&mut n);
    assert_eq!(accept::check_chain_state(&n.dag, &n.store).unwrap(),
        vec![accept::ChainStateFault::RebuildInterrupted]);
    // ...and the next run resumes from the last committed chunk.
    let mid_height = n.dag.read().get_block_data(&mid).unwrap().height as usize;
    let report = accept::rebuild_chain_state(&n.dag, &n.store, &n.shielded, &genesis_seed(&genesis))
        .expect("the rebuild resumes");
    assert_eq!(report.connected_blocks, chain.len() - mid_height, "resumed, not restarted from genesis");
    assert_eq!(applied_tip(&n), Some(tip));
    assert_eq!(digest(&n), clean);
    assert!(accept::check_chain_state(&n.dag, &n.store).unwrap().is_empty());
    restart(&mut n);
    assert_eq!(digest(&n), clean);
}

// ═════════════════════════════════════════════════════════════════════════════
// B1-T20: bounded re-injection
// ═════════════════════════════════════════════════════════════════════════════

/// A large, standard-looking transaction spending `fund` (synthetic witness:
/// re-injection does not re-check witnesses below the activation).
fn fat_tx(fund: ([u8; 32], u32), tag: u32) -> Transaction {
    let mut script_sig = vec![0x5Au8; 9_000];
    script_sig[..4].copy_from_slice(&tag.to_le_bytes());
    Transaction {
        version: 1,
        inputs: vec![TxInput { prev_txid: fund.0, prev_index: fund.1, script_sig, sequence: u32::MAX }],
        outputs: vec![TxOutput { value: 10_000, script_pubkey: vec![0xB7; 20] }],
        locktime: 0,
    }
}

fn synthetic_block(height: u64, nonce: u64, txs: Vec<Transaction>) -> Block {
    let mut all = vec![coinbase(&format!("syn{height}:{nonce}"), 0, vec![0u8; 20])];
    all.extend(txs);
    Block {
        header: BlockHeader {
            version: 1, parents: vec![], merkle_root: MerkleRoot::ZERO,
            timestamp: 1_700_000_000 + height, bits: 0x1d00ffff, nonce,
        },
        transactions: all,
        blue_score: height,
        height,
        shielded_transactions: Vec::new(),
    }
}

/// Bitcoin Core keeps at most `MAX_DISCONNECTED_TX_POOL_BYTES` (20 MB) of
/// disconnected transactions for re-admission and trims the MOST RECENTLY
/// confirmed ones first, so what it keeps (the transactions of the oldest
/// disconnected blocks, in block order) never misses a parent. Pre-fix every
/// non-coinbase transaction of every disconnected block was cloned and
/// re-admitted, under the acceptance lock: here 25 MB of them.
#[test]
fn b1_t20_reinjection_candidates_are_capped_at_the_core_budget() {
    let mut blocks = Vec::new();
    let mut tag = 0u32;
    for h in 0..25u64 {
        let txs: Vec<Transaction> = (0..110)
            .map(|i| {
                tag += 1;
                let mut fund = [0u8; 32];
                fund[..8].copy_from_slice(&(h * 1_000 + i).to_le_bytes());
                fat_tx((fund, 0), tag)
            })
            .collect();
        blocks.push(synthetic_block(h + 1, h, txs));
    }
    let total: usize = blocks.iter()
        .flat_map(|b| b.transactions.iter().skip(1))
        .map(|t| t.actual_size())
        .sum();
    assert!(total > 24_000_000, "the disconnected blocks carry {total} bytes of transactions");

    let tmp = tempfile::TempDir::new().unwrap();
    let store = Storage::open(tmp.path()).unwrap();
    for b in &blocks {
        store.put_block_body(b).unwrap();
    }
    // Tip-first, as a move disconnects them; hashes only (B2-T0).
    let outcome = reorg::ConnectOutcome {
        disconnected: blocks.iter().rev().map(|b| b.block_hash()).collect(),
        ..Default::default()
    };
    let selected = outcome.reinjection_candidates(&store, reorg::MAX_DISCONNECTED_TX_POOL_BYTES);
    assert!(selected.truncated);
    let candidates = selected.txs;
    let bytes: usize = candidates.iter().map(|t| t.actual_size()).sum();
    assert_eq!(bytes, selected.bytes);
    assert_eq!(reorg::MAX_DISCONNECTED_TX_POOL_BYTES, 20_000_000, "Bitcoin Core's budget");
    assert!(bytes <= 20_000_000, "{bytes} bytes of re-admission candidates (budget 20 MB)");
    assert!(bytes > 20_000_000 - 10_000, "the budget is used up to its last transaction");
    let expect: Vec<[u8; 32]> = blocks.iter()
        .flat_map(|b| b.transactions.iter().skip(1).map(|t| t.txid()))
        .take(candidates.len())
        .collect();
    assert_eq!(candidates.iter().map(|t| t.txid()).collect::<Vec<_>>(), expect,
        "the oldest disconnected blocks' transactions, in block order, are kept");
}

/// Re-admission into a full pool, modeled on Core's `MaybeUpdateMempoolForReorg`
/// (re-add with `bypass_limits`, then ONE `LimitMempoolSize`): a candidate
/// that the final trim would remove at once is not inserted (no per-candidate
/// insert-and-trim under the acceptance lock), better-paying candidates
/// displace the cheapest pooled packages, the pool ends within its caps, and
/// the rolling minimum fee (relay policy) does not refuse a transaction that
/// was already mined.
#[test]
fn b1_t20_readmission_into_a_full_pool_trims_once_and_keeps_the_best() {
    const POOL_CAP: usize = gnb::mempool::MAX_MEMPOOL_SIZE;
    let tmp = tempfile::TempDir::new().unwrap();
    let store = Storage::open(tmp.path()).unwrap();
    let mempool = Mempool::new();
    // A full pool of small transactions paying 50 sat/byte.
    for i in 0..POOL_CAP as u64 {
        let mut prev = [0xA0u8; 32];
        prev[..8].copy_from_slice(&i.to_le_bytes());
        let tx = Transaction {
            version: 1,
            inputs: vec![TxInput { prev_txid: prev, prev_index: 0, script_sig: vec![1, 2, 3], sequence: u32::MAX }],
            outputs: vec![TxOutput { value: 5_000, script_pubkey: vec![0xA1; 20] }],
            locktime: 0,
        };
        let fee = 50 * tx.actual_size() as u64;
        mempool.add(tx, fee).expect("pool fills");
    }
    assert_eq!(mempool.size(), POOL_CAP);

    // Candidates from disconnected blocks: 10 paying ~110 sat/byte, 10 paying
    // ~3 sat/byte (above the consensus minimum, below the pool's eviction rate).
    let mut cands = Vec::new();
    for (i, value) in [(0u32, 1_000_000u64), (1, 37_000)].iter().flat_map(|&(k, v)| (0..10).map(move |j| (k * 10 + j, v))) {
        let mut fund = [0xC5u8; 32];
        fund[..4].copy_from_slice(&i.to_le_bytes());
        store.put_utxo(&fund, 0, &TxOutput { value, script_pubkey: vec![0xC6; 20] }).unwrap();
        cands.push(fat_tx((fund, 0), i));
    }
    let high: Vec<[u8; 32]> = cands[..10].iter().map(|t| t.txid()).collect();
    let low: Vec<[u8; 32]> = cands[10..].iter().map(|t| t.txid()).collect();
    let (re, dropped) = reorg::reinject_disconnected(&store, &mempool, cands, 2);
    assert_eq!((re, dropped), (10, 10), "the 10 well-paying candidates are re-admitted, the 10 cheap ones skipped");
    assert!(high.iter().all(|t| mempool.contains(t)));
    assert!(low.iter().all(|t| !mempool.contains(t)));
    assert!(mempool.size() <= POOL_CAP, "the pool is trimmed back within its cap");

    // Not full any more, but the trim raised the rolling minimum (50 sat/byte
    // and up): relay refuses 3 sat/byte, re-admission of a mined transaction
    // does not (Core bypasses the mempool minimum fee for reorged transactions).
    for t in mempool.txids().into_iter().filter(|t| !high.contains(t)).take(100) {
        mempool.remove(&t);
    }
    assert!(mempool.rolling_min_fee_rate() >= 50);
    let mut fund = [0xC7u8; 32];
    fund[0] = 1;
    store.put_utxo(&fund, 0, &TxOutput { value: 37_000, script_pubkey: vec![0xC6; 20] }).unwrap();
    let cheap = fat_tx((fund, 0), 999);
    let id = cheap.txid();
    let (re, _) = reorg::reinject_disconnected(&store, &mempool, vec![cheap], 2);
    assert_eq!(re, 1);
    assert!(mempool.contains(&id));
}
