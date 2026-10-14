//! Chain selection regressions for the 2026-10 audit, package P3:
//!
//! * DAG-6 — no node-local reorg-depth cap or finality gate: nodes holding
//!   the same blocks end on the same chain and the same UTXO set whatever the
//!   arrival order, at any depth (the audit's 1,101-block scenario), also
//!   through pruned bodies; operator `invalidateblock` / `reconsiderblock`.
//! * DAG-11 residual — the footprint of an interrupted pre-fix (non-atomic)
//!   commit is detected at start-up and the chain state is rebuilt from the
//!   block bodies.
//! * POW-3 (node-local anti-DoS half) and DAG-7 residual — see the sections
//!   below.
//!
//! Every block goes through the REAL acceptance pipeline
//! (`gnb::accept::accept_block`, after `validate_structure`). The fixtures
//! mark each block's proof of work as verified in the process-wide PoW cache
//! (`Block::test_only_assume_pow_valid`, compiled only with the dev-only
//! `test-pow-limit` feature) instead of spending one ~0.7 s GnB-SMH
//! evaluation per block; every other check runs unchanged.
//!
//! Under `test-pow-limit` every expected target is the pow limit, so every
//! block carries the same work and "heavier" means "more blue blocks".

mod fix_common;
use fix_common::*;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use gnb::accept;
use gnb::consensus::{BlockHash, GhostDAG};
use gnb::core::{self, Block, BlockHeader, MerkleRoot, Transaction, TxOutput};
use gnb::pow;
use parking_lot::RwLock;

// ── Fixtures ─────────────────────────────────────────────────────────────────

/// Builds blocks with the header height / bits / timestamps the consensus
/// rules require, tracking DAG heights in its own GhostDAG (no storage).
struct Builder {
    dag: GhostDAG,
}

impl Builder {
    fn new(genesis: &Block) -> Self {
        let mut dag = GhostDAG::with_default_k();
        dag.add_genesis(genesis.block_hash(), genesis.header.timestamp);
        Builder { dag }
    }

    fn block_where(
        &mut self,
        parents: Vec<BlockHash>,
        txs: Vec<Transaction>,
        pred: impl Fn(&BlockHash) -> bool,
    ) -> Block {
        let height = parents.iter()
            .map(|p| self.dag.get_block_data(p).expect("parent built").height).max().unwrap() + 1;
        let pts = parents.iter()
            .map(|p| self.dag.get_block_data(p).unwrap().timestamp).max().unwrap();
        let bits = pow::expected_bits(pts, height).unwrap();
        let mut b = Block {
            header: BlockHeader {
                version: 1,
                parents: parents.clone(),
                merkle_root: MerkleRoot::ZERO,
                timestamp: pts + 1,
                bits,
                nonce: 0,
            },
            transactions: txs,
            blue_score: height,
            height,
            shielded_transactions: Vec::new(),
        };
        b.header.merkle_root = b.body_merkle_root();
        while !pred(&b.block_hash()) {
            b.header.nonce += 1;
        }
        b.test_only_assume_pow_valid();
        self.dag.add_block(b.block_hash(), parents, b.header.timestamp, pow::work_from_bits(bits))
            .expect("builder DAG accepts the block");
        b
    }

    fn block(&mut self, parents: Vec<BlockHash>, txs: Vec<Transaction>) -> Block {
        self.block_where(parents, txs, |_| true)
    }

    fn height(&self, h: &BlockHash) -> u64 {
        self.dag.get_block_data(h).unwrap().height
    }

    /// A coinbase-only block on `parents` paying the full subsidy.
    fn empty(&mut self, parents: Vec<BlockHash>, tag: &str) -> Block {
        let h = parents.iter().map(|p| self.height(p)).max().unwrap() + 1;
        let cb = coinbase(tag, core::tokenomics::block_subsidy_sat(h), vec![0xC0; 20]);
        self.block(parents, vec![cb])
    }

    /// Coinbase + `txs` on `parents`, the coinbase claiming subsidy + `fees`.
    fn with_txs(&mut self, parents: Vec<BlockHash>, tag: &str, fees: u64, txs: Vec<Transaction>) -> Block {
        let h = parents.iter().map(|p| self.height(p)).max().unwrap() + 1;
        let mut all = vec![coinbase(tag, core::tokenomics::block_subsidy_sat(h) + fees, vec![0xC1; 20])];
        all.extend(txs);
        self.block(parents, all)
    }

    /// A chain of `n` coinbase-only blocks on `from`.
    fn chain(&mut self, from: BlockHash, n: usize, tag: &str) -> Vec<Block> {
        let mut out = Vec::with_capacity(n);
        let mut p = from;
        for i in 0..n {
            let b = self.empty(vec![p], &format!("{tag}{i}"));
            p = b.block_hash();
            out.push(b);
        }
        out
    }
}

fn digest(n: &Node) -> [u8; 32] {
    n.store.utxo_set_digest().unwrap()
}

/// Deliver `blocks` in this order. A block whose parents are not all known
/// yet waits (as an orphan would) and is retried after every accepted block.
/// Returns the accept results, by block hash.
fn deliver(n: &Node, blocks: &[Block]) -> HashMap<BlockHash, Result<BlockHash, String>> {
    let mut results = HashMap::new();
    let mut pending: Vec<Block> = Vec::new();
    for b in blocks {
        pending.push(b.clone());
        loop {
            let ready = pending.iter().position(|x| {
                let d = n.dag.read();
                x.header.parents.iter().all(|p| d.has_block(p))
            });
            let Some(i) = ready else { break };
            let x = pending.remove(i);
            results.insert(x.block_hash(), accept(n, &x));
        }
    }
    assert!(pending.is_empty(), "every block's parents were delivered");
    results
}

/// Small deterministic RNG (xorshift64*).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            let j = self.below(i + 1);
            v.swap(i, j);
        }
    }
}

/// Reload the DAG from CF_DAG exactly as main() does after a restart, WITHOUT
/// running the reconciliation (the caller decides).
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
    n.shielded = Arc::new(RwLock::new(gnb::coherence::ShieldedPool::new()));
}

fn tip_meta(n: &Node) -> BlockHash {
    applied_tip(n).expect("tip pointer")
}

// ═════════════════════════════════════════════════════════════════════════════
// DAG-6: convergence without a reorg-depth cap
// ═════════════════════════════════════════════════════════════════════════════

/// The audit's DAG-6 scenario, through the real pipeline. Node X sees the
/// honest chain (1,101 blocks) first and then a heavier fork (1,103 blocks)
/// that branches at genesis — a 1,101-block reorg, beyond the old 1,000-block
/// cap that made X refuse it. Node Z receives the same blocks interleaved and
/// node W only the fork. The first block of each branch spends the same
/// funding output to a different recipient, so the two UTXO sets differ.
///
/// Pre-fix: X stayed on the honest chain while Z followed the fork (a
/// permanent split). Now all three end on the fork tip with byte-identical
/// UTXO sets, and X keeps it across a restart.
#[test]
fn dag6_deep_fork_converges_whatever_the_arrival_order() {
    const N: usize = 1_101;
    let genesis = mk_genesis(unix_now() - 200_000);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0x61u8; 32], 0u32, out(5_000_000, &k.spk));
    let t0 = std::time::Instant::now();
    let mut b = Builder::new(&genesis);

    let pay_honest = signed_spend(&k, &[(fund.0, fund.1)], vec![out(4_900_000, &[0xAA; 20])]);
    let pay_fork = signed_spend(&k, &[(fund.0, fund.1)], vec![out(4_900_000, &[0xBB; 20])]);
    let h1 = b.with_txs(vec![gh], "h1", 100_000, vec![pay_honest.clone()]);
    let mut honest = vec![h1.clone()];
    honest.extend(b.chain(h1.block_hash(), N - 1, "h"));
    let f1 = b.with_txs(vec![gh], "f1", 100_000, vec![pay_fork.clone()]);
    let mut fork = vec![f1.clone()];
    fork.extend(b.chain(f1.block_hash(), N + 1, "f"));
    let honest_tip = honest.last().unwrap().block_hash();
    let fork_tip = fork.last().unwrap().block_hash();

    println!("built {} blocks in {:.2?}", honest.len() + fork.len(), t0.elapsed());

    // Node X: honest chain first, then the heavier fork.
    let t = std::time::Instant::now();
    let mut x = node_with(&genesis, std::slice::from_ref(&fund));
    for blk in &honest {
        accept(&x, blk).expect("honest block");
    }
    assert_eq!(tip_meta(&x), honest_tip);
    let honest_digest = digest(&x);
    println!("X: honest chain in {:.2?}", t.elapsed());
    let t = std::time::Instant::now();
    for blk in &fork {
        accept(&x, blk).expect("fork block accepted (fork-loser, then the deep reorg)");
    }
    println!("X: fork + {}-block reorg in {:.2?}", honest.len(), t.elapsed());

    // Node Z: the same blocks, interleaved (as in the audit's PoC, the fork
    // is strictly ahead after every step, so Z never adopts the honest
    // chain and never reorganizes).
    let t = std::time::Instant::now();
    let z = node_with(&genesis, std::slice::from_ref(&fund));
    accept(&z, &fork[0]).expect("fork block on Z");
    accept(&z, &fork[1]).expect("fork block on Z");
    for i in 0..honest.len() {
        accept(&z, &honest[i]).expect("honest block on Z");
        accept(&z, &fork[i + 2]).expect("fork block on Z");
    }
    assert_eq!(honest.len() + 2, fork.len());
    println!("Z: interleaved in {:.2?}", t.elapsed());

    // Node W: only the fork (fresh sync from the network that has it).
    let w = node_with(&genesis, std::slice::from_ref(&fund));
    for blk in &fork {
        accept(&w, blk).unwrap();
    }

    for (name, n) in [("X", &x), ("Z", &z), ("W", &w)] {
        assert_eq!(sel_tip(n), Some(fork_tip), "{name}: selected tip");
        assert_eq!(tip_meta(n), fork_tip, "{name}: applied tip");
        assert!(n.store.get_utxo(&pay_fork.txid(), 0).unwrap().is_some(), "{name}: fork payment");
        assert!(n.store.get_utxo(&pay_honest.txid(), 0).unwrap().is_none(), "{name}: no honest payment");
    }
    let dz = digest(&z);
    assert_eq!(digest(&x), dz, "X and Z hold the same UTXO set");
    assert_eq!(digest(&w), dz, "and so does a node that only saw the fork");
    assert_ne!(honest_digest, dz, "the reorg really changed the UTXO set");

    // The deep reorg is durable on X.
    let t = std::time::Instant::now();
    restart(&mut x);
    println!("X: restart in {:.2?}", t.elapsed());
    assert_eq!(sel_tip(&x), Some(fork_tip));
    assert_eq!(tip_meta(&x), fork_tip);
    assert_eq!(digest(&x), dz);
}

/// A connect-time failure in the heavier branch still converges: the branch
/// is disqualified from the invalid block on, everywhere, whatever the order.
fn shape_with_invalid_branch(b: &mut Builder, gh: BlockHash, k: &Key, fund: ([u8; 32], u32)) -> Vec<Block> {
    // Branch A spends `fund` (valid). Branch B is heavier but its 3rd block
    // spends the output of A's payment, which does not exist on B's chain.
    let pay_a = signed_spend(k, &[fund], vec![out(4_900_000, &[0xA1; 20])]);
    let a1 = b.with_txs(vec![gh], "a1", 100_000, vec![pay_a.clone()]);
    let mut blocks = vec![a1.clone()];
    blocks.extend(b.chain(a1.block_hash(), 5, "a"));
    let bb = b.chain(gh, 2, "b");
    let bad_spend = signed_spend(k, &[(pay_a.txid(), 0)], vec![out(4_800_000, &[0xB9; 20])]);
    blocks.extend(bb.clone());
    let b3 = b.with_txs(vec![bb[1].block_hash()], "b3", 100_000, vec![bad_spend]);
    blocks.push(b3.clone());
    blocks.extend(b.chain(b3.block_hash(), 6, "bx"));
    blocks
}

/// A DAG with two long competing branches that merge repeatedly.
fn shape_merging_branches(b: &mut Builder, gh: BlockHash) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut l = gh;
    let mut r = gh;
    for i in 0..18 {
        let bl = b.empty(vec![l], &format!("ml{i}"));
        let br = b.empty(vec![r], &format!("mr{i}"));
        l = bl.block_hash();
        r = br.block_hash();
        blocks.push(bl);
        blocks.push(br);
        if i % 5 == 4 {
            // Merge the right branch into the left one.
            let m = b.empty(vec![l, r], &format!("mm{i}"));
            l = m.block_hash();
            blocks.push(m);
        }
    }
    // A deep side chain from genesis, longer than everything else.
    blocks.extend(b.chain(gh, 40, "deep"));
    blocks
}

/// A wide DAG: random parents among the recent tips.
fn shape_wide(b: &mut Builder, gh: BlockHash, rng: &mut Rng) -> Vec<Block> {
    let mut blocks: Vec<Block> = Vec::new();
    let mut tips: Vec<BlockHash> = vec![gh];
    for i in 0..60 {
        let np = 1 + rng.below(3.min(tips.len()));
        let mut parents: Vec<BlockHash> = Vec::new();
        for _ in 0..np {
            let p = tips[tips.len() - 1 - rng.below(tips.len().min(4))];
            if !parents.contains(&p) {
                parents.push(p);
            }
        }
        let blk = b.empty(parents.clone(), &format!("w{i}"));
        tips.retain(|t| !parents.contains(t));
        tips.push(blk.block_hash());
        blocks.push(blk);
    }
    blocks
}

/// Randomized arrival order over several DAG shapes: every permutation of the
/// same block set (parents still arrive before children, as an orphan pool
/// guarantees) ends on the same selected tip, the same applied tip and the
/// same UTXO set as delivery in creation order.
#[test]
fn dag6_random_arrival_orders_converge_on_several_dag_shapes() {
    let genesis = mk_genesis(unix_now() - 50_000);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0x62u8; 32], 0u32, out(5_000_000, &k.spk));
    let mut rng = Rng(0x0DAC_6000_0000_0001);

    let mut b = Builder::new(&genesis);
    let shapes: Vec<(&str, Vec<Block>)> = vec![
        ("invalid heavier branch", shape_with_invalid_branch(&mut b, gh, &k, (fund.0, fund.1))),
        ("merging branches + deep side chain", shape_merging_branches(&mut b, gh)),
        ("wide random DAG", shape_wide(&mut b, gh, &mut rng)),
    ];

    for (label, blocks) in shapes {
        let reference = node_with(&genesis, std::slice::from_ref(&fund));
        deliver(&reference, &blocks);
        let want_tip = sel_tip(&reference).unwrap();
        let want_digest = digest(&reference);
        assert_eq!(tip_meta(&reference), want_tip, "{label}: reference applied tip");
        let ref_invalid: HashSet<BlockHash> = {
            let d = reference.dag.read();
            blocks.iter().map(|b| b.block_hash()).filter(|h| d.is_invalid(h)).collect()
        };

        for round in 0..4 {
            let mut order = blocks.clone();
            rng.shuffle(&mut order);
            let n = node_with(&genesis, std::slice::from_ref(&fund));
            deliver(&n, &order);
            assert_eq!(sel_tip(&n), Some(want_tip), "{label} round {round}: selected tip");
            assert_eq!(tip_meta(&n), want_tip, "{label} round {round}: applied tip");
            assert_eq!(digest(&n), want_digest, "{label} round {round}: UTXO set");
            // The same blocks are disqualified (every branch heavier than the
            // final tip is evaluated on every node, whatever the order).
            let d = n.dag.read();
            let got: HashSet<BlockHash> =
                blocks.iter().map(|b| b.block_hash()).filter(|h| d.is_invalid(h)).collect();
            assert_eq!(got, ref_invalid, "{label} round {round}: disqualified set");
        }
        if label == "invalid heavier branch" {
            // b3 and its six descendants.
            assert_eq!(ref_invalid.len(), 7, "the invalid branch was evaluated and disqualified");
        }
    }
}

/// A reorg deeper than the pruning point: the honest chain's bodies below
/// height 40 are pruned on X before the heavier fork arrives. The rollback
/// works from the undo records (never pruned) and the pruned-body records,
/// so X ends with exactly the UTXO set of a node that only saw the fork, and
/// the address history of the disconnected blocks is gone. One pruned body
/// carries no record (pruned by an older release): the UTXO set is still
/// exact.
#[test]
fn dag6_reorg_through_pruned_bodies_is_exact() {
    let genesis = mk_genesis(unix_now() - 50_000);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0x63u8; 32], 0u32, out(5_000_000, &k.spk));
    let mut b = Builder::new(&genesis);

    let pay = signed_spend(&k, &[(fund.0, fund.1)], vec![out(4_900_000, &[0xD1; 20])]);
    let h1 = b.with_txs(vec![gh], "ph1", 100_000, vec![pay.clone()]);
    let mut honest = vec![h1.clone()];
    honest.extend(b.chain(h1.block_hash(), 59, "ph"));
    let fork = b.chain(gh, 62, "pf");

    let x = node_with(&genesis, std::slice::from_ref(&fund));
    for blk in &honest {
        accept(&x, blk).unwrap();
    }
    let addr = [0xD1u8; 20];
    let spender: [u8; 20] = k.spk[..20].try_into().unwrap();
    assert_eq!(x.store.query_address_history(&addr, 0, u64::MAX, 10, 0).unwrap().len(), 1, "output row");
    assert_eq!(x.store.query_address_history(&spender, 0, u64::MAX, 10, 0).unwrap().len(), 1, "input row");
    let pruned = x.store.prune_blocks_below(40).unwrap();
    assert_eq!(pruned, 40, "genesis + 39 honest bodies pruned");
    assert!(x.store.get_block(&h1.block_hash()).unwrap().is_none());
    assert!(x.store.get_pruned_body_record(&h1.block_hash()).unwrap().is_some());
    // Simulate a body pruned by an older release (no rollback record).
    let old_style = honest[20].block_hash();
    {
        let mut batch = rocksdb::WriteBatch::default();
        x.store.stage_delete_pruned_body_record(&mut batch, &old_style).unwrap();
        x.store.write_batch(batch).unwrap();
    }

    for blk in &fork {
        accept(&x, blk).expect("fork block");
    }
    let w = node_with(&genesis, std::slice::from_ref(&fund));
    for blk in &fork {
        accept(&w, blk).unwrap();
    }
    let fork_tip = fork.last().unwrap().block_hash();
    assert_eq!(tip_meta(&x), fork_tip);
    assert_eq!(digest(&x), digest(&w), "UTXO set exact after a reorg through pruned bodies");
    assert!(x.store.get_utxo(&fund.0, 0).unwrap().is_some(), "the fund is unspent again");
    assert!(x.store.get_undo_data(&h1.block_hash()).unwrap().is_none(), "undo consumed");
    assert!(x.store.get_pruned_body_record(&h1.block_hash()).unwrap().is_none(), "record consumed");
    assert!(x.store.query_address_history(&addr, 0, u64::MAX, 10, 0).unwrap().is_empty(),
        "address history (output row) of the pruned, disconnected block is un-indexed");
    assert!(x.store.query_address_history(&spender, 0, u64::MAX, 10, 0).unwrap().is_empty(),
        "address history (input row) of the pruned, disconnected block is un-indexed");
    for (i, blk) in fork.iter().enumerate() {
        assert_eq!(x.store.get_block_hash_at_height(i as u64 + 1).unwrap(), Some(blk.block_hash()));
    }

    // The honest chain grows past the fork again: X must re-apply honest
    // blocks whose bodies it pruned. The connect reports them missing
    // (nothing is written); the ingress core names exactly the bodies to
    // re-fetch, stores them after the usual structure and proof checks, and
    // the chain is followed — with the UTXO set of a node that never left it.
    let more = b.chain(honest.last().unwrap().block_hash(), 4, "ph-more"); // 64 > 62
    let mut core = BlockIngress::new();
    let mut refetched = 0;
    for blk in &more {
        loop {
            match feed(&mut core, &x, blk) {
                BlockOutcome::Processed { result: Ok(_), .. } => break,
                BlockOutcome::Processed { result: Err(e), missing_bodies, .. } => {
                    assert!(e.contains(gnb::reorg::ERR_MISSING_BODIES), "{e}");
                    assert!(!missing_bodies.is_empty());
                    for h in missing_bodies {
                        let body = honest.iter().find(|x| x.block_hash() == h).expect("a pruned honest block");
                        assert!(matches!(feed(&mut core, &x, body), BlockOutcome::BodyRestored));
                        refetched += 1;
                    }
                }
                other => panic!("{other:?}"),
            }
        }
    }
    assert_eq!(refetched, 39, "the 39 pruned honest bodies (genesis is never re-applied)");
    assert_eq!(tip_meta(&x), more.last().unwrap().block_hash());
    let v = node_with(&genesis, std::slice::from_ref(&fund));
    deliver(&v, &honest);
    deliver(&v, &more);
    assert_eq!(digest(&x), digest(&v), "back on the honest chain with its exact UTXO set");
}

// ═════════════════════════════════════════════════════════════════════════════
// DAG-6: operator recovery — invalidateblock / reconsiderblock
// ═════════════════════════════════════════════════════════════════════════════

fn invalidate(n: &Node, h: BlockHash) -> Result<accept::ChainOverride, String> {
    accept::invalidate_block(h, &n.dag, &n.store, &n.mempool, &n.node_state, Some(&n.tip_tx), &n.shielded)
}

fn reconsider(n: &Node, h: BlockHash) -> Result<accept::ChainOverride, String> {
    accept::reconsider_block(h, &n.dag, &n.store, &n.mempool, &n.node_state, Some(&n.tip_tx), &n.shielded)
}

/// `invalidateblock` makes the node leave the heaviest chain for the best
/// chain that does not contain the block (rolling back past it), persists
/// across a restart, and `reconsiderblock` returns to the heaviest chain —
/// each time with exactly the UTXO set of a node that only ever saw the
/// chain it ends on.
#[test]
fn dag6_invalidateblock_and_reconsiderblock_persist_and_converge() {
    let genesis = mk_genesis(unix_now() - 50_000);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0x64u8; 32], 0u32, out(5_000_000, &k.spk));
    let mut b = Builder::new(&genesis);

    let pay_a = signed_spend(&k, &[(fund.0, fund.1)], vec![out(4_900_000, &[0xE1; 20])]);
    let a1 = b.with_txs(vec![gh], "ia1", 100_000, vec![pay_a.clone()]);
    let mut a = vec![a1.clone()];
    a.extend(b.chain(a1.block_hash(), 5, "ia")); // a1..a6
    let pay_b = signed_spend(&k, &[(fund.0, fund.1)], vec![out(4_900_000, &[0xE2; 20])]);
    let b1 = b.with_txs(vec![gh], "ib1", 100_000, vec![pay_b.clone()]);
    let mut bb = vec![b1.clone()];
    bb.extend(b.chain(b1.block_hash(), 3, "ib")); // b1..b4 (lighter)

    let mut n = node_with(&genesis, std::slice::from_ref(&fund));
    deliver(&n, &a);
    deliver(&n, &bb);
    let a_tip = a.last().unwrap().block_hash();
    let b_tip = bb.last().unwrap().block_hash();
    assert_eq!(tip_meta(&n), a_tip);
    let only_a = node_with(&genesis, std::slice::from_ref(&fund));
    deliver(&only_a, &a);
    let only_b = node_with(&genesis, std::slice::from_ref(&fund));
    deliver(&only_b, &bb);

    // Errors: unknown block, genesis.
    assert!(invalidate(&n, [0x99; 32]).unwrap_err().contains("not found"));
    assert!(invalidate(&n, gh).unwrap_err().contains("genesis"));

    // Invalidate a2: chain A is left; the best remaining chain is B.
    let r = invalidate(&n, a[1].block_hash()).expect("invalidateblock");
    assert_eq!((r.tip, r.rolled_back, r.connected), (b_tip, 6, 4));
    assert_eq!(sel_tip(&n), Some(b_tip));
    assert_eq!(tip_meta(&n), b_tip);
    assert_eq!(digest(&n), digest(&only_b));
    assert!(n.dag.read().is_invalid(&a_tip), "selected-chain descendants are disqualified too");
    assert_eq!(n.store.invalid_block_reason(&a[1].block_hash()).unwrap().as_deref(),
        Some(accept::OPERATOR_INVALIDATE_REASON));

    // A new block on A is disqualified on arrival (its selected parent is).
    let a7 = b.empty(vec![a_tip], "ia7");
    assert!(accept(&n, &a7).is_err());
    assert_eq!(tip_meta(&n), b_tip);

    // Persisted: a restart keeps the node on B.
    restart(&mut n);
    assert_eq!(sel_tip(&n), Some(b_tip));
    assert_eq!(tip_meta(&n), b_tip);

    // Reconsider: back to the heaviest chain (now A + a7).
    let r = reconsider(&n, a[1].block_hash()).expect("reconsiderblock");
    assert_eq!(r.tip, a7.block_hash());
    assert_eq!(tip_meta(&n), a7.block_hash());
    deliver(&only_a, std::slice::from_ref(&a7));
    assert_eq!(digest(&n), digest(&only_a));
    assert!(n.store.invalid_block_reason(&a[1].block_hash()).unwrap().is_none());
    restart(&mut n);
    assert_eq!(tip_meta(&n), a7.block_hash());

    // Invalidating the applied tip itself is a pure rollback to its parent.
    let r = invalidate(&n, a7.block_hash()).expect("invalidate the tip");
    assert_eq!((r.tip, r.rolled_back, r.connected), (a_tip, 1, 0));
    assert_eq!(tip_meta(&n), a_tip);
    let only_a6 = node_with(&genesis, std::slice::from_ref(&fund));
    deliver(&only_a6, &a);
    assert_eq!(digest(&n), digest(&only_a6));
    let r = reconsider(&n, a7.block_hash()).expect("reconsider the tip");
    assert_eq!((r.tip, r.rolled_back, r.connected), (a7.block_hash(), 0, 1));

    // Invalidate a6: two blocks are rolled back to a5 (still heavier than
    // B). Reconsidering the DESCENDANT a7 clears the mark of its selected-
    // chain ancestor a6, as Bitcoin Core's reconsiderblock does.
    let r = invalidate(&n, a_tip).expect("invalidate a6");
    assert_eq!((r.tip, r.rolled_back, r.connected), (a[4].block_hash(), 2, 0));
    let r = reconsider(&n, a7.block_hash()).expect("reconsider a descendant");
    assert_eq!(r.tip, a7.block_hash());
    assert_eq!(n.dag.read().invalid_count(), 0);
    assert!(n.store.load_invalid_blocks().unwrap().is_empty());
    assert_eq!(digest(&n), digest(&only_a));
}

// ═════════════════════════════════════════════════════════════════════════════
// DAG-11 residual: interrupted pre-fix commit → detect, rebuild
// ═════════════════════════════════════════════════════════════════════════════

/// The write prefix of the PRE-FIX extension commit (`put_block`, then
/// `apply_block_utxo_mutations` one write at a time: per tx `tx_index`,
/// outputs, coinbase row or input deletions; undo record last) cut after
/// `writes` mutations of the transaction loop: the state a crash leaves.
fn pre_fix_partial_apply(store: &gnb::storage::Storage, blk: &Block, writes: usize) {
    store.put_block(blk).unwrap();
    let h = blk.block_hash();
    let mut left = writes;
    let mut step = |f: &mut dyn FnMut()| {
        if left > 0 {
            f();
            left -= 1;
        }
    };
    for tx in &blk.transactions {
        let txid = tx.txid();
        step(&mut || store.put_tx_index(&txid, &h, blk.height).unwrap());
        for (j, o) in tx.outputs.iter().enumerate() {
            step(&mut || store.put_utxo(&txid, j as u32, o).unwrap());
        }
        if tx.is_coinbase() {
            step(&mut || store.put_coinbase_info(&txid, blk.height).unwrap());
        } else {
            for inp in &tx.inputs {
                step(&mut || store.delete_utxo(&inp.prev_txid, inp.prev_index).unwrap());
            }
        }
    }
}

fn fixture_seed(utxos: Vec<([u8; 32], u32, TxOutput)>)
    -> impl Fn(&gnb::storage::Storage, &mut rocksdb::WriteBatch) -> Result<(), String>
{
    move |st: &gnb::storage::Storage, batch: &mut rocksdb::WriteBatch| {
        for (t, i, o) in &utxos {
            st.stage_utxo(batch, t, *i, o).map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

/// A crash in the middle of the pre-fix, non-atomic extension commit (no undo
/// record, no DAG record, the block's input already deleted) is invisible to
/// `reconcile_on_startup`'s undo-record scan. It is now detected
/// (`check_chain_state`), reconciliation refuses to build on it, and the chain
/// state is rebuilt from the block bodies to exactly the UTXO set of a node
/// that never crashed; the interrupted block is then accepted normally
/// (pre-fix it was rejected forever: its input read as spent).
#[test]
fn dag11_interrupted_pre_fix_commit_is_detected_and_rebuilt() {
    let genesis = mk_genesis(unix_now() - 50_000);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0x65u8; 32], 0u32, out(5_000_000, &k.spk));
    let fund2 = ([0x66u8; 32], 0u32, out(3_000_000, &k.spk));
    let utxos = vec![fund.clone(), fund2.clone()];
    let mut b = Builder::new(&genesis);

    let pay1 = signed_spend(&k, &[(fund.0, fund.1)], vec![out(4_900_000, &[0xF1; 20])]);
    let c1 = b.with_txs(vec![gh], "c1", 100_000, vec![pay1]);
    let mut chain = vec![c1.clone()];
    chain.extend(b.chain(c1.block_hash(), 4, "c"));
    let pay2 = signed_spend(&k, &[(fund2.0, fund2.1)], vec![out(2_900_000, &[0xF2; 20])]);
    let x = b.with_txs(vec![chain.last().unwrap().block_hash()], "x", 100_000, vec![pay2.clone()]);

    let mut n = node_with(&genesis, &utxos);
    deliver(&n, &chain);
    let clean = node_with(&genesis, &utxos);
    deliver(&clean, &chain);
    assert_eq!(digest(&n), digest(&clean));

    // Crash mid-apply of x: coinbase fully applied, pay2's tx_index row and
    // output written, its input (fund2) deleted; no undo, no DAG record.
    pre_fix_partial_apply(&n.store, &x, 6);
    assert!(n.store.get_utxo(&fund2.0, 0).unwrap().is_none(), "crash state: input deleted");
    assert_ne!(digest(&n), digest(&clean));

    reload(&mut n);
    let faults = accept::check_chain_state(&n.dag, &n.store).unwrap();
    assert_eq!(faults, vec![accept::ChainStateFault::UnrecordedEffects { block: x.block_hash(), rows: 2 }]);
    let err = accept::reconcile_on_startup(&n.dag, &n.store, &n.shielded).unwrap_err();
    assert!(err.contains("inconsistent"), "{err}");

    let report = accept::rebuild_chain_state(&n.dag, &n.store, &n.shielded, &fixture_seed(utxos.clone()))
        .expect("rebuild");
    assert_eq!(report.connected_blocks, chain.len());
    assert!(accept::check_chain_state(&n.dag, &n.store).unwrap().is_empty());
    assert_eq!(digest(&n), digest(&clean), "rebuilt UTXO set == never-crashed node's");
    assert_eq!(tip_meta(&n), chain.last().unwrap().block_hash());
    accept::reconcile_on_startup(&n.dag, &n.store, &n.shielded).expect("reconcile after rebuild");

    accept(&n, &x).expect("the interrupted block is accepted normally after the rebuild");
    accept(&clean, &x).unwrap();
    assert_eq!(digest(&n), digest(&clean));
    assert!(n.store.get_utxo(&pay2.txid(), 0).unwrap().is_some());
}

/// The pre-fix error path: a write error inside the apply was only logged,
/// and the tip pointer and DAG record were written anyway — the block sits on
/// the applied chain without an undo record. Detected and rebuilt; an
/// interrupted rebuild is detected on the next start; a pruned node cannot
/// rebuild and says so.
#[test]
fn dag11_applied_without_undo_and_interrupted_rebuild_are_detected() {
    let genesis = mk_genesis(unix_now() - 50_000);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0x67u8; 32], 0u32, out(5_000_000, &k.spk));
    let utxos = vec![fund.clone()];
    let mut b = Builder::new(&genesis);
    let pay = signed_spend(&k, &[(fund.0, fund.1)], vec![out(4_900_000, &[0xF3; 20])]);
    let d1 = b.with_txs(vec![gh], "d1", 100_000, vec![pay]);
    let mut chain = vec![d1.clone()];
    chain.extend(b.chain(d1.block_hash(), 4, "d"));

    let mut n = node_with(&genesis, &utxos);
    deliver(&n, &chain);
    let clean = node_with(&genesis, &utxos);
    deliver(&clean, &chain);
    let lost = chain[2].block_hash();
    n.store.delete_undo_data(&lost).unwrap();

    reload(&mut n);
    let faults = accept::check_chain_state(&n.dag, &n.store).unwrap();
    assert!(faults.contains(&accept::ChainStateFault::AppliedWithoutUndo { block: lost }), "{faults:?}");
    assert!(faults.contains(&accept::ChainStateFault::UnrecordedEffects { block: lost, rows: 1 }), "{faults:?}");

    // An interrupted rebuild leaves its flag: reported on the next start.
    n.store.put_meta(accept::REBUILD_PENDING_META, &[1u8]).unwrap();
    assert!(accept::check_chain_state(&n.dag, &n.store).unwrap()
        .contains(&accept::ChainStateFault::RebuildInterrupted));

    accept::rebuild_chain_state(&n.dag, &n.store, &n.shielded, &fixture_seed(utxos.clone())).unwrap();
    assert!(accept::check_chain_state(&n.dag, &n.store).unwrap().is_empty());
    assert_eq!(digest(&n), digest(&clean));
    restart(&mut n);
    assert_eq!(digest(&n), digest(&clean));

    // A pruned node cannot rebuild from bodies: it refuses, untouched.
    n.store.prune_blocks_below(3).unwrap();
    let before = digest(&n);
    let err = accept::rebuild_chain_state(&n.dag, &n.store, &n.shielded, &fixture_seed(utxos)).unwrap_err();
    assert!(err.contains("pruned"), "{err}");
    assert_eq!(digest(&n), before, "a refused rebuild changes nothing");
}

// ═════════════════════════════════════════════════════════════════════════════
// POW-3 (node-local anti-DoS half): the work rule of the ingress core
// ═════════════════════════════════════════════════════════════════════════════
//
// These drive `gnb::ingress::BlockIngress::handle_block`, the same core the
// node's message processor (main.rs, NewBlock arm) calls for every gossiped
// or pulled block, with a simulated network: a Buffered outcome's parent
// requests are answered next, and an announced tip is re-announced when the
// pipeline stalls (the node's 30 s GetTips nudge).

use gnb::ingress::{self, BlockIngress, BlockOutcome, DropReason, OrphanLimits, WorkAdmission};

fn ctx(n: &Node) -> ingress::AcceptCtx<'_> {
    ingress::AcceptCtx {
        dag: &n.dag, store: &n.store, mempool: &n.mempool, node_state: &n.node_state,
        tip_tx: Some(&n.tip_tx), shielded: &n.shielded,
    }
}

fn feed(core: &mut BlockIngress, n: &Node, b: &Block) -> BlockOutcome {
    core.handle_block(b.clone(), b.block_hash(), b.to_wire_bytes().len(), None,
        std::time::Instant::now(), unix_now(), &ctx(n))
}

/// (a) A flood of low-work blocks forking deep below the tip (siblings of
/// deep blocks, genesis siblings, and orphan chains built on them) is refused
/// before any proof-of-work evaluation, storage or DAG insertion — cheaply —
/// while the same blocks were inserted before (the old height guard only
/// covered blocks more than 1,000 below the tip). Orphan chains on top stay
/// in the bounded pool and, carrying too little work, never make their base
/// acceptable.
#[test]
fn pow3_low_work_flood_is_refused_before_pow_storage_or_insertion() {
    let genesis = mk_genesis(unix_now() - 50_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let honest = b.chain(gh, 800, "lw");
    let x = node_with(&genesis, &[]);
    for blk in &honest {
        accept(&x, blk).unwrap();
    }
    let threshold = ingress::anti_dos_work_threshold(&x.dag.read());
    assert_eq!(threshold, 440 * core::bits_to_work(core::POW_LIMIT_BITS),
        "the work of the selected-chain block 360 below the tip");
    let count_before = x.dag.read().block_count();
    let digest_before = digest(&x);

    // 1,500 connectable flood blocks: children of blocks at heights 0..400.
    let mut rng = Rng(0x0F00_D000_0000_0003);
    let mut flood = Vec::new();
    for i in 0..1_500 {
        let parent = if i % 5 == 0 { gh } else { honest[rng.below(400)].block_hash() };
        flood.push(b.empty(vec![parent], &format!("flood{i}")));
    }
    let mut core = BlockIngress::with_limits(OrphanLimits {
        max_entries: 200, max_bytes: 64 << 20, max_entries_per_peer: 200, max_bytes_per_peer: 64 << 20,
    });
    let t = std::time::Instant::now();
    for blk in &flood {
        assert!(matches!(feed(&mut core, &x, blk), BlockOutcome::Dropped(DropReason::LowWork)));
    }
    let refused = t.elapsed();
    assert_eq!(x.dag.read().block_count(), count_before, "nothing inserted");
    assert!(flood.iter().all(|blk| x.store.get_block(&blk.block_hash()).unwrap().is_none()), "nothing stored");
    assert_eq!(digest(&x), digest_before);

    // An orphan chain of 300 blocks on top of a refused genesis sibling:
    // buffered (the pool stays bounded), and 1 + 300 blocks of work still do
    // not reach the threshold (440), so the base stays refused.
    let base = flood[0].clone();
    assert_eq!(base.header.parents, vec![gh]);
    let mut chain_on_base = b.chain(base.block_hash(), 300, "flood-chain");
    chain_on_base.reverse(); // tip first, as a backward fetch delivers them
    for blk in &chain_on_base {
        let out = feed(&mut core, &x, blk);
        assert!(matches!(out, BlockOutcome::Buffered { .. }), "{out:?}");
        assert!(core.orphans.len() <= 200, "the pool stays bounded");
    }
    assert!(matches!(feed(&mut core, &x, &base), BlockOutcome::Dropped(DropReason::LowWork)));
    assert_eq!(x.dag.read().block_count(), count_before);

    // Before: the same blocks went straight into accept_block.
    let y = node_with(&genesis, &[]);
    for blk in &honest {
        accept(&y, blk).unwrap();
    }
    let t = std::time::Instant::now();
    for blk in &flood[..100] {
        accept(&y, blk).expect("pre-fix: a low-work fork block was stored and inserted");
    }
    let inserted = t.elapsed();
    let per_refusal = refused / flood.len() as u32;
    let per_insertion = inserted / 100;
    println!("POW-3 flood: {} refusals in {:.2?} ({:.2?} each, no PoW/storage/insertion); \
              pre-fix insertion {:.2?} each (without the 64 MiB proof evaluation a real node also paid)",
        flood.len(), refused, per_refusal, per_insertion);
    assert!(per_refusal < per_insertion, "refusing must be cheaper than inserting");
}

/// Simulated network: deliver `want_tip` (the fork tip, as a frontier tip),
/// answer every parent request at once, and re-announce the tip whenever the
/// pipeline stalls, until `n` selects `want_tip`. Returns the admissions of
/// processed blocks, the drops and the number of announcements.
#[allow(clippy::type_complexity)]
fn sync_tip_first(
    core: &mut BlockIngress,
    n: &Node,
    by_hash: &HashMap<BlockHash, Block>,
    want_tip: BlockHash,
) -> (Vec<(BlockHash, WorkAdmission)>, Vec<(BlockHash, DropReason)>, usize) {
    let mut admissions = Vec::new();
    let mut drops = Vec::new();
    let mut queue: std::collections::VecDeque<BlockHash> = std::collections::VecDeque::new();
    let mut rounds = 0usize;
    let mut deliveries = 0usize;
    while sel_tip(n) != Some(want_tip) {
        let Some(h) = queue.pop_front() else {
            rounds += 1;
            assert!(rounds <= 50, "the fork must be followed in a bounded number of re-announcements");
            queue.push_back(want_tip);
            continue;
        };
        deliveries += 1;
        assert!(deliveries < 100_000);
        let blk = &by_hash[&h];
        match feed(core, n, blk) {
            BlockOutcome::Buffered { request, .. } => {
                for p in request.into_iter().rev() {
                    queue.push_front(p);
                }
            }
            BlockOutcome::Processed { admission, result, .. } => {
                result.expect("fork block accepted");
                admissions.push((h, admission));
            }
            BlockOutcome::Dropped(r) => drops.push((h, r)),
            BlockOutcome::Known | BlockOutcome::PoolRefused | BlockOutcome::BodyRestored => {}
            BlockOutcome::Invalid(e) => panic!("invalid: {e}"),
        }
    }
    (admissions, drops, rounds)
}

/// (b) A heavier honest fork that branches deep (1,150 blocks below a
/// 1,200-block tip, so its first ~150 blocks are more than 1,000 below the
/// tip) is followed when it is fetched the way a node fetches it — tip first,
/// parent by parent — through an orphan pool much smaller than the fork. Its
/// work is proven by the announced orphan chain (remembered across
/// evictions), so its deep blocks are admitted as chain-backed, without the
/// deep-insertion budget that used to throttle them to one per 30 s, and the
/// node ends on the fork with exactly the UTXO set of a node that received
/// it in order.
#[test]
fn pow3_heavier_fork_branching_deep_is_followed_tip_first() {
    let genesis = mk_genesis(unix_now() - 50_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let honest = b.chain(gh, 1_200, "hb");
    let fork = b.chain(honest[49].block_hash(), 1_200, "fb"); // tip at height 1,250
    let fork_tip = fork.last().unwrap().block_hash();
    let by_hash: HashMap<BlockHash, Block> = fork.iter().map(|x| (x.block_hash(), x.clone())).collect();

    let x = node_with(&genesis, &[]);
    for blk in &honest {
        accept(&x, blk).unwrap();
    }
    let mut core = BlockIngress::with_limits(OrphanLimits {
        max_entries: 400, max_bytes: 64 << 20, max_entries_per_peer: 400, max_bytes_per_peer: 64 << 20,
    });
    let (admissions, drops, rounds) = sync_tip_first(&mut core, &x, &by_hash, fork_tip);
    println!("POW-3 deep fork: followed after {} announcement(s); {} admissions; drops {:?}",
        rounds, admissions.len(), drops);
    assert!(drops.is_empty(), "no fork block was refused: {drops:?}");
    let first = admissions.iter().find(|(h, _)| *h == fork[0].block_hash()).expect("first fork block");
    assert_eq!(first.1, WorkAdmission::ChainBacked, "deep, low own work, backed by the announced chain");
    assert!(rounds > 1, "the fork is longer than the pool: remembered work carried it across rounds");
    assert_eq!(tip_meta(&x), fork_tip);

    let w = node_with(&genesis, &[]);
    for blk in &honest[..50] {
        accept(&w, blk).unwrap();
    }
    for blk in &fork {
        accept(&w, blk).unwrap();
    }
    assert_eq!(digest(&x), digest(&w));
}

/// Coordination with the existing deep-insertion budget (DAG-7): a deep
/// low-work block that is needed only because a buffered orphan MERGES it
/// (the orphan's own work comes from its other parent) is admitted as
/// merge-backed, and such deep admissions are rationed by
/// `DeepBackfillBudget` — the crafted-orphan bypass of the audit costs one
/// real orphan per insertion and is cut off after the burst.
#[test]
fn pow3_merge_backed_deep_blocks_are_rationed() {
    let genesis = mk_genesis(unix_now() - 50_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let honest = b.chain(gh, 1_100, "mb");
    let x = node_with(&genesis, &[]);
    for blk in &honest {
        accept(&x, blk).unwrap();
    }
    let mut core = BlockIngress::new();
    let mut tip = honest.last().unwrap().block_hash();
    let mut admitted = 0;
    for i in 0..(ingress::DEEP_BACKFILL_BURST as usize + 1) {
        let deep = b.empty(vec![honest[10 + i].block_hash()], &format!("deep{i}"));
        assert!(matches!(feed(&mut core, &x, &deep), BlockOutcome::Dropped(DropReason::LowWork)),
            "alone it is refused");
        let merger = b.empty(vec![tip, deep.block_hash()], &format!("merger{i}"));
        assert!(matches!(feed(&mut core, &x, &merger), BlockOutcome::Buffered { .. }));
        match feed(&mut core, &x, &deep) {
            BlockOutcome::Processed { admission, result, drained, .. } => {
                assert_eq!(admission, WorkAdmission::MergeBacked);
                result.expect("deep block stored as a fork-loser");
                assert_eq!(drained, vec![merger.block_hash()]);
                tip = merger.block_hash();
                admitted += 1;
            }
            BlockOutcome::Dropped(DropReason::DeepBudgetExhausted) => {
                assert_eq!(admitted, ingress::DEEP_BACKFILL_BURST as usize, "only after the burst");
            }
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(admitted, ingress::DEEP_BACKFILL_BURST as usize);
    assert_eq!(tip_meta(&x), tip);
}
