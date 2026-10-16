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
        // The coinbase commitment and Merkle root of the block's height
        // (hardening block rules at/after the activation, package P1).
        commit_block(&mut b);
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
    // As main() does: reload the persisted shielded state (audit COH-2).
    n.shielded = Arc::new(RwLock::new(gnb::coherence::ShieldedPool::load(&n.store).expect("shielded state loads")));
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
    // blocks whose bodies it pruned. The block that makes the honest chain
    // the heaviest is accepted, and the bodies its chain lacks wait for one
    // (nothing is written meanwhile; X stays on the fork); the ingress core
    // names exactly the bodies to fetch, stores each copy after the checks a
    // new block gets, and the chain is connected once the last one is back —
    // with the UTXO set of a node that never left it.
    let more = b.chain(honest.last().unwrap().block_hash(), 4, "ph-more"); // 64 > 62
    let mut core = BlockIngress::new();
    let mut refetched = 0;
    for blk in &more {
        match feed(&mut core, &x, blk) {
            BlockOutcome::Processed { result: Ok(_), missing_bodies, .. } => {
                for h in missing_bodies {
                    assert!(accept::awaits_body(&x.dag, &x.store, &h), "a wanted body");
                    let body = honest.iter().find(|x| x.block_hash() == h).expect("a pruned honest block");
                    assert!(matches!(feed(&mut core, &x, body), BlockOutcome::BodyRestored));
                    refetched += 1;
                }
            }
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(refetched, 39, "the 39 pruned honest bodies (genesis is never re-applied)");
    assert_eq!(tip_meta(&x), more.last().unwrap().block_hash());
    let v = node_with(&genesis, std::slice::from_ref(&fund));
    deliver(&v, &honest);
    deliver(&v, &more);
    assert_eq!(digest(&x), digest(&v), "back on the honest chain with its exact UTXO set");
}

/// A pruned node that reorganized away from bodies it had pruned: node X
/// followed chain A (60 blocks, `a1` pays `fund`), pruned the bodies below
/// height 40, then reorganized to the heavier fork B (62 blocks). A's pruned
/// blocks are in X's DAG without bodies and unapplied (no undo record).
struct PrunedReorged {
    genesis: Block,
    fund:    ([u8; 32], u32, TxOutput),
    b:       Builder,
    honest:  Vec<Block>,
    fork:    Vec<Block>,
    x:       Node,
}

fn pruned_then_reorged(tag: &str, fund_byte: u8) -> PrunedReorged {
    let genesis = mk_genesis(unix_now() - 50_000);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([fund_byte; 32], 0u32, out(5_000_000, &k.spk));
    let mut b = Builder::new(&genesis);
    let pay = signed_spend(&k, &[(fund.0, fund.1)], vec![out(4_900_000, &[fund_byte; 20])]);
    let h1 = b.with_txs(vec![gh], &format!("{tag}a1"), 100_000, vec![pay]);
    let mut honest = vec![h1.clone()];
    honest.extend(b.chain(h1.block_hash(), 59, &format!("{tag}a")));
    let fork = b.chain(gh, 62, &format!("{tag}b"));
    let x = node_with(&genesis, std::slice::from_ref(&fund));
    deliver(&x, &honest);
    assert_eq!(x.store.prune_blocks_below(40).unwrap(), 40);
    deliver(&x, &fork);
    assert_eq!(tip_meta(&x), fork.last().unwrap().block_hash());
    PrunedReorged { genesis, fund, b, honest, fork, x }
}

/// Audit DAG-6 follow-up (review): a re-fetched body used to be stored with
/// whatever `height` the peer put on the wire — the block id commits neither
/// `height` nor `blue_score`. One forged copy (height 0) of a pruned block
/// was stored, made the next connect fail ("coinbase rejected": the subsidy
/// at height 0 is 0), disqualified the heavier chain persistently, and the
/// honest body was ignored ever after: the node stayed on the lighter chain.
/// Now a wanted body goes through `accept_block`'s body-replacement path: it
/// must carry the header height its DAG parents imply (the height the block
/// was accepted at) and pass every other acceptance check, and it is stored
/// byte for byte as `accept_block` stores a block (derived `blue_score`).
#[test]
fn dag6_restored_body_is_bound_to_the_dag_height() {
    let mut f = pruned_then_reorged("rh", 0x71);
    let more = f.b.chain(f.honest.last().unwrap().block_hash(), 4, "rh-more"); // A: 64 > 62
    let mut core = BlockIngress::new();
    // A grows past B: the first block that makes it the heaviest is accepted,
    // but its chain cannot be connected yet; the pruned bodies it needs wait
    // for one and are named for the caller to request.
    let mut trigger = 0;
    let missing = loop {
        match feed(&mut core, &f.x, &more[trigger]) {
            BlockOutcome::Processed { result: Ok(_), missing_bodies, .. } => {
                trigger += 1;
                if !missing_bodies.is_empty() {
                    break missing_bodies;
                }
            }
            other => panic!("{other:?}"),
        }
    };
    assert_eq!(missing.len(), 39, "A's pruned bodies above genesis");
    assert_eq!(tip_meta(&f.x), f.fork.last().unwrap().block_hash(), "still on B meanwhile");
    let a10 = f.honest[9].clone();
    assert!(missing.contains(&a10.block_hash()));

    // The answer carries the real header and transactions, but height 0.
    let mut forged = a10.clone();
    forged.height = 0;
    assert_eq!(forged.block_hash(), a10.block_hash(), "the id does not commit the height");
    match feed(&mut core, &f.x, &forged) {
        BlockOutcome::Invalid(e) => assert!(e.contains("invalid height") && e.contains("expected h=10"), "{e}"),
        other => panic!("a body with a forged height must be refused: {other:?}"),
    }
    assert!(accept::awaits_body(&f.x.dag, &f.x.store, &a10.block_hash()), "still wanted");
    assert!(!f.x.store.has_block_body(&a10.block_hash()).unwrap(), "nothing stored");
    // A wrong wire blue_score is replaced as on acceptance.
    let mut odd = a10.clone();
    odd.blue_score = u64::MAX;
    assert!(matches!(feed(&mut core, &f.x, &odd), BlockOutcome::BodyRestored));
    let v = node_with(&f.genesis, std::slice::from_ref(&f.fund));
    deliver(&v, &f.honest);
    deliver(&v, &more);
    assert_eq!(
        f.x.store.get_block(&a10.block_hash()).unwrap().unwrap().to_wire_bytes(),
        v.store.get_block(&a10.block_hash()).unwrap().unwrap().to_wire_bytes(),
        "the restored body is exactly the body accept_block stores",
    );

    // The other bodies arrive honestly; the heavier chain is followed as soon
    // as the last one is back.
    for h in &missing {
        if *h == a10.block_hash() {
            continue;
        }
        let body = f.honest.iter().find(|x| x.block_hash() == *h).unwrap();
        assert!(matches!(feed(&mut core, &f.x, body), BlockOutcome::BodyRestored));
    }
    assert_eq!(tip_meta(&f.x), more[trigger - 1].block_hash(), "connected without a re-announcement");
    for blk in &more[trigger..] {
        match feed(&mut core, &f.x, blk) {
            BlockOutcome::Processed { result: Ok(_), .. } => {}
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(tip_meta(&f.x), more.last().unwrap().block_hash());
    assert_eq!(f.x.dag.read().invalid_count(), 0, "nothing was disqualified");
    assert_eq!(digest(&f.x), digest(&v));
}

/// Audit DAG-6 follow-up (review): any peer could push the body of any
/// pruned block, and each one cost a full 64 MiB proof evaluation plus a disk
/// write, without penalty and outside the work rule (before the re-fetch
/// change, a block in the DAG was simply ignored). Now a body is restored
/// only if this node requested it, only from a directed answer, and never
/// for an applied block (rollbacks use undo data): everything else is
/// `Known` before any check. Shown with a TAMPERED copy (its transactions do
/// not match the header's merkle root): had any validation run, it would be
/// `Invalid`; it is `Known`, so neither the structure check nor the proof of
/// work (which comes after it) ran.
#[test]
fn dag6_unrequested_old_bodies_are_known_without_any_work() {
    let f = pruned_then_reorged("ur", 0x72);
    // Also prune the applied chain B below 30: those bodies are pruned and
    // APPLIED (undo records).
    f.x.store.prune_blocks_below(30).unwrap();
    let b10 = f.fork[9].clone();
    let a10 = f.honest[9].clone();
    assert!(!f.x.store.has_block_body(&b10.block_hash()).unwrap());
    assert!(!f.x.store.has_block_body(&a10.block_hash()).unwrap());
    let tamper = |blk: &Block| {
        let mut t = blk.clone();
        t.transactions[0].outputs[0].value += 1;
        assert_eq!(t.block_hash(), blk.block_hash());
        assert!(t.validate_structure_without_pow().is_err(), "the tampered copy fails the first check");
        t
    };
    let mut core = BlockIngress::new();
    let len = |b: &Block| b.to_wire_bytes().len();
    for blk in [&b10, &a10] {
        let t = tamper(blk);
        // Pushed by gossip, or answered without a request: Known, no work.
        for (copy, solicited) in [(blk, false), (blk, true), (&t, false), (&t, true)] {
            assert!(matches!(feed_as(&mut core, &f.x, copy, None, solicited, len(copy)), BlockOutcome::Known));
        }
        assert!(!f.x.store.has_block_body(&blk.block_hash()).unwrap(), "not stored");
    }
    // Requested, but an applied block's body is never needed: the request is
    // refused (`accept::request_bodies`) and a copy is Known.
    assert!(accept::request_bodies(&f.x.dag, &f.x.store, &[b10.block_hash()]).is_empty());
    assert!(matches!(feed(&mut core, &f.x, &tamper(&b10)), BlockOutcome::Known));
    assert!(!accept::awaits_body(&f.x.dag, &f.x.store, &b10.block_hash()), "not wanted");
    assert!(!f.x.store.has_block_body(&b10.block_hash()).unwrap());
    // Requested and unapplied: a gossiped copy still does nothing; the
    // directed answer is checked (the tampered one is invalid) and restored.
    assert_eq!(accept::request_bodies(&f.x.dag, &f.x.store, &[a10.block_hash()]), vec![a10.block_hash()]);
    assert!(accept::awaits_body(&f.x.dag, &f.x.store, &a10.block_hash()));
    assert!(matches!(feed_as(&mut core, &f.x, &a10, None, false, len(&a10)), BlockOutcome::Known));
    assert!(matches!(feed(&mut core, &f.x, &tamper(&a10)), BlockOutcome::Invalid(_)));
    assert!(matches!(feed(&mut core, &f.x, &a10), BlockOutcome::BodyRestored));
    assert!(f.x.store.has_block_body(&a10.block_hash()).unwrap());
    assert!(matches!(feed(&mut core, &f.x, &a10), BlockOutcome::Known), "once only");
}

// ═════════════════════════════════════════════════════════════════════════════
// DAG-6: operator recovery — invalidateblock / reconsiderblock
// ═════════════════════════════════════════════════════════════════════════════

fn invalidate(n: &Node, h: BlockHash) -> Result<accept::ChainOverride, accept::OverrideError> {
    accept::invalidate_block(h, &n.dag, &n.store, &n.mempool, &n.node_state, Some(&n.tip_tx), &n.shielded)
}

fn reconsider(n: &Node, h: BlockHash) -> Result<accept::ChainOverride, accept::OverrideError> {
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
    assert!(invalidate(&n, [0x99; 32]).unwrap_err().to_string().contains("not found"));
    assert!(invalidate(&n, gh).unwrap_err().to_string().contains("genesis"));

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

/// Audit DAG-6 follow-up (review): on a pruned node, `invalidateblock` /
/// `reconsiderblock` could never move to a chain whose bodies were pruned —
/// the connect failed on the missing bodies and nothing ever requested them.
/// Now the call changes nothing (marks restored, nothing committed, the
/// applied tip stays the DAG's selected tip) and names the bodies to
/// re-fetch; main.rs records and pulls them, the ingress core restores them,
/// and the retried call succeeds — with the UTXO set of a node that only saw
/// the chain it ends on. The same holds for `reconsiderblock` after a
/// rollback through pruned bodies.
#[test]
fn dag6_operator_overrides_on_a_pruned_node_refetch_bodies_and_retry() {
    let f = pruned_then_reorged("op", 0x73);
    let b1 = f.fork[0].block_hash();
    let a_tip = f.honest.last().unwrap().block_hash();
    let b_tip = f.fork.last().unwrap().block_hash();
    let only_a = node_with(&f.genesis, std::slice::from_ref(&f.fund));
    deliver(&only_a, &f.honest);
    let only_b = node_with(&f.genesis, std::slice::from_ref(&f.fund));
    deliver(&only_b, &f.fork);
    let before = digest(&f.x);
    assert_eq!(before, digest(&only_b));

    let restore = |core: &mut BlockIngress, n: &Node, missing: &[BlockHash], from: &[Block]| {
        // The override made the bodies wait for one (`accept::request_bodies`,
        // the record the processor requests from); main.rs wakes the
        // processor, which pulls them, and the answers arrive here.
        for h in missing {
            assert!(accept::awaits_body(&n.dag, &n.store, h), "requested by the override");
        }
        for h in missing {
            let body = from.iter().find(|x| x.block_hash() == *h).expect("a pruned block");
            assert!(matches!(feed(core, n, body), BlockOutcome::BodyRestored));
        }
    };
    let mut core = BlockIngress::new();

    // invalidateblock B1: the best remaining chain is A, whose bodies below
    // 40 were pruned.
    let missing = match invalidate(&f.x, b1) {
        Err(accept::OverrideError::MissingBodies { missing, reason }) => {
            assert!(reason.contains(gnb::reorg::ERR_MISSING_BODIES), "{reason}");
            missing
        }
        other => panic!("{other:?}"),
    };
    assert_eq!(missing.len(), 39, "A's pruned bodies above genesis, nearest the new tip first");
    assert_eq!(missing[0], f.honest[38].block_hash());
    // Nothing changed.
    assert_eq!((sel_tip(&f.x), tip_meta(&f.x)), (Some(b_tip), b_tip));
    assert_eq!(digest(&f.x), before);
    assert!(!f.x.dag.read().is_invalid(&b1));
    assert!(f.x.store.load_invalid_blocks().unwrap().is_empty());
    restore(&mut core, &f.x, &missing, &f.honest);
    let r = invalidate(&f.x, b1).expect("the retried invalidateblock succeeds");
    assert_eq!((r.tip, r.rolled_back, r.connected), (a_tip, 62, 60));
    assert_eq!(tip_meta(&f.x), a_tip);
    assert_eq!(digest(&f.x), digest(&only_a));
    // And back: B's bodies are all there.
    let r = reconsider(&f.x, b1).expect("reconsiderblock");
    assert_eq!(r.tip, b_tip);
    assert_eq!(digest(&f.x), digest(&only_b));

    // reconsiderblock after a deep invalidateblock on a pruned chain: the
    // rollback only needs undo data; going back needs the pruned bodies.
    let y = node_with(&f.genesis, std::slice::from_ref(&f.fund));
    deliver(&y, &f.honest);
    y.store.prune_blocks_below(40).unwrap();
    let a5 = f.honest[4].block_hash();
    let r = invalidate(&y, a5).expect("a rollback through pruned bodies");
    assert_eq!(r.tip, f.honest[3].block_hash());
    let missing = match reconsider(&y, a5) {
        Err(accept::OverrideError::MissingBodies { missing, .. }) => missing,
        other => panic!("{other:?}"),
    };
    assert_eq!(missing.len(), 35, "a5..a39");
    assert!(y.store.invalid_block_reason(&a5).unwrap().is_some(), "the mark is kept until it succeeds");
    let mut core_y = BlockIngress::new();
    restore(&mut core_y, &y, &missing, &f.honest);
    let r = reconsider(&y, a5).expect("the retried reconsiderblock succeeds");
    assert_eq!(r.tip, a_tip);
    assert!(y.store.load_invalid_blocks().unwrap().is_empty());
    assert_eq!(digest(&y), digest(&only_a));
}

/// Merge P1 x P3 x P4: a block whose body was rejected for a reason that
/// depends on witness bytes its id does not commit to (below the hardening
/// activation) and a pruned body needed again are ONE state — "a body of
/// this DAG block is wanted" (`accept::awaits_body`) — fetched through one
/// request path and accepted through one path. Through the ingress core: the
/// corrupted copy is processed and leaves the block waiting (named in
/// `missing_bodies` for the caller to request); a gossiped copy of the block
/// is known (only the answer to the node's own pull is taken); the same
/// corrupted body re-sent as an answer is refused by the rejected-witness-root
/// memo; the honest answer is stored through `accept_block`'s replacement path
/// and connects the block, and the applied-chain move is reported for the
/// orphan-transaction bookkeeping (`take_chain_move`).
#[test]
fn merge_witness_rejected_body_is_refetched_through_the_ingress_core() {
    let genesis = mk_genesis(unix_now() - 50_000);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0x69u8; 32], 0u32, out(5_000_000, &k.spk));
    let mut b = Builder::new(&genesis);
    let pay = signed_spend(&k, &[(fund.0, fund.1)], vec![out(4_900_000, &[0xB7; 20])]);
    let honest = b.with_txs(vec![gh], "w1", 100_000, vec![pay.clone()]);
    let id = honest.block_hash();
    let mut bad = honest.clone();
    bad.transactions[1].inputs[0].script_sig[100] ^= 0x01;
    assert_eq!(bad.block_hash(), id, "same id: the witness is not committed below the activation");

    let n = node_with(&genesis, std::slice::from_ref(&fund));
    let mut core = BlockIngress::new();
    match feed_as(&mut core, &n, &bad, None, false, bad.to_wire_bytes().len()) {
        BlockOutcome::Processed { result: Err(e), missing_bodies, .. } => {
            assert!(e.contains("body rejected"), "{e}");
            assert_eq!(missing_bodies, vec![id], "the block now waits for a body: request it");
        }
        other => panic!("{other:?}"),
    }
    assert!(accept::awaits_body(&n.dag, &n.store, &id));
    assert!(core.take_chain_move().is_empty(), "nothing was applied");
    assert_eq!(tip_meta(&n), gh);
    // Only the answer to the node's own pull is taken as a body.
    assert!(matches!(feed_as(&mut core, &n, &honest, None, false, honest.to_wire_bytes().len()), BlockOutcome::Known));
    match feed(&mut core, &n, &bad) {
        BlockOutcome::Invalid(e) => assert!(e.contains("already rejected"), "{e}"),
        other => panic!("the same rejected body again: {other:?}"),
    }
    assert!(matches!(feed(&mut core, &n, &honest), BlockOutcome::BodyRestored));
    assert_eq!(tip_meta(&n), id);
    assert!(!accept::awaits_body(&n.dag, &n.store, &id));
    assert!(n.store.get_utxo(&pay.txid(), 0).unwrap().is_some());
    let moved = core.take_chain_move();
    assert_eq!(moved.connected(), vec![id]);
    assert!(matches!(feed(&mut core, &n, &honest), BlockOutcome::Known), "once only");
}

/// Merge P1 x P3: `reconsiderblock` never lifts a consensus verdict without
/// re-validating it. (1) A connect-time failure (`b3` spends an output that
/// does not exist on its chain) on a branch the move does not connect keeps
/// its mark and reason, across a restart. (2) Once that branch is the
/// heaviest, the move re-validates `b3`, which fails again and is
/// disqualified again; the marks its descendants only inherited are lifted
/// (they are re-derived from `b3`). `invalidateblock` never overwrites the
/// consensus reason. (3) A hardening-recheck mark is lifted only when the
/// stored body passes the hardening block rules now (here: a block below the
/// mainnet activation, where they do not apply), and the node returns to the
/// heaviest chain with the UTXO set it had.
#[test]
fn merge_reconsiderblock_revalidates_consensus_and_hardening_marks() {
    let genesis = mk_genesis(unix_now() - 50_000);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0x68u8; 32], 0u32, out(5_000_000, &k.spk));
    let mut b = Builder::new(&genesis);
    let blocks = shape_with_invalid_branch(&mut b, gh, &k, (fund.0, fund.1));
    let (a, b3, bx) = (&blocks[0..6], &blocks[8], &blocks[9..15]);
    let b3h = b3.block_hash();
    let mut n = node_with(&genesis, std::slice::from_ref(&fund));
    deliver(&n, &blocks);
    assert_eq!(tip_meta(&n), a[5].block_hash());
    let reason = n.store.invalid_block_reason(&b3h).unwrap().expect("b3 disqualified");
    assert_eq!(accept::mark_kind(&reason), accept::MarkKind::Consensus, "{reason}");
    let bx_tip = bx.last().unwrap().block_hash();

    // A grows past B (10 > 9): B is not the best even without b3's mark.
    let more = b.chain(a[5].block_hash(), 4, "ra");
    deliver(&n, &more);
    let a_tip = more.last().unwrap().block_hash();
    let before = digest(&n);

    // (1) Not re-validated: the mark and its reason stay.
    let r = reconsider(&n, b3h).expect("reconsiderblock");
    assert_eq!((r.tip, r.rolled_back, r.connected), (a_tip, 0, 0));
    assert_eq!(n.store.invalid_block_reason(&b3h).unwrap().as_deref(), Some(reason.as_str()));
    assert!(n.dag.read().is_invalid(&b3h) && n.dag.read().is_invalid(&bx_tip));
    assert_eq!(digest(&n), before);
    restart(&mut n);
    assert!(n.dag.read().is_invalid(&b3h) && n.dag.read().is_invalid(&bx_tip));

    // (2) B grows past A (12 > 10); its new blocks inherit the mark on
    // arrival. reconsiderblock re-validates b3: it fails again.
    let bmore = b.chain(bx_tip, 3, "rb");
    for blk in &bmore {
        assert!(accept(&n, blk).is_err(), "descends from b3");
    }
    let inherited = n.store.invalid_block_reason(&bmore[0].block_hash()).unwrap().expect("inherited mark");
    assert_eq!(accept::mark_kind(&inherited), accept::MarkKind::Inherited, "{inherited}");
    let r = reconsider(&n, b3h).expect("reconsiderblock");
    assert_eq!(r.tip, a_tip, "b3 is invalid in its own context: A stays");
    let again = n.store.invalid_block_reason(&b3h).unwrap().expect("disqualified again");
    assert_eq!(accept::mark_kind(&again), accept::MarkKind::Consensus, "{again}");
    assert!(n.store.invalid_block_reason(&bmore[0].block_hash()).unwrap().is_none(), "inherited mark lifted");
    assert!(n.dag.read().is_invalid(&bmore.last().unwrap().block_hash()), "re-derived from b3");
    assert_eq!(digest(&n), before);
    let r = invalidate(&n, b3h).expect("invalidateblock on a disqualified block is a no-op");
    assert_eq!((r.tip, r.affected), (a_tip, 0));
    assert_eq!(n.store.invalid_block_reason(&b3h).unwrap().as_deref(), Some(again.as_str()));
    restart(&mut n);
    assert_eq!(tip_meta(&n), a_tip);
    assert!(n.dag.read().is_invalid(&bmore.last().unwrap().block_hash()));

    // (3) A hardening-recheck mark on a3 whose stored body passes the rules.
    let a3 = a[2].block_hash();
    {
        let mut batch = rocksdb::WriteBatch::default();
        n.store.stage_invalid_block(&mut batch, &a3, &format!("{}: test mark", accept::HARDENING_RECHECK_REASON)).unwrap();
        n.store.write_batch(batch).unwrap();
    }
    restart(&mut n);
    assert!(n.dag.read().is_invalid_all_edges(&a3));
    assert_ne!(tip_meta(&n), a_tip, "the applied chain left a3");
    let r = reconsider(&n, a3).expect("reconsiderblock");
    assert_eq!(r.tip, a_tip);
    assert!(n.store.invalid_block_reason(&a3).unwrap().is_none(), "re-validated and lifted");
    assert!(!n.dag.read().is_invalid(&a3));
    assert_eq!(digest(&n), before);
    assert!(n.dag.read().is_invalid(&b3h), "the other marks are untouched");
}

/// Review of the P3 merge (1): `reconsiderblock` on a block R whose
/// consensus mark an older release wrote for a relay-altered body (the
/// pre-P1 behaviour) that it still stores. The move re-validates that body,
/// the witness-dependent failure drops it and R waits for another body; R
/// was not applied, so its mark stays on disk — and now also in memory (as a
/// persistent root, not only through the body-pending mark). Pre-fix the
/// re-mark skipped R (already invalid through the pending mark), the honest
/// body then connected R's chain while `invalid_block/R` stayed on disk, and
/// the next restart disqualified R again and rolled the node back off the
/// chain it followed. Now memory and disk agree throughout; a second
/// `reconsiderblock` with the honest body re-validates R, connects it and
/// lifts the mark, and a restart keeps the node there.
#[test]
fn merge_reconsidered_mark_is_kept_until_its_block_is_revalidated() {
    let genesis = mk_genesis(unix_now() - 50_000);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0x6Au8; 32], 0u32, out(5_000_000, &k.spk));
    let mut b = Builder::new(&genesis);
    let a = b.chain(gh, 3, "ka");
    let a_tip = a.last().unwrap().block_hash();
    let pay = signed_spend(&k, &[(fund.0, fund.1)], vec![out(4_900_000, &[0xB8; 20])]);
    let r = b.with_txs(vec![gh], "kr", 100_000, vec![pay.clone()]);
    let rh = r.block_hash();
    let mut bb = vec![r.clone()];
    bb.extend(b.chain(rh, 4, "kb")); // R + 4: heavier than A
    let b_tip = bb.last().unwrap().block_hash();
    let mut bad = r.clone();
    bad.transactions[1].inputs[0].script_sig[100] ^= 0x01;
    assert_eq!(bad.block_hash(), rh, "same id below the activation");
    let only_b = node_with(&genesis, std::slice::from_ref(&fund));
    deliver(&only_b, &bb);

    // The state an older release left: R disqualified with a consensus
    // reason, its relay-altered body stored, the node on A.
    let mut n = node_with(&genesis, std::slice::from_ref(&fund));
    deliver(&n, &a);
    deliver(&n, &bb);
    assert_eq!(tip_meta(&n), b_tip);
    invalidate(&n, rh).expect("leave B");
    assert_eq!(tip_meta(&n), a_tip);
    {
        let mut batch = rocksdb::WriteBatch::default();
        n.store.stage_invalid_block(&mut batch, &rh, "invalid hybrid signature (older release)").unwrap();
        n.store.write_batch(batch).unwrap();
    }
    n.store.put_block_body(&bad).unwrap();
    restart(&mut n);
    let reason = n.store.invalid_block_reason(&rh).unwrap().expect("marked");
    assert_eq!(accept::mark_kind(&reason), accept::MarkKind::Consensus);
    assert_eq!(tip_meta(&n), a_tip);

    // reconsiderblock: the stored body fails for a witness-dependent reason,
    // is dropped, and R waits for another body. The move does not apply R.
    let r1 = reconsider(&n, rh).expect("reconsiderblock");
    assert_eq!((r1.tip, r1.connected), (a_tip, 0));
    assert!(!n.store.has_block_body(&rh).unwrap(), "the rejected body is dropped");
    assert!(accept::awaits_body(&n.dag, &n.store, &rh), "a body is wanted");
    assert_eq!(n.store.invalid_block_reason(&rh).unwrap().as_deref(), Some(reason.as_str()),
        "not re-validated: the mark stays on disk");
    assert!(n.dag.read().is_invalid_persistently(&rh),
        "... and in memory, as a persistent root (pre-fix: only the body-pending mark)");

    // The honest body arrives as the answer to the node's pull: stored, but
    // R stays disqualified, as on disk. Pre-fix: B connected here with the
    // mark still on disk.
    let mut core = BlockIngress::new();
    assert!(matches!(feed(&mut core, &n, &r), BlockOutcome::BodyRestored));
    assert!(n.store.has_block_body(&rh).unwrap());
    assert_eq!(tip_meta(&n), a_tip, "a persisted mark keeps its block off the chain");
    assert!(n.dag.read().is_invalid(&rh));
    assert!(n.store.invalid_block_reason(&rh).unwrap().is_some());
    // A restart changes nothing (pre-fix: it rolled the node back off B).
    restart(&mut n);
    assert_eq!((sel_tip(&n), tip_meta(&n)), (Some(a_tip), a_tip));

    // reconsiderblock again: the honest body is re-validated, B connects and
    // the mark goes in the same batch.
    let r2 = reconsider(&n, rh).expect("reconsiderblock");
    assert_eq!(r2.tip, b_tip);
    assert_eq!(tip_meta(&n), b_tip);
    assert!(n.store.invalid_block_reason(&rh).unwrap().is_none());
    assert_eq!(digest(&n), digest(&only_b));
    restart(&mut n);
    assert_eq!((sel_tip(&n), tip_meta(&n)), (Some(b_tip), b_tip));
    assert_eq!(digest(&n), digest(&only_b));
}

/// Review of the P3 merge (1, the stronger guard): a connect deletes the
/// persisted consensus or inherited mark of every block it applies (each was
/// just validated in its own context), whatever triggered it — here an
/// ordinary acceptance, for marks memory does not hold. Pre-fix only an
/// operator override's batch removed marks, so an applied block could keep
/// one and be disqualified again (the node rolled back) at the next restart.
#[test]
fn merge_a_connect_lifts_stale_marks_of_the_blocks_it_applies() {
    let genesis = mk_genesis(unix_now() - 50_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let a = b.chain(gh, 4, "sa");
    let fork = b.chain(gh, 3, "sb"); // lighter, stored unapplied
    let mut n = node_with(&genesis, &[]);
    deliver(&n, &a);
    deliver(&n, &fork);
    assert_eq!(tip_meta(&n), a.last().unwrap().block_hash());
    let (f1, f2) = (fork[0].block_hash(), fork[1].block_hash());
    {
        let mut batch = rocksdb::WriteBatch::default();
        n.store.stage_invalid_block(&mut batch, &f1, "bad-txns-inputs-missingorspent (stale)").unwrap();
        n.store.stage_invalid_block(&mut batch, &f2,
            &format!("{}{} is invalid", accept::INHERITED_REASON_PREFIX, hex::encode(&f1[..8]))).unwrap();
        n.store.write_batch(batch).unwrap();
    }
    assert!(!n.dag.read().is_invalid(&f1), "memory does not hold the marks");
    // The fork grows past A and connects through f1, f2.
    let more = b.chain(fork.last().unwrap().block_hash(), 3, "sc");
    deliver(&n, &more);
    let tip = more.last().unwrap().block_hash();
    assert_eq!(tip_meta(&n), tip);
    assert!(n.store.invalid_block_reason(&f1).unwrap().is_none(), "consensus mark lifted by the connect");
    assert!(n.store.invalid_block_reason(&f2).unwrap().is_none(), "inherited mark lifted by the connect");
    restart(&mut n);
    assert_eq!((sel_tip(&n), tip_meta(&n)), (Some(tip), tip), "no rollback at the next start");
}

/// Review of the P3 merge (2): `reconsiderblock` computed the mempool's next
/// block height while the consensus marks it had lifted (to let the move
/// re-validate them) were still lifted in memory, and only re-marked them
/// afterwards. Here the reconsidered block b2 lies on a TALL but lighter
/// branch (a 5-block chain against a 2-high wide DAG, heavier under the
/// hardened rules' Kaspa blue work): the move stays on the wide DAG and b2
/// keeps its mark, but pre-fix the branch tip counted as a template parent
/// for the next height (6 instead of 3) until the next acceptance —
/// admission, eviction and wallets used the wrong height.
#[test]
fn merge_reconsiderblock_sets_the_next_height_after_restoring_marks() {
    let _hardened = gnb::core::activation::scoped_override(0);
    let genesis = mk_genesis(unix_now() - 50_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let b1 = b.empty(vec![gh], "nb1");
    // Its coinbase claims fees it does not collect: fails its connect.
    let b2 = b.with_txs(vec![b1.block_hash()], "nb2", 100_000, vec![]);
    let b2h = b2.block_hash();
    let tall = b.chain(b2h, 3, "nb"); // b3..b5, DAG height 5
    let tall_tip = tall.last().unwrap().block_hash();
    let par: Vec<Block> = (0..6).map(|i| b.empty(vec![gh], &format!("na{i}"))).collect();
    let m = b.empty(par.iter().map(|x| x.block_hash()).collect(), "nm"); // DAG height 2, heavier
    let n = node_with(&genesis, &[]);
    assert!(n.dag.read().is_hardened_at(1));
    deliver(&n, &[b1.clone(), b2.clone()]);
    deliver(&n, &tall);
    let reason = n.store.invalid_block_reason(&b2h).unwrap().expect("b2 fails its connect");
    assert_eq!(accept::mark_kind(&reason), accept::MarkKind::Consensus, "{reason}");
    deliver(&n, &par);
    deliver(&n, std::slice::from_ref(&m));
    assert_eq!(tip_meta(&n), m.block_hash());
    let next = |n: &Node| gnb::template::next_template_height(&n.dag.read(), &n.store);
    assert_eq!(next(&n), 3);
    assert_eq!(n.mempool.next_height(), 3);
    let mut tips = n.tip_tx.subscribe();

    let r = reconsider(&n, b2h).expect("reconsiderblock");
    assert_eq!((r.tip, r.connected, r.rolled_back), (m.block_hash(), 0, 0));
    assert!(n.dag.read().is_invalid(&tall_tip), "b2 keeps its mark: its branch is not a template parent");
    assert!(n.store.invalid_block_reason(&b2h).unwrap().is_some());
    assert_eq!(next(&n), 3);
    assert_eq!(n.mempool.next_height(), 3, "the pool's next height is the template's (pre-fix: 6)");
    let changed = tips.try_recv().expect("TipChanged");
    assert!(!changed.parents.contains(&tall_tip));
    assert_eq!(changed.parents.iter().map(|p| b.height(p)).max().unwrap() + 1, 3,
        "the announced template and the pool agree");
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

    // A stray shielded record (merge P3 x P5): the rebuild must reset the
    // shielded state with the rest of the chain state.
    let stray_nf = [0x5Au8; 32];
    {
        let mut key = vec![b'N'];
        key.extend_from_slice(&stray_nf);
        let mut batch = rocksdb::WriteBatch::default();
        n.store.stage_shielded_put(&mut batch, &key, &[]).unwrap();
        n.store.write_batch(batch).unwrap();
    }

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
    // Merge P3 x P4: the explorer aggregates are recomputed for the rebuilt
    // state (complete, equal to a full recomputation, and to the clean
    // node's).
    assert!(n.store.aggregates_ready());
    let snap = n.store.aggregate_snapshot().unwrap();
    assert_eq!(snap, n.store.recompute_aggregates(&std::sync::atomic::AtomicBool::new(false)).unwrap());
    assert_eq!(snap, clean.store.aggregate_snapshot().unwrap());
    // Merge P3 x P5: the shielded state was reset and follows the rebuilt
    // chain (persisted tip = the applied tip; the stray record is gone).
    let pool = gnb::coherence::ShieldedPool::load(&n.store).expect("shielded state loads");
    assert_eq!(pool.tip(), Some(tip_meta(&n)));
    assert!(!pool.engine.is_spent(&stray_nf));
    assert_eq!(n.shielded.read().tip(), Some(tip_meta(&n)));
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

/// Deliver `b` as the answer to one of the node's directed pulls (how parent
/// fetches, frontier tips and re-fetched bodies arrive).
fn feed(core: &mut BlockIngress, n: &Node, b: &Block) -> BlockOutcome {
    feed_as(core, n, b, None, true, b.to_wire_bytes().len())
}

/// Deliver `b` from `peer`, as a directed answer (`solicited`) or gossip,
/// with `wire_bytes` charged to the peer's orphan quota.
fn feed_as(
    core: &mut BlockIngress,
    n: &Node,
    b: &Block,
    peer: Option<libp2p::PeerId>,
    solicited: bool,
    wire_bytes: usize,
) -> BlockOutcome {
    core.handle_block(b.clone(), b.block_hash(), wire_bytes, peer, solicited,
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
/// answer every parent request in the order the requests were sent (they are
/// all in flight at once, so a DAG-shaped fork arrives level by level), and
/// whenever the pipeline stalls do what the node's 30 s nudge and orphan
/// sweep do — re-request the missing parents buffered orphans still wait for
/// and re-announce the tip — until `n` selects `want_tip`. Returns the
/// admissions of processed blocks, the drops and the number of
/// announcements.
#[allow(clippy::type_complexity)]
fn sync_tip_first(
    core: &mut BlockIngress,
    n: &Node,
    by_hash: &HashMap<BlockHash, Block>,
    want_tip: BlockHash,
) -> (Vec<(BlockHash, WorkAdmission)>, Vec<(BlockHash, DropReason)>, usize) {
    sync_tip_first_with(core, n, by_hash, want_tip, &mut |_| {})
}

/// [`sync_tip_first`], running `between` after every delivery (adversarial
/// traffic interleaved with the honest fetches).
#[allow(clippy::type_complexity)]
fn sync_tip_first_with(
    core: &mut BlockIngress,
    n: &Node,
    by_hash: &HashMap<BlockHash, Block>,
    want_tip: BlockHash,
    between: &mut dyn FnMut(&mut BlockIngress),
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
            {
                // The orphan sweep: re-request awaited parents that are
                // neither in the DAG nor buffered (peers serve the fork's).
                let d = n.dag.read();
                let mut chased: Vec<BlockHash> = core.orphans.waiting_parents().into_iter()
                    .filter(|p| by_hash.contains_key(p) && !d.has_block(p) && !core.orphans.contains(p))
                    .collect();
                chased.sort();
                queue.extend(chased);
            }
            queue.push_back(want_tip);
            continue;
        };
        deliveries += 1;
        assert!(deliveries < 100_000);
        let blk = &by_hash[&h];
        match feed(core, n, blk) {
            BlockOutcome::Buffered { request, .. } => {
                queue.extend(request);
            }
            BlockOutcome::Processed { admission, result, .. } => {
                result.expect("fork block accepted");
                admissions.push((h, admission));
            }
            BlockOutcome::Dropped(r) => drops.push((h, r)),
            BlockOutcome::Known | BlockOutcome::PoolRefused | BlockOutcome::BodyRestored => {}
            BlockOutcome::Invalid(e) => panic!("invalid: {e}"),
        }
        between(core);
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

/// Audit POW-3 follow-up (review): under the hardened rules (testnet and
/// regtest from genesis, mainnet from 110,000) blue work counts merged blues,
/// so the threshold is real blue work — but the work rule credited an
/// announced fork with the work of ONE path of orphans. A heavier DAG-shaped
/// fork (here two blocks per level, each merging both blocks of the level
/// below) was refused for good: its first block's single-path credit
/// (51 + 500 blocks of work) never reached the threshold (640), while the fork
/// (1,051 blocks of blue work) beats the 1,000-block chain. The credit is now
/// the summed work of the distinct orphans announced above a block, buffered
/// or evicted, each counted once; the node follows the fork tip first through
/// a pool much smaller than the fork and ends with the UTXO set of a node fed
/// in order.
#[test]
fn pow3_heavier_dag_shaped_fork_is_followed_under_the_hardened_rules() {
    let _hardened = gnb::core::activation::scoped_override(0);
    let genesis = mk_genesis(unix_now() - 50_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let honest = b.chain(gh, 1_000, "dh");
    let mut fork: Vec<Block> = Vec::new();
    let mut level = vec![honest[49].block_hash()]; // the fork branches at height 50
    for i in 0..500 {
        let l0 = b.empty(level.clone(), &format!("dl{i}a"));
        let l1 = b.empty(level.clone(), &format!("dl{i}b"));
        level = vec![l0.block_hash(), l1.block_hash()];
        fork.push(l0);
        fork.push(l1);
    }
    let top = b.empty(level, "dtop");
    fork.push(top.clone());
    let by_hash: HashMap<BlockHash, Block> = fork.iter().map(|x| (x.block_hash(), x.clone())).collect();

    // The fork is heavier under the hardened rules: a node fed everything in
    // order ends on it.
    let w = node_with(&genesis, &[]);
    assert!(w.dag.read().is_hardened_at(1), "hardened rules from genesis");
    deliver(&w, &honest);
    deliver(&w, &fork);
    assert_eq!(sel_tip(&w), Some(top.block_hash()));
    let unit = core::bits_to_work(core::POW_LIMIT_BITS);

    let x = node_with(&genesis, &[]);
    for blk in &honest {
        accept(&x, blk).unwrap();
    }
    assert_eq!(ingress::anti_dos_work_threshold(&x.dag.read()), 640 * unit);
    let mut core = BlockIngress::with_limits(OrphanLimits {
        max_entries: 300, max_bytes: 64 << 20, max_entries_per_peer: 300, max_bytes_per_peer: 64 << 20,
    });
    let (admissions, drops, rounds) = sync_tip_first(&mut core, &x, &by_hash, top.block_hash());
    println!("POW-3 DAG-shaped fork: followed after {rounds} announcement(s); {} admissions", admissions.len());
    assert!(drops.is_empty(), "no fork block was refused: {drops:?}");
    let first = admissions.iter().find(|(h, _)| *h == fork[0].block_hash()).expect("first fork block");
    assert_eq!(first.1, WorkAdmission::ChainBacked);
    assert_eq!(tip_meta(&x), top.block_hash());
    assert_eq!(digest(&x), digest(&w));
}

/// A junk orphan for the flood below: 256 random missing parents, pow-limit
/// bits (they meet the anti-DoS floor under `test-pow-limit`), proof marked
/// verified.
fn junk_orphan(j: u64, height: u64) -> Block {
    let mut rng = Rng(0x5EED_F100_D000_0000 ^ j);
    let parents: Vec<BlockHash> = (0..256)
        .map(|_| {
            let mut h = [0u8; 32];
            for c in h.chunks_mut(8) {
                c.copy_from_slice(&rng.next().to_le_bytes());
            }
            h
        })
        .collect();
    let mut blk = Block {
        header: BlockHeader {
            version: 1,
            parents,
            merkle_root: MerkleRoot::ZERO,
            timestamp: unix_now(),
            bits: core::POW_LIMIT_BITS,
            nonce: j,
        },
        transactions: vec![coinbase(&format!("junk{j}"), 0, vec![0xEE; 20])],
        blue_score: height,
        height,
        shielded_transactions: Vec::new(),
    };
    blk.header.merkle_root = blk.body_merkle_root();
    blk.test_only_assume_pow_valid();
    blk
}

/// Audit POW-3 follow-up (review): the remembered-work map could be flushed.
/// Every evicted orphan remembered work under each of its (up to 256,
/// sender-chosen) parents in one FIFO, and a re-sent evicted orphan was
/// evicted again for free — 212 orphans of 256 parents, cycled, pushed every
/// honest entry out of the 50,000-entry map between two parent fetches, so a
/// fork deeper than the window plus the pool lost its proven work and was
/// refused. Scaled down here: the remembered stores hold 1,024 entries and
/// one gossiping peer cycles 12 orphans of 256 random parents, each charged
/// 2 MB so its 16 MiB quota holds 8 (every re-send evicts one: 12 x 256 =
/// 3,072 keys per cycle, three times the store, as 212 x 256 exceeds 50,000),
/// after EVERY honest delivery until the fork's first block is admitted. The
/// fork is 550 blocks deep and fetched through a 100-orphan pool (its first
/// block needs 190 blocks of announced work, so the evicted part must be
/// remembered). The first block is still chain-backed and the node ends on
/// the fork tip.
#[test]
fn pow3_remembered_work_survives_a_parent_key_flood() {
    let genesis = mk_genesis(unix_now() - 50_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let honest = b.chain(gh, 600, "kf");
    let fork = b.chain(honest[49].block_hash(), 600, "kg"); // tip at height 650
    let fork_tip = fork.last().unwrap().block_hash();
    let by_hash: HashMap<BlockHash, Block> = fork.iter().map(|x| (x.block_hash(), x.clone())).collect();
    let x = node_with(&genesis, &[]);
    for blk in &honest {
        accept(&x, blk).unwrap();
    }
    let mut core = BlockIngress::with_limits(OrphanLimits {
        max_entries: 10_000, max_bytes: 64 << 20, max_entries_per_peer: 100, max_bytes_per_peer: 16 << 20,
    });
    core.orphans.set_remembered_capacity(1_024);
    let attacker = Some(libp2p::PeerId::random());
    let flood: Vec<Block> = (0..12).map(|j| junk_orphan(j, 600)).collect();
    let f1 = fork[0].block_hash();
    let mut buffered = 0usize;
    let mut between = |core: &mut BlockIngress| {
        if x.dag.read().has_block(&f1) {
            return;
        }
        for o in &flood {
            if matches!(feed_as(core, &x, o, attacker, false, 2_000_000), BlockOutcome::Buffered { .. }) {
                buffered += 1;
            }
        }
    };
    let (admissions, drops, rounds) = sync_tip_first_with(&mut core, &x, &by_hash, fork_tip, &mut between);
    println!("POW-3 flood: fork followed after {rounds} announcement(s); {buffered} flood orphans (re)buffered");
    assert!(buffered > 12 * 500, "the flood cycled through the pool after every delivery: {buffered}");
    assert!(drops.is_empty(), "no fork block was refused: {drops:?}");
    let first = admissions.iter().find(|(h, _)| *h == fork[0].block_hash()).expect("first fork block");
    assert_eq!(first.1, WorkAdmission::ChainBacked);
    assert_eq!(tip_meta(&x), fork_tip);
    let (skeletons, paths) = core.orphans.remembered_len();
    assert!(skeletons <= 1_024 && paths <= 1_024);
}

