//! Phase-4 package R2b: block ingress, initial sync and gossip-validation
//! DoS. Regression tests for POW-3 (minimum chain work, unrequested blocks,
//! submitblock, the iterative orphan drain), B1-T5 (vouching orphans, the
//! drain's work rule, withheld orphan verdicts), POW-4 (the orphan floor gate
//! in `handle_block`), NET-2 (proof of work off the processor, under
//! budgets), B1-T7 (who a refused frame is charged to) and B1-T19 (the
//! transaction verification budget).
//!
//! Revert checks (the production hunk reverted, the test run, the hunk
//! restored) were run for the POW-3, NET-2, NET-4 and POW-4 tests and for
//! the review-finding tests: each failed with its hunk reverted (see the
//! package report for the table). The B1-T5, B1-T7 and B1-T19 tests that
//! predate the review were not revert-checked. Node test builds enable
//! gnb-crypto's `test-pow-limit` feature (every expected target is the pow
//! limit); proofs are marked verified (`test_only_assume_pow_valid`) where a
//! test needs many blocks, and left unevaluated (garbage nonce, nothing
//! marked) where a test must show that no proof was evaluated.

mod fix_common;
use fix_common::*;

use std::time::{Duration, Instant};

use gnb::consensus::{BlockHash, GhostDAG};
use gnb::core::{self, Block, BlockHeader, MerkleRoot, Transaction};
use gnb::ingress::{
    self, BlockFault, BlockIngress, BlockOutcome, BlockPenalty, DeferredBlockVerdicts, DropReason, Gated,
    OrphanFate, OrphanLimits, PowCheck, PowGate, WorkAdmission,
};
use gnb::mempool::admission;
use gnb::mempool::orphanage::OrphanLimits as TxOrphanLimits;
use gnb::mempool::relay::{self, TxRelay};
use gnb::network::GossipVerdict;
use gnb::pow;
use gnb::pow::verifier::{PowJob, PowLimits, PowRefusal, PowScheduler, PowSource, StartNext};
use libp2p::PeerId;

// ── Fixtures ─────────────────────────────────────────────────────────────────

/// Builds blocks with the header height / bits the consensus rules require
/// (tracking DAG heights in its own GhostDAG, no storage). `ts` overrides the
/// timestamp (default: latest parent + 1); `register` adds the block to the
/// builder's DAG (so children can be built on it).
struct Builder {
    dag: GhostDAG,
}

impl Builder {
    fn new(genesis: &Block) -> Self {
        let mut dag = GhostDAG::with_default_k();
        dag.add_genesis(genesis.block_hash(), genesis.header.timestamp);
        Builder { dag }
    }

    fn raw(&mut self, parents: Vec<BlockHash>, txs: Vec<Transaction>, ts: Option<u64>, register: bool) -> Block {
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
                timestamp: ts.unwrap_or(pts + 1),
                bits,
                nonce: 0,
            },
            transactions: txs,
            blue_score: height,
            height,
            shielded_transactions: Vec::new(),
            powit: Default::default(),
        };
        commit_block(&mut b);
        if register {
            self.dag.add_block(b.block_hash(), parents, b.header.timestamp, pow::block_work(bits, height))
                .expect("builder DAG accepts the block");
        }
        b
    }

    fn height(&self, h: &BlockHash) -> u64 {
        self.dag.get_block_data(h).unwrap().height
    }

    /// A coinbase-only block, proof marked verified.
    fn empty_at(&mut self, parents: Vec<BlockHash>, tag: &str, ts: Option<u64>, register: bool) -> Block {
        let h = parents.iter().map(|p| self.height(p)).max().unwrap() + 1;
        let cb = coinbase(tag, core::tokenomics::block_subsidy_sat(h), vec![0xC0; 20]);
        let b = self.raw(parents, vec![cb], ts, register);
        b.test_only_assume_pow_valid();
        b
    }

    fn empty(&mut self, parents: Vec<BlockHash>, tag: &str) -> Block {
        self.empty_at(parents, tag, None, true)
    }

    /// A coinbase-only block whose proof is NOT marked verified (not
    /// registered): evaluating it costs a 64 MiB evaluation, so an outcome
    /// decided before any evaluation shows the cheap check ran first.
    fn unmarked(&mut self, parents: Vec<BlockHash>, tag: &str, ts: Option<u64>) -> Block {
        let h = parents.iter().map(|p| self.height(p)).max().unwrap() + 1;
        let cb = coinbase(tag, core::tokenomics::block_subsidy_sat(h), vec![0xC1; 20]);
        self.raw(parents, vec![cb], ts, false)
    }

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

fn ctx(n: &Node) -> ingress::AcceptCtx<'_> {
    ingress::AcceptCtx {
        dag: &n.dag, store: &n.store, mempool: &n.mempool, node_state: &n.node_state,
        tip_tx: Some(&n.tip_tx), shielded: &n.shielded,
    }
}

/// Deliver `b` as unsolicited gossip from a fresh peer.
fn gossip(core: &mut BlockIngress, n: &Node, b: &Block) -> BlockOutcome {
    core.handle_block(b.clone(), b.block_hash(), b.to_wire_bytes().len(), Some(PeerId::random()), false,
        Instant::now(), unix_now(), &ctx(n))
}

/// Deliver `b` as the answer to one of the node's directed pulls.
fn pulled(core: &mut BlockIngress, n: &Node, b: &Block) -> BlockOutcome {
    core.handle_block(b.clone(), b.block_hash(), b.to_wire_bytes().len(), Some(PeerId::random()), true,
        Instant::now(), unix_now(), &ctx(n))
}

/// A node holding `chain` (genesis first, accepted through the real path).
fn node_on(genesis: &Block, chain: &[Block]) -> Node {
    let x = node_with(genesis, &[]);
    for blk in chain {
        accept(&x, blk).unwrap();
    }
    x
}

fn tip_work(n: &Node) -> u128 {
    ingress::tip_blue_work(&n.dag.read())
}

// ═════════════════════════════════════════════════════════════════════════════
// POW-3: minimum chain work and Bitcoin Core's rule for unrequested blocks
// ═════════════════════════════════════════════════════════════════════════════

/// The challenger's scenario (verify_partial.json, challenge.POW-3): the
/// victim's tip is far behind the network (its genesis is 500,000 s old,
/// its chain 100 blocks); the attacker mines ONE block A on that tip stamped
/// "now" (under the absolute-schedule ASERT every child of A then has the
/// pow-limit target) and floods 50 children of A, then 50 orphans on top of
/// them. Pre-fix every one of them was stored and inserted (the anti-DoS
/// work rule's threshold is relative to the victim's own tip). Revert
/// check: with the unrequested-block rule removed from
/// `handle_block_gated`, A is no longer dropped and this test fails.
/// Now the node knows it is in initial block download (its tip is below the
/// minimum chain work, Bitcoin Core's `nMinimumChainWork`) and stores no
/// block it did not ask for: everything is dropped before structure, proof
/// or storage (the children's proofs are not marked verified: had the
/// orphan path run, each would have cost an evaluation and been buffered).
#[test]
fn pow3_ibd_node_refuses_the_unrequested_cheap_chain() {
    let genesis = mk_genesis(unix_now() - 500_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let honest = b.chain(gh, 100, "h");
    let x = node_on(&genesis, &honest);
    // The network's chain work is far above the victim's tip.
    let w = core::bits_to_work(core::POW_LIMIT_BITS);
    let min_work = 10_000 * w;
    let mut core = BlockIngress::new().with_minimum_chain_work(min_work);
    assert!(core.in_initial_download(&x.dag.read()));
    let before = x.dag.read().block_count();
    let tip = honest.last().unwrap().block_hash();
    let a = b.empty_at(vec![tip], "attacker-a", Some(unix_now()), true);
    assert!(matches!(gossip(&mut core, &x, &a), BlockOutcome::Dropped(DropReason::BelowMinimumChainWork)));
    let mut children = Vec::new();
    for i in 0..50 {
        let c = b.unmarked(vec![a.block_hash()], &format!("cheap{i}"), Some(unix_now()));
        // Children of A (A is not stored): orphans, also refused unrequested.
        assert!(matches!(gossip(&mut core, &x, &c), BlockOutcome::Dropped(DropReason::BelowMinimumChainWork)),
            "an unrequested orphan is not buffered while in initial download");
        children.push(c);
    }
    assert_eq!(x.dag.read().block_count(), before, "nothing stored");
    assert!(core.orphans.is_empty(), "nothing buffered");
    // An unrequested block whose OWN chain reaches the minimum chain work is
    // processed (Core: `pindex->nChainWork >= MinimumChainWork()`).
    let mut core_low = BlockIngress::new().with_minimum_chain_work(tip_work(&x) + w);
    let ext = b.empty_at(vec![tip], "extends-to-min", None, true);
    assert!(matches!(gossip(&mut core_low, &x, &ext), BlockOutcome::Processed { result: Ok(_), .. }));

    // The honest network: blocks this node asked for are processed in IBD.
    let next = b.empty(vec![ext.block_hash()], "pulled");
    match pulled(&mut core, &x, &next) {
        BlockOutcome::Processed { admission: WorkAdmission::NearTip, result: Ok(_), .. } => {}
        other => panic!("a requested block is processed during initial download: {other:?}"),
    }
    // Pre-fix behaviour, for the record: without a minimum chain work (the
    // mainnet default while the repository carries no chain data) the rule is
    // relative to the tip and an unrequested block extending it is processed.
    let y = node_on(&genesis, &honest);
    let mut core0 = BlockIngress::new().with_minimum_chain_work(0);
    assert!(!core0.in_initial_download(&y.dag.read()));
    assert!(matches!(gossip(&mut core0, &y, &a), BlockOutcome::Processed { result: Ok(_), .. }));
}

/// POW-3: a block this node has an outstanding request for counts as
/// requested whoever delivers it (Core's `IsBlockRequested`): the parent of a
/// buffered orphan, delivered by gossip, is processed in IBD.
#[test]
fn pow3_a_block_with_an_outstanding_request_counts_as_requested() {
    let genesis = mk_genesis(unix_now() - 50_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let honest = b.chain(gh, 20, "h");
    let x = node_on(&genesis, &honest);
    let mut core = BlockIngress::new().with_minimum_chain_work(u128::MAX);
    let p = b.empty(vec![honest.last().unwrap().block_hash()], "parent");
    let c = b.empty(vec![p.block_hash()], "child");
    // The child arrives as the answer to a pull (a frontier tip): buffered,
    // and its missing parent is requested.
    match pulled(&mut core, &x, &c) {
        BlockOutcome::Buffered { request, .. } => assert_eq!(request, vec![p.block_hash()]),
        other => panic!("{other:?}"),
    }
    assert!(core.is_requested(&p.block_hash(), false));
    // The parent arrives by gossip: requested, so processed, and the child is
    // drained.
    match gossip(&mut core, &x, &p) {
        BlockOutcome::Processed { result: Ok(_), drained, .. } => assert_eq!(drained, vec![c.block_hash()]),
        other => panic!("{other:?}"),
    }
}

/// POW-3: outside initial download, an unrequested block must come within
/// `UNREQUESTED_WINDOW_BLOCKS` (GhostDAG k + 1) of the selected tip — Bitcoin
/// Core processes an unrequested block only if it has at least the tip's
/// work. A block forking 50 blocks below the tip is refused unless this node
/// asked for it (it is within the 360-block anti-DoS window, so it IS
/// processed when requested, e.g. as the parent of a buffered orphan); a
/// sibling of the tip (honest concurrency) is processed.
#[test]
fn pow3_unrequested_blocks_must_come_near_the_tip() {
    let genesis = mk_genesis(unix_now() - 50_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let honest = b.chain(gh, 100, "h");
    let x = node_on(&genesis, &honest);
    let mut core = BlockIngress::new().with_minimum_chain_work(0);
    let deep = b.empty(vec![honest[48].block_hash()], "deep");
    assert!(matches!(gossip(&mut core, &x, &deep), BlockOutcome::Dropped(DropReason::UnrequestedLowWork)));
    assert!(!x.dag.read().has_block(&deep.block_hash()));
    assert!(matches!(pulled(&mut core, &x, &deep), BlockOutcome::Processed { result: Ok(_), .. }),
        "requested, it is judged by the anti-DoS window instead");
    let sibling = b.empty(vec![honest[98].block_hash()], "sibling");
    assert!(matches!(gossip(&mut core, &x, &sibling), BlockOutcome::Processed { result: Ok(_), .. }));
    // The boundary: a child of the chain block k + 2 below the tip has the
    // bound of the chain block k + 1 below it (admitted); one block deeper
    // is too far.
    let k = ingress::UNREQUESTED_WINDOW_BLOCKS as usize;
    let near = b.empty(vec![honest[98 - k].block_hash()], "near");
    assert!(matches!(gossip(&mut core, &x, &near), BlockOutcome::Processed { result: Ok(_), .. }),
        "a child of the chain block k + 2 below the tip is still near");
    let too_far = b.empty(vec![honest[97 - k].block_hash()], "too-far");
    assert!(matches!(gossip(&mut core, &x, &too_far), BlockOutcome::Dropped(DropReason::UnrequestedLowWork)));
}

/// POW-3: `submitblock` is subject to the minimum chain work (a node in
/// initial block download refuses a block on a chain below it), and NOT to
/// the tip-relative anti-DoS window (review finding: a version that applied
/// it refused, block by block, an operator's replay of a heavier chain that
/// forks more than 360 blocks below the tip; Bitcoin Core's `submitblock`
/// skips its anti-DoS checks too). The first block above the deep fork
/// point, which the window used to refuse, passes. The handler in main.rs
/// calls this function; that call itself has no test.
#[test]
fn pow3_submitblock_is_subject_to_the_minimum_chain_work_only() {
    let genesis = mk_genesis(unix_now() - 50_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let honest = b.chain(gh, 400, "h");
    let x = node_on(&genesis, &honest);
    let d = x.dag.read();
    let w = core::bits_to_work(core::POW_LIMIT_BITS);
    let mined = b.empty(vec![honest.last().unwrap().block_hash()], "mined");
    assert_eq!(ingress::submitted_block_admission(&d, &mined, 0), Ok(()));
    let deep = b.empty(vec![honest[10].block_hash()], "deep-fork");
    let lb = ingress::block_work_lower_bound(&d, &deep.header.parents, deep.header.bits, deep.height).unwrap();
    assert!(lb < ingress::anti_dos_work_threshold(&d), "below the gossip window");
    assert_eq!(ingress::submitted_block_admission(&d, &deep, 0), Ok(()), "a heavier chain's replay starts here");
    let e = ingress::submitted_block_admission(&d, &mined, tip_work(&x) + 2 * w).unwrap_err();
    assert!(e.contains("minimum chain work"), "{e}");
    let mut orphan = mined.clone();
    orphan.header.parents = vec![[0xAB; 32]];
    assert_eq!(ingress::submitted_block_admission(&d, &orphan, u128::MAX), Ok(()), "accept_block refuses it");
}

/// POW-3 / POW-4: the orphan drain is iterative. A recursive drain (one
/// frame per accepted orphan, as before the audit fix) overflows this
/// thread's small stack on a 3,000-orphan chain; the iterative one does not.
/// (Revert check: with the queue replaced by a recursive call per accepted
/// orphan, the test binary aborts with a
/// stack overflow.)
#[test]
fn drain_of_a_deep_orphan_chain_runs_on_a_small_stack() {
    let handle = std::thread::Builder::new()
        .stack_size(1024 * 1024)
        .spawn(|| {
            let genesis = mk_genesis(unix_now() - 500_000);
            let gh = genesis.block_hash();
            let mut b = Builder::new(&genesis);
            let base = b.empty(vec![gh], "base");
            let chain = b.chain(base.block_hash(), 3_000, "deep");
            let x = node_with(&genesis, &[]);
            let mut core = BlockIngress::with_limits(OrphanLimits {
                max_entries: 10_000, max_bytes: 1 << 30, max_entries_per_peer: 10_000, max_bytes_per_peer: 1 << 30,
            }).with_minimum_chain_work(0);
            for blk in chain.iter().rev() {
                assert!(matches!(pulled(&mut core, &x, blk), BlockOutcome::Buffered { .. }));
            }
            match pulled(&mut core, &x, &base) {
                BlockOutcome::Processed { result: Ok(_), drained, .. } => drained.len(),
                other => panic!("{other:?}"),
            }
        })
        .unwrap();
    assert_eq!(handle.join().expect("no stack overflow"), 3_000);
}

// ═════════════════════════════════════════════════════════════════════════════
// B1-T5: vouching orphans and the drain's work rule
// ═════════════════════════════════════════════════════════════════════════════

/// The auditor's scenario (fresh_candidates.json B1-T5): an 800-block chain;
/// a gateway Y forking 500 blocks below the tip (its chain, with the 60-block
/// fork Z announced on top, stays below the anti-DoS threshold); one voucher
/// orphan with parents [tip, Y]. Pre-fix Y was admitted `MergeBacked` and
/// the drain stored all of Z without any work check, with a valid voucher
/// and with one that can never be valid (stamped before its parents) —
/// the auditor's measurement; not re-run by revert here. `act` is
/// the hardening activation height in force.
fn b1t5_scenario(invalid_voucher: bool, act: u64) -> (usize, bool, BlockOutcome, Option<BlockOutcome>) {
    let _a = core::activation::scoped_override(act);
    let genesis = mk_genesis(unix_now() - 50_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let honest = b.chain(gh, 800, "h");
    let x = node_on(&genesis, &honest);
    let w = core::bits_to_work(core::POW_LIMIT_BITS);
    let threshold = ingress::anti_dos_work_threshold(&x.dag.read());
    let tip = honest.last().unwrap().block_hash();
    let y = b.empty(vec![honest[299].block_hash()], "gateway");
    let z = b.chain(y.block_hash(), 60, "z");
    let lb_y = ingress::block_work_lower_bound(&x.dag.read(), &y.header.parents, y.header.bits, y.height).unwrap();
    assert!(lb_y + 60 * w < threshold, "the fork's chain cannot come within the window");
    let mut core = BlockIngress::new().with_minimum_chain_work(0);
    for blk in &z {
        assert!(matches!(pulled(&mut core, &x, blk), BlockOutcome::Buffered { .. }));
    }
    assert!(matches!(pulled(&mut core, &x, &y), BlockOutcome::Dropped(DropReason::LowWork)));
    let mut voucher = b.empty_at(vec![tip, y.block_hash()], "voucher", None, false);
    if invalid_voucher {
        voucher.header.timestamp = 1; // before its parents: never valid
        voucher.test_only_assume_pow_valid();
    }
    assert!(matches!(gossip(&mut core, &x, &voucher), BlockOutcome::Buffered { .. }));
    // The voucher makes the node request Y; Y arrives as the answer.
    let out_y = pulled(&mut core, &x, &y);
    let stored = z.iter().filter(|blk| x.dag.read().has_block(&blk.block_hash())).count();
    let y_in = x.dag.read().has_block(&y.block_hash());
    // Y again, delivered by gossip.
    let unreq = if y_in { None } else { Some(gossip(&mut core, &x, &y)) };
    (stored, y_in, out_y, unreq)
}

/// After the hardening activation no orphan vouches (merging a block whose
/// chain is that far behind is a merge-depth violation): Y stays refused and
/// nothing of Z is stored, whatever the voucher.
#[test]
fn b1t5_no_voucher_after_the_activation() {
    for invalid in [false, true] {
        let (stored, y_in, out_y, unreq) = b1t5_scenario(invalid, 0);
        assert_eq!(stored, 0, "invalid voucher {invalid}: no Z block stored");
        assert!(!y_in);
        assert!(matches!(out_y, BlockOutcome::Dropped(DropReason::LowWork)), "{out_y:?}");
        // Y delivered by gossip counts as requested (the voucher made the
        // node ask for it): judged by the work rule, refused.
        assert!(matches!(unreq, Some(BlockOutcome::Dropped(DropReason::LowWork))), "{unreq:?}");
    }
}

/// Below the activation (merging deep blocks is valid there): a voucher that
/// fails its contextual checks vouches for nothing; a contextually valid one
/// gets Y admitted (charged to the merge-backed budget) and is itself
/// drained and accepted — but the drain judges every orphan by the work rule
/// again, so none of Z (low work, nothing vouching for it) is stored.
#[test]
fn b1t5_pre_activation_only_a_checked_voucher_vouches_and_the_drain_rechecks() {
    let (stored, y_in, out_y, _) = b1t5_scenario(true, core::activation::NEVER);
    assert_eq!((stored, y_in), (0, false), "an unchecked voucher vouches for nothing: {out_y:?}");
    assert!(matches!(out_y, BlockOutcome::Dropped(DropReason::LowWork)));
    let (stored, y_in, out_y, _) = b1t5_scenario(false, core::activation::NEVER);
    assert!(y_in, "a contextually valid voucher still vouches below the activation");
    match out_y {
        BlockOutcome::Processed { admission: WorkAdmission::MergeBacked, result: Ok(_), drained, .. } => {
            assert_eq!(drained.len(), 1, "only the voucher is drained: {drained:?}");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(stored, 0, "the low-work fork above Y is refused by the drain's work rule");
}

/// B1-T5: EVERY merge-backed admission is charged to the budget — the
/// exemption for blocks less than 1,000 below the tip let one voucher per
/// block plant any number of blocks 361..1,000 deep. Five deep blocks 500
/// below an 800-block tip, each merged by its own (valid) orphan: four are
/// admitted (the burst), the fifth is refused.
#[test]
fn b1t5_every_merge_backed_admission_is_rationed() {
    let _a = core::activation::scoped_override(core::activation::NEVER);
    let genesis = mk_genesis(unix_now() - 50_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let honest = b.chain(gh, 800, "mb");
    let x = node_on(&genesis, &honest);
    let mut core = BlockIngress::new().with_minimum_chain_work(0);
    let mut tip = honest.last().unwrap().block_hash();
    let mut admitted = 0;
    for i in 0..(ingress::DEEP_BACKFILL_BURST as usize + 1) {
        let deep = b.empty(vec![honest[300 + i].block_hash()], &format!("deep{i}"));
        let merger = b.empty(vec![tip, deep.block_hash()], &format!("merger{i}"));
        assert!(matches!(pulled(&mut core, &x, &merger), BlockOutcome::Buffered { .. }));
        match pulled(&mut core, &x, &deep) {
            BlockOutcome::Processed { admission: WorkAdmission::MergeBacked, result: Ok(_), .. } => {
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
}

/// B1-T5 (review finding): a merge-backed block is charged to the ration
/// once, after its proof is known valid. The node's gate defers the proof
/// (`Gated::PowPending`) and resubmits the block when the worker is done;
/// the ration used to be spent on both passes, so the burst of 4 admitted
/// only 2 such blocks (the third was dropped `DeepBudgetExhausted` after its
/// evaluation was paid). Now 4 are admitted, and the fifth is still handed
/// to the PoW workers (no token spent before the proof) and refused on
/// resubmission.
#[test]
fn b1t5_merge_backed_ration_is_spent_once_after_the_proof() {
    let _a = core::activation::scoped_override(core::activation::NEVER);
    let genesis = mk_genesis(unix_now() - 50_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let honest = b.chain(gh, 800, "mb");
    let x = node_on(&genesis, &honest);
    let mut core = BlockIngress::new().with_minimum_chain_work(0);
    let mut gate = RecordingGate { asked: Vec::new(), known: Default::default() };
    let mut tip = honest.last().unwrap().block_hash();
    let mut admitted = 0;
    for i in 0..(ingress::DEEP_BACKFILL_BURST as usize + 1) {
        let deep = b.empty(vec![honest[300 + i].block_hash()], &format!("deep{i}"));
        let merger = b.empty(vec![tip, deep.block_hash()], &format!("merger{i}"));
        assert!(matches!(pulled(&mut core, &x, &merger), BlockOutcome::Buffered { .. }));
        let go = |core: &mut BlockIngress, gate: &mut RecordingGate| {
            core.handle_block_gated(deep.clone(), deep.block_hash(), 1_000, Some(PeerId::random()), true,
                Instant::now(), unix_now(), &ctx(&x), gate)
        };
        assert!(matches!(go(&mut core, &mut gate), Gated::PowPending(_)), "deep{i}: proof deferred, nothing spent");
        gate.known.insert(deep.block_hash(), true);
        match go(&mut core, &mut gate) {
            Gated::Done(BlockOutcome::Processed { admission: WorkAdmission::MergeBacked, result: Ok(_), .. }) => {
                tip = merger.block_hash();
                admitted += 1;
            }
            Gated::Done(BlockOutcome::Dropped(DropReason::DeepBudgetExhausted)) => {
                assert_eq!(admitted, ingress::DEEP_BACKFILL_BURST as usize, "deep{i}: only after the burst");
            }
            other => panic!("deep{i}: {other:?}"),
        }
    }
    assert_eq!(admitted, ingress::DEEP_BACKFILL_BURST as usize);
}

/// B1-T5 / POW-4: a buffered orphan's gossip verdict is withheld until it
/// connects (pre-fix it was `Accept` at once, so floor-meeting orphans were
/// relayed network-wide and charged at every hop to the honest relay):
/// Accept when the drain connects it, Ignore when the work rule refuses it on
/// drain, when it leaves the pool, or when its frame expires.
#[test]
fn b1t5_orphan_verdicts_are_withheld_until_the_orphan_connects() {
    let genesis = mk_genesis(unix_now() - 50_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let honest = b.chain(gh, 20, "h");
    let x = node_on(&genesis, &honest);
    let mut core = BlockIngress::new().with_minimum_chain_work(0);
    let mut deferred: DeferredBlockVerdicts<&'static str> = DeferredBlockVerdicts::new();
    let t0 = Instant::now();
    let p = b.empty(vec![honest.last().unwrap().block_hash()], "p");
    let c = b.empty(vec![p.block_hash()], "c");
    assert!(matches!(gossip(&mut core, &x, &c), BlockOutcome::Buffered { .. }));
    assert_eq!(deferred.defer(c.block_hash(), "frame-c", t0, t0), None, "withheld");
    assert_eq!(deferred.defer(c.block_hash(), "dup", t0, t0), Some("dup"), "one per id");
    assert!(deferred.settle(&core.take_orphan_events()).is_empty(), "nothing connected yet");
    // The parent arrives: the drain connects c; its frame is released.
    assert!(matches!(pulled(&mut core, &x, &p), BlockOutcome::Processed { result: Ok(_), .. }));
    assert_eq!(deferred.settle(&core.take_orphan_events()), vec![("frame-c", OrphanFate::Accepted)]);
    // A frame whose orphan left the pool, and an expired one: Ignore.
    let gone = [0x55; 32];
    assert_eq!(deferred.defer(gone, "frame-gone", t0, t0), None);
    let late = [0x66; 32];
    assert_eq!(deferred.defer(late, "frame-late", t0, t0), None);
    let pruned = deferred.prune(|h| *h == late, t0);
    assert_eq!(pruned, vec!["frame-gone"]);
    let pruned = deferred.prune(|_| true, t0 + ingress::DEFERRED_BLOCK_VERDICT_TTL);
    assert_eq!(pruned, vec!["frame-late"]);
    assert_eq!(deferred.defer([1; 32], "too-old", t0, t0 + ingress::DEFERRED_BLOCK_VERDICT_TTL), Some("too-old"));
}

// ═════════════════════════════════════════════════════════════════════════════
// POW-4: the orphan floor gate in handle_block
// ═════════════════════════════════════════════════════════════════════════════

/// POW-4 residual: the floor gate in `handle_block` had no test that fails
/// when it is removed (under `test-pow-limit` the clock-derived floor IS the
/// pow limit; the helper tests checked only the helpers). With a stricter
/// reference injected through the test seam (`with_reference_target`: the
/// genesis target, i.e. a network at launch difficulty), an orphan with
/// pow-limit bits is dropped as `OrphanBelowFloor` BEFORE its proof is
/// evaluated — without the gate its proof would be evaluated (and, at the
/// pow limit, almost surely valid: the orphan would be `Buffered`). An
/// orphan at the genesis target (honest difficulty) passes the floor and its
/// proof is evaluated (a failing nonce: `Invalid`). The IBD evidence uses
/// the same reference.
#[test]
fn pow4_floor_gate_refuses_before_the_proof() {
    let genesis = mk_genesis(unix_now() - 50_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let honest = b.chain(gh, 20, "h");
    let x = node_on(&genesis, &honest);
    let reference = core::bits_to_target(core::GENESIS_BITS);
    let mut core = BlockIngress::new().with_minimum_chain_work(0).with_reference_target(reference);
    let parent = b.empty(vec![honest.last().unwrap().block_hash()], "missing-parent");
    let cheap = b.unmarked(vec![parent.block_hash()], "cheap-orphan", None);
    assert_eq!(cheap.header.bits, core::POW_LIMIT_BITS);
    assert!(matches!(gossip(&mut core, &x, &cheap), BlockOutcome::Dropped(DropReason::OrphanBelowFloor)));
    let mut honest_bits = b.raw(vec![parent.block_hash()], vec![coinbase("hb", 1, vec![0xC2; 20])], None, false);
    honest_bits.header.bits = core::GENESIS_BITS;
    while honest_bits.validate_pow() {
        honest_bits.header.nonce += 1;
    }
    match gossip(&mut core, &x, &honest_bits) {
        BlockOutcome::Invalid(e) => assert_eq!(e, "invalid PoW", "the floor passed; the proof was evaluated"),
        other => panic!("{other:?}"),
    }
    assert!(core.orphans.is_empty());
}

/// POW-4 residual (re-audit: "eviction in arrival order within the global
/// loop is unguarded — no test reaches the global bound before the per-peer
/// bound"): three peers, each well inside its own quota, fill the GLOBAL
/// bound; the next orphan evicts the oldest arrival, not the one claiming
/// the lowest (or highest) height, and never another peer's newer orphans.
#[test]
fn pow4_global_orphan_bound_evicts_by_arrival_not_height() {
    let limits = OrphanLimits { max_entries: 3, max_bytes: 1 << 20, max_entries_per_peer: 3, max_bytes_per_peer: 1 << 20 };
    let mut pool = ingress::OrphanPool::new(limits);
    let genesis = mk_genesis(unix_now() - 50_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let missing = b.empty(vec![gh], "missing");
    let mh = missing.block_hash();
    let peers = [PeerId::random(), PeerId::random(), PeerId::random(), PeerId::random()];
    let claimed = [7u64, 1, 1_000_000, 3];
    let mut ids = Vec::new();
    for (i, (peer, height)) in peers.iter().zip(claimed).enumerate() {
        let o = b.unmarked(vec![mh], &format!("o{i}"), None);
        let id = o.block_hash();
        let r = pool.insert(id, o, height, 100, Some(*peer), false, &[mh]);
        match (i, r) {
            (0..=2, ingress::OrphanInsert::Inserted { evicted }) => assert!(evicted.is_empty()),
            (3, ingress::OrphanInsert::Inserted { evicted }) => {
                assert_eq!(evicted, vec![ids[0]], "the oldest arrival goes first, whatever the heights claimed")
            }
            (_, other) => panic!("insert {i}: {other:?}"),
        }
        ids.push(id);
    }
    assert!(!pool.contains(&ids[0]));
    assert!(ids[1..].iter().all(|id| pool.contains(id)), "the newer orphans of the other peers stay");
}

// ═════════════════════════════════════════════════════════════════════════════
// NET-2 residual: the proof of work off the processor, under budgets
// ═════════════════════════════════════════════════════════════════════════════

/// A gate that records which blocks' proofs were asked for, and answers
/// from a fixed map (else `Deferred`).
struct RecordingGate {
    asked: Vec<[u8; 32]>,
    known: std::collections::HashMap<[u8; 32], bool>,
}

impl PowGate for RecordingGate {
    fn check(&mut self, _b: &Block, hash: &[u8; 32]) -> PowCheck {
        self.asked.push(*hash);
        match self.known.get(hash) {
            Some(true) => PowCheck::Valid,
            Some(false) => PowCheck::Invalid,
            None => PowCheck::Deferred,
        }
    }
}

/// NET-2 residual: the proof is asked for only after every cheap check —
/// a block with wrong bits, a wrong header height or a timestamp before its
/// parent is refused by `accept_block`'s own pre-proof checks without the
/// gate being asked — and a block that passes them is handed back
/// (`Gated::PowPending`) instead of being evaluated on the caller's task;
/// resubmitted with the result, it completes (`Processed`, the proof error
/// for a garbage proof).
#[test]
fn net2_the_proof_is_deferred_and_asked_for_only_after_the_cheap_checks() {
    let genesis = mk_genesis(unix_now() - 50_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let honest = b.chain(gh, 20, "h");
    let x = node_on(&genesis, &honest);
    let tip = honest.last().unwrap().block_hash();
    let mut core = BlockIngress::new().with_minimum_chain_work(0);
    let mut gate = RecordingGate { asked: Vec::new(), known: Default::default() };
    let go = |core: &mut BlockIngress, gate: &mut RecordingGate, blk: &Block| {
        core.handle_block_gated(blk.clone(), blk.block_hash(), 1_000, Some(PeerId::random()), true,
            Instant::now(), unix_now(), &ctx(&x), gate)
    };
    let mut wrong_bits = b.unmarked(vec![tip], "wrong-bits", None);
    wrong_bits.header.bits = core::GENESIS_BITS;
    let mut wrong_height = b.unmarked(vec![tip], "wrong-height", None);
    wrong_height.height += 1;
    let early = b.unmarked(vec![tip], "early", Some(1));
    for (blk, err) in [(&wrong_bits, "invalid difficulty"), (&wrong_height, "invalid height"), (&early, "timestamp rejected")] {
        match go(&mut core, &mut gate, blk) {
            Gated::Done(BlockOutcome::Processed { result: Err(e), .. }) => assert!(e.starts_with(err), "{e}"),
            other => panic!("{other:?}"),
        }
    }
    assert!(gate.asked.is_empty(), "no proof asked for a block that fails a cheap check");
    let junk = b.unmarked(vec![tip], "junk-nonce", None);
    let pending = match go(&mut core, &mut gate, &junk) {
        Gated::PowPending(blk) => *blk,
        other => panic!("{other:?}"),
    };
    assert_eq!(gate.asked, vec![junk.block_hash()]);
    assert!(!x.dag.read().has_block(&junk.block_hash()));
    gate.known.insert(junk.block_hash(), false);
    match go(&mut core, &mut gate, &pending) {
        Gated::Done(BlockOutcome::Processed { result: Err(e), .. }) => {
            assert_eq!(ingress::verdict_for_accept_error(&e), GossipVerdict::Reject, "{e}");
            assert_eq!(ingress::accept_error_fault(&e), BlockFault::ContextFree);
        }
        other => panic!("{other:?}"),
    }
}

fn group_of(a: u8, b: u8) -> Option<gnb::network::discourage::NetGroup> {
    Some(gnb::network::discourage::net_group(format!("{a}.{b}.7.9").parse().unwrap()))
}

/// NET-2 residual: the audit measured about three zero-cost invalid blocks
/// per libp2p identity forcing a 64 MiB evaluation each, with identities
/// free. Now every evaluation is charged to the delivering peer AND to its
/// network group (/16), refunded only for a valid proof: 50 fresh
/// identities in one /16, three junk blocks each (150 frames), get at most
/// the group budget evaluated; an honest peer in another group, whose valid
/// blocks are refunded, is never refused; at most `workers` evaluations run
/// at once, and a gossip job that waited past gossipsub's cache is answered
/// `Ignore` unevaluated.
#[test]
fn net2_evaluations_are_budgeted_per_peer_and_network_group() {
    let limits = PowLimits {
        workers: 2, max_queued: 64, max_queued_per_peer: 4, max_queued_per_group: 8, max_queued_solicited: 64,
        peer_burst: 4, peer_refill_per_sec: 0.0, group_burst: 8, group_refill_per_sec: 0.0,
        verdict_ttl: Duration::from_secs(10), results_cap: 4_096,
    };
    let mut s: PowScheduler<u32> = PowScheduler::new(limits);
    let t0 = Instant::now();
    let mut evaluated = 0u32;
    let mut n = 0u32;
    let run_all = |s: &mut PowScheduler<u32>, valid: bool, evaluated: &mut u32| loop {
        match s.start_next(t0) {
            StartNext::Start(j) => {
                assert!(s.in_flight() <= 2);
                *evaluated += 1;
                s.complete(j.outcome(valid), t0);
            }
            StartNext::Expired(_) => panic!("not stale"),
            StartNext::Idle => break,
        }
    };
    for _identity in 0..50 {
        let source = PowSource { peer: Some(PeerId::random()), group: group_of(45, 77) };
        for _ in 0..3 {
            n += 1;
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&n.to_le_bytes());
            let _ = s.submit(PowJob { id, height: 1, source, solicited: false, received_at: t0, payload: n }, t0);
            run_all(&mut s, false, &mut evaluated);
        }
    }
    assert_eq!(evaluated, 8, "150 junk frames from one /16: the group budget, not 150 evaluations");
    // An honest peer elsewhere: 20 valid blocks, all evaluated, never refused.
    let honest = PowSource { peer: Some(PeerId::random()), group: group_of(80, 1) };
    for i in 0..20u32 {
        let mut id = [0xEE; 32];
        id[..4].copy_from_slice(&i.to_le_bytes());
        s.submit(PowJob { id, height: 1, source: honest, solicited: false, received_at: t0, payload: i }, t0)
            .expect("valid proofs are refunded");
        run_all(&mut s, true, &mut evaluated);
    }
    // A stale gossip job is not evaluated.
    let other = PowSource { peer: Some(PeerId::random()), group: group_of(90, 2) };
    s.submit(PowJob { id: [0xAA; 32], height: 1, source: other, solicited: false, received_at: t0, payload: 0 }, t0).unwrap();
    assert!(matches!(s.start_next(t0 + Duration::from_secs(11)), StartNext::Expired(_)));
    assert_eq!(s.submit(PowJob { id: [0xAB; 32], height: 1, source: PowSource { peer: Some(PeerId::random()), group: group_of(45, 77) },
        solicited: false, received_at: t0, payload: 0 }, t0).unwrap_err().0, PowRefusal::GroupBudget);
}

/// NET-2 (review finding): an orphan below the floor is charged to a
/// gossip deliverer's budget and, if it authored the frame, treated as
/// misbehaving; an answer to this node's own pull (which the processor
/// treats as authored by its sender) is only dropped — the floor depends on
/// this node's tip and clock, and the node asked for the block. Pre-fix the
/// processor applied the gossip penalty to pull answers too, disconnecting
/// and discouraging an honest sync peer for 24 h.
#[test]
fn net2_floor_failure_penalises_gossip_authors_never_pull_answers() {
    use GossipVerdict::*;
    let p = |gossip, misbehaving| BlockPenalty { gossip, misbehaving };
    let a = PeerId::random();
    let r = PeerId::random();
    let gossip_from = |author: PeerId, via: PeerId| gnb::network::InboundOrigin::Gossip {
        propagation_source: via, author: Some(author), pending: None, received_at: Instant::now(),
    };
    let pull = gnb::network::InboundOrigin::Directed { peer: a };
    assert!(gossip_from(a, a).delivered_by_author());
    assert!(!gossip_from(a, r).delivered_by_author());
    assert!(pull.delivered_by_author());
    assert!(!gnb::network::InboundOrigin::Local.delivered_by_author());
    for in_force in [false, true] {
        for origin in [gossip_from(a, a), gossip_from(a, r), pull.clone()] {
            let (pen, charge) = ingress::orphan_floor_penalty(origin.is_solicited(), origin.delivered_by_author(), in_force);
            if origin.is_solicited() {
                assert_eq!((pen, charge), (p(Ignore, false), false), "a pull answer is only dropped");
            } else {
                assert!(charge, "gossip is charged to the budget");
                assert_eq!(pen, p(Ignore, origin.delivered_by_author()), "never Reject: a contextual fault");
            }
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// B1-T7 / NET-4: who a refused block frame is charged to
// ═════════════════════════════════════════════════════════════════════════════

/// B1-T7: the penalty table. A frame the deliverer authored is always
/// charged to it, as a misbehaviour with `Ignore` to gossipsub (no relay
/// that sent a duplicate is charged); a relayed frame only for a
/// context-free fault once the activation block is on the chain (P4,
/// `Reject`); never for a contextual fault (an older release relays orphans
/// before it knows their parents) — and never before the activation (an
/// older release relays every frame unvalidated). Pre-fix every `Reject`
/// was charged to the delivering relay (the re-audit reproduced that live;
/// `fix_ingress_live::live_legacy_relay_is_not_graylisted_for_forwarding_invalid_blocks`
/// checks the fixed behaviour with a stand-in validator that calls
/// `block_penalty`, not the node's processor).
#[test]
fn b1t7_block_penalty_follows_the_author_and_the_rollout() {
    use BlockFault::*;
    use GossipVerdict::*;
    let p = |gossip, misbehaving| BlockPenalty { gossip, misbehaving };
    for in_force in [false, true] {
        assert_eq!(ingress::block_penalty(Reject, ContextFree, true, in_force),
            if in_force { p(Reject, true) } else { p(Ignore, true) });
        assert_eq!(ingress::block_penalty(Reject, Context, true, in_force), p(Ignore, true));
        assert_eq!(ingress::block_penalty(Reject, Context, false, in_force), p(Ignore, false));
        assert_eq!(ingress::block_penalty(Accept, ContextFree, true, in_force), p(Accept, false));
        assert_eq!(ingress::block_penalty(Ignore, ContextFree, true, in_force), p(Ignore, false));
    }
    assert_eq!(ingress::block_penalty(Reject, ContextFree, false, false), p(Ignore, false));
    assert_eq!(ingress::block_penalty(Reject, ContextFree, false, true), p(Reject, true));
    // In force from the activation block on (the tx relay's gate, next block
    // after the activation).
    let mainnet = core::activation::MAINNET_HARDENING_ACTIVATION_HEIGHT;
    assert!(!ingress::block_penalties_in_force(mainnet - 2, mainnet));
    assert!(ingress::block_penalties_in_force(mainnet, mainnet));
    assert!(!ingress::block_penalties_in_force(u64::MAX, core::activation::NEVER));
    assert_eq!(ingress::accept_error_fault("consensus rejection: invalid GnB-SMH proof of work"), ContextFree);
    assert_eq!(ingress::accept_error_fault("invalid difficulty: block bits 0x1 != expected 0x2"), Context);
    // Wire violations: charged to the author, `Reject` (P4) only in force.
    use gnb::network::wire_violation_penalty;
    assert_eq!(wire_violation_penalty(true, false), (true, false));
    assert_eq!(wire_violation_penalty(false, false), (false, false));
    assert_eq!(wire_violation_penalty(false, true), (true, true));
}

/// NET-4 residual: a peer the bounded wire tracker forgets to make room is
/// reported for an application-score reset (it used to keep its last
/// gossipsub score forever).
#[test]
fn net4_evicted_tracker_entries_are_reported_for_reset() {
    use gnb::network::{WirePenaltyTracker, WIRE_PENALTY_TRACK_CAP};
    let mut t = WirePenaltyTracker::new();
    let now = Instant::now();
    let mild = PeerId::random();
    t.record_violation_at(mild, now);
    for _ in 0..WIRE_PENALTY_TRACK_CAP {
        let p = PeerId::random();
        t.record_violation_at(p, now);
        t.record_violation_at(p, now);
    }
    let evicted = t.take_evicted();
    assert!(evicted.contains(&mild), "the mildest entry was evicted and is reported");
    assert!(t.take_evicted().is_empty(), "reported once");
    assert!(t.score_of(&mild).is_none());
    // The gate: a relayed violation (here: a padded frame) before the
    // activation is refused but not recorded against the relay.
    let mut frame = bincode::serde::encode_to_vec(&gnb::network::NetworkMessage::VersionAck, bincode::config::standard())
        .unwrap();
    frame.push(0);
    let q = PeerId::random();
    assert!(matches!(t.classify_gated(q, &frame, false), gnb::network::WireReaction::IgnoreMalformed(_)));
    assert!(t.score_of(&q).is_none());
    assert!(matches!(t.classify_gated(q, &frame, true), gnb::network::WireReaction::Penalize { .. }));
    assert!(t.score_of(&q).is_some());
}

// ═════════════════════════════════════════════════════════════════════════════
// B1-T19: the transaction verification budget
// ═════════════════════════════════════════════════════════════════════════════

/// A funded node and `n` distinct 1-input transactions of ~399 kB (13,450
/// pubkey-hash outputs: this chain admits only its two output kinds,
/// `core::policy::output_kind`, before any signature is checked — the merge
/// of the mainnet line refused the 9,999-byte scripts this fixture used, so
/// those frames never reached the signature step) with a corrupted
/// signature.
fn big_junk(n: usize) -> (Node, Vec<Transaction>) {
    let genesis = mk_genesis(unix_now() - 10_000);
    let k = key();
    let funds: Vec<_> = (0..n as u32).map(|i| {
        let mut t = [0x90u8; 32];
        t[..4].copy_from_slice(&i.to_le_bytes());
        (t, 0u32, out(10_000_000_000, &k.spk))
    }).collect();
    let node = node_with(&genesis, &funds);
    let txs = funds.iter().enumerate().map(|(i, f)| {
        let outputs: Vec<_> = (0..13_450u32).map(|j| {
            let mut spk = [0u8; core::policy::PKH_SPK_LEN];
            spk[..4].copy_from_slice(&j.to_le_bytes());
            spk[4] = i as u8;
            out(1_000, &spk)
        }).collect();
        let mut tx = signed_spend(&k, &[(f.0, 0)], outputs);
        tx.inputs[0].script_sig[10] ^= 0xFF;
        tx
    }).collect();
    (node, txs)
}

/// B1-T19: a 1-input transaction carrying ~390 kB of outputs cost ONE token
/// while every input's sighash v2 re-encodes and hashes the whole
/// transaction (and the frame's decoding and three wtxid hashes ran free):
/// a 400-token burst bought 400 such frames (the engineer's measurement
/// on the unmodified code: "100 of 100 frames of 398782 bytes reached
/// signature verification"; not revert-checked). The gate is now priced in signatures AND bytes hashed,
/// and the frame's decoding is charged first: the same burst buys
/// `400 / (frame + gate)` of them.
#[test]
fn b1t19_gate_is_priced_in_bytes_hashed() {
    let (n, txs) = big_junk(100);
    let next = admission::next_block_height(&n.dag.read());
    let mut relay = TxRelay::with_limits(400, 0.0, TxOrphanLimits::default()).with_node_budget(1_000_000, 0.0);
    let peer = Some(PeerId::random());
    let wire = txs[0].to_wire_bytes(true).len();
    let act = core::activation::hardening_activation_height();
    let per_frame = relay::frame_cost(wire) + relay::signature_gate_cost(&txs[0], wire, next, act);
    assert_eq!(relay::signature_gate_cost(&txs[0], wire, next, act), 1 + wire.div_ceil(relay::SIG_BUDGET_BYTES_PER_TOKEN),
        "v2: one signature + one whole-transaction hash per input");
    let mut verified = 0usize;
    for tx in &txs {
        let o = relay.on_gossip_tx(&n.store, &n.mempool, next, &tx.txid(), &tx.to_wire_bytes(true), peer,
            Instant::now(), unix_now());
        assert_ne!(o.verdict, GossipVerdict::Accept, "{}", o.detail);
        if o.invalid {
            verified += 1;
        } else {
            assert!(o.detail.contains("budget"), "{}", o.detail);
        }
    }
    println!("{verified} of 100 frames of {wire} bytes reached signature verification ({per_frame} tokens each)");
    assert_eq!(verified, 400 / per_frame);
    assert!(verified <= 30);
    // Under sighash v3 (at/after the activation) the digests are linear.
    let v3 = relay::signature_gate_cost(&txs[0], wire, 10, 0);
    assert_eq!(v3, 1 + (wire + relay::V3_PER_INPUT_PREIMAGE_BYTES).div_ceil(relay::SIG_BUDGET_BYTES_PER_TOKEN));
    let ten_inputs = Transaction { inputs: vec![txs[0].inputs[0].clone(); 10], ..txs[0].clone() };
    assert_eq!(relay::signature_gate_cost(&ten_inputs, wire, next, act),
        10 + (10 * wire).div_ceil(relay::SIG_BUDGET_BYTES_PER_TOKEN), "v2: inputs x size");
}

/// Audit F5: the gate charged one token per INPUT, but an input spending a
/// policy output carries up to `MAX_POLICY_KEYS` (7) hybrid signatures, each
/// verified: a 7-of-7 spend bought 7 verifications for the price of one.
/// The gate now counts the policy witness's signatures (decoded, not
/// verified). Frames of 1-input 7-of-7 spends, each with a matching policy
/// and junk signatures, through the real relay: the burst buys
/// `400 / (frame + 7 + bytes)` of them (pre-fix `400 / (frame + 1 + bytes)`).
#[test]
fn f5_gate_counts_every_policy_signature() {
    use gnb::core::policy::{PolicyWitness, SpendPolicy, MAX_POLICY_KEYS};
    let genesis = mk_genesis(unix_now() - 10_000);
    let keys: Vec<Vec<u8>> = (0..MAX_POLICY_KEYS).map(|_| key().pk).collect();
    let m = MAX_POLICY_KEYS as u8;
    let policy = SpendPolicy::new(m, keys, 0, 0).unwrap();
    let funds: Vec<_> = (0..60u32).map(|i| {
        let mut t = [0x91u8; 32];
        t[..4].copy_from_slice(&i.to_le_bytes());
        (t, 0u32, out(10_000_000_000, &policy.script_pubkey()))
    }).collect();
    let n = node_with(&genesis, &funds);
    let witness = |sigs: u8| PolicyWitness {
        policy: policy.clone(),
        signatures: (0..sigs).map(|i| (i, vec![0x5A; 64])).collect(),
    }.encode();
    let txs: Vec<Transaction> = funds.iter().map(|f| Transaction {
        version: 1,
        inputs: vec![core::TxInput { prev_txid: f.0, prev_index: 0, script_sig: witness(m), sequence: u32::MAX }],
        outputs: vec![out(9_000_000_000, &[0x12; 20])],
        locktime: 0,
    }).collect();
    let next = admission::next_block_height(&n.dag.read());
    let act = core::activation::hardening_activation_height();
    let wire = txs[0].to_wire_bytes(true).len();
    let bytes = wire.div_ceil(relay::SIG_BUDGET_BYTES_PER_TOKEN);
    assert_eq!(relay::signature_gate_cost(&txs[0], wire, next, act), MAX_POLICY_KEYS + bytes);
    assert_eq!(relay::input_signature_count(&witness(m)), MAX_POLICY_KEYS);
    // A key-hash witness, or bytes that are no policy witness, count one.
    let k = key();
    let kh = signed_spend(&k, &[([1; 32], 0)], vec![out(1_000, &[2; 20])]);
    assert_eq!(relay::input_signature_count(&kh.inputs[0].script_sig), 1);
    assert_eq!(relay::input_signature_count(&[]), 1);
    let two = Transaction { inputs: vec![txs[0].inputs[0].clone(), kh.inputs[0].clone()], ..txs[0].clone() };
    assert_eq!(relay::signature_gate_cost(&two, wire, next, act), MAX_POLICY_KEYS + 1 + (2 * wire).div_ceil(relay::SIG_BUDGET_BYTES_PER_TOKEN));

    let per_frame = relay::frame_cost(wire) + relay::signature_gate_cost(&txs[0], wire, next, act);
    let mut relay = TxRelay::with_limits(400, 0.0, TxOrphanLimits::default()).with_node_budget(1_000_000, 0.0);
    let peer = Some(libp2p::PeerId::random());
    let mut verified = 0usize;
    for tx in &txs {
        let o = relay.on_gossip_tx(&n.store, &n.mempool, next, &tx.txid(), &tx.to_wire_bytes(true), peer,
            Instant::now(), unix_now());
        assert_ne!(o.verdict, GossipVerdict::Accept, "{}", o.detail);
        if o.invalid {
            assert!(o.detail.contains("signature"), "{}", o.detail);
            verified += 1;
        } else {
            assert!(o.detail.contains("budget"), "{}", o.detail);
        }
    }
    assert_eq!(verified, 400 / per_frame, "{per_frame} tokens a frame");
    assert!(verified < 400 / (relay::frame_cost(wire) + 1 + bytes), "fewer than when an input cost one token");
}

/// B1-T19: the per-connection budget alone let every inbound connection
/// spend a full burst at once; a node-wide budget now bounds them together.
/// 20 connections, each with a fresh 400-token burst, share a node-wide
/// burst of 120 tokens.
#[test]
fn b1t19_node_wide_budget_bounds_every_connection_together() {
    let (n, txs) = big_junk(60);
    let next = admission::next_block_height(&n.dag.read());
    let mut relay = TxRelay::with_limits(400, 0.0, TxOrphanLimits::default()).with_node_budget(120, 0.0);
    let wire = txs[0].to_wire_bytes(true).len();
    let act = core::activation::hardening_activation_height();
    let per_frame = relay::frame_cost(wire) + relay::signature_gate_cost(&txs[0], wire, next, act);
    let mut verified = 0usize;
    for (i, tx) in txs.iter().enumerate() {
        let peer = Some(PeerId::random());
        let _ = i;
        let o = relay.on_gossip_tx(&n.store, &n.mempool, next, &tx.txid(), &tx.to_wire_bytes(true), peer,
            Instant::now(), unix_now());
        if o.invalid {
            verified += 1;
        }
    }
    assert_eq!(verified, 120 / per_frame, "the node-wide budget, not 60 connections' bursts");
}

/// B1-T19: the wtxid is computed once per frame, from the frame's bytes —
/// which must be the canonical encoding byte for byte.
#[test]
fn b1t19_wtxid_from_the_canonical_frame() {
    let (_n, txs) = big_junk(1);
    let tx = &txs[0];
    let bytes = tx.to_wire_bytes(true);
    let decoded = admission::decode_tx_canonical(&bytes).expect("canonical");
    assert_eq!(admission::wtxid_of_canonical_bytes(&bytes), admission::wtxid(&decoded));
    assert_eq!(admission::wtxid(&decoded), admission::wtxid(tx));
    let mut padded = bytes.clone();
    padded.push(0);
    assert!(admission::decode_tx_canonical(&padded).is_err());
}
