//! PoWit audit (PR head 4293747), finding 3, node-local mitigation: the
//! finality pin (`GhostDAG::set_finalized`) is set or advanced only while the
//! chain that carries the finalizing PoWit state has at least the node's
//! minimum chain work (Bitcoin Core's `nMinimumChainWork`:
//! `ingress::minimum_chain_work()`, i.e. `core::MIN_CHAIN_WORK` or
//! `--minimumchainwork`), after each acceptance, per committed chunk of a
//! chain move, and when start-up restores the pin.
//!
//! The attack: a cheap fork with its own witness set (its W comes from its
//! own shares) finalizes a checkpoint; a node that syncs it while eclipsed
//! pinned it, and the heavier honest chain then conflicted with the pin
//! forever. Below the minimum chain work the node now keeps switching to
//! the most work, as Bitcoin Core does during initial block download.
//!
//! Every block goes through the REAL acceptance pipeline; PoWit states are
//! synthetic (below the PoWit activation acceptance computes none), as in
//! `fix_chain_move_bounds.rs`. The minimum chain work is process-wide, set
//! once by the single test of this binary.

mod fix_common;
use fix_common::*;

use gnb::consensus::{BlockHash, GhostDAG};
use gnb::core::{self, Block, BlockHeader, MerkleRoot, Transaction};
use gnb::ingress;
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

    fn block(&mut self, parent: BlockHash, txs: Vec<Transaction>) -> Block {
        let pd = self.dag.get_block_data(&parent).expect("parent built").clone();
        let height = pd.height + 1;
        let bits = pow::expected_bits(pd.timestamp, height).unwrap();
        let mut b = Block {
            header: BlockHeader {
                version: 1, parents: vec![parent], merkle_root: MerkleRoot::ZERO,
                timestamp: pd.timestamp + 1, bits, nonce: 0,
            },
            transactions: txs,
            blue_score: height,
            height,
            shielded_transactions: Vec::new(),
            powit: Default::default(),
        };
        commit_block(&mut b);
        b.test_only_assume_pow_valid();
        self.dag.add_block(b.block_hash(), vec![parent], b.header.timestamp, pow::work_from_bits(bits))
            .expect("builder DAG accepts the block");
        b
    }

    fn chain(&mut self, from: BlockHash, n: usize, tag: &str) -> Vec<Block> {
        let mut out: Vec<Block> = Vec::with_capacity(n);
        let mut p = from;
        for i in 0..n {
            let h = self.dag.get_block_data(&p).unwrap().height + 1;
            let cb = coinbase(&format!("{tag}{i}"), core::tokenomics::block_subsidy_sat(h), vec![0xC0; 20]);
            let b = self.block(p, vec![cb]);
            p = b.block_hash();
            out.push(b);
        }
        out
    }

    fn work(&self, h: &BlockHash) -> u128 {
        self.dag.get_block_data(h).unwrap().blue_work
    }
}

/// A PoWit state whose witness set has finalized `cp` (slot 6, beyond the
/// activation checkpoint at slot 1, so it pins fork choice).
fn state_finalizing(cp: BlockHash) -> core::powit::PowitState {
    let mut st = core::powit::PowitState::genesis(1, cp);
    st.finalized = core::powit::Checkpoint { height: 6, hash: cp };
    st.justified = st.finalized;
    st
}

fn deliver_all(n: &Node, blocks: &[Block]) {
    for b in blocks {
        accept(n, b).unwrap_or_else(|e| panic!("block h={} refused: {e}", b.height));
    }
}

/// F: a 12-block fork whose own witness set finalized F[3] from F[6] on,
/// below the minimum chain work. H: the honest 40-block chain, whose
/// witness set finalized H[5] from H[20] on; the minimum chain work is H[29]'s.
#[test]
fn a_low_work_fork_never_pins_finality_and_the_honest_chain_still_does() {
    let genesis = mk_genesis(unix_now() - 100_000);
    let gh = genesis.block_hash();
    let mut b = Builder::new(&genesis);
    let fork = b.chain(gh, 12, "f");
    let honest = b.chain(gh, 40, "h");
    let min_work = b.work(&honest[29].block_hash());
    assert!(b.work(&fork[11].block_hash()) < min_work);
    ingress::set_minimum_chain_work(min_work).expect("set once, by this binary's only test");
    assert_eq!(ingress::minimum_chain_work(), min_work);

    let mut n = node_with(&genesis, &[]);
    for blk in &fork[6..] {
        gnb::powit::save_state(&n.store, &blk.block_hash(), &state_finalizing(fork[3].block_hash())).unwrap();
    }
    for blk in &honest[20..] {
        gnb::powit::save_state(&n.store, &blk.block_hash(), &state_finalizing(honest[5].block_hash())).unwrap();
    }

    // Eclipsed: the node sees only the cheap fork.
    deliver_all(&n, &fork);
    assert_eq!(applied_tip(&n), Some(fork[11].block_hash()));
    assert_eq!(n.dag.read().finalized(), None, "a chain below the minimum chain work pins nothing");
    restart(&mut n);
    assert_eq!(n.dag.read().finalized(), None, "nor does start-up restore a pin from it");

    // The honest chain arrives: the node moves to it, and pins its finality
    // once its work reaches the minimum.
    for (i, blk) in honest.iter().enumerate() {
        accept(&n, blk).unwrap_or_else(|e| panic!("H[{i}] refused: {e}"));
        let pinned = n.dag.read().finalized();
        if i < 29 {
            assert_eq!(pinned, None, "H[{i}] is below the minimum chain work");
        } else {
            assert_eq!(pinned, Some((honest[5].block_hash(), 6)), "H[{i}] reached the minimum chain work");
        }
    }
    assert_eq!(applied_tip(&n), Some(honest[39].block_hash()), "the most work wins");
    restart(&mut n);
    assert_eq!(n.dag.read().finalized(), Some((honest[5].block_hash(), 6)), "restored above the minimum");
    assert_eq!(applied_tip(&n), Some(honest[39].block_hash()));
}
