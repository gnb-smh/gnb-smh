//! Re-audit B1-T0 / B2-T8 and the POW-8 challenge: the wire `blue_score` is
//! not committed by the block id.
//!
//! * Below the hardening activation the audit's block-size limit measured
//!   the bincode encoding with the `blue_score` AS RECEIVED, while the node
//!   stores and serves the block with the value derived from its parents. A
//!   block of exactly 1,000,000 bincode bytes gossiped with `blue_score` 0
//!   was accepted by every online node and refused ("block too large") by
//!   every node that later received the stored copy (a 3-byte varint once
//!   blue scores pass 250): a permanent split. This chain measures the wire
//!   encoding at every height (`core::block_rules::legacy_block_size` below
//!   the activation, `Block::size_bytes`), whose header writes `blue_score`
//!   as a fixed-width u64: every copy of a block id measures the same.
//! * `accept_block` itself stores the derived `blue_score`, whichever path
//!   called it (gossip, directed sync, orphan drain, body restore,
//!   `submitblock`, the miner), so no stored or served body carries a
//!   peer-chosen value. The gossip path with known parents had no test.
//!
//! Every block goes through the real ingress core
//! (`ingress::BlockIngress::handle_block`) or `accept::accept_block`. Proofs
//! of work are recorded as verified in the process-wide cache
//! (`Block::test_only_assume_pow_valid`, dev-only `test-pow-limit`). The
//! ingress cores run with no minimum chain work (`with_minimum_chain_work(0)`):
//! these chains are far below mainnet's, the default in this binary, and
//! the gossip paths tested here are those of a node out of initial block
//! download.

mod fix_common;
use fix_common::*;

use gnb::consensus::BlockHash;
use gnb::core::{self, Block, BlockHeader, MerkleRoot, Transaction};
use gnb::ingress::{self, BlockIngress, BlockOutcome};
use gnb::pow;

/// A block on `parents` (known to `n`) with the header height, bits and
/// timestamp the rules require, the coinbase commitment and root of its
/// height, and `blue_score` as given; its proof is recorded as verified.
fn block_on(n: &Node, parents: Vec<BlockHash>, txs: Vec<Transaction>, blue_score: u64) -> Block {
    let (height, pts) = {
        let d = n.dag.read();
        let h = parents.iter().map(|p| d.get_block_data(p).unwrap().height).max().unwrap() + 1;
        let ts = parents.iter().map(|p| d.get_block_data(p).unwrap().timestamp).max().unwrap();
        (h, ts)
    };
    let mut b = Block {
        header: BlockHeader {
            version: 1,
            parents,
            merkle_root: MerkleRoot::ZERO,
            timestamp: pts + 1,
            bits: pow::expected_bits(pts, height).unwrap(),
            nonce: 0,
        },
        transactions: txs,
        blue_score,
        height,
        shielded_transactions: Vec::new(),
        powit: Default::default(),
    };
    commit_block(&mut b);
    b.test_only_assume_pow_valid();
    b
}

fn ctx(n: &Node) -> ingress::AcceptCtx<'_> {
    ingress::AcceptCtx {
        dag: &n.dag, store: &n.store, mempool: &n.mempool, node_state: &n.node_state,
        tip_tx: Some(&n.tip_tx), shielded: &n.shielded,
    }
}

/// `b` through the ingress core: gossip (`solicited = false`) or the answer
/// to a directed pull (sync, parent fetch, body re-fetch).
fn deliver(core: &mut BlockIngress, n: &Node, b: &Block, solicited: bool) -> BlockOutcome {
    core.handle_block(b.clone(), b.block_hash(), b.to_wire_bytes().len(), None, solicited,
        std::time::Instant::now(), unix_now(), &ctx(n))
}

fn processed_ok(o: &BlockOutcome) -> bool {
    matches!(o, BlockOutcome::Processed { result: Ok(_), .. })
}

/// The bytes the node serves for `id` (directed sync answers are read from
/// storage), decoded as a receiver decodes them.
fn served(n: &Node, id: &BlockHash) -> Block {
    let stored = n.store.get_block(id).unwrap().expect("stored body");
    Block::from_wire_bytes(&stored.to_wire_bytes()).expect("canonical")
}

/// A block on `tip` (known to `n`) whose size under the rule below the
/// activation (the wire length, `legacy_block_size`) is exactly `target`:
/// one signed spend of `fund` (locked to `k`) with many 546-unit outputs (29
/// wire bytes each) and a change output, the coinbase padded to the exact
/// size; `blue_score` 0. Valid at connect time.
fn sized_block(n: &Node, tip: BlockHash, k: &Key, fund: &([u8; 32], u32, gnb::core::TxOutput), target: usize) -> Block {
    let height = n.dag.read().get_block_data(&tip).unwrap().height + 1;
    let fee = 5_000_000u64;
    let unit = out(core::DUST_THRESHOLD, &[0x7A; 20]);
    let filler = |n_out: usize| {
        let mut outs = vec![unit.clone(); n_out];
        outs.push(out(fund.2.value - fee - core::DUST_THRESHOLD * n_out as u64, &[0x7B; 20]));
        signed_spend(k, &[(fund.0, fund.1)], outs)
    };
    let build = |tx: &Transaction, pad: usize| -> Block {
        let mut cb = coinbase("big", core::tokenomics::block_subsidy_sat(height) + fee, vec![0xC2; 20]);
        cb.inputs[0].script_sig.extend(std::iter::repeat_n(0x20u8, pad));
        block_on(n, vec![tip], vec![cb, tx.clone()], 0)
    };
    let size0 = |b: &Block| core::block_rules::legacy_block_size(b);
    let mut n_out = (target - 2_000) / 29;
    loop {
        let tx = filler(n_out);
        let base = size0(&build(&tx, 0));
        if base > target {
            n_out -= (base - target) / 29 + 1;
            continue;
        }
        if target - base > 150 {
            n_out += (target - base - 100) / 29;
            continue;
        }
        if let Some(b) = (0..200).map(|p| build(&tx, p)).find(|b| size0(b) == target) {
            return b;
        }
        n_out -= 1;
    }
}

/// The finding's scenario, below the activation (mainnet schedule). A chain
/// long enough that the derived blue score would need a 3-byte bincode
/// varint (> 250, the audit's measure: 1,000,002 bytes with the derived
/// value for a block of 1,000,000 with 0), then a block of exactly
/// 1,000,000 bytes under this chain's measure (the wire length), gossiped
/// with `blue_score` 0. Node A takes it from gossip, stores it, and serves
/// the stored copy (derived blue score, the same 1,000,000 wire bytes); a
/// fresh node C that synced the same chain must accept the served copy (and
/// any other copy of the id), and both end on the same tip with the same
/// UTXO set. A block one byte over the limit is refused in every copy.
#[test]
fn block_accepted_from_gossip_and_served_from_storage_is_accepted_by_a_fresh_node() {
    let genesis = mk_genesis(unix_now() - 50_000);
    let gh = genesis.block_hash();
    let k = key();
    let fund_value = 1_000 * core::tokenomics::SAT_PER_GNB;
    let fund = ([0x5Eu8; 32], 0u32, out(fund_value, &k.spk));
    let a = node_with(&genesis, std::slice::from_ref(&fund));
    let c = node_with(&genesis, std::slice::from_ref(&fund));

    // 260 coinbase-only blocks, delivered to both nodes.
    let mut tip = gh;
    let mut chain = Vec::new();
    for i in 0..260u64 {
        let h = i + 1;
        let b = block_on(&a, vec![tip], vec![coinbase(&format!("w{i}"), core::tokenomics::block_subsidy_sat(h), vec![0xC0; 20])], h);
        accept(&a, &b).unwrap_or_else(|e| panic!("chain block {h}: {e}"));
        tip = b.block_hash();
        chain.push(b);
    }
    for b in &chain {
        accept(&c, b).unwrap();
    }
    let derived = a.dag.read().get_block_data(&tip).unwrap().blue_score + 1;
    assert!(derived > 250, "the derived blue score needs a 3-byte varint: {derived}");
    let height = chain.len() as u64 + 1;
    assert!(!core::block_rules::rules_active_at(height, core::activation::hardening_activation_height()),
        "below the hardening activation (mainnet schedule)");

    let x = sized_block(&a, tip, &k, &fund, core::MAX_BLOCK_SIZE);
    let id = x.block_hash();
    assert_eq!(x.blue_score, 0);
    assert_eq!(x.to_wire_bytes().len(), core::MAX_BLOCK_SIZE, "1,000,000 wire bytes as gossiped");
    let mut with_derived = x.clone();
    with_derived.blue_score = derived;
    assert_eq!(with_derived.block_hash(), id, "same block id");
    assert_eq!(core::block_rules::legacy_block_size(&with_derived), core::MAX_BLOCK_SIZE,
        "the same size with the derived value (a fixed-width field)");

    // A takes the gossiped copy, stores and serves the derived blue score.
    let mut core_a = BlockIngress::new().with_minimum_chain_work(0);
    let o = deliver(&mut core_a, &a, &x, false);
    assert!(processed_ok(&o), "gossiped copy: {o:?}");
    assert_eq!(applied_tip(&a), Some(id));
    let copy = served(&a, &id);
    assert_eq!(copy.blue_score, derived, "stored with the derived blue score, never the wire value");
    assert_eq!(copy.block_hash(), id);

    // C syncs it from A: the served copy is accepted.
    let mut core_c = BlockIngress::new().with_minimum_chain_work(0);
    let o = deliver(&mut core_c, &c, &copy, true);
    assert!(processed_ok(&o), "the copy every upgraded node serves must be accepted: {o:?}");
    assert_eq!(applied_tip(&c), Some(id));
    assert_eq!(c.store.utxo_set_digest().unwrap(), a.store.utxo_set_digest().unwrap());
    assert_eq!(served(&c, &id).to_wire_bytes(), copy.to_wire_bytes(), "both nodes serve the same bytes");

    // Any other copy of the id gets the same verdict (a fresh node each).
    for blue in [0u64, 251, 70_000, u64::MAX] {
        let v = node_with(&genesis, std::slice::from_ref(&fund));
        for b in &chain {
            accept(&v, b).unwrap();
        }
        let mut other = x.clone();
        other.blue_score = blue;
        let o = deliver(&mut BlockIngress::new().with_minimum_chain_work(0), &v, &other, true);
        assert!(processed_ok(&o), "blue_score {blue}: {o:?}");
        assert_eq!(served(&v, &id).blue_score, derived, "blue_score {blue}: stored derived");
    }

    // One byte over the limit with blue_score 0: refused in every copy.
    let over = sized_block(&a, tip, &k, &fund, core::MAX_BLOCK_SIZE + 1);
    for blue in [0u64, derived] {
        let mut o_copy = over.clone();
        o_copy.blue_score = blue;
        match deliver(&mut BlockIngress::new().with_minimum_chain_work(0), &c, &o_copy, false) {
            BlockOutcome::Invalid(e) => assert!(e.contains("block too large"), "{e}"),
            other => panic!("blue_score {blue}: {other:?}"),
        }
    }
}

/// POW-8 challenge (2): the main gossip / sync path for a block whose
/// parents are known stores the derived blue score. The fixture builders set
/// `blue_score = height`, which equals the derived value on a linear chain
/// and hid a missing normalization; here the wire values are forged.
#[test]
fn gossip_and_sync_paths_store_the_derived_blue_score() {
    let genesis = mk_genesis(unix_now() - 50_000);
    let gh = genesis.block_hash();
    let n = node_with(&genesis, &[]);
    let mut core = BlockIngress::new().with_minimum_chain_work(0);
    let mut tip = gh;
    for (i, (forged, solicited)) in [(0u64, false), (u64::MAX, true), (7, false), (1 << 40, true)].into_iter().enumerate() {
        let h = i as u64 + 1;
        let b = block_on(&n, vec![tip], vec![coinbase(&format!("g{i}"), core::tokenomics::block_subsidy_sat(h), vec![0xC0; 20])], forged);
        let o = deliver(&mut core, &n, &b, solicited);
        assert!(processed_ok(&o), "{o:?}");
        tip = b.block_hash();
        let want = n.dag.read().get_block_data(&tip).unwrap().blue_score;
        assert_eq!(want, h, "a linear chain");
        assert_eq!(n.store.get_block(&tip).unwrap().unwrap().blue_score, want, "forged {forged}");
    }
}

/// `accept_block` itself replaces the wire blue score, so a caller that does
/// not (an in-process producer, a test harness, a future ingress path) can
/// never store a peer-chosen value.
#[test]
fn accept_block_stores_the_derived_blue_score_whatever_the_caller() {
    let genesis = mk_genesis(unix_now() - 50_000);
    let gh = genesis.block_hash();
    let n = node_with(&genesis, &[]);
    let b1 = block_on(&n, vec![gh], vec![coinbase("a1", core::tokenomics::block_subsidy_sat(1), vec![0xC0; 20])], u64::MAX);
    accept(&n, &b1).unwrap();
    assert_eq!(n.store.get_block(&b1.block_hash()).unwrap().unwrap().blue_score, 1);
    // A merge of two tips: max parent blue score + 1.
    let b2 = block_on(&n, vec![gh], vec![coinbase("a2", core::tokenomics::block_subsidy_sat(1), vec![0xC1; 20])], 1);
    accept(&n, &b2).unwrap();
    let m = block_on(&n, vec![b1.block_hash(), b2.block_hash()],
        vec![coinbase("m", core::tokenomics::block_subsidy_sat(2), vec![0xC2; 20])], 0);
    accept(&n, &m).unwrap();
    assert_eq!(n.store.get_block(&m.block_hash()).unwrap().unwrap().blue_score, 2);
}

/// `accept_block` checks the block-size rule of the VERIFIED height itself:
/// an in-process caller that skips `validate_structure` (the miner, a test
/// harness, a future producer) cannot store a block over the limit. Before
/// the fix `accept_block` checked no size below the activation, and this
/// block, valid at connect time, was stored and applied.
#[test]
fn accept_block_enforces_the_size_rule_for_every_caller() {
    let genesis = mk_genesis(unix_now() - 50_000);
    let gh = genesis.block_hash();
    let k = key();
    let fund = ([0x5Fu8; 32], 0u32, out(1_000 * core::tokenomics::SAT_PER_GNB, &k.spk));
    let n = node_with(&genesis, std::slice::from_ref(&fund));
    let over = sized_block(&n, gh, &k, &fund, core::MAX_BLOCK_SIZE + 1);
    let err = gnb::accept::accept_block(&over, over.block_hash(), over.height, &n.dag, &n.store, &n.mempool,
        &n.node_state, None, &n.shielded).unwrap_err();
    assert!(err.contains("block too large"), "{err}");
    assert!(!n.dag.read().has_block(&over.block_hash()), "not inserted");
    assert!(n.store.get_block(&over.block_hash()).unwrap().is_none(), "not stored");
    let at = sized_block(&n, gh, &k, &fund, core::MAX_BLOCK_SIZE);
    gnb::accept::accept_block(&at, at.block_hash(), at.height, &n.dag, &n.store, &n.mempool,
        &n.node_state, None, &n.shielded).expect("exactly at the limit");
    assert_eq!(applied_tip(&n), Some(at.block_hash()));
}
