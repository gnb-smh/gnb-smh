//! Re-audit POW-5 across the GnB-SMH v1 -> v3 switch (main's PoW v3, 28a619d):
//! from `core::powit_height()` the expected bits are the ASERT bits shifted
//! by `core::POW_V3_DIFFICULTY_SHIFT` (`core::adjust_bits_for_algo`, applied
//! inside `core::expected_bits_at` for `core::pow_algo(height)`), so the
//! node's call sites must pass the height of the block being judged: a
//! v1 / v3 mix-up at the switch accepts a block 4x too easy (or refuses the
//! honest one). On mainnet the switch is at 10,000; this binary moves it to
//! [`POWIT`] (`core::set_powit_height_override`, process-wide, one value per
//! binary) so short chains cross it, and the real ASERT rule is held on the
//! test's thread (`core::scoped_real_expected_bits`). The mainnet constant
//! itself is pinned in `fix_pow_real_asert.rs`
//! (`expected_bits_switch_to_v3_at_the_mainnet_powit_height`).
//!
//! Shape (as in `fix_pow_real_asert.rs`): G -> a -> b one second apart and a
//! side tip c on G stamped 600 s after genesis; the next block, on [b, c], has
//! header height 3 = [`POWIT`] (v3) and difficulty parent timestamp G0 + 600,
//! while its selected parent b (height 2) is a v1 block. The ingress core
//! runs with no minimum chain work (these chains are far below mainnet's,
//! the default here, and an unrequested orphan is not buffered below it).

mod fix_common;
use fix_common::*;

use gnb::consensus::BlockHash;
use gnb::core::{self, activation, Block};
use gnb::{ingress, template};

const G0: u64 = core::GENESIS_TIMESTAMP;
/// The PoW v3 / PoWit activation of this test binary.
const POWIT: u64 = 3;

fn v3_binary() {
    core::set_powit_height_override(POWIT).expect("one PoWit height per test binary");
}

/// The real ASERT bits of `height` (the v3 shift applied from `POWIT`).
fn real_bits(parent_ts: u64, height: u64) -> u32 {
    core::expected_bits_at(parent_ts, height, activation::hardening_activation_height()).unwrap()
}

/// The ASERT bits of `height` WITHOUT the v3 shift (what a call site that
/// judged a v3 block with the v1 rule would expect).
fn v1_bits(parent_ts: u64, height: u64) -> u32 {
    let b = real_bits(parent_ts, height);
    if core::pow_algo(height) == gnb_smh::Algo::V3 {
        let unshifted = gnb_smh::difficulty::asert_next_bits(
            &core::asert_params_at(height, activation::hardening_activation_height()),
            &core::asert_anchor(), parent_ts as i64, height,
        ).unwrap();
        assert_eq!(core::adjust_bits_for_algo(unshifted, gnb_smh::Algo::V3), b);
        unshifted
    } else {
        b
    }
}

fn restamped(mut b: Block, timestamp: u64) -> Block {
    b.header.timestamp = timestamp;
    b.test_only_assume_pow_valid();
    b
}

/// The coinbase of a block at `height` with no witness shares and no fees:
/// from `POWIT` the miner's share of the subsidy only.
fn cb(tag: &str, height: u64) -> core::Transaction {
    let mut c = coinbase(tag, 0, vec![0xC8; 20]);
    c.outputs = Block::coinbase_outputs(height, vec![0xC8; 20], 0, &[]);
    c
}

fn two_tips() -> (Node, BlockHash, BlockHash) {
    v3_binary();
    let genesis = mk_genesis(G0);
    let n = node_with(&genesis, &[]);
    let gh = genesis.block_hash();
    let a = empty_child(&n, gh, "pow5v3-a");
    accept(&n, &a).unwrap();
    let b = empty_child(&n, a.block_hash(), "pow5v3-b");
    accept(&n, &b).unwrap();
    let c = restamped(empty_child(&n, gh, "pow5v3-c"), G0 + 600);
    accept(&n, &c).unwrap();
    assert_eq!(sel_tip(&n), Some(b.block_hash()));
    assert_eq!(core::pow_algo(2), gnb_smh::Algo::V1);
    assert_eq!(core::pow_algo(POWIT), gnb_smh::Algo::V3);
    (n, b.block_hash(), c.block_hash())
}

/// `accept_block` at the switch: the first v3 block must carry the SHIFTED
/// real ASERT bits of its own height; the unshifted (v1) bits of that height,
/// and the shifted bits of the next height, are an invalid difficulty.
#[test]
fn accept_block_requires_the_v3_shifted_bits_from_the_switch() {
    let (n, b, c) = two_tips();
    let x = mk_block(&n, vec![b, c], vec![cb("pow5v3-x", POWIT)]);
    assert_eq!(x.height, POWIT);
    let _real = core::scoped_real_expected_bits();
    let good = real_bits(G0 + 600, POWIT);
    let unshifted = v1_bits(G0 + 600, POWIT);
    let next = real_bits(G0 + 600, POWIT + 1);
    assert!(good != unshifted && good != next && unshifted != next);
    assert_eq!(core::bits_to_target(good), {
        use primitive_types::U256;
        let t = U256::from_big_endian(&core::bits_to_target(unshifted)) >> core::POW_V3_DIFFICULTY_SHIFT;
        core::bits_to_target(core::target_to_bits(&t.to_big_endian()))
    }, "4x harder than the ASERT schedule");
    assert_eq!(core::expected_bits(G0 + 600, POWIT).unwrap(), good, "the seam computes the real rule");
    for (bits, what) in [(unshifted, "the v1 bits of the v3 height"), (next, "the bits of height + 1")] {
        let mut bad = x.clone();
        bad.header.bits = bits;
        let bad = restamped(bad, G0 + 601);
        let err = accept(&n, &bad).unwrap_err();
        assert!(err.contains("invalid difficulty"), "{what}: {err}");
    }
    let mut ok = x;
    ok.header.bits = good;
    let ok = restamped(ok, G0 + 601);
    accept(&n, &ok).expect("the v3-shifted real ASERT bits of its height");
    assert_eq!(sel_tip(&n), Some(ok.block_hash()));
}

/// The template at the switch carries the v3-shifted real bits of its own
/// height (internal miner and `getblocktemplate`), its coinbase pays the
/// miner's share only, and the assembled block is accepted.
#[test]
fn template_bits_at_the_switch_are_the_v3_shifted_real_bits_and_are_accepted() {
    let (n, _b, _c) = two_tips();
    let _real = core::scoped_real_expected_bits();
    let tmpl = template::build_block_template(&n.dag, &n.store, &n.mempool, template::EXTERNAL_COINBASE_RESERVE).unwrap();
    assert_eq!((tmpl.height, tmpl.parent_timestamp), (POWIT, G0 + 600));
    assert_eq!(tmpl.bits, real_bits(G0 + 600, POWIT));
    assert_ne!(tmpl.bits, v1_bits(G0 + 600, POWIT), "the v3 shift is applied");
    let coinbase = tmpl.miner_coinbase(vec![0xC9; 20]);
    let blk = template::assemble_block(&tmpl, coinbase, G0 + 601).expect("self-check");
    blk.test_only_assume_pow_valid();
    accept(&n, &blk).expect("the template block under the real rule at the switch");
}

/// The ingress orphan floor at its call site across the switch: with the
/// selected tip at height 2 the reference is a child at height 3 (v3), so
/// its target is the v3-shifted one; an orphan whose bits are exactly that
/// floor is buffered, one at the floor the v1 rule would give (4x easier)
/// is dropped.
#[test]
fn ingress_orphan_floor_uses_the_v3_target_of_the_tips_child() {
    let (n, _b, _c) = two_tips();
    let tip_h = n.dag.read().get_block_data(&sel_tip(&n).unwrap()).unwrap().height;
    assert_eq!(tip_h, POWIT - 1);
    let orphan_h = tip_h + 60;
    let base = mk_block(&n, vec![sel_tip(&n).unwrap()], vec![cb("pow5v3-orphan", orphan_h)]);
    let _real = core::scoped_real_expected_bits();
    let now = G0 + 30 * (tip_h + 1) - 5 * core::ASERT_HALFLIFE_SECS as u64;
    let v3_ref = core::bits_to_target(real_bits(now, tip_h + 1));
    let v1_ref = core::bits_to_target(v1_bits(now, tip_h + 1));
    assert!(v3_ref < v1_ref);
    assert_eq!(ingress::reference_target(tip_h, now), v3_ref, "the reference is the v3 target of the tip's child");
    let floor = ingress::orphan_admission_floor(tip_h, now, orphan_h);
    let v1_floor = ingress::ease_target(&v1_ref, ingress::ORPHAN_WORK_FLOOR_SHIFT, orphan_h);
    assert!(floor < v1_floor, "the eased v3 floor is below the eased v1 floor");
    assert!(floor < core::Block::pow_limit_target_for_height(orphan_h), "not capped");

    let orphan = |bits: u32, tag: &str| {
        let mut o = base.clone();
        o.transactions[0].inputs[0].script_sig = tag.as_bytes().to_vec();
        o.header.parents = vec![[0x5B; 32]]; // unknown: an orphan
        o.height = orphan_h;
        o.blue_score = orphan_h;
        o.header.bits = bits;
        commit_block(&mut o);
        o.test_only_assume_pow_valid();
        o
    };
    let deliver = |core: &mut ingress::BlockIngress, b: &Block| {
        let ctx = ingress::AcceptCtx {
            dag: &n.dag, store: &n.store, mempool: &n.mempool, node_state: &n.node_state,
            tip_tx: Some(&n.tip_tx), shielded: &n.shielded,
        };
        core.handle_block(b.clone(), b.block_hash(), b.to_wire_bytes().len(), None, false,
            std::time::Instant::now(), now, &ctx)
    };
    let at_floor = core::target_to_bits(&floor);
    assert!(core::bits_to_target(at_floor) <= floor);
    let at_v1_floor = core::target_to_bits(&v1_floor);
    assert!(core::bits_to_target(at_v1_floor) > floor);

    let mut core_ = ingress::BlockIngress::new().with_minimum_chain_work(0);
    let o = deliver(&mut core_, &orphan(at_v1_floor, "pow5v3-orphan-v1"));
    assert!(matches!(o, ingress::BlockOutcome::Dropped(ingress::DropReason::OrphanBelowFloor)), "{o:?}");
    let o = deliver(&mut core_, &orphan(at_floor, "pow5v3-orphan-v3"));
    assert!(matches!(o, ingress::BlockOutcome::Buffered { .. }), "{o:?}");
}
