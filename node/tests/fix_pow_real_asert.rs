//! Re-audit POW-5 (challenge): every node test builds gnb-crypto with the
//! dev feature `test-pow-limit`, which pins `core::expected_bits` to the pow
//! limit whatever its arguments, so the node's consensus-critical call sites
//! of the difficulty rule had no test against the real ASERT function:
//! `accept_block`'s height and parent-timestamp arguments, the template's
//! bits (internal miner and `getblocktemplate`) and the ingress orphan work
//! floor. A test holding `core::scoped_real_expected_bits()` gets the real
//! rule on its thread (`expected_bits_at` under the process-wide activation
//! height, mainnet 110,000 here); proofs of work are recorded as verified
//! (`Block::test_only_assume_pow_valid`), every other check runs unchanged.
//!
//! The chain runs AHEAD of the ASERT schedule (genesis at the real
//! `GENESIS_TIMESTAMP`, one second per block instead of 30) and a side tip
//! is stamped 600 s later, so the targets are strictly between the two pow
//! limits and a change of the height by one, or of the parent timestamp
//! (the latest over ALL parents), changes the bits.

mod fix_common;
use fix_common::*;

use gnb::consensus::BlockHash;
use gnb::core::{self, activation, Block};
use gnb::{ingress, template};

const G0: u64 = core::GENESIS_TIMESTAMP;

fn real_bits(parent_ts: u64, height: u64) -> u32 {
    core::expected_bits_at(parent_ts, height, activation::hardening_activation_height()).unwrap()
}

/// `b` with `timestamp` (and its new id's proof recorded as verified).
fn restamped(mut b: Block, timestamp: u64) -> Block {
    b.header.timestamp = timestamp;
    b.test_only_assume_pow_valid();
    b
}

/// G -> a -> b (one second apart) and a side tip c on G stamped 600 s after
/// genesis. A block on [b, c] has header height 3 (max parent DAG height + 1)
/// and difficulty parent timestamp G0 + 600 (the latest of all parents),
/// while its selected parent b is stamped G0 + 2.
fn two_tips() -> (Node, BlockHash, BlockHash) {
    let genesis = mk_genesis(G0);
    let n = node_with(&genesis, &[]);
    let gh = genesis.block_hash();
    let a = empty_child(&n, gh, "pow5-a");
    accept(&n, &a).unwrap();
    let b = empty_child(&n, a.block_hash(), "pow5-b");
    accept(&n, &b).unwrap();
    let c = restamped(empty_child(&n, gh, "pow5-c"), G0 + 600);
    accept(&n, &c).unwrap();
    assert_eq!(sel_tip(&n), Some(b.block_hash()));
    (n, b.block_hash(), c.block_hash())
}

/// `accept_block` computes the expected bits from the header height and the
/// latest timestamp over all parents: the block carrying exactly those real
/// ASERT bits is accepted; bits computed for height + 1, or from the
/// selected parent's timestamp, are rejected as an invalid difficulty.
#[test]
fn accept_block_checks_the_real_asert_bits_of_its_height_and_parent_timestamp() {
    let (n, b, c) = two_tips();
    // Built (and sealed at the pinned bits) before the real rule is on.
    let x = mk_block(&n, vec![b, c], vec![coinbase("pow5-x", core::tokenomics::block_subsidy_sat(3), vec![0xC5; 20])]);
    let _real = core::scoped_real_expected_bits();
    let good = real_bits(G0 + 600, 3);
    let wrong_height = real_bits(G0 + 600, 4);
    let wrong_ts = real_bits(G0 + 2, 3);
    assert!(good != wrong_height && good != wrong_ts && wrong_height != wrong_ts);
    assert_ne!(good, core::POW_LIMIT_BITS, "not the pinned value");
    assert_eq!(core::expected_bits(G0 + 600, 3).unwrap(), good, "the seam computes the real rule");

    assert_eq!(x.height, 3);
    for (bits, what) in [(wrong_height, "bits of height + 1"), (wrong_ts, "bits of the selected parent's timestamp")] {
        let mut bad = x.clone();
        bad.header.bits = bits;
        let bad = restamped(bad, G0 + 601);
        let err = accept(&n, &bad).unwrap_err();
        assert!(err.contains("invalid difficulty"), "{what}: {err}");
    }
    let mut ok = x;
    ok.header.bits = good;
    let ok = restamped(ok, G0 + 601);
    accept(&n, &ok).expect("the real ASERT bits of its height and parent timestamp");
    assert_eq!(sel_tip(&n), Some(ok.block_hash()));
}

/// The template (internal miner and `getblocktemplate`) carries the real
/// ASERT bits of its own height and parent set, and the block assembled
/// from it is accepted under the real rule.
#[test]
fn template_bits_follow_the_real_asert_rule_and_are_accepted() {
    let (n, b, c) = two_tips();
    let _real = core::scoped_real_expected_bits();
    let tmpl = template::build_block_template(&n.dag, &n.store, &n.mempool, template::EXTERNAL_COINBASE_RESERVE).unwrap();
    let mut parents = tmpl.parents.clone();
    parents.sort();
    let mut want = vec![b, c];
    want.sort();
    assert_eq!(parents, want);
    assert_eq!((tmpl.height, tmpl.parent_timestamp), (3, G0 + 600));
    assert_eq!(tmpl.bits, real_bits(G0 + 600, 3));
    let cb = template::miner_coinbase(tmpl.height, tmpl.subsidy + tmpl.total_fees, vec![0xC6; 20]);
    let blk = template::assemble_block(&tmpl, cb, G0 + 601).expect("self-check");
    blk.test_only_assume_pow_valid();
    accept(&n, &blk).expect("the template block under the real rule");
}

/// The ingress orphan work floor's reference target is the real ASERT target
/// of a child of the tip (height tip + 1) stamped `now`.
#[test]
fn orphan_floor_reference_target_is_the_real_asert_target_of_the_next_height() {
    let _real = core::scoped_real_expected_bits();
    let tip_h = 10;
    let now = G0 + 30 * tip_h;
    let next = core::bits_to_target(real_bits(now, tip_h + 1));
    assert_ne!(next, core::bits_to_target(real_bits(now, tip_h)), "height matters here");
    assert_ne!(next, core::bits_to_target(real_bits(now + 600, tip_h + 1)), "time matters here");
    assert!(next < core::Block::pow_limit_target_for_height(tip_h + 1), "not clamped");
    assert_eq!(ingress::reference_target(tip_h, now), next);
}

/// The ingress orphan work floor at its call site: `BlockIngress::handle_block`
/// derives the floor from the SELECTED TIP's height (the reference is a
/// child of the tip, `ingress::reference_target`) and caps it at the
/// orphan's own claimed height. Under the real ASERT rule, with the node far
/// enough ahead of the schedule that the 16-fold eased floor is below the
/// pow limit, an orphan whose bits are exactly the floor is buffered, and
/// one whose bits are the floor of the tip's parent height (easier) is
/// dropped; computing the floor from the orphan's height or from tip + 1
/// (harder floors) would drop the first, from tip - 1 would admit the second.
#[test]
fn ingress_orphan_floor_call_site_follows_the_real_asert_rule_of_the_tip() {
    let (n, _b, _c) = two_tips();
    let tip_h = n.dag.read().get_block_data(&sel_tip(&n).unwrap()).unwrap().height;
    assert_eq!(tip_h, 2);
    let orphan_h = tip_h + 60;
    // Built (and sealed at the pinned bits) before the real rule is on.
    let base = mk_block(&n, vec![sel_tip(&n).unwrap()],
        vec![coinbase("pow5-orphan", core::tokenomics::block_subsidy_sat(orphan_h), vec![0xC7; 20])]);
    let _real = core::scoped_real_expected_bits();
    // `now` four ASERT half-lives before the schedule of the tip's child.
    let now = G0 + 30 * (tip_h + 1) - 5 * core::ASERT_HALFLIFE_SECS as u64;
    let floor_at = |h: u64| ingress::orphan_admission_floor(h, now, orphan_h);
    let floor = floor_at(tip_h);
    assert!(floor < core::Block::pow_limit_target_for_height(orphan_h), "not capped");
    assert!(floor_at(orphan_h) < floor && floor_at(tip_h + 1) < floor && floor_at(tip_h - 1) > floor,
        "the floor depends on the height it is computed for");

    let orphan = |bits: u32, tag: &str| {
        let mut o = base.clone();
        o.transactions[0].inputs[0].script_sig = tag.as_bytes().to_vec();
        o.header.parents = vec![[0x5A; 32]]; // unknown: an orphan
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
    assert!(core::bits_to_target(at_floor) <= floor && core::bits_to_target(at_floor) > floor_at(tip_h + 1));
    let easier = core::target_to_bits(&floor_at(tip_h - 1));
    assert!(core::bits_to_target(easier) > floor);

    let mut core_ = ingress::BlockIngress::new();
    let o = deliver(&mut core_, &orphan(easier, "pow5-orphan-easy"));
    assert!(matches!(o, ingress::BlockOutcome::Dropped(ingress::DropReason::OrphanBelowFloor)), "{o:?}");
    let o = deliver(&mut core_, &orphan(at_floor, "pow5-orphan-floor"));
    assert!(matches!(o, ingress::BlockOutcome::Buffered { .. }), "{o:?}");
}
