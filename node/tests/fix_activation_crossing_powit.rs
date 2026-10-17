//! The mainnet order of activations, crossed through the miner's real path
//! (`template::build_block_template` -> `BlockTemplate::miner_coinbase` ->
//! `template::assemble_block` -> `accept::accept_block`):
//!
//! 1. PoWit from height 3 (`core::set_powit_height_override`, once per
//!    process): PoWit section, v2 body root, coinbase split by
//!    `Block::coinbase_outputs`;
//! 2. the `|wc:` witness-commitment suffix from `WITNESS_COMMITMENT_HEIGHT`;
//! 3. the audit's hardening rules from `H` = `WITNESS_COMMITMENT_HEIGHT` + 3
//!    (`activation::scoped_override`): the 80-byte coinbase commitment
//!    replaces the suffix, the tagged Merkle root, version 3 / sighash v3.
//!
//! On mainnet the same order is 10,000 (PoWit), 5,000 (suffix, already
//! active) and 17,500 (hardening). Every block on the way must be accepted
//! by the node that produced it, a version-1 payment must be mined below
//! `H` and a version-3 payment at `H`. The proof of work is marked verified
//! (`Block::test_only_assume_pow_valid`, dev-only `test-pow-limit`).

mod fix_common;
use fix_common::*;

use gnb::core::{self, activation};
use gnb::mempool::admission::{self, AdmissionPolicy};
use gnb::template;

const POWIT: u64 = 3;

#[test]
fn mainnet_activation_order_is_crossed_by_the_real_miner_path() {
    let _ = core::set_powit_height_override(POWIT);
    assert_eq!(core::powit_height(), POWIT, "one PoWit activation height per test binary");
    let h_act = core::WITNESS_COMMITMENT_HEIGHT + 3;
    let _g = activation::scoped_override(h_act);

    let genesis = mk_genesis(unix_now() - 100_000);
    let k = key();
    let funds = [([0xA1u8; 32], 0u32, out(3_000_000, &k.spk)), ([0xA2u8; 32], 0u32, out(3_000_000, &k.spk))];
    let n = node_with(&genesis, &funds);
    let miner = vec![0xCB; 20];
    let mut paid = Vec::new();

    for height in 1..=h_act + 3 {
        assert_eq!(admission::next_block_height(&n.dag.read()), height);
        // A payment at H - 1 (version 1, sighash v2) and one at H (version
        // 3, sighash v3), each admitted for the block about to be built.
        for (i, at) in [(0usize, h_act - 1), (1, h_act)] {
            if height == at {
                let tx = signed_spend_at(&k, &[(funds[i].0, 0)], std::slice::from_ref(&funds[i].2),
                    vec![out(2_900_000, &[0x5A; 20])], height);
                assert_eq!(tx.version, if height >= h_act { 3 } else { 1 });
                let policy = AdmissionPolicy::relay(height);
                admission::admit(&n.store, &n.mempool, tx.clone(), &policy)
                    .unwrap_or_else(|e| panic!("payment for height {height}: {e}"));
                paid.push((height, tx.txid()));
            }
        }

        let tmpl = template::build_block_template(&n.dag, &n.store, &n.mempool,
            template::miner_coinbase_reserve(&miner)).expect("template");
        assert_eq!(tmpl.height, height);
        assert_eq!(tmpl.hardened, height >= h_act, "h={height}");
        let block = template::assemble_block(&tmpl, tmpl.miner_coinbase(miner.clone()), unix_now())
            .unwrap_or_else(|e| panic!("assemble h={height}: {e}"));

        let ss = &block.transactions[0].inputs[0].script_sig;
        let suffix = core::suffix_witness_commitment_required(height);
        assert_eq!(suffix, (core::WITNESS_COMMITMENT_HEIGHT..h_act).contains(&height), "h={height}");
        if suffix {
            assert!(ss.ends_with(&block.witness_commitment()), "h={height}: |wc: suffix");
        }
        if tmpl.hardened {
            assert_eq!(&ss[..core::block_rules::COINBASE_COMMITMENT_LEN],
                       &tmpl.coinbase_commitment().unwrap()[..], "h={height}: audit commitment");
            assert!(!ss.windows(4).any(|w| w == b"|wc:"), "h={height}: no suffix once hardened");
        }
        assert_eq!(block.validate_witness_commitment(), Ok(()), "h={height}");
        assert_eq!(block.validate_powit_structure(), Ok(()), "h={height}");
        assert_eq!(core::block_rules::check_block_hardened_at(&block, h_act), Ok(()), "h={height}");
        assert_eq!(block.wire_size(), block.to_wire_bytes().len(), "h={height}");
        if height >= POWIT {
            let want = core::Block::coinbase_outputs(height, miner.clone(), tmpl.total_fees, &tmpl.powit.shares);
            let got = &block.transactions[0].outputs;
            assert_eq!(got.len(), want.len(), "h={height}");
            assert!(got.iter().zip(&want).all(|(g, w)| g.value == w.value && g.script_pubkey == w.script_pubkey),
                    "h={height}: the PoWit coinbase split");
        }

        block.test_only_assume_pow_valid();
        let id = accept(&n, &block).unwrap_or_else(|e| panic!("the node refuses its own block at h={height}: {e}"));
        assert_eq!(applied_tip(&n), Some(id), "h={height}");
        // The block survives the wire round trip a peer would see.
        let back = core::Block::from_wire_bytes(&block.to_wire_bytes()).expect("decode");
        assert_eq!(back.block_hash(), id);
    }

    for (height, txid) in &paid {
        let (_, mined_at) = n.store.get_tx_location(txid).unwrap()
            .unwrap_or_else(|| panic!("the payment for height {height} was never mined"));
        assert_eq!(mined_at, *height, "payment mined in the block it targeted");
    }
    assert_eq!(n.mempool.size(), 0);
}
