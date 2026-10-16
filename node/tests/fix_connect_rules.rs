//! Re-audit package R1a (phase 4): value and connect-time block rules.
//!
//! * B1-T1: the VAL-11 remediation added a block-wide output-total
//!   MoneyRange rule. Chained in-block spends move the same coins once per
//!   hop, so a valid block (and a valid template of a valid mempool chain)
//!   could exceed it; it applied at every height (changing pre-activation
//!   verdicts) and templates ignored it. Removed: Bitcoin Core bounds each
//!   transaction's output total and the accumulated fees, never the sum of
//!   all outputs of a block.
//!
//! Every block goes through the real acceptance pipeline
//! (`gnb::accept::accept_block`, after `validate_structure`); proofs of work
//! are recorded as verified (`Block::test_only_assume_pow_valid`, dev-only
//! `test-pow-limit`).

mod fix_common;
use fix_common::*;

use gnb::core::{self, activation, Transaction, TxOutput};
use gnb::mempool::admission::{self, AdmissionPolicy};
use gnb::template;

/// 4,000,000 GNB: three hops of it sum above `MAX_SUPPLY_SAT` (10,000,000 GNB).
const BIG: u64 = 4_000_000 * core::tokenomics::SAT_PER_GNB;
const HOP_FEE: u64 = 100_000;

/// A chain of `keys.len() - 1` signed spends: hop i moves the previous
/// output (locked to `keys[i]`) to `keys[i + 1]`, paying `HOP_FEE`. Signed
/// for a block at `height` under the calling thread's activation height.
fn hop_chain(keys: &[Key], fund: &([u8; 32], u32, TxOutput), height: u64) -> Vec<Transaction> {
    let mut prev = (fund.0, fund.1, fund.2.clone());
    let mut out_txs = Vec::new();
    for i in 0..keys.len() - 1 {
        let next = out(prev.2.value - HOP_FEE, &keys[i + 1].spk);
        let tx = signed_spend_at(&keys[i], &[(prev.0, prev.1)], std::slice::from_ref(&prev.2), vec![next.clone()], height);
        prev = (tx.txid(), 0, next);
        out_txs.push(tx);
    }
    out_txs
}

/// B1-T1: on both sides of the activation, a mempool chain of three hops of
/// 4,000,000 GNB (each transaction in range, outputs summing to about
/// 12,000,000 GNB) is admitted, templated, assembled (the template
/// self-check) and accepted and connected by the real pipeline. Before the
/// fix `assemble_block` refused it ("block output total ... exceeds
/// MAX_SUPPLY_SAT") and so did `accept_block`: the miner retried the same
/// poisoned template every second while the chain stayed pooled.
#[test]
fn chained_spends_whose_outputs_sum_above_the_supply_are_valid_and_templated() {
    for act in [activation::NEVER, 0] {
        let _g = activation::scoped_override(act);
        let genesis = mk_genesis(unix_now() - 10_000);
        let keys: Vec<Key> = (0..4).map(|_| key()).collect();
        let fund = ([0xB1u8; 32], 0u32, out(BIG, &keys[0].spk));
        let n = node_with(&genesis, std::slice::from_ref(&fund));
        let height = admission::next_block_height(&n.dag.read());
        let chain = hop_chain(&keys, &fund, height);
        let total: u128 = chain.iter().flat_map(|t| &t.outputs).map(|o| u128::from(o.value)).sum();
        assert!(total > u128::from(core::tokenomics::MAX_SUPPLY_SAT), "outputs sum above the supply: {total}");
        for t in &chain {
            assert!(core::limits::check_tx_money_range(t).is_ok(), "each transaction is in range");
            admission::admit(&n.store, &n.mempool, t.clone(), &AdmissionPolicy::relay(height))
                .unwrap_or_else(|e| panic!("act {act}: hop admitted: {e}"));
        }

        let miner = vec![0xCB; 20];
        let tmpl = template::build_block_template(&n.dag, &n.store, &n.mempool, template::miner_coinbase_reserve(&miner)).unwrap();
        assert_eq!(tmpl.transactions.len(), 3, "act {act}: the whole chain, parents first");
        assert_eq!(tmpl.total_fees, 3 * HOP_FEE);
        let cb = template::miner_coinbase(tmpl.height, tmpl.subsidy + tmpl.total_fees, miner.clone());
        let block = template::assemble_block(&tmpl, cb, unix_now())
            .unwrap_or_else(|e| panic!("act {act}: the template self-check refused a valid block: {e}"));
        assert_eq!(core::limits::check_block_context_free(&block), Ok(()));
        block.test_only_assume_pow_valid();
        accept(&n, &block).unwrap_or_else(|e| panic!("act {act}: accept_block: {e}"));
        assert_eq!(applied_tip(&n), Some(block.block_hash()), "act {act}: connected");
        assert!(n.store.get_utxo(&chain[2].txid(), 0).unwrap().is_some());
        assert!(n.store.get_utxo(&fund.0, 0).unwrap().is_none());
        assert_eq!(n.mempool.size(), 0);
    }
}
