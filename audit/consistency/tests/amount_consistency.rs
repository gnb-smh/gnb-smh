//! Amount arithmetic and monetary schedule (CVE-2010-5139 class).
//!
//! Bitcoin Core bounds every output and every sum by `MoneyRange`
//! (src/consensus/amount.h, CheckTransaction in src/consensus/tx_check.cpp).
//! These tests check GnB's equivalents in `gnb-crypto`: checked output sums,
//! the subsidy schedule never exceeding the mining allocation, and the
//! fee function never overflowing.

use gnb_crypto::core::tokenomics::{
    block_subsidy_sat, issued_through_sat, min_tx_fee_sat, CARRYOVER_ALLOCATION_SAT,
    HALVING_INTERVAL, LAST_SUBSIDY_HEIGHT_EXCLUSIVE, MAX_SUPPLY_SAT, MINING_ALLOCATION_SAT,
};
use gnb_crypto::core::{Transaction, TxInput, TxOutput};
use proptest::prelude::*;

fn tx_with_outputs(values: &[u64]) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput { prev_txid: [1; 32], prev_index: 0, script_sig: vec![], sequence: 0 }],
        outputs: values
            .iter()
            .map(|v| TxOutput { value: *v, script_pubkey: vec![0; 20] })
            .collect(),
        locktime: 0,
    }
}

#[test]
fn cve_2010_5139_output_sum_overflow_is_detected() {
    // The 2010 overflow: two outputs that wrap a 64-bit sum.
    let t = tx_with_outputs(&[u64::MAX / 2 + 1, u64::MAX / 2 + 1]);
    assert_eq!(t.total_output(), None);
    let t = tx_with_outputs(&[u64::MAX, 1]);
    assert_eq!(t.total_output(), None);
    let t = tx_with_outputs(&[MAX_SUPPLY_SAT, 1]);
    assert_eq!(t.total_output(), Some(MAX_SUPPLY_SAT + 1));
}

#[test]
fn subsidy_schedule_stays_within_the_mining_allocation() {
    // Exact closed form against a direct per-epoch sum.
    let mut total: u128 = 0;
    for epoch in 0..64u64 {
        let start = (epoch * HALVING_INTERVAL).max(1);
        let end = (epoch + 1) * HALVING_INTERVAL - 1;
        total += (end - start + 1) as u128 * block_subsidy_sat(start) as u128;
        assert_eq!(block_subsidy_sat(start), block_subsidy_sat(end));
    }
    assert!(total <= MINING_ALLOCATION_SAT as u128);
    assert_eq!(issued_through_sat(u64::MAX) as u128, total);
    assert_eq!(block_subsidy_sat(LAST_SUBSIDY_HEIGHT_EXCLUSIVE), 0);
    assert!(block_subsidy_sat(LAST_SUBSIDY_HEIGHT_EXCLUSIVE - 1) > 0);
    assert_eq!(block_subsidy_sat(0), 0, "genesis pays no subsidy");
    assert!(total + CARRYOVER_ALLOCATION_SAT as u128 <= MAX_SUPPLY_SAT as u128);
    println!(
        "mining issuance {} sat of {} allocated ({} sat never issued by rounding)",
        total,
        MINING_ALLOCATION_SAT,
        MINING_ALLOCATION_SAT as u128 - total
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100_000))]

    #[test]
    fn issued_through_is_monotone_and_matches_the_sum(h in 0u64..=LAST_SUBSIDY_HEIGHT_EXCLUSIVE + 10, d in 0u64..5_000) {
        let a = issued_through_sat(h);
        let b = issued_through_sat(h + d);
        prop_assert!(a <= b);
        if d <= 2_000 {
            let direct: u64 = ((h + 1)..=(h + d)).map(block_subsidy_sat).sum();
            prop_assert_eq!(b - a, direct);
        }
    }

    #[test]
    fn fee_function_never_overflows(size in any::<usize>()) {
        let f = std::panic::catch_unwind(|| min_tx_fee_sat(size));
        prop_assert!(f.is_ok());
        prop_assert!(f.unwrap() >= 10_000);
    }

    #[test]
    fn total_output_matches_u128_sum(values in proptest::collection::vec(any::<u64>(), 0..8)) {
        let t = tx_with_outputs(&values);
        let wide: u128 = values.iter().map(|v| *v as u128).sum();
        match t.total_output() {
            Some(s) => prop_assert_eq!(s as u128, wide),
            None => prop_assert!(wide > u64::MAX as u128),
        }
    }
}
