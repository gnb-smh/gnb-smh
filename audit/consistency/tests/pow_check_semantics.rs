//! Proof-of-work acceptance boundary and chain work vs Bitcoin Core.
//!
//! * Bitcoin Core `CheckProofOfWorkImpl` (src/pow.cpp) rejects iff
//!   `hash > target`, so `hash == target` is valid. GnB documents and
//!   implements the strict rule `out < target`. Both are self-consistent;
//!   the tests pin GnB's rule so it cannot drift silently.
//! * Bitcoin Core `GetBitsProof` (src/chain.h) is `~t / (t + 1) + 1`, i.e.
//!   floor(2^256 / (t + 1)). GnB's `work` keeps the top 128 bits of the
//!   target and saturates below 2^128. The tests show GnB never overstates
//!   work, bound the understatement by 1/(t >> 128) (below 2^-64 for every
//!   target GnB can reach), and check monotonicity, which is all chain
//!   selection relies on.

use gnb_audit_consistency::{u256_from_be, u256_to_be};
use gnb_smh::difficulty::{meets_target, work, work_from_bits, Target};
use primitive_types::U256;
use proptest::prelude::*;

fn core_bits_proof(t: U256) -> U256 {
    (!t / (t + U256::one())) + U256::one()
}

fn minus_one(t: [u8; 32]) -> [u8; 32] {
    u256_to_be(u256_from_be(&t) - U256::one())
}

#[test]
fn strict_less_than_boundary() {
    let target = [0x00, 0x00, 0x12, 0x34, 0x56, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let t = Target(target);
    assert!(!meets_target(&target, &t), "out == target must fail (GnB is strict)");
    assert!(meets_target(&minus_one(target), &t), "out == target - 1 must pass");
    let mut above = target;
    above[31] = 1;
    assert!(!meets_target(&above, &t));
    assert!(!meets_target(&[0u8; 32], &Target::ZERO), "zero target never validates");
    assert!(meets_target(&[0u8; 32], &Target([0xff; 32])));
    // The same boundary in the crate-level API.
    assert!(!gnb_smh::meets_target(&target, &target));
    assert!(gnb_smh::meets_target(&minus_one(target), &target));
}

#[test]
fn verify_respects_target_and_rejects_zero() {
    let header = b"audit verify boundary".to_vec();
    let out = gnb_smh::hash(&header, 7);
    // A target equal to the output fails; one above it passes.
    assert!(!gnb_smh::verify(&header, 7, &Target(out)));
    let above = u256_to_be(u256_from_be(&out) + U256::one());
    assert!(gnb_smh::verify(&header, 7, &Target(above)));
    assert!(!gnb_smh::verify(&header, 7, &Target::ZERO));
    let mut sp = gnb_smh::Scratchpad::new(gnb_smh::LOG2_N);
    assert!(gnb_smh::verify_with(&mut sp, &header, 7, &above));
    assert!(!gnb_smh::verify_with(&mut sp, &header, 7, &out));
}

fn arb_target_ge_2_128() -> impl Strategy<Value = [u8; 32]> {
    (0usize..16, any::<[u8; 32]>()).prop_map(|(zeros, mut b)| {
        for x in b.iter_mut().take(zeros) {
            *x = 0;
        }
        if b[..16].iter().all(|&x| x == 0) {
            b[15] = 1;
        }
        b
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100_000))]

    /// GnB never overstates work and understates it by at most a factor
    /// 1/(t >> 128): the truncated low 128 target bits.
    #[test]
    fn work_is_a_conservative_approximation_of_bitcoin_core(t in arb_target_ge_2_128()) {
        let gnb = U256::from(work(&Target(t)));
        let core = core_bits_proof(u256_from_be(&t));
        let hi = u256_from_be(&t) >> 128;
        prop_assert!(gnb <= core);
        prop_assert!(core - gnb <= core / hi + U256::from(2u8), "gnb={} core={}", gnb, core);
    }

    /// For every target GnB can actually use (pow limit 0x2100ffff down to
    /// 2^192), the error is below one part in 2^64.
    #[test]
    fn work_error_is_negligible_for_realistic_targets(zeros in 0usize..8, mut t in any::<[u8; 32]>()) {
        for x in t.iter_mut().take(zeros) { *x = 0; }
        if t[..8].iter().all(|&x| x == 0) { t[7] = 1; }
        let gnb = U256::from(work(&Target(t)));
        let core = core_bits_proof(u256_from_be(&t));
        prop_assert!(gnb <= core);
        prop_assert!(core - gnb <= core / (U256::one() << 64) + U256::from(2u8));
    }

    #[test]
    fn work_is_monotone(a in arb_target_ge_2_128(), b in arb_target_ge_2_128()) {
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        prop_assert!(work(&Target(lo)) >= work(&Target(hi)), "a harder target must not carry less work");
    }

    #[test]
    fn work_from_bits_matches_core_on_valid_bits(e in 0x12u32..=0x20, m in 0x0001_0000u32..0x0080_0000) {
        let bits = (e << 24) | m;
        let t = gnb_smh::difficulty::try_bits_to_target(bits).unwrap();
        let core = core_bits_proof(u256_from_be(&t.0));
        let gnb = U256::from(work_from_bits(bits));
        let hi = u256_from_be(&t.0) >> 128;
        prop_assert!(gnb <= core);
        prop_assert!(core - gnb <= core / hi + U256::from(2u8));
    }
}

#[test]
fn work_saturates_below_2_128_and_is_zero_for_zero() {
    let mut t = [0u8; 32];
    t[16] = 1; // 2^120
    assert_eq!(work(&Target(t)), u128::MAX);
    assert_eq!(work(&Target::ZERO), 0);
    assert_eq!(work(&Target::MAX), 1);
    assert_eq!(work_from_bits(0), 0, "malformed bits carry no work");
}
