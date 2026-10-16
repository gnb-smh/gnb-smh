//! Differential tests of GnB's compact-target codec against Bitcoin Core
//! (line-for-line port) and rust-bitcoin.
//!
//! * Exhaustive over every compact value whose exponent is 0..=34 (the only
//!   exponents that can decode to a non-zero 256-bit target): 35 × 2^24 =
//!   587,202,560 values, plus a sample of every larger exponent.
//! * Property-based (proptest) encoding agreement for arbitrary targets.

use bitcoin::pow::{CompactTarget, Target as BtcTarget};
use gnb_audit_consistency::{core_derive_target, core_get_compact, u256_from_be, u256_to_be};
use gnb_smh::difficulty::{target_to_bits, try_bits_to_target, Target};
use proptest::prelude::*;

fn check_range(lo: u32, hi_inclusive: u32) -> (u64, u64) {
    let mut accepted = 0u64;
    let mut non_canonical = 0u64;
    let mut b = lo;
    loop {
        let gnb = try_bits_to_target(b).ok().map(|t| t.0);
        let core = core_derive_target(b).map(u256_to_be);
        if gnb != core {
            panic!("decode differs from Bitcoin Core at {b:#010x}: gnb={gnb:?} core={core:?}");
        }
        if let Some(t) = gnb {
            accepted += 1;
            if target_to_bits(&Target(t)) != b {
                non_canonical += 1;
            }
        }
        if b == hi_inclusive {
            break;
        }
        b += 1;
    }
    (accepted, non_canonical)
}

#[test]
fn exhaustive_decode_matches_bitcoin_core_derive_target() {
    // Exponents 0..=34, every mantissa and sign bit, split over threads.
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4) as u32;
    let total: u32 = 35 << 24; // exclusive upper bound
    let chunk = total.div_ceil(threads);
    let handles: Vec<_> = (0..threads)
        .map(|i| {
            let lo = i * chunk;
            let hi = ((i + 1) * chunk).min(total) - 1;
            std::thread::spawn(move || check_range(lo, hi))
        })
        .collect();
    let (mut accepted, mut non_canonical) = (0u64, 0u64);
    for h in handles {
        let (a, n) = h.join().unwrap();
        accepted += a;
        non_canonical += n;
    }
    // Exponents 35..=255: everything with a non-zero mantissa overflows in
    // Core; check a deterministic sample of every exponent.
    for exp in 35u32..=255 {
        for m in (0u32..0x0100_0000).step_by(4093) {
            check_range((exp << 24) | m, (exp << 24) | m);
        }
    }
    println!(
        "compact codec: {total} values checked exhaustively; {accepted} accepted by both; \
         {non_canonical} accepted encodings are non-canonical"
    );
    assert!(accepted > 0);
}

fn arb_target() -> impl Strategy<Value = [u8; 32]> {
    (0usize..=32, any::<[u8; 32]>()).prop_map(|(zeros, mut b)| {
        for x in b.iter_mut().take(zeros) {
            *x = 0;
        }
        b
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200_000))]

    #[test]
    fn encode_matches_bitcoin_core_get_compact(t in arb_target()) {
        let gnb = target_to_bits(&Target(t));
        prop_assert_eq!(gnb, core_get_compact(u256_from_be(&t)));
    }

    #[test]
    fn encode_matches_rust_bitcoin_to_compact_lossy(t in arb_target()) {
        let gnb = target_to_bits(&Target(t));
        let btc = BtcTarget::from_be_bytes(t).to_compact_lossy().to_consensus();
        prop_assert_eq!(gnb, btc);
    }

    #[test]
    fn decode_matches_rust_bitcoin_on_valid_domain(bits in any::<u32>()) {
        if let Some(core) = core_derive_target(bits) {
            let btc = BtcTarget::from_compact(CompactTarget::from_consensus(bits)).to_be_bytes();
            prop_assert_eq!(btc, u256_to_be(core));
            prop_assert_eq!(try_bits_to_target(bits).unwrap().0, btc);
        }
    }

    #[test]
    fn encode_rounds_down_and_is_idempotent(t in arb_target()) {
        let bits = target_to_bits(&Target(t));
        if let Ok(d) = try_bits_to_target(bits) {
            // Round-down: the re-decoded target is never easier.
            prop_assert!(d.0 <= t);
            // Canonical form is a fixed point.
            prop_assert_eq!(target_to_bits(&d), bits);
        } else {
            // Only the zero target has no compact encoding.
            prop_assert_eq!(t, [0u8; 32]);
        }
    }
}
