//! Bitcoin Core's own compact-target vectors applied to GnB.
//!
//! Source: bitcoin/bitcoin src/test/arith_uint256_tests.cpp, test case
//! `bignum_SetCompact`, and src/test/pow_tests.cpp `CheckProofOfWork_test_*`.
//! Core accepts a compact value as a target iff it is not negative, does not
//! overflow, and is not zero (`DeriveTarget`, src/pow.cpp). GnB's
//! `try_bits_to_target` must accept exactly the same values, decode them to
//! the same integer, and re-encode them like `GetCompact`.

use gnb_audit_consistency::{core_derive_target, core_get_compact, u256_from_be, u256_to_be};
use gnb_smh::difficulty::{target_to_bits, try_bits_to_target, Target};
use primitive_types::U256;

/// (compact, expected value as hex, Core fNegative, Core fOverflow, GetCompact)
/// `None` for GetCompact where Core's vector does not check it.
const SET_COMPACT: &[(u32, &str, bool, bool, Option<u32>)] = &[
    (0x0000_0000, "00", false, false, Some(0)),
    (0x0012_3456, "00", false, false, Some(0)),
    (0x0100_3456, "00", false, false, Some(0)),
    (0x0200_0056, "00", false, false, Some(0)),
    (0x0300_0000, "00", false, false, Some(0)),
    (0x0400_0000, "00", false, false, Some(0)),
    (0x0092_3456, "00", false, false, Some(0)),
    (0x0180_3456, "00", false, false, Some(0)),
    (0x0280_0056, "00", false, false, Some(0)),
    (0x0380_0000, "00", false, false, Some(0)),
    (0x0480_0000, "00", false, false, Some(0)),
    (0x0112_3456, "12", false, false, Some(0x0112_0000)),
    (0x01fe_dcba, "7e", true, false, None),
    (0x0212_3456, "1234", false, false, Some(0x0212_3400)),
    (0x0312_3456, "123456", false, false, Some(0x0312_3456)),
    (0x0412_3456, "12345600", false, false, Some(0x0412_3456)),
    (0x0492_3456, "12345600", true, false, None),
    (0x0500_9234, "92340000", false, false, Some(0x0500_9234)),
    (
        0x2012_3456,
        "1234560000000000000000000000000000000000000000000000000000000000",
        false,
        false,
        Some(0x2012_3456),
    ),
    (0xff12_3456, "", false, true, None),
];

fn hex_to_u256(h: &str) -> U256 {
    if h.is_empty() {
        return U256::zero();
    }
    U256::from_str_radix(h, 16).unwrap()
}

#[test]
fn bitcoin_core_set_compact_vectors() {
    for &(bits, hex, neg, ovf, get_compact) in SET_COMPACT {
        let core_ok = !neg && !ovf && !hex_to_u256(hex).is_zero();
        // The port reproduces Core's flags exactly.
        let (v, n, o) = gnb_audit_consistency::core_set_compact(bits);
        assert_eq!((n, o), (neg, ovf), "Core port flags for {bits:#010x}");
        if !ovf {
            assert_eq!(v, hex_to_u256(hex), "Core port value for {bits:#010x}");
        }
        let gnb = try_bits_to_target(bits);
        assert_eq!(gnb.is_ok(), core_ok, "accept/reject differs from Core for {bits:#010x}: {gnb:?}");
        if let Ok(t) = gnb {
            assert_eq!(u256_from_be(&t.0), hex_to_u256(hex), "decoded value for {bits:#010x}");
            if let Some(c) = get_compact {
                assert_eq!(target_to_bits(&t), c, "GetCompact for {bits:#010x}");
            }
        }
        assert_eq!(gnb.ok().map(|t| t.0), core_derive_target(bits).map(u256_to_be));
    }
}

#[test]
fn bitcoin_core_never_emits_the_sign_bit() {
    // arith_uint256_tests.cpp: `num = 0x80; GetCompact() == 0x02008000`.
    let mut t = [0u8; 32];
    t[31] = 0x80;
    assert_eq!(target_to_bits(&Target(t)), 0x0200_8000);
    assert_eq!(core_get_compact(U256::from(0x80u32)), 0x0200_8000);
}

#[test]
fn bitcoin_core_check_proof_of_work_rejections() {
    // pow_tests.cpp: CheckProofOfWork_test_negative_target / _overflow_target /
    // _zero_target. GnB must reject the same encodings outright.
    let pow_limit = try_bits_to_target(gnb_crypto::core::POW_LIMIT_BITS).unwrap();
    let neg = target_to_bits(&pow_limit) | 0x0080_0000; // GetCompact(true)
    assert!(try_bits_to_target(neg).is_err(), "negative target accepted");
    assert!(try_bits_to_target(!0x0080_0000u32).is_err(), "overflow target accepted");
    assert!(try_bits_to_target(0).is_err(), "zero target accepted");
    // A target above the pow limit decodes, but can never equal the
    // consensus-expected bits, which ASERT clamps to the limit.
    let params = gnb_crypto::core::asert_params();
    assert_eq!(params.pow_limit, pow_limit);
}
