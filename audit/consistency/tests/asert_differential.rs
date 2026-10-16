//! ASERT (aserti3-2d) consistency.
//!
//! Oracle: the fixed-point step of BCHN `CalculateASERT` (src/pow.cpp), ported
//! in `gnb_audit_consistency::bchn_asert_target`, which multiplies the full
//! target by the 17-bit factor before a single shift.
//!
//! Before audit fix AUD-1, GnB shifted the product right by 16 first
//! (saturating at 2^256 - 1) and then shifted bit by bit, so full 256-bit
//! targets differed from the oracle in their lowest bits and anchors at or
//! above ~2^255 could come out up to 2x too hard. GnB now multiplies exactly
//! and applies the net shift once, so these tests require the full targets
//! (not only the compact `bits`, which consensus compares) to equal the
//! oracle. A port of the pre-fix step (`legacy_gnb_asert_target`) proves the
//! fix changed no compact result for GnB's real parameters and anchor.
//!
//! Also checked as properties over GnB's real consensus parameters: the
//! result is in [1, pow_limit]; it is monotone in the parent timestamp; one
//! half-life ahead of schedule exactly doubles the target; extreme inputs
//! return an error or a clamped target, never a panic.

use gnb_audit_consistency::{bchn_asert_target, u256_from_be, u256_to_be};
use gnb_smh::difficulty::{
    asert_next_target, target_to_bits, try_bits_to_target, AsertAnchor, AsertParams, Target,
};
use primitive_types::{U256, U512};
use proptest::prelude::*;

/// GnB's ASERT step as it was before fix AUD-1 (crates/gnb-smh/src/
/// difficulty.rs at commit 125e9e5): `(target * factor) >> 16` saturated at
/// 2^256 - 1, then shifted one bit at a time, overflow on a left shift
/// clamping to the pow limit.
fn legacy_gnb_asert_target(params: &AsertParams, anchor: &AsertAnchor, parent_time: i64, height: u64) -> Target {
    let anchor_target = u256_from_be(&try_bits_to_target(anchor.bits).unwrap().0);
    let pow_limit = u256_from_be(&params.pow_limit.0);
    let ahead = parent_time as i128
        - anchor.timestamp as i128
        - params.target_spacing as i128 * (height - anchor.height - 1) as i128;
    let exponent = (ahead * 65_536).div_euclid(params.halflife as i128);
    let shifts = exponent >> 16;
    let frac = (exponent & 0xFFFF) as u128;
    let factor: u128 = 65_536
        + ((195_766_423_245_049u128 * frac + 971_821_376u128 * frac * frac + 5_127u128 * frac * frac * frac
            + (1u128 << 47))
            >> 48);
    let wide = (U512::from(anchor_target) * U512::from(factor)) >> 16;
    let mut t = if wide > U512::from(U256::MAX) { U256::MAX } else { U256::try_from(wide).unwrap() };
    if shifts >= 256 {
        return params.pow_limit;
    }
    if shifts > 0 {
        for _ in 0..shifts {
            if t.bit(255) {
                return params.pow_limit;
            }
            t <<= 1;
        }
    } else if shifts < 0 {
        let n = (-shifts).min(256) as usize;
        t = if n >= 256 { U256::zero() } else { t >> n };
    }
    if t > pow_limit {
        t = pow_limit;
    }
    if t.is_zero() {
        t = U256::one();
    }
    Target(u256_to_be(t))
}

fn gnb_params() -> (AsertParams, AsertAnchor) {
    (gnb_crypto::core::asert_params(), gnb_crypto::core::asert_anchor())
}

fn oracle(params: &AsertParams, anchor: &AsertAnchor, parent_time: i64, height: u64) -> Target {
    let anchor_target = u256_from_be(&try_bits_to_target(anchor.bits).unwrap().0);
    let t = bchn_asert_target(
        anchor_target,
        params.target_spacing,
        params.halflife,
        u256_from_be(&params.pow_limit.0),
        parent_time as i128 - anchor.timestamp as i128,
        (height - anchor.height - 1) as i128,
    )
    .expect("oracle overflow");
    Target(u256_to_be(t))
}

fn arb_anchor_bits() -> impl Strategy<Value = u32> {
    // Valid compact values from very hard (exponent 4) up to the pow limit
    // (0x2100ffff). Exponent 0x21 covers anchors from 2^240 to the limit,
    // including the band at and above 2^255 where the pre-fix step saturated
    // (see `high_anchor_saturation_diverges_from_aserti3_2d`).
    prop_oneof![
        (4u32..=0x20, 0x0001_0000u32..0x0080_0000).prop_map(|(e, m)| (e << 24) | m),
        (0x0000_0001u32..=0x0000_ffff).prop_map(|m| (0x21 << 24) | m),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100_000))]

    /// Real GnB parameters and anchor; parent timestamps up to ±20 years from
    /// schedule, heights up to 2^32.
    #[test]
    fn gnb_asert_bits_match_bchn_construction(
        height in 1u64..=(1u64 << 32),
        skew in -630_720_000i64..=630_720_000i64,
    ) {
        let (params, anchor) = gnb_params();
        let schedule = anchor.timestamp + params.target_spacing * (height as i64 - 1);
        let parent_time = schedule + skew;
        let gnb = asert_next_target(&params, &anchor, parent_time, height).unwrap();
        let ora = oracle(&params, &anchor, parent_time, height);
        prop_assert_eq!(target_to_bits(&gnb), target_to_bits(&ora),
            "height={} skew={}", height, skew);
        prop_assert_eq!(gnb, ora, "full target: height={} skew={}", height, skew);
    }

    /// AUD-1 consensus proof: on GnB's real parameters and genesis anchor the
    /// fixed step yields exactly the compact `bits` of the pre-fix step.
    #[test]
    fn gnb_asert_bits_unchanged_by_the_aud1_fix(
        height in 1u64..=(1u64 << 32),
        skew in -630_720_000i64..=630_720_000i64,
    ) {
        let (params, anchor) = gnb_params();
        let schedule = anchor.timestamp + params.target_spacing * (height as i64 - 1);
        let parent_time = schedule + skew;
        let new = asert_next_target(&params, &anchor, parent_time, height).unwrap();
        let old = legacy_gnb_asert_target(&params, &anchor, parent_time, height);
        prop_assert_eq!(target_to_bits(&new), target_to_bits(&old),
            "height={} skew={}", height, skew);
    }

    /// Random anchors (hard to easy, at any height) under GnB's spacing and
    /// half-life. GnB anchors at genesis (height 0); a non-zero anchor height
    /// pins the generic library rule as well.
    #[test]
    fn random_anchor_bits_match_bchn_construction(
        anchor_bits in arb_anchor_bits(),
        anchor_height in 0u64..=1_000_000,
        blocks in 1u64..=10_000_000,
        skew in -100_000_000i64..=100_000_000i64,
    ) {
        let (params, mut anchor) = gnb_params();
        anchor.bits = anchor_bits;
        anchor.height = anchor_height;
        let height = anchor_height + blocks;
        prop_assert!(try_bits_to_target(anchor_bits).unwrap() <= params.pow_limit);
        let schedule = anchor.timestamp + params.target_spacing * (blocks as i64 - 1);
        let parent_time = schedule + skew;
        let gnb = asert_next_target(&params, &anchor, parent_time, height).unwrap();
        let ora = oracle(&params, &anchor, parent_time, height);
        prop_assert_eq!(target_to_bits(&gnb), target_to_bits(&ora),
            "anchor={:#010x}@{} height={} skew={}", anchor_bits, anchor_height, height, skew);
        prop_assert_eq!(gnb, ora,
            "full target: anchor={:#010x}@{} height={} skew={}", anchor_bits, anchor_height, height, skew);
    }

    #[test]
    fn target_is_bounded_and_monotone_in_time(
        height in 1u64..=50_000_000,
        t1 in -2_000_000_000i64..=4_000_000_000i64,
        dt in 0i64..=100_000_000,
    ) {
        let (params, anchor) = gnb_params();
        let a = asert_next_target(&params, &anchor, t1, height).unwrap();
        let b = asert_next_target(&params, &anchor, t1 + dt, height).unwrap();
        let mut one = [0u8; 32];
        one[31] = 1;
        prop_assert!(a >= Target(one) && a <= params.pow_limit);
        prop_assert!(a <= b, "later parent must never yield a harder target");
    }

    #[test]
    fn extreme_inputs_never_panic(height in any::<u64>(), parent_time in any::<i64>()) {
        let (params, anchor) = gnb_params();
        let r = std::panic::catch_unwind(|| asert_next_target(&params, &anchor, parent_time, height));
        prop_assert!(r.is_ok(), "panic at height={} parent_time={}", height, parent_time);
    }
}

#[test]
fn one_halflife_ahead_doubles_the_target() {
    let (params, mut anchor) = gnb_params();
    // Choose an anchor far below the limit so the doubling is not clamped.
    anchor.bits = 0x1d00_ffff;
    let anchor_t = u256_from_be(&try_bits_to_target(anchor.bits).unwrap().0);
    for (anchor_h, blocks) in [0u64, 777].into_iter().flat_map(|a| [1u64, 2, 1_000, 2_000_000].map(|b| (a, b))) {
        anchor.height = anchor_h;
        let height = anchor_h + blocks;
        let schedule = anchor.timestamp + params.target_spacing * (blocks as i64 - 1);
        let on = asert_next_target(&params, &anchor, schedule, height).unwrap();
        let ahead = asert_next_target(&params, &anchor, schedule + params.halflife, height).unwrap();
        let behind = asert_next_target(&params, &anchor, schedule - params.halflife, height).unwrap();
        assert_eq!(u256_from_be(&on.0), anchor_t, "on schedule keeps the anchor target");
        assert_eq!(u256_from_be(&ahead.0), anchor_t * 2, "one half-life ahead doubles it");
        assert_eq!(u256_from_be(&behind.0), anchor_t / 2, "one half-life behind halves it");
    }
}

#[test]
fn full_target_low_bit_divergence_is_measured() {
    // Deterministic sweep over GnB's real parameters and anchor: count
    // full-target and compact differences against BCHN's multiply-then-shift
    // order, and compact differences against the pre-AUD-1 step.
    let (params, anchor) = gnb_params();
    let (mut n, mut diff, mut bits_diff, mut legacy_bits_diff, mut legacy_full_diff) = (0u64, 0u64, 0u64, 0u64, 0u64);
    for height in (1u64..=2_000_001).step_by(9_973) {
        for skew in (-3_000_000i64..=3_000_000).step_by(7_919) {
            let schedule = anchor.timestamp + params.target_spacing * (height as i64 - 1);
            let g = asert_next_target(&params, &anchor, schedule + skew, height).unwrap();
            let o = oracle(&params, &anchor, schedule + skew, height);
            let l = legacy_gnb_asert_target(&params, &anchor, schedule + skew, height);
            n += 1;
            if g != o {
                diff += 1;
            }
            if target_to_bits(&g) != target_to_bits(&o) {
                bits_diff += 1;
            }
            if g != l {
                legacy_full_diff += 1;
            }
            if target_to_bits(&g) != target_to_bits(&l) {
                legacy_bits_diff += 1;
            }
        }
    }
    println!(
        "asert sweep: {n} points; vs oracle: full-target differences {diff}, compact-bits differences \
         {bits_diff}; vs pre-AUD-1 step: full-target differences {legacy_full_diff}, compact-bits \
         differences {legacy_bits_diff}"
    );
    assert_eq!(diff, 0, "GnB now computes the aserti3-2d step exactly");
    assert_eq!(bits_diff, 0);
    assert_eq!(legacy_bits_diff, 0, "the AUD-1 fix must not change any consensus bits");
}

/// Finding AUD-1 (AUD-ASERT-SAT), now fixed: the pre-fix `mul_u64_shr16`
/// saturated `target * factor >> 16` at 2^256 - 1 *before* the right shift by
/// a negative exponent. For anchor targets of about 2^255 and above this
/// returned a target up to ~2x harder than the aserti3-2d arithmetic (BCHN
/// instead requires 32 spare leading bits in pow_limit, so its intermediate
/// never overflows). GnB now holds the product in 320 bits and applies the
/// net shift once, so the result equals the oracle. GnB's deployed anchor is
/// the genesis target (~2^244), far below the threshold, so mainnet
/// consensus was never affected (`gnb_asert_bits_unchanged_by_the_aud1_fix`).
#[test]
fn high_anchor_saturation_diverges_from_aserti3_2d() {
    let (params, mut anchor) = gnb_params();
    anchor.bits = 0x2100_a34e; // ~0.64 * 2^256, below the pow limit
    let height = 1;
    let parent_time = anchor.timestamp - 57_601; // eight half-lives behind
    let gnb = asert_next_target(&params, &anchor, parent_time, height).unwrap();
    let ora = oracle(&params, &anchor, parent_time, height);
    let old = legacy_gnb_asert_target(&params, &anchor, parent_time, height);
    assert_eq!(target_to_bits(&old), 0x1f7f_ffff, "pre-fix GnB behaviour (saturated)");
    assert_eq!(target_to_bits(&ora), 0x2000_a349, "exact aserti3-2d arithmetic");
    assert_eq!(target_to_bits(&gnb), 0x2000_a349, "fixed GnB equals the oracle");
    assert_eq!(gnb, ora, "full target equals the oracle");

    // The deployed anchor keeps at least 11 bits of headroom below 2^255.
    let genesis = try_bits_to_target(gnb_crypto::core::GENESIS_BITS).unwrap();
    let headroom = u256_from_be(&genesis.0).leading_zeros();
    assert!(headroom >= 11, "genesis anchor has {headroom} leading zero bits");
}

/// Results between the pow limit (0xffff << 240) and 2^256 must be clamped to
/// the limit even when the fixed-point step does not overflow 256 bits.
#[test]
fn clamps_to_pow_limit_inside_the_non_overflowing_band() {
    let (params, mut anchor) = gnb_params();
    anchor.bits = gnb_crypto::core::POW_LIMIT_BITS; // anchor exactly at the limit
    for ahead in [1i64, 60, 600, 3_600] {
        let parent_time = anchor.timestamp + ahead;
        let t = asert_next_target(&params, &anchor, parent_time, 1).unwrap();
        assert_eq!(t, params.pow_limit, "ahead={ahead}s must clamp to the pow limit");
    }
}
