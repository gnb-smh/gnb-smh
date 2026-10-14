//! Difficulty arithmetic on adversarial input: compact `bits` <-> target,
//! chain work, and ASERT.
//!
//! * decoding never panics; a decoded target re-encodes to bits that decode
//!   to a target no larger (rounds down) and is stable after one round trip;
//! * work is 0 exactly for malformed bits and monotone in the target;
//! * ASERT never panics, stays in [1, pow_limit], is monotone in the parent
//!   time, and equals an independent U512 implementation of the aserti3-2d
//!   step (exact product, single net shift; audit fix AUD-1) for every anchor
//!   up to the pow limit;
//! * GnB's own parameters and genesis anchor are exercised on every input.
#![no_main]

use gnb_smh::difficulty::{
    asert_next_target, target_to_bits, try_bits_to_target, work, work_from_bits, AsertAnchor,
    AsertError, AsertParams, Target,
};
use libfuzzer_sys::fuzz_target;
use primitive_types::{U256, U512};

fn take<const N: usize>(data: &[u8], at: &mut usize) -> [u8; N] {
    let mut out = [0u8; N];
    for b in out.iter_mut() {
        *b = data.get(*at).copied().unwrap_or(0);
        *at += 1;
    }
    out
}

/// Exact ASERT with unbounded-enough integers: the reference definition
/// (reference/gnb_difficulty.py).
fn oracle(p: &AsertParams, a: &AsertAnchor, parent_time: i64, height: u64) -> Result<Target, AsertError> {
    if height <= a.height {
        return Err(AsertError::HeightNotAboveAnchor);
    }
    let anchor = try_bits_to_target(a.bits).map_err(AsertError::InvalidAnchor)?;
    let schedule = (p.target_spacing as i128)
        .checked_mul((height - a.height - 1) as i128)
        .ok_or(AsertError::ArithmeticOverflow)?;
    let ahead = (parent_time as i128 - a.timestamp as i128)
        .checked_sub(schedule)
        .ok_or(AsertError::ArithmeticOverflow)?;
    let exponent = ahead.checked_mul(65_536).ok_or(AsertError::ArithmeticOverflow)?.div_euclid(p.halflife as i128);
    let shifts = exponent >> 16;
    let frac = (exponent & 0xFFFF) as u128;
    let factor = 65_536u128
        + ((195_766_423_245_049u128 * frac + 971_821_376u128 * frac * frac + 5_127u128 * frac * frac * frac
            + (1u128 << 47))
            >> 48);
    let limit = U256::from_big_endian(&p.pow_limit.0);
    if shifts >= 256 {
        return Ok(p.pow_limit);
    }
    let product = U512::from(U256::from_big_endian(&anchor.0)) * U512::from(factor);
    let net = shifts - 16;
    let value = if net >= 0 {
        // product < 2^273 and net <= 239: fits in 512 bits.
        product << (net as usize)
    } else if -net >= 512 {
        U512::zero()
    } else {
        product >> ((-net) as usize)
    };
    let mut out = if value > U512::from(limit) { limit } else { U256::try_from(value).unwrap() };
    if out.is_zero() {
        out = U256::one();
    }
    Ok(Target(out.to_big_endian()))
}

fuzz_target!(|data: &[u8]| {
    let mut at = 0usize;
    let bits = u32::from_le_bytes(take::<4>(data, &mut at));
    let anchor_bits = u32::from_le_bytes(take::<4>(data, &mut at));
    let parent_time = i64::from_le_bytes(take::<8>(data, &mut at));
    let height = u64::from_le_bytes(take::<8>(data, &mut at));
    let anchor_height = u64::from_le_bytes(take::<8>(data, &mut at));
    let anchor_time = i64::from_le_bytes(take::<8>(data, &mut at));
    let dt = u32::from_le_bytes(take::<4>(data, &mut at)) as i64;
    let spacing = u16::from_le_bytes(take::<2>(data, &mut at)) as i64 + 1;
    let halflife = u32::from_le_bytes(take::<4>(data, &mut at)) as i64 + 1;

    // Compact bits and work.
    match try_bits_to_target(bits) {
        Ok(t) => {
            let re = target_to_bits(&t);
            let back = try_bits_to_target(re).expect("encoded bits must decode");
            assert!(back <= t, "compact encoding rounded up");
            assert_eq!(target_to_bits(&back), re, "compact encoding not stable");
            assert!(work(&t) >= 1);
            assert_eq!(work_from_bits(bits), work(&t));
            assert!(work(&back) >= work(&t), "work not monotone");
        }
        Err(_) => assert_eq!(work_from_bits(bits), 0, "malformed bits carry work"),
    }

    // GnB's real parameters and genesis anchor.
    let gnb = AsertParams {
        target_spacing: 30,
        halflife: 7_200,
        pow_limit: try_bits_to_target(0x2100_FFFF).unwrap(),
    };
    let genesis = AsertAnchor { height: 0, bits: 0x1F0E_9036, timestamp: 1_791_429_092 };
    let one = {
        let mut o = [0u8; 32];
        o[31] = 1;
        Target(o)
    };
    if let Ok(t) = asert_next_target(&gnb, &genesis, parent_time, height) {
        assert!(t >= one && t <= gnb.pow_limit);
        assert_eq!(Ok(t), oracle(&gnb, &genesis, parent_time, height));
        if let Some(later) = parent_time.checked_add(dt) {
            let t2 = asert_next_target(&gnb, &genesis, later, height).unwrap();
            assert!(t2 >= t, "later parent gave a harder target");
        }
    }

    // Generic parameters and anchors (the library rule), anchors up to the limit.
    let params = AsertParams { target_spacing: spacing, halflife, pow_limit: gnb.pow_limit };
    let anchor = AsertAnchor { height: anchor_height, bits: anchor_bits, timestamp: anchor_time };
    let got = asert_next_target(&params, &anchor, parent_time, height);
    let want = oracle(&params, &anchor, parent_time, height);
    match (got, want) {
        (Ok(g), Ok(w)) => {
            assert_eq!(g, w, "ASERT differs from the exact step");
            assert!(g >= one && g <= params.pow_limit);
        }
        (Err(g), Err(w)) => assert_eq!(std::mem::discriminant(&g), std::mem::discriminant(&w)),
        (g, w) => panic!("ASERT result {g:?} vs oracle {w:?}"),
    }
});
