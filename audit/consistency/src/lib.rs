//! Reference oracles used by the consistency tests.
//!
//! Each function is a line-for-line port of the cited upstream routine, kept
//! deliberately naive so it can be checked against the C++ by eye.

#![forbid(unsafe_code)]

use primitive_types::U256;

/// Bitcoin Core `arith_uint256::SetCompact` (src/arith_uint256.cpp).
/// Returns (value, fNegative, fOverflow).
pub fn core_set_compact(n_compact: u32) -> (U256, bool, bool) {
    let n_size = (n_compact >> 24) as i32;
    let mut n_word = n_compact & 0x007f_ffff;
    let value;
    if n_size <= 3 {
        n_word >>= 8 * (3 - n_size);
        value = U256::from(n_word);
    } else {
        let shift = 8 * (n_size - 3) as u32;
        // C++ `<<=` on base_uint drops bits shifted past 256.
        value = if shift >= 256 { U256::zero() } else { U256::from(n_word) << shift };
    }
    let negative = n_word != 0 && (n_compact & 0x0080_0000) != 0;
    let overflow = n_word != 0
        && ((n_size > 34) || (n_word > 0xff && n_size > 33) || (n_word > 0xffff && n_size > 32));
    (value, negative, overflow)
}

/// Bitcoin Core `DeriveTarget` (src/pow.cpp) without the pow-limit bound:
/// a compact value is acceptable iff it is not negative, does not overflow,
/// and is not zero.
pub fn core_derive_target(n_compact: u32) -> Option<U256> {
    let (v, neg, ovf) = core_set_compact(n_compact);
    if neg || ovf || v.is_zero() {
        None
    } else {
        Some(v)
    }
}

/// Bitcoin Core `arith_uint256::GetCompact(false)` (src/arith_uint256.cpp).
pub fn core_get_compact(v: U256) -> u32 {
    let n_size = v.bits().div_ceil(8) as u32;
    let mut n_compact: u32 = if n_size <= 3 {
        (v.low_u64() << (8 * (3 - n_size))) as u32
    } else {
        (v >> (8 * (n_size - 3))).low_u64() as u32
    };
    let mut n_size = n_size;
    if n_compact & 0x0080_0000 != 0 {
        n_compact >>= 8;
        n_size += 1;
    }
    n_compact | (n_size << 24)
}

pub fn u256_from_be(b: &[u8; 32]) -> U256 {
    U256::from_big_endian(b)
}

pub fn u256_to_be(v: U256) -> [u8; 32] {
    v.to_big_endian()
}

/// Bitcoin Core `ComputeMerkleRoot(hashes, &mutated)` (src/consensus/merkle.cpp):
/// returns the root and whether two identical sibling hashes were seen.
pub fn core_compute_merkle_root(mut hashes: Vec<[u8; 32]>) -> ([u8; 32], bool) {
    use sha2::{Digest, Sha256};
    let mut mutation = false;
    if hashes.is_empty() {
        return ([0u8; 32], false);
    }
    while hashes.len() > 1 {
        let mut pos = 0;
        while pos + 1 < hashes.len() {
            if hashes[pos] == hashes[pos + 1] {
                mutation = true;
            }
            pos += 2;
        }
        if hashes.len() & 1 == 1 {
            let last = *hashes.last().unwrap();
            hashes.push(last);
        }
        hashes = hashes
            .chunks(2)
            .map(|p| {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&p[0]);
                buf[32..].copy_from_slice(&p[1]);
                Sha256::digest(Sha256::digest(buf)).into()
            })
            .collect();
    }
    (hashes[0], mutation)
}

/// aserti3-2d fixed-point step as written in BCHN `CalculateASERT`
/// (src/pow.cpp), with GnB's anchor convention (time measured from the anchor
/// block itself, `height_delta` = blocks from the anchor up to and including
/// the parent) and floor division of the exponent, as GnB documents.
///
/// BCHN multiplies the full 256-bit target by the 17-bit factor and applies a
/// single shift of `shifts - 16`. Returns `None` when the 256-bit product
/// would overflow (BCHN asserts 32 spare leading bits in pow_limit instead).
pub fn bchn_asert_target(
    anchor_target: U256,
    target_spacing: i64,
    halflife: i64,
    pow_limit: U256,
    time_delta: i128,
    height_delta: i128,
) -> Option<U256> {
    let ahead = time_delta - target_spacing as i128 * height_delta;
    let exponent = (ahead * 65_536).div_euclid(halflife as i128);
    let mut shifts = exponent >> 16;
    let frac = (exponent & 0xFFFF) as u128;
    let factor: u128 = 65_536
        + ((195_766_423_245_049u128 * frac
            + 971_821_376u128 * frac * frac
            + 5_127u128 * frac * frac * frac
            + (1u128 << 47))
            >> 48);
    // 512-bit product so the oracle itself never truncates.
    let wide = primitive_types::U512::from(anchor_target) * primitive_types::U512::from(factor);
    shifts -= 16;
    let next = if shifts <= 0 {
        let s = (-shifts).min(512) as u32;
        if s >= 512 { primitive_types::U512::zero() } else { wide >> s }
    } else if shifts >= 256 {
        return Some(pow_limit);
    } else {
        let shifted = wide << (shifts as u32);
        if (shifted >> (shifts as u32)) != wide {
            return Some(pow_limit);
        }
        shifted
    };
    let max256 = primitive_types::U512::from(U256::MAX);
    let mut out = if next > max256 { pow_limit } else { U256::try_from(next).ok()? };
    if out > pow_limit {
        out = pow_limit;
    }
    if out.is_zero() {
        out = U256::one();
    }
    Some(out)
}
