//! Difficulty: compact `bits` ⇄ 256-bit target, chain work, and ASERT.
//!
//! The compact form follows Bitcoin's `nBits`: the high byte is a byte
//! exponent, the low 23 bits a mantissa, `target = mantissa << 8*(exp-3)`.
//! Decoding fails hard on every malformed encoding; the infallible wrapper
//! maps malformed bits to the zero target, which no output can meet.
//!
//! Retargeting is ASERT (absolutely scheduled exponentially rising targets,
//! the aserti3-2d construction): every block's target is computed from one
//! fixed anchor and the parent's timestamp, so there is no window to game
//! and no accumulated rounding drift.
//!
//! ```text
//! exponent = (parent_time - anchor_time - T * (height - anchor_height - 1)) / halflife
//! target   = anchor_target * 2^exponent,  clamped to [1, pow_limit]
//! ```
//!
//! `2^frac` for the fractional part uses the aserti3-2d cubic in 16-bit
//! fixed point; the integer part is an exact bit shift.

use core::cmp::Ordering;
use core::fmt;

/// A 256-bit target as 32 big-endian bytes. Valid iff `out < target`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Target(pub [u8; 32]);

impl Target {
    /// The largest target (easiest).
    pub const MAX: Target = Target([0xFF; 32]);
    /// The zero target. No output meets it; consensus never produces it.
    pub const ZERO: Target = Target([0x00; 32]);

    pub const fn from_be_bytes(bytes: [u8; 32]) -> Self {
        Target(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

impl PartialOrd for Target {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Target {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0) // big-endian bytes compare as integers
    }
}

/// Why a compact `bits` value does not encode a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitsError {
    /// The sign bit (0x0080_0000) is set.
    NegativeFlag,
    /// The mantissa is zero.
    ZeroMantissa,
    /// The exponent shifts the mantissa out of the 256-bit range.
    ExponentOutOfRange { exponent: u32 },
    /// High mantissa bytes would spill past the top of the target.
    MantissaOverflow,
    /// The encoding rounds down to the zero target.
    ZeroTarget,
}

impl fmt::Display for BitsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NegativeFlag => f.write_str("compact bits has the negative flag set"),
            Self::ZeroMantissa => f.write_str("compact bits has a zero mantissa"),
            Self::ExponentOutOfRange { exponent } => {
                write!(f, "compact bits exponent {exponent} is out of the 256-bit range")
            }
            Self::MantissaOverflow => f.write_str("compact bits mantissa overflows 256 bits"),
            Self::ZeroTarget => f.write_str("compact bits encodes the zero target"),
        }
    }
}

impl std::error::Error for BitsError {}

/// Decode compact `bits`, rejecting every malformed or zero encoding.
pub fn try_bits_to_target(bits: u32) -> Result<Target, BitsError> {
    if bits & 0x0080_0000 != 0 {
        return Err(BitsError::NegativeFlag);
    }
    let exponent = bits >> 24;
    let mantissa = bits & 0x007F_FFFF;
    if mantissa == 0 {
        return Err(BitsError::ZeroMantissa);
    }
    let mut out = [0u8; 32];
    if exponent <= 3 {
        // Right shift drops low bytes: rounds the target down (harder).
        let m = mantissa >> (8 * (3 - exponent));
        out[29..32].copy_from_slice(&m.to_be_bytes()[1..4]);
    } else {
        let shift_bytes = (exponent - 3) as usize;
        if shift_bytes > 31 {
            return Err(BitsError::ExponentOutOfRange { exponent });
        }
        let low = 31 - shift_bytes; // where the lowest mantissa byte lands
        let m = mantissa.to_be_bytes(); // [0, b0, b1, b2]
        if (low < 2 && m[1] != 0) || (low < 1 && m[2] != 0) {
            return Err(BitsError::MantissaOverflow);
        }
        out[low] = m[3];
        if low >= 1 {
            out[low - 1] = m[2];
        }
        if low >= 2 {
            out[low - 2] = m[1];
        }
    }
    let t = Target(out);
    if t.is_zero() {
        return Err(BitsError::ZeroTarget);
    }
    Ok(t)
}

/// Infallible decode: malformed bits map to [`Target::ZERO`], which no block
/// can meet, so consensus fails closed.
pub fn bits_to_target(bits: u32) -> Target {
    try_bits_to_target(bits).unwrap_or(Target::ZERO)
}

/// Encode a target in compact form. Keeps the top three significant bytes,
/// so encode-then-decode rounds down (harder), never up.
pub fn target_to_bits(target: &Target) -> u32 {
    let b = &target.0;
    let Some(idx) = b.iter().position(|&x| x != 0) else {
        return 0;
    };
    let mut exponent = (32 - idx) as u32;
    let at = |k: usize| b.get(k).copied().unwrap_or(0) as u32;
    let mut mantissa = (at(idx) << 16) | (at(idx + 1) << 8) | at(idx + 2);
    if mantissa & 0x0080_0000 != 0 {
        mantissa >>= 8;
        exponent += 1;
    }
    (exponent << 24) | (mantissa & 0x007F_FFFF)
}

/// `out < target`, both big-endian.
pub fn meets_target(out: &[u8; 32], target: &Target) -> bool {
    out < &target.0
}

/// Expected number of evaluations to meet `target`, approximately
/// 2^256 / target (the spec's `work`), at least 1, saturating at `u128::MAX`.
/// The zero target has work 0: it never validates and must never add weight.
///
/// Computed as floor((2^128 - 1) / ((target >> 128) + 1)), which never
/// overstates the exact value; chain work only needs a monotone, conservative
/// measure.
pub fn work(target: &Target) -> u128 {
    if target.is_zero() {
        return 0;
    }
    let idx = target.0.iter().position(|&x| x != 0).unwrap_or(31);
    if idx >= 16 {
        // target < 2^128, so 2^256 / target >= 2^128: saturate.
        return u128::MAX;
    }
    // target >= 2^128: work = 2^256 / target < 2^128. Use the top 16 bytes
    // (target >> 128) + 1 as the divisor of 2^128.
    let mut hi: u128 = 0;
    for &x in &target.0[..16] {
        hi = (hi << 8) | x as u128;
    }
    match hi.checked_add(1) {
        Some(d) => (u128::MAX / d).max(1),
        None => 1,
    }
}

/// Work for compact `bits`; malformed bits have work 0 (they never validate).
pub fn work_from_bits(bits: u32) -> u128 {
    work(&bits_to_target(bits))
}

// ── ASERT ────────────────────────────────────────────────────────────────────

/// ASERT parameters. All fields are consensus constants of a chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AsertParams {
    /// Target spacing in seconds.
    pub target_spacing: i64,
    /// Half-life in seconds: an excess of one half-life over schedule halves
    /// the difficulty (doubles the target).
    pub halflife: i64,
    /// Easiest target the chain accepts. The result never exceeds it.
    pub pow_limit: Target,
}

/// Anchor of the schedule (the genesis block on GnB).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AsertAnchor {
    pub height: u64,
    pub bits: u32,
    /// Timestamp of the anchor block itself.
    pub timestamp: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsertError {
    /// `height` must be strictly above the anchor height.
    HeightNotAboveAnchor,
    /// The anchor bits do not decode to a target.
    InvalidAnchor(BitsError),
    /// A schedule intermediate overflowed i128.
    ArithmeticOverflow,
}

impl fmt::Display for AsertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeightNotAboveAnchor => f.write_str("ASERT height is not above the anchor"),
            Self::InvalidAnchor(e) => write!(f, "invalid ASERT anchor bits: {e}"),
            Self::ArithmeticOverflow => f.write_str("ASERT arithmetic overflow"),
        }
    }
}

impl std::error::Error for AsertError {}

/// Target for the block at `height` whose parent has timestamp `parent_time`.
pub fn asert_next_target(
    params: &AsertParams,
    anchor: &AsertAnchor,
    parent_time: i64,
    height: u64,
) -> Result<Target, AsertError> {
    if height <= anchor.height {
        return Err(AsertError::HeightNotAboveAnchor);
    }
    let anchor_target = try_bits_to_target(anchor.bits).map_err(AsertError::InvalidAnchor)?;

    // Blocks between the anchor and the parent, inclusive of the parent.
    let height_delta = (height - anchor.height - 1) as i128;
    let time_delta = parent_time as i128 - anchor.timestamp as i128;
    let schedule = (params.target_spacing as i128)
        .checked_mul(height_delta)
        .ok_or(AsertError::ArithmeticOverflow)?;
    let ahead = time_delta.checked_sub(schedule).ok_or(AsertError::ArithmeticOverflow)?;
    // Exponent in 1/65536 units, floor division (toward -inf) like aserti3-2d.
    let exponent = (ahead.checked_mul(65_536).ok_or(AsertError::ArithmeticOverflow)?)
        .div_euclid(params.halflife as i128);

    let shifts = exponent >> 16; // floor
    let frac = (exponent & 0xFFFF) as u64; // 0..65535
    // 2^(frac/65536) * 65536, aserti3-2d cubic (max error < 0.013%).
    let factor: u64 = 65_536
        + ((195_766_423_245_049u128 * frac as u128
            + 971_821_376u128 * (frac as u128).pow(2)
            + 5_127u128 * (frac as u128).pow(3)
            + (1u128 << 47))
            >> 48) as u64;

    let mut t = mul_u64_shr16(&anchor_target.0, factor);
    if shifts >= 256 {
        return Ok(params.pow_limit);
    }
    if shifts > 0 {
        for _ in 0..shifts {
            if shl1(&mut t) {
                return Ok(params.pow_limit);
            }
        }
    } else if shifts < 0 {
        let n = (-shifts).min(256);
        for _ in 0..n {
            shr1(&mut t);
        }
    }
    let mut out = Target(t);
    if out > params.pow_limit {
        out = params.pow_limit;
    }
    if out.is_zero() {
        let mut one = [0u8; 32];
        one[31] = 1;
        out = Target(one);
    }
    Ok(out)
}

/// Compact bits of [`asert_next_target`]. The compact round-down never
/// produces a target above the computed one.
pub fn asert_next_bits(
    params: &AsertParams,
    anchor: &AsertAnchor,
    parent_time: i64,
    height: u64,
) -> Result<u32, AsertError> {
    asert_next_target(params, anchor, parent_time, height).map(|t| target_to_bits(&t))
}

/// (t * factor) >> 16, saturating at 2^256 - 1. `factor` < 2^17.
fn mul_u64_shr16(t: &[u8; 32], factor: u64) -> [u8; 32] {
    // 35 bytes hold t * factor < 2^273. Each step: byte * factor + carry < 2^26.
    let mut wide = [0u8; 35];
    let mut carry: u64 = 0;
    for i in (0..32).rev() {
        let p = t[i] as u64 * factor + carry;
        wide[i + 3] = p as u8;
        carry = p >> 8;
    }
    wide[2] = carry as u8;
    wide[1] = (carry >> 8) as u8;
    wide[0] = (carry >> 16) as u8;
    // >> 16 drops the two lowest bytes, leaving wide[0..33]; anything in
    // wide[0] is at or above 2^256.
    if wide[0] != 0 {
        return [0xFF; 32];
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&wide[1..33]);
    out
}

/// In-place ×2; returns true on overflow.
fn shl1(t: &mut [u8; 32]) -> bool {
    let mut carry = 0u8;
    for b in t.iter_mut().rev() {
        let v = ((*b as u16) << 1) | carry as u16;
        *b = v as u8;
        carry = (v >> 8) as u8;
    }
    carry != 0
}

/// In-place floor(÷2).
fn shr1(t: &mut [u8; 32]) {
    let mut carry = 0u8;
    for b in t.iter_mut() {
        let v = ((carry as u16) << 8) | *b as u16;
        *b = (v >> 1) as u8;
        carry = (v & 1) as u8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMIT_BITS: u32 = 0x2100_FFFF;

    fn params() -> AsertParams {
        AsertParams { target_spacing: 30, halflife: 7_200, pow_limit: bits_to_target(LIMIT_BITS) }
    }

    fn anchor() -> AsertAnchor {
        AsertAnchor { height: 0, bits: 0x1F00_FFFF, timestamp: 1_000_000 }
    }

    #[test]
    fn rejects_malformed_bits() {
        assert_eq!(try_bits_to_target(0x0480_0001), Err(BitsError::NegativeFlag));
        assert_eq!(try_bits_to_target(0x2000_0000), Err(BitsError::ZeroMantissa));
        assert_eq!(try_bits_to_target(0xFF00_FFFF), Err(BitsError::ExponentOutOfRange { exponent: 0xFF }));
        assert_eq!(try_bits_to_target(0x2201_0000), Err(BitsError::MantissaOverflow));
        assert_eq!(try_bits_to_target(0x0100_0001), Err(BitsError::ZeroTarget));
        assert_eq!(bits_to_target(0xFF00_FFFF), Target::ZERO);
    }

    #[test]
    fn compact_round_trip() {
        for bits in [0x1D00_FFFF, 0x1F00_FFFF, 0x2000_FFFF, LIMIT_BITS, 0x1B04_04CB, 0x0300_7FFF] {
            if let Ok(t) = try_bits_to_target(bits) {
                assert_eq!(bits_to_target(target_to_bits(&t)), t, "bits {bits:#x}");
            }
        }
        let t = bits_to_target(LIMIT_BITS);
        assert_eq!(&t.0[..3], &[0xFF, 0xFF, 0x00]);
    }

    #[test]
    fn compact_encoding_rounds_down() {
        let mut t = [0u8; 32];
        t[10] = 0x12;
        t[11] = 0x34;
        t[12] = 0x56;
        t[13] = 0x78; // dropped by the compact form
        let r = bits_to_target(target_to_bits(&Target(t)));
        assert!(r < Target(t));
    }

    #[test]
    fn work_is_monotone_and_saturates() {
        let easy = work_from_bits(LIMIT_BITS);
        let hard = work_from_bits(0x1F00_FFFF);
        assert_eq!(easy, 1);
        assert!(hard > easy);
        assert_eq!(work_from_bits(0x1000_FFFF), u128::MAX);
        assert_eq!(work_from_bits(0xFF00_FFFF), 0);
    }

    #[test]
    fn asert_on_schedule_keeps_anchor_target() {
        let p = params();
        let a = anchor();
        for h in [1u64, 2, 100, 10_000] {
            let parent_time = a.timestamp + 30 * (h as i64 - 1);
            assert_eq!(asert_next_bits(&p, &a, parent_time, h).unwrap(), a.bits, "h={h}");
        }
    }

    #[test]
    fn asert_halflife_doubles_and_halves() {
        let p = params();
        let a = anchor();
        let base = bits_to_target(a.bits);
        let slow = asert_next_target(&p, &a, a.timestamp + 7_200, 1).unwrap();
        let mut doubled = base.0;
        assert!(!shl1(&mut doubled));
        assert_eq!(slow, Target(doubled));
        let fast = asert_next_target(&p, &a, a.timestamp - 7_200, 1).unwrap();
        let mut halved = base.0;
        shr1(&mut halved);
        assert_eq!(fast, Target(halved));
    }

    #[test]
    fn asert_fraction_is_monotone() {
        let p = params();
        let a = anchor();
        let mut prev = Target::ZERO;
        for dt in (0..7_200).step_by(97) {
            let t = asert_next_target(&p, &a, a.timestamp + dt, 1).unwrap();
            assert!(t >= prev);
            prev = t;
        }
    }

    #[test]
    fn asert_clamps_to_pow_limit_and_one() {
        let p = params();
        let a = anchor();
        let t = asert_next_target(&p, &a, a.timestamp + 10_000_000, 1).unwrap();
        assert_eq!(t, p.pow_limit);
        let t = asert_next_target(&p, &a, a.timestamp, 50_000_000).unwrap();
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(t, Target(one));
    }

    #[test]
    fn asert_rejects_bad_inputs() {
        let p = params();
        let a = anchor();
        assert_eq!(asert_next_bits(&p, &a, a.timestamp, 0), Err(AsertError::HeightNotAboveAnchor));
        let bad = AsertAnchor { bits: 0xFF00_FFFF, ..a };
        assert!(matches!(asert_next_bits(&p, &bad, a.timestamp, 1), Err(AsertError::InvalidAnchor(_))));
        // Extreme timestamps do not panic.
        let _ = asert_next_bits(&p, &a, i64::MIN, u64::MAX);
        let _ = asert_next_bits(&p, &a, i64::MAX, 1);
    }
}
