//! GnB-SMH v2 draft — SHA-256, ASIC-friendly, Grover-hostile proof-of-work.
//!
//! DRAFT, NOT CONSENSUS. Normative definition: `reference/gnb_smh_v2.py`;
//! this module must reproduce `reference/test_vectors_v2.json` byte for byte
//! (see `tests/vectors_v2.rs`). Rationale: `DESIGN-v2.md`.
//!
//! ```text
//! X_0   = SHA256(enc(DS_SEED) || u8(log2_n) || enc(header) || u64le(nonce))
//! fill:  for i in 0..N:  V[i] = X;  X = SHA256(X || u32le(i) || 0x01)
//! mix:   for i in 0..N:  j = u64le(X[0..8]) mod N;  X = SHA256((X ^ V[j]) || u32le(i) || 0x02)
//! out   = SHA256(enc(DS_FINAL) || X)
//! ```
//!
//! Every inner call has a 37-byte input, so it costs exactly one SHA-256
//! compression from the standard IV; this module builds the padded block
//! directly.

use sha2::digest::generic_array::GenericArray;
use sha2::{Digest, Sha256};

/// Scratchpad block size in bytes (one SHA-256 output).
pub const BLOCK: usize = 32;
/// Canonical v2 draft memory parameter: N = 2^13 blocks = 256 KiB.
pub const LOG2_N: u32 = 13;
pub const MIN_LOG2_N: u32 = 1;
pub const MAX_LOG2_N: u32 = 30;

const DS_SEED: &[u8] = b"GNB-SMH-v2/seed";
const DS_FINAL: &[u8] = b"GNB-SMH-v2/final";
const TAG_FILL: u8 = 0x01;
const TAG_MIX: u8 = 0x02;

const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

fn check_log2_n(log2_n: u32) -> usize {
    assert!(
        (MIN_LOG2_N..=MAX_LOG2_N).contains(&log2_n),
        "log2_n must be in [{MIN_LOG2_N}, {MAX_LOG2_N}]"
    );
    1usize.checked_shl(log2_n).expect("2^log2_n does not fit in usize")
}

/// One inner step: X <- SHA256(X || u32le(i) || tag), as a single compression.
/// Padding for a 37-byte message: byte 37 = 0x80, bytes 56..64 = 296 big-endian.
#[inline(always)]
fn step(x: &mut [u8; BLOCK], i: u32, tag: u8) {
    let mut block = [0u8; 64];
    block[..BLOCK].copy_from_slice(x);
    block[32..36].copy_from_slice(&i.to_le_bytes());
    block[36] = tag;
    block[37] = 0x80;
    block[56..].copy_from_slice(&(37u64 * 8).to_be_bytes());
    let mut st = IV;
    sha2::compress256(&mut st, &[*GenericArray::from_slice(&block)]);
    for (k, w) in st.iter().enumerate() {
        x[4 * k..4 * k + 4].copy_from_slice(&w.to_be_bytes());
    }
}

fn enc(h: &mut Sha256, b: &[u8]) {
    let len = u32::try_from(b.len()).expect("field longer than u32::MAX");
    h.update(len.to_le_bytes());
    h.update(b);
}

/// X_0 for (header, nonce).
pub fn seed(header: &[u8], nonce: u64, log2_n: u32) -> [u8; BLOCK] {
    check_log2_n(log2_n);
    let mut h = Sha256::new();
    enc(&mut h, DS_SEED);
    h.update([log2_n as u8]);
    enc(&mut h, header);
    h.update(nonce.to_le_bytes());
    h.finalize().into()
}

/// Reusable 2^log2_n-block scratchpad (allocate once per mining thread).
pub struct Scratchpad {
    v: Vec<[u8; BLOCK]>,
    log2_n: u32,
}

impl Scratchpad {
    pub fn new(log2_n: u32) -> Self {
        let n = check_log2_n(log2_n);
        Self { v: vec![[0u8; BLOCK]; n], log2_n }
    }

    pub fn log2_n(&self) -> u32 {
        self.log2_n
    }

    /// Bytes of memory the scratchpad occupies.
    pub fn bytes(&self) -> usize {
        self.v.len() * BLOCK
    }
}

/// Intermediate values, exposed for test vectors and debugging.
pub struct Trace {
    pub seed: [u8; BLOCK],
    pub x_after_fill: [u8; BLOCK],
    pub x_after_mix: [u8; BLOCK],
    pub out: [u8; 32],
}

/// Full evaluation with intermediates.
pub fn trace_with(sp: &mut Scratchpad, header: &[u8], nonce: u64) -> Trace {
    let n = sp.v.len();
    let mask = (n - 1) as u64;
    let s = seed(header, nonce, sp.log2_n);
    let mut x = s;

    // Phase 1 — fill: hash chain of length N. (i < 2^30 always fits in u32.)
    for (i, slot) in sp.v.iter_mut().enumerate() {
        *slot = x;
        step(&mut x, i as u32, TAG_FILL);
    }
    let x_after_fill = x;

    // Phase 2 — mix: N data-dependent reads, each step depends on the previous.
    for i in 0..n {
        let j = (u64::from_le_bytes(x[..8].try_into().unwrap()) & mask) as usize;
        let vj = &sp.v[j];
        for k in 0..BLOCK {
            x[k] ^= vj[k];
        }
        step(&mut x, i as u32, TAG_MIX);
    }
    let x_after_mix = x;

    let mut h = Sha256::new();
    enc(&mut h, DS_FINAL);
    h.update(x_after_mix);
    Trace { seed: s, x_after_fill, x_after_mix, out: h.finalize().into() }
}

/// GnB-SMH v2 output for (header, nonce), reusing `sp` at whatever size it has.
pub fn hash_with(sp: &mut Scratchpad, header: &[u8], nonce: u64) -> [u8; 32] {
    trace_with(sp, header, nonce).out
}

/// GnB-SMH v2 output at the canonical draft parameter (allocates 256 KiB).
pub fn hash(header: &[u8], nonce: u64) -> [u8; 32] {
    hash_with(&mut Scratchpad::new(LOG2_N), header, nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One SHA-256 compression takes about 0.2 s under Miri (measured,
    /// docs/testing/SANITIZERS.md), so the hashing tests below run a few
    /// iterations there and the full count natively.
    const HASH_TRIALS: u32 = if cfg!(miri) { 3 } else { 200 };

    /// The single-compression step must equal FIPS 180-4 SHA256(x || u32le(i) || tag).
    #[test]
    fn step_matches_sha256() {
        for trial in 0u32..HASH_TRIALS {
            let mut x = [0u8; BLOCK];
            for (k, b) in x.iter_mut().enumerate() {
                *b = (trial.wrapping_mul(0x9E37_79B9) >> (k % 24)) as u8 ^ k as u8;
            }
            let i = trial.wrapping_mul(2_654_435_761);
            for tag in [TAG_FILL, TAG_MIX] {
                let mut h = Sha256::new();
                h.update(x);
                h.update(i.to_le_bytes());
                h.update([tag]);
                let want: [u8; 32] = h.finalize().into();
                let mut got = x;
                step(&mut got, i, tag);
                assert_eq!(got, want);
            }
        }
    }

    #[test]
    fn nonce_and_header_change_output() {
        // 2^8 blocks natively; 2 blocks (still both phases, both tags) under Miri.
        let mut sp = Scratchpad::new(if cfg!(miri) { MIN_LOG2_N } else { 8 });
        let a = hash_with(&mut sp, b"gnb", 0);
        assert_ne!(a, hash_with(&mut sp, b"gnb", 1));
        assert_ne!(a, hash_with(&mut sp, b"gnc", 0));
        assert_eq!(a, hash_with(&mut sp, b"gnb", 0));
    }

    #[test]
    #[should_panic]
    fn rejects_log2_n_out_of_range() {
        let _ = Scratchpad::new(MAX_LOG2_N + 1);
    }
}
