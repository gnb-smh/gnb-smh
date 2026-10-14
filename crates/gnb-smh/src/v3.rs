//! GnB-SMH v3 draft — data-dependent multi-pass fill (Argon2d-style), SHAKE-256.
//!
//! Consensus proof of work from the PoWit activation height (`gnb_crypto::core::powit_height`).
//! Normative definition: `reference/gnb_smh_v3.py`;
//! must reproduce `reference/test_vectors_v3.json` (see `tests/vectors_v3.rs`).
//!
//! ```text
//! V[0] = SHAKE256(enc(DS_SEED) || u8(log2_n) || u8(passes) || enc(header) || u64le(nonce), 128)
//! pass 0:  i in 1..N:  r = u64le(V[i-1][0..8]) mod i;  V[i] = SHAKE256(V[i-1] || V[r] || u32le(i) || u8(0), 128)
//! pass p:  i in 0..N:  prev = V[(i-1) mod N]; r = u64le(prev[0..8]) mod N
//!                      V[i] = SHAKE256(prev || V[r] || u32le(i) || u8(p), 128)
//! out  = SHAKE256(enc(DS_FINAL) || V[N-1], 32)
//! ```
//!
//! Versus v1: every block depends on a content-chosen earlier block, so
//! dropping blocks to save memory makes recomputation cascade, and the
//! scratchpad is 16x smaller (4 MiB) so verification is ~10x faster.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

pub const BLOCK: usize = 128;
pub const LOG2_N: u32 = 15;
pub const PASSES: u8 = 2;
pub const MIN_LOG2_N: u32 = 1;
pub const MAX_LOG2_N: u32 = 30;

const DS_SEED: &[u8] = b"GNB-SMH-v3/seed";
const DS_FINAL: &[u8] = b"GNB-SMH-v3/final";

type Blk = [u8; BLOCK];

fn enc(h: &mut Shake256, b: &[u8]) {
    h.update(&(b.len() as u32).to_le_bytes());
    h.update(b);
}

#[inline(always)]
fn step(prev: &Blk, refb: &Blk, i: u32, p: u8) -> Blk {
    let mut h = Shake256::default();
    h.update(prev);
    h.update(refb);
    h.update(&i.to_le_bytes());
    h.update(&[p]);
    let mut out = [0u8; BLOCK];
    h.finalize_xof().read(&mut out);
    out
}

#[inline(always)]
fn idx(b: &Blk) -> u64 {
    u64::from_le_bytes(b[..8].try_into().unwrap())
}

pub struct Scratchpad {
    v: Vec<Blk>,
    log2_n: u32,
}

impl Scratchpad {
    pub fn new(log2_n: u32) -> Self {
        assert!((MIN_LOG2_N..=MAX_LOG2_N).contains(&log2_n), "log2_n out of range");
        Self { v: vec![[0u8; BLOCK]; 1usize << log2_n], log2_n }
    }

    pub fn bytes(&self) -> usize {
        self.v.len() * BLOCK
    }
}

pub struct Trace {
    pub seed: Blk,
    pub after_pass0: Blk,
    pub last: Blk,
    pub out: [u8; 32],
}

pub fn trace_with(sp: &mut Scratchpad, passes: u8, header: &[u8], nonce: u64) -> Trace {
    assert!(passes >= 1, "passes must be at least 1");
    let n = sp.v.len();
    let v = &mut sp.v;
    let mut h = Shake256::default();
    enc(&mut h, DS_SEED);
    h.update(&[sp.log2_n as u8, passes]);
    enc(&mut h, header);
    h.update(&nonce.to_le_bytes());
    h.finalize_xof().read(&mut v[0]);
    let seed = v[0];

    for i in 1..n {
        let r = (idx(&v[i - 1]) % i as u64) as usize;
        v[i] = step(&v[i - 1], &v[r], i as u32, 0);
    }
    let after_pass0 = v[n - 1];
    for p in 1..passes {
        for i in 0..n {
            let prev = v[(i + n - 1) % n];
            let r = (idx(&prev) % n as u64) as usize;
            v[i] = step(&prev, &v[r], i as u32, p);
        }
    }
    let last = v[n - 1];
    let mut h = Shake256::default();
    enc(&mut h, DS_FINAL);
    h.update(&last);
    let mut out = [0u8; 32];
    h.finalize_xof().read(&mut out);
    Trace { seed, after_pass0, last, out }
}

pub fn hash_with(sp: &mut Scratchpad, header: &[u8], nonce: u64) -> [u8; 32] {
    trace_with(sp, PASSES, header, nonce).out
}

std::thread_local! {
    static THREAD_SCRATCHPAD: std::cell::RefCell<Option<Scratchpad>> =
        const { std::cell::RefCell::new(None) };
}

/// Canonical v3 output using a per-thread 4 MiB scratchpad kept for the life
/// of the thread.
pub fn hash_thread_local(header: &[u8], nonce: u64) -> [u8; 32] {
    THREAD_SCRATCHPAD.with(|cell| {
        let mut slot = cell.borrow_mut();
        let sp = slot.get_or_insert_with(|| Scratchpad::new(LOG2_N));
        hash_with(sp, header, nonce)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inputs_change_output() {
        let mut sp = Scratchpad::new(6);
        let a = trace_with(&mut sp, 2, b"gnb", 0).out;
        assert_ne!(a, trace_with(&mut sp, 2, b"gnb", 1).out);
        assert_ne!(a, trace_with(&mut sp, 3, b"gnb", 0).out);
        assert_eq!(a, trace_with(&mut sp, 2, b"gnb", 0).out);
    }
}
