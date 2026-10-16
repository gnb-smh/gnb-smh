//! Proof-of-work and signature verification on adversarial input.
//!
//! * GnB-SMH output against the target encoded by arbitrary `bits` (on a
//!   small scratchpad, 2^1..2^8 blocks, so the fuzzer stays fast; the
//!   canonical 2^19 evaluation is the same code at another size): never
//!   panics, malformed bits never validate, and the strict `out < target`
//!   rule holds at the boundary.
//! * The hybrid ML-DSA-65 + Falcon-1024 `crypto::verify` (the consensus
//!   "parse failure => false" rule): arbitrary public key, message and
//!   signature bytes must return a bool, never panic. This is the coverage-
//!   guided counterpart of `fuzz_verify_never_panics` in
//!   crates/gnb-crypto/src/crypto/mod.rs.
#![no_main]

use gnb_smh::difficulty::{meets_target, try_bits_to_target, Target};
use gnb_smh::{hash_with, Scratchpad};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 14 {
        return;
    }
    let bits = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let nonce = u64::from_le_bytes(data[4..12].try_into().unwrap());
    let log2_n = 1 + (data[12] % 8) as u32;
    let split = data[13] as usize;
    let rest = &data[14..];

    let header = &rest[..split.min(rest.len())];
    let mut sp = Scratchpad::new(log2_n);
    let out = hash_with(&mut sp, header, nonce);
    match try_bits_to_target(bits) {
        Ok(t) => {
            assert_eq!(meets_target(&out, &t), out < t.0);
            assert!(!meets_target(&out, &Target(out)), "out == target must not validate");
        }
        Err(_) => {
            // Consensus decodes malformed bits to the zero target.
            assert!(!meets_target(&out, &Target::ZERO));
        }
    }

    // Signature verify: split the rest into (pk, msg, sig) by two length bytes.
    if rest.len() >= 2 {
        let (a, b) = (rest[0] as usize * 16, rest[1] as usize * 32);
        let body = &rest[2..];
        let pk = &body[..a.min(body.len())];
        let tail = &body[pk.len()..];
        let sig = &tail[..b.min(tail.len())];
        let msg = &tail[sig.len()..];
        let _ = gnb_crypto::crypto::verify(pk, msg, sig);
    }
});
