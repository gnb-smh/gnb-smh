//! Witness (`script_sig`) parsing: the single-key framing
//! (`parse_script_sig`, `parse_script_sig_borrowed`, `parse_script_sig_exact`)
//! and the canonical-witness rule (`core::sighash::canonical_witness`).
//!
//! On this chain the framing is exact at every height (cc5c450: a
//! single-key `script_sig` is exactly `len|sig|len|pk`, no trailing bytes):
//! the historical lenient parse (trailing bytes ignored) is gone, and
//! `parse_script_sig_borrowed` / `parse_script_sig` are the exact parser.
//!
//! * The three parsers equal a straightforward reference parser of
//!   `[u32 LE sig_len][sig][u32 LE pk_len][pk]` that refuses trailing bytes,
//!   and the owned parser equals the borrowed.
//! * Round trips: every accepted input is exactly `build_script_sig(sig, pk)`
//!   of what it parsed to; one byte more is refused by every parser (and so by
//!   the sighash v2 witness rule).
//! * `canonical_witness` accepts exactly the exact framing with a canonical
//!   signature encoding; `check_input_witnesses` agrees with both rules.
//! * Inputs with the "real signature" bit start from a genuine canonical
//!   hybrid signature (deterministic key) and alter it, so the Falcon compact
//!   encoding check and the envelope parser see near-valid inputs.
#![no_main]

mod common;

use std::sync::OnceLock;

use common::*;
use gnb_crypto::core::sighash::{canonical_witness, check_input_witnesses, SighashVersion};
use gnb_crypto::core::{Transaction, TxInput, TxOutput};
use gnb_crypto::crypto;
use libfuzzer_sys::fuzz_target;

/// (public key, canonical signature) of a deterministic hybrid key.
fn real() -> &'static (Vec<u8>, Vec<u8>) {
    static REAL: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    REAL.get_or_init(|| {
        let (pk, sk) = crypto::generate_keypair_from_seed(&[0x5Eu8; 64]).expect("seeded keygen");
        let sig = pqcrypto_internals::with_seeded_rng_scope(&[7u8; 32], || crypto::sign_bound(&sk, &[0x42u8; 32]))
            .expect("sign");
        assert!(crypto::is_canonical_signature_encoding(&sig), "sign_bound output must be canonical");
        assert!(crypto::verify_bound(&pk, &[0x42u8; 32], &sig));
        (pk, sig)
    })
}

/// Reference parser: `(sig, pk, bytes used)` of the leading witness.
fn ref_parse(s: &[u8]) -> Option<(&[u8], &[u8], usize)> {
    if s.len() < 4 {
        return None;
    }
    let sig_len = u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as u64;
    let pk_len_at = 4 + sig_len;
    if (s.len() as u64) < pk_len_at + 4 {
        return None;
    }
    let a = pk_len_at as usize;
    let pk_len = u32::from_le_bytes([s[a], s[a + 1], s[a + 2], s[a + 3]]) as u64;
    let end = pk_len_at + 4 + pk_len;
    if (s.len() as u64) < end {
        return None;
    }
    Some((&s[4..a], &s[a + 4..end as usize], end as usize))
}

fn spk_of(pk: &[u8]) -> Vec<u8> {
    sha3(pk)[..20].to_vec()
}

fn check(s: &[u8]) {
    let r = ref_parse(s);
    let borrowed = Transaction::parse_script_sig_borrowed(s);
    let exact = Transaction::parse_script_sig_exact(s);
    let owned = Transaction::parse_script_sig(s);
    let reference = r.filter(|x| x.2 == s.len()).map(|(a, b, _)| (a, b));
    assert_eq!(exact, reference, "exact parser differs from the reference");
    assert_eq!(borrowed, exact, "borrowed parser differs from the exact one (one framing at every height)");
    assert_eq!(owned, borrowed.map(|(a, b)| (a.to_vec(), b.to_vec())), "owned and borrowed parsers differ");
    if let Some((sig, pk)) = exact {
        assert_eq!(Transaction::build_script_sig(sig, pk), s, "an accepted witness is not its own encoding");
    }
    if let Some((_, _, used)) = r {
        // A well-framed witness followed by trailing bytes: refused.
        assert_eq!(exact.is_some(), used == s.len(), "trailing bytes accepted");
    }
    let canonical = canonical_witness(s);
    match &canonical {
        Ok(w) => {
            assert_eq!(Some(*w), exact, "canonical witness is not the exact framing");
            assert!(crypto::is_canonical_signature_encoding(w.0));
        }
        Err(_) => assert!(exact.is_none_or(|(sig, _)| !crypto::is_canonical_signature_encoding(sig))),
    }

    // The per-input rule of both regimes on a one-input transaction whose
    // spent script is the hash of the parsed public key (or of nothing).
    let pk_for_spk = borrowed.map(|(_, pk)| pk).unwrap_or(&[]);
    let tx = Transaction {
        version: 3,
        inputs: vec![TxInput { prev_txid: [1; 32], prev_index: 0, script_sig: s.to_vec(), sequence: u32::MAX }],
        outputs: vec![],
        locktime: 0,
    };
    let prevouts = [TxOutput { value: 1, script_pubkey: spk_of(pk_for_spk) }];
    let v2 = check_input_witnesses(&tx, &prevouts, SighashVersion::V2);
    assert_eq!(v2.is_ok(), borrowed.is_some(), "V2 witness rule");
    let v3 = check_input_witnesses(&tx, &prevouts, SighashVersion::V3);
    assert_eq!(v3.is_ok(), canonical.is_ok(), "V3 witness rule");
    if let Ok(w) = v3 {
        assert_eq!(w, vec![canonical.unwrap()]);
    }
    // A wrong spent script is always refused.
    let wrong = [TxOutput { value: 1, script_pubkey: vec![0xEE; 21] }];
    assert!(check_input_witnesses(&tx, &wrong, SighashVersion::V2).is_err());
    assert!(check_input_witnesses(&tx, &[], SighashVersion::V2).is_err(), "prevout count mismatch accepted");
}

fuzz_target!(|data: &[u8]| {
    let mut inp = Input::new(data);
    let mode = inp.u8();
    match mode % 4 {
        0 => check(inp.rest()),
        1 => {
            // Built from parts: exact round trip, plus trailing bytes.
            let sig = inp.var_bytes(300);
            let pk = inp.var_bytes(300);
            let tail = inp.var_bytes(6);
            let mut s = Transaction::build_script_sig(&sig, &pk);
            assert_eq!(Transaction::parse_script_sig_exact(&s), Some((&sig[..], &pk[..])));
            check(&s);
            s.extend_from_slice(&tail);
            if !tail.is_empty() {
                assert_eq!(Transaction::parse_script_sig_exact(&s), None, "trailing bytes accepted");
                assert_eq!(Transaction::parse_script_sig_borrowed(&s), None, "trailing bytes accepted (borrowed)");
                assert_eq!(Transaction::parse_script_sig(&s), None, "trailing bytes accepted (owned)");
            }
            check(&s);
        }
        _ => {
            // A genuine canonical signature, altered by the input.
            let (pk, sig) = real();
            let mut sig = sig.clone();
            let mut pk = pk.clone();
            let base_ok = canonical_witness(&Transaction::build_script_sig(&sig, &pk)).is_ok();
            assert!(base_ok, "a genuine canonical witness is refused");
            for _ in 0..inp.below(4) {
                match inp.u8() % 5 {
                    0 if !sig.is_empty() => {
                        let i = inp.below(sig.len());
                        sig[i] ^= inp.u8();
                    }
                    1 => {
                        let n = inp.below(sig.len() + 1);
                        sig.truncate(n);
                    }
                    2 => sig.extend_from_slice(&inp.var_bytes(16)),
                    3 if sig.len() >= 4 => {
                        let i = inp.below(4);
                        sig[i] ^= inp.u8(); // the envelope
                    }
                    4 => {
                        let n = inp.below(pk.len() + 1);
                        pk.truncate(n);
                    }
                    _ => {}
                }
            }
            check(&Transaction::build_script_sig(&sig, &pk));
        }
    }
});
