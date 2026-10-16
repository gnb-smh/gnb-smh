#![no_main]
//! Single-key witnesses: parsing is exact (no trailing bytes) and canonical,
//! and the consensus verifier never panics on arbitrary key/signature bytes.
use libfuzzer_sys::fuzz_target;
use gnb::core::Transaction;

fuzz_target!(|data: &[u8]| {
    if let Some((sig, pk)) = Transaction::parse_script_sig(data) {
        assert_eq!(Transaction::build_script_sig(&sig, &pk), data, "parse must be exact");
        let _ = gnb::crypto::verify_canonical(&pk, b"fuzz-sighash-32-bytes-0000000000", &sig);
    }
});
