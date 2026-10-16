#![no_main]
//! Policy witnesses are canonical: anything the strict decoder accepts must
//! re-encode to exactly the same bytes (one witness byte string per signature
//! set), and decoding must never panic.
use libfuzzer_sys::fuzz_target;
use gnb::core::policy::{PolicyWitness, SpendPolicy};

fuzz_target!(|data: &[u8]| {
    if let Ok(w) = PolicyWitness::decode(data) {
        assert_eq!(w.encode(), data, "accepted witness must be canonical");
        assert!(w.encode().len() <= gnb::core::MAX_SCRIPT_SIG_LEN, "the decoder cap covers every witness");
    }
    if let Ok(p) = SpendPolicy::decode(data) {
        assert_eq!(p.encode(), data, "accepted policy must be canonical");
    }
});
