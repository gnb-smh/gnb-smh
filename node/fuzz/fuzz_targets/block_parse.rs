//! `Block::from_wire_bytes` on untrusted bytes: never panics, and every
//! accepted encoding re-encodes to a fixed point.
#![no_main]

use gnb_crypto::core::Block;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(block) = Block::from_wire_bytes(data) {
        let enc = block.to_wire_bytes();
        let again = Block::from_wire_bytes(&enc).expect("re-encoded block must decode");
        assert_eq!(again.to_wire_bytes(), enc, "encode/decode is not a fixed point");
        // Cheap, attacker-reachable derived values must not panic either.
        let _ = again.header.pow_preimage();
    }
});
