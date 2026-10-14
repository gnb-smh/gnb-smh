//! `BlockHeader::from_wire_bytes` (headers-first sync) on untrusted bytes:
//! never panics, trailing bytes are rejected, and accepted encodings re-encode
//! to a fixed point.
#![no_main]

use gnb_crypto::core::BlockHeader;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok((header, blue_score, height)) = BlockHeader::from_wire_bytes(data) {
        let enc = header.to_wire_bytes(blue_score, height);
        let (again, b2, h2) = BlockHeader::from_wire_bytes(&enc).expect("re-encoded header must decode");
        assert_eq!((b2, h2), (blue_score, height));
        assert_eq!(again.to_wire_bytes(b2, h2), enc, "encode/decode is not a fixed point");
        let mut longer = enc.clone();
        longer.push(0);
        assert!(BlockHeader::from_wire_bytes(&longer).is_err(), "trailing byte accepted");
        let _ = again.pow_preimage();
    }
});
