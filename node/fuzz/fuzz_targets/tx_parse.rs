//! `Transaction::from_wire_bytes` on untrusted bytes: never panics, and every
//! accepted encoding re-encodes to a fixed point (decode . encode is stable).
#![no_main]

use gnb_crypto::core::Transaction;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(tx) = Transaction::from_wire_bytes(data) {
        let enc = tx.to_wire_bytes(true);
        let again = Transaction::from_wire_bytes(&enc).expect("re-encoded transaction must decode");
        assert_eq!(again.to_wire_bytes(true), enc, "encode/decode is not a fixed point");
        assert_eq!(again.txid(), tx.txid());
    }
});
