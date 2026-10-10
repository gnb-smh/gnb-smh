#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(tx) = gnb::core::Transaction::from_wire_bytes(data) {
        let _ = tx.txid();
    }
});
