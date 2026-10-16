#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = gnb::network::sync_rr::decode_request(data);
    let _ = gnb::network::sync_rr::decode_response(data);
});
