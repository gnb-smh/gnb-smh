#![no_main]
//! The three `/gnb/pq/2.0.0` handshake messages are decoded from bytes a
//! not-yet-authenticated peer controls: they must reject, never panic.
use gnb::transport::upgrade::{Finish, Init, Resp};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let cfg = bincode::config::standard();
    let _ = bincode::serde::decode_from_slice::<Init, _>(data, cfg);
    let _ = bincode::serde::decode_from_slice::<Resp, _>(data, cfg);
    let _ = bincode::serde::decode_from_slice::<Finish, _>(data, cfg);
});
