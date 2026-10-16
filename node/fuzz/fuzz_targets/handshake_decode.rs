//! Transport handshake messages — the LIVE `/gnb/pq/2.0.0` ones, `Init` /
//! `Resp` / `Finish` — decoded exactly as `transport::upgrade::read_msg` does
//! (`MAX_HANDSHAKE_MSG_SIZE` body limit, bincode standard configuration).
//! Must never panic. (NET-17: this target used to decode the types of a
//! never-used ML-DSA handshake, since removed. `pq_handshake_decode` decodes
//! the same types without the size bound.)
#![no_main]

use gnb::transport::upgrade::{Finish, Init, Resp, MAX_HANDSHAKE_MSG_SIZE};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_HANDSHAKE_MSG_SIZE as usize {
        return;
    }
    let cfg = bincode::config::standard();
    let _ = bincode::serde::decode_from_slice::<Init, _>(data, cfg);
    let _ = bincode::serde::decode_from_slice::<Resp, _>(data, cfg);
    let _ = bincode::serde::decode_from_slice::<Finish, _>(data, cfg);
});
