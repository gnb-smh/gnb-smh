//! Transport handshake messages — the LIVE ones, `HandshakeInitLp` /
//! `HandshakeRespLp` — decoded exactly as `transport::upgrade::read_msg` does
//! (16 KiB body limit, bincode standard configuration). Must never panic.
//! (NET-17: this target used to decode the types of a never-used ML-DSA
//! handshake, since removed; the two encodings have the same field layout,
//! so the seed corpus is unchanged.)
#![no_main]

use gnb::transport::upgrade::{HandshakeInitLp, HandshakeRespLp, MAX_HANDSHAKE_MSG_SIZE};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_HANDSHAKE_MSG_SIZE as usize {
        return;
    }
    let cfg = bincode::config::standard();
    let _ = bincode::serde::decode_from_slice::<HandshakeInitLp, _>(data, cfg);
    let _ = bincode::serde::decode_from_slice::<HandshakeRespLp, _>(data, cfg);
});
