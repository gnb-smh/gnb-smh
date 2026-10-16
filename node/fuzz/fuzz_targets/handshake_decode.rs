//! Transport handshake messages, decoded exactly as
//! `transport::upgrade::read_msg` does (16 KiB body limit, bincode standard
//! configuration). Must never panic.
#![no_main]

use gnb::transport::{HandshakeInit, HandshakeResp};
use libfuzzer_sys::fuzz_target;

/// `MAX_HANDSHAKE_MSG_SIZE` in node/src/transport/upgrade.rs.
const MAX_HANDSHAKE_MSG_SIZE: usize = 16 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_HANDSHAKE_MSG_SIZE {
        return;
    }
    let cfg = bincode::config::standard();
    let _ = bincode::serde::decode_from_slice::<HandshakeInit, _>(data, cfg);
    let _ = bincode::serde::decode_from_slice::<HandshakeResp, _>(data, cfg);
});
