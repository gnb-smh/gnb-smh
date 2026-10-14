//! `gnb::network::decode_wire_message`: the only decoder for gossip frames
//! from peers (size limit + post-decode bounds). Must never panic.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = gnb::network::decode_wire_message(data);
});
