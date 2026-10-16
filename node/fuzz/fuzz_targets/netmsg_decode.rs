//! `gnb::network::decode_wire_message`: the only decoder for gossip frames
//! from peers (size limit + post-decode bounds). Must never panic, and an
//! accepted frame
//! * obeys every per-field bound (restated here from the protocol limits,
//!   not taken from the decoder), and
//! * is the canonical encoding of what it decodes to: gossipsub message ids
//!   are SHA-256 of the frame bytes, so a second byte string for the same
//!   message would be a fresh message id that bypasses de-duplication (the
//!   reason trailing bytes are refused, audit NET-7).
#![no_main]

use gnb::network::{
    decode_wire_message, NetworkMessage, MAX_WIRE_ADDRS, MAX_WIRE_ADDR_LEN, MAX_WIRE_BYTES, MAX_WIRE_GETHEADERS_LIMIT,
    MAX_WIRE_LOCATOR, MAX_WIRE_PEER_ID_LEN, MAX_WIRE_SYNC_ENTRIES, MAX_WIRE_TIPS, MAX_WIRE_USER_AGENT_LEN,
};
use libfuzzer_sys::fuzz_target;

fn in_bounds(m: &NetworkMessage) -> bool {
    let addrs = |a: &[String]| a.len() <= MAX_WIRE_ADDRS && a.iter().all(|s| s.len() <= MAX_WIRE_ADDR_LEN);
    match m {
        NetworkMessage::NewBlock { block_data, .. } => block_data.len() <= MAX_WIRE_BYTES,
        NetworkMessage::NewTransaction { tx_data, .. } => tx_data.len() <= MAX_WIRE_BYTES,
        NetworkMessage::PeerTip { peer_id, .. } => peer_id.len() <= MAX_WIRE_PEER_ID_LEN,
        NetworkMessage::PeerExchange { peers } => addrs(peers),
        NetworkMessage::PeerCount { addresses, .. } => addrs(addresses),
        NetworkMessage::GetHeaders { limit, .. } => *limit <= MAX_WIRE_GETHEADERS_LIMIT,
        NetworkMessage::Headers { entries } => entries.len() <= MAX_WIRE_SYNC_ENTRIES,
        NetworkMessage::Tips { tips, locator } => tips.len() <= MAX_WIRE_TIPS && locator.len() <= MAX_WIRE_LOCATOR,
        NetworkMessage::Version { user_agent, .. } => user_agent.len() <= MAX_WIRE_USER_AGENT_LEN,
        NetworkMessage::PeerRequest
        | NetworkMessage::VersionAck
        | NetworkMessage::GetTips
        | NetworkMessage::GetBlock { .. }
        | NetworkMessage::BlockNotFound { .. } => true,
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(msg) = decode_wire_message(data) {
        assert!(in_bounds(&msg), "an out-of-bounds gossip frame was accepted: {msg:?}");
        let again = bincode::serde::encode_to_vec(&msg, bincode::config::standard()).unwrap();
        assert_eq!(again, data, "a non-canonical gossip frame was accepted (fresh message id for the same message)");
    }
});
