//! Regressions for defects found by the cargo-fuzz campaign (node/fuzz,
//! docs/testing/FUZZING.md). Each test pins the minimized crashing input the
//! fuzzer reported (also committed as `fuzz/corpus/<target>/regress_*`) and
//! the root-cause property it violated.

use gnb::core::{Block, BlockHeader, MerkleRoot, Transaction, TxInput, TxOutput};
use gnb::network::sync_rr::{decode_request, decode_response, encode_frame, is_sync_protocol_violation, SyncRequest, SyncResponse};
use gnb::network::{decode_wire_message, NetworkMessage, WireDecodeError, WirePenaltyTracker, WireReaction};

fn bincode_of(m: &NetworkMessage) -> Vec<u8> {
    bincode::serde::encode_to_vec(m, bincode::config::standard()).unwrap()
}

/// `netmsg_decode` crash: a `Version` frame whose `version` field is the
/// 5-byte bincode form (`FC 1F 00 00 00`) of 31 decoded to the same message as
/// the canonical 1-byte form. Gossipsub message ids are SHA-256 of the frame,
/// so every such variant was a fresh message id for the same message (the
/// NET-7 de-duplication bypass, without trailing bytes). Such a frame is
/// refused; it is a penalized protocol violation unless the message is one
/// an older release relays (`NewBlock`, `NewTransaction`).
#[test]
fn gossip_frame_with_a_non_minimal_varint_is_a_protocol_violation() {
    let crash = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/fuzz/corpus/netmsg_decode/regress_noncanonical_bincode_varint"))
        .expect("committed crash input");
    assert_eq!(crash, [12u8, 252, 31, 0, 0, 0, 0, 0, 0, 0]);
    let canonical = [12u8, 31, 0, 0, 0, 0];
    let m = decode_wire_message(&canonical).expect("canonical Version frame");
    assert_eq!(bincode_of(&m), canonical);
    match decode_wire_message(&crash) {
        Err(e @ WireDecodeError::NonCanonical { relayable: false }) => assert!(e.is_protocol_violation()),
        other => panic!("non-minimal frame: {other:?}"),
    }
    // The peer that sent it is penalized like any protocol violation: no
    // honest node relays a `Version` frame.
    let mut t = WirePenaltyTracker::new();
    let peer = libp2p::PeerId::random();
    assert!(matches!(t.classify(peer, &crash), WireReaction::Penalize { error: WireDecodeError::NonCanonical { .. }, .. }));

    // A block announcement: the same block id with a 3-byte `blue_score`.
    let nb = NetworkMessage::NewBlock { block_hash: [7; 32], blue_score: 5, height: 4, block_data: vec![1, 2, 3] };
    let enc = bincode_of(&nb);
    assert!(decode_wire_message(&enc).is_ok());
    let at = 1 + 32; // variant, block_hash
    assert_eq!(enc[at], 5);
    let mut wide = enc[..at].to_vec();
    wide.extend_from_slice(&[0xFB, 5, 0]);
    wide.extend_from_slice(&enc[at + 1..]);
    assert!(matches!(decode_wire_message(&wide), Err(WireDecodeError::NonCanonical { relayable: true })));

    // Refused, but not penalized: releases before the one-encoding rule
    // accept this frame and gossipsub relays the bytes they received, so it
    // can come from an honest older relay (docs/CONSENSUS.md, "Wire encoding").
    let peer2 = libp2p::PeerId::random();
    assert!(matches!(t.classify(peer2, &wide), WireReaction::IgnoreMalformed(_)));
    assert_eq!(t.score_of(&peer2), None);
}

/// The directed-sync codec had the same gap (bincode under `decode_frame`).
#[test]
fn sync_frame_with_a_non_minimal_varint_is_refused() {
    let req = SyncRequest::GetHeaders { from_blue_score: 5, limit: 1 };
    let enc = encode_frame(&req).unwrap();
    assert_eq!(enc, [1, 5, 1]);
    assert_eq!(decode_request(&enc).unwrap(), req);
    let wide = [1u8, 0xFB, 5, 0, 1];
    let err = decode_request(&wide).unwrap_err();
    assert!(is_sync_protocol_violation(&err), "{err}");

    let resp = SyncResponse::BlockNotFound { block_hash: [3; 32] };
    let enc = encode_frame(&resp).unwrap();
    assert_eq!(decode_response(&enc).unwrap(), resp);
    let mut wide = vec![0xFC, enc[0], 0, 0, 0]; // the variant index in the 5-byte form
    wide.extend_from_slice(&enc[1..]);
    assert!(is_sync_protocol_violation(&decode_response(&wide).unwrap_err()));
}

/// `wire_roundtrip` crash: a header whose parent count is `FD 01 00` decoded
/// to the header encoded with `01`. Every wire decoder now refuses
/// non-minimal varints (unit tests `wire_canonical_tests` in gnb-crypto cover
/// each field and the block framing).
#[test]
fn header_with_a_non_minimal_parent_count_is_refused() {
    let crash = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/fuzz/corpus/wire_roundtrip/regress_nonminimal_parent_count"))
        .expect("committed crash input");
    // Mode byte 3 (untrusted bytes), two cut bytes, then the header.
    assert_eq!(crash[0] % 4, 3);
    assert!(BlockHeader::from_wire_bytes(&crash[3..]).is_err(), "the fuzzer's header is still accepted");

    let h = BlockHeader { version: 1, parents: vec![[0x33; 32]], merkle_root: MerkleRoot([0x44; 32]), timestamp: 9, bits: 0x2100_FFFF, nonce: 7 };
    let enc = h.to_wire_bytes(1, 1);
    let mut wide = enc[..4].to_vec();
    wide.extend_from_slice(&[0xFD, 0x01, 0x00]);
    wide.extend_from_slice(&enc[5..]);
    assert!(BlockHeader::from_wire_bytes(&enc).is_ok());
    assert!(BlockHeader::from_wire_bytes(&wide).is_err());

    // The same through a block and a transaction.
    let tx = Transaction {
        version: 1,
        inputs: vec![TxInput { prev_txid: [1; 32], prev_index: 0, script_sig: vec![9; 4], sequence: 0 }],
        outputs: vec![TxOutput { value: 1, script_pubkey: vec![2; 20] }],
        locktime: 0,
    };
    let b = Block { header: h, transactions: vec![tx], blue_score: 1, height: 1, shielded_transactions: vec![] };
    let enc = b.to_wire_bytes();
    assert_eq!(Block::from_wire_bytes(&enc).unwrap().to_wire_bytes(), enc);
    let mut wide = enc[..4].to_vec();
    wide.extend_from_slice(&[0xFD, 0x01, 0x00]);
    wide.extend_from_slice(&enc[5..]);
    assert!(Block::from_wire_bytes(&wide).is_err());
}
