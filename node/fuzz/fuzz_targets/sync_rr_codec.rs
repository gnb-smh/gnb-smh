//! The directed-sync request/response codec (`network::sync_rr`, protocol
//! `/gnb/sync/1`): frames read off a libp2p substream from any peer.
//!
//! * `decode_request` / `decode_response` never panic; every refusal is an
//!   `InvalidData` error (`is_sync_protocol_violation`, the penalty path), and
//!   an empty frame is `UnexpectedEof` (a transport failure, never penalized).
//! * An accepted frame obeys every field bound (restated here, not taken from
//!   the module), has no trailing byte, and is the canonical encoding of what
//!   it decodes to (`encode_frame(decode(b)) == b`: one encoding per message,
//!   as on the gossip path).
//! * Both transports enforce the same bounds: an accepted response, mapped to
//!   its gossip message (`response_to_message`), passes the gossip decoder
//!   `decode_wire_message`; an accepted gossip pull message maps
//!   (`as_pull_request`) to a request the directed decoder accepts.
//! * Generated messages round-trip exactly when they are within the bounds
//!   (counts at and one past each bound are generated on purpose).
#![no_main]

mod common;

use common::*;
use gnb::network::sync_rr::{
    as_pull_request, check_nonempty_frame, decode_request, decode_response, encode_frame, is_sync_protocol_violation,
    response_to_message, SyncRequest, SyncResponse,
};
use gnb::network::{
    decode_wire_message, NetworkMessage, SyncEntry, MAX_WIRE_ADDRS, MAX_WIRE_ADDR_LEN, MAX_WIRE_BYTES,
    MAX_WIRE_GETHEADERS_LIMIT, MAX_WIRE_LOCATOR, MAX_WIRE_SYNC_ENTRIES, MAX_WIRE_TIPS,
};
use libfuzzer_sys::fuzz_target;

fn request_in_bounds(r: &SyncRequest) -> bool {
    match r {
        SyncRequest::GetHeaders { limit, .. } => *limit <= MAX_WIRE_GETHEADERS_LIMIT,
        _ => true,
    }
}

fn response_in_bounds(r: &SyncResponse) -> bool {
    match r {
        SyncResponse::Block { block_data, .. } => block_data.len() <= MAX_WIRE_BYTES,
        SyncResponse::Headers { entries } => entries.len() <= MAX_WIRE_SYNC_ENTRIES,
        SyncResponse::Tips { tips, locator } => tips.len() <= MAX_WIRE_TIPS && locator.len() <= MAX_WIRE_LOCATOR,
        SyncResponse::Peers { peers } => peers.len() <= MAX_WIRE_ADDRS && peers.iter().all(|p| p.len() <= MAX_WIRE_ADDR_LEN),
        SyncResponse::BlockNotFound { .. } | SyncResponse::Busy => true,
    }
}

fn gossip_bytes(m: &NetworkMessage) -> Vec<u8> {
    bincode::serde::encode_to_vec(m, bincode::config::standard()).unwrap()
}

fn check_frame(b: &[u8]) {
    match check_nonempty_frame(b.to_vec()) {
        Err(e) => {
            assert!(b.is_empty());
            assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof);
            assert!(!is_sync_protocol_violation(&e), "an empty frame is penalized");
            return;
        }
        Ok(v) => assert_eq!(v, b),
    }
    match decode_request(b) {
        Ok(req) => {
            assert!(request_in_bounds(&req), "an out-of-bounds request was accepted: {req:?}");
            assert_eq!(encode_frame(&req).unwrap(), b, "a non-canonical request frame was accepted");
        }
        Err(e) => assert!(is_sync_protocol_violation(&e), "request refusal is not InvalidData: {e}"),
    }
    match decode_response(b) {
        Ok(resp) => {
            assert!(response_in_bounds(&resp), "an out-of-bounds response was accepted");
            assert_eq!(encode_frame(&resp).unwrap(), b, "a non-canonical response frame was accepted");
            if let Some(msg) = response_to_message(resp.clone()) {
                let g = gossip_bytes(&msg);
                if g.len() <= MAX_WIRE_BYTES {
                    if let Err(e) = decode_wire_message(&g) {
                        panic!("a sync response the directed decoder accepts is refused on gossip: {e:?}");
                    }
                }
            } else {
                assert_eq!(resp, SyncResponse::Busy);
            }
        }
        Err(e) => assert!(is_sync_protocol_violation(&e), "response refusal is not InvalidData: {e}"),
    }
    // The gossip side: a pull message accepted there is accepted here.
    if let Ok(msg) = decode_wire_message(b) {
        if let Some(req) = as_pull_request(&msg) {
            let enc = encode_frame(&req).unwrap();
            assert_eq!(decode_request(&enc).ok(), Some(req), "a gossip-accepted pull is refused by the directed decoder");
        }
    }
}

fn entries(inp: &mut Input, cap: usize) -> Vec<SyncEntry> {
    let n = match inp.u8() % 16 {
        0 => cap,
        1 => cap + 1,
        _ => inp.below(4),
    };
    (0..n).map(|i| SyncEntry { hash: [i as u8; 32], blue_score: inp.u64(), height: i as u64 }).collect()
}

fn gen_response(inp: &mut Input) -> SyncResponse {
    match inp.u8() % 6 {
        0 => SyncResponse::Block { block_hash: inp.arr(), blue_score: inp.u64(), height: inp.u64(), block_data: inp.var_bytes(200) },
        1 => SyncResponse::BlockNotFound { block_hash: inp.arr() },
        2 => SyncResponse::Headers { entries: entries(inp, MAX_WIRE_SYNC_ENTRIES) },
        3 => {
            let tips = entries(inp, MAX_WIRE_TIPS);
            let n = match inp.u8() % 8 {
                0 => MAX_WIRE_LOCATOR,
                1 => MAX_WIRE_LOCATOR + 1,
                _ => inp.below(4),
            };
            SyncResponse::Tips { tips, locator: (0..n).map(|i| [i as u8; 32]).collect() }
        }
        4 => {
            let n = match inp.u8() % 16 {
                0 => MAX_WIRE_ADDRS,
                1 => MAX_WIRE_ADDRS + 1,
                _ => inp.below(4),
            };
            let long = inp.u8() % 8 == 0;
            let peers = (0..n)
                .map(|i| if long && i == 0 { "x".repeat(MAX_WIRE_ADDR_LEN + (inp.u8() & 1) as usize) } else { format!("/ip4/10.0.0.{}/tcp/1", i % 250) })
                .collect();
            SyncResponse::Peers { peers }
        }
        _ => SyncResponse::Busy,
    }
}

fn gen_request(inp: &mut Input) -> SyncRequest {
    match inp.u8() % 4 {
        0 => SyncRequest::GetBlock { block_hash: inp.arr() },
        1 => {
            let limit = match inp.u8() % 4 {
                0 => MAX_WIRE_GETHEADERS_LIMIT,
                1 => MAX_WIRE_GETHEADERS_LIMIT + 1,
                _ => inp.u32(),
            };
            SyncRequest::GetHeaders { from_blue_score: inp.u64(), limit }
        }
        2 => SyncRequest::GetTips,
        _ => SyncRequest::GetPeers,
    }
}

fuzz_target!(|data: &[u8]| {
    let mut inp = Input::new(data);
    match inp.u8() % 3 {
        0 => check_frame(inp.rest()),
        1 => {
            let req = gen_request(&mut inp);
            let enc = encode_frame(&req).unwrap();
            assert_eq!(decode_request(&enc).ok(), request_in_bounds(&req).then(|| req.clone()), "request round trip");
            let mut longer = enc.clone();
            longer.push(inp.u8());
            assert!(decode_request(&longer).is_err(), "a trailing byte was accepted");
            check_frame(&enc);
        }
        _ => {
            let resp = gen_response(&mut inp);
            let enc = encode_frame(&resp).unwrap();
            assert_eq!(decode_response(&enc).ok(), response_in_bounds(&resp).then(|| resp.clone()), "response round trip");
            let mut longer = enc.clone();
            longer.push(inp.u8());
            assert!(decode_response(&longer).is_err(), "a trailing byte was accepted");
            check_frame(&enc);
        }
    }
});
