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
//! * The framing itself: the libp2p codec `BlochSyncCodec` (`read_request` /
//!   `read_response` / `write_*`, the code the request-response behaviour
//!   runs on every substream) is driven over an in-memory stream. Reading a
//!   response stream is exactly `check_nonempty_frame` + the decoder applied
//!   to its first 4 MiB (`MAX_FRAME`, restated here). A request stream is
//!   read up to 64 bytes only (`MAX_REQUEST_FRAME`, restated; the largest
//!   request encodes to 33): one that reaches 64 bytes is a penalized
//!   refusal, a shorter one is `check_nonempty_frame` + `decode_request`.
//!   Writing is `encode_frame`, every generated request encodes below the
//!   request cap, a written message reads back exactly when it is within the
//!   bounds, and a stream past the cap (a valid frame followed by padding:
//!   64 bytes for a request, 4 MiB for a response) is a penalized refusal,
//!   never a decode of its first frame.
#![no_main]

mod common;

use std::fmt::Debug;
use std::io;

use common::*;
use futures::executor::block_on;
use futures::io::Cursor;
// The node's own libp2p (re-exported): the trait BlochSyncCodec implements.
use gnb::libp2p::request_response::Codec as _;
use gnb::network::sync_rr::{
    as_pull_request, check_nonempty_frame, decode_request, decode_response, encode_frame, is_sync_protocol_violation,
    response_to_message, BlochSyncCodec, SyncRequest, SyncResponse, SYNC_PROTOCOL,
};
use gnb::network::{
    decode_wire_message, NetworkMessage, SyncEntry, MAX_WIRE_ADDRS, MAX_WIRE_ADDR_LEN, MAX_WIRE_BYTES,
    MAX_WIRE_GETHEADERS_LIMIT, MAX_WIRE_LOCATOR, MAX_WIRE_SYNC_ENTRIES, MAX_WIRE_TIPS,
};
use libfuzzer_sys::fuzz_target;

/// The read cap of the codec for responses (`take(MAX_FRAME)`), restated.
const MAX_FRAME: usize = 4 * 1024 * 1024;
/// The read cap for requests (`take(MAX_REQUEST_FRAME)`), restated: a request
/// stream that fills it is refused, since no valid request is that long.
const MAX_REQUEST_FRAME: usize = 64;

/// Same value, or errors of the same kind.
fn assert_same_io<T: PartialEq + Debug>(got: &io::Result<T>, want: &io::Result<T>, what: &str) {
    match (got, want) {
        (Ok(a), Ok(b)) => assert_eq!(a, b, "{what}: codec and decoder disagree"),
        (Err(a), Err(b)) => assert_eq!(a.kind(), b.kind(), "{what}: error kinds differ ({a} vs {b})"),
        _ => panic!("{what}: codec {got:?} but decoder {want:?}"),
    }
}

/// Read `stream` through the codec, as the request-response behaviour does.
fn codec_read(stream: &[u8]) -> (io::Result<SyncRequest>, io::Result<SyncResponse>) {
    let mut c = BlochSyncCodec;
    let req = block_on(c.read_request(&SYNC_PROTOCOL, &mut Cursor::new(stream.to_vec())));
    let resp = block_on(c.read_response(&SYNC_PROTOCOL, &mut Cursor::new(stream.to_vec())));
    (req, resp)
}

/// The codec on `stream` equals the frame functions: on the whole stream
/// for a request shorter than the request cap (a longer one is a violation),
/// on the first 4 MiB for a response.
fn check_codec_read(stream: &[u8]) {
    let (req, resp) = codec_read(stream);
    let want_req = if stream.len() >= MAX_REQUEST_FRAME {
        Err(io::Error::new(io::ErrorKind::InvalidData, "request stream reached the request cap"))
    } else {
        check_nonempty_frame(stream.to_vec()).and_then(|f| decode_request(&f))
    };
    if let Err(e) = &req {
        if stream.len() >= MAX_REQUEST_FRAME {
            assert!(is_sync_protocol_violation(e), "a request stream at the cap refused without a penalty: {e}");
        }
    }
    let frame = &stream[..stream.len().min(MAX_FRAME)];
    let want_resp = check_nonempty_frame(frame.to_vec()).and_then(|f| decode_response(&f));
    assert_same_io(&req, &want_req, "read_request");
    assert_same_io(&resp, &want_resp, "read_response");
}

/// Writing through the codec is `encode_frame`; what it wrote reads back.
fn check_codec_write_request(req: &SyncRequest) {
    let mut out = Cursor::new(Vec::new());
    block_on(BlochSyncCodec.write_request(&SYNC_PROTOCOL, &mut out, req.clone())).expect("write_request");
    let written = out.into_inner();
    assert_eq!(written, encode_frame(req).unwrap(), "write_request is not encode_frame");
    let (back, _) = codec_read(&written);
    assert_eq!(back.ok(), request_in_bounds(req).then(|| req.clone()), "codec request round trip");
}

fn check_codec_write_response(resp: &SyncResponse) {
    let mut out = Cursor::new(Vec::new());
    block_on(BlochSyncCodec.write_response(&SYNC_PROTOCOL, &mut out, resp.clone())).expect("write_response");
    let written = out.into_inner();
    assert_eq!(written, encode_frame(resp).unwrap(), "write_response is not encode_frame");
    let (_, back) = codec_read(&written);
    assert_eq!(back.ok(), response_in_bounds(resp).then(|| resp.clone()), "codec response round trip");
}

/// A request stream padded to the request cap (a valid request followed by
/// zeros) is refused as a protocol violation, never decoded from its first
/// frame. Cheap (64 bytes), so it runs for every generated request.
fn check_request_cap(enc: &[u8], extra: usize) {
    let mut padded = enc.to_vec();
    padded.resize(MAX_REQUEST_FRAME + extra, 0);
    let (req, _) = codec_read(&padded);
    let e = req.expect_err("a request stream at the 64-byte cap was accepted");
    assert!(is_sync_protocol_violation(&e), "request stream at the cap refused without a penalty: {e}");
}

/// A stream past the 4 MiB read cap (a valid frame followed by padding) is
/// refused as a protocol violation, never decoded from its first frame.
/// (A single frame longer than the cap is not generated: bincode encodes and
/// decodes a 4 MiB byte vector element by element, which under ASan cut the
/// rate of the whole target to ~40 executions per second.)
fn check_oversize(enc: &[u8], extra: usize) {
    let mut padded = enc.to_vec();
    padded.resize(MAX_FRAME + 1 + extra, 0);
    let (req, resp) = codec_read(&padded);
    for e in [req.err(), resp.err()] {
        let e = e.expect("a stream over the 4 MiB cap was accepted");
        assert!(is_sync_protocol_violation(&e), "oversize stream refused without a penalty: {e}");
    }
}

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
    check_codec_read(b);
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
            assert!(enc.len() < MAX_REQUEST_FRAME, "{req:?} encodes to {} bytes, not below the request cap", enc.len());
            assert_eq!(decode_request(&enc).ok(), request_in_bounds(&req).then(|| req.clone()), "request round trip");
            let mut longer = enc.clone();
            longer.push(inp.u8());
            assert!(decode_request(&longer).is_err(), "a trailing byte was accepted");
            check_frame(&enc);
            check_codec_write_request(&req);
            check_request_cap(&enc, inp.below(4));
        }
        _ => {
            let resp = gen_response(&mut inp);
            let enc = encode_frame(&resp).unwrap();
            assert_eq!(decode_response(&enc).ok(), response_in_bounds(&resp).then(|| resp.clone()), "response round trip");
            let mut longer = enc.clone();
            longer.push(inp.u8());
            assert!(decode_response(&longer).is_err(), "a trailing byte was accepted");
            check_frame(&enc);
            check_codec_write_response(&resp);
            // Rarely (4 MiB per check): the read cap. Past the end of the
            // input every byte reads 0, so 0 must not select it.
            if inp.u8() % 64 == 63 {
                check_oversize(&enc, inp.below(4));
            }
        }
    }
});
