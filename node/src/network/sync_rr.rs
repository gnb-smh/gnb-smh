//! Announce-then-pull directed sync — the IBD PULL path over libp2p
//! `request-response`.
//!
//! ## Why this module exists (root cause)
//!
//! The outbound router in `mod.rs` used to send every message that was not
//! `NewBlock`/`NewTransaction` to the shared "sync" **gossipsub** topic:
//!
//! ```text
//! NewBlock => "blocks", NewTransaction => "txs", _ => "sync"
//! ```
//!
//! That `_` arm swept in `GetBlock` / `GetHeaders` / `GetTips` — the IBD block
//! and header **fetch** requests. So a fresh node in IBD *broadcast* a
//! `GetBlock` for every missing block to the ENTIRE mesh (max-peers up to 500),
//! and every peer tried to answer: O(peers × blocks) amplification. That
//! saturated libp2p's gossipsub send queue ("Send Queue full"), starved real
//! `NewBlock` propagation, and stalled the chain. It also produced the
//! "an archival peer is needed" flood (asking the whole mesh, pruned peers
//! answer `BlockNotFound`).
//!
//! ## The fix: announce on gossip, PULL over request-response
//!
//! Lightweight ANNOUNCEMENTS (`PeerTip`, `Version`) stay on gossip — they are
//! small and benefit from mesh flooding. The PULL path (`GetBlock`,
//! `GetHeaders`, `GetTips`) is moved to a **directed** libp2p
//! `request-response` protocol (`/gnb/sync/1`): one request → one chosen
//! peer, not a broadcast. This removes the O(peers) IBD amplification entirely.
//!
//! ## Failure handling (audit NET-5 / NET-7 / NET-9, re-audit B1-T2 / B1-T6)
//!
//! Every answer is bound to the request it answers ([`check_response`]);
//! any other answer is a protocol violation. A directed request that fails
//! (timeout, reset, peer without `/gnb/sync/1`), is answered
//! [`SyncResponse::Busy`] or `BlockNotFound`, or gets a wrong answer is
//! retried on ANOTHER connected peer by `network::pull::PullScheduler`
//! ([`PullPeerSelector`]: hint first, usefulness- and stall-aware, per-peer
//! in-flight cap). It is NEVER re-published on the gossip sync topic:
//! gossip pulls are no longer answered by anyone, because answering them made
//! every node broadcast a reply to the whole mesh (O(N²) amplification). A
//! request that exhausts its attempts is dropped; the processor's own retry
//! paths (frontier expiry, orphan sweep, the 30 s nudge) re-issue it.
//!
//! ## Serving (re-audit B1-T3 / B1-T18 / B2-T5 / B2-T6)
//!
//! Requests are answered off the swarm task by `network::serve`, each in
//! O(log n + limit), under per-class request budgets
//! ([`SyncRequestLimiter`]) and per-peer / global send-byte budgets (a peer
//! that does not read gets `Busy`).

use futures::prelude::*;
use libp2p::request_response::{self, Codec as RrCodec, Config as RrConfig, ProtocolSupport};
use libp2p::{PeerId, StreamProtocol};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io;
use std::time::Duration;

use super::{
    NetworkMessage, SyncEntry, MAX_WIRE_ADDR_LEN, MAX_WIRE_ADDRS, MAX_WIRE_BYTES,
    MAX_WIRE_GETHEADERS_LIMIT, MAX_WIRE_LOCATOR, MAX_WIRE_SYNC_ENTRIES, MAX_WIRE_TIPS,
};

/// Wire protocol id for the Bloch directed-sync request-response family.
pub const SYNC_PROTOCOL: StreamProtocol = StreamProtocol::new("/gnb/sync/1");

/// Max encoded frame — mirrors gossipsub `max_transmit_size` (one block body).
/// Kept as `u64` because `AsyncReadExt::take` wants that type; `MAX_FRAME_LIMIT`
/// below is the same value as `usize` for bincode's `with_limit`.
const MAX_FRAME: u64 = 4 * 1024 * 1024;
/// Most bytes read from an inbound REQUEST stream before decoding. The largest
/// valid `SyncRequest` is `GetBlock` (1 tag byte + 32 bytes = 33);
/// `GetHeaders` with bincode varints is at most 1 + 9 + 5 = 15. A request
/// stream used to be read up to `MAX_FRAME` (4 MiB, sized for block
/// responses) before anything looked at it, and a connection may hold 256
/// inbound streams for the 30 s request timeout: about 1 GiB buffered per
/// peer connection. 64 bytes leaves headroom and bounds that to 16 KiB.
pub const MAX_REQUEST_FRAME: u64 = 64;

/// H-R3-4: `MAX_FRAME` as a `usize`, for `bincode::config::with_limit`. Frame
/// bytes are already capped at the transport by `.take(MAX_FRAME)`, but that
/// bounds only the RAW READ — see the `decode_*` functions below for why the
/// bincode-level limit is not redundant with it.
const MAX_FRAME_LIMIT: usize = MAX_FRAME as usize;

/// B1-T18 / B2-T6: longest an answer may take to be written to its peer
/// (the whole stream, request and answer, still has the 30 s request
/// timeout). 15 s is about 70 KB/s for a 1 MB block.
pub const RESPONSE_WRITE_TIMEOUT: Duration = Duration::from_secs(15);

// ── Wire types ─────────────────────────────────────────────────────────────

/// A directed sync request (the PULL path). Deliberately carries NO `nonce`:
/// gossip dedup is irrelevant to request-response (each request is its own
/// substream), so the anti-dedup nonces the gossip variants need are dropped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncRequest {
    GetBlock { block_hash: [u8; 32] },
    GetHeaders { from_blue_score: u64, limit: u32 },
    GetTips,
    /// M-10 (audit): directed peer-exchange request, added to move
    /// `PeerRequest`/`PeerExchange` off the gossip mesh. A ~2-byte
    /// `PeerRequest` used to make the receiver PUBLISH its whole known-peers
    /// table (up to `KNOWN_PEERS_CAP` entries) to the ENTIRE gossip mesh —
    /// a broadcast-amplifying reply to a broadcast request, and the
    /// receiver's complete peer table handed to anyone who asked (the
    /// reconnaissance step for an eclipse attempt). Routing this through
    /// `/gnb/sync/1` makes it what it always should have been: one
    /// requester, one direct answer.
    GetPeers,
    /// Never on the wire (serde skips it; appended last so every real
    /// variant keeps its bincode tag): what [`BlochSyncCodec::read_request`]
    /// reports for an inbound request frame that is not a valid request
    /// (undecodable, out of bounds, non-canonical, or 64 bytes long). The
    /// codec used to return an error, and libp2p-request-response 0.30 does
    /// not report a request that fails to decode to the behaviour at all (it
    /// only logs it), so the H-R3-4 penalty for malformed requests never
    /// fired. Returned as a request, it reaches the network loop with its
    /// peer and is penalized there like every other protocol violation.
    #[serde(skip)]
    Malformed,
}

impl SyncRequest {
    /// Variant name for diagnostics.
    pub fn kind_name(&self) -> &'static str {
        match self {
            SyncRequest::GetBlock { .. } => "GetBlock",
            SyncRequest::GetHeaders { .. } => "GetHeaders",
            SyncRequest::GetTips => "GetTips",
            SyncRequest::GetPeers => "GetPeers",
            SyncRequest::Malformed => "Malformed",
        }
    }
}

/// A directed sync response, returned to the ONE requesting peer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncResponse {
    Block {
        block_hash: [u8; 32],
        blue_score: u64,
        height: u64,
        block_data: Vec<u8>,
    },
    BlockNotFound {
        block_hash: [u8; 32],
    },
    Headers {
        entries: Vec<SyncEntry>,
    },
    Tips {
        tips: Vec<SyncEntry>,
        locator: Vec<[u8; 32]>,
    },
    /// M-10: answer to [`SyncRequest::GetPeers`] — a bounded, RANDOM SAMPLE
    /// of the responder's known peers (never the whole table; see
    /// `network::mod::PEX_RESPONSE_SAMPLE_SIZE`), sent to the ONE requester.
    Peers {
        peers: Vec<String>,
    },
    /// NET-5 (audit): explicit "rate-limited, ask someone else / later". The
    /// server used to DROP the response channel when its `SyncRequestLimiter`
    /// refused a request; libp2p then closed the stream cleanly, the requester
    /// decoded the empty frame as InvalidData and charged the honest server a
    /// protocol-violation penalty. A refusal is now an answer, and a requester
    /// treats it as back-pressure (rotate peer, retry later), never as an
    /// offence. Appended LAST so every existing variant keeps its bincode tag.
    Busy,
}

impl SyncResponse {
    /// Variant name for diagnostics.
    pub fn kind_name(&self) -> &'static str {
        match self {
            SyncResponse::Block { .. } => "Block",
            SyncResponse::BlockNotFound { .. } => "BlockNotFound",
            SyncResponse::Headers { .. } => "Headers",
            SyncResponse::Tips { .. } => "Tips",
            SyncResponse::Peers { .. } => "Peers",
            SyncResponse::Busy => "Busy",
        }
    }
}

/// Map an outbound `NetworkMessage` to a `SyncRequest` IFF it is a PULL message
/// that must go out as a directed request rather than a gossip broadcast.
///
/// Returns `None` for everything that stays on the gossip announce/response
/// path (`PeerTip`, `Version`, `NewBlock`, `NewTransaction`, `Headers`, `Tips`,
/// `BlockNotFound`, PEX …). This is the router's single source of truth for
/// "does this leave the node as a directed pull, or as gossip?" — and is unit
/// tested to prove IBD fetches never hit the gossip mesh.
pub fn as_pull_request(msg: &NetworkMessage) -> Option<SyncRequest> {
    match msg {
        NetworkMessage::GetBlock { block_hash, .. } => {
            Some(SyncRequest::GetBlock { block_hash: *block_hash })
        }
        NetworkMessage::GetHeaders { from_blue_score, limit, .. } => Some(SyncRequest::GetHeaders {
            from_blue_score: *from_blue_score,
            limit: *limit,
        }),
        NetworkMessage::GetTips => Some(SyncRequest::GetTips),
        // M-10: PeerRequest is now a directed pull too — see `SyncRequest::GetPeers`.
        NetworkMessage::PeerRequest => Some(SyncRequest::GetPeers),
        _ => None,
    }
}

/// Whether a directed pull, answered with `resp` by one peer, must be tried on
/// another peer: `Busy` (back-pressure, NET-5) and `BlockNotFound` (that peer
/// does not have the body; the selector picks peers without knowing who
/// announced the block, so it is often not the peer that has it). Every other
/// answer completes the pull. `BlockNotFound` used to complete it: after a
/// partition healed, a node asked the one peer that lacked a block and waited
/// for the 30-60 s sweeps (test/functional/feature_partition_heal.py).
pub fn retry_pull_elsewhere(resp: &SyncResponse) -> bool {
    matches!(resp, SyncResponse::Busy | SyncResponse::BlockNotFound { .. })
}

/// Audit B1-T2 / NET-10: whether `resp` is an answer an honest server can
/// give to `req`. Every answer is bound to the request it answers:
///
/// * `GetBlock { h }`: `Block` or `BlockNotFound` for exactly `h`;
/// * `GetHeaders { from, limit }`: `Headers` with at most `limit` entries,
///   none below `from` (what every release's `ordered_hashes_from` returns);
/// * `GetTips`: `Tips`; `GetPeers`: `Peers`;
/// * `Busy` (NET-5): to any request.
///
/// Anything else is a protocol violation by the answering peer: it is
/// penalized, not delivered to the processor, and does not complete the pull.
/// Before, any well-formed answer completed any pull and reached the
/// processor as solicited data: a peer answering the on-connect GetPeers or
/// GetTips with 2,000 made-up headers made the node issue 2,000 GetBlocks.
/// (Bitcoin Core processes a `block` only if it is in `mapBlocksInFlight`
/// from that peer and `headers` only if they connect.)
pub fn check_response(req: &SyncRequest, resp: &SyncResponse) -> Result<(), &'static str> {
    use SyncRequest as Q;
    use SyncResponse as A;
    match (req, resp) {
        (_, A::Busy) => Ok(()),
        (Q::GetBlock { block_hash }, A::Block { block_hash: got, .. }) => {
            if got == block_hash { Ok(()) } else { Err("Block answer for another block") }
        }
        (Q::GetBlock { block_hash }, A::BlockNotFound { block_hash: got }) => {
            if got == block_hash { Ok(()) } else { Err("BlockNotFound answer for another block") }
        }
        (Q::GetHeaders { from_blue_score, limit }, A::Headers { entries }) => {
            if entries.len() > *limit as usize {
                Err("more headers than requested")
            } else if entries.iter().any(|e| e.blue_score < *from_blue_score) {
                Err("header below the requested blue score")
            } else {
                Ok(())
            }
        }
        (Q::GetTips, A::Tips { .. }) | (Q::GetPeers, A::Peers { .. }) => Ok(()),
        _ => Err("answer of the wrong kind for the request"),
    }
}

/// Convert a received `SyncResponse` into the `NetworkMessage` the existing
/// `main.rs` message-processor already understands, so directed-pull answers
/// flow through the SAME ingest path as the legacy gossip answers — no change
/// to the processor's block/header handling.
///
/// `Busy` (NET-5) carries no payload for the processor and maps to `None`:
/// the network loop handles it (peer rotation + retry) before delivery.
pub fn response_to_message(resp: SyncResponse) -> Option<NetworkMessage> {
    Some(match resp {
        SyncResponse::Block { block_hash, blue_score, height, block_data } => {
            NetworkMessage::NewBlock { block_hash, blue_score, height, block_data }
        }
        // nonce is meaningless off the gossip topic; the processor ignores it.
        SyncResponse::BlockNotFound { block_hash } => {
            NetworkMessage::BlockNotFound { block_hash, nonce: 0 }
        }
        SyncResponse::Headers { entries } => NetworkMessage::Headers { entries },
        SyncResponse::Tips { tips, locator } => NetworkMessage::Tips { tips, locator },
        // M-10: feeds into the SAME `PeerExchange` ingest path gossip PEX
        // already uses (rate limit, batch cap, address validation, no
        // persistence until a dial confirms) — no new client-side logic
        // needed, only the transport (directed vs. broadcast) changed.
        SyncResponse::Peers { peers } => NetworkMessage::PeerExchange { peers },
        SyncResponse::Busy => return None,
    })
}

// ── Codec ──────────────────────────────────────────────────────────────────

/// Length-delimited-by-EOF bincode codec (mirrors libp2p's own cbor codec: the
/// request-response framework opens a fresh substream per message and closes
/// the write half after writing, so `read_to_end` cleanly delimits the frame).
#[derive(Clone, Default)]
pub struct BlochSyncCodec;

// libp2p-request-response 0.30 declares the codec methods as
// `fn … -> impl Future + Send` (no `#[async_trait]`); `async fn` implements them.
impl RrCodec for BlochSyncCodec {
    type Protocol = StreamProtocol;
    type Request = SyncRequest;
    type Response = SyncResponse;

    async fn read_request<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<SyncRequest>
    where
        T: AsyncRead + Unpin + Send,
    {
        // A stream closed without a frame stays a transport error.
        let buf = read_raw_frame(io, MAX_REQUEST_FRAME).await?;
        // No valid request is MAX_REQUEST_FRAME bytes long, and a frame that
        // fails `decode_request` is no valid request either: both are
        // reported as `Malformed` so the network loop can attribute and
        // penalize them (see `SyncRequest::Malformed`).
        if buf.len() as u64 >= MAX_REQUEST_FRAME {
            return Ok(SyncRequest::Malformed);
        }
        match decode_request(&buf) {
            Ok(req) => Ok(req),
            Err(e) if is_sync_protocol_violation(&e) => Ok(SyncRequest::Malformed),
            Err(e) => Err(e),
        }
    }

    async fn read_response<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<SyncResponse>
    where
        T: AsyncRead + Unpin + Send,
    {
        let buf = read_raw_frame(io, MAX_FRAME).await?;
        decode_response(&buf)
    }

    async fn write_request<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        req: SyncRequest,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let data = encode_frame(&req)?;
        io.write_all(&data).await
    }

    /// B1-T18 / B2-T6: a `Block` answer is streamed (its frame prefix, then
    /// the stored block bytes as they are) instead of being encoded into a
    /// second full copy, and every answer is given at most
    /// [`RESPONSE_WRITE_TIMEOUT`] to be written: a peer that does not read
    /// stops holding the answer (and its send-budget charge) at that point,
    /// not at the 30 s stream timeout. The bytes written are exactly
    /// `encode_frame(&resp)` (`block_response_is_written_as_its_exact_frame`).
    async fn write_response<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        resp: SyncResponse,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        with_write_deadline(async move {
            match &resp {
                SyncResponse::Block { block_data, .. } => {
                    io.write_all(&block_frame_prefix(&resp)?).await?;
                    io.write_all(block_data).await
                }
                _ => io.write_all(&encode_frame(&resp)?).await,
            }
        })
        .await
    }
}

/// Bounds a response write by [`RESPONSE_WRITE_TIMEOUT`] when it runs on a
/// tokio runtime (the swarm's connection tasks do); elsewhere (the fuzz
/// target and codec tests drive the codec with `block_on`) it is unbounded.
async fn with_write_deadline<F>(write: F) -> io::Result<()>
where
    F: std::future::Future<Output = io::Result<()>> + Send,
{
    if tokio::runtime::Handle::try_current().is_err() {
        return write.await;
    }
    match tokio::time::timeout(RESPONSE_WRITE_TIMEOUT, write).await {
        Ok(r) => r,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "sync response not written within RESPONSE_WRITE_TIMEOUT (the peer does not read)",
        )),
    }
}

/// Append bincode's `standard()` varint encoding of `v`.
fn push_varint(out: &mut Vec<u8>, v: u64) {
    match v {
        0..=250 => out.push(v as u8),
        251..=0xFFFF => {
            out.push(0xFB);
            out.extend_from_slice(&(v as u16).to_le_bytes());
        }
        0x1_0000..=0xFFFF_FFFF => {
            out.push(0xFC);
            out.extend_from_slice(&(v as u32).to_le_bytes());
        }
        _ => {
            out.push(0xFD);
            out.extend_from_slice(&v.to_le_bytes());
        }
    }
}

/// The bytes of `encode_frame(resp)` before the block bytes of a `Block`
/// answer: the encoding of the same answer with an empty `block_data`, whose
/// last byte (the length 0) is replaced by the real length.
fn block_frame_prefix(resp: &SyncResponse) -> io::Result<Vec<u8>> {
    let SyncResponse::Block { block_hash, blue_score, height, block_data } = resp else {
        return encode_frame(resp);
    };
    let mut prefix = encode_frame(&SyncResponse::Block {
        block_hash: *block_hash,
        blue_score: *blue_score,
        height: *height,
        block_data: Vec::new(),
    })?;
    debug_assert_eq!(prefix.last(), Some(&0));
    prefix.pop();
    push_varint(&mut prefix, block_data.len() as u64);
    Ok(prefix)
}

/// Read the raw frame bytes off the wire, capped at `cap` ([`MAX_REQUEST_FRAME`]
/// for requests, [`MAX_FRAME`] for responses). This bounds the READ; it does
/// not by itself bound what bincode does with the bytes (see
/// [`decode_frame`]'s doc comment) — it only stops a peer from streaming
/// unbounded data down an open substream.
async fn read_raw_frame<T>(io: &mut T, cap: u64) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let mut buf = Vec::new();
    io.take(cap).read_to_end(&mut buf).await?;
    check_nonempty_frame(buf)
}

/// NET-5 (audit): a clean EOF with zero bytes is what a peer produces when it
/// closes the stream without answering (an overloaded or restarting server,
/// a dropped response channel, a stream reset by the muxer). No well-formed
/// frame is empty, but no DELIBERATE violation looks like this either, so it
/// is reported as `UnexpectedEof` — a transport failure that
/// [`is_sync_protocol_violation`] never penalizes — instead of falling
/// through to the decoder's `InvalidData`.
pub fn check_nonempty_frame(buf: Vec<u8>) -> io::Result<Vec<u8>> {
    if buf.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "sync stream closed without a frame (transport failure, not a violation)",
        ));
    }
    Ok(buf)
}

/// Length of bincode's `standard()` varint encoding of `v`.
fn varint_len(v: u64) -> usize {
    match v {
        0..=250 => 1,
        251..=0xFFFF => 3,
        0x1_0000..=0xFFFF_FFFF => 5,
        _ => 9,
    }
}

fn entries_wire_len(entries: &[SyncEntry]) -> usize {
    varint_len(entries.len() as u64)
        + entries.iter().map(|e| 32 + varint_len(e.blue_score) + varint_len(e.height)).sum::<usize>()
}

/// Exact length of `encode_frame(resp)`, computed without encoding: what a
/// response costs while it waits to be written to a peer (B1-T18 / B2-T6
/// send-buffer accounting).
pub fn response_wire_len(resp: &SyncResponse) -> usize {
    // Every variant index is below 251: a one-byte tag.
    1 + match resp {
        SyncResponse::Block { blue_score, height, block_data, .. } => {
            32 + varint_len(*blue_score) + varint_len(*height) + varint_len(block_data.len() as u64) + block_data.len()
        }
        SyncResponse::BlockNotFound { .. } => 32,
        SyncResponse::Headers { entries } => entries_wire_len(entries),
        SyncResponse::Tips { tips, locator } => entries_wire_len(tips) + varint_len(locator.len() as u64) + 32 * locator.len(),
        SyncResponse::Peers { peers } => {
            varint_len(peers.len() as u64) + peers.iter().map(|p| varint_len(p.len() as u64) + p.len()).sum::<usize>()
        }
        SyncResponse::Busy => 0,
    }
}

/// Bincode-encode a frame (same wire config as the gossip path uses).
pub fn encode_frame<M: Serialize>(m: &M) -> io::Result<Vec<u8>> {
    bincode::serde::encode_to_vec(m, bincode::config::standard())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

/// H-R3-4: this used to decode with `bincode::config::standard()` — NO
/// read limit — the exact anti-pattern `network/mod.rs::decode_wire_message`
/// exists to forbid on untrusted input ("`bincode::config::standard()`
/// without a limit must never be used on untrusted input"). The 4 MiB
/// `read_raw_frame` cap made the immediate blast radius accidental, not
/// structural: raise `MAX_FRAME`, or decode a buffer sourced any other way,
/// and `claim_container_read` becomes a no-op again and a small frame can
/// declare a multi-GB `Vec` length. This function is now the ONLY correct
/// way to decode a `/gnb/sync/1` frame: it (1) applies a bincode read
/// limit equal to `MAX_FRAME`, so an over-declared length is rejected before
/// allocation, and (2) rejects trailing bytes — `decode_from_slice` reports
/// how many bytes it consumed, and a frame padded past its logical content
/// (e.g. a 1-byte `GetTips` padded to 4 MiB) used to decode successfully with
/// the remainder silently discarded.
///
/// Field-level bounds (`GetHeaders.limit`, `Headers.entries.len()`, etc.) are
/// NOT applied here — see [`decode_request`] / [`decode_response`], which
/// call this and then apply the mirror of `validate_wire_bounds` for the
/// gossip path.
pub fn decode_frame<M: for<'de> Deserialize<'de>>(buf: &[u8]) -> io::Result<M> {
    let cfg = bincode::config::standard().with_limit::<MAX_FRAME_LIMIT>();
    let (msg, consumed) = bincode::serde::decode_from_slice(buf, cfg).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, e.to_string())
    })?;
    if consumed != buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "sync frame has {} trailing byte(s) after a {}-byte decode",
                buf.len() - consumed,
                consumed
            ),
        ));
    }
    Ok(msg)
}

/// [`decode_frame`] plus the one-encoding rule of the gossip path
/// (`network::WireDecodeError::NonCanonical`): bincode accepts non-minimal
/// varints, so the frame must equal the re-encoding of what it decoded to.
fn decode_canonical<M: Serialize + for<'de> Deserialize<'de>>(buf: &[u8]) -> io::Result<M> {
    let msg: M = decode_frame(buf)?;
    if encode_frame(&msg)? != buf {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "non-canonical sync frame (non-minimal varint)"));
    }
    Ok(msg)
}

/// Decode + bounds-validate an inbound [`SyncRequest`]. The directed-sync
/// analogue of `network/mod.rs::decode_wire_message` for the gossip path:
/// same read-limit discipline, same per-field bounds, so a peer cannot use
/// the directed protocol to bypass limits enforced on the gossip one.
pub fn decode_request(buf: &[u8]) -> io::Result<SyncRequest> {
    let req: SyncRequest = decode_canonical(buf)?;
    validate_sync_request_bounds(&req)?;
    Ok(req)
}

/// Decode + bounds-validate an inbound [`SyncResponse`]. Without this, a
/// malicious peer answering our `GetHeaders` could return ~123,000
/// `SyncEntry`s in one 4 MiB frame instead of the `MAX_WIRE_SYNC_ENTRIES`
/// (2000) the gossip path enforces, and the processor would then walk the
/// whole thing and issue a `GetBlock` per unknown entry.
pub fn decode_response(buf: &[u8]) -> io::Result<SyncResponse> {
    let resp: SyncResponse = decode_canonical(buf)?;
    validate_sync_response_bounds(&resp)?;
    Ok(resp)
}

fn bounds_violation(msg: &'static str) -> io::Error {
    // `InvalidData` is the marker the caller (network/mod.rs's SyncRr event
    // arm) uses to recognise a deliberate protocol violation — as opposed to
    // a transport-level `InboundFailure`/`OutboundFailure::Io` (timeout,
    // connection reset) which must NOT be treated as an attack — and route it
    // to `WirePenaltyTracker`, mirroring the gossip path's reaction to
    // `WireDecodeError::Bounds`.
    io::Error::new(io::ErrorKind::InvalidData, format!("sync wire bounds violation: {msg}"))
}

/// Mirrors `network/mod.rs::validate_wire_bounds` for [`SyncRequest`]. This is
/// what closes the gap C-1/H-4 both name: the directed protocol previously
/// enforced NONE of the bounds the gossip protocol enforces on the same
/// logical fields.
fn validate_sync_request_bounds(req: &SyncRequest) -> io::Result<()> {
    match req {
        SyncRequest::GetHeaders { limit, .. } => {
            if *limit > MAX_WIRE_GETHEADERS_LIMIT {
                return Err(bounds_violation("GetHeaders limit above MAX_WIRE_GETHEADERS_LIMIT"));
            }
        }
        SyncRequest::GetBlock { .. } | SyncRequest::GetTips | SyncRequest::GetPeers => {}
        // Unreachable from a decode (serde never produces it).
        SyncRequest::Malformed => return Err(bounds_violation("malformed request")),
    }
    Ok(())
}

/// Mirrors `network/mod.rs::validate_wire_bounds` for [`SyncResponse`].
fn validate_sync_response_bounds(resp: &SyncResponse) -> io::Result<()> {
    match resp {
        SyncResponse::Block { block_data, .. } => {
            // Belt-and-braces: unreachable today (a response body can't
            // exceed the MAX_FRAME-capped frame that carries it), kept in
            // case the two constants ever diverge — same rationale as the
            // gossip path's NewBlock/NewTransaction checks.
            if block_data.len() > MAX_WIRE_BYTES {
                return Err(bounds_violation("block_data larger than MAX_WIRE_BYTES"));
            }
        }
        SyncResponse::BlockNotFound { .. } | SyncResponse::Busy => {}
        SyncResponse::Headers { entries } => {
            if entries.len() > MAX_WIRE_SYNC_ENTRIES {
                return Err(bounds_violation("Headers entries longer than MAX_WIRE_SYNC_ENTRIES"));
            }
        }
        SyncResponse::Tips { tips, locator } => {
            // Every release caps the locator: checked first, so only a
            // frame an honest older release can send escapes the penalty.
            if locator.len() > MAX_WIRE_LOCATOR {
                return Err(bounds_violation("Tips locator longer than MAX_WIRE_LOCATOR"));
            }
            if tips.len() > MAX_WIRE_TIPS {
                // B2-T7: refused, but releases before this one answered
                // GetTips with every DAG leaf, so an honest server with more
                // than MAX_WIRE_TIPS leaves sends this: not penalized.
                return Err(honest_overflow("Tips tips longer than MAX_WIRE_TIPS"));
            }
        }
        // M-10: mirrors the gossip PeerExchange/PeerCount bound exactly —
        // same field, same cap, whichever transport it arrives over.
        SyncResponse::Peers { peers } => {
            if peers.len() > MAX_WIRE_ADDRS {
                return Err(bounds_violation("Peers list longer than MAX_WIRE_ADDRS"));
            }
            if peers.iter().any(|a| a.len() > MAX_WIRE_ADDR_LEN) {
                return Err(bounds_violation("Peers address string longer than MAX_WIRE_ADDR_LEN"));
            }
        }
    }
    Ok(())
}

/// Marker inside an `InvalidData` error for a frame that breaks a wire bound
/// but that an honest older release can send (B2-T7): refused, never
/// penalized.
#[derive(Debug)]
struct HonestOverflow(&'static str);

impl std::fmt::Display for HonestOverflow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sync wire bound exceeded (sent by older releases, not penalized): {}", self.0)
    }
}

impl std::error::Error for HonestOverflow {}

fn honest_overflow(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, HonestOverflow(msg))
}

/// True iff an `io::Error` surfaced from this codec (via `OutboundFailure::Io`
/// in the caller) represents a DELIBERATE protocol violation
/// (oversized/malformed/out-of-bounds frame) rather than an ordinary
/// transport failure (peer disconnected, timed out, reset). Callers use this
/// to decide whether to apply a `WirePenaltyTracker` penalty — penalizing a
/// peer for a network hiccup would be a correctness bug, not just an
/// accounting one. B2-T7: only answers an honest node cannot produce count;
/// a Tips answer over `MAX_WIRE_TIPS` (every release before this one sent
/// all its DAG leaves) is refused but is not a violation.
pub fn is_sync_protocol_violation(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::InvalidData && !e.get_ref().is_some_and(|inner| inner.is::<HonestOverflow>())
}

// ── Behaviour ──────────────────────────────────────────────────────────────

pub type Behaviour = request_response::Behaviour<BlochSyncCodec>;
pub type Event = request_response::Event<SyncRequest, SyncResponse>;

/// Max concurrent request-response streams (inbound + outbound) the handler keeps
/// open per connection before it drops new INBOUND streams with
/// "Dropping inbound stream because we are at capacity". libp2p's default is 100,
/// which a node catching up across the wide damaged-fork anticone blows past: the
/// recursive missing-parent resolution (`GetBlock` per absent ancestor) opens a
/// burst of streams, and once at capacity the peer's new-block deliveries AND its
/// inbound peering handshake get dropped — the follower sits `syncing:false` at its
/// snapshot tip and never converges.
///
/// H-R3-1 lowered it from 2048 to 256. B1-T18 / B2-T6 (re-audit): every open
/// inbound stream can hold one answer until it is written (up to
/// [`RESPONSE_WRITE_TIMEOUT`]), and yamux lets each stream push up to its
/// 256 KiB window into the connection, so the cap bounds the memory a peer
/// that does not read can pin. An honest client keeps at most
/// [`MAX_INFLIGHT_PER_PEER`] (16) pulls in flight to one peer, plus its
/// on-connect GetPeers / GetTips and claim-driven GetTips, and the server
/// answers Busy above [`crate::network::serve::PER_PEER_SEND_BUDGET`] bytes
/// anyway: 64 keeps a 4x margin over an honest client. A stream over the cap
/// is dropped by libp2p, which the requester sees as a transport failure
/// (retried elsewhere, never penalized).
pub const MAX_CONCURRENT_SYNC_STREAMS: usize = 64;

// ── H-R3-1 fix #4: per-peer token buckets on inbound sync requests ─────────
//
// Each served request is O(log n + limit) (B1-T3 / B2-T5: indexed DAG reads,
// stored block bytes), but a peer could still send legitimately-shaped
// requests back-to-back: these buckets bound the RATE, per peer and in
// total, independently of the per-request cost. GetHeaders and GetTips (the
// answers that read the DAG: up to 2,000 headers / 256 tips) have their own
// per-peer budgets, far lower than GetBlock's, and an exhausted class does
// not eat into another.

/// GetBlock bucket capacity (burst allowance) per peer.
pub const SYNC_BUCKET_CAPACITY: u32 = 64;
/// GetBlock refill rate per peer, tokens/second. At capacity 64 this allows a
/// burst of 64 immediately, then a sustained 8 req/s — comfortably above what
/// one honest IBD follower asks of one peer (at most `MAX_INFLIGHT_PER_PEER`
/// in flight, spread over its peers) while bounding what a single hostile
/// identity can sustain against us.
const SYNC_BUCKET_REFILL_PER_SEC: u32 = 8;
/// GetHeaders per peer: burst 16, then 2/s. An honest follower asks one
/// GetHeaders per 500-block batch it has fetched, per 30 s nudge and per
/// tip claim it acts on.
pub const SYNC_HEADERS_BUCKET_CAPACITY: u32 = 16;
const SYNC_HEADERS_REFILL_PER_SEC: f64 = 2.0;
/// GetTips per peer: burst 8, then one per 2 s. An honest peer asks on
/// connect, per tip claim of ours it acts on (rate-limited per author), and
/// on its 30 s nudge.
pub const SYNC_TIPS_BUCKET_CAPACITY: u32 = 8;
const SYNC_TIPS_REFILL_PER_SEC: f64 = 0.5;
/// GetPeers per peer: burst 4, then one per 10 s (asked once per connection).
pub const SYNC_PEERS_BUCKET_CAPACITY: u32 = 4;
const SYNC_PEERS_REFILL_PER_SEC: f64 = 0.1;
/// Cap on the number of peers tracked, mirroring
/// `network::WIRE_PENALTY_TRACK_CAP` — bounds memory against an attacker
/// cycling libp2p identities (free to generate).
const SYNC_LIMITER_TRACK_CAP: usize = 1024;
/// NET-8: aggregate serving budget across ALL peers (burst / per second).
/// Bounds the total directed-sync work this node does regardless of how many
/// identities ask, so per-peer buckets can evict freely without ever turning
/// identity cycling into extra capacity.
const SYNC_GLOBAL_CAPACITY: u32 = 1024;
const SYNC_GLOBAL_REFILL_PER_SEC: f64 = 256.0;
/// Keys idle this long (or whose bucket refilled) are garbage-collected.
pub const SYNC_LIMITER_IDLE_TTL: Duration = Duration::from_secs(120);

/// Per-peer token buckets for inbound `/gnb/sync/1` REQUESTS (as opposed to
/// [`super::WirePenaltyTracker`], which scores DECODE/BOUNDS violations), one
/// per request class, plus a global bucket. They refill lazily on each call
/// (no background task); a call consumes one token of the request's class
/// and one of the global bucket and says whether the request should be
/// served. A refused request is answered with [`SyncResponse::Busy`]
/// (NET-5), never by dropping the channel.
///
/// NET-8 (audit): the per-peer map used to fail CLOSED once 1,024 identities
/// had been seen — every later peer, honest or not, was refused forever. It is
/// now a bounded LRU ([`super::ratelimit::TokenBuckets`]): a newcomer always
/// gets a bucket (an idle or least-recently-used key is evicted), and a global
/// bucket bounds the aggregate rate so eviction cannot be farmed.
pub struct SyncRequestLimiter {
    per_peer: super::ratelimit::TokenBuckets<PeerId>,
    headers: super::ratelimit::TokenBuckets<PeerId>,
    tips: super::ratelimit::TokenBuckets<PeerId>,
    peers: super::ratelimit::TokenBuckets<PeerId>,
    global: super::ratelimit::TokenBuckets<()>,
}

impl Default for SyncRequestLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl SyncRequestLimiter {
    pub fn new() -> Self {
        use super::ratelimit::TokenBuckets;
        Self {
            per_peer: TokenBuckets::new(SYNC_BUCKET_CAPACITY, f64::from(SYNC_BUCKET_REFILL_PER_SEC), SYNC_LIMITER_TRACK_CAP),
            headers: TokenBuckets::new(SYNC_HEADERS_BUCKET_CAPACITY, SYNC_HEADERS_REFILL_PER_SEC, SYNC_LIMITER_TRACK_CAP),
            tips: TokenBuckets::new(SYNC_TIPS_BUCKET_CAPACITY, SYNC_TIPS_REFILL_PER_SEC, SYNC_LIMITER_TRACK_CAP),
            peers: TokenBuckets::new(SYNC_PEERS_BUCKET_CAPACITY, SYNC_PEERS_REFILL_PER_SEC, SYNC_LIMITER_TRACK_CAP),
            global: TokenBuckets::new(SYNC_GLOBAL_CAPACITY, SYNC_GLOBAL_REFILL_PER_SEC, 1),
        }
    }

    /// Returns `true` iff a GetBlock token was available (and is now
    /// consumed) for `peer`. Callers must NOT serve the request when this
    /// returns `false` (they answer [`SyncResponse::Busy`] instead).
    pub fn allow(&mut self, peer: PeerId) -> bool {
        self.allow_at(peer, std::time::Instant::now())
    }

    /// [`Self::allow`] with an explicit clock (deterministic tests).
    pub fn allow_at(&mut self, peer: PeerId, now: std::time::Instant) -> bool {
        if !self.per_peer.allow_at(peer, now) {
            return false;
        }
        self.global.allow_at((), now)
    }

    /// Whether `req` from `peer` may be served now: one token of the
    /// request's own class (GetBlock, GetHeaders, GetTips, GetPeers) and one
    /// of the global bucket. A `Malformed` request is never served.
    pub fn allow_request(&mut self, peer: PeerId, req: &SyncRequest, now: std::time::Instant) -> bool {
        let class_ok = match req {
            SyncRequest::GetBlock { .. } => self.per_peer.allow_at(peer, now),
            SyncRequest::GetHeaders { .. } => self.headers.allow_at(peer, now),
            SyncRequest::GetTips => self.tips.allow_at(peer, now),
            SyncRequest::GetPeers => self.peers.allow_at(peer, now),
            SyncRequest::Malformed => false,
        };
        class_ok && self.global.allow_at((), now)
    }

    /// Drop idle / fully-refilled peers (heartbeat housekeeping).
    pub fn gc_at(&mut self, now: std::time::Instant) {
        for b in [&mut self.per_peer, &mut self.headers, &mut self.tips, &mut self.peers] {
            b.gc_at(now, SYNC_LIMITER_IDLE_TTL);
        }
    }

    /// Number of peers currently tracked (observability for tests/metrics).
    pub fn tracked_peers(&self) -> usize {
        self.per_peer.tracked()
    }
}

/// Build the request-response behaviour for `/gnb/sync/1`. `Full` support =
/// this node both serves inbound pulls and issues outbound pulls.
pub fn new_behaviour() -> Behaviour {
    Behaviour::with_codec(
        BlochSyncCodec,
        std::iter::once((SYNC_PROTOCOL, ProtocolSupport::Full)),
        RrConfig::default()
            .with_request_timeout(Duration::from_secs(30))
            .with_max_concurrent_streams(MAX_CONCURRENT_SYNC_STREAMS),
    )
}

// ── Peer selection ───────────────────────────────────────────────────────────

/// Per-peer sync hint: highest announced blue_score and the peer's
/// SELF-DECLARED archival bit (identify agent-version; `None` = unknown).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerSync {
    pub blue_score: u64,
    pub archival: Option<bool>,
}

/// Stateless legacy selector: the explicit `--peer` (highest blue_score among
/// them), else the highest-blue_score peer. Ties break by PeerId bytes.
///
/// NET-9 (audit): the `archival` bit is IGNORED. It is self-declared in the
/// identify agent string, so preferring it let any peer that claimed
/// "archival" (and announced a high score) capture every pull. The live
/// network loop no longer uses this function at all: it uses
/// [`PullPeerSelector`], which rotates, caps in-flight requests and puts
/// stalling peers on cooldown.
pub fn select_pull_peer(
    peers: &HashMap<PeerId, PeerSync>,
    explicit: &HashSet<PeerId>,
) -> Option<PeerId> {
    if let Some(p) = peers
        .iter()
        .filter(|(p, _)| explicit.contains(p))
        .max_by(|a, b| score_cmp(a, b))
        .map(|(p, _)| *p)
    {
        return Some(p);
    }
    peers.iter().max_by(|a, b| score_cmp(a, b)).map(|(p, _)| *p)
}

fn score_cmp(
    a: &(&PeerId, &PeerSync),
    b: &(&PeerId, &PeerSync),
) -> std::cmp::Ordering {
    a.1.blue_score
        .cmp(&b.1.blue_score)
        .then_with(|| a.0.to_bytes().cmp(&b.0.to_bytes()))
}

/// NET-5: client-side cap on concurrent directed pulls to ONE peer. Kept well
/// below the server's per-peer burst (`SYNC_BUCKET_CAPACITY`) so an honest
/// IBD burst is spread across peers instead of tripping one server's limiter.
/// (Bitcoin Core: MAX_BLOCKS_IN_TRANSIT_PER_PEER = 16.)
pub const MAX_INFLIGHT_PER_PEER: u32 = 16;
/// NET-9: stall score (timeouts, transport failures, violations; decaying
/// with [`SCORE_HALF_LIFE`]) at which a peer is put on cooldown.
pub const STALL_FAILURES: u32 = 2;
/// NET-9: first cooldown of a stalled peer. Each further cooldown within
/// [`COOLDOWN_MEMORY`] of the previous one doubles it, up to
/// [`MAX_STALL_COOLDOWN`].
pub const STALL_COOLDOWN: Duration = Duration::from_secs(60);
/// Longest stall cooldown.
pub const MAX_STALL_COOLDOWN: Duration = Duration::from_secs(16 * 60);
/// A cooldown this long after the previous one starts again at
/// [`STALL_COOLDOWN`].
pub const COOLDOWN_MEMORY: Duration = Duration::from_secs(30 * 60);
/// NET-5: short back-off after a `Busy` answer (honest back-pressure).
pub const BUSY_COOLDOWN: Duration = Duration::from_secs(2);
/// B1-T6: half-life of a peer's stall and useless-answer scores.
pub const SCORE_HALF_LIFE: Duration = Duration::from_secs(60);
/// B1-T6: a peer whose penalty (useless answers + 2 x stall score) reaches
/// this is asked only when no better connected peer could take the pull,
/// even later: a pull waits for a better peer to have a free slot instead.
pub const POOR_PEER_PENALTY: f64 = 4.0;
/// NET-9 residual: selector state of disconnected peers is kept (bounded) so
/// a cooldown survives a reconnect; beyond this many entries the longest
/// disconnected ones are forgotten.
pub const MAX_TRACKED_PULL_PEERS: usize = 1024;

#[derive(Clone, Debug, Default)]
struct PullPeer {
    connected: bool,
    /// The current connection was dialed by us (not an identity that
    /// connected to us).
    outbound: bool,
    in_flight: u32,
    /// Timeouts, transport failures and violations (decaying).
    stall: f64,
    /// NotFound and other answers that did not help (decaying).
    useless: f64,
    /// When `stall` / `useless` were last brought up to date.
    scored_at: Option<std::time::Instant>,
    cooldown_until: Option<std::time::Instant>,
    /// Consecutive stall cooldowns (each doubles the next).
    cooldown_level: u32,
    last_cooldown: Option<std::time::Instant>,
    last_selected: Option<std::time::Instant>,
    disconnected_at: Option<std::time::Instant>,
}

impl PullPeer {
    fn decay_factor(&self, now: std::time::Instant) -> f64 {
        match self.scored_at {
            Some(t) => 0.5f64.powf(now.saturating_duration_since(t).as_secs_f64() / SCORE_HALF_LIFE.as_secs_f64()),
            None => 1.0,
        }
    }

    /// Bring the decaying scores up to `now`.
    fn decay(&mut self, now: std::time::Instant) {
        let f = self.decay_factor(now);
        self.stall *= f;
        self.useless *= f;
        self.scored_at = Some(now);
    }

    fn penalty_at(&self, now: std::time::Instant) -> f64 {
        (self.useless + 2.0 * self.stall) * self.decay_factor(now)
    }

    fn eligible(&self, now: std::time::Instant) -> bool {
        self.connected && self.in_flight < MAX_INFLIGHT_PER_PEER && self.cooldown_until.is_none_or(|t| now >= t)
    }

    fn cool_down(&mut self, now: std::time::Instant) {
        self.cooldown_level = match self.last_cooldown {
            Some(t) if now.saturating_duration_since(t) < COOLDOWN_MEMORY => self.cooldown_level.saturating_add(1),
            _ => 0,
        };
        let d = STALL_COOLDOWN.saturating_mul(1u32 << self.cooldown_level.min(4)).min(MAX_STALL_COOLDOWN);
        let until = now + d;
        self.cooldown_until = Some(self.cooldown_until.map_or(until, |t| t.max(until)));
        self.last_cooldown = Some(now);
    }
}

/// Rank class of a penalty: 0 below 2, then one more per doubling.
fn penalty_rank(p: f64) -> u32 {
    if p < 2.0 { 0 } else { p.log2().floor().min(30.0) as u32 }
}

/// NET-9 / B1-T6 (audit, re-audit): stateful directed-pull peer selection.
///
/// Candidates are the connected peers below [`MAX_INFLIGHT_PER_PEER`] and not
/// on cooldown, minus the peers a pull already tried. Among them the
/// selector prefers, in order:
///
/// 1. peers in good standing (penalty below [`POOR_PEER_PENALTY`]);
/// 2. the peers the pull names as having the block (the peer whose answer
///    announced it — Bitcoin Core downloads a block from a peer whose headers
///    chain contains it);
/// 3. a lower penalty class: useless answers (NotFound, an empty answer from
///    a peer that claimed more) and twice the stall score (timeouts,
///    violations), both decaying with [`SCORE_HALF_LIFE`] — so a peer that
///    answers fast with nothing, which always has the fewest pulls in flight,
///    no longer wins by being fast;
/// 4. fewer pulls in flight, then the least recently selected (rotation),
///    then an explicit `--peer`, then the PeerId.
///
/// A poor peer is chosen only when no better connected peer could take the
/// pull at all (the caller waits instead while one is busy or cooling down).
/// Nothing self-declared (archival bit, announced score) influences the
/// choice. The state of a disconnected peer (scores, cooldown, rotation slot)
/// is kept in a bounded table, so reconnecting does not clear a cooldown.
#[derive(Debug, Default)]
pub struct PullPeerSelector {
    peers: HashMap<PeerId, PullPeer>,
    explicit: HashSet<PeerId>,
}

impl PullPeerSelector {
    pub fn new(explicit: HashSet<PeerId>) -> Self {
        Self { peers: HashMap::new(), explicit }
    }

    /// A connection to `peer` was established (direction unknown: inbound).
    #[allow(dead_code)] // library API and tests; the node binary compiles this module too
    pub fn on_connect(&mut self, peer: PeerId) {
        self.on_connect_with(peer, false, std::time::Instant::now());
    }

    /// A connection to `peer` was established; `outbound` = we dialed it.
    /// A known peer keeps its scores, cooldown and rotation slot.
    pub fn on_connect_with(&mut self, peer: PeerId, outbound: bool, now: std::time::Instant) {
        if !self.peers.contains_key(&peer) && self.peers.len() >= MAX_TRACKED_PULL_PEERS {
            self.forget_one_disconnected();
        }
        let s = self.peers.entry(peer).or_default();
        s.outbound = if s.connected { s.outbound || outbound } else { outbound };
        s.connected = true;
        s.disconnected_at = None;
        s.decay(now);
    }

    fn forget_one_disconnected(&mut self) {
        let victim = self
            .peers
            .iter()
            .filter(|(_, s)| !s.connected)
            .min_by_key(|(p, s)| (s.disconnected_at, p.to_bytes()))
            .map(|(p, _)| *p);
        if let Some(v) = victim {
            self.peers.remove(&v);
        }
    }

    /// The last connection to `peer` closed: it stops being a candidate. Its
    /// state is kept (bounded by [`MAX_TRACKED_PULL_PEERS`]).
    #[allow(dead_code)] // library API and tests; the node binary compiles this module too
    pub fn on_disconnect(&mut self, peer: &PeerId) {
        self.on_disconnect_at(peer, std::time::Instant::now());
    }

    /// [`Self::on_disconnect`] with an explicit clock.
    pub fn on_disconnect_at(&mut self, peer: &PeerId, now: std::time::Instant) {
        if let Some(s) = self.peers.get_mut(peer) {
            s.connected = false;
            s.outbound = false;
            s.in_flight = 0;
            s.disconnected_at = Some(now);
        }
    }

    /// Pick the peer for the next pull, skipping `exclude` (peers that already
    /// answered or failed this particular request). `None` = no eligible peer
    /// right now (none connected, all saturated, or all cooling down).
    #[allow(dead_code)] // library API and tests; the node binary compiles this module too
    pub fn select(&self, now: std::time::Instant, exclude: &[PeerId]) -> Option<PeerId> {
        self.select_for(now, exclude, &[])
    }

    /// [`Self::select`] preferring the peers in `prefer` (the peers that
    /// announced what is pulled). `None` also when the best eligible peer is
    /// a poor one ([`POOR_PEER_PENALTY`]) while a better connected peer that
    /// is not excluded is only busy or cooling down: the pull waits for it.
    pub fn select_for(&self, now: std::time::Instant, exclude: &[PeerId], prefer: &[PeerId]) -> Option<PeerId> {
        let key = |p: &PeerId, s: &PullPeer| {
            let penalty = s.penalty_at(now);
            (
                penalty >= POOR_PEER_PENALTY,
                !prefer.contains(p),
                penalty_rank(penalty),
                s.in_flight,
                s.last_selected,
                !self.explicit.contains(p),
            )
        };
        let (best, poor) = self
            .peers
            .iter()
            .filter(|(p, s)| s.eligible(now) && !exclude.contains(p))
            .min_by(|(pa, a), (pb, b)| key(pa, a).cmp(&key(pb, b)).then_with(|| pa.to_bytes().cmp(&pb.to_bytes())))
            .map(|(p, s)| (*p, s.penalty_at(now) >= POOR_PEER_PENALTY))?;
        if poor
            && self
                .peers
                .iter()
                .any(|(p, s)| s.connected && !exclude.contains(p) && s.penalty_at(now) < POOR_PEER_PENALTY)
        {
            return None;
        }
        Some(best)
    }

    /// Whether any connected peer could take a pull now (cheap early exit).
    pub fn any_eligible(&self, now: std::time::Instant) -> bool {
        self.peers.values().any(|s| s.eligible(now))
    }

    /// Whether some connected peer is not in `tried` (a pull that has asked
    /// every connected peer can only wait for a new one).
    pub fn has_untried(&self, tried: &[PeerId]) -> bool {
        self.peers.iter().any(|(p, s)| s.connected && !tried.contains(p))
    }

    /// A request was sent to `peer`.
    pub fn on_sent(&mut self, peer: PeerId, now: std::time::Instant) {
        let s = self.peers.entry(peer).or_default();
        s.in_flight = s.in_flight.saturating_add(1);
        s.last_selected = Some(now);
    }

    /// `peer` answered usefully (the block, the asked-for headers / tips /
    /// peers).
    pub fn on_success(&mut self, peer: &PeerId) {
        if let Some(s) = self.peers.get_mut(peer) {
            s.in_flight = s.in_flight.saturating_sub(1);
        }
    }

    /// B1-T6: `peer` answered, but uselessly (NotFound; an empty answer from
    /// a peer that claimed more): ranks it down by `weight`. Never a
    /// cooldown: honest peers answer NotFound for blocks they pruned or never
    /// had, and an attacker can make them do so for blocks that do not
    /// exist.
    pub fn on_useless(&mut self, peer: &PeerId, now: std::time::Instant, weight: f64) {
        if let Some(s) = self.peers.get_mut(peer) {
            s.in_flight = s.in_flight.saturating_sub(1);
            s.decay(now);
            s.useless += weight;
        }
    }

    /// Take back a useless-answer charge: the NotFound was true (the pull was
    /// dropped because no peer had the block).
    pub fn refund_useless(&mut self, peer: &PeerId, now: std::time::Instant, weight: f64) {
        if let Some(s) = self.peers.get_mut(peer) {
            s.decay(now);
            s.useless = (s.useless - weight).max(0.0);
        }
    }

    /// `peer` answered `Busy`: back off briefly, no failure recorded.
    pub fn on_busy(&mut self, peer: &PeerId, now: std::time::Instant) {
        if let Some(s) = self.peers.get_mut(peer) {
            s.in_flight = s.in_flight.saturating_sub(1);
            let until = now + BUSY_COOLDOWN;
            s.cooldown_until = Some(s.cooldown_until.map_or(until, |t| t.max(until)));
        }
    }

    /// The request to `peer` failed (timeout, reset, undecodable answer).
    /// A stall score of [`STALL_FAILURES`] (decaying) puts the peer on
    /// cooldown ([`STALL_COOLDOWN`], doubling for repeat offenders).
    pub fn on_failure(&mut self, peer: &PeerId, now: std::time::Instant) {
        if let Some(s) = self.peers.get_mut(peer) {
            s.in_flight = s.in_flight.saturating_sub(1);
            s.decay(now);
            s.stall += 1.0;
            if s.stall >= f64::from(STALL_FAILURES) - 1e-9 {
                s.stall = 0.0;
                s.cool_down(now);
            }
        }
    }

    /// The request to `peer` ended without a verdict on the peer (its
    /// connection closed): frees the slot only.
    pub fn on_closed(&mut self, peer: &PeerId) {
        if let Some(s) = self.peers.get_mut(peer) {
            s.in_flight = s.in_flight.saturating_sub(1);
        }
    }

    /// `peer` broke the protocol (a wrong answer, a malformed frame): an
    /// immediate stall cooldown, escalating like a stall's.
    pub fn on_misbehaving(&mut self, peer: &PeerId, now: std::time::Instant) {
        if let Some(s) = self.peers.get_mut(peer) {
            s.decay(now);
            s.stall += 1.0;
            s.cool_down(now);
        }
    }

    /// Requests currently outstanding to `peer`.
    #[allow(dead_code)] // library API and tests; the node binary compiles this module too
    pub fn in_flight(&self, peer: &PeerId) -> u32 {
        self.peers.get(peer).map(|s| s.in_flight).unwrap_or(0)
    }

    /// True while `peer` is on a stall/Busy cooldown.
    #[allow(dead_code)] // library API and tests; the node binary compiles this module too
    pub fn is_cooling_down(&self, peer: &PeerId, now: std::time::Instant) -> bool {
        self.peers.get(peer).and_then(|s| s.cooldown_until).is_some_and(|t| now < t)
    }

    /// True while `peer` is connected through a connection we dialed.
    pub fn is_outbound(&self, peer: &PeerId) -> bool {
        self.peers.get(peer).is_some_and(|s| s.connected && s.outbound)
    }

    /// The peer's current penalty (useless answers + 2 x stall score).
    #[allow(dead_code)] // library API and tests; the node binary compiles this module too
    pub fn penalty(&self, peer: &PeerId, now: std::time::Instant) -> f64 {
        self.peers.get(peer).map_or(0.0, |s| s.penalty_at(now))
    }

    /// Number of candidate (connected) peers.
    #[allow(dead_code)] // library API and tests; the node binary compiles this module too
    pub fn len(&self) -> usize {
        self.peers.values().filter(|s| s.connected).count()
    }

    #[allow(dead_code)] // library API and tests; the node binary compiles this module too
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Peers whose state is remembered (connected or not).
    #[allow(dead_code)] // library API and tests; the node binary compiles this module too
    pub fn tracked(&self) -> usize {
        self.peers.len()
    }
}

// ── Archival advertisement over the identify handshake (wire-safe) ───────────

/// The identify agent-version string this node advertises. We do NOT add a
/// field to the gossip `Version` frame (that would change the bincode wire
/// layout and break the mixed old/new fleet); instead archival is carried in
/// the standard libp2p identify agent-version string — a plain, self-describing
/// field that old binaries simply don't parse.
///
/// Format: `bloch/<pkg-version>/a` (archival) or `bloch/<pkg-version>/n`.
pub fn agent_version(archive: bool) -> String {
    format!(
        "gnb/{}/{}",
        env!("CARGO_PKG_VERSION"),
        if archive { "a" } else { "n" }
    )
}

/// Parse the archival bit out of a peer's identify agent-version. Returns
/// `None` for peers that don't speak our scheme (old binaries / other agents),
/// so peer-selection treats their archival status as unknown.
pub fn parse_archival_agent(agent_version: &str) -> Option<bool> {
    if !agent_version.starts_with("gnb/") {
        return None;
    }
    match agent_version.rsplit('/').next() {
        Some("a") => Some(true),
        Some("n") => Some(false),
        _ => None,
    }
}

/// Extract PeerIds from `--peer` multiaddrs (the trailing `/p2p/<id>`), used to
/// recognise explicitly-configured peers in `select_pull_peer`.
pub fn explicit_peer_ids(multiaddrs: &[String]) -> HashSet<PeerId> {
    multiaddrs
        .iter()
        .filter_map(|s| {
            s.rsplit("/p2p/")
                .next()
                .filter(|tail| *tail != s.as_str()) // require an actual /p2p/ segment
                .and_then(|id| id.parse::<PeerId>().ok())
        })
        .collect()
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_requests() -> Vec<SyncRequest> {
        vec![
            SyncRequest::GetBlock { block_hash: [7u8; 32] },
            SyncRequest::GetHeaders { from_blue_score: 42, limit: 500 },
            SyncRequest::GetTips,
            SyncRequest::GetPeers,
        ]
    }

    fn sample_responses() -> Vec<SyncResponse> {
        vec![
            SyncResponse::Block {
                block_hash: [9u8; 32],
                blue_score: 123,
                height: 45,
                block_data: vec![1, 2, 3, 4, 5],
            },
            SyncResponse::BlockNotFound { block_hash: [3u8; 32] },
            SyncResponse::Headers {
                entries: vec![
                    SyncEntry { hash: [1u8; 32], blue_score: 1, height: 1 },
                    SyncEntry { hash: [2u8; 32], blue_score: 2, height: 2 },
                ],
            },
            SyncResponse::Tips {
                tips: vec![SyncEntry { hash: [4u8; 32], blue_score: 9, height: 9 }],
                locator: vec![[5u8; 32], [6u8; 32]],
            },
            SyncResponse::Peers {
                peers: vec!["/ip4/1.2.3.4/tcp/17110/p2p/x".to_string()],
            },
            SyncResponse::Busy,
        ]
    }

    /// Only Busy and BlockNotFound send a pull to another peer; every other
    /// answer completes it (a BlockNotFound that completed the pull left a
    /// healing partition waiting for the 30-60 s sweeps). The swarm loop's
    /// use of it is tested in network/mod.rs (`on_pull_response`).
    #[test]
    fn not_found_and_busy_retry_on_another_peer() {
        // sample_responses(): Block, BlockNotFound, Headers, Tips, Peers, Busy.
        let expected = [false, true, false, false, false, true];
        let responses = sample_responses();
        assert_eq!(responses.len(), expected.len());
        for (resp, want) in responses.iter().zip(expected) {
            assert_eq!(retry_pull_elsewhere(resp), want, "{resp:?}");
        }
        assert!(!retry_pull_elsewhere(&SyncResponse::Tips { tips: vec![], locator: vec![] }));
        assert!(!retry_pull_elsewhere(&SyncResponse::Headers { entries: vec![] }));
    }

    // 1. Pure bincode frame round-trip for every request/response variant.
    #[test]
    fn frame_roundtrip() {
        for req in sample_requests() {
            let bytes = encode_frame(&req).unwrap();
            let back: SyncRequest = decode_frame(&bytes).unwrap();
            assert_eq!(req, back, "request frame round-trip");
        }
        for resp in sample_responses() {
            let bytes = encode_frame(&resp).unwrap();
            let back: SyncResponse = decode_frame(&bytes).unwrap();
            assert_eq!(resp, back, "response frame round-trip");
        }
    }

    // 2. Exercise the ACTUAL async Codec methods (write_* then read_* over an
    //    in-memory stream), proving the /bloch/sync/1 wire encode/decode works.
    #[test]
    fn codec_async_roundtrip() {
        use futures::executor::block_on;
        use futures::io::Cursor;

        block_on(async {
            let mut codec = BlochSyncCodec;
            for req in sample_requests() {
                let mut out = Cursor::new(Vec::new());
                codec
                    .write_request(&SYNC_PROTOCOL, &mut out, req.clone())
                    .await
                    .unwrap();
                let mut input = Cursor::new(out.into_inner());
                let back = codec.read_request(&SYNC_PROTOCOL, &mut input).await.unwrap();
                assert_eq!(req, back, "async request round-trip");
            }
            for resp in sample_responses() {
                let mut out = Cursor::new(Vec::new());
                codec
                    .write_response(&SYNC_PROTOCOL, &mut out, resp.clone())
                    .await
                    .unwrap();
                let mut input = Cursor::new(out.into_inner());
                let back = codec.read_response(&SYNC_PROTOCOL, &mut input).await.unwrap();
                assert_eq!(resp, back, "async response round-trip");
            }
        });
    }

    // 3. THE core assertion: IBD fetches route as directed pulls, never gossip.
    #[test]
    fn pull_variants_never_gossip_others_do() {
        // PULL variants -> directed request-response (Some).
        assert!(as_pull_request(&NetworkMessage::GetBlock { block_hash: [0u8; 32], nonce: 1 }).is_some());
        assert!(as_pull_request(&NetworkMessage::GetHeaders { from_blue_score: 0, limit: 500, nonce: 1 }).is_some());
        assert!(as_pull_request(&NetworkMessage::GetTips).is_some());
        // M-10: PeerRequest joined the directed pull side — no more
        // broadcasting "please tell me your peers" to the whole mesh.
        assert_eq!(as_pull_request(&NetworkMessage::PeerRequest), Some(SyncRequest::GetPeers));

        // Announce / response / block / tx -> stay on gossip (None).
        assert!(as_pull_request(&NetworkMessage::PeerTip { peer_id: "p".into(), blue_score: 1, height: 1 }).is_none());
        assert!(as_pull_request(&NetworkMessage::Version {
            version: 1, user_agent: "x".into(), blue_score: 1, height: 1, timestamp: 0,
        }).is_none());
        assert!(as_pull_request(&NetworkMessage::NewBlock {
            block_hash: [0u8; 32], blue_score: 0, height: 0, block_data: vec![],
        }).is_none());
        assert!(as_pull_request(&NetworkMessage::NewTransaction { txid: [0u8; 32], tx_data: vec![] }).is_none());
        assert!(as_pull_request(&NetworkMessage::Headers { entries: vec![] }).is_none());
        assert!(as_pull_request(&NetworkMessage::Tips { tips: vec![], locator: vec![] }).is_none());
        assert!(as_pull_request(&NetworkMessage::BlockNotFound { block_hash: [0u8; 32], nonce: 1 }).is_none());
        // PeerExchange (the ANSWER) stays off the directed-request path — it
        // only ever travels as a SyncResponse::Peers, never as a SyncRequest.
        assert!(as_pull_request(&NetworkMessage::PeerExchange { peers: vec![] }).is_none());
    }

    // 4. Peer selection: explicit --peer > highest blue_score. NET-9 (audit):
    //    this test used to assert that a self-declared ARCHIVAL peer wins over
    //    everyone — exactly the capture primitive the audit reported. It now
    //    pins the fixed behaviour: the self-declared bit is ignored.
    #[test]
    fn peer_selection_ignores_self_declared_archival() {
        let archival = PeerId::random();
        let explicit_peer = PeerId::random();
        let high_score = PeerId::random();

        let mut peers = HashMap::new();
        peers.insert(archival, PeerSync { blue_score: 10, archival: Some(true) });
        peers.insert(explicit_peer, PeerSync { blue_score: 20, archival: Some(false) });
        peers.insert(high_score, PeerSync { blue_score: 99, archival: None });

        let mut explicit = HashSet::new();
        explicit.insert(explicit_peer);

        assert_eq!(select_pull_peer(&peers, &explicit), Some(explicit_peer),
            "a self-declared archival peer must NOT win over the explicit --peer");
        assert_eq!(select_pull_peer(&peers, &HashSet::new()), Some(high_score),
            "nor over the highest-score peer when no explicit peer is configured");
    }

    #[test]
    fn peer_selection_falls_back_to_explicit_then_score() {
        let explicit_peer = PeerId::random();
        let high_score = PeerId::random();
        let low_score = PeerId::random();

        // No archival peer known -> explicit --peer wins next.
        let mut peers = HashMap::new();
        peers.insert(explicit_peer, PeerSync { blue_score: 5, archival: Some(false) });
        peers.insert(high_score, PeerSync { blue_score: 99, archival: None });
        peers.insert(low_score, PeerSync { blue_score: 1, archival: None });
        let mut explicit = HashSet::new();
        explicit.insert(explicit_peer);
        assert_eq!(select_pull_peer(&peers, &explicit), Some(explicit_peer),
            "with no archival peer, the explicit --peer is chosen");

        // No archival, no explicit -> highest blue_score.
        let empty = HashSet::new();
        assert_eq!(select_pull_peer(&peers, &empty), Some(high_score),
            "with neither archival nor explicit, the highest blue_score peer is chosen");
    }

    #[test]
    fn peer_selection_empty_is_none() {
        let peers: HashMap<PeerId, PeerSync> = HashMap::new();
        assert_eq!(select_pull_peer(&peers, &HashSet::new()), None);
    }

    // 5. Archival advertisement over the identify agent-version.
    #[test]
    fn archival_agent_roundtrip() {
        assert_eq!(parse_archival_agent(&agent_version(true)), Some(true));
        assert_eq!(parse_archival_agent(&agent_version(false)), Some(false));
        // old binary / other agent -> unknown.
        assert_eq!(parse_archival_agent("rust-libp2p/0.56.0"), None);
        assert_eq!(parse_archival_agent(""), None);
    }

    #[test]
    fn explicit_peer_id_parsing() {
        let id = PeerId::random();
        let with = format!("/ip4/1.2.3.4/tcp/17110/p2p/{}", id);
        let without = "/ip4/1.2.3.4/tcp/17110".to_string();
        let set = explicit_peer_ids(&[with, without]);
        assert!(set.contains(&id));
        assert_eq!(set.len(), 1, "only the addr carrying /p2p/<id> yields a PeerId");
    }

    #[test]
    fn response_maps_to_ingest_message() {
        // A directed Block answer must ingest exactly like a gossip NewBlock.
        let m = response_to_message(SyncResponse::Block {
            block_hash: [1u8; 32], blue_score: 7, height: 3, block_data: vec![9, 9],
        }).expect("Block maps to NewBlock");
        match m {
            NetworkMessage::NewBlock { block_hash, blue_score, height, block_data } => {
                assert_eq!(block_hash, [1u8; 32]);
                assert_eq!((blue_score, height), (7, 3));
                assert_eq!(block_data, vec![9, 9]);
            }
            other => panic!("expected NewBlock, got {:?}", other.kind_name()),
        }
    }

    /// M-10: a directed `Peers` answer must ingest exactly like a gossip
    /// `PeerExchange` — same rate limit, batch cap, address validation,
    /// dial-before-persist discipline, just a different transport.
    #[test]
    fn peers_response_maps_to_peer_exchange_ingest_message() {
        let m = response_to_message(SyncResponse::Peers { peers: vec!["/ip4/9.9.9.9/tcp/1".to_string()] })
            .expect("Peers maps to PeerExchange");
        match m {
            NetworkMessage::PeerExchange { peers } => {
                assert_eq!(peers, vec!["/ip4/9.9.9.9/tcp/1".to_string()]);
            }
            other => panic!("expected PeerExchange, got {:?}", other.kind_name()),
        }
    }

    // ── H-R3-4 regressions ──────────────────────────────────────────────────

    /// A genuine length-bomb frame: bincode-encode a `SyncResponse::Headers`
    /// whose length PREFIX declares far more `SyncEntry` items than the frame
    /// actually carries (truncate the real encoding down to a handful of
    /// bytes after the length prefix). Before the fix,
    /// `bincode::config::standard()` (no limit) would walk `claim_container_read`
    /// as a no-op and attempt to satisfy the declared length against a starved
    /// buffer; with the read limit configured, this must fail fast as a
    /// bounds/limit violation rather than attempt to allocate or read past
    /// what the frame contains.
    #[test]
    fn length_bomb_frame_is_rejected_not_decoded() {
        // A real encoding of a big-but-legal Headers response, so the length
        // prefix is authentic bincode varint output for a large count.
        let huge: Vec<SyncEntry> = (0..100_000u32)
            .map(|i| SyncEntry { hash: [0u8; 32], blue_score: i as u64, height: i as u64 })
            .collect();
        let full = encode_frame(&SyncResponse::Headers { entries: huge }).unwrap();
        assert!(full.len() > 1_000_000, "test premise: the full encoding is large");

        // Truncate to just past the enum discriminant + length prefix: the
        // declared entry count is still ~100,000, but almost none of the
        // per-entry bytes are present. This is exactly the "declared length
        // vastly exceeds actual bytes" shape of a length bomb.
        let bomb = &full[..full.len().min(32)];
        let err = decode_response(bomb).expect_err("a starved/truncated declared-length frame must be rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(is_sync_protocol_violation(&err));
    }

    /// Trailing bytes after a fully-decoded frame must be rejected, not
    /// silently ignored. Before the fix, `decode_from_slice`'s second return
    /// value (`bytes_read`) was discarded, so a valid small message padded
    /// with arbitrary trailing bytes decoded successfully.
    #[test]
    fn trailing_bytes_after_valid_frame_are_rejected() {
        let req = SyncRequest::GetTips;
        let mut bytes = encode_frame(&req).unwrap();
        let clean_len = bytes.len();
        bytes.extend_from_slice(&[0xAAu8; 16]); // pad with trailing garbage

        // The generic decode_frame must reject the padded buffer...
        let err = decode_frame::<SyncRequest>(&bytes).expect_err("trailing bytes must be rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(is_sync_protocol_violation(&err));

        // ...while the unpadded buffer decodes cleanly, proving the
        // rejection is specifically about the trailing bytes.
        let clean: SyncRequest = decode_frame(&bytes[..clean_len]).unwrap();
        assert_eq!(clean, req);
    }

    /// The directed protocol has the gossip path's one-encoding rule: a
    /// non-minimal varint, or a length of 2^32 + 3 (which bincode truncates
    /// to 3 on 32-bit targets, where the frame then decoded as a 3-byte
    /// `block_data`), is refused as a protocol violation on every target.
    #[test]
    fn non_canonical_frames_are_rejected() {
        let resp = SyncResponse::Block {
            block_hash: [0u8; 32],
            blue_score: 5,
            height: 9,
            block_data: vec![7u8; 3],
        };
        let enc = encode_frame(&resp).unwrap();
        assert_eq!(decode_response(&enc).unwrap(), resp);
        assert!(enc.ends_with(&[3, 7, 7, 7]), "bincode encoding layout changed; update this test");
        let head = &enc[..enc.len() - 4];
        let with_len = |len: &[u8]| -> Vec<u8> {
            let mut f = head.to_vec();
            f.extend_from_slice(len);
            f.extend_from_slice(&[7, 7, 7]);
            f
        };
        let mut frames = vec![
            with_len(&[0xFB, 3, 0]),
            with_len(&[0xFD, 3, 0, 0, 0, 0, 0, 0, 0]),
            with_len(&[0xFD, 3, 0, 0, 0, 1, 0, 0, 0]), // 2^32 + 3
        ];
        let mut tag = vec![0xFB, enc[0], 0];
        tag.extend_from_slice(&enc[1..]);
        frames.push(tag);
        for frame in &frames {
            let err = decode_response(frame).expect_err("non-canonical frame must be rejected");
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert!(is_sync_protocol_violation(&err));
        }
    }

    /// GetHeaders.limit above MAX_WIRE_GETHEADERS_LIMIT must be rejected by
    /// decode_request — mirrors the gossip path's validate_wire_bounds for
    /// the same logical field, closing the gap the directed protocol left
    /// open (a peer could ask for far more than 2000 headers per pull).
    #[test]
    fn oversized_getheaders_limit_is_rejected() {
        let req = SyncRequest::GetHeaders { from_blue_score: 0, limit: MAX_WIRE_GETHEADERS_LIMIT + 1 };
        let bytes = encode_frame(&req).unwrap();
        let err = decode_request(&bytes).expect_err("limit above MAX_WIRE_GETHEADERS_LIMIT must be rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(is_sync_protocol_violation(&err));

        // At-the-cap is accepted.
        let ok_req = SyncRequest::GetHeaders { from_blue_score: 0, limit: MAX_WIRE_GETHEADERS_LIMIT };
        let ok_bytes = encode_frame(&ok_req).unwrap();
        assert_eq!(decode_request(&ok_bytes).unwrap(), ok_req);
    }

    /// A `Headers` response carrying more entries than MAX_WIRE_SYNC_ENTRIES
    /// must be rejected by decode_response — the scenario the annex names
    /// directly: a malicious peer answering our GetHeaders with ~123,000
    /// SyncEntry items instead of the 2000-entry cap the gossip path
    /// enforces.
    #[test]
    fn oversized_headers_response_rejected() {
        let entries: Vec<SyncEntry> = (0..(MAX_WIRE_SYNC_ENTRIES + 1))
            .map(|i| SyncEntry { hash: [0u8; 32], blue_score: i as u64, height: i as u64 })
            .collect();
        let resp = SyncResponse::Headers { entries };
        let bytes = encode_frame(&resp).unwrap();
        let err = decode_response(&bytes).expect_err("entries beyond MAX_WIRE_SYNC_ENTRIES must be rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(is_sync_protocol_violation(&err));
    }

    /// A `Tips` response carrying more tips or locator hashes than the wire
    /// caps must be rejected.
    #[test]
    fn oversized_tips_response_rejected() {
        let too_many_tips = SyncResponse::Tips {
            tips: (0..(MAX_WIRE_TIPS + 1))
                .map(|i| SyncEntry { hash: [0u8; 32], blue_score: i as u64, height: i as u64 })
                .collect(),
            locator: vec![],
        };
        let bytes = encode_frame(&too_many_tips).unwrap();
        assert!(decode_response(&bytes).is_err());

        let too_long_locator = SyncResponse::Tips {
            tips: vec![],
            locator: (0..(MAX_WIRE_LOCATOR + 1)).map(|i| {
                let mut h = [0u8; 32];
                h[0] = (i % 256) as u8;
                h
            }).collect(),
        };
        let bytes2 = encode_frame(&too_long_locator).unwrap();
        assert!(decode_response(&bytes2).is_err());
    }

    /// M-10: a `Peers` response is bounded exactly like the gossip
    /// `PeerExchange`/`PeerCount` fields it now shares a transport with —
    /// too many entries, or one entry too long, must be rejected.
    #[test]
    fn oversized_peers_response_rejected() {
        let too_many = SyncResponse::Peers {
            peers: (0..(MAX_WIRE_ADDRS + 1)).map(|i| format!("/ip4/1.2.3.{}/tcp/1", i % 256)).collect(),
        };
        let bytes = encode_frame(&too_many).unwrap();
        assert!(decode_response(&bytes).is_err());

        let too_long_addr = SyncResponse::Peers {
            peers: vec!["x".repeat(MAX_WIRE_ADDR_LEN + 1)],
        };
        let bytes2 = encode_frame(&too_long_addr).unwrap();
        assert!(decode_response(&bytes2).is_err());

        // A well-formed sample must still decode cleanly.
        let ok = SyncResponse::Peers { peers: vec!["/ip4/1.2.3.4/tcp/17110/p2p/x".to_string()] };
        let ok_bytes = encode_frame(&ok).unwrap();
        assert_eq!(decode_response(&ok_bytes).unwrap(), ok);
    }

    /// `GetPeers` carries no fields to bound — it must always decode cleanly
    /// (a mutation guard: if a field is ever added here, this test should be
    /// revisited alongside a matching bounds check).
    #[test]
    fn get_peers_request_roundtrips() {
        let bytes = encode_frame(&SyncRequest::GetPeers).unwrap();
        assert_eq!(decode_request(&bytes).unwrap(), SyncRequest::GetPeers);
    }

    /// Ordinary transport failures (not protocol violations) must NOT be
    /// classified as a violation — penalizing a peer for a connection reset
    /// or timeout would be a correctness bug in the caller's reaction logic.
    #[test]
    fn transport_errors_are_not_protocol_violations() {
        let timeout = io::Error::new(io::ErrorKind::TimedOut, "timed out");
        let reset = io::Error::new(io::ErrorKind::ConnectionReset, "reset");
        assert!(!is_sync_protocol_violation(&timeout));
        assert!(!is_sync_protocol_violation(&reset));
    }

    // ── H-R3-1 fix #4: SyncRequestLimiter ───────────────────────────────────

    /// A peer can burst up to SYNC_BUCKET_CAPACITY requests immediately, then
    /// the (capacity + 1)-th is rejected until tokens refill.
    #[test]
    fn sync_request_limiter_bounds_burst() {
        let mut lim = SyncRequestLimiter::new();
        let peer = PeerId::random();
        for i in 0..SYNC_BUCKET_CAPACITY {
            assert!(lim.allow(peer), "request {} within burst capacity must be allowed", i);
        }
        assert!(!lim.allow(peer), "request beyond burst capacity must be rejected");
    }

    /// Different peers get independent buckets — one peer exhausting its
    /// burst must not affect another.
    #[test]
    fn sync_request_limiter_is_per_peer() {
        let mut lim = SyncRequestLimiter::new();
        let attacker = PeerId::random();
        let honest = PeerId::random();
        for _ in 0..SYNC_BUCKET_CAPACITY {
            assert!(lim.allow(attacker));
        }
        assert!(!lim.allow(attacker), "attacker's bucket must be exhausted");
        assert!(lim.allow(honest), "an unrelated peer's bucket must be untouched");
    }

    /// NET-8 (audit): this test used to assert that, once the tracked-peer
    /// cap was reached, every NEW peer was refused — a permanent lockout of
    /// honest newcomers after 1,024 free identities. It now pins the fixed
    /// behaviour: the map stays bounded (LRU / idle eviction) and a newcomer
    /// is served; the global bucket bounds the aggregate instead.
    #[test]
    fn sync_request_limiter_fails_closed_when_tracking_map_is_full() {
        let mut lim = SyncRequestLimiter::new();
        let t0 = std::time::Instant::now();
        for i in 0..SYNC_LIMITER_TRACK_CAP {
            let p = PeerId::random();
            assert!(lim.allow_at(p, t0 + Duration::from_micros(i as u64)),
                "each distinct peer's first request must be allowed");
        }
        assert_eq!(lim.tracked_peers(), SYNC_LIMITER_TRACK_CAP);
        let newcomer = PeerId::random();
        assert!(
            lim.allow_at(newcomer, t0 + Duration::from_secs(1)),
            "a brand-new honest peer must be served after the map filled (NET-8)"
        );
        assert_eq!(lim.tracked_peers(), SYNC_LIMITER_TRACK_CAP, "map stays bounded");
    }

    // ── Inbound request read cap ────────────────────────────────────────────

    /// An endless request stream: counts the bytes handed out, never EOFs.
    struct EndlessJunk {
        served: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl futures::io::AsyncRead for EndlessJunk {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &mut [u8],
        ) -> std::task::Poll<io::Result<usize>> {
            buf.fill(0xFF);
            self.served.fetch_add(buf.len(), std::sync::atomic::Ordering::Relaxed);
            std::task::Poll::Ready(Ok(buf.len()))
        }
    }

    /// Review follow-up (pre-existing): a request stream is read only up to
    /// MAX_REQUEST_FRAME bytes before it is judged, not up to the 4 MiB block
    /// frame cap — so 256 open streams per connection can no longer pin about
    /// 1 GiB of junk for the request timeout. The oversized request is a
    /// protocol violation. Re-audit B1-T2: the codec used to return it as an
    /// `InvalidData` error, which libp2p-request-response 0.30 never reports
    /// to the behaviour (it only logs a request that fails to decode), so the
    /// penalty never fired; it is now reported as `SyncRequest::Malformed`,
    /// which the network loop attributes to its peer and penalizes.
    #[test]
    fn oversized_request_is_cut_at_the_request_cap_and_is_a_violation() {
        use futures::executor::block_on;
        let served = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut io = EndlessJunk { served: served.clone() };
        let r = block_on(BlochSyncCodec.read_request(&SYNC_PROTOCOL, &mut io)).expect("reported, not an error");
        assert_eq!(r, SyncRequest::Malformed);
        assert!(
            served.load(std::sync::atomic::Ordering::Relaxed) as u64 <= MAX_REQUEST_FRAME,
            "read {} bytes from a request stream",
            served.load(std::sync::atomic::Ordering::Relaxed)
        );

        // A valid request followed by padding up to the cap is refused too.
        let mut padded = encode_frame(&SyncRequest::GetTips).unwrap();
        padded.resize(MAX_REQUEST_FRAME as usize + 10, 0);
        let r = block_on(BlochSyncCodec.read_request(&SYNC_PROTOCOL, &mut futures::io::Cursor::new(padded)))
            .expect("padded request");
        assert_eq!(r, SyncRequest::Malformed);
        // So is an undecodable short frame; a stream closed without a frame
        // stays a transport error (never penalized).
        let r = block_on(BlochSyncCodec.read_request(&SYNC_PROTOCOL, &mut futures::io::Cursor::new(vec![0xFF; 5])));
        assert_eq!(r.unwrap(), SyncRequest::Malformed);
        let e = block_on(BlochSyncCodec.read_request(&SYNC_PROTOCOL, &mut futures::io::Cursor::new(Vec::new())))
            .expect_err("no frame");
        assert!(!is_sync_protocol_violation(&e));
        // `Malformed` never goes on the wire.
        assert!(encode_frame(&SyncRequest::Malformed).is_err());
    }

    /// Every valid request fits well under the request cap, including the
    /// longest encodings bincode varints can produce.
    #[test]
    fn every_valid_request_fits_the_request_cap() {
        let mut reqs = sample_requests();
        reqs.push(SyncRequest::GetBlock { block_hash: [0xFF; 32] });
        reqs.push(SyncRequest::GetHeaders { from_blue_score: u64::MAX, limit: u32::MAX });
        for req in reqs {
            let bytes = encode_frame(&req).unwrap();
            assert!((bytes.len() as u64) < MAX_REQUEST_FRAME, "{req:?} encodes to {} bytes", bytes.len());
            if let SyncRequest::GetBlock { .. } = req {
                assert_eq!(bytes.len(), 33);
            }
            // And it still round-trips through the capped reader.
            let back = futures::executor::block_on(
                BlochSyncCodec.read_request(&SYNC_PROTOCOL, &mut futures::io::Cursor::new(bytes)),
            );
            match req {
                SyncRequest::GetHeaders { limit, .. } if limit > MAX_WIRE_GETHEADERS_LIMIT => {
                    assert_eq!(back.unwrap(), SyncRequest::Malformed, "bounds still apply")
                }
                _ => assert_eq!(back.unwrap(), req),
            }
        }
    }

    /// Responses keep the block-sized cap.
    #[test]
    fn responses_are_not_held_to_the_request_cap() {
        let big = SyncResponse::Block { block_hash: [1; 32], blue_score: 2, height: 3, block_data: vec![7u8; 64 * 1024] };
        let bytes = encode_frame(&big).unwrap();
        let back = futures::executor::block_on(
            BlochSyncCodec.read_response(&SYNC_PROTOCOL, &mut futures::io::Cursor::new(bytes)),
        )
        .unwrap();
        assert_eq!(back, big);
    }

    // ── NET-5 / NET-9 regressions ───────────────────────────────────────────

    /// NET-5: an empty frame (server closed the stream without answering) is a
    /// transport failure, NOT a protocol violation — the requester must never
    /// penalize a server for it.
    #[test]
    fn empty_frame_is_eof_not_protocol_violation() {
        let e = check_nonempty_frame(Vec::new()).expect_err("empty frame is an error");
        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
        assert!(!is_sync_protocol_violation(&e), "clean EOF must not be penalized");
        assert_eq!(check_nonempty_frame(vec![1]).unwrap(), vec![1]);
    }

    /// NET-5: the codec turns a closed-without-answer stream into EOF too.
    #[test]
    fn codec_reads_empty_response_as_eof() {
        use futures::executor::block_on;
        use futures::io::Cursor;
        block_on(async {
            let mut codec = BlochSyncCodec;
            let mut input = Cursor::new(Vec::<u8>::new());
            let e = codec.read_response(&SYNC_PROTOCOL, &mut input).await.expect_err("no frame");
            assert!(!is_sync_protocol_violation(&e));
        });
    }

    /// NET-5: `Busy` is a well-formed answer that the processor never sees.
    #[test]
    fn busy_roundtrips_and_is_not_delivered() {
        let bytes = encode_frame(&SyncResponse::Busy).unwrap();
        assert_eq!(decode_response(&bytes).unwrap(), SyncResponse::Busy);
        assert!(response_to_message(SyncResponse::Busy).is_none());
    }

    /// NET-9: consecutive pulls rotate across connected peers.
    #[test]
    fn selector_rotates_across_peers() {
        let (a, b, c) = (PeerId::random(), PeerId::random(), PeerId::random());
        let mut sel = PullPeerSelector::new(HashSet::new());
        for p in [a, b, c] { sel.on_connect(p); }
        let t0 = std::time::Instant::now();
        let mut picked = Vec::new();
        for i in 0..6u64 {
            let now = t0 + Duration::from_millis(i);
            let p = sel.select(now, &[]).expect("a candidate");
            sel.on_sent(p, now);
            sel.on_success(&p);
            picked.push(p);
        }
        for p in [a, b, c] {
            assert_eq!(picked.iter().filter(|x| **x == p).count(), 2, "every peer gets its turn");
        }
    }

    /// NET-9: a peer that stalls (repeated timeouts) is put on cooldown and
    /// the pulls move to another peer.
    #[test]
    fn selector_cools_down_stalled_peer() {
        let (bad, good) = (PeerId::random(), PeerId::random());
        let mut sel = PullPeerSelector::new(HashSet::new());
        sel.on_connect(bad);
        sel.on_connect(good);
        let t0 = std::time::Instant::now();
        for _ in 0..STALL_FAILURES {
            sel.on_sent(bad, t0);
            sel.on_failure(&bad, t0);
        }
        assert!(sel.is_cooling_down(&bad, t0));
        for i in 0..5u64 {
            let now = t0 + Duration::from_millis(i);
            assert_eq!(sel.select(now, &[]), Some(good));
            sel.on_sent(good, now);
            sel.on_success(&good);
        }
        // After the cooldown the stalled peer is eligible again.
        assert!(!sel.is_cooling_down(&bad, t0 + STALL_COOLDOWN));
    }

    /// NET-5: in-flight requests per peer are capped client-side, and `Busy`
    /// backs off without counting as a failure.
    #[test]
    fn selector_caps_in_flight_and_handles_busy() {
        let p = PeerId::random();
        let mut sel = PullPeerSelector::new(HashSet::new());
        sel.on_connect(p);
        let t0 = std::time::Instant::now();
        for _ in 0..MAX_INFLIGHT_PER_PEER {
            assert_eq!(sel.select(t0, &[]), Some(p));
            sel.on_sent(p, t0);
        }
        assert_eq!(sel.select(t0, &[]), None, "per-peer in-flight cap reached");
        sel.on_busy(&p, t0);
        assert!(sel.is_cooling_down(&p, t0));
        assert_eq!(sel.select(t0 + BUSY_COOLDOWN, &[]), Some(p), "Busy is a short back-off");
        assert_eq!(sel.select(t0 + BUSY_COOLDOWN, &[p]), None, "exclusion is honoured");
        sel.on_disconnect(&p);
        assert!(sel.is_empty());
    }

    // ── Phase 4, package R2a ────────────────────────────────────────────────

    /// The send-buffer accounting (B1-T18 / B2-T6) charges exactly what the
    /// codec writes: `response_wire_len` equals the encoded length for every
    /// variant and every varint width.
    #[test]
    fn response_wire_len_is_the_encoded_length() {
        let mut cases = sample_responses();
        for v in [0u64, 250, 251, 0xFFFF, 0x1_0000, 0xFFFF_FFFF, 0x1_0000_0000, u64::MAX] {
            cases.push(SyncResponse::Block { block_hash: [1; 32], blue_score: v, height: v, block_data: vec![3; (v % 70_000) as usize] });
            cases.push(SyncResponse::Headers { entries: vec![SyncEntry { hash: [2; 32], blue_score: v, height: v }; 3] });
            cases.push(SyncResponse::Tips { tips: vec![SyncEntry { hash: [2; 32], blue_score: v, height: 1 }], locator: vec![[4; 32]; 2] });
        }
        cases.push(SyncResponse::Peers { peers: vec!["x".repeat(300), String::new(), "/ip4/1.2.3.4/tcp/1".into()] });
        cases.push(SyncResponse::Headers { entries: vec![SyncEntry { hash: [9; 32], blue_score: 1, height: 1 }; 300] });
        for r in &cases {
            assert_eq!(response_wire_len(r), encode_frame(r).unwrap().len(), "{r:?}");
        }
    }

    /// B2-T7: releases before this one answered GetTips with EVERY DAG tip, so
    /// an honest server with more than MAX_WIRE_TIPS tips sends a Tips frame
    /// over the wire bound. It is still refused (the bound holds), but it is
    /// not a protocol violation: only answers an honest node cannot produce
    /// are penalized.
    #[test]
    fn oversized_tips_answer_is_refused_without_penalty() {
        let resp = SyncResponse::Tips {
            tips: (0..(MAX_WIRE_TIPS + 1)).map(|i| SyncEntry { hash: [i as u8; 32], blue_score: i as u64, height: 1 }).collect(),
            locator: vec![],
        };
        let e = decode_response(&encode_frame(&resp).unwrap()).expect_err("over the wire bound");
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        assert!(!is_sync_protocol_violation(&e), "an honest older server's answer must not be penalized");
        // Every other bound is still a violation.
        let headers = SyncResponse::Headers {
            entries: (0..(MAX_WIRE_SYNC_ENTRIES + 1)).map(|i| SyncEntry { hash: [0; 32], blue_score: i as u64, height: 0 }).collect(),
        };
        assert!(is_sync_protocol_violation(&decode_response(&encode_frame(&headers).unwrap()).unwrap_err()));
        let locator = SyncResponse::Tips { tips: vec![], locator: vec![[0; 32]; MAX_WIRE_LOCATOR + 1] };
        assert!(is_sync_protocol_violation(&decode_response(&encode_frame(&locator).unwrap()).unwrap_err()));
    }

    /// B1-T3 / B2-T5: GetTips and GetHeaders have their own per-peer budgets,
    /// much lower than GetBlock's, and exhausting them does not touch the
    /// GetBlock budget.
    #[test]
    fn tips_and_headers_requests_have_their_own_lower_budgets() {
        let mut lim = SyncRequestLimiter::new();
        let p = PeerId::random();
        let t0 = std::time::Instant::now();
        let tips = (0..SYNC_BUCKET_CAPACITY).filter(|_| lim.allow_request(p, &SyncRequest::GetTips, t0)).count();
        assert!(tips >= 2 && tips < SYNC_BUCKET_CAPACITY as usize / 4, "GetTips burst {tips}");
        let get_headers = SyncRequest::GetHeaders { from_blue_score: 0, limit: 500 };
        let headers = (0..SYNC_BUCKET_CAPACITY).filter(|_| lim.allow_request(p, &get_headers, t0)).count();
        assert!(headers >= 4 && headers < SYNC_BUCKET_CAPACITY as usize / 2, "GetHeaders burst {headers}");
        let blocks = (0..SYNC_BUCKET_CAPACITY)
            .filter(|_| lim.allow_request(p, &SyncRequest::GetBlock { block_hash: [0; 32] }, t0))
            .count();
        assert_eq!(blocks, SYNC_BUCKET_CAPACITY as usize, "the GetBlock budget is separate");
    }

    /// A writer that never accepts a byte: a peer that never reads.
    struct NeverDrains;

    impl futures::io::AsyncWrite for NeverDrains {
        fn poll_write(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>, _: &[u8]) -> std::task::Poll<io::Result<usize>> {
            std::task::Poll::Pending
        }
        fn poll_flush(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Pending
        }
        fn poll_close(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Pending
        }
    }

    /// B1-T18 / B2-T6: a response to a peer that never reads is given up after
    /// RESPONSE_WRITE_TIMEOUT (shorter than the 30 s stream timeout), which
    /// frees it and its send-budget charge sooner.
    #[tokio::test(start_paused = true)]
    async fn response_write_gives_up_on_a_peer_that_never_reads() {
        assert!(RESPONSE_WRITE_TIMEOUT < Duration::from_secs(30));
        let resp = SyncResponse::Block { block_hash: [1; 32], blue_score: 1, height: 1, block_data: vec![0; 1 << 20] };
        let started = tokio::time::Instant::now();
        let r = tokio::time::timeout(
            RESPONSE_WRITE_TIMEOUT * 2,
            BlochSyncCodec.write_response(&SYNC_PROTOCOL, &mut NeverDrains, resp),
        )
        .await
        .expect("the codec must give up on its own");
        assert_eq!(r.expect_err("never written").kind(), io::ErrorKind::TimedOut);
        assert_eq!(started.elapsed(), RESPONSE_WRITE_TIMEOUT);
    }

    /// A Block response is written as exactly the bytes `encode_frame` gives,
    /// for every length-prefix width (it is streamed: no second copy).
    #[test]
    fn block_response_is_written_as_its_exact_frame() {
        for len in [0usize, 1, 250, 251, 0xFFFF, 0x1_0000, 300_000] {
            let resp = SyncResponse::Block { block_hash: [7; 32], blue_score: 300, height: 70_000, block_data: (0..len).map(|i| i as u8).collect() };
            let mut out = futures::io::Cursor::new(Vec::new());
            futures::executor::block_on(BlochSyncCodec.write_response(&SYNC_PROTOCOL, &mut out, resp.clone())).unwrap();
            assert_eq!(out.into_inner(), encode_frame(&resp).unwrap(), "len {len}");
        }
    }
}
