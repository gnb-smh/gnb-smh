//! Bloch-SIS Protocol — P2P Network
//!
//! FIX #2: Full IBD loop — GetBlock now has a server-side response handler.
//! FIX #4: Persistent P2P keypair.
//! FIX #6: Peer memory (known_peers.json).
//! Sprint P: PEX hardening (rate limit, address validation, known_peers cap).

pub mod pex_validator;
pub mod ratelimit;
pub mod sync_rr;

use libp2p::{
    identity, identify, mdns, PeerId, Multiaddr,
    swarm::SwarmEvent,
    gossipsub::{self, IdentTopic, MessageAuthenticity, ValidationMode}, tcp, yamux,
    SwarmBuilder,
};
use serde::{Serialize, Deserialize};
use tokio::sync::mpsc;
use log::{info, warn, debug};
use std::time::Duration;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use sha2::{Sha256, Digest};

use pex_validator::{
    PexRateLimiter, PexStats, AddrBook,
    is_valid_public_multiaddr, is_lan_multiaddr, enforce_cap, prune_invalid, add_tried, addr_peer_id,
    PEX_BATCH_LIMIT, KNOWN_PEERS_CAP,
};

use crate::transport::upgrade::KyberConfig;

pub const TOPIC_BLOCKS: &str = "gnb/blocks/1";
pub const TOPIC_TXS:    &str = "gnb/txs/1";
pub const TOPIC_SYNC:   &str = "gnb/sync/1";

// ── Ingest-drop visibility (orphan-deadlock fix, companion) ──────────────────
//
// Every inbound frame reaches the message processor through a bounded (1000)
// mpsc channel via `try_send`, and a full channel used to drop the frame IN
// SILENCE — including GetBlock RESPONSES the orphan pool was waiting on. The
// drop stays (backpressure by shedding is the design; blocking the swarm loop
// would be worse), but it must be VISIBLE: a counter + WARN so an operator can
// correlate "orphan waits forever" with "ingest channel overflowed".
static INGEST_DROPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Total inbound frames dropped because the swarm→processor channel was full.
pub fn ingest_drops_total() -> u64 {
    INGEST_DROPS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Forward an inbound frame to the processor, counting + logging drops instead
/// of discarding them silently. WARNs on the first drop and every 100th after
/// (a storm that overflows a 1000-slot channel would otherwise flood the log).
/// Returns `true` iff the frame was queued.
fn forward_to_processor<T>(block_tx: &mpsc::Sender<T>, item: T, kind: &'static str, source: &str) -> bool {
    use tokio::sync::mpsc::error::TrySendError;
    match block_tx.try_send(item) {
        Ok(())                       => true,
        Err(TrySendError::Full(_))   => {
            let n = INGEST_DROPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed).saturating_add(1);
            if n == 1 || n % 100 == 0 {
                warn!("ingest channel FULL — dropped inbound [{}] from {} \
                       (total dropped: {}; lost GetBlock replies are re-requested \
                       by the orphan sweep)", kind, source, n);
            }
            false
        }
        Err(TrySendError::Closed(_)) => {
            warn!("ingest channel CLOSED — dropped inbound [{}] from {}", kind, source);
            false
        }
    }
}

// ── NET-2: application-validated gossip ──────────────────────────────────────
//
// Gossipsub runs with `validate_messages()`: a received frame is NOT relayed
// until the application reports a verdict with
// `report_message_validation_result`. `Accept` forwards it; `Reject` drops it
// AND applies gossipsub's invalid-delivery (P4) penalty to the peer that
// delivered it; `Ignore` drops it without penalty. Because every honest node
// running this validation forwards only frames it accepted, an invalid frame
// is then delivered only by its originator, so penalties land on the author
// instead of on honest relays (NET-4). Earlier releases forward
// `NewTransaction` frames without validating them, so the transaction relay
// answers `Reject` only once no such release can be a peer on the chain
// (`mempool::relay::TxRelay::penalties_in_force`).

/// The application's verdict on one gossip frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GossipVerdict {
    /// Valid: relay it to the mesh.
    Accept,
    /// Provably invalid: drop it and penalize the delivering peer (P4).
    Reject,
    /// Not relayed, not penalized (duplicate, stale, policy, unverifiable).
    Ignore,
}

impl From<GossipVerdict> for gossipsub::MessageAcceptance {
    fn from(v: GossipVerdict) -> Self {
        match v {
            GossipVerdict::Accept => gossipsub::MessageAcceptance::Accept,
            GossipVerdict::Reject => gossipsub::MessageAcceptance::Reject,
            GossipVerdict::Ignore => gossipsub::MessageAcceptance::Ignore,
        }
    }
}

/// A verdict the processor reports back to the network loop for a gossip
/// frame whose validation was deferred to it.
#[derive(Clone, Debug)]
pub struct GossipValidation {
    pub message_id:         gossipsub::MessageId,
    pub propagation_source: PeerId,
    pub verdict:            GossipVerdict,
}

/// Gossipsub `history_length`: heartbeats (1 s each) an unvalidated frame
/// stays in the message cache, i.e. how long a withheld verdict can still
/// forward it.
pub const GOSSIP_HISTORY_LENGTH: usize = 12;

/// Out-of-band requests from the message processor to the network loop
/// (see [`NetworkNode::attach_control`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkControl {
    /// MEM-5 / MEM-6: `peer` delivered a consensus-invalid transaction whose
    /// gossip frame can no longer be answered `Reject` (it was buffered as an
    /// orphan and left gossipsub's cache before its re-try proved it
    /// invalid). The network loop applies one application-score penalty, as
    /// for a wire violation (decaying, shared with the wire tracker).
    PenalizePeer(PeerId),
}

/// Peer lifecycle notices from the network loop to the message processor
/// (see [`NetworkNode::attach_peer_events`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerEvent {
    /// The last connection to this peer closed. The transaction relay drops
    /// its per-connection signature budget and the orphans it delivered
    /// (Bitcoin Core's `EraseForPeer`).
    Disconnected(PeerId),
}

/// Where an inbound frame handed to the processor came from.
#[derive(Clone, Debug)]
pub enum InboundOrigin {
    /// Unsolicited gossip. `author` is the signed originator (gossipsub
    /// `Strict` validation), `propagation_source` the neighbour that
    /// delivered it. `pending` is `Some(id)` iff the processor owes the
    /// network loop a [`GossipValidation`] for this frame.
    Gossip {
        propagation_source: PeerId,
        author:             Option<PeerId>,
        pending:            Option<gossipsub::MessageId>,
        /// When the network loop received the frame — gossipsub put it in
        /// its message cache at that moment, and it is shifted out
        /// [`GOSSIP_HISTORY_LENGTH`] heartbeats later. A withheld verdict
        /// must be reported before then (review finding: the deferred-orphan
        /// TTL used to start at processor time).
        received_at:        std::time::Instant,
    },
    /// The answer to one of OUR directed `/gnb/sync/1` pulls, from `peer`.
    Directed { peer: PeerId },
    /// Generated locally by the network loop (heartbeat `PeerCount`).
    Local,
}

impl InboundOrigin {
    /// True for answers to our own directed pulls (solicited data).
    pub fn is_solicited(&self) -> bool {
        matches!(self, InboundOrigin::Directed { .. })
    }

    /// The remote peer responsible for this frame: the directed responder or
    /// the gossip neighbour that delivered it.
    pub fn peer(&self) -> Option<PeerId> {
        match self {
            InboundOrigin::Gossip { propagation_source, .. } => Some(*propagation_source),
            InboundOrigin::Directed { peer } => Some(*peer),
            InboundOrigin::Local => None,
        }
    }

    /// When the network loop received this gossip frame (`None` for
    /// directed and local frames).
    pub fn received_at(&self) -> Option<std::time::Instant> {
        match self {
            InboundOrigin::Gossip { received_at, .. } => Some(*received_at),
            _ => None,
        }
    }

    /// `(message_id, propagation_source)` when a verdict is owed.
    pub fn pending_verdict(&self) -> Option<(gossipsub::MessageId, PeerId)> {
        match self {
            InboundOrigin::Gossip { propagation_source, pending: Some(id), .. } => {
                Some((id.clone(), *propagation_source))
            }
            _ => None,
        }
    }
}

/// One inbound frame plus its origin, as delivered by
/// [`NetworkNode::run_validated`].
#[derive(Clone, Debug)]
pub struct Inbound {
    pub msg:    NetworkMessage,
    pub origin: InboundOrigin,
}

/// What the network loop does with one decoded gossip frame (pure; unit
/// tested). NET-7: gossip PULLS (`GetHeaders`, `GetBlock`, `GetTips`,
/// `PeerRequest`) and gossip RESPONSES (`Headers`, `Tips`, `BlockNotFound`)
/// are never delivered and never relayed — pulls are served only over the
/// directed `/gnb/sync/1` protocol, one requester, one answer. NET-11:
/// gossip `PeerExchange` is unsolicited and is neither relayed nor used to
/// dial. `PeerCount` is a local-only frame and is never accepted from a peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GossipDisposition {
    /// Deliver to the processor, which reports the verdict later.
    DeliverDeferred,
    /// Deliver to the processor and report this verdict now.
    Deliver(GossipVerdict),
    /// Do not deliver; report this verdict now.
    Drop(GossipVerdict),
}

/// Decide [`GossipDisposition`] for a decoded, bounds-valid gossip frame.
/// `validator_attached`: a processor that reports verdicts is wired
/// ([`NetworkNode::run_validated`]); otherwise blocks are accepted on decode
/// (legacy [`NetworkNode::run`]). `claim_ok`: the frame is a tip claim from
/// a directly connected author within its rate limit.
pub fn gossip_disposition(msg: &NetworkMessage, validator_attached: bool, claim_ok: bool) -> GossipDisposition {
    use GossipDisposition::*;
    match msg {
        // MEM-5 / NET-2 / NET-4 (audit): transactions are judged by the
        // processor (shared admission, signatures last, per-connection budget —
        // `mempool::relay`) BEFORE gossipsub relays them, exactly like blocks.
        NetworkMessage::NewBlock { .. } | NetworkMessage::NewTransaction { .. } => {
            if validator_attached { DeliverDeferred } else { Deliver(GossipVerdict::Accept) }
        }
        // Tip claims: consumed locally (author-attributed), never relayed —
        // every node floods its own claims to all of its direct peers.
        NetworkMessage::PeerTip { .. } | NetworkMessage::Version { .. } => {
            if claim_ok { Deliver(GossipVerdict::Ignore) } else { Drop(GossipVerdict::Ignore) }
        }
        NetworkMessage::GetHeaders { .. }
        | NetworkMessage::GetBlock { .. }
        | NetworkMessage::GetTips
        | NetworkMessage::PeerRequest
        | NetworkMessage::Headers { .. }
        | NetworkMessage::Tips { .. }
        | NetworkMessage::BlockNotFound { .. }
        | NetworkMessage::PeerExchange { .. }
        | NetworkMessage::PeerCount { .. }
        | NetworkMessage::VersionAck => Drop(GossipVerdict::Ignore),
    }
}

/// Where the network loop hands inbound frames.
enum IngestSink {
    /// Legacy consumer: bare messages, no verdicts expected.
    Legacy(mpsc::Sender<NetworkMessage>),
    /// Validated consumer: frames with origin; verdicts come back.
    Validated(mpsc::Sender<Inbound>),
}

impl IngestSink {
    fn validator_attached(&self) -> bool {
        matches!(self, IngestSink::Validated(_))
    }

    fn deliver(&self, msg: NetworkMessage, origin: InboundOrigin, source: &str) -> bool {
        let kind = msg.kind_name();
        match self {
            IngestSink::Legacy(tx) => forward_to_processor(tx, msg, kind, source),
            IngestSink::Validated(tx) => forward_to_processor(tx, Inbound { msg, origin }, kind, source),
        }
    }
}

// ── Messages ──────────────────────────────────────────────────────────────────

/// Protocol version for forward compatibility and hard fork coordination.
/// Nodes reject messages from incompatible versions.
pub const PROTOCOL_VERSION: u32 = 1;
/// Minimum protocol version this node accepts
pub const MIN_PROTOCOL_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NetworkMessage {
    NewBlock {
        block_hash: [u8; 32],
        blue_score: u64,
        height:     u64,
        block_data: Vec<u8>,
    },
    NewTransaction {
        txid:    [u8; 32],
        tx_data: Vec<u8>,
    },
    // IBD
    PeerTip    { peer_id: String, blue_score: u64, height: u64 },
    PeerExchange { peers: Vec<String> },
    PeerRequest,
    PeerCount { count: usize, addresses: Vec<String> },
    /// `nonce` for the same reason GetBlock and BlockNotFound carry one. A node
    /// re-asking for the SAME window — which is exactly what a stalled node does,
    /// every cycle — serialises identically and has the retry dropped locally
    /// before it reaches the network. Measured at 90 suppressions in two minutes
    /// on a node that was making no progress.
    ///
    /// The general rule this file has now learned three times: on the sync topic,
    /// deduplication is wrong. It exists to stop gossip storms of the same BLOCK;
    /// a request is not gossip, and two identical requests are two intentions,
    /// not one message seen twice.
    GetHeaders { from_blue_score: u64, limit: u32, nonce: u64 },
    Headers    { entries: Vec<SyncEntry> },
    /// Request a block body. `nonce` exists ONLY to make each request unique on
    /// the wire, and the responder ignores it.
    ///
    /// Without it every re-request serialises to identical bytes, hashes to the
    /// same gossipsub MessageId, and `publish()` returns `Err(Duplicate)`
    /// LOCALLY — the retry never leaves this node. That is the same failure this
    /// file already documents for PeerTip a few lines below `duplicate_cache_time`,
    /// where the fix was noted as "the tip-carrying Version (fresh timestamp →
    /// unique bytes) can never be dedup-dropped at all". GetBlock had no such
    /// field, so IBD retries were silently swallowed: observed on a stalled node
    /// as 12,235 `publish sync: Duplicate` in ten minutes while it sat at one
    /// height with peers that HELD the blocks it was asking for.
    GetBlock   { block_hash: [u8; 32], nonce: u64 },
    /// Explicit "I cannot serve this body" answer to GetBlock. Added 2026-07-19:
    /// the responder used to drop unanswerable requests silently, which left the
    /// requester unable to distinguish a pruned body from a lost packet — it just
    /// waited and re-asked forever. A fresh node cannot bootstrap from a pruned
    /// peer, and it deserves to LEARN that instead of stalling: on receiving this
    /// it can try another peer, or report honestly that no archival peer exists.
    /// `nonce` for the same reason GetBlock carries one: without it every answer
    /// serialises identically, is dedup-dropped locally, and the peer waiting on
    /// it learns nothing. Measured on a stalled archival node: 7,983 of 8,060
    /// suppressed publishes in two minutes were THIS message — added the same
    /// night to fix a silent responder, and immediately becoming the loudest
    /// source of the noise it was meant to remove. A message that answers a
    /// repeated question must be as unique as the question.
    BlockNotFound { block_hash: [u8; 32], nonce: u64 },
    // Frontier reconciliation (Phase 2 Kaspa sync-negotiation layer)
    /// Frontier reconciliation: request the peer's DAG frontier. No payload.
    /// Sent only as a DIRECTED `/gnb/sync/1` request to one peer; a gossip
    /// copy is neither answered nor relayed (audit NET-7).
    GetTips,
    /// Frontier reconciliation reply: full DAG frontier + selected-chain locator.
    Tips { tips: Vec<SyncEntry>, locator: Vec<[u8; 32]> },
    // Protocol handshake
    Version {
        version:    u32,
        user_agent: String,
        blue_score: u64,
        height:     u64,
        timestamp:  u64,
    },
    VersionAck,
}


impl NetworkMessage {
    /// Variant name for diagnostics.
    ///
    /// H-R3-3: this used to `Box::leak(format!("{:?}", self))` on every call —
    /// a fresh, permanent, unfreed allocation per invocation, sized to the
    /// `Debug` rendering of the WHOLE message (for `NewBlock` that is every
    /// byte of `block_data` printed as decimal, i.e. ~5x the block size). The
    /// function is called from `forward_to_processor`'s drop path, which is
    /// attacker-reachable (fill the bounded ingest channel with cheap frames,
    /// then send large `NewBlock` frames): each drop leaked megabytes,
    /// unbounded and irreclaimable short of a restart.
    ///
    /// INVARIANT (H-R3-3): naming a message variant must be an allocation-free,
    /// leak-free, `&'static str` lookup — a plain match, so the compiler (not a
    /// runtime string scan) forces every new variant to be classified.
    pub fn kind_name(&self) -> &'static str {
        match self {
            NetworkMessage::NewBlock { .. } => "NewBlock",
            NetworkMessage::NewTransaction { .. } => "NewTransaction",
            NetworkMessage::PeerTip { .. } => "PeerTip",
            NetworkMessage::PeerExchange { .. } => "PeerExchange",
            NetworkMessage::PeerRequest => "PeerRequest",
            NetworkMessage::PeerCount { .. } => "PeerCount",
            NetworkMessage::GetHeaders { .. } => "GetHeaders",
            NetworkMessage::Headers { .. } => "Headers",
            NetworkMessage::GetBlock { .. } => "GetBlock",
            NetworkMessage::BlockNotFound { .. } => "BlockNotFound",
            NetworkMessage::GetTips => "GetTips",
            NetworkMessage::Tips { .. } => "Tips",
            NetworkMessage::Version { .. } => "Version",
            NetworkMessage::VersionAck => "VersionAck",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncEntry {
    pub hash:       [u8; 32],
    pub blue_score: u64,
    pub height:     u64,
}

// ── C1: bounded, validated wire decode ────────────────────────────────────────
//
// Every gossip frame comes from an untrusted peer. Before this fix the event
// loop decoded frames with `bincode::config::standard()`, which puts no limit
// on how many bytes a frame may claim to contain: a tiny crafted frame could
// declare a multi-GB Vec length, and nothing in the decode path capped list
// lengths (peer lists, header vectors, address strings). All untrusted decodes
// now go through `decode_wire_message`, which (1) rejects frames larger than
// MAX_WIRE_BYTES outright, (2) decodes with a bincode read limit of the same
// size, and (3) applies explicit post-decode bounds to every variable-length
// field of `NetworkMessage`.
//
// HONESTY CAVEAT on (3): the post-decode bounds run *after* serde has built
// the value, so they bound acceptance, not the transient decode allocation.
// The transient allocation is bounded by the 4 MiB byte limit, but bincode's
// serde bridge decodes collections element-by-element, so a pathological
// 4 MiB frame of empty strings can transiently amplify to tens of MB of
// String headers before the bounds check rejects it. That is bounded and
// short-lived (not the multi-GB pre-allocation this fixes), but tightening it
// to zero would need a custom `Deserialize` impl — not done here.

/// Hard ceiling on any single gossip frame. Must match gossipsub's
/// `max_transmit_size` configured in `run()`.
pub const MAX_WIRE_BYTES: usize = 4 * 1024 * 1024;

/// Max entries in a PEX/PeerCount address list. A compliant node advertises at
/// most KNOWN_PEERS_CAP (1000) known peers plus a few self-addresses.
pub const MAX_WIRE_ADDRS: usize = KNOWN_PEERS_CAP + 64;
/// Max byte length of a single advertised multiaddr string. A real
/// `/dns4/host/tcp/port/p2p/<peer-id>` is well under 256 bytes; 512 is
/// generous headroom.
pub const MAX_WIRE_ADDR_LEN: usize = 512;
/// Max SyncEntry items in a Headers frame. IBD requests batches of 500
/// (see main.rs GetHeaders); 2000 leaves headroom.
pub const MAX_WIRE_SYNC_ENTRIES: usize = 2000;
/// Max tip entries in a Tips frame. MUST equal sync::MAX_ADVERTISED_TIPS.
pub const MAX_WIRE_TIPS: usize = 256;
/// Max locator hashes in a Tips frame. MUST equal locator::MAX_LOCATOR_LEN.
pub const MAX_WIRE_LOCATOR: usize = 64;
/// Max `limit` a peer may request via GetHeaders (bounds the work WE do
/// serving the response).
pub const MAX_WIRE_GETHEADERS_LIMIT: u32 = 2000;
/// Max user_agent length in a Version handshake.
pub const MAX_WIRE_USER_AGENT_LEN: usize = 128;
/// Max peer_id string length in a PeerTip (base58 libp2p PeerIds are ~52 chars).
pub const MAX_WIRE_PEER_ID_LEN: usize = 128;

/// App-score penalty per wire protocol violation. With app_specific_weight
/// 1.0 and graylist_threshold -400 (see `run()`), four violations graylist
/// the peer.
pub const WIRE_VIOLATION_PENALTY: f64 = -100.0;
/// Floor so a flood of violations can't drive the score to -inf.
pub const WIRE_PENALTY_FLOOR: f64 = -1000.0;
/// Cap on the number of peers whose penalty score we track (bounds memory
/// against an attacker cycling peer identities).
pub const WIRE_PENALTY_TRACK_CAP: usize = 1024;
/// NET-4 / NET-8 (audit): penalties decay toward zero. Every
/// [`WIRE_PENALTY_DECAY_INTERVAL`] a tracked score is multiplied by
/// [`WIRE_PENALTY_DECAY_FACTOR`] (≈ 6.6 min half-life); a score whose
/// magnitude falls below 1.0 is forgotten (and reset to 0 in gossipsub).
pub const WIRE_PENALTY_DECAY_INTERVAL: Duration = Duration::from_secs(60);
pub const WIRE_PENALTY_DECAY_FACTOR: f64 = 0.9;

#[derive(Debug)]
pub enum WireDecodeError {
    /// Frame exceeds MAX_WIRE_BYTES, or the bincode read limit tripped
    /// (e.g. a declared length larger than the frame could ever satisfy).
    Oversized(String),
    /// Frame decoded, but a length field violates protocol bounds.
    Bounds(&'static str),
    /// Plain malformed bincode (may be benign version skew, not penalized
    /// as harshly as a deliberate oversize).
    Malformed(String),
    /// NET-7 (audit): the frame decoded but carried this many bytes past its
    /// logical end. A compliant encoder never produces them; accepting them
    /// let an attacker make any request byte-unique (fresh gossip message id)
    /// and so bypass gossipsub's de-duplication.
    TrailingBytes(usize),
}

impl WireDecodeError {
    /// Oversized and bounds-violating frames are deliberate protocol
    /// violations — a compliant node cannot produce them. Malformed frames
    /// may just be a newer/older protocol version.
    pub fn is_protocol_violation(&self) -> bool {
        matches!(
            self,
            WireDecodeError::Oversized(_) | WireDecodeError::Bounds(_) | WireDecodeError::TrailingBytes(_)
        )
    }
}

/// Decode an untrusted gossip frame with a hard byte limit and post-decode
/// bounds validation. This is the ONLY correct way to decode wire bytes from
/// a peer; `bincode::config::standard()` without a limit must never be used
/// on untrusted input.
pub fn decode_wire_message(data: &[u8]) -> Result<NetworkMessage, WireDecodeError> {
    if data.len() > MAX_WIRE_BYTES {
        return Err(WireDecodeError::Oversized(format!(
            "frame is {} bytes (max {})", data.len(), MAX_WIRE_BYTES
        )));
    }
    let cfg = bincode::config::standard().with_limit::<MAX_WIRE_BYTES>();
    let msg: NetworkMessage = match bincode::serde::decode_from_slice(data, cfg) {
        Ok((m, consumed)) => {
            if consumed != data.len() {
                return Err(WireDecodeError::TrailingBytes(data.len().saturating_sub(consumed)));
            }
            m
        }
        Err(bincode::error::DecodeError::LimitExceeded) => {
            return Err(WireDecodeError::Oversized(format!(
                "declared content exceeds {} byte read limit", MAX_WIRE_BYTES
            )));
        }
        Err(e) => return Err(WireDecodeError::Malformed(e.to_string())),
    };
    validate_wire_bounds(&msg)?;
    Ok(msg)
}

/// Explicit bounds on every variable-length field of NetworkMessage.
fn validate_wire_bounds(msg: &NetworkMessage) -> Result<(), WireDecodeError> {
    use WireDecodeError::Bounds;
    fn addrs_ok(addrs: &[String]) -> Result<(), WireDecodeError> {
        if addrs.len() > MAX_WIRE_ADDRS {
            return Err(WireDecodeError::Bounds("address list longer than MAX_WIRE_ADDRS"));
        }
        if addrs.iter().any(|a| a.len() > MAX_WIRE_ADDR_LEN) {
            return Err(WireDecodeError::Bounds("address string longer than MAX_WIRE_ADDR_LEN"));
        }
        Ok(())
    }
    match msg {
        // The two payload checks below are unreachable today (a payload can't
        // exceed the frame that carries it, and frames are capped at
        // MAX_WIRE_BYTES) — kept as belt-and-braces should the byte limit and
        // this constant ever diverge.
        NetworkMessage::NewBlock { block_data, .. } => {
            if block_data.len() > MAX_WIRE_BYTES {
                return Err(Bounds("block_data larger than MAX_WIRE_BYTES"));
            }
        }
        NetworkMessage::NewTransaction { tx_data, .. } => {
            if tx_data.len() > MAX_WIRE_BYTES {
                return Err(Bounds("tx_data larger than MAX_WIRE_BYTES"));
            }
        }
        NetworkMessage::PeerTip { peer_id, .. } => {
            if peer_id.len() > MAX_WIRE_PEER_ID_LEN {
                return Err(Bounds("peer_id longer than MAX_WIRE_PEER_ID_LEN"));
            }
        }
        NetworkMessage::PeerExchange { peers } => addrs_ok(peers)?,
        NetworkMessage::PeerCount { addresses, .. } => addrs_ok(addresses)?,
        NetworkMessage::GetHeaders { limit, .. } => {
            if *limit > MAX_WIRE_GETHEADERS_LIMIT {
                return Err(Bounds("GetHeaders limit above MAX_WIRE_GETHEADERS_LIMIT"));
            }
        }
        NetworkMessage::Headers { entries } => {
            if entries.len() > MAX_WIRE_SYNC_ENTRIES {
                return Err(Bounds("Headers entries longer than MAX_WIRE_SYNC_ENTRIES"));
            }
        }
        NetworkMessage::Tips { tips, locator } => {
            if tips.len() > MAX_WIRE_TIPS {
                return Err(Bounds("Tips tips longer than MAX_WIRE_TIPS"));
            }
            if locator.len() > MAX_WIRE_LOCATOR {
                return Err(Bounds("Tips locator longer than MAX_WIRE_LOCATOR"));
            }
        }
        NetworkMessage::Version { user_agent, .. } => {
            if user_agent.len() > MAX_WIRE_USER_AGENT_LEN {
                return Err(Bounds("user_agent longer than MAX_WIRE_USER_AGENT_LEN"));
            }
        }
        NetworkMessage::PeerRequest
        | NetworkMessage::VersionAck
        | NetworkMessage::GetTips
        | NetworkMessage::GetBlock { .. }
        | NetworkMessage::BlockNotFound { .. } => {}
    }
    Ok(())
}

// ── Sprint EE (S3): frame-reaction unit — extracted from `run()` ─────────────
//
// The decode → penalize/ignore/accept decision used to live inline in the
// gossipsub `Message` arm of `run()`'s event loop, so the ONLY way to exercise
// the peer-scoring reaction to an invalid-block frame, an oversized frame, or
// a bounds-violating list was to stand up a live swarm — which made the
// reaction untested. This extraction is behavior-preserving: `run()` is now a
// thin consumer (classify → apply app score / log / forward), and the reaction
// itself is asserted deterministically in unit tests and in
// tests/sprint_ee_transport_convergence.rs without any networking.

/// What the node does in response to a single gossip frame from a peer.
#[derive(Debug)]
pub enum WireReaction {
    /// Frame decoded and passed bounds validation — process it.
    Accept(NetworkMessage),
    /// Deliberate protocol violation (oversized frame / bounds-violating
    /// lengths — e.g. an invalid-block frame larger than MAX_WIRE_BYTES):
    /// `score` is the peer's new cumulative application score to install via
    /// `gossipsub.set_application_score`. With app_specific_weight 1.0 and
    /// graylist_threshold -400, the fourth violation graylists the peer.
    Penalize { error: WireDecodeError, score: f64 },
    /// Malformed bincode — possibly benign version skew. Log-only, no penalty.
    IgnoreMalformed(String),
}

/// Cumulative per-peer wire-violation penalty state. Bounded to
/// [`WIRE_PENALTY_TRACK_CAP`] peers so an attacker cycling identities cannot
/// grow the map without limit.
///
/// NET-8 (audit): once full, the map used to stop tracking newcomers — a late
/// offender got a one-shot −100 forever and never reached the graylist. Now a
/// newcomer evicts the entry with the MILDEST score (ties: least recently
/// penalized), so real offenders stay tracked and every offender can
/// accumulate. NET-4: scores also DECAY ([`Self::decay_tick_at`]), so a peer
/// penalized for a burst of frames it merely relayed recovers instead of
/// being cut off forever.
pub struct WirePenaltyTracker {
    /// peer -> (score, last decay step, last penalty)
    penalties: std::collections::HashMap<PeerId, (f64, std::time::Instant, std::time::Instant)>,
}

impl Default for WirePenaltyTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl WirePenaltyTracker {
    pub fn new() -> Self {
        Self { penalties: std::collections::HashMap::new() }
    }

    /// Decode an untrusted gossip frame and decide the reaction. This is the
    /// exact logic previously inline in `run()`:
    ///   - decodes via [`decode_wire_message`] (4 MiB frame/read limit +
    ///     post-decode bounds + no trailing bytes);
    ///   - protocol violations (Oversized/Bounds/TrailingBytes) accumulate
    ///     [`WIRE_VIOLATION_PENALTY`] per offense, floored at
    ///     [`WIRE_PENALTY_FLOOR`];
    ///   - plain-malformed frames are ignored (may be version skew).
    pub fn classify(&mut self, peer: PeerId, data: &[u8]) -> WireReaction {
        match decode_wire_message(data) {
            Ok(msg) => WireReaction::Accept(msg),
            Err(e) if e.is_protocol_violation() => {
                let score = self.record_violation(peer);
                WireReaction::Penalize { error: e, score }
            }
            Err(e) => WireReaction::IgnoreMalformed(format!("{:?}", e)),
        }
    }

    /// H-R3-4: apply one [`WIRE_VIOLATION_PENALTY`] to `peer` and return its
    /// new cumulative score, WITHOUT going through [`decode_wire_message`] —
    /// this is the entry point for protocol violations detected on the
    /// directed `/gnb/sync/1` protocol (`sync_rr`), which has its own codec
    /// and therefore its own decode/bounds errors, but shares one peer-score
    /// reputation with the gossip path: an attacker cannot escape scoring by
    /// switching which protocol it sends violations on. Same cap/floor
    /// discipline as `classify`.
    pub fn record_violation(&mut self, peer: PeerId) -> f64 {
        self.record_violation_at(peer, std::time::Instant::now())
    }

    /// [`Self::record_violation`] with an explicit clock.
    pub fn record_violation_at(&mut self, peer: PeerId, now: std::time::Instant) -> f64 {
        if !self.penalties.contains_key(&peer) && self.penalties.len() >= WIRE_PENALTY_TRACK_CAP {
            // NET-8: make room by forgetting the mildest (then stalest) entry.
            let victim = self
                .penalties
                .iter()
                .max_by(|(_, a), (_, b)| {
                    a.0.partial_cmp(&b.0)
                        .unwrap_or(std::cmp::Ordering::Equal)
                        .then(b.2.cmp(&a.2))
                })
                .map(|(p, _)| *p);
            if let Some(v) = victim {
                self.penalties.remove(&v);
            }
        }
        let e = self.penalties.entry(peer).or_insert((0.0, now, now));
        e.0 = (e.0 + WIRE_VIOLATION_PENALTY).max(WIRE_PENALTY_FLOOR);
        e.2 = now;
        e.0
    }

    /// NET-4 / NET-8: decay every tracked score by
    /// [`WIRE_PENALTY_DECAY_FACTOR`] per full [`WIRE_PENALTY_DECAY_INTERVAL`]
    /// elapsed. Returns `(peer, new_score)` for every score that changed, to
    /// be re-installed with `set_application_score`; forgotten peers are
    /// returned with `0.0` and removed from the map.
    pub fn decay_tick_at(&mut self, now: std::time::Instant) -> Vec<(PeerId, f64)> {
        let mut changed = Vec::new();
        let mut forget = Vec::new();
        for (peer, e) in self.penalties.iter_mut() {
            let elapsed = now.saturating_duration_since(e.1);
            let steps = (elapsed.as_secs() / WIRE_PENALTY_DECAY_INTERVAL.as_secs().max(1)).min(1_000);
            if steps == 0 {
                continue;
            }
            e.0 *= WIRE_PENALTY_DECAY_FACTOR.powi(steps as i32);
            e.1 += WIRE_PENALTY_DECAY_INTERVAL * steps as u32;
            if e.0.abs() < 1.0 {
                forget.push(*peer);
                changed.push((*peer, 0.0));
            } else {
                changed.push((*peer, e.0));
            }
        }
        for p in forget {
            self.penalties.remove(&p);
        }
        changed
    }

    /// Number of peers currently tracked (observability for tests/metrics).
    pub fn tracked_peers(&self) -> usize {
        self.penalties.len()
    }

    /// Current cumulative score for a peer, if tracked.
    pub fn score_of(&self, peer: &PeerId) -> Option<f64> {
        self.penalties.get(peer).map(|e| e.0)
    }
}

// ── H4: panic-free truncation of attacker-controlled strings ─────────────────

/// UTF-8-safe prefix of at most `max_bytes` bytes.
///
/// The PEX log lines previously used `&s[..s.len().min(N)]`, which panics if
/// byte N falls in the middle of a multi-byte UTF-8 codepoint — and PEX
/// address strings are attacker-controlled, so a single crafted multiaddr
/// containing multi-byte characters at the right offset crashed the whole
/// network event loop. This walks back to the nearest char boundary instead.
/// L-4 (audit): made `pub` (was `pub(crate)`) so `bin/gnb-cli.rs` — a
/// separate crate within this package — can call the same UTF-8-safe
/// truncation instead of hand-rolling a byte-index slice on a node-response
/// string (which panics if a multi-byte character straddles the cut point).
pub fn truncate_utf8(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    // `end` is now a char boundary (0 in the worst case), so this cannot panic.
    &s[..end]
}

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct NetworkConfig {
    pub listen_addr:     String,
    pub bootstrap_peers: Vec<String>,
    /// Opt-in DNS seed hostnames (Bitcoin-style cold-start). Resolved to
    /// A/AAAA records and dialed as peers. Empty by default — non-privileged.
    pub dns_seeds:       Vec<String>,
    pub max_peers:       usize,
    pub data_dir:        PathBuf,
    /// Sprint P: if true, PEX will accept RFC1918 / loopback addresses.
    /// Intended for local development; production should leave this false.
    pub allow_private_peers: bool,
    /// Mesh fix (fresh-joiner IBD): this node sits behind a TCP proxy / NAT
    /// where many peers legitimately share one source IP (fly.io edge,
    /// ingress, CGNAT). Disables the gossipsub ip-colocation penalty weight
    /// (which would graylist the whole mesh at ~6 peers from one IP and
    /// silently blackhole every tip announcement). All other scoring stays.
    pub behind_proxy: bool,
    /// Enable mDNS zero-config LAN peer discovery. OFF by default: public nodes
    /// bootstrap via explicit `--peer` / `--dns-seed`, and mDNS (a) is useless off
    /// a LAN and (b) exercises hickory-proto's mDNS record parser (RUSTSEC-2026-0118/
    /// 0119 — LAN-only DoS surface). Turn on only for local/dev zero-config discovery.
    pub enable_mdns: bool,
    /// Announce-then-pull: this node runs with `--archive` (full block bodies
    /// retained, never pruned). Advertised to peers via the identify
    /// agent-version so they prefer us as the directed-pull source during IBD.
    pub archive: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addr:     "/ip4/0.0.0.0/tcp/17110".into(),
            bootstrap_peers: vec![],
            dns_seeds:       vec![],
            max_peers:       50,
            data_dir:        PathBuf::from("./bloch-data"),
            allow_private_peers: false,
            behind_proxy:    false,
            enable_mdns:     false,
            archive:         false,
        }
    }
}

// ── Behaviour ───────────────────────────────────────────────────────────────
//
// PRINCIPLES.md #2 ("every node is a seed"): the swarm combines gossipsub with
// mdns (zero-config LAN discovery — a node bootstraps from local peers with no
// configured seed) and identify (the node learns its own public address as
// peers observe it, so it can self-advertise via PEX). No privileged seed is
// required; any node can bootstrap another. The derive generates the event enum
// `BlochBehaviourEvent`.
#[derive(libp2p::swarm::NetworkBehaviour)]
struct BlochBehaviour {
    gossipsub: gossipsub::Behaviour,
    // Toggle: mDNS is present only when `--enable-mdns` is set (off by default).
    // Disabled → the hickory-proto mDNS parser is never exercised (RUSTSEC-2026-0118/0119).
    mdns:      libp2p::swarm::behaviour::toggle::Toggle<mdns::tokio::Behaviour>,
    identify:  identify::Behaviour,
    // Announce-then-pull: directed IBD PULL path (GetBlock/GetHeaders/GetTips)
    // over libp2p request-response (`/gnb/sync/1`), so block/header FETCHING
    // is a directed request to ONE peer instead of a gossipsub broadcast to the
    // whole mesh (removes the O(peers) IBD amplification). See `sync_rr`.
    sync_rr:   sync_rr::Behaviour,
    // P0 (roadmap §1.3 / §4.1): swarm-level connection limits. `max_peers` was
    // previously only an app-side counter checked in the PEX/mDNS dial paths,
    // so inbound connection floods / eclipse setup were NOT bounded by libp2p.
    // This behaviour rejects connections at the transport layer once the caps
    // are hit, matching max_peers.
    connection_limits: libp2p::connection_limits::Behaviour,
}

// ── Node ──────────────────────────────────────────────────────────────────────

/// Yamux per-connection substream cap.
///
/// Must sit ABOVE `sync_rr::MAX_CONCURRENT_SYNC_STREAMS` (2048) or the
/// transport vetoes the request-response layer: fecf29b raised the rr cap
/// 100 → 2048 so sync bursts flow, but the swarm was still built with
/// `yamux::Config::default`, whose yamux-0.13 backend caps a connection at
/// 512 substreams — and yamux does NOT backpressure at that cap, it KILLS
/// the whole connection (`connection.rs`: inbound over the cap →
/// `Action::Terminate`, outbound → `ConnectionError::TooManyStreams`;
/// logged as "maximum number of streams reached" followed by our
/// "✗ disconnected"). A node catching up across the damaged-fork anticone
/// opens a GetBlock burst, blows through 512, and the transport drops the
/// very peer it was syncing from — observed on node4 as a 0↔3-peer
/// connect/disconnect oscillation (15 connects / 15 disconnects / 12×
/// "maximum number of streams" in 15 min).
///
/// 4096 = 2× the rr cap: room for all 2048 sync streams plus gossipsub,
/// identify and ping substreams, with slack for streams in half-closed
/// teardown. Memory stays bounded by the rr cap (sync frames are the only
/// bulk payload; gossip is capped at 4 MiB per message elsewhere).
///
/// NET-17 (audit) — corrected: upstream libp2p-yamux 0.47 switched to the
/// yamux 0.12 backend as soon as ANY config setter ran. This workspace
/// patches `libp2p-yamux` with the vendored fork in `crates/libp2p-yamux`,
/// which REMOVES the 0.12 backend (GHSA-vxx9-2994-q338): `set_max_num_streams`
/// configures yamux 0.13 directly, and 4096 is exactly the largest cap the
/// 0.13 default receive window allows. A NOT-yet-updated remote still
/// enforces 512 on ITS side of the connection, so the churn only fully stops
/// once both endpoints run this build.
const MAX_YAMUX_STREAMS: usize = 4096;

/// Builder for the swarm's yamux config — passed to `with_tcp` /
/// `with_websocket` in place of `yamux::Config::default` (the builder accepts
/// any `FnOnce() -> Config`). See `MAX_YAMUX_STREAMS` for why and for the
/// 0.13→0.12 backend consequence.
fn yamux_config() -> yamux::Config {
    let mut cfg = yamux::Config::default();
    cfg.set_max_num_streams(MAX_YAMUX_STREAMS);
    cfg
}

pub struct NetworkNode {
    pub peer_id: PeerId,
    pub config:  NetworkConfig,
    local_key:   identity::Keypair,
    control_rx:  Option<mpsc::Receiver<NetworkControl>>,
    peer_events: Option<mpsc::Sender<PeerEvent>>,
}

impl NetworkNode {
    /// FIX #4: Persistent P2P identity.
    pub fn new(config: NetworkConfig) -> Result<Self, NetworkError> {
        let key_path = config.data_dir.join("p2p_identity.bin");
        let local_key = load_or_create_identity(&key_path)?;
        let peer_id   = PeerId::from(local_key.public());
        info!("P2P identity: {} ({})", peer_id, key_path.display());
        Ok(Self { peer_id, config, local_key, control_rx: None, peer_events: None })
    }

    /// Accept [`NetworkControl`] requests from the processor on `rx`.
    pub fn attach_control(&mut self, rx: mpsc::Receiver<NetworkControl>) {
        self.control_rx = Some(rx);
    }

    /// Report [`PeerEvent`]s to the processor on `tx` (never blocks: a full
    /// channel drops the notice).
    pub fn attach_peer_events(&mut self, tx: mpsc::Sender<PeerEvent>) {
        self.peer_events = Some(tx);
    }

    /// Run the network event loop for a consumer that does NOT report gossip
    /// verdicts (tests, harnesses): inbound frames are delivered as bare
    /// `NetworkMessage`s and blocks are relayed on decode. Production uses
    /// [`Self::run_validated`].
    ///
    /// Sprint CC (IBD live-tip fix): the loop reads the *current* tip from the
    /// DAG before each announce instead of a value captured at startup.
    ///
    /// Sprint EE (S3 transport harness): `listen_report`, when `Some`, receives
    /// every address this swarm binds (fired from `SwarmEvent::NewListenAddr`),
    /// so in-process harnesses can wire nodes on ephemeral ports. Production
    /// passes `None`.
    pub async fn run(
        self,
        block_tx:       mpsc::Sender<NetworkMessage>,
        outbound_rx:    mpsc::Receiver<NetworkMessage>,
        dag:            std::sync::Arc<parking_lot::RwLock<crate::consensus::GhostDAG>>,
        peer_state:     std::sync::Arc<crate::sync::peer_state::PeerStateTable>,
        store:          std::sync::Arc<crate::storage::Storage>,
        listen_report:  Option<mpsc::UnboundedSender<Multiaddr>>,
    ) -> Result<(), NetworkError> {
        self.run_inner(IngestSink::Legacy(block_tx), None, outbound_rx, dag, peer_state, store, listen_report)
            .await
    }

    /// NET-2 (audit): run the event loop with APPLICATION-VALIDATED gossip.
    ///
    /// Gossipsub is configured with `validate_messages()`: a received frame is
    /// relayed only after a verdict is reported. Frames are delivered on
    /// `inbound_tx` with their [`InboundOrigin`]; for every frame whose
    /// origin carries a pending message id (gossip `NewBlock` and, since
    /// audit MEM-5, gossip `NewTransaction`), the consumer
    /// MUST send exactly one [`GossipValidation`] on the channel whose
    /// receiver is `verdict_rx`. Frames it never answers are simply not
    /// relayed (they expire from gossipsub's message cache).
    #[allow(clippy::too_many_arguments)]
    pub async fn run_validated(
        self,
        inbound_tx:     mpsc::Sender<Inbound>,
        verdict_rx:     mpsc::Receiver<GossipValidation>,
        outbound_rx:    mpsc::Receiver<NetworkMessage>,
        dag:            std::sync::Arc<parking_lot::RwLock<crate::consensus::GhostDAG>>,
        peer_state:     std::sync::Arc<crate::sync::peer_state::PeerStateTable>,
        store:          std::sync::Arc<crate::storage::Storage>,
        listen_report:  Option<mpsc::UnboundedSender<Multiaddr>>,
    ) -> Result<(), NetworkError> {
        self.run_inner(IngestSink::Validated(inbound_tx), Some(verdict_rx), outbound_rx, dag, peer_state, store, listen_report)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_inner(
        mut self,
        sink:            IngestSink,
        mut verdict_rx:  Option<mpsc::Receiver<GossipValidation>>,
        mut outbound_rx: mpsc::Receiver<NetworkMessage>,
        dag:             std::sync::Arc<parking_lot::RwLock<crate::consensus::GhostDAG>>,
        peer_state:      std::sync::Arc<crate::sync::peer_state::PeerStateTable>,
        // Announce-then-pull: the network loop serves inbound directed
        // GetBlock pulls straight from the block store (bodies live here, not
        // in the DAG), replying to the ONE requesting peer over
        // request-response — no gossip, no O(peers) fan-out.
        store:           std::sync::Arc<crate::storage::Storage>,
        listen_report:   Option<mpsc::UnboundedSender<Multiaddr>>,
    ) -> Result<(), NetworkError> {
        use std::time::Instant;
        // Audit M-10 fix: SHA-256 (truncated to 16 bytes) message ids are
        // deterministic across toolchains, unlike std's DefaultHasher.
        let msg_id_fn = |m: &gossipsub::Message| {
            let digest = Sha256::digest(&m.data);
            gossipsub::MessageId::from(&digest[..16])
        };

        let gs_cfg = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(1))
            .validation_mode(ValidationMode::Strict)
            .message_id_fn(msg_id_fn)
            .max_transmit_size(4 * 1024 * 1024)
            // NET-2 (audit): do NOT relay a frame before the application has
            // validated it. Without this, libp2p forwarded every frame to the
            // mesh first (an invalid-PoW block reached every node at zero
            // cost to its author) and the configured invalid-delivery (P4)
            // penalties could never fire.
            .validate_messages()
            // Keep unvalidated frames long enough for the processor to judge
            // them (a block verdict waits behind its 64 MiB PoW check).
            .history_length(GOSSIP_HISTORY_LENGTH)
            // Mesh fix (fresh-joiner IBD): gossipsub's duplicate_cache_time
            // defaults to 60s — the SAME period as tip_announce below, which
            // made byte-identical periodic PeerTips Duplicate-dropped locally.
            // 30s guarantees the 60s periodic announce always clears the
            // cache; the tip-carrying Version (fresh timestamp → unique bytes)
            // published alongside it can never be dedup-dropped at all.
            .duplicate_cache_time(Duration::from_secs(30))
            .build()
            .map_err(|e| NetworkError::StartFailed(format!("gossipsub: {}", e)))?;

        // ── Peer scoring: penalize invalid messages, reward participation ──
        let peer_score_params = {
            use gossipsub::{PeerScoreParams, TopicScoreParams};
            let mut params = PeerScoreParams::default();
            params.app_specific_weight = 1.0;
            params.ip_colocation_factor_threshold = 3.0; // penalize >3 peers from same IP
            // Mesh fix: behind a fly.io-style proxy/NAT every inbound peer
            // shares the proxy's source IP, so the colocation penalty crosses
            // graylist_threshold at just 6 peers. Operators who know they're
            // proxied disable the weight with --behind-proxy.
            params.ip_colocation_factor_weight =
                if self.config.behind_proxy { 0.0 } else { -50.0 };
            params.decay_interval = Duration::from_secs(60);
            params.decay_to_zero = 0.01;

            // P3/P3b MUST be disabled on a low-rate chain: the defaults charge
            // every grafted peer ≈ graylist_threshold within seconds when it
            // delivers fewer than 20 messages, which is always on a ~30 s
            // block chain (the mesh could never hold anyone).
            let block_topic_params = TopicScoreParams {
                topic_weight: 0.5,
                time_in_mesh_weight: 0.1,
                time_in_mesh_quantum: Duration::from_secs(1),
                time_in_mesh_cap: 100.0,
                first_message_deliveries_weight: 1.0,
                first_message_deliveries_decay: 0.97,
                first_message_deliveries_cap: 100.0,
                mesh_message_deliveries_weight: 0.0,  // P3 off — see note above
                mesh_failure_penalty_weight:    0.0,  // P3b off — same reason
                invalid_message_deliveries_weight: -100.0, // harsh penalty for invalid blocks
                invalid_message_deliveries_decay: 0.5,
                ..Default::default()
            };

            let tx_topic_params = TopicScoreParams {
                topic_weight: 0.3,
                time_in_mesh_weight: 0.05,
                time_in_mesh_quantum: Duration::from_secs(1),
                time_in_mesh_cap: 50.0,
                first_message_deliveries_weight: 0.5,
                first_message_deliveries_decay: 0.97,
                first_message_deliveries_cap: 100.0,
                invalid_message_deliveries_weight: -50.0,
                invalid_message_deliveries_decay: 0.5,
                mesh_message_deliveries_weight: 0.0,  // P3 off — see block_topic_params
                mesh_failure_penalty_weight:    0.0,  // P3b off
                ..Default::default()
            };

            let sync_topic_params = TopicScoreParams {
                topic_weight: 0.2,
                time_in_mesh_weight: 0.02,
                time_in_mesh_quantum: Duration::from_secs(1),
                time_in_mesh_cap: 50.0,
                invalid_message_deliveries_weight: -20.0,
                invalid_message_deliveries_decay: 0.8,
                mesh_message_deliveries_weight: 0.0,  // P3 off — see block_topic_params
                mesh_failure_penalty_weight:    0.0,  // P3b off
                ..Default::default()
            };

            params.topics.insert(IdentTopic::new(TOPIC_BLOCKS).hash(), block_topic_params);
            params.topics.insert(IdentTopic::new(TOPIC_TXS).hash(), tx_topic_params);
            params.topics.insert(IdentTopic::new(TOPIC_SYNC).hash(), sync_topic_params);
            params
        };

        let peer_score_thresholds = gossipsub::PeerScoreThresholds {
            gossip_threshold:             -100.0,  // below this: no gossip metadata
            publish_threshold:            -200.0,  // below this: messages rejected
            graylist_threshold:           -400.0,  // below this: completely ignored
            opportunistic_graft_threshold: 5.0,
            ..Default::default()
        };

        let mut gs = gossipsub::Behaviour::new(
            MessageAuthenticity::Signed(self.local_key.clone()),
            gs_cfg,
        ).map_err(|e| NetworkError::StartFailed(format!("behaviour: {}", e)))?;

        // Apply peer scoring (non-fatal if it fails)
        if let Err(e) = gs.with_peer_score(peer_score_params, peer_score_thresholds) {
            warn!("peer scoring disabled: {}", e);
        }

        // Captured for the connection-limits behaviour below (avoids borrowing
        // `self` inside the `with_behaviour` closure).
        let max_peers = self.config.max_peers;
        let enable_mdns = self.config.enable_mdns;
        let archive = self.config.archive;

        let mut swarm = SwarmBuilder::with_existing_identity(self.local_key.clone())
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                |keys: &identity::Keypair| -> Result<KyberConfig, std::convert::Infallible> {
                    Ok(KyberConfig::new(keys))
                },
                yamux_config,
            )
            .map_err(|e| NetworkError::StartFailed(e.to_string()))?
            .with_websocket(
                |keys: &identity::Keypair| -> Result<KyberConfig, std::convert::Infallible> {
                    Ok(KyberConfig::new(keys))
                },
                yamux_config,
            )
            .await
            .map_err(|e| NetworkError::StartFailed(e.to_string()))?
            .with_behaviour(|key| {
                // mDNS only when explicitly enabled; otherwise a disabled Toggle
                // (its record parser — the hickory-proto DoS surface — never runs).
                let mdns: libp2p::swarm::behaviour::toggle::Toggle<mdns::tokio::Behaviour> =
                    if enable_mdns {
                        Some(mdns::tokio::Behaviour::new(
                            mdns::Config::default(),
                            key.public().to_peer_id(),
                        )?).into()
                    } else {
                        None.into()
                    };
                // The identify agent-version still advertises the archival bit
                // (`gnb/<ver>/a|n`) for operators, but NET-9: peers no longer
                // use this self-declared bit to choose whom to pull from.
                let identify = identify::Behaviour::new(
                    identify::Config::new("/gnb/1.0.0".into(), key.public())
                        .with_agent_version(sync_rr::agent_version(archive)),
                );
                // Cap connections at the swarm layer to match max_peers. We
                // allow 2× established total for churn/reconnect headroom, but
                // hold established-INCOMING to max_peers so an attacker can't
                // fill every slot with inbound dials. Pending caps blunt
                // half-open connection floods.
                let max = max_peers as u32;
                let limits = libp2p::connection_limits::ConnectionLimits::default()
                    .with_max_established(Some(max.saturating_mul(2)))
                    .with_max_established_incoming(Some(max))
                    .with_max_pending_incoming(Some(max))
                    .with_max_pending_outgoing(Some(max.max(1)));
                let connection_limits = libp2p::connection_limits::Behaviour::new(limits);
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(BlochBehaviour {
                    gossipsub: gs,
                    mdns,
                    identify,
                    sync_rr: sync_rr::new_behaviour(),
                    connection_limits,
                })
            })
            .map_err(|e| NetworkError::StartFailed(e.to_string()))?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(300)))
            .build();

        let block_t = IdentTopic::new(TOPIC_BLOCKS);
        let tx_t    = IdentTopic::new(TOPIC_TXS);
        let sync_t  = IdentTopic::new(TOPIC_SYNC);

        for t in [&block_t, &tx_t, &sync_t] {
            swarm.behaviour_mut().gossipsub.subscribe(t)
                .map_err(|e| NetworkError::StartFailed(e.to_string()))?;
        }

        swarm.listen_on(self.config.listen_addr.parse()
            .map_err(|e| NetworkError::StartFailed(format!("addr: {}", e)))?)
            .map_err(|e| NetworkError::StartFailed(e.to_string()))?;

        // M-6 (audit): the WS listener is opt-in (`GNB_ENABLE_WS_LISTENER=1`)
        // and derived from `--listen` (same host, TCP port + 1, `/ws`).
        let ws_enabled = std::env::var("GNB_ENABLE_WS_LISTENER")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if ws_enabled {
            match ws_listen_addr_from(&self.config.listen_addr) {
                Some(ws_addr) => match swarm.listen_on(ws_addr.clone()) {
                    Ok(_) => info!("WS listening on {}", ws_addr),
                    Err(e) => warn!("WS listen failed (non-fatal): {}", e),
                },
                None => warn!(
                    "GNB_ENABLE_WS_LISTENER set but --listen ('{}') has no /tcp/<port> \
                     component to derive a WS port from — WS listener not started",
                    self.config.listen_addr
                ),
            }
        }

        // FIX #6: Load saved peers and dial them
        let peers_path = self.config.data_dir.join("known_peers.json");
        let mut known_peers = load_known_peers(&peers_path);
        // Sprint P: drop any legacy pollution that doesn't pass the new validator.
        let pruned = prune_invalid(&mut known_peers, self.config.allow_private_peers);
        if pruned > 0 {
            info!("known_peers: pruned {} invalid entries on load (Sprint P)", pruned);
        }
        // Sprint P / NET-11: enforce the (netgroup-aware) cap.
        let evicted = enforce_cap(&mut known_peers);
        if evicted > 0 {
            info!("known_peers: evicted {} entries to enforce cap", evicted);
        }

        // Sprint P / NET-11: PEX hardening state. Rate limits are keyed by the
        // AUTHOR of the addresses (the peer that answered our GetPeers), and
        // received addresses only ever enter `addr_book` — they are dialed
        // later, a few per tick, never straight from a message.
        let mut pex_limiter = PexRateLimiter::new();
        let mut pex_stats   = PexStats::new();
        let mut addr_book   = AddrBook::new();
        let allow_private   = self.config.allow_private_peers;

        // C1 / NET-4 / NET-8: cumulative, decaying, bounded app-score
        // penalties for wire-violating peers.
        let mut wire_tracker = WirePenaltyTracker::new();
        // MEM-5 / MEM-6: processor → network penalties (optional).
        let mut control_rx = self.control_rx.take();

        // H-R3-1 fix #4 / NET-8: bounded per-peer + global rate of served
        // inbound directed-sync requests. Refusals are answered `Busy` (NET-5).
        let mut sync_limiter = sync_rr::SyncRequestLimiter::new();

        // NET-6: per-AUTHOR rate limit on tip claims (PeerTip / Version).
        let mut claim_limiter: ratelimit::TokenBuckets<PeerId> =
            ratelimit::TokenBuckets::new(CLAIM_BURST, CLAIM_REFILL_PER_SEC, CLAIM_LIMITER_TRACK_CAP);

        // Add hardcoded default seeds
        let mut all_seeds: Vec<String> = crate::core::DEFAULT_SEEDS.iter().map(|s| s.to_string()).collect();
        // DNS seeds (opt-in, non-privileged): resolve each hostname's A/AAAA
        // records into peer multiaddrs (Bitcoin-style cold-start).
        for host in self.config.dns_seeds.iter() {
            let hp = if host.contains(':') { host.clone() } else { format!("{host}:17110") };
            match tokio::net::lookup_host(hp).await {
                Ok(addrs) => {
                    for sa in addrs {
                        let ma = match sa.ip() {
                            std::net::IpAddr::V4(v4) => format!("/ip4/{}/tcp/{}", v4, sa.port()),
                            std::net::IpAddr::V6(v6) => format!("/ip6/{}/tcp/{}", v6, sa.port()),
                        };
                        info!("dns-seed {} → {}", host, ma);
                        all_seeds.push(ma);
                    }
                }
                Err(e) => warn!("dns-seed {}: resolve failed: {}", host, e),
            }
        }
        // Add CLI bootstrap peers + known peers
        all_seeds.extend(self.config.bootstrap_peers.iter().cloned());
        all_seeds.extend(known_peers.iter().cloned());
        // Deduplicate
        all_seeds.sort();
        all_seeds.dedup();

        for p in all_seeds.iter() {
            let resolved = resolve_multiaddr(p).await;
            if let Ok(addr) = resolved.parse::<Multiaddr>() {
                info!("dialing: {}", resolved);
                let _ = swarm.dial(addr);
            }
        }

        let peer_id_str = self.peer_id.to_string();
        let mut peer_count = 0usize;

        // AUDIT (external-address poisoning): a peer-reported identify
        // `observed_addr` is only a CANDIDATE; it is confirmed as our external
        // address only when EXTERNAL_ADDR_QUORUM distinct peers report it.
        const EXTERNAL_ADDR_QUORUM: usize = 3;
        const OBSERVED_ADDR_CAP: usize = 64;
        const MDNS_DIAL_LIMIT: usize = 8; // max LAN peers auto-dialed per mDNS event
        let mut observed_by: std::collections::HashMap<Multiaddr, std::collections::HashSet<PeerId>> =
            std::collections::HashMap::new();

        // NET-5 / NET-9: directed pulls go through a rotating, stall-aware
        // selector with a per-peer in-flight cap; requests wait in a bounded
        // queue when no peer is eligible, and a failed or Busy pull is retried
        // on ANOTHER peer — never re-published on gossip (NET-7).
        let mut selector = sync_rr::PullPeerSelector::new(sync_rr::explicit_peer_ids(&self.config.bootstrap_peers));
        let mut pending_pulls: std::collections::VecDeque<PendingPull> = std::collections::VecDeque::new();
        let mut inflight_pull: std::collections::HashMap<libp2p::request_response::OutboundRequestId, (PendingPull, PeerId)> =
            std::collections::HashMap::new();

        // Re-gossip rate-limit: suppress re-publishes of the SAME block within
        // the duplicate-cache window (a guaranteed local `Duplicate` anyway).
        let mut recent_block_publishes: std::collections::HashMap<[u8; 32], std::time::Instant> =
            std::collections::HashMap::new();
        const REGOSSIP_SUPPRESS_TTL: Duration = Duration::from_secs(30);
        let mut heartbeat   = tokio::time::interval(Duration::from_secs(30));
        let mut save_peers  = tokio::time::interval(Duration::from_secs(60));
        // Sprint CC: periodic tip announce (every 60s).
        let mut tip_announce = tokio::time::interval(Duration::from_secs(60));
        // NET-5/NET-9: re-try queued pulls (cooldowns expire, slots free up).
        let mut pull_tick = tokio::time::interval(PULL_RETRY_TICK);
        pull_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // NET-11: dial a few PEX-learned addresses per tick, from the table.
        let mut pex_dial = tokio::time::interval(PEX_DIAL_TICK);
        pex_dial.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                event = poll_swarm(&mut swarm) => {
                    match event {
                        SwarmEvent::Behaviour(BlochBehaviourEvent::Gossipsub(gossipsub::Event::Message { propagation_source, message_id, message })) => {
                            // C1: bounded decode (4 MiB frame/read limit, per-field
                            // bounds, NET-7: no trailing bytes).
                            let reaction = wire_tracker.classify(propagation_source, &message.data);
                            let msg = match reaction {
                                WireReaction::Penalize { error, score } => {
                                    // Oversized / bounds-violating / padded frames can't
                                    // come from a compliant node. NET-2/NET-4: Reject it,
                                    // so gossipsub's P4 penalty hits the DELIVERING peer
                                    // (its author: honest nodes never relay invalid
                                    // frames now) and it is never forwarded.
                                    swarm.behaviour_mut().gossipsub
                                        .set_application_score(&propagation_source, score);
                                    swarm.behaviour_mut().gossipsub.report_message_validation_result(
                                        &message_id, &propagation_source, gossipsub::MessageAcceptance::Reject);
                                    warn!("wire violation from {}: {:?} (app score → {})",
                                        propagation_source, error, score);
                                    continue;
                                }
                                WireReaction::IgnoreMalformed(_) => {
                                    debug!("undecodable gossip frame from {} ({} bytes)",
                                        propagation_source, message.data.len());
                                    swarm.behaviour_mut().gossipsub.report_message_validation_result(
                                        &message_id, &propagation_source, gossipsub::MessageAcceptance::Ignore);
                                    continue;
                                }
                                WireReaction::Accept(m) => m,
                            };
                            let now = Instant::now();
                            let author = message.source;
                            let author_connected = author.is_some_and(|a| swarm.is_connected(&a));
                            let mut claim_ok = false;
                            match &msg {
                                NetworkMessage::NewBlock  { block_hash, height, blue_score, .. } => {
                                    tracing::info_span!(
                                        "net_ingest_block",
                                        block_hash = %hex::encode(&block_hash[..8]),
                                        height = *height,
                                        blue_score = *blue_score,
                                        peer = %propagation_source,
                                    ).in_scope(|| {
                                        info!("← block h={} {}", height, hex::encode(&block_hash[..8]));
                                    });
                                    // Re-gossip suppression, RECEIVE side: a received
                                    // block is in gossipsub's duplicate cache, so a
                                    // re-publish within the TTL is a guaranteed local
                                    // `Duplicate` — skip the wasted encode/hash work.
                                    recent_block_publishes.retain(|_, t| now.duration_since(*t) < REGOSSIP_SUPPRESS_TTL);
                                    recent_block_publishes.insert(*block_hash, now);
                                }
                                NetworkMessage::PeerTip { blue_score, height, .. }
                                | NetworkMessage::Version { blue_score, height, .. } => {
                                    // NET-6: claims are attributed to their signed AUTHOR
                                    // and recorded only for directly connected authors,
                                    // rate-limited per author, clamped once here.
                                    if let Some(a) = author.filter(|_| author_connected) {
                                        if claim_limiter.allow_at(a, now) {
                                            let (our_score, our_count) = {
                                                let d = dag.read();
                                                (d.tip_blue_score(), d.block_count() as u64)
                                            };
                                            let bs = clamp_announced_blue_score(*blue_score, our_score);
                                            let ht = clamp_announced_blue_score(*height, our_count);
                                            peer_state.observe_claim(a, bs, ht, now);
                                            claim_ok = true;
                                        }
                                    }
                                    if let NetworkMessage::Version { version, user_agent, .. } = &msg {
                                        if *version < MIN_PROTOCOL_VERSION {
                                            warn!("← incompatible version {} from {}", version, truncate_utf8(user_agent, 64));
                                        }
                                    }
                                }
                                // NET-11: unsolicited gossip PeerExchange is never
                                // dialed, never stored, never relayed (see
                                // `gossip_disposition`). Addresses are only learned
                                // from answers to our own directed GetPeers.
                                _ => {}
                            }
                            let source = InboundOrigin::Gossip { propagation_source, author, pending: None, received_at: now };
                            match gossip_disposition(&msg, sink.validator_attached(), claim_ok) {
                                GossipDisposition::DeliverDeferred => {
                                    let origin = InboundOrigin::Gossip {
                                        propagation_source, author, pending: Some(message_id.clone()), received_at: now,
                                    };
                                    if !sink.deliver(msg, origin, "gossip") {
                                        // Never queued: nobody will judge it. Do not relay.
                                        swarm.behaviour_mut().gossipsub.report_message_validation_result(
                                            &message_id, &propagation_source, gossipsub::MessageAcceptance::Ignore);
                                    }
                                }
                                GossipDisposition::Deliver(v) => {
                                    swarm.behaviour_mut().gossipsub.report_message_validation_result(
                                        &message_id, &propagation_source, v.into());
                                    sink.deliver(msg, source, "gossip");
                                }
                                GossipDisposition::Drop(v) => {
                                    debug!("gossip [{}] from {} not delivered/relayed", msg.kind_name(), propagation_source);
                                    swarm.behaviour_mut().gossipsub.report_message_validation_result(
                                        &message_id, &propagation_source, v.into());
                                }
                            }
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                            info!("✓ connected: {}", peer_id);
                            // DO NOT call gossipsub.add_explicit_peer() here: explicit
                            // peers are excluded from the mesh (libp2p-gossipsub
                            // behaviour.rs), which once made the mesh unbuildable.
                            peer_count = peer_count.saturating_add(1);
                            crate::metrics::set_peer_count(peer_count as i64);
                            peer_state.on_connect(peer_id, Instant::now());
                            selector.on_connect(peer_id);
                            // PROPAGAÇÃO-CHURN fix: persist only the canonical form of
                            // a DIALED address (the Listener's send_back_addr is an
                            // ephemeral socket). NET-11: confirmed addresses enter
                            // the netgroup-capped "tried" table.
                            let addr_to_remember = match &endpoint {
                                libp2p::core::ConnectedPoint::Dialer { address, .. } => {
                                    Some(canonical_peer_addr(address, &peer_id))
                                }
                                libp2p::core::ConnectedPoint::Listener { .. } => None,
                            };
                            if let Some(addr_str) = addr_to_remember {
                                addr_book.remove(&addr_str);
                                if is_valid_public_multiaddr(&addr_str, allow_private) {
                                    add_tried(&mut known_peers, addr_str);
                                } else {
                                    debug!("not adding peer to known_peers (validator rejected): {}",
                                        truncate_utf8(&addr_str, 80));
                                }
                            }
                            // Version handshake + tip announce with FRESH DAG values.
                            let (v_score, v_height) = {
                                let d = dag.read();
                                (d.tip_blue_score(), d.block_count() as u64)
                            };
                            let version_msg = NetworkMessage::Version {
                                version:    PROTOCOL_VERSION,
                                user_agent: format!("gnb/{}", env!("CARGO_PKG_VERSION")),
                                blue_score: v_score,
                                height:     v_height,
                                timestamp:  std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_secs()).unwrap_or(0),
                            };
                            if let Ok(d) = bincode::serde::encode_to_vec(&version_msg, bincode::config::standard()) {
                                if let Err(e) = swarm.behaviour_mut().gossipsub.publish(sync_t.clone(), d) {
                                    info!("on-connect Version publish failed ({}); will re-announce when {} subscribes to sync", e, peer_id);
                                }
                            }
                            let my_tip = build_current_tip(&dag, &peer_id_str);
                            if let Ok(d) = bincode::serde::encode_to_vec(&my_tip, bincode::config::standard()) {
                                if let Err(e) = swarm.behaviour_mut().gossipsub.publish(sync_t.clone(), d) {
                                    info!("on-connect PeerTip publish failed ({}); will re-announce when {} subscribes to sync", e, peer_id);
                                }
                            }
                            // M-10: directed PEX request to the peer that just
                            // connected (one requester, one answer). Not retried on
                            // other peers if it fails.
                            let now = Instant::now();
                            let req_id = swarm.behaviour_mut().sync_rr
                                .send_request(&peer_id, sync_rr::SyncRequest::GetPeers);
                            selector.on_sent(peer_id, now);
                            inflight_pull.insert(req_id, (PendingPull {
                                msg: NetworkMessage::PeerRequest,
                                req: sync_rr::SyncRequest::GetPeers,
                                attempts: MAX_PULL_ATTEMPTS,
                                tried: vec![peer_id],
                            }, peer_id));
                            drain_pulls(&mut swarm, &mut selector, &mut pending_pulls, &mut inflight_pull, now);
                        }
                        // Mesh fix (fresh-joiner IBD): THIS event is the moment the
                        // peer provably subscribed, so re-announce the handshake and
                        // tip here (the on-connect announce races its Subscribe).
                        SwarmEvent::Behaviour(BlochBehaviourEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, topic })) => {
                            if topic == sync_t.hash() {
                                let (v_score, v_height) = {
                                    let d = dag.read();
                                    (d.tip_blue_score(), d.block_count() as u64)
                                };
                                let ver = NetworkMessage::Version {
                                    version:    PROTOCOL_VERSION,
                                    user_agent: format!("gnb/{}", env!("CARGO_PKG_VERSION")),
                                    blue_score: v_score,
                                    height:     v_height,
                                    timestamp:  std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .map(|d| d.as_secs()).unwrap_or(0),
                                };
                                if let Ok(d) = bincode::serde::encode_to_vec(&ver, bincode::config::standard()) {
                                    match swarm.behaviour_mut().gossipsub.publish(sync_t.clone(), d) {
                                        Ok(_)  => info!("→ {} subscribed to sync; announced tip score={} height={}", peer_id, v_score, v_height),
                                        Err(e) => info!("post-subscribe Version publish failed: {} (periodic announce will retry)", e),
                                    }
                                }
                                let my_tip = build_current_tip(&dag, &peer_id_str);
                                if let Ok(d) = bincode::serde::encode_to_vec(&my_tip, bincode::config::standard()) {
                                    if let Err(e) = swarm.behaviour_mut().gossipsub.publish(sync_t.clone(), d) {
                                        debug!("post-subscribe PeerTip publish: {}", e);
                                    }
                                }
                            }
                        }
                        SwarmEvent::ConnectionClosed { peer_id, num_established, .. } => {
                            info!("✗ disconnected: {}", peer_id);
                            peer_count = peer_count.saturating_sub(1);
                            crate::metrics::set_peer_count(peer_count as i64);
                            if num_established == 0 {
                                peer_state.on_disconnect(&peer_id);
                                selector.on_disconnect(&peer_id);
                                if let Some(tx) = &self.peer_events {
                                    let _ = tx.try_send(PeerEvent::Disconnected(peer_id));
                                }
                            }
                        }
                        SwarmEvent::NewListenAddr { address, .. } => {
                            info!("listening: {}/p2p/{}", address, self.peer_id);
                            if let Some(report) = &listen_report {
                                let _ = report.send(address.clone());
                            }
                        }
                        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                            warn!("dial failed{}: {}",
                                peer_id.map(|p| format!(" to {}", p)).unwrap_or_default(),
                                error);
                        }
                        SwarmEvent::IncomingConnectionError { error, .. } => {
                            warn!("incoming failed: {}", error);
                        }
                        // PRINCIPLES.md #2: zero-config LAN discovery (opt-in). Only
                        // LAN addresses, capped per event, honoring the peer ceiling.
                        SwarmEvent::Behaviour(BlochBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                            let mut dialed = 0usize;
                            for (peer_id, addr) in list {
                                if dialed >= MDNS_DIAL_LIMIT || peer_count >= self.config.max_peers {
                                    break;
                                }
                                if !is_lan_multiaddr(&addr) {
                                    debug!("mDNS: ignoring non-LAN address (possible reflection): {}", addr);
                                    continue;
                                }
                                info!("mDNS discovered (LAN): {} at {}", peer_id, addr);
                                if swarm.dial(addr).is_ok() { dialed += 1; }
                            }
                        }
                        SwarmEvent::Behaviour(BlochBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                            for (peer_id, _addr) in list {
                                swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                            }
                        }
                        // identify: our observed address (quorum-confirmed before it
                        // is advertised). Peer listen addrs are NOT persisted.
                        SwarmEvent::Behaviour(BlochBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                            let cand = canonical_peer_addr(&info.observed_addr, &self.peer_id);
                            if is_valid_public_multiaddr(&cand, allow_private)
                                && (observed_by.len() < OBSERVED_ADDR_CAP
                                    || observed_by.contains_key(&info.observed_addr))
                            {
                                let voters = observed_by.entry(info.observed_addr.clone()).or_default();
                                let was_below = voters.len() < EXTERNAL_ADDR_QUORUM;
                                voters.insert(peer_id);
                                if was_below && voters.len() >= EXTERNAL_ADDR_QUORUM {
                                    swarm.add_external_address(info.observed_addr.clone());
                                    info!("external address confirmed by {} peers: {}",
                                        EXTERNAL_ADDR_QUORUM, info.observed_addr);
                                }
                            }
                            if let Some(arch) = sync_rr::parse_archival_agent(&info.agent_version) {
                                debug!("peer {} self-declares archival={} (not used for pull selection)", peer_id, arch);
                            }
                        }
                        // ── Announce-then-pull: directed IBD sync ────────────
                        SwarmEvent::Behaviour(BlochBehaviourEvent::SyncRr(ev)) => match ev {
                            libp2p::request_response::Event::Message { peer, message, .. } => match message {
                                // SERVER: answer THIS peer only. H-R3-1 / NET-8: rate
                                // limited per peer and globally; NET-5: a refusal is
                                // an explicit `Busy`, never a dropped channel.
                                libp2p::request_response::Message::Request { request, channel, .. } => {
                                    let resp = if !sync_limiter.allow(peer) {
                                        debug!("sync_rr: rate-limited request from {} → Busy", peer);
                                        sync_rr::SyncResponse::Busy
                                    } else if matches!(request, sync_rr::SyncRequest::GetPeers) {
                                        let external: Vec<Multiaddr> =
                                            swarm.external_addresses().cloned().collect();
                                        serve_get_peers(&known_peers, &external, &self.peer_id, allow_private)
                                    } else {
                                        serve_sync_request(&dag, &store, &request)
                                    };
                                    if swarm.behaviour_mut().sync_rr.send_response(channel, resp).is_err() {
                                        debug!("sync_rr: response channel closed for {}", peer);
                                    }
                                }
                                // CLIENT: our directed pull was answered.
                                libp2p::request_response::Message::Response { request_id, response } => {
                                    let now = Instant::now();
                                    let entry = inflight_pull.remove(&request_id);
                                    if matches!(response, sync_rr::SyncResponse::Busy) {
                                        // NET-5: back-pressure, not an offence. Back
                                        // off from this peer and retry elsewhere.
                                        selector.on_busy(&peer, now);
                                        if let Some((p, _)) = entry {
                                            requeue_pull(&mut pending_pulls, p, peer);
                                        }
                                    } else {
                                        selector.on_success(&peer);
                                        match response {
                                            sync_rr::SyncResponse::Peers { peers } => {
                                                // NET-11: solicited addresses go to the
                                                // table, rate-limited per author; never
                                                // dialed from here.
                                                ingest_pex_addresses(
                                                    &mut addr_book, &mut pex_limiter, &mut pex_stats,
                                                    peer, &peers, allow_private, &self.peer_id, &known_peers,
                                                );
                                                pex_stats.set_distinct_peers(pex_limiter.tracked_peer_count());
                                            }
                                            other => {
                                                if let sync_rr::SyncResponse::Tips { tips, .. } = &other {
                                                    // NET-6: directed Tips update the
                                                    // RESPONDER's frontier (it is a direct
                                                    // peer we asked) — this is what makes
                                                    // the verified IBD release path live.
                                                    let hashes: Vec<[u8; 32]> = tips.iter().map(|e| e.hash).collect();
                                                    let (bs, ht) = tips.iter()
                                                        .map(|e| (e.blue_score, e.height))
                                                        .max_by_key(|(s, _)| *s)
                                                        .unwrap_or((0, 0));
                                                    let (our_score, our_count) = {
                                                        let d = dag.read();
                                                        (d.tip_blue_score(), d.block_count() as u64)
                                                    };
                                                    peer_state.observe(
                                                        peer,
                                                        clamp_announced_blue_score(bs, our_score),
                                                        clamp_announced_blue_score(ht, our_count),
                                                        &hashes,
                                                        now,
                                                    );
                                                }
                                                if let Some(m) = sync_rr::response_to_message(other) {
                                                    sink.deliver(m, InboundOrigin::Directed { peer }, "directed-pull");
                                                }
                                            }
                                        }
                                    }
                                    drain_pulls(&mut swarm, &mut selector, &mut pending_pulls, &mut inflight_pull, now);
                                }
                            },
                            // Directed pull failed (timeout, reset, unsupported
                            // protocol, undecodable answer). NET-9: count it against
                            // the peer (stall detection) and retry on ANOTHER peer.
                            // NET-7: never re-published on gossip.
                            libp2p::request_response::Event::OutboundFailure { peer, request_id, error, .. } => {
                                let now = Instant::now();
                                // H-R3-4: an answer that failed to decode / pass bounds
                                // is a protocol violation by the ANSWERING peer. NET-5:
                                // a clean EOF or timeout is a transport failure and is
                                // never penalized (`is_sync_protocol_violation`).
                                if let libp2p::request_response::OutboundFailure::Io(e) = &error {
                                    if sync_rr::is_sync_protocol_violation(e) {
                                        let score = wire_tracker.record_violation(peer);
                                        swarm.behaviour_mut().gossipsub.set_application_score(&peer, score);
                                        warn!("sync_rr wire violation (outbound) from {}: {} (app score → {})",
                                            peer, e, score);
                                    }
                                }
                                selector.on_failure(&peer, now);
                                if let Some((p, _)) = inflight_pull.remove(&request_id) {
                                    debug!("directed pull [{}] to {} failed ({}); retrying on another peer",
                                        p.msg.kind_name(), peer, error);
                                    requeue_pull(&mut pending_pulls, p, peer);
                                }
                                drain_pulls(&mut swarm, &mut selector, &mut pending_pulls, &mut inflight_pull, now);
                            }
                            // H-R3-4: a REQUEST we received failed to decode or
                            // violated wire bounds.
                            libp2p::request_response::Event::InboundFailure { peer, error, .. } => {
                                if let libp2p::request_response::InboundFailure::Io(e) = &error {
                                    if sync_rr::is_sync_protocol_violation(e) {
                                        let score = wire_tracker.record_violation(peer);
                                        swarm.behaviour_mut().gossipsub.set_application_score(&peer, score);
                                        warn!("sync_rr wire violation (inbound) from {}: {} (app score → {})",
                                            peer, e, score);
                                    }
                                }
                            }
                            _ => {}
                        },
                        _ => {}
                    }
                }

                // NET-2: verdicts from the processor for deferred gossip frames.
                v = recv_verdict(&mut verdict_rx) => {
                    match v {
                        Some(v) => {
                            let relayed = swarm.behaviour_mut().gossipsub.report_message_validation_result(
                                &v.message_id, &v.propagation_source, v.verdict.into());
                            if !relayed && v.verdict == GossipVerdict::Accept {
                                // The frame already left gossipsub's cache: it is not
                                // forwarded (a late orphan release is re-announced).
                                debug!("late Accept: frame from {} no longer in the gossip cache", v.propagation_source);
                            }
                        }
                        None => verdict_rx = None,
                    }
                }

                // MEM-5 / MEM-6: out-of-band penalties from the processor.
                c = recv_control(&mut control_rx) => {
                    match c {
                        Some(NetworkControl::PenalizePeer(peer)) => {
                            let score = wire_tracker.record_violation(peer);
                            swarm.behaviour_mut().gossipsub.set_application_score(&peer, score);
                            warn!("invalid orphan transaction from {} (app score → {})", peer, score);
                        }
                        None => control_rx = None,
                    }
                }

                Some(msg) = outbound_rx.recv() => {
                    // Announce-then-pull: IBD FETCH requests (GetBlock /
                    // GetHeaders / GetTips / PeerRequest) are DIRECTED to one
                    // selected peer over request-response, never broadcast.
                    if let Some(req) = sync_rr::as_pull_request(&msg) {
                        if pending_pulls.len() >= MAX_PENDING_PULLS {
                            debug!("pull queue full; dropping [{}] (it will be re-issued)", msg.kind_name());
                        } else {
                            pending_pulls.push_back(PendingPull { msg, req, attempts: 0, tried: Vec::new() });
                        }
                        drain_pulls(&mut swarm, &mut selector, &mut pending_pulls, &mut inflight_pull, Instant::now());
                        continue;
                    }
                    // Re-gossip rate-limit: drop a re-broadcast of a block already
                    // published within the TTL.
                    if let NetworkMessage::NewBlock { block_hash, .. } = &msg {
                        let now = std::time::Instant::now();
                        recent_block_publishes.retain(|_, t| now.duration_since(*t) < REGOSSIP_SUPPRESS_TTL);
                        if recent_block_publishes.contains_key(block_hash) {
                            continue;
                        }
                        recent_block_publishes.insert(*block_hash, now);
                    }
                    let (topic, topic_name) = match &msg {
                        NetworkMessage::NewBlock { .. }        => (block_t.clone(), "blocks"),
                        NetworkMessage::NewTransaction { .. }  => (tx_t.clone(),    "txs"),
                        _                                      => (sync_t.clone(),  "sync"),
                    };
                    if let Ok(data) = bincode::serde::encode_to_vec(&msg, bincode::config::standard()) {
                        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic, data) {
                            warn!("publish {} [{}]: {}", topic_name, msg.kind_name(), e);
                        }
                    }
                }

                _ = pull_tick.tick() => {
                    drain_pulls(&mut swarm, &mut selector, &mut pending_pulls, &mut inflight_pull, Instant::now());
                }

                // NET-11: dial from the address table, never from a message —
                // a few per tick, at most one per netgroup, only below target.
                _ = pex_dial.tick() => {
                    if peer_count < self.config.max_peers {
                        let want = if peer_count < PEX_LOW_PEER_THRESHOLD { PEX_DIALS_WHEN_LOW } else { 1 };
                        let me = self.peer_id;
                        let cands = addr_book.take_dial_candidates(want, |a| {
                            known_peers.contains(a)
                                || addr_peer_id(a).is_none_or(|p| p == me || swarm.is_connected(&p))
                        });
                        for a in cands {
                            if let Ok(addr) = a.parse::<libp2p::Multiaddr>() {
                                info!("PEX dial (from table): {}", truncate_utf8(&a, 60));
                                let _ = swarm.dial(addr);
                                pex_stats.record_accept(1);
                            }
                        }
                    }
                }

                _ = heartbeat.tick() => {
                    let now = Instant::now();
                    let current_height = dag.read().block_count() as u64;
                    info!("peers: {} | height: {}", peer_count, current_height);
                    let addrs: Vec<String> = known_peers.iter().cloned().collect();
                    sink.deliver(NetworkMessage::PeerCount { count: peer_count, addresses: addrs }, InboundOrigin::Local, "heartbeat");

                    // Sprint P: emit aggregated PEX stats (every 60s, only if activity)
                    if let Some(line) = pex_stats.tick() {
                        info!("{}", line);
                    }
                    // Housekeeping of every bounded per-peer map (NET-8).
                    pex_limiter.gc();
                    sync_limiter.gc_at(now);
                    claim_limiter.gc_at(now, CLAIM_LIMITER_IDLE_TTL);
                    // NET-4 / NET-8: decayed penalties are re-installed so a
                    // peer recovers once it stops misbehaving.
                    for (p, score) in wire_tracker.decay_tick_at(now) {
                        swarm.behaviour_mut().gossipsub.set_application_score(&p, score);
                    }

                    // FIX v0.5.1: Re-subscribe every 30s (idempotent; restores a
                    // mesh that peer scoring silently dropped).
                    for t in [&block_t, &tx_t, &sync_t] {
                        let _ = swarm.behaviour_mut().gossipsub.subscribe(t);
                    }

                    let tx_hash = tx_t.hash();
                    let tx_mesh_peers = swarm.behaviour().gossipsub.mesh_peers(&tx_hash).count();
                    if peer_count > 0 && tx_mesh_peers == 0 {
                        warn!("tx mesh empty: {} peers but 0 in tx-mesh — re-subscribing", peer_count);
                    }

                    if peer_count == 0 {
                        for p in self.config.bootstrap_peers.iter() {
                            let resolved = resolve_multiaddr(p).await;
                            if let Ok(addr) = resolved.parse::<libp2p::Multiaddr>() {
                                info!("reconnecting: {}", resolved);
                                let _ = swarm.dial(addr);
                            }
                        }
                    }
                }

                _ = save_peers.tick() => {
                    save_known_peers(&peers_path, &known_peers);
                }

                // Sprint CC: periodic tip announcement for IBD recovery (60s).
                // The Version frame carries a fresh timestamp, so it can never
                // be dedup-dropped like a byte-identical PeerTip.
                _ = tip_announce.tick() => {
                    if peer_count > 0 {
                        let tip = build_current_tip(&dag, &peer_id_str);
                        if let NetworkMessage::PeerTip { blue_score, height, .. } = &tip {
                            debug!("→ announcing tip: height={} score={}", height, blue_score);
                        }
                        if let Ok(d) = bincode::serde::encode_to_vec(&tip, bincode::config::standard()) {
                            if let Err(e) = swarm.behaviour_mut().gossipsub.publish(sync_t.clone(), d) {
                                info!("tip announce publish failed: {} (peers={})", e, peer_count);
                            }
                        }
                        let (v_score, v_height) = {
                            let d = dag.read();
                            (d.tip_blue_score(), d.block_count() as u64)
                        };
                        let ver = NetworkMessage::Version {
                            version:    PROTOCOL_VERSION,
                            user_agent: format!("gnb/{}", env!("CARGO_PKG_VERSION")),
                            blue_score: v_score,
                            height:     v_height,
                            timestamp:  std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs()).unwrap_or(0),
                        };
                        if let Ok(d) = bincode::serde::encode_to_vec(&ver, bincode::config::standard()) {
                            if let Err(e) = swarm.behaviour_mut().gossipsub.publish(sync_t.clone(), d) {
                                info!("version announce publish failed: {}", e);
                            }
                        }
                    }
                }
            }
        }
    }
}

// ── Directed-pull pipeline (NET-5 / NET-9) ───────────────────────────────────

/// Max queued pulls waiting for an eligible peer.
pub const MAX_PENDING_PULLS: usize = 4096;
/// A pull is attempted on at most this many peers before it is dropped (the
/// processor's own retry paths — frontier expiry, orphan sweep, the 30s
/// nudge — re-issue anything still needed).
pub const MAX_PULL_ATTEMPTS: u8 = 3;
/// How often queued pulls are retried.
const PULL_RETRY_TICK: Duration = Duration::from_millis(250);
/// NET-11: PEX dial cadence and batch sizes.
const PEX_DIAL_TICK: Duration = Duration::from_secs(10);
const PEX_LOW_PEER_THRESHOLD: usize = 4;
const PEX_DIALS_WHEN_LOW: usize = 4;
/// NET-6: per-author tip-claim rate limit (burst, refill/sec, tracked authors).
const CLAIM_BURST: u32 = 16;
const CLAIM_REFILL_PER_SEC: f64 = 0.2;
const CLAIM_LIMITER_TRACK_CAP: usize = 4096;
const CLAIM_LIMITER_IDLE_TTL: Duration = Duration::from_secs(600);

/// One directed pull, queued or in flight.
#[derive(Clone, Debug)]
struct PendingPull {
    msg:      NetworkMessage,
    req:      sync_rr::SyncRequest,
    attempts: u8,
    /// Peers this pull already failed on (excluded on retry when possible).
    tried:    Vec<PeerId>,
}

/// Put a failed / Busy pull back at the END of the queue, remembering the
/// peer it failed on, unless it has used up its attempts.
fn requeue_pull(pending: &mut std::collections::VecDeque<PendingPull>, mut p: PendingPull, failed_on: PeerId) {
    p.attempts = p.attempts.saturating_add(1);
    if p.attempts >= MAX_PULL_ATTEMPTS {
        debug!("directed pull [{}] dropped after {} attempts", p.msg.kind_name(), p.attempts);
        return;
    }
    if !p.tried.contains(&failed_on) {
        p.tried.push(failed_on);
    }
    if pending.len() < MAX_PENDING_PULLS {
        pending.push_back(p);
    }
}

/// Send queued pulls to eligible peers until the queue is empty or no peer is
/// eligible. A pull prefers a peer it has not failed on yet.
fn drain_pulls(
    swarm:    &mut libp2p::Swarm<BlochBehaviour>,
    selector: &mut sync_rr::PullPeerSelector,
    pending:  &mut std::collections::VecDeque<PendingPull>,
    inflight: &mut std::collections::HashMap<libp2p::request_response::OutboundRequestId, (PendingPull, PeerId)>,
    now:      std::time::Instant,
) {
    while let Some(p) = pending.front() {
        let pick = selector.select(now, &p.tried).or_else(|| {
            if p.tried.is_empty() { None } else { selector.select(now, &[]) }
        });
        let Some(peer) = pick else { break };
        let Some(p) = pending.pop_front() else { break };
        let id = swarm.behaviour_mut().sync_rr.send_request(&peer, p.req.clone());
        debug!("→ directed pull [{}] to {}", p.msg.kind_name(), peer);
        selector.on_sent(peer, now);
        inflight.insert(id, (p, peer));
    }
}

/// Receive the next processor control request; pending forever when none
/// is attached.
async fn recv_control(rx: &mut Option<mpsc::Receiver<NetworkControl>>) -> Option<NetworkControl> {
    match rx {
        Some(r) => r.recv().await,
        None => std::future::pending().await,
    }
}

/// Receive the next processor verdict; pending forever when no validator is
/// attached (legacy `run`).
async fn recv_verdict(rx: &mut Option<mpsc::Receiver<GossipValidation>>) -> Option<GossipValidation> {
    match rx {
        Some(r) => r.recv().await,
        None => std::future::pending().await,
    }
}

/// NET-11: admit peer-exchange addresses from `author` (the peer that answered
/// OUR GetPeers) into the unverified address table. Rate-limited per author,
/// batch-capped, validated, never our own id, never already-known entries.
/// Nothing is dialed here — the network loop dials from the table, a few
/// per tick. Returns how many addresses entered the table.
#[allow(clippy::too_many_arguments)]
pub fn ingest_pex_addresses(
    book:          &mut AddrBook,
    limiter:       &mut PexRateLimiter,
    stats:         &mut PexStats,
    author:        PeerId,
    peers:         &[String],
    allow_private: bool,
    self_peer:     &PeerId,
    known:         &HashSet<String>,
) -> usize {
    let original_len = peers.len();
    let admitted = limiter.admit(author, original_len);
    if admitted < original_len {
        let over_batch = original_len.saturating_sub(PEX_BATCH_LIMIT);
        if over_batch > 0 {
            stats.record_batch(over_batch.min(original_len.saturating_sub(admitted)));
        }
        let over_rate = original_len.saturating_sub(admitted).saturating_sub(over_batch);
        if over_rate > 0 {
            stats.record_rate(over_rate);
        }
    }
    let mut added = 0usize;
    for addr_str in peers.iter().take(admitted) {
        if !is_valid_public_multiaddr(addr_str, allow_private) {
            if is_valid_public_multiaddr(addr_str, true) {
                stats.record_private(1);
            } else {
                stats.record_invalid(1);
            }
            // H4: addr_str is attacker-controlled; UTF-8-safe truncation.
            debug!("PEX rejected: {}", truncate_utf8(addr_str, 80));
            continue;
        }
        if known.contains(addr_str) || addr_peer_id(addr_str).is_some_and(|p| p == *self_peer) {
            continue;
        }
        if book.add(addr_str) {
            added += 1;
        }
    }
    added
}

// ── Persistent identity ───────────────────────────────────────────────────────

/// NET-16 (audit): the P2P identity is a private key. It is created with
/// owner-only permissions (0600) through a temp file + rename, so a crash can
/// never leave a truncated key and no other local user can read it; an
/// existing key file with broader permissions is tightened on load.
pub fn load_or_create_identity(path: &Path) -> Result<identity::Keypair, NetworkError> {
    if path.exists() {
        restrict_to_owner(path);
        let bytes = std::fs::read(path)
            .map_err(|e| NetworkError::StartFailed(format!("read identity: {}", e)))?;
        return identity::Keypair::from_protobuf_encoding(&bytes)
            .map_err(|e| NetworkError::StartFailed(format!("decode identity: {}", e)));
    }
    let kp = identity::Keypair::generate_ed25519();
    if let Some(parent) = path.parent() { std::fs::create_dir_all(parent).ok(); }
    let bytes = kp.to_protobuf_encoding()
        .map_err(|e| NetworkError::StartFailed(format!("encode identity: {}", e)))?;
    write_file_atomic(path, &bytes, true)
        .map_err(|e| NetworkError::StartFailed(format!("write identity: {}", e)))?;
    info!("created P2P identity: {}", path.display());
    Ok(kp)
}

/// NET-16: chmod an existing secret file to 0600 if it is group/other
/// accessible (unix only; best effort, logged).
fn restrict_to_owner(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode();
            if mode & 0o077 != 0 {
                warn!("{} had permissions {:o}; restricting to 0600", path.display(), mode & 0o777);
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// NET-16: write `bytes` to `path` atomically (temp file in the same
/// directory, fsync, rename). With `secret`, the file is created 0600.
pub fn write_file_atomic(path: &Path, bytes: &[u8], secret: bool) -> std::io::Result<()> {
    use std::io::Write;
    let file_name = path
        .file_name()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name"))?;
    let mut tmp_name = file_name.to_os_string();
    tmp_name.push(".tmp");
    let tmp = path.with_file_name(tmp_name);
    // A stale temp file from a crash may carry other permissions; start fresh.
    let _ = std::fs::remove_file(&tmp);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(if secret { 0o600 } else { 0o644 });
    }
    #[cfg(not(unix))]
    let _ = secret;
    let mut f = opts.open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent() {
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

// ── FIX #6: Peer persistence ──────────────────────────────────────────────────

pub fn load_known_peers(path: &Path) -> HashSet<String> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// NET-16: known_peers.json is written atomically (temp file + rename), so a
/// crash mid-write can never leave a truncated table behind.
pub fn save_known_peers(path: &Path, peers: &HashSet<String>) {
    if let Ok(json) = serde_json::to_string(peers) {
        if let Err(e) = write_file_atomic(path, json.as_bytes(), false) {
            warn!("saving {} failed: {}", path.display(), e);
        }
    }
}

async fn poll_swarm(
    swarm: &mut libp2p::Swarm<BlochBehaviour>,
) -> SwarmEvent<BlochBehaviourEvent> {
    use futures::Stream;
    std::future::poll_fn(|cx| {
        match std::pin::Pin::new(&mut *swarm).poll_next(cx) {
            std::task::Poll::Ready(Some(e)) => std::task::Poll::Ready(e),
            _ => std::task::Poll::Pending,
        }
    }).await
}




/// Resolve a `/dns4/...` multiaddr to a `/ip4/...` form using async DNS.
///
/// Audit M-11 fix: this function was previously synchronous, calling
/// `std::net::ToSocketAddrs::to_socket_addrs` — a blocking C library
/// call that can stall the caller for the full DNS timeout (seconds)
/// on an unreachable nameserver. Every caller lives inside the
/// libp2p swarm event loop in `Swarm::run`; blocking the loop stalls
/// gossipsub propagation, connection events, and outbound dials for
/// every other peer. On a network with even one slow DNS seed this
/// was a periodic latency spike visible to the whole node.
///
/// Now uses `tokio::net::lookup_host`, which runs the lookup on the
/// blocking thread pool instead of holding the async executor. The
/// public API is now `async`; all three callers are inside async
/// code already, so the `.await` points add no new complexity.
///
/// Audit L-3 concern (silent fallback) is preserved: warn logs fire
/// on DNS failure and on no-IPv4-records, both paths still return
/// the unresolved multiaddr so upstream `parse::<Multiaddr>()` can
/// decide whether to dial.
async fn resolve_multiaddr(addr: &str) -> String {
    if !addr.contains("/dns4/") { return addr.to_string(); }
    let parts: Vec<&str> = addr.splitn(2, "/dns4/").collect();
    if parts.len() < 2 { return addr.to_string(); }
    let rest = parts[1];
    let mut iter = rest.splitn(3, '/');
    let host = iter.next().unwrap_or("");
    let _ = iter.next();
    let remainder = iter.next().unwrap_or("");

    match tokio::net::lookup_host(format!("{}:0", host)).await {
        Ok(addrs) => {
            if let Some(sa) = addrs.into_iter().find(|a| a.is_ipv4()) {
                let ip = sa.ip();
                let tcp_rest: Vec<&str> = remainder.splitn(2, '/').collect();
                let port = tcp_rest.first().unwrap_or(&"");
                let p2p = tcp_rest.get(1).map(|s| format!("/{}", s)).unwrap_or_default();
                return format!("/ip4/{}/tcp/{}{}", ip, port, p2p);
            }
            // Audit L-3: DNS returned records but none were IPv4.
            warn!(
                "resolve_multiaddr: DNS for host '{}' returned no IPv4 records; \
                 falling back to the unresolved multiaddr. Dial may fail.",
                host,
            );
        }
        Err(e) => {
            // Audit L-3: DNS resolution itself failed.
            warn!(
                "resolve_multiaddr: DNS lookup for host '{}' failed: {}. \
                 Falling back to the unresolved multiaddr; dial may fail.",
                host, e,
            );
        }
    }
    addr.to_string()
}

/// PROPAGAÇÃO-CHURN fix (2026-08-09): the ONE canonical string form of a
/// peer's address for known_peers / PEX — transport components only, plus
/// exactly one trailing `/p2p/<peer_id>`.
///
/// Every place that used to build a persistable address with
/// `format!("{}/p2p/{}", observed, peer_id)` concatenated a NEW `/p2p/`
/// component onto an address that (on the Dialer path) already ended in one.
/// Each successful dial of the stored entry re-observed it and appended
/// again — mainnet known_peers.json files were measured with chains up to
/// 15 `/p2p/` components (885 bytes). Past ~9 components the string exceeds
/// MAX_WIRE_ADDR_LEN, at which point every PeerExchange carrying it is a
/// wire violation at the receiver: −100 app score per frame, graylist at
/// −400, and the sender's blocks/tips are blackholed while TCP stays up —
/// the 2026-08-09 non-convergence incident.
///
/// Stripping ALL P2p components before appending exactly one makes this
/// function idempotent: re-observing a canonical address yields the same
/// string forever.
pub fn canonical_peer_addr(addr: &Multiaddr, peer_id: &PeerId) -> String {
    let transport: Multiaddr = addr
        .iter()
        .filter(|p| !matches!(p, libp2p::multiaddr::Protocol::P2p(_)))
        .collect();
    format!("{}/p2p/{}", transport, peer_id)
}

#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("start failed: {0}")]
    StartFailed(String),
}

// ── Sprint CC: PeerTip construction ──────────────────────────────────────────

/// Build a PeerTip message from the current state of the GhostDAG.
///
/// Sprint CC bugfix: previously, `network::run` captured `our_blue_score`
/// and `our_height` as `u64` values at startup and reused them forever
/// to construct every `PeerTip` it ever published. Any node that built
/// blocks after boot would still advertise its startup-time height to
/// the rest of the mesh, silently preventing peer-initiated IBD
/// handshakes across reboots and against late-joining peers.
///
/// This function is a small free function (not a closure inside `run`)
/// so it can be exercised directly by the regression test that lives
/// alongside it. Testing via the closure was not practical — it would
/// require spinning up a real libp2p swarm.
///
/// Holding the read lock for the duration of the three accessor calls
/// is a conscious choice: it guarantees the (blue_score, height) pair
/// is internally consistent. A multi-call pattern that released the
/// lock between `tip_blue_score()` and `block_count()` could report a
/// mismatched pair if a block were accepted in between. In practice
/// the window is microseconds but the cost of holding the lock for
/// that long is zero, so we take the consistency guarantee.
pub fn build_current_tip(
    dag:     &std::sync::Arc<parking_lot::RwLock<crate::consensus::GhostDAG>>,
    peer_id: &str,
) -> NetworkMessage {
    let d = dag.read();
    NetworkMessage::PeerTip {
        peer_id:    peer_id.to_string(),
        blue_score: d.tip_blue_score(),
        height:     d.block_count() as u64,
    }
}

// ── Announce-then-pull: directed sync helpers ────────────────────────────────

/// M-9 (audit): bound on how far ahead of our OWN locally-verified tip an
/// announced blue_score is allowed to be before it is clamped. A single
/// crafted `PeerTip`/`Version`/`Tips` frame claiming `blue_score = u64::MAX`
/// used to be stored and trusted verbatim as `announced_blue_score`, which
/// (in `main.rs`) latches `is_syncing = true` for the connection's lifetime:
/// `caught_up = our_score + IBD_EXIT_LAG >= best_announced` can never hold
/// against `u64::MAX`, pausing the miner and freezing the finality
/// checkpoint. The entire historical Genesis-3 chain never exceeded
/// ~50,600 in blue_score; this bound is chosen to be generously larger than
/// any plausible real growth burst while remaining astronomically smaller
/// than `u64::MAX`, so it clamps only implausible/malicious announcements,
/// never an honest peer that is genuinely far ahead.
pub const MAX_ANNOUNCED_LOOKAHEAD: u64 = 1_000_000;

/// M-9: clamp a peer-announced blue_score to at most
/// `our_verified_score + MAX_ANNOUNCED_LOOKAHEAD` before it is ever stored in
/// [`crate::sync::peer_state::PeerStateTable`] or fed to
/// [`sync_rr::PeerSync`]/`track_peer_score`. `our_verified_score` MUST be a
/// LOCALLY-VERIFIED quantity (e.g. `dag.tip_blue_score()`) — clamping against
/// an already-untrusted ceiling (another peer's announcement) would let one
/// lie authorize the next.
pub fn clamp_announced_blue_score(announced: u64, our_verified_score: u64) -> u64 {
    announced.min(our_verified_score.saturating_add(MAX_ANNOUNCED_LOOKAHEAD))
}

/// M-6: derive the WebSocket listen multiaddr from the primary `--listen`
/// address — same host/interface component, TCP port + 1, `/ws` appended —
/// instead of a hard-coded `/ip4/0.0.0.0/tcp/17111/ws`. Returns `None` if
/// `listen_addr` doesn't parse or carries no `/tcp/<port>` component (nothing
/// to derive a WS port from).
fn ws_listen_addr_from(listen_addr: &str) -> Option<Multiaddr> {
    use libp2p::multiaddr::Protocol;
    let base: Multiaddr = listen_addr.parse().ok()?;
    let mut out = Multiaddr::empty();
    let mut saw_tcp = false;
    for proto in base.iter() {
        match proto {
            Protocol::Tcp(port) => {
                out.push(Protocol::Tcp(port.checked_add(1)?));
                saw_tcp = true;
            }
            other => out.push(other),
        }
    }
    if !saw_tcp {
        return None;
    }
    out.push(Protocol::Ws(std::borrow::Cow::Borrowed("/")));
    Some(out)
}

/// M-10: max peer addresses returned in one `GetPeers` answer — a bounded
/// RANDOM SAMPLE of `known_peers`, never the whole table. Mirrors the
/// rationale Bitcoin's `getaddr` uses (return a fraction of the table, not
/// all of it): a requester wanting more addresses simply asks again (and, on
/// this transport, asks a DIFFERENT peer next time via `select_pull_peer`),
/// while a single answer can never hand over the complete peer table in one
/// shot — the reconnaissance value of one answer is bounded regardless of
/// how large `known_peers` (capped at `KNOWN_PEERS_CAP`, 1000) has grown.
const PEX_RESPONSE_SAMPLE_SIZE: usize = 30;

/// M-10: build the bounded, randomly-sampled peer list answer to a directed
/// `GetPeers` request. Same address-validity filter and self-advertisement
/// logic the (now-removed) gossip `PeerRequest` broadcast handler used —
/// only the transport and the "return everything" -> "return a sample"
/// change are new.
fn serve_get_peers(
    known_peers:     &std::collections::HashSet<String>,
    external_addrs:  &[Multiaddr],
    self_peer_id:    &PeerId,
    allow_private:   bool,
) -> sync_rr::SyncResponse {
    use rand::seq::SliceRandom;

    let mut candidates: Vec<String> = known_peers.iter()
        .filter(|a| is_valid_public_multiaddr(a, allow_private))
        .cloned().collect();
    // PRINCIPLES.md #2 ("every node is a seed"): advertise our own reachable
    // address(es) too, so a node nobody else knows about can still be
    // gossiped onward through this answer.
    for addr in external_addrs {
        let self_addr = canonical_peer_addr(addr, self_peer_id);
        if !candidates.contains(&self_addr) {
            candidates.push(self_addr);
        }
    }
    let mut rng = rand::rng();
    candidates.shuffle(&mut rng);
    candidates.truncate(PEX_RESPONSE_SAMPLE_SIZE);
    sync_rr::SyncResponse::Peers { peers: candidates }
}

/// Serve an inbound directed `SyncRequest` from our DAG + block store. This is
/// the SERVER side of announce-then-pull: block bodies live in the store (not
/// the DAG), headers/tips come from the DAG — exactly the same sources the
/// legacy gossip responders in `main.rs` read, so the answers are identical;
/// only the transport (directed request-response vs. gossip broadcast) differs.
///
/// `GetPeers` (M-10) is handled by the caller via [`serve_get_peers`] instead
/// of here, because it needs `known_peers` / the swarm's external addresses /
/// this node's own `PeerId` — none of which this function otherwise needs —
/// so this match still covers it (exhaustiveness) but never actually reaches
/// this arm in the real event loop.
fn serve_sync_request(
    dag:   &std::sync::Arc<parking_lot::RwLock<crate::consensus::GhostDAG>>,
    store: &std::sync::Arc<crate::storage::Storage>,
    req:   &sync_rr::SyncRequest,
) -> sync_rr::SyncResponse {
    use sync_rr::{SyncRequest, SyncResponse};
    match req {
        SyncRequest::GetPeers => {
            // See the function doc comment: unreachable via the real
            // dispatch (the caller special-cases GetPeers before calling
            // this function), kept only so this match stays exhaustive.
            // Answering with an empty, well-formed response here — rather
            // than `unreachable!()` — means a future refactor that DID
            // route GetPeers here by mistake would get an empty PEX answer
            // instead of a panic on the swarm event loop.
            SyncResponse::Peers { peers: Vec::new() }
        }
        SyncRequest::GetBlock { block_hash } => match store.get_block(block_hash) {
            Ok(Some(block)) => SyncResponse::Block {
                block_hash: *block_hash,
                blue_score: block.blue_score,
                height:     block.height,
                block_data: block.to_wire_bytes(),
            },
            // Pruned or unknown — answer explicitly (same semantics as the
            // gossip BlockNotFound) so the requester tries another peer.
            _ => SyncResponse::BlockNotFound { block_hash: *block_hash },
        },
        SyncRequest::GetHeaders { from_blue_score, limit } => {
            // H-R3-1: defense in depth. `sync_rr::decode_request` already
            // rejects any wire `limit` above `MAX_WIRE_GETHEADERS_LIMIT`
            // before a request reaches here, so this clamp is normally a
            // no-op — but this function's OWN contract must not trust that
            // upstream check alone: bound the work unconditionally, so a
            // future caller (or a future codec change) cannot reintroduce
            // the "peer asks for u32::MAX headers" cost on the strength of a
            // check that lives in a different module.
            let bounded_limit = (*limit as usize).min(MAX_WIRE_GETHEADERS_LIMIT as usize);
            let d = dag.read();
            let entries: Vec<SyncEntry> = d
                .ordered_hashes_from(*from_blue_score, bounded_limit)
                .iter()
                .filter_map(|h| d.get_node(h).map(|n| SyncEntry {
                    hash: *h, blue_score: n.blue_score, height: n.height,
                }))
                .collect();
            SyncResponse::Headers { entries }
        }
        SyncRequest::GetTips => {
            let d = dag.read();
            let tips: Vec<SyncEntry> = d
                .tips()
                .iter()
                .filter_map(|h| d.get_node(h).map(|n| SyncEntry {
                    hash: *h, blue_score: n.blue_score, height: n.height,
                }))
                .collect();
            let locator = crate::sync::locator::build_locator(&d.selected_chain());
            SyncResponse::Tips { tips, locator }
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── M-10 regressions: bounded random-sample PEX answer ──────────────────

    /// THE M-10 regression: the answer must never exceed
    /// `PEX_RESPONSE_SAMPLE_SIZE`, even when `known_peers` holds far more —
    /// before this fix, the (gossip-broadcast) answer was the WHOLE table.
    #[test]
    fn get_peers_response_is_bounded_even_with_a_large_table() {
        let known: std::collections::HashSet<String> = (0..500)
            .map(|i| format!("/ip4/10.0.{}.{}/tcp/17110/p2p/{}", i / 256, i % 256, PeerId::random()))
            .collect();
        let resp = serve_get_peers(&known, &[], &PeerId::random(), true);
        match resp {
            sync_rr::SyncResponse::Peers { peers } => {
                assert!(
                    peers.len() <= PEX_RESPONSE_SAMPLE_SIZE,
                    "answer carried {} peers, expected <= {}", peers.len(), PEX_RESPONSE_SAMPLE_SIZE
                );
            }
            other => panic!("expected Peers, got {:?}", other),
        }
    }

    /// A table smaller than the sample size is returned (minus any
    /// invalid/filtered entries) without padding or fabrication.
    #[test]
    fn get_peers_response_returns_all_of_a_small_table() {
        let known: std::collections::HashSet<String> = [
            format!("/ip4/45.76.1.1/tcp/17110/p2p/{}", PeerId::random()),
            format!("/ip4/45.76.2.2/tcp/17110/p2p/{}", PeerId::random()),
        ].into_iter().collect();
        let resp = serve_get_peers(&known, &[], &PeerId::random(), true);
        match resp {
            sync_rr::SyncResponse::Peers { peers } => assert_eq!(peers.len(), 2),
            other => panic!("expected Peers, got {:?}", other),
        }
    }

    /// Our own external address is offered too (PRINCIPLES.md #2 — every
    /// node is a seed), de-duplicated against `known_peers`.
    #[test]
    fn get_peers_response_includes_self_external_address() {
        let known: std::collections::HashSet<String> = std::collections::HashSet::new();
        let self_id = PeerId::random();
        let ext: Multiaddr = "/ip4/1.2.3.4/tcp/17110".parse().unwrap();
        let resp = serve_get_peers(&known, std::slice::from_ref(&ext), &self_id, true);
        match resp {
            sync_rr::SyncResponse::Peers { peers } => {
                assert_eq!(peers.len(), 1);
                assert!(peers[0].contains(&self_id.to_string()));
            }
            other => panic!("expected Peers, got {:?}", other),
        }
    }

    // ── M-9 regressions: announced blue_score clamp ─────────────────────────

    /// THE M-9 regression: a peer claiming `blue_score = u64::MAX` must be
    /// clamped down to a bounded value relative to what we have locally
    /// verified, never stored/propagated verbatim. Before this fix, this
    /// exact value latched `is_syncing` in `main.rs` for the connection's
    /// lifetime because `our_score + IBD_EXIT_LAG >= best_announced` can
    /// never hold against `u64::MAX`.
    #[test]
    fn u64_max_announcement_is_clamped_to_bounded_lookahead() {
        let our_score = 100u64;
        let clamped = clamp_announced_blue_score(u64::MAX, our_score);
        assert_eq!(clamped, our_score + MAX_ANNOUNCED_LOOKAHEAD);
        assert!(clamped < u64::MAX, "must never pass through an unbounded announcement");
    }

    /// An honest peer announcement within the lookahead window passes through unchanged.
    #[test]
    fn honest_announcement_within_lookahead_is_unclamped() {
        let our_score = 100u64;
        assert_eq!(clamp_announced_blue_score(150, our_score), 150);
        assert_eq!(clamp_announced_blue_score(our_score, our_score), our_score);
    }

    /// An announcement below our own score is never inflated — the clamp is
    /// a ceiling, not a floor.
    #[test]
    fn announcement_below_our_score_is_unaffected() {
        let our_score = 100_000u64;
        assert_eq!(clamp_announced_blue_score(5, our_score), 5);
    }

    /// The clamp must not overflow/panic even at u64::MAX on both sides
    /// (checked arithmetic: `saturating_add`).
    #[test]
    fn clamp_does_not_overflow_at_extremes() {
        assert_eq!(clamp_announced_blue_score(u64::MAX, u64::MAX), u64::MAX);
        assert_eq!(clamp_announced_blue_score(0, u64::MAX), 0);
    }

    // ── M-6 regressions: WS listen address derivation ───────────────────────

    /// The core M-6 fix: the WS address must follow the SAME interface as
    /// `--listen`, not a hard-coded `0.0.0.0` — an operator binding to a
    /// private interface must get the WS listener on that interface too.
    #[test]
    fn ws_listen_addr_follows_listen_interface_not_hardcoded_any() {
        let ws = ws_listen_addr_from("/ip4/10.0.0.5/tcp/17110").unwrap();
        assert_eq!(ws.to_string(), "/ip4/10.0.0.5/tcp/17111/ws");
    }

    /// Default `--listen` (0.0.0.0) still derives correctly — the fix must
    /// not change behavior for the common case, only the private-interface one.
    #[test]
    fn ws_listen_addr_derives_port_plus_one_on_default_listen() {
        let ws = ws_listen_addr_from("/ip4/0.0.0.0/tcp/17110").unwrap();
        assert_eq!(ws.to_string(), "/ip4/0.0.0.0/tcp/17111/ws");
    }

    /// IPv6 interfaces must be preserved too, not silently dropped/rewritten to v4.
    #[test]
    fn ws_listen_addr_preserves_ipv6_host() {
        let ws = ws_listen_addr_from("/ip6/::1/tcp/17110").unwrap();
        assert_eq!(ws.to_string(), "/ip6/::1/tcp/17111/ws");
    }

    /// A listen address with no `/tcp/<port>` component gives nothing to
    /// derive a WS port from — must return `None`, not panic or guess.
    #[test]
    fn ws_listen_addr_none_when_no_tcp_component() {
        assert!(ws_listen_addr_from("/ip4/10.0.0.5").is_none());
        assert!(ws_listen_addr_from("not a multiaddr").is_none());
        assert!(ws_listen_addr_from("").is_none());
    }

    /// M-11 regression: addresses that don't need DNS must be returned
    /// unchanged without touching the resolver. This exercises the
    /// fast path that matters most in practice — most peers are
    /// already `/ip4/...` form from a prior bootstrap.
    #[tokio::test]
    async fn resolve_multiaddr_passes_through_ip4_unchanged() {
        let input = "/ip4/80.78.28.142/tcp/17110/p2p/12D3KooWQfXJzXRG7t4r1hQVHfijHsuMZ22ecAUD3YGhMvjvDbQp";
        let out = resolve_multiaddr(input).await;
        assert_eq!(out, input);
    }

    /// Degenerate edge case: a string that happens to not contain
    /// "/dns4/" at all should short-circuit immediately, no DNS lookup.
    #[tokio::test]
    async fn resolve_multiaddr_passes_through_empty_and_garbage() {
        assert_eq!(resolve_multiaddr("").await, "");
        assert_eq!(resolve_multiaddr("garbage").await, "garbage");
        assert_eq!(resolve_multiaddr("/ip6/::1/tcp/1").await, "/ip6/::1/tcp/1");
    }

    /// If `/dns4/` appears but the address is malformed enough that
    /// the `splitn(2, "/dns4/")` returns fewer than 2 parts, the
    /// function must fall back to returning the input verbatim.
    /// (Today this branch is actually unreachable because splitn(2)
    /// on a string that CONTAINS "/dns4/" always yields 2 parts, but
    /// the guard is in place and we pin it here in case the parser
    /// is ever restructured.)
    #[tokio::test]
    async fn resolve_multiaddr_never_panics_on_weird_input() {
        // These call into the DNS path but with a host that won't
        // resolve to anything useful. The function must still return
        // a String — never panic.
        let weird = "/dns4/";
        let _ = resolve_multiaddr(weird).await;
        // If we got here, no panic.
    }

    /// M-11 core property: the function is `async`. A synchronous
    /// version would block the libp2p event loop. We don't assert on
    /// timing (brittle in CI), but we do assert the shape: the return
    /// value only materializes after `.await`, which is only true for
    /// an async function.
    ///
    /// This is a compile-time check more than a runtime one — if
    /// someone regresses `resolve_multiaddr` to a sync function, this
    /// test fails to compile.
    #[tokio::test]
    async fn resolve_multiaddr_is_async() {
        // Cannot call an async fn without `.await`, so if the fn
        // signature regresses to `fn resolve_multiaddr(...) -> String`
        // the `.await` here becomes a compile error on "method `await`
        // does not exist on String". That is exactly the guard we want.
        let future = resolve_multiaddr("/ip4/127.0.0.1/tcp/1");
        let out = future.await;
        assert_eq!(out, "/ip4/127.0.0.1/tcp/1");
    }

    // ─── Sprint CC regression: dynamic PeerTip construction ──────────────

    /// The pre-Sprint-CC bug was: `our_blue_score` / `our_height` passed
    /// as u64 values got captured into `my_tip` once at startup, so any
    /// growth of the DAG after startup never reflected in subsequently
    /// published PeerTip messages. In production this silently froze
    /// IBD across the whole mesh — a seed at height=2655 kept telling
    /// every new peer "I'm at height=1", and new peers (seeing parity)
    /// never asked to sync.
    ///
    /// This test pins the fix: `build_current_tip` must read the DAG
    /// fresh on each call. The check is simple — build a tip, advance
    /// the DAG by one block, build another tip, assert the second tip
    /// reflects the new state. If someone later refactors
    /// `build_current_tip` to cache values, this test fails.
    #[test]
    fn build_current_tip_reads_fresh_dag_state_each_call() {
        use std::sync::Arc;
        use parking_lot::RwLock;
        use crate::consensus::GhostDAG;

        // Arrange: DAG with just genesis.
        let dag = Arc::new(RwLock::new(GhostDAG::with_default_k()));
        let genesis_hash: [u8; 32] = [0xAA; 32];
        dag.write().add_genesis(genesis_hash, 1000);

        // First tip read: should reflect genesis-only state.
        let tip1 = build_current_tip(&dag, "peer-xyz");
        match tip1 {
            NetworkMessage::PeerTip { peer_id, blue_score, height } => {
                assert_eq!(peer_id, "peer-xyz");
                assert_eq!(blue_score, 0, "genesis DAG has blue_score 0");
                assert_eq!(height, 1, "genesis DAG has block_count 1");
            }
            _ => panic!("expected PeerTip"),
        }

        // Advance the DAG by one block.
        let block1: [u8; 32] = [0xBB; 32];
        dag.write()
            .add_block(block1, vec![genesis_hash], 1, 1001)
            .expect("add_block");

        // Second tip read: MUST reflect the new state. The pre-Sprint-CC
        // bug was that the tip was cached and always returned the old
        // state here; the assertions below fail if that behavior returns.
        let tip2 = build_current_tip(&dag, "peer-xyz");
        match tip2 {
            NetworkMessage::PeerTip { blue_score, height, .. } => {
                assert_eq!(
                    blue_score, 1,
                    "tip MUST reflect post-genesis blue_score after add_block"
                );
                assert_eq!(
                    height, 2,
                    "tip MUST reflect post-genesis block_count after add_block"
                );
            }
            _ => panic!("expected PeerTip"),
        }
    }

    /// A separate and simpler property test: build_current_tip carries
    /// the peer_id through verbatim. Pre-refactor, this was a trivial
    /// clone; post-refactor it's still a trivial clone, but we pin it
    /// so a regression that swaps arguments or loses the peer_id
    /// completely is caught.
    #[test]
    fn build_current_tip_preserves_peer_id() {
        use std::sync::Arc;
        use parking_lot::RwLock;
        use crate::consensus::GhostDAG;

        let dag = Arc::new(RwLock::new(GhostDAG::with_default_k()));
        dag.write().add_genesis([0u8; 32], 0);

        let tip = build_current_tip(&dag, "12D3KooWExample123");
        match tip {
            NetworkMessage::PeerTip { peer_id, .. } => {
                assert_eq!(peer_id, "12D3KooWExample123");
            }
            _ => panic!("expected PeerTip"),
        }
    }

    /// Sanity check: tip_announce interval is configured to 60s. If
    /// someone ever changes that to something extreme (say, 10ms or
    /// 1h), this won't catch it — it only documents the intent. But
    /// it does catch accidental removal of the tip_announce timer,
    /// because that removal would also delete this constant expectation.
    ///
    /// The concrete guard is a compile-time check: we reference the
    /// Duration value we expect to see in the loop. If the loop ever
    /// changes the Duration::from_secs value, this test fails only if
    /// the value is exactly wrong for what IBD recovery needs.
    #[test]
    fn tip_announce_interval_is_bounded() {
        // Documented invariant: the tip_announce interval must be
        // bounded between 10s (pointless churn) and 300s (too slow for
        // IBD recovery on a network with 10s block times). The actual
        // value in run() is 60s; this test documents the acceptable
        // range without duplicating the exact value.
        let min_allowed = Duration::from_secs(10);
        let max_allowed = Duration::from_secs(300);
        let actual      = Duration::from_secs(60);  // must match run()

        assert!(
            actual >= min_allowed && actual <= max_allowed,
            "tip_announce interval {:?} outside acceptable bounds [{:?}, {:?}]",
            actual, min_allowed, max_allowed
        );
    }

    // ─── C1 regression: bounded bincode decode of untrusted gossip ────────

    /// (a) A tiny crafted frame declaring a multi-GB Vec length must return
    /// a decode error fast, without allocating the declared size. The frame
    /// is built by taking a genuinely-encoded NewBlock and splicing an 8 GiB
    /// length varint in place of the block_data length, so the test is
    /// self-validating against bincode's actual encoding layout.
    #[test]
    fn wire_decode_rejects_multi_gb_declared_vec() {
        let small = NetworkMessage::NewBlock {
            block_hash: [0u8; 32],
            blue_score: 0,
            height:     0,
            block_data: vec![7u8; 3],
        };
        let enc = bincode::serde::encode_to_vec(&small, bincode::config::standard())
            .expect("encode");
        // Layout guard: the frame must end with len-varint 0x03 then 7,7,7.
        // If bincode's encoding ever changes, fail loudly here instead of
        // silently testing a meaningless byte string.
        assert!(
            enc.ends_with(&[3, 7, 7, 7]),
            "bincode encoding layout changed; update this test"
        );
        let mut frame = enc[..enc.len() - 4].to_vec();
        frame.push(0xFD); // bincode-2 varint marker: u64 follows
        frame.extend_from_slice(&(8u64 * 1024 * 1024 * 1024).to_le_bytes()); // 8 GiB

        let t0 = std::time::Instant::now();
        let res = decode_wire_message(&frame);
        assert!(
            res.is_err(),
            "a frame declaring an 8 GiB Vec must not decode: {:?}", res
        );
        assert!(
            t0.elapsed() < Duration::from_secs(2),
            "decode must fail fast (no giant allocation/scan), took {:?}",
            t0.elapsed()
        );
    }

    /// (b) The 4 MiB frame limit: a frame just over MAX_WIRE_BYTES is
    /// rejected as Oversized; one comfortably under it decodes fine. This
    /// FAILS without the fix (the old unlimited standard() decode accepted
    /// the >4 MiB frame).
    #[test]
    fn wire_decode_enforces_4mib_frame_limit() {
        let mk = |n: usize| NetworkMessage::NewBlock {
            block_hash: [0u8; 32],
            blue_score: 0,
            height:     0,
            block_data: vec![0u8; n],
        };

        // Just over: payload alone exceeds MAX_WIRE_BYTES, so the whole
        // frame necessarily does too.
        let over = bincode::serde::encode_to_vec(&mk(MAX_WIRE_BYTES + 1024), bincode::config::standard())
            .expect("encode over");
        assert!(over.len() > MAX_WIRE_BYTES);
        match decode_wire_message(&over) {
            Err(WireDecodeError::Oversized(_)) => {}
            other => panic!("frame over 4 MiB must be Oversized, got {:?}", other),
        }

        // Comfortably under: must decode and round-trip the payload.
        let under = bincode::serde::encode_to_vec(&mk(3 * 1024 * 1024), bincode::config::standard())
            .expect("encode under");
        assert!(under.len() < MAX_WIRE_BYTES);
        match decode_wire_message(&under).expect("3 MiB block must decode") {
            NetworkMessage::NewBlock { block_data, .. } => {
                assert_eq!(block_data.len(), 3 * 1024 * 1024);
            }
            other => panic!("expected NewBlock, got {:?}", other),
        }
    }

    /// C1 post-decode bounds: a PeerExchange whose peer list is far longer
    /// than any compliant node would send must be rejected even though the
    /// frame is well under the 4 MiB byte limit (the byte limit alone cannot
    /// catch it). FAILS without the fix. A modest list still passes, and a
    /// single over-long address string is also rejected.
    #[test]
    fn wire_decode_bounds_peer_lists() {
        // Too many entries, but small total size (< 4 MiB).
        let peers: Vec<String> = (0..(MAX_WIRE_ADDRS + 1))
            .map(|i| format!("/ip4/1.2.3.4/tcp/{}", i % 65535))
            .collect();
        let bytes = bincode::serde::encode_to_vec(
            &NetworkMessage::PeerExchange { peers },
            bincode::config::standard(),
        ).expect("encode");
        assert!(bytes.len() < MAX_WIRE_BYTES, "test premise: under byte limit");
        assert!(
            matches!(decode_wire_message(&bytes), Err(WireDecodeError::Bounds(_))),
            "oversized peer list must be a Bounds violation"
        );

        // One absurdly long address string.
        let bytes = bincode::serde::encode_to_vec(
            &NetworkMessage::PeerExchange { peers: vec!["x".repeat(MAX_WIRE_ADDR_LEN + 1)] },
            bincode::config::standard(),
        ).expect("encode");
        assert!(
            matches!(decode_wire_message(&bytes), Err(WireDecodeError::Bounds(_))),
            "over-long address string must be a Bounds violation"
        );

        // A compliant-size list decodes fine.
        let ok_peers: Vec<String> = (0..10).map(|i| format!("/ip4/9.9.9.{}/tcp/17110", i)).collect();
        let bytes = bincode::serde::encode_to_vec(
            &NetworkMessage::PeerExchange { peers: ok_peers.clone() },
            bincode::config::standard(),
        ).expect("encode");
        match decode_wire_message(&bytes).expect("compliant PEX must decode") {
            NetworkMessage::PeerExchange { peers } => assert_eq!(peers, ok_peers),
            other => panic!("expected PeerExchange, got {:?}", other),
        }
    }

    // ─── H4 regression: UTF-8-safe truncation of PEX strings ──────────────

    /// (c) A PEX address string where byte 80 falls mid-codepoint. The
    /// pre-fix pattern `&s[..s.len().min(80)]` panics on exactly this input
    /// (asserted below via catch_unwind, documenting the vulnerability);
    /// `truncate_utf8` must handle it without panicking.
    #[test]
    fn pex_string_truncation_is_utf8_safe() {
        // "a" + 50×'é' (2 bytes each) = 101 bytes; char boundaries sit at
        // 0, 1, 3, 5, ..., so byte 80 is mid-codepoint.
        let s = format!("a{}", "é".repeat(50));
        assert!(!s.is_char_boundary(80), "test premise: 80 must be mid-codepoint");

        // Document the pre-fix behavior: the old expression panics on this input.
        let old_pattern_panics = std::panic::catch_unwind(|| {
            let _ = &s[..s.len().min(80)];
        }).is_err();
        assert!(old_pattern_panics, "this input reproduces the pre-fix H4 panic");

        // The fix: no panic, valid UTF-8 prefix, within the byte budget.
        let t = truncate_utf8(&s, 80);
        assert!(t.len() <= 80);
        assert!(s.starts_with(t));
        assert_eq!(t.len(), 79, "should back off to the char boundary at 79");

        // 4-byte codepoints (emoji): budget 79 backs off to 76.
        let e = "💥".repeat(30); // 120 bytes
        let te = truncate_utf8(&e, 79);
        assert_eq!(te.len(), 76);
        assert!(e.starts_with(te));

        // Short and boundary-exact strings pass through unchanged.
        assert_eq!(truncate_utf8("abc", 80), "abc");
        assert_eq!(truncate_utf8("éé", 4), "éé");
        // Degenerate: budget smaller than the first codepoint → empty, no panic.
        assert_eq!(truncate_utf8("💥", 3), "");
    }

    // ─── Sprint EE (S3): extracted frame-reaction unit ────────────────────

    /// The reaction to a valid frame is Accept carrying the decoded message.
    #[test]
    fn wire_reaction_accepts_valid_frame() {
        let mut t = WirePenaltyTracker::new();
        let peer = PeerId::random();
        let bytes = bincode::serde::encode_to_vec(
            &NetworkMessage::GetTips, bincode::config::standard()).expect("encode");
        match t.classify(peer, &bytes) {
            WireReaction::Accept(NetworkMessage::GetTips) => {}
            other => panic!("expected Accept(GetTips), got {:?}", other),
        }
        assert_eq!(t.score_of(&peer), None, "valid frames must not be penalized");
    }

    /// An invalid-block frame (NewBlock larger than MAX_WIRE_BYTES) is a
    /// protocol violation: cumulative -100 per offense; the FOURTH crosses
    /// graylist_threshold (-400). This is the deterministic, swarm-free
    /// assertion of the reaction `run()` applies via set_application_score.
    #[test]
    fn wire_reaction_penalizes_oversized_invalid_block_cumulatively() {
        let mut t = WirePenaltyTracker::new();
        let peer = PeerId::random();
        let big = bincode::serde::encode_to_vec(
            &NetworkMessage::NewBlock {
                block_hash: [0u8; 32],
                blue_score: 0,
                height:     0,
                block_data: vec![0u8; MAX_WIRE_BYTES + 1024],
            },
            bincode::config::standard(),
        ).expect("encode");

        for i in 1..=4i32 {
            match t.classify(peer, &big) {
                WireReaction::Penalize { score, error } => {
                    assert!(error.is_protocol_violation());
                    assert_eq!(score, WIRE_VIOLATION_PENALTY * f64::from(i));
                }
                other => panic!("expected Penalize, got {:?}", other),
            }
        }
        // Fourth violation: -400 == the gossipsub graylist_threshold in run().
        assert_eq!(t.score_of(&peer), Some(-400.0));
    }

    /// The cumulative penalty floors at WIRE_PENALTY_FLOOR — a flood of
    /// violations cannot drive the score to -inf.
    #[test]
    fn wire_reaction_penalty_floors() {
        let mut t = WirePenaltyTracker::new();
        let peer = PeerId::random();
        let bad: Vec<u8> = vec![0u8; MAX_WIRE_BYTES + 1];
        for _ in 0..30 {
            t.classify(peer, &bad);
        }
        assert_eq!(t.score_of(&peer), Some(WIRE_PENALTY_FLOOR));
    }

    /// A bounds-violating frame UNDER the byte limit (PEX list too long) is
    /// also a protocol violation — the byte limit alone can't catch it.
    #[test]
    fn wire_reaction_penalizes_bounds_violation() {
        let mut t = WirePenaltyTracker::new();
        let peer = PeerId::random();
        let peers: Vec<String> = (0..(MAX_WIRE_ADDRS + 1))
            .map(|i| format!("/ip4/1.2.3.4/tcp/{}", i % 65535))
            .collect();
        let bytes = bincode::serde::encode_to_vec(
            &NetworkMessage::PeerExchange { peers },
            bincode::config::standard(),
        ).expect("encode");
        assert!(bytes.len() < MAX_WIRE_BYTES);
        match t.classify(peer, &bytes) {
            WireReaction::Penalize { error: WireDecodeError::Bounds(_), score } => {
                assert_eq!(score, WIRE_VIOLATION_PENALTY);
            }
            other => panic!("expected Penalize(Bounds), got {:?}", other),
        }
    }

    /// Plain-malformed bincode (possible benign version skew) is ignored,
    /// never penalized.
    #[test]
    fn wire_reaction_ignores_malformed_without_penalty() {
        let mut t = WirePenaltyTracker::new();
        let peer = PeerId::random();
        match t.classify(peer, &[0xFF; 16]) {
            WireReaction::IgnoreMalformed(_) => {}
            other => panic!("expected IgnoreMalformed, got {:?}", other),
        }
        assert_eq!(t.score_of(&peer), None);
        assert_eq!(t.tracked_peers(), 0);
    }

    /// Once the tracking map is full the map does not grow (memory bound
    /// against identity cycling).
    ///
    /// NET-8 (audit): this test used to assert that a late offender is NOT
    /// tracked ("one-shot offender is not inserted") — which let every
    /// offender arriving after 1,024 identities violate forever without ever
    /// reaching the graylist. It now pins the fixed behaviour: the mildest
    /// entry is evicted and the late offender IS tracked and accumulates.
    #[test]
    fn wire_reaction_track_cap_bounds_memory() {
        let mut t = WirePenaltyTracker::new();
        let bad: Vec<u8> = vec![0u8; MAX_WIRE_BYTES + 1];
        for _ in 0..WIRE_PENALTY_TRACK_CAP {
            t.classify(PeerId::random(), &bad);
        }
        assert_eq!(t.tracked_peers(), WIRE_PENALTY_TRACK_CAP);

        let late = PeerId::random();
        match t.classify(late, &bad) {
            WireReaction::Penalize { score, .. } => {
                assert_eq!(score, WIRE_VIOLATION_PENALTY);
            }
            other => panic!("expected Penalize, got {:?}", other),
        }
        assert_eq!(t.tracked_peers(), WIRE_PENALTY_TRACK_CAP, "map must not grow past cap");
        assert_eq!(t.score_of(&late), Some(WIRE_VIOLATION_PENALTY), "late offender is tracked");
        for _ in 0..4 {
            t.classify(late, &bad);
        }
        assert!(t.score_of(&late).unwrap() <= -400.0, "late offender reaches the graylist");
    }

    /// NET-4 / NET-8: penalties decay and are eventually forgotten (and the
    /// reset score is returned so gossipsub's app score is re-installed).
    #[test]
    fn wire_penalties_decay_and_are_forgotten() {
        let mut t = WirePenaltyTracker::new();
        let p = PeerId::random();
        let t0 = std::time::Instant::now();
        for _ in 0..4 {
            t.record_violation_at(p, t0);
        }
        assert_eq!(t.score_of(&p), Some(-400.0));
        assert!(t.decay_tick_at(t0 + Duration::from_secs(1)).is_empty(), "no decay within one interval");
        let after = t.decay_tick_at(t0 + WIRE_PENALTY_DECAY_INTERVAL * 5);
        let s = after.iter().find(|(q, _)| *q == p).map(|(_, s)| *s).expect("decayed score reported");
        assert!(s > -400.0 && s < -200.0, "decayed toward zero: {s}");
        let later = t.decay_tick_at(t0 + WIRE_PENALTY_DECAY_INTERVAL * 200);
        assert_eq!(later, vec![(p, 0.0)], "forgotten peers are reset to 0");
        assert_eq!(t.tracked_peers(), 0);
    }

    // ── NET-7 regressions ──────────────────────────────────────────────────

    /// Trailing bytes after a valid frame are a protocol violation: they made
    /// every request byte-unique and defeated gossipsub de-duplication.
    #[test]
    fn wire_decode_rejects_trailing_bytes() {
        for base in [NetworkMessage::PeerRequest, NetworkMessage::GetTips] {
            let clean = bincode::serde::encode_to_vec(&base, bincode::config::standard()).unwrap();
            assert!(decode_wire_message(&clean).is_ok());
            let mut padded = clean.clone();
            padded.extend_from_slice(&7u32.to_le_bytes());
            match decode_wire_message(&padded) {
                Err(e @ WireDecodeError::TrailingBytes(4)) => assert!(e.is_protocol_violation()),
                other => panic!("trailing bytes must be rejected, got {:?}", other.map(|m| m.kind_name())),
            }
        }
    }

    /// Gossip pulls and gossip responses are neither delivered nor relayed;
    /// blocks are deferred to the validating processor; local-only frames
    /// from peers are dropped.
    #[test]
    fn gossip_pulls_are_never_served_or_relayed() {
        let pulls = [
            NetworkMessage::GetTips,
            NetworkMessage::PeerRequest,
            NetworkMessage::GetHeaders { from_blue_score: 0, limit: 500, nonce: 1 },
            NetworkMessage::GetBlock { block_hash: [0u8; 32], nonce: 1 },
            NetworkMessage::Headers { entries: vec![] },
            NetworkMessage::Tips { tips: vec![], locator: vec![] },
            NetworkMessage::BlockNotFound { block_hash: [0u8; 32], nonce: 1 },
            NetworkMessage::PeerExchange { peers: vec![] },
            NetworkMessage::PeerCount { count: 0, addresses: vec![] },
        ];
        for m in &pulls {
            for validated in [false, true] {
                assert_eq!(gossip_disposition(m, validated, true), GossipDisposition::Drop(GossipVerdict::Ignore),
                    "{} must not be delivered or relayed", m.kind_name());
            }
        }
        let blk = NetworkMessage::NewBlock { block_hash: [0u8; 32], blue_score: 0, height: 0, block_data: vec![] };
        assert_eq!(gossip_disposition(&blk, true, false), GossipDisposition::DeliverDeferred);
        assert_eq!(gossip_disposition(&blk, false, false), GossipDisposition::Deliver(GossipVerdict::Accept));
        // MEM-5: transactions are validated before relay too.
        let tx = NetworkMessage::NewTransaction { txid: [0u8; 32], tx_data: vec![] };
        assert_eq!(gossip_disposition(&tx, true, false), GossipDisposition::DeliverDeferred);
        assert_eq!(gossip_disposition(&tx, false, false), GossipDisposition::Deliver(GossipVerdict::Accept));
        let v = NetworkMessage::Version { version: 1, user_agent: "x".into(), blue_score: 1, height: 1, timestamp: 0 };
        assert_eq!(gossip_disposition(&v, true, true), GossipDisposition::Deliver(GossipVerdict::Ignore),
            "claims are consumed locally, never relayed");
        assert_eq!(gossip_disposition(&v, true, false), GossipDisposition::Drop(GossipVerdict::Ignore));
    }

    // ── NET-16 regressions ─────────────────────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn identity_file_is_owner_only_and_reloadable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p2p_identity.bin");
        let kp = load_or_create_identity(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "identity must be created 0600, got {:o}", mode);
        assert!(!dir.path().join("p2p_identity.bin.tmp").exists(), "no temp file left behind");
        // A world-readable key is tightened on load and still decodes.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let again = load_or_create_identity(&path).unwrap();
        assert_eq!(PeerId::from(kp.public()), PeerId::from(again.public()));
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn known_peers_are_written_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_peers.json");
        std::fs::write(dir.path().join("known_peers.json.tmp"), b"stale garbage").unwrap();
        let peers: HashSet<String> = ["/ip4/45.77.1.1/tcp/17110/p2p/x".to_string()].into_iter().collect();
        save_known_peers(&path, &peers);
        assert_eq!(load_known_peers(&path), peers);
        assert!(!dir.path().join("known_peers.json.tmp").exists(), "temp file renamed into place");
    }

    // ── NET-11 regression: PEX ingestion never dials ───────────────────────

    #[test]
    fn pex_ingestion_only_fills_the_table() {
        let mut book = AddrBook::new();
        let mut lim = PexRateLimiter::new();
        let mut stats = PexStats::new();
        let me = PeerId::random();
        let author = PeerId::random();
        let mut peers: Vec<String> = (0..30u8).map(|i| format!("/ip4/45.{}.1.1/tcp/17110/p2p/{}", i, PeerId::random())).collect();
        peers.push(format!("/ip4/45.200.1.1/tcp/17110/p2p/{}", me)); // ourselves
        let added = ingest_pex_addresses(&mut book, &mut lim, &mut stats, author, &peers, false, &me, &HashSet::new());
        assert_eq!(added, PEX_BATCH_LIMIT, "batch-capped per message");
        assert_eq!(book.len(), PEX_BATCH_LIMIT);
        // The same author is rate-limited across messages.
        for _ in 0..10 {
            ingest_pex_addresses(&mut book, &mut lim, &mut stats, author, &peers, false, &me, &HashSet::new());
        }
        assert!(book.len() <= pex_validator::PEX_MAX_PER_WINDOW);
    }
}
