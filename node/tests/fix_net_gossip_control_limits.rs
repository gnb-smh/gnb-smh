//! Review follow-up to OPS-2 (libp2p 0.57 brings gossipsub 0.50): a
//! default-config gossipsub 0.50 receiver rejects any RPC whose control part
//! is over 16 KiB and closes its inbound gossipsub stream, but the sender put
//! up to 5000 ids (about 90 KB) into one IHAVE. Anyone could fill the tx
//! topic's gossip window with about 1000 cheap frames and so make honest nodes
//! cut each other's gossip links (blocks included) with their own IHAVEs.
//!
//! Harness: three real libp2p swarms on loopback with the node's transport
//! (TCP + `KyberConfig` + the node's yamux config) and the node's gossipsub
//! configuration (`gnb::network::gossipsub_config_builder`). Topology
//! C — A — B: C floods A with unique `NewTransaction` frames, which A accepts
//! (the worst case: frames that pass validation). The mesh is switched off
//! (`mesh_n = 0`), so B is a non-mesh peer of A, as most of a node's 50 peers
//! are on mainnet: everything B learns from A on the tx topic comes through
//! A's IHAVE gossip (IHAVE -> IWANT -> message), and A's block reaches B by
//! flood publishing on the same A -> B stream.
//!
//! Frames are unsigned here (gossipsub `Anonymous` mode instead of the node's
//! `Signed` + `Strict`): unoptimized ed25519 limits a debug-build swarm to
//! about 120 frames/s, far below the attack's volume. What is under test, the
//! size of an IHAVE, depends only on how many ids it carries.

use std::convert::Infallible;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use gnb::network::{
    gossipsub_config_builder, yamux_config, NetworkMessage, GOSSIP_MAX_CONTROL_BYTES, GOSSIP_MAX_CONTROL_IDS,
    GOSSIP_PEER_DEFAULT_CONTROL_BYTES, TOPIC_BLOCKS, TOPIC_TXS,
};
use gnb::transport::identity::{PeerPins, PqIdentity};
use gnb::transport::upgrade::PqConfig;
use libp2p::gossipsub::{self, IdentTopic, MessageAcceptance, MessageAuthenticity};
use libp2p::swarm::SwarmEvent;
use libp2p::{identity, tcp, Multiaddr, PeerId, SwarmBuilder};
use tokio::sync::mpsc;

/// What gossipsub 0.50 uses when nothing is configured (the pre-fix node).
const DEFAULT_IDS_SENT: usize = 5000;

/// How many unique frames C publishes, and over how long.
const FLOOD_FRAMES: usize = 1500;
const FLOOD_BATCH: usize = 75;
const FLOOD_BATCH_GAP: Duration = Duration::from_millis(100);

#[derive(Clone, Copy)]
struct Limits {
    ids_sent: usize,
    control_bytes: usize,
}

enum Cmd {
    Dial(Multiaddr),
    Publish(&'static str, Vec<u8>),
}

#[derive(Default)]
struct Seen {
    /// Tx-topic frames received with this propagation source (`via`).
    txs_via: AtomicUsize,
    /// Tx-topic frames received from anyone.
    txs_total: AtomicUsize,
    /// A block-topic frame was received.
    block: AtomicBool,
}

struct Peer {
    id: PeerId,
    addr: Multiaddr,
    cmd: mpsc::UnboundedSender<Cmd>,
    seen: Arc<Seen>,
}

/// One swarm with the node's gossipsub config, mesh off, unsigned frames,
/// `limits` applied.
async fn spawn(limits: Limits, via: Option<PeerId>) -> Peer {
    let mut builder = gossipsub_config_builder();
    builder
        .mesh_outbound_min(0)
        .mesh_n_low(0)
        .mesh_n(0)
        .mesh_n_high(0)
        .max_control_messages_sent(limits.ids_sent)
        .max_control_message_size(limits.control_bytes)
        .validation_mode(gossipsub::ValidationMode::Anonymous);
    let cfg = builder.build().expect("gossipsub config");
    let pq = Arc::new(PqIdentity::generate().expect("PQ identity"));
    let pins = Arc::new(PeerPins::in_memory());
    let mut swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            move |keys: &identity::Keypair| -> Result<PqConfig, Infallible> { Ok(PqConfig::new(keys, pq, pins)) },
            yamux_config,
        )
        .expect("tcp")
        .with_behaviour(|_key| {
            gossipsub::Behaviour::<gossipsub::IdentityTransform, gossipsub::AllowAllSubscriptionFilter>::new(
                MessageAuthenticity::Anonymous,
                cfg,
            )
            .expect("gs")
        })
        .expect("behaviour")
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(300)))
        .build();
    for t in [TOPIC_BLOCKS, TOPIC_TXS] {
        swarm.behaviour_mut().subscribe(&IdentTopic::new(t)).unwrap();
    }
    swarm.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();
    let addr = loop {
        if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
            break address;
        }
    };
    let id = *swarm.local_peer_id();
    let seen = Arc::new(Seen::default());
    let (cmd, mut cmd_rx) = mpsc::unbounded_channel::<Cmd>();
    let seen_task = seen.clone();
    let tx_hash = IdentTopic::new(TOPIC_TXS).hash();
    let block_hash = IdentTopic::new(TOPIC_BLOCKS).hash();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                ev = swarm.select_next_some() => {
                    if let SwarmEvent::Behaviour(gossipsub::Event::Message { propagation_source, message_id, message }) = ev {
                        if message.topic == tx_hash {
                            seen_task.txs_total.fetch_add(1, Ordering::Relaxed);
                            if Some(propagation_source) == via {
                                seen_task.txs_via.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        if message.topic == block_hash {
                            seen_task.block.store(true, Ordering::Relaxed);
                        }
                        // Every frame passes validation (worst case for the tx flood).
                        swarm.behaviour_mut().report_message_validation_result(
                            &message_id, &propagation_source, MessageAcceptance::Accept);
                    }
                }
                c = cmd_rx.recv() => match c {
                    Some(Cmd::Dial(a)) => { let _ = swarm.dial(a); }
                    Some(Cmd::Publish(t, data)) => { let _ = swarm.behaviour_mut().publish(IdentTopic::new(t), data); }
                    None => break,
                },
            }
        }
    });
    Peer { id, addr, cmd, seen }
}

fn frame(msg: &NetworkMessage) -> Vec<u8> {
    bincode::serde::encode_to_vec(msg, bincode::config::standard()).unwrap()
}

async fn wait_for(secs: u64, f: impl Fn() -> bool) -> bool {
    tokio::time::timeout(Duration::from_secs(secs), async {
        while !f() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .is_ok()
}

struct Outcome {
    block_delivered: bool,
    txs_from_a: usize,
}

/// C floods A, then A publishes a block; report what B got from A.
async fn run(a_limits: Limits, b_limits: Limits) -> Outcome {
    let a = spawn(a_limits, None).await;
    let b = spawn(b_limits, Some(a.id)).await;
    let c = spawn(a_limits, None).await;
    b.cmd.send(Cmd::Dial(a.addr.clone())).unwrap();
    c.cmd.send(Cmd::Dial(a.addr.clone())).unwrap();
    // Connections and subscriptions settle; nobody is in anybody's mesh.
    tokio::time::sleep(Duration::from_secs(4)).await;

    let mut sent = 0usize;
    while sent < FLOOD_FRAMES {
        for _ in 0..FLOOD_BATCH {
            let mut txid = [0u8; 32];
            txid[..8].copy_from_slice(&(sent as u64).to_le_bytes());
            let msg = NetworkMessage::NewTransaction { txid, tx_data: vec![0xA5; 64] };
            c.cmd.send(Cmd::Publish(TOPIC_TXS, frame(&msg))).unwrap();
            sent += 1;
        }
        tokio::time::sleep(FLOOD_BATCH_GAP).await;
    }
    // A's gossip window now holds every frame: let a few heartbeats pass so
    // its IHAVEs to B carry them.
    tokio::time::sleep(Duration::from_secs(4)).await;
    let flood_at_a = a.seen.txs_total.load(Ordering::Relaxed);
    assert!(flood_at_a >= 1000, "harness: A received only {flood_at_a} of the {FLOOD_FRAMES} flood frames");

    let block = NetworkMessage::NewBlock {
        block_hash: [0xB1; 32],
        blue_score: 1,
        height: 1,
        block_data: vec![0x42; 200],
    };
    a.cmd.send(Cmd::Publish(TOPIC_BLOCKS, frame(&block))).unwrap();
    let seen = b.seen.clone();
    let block_delivered = wait_for(10, move || seen.block.load(Ordering::Relaxed)).await;
    let out = Outcome { block_delivered, txs_from_a: b.seen.txs_via.load(Ordering::Relaxed) };
    eprintln!("A received {flood_at_a} flood frames; B fetched {} of them from A; block delivered: {}",
        out.txs_from_a, out.block_delivered);
    out
}

const NODE: Limits = Limits { ids_sent: GOSSIP_MAX_CONTROL_IDS, control_bytes: GOSSIP_MAX_CONTROL_BYTES };

/// The fix, send side: A (this node's config) keeps every IHAVE under the
/// 16 KiB a default gossipsub 0.50 receiver accepts. B, with exactly that
/// default receive limit, decodes A's IHAVEs (it fetches the advertised frames
/// from A by IWANT) and A's later block still reaches it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ihave_floods_do_not_cut_the_link_to_a_default_receiver() {
    let default_receiver = Limits { ids_sent: GOSSIP_MAX_CONTROL_IDS, control_bytes: GOSSIP_PEER_DEFAULT_CONTROL_BYTES };
    let out = run(NODE, default_receiver).await;
    assert!(out.txs_from_a > 0, "B never fetched a frame A advertised: no IHAVE from A was decoded");
    assert!(out.block_delivered, "A's block must reach B after the flood ({} txs via A)", out.txs_from_a);
}

/// The fix, receive side: B (this node's config) decodes the full 5000-id
/// IHAVEs a sender on gossipsub's default send limit (libp2p 0.49 nodes
/// during the rollout, other implementations) produces.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_node_decodes_full_size_ihaves_from_default_senders() {
    let default_sender = Limits { ids_sent: DEFAULT_IDS_SENT, control_bytes: GOSSIP_MAX_CONTROL_BYTES };
    let out = run(default_sender, NODE).await;
    assert!(out.txs_from_a > 0, "B never fetched a frame A advertised: no IHAVE from A was decoded");
    assert!(out.block_delivered, "A's block must reach B after the flood ({} txs via A)", out.txs_from_a);
}

/// Control: with gossipsub 0.50's defaults on both sides (the configuration
/// before the fix) the same flood makes A's IHAVE undecodable for B, and A's
/// block never arrives — the attack this file guards against reproduces in
/// this harness. (If a later libp2p splits oversized IHAVEs itself, this
/// control fails and can be dropped; the two tests above must keep passing.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn control_default_limits_cut_the_link() {
    let defaults = Limits { ids_sent: DEFAULT_IDS_SENT, control_bytes: GOSSIP_PEER_DEFAULT_CONTROL_BYTES };
    let out = run(defaults, defaults).await;
    assert!(!out.block_delivered,
        "expected the pre-fix defaults to cut A -> B gossip ({} txs via A before the cut)", out.txs_from_a);
}
