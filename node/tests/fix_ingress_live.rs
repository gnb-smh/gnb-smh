//! Phase-4 package R2b, live (real `NetworkNode` swarms on loopback):
//!
//! * B1-T7 / NET-4 residual — an upgraded node does not cut off an honest
//!   older relay that forwards invalid block frames unvalidated (the
//!   re-audit's proof of concept, `reaudit_upgraded_node_graylists_old_honest_relay`,
//!   inverted); the control (penalties in force) shows the gate is what
//!   makes the difference;
//! * B1-T19 — a transaction flood cannot delay or drop blocks: gossip
//!   transactions have their own channel and consumer
//!   (`NetworkNode::attach_tx_ingest`); the control (one shared channel, as
//!   before) shows the block stuck behind the flood.
//!
//! Blocks are a harness payload (`SimPayload`, as in `fix_net_live.rs`);
//! the stand-in validator's verdicts go through the node's real penalty
//! policy (`ingress::block_penalty`).

use std::sync::Arc;
use std::time::{Duration, Instant};

use gnb::consensus::GhostDAG;
use gnb::ingress::{self, BlockFault};
use gnb::network::{
    GossipValidation, GossipVerdict, Inbound, InboundOrigin, NetworkConfig, NetworkControl, NetworkMessage, NetworkNode,
};
use gnb::sync::peer_state::PeerStateTable;
use libp2p::PeerId;
use parking_lot::RwLock;
use tokio::sync::mpsc;

const GENESIS: [u8; 32] = [0xCA; 32];

struct Harness {
    peer_id: PeerId,
    addr: libp2p::Multiaddr,
    dag: Arc<RwLock<GhostDAG>>,
    outbound_tx: mpsc::Sender<NetworkMessage>,
    /// When each block (by hash) reached this node's block consumer.
    block_seen: Arc<parking_lot::Mutex<std::collections::HashMap<[u8; 32], Instant>>>,
    _dir: tempfile::TempDir,
}

fn full_addr(h: &Harness) -> String {
    format!("{}/p2p/{}", h.addr, h.peer_id)
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct SimPayload {
    hash: [u8; 32],
    parents: Vec<[u8; 32]>,
    timestamp: u64,
    work: u128,
}

fn apply(dag: &Arc<RwLock<GhostDAG>>, block_data: &[u8]) -> Option<SimPayload> {
    let (p, _) = bincode::serde::decode_from_slice::<SimPayload, _>(block_data, bincode::config::standard()).ok()?;
    let mut d = dag.write();
    if !d.has_block(&p.hash) && p.parents.iter().all(|h| d.has_block(h)) {
        let _ = d.add_block(p.hash, p.parents.clone(), p.timestamp, p.work);
    }
    Some(p)
}

fn config(dir: &tempfile::TempDir, bootstrap_peers: Vec<String>) -> NetworkConfig {
    NetworkConfig {
        listen_addr: "/ip4/127.0.0.1/tcp/0".into(),
        bootstrap_peers,
        dns_seeds: vec![],
        max_peers: 8,
        data_dir: dir.path().to_path_buf(),
        allow_private_peers: true,
        behind_proxy: true,
        enable_mdns: false,
        archive: false,
    }
}

async fn learn_addr(mut addr_rx: mpsc::UnboundedReceiver<libp2p::Multiaddr>) -> libp2p::Multiaddr {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let a = addr_rx.recv().await.expect("listen_report closed");
            let s = a.to_string();
            if s.starts_with("/ip4/127.0.0.1/tcp/") && !s.contains("/ws") {
                return a;
            }
        }
    })
    .await
    .expect("listen addr")
}

fn new_dag() -> Arc<RwLock<GhostDAG>> {
    let dag = Arc::new(RwLock::new(GhostDAG::with_k(3)));
    dag.write().add_genesis(GENESIS, 0);
    dag
}

/// A node on the legacy `run()` path: every decodable block frame is
/// accepted and relayed on decode — a release from before the validated
/// relay (NET-2) as far as block frames go.
async fn spawn_legacy(bootstrap_peers: Vec<String>) -> Harness {
    let dir = tempfile::tempdir().expect("tempdir");
    let node = NetworkNode::new(config(&dir, bootstrap_peers)).expect("NetworkNode::new");
    let peer_id = node.peer_id;
    let dag = new_dag();
    let store = Arc::new(gnb::storage::Storage::open(&dir.path().join("db")).expect("store"));
    let (block_tx, mut block_rx) = mpsc::channel::<NetworkMessage>(1024);
    let (outbound_tx, outbound_rx) = mpsc::channel::<NetworkMessage>(4096);
    let (addr_tx, addr_rx) = mpsc::unbounded_channel::<libp2p::Multiaddr>();
    {
        let (dag, store) = (dag.clone(), store.clone());
        let ps = Arc::new(PeerStateTable::new());
        tokio::spawn(async move {
            let _ = node.run(block_tx, outbound_rx, dag, ps, store, Some(addr_tx)).await;
        });
    }
    let block_seen = Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new()));
    {
        let (dag, seen) = (dag.clone(), block_seen.clone());
        tokio::spawn(async move {
            while let Some(msg) = block_rx.recv().await {
                if let NetworkMessage::NewBlock { block_data, block_hash, .. } = msg {
                    seen.lock().entry(block_hash).or_insert_with(Instant::now);
                    apply(&dag, &block_data);
                }
            }
        });
    }
    let addr = learn_addr(addr_rx).await;
    Harness { peer_id, addr, dag, outbound_tx, block_seen, _dir: dir }
}

/// A node on the production `run_validated()` path whose stand-in block
/// processor Accepts blocks with `work > 0` and refuses `work == 0` ones as
/// a context-free fault (an invalid proof of work), charged through the
/// node's real policy: `ingress::block_penalty(Reject, ContextFree,
/// self_authored, in_force)` — a `Misbehaving` notice disconnects the peer.
async fn spawn_gated_validator(bootstrap_peers: Vec<String>, in_force: bool) -> Harness {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut node = NetworkNode::new(config(&dir, bootstrap_peers)).expect("NetworkNode::new");
    let peer_id = node.peer_id;
    let dag = new_dag();
    let store = Arc::new(gnb::storage::Storage::open(&dir.path().join("db")).expect("store"));
    let (inbound_tx, mut inbound_rx) = mpsc::channel::<Inbound>(1024);
    let (verdict_tx, verdict_rx) = mpsc::channel::<GossipValidation>(1024);
    let (ctl_tx, ctl_rx) = mpsc::channel::<NetworkControl>(64);
    node.attach_control(ctl_rx);
    let (outbound_tx, outbound_rx) = mpsc::channel::<NetworkMessage>(1024);
    let (addr_tx, addr_rx) = mpsc::unbounded_channel::<libp2p::Multiaddr>();
    {
        let (dag, store) = (dag.clone(), store.clone());
        let ps = Arc::new(PeerStateTable::new());
        tokio::spawn(async move {
            let _ = node.run_validated(inbound_tx, verdict_rx, outbound_rx, dag, ps, store, Some(addr_tx)).await;
        });
    }
    let block_seen = Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new()));
    {
        let (dag, seen) = (dag.clone(), block_seen.clone());
        tokio::spawn(async move {
            while let Some(Inbound { msg, origin }) = inbound_rx.recv().await {
                let NetworkMessage::NewBlock { block_data, block_hash, .. } = msg else {
                    if let Some((message_id, propagation_source)) = origin.pending_verdict() {
                        let _ = verdict_tx.send(GossipValidation { message_id, propagation_source, verdict: GossipVerdict::Ignore }).await;
                    }
                    continue;
                };
                let (verdict, misbehaving) = match bincode::serde::decode_from_slice::<SimPayload, _>(&block_data, bincode::config::standard()) {
                    Ok((p, _)) if p.work > 0 => {
                        seen.lock().entry(block_hash).or_insert_with(Instant::now);
                        apply(&dag, &block_data);
                        (GossipVerdict::Accept, false)
                    }
                    _ => {
                        let self_authored = matches!(&origin,
                            InboundOrigin::Gossip { propagation_source, author: Some(a), .. } if a == propagation_source);
                        let p = ingress::block_penalty(GossipVerdict::Reject, BlockFault::ContextFree, self_authored, in_force);
                        (p.gossip, p.misbehaving)
                    }
                };
                if let Some((message_id, propagation_source)) = origin.pending_verdict() {
                    let _ = verdict_tx.send(GossipValidation { message_id, propagation_source, verdict }).await;
                }
                if misbehaving {
                    if let Some(p) = origin.peer() {
                        let _ = ctl_tx.send(NetworkControl::Misbehaving(p)).await;
                    }
                }
            }
        });
    }
    let addr = learn_addr(addr_rx).await;
    Harness { peer_id, addr, dag, outbound_tx, block_seen, _dir: dir }
}

/// A validating node whose stand-in processor is SLOW on transactions (100 ms
/// per frame) and instant on blocks. `split`: gossip transactions go to
/// their own channel and consumer (`attach_tx_ingest`, B1-T19); otherwise
/// both share the block channel and its consumer, as before.
async fn spawn_tx_flooded_validator(bootstrap_peers: Vec<String>, split: bool) -> Harness {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut node = NetworkNode::new(config(&dir, bootstrap_peers)).expect("NetworkNode::new");
    let peer_id = node.peer_id;
    let dag = new_dag();
    let store = Arc::new(gnb::storage::Storage::open(&dir.path().join("db")).expect("store"));
    let (inbound_tx, inbound_rx) = mpsc::channel::<Inbound>(1000);
    let (verdict_tx, verdict_rx) = mpsc::channel::<GossipValidation>(8192);
    let tx_rx = if split {
        let (t, r) = mpsc::channel::<Inbound>(1000);
        node.attach_tx_ingest(t);
        Some(r)
    } else {
        None
    };
    let (outbound_tx, outbound_rx) = mpsc::channel::<NetworkMessage>(1024);
    let (addr_tx, addr_rx) = mpsc::unbounded_channel::<libp2p::Multiaddr>();
    {
        let (dag, store) = (dag.clone(), store.clone());
        let ps = Arc::new(PeerStateTable::new());
        tokio::spawn(async move {
            let _ = node.run_validated(inbound_tx, verdict_rx, outbound_rx, dag, ps, store, Some(addr_tx)).await;
        });
    }
    let block_seen = Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new()));
    async fn consume(
        mut rx: mpsc::Receiver<Inbound>,
        verdict_tx: mpsc::Sender<GossipValidation>,
        dag: Arc<RwLock<GhostDAG>>,
        seen: Arc<parking_lot::Mutex<std::collections::HashMap<[u8; 32], Instant>>>,
    ) {
        while let Some(Inbound { msg, origin }) = rx.recv().await {
            let verdict = match msg {
                NetworkMessage::NewBlock { block_data, block_hash, .. } => {
                    seen.lock().entry(block_hash).or_insert_with(Instant::now);
                    apply(&dag, &block_data);
                    GossipVerdict::Accept
                }
                NetworkMessage::NewTransaction { .. } => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    GossipVerdict::Ignore
                }
                _ => GossipVerdict::Ignore,
            };
            if let Some((message_id, propagation_source)) = origin.pending_verdict() {
                let _ = verdict_tx.try_send(GossipValidation { message_id, propagation_source, verdict });
            }
        }
    }
    tokio::spawn(consume(inbound_rx, verdict_tx.clone(), dag.clone(), block_seen.clone()));
    if let Some(r) = tx_rx {
        tokio::spawn(consume(r, verdict_tx, dag.clone(), block_seen.clone()));
    }
    let addr = learn_addr(addr_rx).await;
    Harness { peer_id, addr, dag, outbound_tx, block_seen, _dir: dir }
}

async fn publish_block(h: &Harness, hash: [u8; 32], parent: [u8; 32], ts: u64, work: u128) {
    let p = SimPayload { hash, parents: vec![parent], timestamp: ts, work };
    h.outbound_tx
        .send(NetworkMessage::NewBlock {
            block_hash: hash,
            block_data: bincode::serde::encode_to_vec(&p, bincode::config::standard()).unwrap(),
            height: ts,
            blue_score: ts,
        })
        .await
        .unwrap();
}

async fn arrives(h: &Harness, hash: [u8; 32], secs: u64) -> bool {
    tokio::time::timeout(Duration::from_secs(secs), async {
        loop {
            if h.dag.read().has_block(&hash) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .unwrap_or(false)
}

fn init_log() {
    let _ = env_logger::builder()
        .is_test(true)
        .filter_level(log::LevelFilter::Warn)
        .filter_module("libp2p_gossipsub", log::LevelFilter::Error)
        .try_init();
}

/// The re-audit's scenario (verify_partial.json, verify.NET-4 residual;
/// B1-T7): legacy hub B forwards every block frame on decode; attacker A,
/// connected only to B, publishes five invalid blocks; upgraded C and honest
/// D are connected only to B. Pre-fix C answered `Reject` for each relayed
/// frame, gossipsub charged B, and C graylisted its only path to D: D's next
/// block never reached C (reproduced by the re-audit). Now, before the
/// activation, a relayed frame is not charged to the relay
/// (`ingress::block_penalty`): D's block still arrives. Control: with
/// penalties in force (a chain past the activation, where no release that
/// forwards unvalidated frames follows the chain), C charges the relay and
/// D's block does not arrive — the gate is what makes the difference.
async fn legacy_relay_scenario(in_force: bool) -> bool {
    let b = spawn_legacy(vec![]).await;
    let c = spawn_gated_validator(vec![full_addr(&b)], in_force).await;
    let d = spawn_legacy(vec![full_addr(&b)]).await;
    let a = spawn_legacy(vec![full_addr(&b)]).await;
    tokio::time::sleep(Duration::from_secs(12)).await;

    publish_block(&d, [0xD1; 32], GENESIS, 1, 1).await;
    assert!(arrives(&c, [0xD1; 32], 20).await, "control: D's block must reach C via B");
    for i in 0..5u8 {
        publish_block(&a, [0xB0 + i; 32], GENESIS, 10 + i as u64, 0).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    tokio::time::sleep(Duration::from_secs(5)).await;
    publish_block(&d, [0xD2; 32], [0xD1; 32], 2, 1).await;
    assert!(arrives(&b, [0xD2; 32], 20).await, "B (the old relay) gets D's block");
    arrives(&c, [0xD2; 32], 30).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_legacy_relay_is_not_graylisted_for_forwarding_invalid_blocks() {
    init_log();
    assert!(legacy_relay_scenario(false).await, "C kept the honest old relay B: D's block arrived");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_control_relayed_invalid_blocks_are_charged_once_penalties_are_in_force() {
    init_log();
    assert!(!legacy_relay_scenario(true).await, "control: with penalties in force C cut off the relay");
}

/// B1-T19: attacker A floods transaction frames at validator V, whose
/// processor needs 100 ms per transaction (the cost of an expensive junk
/// frame, modelled) — faster than V can judge them, so a backlog builds;
/// honest D, on its own connection, then publishes a block. With
/// transactions on their own channel and consumer (the node since Phase 4)
/// D's block reaches V's block consumer at once. Control (`split = false`:
/// one channel and one consumer shared with the flood, as before): D's block
/// waits behind the backlog of A's transactions — or is dropped by the full
/// channel — and does not arrive within the same time. (A single peer's own
/// frames arrive in order on its connection: what the attacker could delay
/// was everyone else's blocks.)
async fn tx_flood_scenario(split: bool) -> Option<Duration> {
    let v = spawn_tx_flooded_validator(vec![], split).await;
    let a = spawn_legacy(vec![full_addr(&v)]).await;
    let d = spawn_legacy(vec![full_addr(&v)]).await;
    tokio::time::sleep(Duration::from_secs(12)).await;
    publish_block(&d, [0xB0; 32], GENESIS, 1, 1).await;
    assert!(arrives(&v, [0xB0; 32], 20).await, "control: D's block reaches V before the flood");
    for i in 0..1_500u32 {
        let mut txid = [0x7Au8; 32];
        txid[..4].copy_from_slice(&i.to_le_bytes());
        a.outbound_tx.send(NetworkMessage::NewTransaction { txid, tx_data: vec![0xEE; 256] }).await.unwrap();
    }
    // Let the backlog build (A's frames arrive faster than V judges them).
    tokio::time::sleep(Duration::from_secs(4)).await;
    let sent = Instant::now();
    publish_block(&d, [0xB1; 32], [0xB0; 32], 2, 1).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(at) = v.block_seen.lock().get(&[0xB1; 32]) {
                return at.saturating_duration_since(sent);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .ok()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_tx_flood_does_not_delay_blocks() {
    init_log();
    let latency = tx_flood_scenario(true).await;
    println!("honest block latency during a transaction flood (own channel): {latency:?}");
    assert!(latency.is_some_and(|l| l < Duration::from_secs(2)), "{latency:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_control_shared_channel_delays_blocks_behind_a_tx_flood() {
    init_log();
    let latency = tx_flood_scenario(false).await;
    println!("honest block latency during a transaction flood (shared channel): {latency:?}");
    assert!(latency.is_none_or(|l| l >= Duration::from_secs(3)), "control: the block waits behind the flood: {latency:?}");
}
