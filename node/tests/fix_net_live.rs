//! Live (real `NetworkNode` swarms on loopback) regression tests for the
//! network fixes NET-2, NET-4, NET-5, NET-6 and NET-11. Each test is the
//! inverse of the corresponding live proof of concept in
//! `audit/poc/node/tests/audit_poc_net.rs`.
//!
//! Blocks here are a harness payload (`SimPayload`), not real PoW blocks: the
//! point is the transport/relay policy, not block validation.

use std::sync::Arc;
use std::time::Duration;

use gnb::consensus::GhostDAG;
use gnb::network::{
    GossipValidation, GossipVerdict, Inbound, NetworkConfig, NetworkMessage, NetworkNode,
    MAX_WIRE_USER_AGENT_LEN,
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
    peer_state: Arc<PeerStateTable>,
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

/// A node on the legacy `run()` path (blocks relayed on decode).
async fn spawn_node(bootstrap_peers: Vec<String>) -> Harness {
    let dir = tempfile::tempdir().expect("tempdir");
    let node = NetworkNode::new(config(&dir, bootstrap_peers)).expect("NetworkNode::new");
    let peer_id = node.peer_id;
    let dag = Arc::new(RwLock::new(GhostDAG::with_k(3)));
    dag.write().add_genesis(GENESIS, 0);
    let peer_state = Arc::new(PeerStateTable::new());
    let store = Arc::new(gnb::storage::Storage::open(&dir.path().join("db")).expect("store"));
    let (block_tx, mut block_rx) = mpsc::channel::<NetworkMessage>(1024);
    let (outbound_tx, outbound_rx) = mpsc::channel::<NetworkMessage>(1024);
    let (addr_tx, addr_rx) = mpsc::unbounded_channel::<libp2p::Multiaddr>();
    {
        let (dag, ps, store) = (dag.clone(), peer_state.clone(), store.clone());
        tokio::spawn(async move {
            let _ = node.run(block_tx, outbound_rx, dag, ps, store, Some(addr_tx)).await;
        });
    }
    {
        let dag = dag.clone();
        tokio::spawn(async move {
            while let Some(msg) = block_rx.recv().await {
                if let NetworkMessage::NewBlock { block_data, .. } = msg {
                    apply(&dag, &block_data);
                }
            }
        });
    }
    let addr = learn_addr(addr_rx).await;
    Harness { peer_id, addr, dag, outbound_tx, peer_state, _dir: dir }
}

/// A node on the production `run_validated()` path whose "processor" Accepts
/// blocks with `work > 0` and Rejects blocks with `work == 0` (invalid).
async fn spawn_validating_node(bootstrap_peers: Vec<String>) -> Harness {
    let dir = tempfile::tempdir().expect("tempdir");
    let node = NetworkNode::new(config(&dir, bootstrap_peers)).expect("NetworkNode::new");
    let peer_id = node.peer_id;
    let dag = Arc::new(RwLock::new(GhostDAG::with_k(3)));
    dag.write().add_genesis(GENESIS, 0);
    let peer_state = Arc::new(PeerStateTable::new());
    let store = Arc::new(gnb::storage::Storage::open(&dir.path().join("db")).expect("store"));
    let (inbound_tx, mut inbound_rx) = mpsc::channel::<Inbound>(1024);
    let (verdict_tx, verdict_rx) = mpsc::channel::<GossipValidation>(1024);
    let (outbound_tx, outbound_rx) = mpsc::channel::<NetworkMessage>(1024);
    let (addr_tx, addr_rx) = mpsc::unbounded_channel::<libp2p::Multiaddr>();
    {
        let (dag, ps, store) = (dag.clone(), peer_state.clone(), store.clone());
        tokio::spawn(async move {
            let _ = node.run_validated(inbound_tx, verdict_rx, outbound_rx, dag, ps, store, Some(addr_tx)).await;
        });
    }
    {
        let dag = dag.clone();
        tokio::spawn(async move {
            while let Some(Inbound { msg, origin }) = inbound_rx.recv().await {
                if let NetworkMessage::NewBlock { block_data, .. } = msg {
                    let verdict = match bincode::serde::decode_from_slice::<SimPayload, _>(&block_data, bincode::config::standard()) {
                        Ok((p, _)) if p.work > 0 => {
                            apply(&dag, &block_data);
                            GossipVerdict::Accept
                        }
                        _ => GossipVerdict::Reject,
                    };
                    if let Some((message_id, propagation_source)) = origin.pending_verdict() {
                        let _ = verdict_tx.send(GossipValidation { message_id, propagation_source, verdict }).await;
                    }
                }
            }
        });
    }
    let addr = learn_addr(addr_rx).await;
    Harness { peer_id, addr, dag, outbound_tx, peer_state, _dir: dir }
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

/// NET-2 (live): with `validate_messages()`, a relay forwards ONLY frames its
/// processor accepted. Topology A — B — C; B runs `run_validated`. A's invalid
/// block (work 0) is rejected by B and never reaches C; A's valid block does.
/// Before the fix gossipsub forwarded every frame before validation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_relay_forwards_only_validated_blocks() {
    init_log();
    let b = spawn_validating_node(vec![]).await;
    let c = spawn_node(vec![full_addr(&b)]).await;
    let a = spawn_node(vec![full_addr(&b)]).await;
    tokio::time::sleep(Duration::from_secs(12)).await;

    let bad = [0xBA; 32];
    let good = [0x60; 32];
    publish_block(&a, bad, GENESIS, 1, 0).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    publish_block(&a, good, GENESIS, 2, 1).await;

    assert!(arrives(&c, good, 30).await, "the validated block is relayed by B to C");
    assert!(arrives(&b, good, 1).await);
    assert!(!arrives(&c, bad, 5).await, "the rejected block is never relayed to C");
}

/// NET-4 (live): A, C, D each connected only to hub B. A's bounds-violating
/// frames are rejected at B and never relayed, so honest C never charges
/// honest relay B for them and D's later block still reaches C through B.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_relayed_violations_do_not_cut_honest_relay() {
    init_log();
    let b = spawn_node(vec![]).await;
    let c = spawn_node(vec![full_addr(&b)]).await;
    let d = spawn_node(vec![full_addr(&b)]).await;
    let a = spawn_node(vec![full_addr(&b)]).await;
    tokio::time::sleep(Duration::from_secs(12)).await;

    publish_block(&d, [0xD1; 32], GENESIS, 1, 1).await;
    assert!(arrives(&c, [0xD1; 32], 20).await, "control: D's block must reach C via B");

    for i in 0..5u8 {
        a.outbound_tx
            .send(NetworkMessage::Version {
                version: 1,
                user_agent: format!("{}{}", "z".repeat(MAX_WIRE_USER_AGENT_LEN + 1), i),
                blue_score: 0,
                height: 0,
                timestamp: i as u64,
            })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(700)).await;
    }
    tokio::time::sleep(Duration::from_secs(5)).await;

    publish_block(&d, [0xD2; 32], [0xD1; 32], 2, 1).await;
    assert!(arrives(&b, [0xD2; 32], 20).await);
    assert!(arrives(&c, [0xD2; 32], 30).await, "honest C must still receive D's block through honest B");
}

/// NET-5 (live): an IBD-sized burst of 200 directed pulls from X exceeds Y's
/// limiter; Y answers `Busy` instead of closing the stream, X does not charge
/// Y a protocol violation, and Y's next block still reaches X.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_rate_limited_server_is_not_graylisted() {
    init_log();
    let y = spawn_node(vec![]).await;
    let x = spawn_node(vec![full_addr(&y)]).await;
    tokio::time::sleep(Duration::from_secs(12)).await;

    publish_block(&y, [0xC1; 32], GENESIS, 1, 1).await;
    assert!(arrives(&x, [0xC1; 32], 20).await, "control: Y's block must reach X");

    for i in 0u32..200 {
        let mut h = [0x5Au8; 32];
        h[..4].copy_from_slice(&i.to_le_bytes());
        x.outbound_tx
            .send(NetworkMessage::GetBlock { block_hash: h, nonce: i as u64 })
            .await
            .unwrap();
    }
    tokio::time::sleep(Duration::from_secs(8)).await;

    publish_block(&y, [0xC2; 32], [0xC1; 32], 2, 1).await;
    assert!(arrives(&x, [0xC2; 32], 25).await, "X must not graylist Y for rate-limiting X's own requests");
}

/// NET-6 (live): A's `Version { blue_score: u64::MAX }` reaches C only via
/// relay B. It is not relayed at all now, and C never records it against B
/// (nor against A, to which C is not connected): C's best announced claim
/// stays at the honest value.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_relayed_tip_inflation_is_not_attributed_to_relay() {
    init_log();
    let b = spawn_node(vec![]).await;
    let c = spawn_node(vec![full_addr(&b)]).await;
    let a = spawn_node(vec![full_addr(&b)]).await;
    tokio::time::sleep(Duration::from_secs(12)).await;

    a.outbound_tx
        .send(NetworkMessage::Version {
            version: 1,
            user_agent: "gnb/poc".into(),
            blue_score: u64::MAX,
            height: u64::MAX,
            timestamp: 12345,
        })
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(4)).await;
    for i in 0..3u64 {
        b.outbound_tx
            .send(NetworkMessage::Version {
                version: 1,
                user_agent: "gnb/honest".into(),
                blue_score: 0,
                height: 1,
                timestamp: 99_000 + i,
            })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    tokio::time::sleep(Duration::from_secs(3)).await;

    let our = c.dag.read().tip_blue_score();
    let snap = c.peer_state.snapshot();
    let b_row = snap.iter().find(|(p, _)| *p == b.peer_id).map(|(_, s)| s.announced_blue_score);
    let best = c.peer_state.best_announced_blue_score();
    assert_eq!(b_row, Some(0), "relay B is charged only with its own (honest) claim");
    assert!(!snap.iter().any(|(p, _)| *p == a.peer_id), "a non-connected author never gets a row");
    assert!(our.saturating_add(gnb::sync::IBD_EXIT_LAG) >= best, "C is caught up by every claim it holds");
}

/// NET-11 (live): an unsolicited gossip PeerExchange naming an address must
/// never make the receiver dial it — not immediately, and not later from the
/// address table either (unsolicited addresses never enter it).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_unsolicited_pex_triggers_no_dials() {
    init_log();
    let a = spawn_node(vec![]).await;
    let b = spawn_node(vec![full_addr(&a)]).await;
    tokio::time::sleep(Duration::from_secs(12)).await;

    // A plain TCP listener standing in for a reflection / port-scan victim.
    let victim = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = victim.local_addr().unwrap().port();
    let target = format!("/ip4/127.0.0.1/tcp/{}/p2p/{}", port, PeerId::random());
    for _ in 0..3 {
        b.outbound_tx.send(NetworkMessage::PeerExchange { peers: vec![target.clone()] }).await.unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    // Longer than two PEX dial ticks (10 s each).
    let dialed = tokio::time::timeout(Duration::from_secs(25), victim.accept()).await;
    assert!(dialed.is_err(), "the victim address must never be dialed");
}
