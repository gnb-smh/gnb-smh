//! Audit POW-9 (residual): mainnet and testnet share the genesis and the
//! ASERT anchor, so the networks must be separated on the wire, as Bitcoin
//! Core separates them with per-network message start bytes. Live swarms on
//! loopback: a testnet node connected to a mainnet node receives none of its
//! gossip (and vice versa), while two mainnet nodes exchange blocks as
//! before. Transactions are separated by the chain id in every sighash
//! (`core::chain_id_tests::cross_chain_id_replay_is_rejected`, the `net/`
//! consensus vectors).
//!
//! Blocks here are a harness payload, not real PoW blocks: the point is the
//! transport.

use std::sync::Arc;
use std::time::Duration;

use gnb::consensus::GhostDAG;
use gnb::core::ChainId;
use gnb::network::{NetworkConfig, NetworkMessage, NetworkNode};
use gnb::sync::peer_state::PeerStateTable;
use libp2p::PeerId;
use parking_lot::RwLock;
use tokio::sync::mpsc;

const GENESIS: [u8; 32] = [0xCB; 32];

struct Harness {
    peer_id: PeerId,
    addr: libp2p::Multiaddr,
    dag: Arc<RwLock<GhostDAG>>,
    outbound_tx: mpsc::Sender<NetworkMessage>,
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

async fn spawn_node(chain: ChainId, bootstrap_peers: Vec<String>) -> Harness {
    let dir = tempfile::tempdir().expect("tempdir");
    let node = NetworkNode::new(config(&dir, bootstrap_peers)).expect("NetworkNode::new").with_chain(chain);
    let peer_id = node.peer_id;
    let dag = Arc::new(RwLock::new(GhostDAG::with_k(3)));
    dag.write().add_genesis(GENESIS, 0);
    let peer_state = Arc::new(PeerStateTable::new());
    let store = Arc::new(gnb::storage::Storage::open(&dir.path().join("db")).expect("store"));
    let (block_tx, mut block_rx) = mpsc::channel::<NetworkMessage>(1024);
    let (outbound_tx, outbound_rx) = mpsc::channel::<NetworkMessage>(1024);
    let (addr_tx, mut addr_rx) = mpsc::unbounded_channel::<libp2p::Multiaddr>();
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
                    if let Ok((p, _)) =
                        bincode::serde::decode_from_slice::<SimPayload, _>(&block_data, bincode::config::standard())
                    {
                        let mut d = dag.write();
                        if !d.has_block(&p.hash) && p.parents.iter().all(|h| d.has_block(h)) {
                            let _ = d.add_block(p.hash, p.parents.clone(), p.timestamp, p.work);
                        }
                    }
                }
            }
        });
    }
    let addr = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let a = addr_rx.recv().await.expect("listen_report closed");
            let s = a.to_string();
            if s.starts_with("/ip4/127.0.0.1/tcp/") && !s.contains("/ws") {
                return a;
            }
        }
    })
    .await
    .expect("listen addr");
    Harness { peer_id, addr, dag, outbound_tx, _dir: dir }
}

async fn publish_block(h: &Harness, hash: [u8; 32], ts: u64) {
    let p = SimPayload { hash, parents: vec![GENESIS], timestamp: ts, work: 1 };
    h.outbound_tx
        .send(NetworkMessage::NewBlock {
            block_hash: hash,
            block_data: bincode::serde::encode_to_vec(&p, bincode::config::standard()).unwrap(),
            height: 1,
            blue_score: 1,
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

/// Publish blocks from `from` until one reaches `to` (the gossip mesh needs a
/// few heartbeats to form). Returns whether one did within `rounds`.
async fn mesh_carries(from: &Harness, to: &Harness, tag: u8, rounds: u64) -> bool {
    for i in 0..rounds {
        let mut h = [tag; 32];
        h[31] = i as u8;
        publish_block(from, h, 10 + i).await;
        if arrives(to, h, 3).await {
            return true;
        }
    }
    false
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn testnet_and_mainnet_nodes_exchange_no_gossip() {
    let main_a = spawn_node(ChainId::Mainnet, vec![]).await;
    let main_c = spawn_node(ChainId::Mainnet, vec![full_addr(&main_a)]).await;
    let test_b = spawn_node(ChainId::Testnet, vec![full_addr(&main_a)]).await;
    // Two mainnet nodes: the mesh carries blocks (the harness works).
    assert!(mesh_carries(&main_a, &main_c, 0xA1, 10).await, "mainnet -> mainnet gossip works");
    // Mainnet gossip never reaches the testnet node it is connected to...
    let mut x = [0xA2; 32];
    for i in 0..3u8 {
        x[31] = i;
        publish_block(&main_a, x, 100 + i as u64).await;
        assert!(arrives(&main_c, x, 10).await, "the mainnet peer receives it");
    }
    assert!(!arrives(&test_b, x, 5).await, "a testnet node received a mainnet block");
    // ...and testnet gossip never reaches mainnet nodes.
    let mut y = [0xB1; 32];
    for i in 0..3u8 {
        y[31] = i;
        publish_block(&test_b, y, 200 + i as u64).await;
    }
    assert!(!arrives(&main_a, y, 5).await, "a mainnet node received a testnet block");
    assert!(!arrives(&main_c, y, 1).await, "a mainnet node received a testnet block");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_testnet_nodes_exchange_gossip() {
    let a = spawn_node(ChainId::Testnet, vec![]).await;
    let b = spawn_node(ChainId::Testnet, vec![full_addr(&a)]).await;
    assert!(mesh_carries(&a, &b, 0xC1, 10).await, "testnet -> testnet gossip works");
}
