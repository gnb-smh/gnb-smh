//! Live (real `NetworkNode` swarms on loopback) tests for validated
//! transaction relay — audit MEM-5 residual and NET-2 / NET-4 on the
//! transaction side, plus MEM-6 orphan relay.
//!
//! The validating nodes run the production `run_validated` path with a
//! processor that calls the SAME library function as `main.rs`
//! (`mempool::relay::TxRelay::on_gossip_tx`, i.e. the shared admission with
//! real hybrid signatures, real UTXO stores) and reports its verdicts, and
//! defers orphan verdicts with `DeferredVerdicts` exactly like `main.rs`
//! (relay key = the delivering connection, deferral keyed by the frame's
//! wtxid and timed from its arrival, settlement from the relay's
//! `OrphanEvents`, penalties through `NetworkControl`).
//! Before the fix, `gossip_disposition` relayed every decodable
//! `NewTransaction` frame (`Deliver(Accept)`).

mod fix_common;
use fix_common::*;

use std::sync::Arc;
use std::time::{Duration, Instant};

use gnb::core::{Block, Transaction};
use gnb::mempool::admission;
use gnb::mempool::relay::{DeferredVerdicts, TxRelay};
use gnb::mempool::Mempool;
use gnb::network::{
    GossipValidation, GossipVerdict, Inbound, InboundOrigin, NetworkConfig, NetworkControl, NetworkMessage, NetworkNode,
};
use libp2p::PeerId;
use parking_lot::Mutex;
use tokio::sync::mpsc;

struct Peer {
    peer_id: PeerId,
    addr: libp2p::Multiaddr,
    outbound_tx: mpsc::Sender<NetworkMessage>,
    /// Every NewTransaction txid this node's processor received.
    seen: Arc<Mutex<Vec<[u8; 32]>>>,
    mempool: Option<Arc<Mempool>>,
    _node: Option<Node>,
    _dir: tempfile::TempDir,
}

fn full_addr(p: &Peer) -> String {
    format!("{}/p2p/{}", p.addr, p.peer_id)
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

/// A publisher on the legacy `run()` path (no validation).
async fn spawn_publisher(bootstrap_peers: Vec<String>) -> Peer {
    let dir = tempfile::tempdir().expect("tempdir");
    let node = NetworkNode::new(config(&dir, bootstrap_peers)).expect("NetworkNode::new");
    let peer_id = node.peer_id;
    let n = node_with(&mk_genesis(unix_now() - 10_000), &[]);
    let peer_state = Arc::new(gnb::sync::peer_state::PeerStateTable::new());
    let (block_tx, mut block_rx) = mpsc::channel::<NetworkMessage>(1024);
    let (outbound_tx, outbound_rx) = mpsc::channel::<NetworkMessage>(1024);
    let (addr_tx, addr_rx) = mpsc::unbounded_channel::<libp2p::Multiaddr>();
    let seen = Arc::new(Mutex::new(Vec::new()));
    {
        let (dag, store) = (n.dag.clone(), n.store.clone());
        tokio::spawn(async move {
            let _ = node.run(block_tx, outbound_rx, dag, peer_state, store, Some(addr_tx)).await;
        });
    }
    {
        let seen = seen.clone();
        tokio::spawn(async move {
            while let Some(msg) = block_rx.recv().await {
                if let NetworkMessage::NewTransaction { txid, .. } = msg {
                    seen.lock().push(txid);
                }
            }
        });
    }
    let addr = learn_addr(addr_rx).await;
    Peer { peer_id, addr, outbound_tx, seen, mempool: None, _node: Some(n), _dir: dir }
}

/// A validating node: production `run_validated`, real store holding
/// `genesis` + `funds`, the library transaction relay as processor.
async fn spawn_validator(bootstrap_peers: Vec<String>, genesis: &Block, funds: &[([u8; 32], u32, gnb::core::TxOutput)]) -> Peer {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut node = NetworkNode::new(config(&dir, bootstrap_peers)).expect("NetworkNode::new");
    let peer_id = node.peer_id;
    let (ctl_tx, ctl_rx) = mpsc::channel::<NetworkControl>(64);
    node.attach_control(ctl_rx);
    let n = node_with(genesis, funds);
    let peer_state = Arc::new(gnb::sync::peer_state::PeerStateTable::new());
    let (inbound_tx, mut inbound_rx) = mpsc::channel::<Inbound>(1024);
    let (verdict_tx, verdict_rx) = mpsc::channel::<GossipValidation>(1024);
    let (outbound_tx, outbound_rx) = mpsc::channel::<NetworkMessage>(1024);
    let (addr_tx, addr_rx) = mpsc::unbounded_channel::<libp2p::Multiaddr>();
    let seen = Arc::new(Mutex::new(Vec::new()));
    {
        let (dag, store) = (n.dag.clone(), n.store.clone());
        tokio::spawn(async move {
            let _ = node.run_validated(inbound_tx, verdict_rx, outbound_rx, dag, peer_state, store, Some(addr_tx)).await;
        });
    }
    {
        let (dag, store, mempool, seen) = (n.dag.clone(), n.store.clone(), n.mempool.clone(), seen.clone());
        tokio::spawn(async move {
            let mut relay = TxRelay::new();
            let mut deferred: DeferredVerdicts<InboundOrigin> = DeferredVerdicts::new();
            let report = |origin: &InboundOrigin, verdict: GossipVerdict| {
                if let Some((message_id, propagation_source)) = origin.pending_verdict() {
                    let _ = verdict_tx.try_send(GossipValidation { message_id, propagation_source, verdict });
                }
            };
            while let Some(Inbound { msg, origin }) = inbound_rx.recv().await {
                let NetworkMessage::NewTransaction { txid, tx_data } = msg else {
                    report(&origin, GossipVerdict::Ignore);
                    continue;
                };
                seen.lock().push(txid);
                let peer = origin.peer();
                let received_at = origin.received_at().unwrap_or_else(Instant::now);
                let next = admission::next_block_height(&dag.read());
                let o = tokio::task::block_in_place(|| {
                    relay.on_gossip_tx(&store, &mempool, next, &txid, &tx_data, peer, Instant::now(), unix_now())
                });
                if o.orphaned {
                    if let Some(back) = deferred.defer(o.wtxid, origin, received_at, Instant::now()) {
                        report(&back, GossipVerdict::Ignore);
                    }
                } else {
                    report(&origin, o.verdict);
                }
                let settled = deferred.settle(&o.orphans, Instant::now());
                for (released, verdict) in settled.verdicts {
                    report(&released, verdict);
                }
                for p in settled.penalize {
                    let _ = ctl_tx.try_send(NetworkControl::PenalizePeer(p));
                }
            }
        });
    }
    let addr = learn_addr(addr_rx).await;
    let mempool = Some(n.mempool.clone());
    Peer { peer_id, addr, outbound_tx, seen, mempool, _node: Some(n), _dir: dir }
}

async fn publish(p: &Peer, tx: &Transaction) {
    p.outbound_tx
        .send(NetworkMessage::NewTransaction { txid: tx.txid(), tx_data: tx.to_wire_bytes(true) })
        .await
        .unwrap();
}

async fn pooled(p: &Peer, txid: [u8; 32], secs: u64) -> bool {
    let mp = p.mempool.clone().expect("validating peer");
    tokio::time::timeout(Duration::from_secs(secs), async {
        loop {
            if mp.contains(&txid) {
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

/// MEM-5 / NET-2 / NET-4 (live). Topology A — B — C and D — B; B and C
/// validate. Attacker A publishes eight consensus-invalid transactions (bad
/// hybrid signatures): honest relay B rejects them (A, their author, takes
/// gossipsub's invalid-message penalty and is graylisted by B) and never
/// forwards them, so C never sees one and never has a reason to penalise B.
/// A valid transaction from honest D still reaches C through B (B was not
/// cut off) and enters C's pool.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_invalid_tx_is_not_relayed_and_relay_is_not_penalised() {
    init_log();
    let genesis = mk_genesis(unix_now() - 10_000);
    let k = key();
    let funds: Vec<_> = (0..2u8).map(|i| ([0xD0 + i; 32], 0u32, out(1_000_000, &k.spk))).collect();
    let b = spawn_validator(vec![], &genesis, &funds).await;
    let c = spawn_validator(vec![full_addr(&b)], &genesis, &funds).await;
    let a = spawn_publisher(vec![full_addr(&b)]).await;
    let d = spawn_publisher(vec![full_addr(&b)]).await;
    tokio::time::sleep(Duration::from_secs(12)).await;

    let mut invalid = Vec::new();
    for i in 0..8u64 {
        let mut t = signed_spend(&k, &[(funds[0].0, 0)], vec![out(900_000 - i, &[0x11; 20])]);
        t.inputs[0].script_sig[10] ^= 0xFF;
        invalid.push(t.txid());
        publish(&a, &t).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    tokio::time::sleep(Duration::from_secs(5)).await;
    let b_seen = b.seen.lock().clone();
    assert!(invalid.iter().any(|t| b_seen.contains(t)), "the invalid frames reached relay B");

    let valid = signed_spend(&k, &[(funds[1].0, 0)], vec![out(950_000, &[0x22; 20])]);
    publish(&d, &valid).await;
    assert!(pooled(&b, valid.txid(), 30).await, "B admits the valid transaction");
    assert!(pooled(&c, valid.txid(), 30).await, "the valid transaction propagates through B to C");

    let c_seen = c.seen.lock().clone();
    assert!(!invalid.iter().any(|t| c_seen.contains(t)), "B never forwarded an invalid transaction");
    for t in &invalid {
        assert!(!b.mempool.as_ref().unwrap().contains(t));
    }
}

/// MEM-6 (live). A publishes a child BEFORE its parent. Relay B buffers the
/// child as an orphan and withholds its verdict; when the parent arrives B
/// admits both and releases the child's frame, so C receives and pools both.
/// Pre-fix the child was dropped at B ("UTXO not found") and never reached
/// C's pool.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_child_before_parent_propagates_through_the_orphan_pool() {
    init_log();
    let genesis = mk_genesis(unix_now() - 10_000);
    let k = key();
    let funds = vec![([0xE0u8; 32], 0u32, out(1_000_000, &k.spk))];
    let b = spawn_validator(vec![], &genesis, &funds).await;
    let c = spawn_validator(vec![full_addr(&b)], &genesis, &funds).await;
    let a = spawn_publisher(vec![full_addr(&b)]).await;
    tokio::time::sleep(Duration::from_secs(12)).await;

    let parent = signed_spend(&k, &[(funds[0].0, 0)], vec![out(950_000, &k.spk)]);
    let child = signed_spend(&k, &[(parent.txid(), 0)], vec![out(900_000, &[0x33; 20])]);
    publish(&a, &child).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(!b.mempool.as_ref().unwrap().contains(&child.txid()), "an orphan waits for its parent");
    publish(&a, &parent).await;

    assert!(pooled(&b, parent.txid(), 30).await);
    assert!(pooled(&b, child.txid(), 30).await, "B admitted the orphan when its parent arrived");
    assert!(pooled(&c, parent.txid(), 30).await, "the parent propagates to C");
    assert!(pooled(&c, child.txid(), 30).await, "the child propagates to C");
    let e = c.mempool.as_ref().unwrap().get_entry(&child.txid()).unwrap();
    assert!(e.parents.contains(&parent.txid()), "C holds the chain as parent and child");
    let _ = &a;
}
