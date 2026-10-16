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

mod fix_common;

const GENESIS: [u8; 32] = [0xCB; 32];

/// `PeerCount` reports: (peer count, tried table at that moment).
type Reports = Arc<RwLock<Vec<(usize, Vec<String>)>>>;

struct Harness {
    peer_id: PeerId,
    addr: libp2p::Multiaddr,
    dag: Arc<RwLock<GhostDAG>>,
    outbound_tx: mpsc::Sender<NetworkMessage>,
    /// Every `PeerCount` report the node delivered: the peer count and the
    /// tried table (`known_peers`) at that moment.
    reports: Reports,
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
    let reports: Reports = Arc::default();
    {
        let (dag, ps, store) = (dag.clone(), peer_state.clone(), store.clone());
        tokio::spawn(async move {
            let _ = node.run(block_tx, outbound_rx, dag, ps, store, Some(addr_tx)).await;
        });
    }
    {
        let (dag, reports) = (dag.clone(), reports.clone());
        tokio::spawn(async move {
            while let Some(msg) = block_rx.recv().await {
                if let NetworkMessage::PeerCount { count, addresses } = &msg {
                    reports.write().push((*count, addresses.clone()));
                }
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
    Harness { peer_id, addr, dag, outbound_tx, reports, _dir: dir }
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

/// Wait until `cond` holds on `h`'s reports, for at most `secs`.
async fn reports_reach(h: &Harness, secs: u64, cond: impl Fn(&[(usize, Vec<String>)]) -> bool) -> bool {
    tokio::time::timeout(Duration::from_secs(secs), async {
        loop {
            if cond(&h.reports.read()) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .unwrap_or(false)
}

/// POW-9 (review): a dialed address enters the tried table (`known_peers`,
/// saved to known_peers.json, redialed at start, served to `GetPeers`) only
/// after the peer's identify shows it runs this network. A testnet node
/// that dials a mainnet node is dropped on identify and never records the
/// mainnet address (it used to record it at the connection, before
/// identify, and keep it after the disconnect); a mainnet node that dials
/// the same address records it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_address_of_the_other_network_never_enters_the_tried_table() {
    let main_a = spawn_node(ChainId::Mainnet, vec![]).await;
    let test_b = spawn_node(ChainId::Testnet, vec![full_addr(&main_a)]).await;
    let main_c = spawn_node(ChainId::Mainnet, vec![full_addr(&main_a)]).await;
    let a_id = format!("/p2p/{}", main_a.peer_id);
    let names_a = |r: &(usize, Vec<String>)| r.1.iter().any(|x| x.ends_with(&a_id));

    // The testnet node connects, identifies the mainnet node and drops it:
    // a disconnect report (count back to 0 after a connection).
    assert!(
        reports_reach(&test_b, 20, |r| {
            r.iter().position(|(c, _)| *c >= 1).is_some_and(|i| r[i..].iter().any(|(c, _)| *c == 0))
        })
        .await,
        "the testnet node connected to the mainnet node and was dropped: {:?}",
        test_b.reports.read()
    );
    // The heartbeat (30 s) reports the tried table of both dialers.
    assert!(
        reports_reach(&main_c, 45, |r| r.iter().any(names_a)).await,
        "a mainnet dialer records the mainnet address once identify confirms it: {:?}",
        main_c.reports.read()
    );
    assert!(
        reports_reach(&test_b, 10, |r| r.iter().filter(|(c, _)| *c == 0).count() >= 2).await,
        "the testnet node reported its tried table again: {:?}",
        test_b.reports.read()
    );
    let reports = test_b.reports.read().clone();
    assert!(
        !reports.iter().any(names_a),
        "the mainnet address entered the testnet node's tried table: {reports:?}"
    );
}

/// POW-9 (review): a data dir without the chain id marker (every data dir of
/// an earlier release) used to be marked for whichever network opened it
/// first, so a mainnet node restarted with `--testnet` by mistake marked its
/// dir as testnet (and the hardening recheck then disqualified its blocks
/// below 110,000). The network is now read from the stored blocks: below
/// the mainnet activation a mainnet block follows the pre-activation rules
/// and a testnet block the hardening rules, and the other network is
/// refused without marking anything.
#[test]
fn an_unmarked_data_dir_is_marked_only_for_the_network_its_blocks_follow() {
    use gnb::core::activation;
    use gnb::storage::Storage;
    let (main, test) = (ChainId::Mainnet.to_u32(), ChainId::Testnet.to_u32());
    let genesis = fix_common::mk_genesis(fix_common::unix_now() - 10_000);
    let gh = genesis.block_hash();
    let two_blocks = |n: &fix_common::Node| {
        let b1 = fix_common::empty_child(n, gh, "b1");
        fix_common::accept(n, &b1).unwrap();
        let b2 = fix_common::empty_child(n, b1.block_hash(), "b2");
        fix_common::accept(n, &b2).unwrap();
        (b1, b2)
    };

    // Only the genesis: nothing tells, the running network is adopted.
    let n = fix_common::node_with(&genesis, &[]);
    assert_eq!(n.store.stored_chain_network().unwrap(), None);
    assert_eq!(n.store.check_chain_marker(test), Ok(true));

    // A mainnet data dir (pre-activation rules below 110,000).
    {
        let _g = activation::scoped_override(activation::MAINNET_HARDENING_ACTIVATION_HEIGHT);
        let n = fix_common::node_with(&genesis, &[]);
        let (b1, b2) = two_blocks(&n);
        assert_eq!(n.store.stored_chain_network().unwrap(), Some((ChainId::Mainnet, b2.block_hash(), 2)));
        let err = n.store.check_chain_marker(test).unwrap_err();
        assert!(err.contains("no chain id marker") && err.contains("0x474e0001") && err.contains("0x474e0002"), "{err}");
        assert_eq!(n.store.get_meta(Storage::CHAIN_ID_META).unwrap(), None, "the refused open marks nothing");
        // The tip's body pruned: the next row with a body tells.
        n.store.delete_block_body(&b2.block_hash()).unwrap();
        assert_eq!(n.store.stored_chain_network().unwrap(), Some((ChainId::Mainnet, b1.block_hash(), 1)));
        assert!(n.store.check_chain_marker(test).is_err());
        assert_eq!(n.store.check_chain_marker(main), Ok(true), "the right network marks it");
        assert_eq!(n.store.check_chain_marker(main), Ok(false));
        assert!(n.store.check_chain_marker(test).unwrap_err().contains("belongs to chain id 0x474e0001"));
    }

    // A testnet data dir (hardening rules from height 1).
    {
        let _g = activation::scoped_override(activation::TESTNET_HARDENING_ACTIVATION_HEIGHT);
        let n = fix_common::node_with(&genesis, &[]);
        let (_, b2) = two_blocks(&n);
        assert_eq!(n.store.stored_chain_network().unwrap(), Some((ChainId::Testnet, b2.block_hash(), 2)));
        let err = n.store.check_chain_marker(main).unwrap_err();
        assert!(err.contains("no chain id marker") && err.contains("hardened"), "{err}");
        assert_eq!(n.store.get_meta(Storage::CHAIN_ID_META).unwrap(), None);

        // A testnet block above the mainnet PoWit height (10,000). Testnet's
        // PoWit height is its own (off, or --powit-height), so the block has
        // the testnet body root (the tagged transaction root, no PoWit
        // section); this process runs mainnet's PoWit height and expects the
        // v2 body root there, so the Merkle check fails it. The network is
        // still told by the hardened coinbase commitment (it read as mainnet
        // when the inference checked the Merkle root).
        use gnb::core::{block_rules, Block, BlockHeader, MerkleRoot};
        let high = gnb::core::POWIT_HEIGHT_MAINNET + 50;
        let mut hb = Block {
            header: BlockHeader {
                version: 1, parents: vec![b2.block_hash()], merkle_root: MerkleRoot::default(),
                timestamp: b2.header.timestamp + 1, bits: b2.header.bits, nonce: 0,
            },
            transactions: vec![fix_common::coinbase("high", 1, vec![0x33; 20])],
            blue_score: high,
            height: high,
            shielded_transactions: Vec::new(),
            powit: Default::default(),
        };
        let c = block_rules::expected_coinbase_commitment(&hb);
        let input = &mut hb.transactions[0].inputs[0];
        input.script_sig = block_rules::coinbase_script_sig(&c, &std::mem::take(&mut input.script_sig));
        hb.header.merkle_root = block_rules::tx_merkle_root(&hb.transactions, true);
        assert!(gnb::core::powit_active(high) && !hb.validate_merkle_at(0),
            "this process expects the PoWit v2 body root at that height");
        assert_eq!(block_rules::check_hardened_body(&hb), Ok(()));
        n.store.put_block_body(&hb).unwrap();
        let mut batch = rocksdb::WriteBatch::default();
        n.store.stage_chain_position(&mut batch, 3, &hb.block_hash(), hb.header.timestamp).unwrap();
        n.store.write_batch(batch).unwrap();
        assert_eq!(n.store.stored_chain_network().unwrap(), Some((ChainId::Testnet, hb.block_hash(), high)));
        assert!(n.store.check_chain_marker(main).is_err(), "still refused to a mainnet node");
        assert_eq!(n.store.check_chain_marker(test), Ok(true));
    }
}

/// PoWit (from the mainnet PoWit height) adds signed messages of its own: a
/// witness attestation signs a digest bound to the chain id, so an
/// attestation for one network never verifies on the other, even for the
/// same checkpoint pair (the shared genesis is one). Witness shares commit
/// to a block id of the attested network, and PoWit items travel on that
/// network's own transaction topic (`chain_separation::chain_protocols`).
#[test]
fn powit_attestations_are_bound_to_the_chain_id() {
    use gnb::core::powit::{attestation_message, Checkpoint};
    let genesis = gnb::core::genesis_block().block_hash();
    let source = Checkpoint { height: 0, hash: genesis };
    let target = Checkpoint { height: 10_000, hash: [0x7A; 32] };
    assert_ne!(attestation_message(ChainId::Mainnet, &source, &target),
               attestation_message(ChainId::Testnet, &source, &target));
    let (m, t) = (gnb::network::chain_separation::chain_protocols(ChainId::Mainnet),
                  gnb::network::chain_separation::chain_protocols(ChainId::Testnet));
    assert_ne!(m.txs_topic, t.txs_topic, "NewPowitItem is gossiped on the transaction topic");
}
