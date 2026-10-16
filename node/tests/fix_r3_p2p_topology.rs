//! Phase-4 package R3 regression tests: P2P topology and eclipse resistance
//! (re-audit items B1-T8, B1-T9, NET-11 residual).
//!
//! Each test is the inverse of the failing scenario on the code before the
//! fix (commit e3e45df):
//!
//! * B1-T8: the PEX address filter accepted host names (`/dns4/...`, each its
//!   own "netgroup", resolved later to any IP) and IPv6 literals that embed
//!   loopback / private IPv4 (`::ffff:127.0.0.1`, 6to4, Teredo, NAT64).
//! * B1-T9: dialing from the address table ran only while the TOTAL peer
//!   count (inbound included) was below `max_peers`, so inbound connections
//!   froze the outbound set.
//! * NET-11 (a): inbound slots were first-come (libp2p `connection_limits`
//!   refused every newcomer once full); now an unprotected inbound peer is
//!   evicted (Bitcoin Core's `AttemptToEvictConnection`).
//! * NET-11 (b)/(d): anchors (Core's `anchors.dat`) — block-relay-only
//!   outbound peers are persisted and re-dialed first after a restart, and a
//!   block-relay-only connection carries no gossip (no transaction or address
//!   relay); blocks are learned from it by directed frontier polls.
//!
//! The live tests run real `NetworkNode` swarms (and, for the inbound flood,
//! minimal libp2p swarms with the node's transport) on loopback.

use std::convert::Infallible;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use gnb::consensus::GhostDAG;
use gnb::network::pex_validator::{is_valid_public_multiaddr, netgroup};
use gnb::network::{yamux_config, NetworkConfig, NetworkMessage, NetworkNode};
use gnb::sync::peer_state::PeerStateTable;
use gnb::transport::upgrade::KyberConfig;
use libp2p::swarm::SwarmEvent;
use libp2p::{identity, tcp, Multiaddr, PeerId, SwarmBuilder};
use parking_lot::RwLock;
use tokio::sync::mpsc;

const GENESIS: [u8; 32] = [0xCA; 32];

fn pid() -> String {
    PeerId::random().to_string()
}

// ── B1-T8: address filter, table-driven ─────────────────────────────────────

/// B1-T8: every form that names a host or reaches a loopback / private /
/// link-local IPv4 through an IPv6 literal is refused from peer exchange,
/// whatever its spelling. Before the fix every one of these was accepted.
#[test]
fn pex_filter_refuses_host_names_and_embedded_private_ipv4() {
    let refused = [
        // Host names: each was its own netgroup and resolved to any IP.
        "/dns/x.evil.example/tcp/17110",
        "/dns4/n1.attacker.example/tcp/17110",
        "/dns6/n2.attacker.example/tcp/17110",
        "/dns4/n3.attacker.example/tcp/17111/ws",
        "/dns4/localhost/tcp/17110",
        // IPv4-mapped (::ffff:a.b.c.d) loopback / RFC1918 / link-local (cloud metadata).
        "/ip6/::ffff:127.0.0.1/tcp/17110",
        "/ip6/::ffff:10.0.0.5/tcp/17110",
        "/ip6/::ffff:192.168.1.1/tcp/17110",
        "/ip6/::ffff:172.16.0.9/tcp/17110",
        "/ip6/::ffff:169.254.169.254/tcp/80",
        "/ip6/::ffff:100.64.0.1/tcp/17110",
        "/ip6/::ffff:0.0.0.0/tcp/17110",
        // IPv4-compatible (::a.b.c.d, deprecated).
        "/ip6/::127.0.0.1/tcp/17110",
        "/ip6/::10.1.2.3/tcp/17110",
        // SIIT (RFC 6145, ::ffff:0:a.b.c.d).
        "/ip6/::ffff:0:10.0.0.1/tcp/17110",
        // NAT64 well-known prefix (RFC 6052, 64:ff9b::/96).
        "/ip6/64:ff9b::a00:5/tcp/17110",
        "/ip6/64:ff9b::7f00:1/tcp/17110",
        // 6to4 (RFC 3964, 2002:AABB:CCDD::/48) of 10.0.0.5 and 127.0.0.1.
        "/ip6/2002:a00:5::1/tcp/17110",
        "/ip6/2002:7f00:1::1/tcp/17110",
        // Teredo (RFC 4380): client IPv4 is the bit-inverted last 32 bits;
        // !0xf5ff:fffa = 10.0.0.5.
        "/ip6/2001:0:4136:e378:8000:63bf:f5ff:fffa/tcp/17110",
        // IPv6 documentation / ORCHID ranges: never routable.
        "/ip6/2001:db8::1/tcp/17110",
        "/ip6/2001:10::1/tcp/17110",
        "/ip6/2001:20::1/tcp/17110",
        // Port 0 is not a reachable service.
        "/ip4/80.78.28.142/tcp/0",
    ];
    for a in refused {
        let addr = format!("{a}/p2p/{}", pid());
        assert!(!is_valid_public_multiaddr(&addr, false), "must be refused from PEX: {addr}");
    }
    // Public forms stay accepted, including IPv6 forms that embed a PUBLIC
    // IPv4 (they are dialable public addresses).
    let accepted = [
        "/ip4/80.78.28.142/tcp/17110",
        "/ip6/2606:4700:4700::1111/tcp/17110",
        "/ip6/::ffff:80.78.28.142/tcp/17110",
        "/ip6/2002:504e:1c8e::1/tcp/17110",
        "/ip4/80.78.28.142/tcp/17111/ws",
    ];
    for a in accepted {
        let addr = format!("{a}/p2p/{}", pid());
        assert!(is_valid_public_multiaddr(&addr, false), "public address must be accepted: {addr}");
    }
    // In dev mode (--allow-private-peers) a mapped loopback is accepted like
    // the plain IPv4 literal it denotes, but a host name still is not.
    assert!(is_valid_public_multiaddr(&format!("/ip6/::ffff:127.0.0.1/tcp/1/p2p/{}", pid()), true));
    assert!(!is_valid_public_multiaddr(&format!("/dns4/localhost/tcp/1/p2p/{}", pid()), true));
}

/// B1-T8: the netgroup of an address that embeds an IPv4 is the /16 of that
/// IPv4, whatever IPv6 spelling carries it, so the per-netgroup caps cannot be
/// dodged by re-spelling the same /16. Host names have no netgroup at all.
#[test]
fn netgroup_is_computed_on_the_embedded_ipv4() {
    let v4 = netgroup(&format!("/ip4/45.77.1.2/tcp/1/p2p/{}", pid()));
    assert!(v4.is_some());
    for spelled in [
        "/ip6/::ffff:45.77.9.9/tcp/1",
        "/ip6/::45.77.9.9/tcp/1",
        "/ip6/64:ff9b::2d4d:909/tcp/1",
        "/ip6/2002:2d4d:909::1/tcp/1",
    ] {
        assert_eq!(netgroup(&format!("{spelled}/p2p/{}", pid())), v4, "{spelled} is in 45.77/16");
    }
    assert_eq!(netgroup(&format!("/dns4/a.example/tcp/1/p2p/{}", pid())), None);
}

// ── Live harness ─────────────────────────────────────────────────────────────

struct Node {
    peer_id: PeerId,
    addr: Multiaddr,
    outbound_tx: mpsc::Sender<NetworkMessage>,
    peer_state: Arc<PeerStateTable>,
    /// Gossip `NewBlock` frames delivered to this node's processor.
    blocks: Arc<AtomicUsize>,
    /// Directed `Tips` answers delivered to this node's processor.
    tips: Arc<AtomicUsize>,
    /// Times the peer count rose from 0 (a first peer connected).
    rises_from_zero: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
    dir: Arc<tempfile::TempDir>,
}

impl Node {
    fn full_addr(&self) -> String {
        format!("{}/p2p/{}", self.addr, self.peer_id)
    }
    fn is_connected_to(&self, p: &PeerId) -> bool {
        self.peer_state.snapshot().iter().any(|(q, _)| q == p)
    }
}

fn init_log() {
    let _ = env_logger::builder()
        .is_test(true)
        .filter_level(log::LevelFilter::Warn)
        .filter_module("libp2p_gossipsub", log::LevelFilter::Error)
        .try_init();
}

/// A node on the legacy `run()` path. `dir` may be pre-seeded (identity,
/// known_peers.json, anchors.json) by the caller.
async fn spawn_node(dir: Arc<tempfile::TempDir>, bootstrap_peers: Vec<String>, max_peers: usize) -> Node {
    spawn_node_with(dir, bootstrap_peers, max_peers, |_| {}).await
}

/// [`spawn_node`] with `tune` applied to the `NetworkNode` before it runs.
async fn spawn_node_with(
    dir: Arc<tempfile::TempDir>,
    bootstrap_peers: Vec<String>,
    max_peers: usize,
    tune: impl FnOnce(&mut NetworkNode),
) -> Node {
    let cfg = NetworkConfig {
        listen_addr: "/ip4/127.0.0.1/tcp/0".into(),
        bootstrap_peers,
        dns_seeds: vec![],
        max_peers,
        data_dir: dir.path().to_path_buf(),
        allow_private_peers: true,
        behind_proxy: true,
        enable_mdns: false,
        archive: false,
    };
    let mut node = NetworkNode::new(cfg).expect("NetworkNode::new");
    tune(&mut node);
    let peer_id = node.peer_id;
    let dag = Arc::new(RwLock::new(GhostDAG::with_k(3)));
    dag.write().add_genesis(GENESIS, 0);
    let peer_state = Arc::new(PeerStateTable::new());
    let store = Arc::new(gnb::storage::Storage::open(&dir.path().join("db")).expect("store"));
    let (block_tx, mut block_rx) = mpsc::channel::<NetworkMessage>(1024);
    let (outbound_tx, outbound_rx) = mpsc::channel::<NetworkMessage>(1024);
    let (addr_tx, mut addr_rx) = mpsc::unbounded_channel::<Multiaddr>();
    let task = {
        let (dag, ps) = (dag.clone(), peer_state.clone());
        tokio::spawn(async move {
            let _ = node.run(block_tx, outbound_rx, dag, ps, store, Some(addr_tx)).await;
        })
    };
    let blocks = Arc::new(AtomicUsize::new(0));
    let tips = Arc::new(AtomicUsize::new(0));
    let rises_from_zero = Arc::new(AtomicUsize::new(0));
    {
        let (blocks, tips, rises) = (blocks.clone(), tips.clone(), rises_from_zero.clone());
        tokio::spawn(async move {
            let mut last_count = 0usize;
            while let Some(msg) = block_rx.recv().await {
                match msg {
                    NetworkMessage::NewBlock { .. } => {
                        blocks.fetch_add(1, Ordering::Relaxed);
                    }
                    NetworkMessage::Tips { .. } => {
                        tips.fetch_add(1, Ordering::Relaxed);
                    }
                    NetworkMessage::PeerCount { count, .. } => {
                        if last_count == 0 && count > 0 {
                            rises.fetch_add(1, Ordering::SeqCst);
                        }
                        last_count = count;
                    }
                    _ => {}
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
    Node { peer_id, addr, outbound_tx, peer_state, blocks, tips, rises_from_zero, task, dir }
}

fn new_dir() -> Arc<tempfile::TempDir> {
    Arc::new(tempfile::tempdir().expect("tempdir"))
}

async fn wait_for(secs: u64, mut cond: impl FnMut() -> bool) -> bool {
    tokio::time::timeout(Duration::from_secs(secs), async {
        loop {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .is_ok()
}

/// A bare libp2p swarm with the node's transport and no protocols: it only
/// holds a connection open (an attacker's inbound slot filler, or a minimal
/// inbound peer). `connected` is true while a connection to the target is up.
struct Bare {
    connected: Arc<AtomicBool>,
    _task: tokio::task::JoinHandle<()>,
}

async fn spawn_bare(target: Multiaddr) -> Bare {
    let mut swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            |keys: &identity::Keypair| -> Result<KyberConfig, Infallible> { Ok(KyberConfig::new(keys)) },
            yamux_config,
        )
        .expect("tcp")
        .with_behaviour(|_| libp2p::swarm::dummy::Behaviour)
        .expect("behaviour")
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(600)))
        .build();
    swarm.dial(target).expect("dial");
    let connected = Arc::new(AtomicBool::new(false));
    let flag = connected.clone();
    let task = tokio::spawn(async move {
        loop {
            match swarm.select_next_some().await {
                SwarmEvent::ConnectionEstablished { .. } => flag.store(true, Ordering::SeqCst),
                SwarmEvent::ConnectionClosed { num_established: 0, .. } => flag.store(false, Ordering::SeqCst),
                _ => {}
            }
        }
    });
    Bare { connected, _task: task }
}

// ── B1-T9: inbound connections never freeze outbound dialing ────────────────

/// B1-T9 (live). V (max_peers = 3) learns honest H's address from its
/// bootstrap peer R's GetPeers answer, then two inbound connections arrive
/// (V: 1 outbound + 2 inbound = 3 = max_peers). Before the fix the table
/// dialer ran only while the TOTAL peer count was below max_peers, so V never
/// dialed H: an attacker filling inbound slots froze the outbound set. Now
/// outbound slots are counted apart from inbound and V dials H.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_inbound_connections_do_not_freeze_outbound_dialing() {
    init_log();
    let h = spawn_node(new_dir(), vec![], 8).await;
    // R knows H (its persisted tried table) and serves it in GetPeers answers.
    let r_dir = new_dir();
    std::fs::write(r_dir.path().join("known_peers.json"), serde_json::to_string(&vec![h.full_addr()]).unwrap()).unwrap();
    let r = spawn_node(r_dir, vec![], 8).await;
    let v = spawn_node(new_dir(), vec![r.full_addr()], 3).await;
    // Two inbound slot fillers, connected within a second or two (well before
    // the old 10 s table-dial tick).
    let a1 = spawn_bare(v.addr.clone()).await;
    let a2 = spawn_bare(v.addr.clone()).await;
    assert!(wait_for(10, || a1.connected.load(Ordering::SeqCst) && a2.connected.load(Ordering::SeqCst)).await,
        "the two inbound connections are up");
    assert!(wait_for(10, || v.is_connected_to(&r.peer_id)).await, "V is connected to its bootstrap peer R");
    // H must not have dialed V itself (it has no peers configured).
    assert!(
        wait_for(40, || v.is_connected_to(&h.peer_id)).await,
        "V must dial H from its address table although its inbound slots are full"
    );
}

// ── NET-11 (a): inbound eviction instead of first-come slots ────────────────

/// NET-11 (a) (live). V's 24 inbound slots are full; a 25th inbound peer
/// connects. Before the fix libp2p's connection limit refused it (slots were
/// first-come). Now V evicts one unprotected inbound peer (Bitcoin Core's
/// `AttemptToEvictConnection`): the newcomer stays, exactly one older peer is
/// dropped, and the longest-connected peer is never the one evicted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_full_inbound_evicts_an_unprotected_peer_instead_of_refusing() {
    init_log();
    const MAX: usize = 24;
    let v = spawn_node(new_dir(), vec![], MAX).await;
    let mut old = Vec::new();
    for _ in 0..MAX {
        let b = spawn_bare(v.addr.clone()).await;
        assert!(wait_for(10, || b.connected.load(Ordering::SeqCst)).await, "inbound slot filled");
        old.push(b);
        tokio::time::sleep(Duration::from_millis(60)).await;
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(old.iter().all(|b| b.connected.load(Ordering::SeqCst)));

    let newcomer = spawn_bare(v.addr.clone()).await;
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(newcomer.connected.load(Ordering::SeqCst), "a full inbound table must evict, not refuse the newcomer");
    let dropped = old.iter().filter(|b| !b.connected.load(Ordering::SeqCst)).count();
    assert_eq!(dropped, 1, "exactly one inbound peer is evicted");
    assert!(old[0].connected.load(Ordering::SeqCst), "the longest-connected inbound peer is protected");
}

// ── NET-11 (b)/(d): anchors and block-relay-only connections ────────────────

/// NET-11 (b)+(d) (live). V starts with B in `anchors.json` (Core's
/// anchors.dat). V dials B first, as a BLOCK-RELAY-ONLY connection: no gossip
/// runs on it (B's gossiped block never reaches V that way), while V keeps
/// learning B's frontier through the PERIODIC directed `GetTips` polls (the
/// poll period is shortened to 1 s here; several Tips answers must arrive,
/// not only the one-off connect-time exchange). Such a peer is not reported
/// to the processor as a peer (the miner's no-peer gate). V persists its
/// block-relay-only peers as the new anchors; after a restart (same data dir)
/// V dials B again. Before the fix `anchors.json` did not exist and V never
/// connected to B.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_anchor_is_redialed_after_restart_as_block_relay_only() {
    init_log();
    let b = spawn_node(new_dir(), vec![], 8).await;
    let v_dir = new_dir();
    std::fs::write(v_dir.path().join("anchors.json"), serde_json::to_string(&vec![b.full_addr()]).unwrap()).unwrap();
    let fast_poll = |n: &mut NetworkNode| n.set_block_relay_poll_interval(Duration::from_secs(1));
    let v = spawn_node_with(v_dir.clone(), vec![], 8, fast_poll).await;
    assert!(wait_for(15, || v.is_connected_to(&b.peer_id)).await, "V dials its anchor B at start-up");

    // Block relay over the anchor works by periodic directed frontier polls
    // (the connect-time GetTips alone would give exactly one answer)...
    assert!(wait_for(20, || v.tips.load(Ordering::Relaxed) >= 3).await, "V keeps polling B's frontier (GetTips)");
    // ...but no gossip runs on it: B's gossiped block does not reach V.
    let payload = vec![1u8, 2, 3];
    b.outbound_tx
        .send(NetworkMessage::NewBlock { block_hash: [0xB1; 32], blue_score: 1, height: 1, block_data: payload })
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(v.blocks.load(Ordering::Relaxed), 0, "a block-relay-only connection carries no gossip");
    // Nothing V publishes reaches B either, so V must not count B as a peer
    // for its miner / relay (its reported peer count never left 0).
    assert_eq!(v.rises_from_zero.load(Ordering::SeqCst), 0, "a block-relay-only peer is not a relay peer");

    // The anchors file now names B (written by V itself).
    let anchors_path = v_dir.path().join("anchors.json");
    assert!(
        wait_for(10, || std::fs::read_to_string(&anchors_path).map(|s| s.contains(&b.peer_id.to_string())).unwrap_or(false)).await,
        "V persists its block-relay-only peer as an anchor"
    );

    // Restart V on the same data dir: it dials B again.
    v.task.abort();
    let _ = v.task.await;
    assert!(wait_for(15, || !b.is_connected_to(&v.peer_id)).await, "B sees V go away");
    let v2 = spawn_node_with(v_dir.clone(), vec![], 8, fast_poll).await;
    assert_eq!(v2.peer_id, v.peer_id, "same identity after restart");
    assert!(wait_for(15, || v2.is_connected_to(&b.peer_id)).await, "the anchor survives the restart");
    drop(v.dir);
}

// ── NET-11 (c): feelers ─────────────────────────────────────────────────────

/// NET-11 (c) (live). With every outbound slot full (targets 0/0 here) V
/// tests addresses from its new table with FEELER connections: it learns H
/// from R's GetPeers answer, connects to H, and closes the connection shortly
/// (H is never kept as a peer, and is tested only once: the address leaves
/// the new table and is promoted to the tried table). R also has targets 0/0,
/// so V's feeler is the only connection H ever sees. Before the fix there
/// were no feelers: H was never contacted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_feeler_tests_a_new_table_address_and_disconnects() {
    init_log();
    let h = spawn_node(new_dir(), vec![], 8).await;
    let r_dir = new_dir();
    std::fs::write(r_dir.path().join("known_peers.json"), serde_json::to_string(&vec![h.full_addr()]).unwrap()).unwrap();
    let r = spawn_node_with(r_dir, vec![], 8, |n| n.set_outbound_targets(0, 0)).await;
    let v = spawn_node_with(new_dir(), vec![r.full_addr()], 8, |n| {
        n.set_outbound_targets(0, 0);
        n.set_feeler_interval(Duration::from_secs(1));
    })
    .await;
    assert!(wait_for(30, || h.rises_from_zero.load(Ordering::SeqCst) >= 1).await, "V's feeler reaches H");
    tokio::time::sleep(Duration::from_secs(8)).await;
    assert!(!h.is_connected_to(&v.peer_id), "the feeler connection is closed after a second");
    assert!(!v.is_connected_to(&h.peer_id), "a feeler is never one of V's peers");
    assert_eq!(h.rises_from_zero.load(Ordering::SeqCst), 1, "H is tested once, not re-dialed");
    assert!(v.is_connected_to(&r.peer_id), "V's manual connection to R is unaffected");
}
