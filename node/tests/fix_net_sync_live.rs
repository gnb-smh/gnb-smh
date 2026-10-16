//! Live Phase 4 (package R2a) regressions: a real `NetworkNode` on loopback
//! against a hand-built libp2p peer that speaks `/gnb/sync/1` with the node's
//! transport (TCP + `PqConfig` + the node's yamux settings) but answers
//! and requests whatever it likes.
//!
//! * B1-T2 / NET-10: the node sends every new peer GetTips (and GetPeers
//!   when it dialed the peer: package R3, Core's getaddr rule). The
//!   attacker answers with 2,000 made-up headers. Those answers used to
//!   reach the processor as solicited data (2,000 GetBlocks each) and nothing
//!   ever disconnected the peer. Now they are protocol violations: nothing
//!   is delivered, and at the misbehaviour threshold (shared with the gossip
//!   and wire-violation scores) the peer is disconnected and refused on
//!   reconnect.
//! * B1-T18 / B2-T6: a peer that requests a large block over and over and
//!   never reads the answers used to make the node hold every answer (64 per
//!   burst, about 1 MB each) for the 30 s stream timeout. The node now
//!   charges each peer for the bytes of its unwritten answers and answers
//!   Busy above a small budget.

use std::convert::Infallible;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};
use gnb::consensus::GhostDAG;
use gnb::core::{Block, BlockHeader, Transaction, TxInput, TxOutput};
use gnb::network::sync_rr::{decode_request, decode_response, encode_frame, SyncRequest, SyncResponse, SYNC_PROTOCOL};
use gnb::network::{
    sync_send_bytes_outstanding, yamux_config, GossipValidation, Inbound, InboundOrigin, NetworkConfig, NetworkMessage,
    NetworkNode, SyncEntry,
};
use gnb::sync::peer_state::PeerStateTable;
use gnb::transport::identity::{PeerPins, PqIdentity};
use gnb::transport::upgrade::PqConfig;
use libp2p::request_response::{self, Codec, ProtocolSupport};
use libp2p::swarm::{Swarm, SwarmEvent};
use libp2p::{identity, tcp, Multiaddr, PeerId, StreamProtocol, SwarmBuilder};
use parking_lot::{Mutex, RwLock};
use tokio::sync::mpsc;

const GENESIS: [u8; 32] = [0xCA; 32];

/// What the attacker sends: a real request, or raw bytes.
#[derive(Clone, Debug)]
enum Out {
    Request(SyncRequest),
    Raw(Vec<u8>),
}

/// `/gnb/sync/1` with the attacker's freedom: requests are raw or encoded,
/// and with `never_read` the answers to its requests are never read.
#[derive(Clone, Default)]
struct AttackCodec {
    never_read: bool,
}

impl Codec for AttackCodec {
    type Protocol = StreamProtocol;
    type Request = Out;
    type Response = SyncResponse;

    async fn read_request<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<Out>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        io.take(64).read_to_end(&mut buf).await?;
        decode_request(&buf).map(Out::Request)
    }

    async fn read_response<T>(&mut self, _: &StreamProtocol, io: &mut T) -> io::Result<SyncResponse>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        if self.never_read {
            futures::future::pending::<()>().await;
        }
        let mut buf = Vec::new();
        io.take(4 << 20).read_to_end(&mut buf).await?;
        decode_response(&buf)
    }

    async fn write_request<T>(&mut self, _: &StreamProtocol, io: &mut T, req: Out) -> io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        let bytes = match req {
            Out::Request(r) => encode_frame(&r)?,
            Out::Raw(b) => b,
        };
        io.write_all(&bytes).await
    }

    async fn write_response<T>(&mut self, _: &StreamProtocol, io: &mut T, resp: SyncResponse) -> io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        io.write_all(&encode_frame(&resp)?).await
    }
}

type Attacker = Swarm<request_response::Behaviour<AttackCodec>>;

fn attacker_swarm(never_read: bool) -> Attacker {
    let pq = Arc::new(PqIdentity::generate().expect("PQ identity"));
    let pins = Arc::new(PeerPins::in_memory());
    SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            move |keys: &identity::Keypair| -> Result<PqConfig, Infallible> { Ok(PqConfig::new(keys, pq, pins)) },
            yamux_config,
        )
        .expect("tcp")
        .with_behaviour(|_| {
            request_response::Behaviour::with_codec(
                AttackCodec { never_read },
                std::iter::once((SYNC_PROTOCOL, ProtocolSupport::Full)),
                request_response::Config::default()
                    .with_request_timeout(Duration::from_secs(120))
                    .with_max_concurrent_streams(1024),
            )
        })
        .expect("behaviour")
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(300)))
        .build()
}

struct Victim {
    id: PeerId,
    addr: Multiaddr,
    /// Kinds of the frames delivered to the processor as directed answers.
    directed: Arc<Mutex<Vec<&'static str>>>,
    _keep: (mpsc::Sender<GossipValidation>, mpsc::Sender<NetworkMessage>, tempfile::TempDir),
}

async fn spawn_victim(stored: Option<&Block>) -> Victim {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = NetworkConfig {
        listen_addr: "/ip4/127.0.0.1/tcp/0".into(),
        bootstrap_peers: vec![],
        dns_seeds: vec![],
        max_peers: 8,
        data_dir: dir.path().to_path_buf(),
        allow_private_peers: true,
        behind_proxy: true,
        enable_mdns: false,
        archive: false,
    };
    let node = NetworkNode::new(config).expect("NetworkNode::new");
    let id = node.peer_id;
    let dag = Arc::new(RwLock::new(GhostDAG::with_k(3)));
    dag.write().add_genesis(GENESIS, 0);
    let ps = Arc::new(PeerStateTable::new());
    let store = Arc::new(gnb::storage::Storage::open(&dir.path().join("db")).expect("store"));
    if let Some(b) = stored {
        store.put_block_body(b).expect("store block");
    }
    let (inbound_tx, mut inbound_rx) = mpsc::channel::<Inbound>(1024);
    let (verdict_tx, verdict_rx) = mpsc::channel::<GossipValidation>(1024);
    let (otx, outbound_rx) = mpsc::channel::<NetworkMessage>(1024);
    let (addr_tx, mut addr_rx) = mpsc::unbounded_channel::<Multiaddr>();
    tokio::spawn(async move {
        let _ = node.run_validated(inbound_tx, verdict_rx, outbound_rx, dag, ps, store, Some(addr_tx)).await;
    });
    let directed = Arc::new(Mutex::new(Vec::new()));
    {
        let directed = directed.clone();
        tokio::spawn(async move {
            while let Some(Inbound { msg, origin }) = inbound_rx.recv().await {
                if matches!(origin, InboundOrigin::Directed { .. }) {
                    directed.lock().push(msg.kind_name());
                }
            }
        });
    }
    let addr = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let a = addr_rx.recv().await.expect("listen_report closed");
            if a.to_string().starts_with("/ip4/127.0.0.1/tcp/") {
                return a;
            }
        }
    })
    .await
    .expect("listen addr");
    Victim { id, addr, directed, _keep: (verdict_tx, otx, dir) }
}

/// Dial `v` and wait for the connection.
async fn connect(a: &mut Attacker, v: &Victim) {
    a.dial(v.addr.clone().with(libp2p::multiaddr::Protocol::P2p(v.id))).expect("dial");
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let SwarmEvent::ConnectionEstablished { peer_id, .. } = a.select_next_some().await {
                if peer_id == v.id {
                    return;
                }
            }
        }
    })
    .await
    .expect("connected");
}

fn junk_headers() -> SyncResponse {
    SyncResponse::Headers {
        entries: (0..2_000u32)
            .map(|i| {
                let mut hash = [0xEE; 32];
                hash[..4].copy_from_slice(&i.to_le_bytes());
                SyncEntry { hash, blue_score: u64::MAX, height: u64::MAX }
            })
            .collect(),
    }
}

/// B1-T2 / NET-10 (live): answers of the wrong variant are never delivered,
/// count as misbehaviour, and the fourth violation disconnects the peer,
/// which is then refused on reconnect.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_variant_answers_are_not_delivered_and_the_offender_is_disconnected() {
    let v = spawn_victim(None).await;
    let mut a = attacker_swarm(false);
    connect(&mut a, &v).await;

    // Answer everything the victim asks on connect with 2,000 made-up
    // headers. The attacker dialed, so the victim asks for its tips only:
    // package R3 sends GetPeers to outbound full-relay and manual peers
    // only (Core's getaddr rule), never to an inbound connection.
    let mut asked = Vec::new();
    let mut deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while tokio::time::Instant::now() < deadline {
        if let Ok(SwarmEvent::Behaviour(request_response::Event::Message {
            message: request_response::Message::Request { request, channel, .. },
            ..
        })) = tokio::time::timeout(Duration::from_millis(250), a.select_next_some()).await
        {
            let _ = a.behaviour_mut().send_response(channel, junk_headers());
            let tips = matches!(request, Out::Request(SyncRequest::GetTips));
            asked.push(request);
            if tips {
                // A GetPeers sent with it would arrive at about the same time.
                deadline = deadline.min(tokio::time::Instant::now() + Duration::from_millis(1_500));
            }
        }
    }
    assert!(
        matches!(asked.as_slice(), [Out::Request(SyncRequest::GetTips)]),
        "the victim asks a new inbound peer for its tips only: {asked:?}"
    );

    // Three more violations: request frames no honest node sends.
    for _ in 0..3 {
        a.behaviour_mut().send_request(&v.id, Out::Raw(vec![0xFF; 64]));
    }
    let closed = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let SwarmEvent::ConnectionClosed { peer_id, num_established: 0, .. } = a.select_next_some().await {
                if peer_id == v.id {
                    return;
                }
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "four protocol violations did not disconnect the peer");
    assert!(
        !v.directed.lock().contains(&"Headers"),
        "made-up Headers answers to GetTips reached the processor: {:?}",
        v.directed.lock()
    );

    // Discouraged: a reconnect under the same identity is closed at once.
    a.dial(v.addr.clone().with(libp2p::multiaddr::Protocol::P2p(v.id))).expect("redial");
    let refused = tokio::time::timeout(Duration::from_secs(10), async {
        let mut up = false;
        loop {
            match a.select_next_some().await {
                SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == v.id => up = true,
                SwarmEvent::ConnectionClosed { peer_id, .. } if peer_id == v.id && up => return true,
                SwarmEvent::OutgoingConnectionError { .. } => return true,
                _ => {}
            }
        }
    })
    .await;
    assert_eq!(refused, Ok(true), "a discouraged peer was let back in");
}

/// A block of about `size` bytes (only stored and served, never validated;
/// decodable: the wire decoder caps one script_sig at 10,000 bytes).
fn big_block(size: usize) -> Block {
    let txs = vec![Transaction {
        version: 1,
        inputs: (0..size / 9_000)
            .map(|i| TxInput { prev_txid: [i as u8; 32], prev_index: i as u32, script_sig: vec![0xAB; 9_000], sequence: u32::MAX })
            .collect(),
        outputs: vec![TxOutput { value: 1, script_pubkey: vec![0xCD; 20] }],
        locktime: 0,
    }];
    Block {
        header: BlockHeader {
            version: 1,
            parents: vec![GENESIS],
            merkle_root: Transaction::merkle_root(&txs),
            timestamp: 1,
            bits: 0x207f_ffff,
            nonce: 0,
        },
        transactions: txs,
        blue_score: 1,
        height: 1,
        shielded_transactions: Vec::new(),
        powit: Default::default(),
    }
}

/// B1-T18 / B2-T6 (live): a peer that asks for a ~900 KB block 64 times and
/// never reads an answer pins at most its small send budget in the node,
/// not 64 answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_that_never_reads_cannot_pin_answer_memory() {
    let b = big_block(900_000);
    assert!(Block::from_wire_bytes(&b.to_wire_bytes()).is_ok(), "fixture must decode");
    let hash = b.block_hash();
    let v = spawn_victim(Some(&b)).await;
    let mut a = attacker_swarm(true);
    connect(&mut a, &v).await;
    let base = sync_send_bytes_outstanding();
    for _ in 0..64 {
        a.behaviour_mut().send_request(&v.id, Out::Request(SyncRequest::GetBlock { block_hash: hash }));
    }
    // Let the victim serve; the attacker's swarm keeps running (never reading).
    let mut peak = 0u64;
    let until = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < until {
        let _ = tokio::time::timeout(Duration::from_millis(100), a.select_next_some()).await;
        peak = peak.max(sync_send_bytes_outstanding().saturating_sub(base));
    }
    eprintln!("peak unwritten answer bytes held for a peer that never reads: {peak}");
    assert!(peak >= 900_000, "the victim served nothing ({peak} bytes outstanding): test premise");
    assert!(
        peak <= 6 * 1024 * 1024,
        "a peer that never reads pinned {peak} bytes of unwritten answers in the node"
    );
}
