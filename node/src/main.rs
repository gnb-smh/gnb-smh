//! GnB node — GnB-SMH proof of work · Falcon‖ML-DSA · GhostDAG.
//!
//! Inherited from the Bloch node (fixes applied there):
//!   #1  Real ML-DSA-65 signatures
//!   #2  Full IBD: PeerTip → GetHeaders → Headers → GetBlock → NewBlock response
//!   #3  Block structural + TX signature validation before storing
//!   #4  Persistent P2P identity
//!   #5  Mempool with fee ordering
//!   #6  Peer memory (known_peers.json)
//!   #7  Difficulty retargeting every 2016 blocks (seconds, not ms)
//!   #8  Founder/miner address uses proper 20-byte pubkey hash
//!   #9  Intra-block double-spend prevention via spent-set tracking
//!   #10 Unified TX validation (single code path for block/mempool/RPC)
//!   #11 Removed duplicated mining loop

// The crypto/wallet/tx island moved to the `gnb-crypto` crate
// (crates/gnb-crypto). Re-export its modules under `crate::` so every
// `core::…` / `crate::crypto::…` path in this binary and its sibling node
// modules keeps resolving unchanged.
use gnb_crypto::{crypto, core, address};

mod consensus;
mod mining;
mod storage;
mod network;
mod rpc;
mod metrics;
mod pow;         // GnB-SMH PoW adapter
mod transport;
mod mempool;
mod analytics;
mod reorg;
mod attestation;  // L3 attestation (referenced by rpc)
mod coherence;    // Coherence C2 shielded pool
mod dandelion;    // Coherence P3 Dandelion++ tx-relay privacy
mod tip;
mod sync;         // Phase 2 — drop-in Kaspa sync-negotiation layer

use clap::Parser;
use log::{info, warn, error, debug};
use std::sync::Arc;
use std::collections::HashSet;
use std::path::PathBuf;
use parking_lot::RwLock;
use tokio::sync::{mpsc, broadcast};

#[derive(Parser)]
#[command(name = "gnb")]
#[command(about = "GnB (Gödel and Bell) — GnB-SMH memory-hard PoW · Falcon‖ML-DSA · GhostDAG")]
#[command(version)]
struct Cli {
    #[arg(long)]                                         mine: bool,
    /// Number of CPU threads the GnB-SMH miner uses. Each thread holds its own
    /// 64 MiB scratchpad and searches a disjoint nonce range. Defaults to all
    /// logical CPUs.
    #[arg(long)]                                         mine_threads: Option<usize>,
    /// Keep EVERY block body — never prune. An archival node is what lets a
    /// FRESH node bootstrap: the default pruning depth (10,000 blocks) deletes
    /// bodies from CF_BLOCKS while the header/DAG map keeps every entry, so a
    /// pruned node still ADVERTISES headers it can no longer serve. With no
    /// archival peer anywhere on the network, a new node asks for block 0, is
    /// promised 500 headers, receives no bodies, and loops forever at height 1.
    /// That is the observed failure on this fleet (2026-07-19): every node had
    /// pruned below ~394,913, so those bodies exist nowhere and cannot be
    /// recovered. Run at least one archival node, or new nodes cannot join.
    /// Costs disk: the full chain instead of the last 10,000 blocks.
    #[arg(long)]                                         archive: bool,
    /// Path to the uncompressed Bloch Genesis-3 carryover snapshot
    /// (`gunzip -k genesis/bloch-g3-carryover.tsv.gz`). Required on first
    /// boot: the genesis ledger is that snapshot converted to 1,000,000 GNB.
    /// The file is verified against the consensus constants (SHA3-256, rows,
    /// totals) before anything is written; any mismatch refuses to start.
    #[arg(long)]                                         carryover_snapshot: Option<PathBuf>,
    #[arg(long)]                                         testnet: bool,
    #[arg(long, default_value = "./gnb-data")]            data_dir: String,
    /// RPC bind address. SECURITY: defaults to 127.0.0.1 (local only).
    /// Use --rpc-public to bind 0.0.0.0, which exposes RPC to the internet.
    #[arg(long, default_value = "127.0.0.1")]            rpc_bind: String,
    /// Override rpc_bind to 0.0.0.0. DANGEROUS when unauthenticated.
    #[arg(long)]                                         rpc_public: bool,
    #[arg(long, default_value = "17210")]                rpc_port: u16,

    // ── Sprint M: authentication ────────────────────────────────────
    /// Shared-secret API key required for authenticated endpoints.
    /// Takes precedence over --rpc-api-key-file. Passing via CLI leaks
    /// the key into `ps aux`; prefer --rpc-api-key-file in production.
    #[arg(long)]                                         rpc_api_key: Option<String>,
    /// File containing the API key (first line, trimmed). Safer than --rpc-api-key.
    /// Suggested permissions: 0600, owned by the node user.
    #[arg(long)]                                         rpc_api_key_file: Option<std::path::PathBuf>,
    /// When true, writes (sendrawtransaction) require X-API-Key.
    /// Requires --rpc-api-key or --rpc-api-key-file to be set.
    /// Reads remain public (explorers need them).
    #[arg(long)]                                         rpc_require_auth_for_writes: bool,

    // ── Sprint M: rate limiting ─────────────────────────────────────
    /// Per-IP read-method rate limit, requests per minute. Default 60.
    /// Localhost (127.0.0.1, ::1) is exempt.
    #[arg(long, default_value = "60")]                   rpc_rate_limit_reads: u32,
    /// Per-IP write-method rate limit, requests per minute. Default 5.
    #[arg(long, default_value = "5")]                    rpc_rate_limit_writes: u32,

    /// Sprint M-patch1: also trust RFC1918 (10/8, 172.16/12, 192.168/16) and
    /// IPv6 ULA (fc00::/7) as "loopback" for auth/rate-limit bypass.
    /// This is needed when running in Docker with default bridge networking,
    /// where the host's 127.0.0.1 traffic appears as 172.17.0.1 inside the
    /// container. SECURITY: only enable on trusted single-tenant hosts. On
    /// Kubernetes, shared VLANs, or any multi-tenant network, leave this off.
    #[arg(long)]                                         rpc_trust_private_ranges: bool,

    // ── R3-audit H-R3-5: browser gate + loopback-auth policy ────────
    /// Browser origin allowed to call the RPC (repeatable), as exact
    /// `scheme://host[:port]`. Default: none — no CORS grants are emitted and
    /// any request carrying an Origin header is refused. `*` allows any
    /// origin for READ methods only; write methods never honour the wildcard.
    #[arg(long = "rpc-allow-origin")]                    rpc_allow_origins: Vec<String>,
    /// Extra hostname accepted in the Host header (repeatable),
    /// anti-DNS-rebinding. IP literals and `localhost` always pass; list your
    /// reverse-proxy / tunnel hostname here. `*` disables the check.
    #[arg(long = "rpc-allow-host")]                      rpc_allow_hosts: Vec<String>,
    /// Restore the pre-R3 "loopback bypasses auth" behaviour. Off by
    /// default: 127.0.0.1/::1 keep their rate-limit exemption but must
    /// present the API key like everyone else (a browser on this machine
    /// connects from loopback — the blanket bypass let any web page write).
    #[arg(long)]                                         rpc_trust_loopback: bool,

    // ── Sprint D: Prometheus metrics ─────────────────────────────────
    /// Enable Prometheus metrics server. Off by default (opt-in).
    /// Convention follows Geth: endpoint at /debug/metrics/prometheus.
    #[arg(long)]                                         metrics: bool,
    /// Metrics bind address. Default 127.0.0.1 (localhost-only).
    #[arg(long, default_value = "127.0.0.1")]            metrics_addr: String,
    /// Metrics port. Default 17310.
    #[arg(long, default_value = "17310")]                metrics_port: u16,
    /// Shortcut: binds metrics to 0.0.0.0 (publicly reachable).
    /// DANGER: reveals version, peer count, timing data. Use only if you
    /// accept that the node advertises its status publicly.
    #[arg(long)]                                         metrics_public: bool,
    #[arg(long, default_value = "/ip4/0.0.0.0/tcp/17110")] listen: String,
    #[arg(long)]                                         peer: Vec<String>,
    #[arg(long)]                                         miner_address: Option<String>,
    /// Sprint P: allow RFC1918 / loopback addresses via PEX. Dev/test only.
    /// Production deployments should leave this off; it opens a scanning vector.
    #[arg(long)]                                         allow_private_peers: bool,
    /// Mesh fix: set when this node sits behind a TCP proxy / NAT that makes
    /// many peers share one source IP (fly.io edge, k8s ingress, CGNAT). The
    /// gossipsub ip-colocation penalty (-50 x excess^2 above 3 peers/IP) would
    /// otherwise graylist the whole mesh at ~6 peers and silently blackhole
    /// every tip announcement. Disables only that weight; all other peer
    /// scoring stays active. Non-consensus — purely an operator knob.
    #[arg(long)]                                         behind_proxy: bool,
    /// Enable mDNS zero-config LAN peer discovery (OFF by default). Public nodes
    /// bootstrap via --peer/--dns-seed and should leave this off — mDNS is useless
    /// off a LAN and exercises a DNS-record parser with known LAN-only DoS CVEs.
    #[arg(long)]                                         enable_mdns: bool,
    /// Maximum peer connections (inbound cap). Raise this on a well-provisioned
    /// bootstrap / hub node so newcomers aren't rejected once the cap fills;
    /// keep it modest on a leaf node. Non-consensus — purely an operator knob.
    #[arg(long, default_value_t = 50)]                   max_peers: usize,
    /// Optional DNS seed hostname(s): the node resolves each to its A/AAAA
    /// records and dials them as peers (default port 17110; pass host:port to
    /// override). Bitcoin-style cold-start convenience — NON-privileged and
    /// opt-in: the shipped DEFAULT_SEEDS stays empty, so nobody's seed is
    /// required and you can point at (or run) any seed you trust. Repeatable.
    #[arg(long)]                                         dns_seed: Vec<String>,

}

// Bloch-SIS founder address}

/// Parse a gnb1q/gnb1t address string
/// into its 20-byte pubkey-hash script_pubkey.
///
/// This used to byte-slice the input directly
/// (`&stripped[..40.min(stripped.len())]`) — a panic hazard on any string
/// whose byte 40 is not a UTF-8 char boundary, i.e. indexing untrusted input
/// — and, on ANY parse failure (bad hex, wrong length, bad checksum),
/// silently fell back to `addr.as_bytes().to_vec()`: the RAW STRING BYTES of
/// the address, used as-is as a script_pubkey. That is neither a valid
/// P2PKH hash nor an error signal — it is an unspendable script that would
/// silently swallow every coinbase reward a miner earns under a mistyped
/// `--miner-address`, with no warning ever surfaced. Routes through the real
/// address parser (`Address::parse`: prefix, hex, length, AND checksum, none
/// of which does any raw indexing) and fails closed — every caller below
/// exits loudly instead of constructing a block that pays a burned address.
fn address_to_script_pubkey(addr: &str) -> Result<Vec<u8>, address::AddressError> {
    Ok(address::Address::parse(addr)?.hash().to_vec())
}

#[cfg(test)]
mod address_to_script_pubkey_tests {
    use super::*;

    fn sample_address() -> String {
        address::Address::from_hash([7u8; 20], address::Network::Mainnet).to_string()
    }

    #[test]
    fn valid_address_parses() {
        let spk = address_to_script_pubkey(&sample_address()).expect("valid address");
        assert_eq!(spk, vec![7u8; 20]);
    }

    /// Legacy L-3 regression: a malformed address (bad checksum) must be
    /// REJECTED, not silently converted into some other byte string used as
    /// a script_pubkey. Reverting the fix (restoring the raw byte-slice +
    /// `unwrap_or_else(|_| addr.as_bytes().to_vec())` fallback) makes this
    /// test fail — it would return `Ok(_)` with the raw ASCII bytes of the
    /// (invalid) address instead of an `Err`.
    #[test]
    fn malformed_address_is_rejected_not_silently_converted() {
        // A valid address with the last checksum hex digit flipped.
        let mut bad = sample_address();
        let last = bad.pop().unwrap();
        let flipped = if last == '0' { '1' } else { '0' };
        bad.push(flipped);
        assert!(address_to_script_pubkey(&bad).is_err(),
            "a bad-checksum address must be rejected, never silently accepted");
    }

    /// A garbage string (not even address-shaped) must also be rejected,
    /// never panic (the old code indexed the input directly) and never
    /// silently accepted as a script_pubkey.
    #[test]
    fn garbage_input_is_rejected_not_panicking() {
        assert!(address_to_script_pubkey("not-an-address").is_err());
        assert!(address_to_script_pubkey("").is_err());
        // Shorter than the old code's hardcoded byte-40 slice point — this
        // used to panic ("byte index 40 is out of bounds"); it must now
        // return a clean Err instead.
        assert!(address_to_script_pubkey("gnb1q").is_err());
    }
}

// Floor the worker count at 4. The default is the core count, and the
// production nodes are 2-core boxes: with only two workers, any pair of tasks
// that blocks (a held `node_state`/`dag` lock, a synchronous RocksDB read)
// parks the entire runtime, including the RPC accept loop. The RPC dispatch
// itself now runs on the blocking pool (see rpc/mod.rs), which is the actual
// fix; this is headroom so the async side keeps making progress while blocking
// work is in flight. Extra workers on a 2-core box cost context switches, not
// correctness.
#[tokio::main(worker_threads = 4)]
async fn main() {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info")
    ).init();

    let cli = Cli::parse();

    if core::TEST_POW_LIMIT {
        eprintln!("❌ this binary was built with gnb-crypto/test-pow-limit (tests only); refusing to run a node.");
        std::process::exit(2);
    }

    // Roadmap #8: wire the node-level chain-id ONCE at startup from the runtime
    // network selection, before any validation runs. The miner and every
    // validator read core::node_chain_id() (design §4.3 invariant 6); without
    // this call a testnet node would default to the Mainnet sighash domain and
    // reject every correctly-signed testnet transaction.
    core::set_node_chain_id(
        if cli.testnet { core::ChainId::Testnet } else { core::ChainId::Mainnet }
    ).expect("node chain-id must be settable exactly once at startup");

    // FIX v0.5.1 BLK-3: apply --rpc-public escape hatch.
    let rpc_bind = if cli.rpc_public { "0.0.0.0".to_string() } else { cli.rpc_bind.clone() };

    // ── Sprint M: load API key (CLI takes precedence over file) ────
    let api_key: Option<String> = match (&cli.rpc_api_key, &cli.rpc_api_key_file) {
        (Some(k), _) => Some(k.trim().to_string()),
        (None, Some(path)) => {
            match std::fs::read_to_string(path) {
                Ok(contents) => {
                    let k = contents.lines().next().unwrap_or("").trim().to_string();
                    if k.is_empty() {
                        eprintln!("⚠  --rpc-api-key-file {:?} is empty; ignoring.", path);
                        None
                    } else {
                        Some(k)
                    }
                }
                Err(e) => {
                    eprintln!("⚠  failed to read --rpc-api-key-file {:?}: {}", path, e);
                    None
                }
            }
        }
        (None, None) => None,
    };

    // Guard: --rpc-require-auth-for-writes without a key is a config error
    if cli.rpc_require_auth_for_writes && api_key.is_none() {
        eprintln!("❌ --rpc-require-auth-for-writes requires --rpc-api-key or --rpc-api-key-file");
        std::process::exit(2);
    }

    // Warnings on public bind
    if cli.rpc_trust_private_ranges {
        eprintln!("⚠  --rpc-trust-private-ranges: RFC1918 and IPv6 ULA ranges");
        eprintln!("   will bypass auth and rate limits. Only safe on trusted");
        eprintln!("   single-tenant hosts. DO NOT use on Kubernetes or shared VLANs.");
    }
    if cli.rpc_trust_loopback {
        eprintln!("⚠  --rpc-trust-loopback: 127.0.0.1/::1 will bypass API-key auth.");
        eprintln!("   Any local process — including a web page in a browser on this");
        eprintln!("   machine — can then call write methods without the key.");
    }
    if cli.rpc_allow_origins.iter().any(|o| o == "*") {
        eprintln!("⚠  --rpc-allow-origin '*': any web page may issue READ calls.");
        eprintln!("   Write methods still refuse wildcard origins.");
    }

    // ── Sprint D: resolve metrics bind, print warnings ───────────────
    let metrics_bind = if cli.metrics_public {
        "0.0.0.0".to_string()
    } else {
        cli.metrics_addr.clone()
    };
    if cli.metrics && cli.metrics_public {
        eprintln!("⚠  --metrics-public: Prometheus endpoint on 0.0.0.0:{}", cli.metrics_port);
        eprintln!("   Reveals version, peer count, hashrate, timing data.");
        eprintln!("   For most operators, prefer localhost + SSH tunnel or Grafana Agent push.");
    }

    if cli.rpc_public {
        eprintln!("⚠  --rpc-public binds RPC to 0.0.0.0 (all interfaces).");
        if api_key.is_none() {
            eprintln!("⚠  No --rpc-api-key set. Writes are rate-limited but not authenticated.");
            eprintln!("⚠  Recommend: --rpc-api-key-file <PATH> --rpc-require-auth-for-writes");
        } else if !cli.rpc_require_auth_for_writes {
            eprintln!("ℹ  API key set but --rpc-require-auth-for-writes is off.");
            eprintln!("ℹ  Writes will still accept unauthenticated requests (rate-limited).");
        } else {
            eprintln!("✓  RPC public with auth required for writes.");
        }
    }

    println!();
    println!("  ╔══════════════════════════════════════════════════╗");
    println!("  ║               ◆  G n B  ◆                        ║");
    println!("  ║  GnB-SMH memory-hard PoW · Falcon‖ML-DSA · DAG   ║");
    println!("  ║   Fair launch. Post-quantum. 10M GNB hard cap.   ║");
    println!("  ╚══════════════════════════════════════════════════╝");
    println!();

    let data_path = PathBuf::from(&cli.data_dir);
    std::fs::create_dir_all(&data_path).expect("create data dir");

    // ── Storage ───────────────────────────────────────────────────────────────
    let store = match storage::Storage::open(&data_path.join("db")) {
        Ok(s)  => { info!("storage ready"); Arc::new(s) }
        Err(e) => { error!("storage: {}", e); std::process::exit(1); }
    };



    // ── Consensus ─────────────────────────────────────────────────────────────
    // `with_default_k_env` == `with_default_k` (Legacy) unless the dev/test
    // override `GNB_GHOSTDAG_COLORING=fast` is set. The live gate
    // (CORRECTED_COLORING_ACTIVATION_HEIGHT) is unchanged; see ColoringMode docs.
    let dag = Arc::new(RwLock::new(consensus::GhostDAG::with_default_k_env()));

    // ── Genesis + DAG reload ─────────────────────────────────────────────────
    // Archival mode is process-wide and fixed; set it before any block is accepted.
    if cli.archive {
        ARCHIVE_MODE.store(true, std::sync::atomic::Ordering::Relaxed);
        info!("--archive: pruning DISABLED, every block body retained. This node can \
               bootstrap fresh peers; a pruned node cannot.");
    }

    if store.get_meta("genesis_hash").ok().flatten().is_none() {
        // ── Genesis ledger: verified Bloch Genesis-3 carryover ───────────
        // Verify fully, then write in one atomic batch, before block 0. A
        // crash between ingestion and genesis init re-runs both (same keys).
        let Some(snap_path) = cli.carryover_snapshot.as_ref() else {
            error!("first boot requires --carryover-snapshot <bloch-g3-carryover.tsv> \
                    (gunzip -k genesis/bloch-g3-carryover.tsv.gz). Refusing to start.");
            std::process::exit(1);
        };
        let bytes = std::fs::read(snap_path).unwrap_or_else(|e| {
            error!("cannot read {}: {e}", snap_path.display());
            std::process::exit(1);
        });
        match core::carryover::verify_and_convert(&bytes) {
            Ok(snap) => {
                info!("carryover VERIFIED: {} Bloch outputs ({} BLCH sat) -> {} UTXOs, {} GNB sat \
                       ({} zero-value dropped, {} vouts fixed)",
                      snap.source_rows, snap.source_total_sat, snap.utxos.len(),
                      snap.converted_total_sat, snap.dropped_zero, snap.fixed_vouts);
                match store.ingest_carryover(&snap) {
                    Ok(n) => info!("carryover ingested: {n} UTXOs written atomically"),
                    Err(e) => {
                        error!("carryover ingestion failed: {e}. Nothing was written. Refusing to start.");
                        std::process::exit(1);
                    }
                }
            }
            Err(failures) => {
                for f in &failures { error!("carryover verification FAILED: {f}"); }
                error!("REFUSING TO START: the snapshot is not this chain's carryover.");
                std::process::exit(1);
            }
        }

        // Construct the canonical genesis from constants and verify its
        // GnB-SMH proof; refuse to start if it does not check out.
        info!("Initialising canonical genesis and verifying its GnB-SMH proof...");
        let genesis = core::genesis_block();
        if !genesis.validate_pow() {
            error!("Genesis PoW invalid: the genesis does not verify against this \
                    binary's constants. Refusing to start.");
            std::process::exit(1);
        }
        if core::GENESIS_EXPECTED_HASH != [0u8; 32]
            && genesis.block_hash() != core::GENESIS_EXPECTED_HASH {
            error!("Genesis block hash {} != expected {} — a baked constant drifted. \
                    Refusing to start.",
                   hex::encode(genesis.block_hash()),
                   hex::encode(core::GENESIS_EXPECTED_HASH));
            std::process::exit(1);
        }

        let hash = genesis.block_hash();
        store.put_block(&genesis).expect("store genesis");
        store.put_meta("genesis_hash", &hash).expect("meta genesis_hash");
        store.put_meta("tip_hash", &hash).expect("meta tip_hash");
        store.put_meta("current_bits", &core::GENESIS_BITS.to_le_bytes())
            .expect("meta current_bits");
        dag.write().add_genesis(hash, genesis.header.timestamp);
        // Bind in a `let` so the read guard drops before the `dag.write()` inside
        // (parking_lot RwLock is not reentrant — holding this read across the
        // write deadlocks once the reachability gate is armed).
        let gdata_opt = dag.read().get_block_data(&hash).cloned();
        if let Some(gdata) = gdata_opt {
            // Sprint Y (M-2): atomic put to CF_DAG + CF_DAG_INTEGRITY.
            // Genesis anchors the hash-chain with an all-zero parent
            // integrity; see `compute_integrity_hash` for the convention.
            store.put_dag_with_integrity(&hash, &gdata)
                .expect("persist genesis dag + integrity");
            // Phase 1: when the reachability index is maintained (Fast / armed),
            // persist the genesis reachability record + version tag + root.
            // (Live Legacy path leaves CF_REACHABILITY untouched.)
            if dag.read().maintains_reachability_index() {
                let _ = dag.write().reach_take_delta(); // start tracking clean
                store.store_reachability_snapshot(&dag.read().reach_export_all(),
                                                  dag.read().reach_root())
                    .expect("persist genesis reachability index");
            }
        }
        // The genesis coinbase is unspendable: index it, but create no UTXO.
        for tx in &genesis.transactions {
            store.put_tx_index(&tx.txid(), &hash, 0).expect("tx_index");
        }
        info!("Genesis: {}", hex::encode(hash));
        info!("Supply: hard cap {} GNB (carryover {} sat), initial subsidy {} sat/block, halving every {} blocks",
              core::tokenomics::MAX_SUPPLY_SAT / core::tokenomics::SAT_PER_GNB,
              core::carryover::CARRYOVER_CONVERTED_TOTAL_SAT,
              core::tokenomics::INITIAL_SUBSIDY_SAT,
              core::tokenomics::HALVING_INTERVAL);
    } else {
        // A data-dir from another chain (or another genesis) must never be
        // reused: refuse to start unless its genesis is this binary's genesis.
        let canonical = core::genesis_block().block_hash();
        match store.get_meta("genesis_hash").ok().flatten() {
            Some(g) if g.as_slice() == canonical => {}
            other => {
                error!("data-dir genesis {} != this binary's genesis {}. Refusing to start; \
                        use a fresh --data-dir.",
                       other.map(hex::encode).unwrap_or_default(), hex::encode(canonical));
                std::process::exit(1);
            }
        }
        match store.get_meta("carryover_sha3").ok().flatten() {
            Some(r) if r.as_slice() == core::carryover::CARRYOVER_SNAPSHOT_SHA3 => {}
            _ => {
                error!("data-dir has no (or a different) carryover marker. Refusing to start; \
                        use a fresh --data-dir with --carryover-snapshot.");
                std::process::exit(1);
            }
        }
        // Full DAG reconstruction from persisted data.
        //
        // Sprint Y (M-2): load_persisted_validated verifies a hash-chain
        // over GhostdagData before inserting into the in-memory DAG. If
        // the database was written by a pre-Sprint-Y binary, the integrity
        // CF will be empty — the loader self-heals by computing and
        // returning a fresh map, which we persist immediately so the next
        // boot validates strictly.
        //
        // Any mismatch is fatal: we log loudly and exit. The operator
        // can then investigate disk integrity / provenance of the data
        // directory before the node rejoins the network.
        match store.load_all_dag_data() {
            Ok(entries) if !entries.is_empty() => {
                let _count = entries.len();
                let integrity_map = store.load_all_integrity_hashes()
                    .unwrap_or_else(|e| {
                        warn!("failed to read CF_DAG_INTEGRITY ({}); \
                              assuming pre-Sprint-Y DB, will self-heal", e);
                        std::collections::HashMap::new()
                    });

                match dag.write().load_persisted_validated(entries, integrity_map) {
                    Ok(loaded) => {
                        if loaded.self_healed {
                            warn!("CF_DAG_INTEGRITY was empty — self-healed \
                                   {} integrity records. This is expected on \
                                   first boot after Sprint Y upgrade. Subsequent \
                                   boots will validate strictly.",
                                  loaded.blocks_loaded);
                            if let Some(fresh) = loaded.fresh_map {
                                for (h, integrity) in &fresh {
                                    if let Err(e) = store.put_integrity_hash(h, integrity) {
                                        warn!("self-heal: failed to persist \
                                               integrity for block {}: {}",
                                              hex::encode(&h[..8]), e);
                                    }
                                }
                            }
                            info!("DAG loaded from disk (self-healed): {} blocks",
                                  loaded.blocks_loaded);
                        } else {
                            info!("DAG loaded from disk (integrity verified): {} blocks",
                                  loaded.blocks_loaded);
                        }
                    }
                    Err(e) => {
                        error!("GhostDAG integrity check FAILED: {}", e);
                        error!("Refusing to continue with unverifiable DAG state.");
                        error!("Investigate: disk corruption, targeted tampering, \
                               or a partial restore from a mismatched backup.");
                        std::process::exit(1);
                    }
                }
            }
            _ => {
                // Fallback: at least load genesis
                let gh = store.get_meta("genesis_hash").unwrap().unwrap();
                let gh32: [u8;32] = gh.as_slice().try_into().unwrap_or([0u8;32]);
                if let Ok(Some(blk)) = store.get_block(&gh32) {
                    dag.write().add_genesis(blk.block_hash(), blk.header.timestamp);
                    info!("Genesis loaded (fallback): {}", hex::encode(&gh));
                }
            }
        }
    }

    // ── Phase 2: durable reachability index — load-or-rebuild on boot ─────────
    //
    // `load_persisted*` above inserts blocks straight into the in-memory DAG
    // WITHOUT feeding the reachability index (it bypasses `add_block`). So when
    // the index is maintained (Fast / armed activation) it is empty here and
    // must be initialized before it colors any block:
    //
    //   * Fast-path: if CF_REACHABILITY carries the matching schema version and
    //     covers every CF_DAG block, load it directly (no O(chain) recompute).
    //   * Migration: otherwise rebuild by replaying the SAME `reach.add_block`
    //     code path in topological order, then persist the fresh snapshot.
    //   * Guard: random-sample self-check against the brute-force oracle before
    //     trusting the index; a loaded index that fails is rebuilt once.
    //
    // This whole block is inert on the live Legacy path (the gate is disabled),
    // so it never runs on a mainnet node from this branch. No peer resync ever.
    if dag.read().maintains_reachability_index() && dag.read().block_count() > 0 {
        let want_ver = storage::Storage::REACHABILITY_SCHEMA_VERSION;
        let have_ver = store.get_reachability_version().ok().flatten();
        let block_count = dag.read().block_count();

        let mut loaded_ok = false;
        if have_ver == Some(want_ver) {
            match store.load_all_reachability() {
                Ok(records) if records.len() == block_count => {
                    let root = store.get_reachability_root().ok().flatten();
                    match dag.write().reach_load_records(&records, root) {
                        Ok(()) => {
                            loaded_ok = true;
                            info!("reachability index loaded from disk: {} records", records.len());
                        }
                        Err(e) => warn!("reachability load failed ({e}); will rebuild"),
                    }
                }
                Ok(records) => warn!(
                    "reachability CF covers {}/{} blocks (partial/torn); will rebuild",
                    records.len(), block_count
                ),
                Err(e) => warn!("reachability CF read failed ({e}); will rebuild"),
            }
        } else {
            info!(
                "reachability index absent/version-mismatch (have {:?}, want {}); \
                 rebuilding from CF_DAG (one-time)",
                have_ver, want_ver
            );
        }

        let persist_rebuilt = |dag: &Arc<RwLock<consensus::GhostDAG>>, store: &storage::Storage| {
            let snap = dag.read().reach_export_all();
            let root = dag.read().reach_root();
            let _ = dag.write().reach_take_delta(); // clear the rebuild's dirty flags
            if let Err(e) = store.store_reachability_snapshot(&snap, root) {
                warn!("failed to persist rebuilt reachability index: {e}");
            }
        };

        if !loaded_ok {
            match dag.write().rebuild_reachability_from_store() {
                Ok(n) => info!("reachability index rebuilt from CF_DAG: {} blocks", n),
                Err(e) => {
                    error!("reachability rebuild FAILED: {e}");
                    error!("Refusing to continue with an uninitialized Fast-coloring index.");
                    std::process::exit(1);
                }
            }
            persist_rebuilt(&dag, &store);
        }

        // Self-check the (loaded or rebuilt) index against the unbounded oracle.
        // Bind in a `let` so the read guard drops before the rebuild's
        // `dag.write()` below (non-reentrant RwLock — holding it across the write
        // would deadlock the very path that recovers from a bad index).
        let self_check = dag.read().reach_self_check_sample(2000, 0xB10C_5157);
        if let Err(e) = self_check {
            if loaded_ok {
                warn!("loaded reachability failed self-check ({e}); rebuilding from CF_DAG");
                match dag.write().rebuild_reachability_from_store() {
                    Ok(n) => info!("reachability rebuilt after failed self-check: {} blocks", n),
                    Err(e2) => { error!("rebuild after failed self-check errored: {e2}"); std::process::exit(1); }
                }
                persist_rebuilt(&dag, &store);
                if let Err(e2) = dag.read().reach_self_check_sample(2000, 0x5157_B10C) {
                    error!("reachability STILL fails self-check after rebuild: {e2}");
                    std::process::exit(1);
                }
                info!("reachability self-check OK after rebuild");
            } else {
                error!("rebuilt reachability failed self-check: {e}");
                std::process::exit(1);
            }
        } else {
            info!("reachability self-check OK (sampled pairs match brute-force oracle)");
        }
    }

    // ── Heal poisoned finality checkpoint (blue-score/height unit bug) ─────────
    // Older builds persisted finalized_height = tip_blue_score − CHECKPOINT_DEPTH,
    // which runs ahead of the selected tip's *height* by the DAG width and can
    // exceed it once the skew passes CHECKPOINT_DEPTH — bricking block ingestion
    // (every chain-extending block is <= finalized_height and gets rejected). The
    // monotonic guard in accept_block cannot lower the value, so clamp it down to
    // a height-based ceiling here, once, at startup.
    {
        let tip_h = {
            let d = dag.read();
            d.selected_tip()
                .and_then(|h| d.get_block_data(&h).map(|x| x.height))
                .unwrap_or(0)
        };
        let cap = tip_h.saturating_sub(core::CHECKPOINT_DEPTH);
        let cur = store.get_meta("finalized_height").ok().flatten()
            .and_then(|b| b.as_slice().try_into().ok().map(u64::from_le_bytes))
            .unwrap_or(0);
        if cur > cap {
            warn!("finalized_height {} exceeds height-based cap {} \
                   (blue-score/height unit bug) — clamping to heal ingestion", cur, cap);
            store.put_meta("finalized_height", &cap.to_le_bytes()).ok();
        }
    }

    // ── Mempool + Network ─────────────────────────────────────────────────────
    let mempool  = Arc::new(mempool::Mempool::new());
    let net_cfg  = network::NetworkConfig {
        listen_addr:     cli.listen.clone(),
        bootstrap_peers: cli.peer.clone(),
        dns_seeds:       cli.dns_seed.clone(),
        max_peers:       cli.max_peers,
        data_dir:        data_path.clone(),
        allow_private_peers: cli.allow_private_peers,
        behind_proxy:    cli.behind_proxy,
        enable_mdns:     cli.enable_mdns,
        archive:         cli.archive,
    };
    let node = match network::NetworkNode::new(net_cfg) {
        Ok(n)  => { info!("P2P: {}", n.peer_id); n }
        Err(e) => { error!("network: {}", e); std::process::exit(1); }
    };

    let (our_score, our_count) = {
        let d = dag.read();
        (d.tip_blue_score(), d.block_count() as u64)
    };

    let node_state = Arc::new(RwLock::new(rpc::NodeState {
        tip_blue_score: our_score,
        block_count:    our_count,
        version:        env!("CARGO_PKG_VERSION").into(),
        ..Default::default()
    }));

    let (block_tx, mut block_rx) = mpsc::channel::<network::NetworkMessage>(1000);
    let (outbound_tx, outbound_rx) = mpsc::channel::<network::NetworkMessage>(1000);

    // ── Sprint 2.c: Tip-change broadcast channel ─────────────────────────────
    //
    // Fired whenever the selected DAG tip moves (Extension or Reorg disposition
    // in accept_block, or successful add_block in the miner loop). Stratum
    // server subscribes and re-broadcasts mining.notify with clean_jobs=true.
    //
    // Capacity 64: generous for burst tolerance; a lagging subscriber
    // (Lagged error variant) triggers a warn-and-continue in the server loop.
    //
    // When no subscriber exists (stratum disabled), send() returns Err and
    // all senders `let _ = ...` it. Safe no-op.
    let (tip_tx, _) = broadcast::channel::<tip::TipChanged>(64);

    // Coherence C2: the node's shielded-pool engine (in-memory).
    let shielded = Arc::new(RwLock::new(crate::coherence::ShieldedPool::new()));

    // ── Message processor ─────────────────────────────────────────────────────
    let store2    = store.clone();
    let shielded2 = shielded.clone();
    let dag2    = dag.clone();
    let state2  = node_state.clone();
    let mem2    = mempool.clone();
    let otx2    = outbound_tx.clone();
    let tip_tx2 = tip_tx.clone();

    // ── Phase-2 Kaspa sync-negotiation shared state (drop-in, additive) ───────
    // `peer_state`: PeerId-keyed chain-state table, written by the network loop
    // (P4) where the real libp2p PeerId is in scope; read here by the processor
    // + nudge. `frontier`: in-flight tip-request tracker gating IBD release.
    // Lock order everywhere: dag → peer_state → frontier → node_state.
    let peer_state = Arc::new(sync::peer_state::PeerStateTable::new());
    let frontier   = Arc::new(parking_lot::Mutex::new(sync::frontier::FrontierState::new()));
    let peer_state2 = peer_state.clone();
    let frontier2   = frontier.clone();

    // ── Echo-storm fix: correlate Headers replies with OUR OWN requests ──────
    // The gossip GetHeaders server arm replies by BROADCASTING Headers to the
    // whole mesh (wire compat: a gossip requester can only be answered on
    // gossip), so every node also receives replies meant for someone else.
    // Since the Headers frame carries no requester id (adding one would change
    // the wire format for the deployed fleet), correlation is local: record a
    // monotonic ms timestamp every time WE send a GetHeaders; a Headers frame
    // is "solicited" only within HEADERS_SOLICITED_WINDOW_MS of that. Shared
    // between the processor task (send sites + Headers arm) and the 30s nudge
    // task (its own send site). u64::MAX = never sent.
    let proc_start = std::time::Instant::now();
    let getheaders_sent_ms = Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX));
    let getheaders_sent2   = getheaders_sent_ms.clone();

    tokio::spawn(async move {
        use futures::future::FutureExt;
        // ── P0 supervision (roadmap §2.5, top reliability risk #1) ───────────
        // Before this, the single message-processor task was `tokio::spawn`ed
        // with no supervision: a panic in accept_block / block decode / orphan
        // handling silently killed the task. The process stayed "up", RPC kept
        // answering, but the node stopped syncing FOREVER with no error
        // surfaced. Here we catch a panic, log it loudly + meter it
        // (`task_panics_total`), back off, and restart the processing loop
        // without dropping the node. The processor's BEHAVIOUR is unchanged —
        // only its supervision is added.
        //
        // Orphan-pool state lives inside the restartable closure, so a panic
        // rebuilds it empty (the in-flight orphan buffer is lost — acceptable;
        // peers resend). A clean channel close (all senders dropped) exits.
        let mut backoff = std::time::Duration::from_millis(100);
        const MAX_BACKOFF: std::time::Duration = std::time::Duration::from_secs(30);
        loop {
          let processor = async {
            // Orphan pool: blocks received before their parents
            const MAX_ORPHANS: usize = 10_000;
            let mut orphans: std::collections::HashMap<[u8; 32], (core::Block, Vec<u8>, u64)> =
                std::collections::HashMap::new();
            // Reverse index: parent_hash → set of orphan hashes waiting for it
            let mut waiting_for: std::collections::HashMap<[u8; 32], HashSet<[u8; 32]>> =
                std::collections::HashMap::new();
            // Orphan-deadlock fix: per-missing-parent retry state. The one-shot
            // GetBlock below (first_waiter && !buffered) is recorded here; the
            // periodic sweep re-requests lost ones with backoff and prunes
            // hopeless ones so waiting_for cannot grow stale forever.
            let mut parent_fetch = sync::parent_fetch::ParentFetchTracker::new();
            let mut orphan_sweep = tokio::time::interval(sync::parent_fetch::SWEEP_PERIOD);
            orphan_sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // Never fire immediately on (re)start — tick 0 is now.
            orphan_sweep.reset();
            // Mesh fix (reciprocal tip): rate limiter for answering behind-
            // peers' PeerTip announcements with our own tip. None = never sent.
            let mut last_reciprocal_tip: Option<std::time::Instant> = None;
            // Echo-storm fix (server side): TTL-dedupe of gossip GetHeaders
            // service. A gossip GetHeaders reaches EVERY node and each reply is
            // a mesh-wide Headers broadcast — N serving nodes × M requesters
            // asking the same range was the measured ~16 frames/s echo. Within
            // the TTL the FIRST broadcast already reached every requester, so
            // identical (from_blue_score, limit) requests are served once.
            const HEADERS_SERVE_DEDUP_TTL: std::time::Duration = std::time::Duration::from_secs(10);
            let mut recent_headers_served: std::collections::HashMap<(u64, u32), std::time::Instant> =
                std::collections::HashMap::new();

            loop {
            // Orphan-deadlock fix: the message wait is now a select between the
            // inbound channel and the ~30s orphan sweep. The match body below is
            // unchanged; `continue`/`break` semantics inside it are identical.
            let msg = tokio::select! {
                m = block_rx.recv() => match m { Some(m) => m, None => break },
                _ = orphan_sweep.tick() => {
                    let ready = sweep_orphan_parents(
                        &mut orphans, &mut waiting_for, &mut parent_fetch,
                        &dag2, &otx2,
                    ).await;
                    // Defensive liveness: a waited-on parent that is ALREADY in
                    // the DAG (its accept raced the waiting_for insert) would
                    // otherwise strand its orphans forever — drain them now.
                    for p in ready {
                        process_orphans(
                            p, &mut orphans, &mut waiting_for,
                            &dag2, &store2, &mem2, &state2,
                            Some(&tip_tx2), &shielded2,
                        );
                    }
                    continue;
                }
            };
            match msg {

                // IBD step 1: peer tip — if behind, request headers
                network::NetworkMessage::PeerTip { blue_score: peer_s, ref peer_id, .. } => {
                    let our_s = dag2.read().tip_blue_score();
                    {
                        let mut s = state2.write();
                        s.seen_first_tip = true;
                        // Phase-2: best_seen_blue_score is kept ONLY as an RPC
                        // display hint — it no longer releases the IBD latch. A
                        // peer can announce any blue_score; release is decided
                        // solely by maybe_release_ibd (blue_work-verified below).
                        if peer_s > s.best_seen_blue_score { s.best_seen_blue_score = peer_s; }
                    }
                    if peer_s > our_s {
                        info!("Peer {} ahead ({}), requesting headers", peer_id, peer_s);
                        // Retained legacy over-trigger fallback (entering IBD is
                        // always safe); the announced score never RELEASES it.
                        state2.write().is_syncing = true;
                        getheaders_sent2.store(proc_start.elapsed().as_millis() as u64, std::sync::atomic::Ordering::Relaxed);
                        let _ = otx2.send(network::NetworkMessage::GetHeaders { from_blue_score: our_s, limit: 500, nonce: getblock_nonce() }).await;
                    } else if peer_s < our_s {
                        // Mesh fix (reciprocal tip): the announcing peer is
                        // BEHIND us, and its other ways of learning our tip are
                        // all fragile — the on-connect announce races its
                        // Subscribe, and our 60s periodic PeerTip is byte-
                        // identical while our tip is unchanged (dedup-fragile).
                        // Answer with a fresh-timestamp Version (unique bytes,
                        // can never be dedup-dropped) carrying our blue_score;
                        // the peer's Version arm below treats it as an IBD
                        // trigger. Rate-limited so a burst of behind-tips from
                        // many peers can't make us spam the sync topic.
                        let due = last_reciprocal_tip
                            .map(|t| t.elapsed() >= std::time::Duration::from_secs(15))
                            .unwrap_or(true);
                        if due {
                            last_reciprocal_tip = Some(std::time::Instant::now());
                            let height = dag2.read().block_count() as u64;
                            debug!("peer {} behind (score {} < {}), sending reciprocal tip", peer_id, peer_s, our_s);
                            let _ = otx2.send(network::NetworkMessage::Version {
                                version:    network::PROTOCOL_VERSION,
                                user_agent: format!("gnb/{}", env!("CARGO_PKG_VERSION")),
                                blue_score: our_s,
                                height,
                                timestamp:  std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_secs()).unwrap_or(0),
                            }).await;
                        }
                    }
                    maybe_release_ibd(&dag2, &peer_state2, &frontier2, &state2);
                }

                // Frontier reconciliation: a peer asks for our DAG frontier.
                // Reply with every tip (as SyncEntry) plus an exponential
                // block-locator over our selected chain (common-ancestor hint).
                network::NetworkMessage::GetTips => {
                    let (entries, locator) = {
                        let d = dag2.read();
                        let entries: Vec<network::SyncEntry> = d.tips().iter()
                            .filter_map(|h| d.get_node(h).map(|n| network::SyncEntry {
                                hash: *h, blue_score: n.blue_score, height: n.height,
                            }))
                            .collect();
                        let locator = sync::locator::build_locator(&d.selected_chain());
                        (entries, locator)
                    };
                    let _ = otx2.send(network::NetworkMessage::Tips { tips: entries, locator }).await;
                }

                // Frontier reconciliation: a peer's advertised frontier. GetBlock
                // every advertised tip we lack; a frontier gap means we are
                // behind, so enter IBD. Missing parents of the fetched tips flow
                // into the EXISTING orphan pool via the NewBlock arm — no new
                // orphan logic here.
                network::NetworkMessage::Tips { tips, .. } => {
                    let advertised: Vec<[u8; 32]> = tips.iter().map(|e| e.hash).collect();
                    let now = std::time::Instant::now();
                    let to_req = {
                        let d = dag2.read();
                        frontier2.lock().to_request(&advertised, |h| d.has_block(h), now)
                    };
                    if !to_req.is_empty() {
                        // Frontier gap → enter IBD (blue_work-verified release).
                        state2.write().is_syncing = true;
                        for h in &to_req {
                            let _ = otx2.send(network::NetworkMessage::GetBlock { block_hash: *h, nonce: getblock_nonce() }).await;
                        }
                    }
                    maybe_release_ibd(&dag2, &peer_state2, &frontier2, &state2);
                }

                // IBD step 2: someone asks for our headers.
                // NB: this arm only serves GOSSIP requesters (old binaries /
                // early-boot fallback) — directed pulls are served in
                // network/mod.rs (sync_rr) and answered to that peer alone.
                network::NetworkMessage::GetHeaders { from_blue_score, limit, .. } => {
                    // Echo-storm fix (server side): the reply below is a mesh-
                    // wide broadcast; within the TTL the first one already
                    // reached every requester of this same range. Serve it once.
                    let now = std::time::Instant::now();
                    recent_headers_served.retain(|_, t| now.duration_since(*t) < HEADERS_SERVE_DEDUP_TTL);
                    if recent_headers_served.contains_key(&(from_blue_score, limit)) {
                        debug!("GetHeaders from_score={} limit={}: served this range <{:?} ago; suppressing duplicate broadcast",
                            from_blue_score, limit, HEADERS_SERVE_DEDUP_TTL);
                        continue;
                    }
                    recent_headers_served.insert((from_blue_score, limit), now);
                    let entries: Vec<network::SyncEntry> = {
                        let d = dag2.read();
                        d.ordered_hashes_from(from_blue_score, limit as usize)
                            .iter()
                            .filter_map(|h| d.get_node(h).map(|n| network::SyncEntry { hash: *h,
                                blue_score: n.blue_score, height: n.height,
                            }))
                            .collect()
                    };
                    if !entries.is_empty() {
                        let _ = otx2.send(network::NetworkMessage::Headers { entries }).await;
                    }
                }

                // IBD step 3: received headers — request missing blocks
                network::NetworkMessage::Headers { entries } => {
                    // Echo-storm fix (client side): Headers replies to gossip
                    // requesters are mesh-wide broadcasts, so we also hear
                    // frames answering SOMEONE ELSE. The frame carries no
                    // requester id (wire compat), so correlate locally: it is
                    // "solicited" only if WE sent a GetHeaders recently. An
                    // unsolicited frame must never drive the pipeline — every
                    // listener continuing the stream on every overheard batch
                    // was the ~16 frames/s echo amplifier ("IBD: need 0/500"
                    // forever on synced nodes).
                    let solicited = {
                        let sent = getheaders_sent2.load(std::sync::atomic::Ordering::Relaxed);
                        sent != u64::MAX
                            && (proc_start.elapsed().as_millis() as u64).saturating_sub(sent)
                                <= HEADERS_SOLICITED_WINDOW_MS
                    };
                    let missing: Vec<_> = entries.iter()
                        .filter(|e| !dag2.read().has_block(&e.hash))
                        .map(|e| e.hash).collect();
                    if !solicited && missing.is_empty() {
                        // Pure echo of someone else's IBD stream: nothing we
                        // lack, nothing we asked. Ignore silently (debug, not
                        // info — this was continuous log spam at parity).
                        debug!("Headers echo ignored ({} entries, 0 missing, no GetHeaders of ours outstanding)", entries.len());
                        continue;
                    }
                    info!("IBD: need {}/{} blocks", missing.len(), entries.len());
                    // Missing bodies are still fetched even from an overheard
                    // frame — if we lack them we are genuinely behind, and the
                    // fetch is a directed pull (no gossip amplification).
                    for hash in missing {
                        let _ = otx2.send(network::NetworkMessage::GetBlock { block_hash: hash, nonce: getblock_nonce() }).await;
                    }
                    if entries.is_empty() {
                        // Phase-2: an empty Headers reply no longer clears
                        // is_syncing (a lying/lagging peer must not fake
                        // completion). Release is blue_work-verified only.
                        maybe_release_ibd(&dag2, &peer_state2, &frontier2, &state2);
                    } else if entries.len() >= 500 && solicited {
                        // Pipeline IBD: a full batch means the serving peer has
                        // more. Re-request the next batch IMMEDIATELY from the
                        // highest blue_score we just learned, instead of waiting
                        // for the 30s nudge. Turns IBD from ~500 headers / 30s
                        // into a continuous stream so a node thousands of blocks
                        // behind converges in seconds, not minutes. At parity
                        // the batch comes back < 500 (or empty) and the stream
                        // stops, so steady-state cost is zero.
                        let next_from = entries.iter().map(|e| e.blue_score).max().unwrap_or(0);
                        getheaders_sent2.store(proc_start.elapsed().as_millis() as u64, std::sync::atomic::Ordering::Relaxed);
                        let _ = otx2.send(network::NetworkMessage::GetHeaders { from_blue_score: next_from, limit: 500, nonce: getblock_nonce() }).await;
                    }
                }

                // A peer told us it cannot serve this body — it pruned it, or never
                // had it. Log it and move on: the point of the message is that the
                // requester now KNOWS, instead of waiting on silence and re-asking
                // the same batch every 30s. If every peer answers NotFound for the
                // early chain, no archival peer exists and a fresh node genuinely
                // cannot bootstrap — a condition worth surfacing rather than hiding
                // behind an apparently-healthy log full of header traffic.
                network::NetworkMessage::BlockNotFound { block_hash, .. } => {
                    warn!("peer cannot serve block {} (pruned or unknown) — an \
                           archival peer is needed to bootstrap from this height",
                          hex::encode(&block_hash[..8]));
                    // An explicit NotFound is DEFINITIVE (not a lost packet or a
                    // busy peer): advance this tip toward abandonment so an
                    // unreachable frontier — the H=3413 orphan header chain whose
                    // bodies are gone network-wide — stops pinning us in IBD.
                    // Then re-check the release gate: once every advertised tip is
                    // held-or-abandoned, maybe_release_ibd clears is_syncing and
                    // the node serves/mines/propagates its bodied tip instead of
                    // chasing dead work forever.
                    frontier2.lock().note_not_found(&block_hash, std::time::Instant::now());
                    maybe_release_ibd(&dag2, &peer_state2, &frontier2, &state2);
                }

                // IBD step 4: respond to GetBlock with the actual block
                network::NetworkMessage::GetBlock { block_hash, .. } => {
                    match store2.get_block(&block_hash) {
                        Ok(Some(block)) => {
                            // Sprint 1.c: Bitcoin-format wire.
                            let data = block.to_wire_bytes();
                            let _ = otx2.send(network::NetworkMessage::NewBlock {
                                block_hash,
                                blue_score: block.blue_score,
                                height:     block.height,
                                block_data: data,
                            }).await;
                        }
                        // Answer explicitly instead of dropping the frame. A silent
                        // non-answer is unrecoverable for the requester: it cannot
                        // tell "body pruned" from "packet lost" from "peer busy", so
                        // it waits, re-asks the same batch on the 30s nudge, and loops
                        // forever — exactly how a fresh node sat at height 1 through
                        // 4,397 identical rounds with 15 peers connected. warn!, not
                        // debug!: a node advertising headers whose bodies it pruned is
                        // a real operational fault, and at RUST_LOG=info the old debug
                        // line made it invisible.
                        _ => {
                            warn!("GetBlock: body unavailable (pruned or unknown) for {} \
                                   — replying NotFound so the peer can try another source",
                                  hex::encode(&block_hash[..8]));
                            let _ = otx2.send(network::NetworkMessage::BlockNotFound {
                                block_hash, nonce: getblock_nonce(),
                            }).await;
                        }
                    }
                }

                // Full validation before storing — with orphan pool support
                network::NetworkMessage::NewBlock { block_data, block_hash, height, .. } => {
                    if dag2.read().has_block(&block_hash) { continue; }
                    // Sprint 1.c: Bitcoin-format wire. A malformed block_data
                    // payload gets warned about and dropped; peer may re-send
                    // or stay on a divergent chain.
                    match core::Block::from_wire_bytes(&block_data) {
                        Err(e) => warn!("block deserialise: {}", e),
                        Ok(block) => {
                            // SECURITY (audit H2): bind the wire-supplied block_hash/height to
                            // the actual block content BEFORE any dedup or DAG insertion.
                            // Otherwise an attacker rebroadcasts a valid block under endless
                            // random ids, each minting a distinct GhostDAG node → unbounded
                            // memory/disk growth at zero PoW cost.
                            let real_hash = block.block_hash();
                            if real_hash != block_hash {
                                warn!("block id mismatch: claimed {} but content hashes to {}; dropping",
                                    hex::encode(&block_hash[..8]), hex::encode(&real_hash[..8]));
                                continue;
                            }
                            if height != block.height {
                                warn!("block {} height mismatch: claimed {} vs content {}; dropping",
                                    hex::encode(&block_hash[..8]), height, block.height);
                                continue;
                            }

                            // ── BACKFILL-FLOOD guard (frente BACKFILL-FLOOD) ──────────
                            // `height` is now content-verified (== block.height). A block
                            // far BELOW our selected tip that we did NOT ask for is
                            // backfill a healthy node PULLS, never something a peer should
                            // PUSH. Ingesting one is not cheap: add_block →
                            // compute_mergeset unconditionally walks compute_past(selected
                            // parent) (O(past-cone)) and the reachability index reindexes
                            // the whole subtree above the insertion point — measured at
                            // ~7.0s for a SINGLE h=10.8k block against a 27.4k tip vs
                            // ~6ms to extend the tip (tests/backfill_flood_lab.rs). All of
                            // it runs under the global dag.write(), so one lagging peer
                            // pushing thousands of these (observed: 12D3KooWBZeik… on
                            // 2026-08-09, 1.270 blocks in 5 min) starves the miner's
                            // read/write for up to ~10s at a time and freezes block
                            // production. Drop such a block cheaply UNLESS we explicitly
                            // requested it (orphan-parent resolution). Backfill for
                            // legitimately-behind nodes is unaffected: they PULL via
                            // directed GetBlock/GetHeaders, which we serve straight from
                            // storage (store.get_block — no add_block, no cone walk). A
                            // node still mid-IBD has a LOW tip, so height is never far
                            // below it and this never fires. Not consensus: declining to
                            // ingest an ancient gossiped block changes no validation rule.
                            {
                                let tip_h = {
                                    let d = dag2.read();
                                    d.selected_tip()
                                        .and_then(|t| d.get_block_data(&t).map(|bd| bd.height))
                                        .unwrap_or(0)
                                };
                                let awaited = waiting_for.contains_key(&block_hash)
                                    || parent_fetch.is_awaited(&block_hash);
                                // CHECKPOINT_DEPTH is the finality horizon: a block deeper
                                // than that below the tip can never legitimately become the
                                // selected tip (disposition guard + MAX_REORG_DEPTH), and a
                                // real mergeset member of a recent tip sits within the
                                // (narrow, K=10) anticone near tip height — never this far
                                // down. So this window drops only useless/attack pushes.
                                if !awaited
                                    && tip_h > core::CHECKPOINT_DEPTH
                                    && height + core::CHECKPOINT_DEPTH < tip_h
                                {
                                    debug!(
                                        "backfill-flood guard: dropped unsolicited deep block h={} \
                                         (tip h={}, {} below) from gossip — backfill must be pulled",
                                        height, tip_h, tip_h - height
                                    );
                                    crate::metrics::inc_block_backfill_dropped();
                                    continue;
                                }
                            }

                            // Structural validation (PoW, merkle, coinbase) — always do first
                            if let Err(reason) = block.validate_structure() {
                                warn!("block {} rejected ({})", hex::encode(&block_hash[..8]), reason);
                                continue;
                            }

                            // Check if all parents are in the DAG
                            let missing_parents: Vec<[u8; 32]> = block.header.parents.iter()
                                .filter(|p| !dag2.read().has_block(p))
                                .cloned()
                                .collect();

                            if !missing_parents.is_empty() {
                                // Orphan: parents not yet available — buffer for later
                                if orphans.len() >= MAX_ORPHANS {
                                    // Evict oldest orphan (by height, lowest first)
                                    if let Some((&evict_hash, _)) = orphans.iter()
                                        .min_by_key(|(_, (b, _, _))| b.height)
                                    {
                                        let evict_parents: Vec<[u8;32]> = orphans[&evict_hash].0.header.parents.clone();
                                        orphans.remove(&evict_hash);
                                        for p in &evict_parents {
                                            if let Some(set) = waiting_for.get_mut(p) {
                                                set.remove(&evict_hash);
                                                if set.is_empty() { waiting_for.remove(p); }
                                            }
                                        }
                                    }
                                }
                                debug!("orphan block h={} (missing {} parents), buffered (pool={})",
                                    height, missing_parents.len(), orphans.len() + 1);
                                for mp in &missing_parents {
                                    let first_waiter = !waiting_for.contains_key(mp);
                                    waiting_for.entry(*mp).or_default().insert(block_hash);
                                    // Kaspa-style recursive ancestor resolution
                                    // (RequestRelayBlocks): explicitly request each
                                    // missing parent so the past cone closes even
                                    // when IBD-by-blue_score hasn't reached this
                                    // branch. Without this the orphan waits forever
                                    // and the node silently partitions onto a
                                    // sub-DAG. Skip parents already buffered or
                                    // already awaited (their arrival chains the next
                                    // request), so a deep gap fans out one level at a
                                    // time instead of duplicating GetBlocks.
                                    if first_waiter && !orphans.contains_key(mp) {
                                        // Orphan-deadlock fix: record the attempt so the
                                        // periodic sweep can re-request it if the response
                                        // is lost (this send used to be fire-and-forget-
                                        // exactly-once — a dropped reply deadlocked the
                                        // orphan and every descendant forever).
                                        parent_fetch.note_requested(*mp, std::time::Instant::now());
                                        let _ = otx2.send(network::NetworkMessage::GetBlock {
                                            block_hash: *mp, nonce: getblock_nonce(),
                                        }).await;
                                    }
                                }
                                orphans.insert(block_hash, (block, block_data, height));
                                continue;
                            }

                            // All parents present — try to accept
                            let _t_validate = std::time::Instant::now();
                            match accept_block(
                                &block, block_hash, height,
                                &dag2, &store2, &mem2, &state2,
                                Some(&tip_tx2), &shielded2,
                            ) {
                            Err(e) => {
                                crate::metrics::observe_block_validation(_t_validate.elapsed().as_secs_f64());
                                crate::metrics::inc_block_rejected();
                                warn!("block {} h={} REJECTED: {}", hex::encode(&block_hash[..8]), height, e);
                            }
                            Ok(accepted_hash) => {
                                crate::metrics::observe_block_validation(_t_validate.elapsed().as_secs_f64());
                                crate::metrics::inc_block_accepted();
                                // Process any orphans that were waiting for this block
                                process_orphans(
                                    accepted_hash,
                                    &mut orphans,
                                    &mut waiting_for,
                                    &dag2, &store2, &mem2, &state2,
                                    Some(&tip_tx2), &shielded2,
                                );
                                // Phase-2 frontier: this tip (if it was in flight)
                                // is now present — clear it and re-test the IBD
                                // latch. Orphans drained by process_orphans that
                                // were themselves advertised tips get cleared by
                                // the next Tips round (to_request skips present
                                // blocks), so clearing block_hash here suffices.
                                frontier2.lock().note_received(&block_hash);
                                maybe_release_ibd(&dag2, &peer_state2, &frontier2, &state2);
                            }}
                        }
                    }
                }

                network::NetworkMessage::PeerCount { count, addresses } => {
                    let mut s = state2.write();
                    s.peer_count = count as u32;
                    s.peer_addresses = addresses;
                }

                // Add validated tx to mempool
                network::NetworkMessage::NewTransaction { tx_data, .. } => {
                    // Sprint 1.d: Bitcoin-format tx wire.
                    if let Ok(tx) = core::Transaction::from_wire_bytes(&tx_data) {
                        if !tx.is_coinbase() {
                            let height = dag2.read().block_count() as u64;
                            // P0 (roadmap §1.2 / §2.5 #6): move CPU-bound PQ
                            // signature verification off the async reactor so a
                            // gossiped valid-tx flood can't stall this task's
                            // worker thread. Logic unchanged — only the thread.
                            let store_v = store2.clone();
                            let tx_v = tx.clone();
                            let verified = tokio::task::spawn_blocking(move || {
                                validate_tx_standalone(&tx_v, &store_v, height)
                            }).await;
                            match verified {
                                Ok(Ok(fee)) => { let _ = mem2.add(tx, fee); }
                                Ok(Err(e))  => debug!("mempool reject: {}", e),
                                Err(e)      => warn!("tx verify task failed: {}", e),
                            }
                        }
                        state2.write().mempool_size = mem2.size();
                    }
                }

                // Mesh fix (fresh-joiner IBD): Version was a no-op here, yet it
                // is the only tip-carrying frame on the wire whose bytes are
                // always unique (fresh `timestamp` → unique gossipsub
                // MessageId, so it can never be Duplicate-dropped the way a
                // byte-identical PeerTip can). Treat it exactly like a PeerTip
                // for IBD triggering: on-connect handshakes, post-Subscribed
                // re-announces, periodic announces, and reciprocal tips all
                // arrive as Version frames.
                //
                // SHARED-LATCH NOTE ([stall] interface): this arm feeds the
                // same is_syncing / best_seen_blue_score / seen_first_tip
                // latch as the PeerTip arm above, with IDENTICAL semantics.
                // It widens the set of messages that can raise the
                // best_seen_blue_score high-water mark (still unvalidated,
                // peer-supplied). Any [stall]-side fix that decays or
                // validates that mark must cover this arm too.
                network::NetworkMessage::Version { version, blue_score: peer_s, .. } => {
                    if version < network::MIN_PROTOCOL_VERSION { continue; }
                    let our_s = dag2.read().tip_blue_score();
                    {
                        let mut s = state2.write();
                        s.seen_first_tip = true;
                        // Phase-2: RPC hint only — never releases the latch.
                        if peer_s > s.best_seen_blue_score { s.best_seen_blue_score = peer_s; }
                    }
                    if peer_s > our_s {
                        info!("Version peer ahead (score {} > {}), requesting headers", peer_s, our_s);
                        // Retained legacy over-trigger fallback (safe).
                        state2.write().is_syncing = true;
                        getheaders_sent2.store(proc_start.elapsed().as_millis() as u64, std::sync::atomic::Ordering::Relaxed);
                        let _ = otx2.send(network::NetworkMessage::GetHeaders { from_blue_score: our_s, limit: 500, nonce: getblock_nonce() }).await;
                    }
                    maybe_release_ibd(&dag2, &peer_state2, &frontier2, &state2);
                }
                network::NetworkMessage::VersionAck
                | network::NetworkMessage::PeerExchange { .. }
                | network::NetworkMessage::PeerRequest => {}
            }
            }
          };
          // Catch a panic that escapes the processing loop, meter + log it, and
          // restart with bounded exponential backoff. Ok(()) means the input
          // channel closed cleanly (every sender dropped) → exit the task.
          match std::panic::AssertUnwindSafe(processor).catch_unwind().await {
              Ok(()) => {
                  info!("message-processor: input channel closed; task exiting cleanly");
                  break;
              }
              Err(panic) => {
                  crate::metrics::inc_task_panic("message_processor");
                  let detail = panic.downcast_ref::<&str>().map(|s| (*s).to_string())
                      .or_else(|| panic.downcast_ref::<String>().cloned())
                      .unwrap_or_else(|| "<non-string panic payload>".to_string());
                  error!("message-processor PANICKED: {} — node stays up; restarting loop in {:?}",
                      detail, backoff);
                  tokio::time::sleep(backoff).await;
                  backoff = (backoff * 2).min(MAX_BACKOFF);
              }
          }
        }
    });

    // ── Mesh fix: proactive IBD nudge ─────────────────────────────────────────
    //
    // A fresh joiner can miss every inbound tip signal: the seed's on-connect
    // announce races our Subscribe, the 60s periodic PeerTip is dedup-fragile,
    // and colocation scoring can graylist proxied peers. Don't wait to be told
    // we're behind — while we have peers and either (a) we've never seen a
    // remote tip, or (b) we know we're behind (is_syncing latched, or the
    // best announced blue_score exceeds ours), publish GetHeaders every 30s.
    //
    // This also un-crawls multi-batch IBD: the Headers handler requests one
    // 500-block batch and never issues a follow-up GetHeaders, so a node
    // thousands of blocks behind previously advanced one batch per 60s tip
    // re-announce. With the nudge it re-requests from its ADVANCING blue_score
    // at least every 30s. At parity the nudge stops (and the serving side
    // suppresses empty Headers replies), so steady-state cost is zero.
    {
        let dag_n        = dag.clone();
        let state_n      = node_state.clone();
        let otx_n        = outbound_tx.clone();
        let peer_state_n = peer_state.clone();
        let frontier_n   = frontier.clone();
        let getheaders_sent_n = getheaders_sent_ms.clone();
        tokio::spawn(async move {
            let mut nudge = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                nudge.tick().await;
                let our_s = dag_n.read().tip_blue_score();
                let (peers, syncing, best_seen, seen_tip) = {
                    let s = state_n.read();
                    (s.peer_count, s.is_syncing, s.best_seen_blue_score, s.seen_first_tip)
                };
                if peers > 0 {
                    // Retained legacy fallback (gossip path): only when we have a
                    // reason to believe we're behind, exactly as before.
                    if syncing || !seen_tip || best_seen > our_s {
                        debug!("IBD nudge: GetHeaders from score {} (best_seen={} syncing={} seen_tip={})",
                            our_s, best_seen, syncing, seen_tip);
                        getheaders_sent_n.store(proc_start.elapsed().as_millis() as u64, std::sync::atomic::Ordering::Relaxed);
                        let _ = otx_n.send(network::NetworkMessage::GetHeaders { from_blue_score: our_s, limit: 500, nonce: getblock_nonce() }).await;
                    }
                    // Phase-2 frontier reconciliation: every peer replies Tips.
                    let _ = otx_n.send(network::NetworkMessage::GetTips).await;
                    // Re-request timed-out tip GetBlocks.
                    let now = std::time::Instant::now();
                    let stale = frontier_n.lock().expired(sync::TIP_REQUEST_TIMEOUT, now);
                    for h in stale {
                        let _ = otx_n.send(network::NetworkMessage::GetBlock { block_hash: h, nonce: getblock_nonce() }).await;
                    }
                    // Re-test the blue_work-verified IBD latch so a node never
                    // wedges in is_syncing after it has actually caught up —
                    // the liveness backstop against a fabricated high announced
                    // score freezing the node.
                    maybe_release_ibd(&dag_n, &peer_state_n, &frontier_n, &state_n);
                }
            }
        });
    }

    // ── Ready ─────────────────────────────────────────────────────────────────
    let (score, count) = { let d = dag.read(); (d.tip_blue_score(), d.block_count()) };
    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    info!("  P2P   {}", cli.listen);
    info!("  RPC   {}:{}", cli.rpc_bind, cli.rpc_port);
    info!("  Mine  {}", if cli.mine { "ON" } else { "OFF" });
    info!("  DAG   {} blocks, score={}", count, score);

    // ── UTXO Reindex DISABLED (needs topological ordering for DAG) ──
    /*
    {
        let bc = dag.read().block_count() as u64;
        if bc > 1 {
            info!("Reindexing UTXOs from {} blocks...", bc);
            let _ = store.clear_utxos();
            let mut all_blocks = store.iter_all_blocks();
            // Sort by height for correct topological processing
            all_blocks.sort_by_key(|(_, b)| b.height);
            let mut reindexed = 0u64;
            for (hash, block) in &all_blocks {
                for tx in &block.transactions {
                    let txid = tx.txid();
                    for (j, out) in tx.outputs.iter().enumerate() {
                        let _ = store.put_utxo(&txid, j as u32, out);
                    }
                    if !tx.is_coinbase() {
                        for inp in &tx.inputs {
                            let _ = store.delete_utxo(&inp.prev_txid, inp.prev_index);
                        }
                    }
                }
                reindexed += 1;
            }
            info!("UTXO reindex complete: {} blocks processed", reindexed);
        }
    }*/

    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");


    // ── Continuous Mining Loop ────────────────────────────────────────────────
    if cli.mine {
        // Fresh-miner fork guard: if the operator configured a bootstrap peer
        // or DNS seed they intend to JOIN an existing network, so mining before
        // we have any peer would fork from genesis on the forgeable chain.
        // Nodes with no peer/seed configured (intentional solo / island) keep
        // mining immediately.
        let wants_to_join = !cli.peer.is_empty() || !cli.dns_seed.is_empty();
        let store_m  = store.clone();
        let dag_m    = dag.clone();
        let state_m  = node_state.clone();
        let mem_m    = mempool.clone();
        let otx_m    = outbound_tx.clone();
        let tip_tx_m = tip_tx.clone();  // Sprint 2.c: tip broadcast for stratum
        let shielded_m = shielded.clone(); // LEG1: accept_block needs the shielded pool
        let miner_addr = cli.miner_address.clone().unwrap_or_else(|| {
            eprintln!("❌ --mine requires --miner-address <gnb1q…>: there is no default payout address.");
            std::process::exit(2);
        });
        // FIX #8 / Legacy L-3: convert miner address to a proper 20-byte
        // script_pubkey, or exit loudly — never silently mine into an
        // unspendable script built from the raw --miner-address bytes.
        let miner_spk = address_to_script_pubkey(&miner_addr)
            .unwrap_or_else(|e| {
                eprintln!("❌ --miner-address {miner_addr:?} is not a valid GnB address: {e}. Refusing to mine into an address that cannot be parsed back — every coinbase reward would be unspendable.");
                std::process::exit(1);
            });

        // Capacity: grind the SIS search across all logical CPUs by default
        // (result-identical — see pow::mine_sis_pow_parallel). Override with
        // --mine-threads. Clamp to >=1.
        let mine_threads = cli.mine_threads
            .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1))
            .max(1);

        tokio::spawn(async move {
            info!("⛏  Miner started → {} ({} thread(s))", miner_addr, mine_threads);
            let mut mining_round: u64 = 0;
            // Sprint GG: warn once when we first see IBD active, log
            // transition back to ready so operators see the transition.
            let mut was_syncing_last_tick: bool = false;
            let mut warned_no_peers: bool = false;
            // Sync-stall release: is_syncing pauses mining during genuine IBD,
            // but must never latch forever. If the tip has not advanced for
            // SYNC_STALL_SECS while syncing — peers cannot deliver the announced
            // best_seen tip (e.g. the whole network is wedged behind the
            // reachability perf wall) — resume mining on the best local tip.
            // is_syncing STAYS true so the IBD nudge keeps pulling; PoW advances
            // the chain in the meantime and we reorg to any heavier chain the
            // instant its blocks arrive. This is what stops a network-wide
            // freeze from being permanent.
            const SYNC_STALL_SECS: u64 = 90;
            let mut last_seen_tip: u64 = dag_m.read().tip_blue_score();
            let mut last_tip_advance = std::time::Instant::now();
            let mut warned_stall_release: bool = false;
            loop {
                // Fresh-miner fork guard (see wants_to_join above): a node told
                // to join a network but with 0 peers so far must not mine — it
                // would build an isolated fork from genesis that the network
                // rejects on cumulative work. Pause until at least one peer.
                // Wait not just for a connection but for the first remote tip:
                // there is a window where peer_count>0 but no PeerTip has been
                // evaluated yet, during which a fresh joiner would mine a
                // genesis fork. seen_first_tip closes that race.
                let (has_no_peer, no_tip_yet) = {
                    let s = state_m.read();
                    (s.peer_count == 0, !s.seen_first_tip)
                };
                if wants_to_join && (has_no_peer || no_tip_yet) {
                    if !warned_no_peers {
                        info!("⛏  not ready to mine yet — waiting to connect and see the network tip (would otherwise fork from genesis); still trying to reach the configured peer/seed");
                        warned_no_peers = true;
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }
                if warned_no_peers {
                    info!("⛏  connected and tip evaluated — miner active");
                    warned_no_peers = false;
                }
                // Sprint GG fix (pre-IBD mining bug, 2026-04-22):
                // During IBD the DAG tip reflects the local view, which
                // lags the network by up to thousands of blocks. Mining
                // against a stale tip produces blocks at low height
                // which the rest of the network rejects via the finality
                // rule (block at or below finalized_height). Pre-fix,
                // fresh miners would burn CPU for hours producing
                // orphan blocks that never paid out — an awful new-user
                // experience that looked like a protocol fault.
                //
                // This check pauses the miner loop while is_syncing is
                // true. The heartbeat logs the transition once in each
                // direction so operators can see when IBD started and
                // when mining resumed.
                let syncing_now = state_m.read().is_syncing;
                // Track tip progress for the sync-stall release.
                {
                    let cur_tip = dag_m.read().tip_blue_score();
                    if cur_tip > last_seen_tip {
                        last_seen_tip = cur_tip;
                        last_tip_advance = std::time::Instant::now();
                        warned_stall_release = false;
                    }
                }
                let sync_stalled = last_tip_advance.elapsed()
                    >= std::time::Duration::from_secs(SYNC_STALL_SECS);
                // [no-fork] Freeze finality while mining through a stall (the
                // announced heaviest tip is unreachable and we mine our local
                // tip to stay live): a strictly-heavier chain must still be able
                // to deep-reorg us back once its holder becomes reachable, so
                // mine-through can never self-finalize a solo fork. Unfrozen
                // whenever we are synced or catching up normally.
                FINALITY_FROZEN.store(syncing_now && sync_stalled,
                    std::sync::atomic::Ordering::Relaxed);
                if syncing_now && !sync_stalled {
                    if !was_syncing_last_tick {
                        info!("⛏  IBD in progress — miner paused, will resume when sync completes");
                        was_syncing_last_tick = true;
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }
                if syncing_now && sync_stalled && !warned_stall_release {
                    warn!("⛏  sync stalled {}s at tip {} (announced best_seen unreachable) — resuming mining on best local tip; will reorg when heavier blocks arrive",
                        SYNC_STALL_SECS, last_seen_tip);
                    warned_stall_release = true;
                }
                if was_syncing_last_tick && !syncing_now {
                    info!("⛏  IBD complete — miner resumed at tip");
                    was_syncing_last_tick = false;
                }

                let (tips, current_bits, current_height, current_blue_score) = {
                    let d = dag_m.read();
                    // Mine only on BODIED tips: a header-only tip (accepted via
                    // headers-first sync but whose body never arrived) is
                    // unmineable — a candidate built on it can't be validated by
                    // accept_block, so the miner silently stalls on a phantom
                    // parent. This is exactly what wedged the founder behind a
                    // bodyless header. Fall back to the nearest bodied ancestor
                    // when every tip is header-only.
                    let tips = d.bodied_tips(|h| store_m.get_block(h).ok().flatten().is_some());
                    let h = tips.iter()
                        .filter_map(|t| d.get_block_data(t))
                        .map(|data| data.height)
                        .max()
                        .unwrap_or(0);
                    // blue_score from the bodied parents only — NOT
                    // tip_blue_score(), which follows the bodyless selected_tip.
                    let bs = tips.iter()
                        .filter_map(|t| d.get_block_data(t))
                        .map(|data| data.blue_score)
                        .max()
                        .unwrap_or(0);
                    // ASERT anchored at genesis over the latest parent
                    // timestamp — the exact function accept_block applies to
                    // `tips`, the parents this block will carry.
                    let parent_ts = core::difficulty_parent_timestamp(
                        tips.iter().filter_map(|t| d.get_block_data(t)).map(|data| data.timestamp));
                    let bits_res = pow::expected_bits(parent_ts, h + 1).map(|b| (b, parent_ts));
                    (tips, bits_res, h, bs)
                };

                // Fail closed: never mine on a guessed target.
                let (current_bits, parent_ts) = match current_bits {
                    Ok(b) => b,
                    Err(e) => {
                        warn!("⛏  cannot derive expected bits for next block (h={}): {} — \
                               skipping mining round (fail-closed, no guessed target)",
                              current_height + 1, e);
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        continue;
                    }
                };

                // Re-broadcast mempool TXs before mining
                {
                    let pending = mem_m.get_for_block(100);
                    for tx in &pending {
                        let txid = tx.txid();
                        // Sprint 1.d: Bitcoin-format tx wire.
                        let data = tx.to_wire_bytes(true);
                        let _ = otx_m.try_send(network::NetworkMessage::NewTransaction {
                            txid, tx_data: data,
                        });
                    }
                }
                // Re-broadcast mempool TXs every ~30s to ensure propagation
                if mining_round % 10 == 0 {
                    let pending = mem_m.get_for_block(100);
                    for tx in &pending {
                        let txid = tx.txid();
                        let data = tx.to_wire_bytes(true);
                        let _ = otx_m.try_send(network::NetworkMessage::NewTransaction {
                            txid, tx_data: data,
                        });
                    }
                }
                mining_round += 1;
                let txs = mem_m.get_for_block(2000);

                // FIX VULN-05: Compute fees and include in coinbase. See
                // `miner_template_total_fees`'s doc comment for N-7 (the
                // duplicate-outpoint fee-inflation fix).
                let total_fees: u64 = miner_template_total_fees(&txs, &store_m);

                let block_height = current_height + 1;
                // Fair launch: 100% of subsidy + fees to the miner, one output.
                let subsidy = core::tokenomics::block_subsidy_sat(block_height);
                let cb_outputs = vec![core::TxOutput {
                    value:         subsidy.saturating_add(total_fees),
                    script_pubkey: miner_spk.clone(),
                }];

                let coinbase = core::Transaction {
                    version: 1,
                    inputs: vec![core::TxInput {
                        prev_txid:  [0u8; 32],
                        prev_index: u32::MAX,
                        // Height plus a random tag: two blocks at the same
                        // height (common in a DAG) must never share a
                        // coinbase txid.
                        script_sig: format!("gnb:h{}:{:016x}", block_height, rand::random::<u64>()).into_bytes(),
                        sequence:   u32::MAX,
                    }],
                    outputs: cb_outputs,
                    locktime: 0,
                };

                let all_txs: Vec<core::Transaction> = std::iter::once(coinbase).chain(txs).collect();
                let merkle = core::Transaction::merkle_root(&all_txs);

                let mut block = core::Block {
                    header: core::BlockHeader {
                        version:     1,
                        parents:     tips.clone(),
                        merkle_root: merkle,
                        // Never before a parent (validate_timestamp).
                        timestamp:   std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default().as_secs()
                            .max(parent_ts),
                        bits:        current_bits,
                        nonce:       0,
                    },
                    transactions: all_txs,
                    blue_score:   current_blue_score + 1,
                    height:       block_height,
                    shielded_transactions: Vec::new(),
                };

                // GnB-SMH search. Short rounds (MINE_ROUND_ATTEMPTS nonces per
                // thread, ~10-20 s on a typical core) so the template — tips,
                // mempool, timestamp — is rebuilt often; a fresh random start
                // nonce per round. Aborted early when a new tip arrives.
                const MINE_ROUND_ATTEMPTS: u64 = 64;
                let preimage = block.header.pow_preimage();
                let bits = block.header.bits;
                let start_nonce: u64 = rand::random();
                let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let mut tip_rx = tip_tx_m.subscribe();
                let stop_on_tip = stop.clone();
                let tip_watch = tokio::spawn(async move {
                    if tip_rx.recv().await.is_ok() {
                        stop_on_tip.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                });
                let stop_m = stop.clone();
                let mined = tokio::task::spawn_blocking(move || {
                    pow::mine_parallel(&preimage, bits, start_nonce, MINE_ROUND_ATTEMPTS,
                                       mine_threads, Some(&stop_m))
                }).await;
                tip_watch.abort();

                match mined {
                    Ok(Some(nonce)) => {
                        block.header.nonce = nonce;
                        let hash = block.block_hash();
                        info!("⛏  Block found! h={} {}", block.height, hex::encode(&hash[..8]));

                        // ── Round-2 audit LEG1-selfmine-accept ──────────
                        // Route the self-mined block through the SAME
                        // accept_block pipeline every other ingress uses
                        // (network gossip, RPC submitblock, stratum submit).
                        // The old inline put_block/apply path here committed
                        // the block with NO consensus validation, so a miner
                        // bug the mempool can miss (coinbase over-claim, dust
                        // tx, wrong expected bits, below-finality height, ...)
                        // was persisted locally and only rejected by PEERS —
                        // silently forking the producer off its own network.
                        // accept_block handles the DAG insert, storage,
                        // UTXO/undo mutations (Sprint DD), retarget meta
                        // ("current_bits"), mempool cleanup and the stratum
                        // tip notification; commit_self_mined_block adds the
                        // structural gate + RPC-state refresh, mirroring the
                        // stratum/RPC submission callbacks exactly.
                        if let Err(e) = commit_self_mined_block(
                            &block,
                            &dag_m, &store_m, &mem_m, &state_m,
                            Some(&tip_tx_m), &shielded_m,
                        ) {
                            // A locally-mined block should never be rejected
                            // by our own acceptor — this indicates a miner
                            // bug, not a peer attack. Log loud, do NOT
                            // broadcast, and skip so the miner doesn't spin
                            // on (or propagate) an invalid block.
                            log::error!(
                                "mining: our own block {} was rejected by accept_block: {} — discarding (miner bug)",
                                hex::encode(hash), e,
                            );
                            continue;
                        }

                        // Sprint 1.c: Bitcoin-format wire (replaces bincode).
                        // Infallible — no Result to unwrap.
                        let data = block.to_wire_bytes();
                        let _ = otx_m.send(network::NetworkMessage::NewBlock {
                            block_hash: hash,
                            blue_score: block.blue_score,
                            height:     block.height,
                            block_data: data,
                        }).await;
                    }
                    _ => {
                        tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
                    }
                }
            }
        });
    }

    // ── External block submission (RPC submitblock) ──────────────────────────
    let rpc_submit_block: Arc<rpc::SubmitBlockFn> = make_rpc_submit_block_cb(
        dag.clone(), store.clone(), mempool.clone(), node_state.clone(),
        shielded.clone(), outbound_tx.clone(), tip_tx.clone(),
    );

    let metrics_state = std::sync::Arc::new(
        crate::metrics::MetricsState::new(
            env!("CARGO_PKG_VERSION"),
            if cli.testnet { "testnet" } else { "mainnet" },
        )
    );
    let metrics_config = crate::metrics::MetricsConfig {
        enabled:      cli.metrics,
        bind_address: metrics_bind,
        port:         cli.metrics_port,
    };
    // Install as process-wide singleton so instrumentation points in other
    // modules can increment counters via free functions without plumbing.
    if cli.metrics {
        crate::metrics::install(metrics_state.clone());
    }

    // Periodic sync of gauges from NodeState to Prometheus.
    // Runs every 5s. Cheap — just atomic reads + atomic gauge sets.
    let state_for_metrics = node_state.clone();
    let mempool_for_metrics = mempool.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
        loop {
            interval.tick().await;
            let (height, peers) = {
                let s = state_for_metrics.read();
                (s.block_count as i64, s.peer_count as i64)
            };
            crate::metrics::set_block_count(height);
            crate::metrics::set_peer_count(peers);
            crate::metrics::set_mempool_size(mempool_for_metrics.size() as i64);
        }
    });

    tokio::select! {
        _ = crate::metrics::start_metrics_server(
                metrics_config,
                metrics_state.clone(),
            ) => { error!("metrics exited"); }
        _ = rpc::start_rpc_server(
                rpc::RpcConfig {
                    bind_address:              rpc_bind,
                    port:                      cli.rpc_port,
                    api_key,
                    require_auth_for_writes:   cli.rpc_require_auth_for_writes,
                    rate_limit_reads_per_min:  cli.rpc_rate_limit_reads,
                    rate_limit_writes_per_min: cli.rpc_rate_limit_writes,
                    trust_private_ranges:      cli.rpc_trust_private_ranges,
                    allowed_origins:           cli.rpc_allow_origins.clone(),
                    allowed_hosts:             cli.rpc_allow_hosts.clone(),
                    trust_loopback:            cli.rpc_trust_loopback,
                },
                node_state.clone(), store.clone(), mempool.clone(), dag.clone(), outbound_tx.clone(),
                // B5f pool seam: submitblock hook (see rpc::SubmitBlockFn).
                Some(rpc_submit_block.clone()),
            ) => { error!("RPC exited"); }
        // Sprint EE (S3): `None` = no listen-addr report; production behavior
        // is byte-identical to before the harness affordance was added.
        _ = node.run(block_tx, outbound_rx, dag.clone(), peer_state.clone(), store.clone(), None) => {
            error!("Network exited");
        }
    }
}

// ── External block submission callbacks (RPC submitblock) ──────────────────
//
// Both builders wrap the shared `accept_block` consensus pipeline. They are
// named functions (not inline closures in main()) so their gates can be
// unit-tested — see `external_submission_tests` at the bottom of this file.

/// Commit a block THIS node just mined (Round-2 audit LEG1-selfmine-accept).
///
/// Self-mined blocks MUST take the same acceptance pipeline as every other
/// ingress: structural gate first (same call + error shape as
/// `make_rpc_submit_block_cb` / `make_stratum_accept_block_cb`), then the
/// shared `accept_block` (consensus validation, DAG insert, storage,
/// UTXO/undo mutations, retarget meta, mempool cleanup, finality, stratum
/// tip notification), then the RPC-visible state refresh. Broadcasting to
/// the network stays with the caller — the miner loop only gossips a block
/// its OWN acceptor has admitted.
///
/// Returns the block hash on acceptance; any rejection here means the miner
/// produced a block its own validator refuses (a miner bug), and the caller
/// must discard it WITHOUT broadcasting.
fn commit_self_mined_block(
    block:      &core::Block,
    dag:        &Arc<RwLock<consensus::GhostDAG>>,
    store:      &Arc<storage::Storage>,
    mempool:    &Arc<mempool::Mempool>,
    node_state: &Arc<RwLock<rpc::NodeState>>,
    tip_tx:     Option<&broadcast::Sender<tip::TipChanged>>,
    shielded:   &Arc<RwLock<crate::coherence::ShieldedPool>>,
) -> Result<[u8; 32], String> {
    // Same structural gate as external submissions (audit H2): the producer
    // grants itself no bypass.
    block.validate_structure()
        .map_err(|e| format!("structural validation: {}", e))?;

    let block_hash = block.block_hash();
    accept_block(
        block, block_hash, block.height,
        dag, store, mempool, node_state,
        tip_tx, shielded,
    )?;

    // Refresh RPC-visible state (mirrors the stratum/RPC accept callbacks).
    {
        let mut s = node_state.write();
        s.tip_blue_score = dag.read().tip_blue_score();
        s.block_count    = dag.read().block_count() as u64;
        s.mempool_size   = mempool.size();
    }

    Ok(block_hash)
}

/// Build the RPC `submitblock` hook (B5f pool seam). Behavior is unchanged
/// from the previous inline closure: `Block::block_hash()` identity, dedup,
/// `validate_structure()`, then the shared `accept_block` pipeline + gossip.
fn make_rpc_submit_block_cb(
    dag:        Arc<RwLock<consensus::GhostDAG>>,
    store:      Arc<storage::Storage>,
    mempool:    Arc<mempool::Mempool>,
    node_state: Arc<RwLock<rpc::NodeState>>,
    shielded:   Arc<RwLock<crate::coherence::ShieldedPool>>,
    otx:        mpsc::Sender<network::NetworkMessage>,
    tip_tx:     broadcast::Sender<tip::TipChanged>,
) -> Arc<rpc::SubmitBlockFn> {
    Arc::new(move |block: core::Block| -> Result<String, String> {
        let block_hash = block.block_hash();
        if dag.read().has_block(&block_hash) {
            return Err("duplicate block".to_string());
        }
        block.validate_structure()
            .map_err(|e| format!("structural validation: {}", e))?;

        accept_block(
            &block, block_hash, block.height,
            &dag, &store, &mempool, &node_state,
            Some(&tip_tx), &shielded,
        )?;

        // Refresh RPC-visible state (mirrors the miner loop).
        {
            let mut s = node_state.write();
            s.tip_blue_score = dag.read().tip_blue_score();
            s.block_count    = dag.read().block_count() as u64;
            s.mempool_size   = mempool.size();
        }

        // Broadcast to gossipsub — other peers learn about the block.
        let data = block.to_wire_bytes();
        let msg = network::NetworkMessage::NewBlock {
            block_hash,
            blue_score: block.blue_score,
            height:     block.height,
            block_data: data,
        };
        let otx_clone = otx.clone();
        tokio::spawn(async move { let _ = otx_clone.send(msg).await; });

        Ok(hex::encode(block_hash))
    })
}

// ── Block acceptance + Orphan processing ─────────────────────────────────────

/// [no-fork] Set true while the miner is mining through a stalled IBD latch
/// (the announced heaviest tip is unreachable and we mine our locally-heaviest
/// validated tip to keep the chain live). While frozen we do NOT advance
/// `finalized_height`, so a strictly-heavier chain can still deep-reorg us back
/// once its holder becomes reachable — mine-through can never self-finalize a
/// solo fork. Driven by the miner loop; cleared when synced / catching up.
/// A per-request nonce whose ONLY job is to make each GetBlock unique on the
/// wire, so gossipsub's duplicate cache cannot swallow a retry. Monotonic rather
/// than random: retries must differ from each other, and a counter guarantees
/// that without depending on an RNG or on the clock's resolution.
fn getblock_nonce() -> u64 {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Echo-storm fix: a broadcast Headers frame counts as a reply to OUR OWN
/// GetHeaders only within this window of us actually sending one. Generous vs
/// the ~seconds a real reply takes (each pipeline continuation refreshes the
/// stamp), and safely above the 30s IBD nudge period, so a syncing node can
/// never starve itself; a SYNCED node stops reacting to overheard streams.
const HEADERS_SOLICITED_WINDOW_MS: u64 = 60_000;

static FINALITY_FROZEN: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Set once from `--archive` at startup. Same static-flag shape as
/// FINALITY_FROZEN above: accept_block runs far from the CLI struct and
/// threading a bool through every caller would be noise for a value that is
/// fixed for the process lifetime.
static ARCHIVE_MODE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Validate TX contents, add block to DAG + storage, update UTXO set.
/// Returns Ok(block_hash) on success.
fn accept_block(
    block:      &core::Block,
    block_hash: [u8; 32],
    height:     u64,
    dag:        &Arc<RwLock<consensus::GhostDAG>>,
    store:      &Arc<storage::Storage>,
    mempool:    &Arc<mempool::Mempool>,
    node_state: &Arc<RwLock<rpc::NodeState>>,
    // Sprint 2.c: tip-change broadcast for stratum re-notify.
    // None disables notification (tests, CLI without --stratum).
    tip_tx:     Option<&broadcast::Sender<tip::TipChanged>>,
    // Coherence C2: the node's shielded-pool engine. Block's shielded txs are
    // validated + applied here before the block is committed.
    shielded:   &Arc<RwLock<crate::coherence::ShieldedPool>>,
) -> Result<[u8; 32], String> {

    // Sprint 2.c: snapshot selected tip BEFORE any DAG mutation so we
    // can detect whether this block changed the chain's head. Nested
    // {} scope ensures the lock drops immediately.
    let old_tip = { dag.read().selected_tip() };

    // ── Early dedup ──────────────────────────────────────────────────
    // A block already in the DAG needs no re-validation. Return the same
    // "already in DAG" rejection `add_block` produces, but BEFORE tx
    // validation — so a re-gossip / IBD re-request flood of known blocks
    // stays cheap now that the finality gate below no longer rejects (and
    // thereby short-circuits) below-finality blocks.
    if dag.read().get_block_data(&block_hash).is_some() {
        return Err(format!(
            "consensus rejection: block already in DAG: {}",
            hex::encode(block_hash)
        ));
    }

    // ── Parents must be known (cheap, before anything else) ──────────
    // Height, timestamp and difficulty below are all derived from the
    // parents' DAG entries; an unknown parent would silently skew them.
    if block.header.parents.is_empty() {
        return Err("consensus rejection: non-genesis block without parents".into());
    }
    let parent_data: Vec<(u64, u64)> = {
        let d = dag.read();
        let mut v = Vec::with_capacity(block.header.parents.len());
        for p in &block.header.parents {
            match d.get_block_data(p) {
                Some(data) => v.push((data.height, data.timestamp)),
                None => return Err(format!(
                    "consensus rejection: unknown parent {}", hex::encode(p))),
            }
        }
        v
    };

    // ── FIX VULN-02: height = max parent height + 1 ──────────────────
    let expected_height = parent_data.iter().map(|(h, _)| *h).max().unwrap_or(0) + 1;
    if block.height != expected_height || height != expected_height {
        return Err(format!(
            "invalid height: block claims h={} but expected h={}",
            block.height, expected_height
        ));
    }

    // ── FIX VULN-01: difficulty bits must equal the ASERT schedule ───
    // A pure function of the parent set (latest parent timestamp) and the
    // height, shared with the miner and getblocktemplate. Checked for every
    // block, before the proof of work.
    let parent_ts = core::difficulty_parent_timestamp(parent_data.iter().map(|(_, t)| *t));
    let expected_bits = pow::expected_bits(parent_ts, block.height)
        .map_err(|e| format!("invalid difficulty: {}", e))?;
    if block.header.bits != expected_bits {
        return Err(format!(
            "invalid difficulty: block bits 0x{:08x} != expected 0x{:08x}",
            block.header.bits, expected_bits
        ));
    }

    let finalized_height = store.get_meta("finalized_height").ok().flatten()
        .and_then(|b| b.as_slice().try_into().ok().map(u64::from_le_bytes))
        .unwrap_or(0);

    // ── FIX VULN-04: Validate timestamp ──────────────────────────────
    {
        let parent_ts = block.header.parents.iter()
            .filter_map(|p| dag.read().get_block_data(p).map(|d| d.timestamp))
            .max()
            .unwrap_or(0);
        block.validate_timestamp(parent_ts)
            .map_err(|e| format!("timestamp rejected: {}", e))?;
    }

    // ── Proof of work (expensive: 64 MiB GnB-SMH, cached by block id) ─
    // Runs only after every cheap contextual check above has passed.
    if !block.validate_pow() {
        return Err("consensus rejection: invalid GnB-SMH proof of work".into());
    }

    // ── Validate non-coinbase TXs + compute fees ─────────────────────
    // Coinbase maturity uses the block's consensus-checked height, identical
    // on every honest node.
    let current_height = block.height;
    let mut spent_in_block: HashSet<([u8; 32], u32)> = HashSet::new();
    let mut total_fees: u64 = 0;

    for tx in block.transactions.iter().skip(1) {
        let fee = validate_tx_in_block_with_maturity(
            block, tx, store, &mut spent_in_block, current_height
        )?;
        total_fees = total_fees.checked_add(fee).ok_or("block fee sum overflow")?;
    }

    // ── FIX VULN-05: Validate coinbase value includes fees ───────────
    block.validate_coinbase_value(total_fees)
        .map_err(|e| format!("coinbase rejected: {}", e))?;

    // ── Add to DAG ───────────────────────────────────────────────────
    //
    // Sprint U.4 — capture the selected tip BEFORE add_block so we can
    // classify what this block did to the selected chain once GhostDAG
    // recomputes after insertion.
    let old_selected_tip = dag.read().selected_tip();

    let ts      = block.header.timestamp;
    let parents = block.header.parents.clone();
    let work    = pow::work_from_bits(block.header.bits);
    // M-9: propagate consensus rejection upward instead of panicking.
    // NoParents / DuplicateBlock here mean the caller (the sync path or
    // gossipsub) handed us a structurally-broken block; we reject with
    // a string error just like the other validation steps above.
    // Coherence C2/P1: validate + apply this block's shielded transactions
    // before committing, using the pool's configured ShieldedVerifier — RejectAll
    // by default (safe: no unverifiable value admitted), or the SP1/FRI verifier
    // with `GNB_SHIELDED_VERIFY=sp1` (feature `sp1-verify`). Transparent blocks
    // (no shielded txs) are a no-op. NOTE: the shielded state does not yet track
    // reorgs; that lands with the live SP1 verifier. Merkle-binding already
    // commits the shielded txs into the PoW, so they are non-malleable.
    shielded.write().apply_block_self(block_hash, &block.shielded_transactions)
        .map_err(|e| format!("shielded consensus rejection: {:?}", e))?;

    dag.write().add_block(block_hash, parents, ts, work)
        .map_err(|e| format!("consensus rejection: {}", e))?;

    // CONSENSUS-HALT FIX (DAG-vs-UTXO ordering): the CF_DAG /
    // CF_DAG_INTEGRITY persist that used to happen right here is DEFERRED
    // until after the disposition match below succeeds. `add_block` above is
    // still needed first (GhostDAG selection is the single source of truth
    // for classifying this block), but if the disposition is REFUSED — e.g.
    // `execute_reorg` rejects an over-deep fork flip — the in-memory
    // insertion is rolled back via `GhostDAG::remove_block` and nothing was
    // persisted, so DAG store, CF_DAG and the applied UTXO state move
    // together or not at all. Previously the insertion was persisted
    // unconditionally: a refused deep reorg left `selected_tip()` pinned to
    // the attacker fork forever (every legitimate extension misclassified as
    // ForkLoser) — a durable consensus halt.

    // Persist block body — even if this block ends up in a losing fork, we
    // keep its bytes so a future reorg can apply it without re-downloading.
    // This must happen BEFORE the disposition match: `execute_reorg` reads
    // the bodies of `to_apply` blocks (including this one) from CF_BLOCKS.
    // Block bodies are not consensus state — selected-tip / blue-work
    // decisions are driven solely by CF_DAG, which is only written after
    // success — so a body left behind by a rejected block is inert.
    // On a body-persist failure, roll the in-memory insertion back.
    if let Err(e) = store.put_block(block) {
        dag.write().remove_block(&block_hash);
        return Err(e.to_string());
    }

    // Informational only (RPC / tip notifications): the bits of the most
    // recently accepted block. Consensus never reads this; expected bits are
    // derived from each block's parents (pow::expected_bits).
    let _ = store.put_meta("current_bits", &block.header.bits.to_le_bytes());

    // ── Sprint U.4: disposition-based state application (closes C-1) ──
    //
    // Classify how this block affected the selected chain, then apply
    // UTXO mutations only when appropriate:
    //
    //   * FORK-LOSER   — the selected tip didn't move to this block.
    //                    Persist block + DAG data only; do NOT touch
    //                    UTXO set or mempool. The block lives in the DAG
    //                    and may win later (triggering a reorg).
    //
    //   * EXTENSION    — this block IS the new selected tip, and its
    //                    selected_parent is exactly the old tip. Apply
    //                    forward just like the pre-U.4 path.
    //
    //   * REORG        — this block IS the new selected tip, but its
    //                    selected_parent is NOT the old tip. The fork
    //                    that contains this block has outgrown the old
    //                    chain. Roll back old chain blocks to the LCA,
    //                    apply new chain blocks from LCA to this block,
    //                    reinject still-valid mempool txs.
    //
    // The match is exhaustive over the (old, new) tuple; unexpected
    // transitions (e.g. add_block produced no tip) log a warning and
    // leave state untouched so we don't corrupt anything.
    let new_selected_tip = dag.read().selected_tip();

    enum Disposition {
        Extension,
        ForkLoser,
        Reorg,
        Unexpected,
    }

    let disposition = match (old_selected_tip, new_selected_tip) {
        (None, Some(t)) if t == block_hash => {
            // Post-genesis first block — no prior tip. Treat as extension.
            Disposition::Extension
        }
        (Some(old), Some(new)) if new == old => Disposition::ForkLoser,
        (Some(old), Some(new)) if new == block_hash => {
            let selected_parent = dag.read()
                .get_block_data(&block_hash)
                .and_then(|d| d.selected_parent);
            if selected_parent == Some(old) {
                Disposition::Extension
            } else {
                Disposition::Reorg
            }
        }
        _ => Disposition::Unexpected,
    };

    // ── Finality invariant: below-finality blocks stay inert ─────────
    // A block at or below the finalized height is welcome in the DAG as a
    // fork-loser (its body was retained above), but it must NEVER become the
    // selected tip — that would rewrite finalized history. In practice an
    // Extension cannot reach here below finality (it extends a tip already
    // above it), and a Reorg flipping the tip below finality is over-deep and
    // also refused by MAX_REORG_DEPTH; this guard makes the invariant explicit
    // and independent of that constant. Roll the in-memory insertion back the
    // same way the refused-reorg path does (nothing is persisted to CF_DAG
    // yet; the body left in CF_BLOCKS is inert).
    if block.height <= finalized_height
        && matches!(disposition, Disposition::Extension | Disposition::Reorg)
    {
        dag.write().remove_block(&block_hash);
        return Err(format!(
            "finality: block h={} may not become the selected tip at or below finalized height {}",
            block.height, finalized_height
        ));
    }

    match disposition {
        Disposition::ForkLoser => {
            info!(
                "block h={} {} accepted into fork (not selected tip)",
                block.height, hex::encode(&block_hash[..8])
            );
            // Intentional no-op on UTXO / mempool / tip_hash. The block is
            // now reachable via CF_BLOCKS + DAG; a future reorg can bring
            // it into the selected chain.
        }

        Disposition::Extension => {
            // Apply this block's mutations forward. Uses the shared helper
            // (src/reorg.rs) so extension and reorg re-apply go through
            // identical code — they must produce byte-identical UndoData.
            // Legacy L-1: `apply_block_utxo_mutations` now propagates every
            // write error instead of silently discarding it (previously
            // only `put_undo_data` failures were even visible here). This
            // call site does NOT yet roll back or abort on failure — doing
            // so safely requires the atomic single-WriteBatch commit and
            // startup reconciliation check tracked as Legacy M-7 (not yet
            // implemented: mid-block failure here can already leave the
            // UTXO set, block body, and tip in different states, and
            // returning early now — without a rollback path — would not
            // fix that, only change WHICH state is inconsistent). Until
            // M-7 lands, a failure here is a fleet-visible, actionable
            // signal (error!, not warn!) that this node's UTXO set may have
            // diverged and needs `--verify-carryover`-style reconciliation.
            if let Err(e) = reorg::apply_block_utxo_mutations(store, block) {
                error!(
                    "U.4/L-1: apply_block_utxo_mutations FAILED for h={}: {} — this node's \
                     UTXO set may now be inconsistent with its block/DAG state (Legacy M-7: \
                     atomic commit + startup reconciliation not yet implemented). Investigate \
                     storage health immediately.",
                    block.height, e
                );
            }

            let confirmed: Vec<[u8; 32]> = block.transactions.iter().map(|t| t.txid()).collect();
            mempool.remove_confirmed(&confirmed);
            store.put_meta("tip_hash", &block_hash).ok();
        }

        Disposition::Reorg => {
            // new_selected_tip must be Some here (we matched on it).
            let new_tip = new_selected_tip.expect("reorg disposition implies Some(new_tip)");
            let old_tip = old_selected_tip.expect("reorg disposition implies Some(old_tip)");

            let plan = {
                let d = dag.read();
                reorg::compute_reorg_plan(&d, &old_tip, &new_tip)
            };
            let plan = match plan {
                Some(p) => p,
                None => {
                    // CONSENSUS-HALT FIX: roll the in-memory DAG insertion
                    // back before rejecting — nothing has been persisted to
                    // CF_DAG yet, so DAG and applied UTXO state stay in sync.
                    dag.write().remove_block(&block_hash);
                    return Err(format!(
                        "U.4: tip changed to {} via reorg but compute_reorg_plan returned None (old={}, new={})",
                        hex::encode(&new_tip[..8]),
                        hex::encode(&old_tip[..8]),
                        hex::encode(&new_tip[..8]),
                    ));
                }
            };

            info!(
                "🔀 Reorg at h={}: rollback {} blocks, apply {} blocks (lca={})",
                block.height,
                plan.to_rollback.len(),
                plan.to_apply.len(),
                hex::encode(&plan.lca[..8]),
            );

            let outcome = match reorg::execute_reorg(store, mempool, &plan) {
                Ok(o) => o,
                Err(e) => {
                    // CONSENSUS-HALT FIX: a refused reorg (e.g. deeper than
                    // reorg::MAX_REORG_DEPTH) or a failed one left the UTXO
                    // store untouched by design. The in-memory DAG insertion
                    // must be undone as well — otherwise selected_tip()
                    // permanently adopts a fork whose state was never
                    // applied, and every legitimate extension of the real
                    // chain is misclassified as ForkLoser: a durable halt.
                    // Nothing was persisted to CF_DAG (deferred until after
                    // this match), so the undo is purely in-memory.
                    if !dag.write().remove_block(&block_hash) {
                        warn!(
                            "U.4: failed to roll back DAG insertion of {} after refused reorg \
                             (block gained children concurrently?) — tip may be inconsistent",
                            hex::encode(&block_hash[..8]),
                        );
                    }
                    return Err(format!("U.4: execute_reorg failed: {}", e));
                }
            };

            info!(
                "   reorg done: rolled_back={}, applied={}, txs_reinjected={}, txs_discarded={}",
                outcome.rolled_back, outcome.applied,
                outcome.txs_reinjected, outcome.txs_discarded,
            );

            // execute_reorg already applied all to_apply blocks (including
            // the one we just accepted). Now remove those txs from mempool
            // in case any had slipped in between rollback and apply.
            let confirmed: Vec<[u8; 32]> = block.transactions.iter().map(|t| t.txid()).collect();
            mempool.remove_confirmed(&confirmed);
            store.put_meta("tip_hash", &new_tip).ok();
        }

        Disposition::Unexpected => {
            warn!(
                "U.4: unexpected selected-tip transition during accept of block h={} \
                 (old={:?}, new={:?}, block={})",
                block.height, old_selected_tip, new_selected_tip, hex::encode(&block_hash[..8])
            );
            // Refuse to mutate state on an unexpected transition.
            // CONSENSUS-HALT FIX: previously the block stayed in the DAG
            // (and was persisted) while UTXO state was left untouched — the
            // same DAG-vs-UTXO divergence as the refused-reorg case. Roll
            // the in-memory insertion back and reject, so a re-submission
            // can be classified cleanly later.
            dag.write().remove_block(&block_hash);
            return Err(format!(
                "U.4: unexpected selected-tip transition (old={:?}, new={:?}); block {} rejected",
                old_selected_tip, new_selected_tip, hex::encode(&block_hash[..8]),
            ));
        }
    }

    // CONSENSUS-HALT FIX: the DAG entry is persisted only NOW, after the
    // disposition above has been applied successfully. Every refusal path
    // above rolled the in-memory insertion back and returned Err, so CF_DAG
    // can never adopt a fork tip whose chain state was refused.
    // NOTE: bind the cloned data in its own `let` so the `dag.read()` guard is
    // released at the `;` — parking_lot's RwLock is NOT reentrant, so keeping a
    // read guard alive across `dag.write()` below deadlocks (write parks waiting
    // for the reader that this same thread holds). Harmless while Legacy left the
    // index untouched; a hard hang once the reachability gate arms `dag.write()`.
    let ddata_opt = dag.read().get_block_data(&block_hash).cloned();
    if let Some(ddata) = ddata_opt {
        // Sprint Y (M-2): atomic put to CF_DAG + CF_DAG_INTEGRITY.
        // Phase 1: when the reachability index is maintained, fold its delta
        // (which may span several blocks if this insert triggered a reindex)
        // into the SAME WriteBatch, so a crash here leaves CF_DAG and
        // CF_REACHABILITY consistent all-or-nothing. Live Legacy: unchanged.
        if dag.read().maintains_reachability_index() {
            let (upserts, removals) = dag.write().reach_take_delta();
            store.put_dag_with_integrity_and_reach(&block_hash, &ddata, &upserts, &removals).ok();
        } else {
            store.put_dag_with_integrity(&block_hash, &ddata).ok();
        }
    }

    // ── Update node state ────────────────────────────────────────────
    {
        let mut s = node_state.write();
        s.tip_blue_score = dag.read().tip_blue_score();
        s.block_count    = dag.read().block_count() as u64;
        s.mempool_size   = mempool.size();
    }
    info!("✓ block h={} accepted", height);

    // ── Update finality checkpoint ───────────────────────────────────
    // Once tip is CHECKPOINT_DEPTH ahead, finalize everything below.
    // NOTE: this MUST be the selected tip's *height*, not tip_blue_score().
    // finalized_height is compared against block.height at the finality gate
    // above; feeding it blue_score (which runs ahead of height by the DAG
    // width) makes the node "finalize" a height above its own tip once the
    // skew exceeds CHECKPOINT_DEPTH, permanently rejecting every
    // chain-extending block. Same height unit feeds the pruning block below.
    let tip_height = {
        let d = dag.read();
        d.selected_tip()
            .and_then(|h| d.get_block_data(&h).map(|data| data.height))
            .unwrap_or(0)
    };
    // [no-fork] Do not advance finality while mining through a stalled latch —
    // freezing finalized_height keeps a heavier chain able to reorg us back.
    if tip_height > core::CHECKPOINT_DEPTH
        && !FINALITY_FROZEN.load(std::sync::atomic::Ordering::Relaxed)
    {
        let new_finalized = tip_height - core::CHECKPOINT_DEPTH;
        let current_finalized = store.get_meta("finalized_height").ok().flatten()
            .and_then(|b| b.as_slice().try_into().ok().map(u64::from_le_bytes))
            .unwrap_or(0);
        if new_finalized > current_finalized {
            store.put_meta("finalized_height", &new_finalized.to_le_bytes()).ok();
        }
    }

    // ── Prune old block bodies ───────────────────────────────────────
    // Remove full block data beyond PRUNING_DEPTH (keeps height→hash, DAG, TX index)
    if ARCHIVE_MODE.load(std::sync::atomic::Ordering::Relaxed) {
        // Archival node: keep everything. Logged once per prune window so an
        // operator can see the choice is in effect rather than inferring it.
        if tip_height % 10_000 == 0 {
            info!("archival mode: retaining ALL block bodies (h={}); pruning disabled", tip_height);
        }
    } else if tip_height > core::PRUNING_DEPTH {
        let prune_below = tip_height - core::PRUNING_DEPTH;
        let last_pruned = store.pruned_height();
        if prune_below > last_pruned + 1000 { // batch: prune every 1000 blocks
            match store.prune_blocks_below(prune_below) {
                Ok(n) if n > 0 => info!("Pruned {} block bodies below h={}", n, prune_below),
                Err(e)         => warn!("Prune failed: {}", e),
                _ => {}
            }
        }
    }

    // ── Sprint 2.c: emit TipChanged if the selected tip moved ────────
    //
    // This hook runs regardless of how the block got here (network
    // gossipsub, stratum submit, orphan resurrection, miner loop —
    // miner loop has its own inline hook because it doesn't route
    // through this function). If `tip_tx` is None (no subscriber or
    // unit test) the work is skipped entirely.
    //
    // Semantics of TipChanged fields: describe the CURRENT tip
    // (post-accept). Stratum consumers use this + dag.tips() +
    // current_bits to build a fresh template for the NEXT block.
    if let Some(tip_tx) = tip_tx {
        // Bodied tip only: a header-only tip is unmineable, so stratum must
        // be notified on the best BODIED tip / parents, never a phantom.
        let has_body = |h: &[u8; 32]| store.get_block(h).ok().flatten().is_some();
        let new_tip = { dag.read().best_bodied_tip(has_body) };
        if new_tip != old_tip {
            if let Some(tip_hash) = new_tip {
                let d = dag.read();
                if let Some(data) = d.get_block_data(&tip_hash).cloned() {
                    let tips_parents: Vec<[u8; 32]> = d.bodied_tips(has_body);
                    drop(d);

                    let bits = store.get_meta("current_bits").ok().flatten()
                        .and_then(|b| b.as_slice().try_into().ok().map(u32::from_le_bytes))
                        .unwrap_or(0x1d00ffff_u32);

                    // send() returns Err(SendError) iff there are 0
                    // receivers — we intentionally ignore that case
                    // since stratum might not be running.
                    let _ = tip_tx.send(tip::TipChanged {
                        hash:       tip_hash,
                        height:     data.height,
                        blue_score: data.blue_score,
                        parents:    tips_parents,
                        bits,
                    });
                }
            }
        }
    }

    Ok(block_hash)
}

/// Blue_work-VERIFIED IBD release — the ONLY path that clears `is_syncing`.
///
/// Phase-2 sync-negotiation invariant: announced blue_score NEVER releases the
/// latch (a peer can lie). We clear IBD only when, computed locally from the
/// DAG: (1) the frontier is reconciled — we `has_block` every connected peer's
/// advertised tip AND nothing is in flight — AND (2) our selected-tip
/// `blue_work` is at least the greatest locally-verified `blue_work` reachable
/// from a connected peer (`servable_blue_work`). Tips we cannot verify against
/// our own DAG contribute 0, so unbacked high announcements cannot gate release.
///
/// Lock order (must match every other call-site): dag → peer_state → frontier
/// → node_state. All read locks drop before node_state.write().
fn maybe_release_ibd(
    dag:        &Arc<RwLock<consensus::GhostDAG>>,
    peer_state: &Arc<sync::peer_state::PeerStateTable>,
    frontier:   &Arc<parking_lot::Mutex<sync::frontier::FrontierState>>,
    node_state: &Arc<RwLock<rpc::NodeState>>,
) {
    let (our_work, our_score, servable, reconciled, have_frontier, abandoned_gap) = {
        let d = dag.read();
        let selected = d.selected_tip().and_then(|h| d.get_node(&h));
        let our_work = selected.as_ref().map(|n| n.blue_work).unwrap_or(0);
        let our_score = selected.as_ref().map(|n| n.blue_score).unwrap_or(0);
        let servable = peer_state.servable_blue_work(|h| d.get_node(h).map(|n| n.blue_work));
        let advertised = peer_state.connected_advertised_tips();
        let have_frontier = !advertised.is_empty();
        // Frontier lock taken into a local guard (lock order dag→peer_state→
        // frontier→node_state); compute outstanding + reconciled, drop before write.
        let fr = frontier.lock();
        let outstanding = fr.outstanding();
        let reconciled = sync::frontier::reconciled(
            &advertised, |h| d.has_block(h), outstanding, |h| fr.is_abandoned(h),
        );
        // Honest-RPC fix: an advertised tip we do NOT hold that only counts as
        // "resolved" because we gave up fetching it (abandoned after
        // BlockNotFound/timeouts). Giving up is not catching up — this must
        // never let the VERIFIED release claim completion (the captured lie:
        // "IBD complete (verified=true caught_up=false; score 27779
        // best_announced 27852)", declared complete 173 blue_score behind
        // BECAUSE the unreachable frontier made `servable` under-count).
        let abandoned_gap = advertised.iter().any(|h| !d.has_block(h) && fr.is_abandoned(h));
        drop(fr);
        (our_work, our_score, servable, reconciled, have_frontier, abandoned_gap)
    };
    let best_announced = peer_state.best_announced_blue_score();
    // Release the IBD latch on the FIRST of two signals (both backstopped by the
    // 90s mine-through valve, so neither can freeze the miner):
    //  (A) VERIFIED / griefer-proof: we hold every advertised tip (or it is
    //      abandoned-as-unreachable, per Fix #1) AND our selected chain is at
    //      least the best VERIFIED reachable work. Gated on `have_frontier` so an
    //      empty advertised set cannot vacuously release us mid-catch-up.
    //  (B) LAG / mining-lag tolerant: our selected tip is within IBD_EXIT_LAG
    //      blue_score of the best ANNOUNCED tip — normal operation, not a bulk
    //      backlog. This is what lets a trailing MINER keep mining (leapfrog)
    //      instead of freezing as a pure follower: the canary proved the strict
    //      verified gate (A) never completes while a peer mines continuously (the
    //      chased frontier keeps moving). Announced score is UNTRUSTED and only
    //      ever RELEASES here (never blocks); a lying high-announce peer keeps us
    //      out of (A)+(B) and we fall back to the 90s throttled mine-through — it
    //      can never freeze us and never fakes a completion during a real backlog.
    // Honest-RPC fix: `!abandoned_gap` keeps an abandoned (given-up) frontier
    // from releasing the VERIFIED path — `servable` under-counts exactly when
    // tips were abandoned, so "our_work >= servable" is vacuous then. The
    // caught_up path (B) still releases a node genuinely near the announced
    // tip, and the 90s mine-through valve still protects miner liveness, so a
    // phantom unreachable tip cannot freeze anything — the node just STOPS
    // CLAIMING it finished syncing when it actually gave up.
    let verified  = have_frontier && reconciled && !abandoned_gap && our_work >= servable;
    let caught_up = our_score.saturating_add(sync::IBD_EXIT_LAG) >= best_announced;
    {
        let mut s = node_state.write();
        // Refresh the RPC honesty hint on every latch re-test (event-driven +
        // 30s nudge), so `getnetworkinfo` can report real lag (`behind_by`)
        // even while `syncing` stays latched — or after a stale release.
        s.best_announced_blue_score = best_announced;
        if (verified || caught_up) && s.is_syncing {
            s.is_syncing = false;
            info!("IBD complete (verified={} caught_up={}; score {} best_announced {}; work {} servable {}; abandoned_gap={})",
                verified, caught_up, our_score, best_announced, our_work, servable, abandoned_gap);
        }
    }
}

/// After accepting a block, check if any orphans can now be processed.
/// Recursively processes orphans whose parents become available.
fn process_orphans(
    accepted_hash: [u8; 32],
    orphans:       &mut std::collections::HashMap<[u8; 32], (core::Block, Vec<u8>, u64)>,
    waiting_for:   &mut std::collections::HashMap<[u8; 32], HashSet<[u8; 32]>>,
    dag:           &Arc<RwLock<consensus::GhostDAG>>,
    store:         &Arc<storage::Storage>,
    mempool:       &Arc<mempool::Mempool>,
    node_state:    &Arc<RwLock<rpc::NodeState>>,
    // Sprint 2.c: propagate tip broadcast through orphan resurrection.
    tip_tx:        Option<&broadcast::Sender<tip::TipChanged>>,
    shielded:      &Arc<RwLock<crate::coherence::ShieldedPool>>,
) {
    // Collect orphans waiting for the accepted block
    let candidates: Vec<[u8; 32]> = waiting_for.remove(&accepted_hash)
        .unwrap_or_default()
        .into_iter()
        .collect();

    for orphan_hash in candidates {
        let all_parents_present = orphans.get(&orphan_hash)
            .map(|(b, _, _)| b.header.parents.iter().all(|p| dag.read().has_block(p)))
            .unwrap_or(false);

        if !all_parents_present { continue; }

        // Remove from orphan pool
        if let Some((block, _block_data, height)) = orphans.remove(&orphan_hash) {
            // Clean up waiting_for entries for this orphan
            for p in &block.header.parents {
                if let Some(set) = waiting_for.get_mut(p) {
                    set.remove(&orphan_hash);
                    if set.is_empty() { waiting_for.remove(p); }
                }
            }

            match accept_block(&block, orphan_hash, height, dag, store, mempool, node_state, tip_tx, shielded) {
                Ok(hash) => {
                    info!("✓ orphan h={} accepted (pool={})", height, orphans.len());
                    // Recursively process orphans waiting for THIS block
                    process_orphans(hash, orphans, waiting_for, dag, store, mempool, node_state, tip_tx, shielded);
                }
                Err(e) => {
                    warn!("orphan h={} rejected: {}", height, e);
                }
            }
        }
    }
}

/// Orphan-deadlock fix: periodic (~30s) sweep over the missing-parent set.
///
/// The one-shot GetBlock in the NewBlock orphan arm has no timeout and no
/// retry — a single lost response (full ingest channel, gossip publish racing
/// a subscription, directed-pull timeout) used to deadlock the orphan and
/// every descendant forever. This sweep re-emits GetBlock for parents pending
/// past their (exponential, capped) backoff, gives up past an attempt/age
/// ceiling (dropping the dependent orphans so `waiting_for` stays bounded),
/// and returns waited-on parents that are ALREADY in the DAG so the caller
/// can drain their orphans (accept/insert race liveness).
///
/// NOT consensus: only re-sends an existing wire message and prunes a local
/// buffer. Validation/acceptance paths untouched.
async fn sweep_orphan_parents(
    orphans:      &mut std::collections::HashMap<[u8; 32], (core::Block, Vec<u8>, u64)>,
    waiting_for:  &mut std::collections::HashMap<[u8; 32], HashSet<[u8; 32]>>,
    parent_fetch: &mut sync::parent_fetch::ParentFetchTracker,
    dag:          &Arc<RwLock<consensus::GhostDAG>>,
    otx:          &tokio::sync::mpsc::Sender<network::NetworkMessage>,
) -> Vec<[u8; 32]> {
    let now = std::time::Instant::now();
    // Partition waited-on parents WITHOUT holding the DAG lock across awaits:
    //  ready — already in the DAG (drainable orphans);
    //  chased — not buffered, not in the DAG: these need (re-)fetching.
    let (ready, chased) = {
        let d = dag.read();
        let mut ready = Vec::new();
        let mut chased = Vec::new();
        for p in waiting_for.keys() {
            if d.has_block(p) {
                ready.push(*p);
            } else if !orphans.contains_key(p) {
                chased.push(*p);
            }
        }
        (ready, chased)
    };
    let (retry, give_up) = parent_fetch.sweep(&chased, now);
    for h in &retry {
        let _ = otx.send(network::NetworkMessage::GetBlock {
            block_hash: *h, nonce: getblock_nonce(),
        }).await;
    }
    if !retry.is_empty() {
        info!("orphan sweep: re-requested {} missing parent(s) (orphans={} waiting={})",
            retry.len(), orphans.len(), waiting_for.len());
    }
    for (h, attempts) in give_up {
        let dropped = drop_orphan_subtree(h, orphans, waiting_for);
        warn!("orphan sweep: giving up on missing parent {} after {} attempts; \
               dropped {} dependent orphan(s) — peers will re-announce if the \
               branch is real", hex::encode(&h[..8]), attempts, dropped);
    }
    ready
}

/// Remove every orphan transitively waiting on `root_parent` (which we gave up
/// fetching), cleaning their `waiting_for` back-references. Returns how many
/// orphans were dropped. Dropped orphans are NOT banned: if a peer re-announces
/// the branch and its ancestry becomes fetchable, it re-enters the pool.
fn drop_orphan_subtree(
    root_parent: [u8; 32],
    orphans:     &mut std::collections::HashMap<[u8; 32], (core::Block, Vec<u8>, u64)>,
    waiting_for: &mut std::collections::HashMap<[u8; 32], HashSet<[u8; 32]>>,
) -> usize {
    let mut dropped = 0usize;
    let mut stack: Vec<[u8; 32]> = waiting_for
        .remove(&root_parent)
        .map(|s| s.into_iter().collect())
        .unwrap_or_default();
    while let Some(h) = stack.pop() {
        if let Some((block, _, _)) = orphans.remove(&h) {
            dropped += 1;
            // Detach from any OTHER parents this orphan was waiting on.
            for p in &block.header.parents {
                if let Some(set) = waiting_for.get_mut(p) {
                    set.remove(&h);
                    if set.is_empty() { waiting_for.remove(p); }
                }
            }
            // Cascade: orphans waiting on the one we just dropped.
            if let Some(children) = waiting_for.remove(&h) {
                stack.extend(children);
            }
        }
    }
    dropped
}

// ── Unified TX validation ────────────────────────────────────────────────────
// FIX #10: Single validation core used by all code paths.

/// Core input validation logic shared by all TX validation paths.
/// Resolves each input's UTXO, checks pubkey hash match, verifies ML-DSA-65
/// signature, and accumulates total input value.
fn validate_tx_inputs(
    tx:           &core::Transaction,
    utxo_lookup:  &dyn Fn(&[u8; 32], u32) -> Result<Option<core::TxOutput>, String>,
    mut spent_set: Option<&mut HashSet<([u8; 32], u32)>>,
) -> Result<u64, String> {
    let mut total_in = 0u64;

    // C-R3-2: the intra-tx duplicate-outpoint check is UNCONDITIONAL. The
    // standalone (gossip-relay) path passes `spent_set = None`, and the old
    // Some-gated check let a tx list the SAME outpoint N times — its value
    // was counted N times below, so a doubled-fee double-spend was admitted
    // to the mempool. `local_spent` catches duplicates within THIS tx on
    // every path; the caller's `spent_set` (when provided) still tracks
    // cross-tx conflicts inside a block.
    let mut local_spent: HashSet<([u8; 32], u32)> = HashSet::new();

    for (i, inp) in tx.inputs.iter().enumerate() {
        let outpoint = (inp.prev_txid, inp.prev_index);

        // FIX #9 + C-R3-2: double-spend within the same validation context —
        // cross-tx via the caller's set (when present), intra-tx ALWAYS via
        // the local insert-as-check.
        let cross_tx_dup = spent_set.as_ref().is_some_and(|s| s.contains(&outpoint));
        if cross_tx_dup || !local_spent.insert(outpoint) {
            return Err(format!("double-spend: {}:{} already consumed",
                hex::encode(&inp.prev_txid[..8]), inp.prev_index));
        }

        // Resolve UTXO
        let utxo = utxo_lookup(&inp.prev_txid, inp.prev_index)?
            .ok_or_else(|| format!("UTXO {}:{} not found",
                hex::encode(&inp.prev_txid[..8]), inp.prev_index))?;

        total_in = total_in.checked_add(utxo.value).ok_or("input overflow")?;

        // Parse and verify script_sig
        let (sig, pk) = core::Transaction::parse_script_sig(&inp.script_sig)
            .ok_or_else(|| format!("malformed script_sig at input {}", i))?;

        // Verify pubkey hash matches UTXO script_pubkey
        let pk_hash = {
            use sha3::{Sha3_256, Digest};
            Sha3_256::digest(&pk)[..20].to_vec()
        };
        if pk_hash != utxo.script_pubkey {
            return Err(format!("pubkey mismatch at input {}", i));
        }

        // Verify hybrid ML-DSA-65 ‖ Falcon-1024 signature. Chain-id (Roadmap #8)
        // is the node-level single source of truth — miner and validator share it
        // (see core::node_chain_id / set_node_chain_id).
        let sighash = tx.sighash(i, core::node_chain_id());
        if !crypto::verify(&pk, &sighash, &sig) {
            return Err(format!("invalid signature at input {}", i));
        }

        // Mark outpoint as spent
        if let Some(spent) = spent_set.as_mut() {
            spent.insert(outpoint);
        }
    }

    let total_out: u64 = tx.outputs.iter()
        .try_fold(0u64, |acc, o| acc.checked_add(o.value))
        .ok_or("output sum overflow")?;
    if total_in < total_out {
        return Err(format!("inputs {} < outputs {}", total_in, total_out));
    }
    let fee = total_in - total_out;
    core::check_min_fee(tx, fee)?;
    Ok(fee)
}

/// Compute the total fee the miner's OWN block template may claim across
/// `txs` (the candidate set selected from the mempool), reading prevout
/// values from the persistent UTXO set.
///
/// SECURITY (Legacy N-7): counts each of a transaction's outpoints ONCE —
/// insert-as-check, mirroring the C-R3-2 duplicate-outpoint rejection real
/// admission applies (`validate_tx_inputs`'s `local_spent`). This used to
/// `filter_map`+`sum` over `tx.inputs` unconditionally, so a transaction
/// listing the SAME outpoint N times had that outpoint's value summed N
/// times, inflating the fee the coinbase this template builds is allowed to
/// claim. Such a transaction is rejected outright by real consensus
/// validation (the identical insert-as-check, re-run when this self-mined
/// block is committed through the normal `accept_block` path) — it can never
/// legitimately contribute ANY fee, so this estimate must not act as if it
/// could either. Concretely: without this fix, a template that included such
/// a transaction would build a coinbase `validate_coinbase_value` then
/// rejects when the self-mined block is committed — wasting the mined block
/// (a liveness bug) rather than minting anything (accept_block's real,
/// non-inflating fee computation is still the actual consensus gate) — but
/// the template must not rely on that backstop to compute a correct number.
fn miner_template_total_fees(
    txs:   &[core::Transaction],
    store: &storage::Storage,
) -> u64 {
    txs.iter().map(|tx| {
        let mut seen_outpoints: HashSet<([u8; 32], u32)> = HashSet::new();
        let mut has_duplicate_outpoint = false;
        let mut total_in: u64 = 0;
        for inp in &tx.inputs {
            if !seen_outpoints.insert((inp.prev_txid, inp.prev_index)) {
                has_duplicate_outpoint = true;
                continue;
            }
            if let Ok(Some(out)) = store.get_utxo(&inp.prev_txid, inp.prev_index) {
                total_in = total_in.saturating_add(out.value);
            }
        }
        if has_duplicate_outpoint {
            return 0;
        }
        let total_out: u64 = tx.outputs.iter()
            .try_fold(0u64, |acc, o| acc.checked_add(o.value))
            .unwrap_or(u64::MAX); // overflow → caller (validate_coinbase_value) will reject
        total_in.saturating_sub(total_out)
    }).sum()
}

/// Validate a transaction within a block context.
/// Uses both in-block outputs and persistent UTXO set, with double-spend tracking.
fn validate_tx_in_block(
    block:          &core::Block,
    tx:             &core::Transaction,
    store:          &Arc<storage::Storage>,
    spent_in_block: &mut HashSet<([u8; 32], u32)>,
) -> Result<(), String> {
    validate_tx_in_block_with_maturity(block, tx, store, spent_in_block, 0)?;
    Ok(())
}

/// FIX VULN-03: Validate TX within a block, including coinbase maturity check.
/// Returns the fee (total_in - total_out) for coinbase value validation.
fn validate_tx_in_block_with_maturity(
    block:          &core::Block,
    tx:             &core::Transaction,
    store:          &Arc<storage::Storage>,
    spent_in_block: &mut HashSet<([u8; 32], u32)>,
    current_height: u64,
) -> Result<u64, String> {
    // SECURITY (Legacy C-2): build the in-block prevout map from ONLY the
    // transactions STRICTLY BEFORE `tx` in `block.transactions` — never from
    // the whole block. This used to `flat_map` over ALL of
    // `block.transactions` unconditionally, so a transaction could spend the
    // output of a LATER transaction in the same block: `tx[i]` validates
    // (and is fee-accounted, and its own outputs get created) as if it had
    // genuinely spent `tx[j]`'s (j > i) output, while the actual UTXO
    // application (`reorg::apply_block_utxo_mutations`) writes each
    // transaction's outputs THEN deletes its inputs, walking the block IN
    // ORDER — so `tx[j]`'s output is written to storage only AFTER `tx[i]`'s
    // (no-op, not-yet-existent-key) delete already ran, leaving it
    // permanently unspent. The value tx[i] was credited for spending is
    // never actually removed from the UTXO set: a supply-inflating mint,
    // out-of-order-block-only, requiring no signature forgery.
    //
    // A transaction MAY legitimately spend an EARLIER same-block
    // transaction's output (ordinary same-block chaining, e.g. a miner
    // including a child of a transaction it also included) — that is
    // exactly what the apply-order above expects and this preserves. It may
    // never spend its own or a later transaction's not-yet-created output.
    //
    // `tx` is identified by TXID (content hash) rather than by reference
    // identity so this is correct whether the caller passes a reference
    // borrowed from `block.transactions` (the real consensus path) or an
    // owned clone with identical content (as some call sites do); if `tx`'s
    // txid is not found in `block.transactions` at all (a misuse this
    // function's real callers never trigger), this falls back to the full
    // block — permissive only for that out-of-invariant case.
    let tx_txid = tx.txid();
    let cutoff = block.transactions.iter()
        .position(|t| t.txid() == tx_txid)
        .unwrap_or(block.transactions.len());
    let block_utxos: std::collections::HashMap<([u8; 32], u32), core::TxOutput> = block.transactions[..cutoff]
        .iter()
        .flat_map(|t| {
            let txid = t.txid();
            t.outputs.iter().enumerate().map(move |(i, o)| ((txid, i as u32), o.clone()))
        })
        .collect();

    // Coinbase maturity check (VULN-03). Single source of truth in
    // core::check_coinbase_maturity; this call site is one of two.
    core::check_coinbase_maturity(tx, current_height, |txid| {
        store.get_coinbase_height(txid).ok().flatten()
    })?;

    let lookup = |txid: &[u8; 32], idx: u32| -> Result<Option<core::TxOutput>, String> {
        if let Some(out) = block_utxos.get(&(*txid, idx)) {
            return Ok(Some(out.clone()));
        }
        store.get_utxo(txid, idx).map_err(|e| e.to_string())
    };

    validate_tx_inputs(tx, &lookup, Some(spent_in_block))
}


/// Standalone tx validation (for mempool / sendrawtransaction).
/// Returns the fee (total_in - total_out).
/// Also checks coinbase maturity (VULN-03).
fn validate_tx_standalone(
    tx:    &core::Transaction,
    store: &Arc<storage::Storage>,
    current_height: u64,
) -> Result<u64, String> {
    // Coinbase maturity check
    if current_height > 0 {
        for (i, inp) in tx.inputs.iter().enumerate() {
            if let Ok(Some(cb_height)) = store.get_coinbase_height(&inp.prev_txid) {
                let depth = current_height.saturating_sub(cb_height);
                if depth < core::COINBASE_MATURITY {
                    return Err(format!(
                        "coinbase maturity: input {} needs {} more confirmations",
                        i, core::COINBASE_MATURITY - depth
                    ));
                }
            }
        }
    }
    let lookup = |txid: &[u8; 32], idx: u32| -> Result<Option<core::TxOutput>, String> {
        store.get_utxo(txid, idx).map_err(|e| e.to_string())
    };

    validate_tx_inputs(tx, &lookup, None)
}
// v0.2.0 PoI
// v0.2.1 reconnect
// v0.2.2 ws+pex
// v0.2.2 ws+pex
// v0.2.3 block-debug
// v0.2.4 height-fix
// v0.2.5 tx-rebroadcast
// v0.2.6 peer-count
// v0.2.7 utxo-reindex
// v0.2.8 dag-reindex
// v0.2.9 topo-sort
// v0.3.0 getpeers
// v0.3.0 getpeers
// v0.3.1 utxo-fix
// v0.3.2 balance-fix
// v0.3.3 recentblocks

// ─────────────────────────────────────────────────────────────────────────────
// Audit H2 regression tests — external-submission structural gate.
//
// The vulnerability: the stratum accept_block_cb handed miner-submitted
// blocks straight to `accept_block`, which checks bits/height/timestamp/tx
// validity but NOT `Block::validate_structure()` (Module-SIS PoW witness,
// merkle binding, coinbase format). A block with no SIS witness therefore
// passed the stratum path while the gossipsub and RPC paths rejected it.
//
// These tests build the callbacks through the same builders `main()` uses,
// so they exercise the real submission closures, not a re-implementation.
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod external_submission_tests {
    use super::*;
    use tempfile::TempDir;

    fn unix_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    struct TestNode {
        _tmp:       TempDir,
        dag:        Arc<RwLock<consensus::GhostDAG>>,
        store:      Arc<storage::Storage>,
        mempool:    Arc<mempool::Mempool>,
        node_state: Arc<RwLock<rpc::NodeState>>,
        shielded:   Arc<RwLock<crate::coherence::ShieldedPool>>,
        otx:        mpsc::Sender<network::NetworkMessage>,
        // Keep the receiver alive so post-accept broadcasts don't error.
        _orx:       mpsc::Receiver<network::NetworkMessage>,
        tip_tx:     broadcast::Sender<tip::TipChanged>,
    }

    impl TestNode {
        fn rpc_cb(&self) -> Arc<rpc::SubmitBlockFn> {
            make_rpc_submit_block_cb(
                self.dag.clone(), self.store.clone(), self.mempool.clone(),
                self.node_state.clone(), self.shielded.clone(),
                self.otx.clone(), self.tip_tx.clone(),
            )
        }
    }

    fn mk_coinbase(height: u64, value: u64) -> core::Transaction {
        core::Transaction {
            version: 1,
            inputs: vec![core::TxInput {
                prev_txid:  [0u8; 32],
                prev_index: u32::MAX,
                script_sig: format!("height:{}", height).into_bytes(),
                sequence:   u32::MAX,
            }],
            outputs: vec![core::TxOutput {
                value,
                script_pubkey: vec![0xAB; 20],
            }],
            locktime: 0,
        }
    }

    /// Fixture genesis. Deliberately NOT structurally valid (no SIS witness) —
    /// `accept_block` never re-validates ancestors, it only needs the genesis
    /// present in the DAG (for height/parent checks) and in storage (for the
    /// height-0 timestamp that seeds ASERT). The timestamp is "now" so ASERT
    /// eases difficulty for block 1, keeping the mined-block test fast.
    fn mk_genesis(ts: u64) -> core::Block {
        core::Block {
            header: core::BlockHeader {
                version:     1,
                parents:     vec![],
                merkle_root: core::MerkleRoot::ZERO,
                timestamp:   ts,
                bits:        core::GENESIS_BITS,
                nonce:       0,
            },
            transactions: vec![mk_coinbase(0, 0)],
            blue_score: 0,
            height: 0,
            shielded_transactions: Vec::new(),
        }
    }

    fn node_with_genesis(genesis: &core::Block) -> TestNode {
        let tmp   = TempDir::new().expect("tempdir");
        let store = Arc::new(storage::Storage::open(&tmp.path().join("db")).expect("storage"));
        let dag   = Arc::new(RwLock::new(consensus::GhostDAG::with_default_k()));

        let gh = genesis.block_hash();
        store.put_block(genesis).expect("store genesis");
        dag.write().add_genesis(gh, genesis.header.timestamp);

        let (otx, orx) = mpsc::channel::<network::NetworkMessage>(64);
        let (tip_tx, _) = broadcast::channel::<tip::TipChanged>(8);

        TestNode {
            _tmp: tmp,
            dag,
            store,
            mempool:    Arc::new(mempool::Mempool::new()),
            node_state: Arc::new(RwLock::new(rpc::NodeState::default())),
            shielded:   Arc::new(RwLock::new(crate::coherence::ShieldedPool::new())),
            otx,
            _orx: orx,
            tip_tx,
        }
    }

    /// Build a height-1 child of the fixture genesis that satisfies every
    /// check `accept_block` performs (bits, height, finality, timestamp,
    /// coinbase value). With `mine == false` the block carries NO Module-SIS
    /// witness and a stale merkle root, so it fails `validate_structure()`
    /// while still being acceptable to `accept_block` — exactly the H2 gap.
    /// With `mine == true` a real SIS witness is mined (k = 4 regime below
    /// the SF-1 activation height) and the merkle root is binding.
    fn mk_child(node: &TestNode, genesis: &core::Block, mine: bool) -> core::Block {
        let gh = genesis.block_hash();
        let parent_ts = node.store.get_timestamp_at_height(0)
            .expect("ts read").expect("genesis ts present");
        let bits = pow::expected_bits(parent_ts, 1).expect("expected bits");
        let subsidy = core::tokenomics::block_subsidy_sat(1);

        let all_txs = vec![mk_coinbase(1, subsidy)];
        let merkle  = core::Transaction::merkle_root(&all_txs);

        let mut block = core::Block {
            header: core::BlockHeader {
                version:     1,
                parents:     vec![gh],
                merkle_root: if mine { merkle } else { core::MerkleRoot::ZERO },
                timestamp:   parent_ts + 30,
                bits,
                nonce:       0,
            },
            transactions: all_txs,
            blue_score: 1,
            height: 1,
            shielded_transactions: Vec::new(),
                };

        if mine {
            let preimage = block.header.pow_preimage();
            let nonce = pow::mine_parallel(&preimage, bits, 0, 1 << 16, 4, None)
                .expect("GnB-SMH solve within attempt budget");
            block.header.nonce = nonce;
            assert!(
                block.validate_structure().is_ok(),
                "mined fixture block must be structurally valid",
            );
        } else {
            assert!(
                block.validate_structure().is_err(),
                "fixture block must fail validate_structure",
            );
        }
        block
    }

    /// H2 regression: a block with a non-binding merkle root must be
    /// rejected by the RPC submitblock callback before it reaches the
    /// DAG/storage, by the structural gate.
    #[tokio::test(flavor = "multi_thread")]
    async fn rpc_submit_rejects_structure_invalid_block() {
        let genesis = mk_genesis(unix_now());
        let node = node_with_genesis(&genesis);
        let bad = mk_child(&node, &genesis, false);
        let err = (node.rpc_cb())(bad).unwrap_err();
        assert!(err.contains("structural validation"), "rpc: {}", err);
        assert_eq!(node.dag.read().block_count(), 1, "DAG must contain only genesis");
    }

    /// Positive control: a genuinely mined block (GnB-SMH proof, binding
    /// merkle) is accepted by the RPC submitblock callback.
    #[tokio::test(flavor = "multi_thread")]
    async fn rpc_submit_accepts_valid_block() {
        let genesis = mk_genesis(unix_now());
        let node = node_with_genesis(&genesis);
        let good = mk_child(&node, &genesis, true);
        let res = (node.rpc_cb())(good);
        assert!(res.is_ok(), "rpc submitblock must accept a valid block: {:?}", res);
        assert_eq!(node.dag.read().block_count(), 2);
    }

    // ── LEG1-selfmine-accept regressions (Round-2 audit) ────────────────────
    //
    // Self-mined blocks must go through `commit_self_mined_block` →
    // `accept_block`, the SAME pipeline as network/RPC/stratum ingress. The
    // pre-fix miner loop committed its own block inline (put_block +
    // apply_block_utxo_mutations + dag.add_block) with NO consensus
    // validation, so a block violating an invariant the mempool cannot catch
    // (e.g. a coinbase over-claim) was persisted locally and only rejected by
    // peers — forking the producer off its own network. These tests FAIL if
    // that inline commit path is ever restored.

    /// Like `mk_child(mine = true)` but with an arbitrary coinbase value:
    /// real SIS witness + binding merkle root, so `validate_structure()`
    /// passes and only `accept_block`'s consensus checks can stop it.
    fn mk_mined_child_with_coinbase(
        node: &TestNode,
        genesis: &core::Block,
        cb_value: u64,
    ) -> core::Block {
        let gh = genesis.block_hash();
        let parent_ts = node.store.get_timestamp_at_height(0)
            .expect("ts read").expect("genesis ts present");
        let bits = pow::expected_bits(parent_ts, 1).expect("expected bits");
        let all_txs = vec![mk_coinbase(1, cb_value)];
        let merkle  = core::Transaction::merkle_root(&all_txs);
        let mut block = core::Block {
            header: core::BlockHeader {
                version:     1,
                parents:     vec![gh],
                merkle_root: merkle,
                timestamp:   parent_ts + 30,
                bits,
                nonce:       0,
            },
            transactions: all_txs,
            blue_score: 1,
            height: 1,
            shielded_transactions: Vec::new(),
        };
        let preimage = block.header.pow_preimage();
        let nonce = pow::mine_parallel(&preimage, bits, 0, 1 << 16, 4, None)
                .expect("GnB-SMH solve within attempt budget");
            block.header.nonce = nonce;
        assert!(
            block.validate_structure().is_ok(),
            "fixture must be structurally valid — the rejection under test \
             is consensus-level, which only accept_block performs",
        );
        block
    }

    fn commit_mined(node: &TestNode, block: &core::Block) -> Result<[u8; 32], String> {
        commit_self_mined_block(
            block,
            &node.dag, &node.store, &node.mempool, &node.node_state,
            Some(&node.tip_tx), &node.shielded,
        )
    }

    /// C-R3-1 core regression: a self-mined block violating a
    /// mempool-missable invariant (coinbase over-claims subsidy by 1 sat —
    /// the coinbase never passes through the mempool) must be rejected by
    /// the PRODUCER ITSELF and leave no trace in DAG or storage. On the
    /// pre-fix inline path this block was committed unconditionally.
    #[tokio::test(flavor = "multi_thread")]
    async fn self_mined_block_violating_consensus_is_rejected_by_producer() {
        let genesis = mk_genesis(unix_now());
        let node    = node_with_genesis(&genesis);
        let subsidy = core::tokenomics::block_subsidy_sat(1);
        let bad     = mk_mined_child_with_coinbase(&node, &genesis, subsidy + 1);
        let hash    = bad.block_hash();

        let res = commit_mined(&node, &bad);
        assert!(
            res.is_err(),
            "LEG1: producer must reject its own consensus-invalid block, \
             got acceptance: {:?}", res,
        );
        let msg = res.unwrap_err();
        assert!(
            msg.contains("coinbase"),
            "rejection must come from the coinbase-value consensus check, got: {}", msg,
        );
        // The pre-fix path persisted the block BEFORE any validation — the
        // whole point of the fix is that a rejected block leaves no trace.
        assert!(
            node.store.get_block(&hash).expect("store read").is_none(),
            "rejected self-mined block must NOT be persisted",
        );
        assert!(
            node.dag.read().get_block_data(&hash).is_none(),
            "rejected self-mined block must NOT enter the DAG",
        );
        assert_eq!(node.dag.read().block_count(), 1, "DAG must contain only genesis");
    }

    /// Structural gate parity: the self-miner gets no structural bypass
    /// either (same H2 gate as stratum/RPC submissions).
    #[tokio::test(flavor = "multi_thread")]
    async fn self_mined_structure_invalid_block_is_rejected_by_producer() {
        let genesis = mk_genesis(unix_now());
        let node    = node_with_genesis(&genesis);
        let bad     = mk_child(&node, &genesis, false);
        let hash    = bad.block_hash();

        let msg = commit_mined(&node, &bad)
            .expect_err("structure-invalid self-mined block must be rejected");
        assert!(
            msg.contains("structural validation"),
            "rejection must come from the structural gate, got: {}", msg,
        );
        assert!(node.store.get_block(&hash).expect("store read").is_none());
        assert_eq!(node.dag.read().block_count(), 1);
    }

    /// Positive control: a genuinely valid self-mined block flows through
    /// the shared pipeline, is committed, advances the selected tip and
    /// refreshes the RPC-visible state — the fix does not over-reject.
    #[tokio::test(flavor = "multi_thread")]
    async fn self_mined_valid_block_is_committed_through_accept_block() {
        let genesis = mk_genesis(unix_now());
        let node    = node_with_genesis(&genesis);
        let good    = mk_child(&node, &genesis, true);
        let hash    = good.block_hash();

        let res = commit_mined(&node, &good);
        assert_eq!(
            res.expect("valid self-mined block must be accepted"), hash,
        );
        assert_eq!(node.dag.read().block_count(), 2);
        assert_eq!(node.dag.read().selected_tip(), Some(hash));
        assert!(
            node.store.get_block(&hash).expect("store read").is_some(),
            "accepted self-mined block must be persisted",
        );
        assert_eq!(node.node_state.read().block_count, 2, "RPC state must be refreshed");
    }

    // ── CONSENSUS-HALT regression (DAG-vs-UTXO ordering) ────────────────────
    //
    // Drive the REAL `accept_block` pipeline (add_block → disposition →
    // execute_reorg) — NOT a synthetic ReorgPlan — with an attacker fork
    // whose accumulated blue_work beats the live chain but whose reorg depth
    // exceeds reorg::MAX_REORG_DEPTH. On the unfixed baseline the flipping
    // fork block is inserted + persisted into the DAG BEFORE the depth cap
    // runs; the refusal then leaves selected_tip() pinned to the fork
    // forever, freezing the real chain (durable halt).

    /// Submit a block through the real `accept_block` pipeline. This is the
    /// exact function the stratum/RPC callbacks delegate to; those wrappers
    /// only add the H2 `validate_structure()` pre-gate, which is orthogonal
    /// to the consensus ordering under test and would force mining a real
    /// SIS witness for every fixture block.
    fn accept(node: &TestNode, block: &core::Block) -> Result<[u8; 32], String> {
        accept_block(
            block, block.block_hash(), block.height,
            &node.dag, &node.store, &node.mempool, &node.node_state,
            Some(&node.tip_tx), &node.shielded,
        )
    }

    /// Build an H2-fixture-style (structurally lax) child of `parent` at
    /// `height` that satisfies every check `accept_block` performs (bits,
    /// height, finality, timestamp, coinbase value). The merkle root is
    /// ZERO for these fixtures, so `nonce` is what differentiates
    /// same-position blocks on competing chains (block_hash covers it).
    fn mk_block_at(
        node: &TestNode,
        parent: [u8; 32],
        height: u64,
        ts: u64,
        nonce: u64,
    ) -> core::Block {
        let parent_ts = node.store.get_timestamp_at_height(height - 1)
            .expect("ts read").expect("parent-height timestamp present");
        let bits = pow::expected_bits(parent_ts, height).expect("expected bits");
        let subsidy = core::tokenomics::block_subsidy_sat(height);
        core::Block {
            header: core::BlockHeader {
                version:     1,
                parents:     vec![parent],
                merkle_root: core::MerkleRoot::ZERO,
                timestamp:   ts,
                bits,
                nonce,
            },
            transactions: vec![mk_coinbase(height, subsidy)],
            blue_score: height,
            height,
            shielded_transactions: Vec::new(),
        }
    }

    /// Acceptance regression for the DAG-vs-UTXO ordering halt.
    ///
    /// FAILS on baseline cad723c (tip poisoned by the refused fork; real
    /// chain frozen as ForkLoser), PASSES with the fix (GhostDAG undo +
    /// deferred CF_DAG persist).
    #[tokio::test(flavor = "multi_thread")]
    async fn refused_deep_reorg_must_not_poison_dag_selected_tip() {
        let d = reorg::MAX_REORG_DEPTH;
        assert!(
            d <= 16,
            "this regression builds chains of length MAX_REORG_DEPTH+2 through \
             the real accept path; keep the cfg(test) cap small (got {})", d,
        );

        let g_ts    = unix_now();
        let genesis = mk_genesis(g_ts);
        let node    = node_with_genesis(&genesis);
        let gh      = genesis.block_hash();

        // (a) Real chain R: genesis → r1 … r_{D+1}, all through accept_block.
        let mut parent = gh;
        for i in 1..=(d + 1) {
            let b = mk_block_at(&node, parent, i, g_ts + 30 * i, i);
            accept(&node, &b).expect("real-chain block must be accepted");
            parent = b.block_hash();
        }
        let real_tip = parent;
        assert_eq!(
            node.dag.read().selected_tip(), Some(real_tip),
            "sanity: R's head is the selected tip before the attack",
        );

        // (b) Attacker fork F branching at genesis: f1 … f_{D+2}, same
        // per-height timestamps as R (so expected bits — hence per-block
        // work — match per height) but distinct nonces (distinct hashes).
        // The fork block at height D+1 TIES R's tip on blue_work; grind its
        // nonce so its hash LOSES the deterministic tie-break (blue_work,
        // then blue_score, then lexicographic hash — larger wins) and stays
        // a fork-loser. The flip then happens deterministically at f_{D+2},
        // which strictly out-weighs R and forces to_rollback.len() == D+1 > D.
        let mut fparent = gh;
        let mut flip_res: Result<[u8; 32], String> = Err("unreached".into());
        for i in 1..=(d + 2) {
            let mut nonce = 1_000_000 + i;
            let mut fb = mk_block_at(&node, fparent, i, g_ts + 30 * i, nonce);
            if i == d + 1 {
                while fb.block_hash() >= real_tip {
                    nonce += 1;
                    fb = mk_block_at(&node, fparent, i, g_ts + 30 * i, nonce);
                }
            }
            let res = accept(&node, &fb);
            if i <= d + 1 {
                assert!(
                    res.is_ok(),
                    "non-flipping fork block f{} must be accepted as a \
                     fork-loser, got: {:?}", i, res,
                );
                assert_eq!(
                    node.dag.read().selected_tip(), Some(real_tip),
                    "fork-loser f{} must not move the selected tip", i,
                );
            }
            fparent = fb.block_hash();
            flip_res = res;
        }

        // (1) The flipping fork block is REFUSED by the reorg depth cap.
        let err = flip_res.expect_err(
            "over-deep flipping fork block must be rejected by accept_block",
        );
        assert!(
            err.contains(reorg::ERR_REORG_DEPTH),
            "rejection must be the depth-cap refusal, got: {}", err,
        );

        // (2) HALT GUARD: the refusal must leave the DAG selected tip on the
        // real chain. Baseline fails HERE: add_block already adopted (and
        // persisted) the fork tip before execute_reorg refused.
        assert_eq!(
            node.dag.read().selected_tip(), Some(real_tip),
            "refused deep reorg must NOT poison the DAG selected tip",
        );

        // (3) LIVENESS GUARD: a further legitimate extension of the real
        // chain is still accepted AND applied. Baseline fails here too: with
        // the tip pinned to the poison fork, R_next is misclassified and the
        // applied chain state never advances.
        let r_next = mk_block_at(
            &node, real_tip, d + 2, g_ts + 30 * (d + 2), 424_242,
        );
        let r_next_hash = r_next.block_hash();
        let res = accept(&node, &r_next);
        assert!(
            res.is_ok(),
            "legitimate extension of the real chain must still be accepted \
             after the refused fork, got: {:?}", res,
        );
        assert_eq!(
            node.dag.read().selected_tip(), Some(r_next_hash),
            "real chain must re-take / keep the selected tip",
        );
        let tip_meta = node.store.get_meta("tip_hash")
            .expect("meta read").expect("tip_hash meta present");
        assert_eq!(
            tip_meta.as_slice(), &r_next_hash[..],
            "applied chain state (tip_hash meta / UTXO apply) must advance \
             with the real chain",
        );
    }

    /// Root-cause regression for the red/side-block body-retention starvation
    /// that froze tip-selection (selected tip stuck while blue_score climbed)
    /// and stalled IBD ("body unavailable — an archival peer is needed").
    ///
    /// A block at or below the finalized height that is a *fork-loser* must be
    /// ACCEPTED and RETAINED (body in CF_BLOCKS + entry in the DAG) so it can
    /// serve as a GhostDAG mergeset member — it must NOT be rejected by the
    /// finality checkpoint, and it must NOT move the selected tip. Pre-fix,
    /// accept_block rejected it outright ("finality: ... at or below finalized
    /// height"), so its body was never stored and no node could serve it.
    #[tokio::test(flavor = "multi_thread")]
    async fn below_finality_fork_loser_is_retained_not_rejected() {
        let g_ts    = unix_now();
        let genesis = mk_genesis(g_ts);
        let node    = node_with_genesis(&genesis);
        let gh      = genesis.block_hash();

        // Real chain: genesis → r1 … r5, all through the real accept path.
        let mut parent = gh;
        let mut r1 = gh;
        for i in 1..=5u64 {
            let b = mk_block_at(&node, parent, i, g_ts + 30 * i, i);
            accept(&node, &b).expect("real-chain block must be accepted");
            if i == 1 { r1 = b.block_hash(); }
            parent = b.block_hash();
        }
        let real_tip = parent;

        // Simulate a finalized checkpoint at height 3 (as a live node sets once
        // its tip is CHECKPOINT_DEPTH ahead).
        node.store.put_meta("finalized_height", &3u64.to_le_bytes())
            .expect("set finalized_height");

        // A side block at height 2 (<= finalized 3): sibling of r2 (same parent
        // r1, distinct nonce → distinct hash). It is a fork-loser — the real
        // chain to r5 has far more blue work.
        let fork = mk_block_at(&node, r1, 2, g_ts + 30 * 2, 987_654);
        let fork_hash = fork.block_hash();
        assert_ne!(fork_hash, real_tip);

        let res = accept(&node, &fork);
        assert!(
            res.is_ok(),
            "a below-finality FORK-LOSER must be accepted (retained as a \
             mergeset member), not rejected by finality; got: {:?}", res,
        );

        // Retained: body servable + present in the DAG.
        assert!(
            node.store.get_block(&fork_hash).expect("body read").is_some(),
            "below-finality fork-loser body must be RETAINED in CF_BLOCKS \
             (else peers answer 'body unavailable')",
        );
        assert!(
            node.dag.read().get_block_data(&fork_hash).is_some(),
            "below-finality fork-loser must be present in the DAG",
        );

        // Inert: it must NOT move the selected tip (finality invariant intact).
        assert_eq!(
            node.dag.read().selected_tip(), Some(real_tip),
            "a below-finality fork-loser must NOT become the selected tip",
        );

        // And re-submitting it is a cheap dedup no-op rejection, not a re-run.
        let again = accept(&node, &fork);
        assert!(
            again.is_err() && again.unwrap_err().contains("already in DAG"),
            "a block already in the DAG must be rejected by the early dedup",
        );
    }

    /// GnB derives expected difficulty from the block's parents' DAG entries
    /// (latest parent timestamp), never from pruned body history, so the
    /// check is complete at every height and enforced below finality too.
    /// (Bloch skipped it below finality because its re-derivation read pruned
    /// history; that hole let below-finality blocks carry arbitrary bits.)
    #[tokio::test(flavor = "multi_thread")]
    async fn difficulty_is_checked_below_and_above_finality() {
        let g_ts    = unix_now();
        let genesis = mk_genesis(g_ts);
        let node    = node_with_genesis(&genesis);
        let gh      = genesis.block_hash();

        // Real chain: genesis → r1 … r5.
        let mut parent = gh;
        let mut r1 = gh;
        let mut r3 = gh;
        for i in 1..=5u64 {
            let b = mk_block_at(&node, parent, i, g_ts + 30 * i, i);
            accept(&node, &b).expect("real-chain block must be accepted");
            if i == 1 { r1 = b.block_hash(); }
            if i == 3 { r3 = b.block_hash(); }
            parent = b.block_hash();
        }
        let real_tip = parent;

        // Finalize at height 3.
        node.store.put_meta("finalized_height", &3u64.to_le_bytes())
            .expect("set finalized_height");

        // (1) BELOW finality (h=2 ≤ 3): fork-loser sibling of r2 with the WRONG
        // difficulty bits must be rejected.
        let mut below = mk_block_at(&node, r1, 2, g_ts + 30 * 2, 111_222);
        let good_bits = below.header.bits;
        below.header.bits = good_bits ^ 0x0000_0001; // != expected
        assert_ne!(below.header.bits, good_bits);
        let below_hash = below.block_hash();
        let res = accept(&node, &below);
        assert!(
            res.as_ref().is_err_and(|e| e.contains("invalid difficulty")),
            "below-finality block with wrong bits must be rejected; got: {:?}", res,
        );
        assert!(node.dag.read().get_block_data(&below_hash).is_none());
        assert_eq!(node.dag.read().selected_tip(), Some(real_tip));

        // With the right bits the same below-finality sibling is retained as
        // an inert fork-loser and does not move the selected tip.
        below.header.bits = good_bits;
        assert!(accept(&node, &below).is_ok());
        assert_eq!(node.dag.read().selected_tip(), Some(real_tip));

        // (2) ABOVE finality (h=4 > 3): sibling of r4 with WRONG bits.
        let mut above = mk_block_at(&node, r3, 4, g_ts + 30 * 4, 333_444);
        above.header.bits ^= 0x0000_0001; // != expected
        let res2 = accept(&node, &above);
        assert!(
            res2.is_err() && res2.as_ref().unwrap_err().contains("invalid difficulty"),
            "above-finality block with wrong bits must STILL be rejected for \
             difficulty; got: {:?}", res2,
        );
    }
}

#[cfg(test)]
mod intra_tx_dup_tests {
    use super::*;
    use tempfile::TempDir;

    fn mk_store() -> (TempDir, Arc<storage::Storage>) {
        let tmp = TempDir::new().expect("tempdir");
        let store = Arc::new(storage::Storage::open(&tmp.path().join("db")).expect("storage"));
        (tmp, store)
    }

    /// A tx spending the SAME confirmed 100_000-sat outpoint `n` times, every
    /// input carrying a VALID hybrid signature over its own sighash — so
    /// without the duplicate-outpoint check nothing else rejects it and the
    /// fee comes out inflated by the duplicated value.
    fn dup_input_tx(store: &Arc<storage::Storage>, n: usize, out_value: u64)
        -> core::Transaction
    {
        use sha3::{Digest as _, Sha3_256};
        let (pk, sk) = crypto::generate_keypair();
        let pk_hash = Sha3_256::digest(&pk)[..20].to_vec();
        let prev_txid = [0x42u8; 32];
        store.put_utxo(&prev_txid, 0,
            &core::TxOutput { value: 100_000, script_pubkey: pk_hash })
            .expect("put_utxo");

        let mut tx = core::Transaction {
            version: 1,
            inputs: (0..n).map(|_| core::TxInput {
                prev_txid, prev_index: 0, script_sig: vec![], sequence: u32::MAX,
            }).collect(),
            outputs: vec![core::TxOutput { value: out_value, script_pubkey: vec![7u8; 20] }],
            locktime: 0,
        };
        for i in 0..n {
            let sighash = tx.sighash(i, core::node_chain_id());
            let sig = crypto::sign(&sk, &sighash).expect("sign");
            tx.inputs[i].script_sig = core::Transaction::build_script_sig(&sig, &pk);
        }
        tx
    }

    /// Gossip-relay admission (`validate_tx_standalone`, spent_set = None):
    /// a 2-duplicate-input tx spending a 100k outpoint but emitting 150k must
    /// be refused. Without the fix this was ADMITTED with fee = 50_000.
    #[test]
    fn gossip_path_refuses_intra_tx_duplicate_outpoint() {
        let (_tmp, store) = mk_store();
        let tx = dup_input_tx(&store, 2, 150_000);
        let err = validate_tx_standalone(&tx, &store, 0)
            .expect_err("intra-tx duplicate outpoint must be refused");
        assert!(err.contains("double-spend"), "got: {err}");
    }

    /// The exact conditional the audit flagged, hit directly: the shared core
    /// with `spent_set = None` must still catch an N=3 duplication (value
    /// would otherwise triple: 300k in, 290k out, fee 10k).
    #[test]
    fn validate_tx_inputs_refuses_duplicates_without_spent_set() {
        let (_tmp, store) = mk_store();
        let tx = dup_input_tx(&store, 3, 290_000);
        let lookup = |txid: &[u8; 32], idx: u32| -> Result<Option<core::TxOutput>, String> {
            store.get_utxo(txid, idx).map_err(|e| e.to_string())
        };
        let err = validate_tx_inputs(&tx, &lookup, None)
            .expect_err("intra-tx duplicate outpoint must be refused");
        assert!(err.contains("double-spend"), "got: {err}");
    }

    /// Control: the SAME signed shape with a single input and honest amounts
    /// is still admitted with the right fee — the fix rejects duplication,
    /// not the legacy path itself.
    #[test]
    fn single_input_control_still_admitted() {
        let (_tmp, store) = mk_store();
        let tx = dup_input_tx(&store, 1, 70_000);
        let fee = validate_tx_standalone(&tx, &store, 0)
            .expect("valid single-input spend must be admitted");
        assert_eq!(fee, 30_000);
    }

    /// Consensus minimum fee: a well-formed, correctly signed spend paying
    /// less than `tokenomics::min_tx_fee_sat(size)` is refused.
    #[test]
    fn below_minimum_fee_is_refused() {
        let (_tmp, store) = mk_store();
        let tx = dup_input_tx(&store, 1, 90_000); // fee 10_000 < ~17_000 minimum
        let err = validate_tx_standalone(&tx, &store, 0).unwrap_err();
        assert!(err.contains("below consensus minimum"), "{err}");
    }

    /// Legacy N-7 regression: the MINER's OWN block-template fee estimate
    /// (`miner_template_total_fees`) must not inflate a duplicate-outpoint
    /// transaction's fee contribution. A 2-duplicate-input tx spending a
    /// 100k outpoint and emitting 150k has NO legitimate fee at all (such a
    /// tx is rejected outright by real admission) — but before the fix,
    /// summing every input's resolved value unconditionally would have
    /// counted the 100k outpoint TWICE (200k in, 150k out => 50k "fee").
    /// Reverting the fix (dropping the insert-as-check) makes this test
    /// fail (asserting 0 would fail; it would instead read 50_000).
    #[test]
    fn miner_template_does_not_inflate_duplicate_outpoint_fee() {
        let (_tmp, store) = mk_store();
        let dup_tx = dup_input_tx(&store, 2, 150_000);
        let total = miner_template_total_fees(std::slice::from_ref(&dup_tx), &store);
        assert_eq!(total, 0, "a duplicate-outpoint tx must contribute zero fee to the template");
    }

    /// Control: an honest, non-duplicated single-input tx still contributes
    /// its real fee to the template estimate, and a mixed set (one honest,
    /// one duplicate-outpoint) counts only the honest one.
    #[test]
    fn miner_template_counts_honest_fees_normally() {
        let (_tmp, store) = mk_store();
        let honest_tx = dup_input_tx(&store, 1, 90_000);
        assert_eq!(
            miner_template_total_fees(std::slice::from_ref(&honest_tx), &store),
            10_000,
        );

        let (_tmp2, store2) = mk_store();
        let honest_tx2 = dup_input_tx(&store2, 1, 90_000);
        let dup_tx2 = dup_input_tx(&store2, 2, 150_000);
        assert_eq!(
            miner_template_total_fees(&[honest_tx2, dup_tx2], &store2),
            10_000,
            "the mixed batch's total must equal the honest tx's fee alone",
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Legacy C-2 — a transaction may spend an EARLIER same-block transaction's
// output, but never a LATER one. `reorg::apply_block_utxo_mutations` applies
// each transaction's outputs THEN its inputs, walking `block.transactions` IN
// ORDER, so a later transaction's output does not exist in storage yet when
// an earlier transaction is applied. Before the fix,
// `validate_tx_in_block_with_maturity` (and the `euvm`-feature
// `validate_tx_in_block_euvm`) built their in-block prevout map from ALL of
// `block.transactions` unconditionally, so an out-of-order spend validated —
// and would have minted supply on acceptance (the spent value credited to
// the earlier tx's fee accounting was never actually removed from the UTXO
// set, since the later tx's `put_utxo` for that same output ran AFTER the
// earlier tx's no-op `delete_utxo` on a not-yet-existent key).
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod out_of_order_spend_tests {
    use super::*;
    use tempfile::TempDir;

    fn mk_store() -> (TempDir, Arc<storage::Storage>) {
        let tmp = TempDir::new().expect("tempdir");
        let store = Arc::new(storage::Storage::open(&tmp.path().join("db")).expect("storage"));
        (tmp, store)
    }

    fn coinbase() -> core::Transaction {
        core::Transaction {
            version: 1,
            inputs: vec![core::TxInput {
                prev_txid: [0u8; 32], prev_index: u32::MAX,
                script_sig: vec![], sequence: u32::MAX,
            }],
            outputs: vec![core::TxOutput { value: 1_000, script_pubkey: vec![0xABu8; 20] }],
            locktime: 0,
        }
    }

    /// Regression: block index 1 ("early") claims to spend block index 2's
    /// ("late") not-yet-applied output. Reverting the Legacy C-2 fix
    /// (restoring the unconditional `block.transactions.iter()` prevout map)
    /// makes this test fail — the spend would validate (and return a fee)
    /// instead of being rejected.
    #[test]
    fn cannot_spend_a_later_transactions_output_in_the_same_block() {
        use sha3::{Digest as _, Sha3_256};
        let (_tmp, store) = mk_store();
        let (pk, sk) = crypto::generate_keypair();
        let pk_hash = Sha3_256::digest(&pk)[..20].to_vec();

        // tx_late (block index 2): an ordinary spend of an already-confirmed
        // UTXO, producing a fresh output paying `pk_hash`. Its own inputs are
        // irrelevant to this test — only the attempted spend of ITS output
        // (by tx_early, below) is under test.
        let late_prev_txid = [0x77u8; 32];
        store.put_utxo(&late_prev_txid, 0,
            &core::TxOutput { value: 100_000, script_pubkey: vec![9u8; 20] })
            .expect("put_utxo");
        let tx_late = core::Transaction {
            version: 1,
            inputs: vec![core::TxInput {
                prev_txid: late_prev_txid, prev_index: 0,
                script_sig: vec![], sequence: u32::MAX,
            }],
            outputs: vec![core::TxOutput { value: 90_000, script_pubkey: pk_hash }],
            locktime: 0,
        };
        let late_txid = tx_late.txid();

        // tx_early (block index 1): a VALIDLY-SIGNED spend of tx_late's
        // output 0 — which does not exist anywhere (not in the block-applied
        // prefix, not in storage) at the point tx_early is validated/applied.
        let mut tx_early = core::Transaction {
            version: 1,
            inputs: vec![core::TxInput {
                prev_txid: late_txid, prev_index: 0,
                script_sig: vec![], sequence: u32::MAX,
            }],
            outputs: vec![core::TxOutput { value: 80_000, script_pubkey: vec![1u8; 20] }],
            locktime: 0,
        };
        let sighash = tx_early.sighash(0, core::node_chain_id());
        let sig = crypto::sign(&sk, &sighash).expect("sign");
        tx_early.inputs[0].script_sig = core::Transaction::build_script_sig(&sig, &pk);

        let block = core::Block {
            header: core::BlockHeader {
                version: 1, parents: vec![], merkle_root: core::MerkleRoot::ZERO,
                timestamp: 0, bits: core::GENESIS_BITS, nonce: 0,
            },
            transactions: vec![coinbase(), tx_early, tx_late],
            blue_score: 0, height: 1,
            shielded_transactions: Vec::new(),
        };

        let mut spent = HashSet::new();
        let err = validate_tx_in_block_with_maturity(
            &block, &block.transactions[1], &store, &mut spent, 0,
        ).expect_err("a transaction must never validate against a LATER transaction's output");
        assert!(err.contains("not found"), "expected a prevout-not-found error, got: {err}");
    }

    /// Control: the SAME shape, but tx_early spends tx_late's output when
    /// tx_late sits EARLIER in the block (index 1, before tx_early at index
    /// 2) — ordinary, legitimate same-block chaining, which must still
    /// validate (the fix must not over-reject legal same-block spends).
    #[test]
    fn can_spend_an_earlier_transactions_output_in_the_same_block() {
        use sha3::{Digest as _, Sha3_256};
        let (_tmp, store) = mk_store();
        let (pk, sk) = crypto::generate_keypair();
        let pk_hash = Sha3_256::digest(&pk)[..20].to_vec();

        let early_prev_txid = [0x88u8; 32];
        store.put_utxo(&early_prev_txid, 0,
            &core::TxOutput { value: 100_000, script_pubkey: vec![9u8; 20] })
            .expect("put_utxo");
        // This transaction now sits EARLIER in the block (index 1).
        let tx_funding = core::Transaction {
            version: 1,
            inputs: vec![core::TxInput {
                prev_txid: early_prev_txid, prev_index: 0,
                script_sig: vec![], sequence: u32::MAX,
            }],
            outputs: vec![core::TxOutput { value: 90_000, script_pubkey: pk_hash }],
            locktime: 0,
        };
        let funding_txid = tx_funding.txid();

        // This transaction sits LATER (index 2) and spends the funding tx's
        // output — a legitimate same-block chained spend.
        let mut tx_spend = core::Transaction {
            version: 1,
            inputs: vec![core::TxInput {
                prev_txid: funding_txid, prev_index: 0,
                script_sig: vec![], sequence: u32::MAX,
            }],
            outputs: vec![core::TxOutput { value: 60_000, script_pubkey: vec![1u8; 20] }],
            locktime: 0,
        };
        let sighash = tx_spend.sighash(0, core::node_chain_id());
        let sig = crypto::sign(&sk, &sighash).expect("sign");
        tx_spend.inputs[0].script_sig = core::Transaction::build_script_sig(&sig, &pk);

        let block = core::Block {
            header: core::BlockHeader {
                version: 1, parents: vec![], merkle_root: core::MerkleRoot::ZERO,
                timestamp: 0, bits: core::GENESIS_BITS, nonce: 0,
            },
            transactions: vec![coinbase(), tx_funding, tx_spend],
            blue_score: 0, height: 1,
            shielded_transactions: Vec::new(),
        };

        let mut spent = HashSet::new();
        let fee = validate_tx_in_block_with_maturity(
            &block, &block.transactions[2], &store, &mut spent, 0,
        ).expect("a transaction MAY spend an earlier same-block transaction's output");
        assert_eq!(fee, 30_000);
    }
}
