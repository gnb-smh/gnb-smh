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
mod ingress;      // audit fixes: block-ingress / orphan / IBD-latch policy
mod accept;       // Block acceptance pipeline (accept/connect split, DAG-1)
mod template;     // Block templates for the miner + getblocktemplate (MEM-2, DAG-2)

// The acceptance pipeline lives in `accept.rs` (shared with the library so
// integration tests drive the real path); same names and signatures as the
// functions that used to be defined in this file.
#[allow(unused_imports)]
use accept::{
    accept_block, validate_tx_standalone, validate_tx_inputs, miner_template_total_fees,
    validate_tx_in_block, validate_tx_in_block_with_maturity, ARCHIVE_MODE,
};

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
///
/// CRY-7: the address checksum does not cover the gnb1q/gnb1t prefix, so the
/// network is compared explicitly against the node's chain (set from
/// `--testnet` before any caller runs): a testnet address on a mainnet node
/// (or the reverse) is refused instead of silently paying the same hash.
fn address_to_script_pubkey(addr: &str) -> Result<Vec<u8>, address::AddressError> {
    let network = match core::node_chain_id() {
        core::ChainId::Testnet => address::Network::Testnet,
        core::ChainId::Mainnet => address::Network::Mainnet,
    };
    Ok(address::Address::parse_for_network(addr, network)?.hash().to_vec())
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

    /// CRY-7 regression: an address of the other network (valid checksum,
    /// same 20-byte hash) is rejected. Unit tests run with the default
    /// (mainnet) node chain id.
    #[test]
    fn address_of_the_wrong_network_is_rejected() {
        assert_eq!(core::node_chain_id(), core::ChainId::Mainnet);
        let testnet = address::Address::from_hash([7u8; 20], address::Network::Testnet).to_string();
        assert!(matches!(
            address_to_script_pubkey(&testnet),
            Err(address::AddressError::WrongNetwork { .. })
        ));
        assert_eq!(address_to_script_pubkey(&sample_address()).unwrap(), vec![7u8; 20]);
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
            // NET-16: an operator who names a key file wants authentication.
            // A missing, unreadable, empty or over-permissive file is a fatal
            // configuration error (it used to fall back to NO key, i.e. auth
            // silently disabled).
            match rpc::auth::check_key_file_permissions(std::path::Path::new(path)) {
                Ok(None) => {}
                Ok(Some(warning)) => eprintln!("⚠  {warning}"),
                Err(refusal) => {
                    eprintln!("❌ {refusal}");
                    std::process::exit(2);
                }
            }
            match std::fs::read_to_string(path) {
                Ok(contents) => {
                    let k = contents.lines().next().unwrap_or("").trim().to_string();
                    if k.is_empty() {
                        eprintln!("❌ --rpc-api-key-file {:?} is empty", path);
                        std::process::exit(2);
                    }
                    Some(k)
                }
                Err(e) => {
                    eprintln!("❌ failed to read --rpc-api-key-file {:?}: {}", path, e);
                    std::process::exit(2);
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

    // (The start-up clamp of `finalized_height` is gone with the finality
    // checkpoint itself — audit DAG-6. The meta key, if present in an old
    // data dir, is no longer read.)

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

    // NET-2: inbound frames carry their origin; gossip block verdicts flow
    // back to the network loop, which relays only Accepted frames.
    let (block_tx, mut block_rx) = mpsc::channel::<network::Inbound>(1000);
    let (vtx2, validation_rx) = mpsc::channel::<network::GossipValidation>(4096);
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

    // DAG-11 residual: detect the footprint of the pre-fix NON-atomic
    // extension commit (UTXO effects without an undo record) that the
    // reconciliation below cannot repair, and rebuild the chain state from the
    // block bodies. A node must not run on an inconsistent UTXO set: it would
    // disqualify valid blocks and leave the network, so without the means to
    // rebuild it refuses to start.
    match accept::check_chain_state(&dag, &store) {
        Ok(faults) if faults.is_empty() => {}
        Ok(faults) => {
            for f in &faults {
                error!("chain-state check: {}", f);
            }
            let Some(snap_path) = cli.carryover_snapshot.as_ref() else {
                error!("the chain state is inconsistent (interrupted pre-fix commit). Restart with \
                        --carryover-snapshot <bloch-g3-carryover.tsv> to rebuild it from the block \
                        bodies. Refusing to start.");
                std::process::exit(1);
            };
            let snap = match std::fs::read(snap_path).map_err(|e| vec![e.to_string()])
                .and_then(|b| core::carryover::verify_and_convert(&b))
            {
                Ok(s) => s,
                Err(failures) => {
                    for f in &failures { error!("carryover for the rebuild: {f}"); }
                    error!("cannot rebuild the chain state without a valid carryover snapshot. Refusing to start.");
                    std::process::exit(1);
                }
            };
            let genesis = core::genesis_block();
            let gh = genesis.block_hash();
            let seed = |st: &storage::Storage, batch: &mut rocksdb::WriteBatch| -> Result<(), String> {
                st.stage_carryover(batch, &snap).map_err(|e| e.to_string())?;
                // Exactly what first boot writes for the genesis block.
                for tx in &genesis.transactions {
                    st.stage_tx_index(batch, &tx.txid(), &gh, 0).map_err(|e| e.to_string())?;
                }
                Ok(())
            };
            match accept::rebuild_chain_state(&dag, &store, &shielded, &seed) {
                Ok(r) => info!("chain state rebuilt: {} block(s) re-applied from genesis", r.connected_blocks),
                Err(e) => {
                    error!("chain-state rebuild failed: {e}. Refusing to start.");
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            error!("chain-state check failed: {e}. Refusing to start.");
            std::process::exit(1);
        }
    }

    // DAG-1 / DAG-11: load the persisted invalid-block set and reconcile any
    // state a pre-fix non-atomic commit left behind, before any block is accepted.
    if let Err(e) = accept::reconcile_on_startup(&dag, &store, &shielded) {
        error!("start-up chain-state reconciliation failed: {}", e);
    }

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
        // A panic that escapes the processing loop is caught, logged, metered
        // (`task_panics_total`) and the loop restarts without dropping the
        // node. POW-2 (audit): the restart back-off is now RESET after a
        // healthy run (`ingress::SupervisorBackoff`); it used to only grow, to
        // its 30 s cap, so one crafted frame every 30 s kept block processing
        // stopped network-wide. (The panic itself — `height + CHECKPOINT_DEPTH`
        // on a wire-supplied `u64::MAX` — is gone: every peer-supplied integer
        // below is compared with saturating arithmetic.)
        //
        // Orphan-pool state lives inside the restartable closure, so a panic
        // rebuilds it empty (peers resend). A clean channel close exits.
        let mut backoff = ingress::SupervisorBackoff::new(
            std::time::Duration::from_millis(100),
            std::time::Duration::from_secs(30),
        );
        loop {
          let run_started = std::time::Instant::now();
          let processor = async {
            // The block-ingress core (`ingress::BlockIngress`, shared with the
            // integration tests): the orphan pool (POW-4: bounded by entries
            // AND bytes, globally and per delivering peer, evicting by ARRIVAL
            // order; first copy of an id wins, POW-8; reverse index parent ->
            // waiting orphans; POW-3 announced work), the missing-parent
            // retry tracker (orphan-deadlock fix: the periodic sweep
            // re-requests lost parents with backoff and prunes hopeless ones),
            // the deep-insertion budget (DAG-7 / POW-3) and the POW-3 anti-DoS
            // work rule. Lives inside the restartable closure: a panic
            // rebuilds it empty (peers resend).
            let mut ingress_core = ingress::BlockIngress::new();
            let mut orphan_sweep = tokio::time::interval(sync::parent_fetch::SWEEP_PERIOD);
            orphan_sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // Never fire immediately on (re)start — tick 0 is now.
            orphan_sweep.reset();
            // NET-6: tip claims only trigger (rate-limited) directed pulls and
            // reciprocal announcements; they never latch IBD.
            let mut claims = ingress::ClaimPolicy::new();
            let ctx = ingress::AcceptCtx {
                dag: &dag2, store: &store2, mempool: &mem2, node_state: &state2,
                tip_tx: Some(&tip_tx2), shielded: &shielded2,
            };

            loop {
            // Orphan-deadlock fix: select between the inbound channel and the
            // ~30s orphan sweep.
            let inbound = tokio::select! {
                m = block_rx.recv() => match m { Some(m) => m, None => break },
                _ = orphan_sweep.tick() => {
                    let ready = sweep_orphan_parents(
                        &mut ingress_core.orphans, &mut ingress_core.parent_fetch, &dag2, &otx2,
                    ).await;
                    // Defensive liveness: a waited-on parent that is ALREADY in
                    // the DAG (its accept raced the waiting_for insert) would
                    // otherwise strand its orphans forever — drain them now.
                    for p in ready {
                        ingress_core.drain_orphans(p, &ctx);
                    }
                    frontier2.lock().set_orphan_evidence(ingress_core.orphans.max_evidence_height());
                    maybe_release_ibd(&dag2, &peer_state2, &frontier2, &state2);
                    continue;
                }
            };
            let network::Inbound { msg, origin } = inbound;
            match msg {

                // NET-6: a peer's tip claim. Clamped once, consistently; a claim
                // ahead of us triggers a rate-limited DIRECTED pull (headers +
                // frontier) — it no longer sets `is_syncing`. The IBD latch is
                // set only by work-backed evidence (NewBlock arm below) and
                // released by `maybe_release_ibd`.
                network::NetworkMessage::PeerTip { blue_score: peer_s, ref peer_id, .. } => {
                    let our_s = dag2.read().tip_blue_score();
                    let act = claims.evaluate(peer_s, our_s, std::time::Instant::now());
                    {
                        let mut s = state2.write();
                        s.seen_first_tip = true;
                        // RPC display hint only (clamped).
                        if act.clamped > s.best_seen_blue_score { s.best_seen_blue_score = act.clamped; }
                    }
                    if act.pull {
                        info!("Peer {} claims to be ahead ({} > {}), pulling headers + frontier",
                            network::truncate_utf8(peer_id, 64), act.clamped, our_s);
                        getheaders_sent2.store(proc_start.elapsed().as_millis() as u64, std::sync::atomic::Ordering::Relaxed);
                        let _ = otx2.send(network::NetworkMessage::GetHeaders { from_blue_score: our_s, limit: 500, nonce: getblock_nonce() }).await;
                        let _ = otx2.send(network::NetworkMessage::GetTips).await;
                    } else if act.reciprocal {
                        // Mesh fix (reciprocal tip): the announcing peer is BEHIND
                        // us; answer with a fresh-timestamp Version (unique bytes,
                        // never dedup-dropped) carrying our blue_score.
                        let height = dag2.read().block_count() as u64;
                        debug!("peer behind (score {} < {}), sending reciprocal tip", act.clamped, our_s);
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
                    maybe_release_ibd(&dag2, &peer_state2, &frontier2, &state2);
                }

                // NET-7 (audit): gossip PULLS are never served. Answering them
                // made every node broadcast a reply to the whole mesh (up to
                // 2,000 headers, a full block, a NotFound) for every request —
                // O(N²) amplification, and DAG-12's unclamped `limit`. Pulls are
                // served only over directed `/gnb/sync/1` (network/mod.rs,
                // `serve_sync_request`, limit clamped), one requester, one
                // answer. The network loop no longer even delivers these.
                network::NetworkMessage::GetTips
                | network::NetworkMessage::GetHeaders { .. }
                | network::NetworkMessage::GetBlock { .. } => {
                    debug!("gossip pull ignored (served only over directed /gnb/sync/1)");
                }

                // Frontier reconciliation: a peer's advertised frontier. NET-10:
                // only a SOLICITED frontier (the answer to our own directed
                // GetTips) drives fetches, at most MAX_NEW_TIPS_PER_RESPONSE new
                // tips per answer and MAX_FRONTIER_IN_FLIGHT overall. NET-6: a
                // frontier gap no longer latches IBD by itself — the fetched tips
                // do, if they arrive as full-difficulty orphans well ahead of us.
                network::NetworkMessage::Tips { tips, .. } => {
                    if !origin.is_solicited() {
                        debug!("unsolicited Tips ignored");
                        continue;
                    }
                    let advertised: Vec<[u8; 32]> = tips.iter().map(|e| e.hash).collect();
                    let now = std::time::Instant::now();
                    let to_req = {
                        let d = dag2.read();
                        frontier2.lock().to_request_capped(
                            &advertised,
                            |h| d.has_block(h) || ingress_core.orphans.contains(h),
                            now,
                            sync::frontier::MAX_NEW_TIPS_PER_RESPONSE,
                        )
                    };
                    for h in &to_req {
                        let _ = otx2.send(network::NetworkMessage::GetBlock { block_hash: *h, nonce: getblock_nonce() }).await;
                    }
                    maybe_release_ibd(&dag2, &peer_state2, &frontier2, &state2);
                }

                // IBD step 3: headers — request missing blocks. NET-10: only the
                // answer to our own directed GetHeaders is acted on (gossip
                // Headers are no longer delivered; an overheard stream must
                // never drive the pipeline).
                network::NetworkMessage::Headers { entries } => {
                    if !origin.is_solicited() {
                        debug!("unsolicited Headers ignored ({} entries)", entries.len());
                        continue;
                    }
                    let missing: Vec<[u8; 32]> = {
                        let d = dag2.read();
                        entries.iter()
                            .filter(|e| !d.has_block(&e.hash) && !ingress_core.orphans.contains(&e.hash))
                            .map(|e| e.hash).collect()
                    };
                    if !missing.is_empty() {
                        info!("IBD: need {}/{} blocks", missing.len(), entries.len());
                    }
                    for hash in missing {
                        let _ = otx2.send(network::NetworkMessage::GetBlock { block_hash: hash, nonce: getblock_nonce() }).await;
                    }
                    let recent_request = {
                        let sent = getheaders_sent2.load(std::sync::atomic::Ordering::Relaxed);
                        sent != u64::MAX
                            && (proc_start.elapsed().as_millis() as u64).saturating_sub(sent)
                                <= HEADERS_SOLICITED_WINDOW_MS
                    };
                    if entries.is_empty() {
                        maybe_release_ibd(&dag2, &peer_state2, &frontier2, &state2);
                    } else if entries.len() >= 500 && recent_request {
                        // Pipeline IBD: a full batch means the serving peer has
                        // more — request the next batch immediately.
                        let next_from = entries.iter().map(|e| e.blue_score).max().unwrap_or(0);
                        getheaders_sent2.store(proc_start.elapsed().as_millis() as u64, std::sync::atomic::Ordering::Relaxed);
                        let _ = otx2.send(network::NetworkMessage::GetHeaders { from_blue_score: next_from, limit: 500, nonce: getblock_nonce() }).await;
                    }
                }

                // A peer told us it cannot serve this body. NET-9: counted once
                // per DISTINCT answering peer toward abandoning a frontier tip, so
                // a single peer can no longer abandon a tip by itself.
                network::NetworkMessage::BlockNotFound { block_hash, .. } => {
                    let Some(peer) = origin.peer().filter(|_| origin.is_solicited()) else { continue };
                    warn!("peer {} cannot serve block {} (pruned or unknown) — an \
                           archival peer is needed to bootstrap from this height",
                          peer, hex::encode(&block_hash[..8]));
                    frontier2.lock().note_not_found_from(&block_hash, peer, std::time::Instant::now());
                    maybe_release_ibd(&dag2, &peer_state2, &frontier2, &state2);
                }

                // Full validation before storing — with orphan pool support.
                //
                // NET-2 (audit): checks run CHEAPEST FIRST and the 64 MiB PoW
                // only after every cheap check has passed; the gossip frame is
                // relayed only after the verdict computed here is reported
                // (`report_verdict`): Accept → forwarded, Reject → not forwarded
                // and the delivering peer takes gossipsub's P4 penalty, Ignore →
                // dropped without penalty.
                network::NetworkMessage::NewBlock { block_data, block_hash, height, .. } => {
                    let now = std::time::Instant::now();
                    let verdict: network::GossipVerdict = 'blk: {
                        if dag2.read().has_block(&block_hash) || ingress_core.orphans.contains(&block_hash) {
                            break 'blk network::GossipVerdict::Ignore;
                        }
                        let tip_h = selected_tip_height(&dag2);
                        // POW-2: bound the peer-supplied height BEFORE any
                        // decoding or arithmetic (unsolicited frames only — an
                        // answer to our own pull may legitimately be far ahead).
                        if !origin.is_solicited() && ingress::unsolicited_height_too_far_ahead(height, tip_h) {
                            debug!("NewBlock {} claims h={} far above tip h={}; ignored (pull-based IBD fetches it)",
                                hex::encode(&block_hash[..8]), height, tip_h);
                            break 'blk network::GossipVerdict::Ignore;
                        }
                        // Sprint 1.c: Bitcoin-format wire.
                        let block = match core::Block::from_wire_bytes(&block_data) {
                            Ok(b) => b,
                            Err(e) => {
                                warn!("block deserialise: {}", e);
                                break 'blk network::GossipVerdict::Reject;
                            }
                        };
                        // SECURITY (audit H2): bind the wire-supplied block_hash /
                        // height to the actual block content before anything else.
                        let real_hash = block.block_hash();
                        if real_hash != block_hash {
                            warn!("block id mismatch: claimed {} but content hashes to {}; dropping",
                                hex::encode(&block_hash[..8]), hex::encode(&real_hash[..8]));
                            break 'blk network::GossipVerdict::Reject;
                        }
                        if height != block.height {
                            warn!("block {} height mismatch: claimed {} vs content {}; dropping",
                                hex::encode(&block_hash[..8]), height, block.height);
                            break 'blk network::GossipVerdict::Reject;
                        }

                        // Everything else is the ingress core (shared with the
                        // integration tests), cheapest checks first:
                        //  * structure without PoW;
                        //  * ORPHAN (a parent unknown): backfill-flood guard (an
                        //    unsolicited far-below-tip orphan is dropped — backfill
                        //    is pulled), the anti-DoS bits floor BEFORE the proof
                        //    (NET-2 / POW-4), the proof, then the bounded pool;
                        //  * parents known: the POW-3 anti-DoS WORK rule — the
                        //    block's chain must come within ANTI_DOS_WINDOW_BLOCKS
                        //    of our tip's work, or be backed by a proof-of-work-
                        //    verified orphan chain announced on top of it (deep
                        //    merge-backed blocks are rationed, DAG-7) — BEFORE the
                        //    proof, storage or DAG insertion; then POW-8 metadata
                        //    normalization, `accept_block` (height, expected bits,
                        //    timestamp before the proof, NET-2) and the iterative
                        //    orphan drain (POW-3 / POW-4).
                        let now_unix = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs()).unwrap_or(0);
                        let t_validate = std::time::Instant::now();
                        match ingress_core.handle_block(block, block_hash, block_data.len(), origin.peer(), now, now_unix, &ctx) {
                            ingress::BlockOutcome::Known | ingress::BlockOutcome::PoolRefused => {
                                network::GossipVerdict::Ignore
                            }
                            ingress::BlockOutcome::Dropped(reason) => {
                                debug!("block {} h={} dropped before PoW: {:?} (tip h={})",
                                    hex::encode(&block_hash[..8]), height, reason, tip_h);
                                crate::metrics::inc_block_backfill_dropped();
                                network::GossipVerdict::Ignore
                            }
                            ingress::BlockOutcome::Invalid(reason) => {
                                warn!("block {} rejected ({})", hex::encode(&block_hash[..8]), reason);
                                network::GossipVerdict::Reject
                            }
                            ingress::BlockOutcome::Buffered { request, evidence, evicted } => {
                                if evicted > 0 {
                                    debug!("orphan pool full: evicted {} oldest orphan(s)", evicted);
                                }
                                for mp in request {
                                    // Orphan-deadlock fix: the attempt was recorded
                                    // by the core so the sweep can re-request it.
                                    let _ = otx2.send(network::NetworkMessage::GetBlock {
                                        block_hash: mp, nonce: getblock_nonce(),
                                    }).await;
                                }
                                {
                                    let mut fr = frontier2.lock();
                                    fr.note_received(&block_hash);
                                    fr.set_orphan_evidence(ingress_core.orphans.max_evidence_height());
                                }
                                // NET-6: the IBD latch is set ONLY by work-backed
                                // evidence — a full-difficulty orphan claiming to be
                                // well ahead of our tip.
                                if evidence {
                                    let mut s = state2.write();
                                    if !s.is_syncing {
                                        info!("IBD latched: work-backed orphan claims h={} (tip h={})", height, tip_h);
                                    }
                                    s.is_syncing = true;
                                }
                                maybe_release_ibd(&dag2, &peer_state2, &frontier2, &state2);
                                network::GossipVerdict::Accept
                            }
                            ingress::BlockOutcome::Processed { admission, result, drained } => {
                                crate::metrics::observe_block_validation(t_validate.elapsed().as_secs_f64());
                                match result {
                                    Err(e) => {
                                        crate::metrics::inc_block_rejected();
                                        warn!("block {} h={} REJECTED: {}", hex::encode(&block_hash[..8]), height, e);
                                        ingress::verdict_for_accept_error(&e)
                                    }
                                    Ok(_) => {
                                        crate::metrics::inc_block_accepted();
                                        if admission != ingress::WorkAdmission::NearTip {
                                            info!("block {} h={} admitted as {:?} (POW-3 work rule); {} orphan(s) drained",
                                                hex::encode(&block_hash[..8]), height, admission, drained.len());
                                        }
                                        {
                                            let mut fr = frontier2.lock();
                                            fr.note_received(&block_hash);
                                            fr.set_orphan_evidence(ingress_core.orphans.max_evidence_height());
                                        }
                                        maybe_release_ibd(&dag2, &peer_state2, &frontier2, &state2);
                                        network::GossipVerdict::Accept
                                    }
                                }
                            }
                        }
                    };
                    report_verdict(&vtx2, &origin, verdict);
                }

                // Local heartbeat only: a PeerCount from a peer would let it set
                // our RPC peer count / addresses (and the miner's no-peer gate).
                network::NetworkMessage::PeerCount { count, addresses } => {
                    if matches!(origin, network::InboundOrigin::Local) {
                        let mut s = state2.write();
                        s.peer_count = count as u32;
                        s.peer_addresses = addresses;
                    }
                }

                // Add validated tx to mempool
                network::NetworkMessage::NewTransaction { tx_data, .. } => {
                    // Sprint 1.d: Bitcoin-format tx wire. MEM-5: strict decode —
                    // trailing bytes are refused, so one tx has exactly one
                    // encoding (no gossipsub-dedup bypass by byte mutation).
                    match mempool::admission::decode_tx_strict(&tx_data) {
                        Ok(tx) => {
                            // MEM-1/4/5: the shared admission function (same rules
                            // as sendrawtransaction and reorg re-injection): size,
                            // standardness incl. dust, known/recent-reject, UTXO,
                            // maturity at the NEXT block height (selected-tip DAG
                            // height + 1 — never dag.block_count()), fees, and
                            // signatures last. P0: it runs on the blocking pool so
                            // PQ signature work cannot stall this task's reactor.
                            let next_height = mempool::admission::next_block_height(&dag2.read());
                            let store_v = store2.clone();
                            let mem_v = mem2.clone();
                            let admitted = tokio::task::spawn_blocking(move || {
                                let policy = mempool::admission::AdmissionPolicy::relay(next_height);
                                mempool::admission::admit(&store_v, &mem_v, tx, &policy)
                            }).await;
                            match admitted {
                                Ok(Ok(_))  => {}
                                Ok(Err(e)) => debug!("mempool reject: {}", e),
                                Err(e)     => warn!("tx verify task failed: {}", e),
                            }
                            state2.write().mempool_size = mem2.size();
                        }
                        Err(e) => debug!("tx decode rejected: {}", e),
                    }
                }

                // NET-6: same claim handling as PeerTip (rate-limited directed
                // pull; never latches IBD). Version frames carry a fresh
                // timestamp, so they are the dedup-proof tip announcement.
                network::NetworkMessage::Version { version, blue_score: peer_s, .. } => {
                    if version < network::MIN_PROTOCOL_VERSION { continue; }
                    let our_s = dag2.read().tip_blue_score();
                    let act = claims.evaluate(peer_s, our_s, std::time::Instant::now());
                    {
                        let mut s = state2.write();
                        s.seen_first_tip = true;
                        if act.clamped > s.best_seen_blue_score { s.best_seen_blue_score = act.clamped; }
                    }
                    if act.pull {
                        info!("Version peer claims to be ahead (score {} > {}), pulling headers + frontier", act.clamped, our_s);
                        getheaders_sent2.store(proc_start.elapsed().as_millis() as u64, std::sync::atomic::Ordering::Relaxed);
                        let _ = otx2.send(network::NetworkMessage::GetHeaders { from_blue_score: our_s, limit: 500, nonce: getblock_nonce() }).await;
                        let _ = otx2.send(network::NetworkMessage::GetTips).await;
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
          // restart with bounded exponential backoff (reset after a healthy
          // run). Ok(()) means the input channel closed cleanly → exit.
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
                  let wait = backoff.on_panic(run_started.elapsed());
                  error!("message-processor PANICKED: {} — node stays up; restarting loop in {:?}",
                      detail, wait);
                  tokio::time::sleep(wait).await;
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
                // which lose to the network chain on blue work (and were,
                // before audit DAG-6, refused by its finality rule). Pre-fix,
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
                // (Mining through a stall can no longer self-finalize a solo
                // fork: there is no finality checkpoint and no reorg-depth
                // limit, audit DAG-6 — a strictly heavier chain reorgs us at
                // any depth once its blocks arrive. The old FINALITY_FROZEN
                // flag is gone.)
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

                // ── Block template (audit MEM-2 / DAG-2 / MEM-1 / MEM-3) ──────
                // Shared with getblocktemplate (`template::build_block_template`):
                // at most MAX_PARENTS bodied, non-disqualified tips by blue work
                // (header-only tips are unmineable, see GhostDAG::bodied_tips);
                // expected ASERT bits for exactly those parents (fail closed if
                // underivable — never mine on a guessed target); transactions by
                // fee rate under a byte budget measured exactly like the
                // consensus size rule, each re-validated against the UTXO set
                // (offenders are evicted from the mempool); coinbase fees
                // recomputed from the UTXO set (N-7 duplicate-outpoint safe).
                // Coinbase reserve: our own coinbase at its widest encoding.
                let cb_reserve = template::miner_coinbase(u64::MAX, u64::MAX, miner_spk.clone())
                    .actual_size();
                let tmpl = match template::build_block_template(&dag_m, &store_m, &mem_m, cb_reserve) {
                    Ok(t) => t,
                    Err(e) => {
                        warn!("⛏  cannot build a block template: {} — skipping mining round \
                               (fail-closed, no guessed target)", e);
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        continue;
                    }
                };
                // Fair launch: 100% of subsidy + fees to the miner, one output.
                let coinbase = template::miner_coinbase(
                    tmpl.height,
                    tmpl.subsidy.saturating_add(tmpl.total_fees),
                    miner_spk.clone(),
                );
                let now_ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default().as_secs();
                // Never before a parent (validate_timestamp); the template
                // self-check runs every structural rule except the PoW.
                let mut block = match template::assemble_block(&tmpl, coinbase, now_ts) {
                    Ok(b) => b,
                    Err(e) => {
                        error!("⛏  block template failed its self-check: {} — skipping round", e);
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        continue;
                    }
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
                            // MEM-1/MEM-3: never retry with the same poisoned
                            // template — drop every pooled tx no longer minable.
                            let next_height = mempool::admission::next_block_height(&dag_m.read());
                            let dropped = accept::revalidate_mempool(&store_m, &mem_m, next_height);
                            if dropped > 0 {
                                warn!("mining: evicted {} stale tx(s) after the rejected block", dropped);
                            }
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
    // Audit DAG-6: operator recovery (invalidateblock / reconsiderblock).
    let rpc_chain_admin: Arc<rpc::ChainAdminFn> = make_chain_admin_cb(
        dag.clone(), store.clone(), mempool.clone(), node_state.clone(),
        shielded.clone(), tip_tx.clone(),
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

    // NET-14: validate the auxiliary servers' addresses before starting
    // them (a bad address is a configuration error, reported clearly), then
    // run them as independent tasks. A server that fails later (bind error,
    // runtime error) logs and stops ITSELF; only the network loop's exit
    // ends the node. Previously both sat in the top-level `select!`, so any
    // RPC/metrics failure (e.g. `--metrics-addr ::1`) stopped the node.
    if let Err(e) = rpc::resolve_bind_address(&rpc_bind, cli.rpc_port) {
        eprintln!("❌ invalid RPC address (--rpc-bind/--rpc-port): {e}");
        std::process::exit(2);
    }
    if metrics_config.enabled {
        if let Err(e) = rpc::resolve_bind_address(&metrics_config.bind_address, metrics_config.port) {
            eprintln!("❌ invalid metrics address (--metrics-addr/--metrics-port): {e}");
            std::process::exit(2);
        }
    }
    tokio::spawn(crate::metrics::start_metrics_server(
        metrics_config,
        metrics_state.clone(),
    ));
    tokio::spawn(rpc::start_rpc_server(
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
        // Audit DAG-6: invalidateblock / reconsiderblock (see rpc::ChainAdminFn).
        Some(rpc_chain_admin.clone()),
    ));
    // Sprint EE (S3): `None` = no listen-addr report; production behavior
    // is byte-identical to before the harness affordance was added.
    match node.run_validated(block_tx, validation_rx, outbound_rx, dag.clone(), peer_state.clone(), store.clone(), None).await {
        Ok(_) => error!("Network exited"),
        Err(e) => error!("Network exited: {:?}", e),
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
            // DAG-1: a disqualified block stays in the DAG; tell the
            // submitter it is invalid rather than merely a duplicate.
            if dag.read().is_invalid(&block_hash) {
                let reason = store.invalid_block_reason(&block_hash).ok().flatten()
                    .unwrap_or_else(|| "descends from an invalid block".to_string());
                return Err(format!("duplicate block (known invalid: {})", reason));
            }
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

/// Build the `invalidateblock` / `reconsiderblock` hook (audit DAG-6): both
/// run through the acceptance pipeline (`accept::invalidate_block` /
/// `accept::reconsider_block`) under the acceptance lock, persist their marks
/// atomically with the chain move, and refresh mempool, RPC state and the
/// stratum tip notification. Authorization is the RPC layer's
/// (`rpc::auth::ADMIN_METHODS`: never anonymous).
fn make_chain_admin_cb(
    dag:        Arc<RwLock<consensus::GhostDAG>>,
    store:      Arc<storage::Storage>,
    mempool:    Arc<mempool::Mempool>,
    node_state: Arc<RwLock<rpc::NodeState>>,
    shielded:   Arc<RwLock<crate::coherence::ShieldedPool>>,
    tip_tx:     broadcast::Sender<tip::TipChanged>,
) -> Arc<rpc::ChainAdminFn> {
    Arc::new(move |op: rpc::ChainAdminOp, hash: [u8; 32]| -> Result<serde_json::Value, String> {
        let r = match op {
            rpc::ChainAdminOp::Invalidate => accept::invalidate_block(
                hash, &dag, &store, &mempool, &node_state, Some(&tip_tx), &shielded),
            rpc::ChainAdminOp::Reconsider => accept::reconsider_block(
                hash, &dag, &store, &mempool, &node_state, Some(&tip_tx), &shielded),
        }?;
        Ok(serde_json::json!({
            "block":       hex::encode(hash),
            "affected":    r.affected,
            "rolled_back": r.rolled_back,
            "connected":   r.connected,
            "tip":         hex::encode(r.tip),
            "tip_height":  r.tip_height,
        }))
    })
}

// ── Block acceptance + Orphan processing ─────────────────────────────────────

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

// `ARCHIVE_MODE` and `accept_block` moved to `accept.rs` (audit
// DAG-1/DAG-10/DAG-11); imported at the top of this file. `FINALITY_FROZEN`
// was removed with the finality checkpoint (audit DAG-6).

/// Blue_work-VERIFIED / evidence-based IBD release — the ONLY path that clears
/// `is_syncing`.
///
/// NET-6 (audit): both the latch and its release are driven by work-backed
/// evidence only. The latch is set solely by a PoW-verified, full-difficulty
/// orphan that claims to be well ahead of us (NewBlock arm); announced
/// `blue_score` claims never set it and no longer gate its release either (a
/// single inflated `Version` frame used to keep every node in IBD). Release
/// fires on the FIRST of:
///  (A) VERIFIED: we hold every advertised tip of the connected peers'
///      (directed, responder-attributed) frontiers — or gave up on it — AND our
///      selected-tip `blue_work` is at least the greatest locally-verified
///      `blue_work` reachable from them (`servable_blue_work`). Tips we cannot
///      verify contribute 0. `!abandoned_gap` keeps a given-up frontier from
///      counting as "verified".
///  (B) CAUGHT UP: no buffered work-backed orphan claims a height more than
///      `IBD_EXIT_LAG` above our selected tip any more (the evidence that
///      latched us was accepted, or evicted / given up by the orphan sweep).
///
/// Announced scores are still recorded (author-attributed, latest-wins,
/// TTL-decayed) for the RPC `best_announced` / `behind_by` hint.
///
/// Lock order (must match every other call-site): dag → peer_state → frontier
/// → node_state. All read locks drop before node_state.write().
fn maybe_release_ibd(
    dag:        &Arc<RwLock<consensus::GhostDAG>>,
    peer_state: &Arc<sync::peer_state::PeerStateTable>,
    frontier:   &Arc<parking_lot::Mutex<sync::frontier::FrontierState>>,
    node_state: &Arc<RwLock<rpc::NodeState>>,
) {
    let (our_work, our_score, our_height, servable, reconciled, have_frontier, abandoned_gap, evidence) = {
        let d = dag.read();
        let selected = d.selected_tip().and_then(|h| d.get_node(&h));
        let our_work = selected.as_ref().map(|n| n.blue_work).unwrap_or(0);
        let our_score = selected.as_ref().map(|n| n.blue_score).unwrap_or(0);
        let our_height = selected.as_ref().map(|n| n.height).unwrap_or(0);
        // Disqualified blocks (DAG-1) are never selectable, so a peer frontier
        // that only leads to them must not hold the IBD latch.
        let servable = peer_state.servable_blue_work(|h| {
            if d.is_invalid(h) { None } else { d.get_node(h).map(|n| n.blue_work) }
        });
        let advertised = peer_state.connected_advertised_tips();
        let have_frontier = !advertised.is_empty();
        let fr = frontier.lock();
        let outstanding = fr.outstanding();
        let reconciled = sync::frontier::reconciled(
            &advertised, |h| d.has_block(h), outstanding, |h| fr.is_abandoned(h),
        );
        let abandoned_gap = advertised.iter().any(|h| !d.has_block(h) && fr.is_abandoned(h));
        let evidence = fr.orphan_evidence_height();
        drop(fr);
        (our_work, our_score, our_height, servable, reconciled, have_frontier, abandoned_gap, evidence)
    };
    let best_announced = peer_state.best_announced_blue_score();
    let evidence_ahead = evidence.is_some_and(|h| h > our_height.saturating_add(sync::IBD_EXIT_LAG));
    let verified  = have_frontier && reconciled && !abandoned_gap && our_work >= servable;
    let caught_up = !evidence_ahead;
    {
        let mut s = node_state.write();
        // RPC honesty hint (fresh, author-attributed claims only).
        s.best_announced_blue_score = best_announced;
        if (verified || caught_up) && s.is_syncing {
            s.is_syncing = false;
            info!("IBD complete (verified={} caught_up={}; score {} height {} best_announced {}; work {} servable {}; abandoned_gap={}; orphan_evidence={:?})",
                verified, caught_up, our_score, our_height, best_announced, our_work, servable, abandoned_gap, evidence);
        }
    }
}

/// NET-2: report the processor's verdict for a deferred gossip frame. No-op
/// for frames that owe none (directed answers, local frames, or gossip whose
/// verdict the network loop already reported).
fn report_verdict(
    vtx:     &mpsc::Sender<network::GossipValidation>,
    origin:  &network::InboundOrigin,
    verdict: network::GossipVerdict,
) {
    if let Some((message_id, propagation_source)) = origin.pending_verdict() {
        // A full channel only means this frame is not relayed (it expires
        // from gossipsub's cache); never block the processor on it.
        let _ = vtx.try_send(network::GossipValidation { message_id, propagation_source, verdict });
    }
}

/// Height of our selected tip (0 for an empty DAG).
fn selected_tip_height(dag: &Arc<RwLock<consensus::GhostDAG>>) -> u64 {
    let d = dag.read();
    d.selected_tip()
        .and_then(|t| d.get_block_data(&t).map(|bd| bd.height))
        .unwrap_or(0)
}

// `normalize_wire_metadata` (POW-8) and `process_orphans` (iterative orphan
// drain, POW-3 / POW-4) moved to the library's `ingress` module, where the
// processor core (`ingress::BlockIngress`) and the integration tests use them.

/// Orphan-deadlock fix: periodic (~30s) sweep over the missing-parent set.
///
/// Re-emits GetBlock for parents pending past their (exponential, capped)
/// backoff, gives up past an attempt/age ceiling (dropping the dependent
/// orphans so the pool stays bounded), and returns waited-on parents that are
/// ALREADY in the DAG so the caller can drain their orphans.
///
/// NOT consensus: only re-sends an existing wire message and prunes a local
/// buffer. Validation/acceptance paths untouched.
async fn sweep_orphan_parents(
    orphans:      &mut ingress::OrphanPool,
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
        for p in orphans.waiting_parents() {
            if d.has_block(&p) {
                ready.push(p);
            } else if !orphans.contains(&p) {
                chased.push(p);
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
        info!("orphan sweep: re-requested {} missing parent(s) (orphans={} bytes={})",
            retry.len(), orphans.len(), orphans.total_bytes());
    }
    for (h, attempts) in give_up {
        let dropped = drop_orphan_subtree(h, orphans);
        warn!("orphan sweep: giving up on missing parent {} after {} attempts; \
               dropped {} dependent orphan(s) — peers will re-announce if the \
               branch is real", hex::encode(&h[..8]), attempts, dropped);
    }
    ready
}

/// Remove every orphan transitively waiting on `root_parent` (which we gave up
/// fetching), iteratively. Returns how many orphans were dropped. Dropped
/// orphans are NOT banned: if a peer re-announces the branch and its ancestry
/// becomes fetchable, it re-enters the pool.
fn drop_orphan_subtree(root_parent: [u8; 32], orphans: &mut ingress::OrphanPool) -> usize {
    orphans.drop_subtree(&root_parent)
}

#[cfg(test)]
mod ingress_processor_tests {
    //! Regressions for the processor-side audit fixes that live in this
    //! binary: iterative orphan draining with derived metadata (POW-3/4/8)
    //! and the evidence-driven IBD latch release (NET-6).
    use super::*;
    use crate::ingress::{normalize_wire_metadata, process_orphans};

    fn unix_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn coinbase(height: u64) -> core::Transaction {
        core::Transaction {
            version: 1,
            inputs: vec![core::TxInput {
                prev_txid:  [0u8; 32],
                prev_index: u32::MAX,
                script_sig: format!("ingress-test:{}", height).into_bytes(),
                sequence:   u32::MAX,
            }],
            outputs: vec![core::TxOutput {
                value: core::tokenomics::block_subsidy_sat(height),
                script_pubkey: vec![0xAB; 20],
            }],
            locktime: 0,
        }
    }

    /// A valid (mined) child of `parent` at `height`.
    fn child(parent: &core::Block, height: u64) -> core::Block {
        let txs = vec![coinbase(height)];
        let ts = parent.header.timestamp + 30;
        let bits = pow::expected_bits(parent.header.timestamp, height).expect("bits");
        let mut b = core::Block {
            header: core::BlockHeader {
                version: 1,
                parents: vec![parent.block_hash()],
                merkle_root: core::Transaction::merkle_root(&txs),
                timestamp: ts,
                bits,
                nonce: 0,
            },
            transactions: txs,
            blue_score: 0,
            height,
            shielded_transactions: Vec::new(),
        };
        let nonce = pow::mine_parallel(&b.header.pow_preimage(), bits, 0, 1 << 16, 2, None)
            .expect("solve");
        b.header.nonce = nonce;
        assert!(b.validate_structure().is_ok());
        b
    }

    struct Fixture {
        _tmp:       tempfile::TempDir,
        dag:        Arc<RwLock<consensus::GhostDAG>>,
        store:      Arc<storage::Storage>,
        mempool:    Arc<mempool::Mempool>,
        node_state: Arc<RwLock<rpc::NodeState>>,
        shielded:   Arc<RwLock<crate::coherence::ShieldedPool>>,
        genesis:    core::Block,
    }

    fn fixture() -> Fixture {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let store = Arc::new(storage::Storage::open(&tmp.path().join("db")).expect("storage"));
        let dag = Arc::new(RwLock::new(consensus::GhostDAG::with_default_k()));
        let genesis = core::Block {
            header: core::BlockHeader {
                version: 1,
                parents: vec![],
                merkle_root: core::MerkleRoot::ZERO,
                timestamp: unix_now().saturating_sub(600),
                bits: core::GENESIS_BITS,
                nonce: 0,
            },
            transactions: vec![coinbase(0)],
            blue_score: 0,
            height: 0,
            shielded_transactions: Vec::new(),
        };
        store.put_block(&genesis).expect("store genesis");
        dag.write().add_genesis(genesis.block_hash(), genesis.header.timestamp);
        Fixture {
            _tmp: tmp,
            dag,
            store,
            mempool: Arc::new(mempool::Mempool::new()),
            node_state: Arc::new(RwLock::new(rpc::NodeState::default())),
            shielded: Arc::new(RwLock::new(crate::coherence::ShieldedPool::new())),
            genesis,
        }
    }

    /// POW-3 / POW-4 / POW-8: orphans are drained iteratively once their
    /// ancestor arrives, and the stored blue_score is DERIVED from verified
    /// parents, never the (forged) wire value.
    #[test]
    fn orphan_chain_drains_iteratively_with_derived_metadata() {
        let f = fixture();
        let b1 = child(&f.genesis, 1);
        let b2 = child(&b1, 2);
        let b3 = child(&b2, 3);
        let mut pool = ingress::OrphanPool::default();
        for (b, missing) in [(&b3, b2.block_hash()), (&b2, b1.block_hash())] {
            let mut forged = b.clone();
            forged.blue_score = u64::MAX; // wire metadata, not committed by the id
            let id = forged.block_hash();
            assert!(matches!(
                pool.insert(id, forged, b.height, 1_000, None, false, &[missing]),
                ingress::OrphanInsert::Inserted { .. }
            ));
        }
        let mut b1n = b1.clone();
        normalize_wire_metadata(&mut b1n, &f.dag);
        let h1 = accept_block(&b1n, b1.block_hash(), 1, &f.dag, &f.store, &f.mempool, &f.node_state, None, &f.shielded)
            .expect("b1 accepted");
        process_orphans(h1, &mut pool, &f.dag, &f.store, &f.mempool, &f.node_state, None, &f.shielded);
        assert!(pool.is_empty(), "the whole orphan chain was drained");
        assert!(f.dag.read().has_block(&b3.block_hash()));
        let stored = f.store.get_block(&b3.block_hash()).unwrap().unwrap();
        assert_eq!(stored.blue_score, 3, "derived from parents, not the forged u64::MAX");
    }

    fn release_fixture() -> (
        Arc<RwLock<consensus::GhostDAG>>,
        Arc<sync::peer_state::PeerStateTable>,
        Arc<parking_lot::Mutex<sync::frontier::FrontierState>>,
        Arc<RwLock<rpc::NodeState>>,
    ) {
        let dag = Arc::new(RwLock::new(consensus::GhostDAG::with_default_k()));
        dag.write().add_genesis([0xAA; 32], 1_000);
        (
            dag,
            Arc::new(sync::peer_state::PeerStateTable::new()),
            Arc::new(parking_lot::Mutex::new(sync::frontier::FrontierState::new())),
            Arc::new(RwLock::new(rpc::NodeState::default())),
        )
    }

    /// NET-6: an inflated tip claim (even u64::MAX from a connected peer) can
    /// no longer hold the IBD latch: without work-backed evidence it releases.
    #[test]
    fn inflated_claim_cannot_hold_ibd_latch() {
        let (dag, ps, fr, st) = release_fixture();
        let liar = libp2p::PeerId::random();
        ps.on_connect(liar, std::time::Instant::now());
        ps.observe_claim(liar, u64::MAX, u64::MAX, std::time::Instant::now());
        st.write().is_syncing = true;
        maybe_release_ibd(&dag, &ps, &fr, &st);
        assert!(!st.read().is_syncing, "a claim alone must not keep the node in IBD");
    }

    /// NET-6: work-backed evidence (an orphan claiming to be well ahead) holds
    /// the latch until it is resolved.
    #[test]
    fn work_backed_evidence_holds_latch_until_resolved() {
        let (dag, ps, fr, st) = release_fixture();
        fr.lock().set_orphan_evidence(Some(sync::IBD_EXIT_LAG + 100));
        st.write().is_syncing = true;
        maybe_release_ibd(&dag, &ps, &fr, &st);
        assert!(st.read().is_syncing, "evidence of a chain far ahead keeps the latch");
        fr.lock().set_orphan_evidence(Some(sync::IBD_EXIT_LAG));
        maybe_release_ibd(&dag, &ps, &fr, &st);
        assert!(!st.read().is_syncing, "within IBD_EXIT_LAG counts as caught up");
    }
}

// ── Unified TX validation ────────────────────────────────────────────────────
// `validate_tx_inputs`, `miner_template_total_fees`, `validate_tx_in_block*`
// and `validate_tx_standalone` moved to `accept.rs`; imported at the top.

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
        // UPDATED for audit DAG-1 (accept/connect split). The pre-fix path
        // deleted a block that failed transaction validation. Transaction
        // validity is now a connect-time property of the block's own chain
        // context; a block failing it is recorded as CHAIN-DISQUALIFIED and
        // kept in the DAG (so a peer that merged it as a non-selected parent
        // stays acceptable — arrival-order independence), but it is never
        // selected, never applied and never broadcast. What this test guards —
        // the producer refuses its own invalid block and nothing of it reaches
        // the chain state — is unchanged:
        assert!(node.dag.read().is_invalid(&hash), "must be recorded as disqualified");
        assert!(
            node.store.invalid_block_reason(&hash).expect("meta read").is_some(),
            "the disqualification must be persisted",
        );
        assert_eq!(
            node.dag.read().selected_tip(), Some(genesis.block_hash()),
            "a rejected self-mined block must never become the selected tip",
        );
        assert!(
            node.store.get_utxo(&bad.transactions[0].txid(), 0).expect("utxo read").is_none(),
            "a rejected self-mined block must have no UTXO effect",
        );
        assert!(
            node.store.get_meta("tip_hash").expect("meta read").is_none(),
            "the applied tip pointer must not move",
        );
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

    // ── Audit DAG-6: no reorg-depth limit ───────────────────────────────────
    //
    // Drive the REAL `accept_block` pipeline (add_block → resolve → atomic
    // connect) with a fork that out-weighs the live chain only once it is
    // deeper than the live chain itself. The old pipeline refused such a
    // reorg once it exceeded `MAX_REORG_DEPTH` (a node-local cap, so nodes
    // that saw the blocks in different orders split); it is now followed at
    // any depth. The >1,000-block audit scenario, with two nodes and UTXO
    // digests, is `node/tests/fix_chain_selection.rs`.

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

    /// Audit DAG-6 (replaces `refused_deep_reorg_must_not_poison_dag_selected_tip`,
    /// which pinned the removed depth cap): a heavier fork that branches at
    /// genesis, deeper than the whole live chain, is adopted — selected AND
    /// applied — and a later extension of the old chain is an ordinary
    /// fork-loser. The DAG and the applied state never disagree.
    #[tokio::test(flavor = "multi_thread")]
    async fn heavier_fork_is_followed_at_any_depth() {
        const D: u64 = 6;
        let g_ts    = unix_now();
        let genesis = mk_genesis(g_ts);
        let node    = node_with_genesis(&genesis);
        let gh      = genesis.block_hash();

        // (a) Real chain R: genesis → r1 … r_{D+1}, all through accept_block.
        let mut parent = gh;
        for i in 1..=(D + 1) {
            let b = mk_block_at(&node, parent, i, g_ts + 30 * i, i);
            accept(&node, &b).expect("real-chain block must be accepted");
            parent = b.block_hash();
        }
        let real_tip = parent;
        assert_eq!(node.dag.read().selected_tip(), Some(real_tip));

        // (b) Fork F from genesis: f1 … f_{D+2}. f_{D+1} ties R's tip on
        // blue_work and is ground to lose the hash tie-break; f_{D+2}
        // strictly out-weighs R and needs a reorg of all D+1 blocks of R.
        let mut fparent = gh;
        let mut fork_tip = gh;
        for i in 1..=(D + 2) {
            let mut nonce = 1_000_000 + i;
            let mut fb = mk_block_at(&node, fparent, i, g_ts + 30 * i, nonce);
            if i == D + 1 {
                while fb.block_hash() >= real_tip {
                    nonce += 1;
                    fb = mk_block_at(&node, fparent, i, g_ts + 30 * i, nonce);
                }
            }
            let res = accept(&node, &fb);
            assert!(res.is_ok(), "fork block f{} must be accepted, got: {:?}", i, res);
            if i <= D + 1 {
                assert_eq!(node.dag.read().selected_tip(), Some(real_tip),
                    "fork-loser f{} must not move the selected tip", i);
            }
            fparent = fb.block_hash();
            fork_tip = fparent;
        }

        // (1) The heavier fork is followed: selected tip and applied tip.
        assert_eq!(node.dag.read().selected_tip(), Some(fork_tip));
        let tip_meta = node.store.get_meta("tip_hash").expect("meta read").expect("tip_hash");
        assert_eq!(tip_meta.as_slice(), &fork_tip[..], "the applied state follows the fork");

        // (2) An extension of the old chain that only TIES the fork (and is
        // ground to lose the hash tie-break) is a fork-loser: accepted into
        // the DAG, applied tip unchanged.
        let mut nonce = 424_242;
        let mut r_next = mk_block_at(&node, real_tip, D + 2, g_ts + 30 * (D + 2), nonce);
        while r_next.block_hash() >= fork_tip {
            nonce += 1;
            r_next = mk_block_at(&node, real_tip, D + 2, g_ts + 30 * (D + 2), nonce);
        }
        assert!(accept(&node, &r_next).is_ok());
        assert_eq!(node.dag.read().selected_tip(), Some(fork_tip));
        let tip_meta = node.store.get_meta("tip_hash").expect("meta read").expect("tip_hash");
        assert_eq!(tip_meta.as_slice(), &fork_tip[..]);
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

        // An old data dir may still carry a `finalized_height` meta key (here
        // 3). Since audit DAG-6 it is ignored: nothing below must change.
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

        // A stale `finalized_height` meta key (ignored since audit DAG-6).
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
