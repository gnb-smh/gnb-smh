//! Bloch-SIS Protocol — JSON-RPC over HTTP (axum)
//!
//! Methods:
//!   getnetworkinfo, getblockcount, getmempoolinfo,
//!   getblockhash, getblock, getblockbyheight, getrecentblocks,
//!   gettransaction, getbalance, getutxos,
//!   sendrawtransaction,
//!   validateaddress, estimatefee, getrawmempool,
//!   decoderawtransaction, getdaginfo, listtransactions, getpeerinfo,
//!   invalidateblock, reconsiderblock (admin: audit DAG-6)
//!
//! Mempool policy (audit MEM-6, `docs/MEMPOOL.md`): `sendrawtransaction`
//! accepts children of unconfirmed transactions (≤ 25 ancestors and
//! descendants, ≤ 500,000-byte packages) and applies FULL-RBF — a
//! transaction double-spending pooled ones replaces them iff it adds no new
//! unconfirmed input, pays a higher fee rate than each direct conflict, an
//! absolute fee ≥ the fees of everything it evicts plus 1 sat/byte of its own
//! size, and evicts ≤ 100 transactions (BIP125 rules 2–6, no signalling).
//! `getmempoolinfo` reports these parameters under `policy`.

pub mod auth;
mod explorer;


use std::sync::Arc;
use parking_lot::RwLock;
use log::{info, error};
use axum::{routing::post, Router, extract::State, extract::DefaultBodyLimit, http::StatusCode, Json};
use tower_http::cors::CorsLayer;
use tower_http::timeout::TimeoutLayer;
use tower::limit::GlobalConcurrencyLimitLayer;

/// P0 RPC hardening (roadmap §1.6 / §4.3).
/// Max request body: JSON-RPC calls are tiny; 1 MiB is generous and tighter
/// than axum's 2 MiB default. Blocks oversized-payload memory abuse.
const RPC_MAX_BODY_BYTES: usize = 1024 * 1024;
/// Global cap on concurrently in-flight RPC handlers, shared across all
/// connections (GlobalConcurrencyLimitLayer holds one Arc'd semaphore). Bounds
/// how many expensive storage-scanning methods can pile up at once. Value is a
/// conservative default — needs load-testing to tune (not yet done).
const RPC_MAX_CONCURRENCY: usize = 256;
/// Per-request wall-clock timeout (returns 408). Kills slow-loris / stuck
/// handlers so they can't hold a concurrency slot forever.
const RPC_REQUEST_TIMEOUT_SECS: u64 = 30;
/// L-9 (audit): the dispatch-level timeout `handle_rpc` races its
/// `spawn_blocking` `JoinHandle` against, strictly SHORTER than
/// `RPC_REQUEST_TIMEOUT_SECS` so this one fires first and gets the chance to
/// `abort()` the handle — the outer `TimeoutLayer` only ever dropped the
/// response future, which never cancelled the underlying blocking task. See
/// the long comment at the `tokio::select!` call site for what `.abort()`
/// can and cannot stop.
const DISPATCH_INNER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(RPC_REQUEST_TIMEOUT_SECS - 5);
use serde_json::{json, Value};
use crate::storage::{Storage, StorageError};
use crate::mempool::Mempool;
use crate::consensus::GhostDAG;
use crate::core::{Transaction, PROTOCOL_VERSION, MAINNET_PREFIX, TESTNET_PREFIX};
use tokio::sync::mpsc;
use crate::network::NetworkMessage;

#[derive(Clone, Debug, Default)]
pub struct NodeState {
    pub tip_blue_score: u64,
    pub block_count:    u64,
    pub peer_count:     u32,
    pub mempool_size:   usize,
    pub is_syncing:     bool,
    /// Highest tip blue-score any peer has announced (via PeerTip). Used to
    /// release the IBD latch: is_syncing clears once tip_blue_score catches up
    /// to this. (The old code only cleared on an empty Headers message, which
    /// no peer ever sends, so is_syncing — and the miner pause — latched
    /// forever and joining miners synced but never mined.)
    pub best_seen_blue_score: u64,
    /// Set once the node has processed at least one remote PeerTip. The
    /// fresh-miner fork guard waits for this so a joining miner never mines a
    /// genesis fork in the window between "connected" and "evaluated a tip".
    pub seen_first_tip: bool,
    /// Honest-RPC fix: highest blue_score announced by a CONNECTED peer,
    /// refreshed by every maybe_release_ibd re-test (event-driven + 30s
    /// nudge). UNTRUSTED wire hint — never gates consensus or the IBD latch;
    /// it exists so `getnetworkinfo` can report `best_announced`/`behind_by`
    /// and a lagging node SAYS it is lagging instead of just `syncing:false`.
    /// Differs from `best_seen_blue_score` (lifetime max over any peer ever,
    /// including long-gone ones): this one tracks currently-connected peers.
    pub best_announced_blue_score: u64,
    pub peer_addresses: Vec<String>,
    pub version:        String,
}

/// Block-submission hook — the B5f pool seam.
///
/// Stratum V1/V2 cannot carry the Module-SIS solution vector in their share
/// messages (see main.rs B5f), so external pools mine full SIS blocks and
/// hand them in over RPC instead. main.rs wires this with a closure that
/// mirrors the gossipsub NewBlock path: `Block::block_hash()` identity,
/// `validate_structure()` (PoW witness + merkle + coinbase), then the same
/// `accept_block` consensus pipeline, then network broadcast.
///
/// `None` (tests, or callers that don't wire it) makes `submitblock` return
/// a "not wired" error instead of silently accepting.
pub type SubmitBlockFn = dyn Fn(crate::core::Block) -> Result<String, String> + Send + Sync;

/// Operator chain overrides (audit DAG-6), Bitcoin Core's `invalidateblock`
/// and `reconsiderblock`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainAdminOp {
    /// Disqualify a block and its selected-chain descendants, persistently.
    Invalidate,
    /// Remove such disqualifications (the block, its selected-chain ancestors
    /// and descendants) and let the node re-evaluate them.
    Reconsider,
}

/// Hook that performs a [`ChainAdminOp`] on a block through the acceptance
/// pipeline (`accept::invalidate_block` / `accept::reconsider_block`), wired by
/// main.rs. Returns a JSON summary. `None` makes the methods report "not wired".
pub type ChainAdminFn = dyn Fn(ChainAdminOp, [u8; 32]) -> Result<Value, String> + Send + Sync;

#[derive(Clone, Debug)]
pub struct RpcConfig {
    pub bind_address:              String,
    pub port:                      u16,
    /// Sprint M: shared-secret API key. None = no auth layer.
    pub api_key:                   Option<String>,
    /// Sprint M: require X-API-Key for write methods (sendrawtransaction).
    pub require_auth_for_writes:   bool,
    /// Sprint M: per-IP read rate limit, requests/minute.
    pub rate_limit_reads_per_min:  u32,
    /// Sprint M: per-IP write rate limit, requests/minute.
    pub rate_limit_writes_per_min: u32,
    /// Sprint M-patch1: also trust RFC1918/ULA ranges as loopback.
    /// Needed when node runs in Docker with default bridge networking.
    /// SECURITY: only set true on trusted single-tenant hosts.
    pub trust_private_ranges:      bool,
    /// R3-audit H-R3-5: browser origins allowed to call this RPC (exact
    /// `scheme://host[:port]` values). Empty (default) = no browser origin is
    /// allowed: no CORS grants are emitted and any request carrying an
    /// `Origin` header is refused. `"*"` allows any origin for READ methods
    /// only — write methods never honour the wildcard.
    pub allowed_origins:           Vec<String>,
    /// R3-audit H-R3-5: extra hostnames accepted in the `Host` header
    /// (anti-DNS-rebinding). IP literals and `localhost` are always accepted;
    /// a reverse-proxy / tunnel hostname must be listed here. `"*"` disables
    /// the check.
    pub allowed_hosts:             Vec<String>,
    /// R3-audit H-R3-5: restore the historical "loopback bypasses auth"
    /// behaviour. Default false: loopback keeps its rate-limit exemption but
    /// must satisfy the same API-key policy as remote callers (a browser on
    /// the operator's machine connects from 127.0.0.1 — the blanket bypass
    /// made every local web page an authenticated operator).
    pub trust_loopback:            bool,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            bind_address:              "127.0.0.1".into(),
            port:                      17210,
            api_key:                   None,
            require_auth_for_writes:   false,
            rate_limit_reads_per_min:  60,
            rate_limit_writes_per_min: 5,
            trust_private_ranges:      false,
            allowed_origins:           Vec::new(),
            allowed_hosts:             Vec::new(),
            trust_loopback:            false,
        }
    }
}

#[derive(Clone)]
struct AppState {
    node_state:              Arc<RwLock<NodeState>>,
    store:                   Arc<Storage>,
    mempool:                 Arc<Mempool>,
    dag:                     Arc<RwLock<GhostDAG>>,
    outbound_tx:             mpsc::Sender<NetworkMessage>,
    // Sprint M additions:
    api_key:                 Option<String>,
    require_auth_for_writes: bool,
    // M-1 (audit): `--rpc-require-auth-for-reads` mode. This is a
    // `RpcConfig`/CLI-flag-shaped concern, but the flag parser lives in
    // `main.rs`, which is outside this change's ownership — read directly
    // from the environment instead (see `start_rpc_server` below), matching
    // the same env-var-not-main.rs-touching pattern used for M-6 in
    // `network/mod.rs`. `GNB_RPC_REQUIRE_AUTH_FOR_READS=1` (or `true`)
    // turns it on; unset/anything else leaves the historical
    // "reads are public" default untouched. A future change should promote
    // this to a proper `RpcConfig` field + `--rpc-require-auth-for-reads`
    // CLI flag wired in `main.rs`, mirroring `require_auth_for_writes`.
    require_auth_for_reads:  bool,
    rate_limiter:            Arc<auth::RateLimiterSet>,
    trust_private_ranges:    bool,
    // R3-audit H-R3-5: browser gate + loopback-auth policy + heavy-read bound.
    allowed_origins:         Arc<Vec<String>>,
    allowed_hosts:           Arc<Vec<String>>,
    trust_loopback:          bool,
    heavy_gate:              Arc<HeavyGate>,
    /// L-8: `getblocktemplate`'s own cache and build permit
    /// (`gated_dispatch`), so an analytics scan never answers a miner "busy".
    template_gate:           Arc<HeavyGate>,
    // B5f pool seam: submitblock hook (None = method returns "not wired").
    submit_block:            Option<Arc<SubmitBlockFn>>,
    // NET-12: cancellation flag of THIS request (a fresh flag per request,
    // set when the dispatch timeout fires); long loops check it.
    cancel:                  Arc<std::sync::atomic::AtomicBool>,
    // Audit DAG-6: invalidateblock / reconsiderblock hook.
    chain_admin:             Option<Arc<ChainAdminFn>>,
}

// ─── R3-audit H-R3-5 / L-8: bound the expensive analytics + template RPCs ───
//
// These methods did expensive per-call work. NET-12 (audit): the chain
// statistics, rich list, supply distribution and address count are now
// served from incremental aggregates (`storage::aggregates`) with bounded,
// cancellable work (`analytics::*_bounded`); they stay classed heavy (TTL
// cache + single flight) as defence in depth. Still genuinely heavy: the
// per-address history walk (`getaddressbalance_at_height`, streamed and
// cancellable), and `getblocktemplate` (L-8), which reads the
// DAG twice, walks parent ancestry to derive `bits`, and drains + serialises
// up to 2000 mempool transactions — on a port that, for the analytics
// methods, has no auth and, for loopback/private callers, no rate limit
// either, so a request loop stacks that cost without bound. The bound is
// structural: results are served from a short TTL cache, and at most ONE
// cache-missing computation runs at a time — a second concurrent caller gets
// an immediate "busy" error instead of stacking another full computation.
const HEAVY_READ_METHODS: &[&str] = &[
    "getsupplydistribution",
    "getrichlist",
    "getchainstats",
    "gethashrate",
    "getaddresscount",
    "getaddressbalance_at_height",
    // NET-12: chain-walking explorer reads. Both are now bounded walks of
    // the selected chain (see `explorer::get_difficulty_history` /
    // `explorer::get_block_time_percentiles`) instead of decoding every
    // block body, and additionally share the single-flight TTL cache.
    "getdifficultyhistory",
    "getblocktimepercentiles",
    // L-8 (audit): `getblocktemplate` is bounded the same way (cache +
    // single flight) but through its OWN gate (`AppState::template_gate`,
    // `gated_dispatch`): sharing this one's single scan permit answered a
    // miner "busy" whenever a public analytics scan was in flight.
];

/// NET-13: every method name `dispatch` implements. Metrics label anything
/// else as `"unknown"`, so a caller cannot mint unbounded Prometheus label
/// values, and logs show at most [`MAX_LOGGED_METHOD_LEN`] bytes of it.
/// `known_methods_list_matches_dispatch` keeps this list in sync.
const KNOWN_RPC_METHODS: &[&str] = &[
    "getnetworkinfo", "getblockcount", "getmempoolinfo", "getblockhash", "getblock",
    "getblockbyheight", "getrecentblocks", "gettransaction", "getrawtransaction", "getbalance",
    "getaddresscount", "getutxos", "sendrawtransaction", "validateaddress", "estimatefee",
    "getrawmempool", "decoderawtransaction", "getblocktemplate", "submitblock", "getdaginfo",
    "submitpowititem", "getpowitinfo",
    "listtransactions", "getpeerinfo", "getpeers", "getsupplyinfo", "getchainstats",
    "getsupplydistribution", "getselectedchain", "getblockdag", "gettransactionfull",
    "getdagwindow", "getaddresshistory", "getrichlist", "gethashrate", "getdifficultyhistory",
    "getblocktimepercentiles", "gettxstatus", "getaddressinfo", "estimatefeeadvanced",
    "getmempoolstats", "validateaddressverbose", "gettxsbyblock", "getaddressbalance_at_height",
    "getattestation", "invalidateblock", "reconsiderblock",
];

/// Longest method-name prefix written to a log line (NET-13).
const MAX_LOGGED_METHOD_LEN: usize = 48;

/// NET-16: pause before answering a request that failed authentication, so
/// key guessing is slow even from loopback (which skips the rate limiter).
const FAILED_AUTH_DELAY: std::time::Duration = std::time::Duration::from_millis(250);

/// Bounded metrics label for a method name (NET-13).
pub fn method_label(method: &str) -> &'static str {
    KNOWN_RPC_METHODS.iter().copied().find(|m| *m == method).unwrap_or("unknown")
}

/// Log-safe form of a caller-supplied method name: known names verbatim,
/// anything else truncated and debug-escaped (no control characters).
fn method_for_log(method: &str) -> String {
    match KNOWN_RPC_METHODS.iter().find(|m| **m == method) {
        Some(m) => (*m).to_string(),
        None => format!("{:?}", crate::network::truncate_utf8(method, MAX_LOGGED_METHOD_LEN)),
    }
}

/// NET-14: resolve a configured bind address (`127.0.0.1`, `0.0.0.0`,
/// `::1`, `[::1]`, `localhost`) and port into a socket address, with a
/// clear error instead of a failure deep inside the server task.
pub fn resolve_bind_address(host: &str, port: u16) -> Result<std::net::SocketAddr, String> {
    let bare = host.trim().trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = bare.parse::<std::net::IpAddr>() {
        return Ok(std::net::SocketAddr::new(ip, port));
    }
    use std::net::ToSocketAddrs;
    (bare, port).to_socket_addrs()
        .map_err(|e| format!("cannot resolve bind address {host:?}: {e}"))?
        .next()
        .ok_or_else(|| format!("bind address {host:?} resolves to nothing"))
}

/// TTL for cached heavy-read results. Analytics freshness of ~1 block is fine.
const HEAVY_READ_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(30);
/// L-8: how long a `getblocktemplate` result is served while its parents and
/// height are unchanged. A new tip misses the cache at once (`template_cache_key`); a
/// mempool change shows in the template within this time, which bounds the
/// rebuilds a polling miner causes on a busy pool to one per this interval
/// (Bitcoin Core rebuilds on a new tip, and on a mempool change at most every
/// 5 s).
const TEMPLATE_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(5);
/// Cap on distinct cached keys (parameterised methods could otherwise grow
/// the map unboundedly — the exact DoS shape this gate exists to close).
const HEAVY_READ_CACHE_MAX_KEYS: usize = 64;
/// Cap on cached templates (`HeavyGate::for_templates`). The template key
/// changes with every new block, so all but the newest entries are dead:
/// with the analytics cap of 64, a node kept up to 63 expired templates of
/// up to about 2 MB each (as JSON) for good. Expired entries are also dropped
/// on every insert; the few left cover two miners asking with different
/// params, or a parent set an invalidation brings back within the TTL.
const TEMPLATE_CACHE_MAX_KEYS: usize = 4;
/// The answer of the analytics gate while its single scan is in flight.
const HEAVY_BUSY: &str = "busy: another heavy analytics scan is in flight; retry shortly";
/// The answer of the template gate while another template is being built.
const TEMPLATE_BUSY: &str = "busy: another getblocktemplate build is in flight; retry shortly";

pub struct HeavyGate {
    ttl:   std::time::Duration,
    /// Most entries kept; expired ones are dropped on every insert, and the
    /// oldest when the map is still full.
    max_keys: usize,
    /// The error text for a caller that finds the permit taken.
    busy:  &'static str,
    cache: parking_lot::Mutex<std::collections::HashMap<String, (std::time::Instant, Value)>>,
    /// Held for the duration of a scan; `try_lock` makes concurrency-1 a hard
    /// bound with no queueing (queueing would just move the pile-up).
    scan:  parking_lot::Mutex<()>,
}

impl HeavyGate {
    /// The analytics gate (`HEAVY_READ_METHODS`): `ttl`, at most
    /// `HEAVY_READ_CACHE_MAX_KEYS` results.
    pub fn new(ttl: std::time::Duration) -> Self {
        Self::with_limits(ttl, HEAVY_READ_CACHE_MAX_KEYS, HEAVY_BUSY)
    }

    /// `getblocktemplate`'s own gate (L-8): `TEMPLATE_CACHE_TTL`, at most
    /// `TEMPLATE_CACHE_MAX_KEYS` templates, and a "busy" answer that names
    /// the template build, not an analytics scan.
    pub fn for_templates() -> Self {
        Self::with_limits(TEMPLATE_CACHE_TTL, TEMPLATE_CACHE_MAX_KEYS, TEMPLATE_BUSY)
    }

    fn with_limits(ttl: std::time::Duration, max_keys: usize, busy: &'static str) -> Self {
        Self {
            ttl,
            max_keys: max_keys.max(1),
            busy,
            cache: parking_lot::Mutex::new(std::collections::HashMap::new()),
            scan:  parking_lot::Mutex::new(()),
        }
    }

    pub fn is_heavy(method: &str) -> bool {
        HEAVY_READ_METHODS.contains(&method)
    }

    /// Serve `key` from cache when fresh; otherwise run `f` under the single
    /// scan permit. A caller that can neither hit the cache nor take the
    /// permit gets an error Value immediately (bounded, non-queueing).
    pub fn run<F: FnOnce() -> Value>(&self, key: String, f: F) -> Value {
        let store_key = key.clone();
        self.run_keyed(key, f, move |_| Some(store_key))
    }

    /// [`Self::run`], but a computed result is stored under
    /// `store_key(&result)` (`None`: not stored) instead of under `key`: the
    /// key of what the result was actually computed from, when that can
    /// differ from what `key` was read from (`getblocktemplate`: a block
    /// accepted between reading `key` and the build changes the parents the
    /// template is built on). A hit on a key then only ever returns a result
    /// computed from what the key names.
    pub fn run_keyed<F, K>(&self, key: String, f: F, store_key: K) -> Value
    where
        F: FnOnce() -> Value,
        K: FnOnce(&Value) -> Option<String>,
    {
        let now = std::time::Instant::now();
        if let Some((at, v)) = self.cache.lock().get(&key) {
            if now.duration_since(*at) < self.ttl {
                return v.clone();
            }
        }
        match self.scan.try_lock() {
            Some(_permit) => {
                let v = f();
                // NET-12: never cache a failure (a cancelled or not-ready
                // computation must not answer the next caller for 30 s).
                if v.get("error").is_some() {
                    return v;
                }
                let Some(store_key) = store_key(&v) else { return v };
                let now = std::time::Instant::now();
                let mut cache = self.cache.lock();
                // Expired entries are dead (never served again): drop them on
                // every insert, then the oldest while the map is still full.
                cache.retain(|_, (at, _)| now.duration_since(*at) < self.ttl);
                if !cache.contains_key(&store_key) {
                    while cache.len() >= self.max_keys {
                        let Some(oldest) = cache.iter().min_by_key(|(_, (at, _))| *at).map(|(k, _)| k.clone())
                            else { break };
                        cache.remove(&oldest);
                    }
                }
                cache.insert(store_key, (now, v.clone()));
                v
            }
            None => json!({ "error": self.busy }),
        }
    }
}

/// R3-audit H-R3-5: the CORS layer this server actually mounts.
///
/// Replaces `CorsLayer::permissive()`, which reflected EVERY origin (with
/// methods and headers) and thereby let any web page preflight its way into
/// `sendrawtransaction`. Policy:
///   - empty allowlist (default): `CorsLayer::new()` — no CORS grants at all;
///   - `"*"`: any origin may make CORS requests, but the per-request Origin
///     gate in `handle_rpc` still refuses write methods (wildcard never
///     applies to writes);
///   - otherwise: exactly the listed origins.
/// Credentials are never allowed; the API key travels in explicit headers.
fn build_cors_layer(allowed_origins: &[String]) -> CorsLayer {
    use axum::http::{HeaderValue, Method, header};
    let base = CorsLayer::new()
        .allow_methods([Method::POST])
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            header::HeaderName::from_static("x-api-key"),
        ]);
    if allowed_origins.is_empty() {
        // No allow-origin is ever emitted; browsers refuse the response.
        CorsLayer::new()
    } else if allowed_origins.iter().any(|o| o == "*") {
        base.allow_origin(tower_http::cors::Any)
    } else {
        let origins: Vec<HeaderValue> = allowed_origins
            .iter()
            .filter_map(|o| HeaderValue::from_str(o.trim_end_matches('/')).ok())
            .collect();
        base.allow_origin(tower_http::cors::AllowOrigin::list(origins))
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn start_rpc_server(
    config:      RpcConfig,
    state:       Arc<RwLock<NodeState>>,
    store:       Arc<Storage>,
    mempool:     Arc<Mempool>,
    dag:         Arc<RwLock<GhostDAG>>,
    outbound_tx: mpsc::Sender<NetworkMessage>,
    // B5f pool seam — see `SubmitBlockFn`.
    submit_block: Option<Arc<SubmitBlockFn>>,
    // Audit DAG-6 — see `ChainAdminFn`.
    chain_admin: Option<Arc<ChainAdminFn>>,
) {
    // NET-14: `format!("{host}:{port}")` could not express IPv6 hosts such as
    // `::1`; resolve explicitly and report a bad address clearly. main.rs
    // validates the same way at start-up, before the node starts.
    let addr = match resolve_bind_address(&config.bind_address, config.port) {
        Ok(a) => a,
        Err(e) => {
            error!("RPC: {}; the RPC service is not running (the node keeps running)", e);
            return;
        }
    };

    // L-6 (audit): validate the configured key BEFORE it is ever compared
    // against anything, regardless of how the caller sourced it
    // (`--rpc-api-key` directly, or `--rpc-api-key-file` read by main.rs).
    // Nothing previously prevented `--rpc-api-key x` (a one-character
    // "secret" the constant-time comparison then faithfully protects) or a
    // key containing control characters (a header-injection primitive
    // wherever it is later interpolated into raw text — see `bin/gnb-cli.rs`'s
    // M-11 fix). Refuse to start the RPC service on an invalid key rather
    // than silently running with one that provides no real protection, or
    // silently treating it as "no key" (which would DISABLE auth instead).
    if let Some(k) = &config.api_key {
        if let Err(reason) = auth::validate_api_key(k) {
            error!("RPC: configured API key is invalid ({}); refusing to start the RPC service. \
                    Fix --rpc-api-key / --rpc-api-key-file and restart.", reason);
            return;
        }
    }

    let rate_limiter = Arc::new(auth::RateLimiterSet::new(
        config.rate_limit_reads_per_min,
        config.rate_limit_writes_per_min,
    ));

    // M-1: see the field doc on `AppState::require_auth_for_reads`.
    let require_auth_for_reads = std::env::var("GNB_RPC_REQUIRE_AUTH_FOR_READS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if require_auth_for_reads && config.api_key.is_none() {
        // Fail-safe, loudly: the auth layer itself refuses every
        // non-trusted read in this configuration (see
        // `auth::authorize_with_read_policy`'s fail-safe doc), but an
        // operator who set the flag almost certainly meant to configure a
        // key too — say so instead of silently locking the RPC surface.
        log::warn!(
            "GNB_RPC_REQUIRE_AUTH_FOR_READS is set but no --rpc-api-key is \
             configured: every non-trusted read will be refused (fail-safe, \
             not a bug) until a key is configured"
        );
    }

    let app_state = AppState {
        node_state: state,
        store,
        mempool,
        dag,
        outbound_tx,
        api_key:                 config.api_key.clone(),
        require_auth_for_writes: config.require_auth_for_writes,
        require_auth_for_reads,
        rate_limiter,
        trust_private_ranges:    config.trust_private_ranges,
        allowed_origins:         Arc::new(config.allowed_origins.clone()),
        allowed_hosts:           Arc::new(config.allowed_hosts.clone()),
        trust_loopback:          config.trust_loopback,
        heavy_gate:              Arc::new(HeavyGate::new(HEAVY_READ_CACHE_TTL)),
        template_gate:           Arc::new(HeavyGate::for_templates()),
        submit_block,
        cancel:                  Arc::new(std::sync::atomic::AtomicBool::new(false)),
        chain_admin,
    };

    // P0 RPC hardening (roadmap §1.6 / §4.3): body-size cap, global
    // concurrency limit, and a per-request timeout on top of the existing
    // per-IP auth/rate-limit.
    // R3-audit H-R3-5: the CORS layer is restrictive (see build_cors_layer);
    // Host/Origin are additionally checked per request in handle_rpc.
    let app = Router::new()
        .route("/", post(handle_rpc))
        .layer(build_cors_layer(&config.allowed_origins))
        .layer(DefaultBodyLimit::max(RPC_MAX_BODY_BYTES))
        .layer(GlobalConcurrencyLimitLayer::new(RPC_MAX_CONCURRENCY))
        .layer(TimeoutLayer::new(std::time::Duration::from_secs(RPC_REQUEST_TIMEOUT_SECS)))
        .with_state(app_state);

    info!("RPC on {} (auth={}, require_auth_writes={}, trust_private={}, trust_loopback={}, origins={:?}, hosts={:?}, limits: {}r/min, {}w/min)",
        addr,
        config.api_key.is_some(),
        config.require_auth_for_writes,
        config.trust_private_ranges,
        config.trust_loopback,
        config.allowed_origins,
        config.allowed_hosts,
        config.rate_limit_reads_per_min,
        config.rate_limit_writes_per_min,
    );
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l)  => l,
        Err(e) => {
            error!("RPC bind {} failed: {}; the RPC service is not running (the node keeps running)", addr, e);
            return;
        }
    };
    // Sprint M: connect_info makes the client IP available to handlers.
    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    ).await {
        error!("RPC error: {}", e);
    }
}

/// L-5 (audit): storage errors used to be returned to RPC callers verbatim
/// (`json!({ "error": e.to_string() })`) at every one of this file's ~13
/// `state.store.*` call sites. `StorageError::ReadFailed` / `OpenFailed` /
/// `WriteFailed` wrap the underlying RocksDB error message
/// (`storage/mod.rs`'s `From<rocksdb::Error>` / explicit `.map_err`s), which
/// can include filesystem paths and column-family/engine internals — none of
/// which an unauthenticated caller (see M-1: reads are public by default) has
/// any business receiving. INVARIANT (L-5): the detail is logged
/// server-side, at a level an operator will see; the caller gets a stable,
/// content-free error code and message, identical across every storage
/// failure mode so nothing about the underlying condition leaks through
/// message shape either.
/// L-10 (audit): max bytes an echoed JSON-RPC `id` string may occupy in the
/// response. JSON-RPC 2.0 ids are meant to be short correlation tokens, not
/// payload; nothing legitimate needs anywhere near this much.
const MAX_ECHOED_ID_LEN: usize = 256;

/// L-10: normalize the request's `id` to a shape and size safe to echo back
/// unconditionally. A string is truncated (UTF-8-safely — see
/// `network::truncate_utf8`) rather than rejected outright, so a client
/// using a slightly-too-long-but-otherwise-legitimate correlation id still
/// gets a response, just a truncated echo of what it sent (a client cannot
/// reasonably rely on more than JSON-RPC 2.0 itself promises, which is
/// "echo the id", not "echo it losslessly at any length"). A `bool`,
/// `array`, or `object` id is not spec-compliant at all and is replaced with
/// `null` rather than echoed.
/// L-11 (audit): the JSON-RPC 2.0 error body for an unsupported batch
/// (top-level JSON array) request. Extracted so the exact code/shape is
/// unit-testable without constructing axum extractors.
fn batch_not_supported_response() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id":      Value::Null,
        "error":   { "code": -32600, "message": "Invalid Request: batch requests are not supported" },
    })
}

fn cap_echoed_id(id: Value) -> Value {
    match id {
        Value::String(s) => {
            Value::String(crate::network::truncate_utf8(&s, MAX_ECHOED_ID_LEN).to_string())
        }
        v @ (Value::Number(_) | Value::Null) => v,
        _ => Value::Null,
    }
}

/// Current Unix time in seconds.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// MEM-6: the node's transaction relay policy, as reported by
/// `getmempoolinfo` (normative text: docs/MEMPOOL.md).
fn mempool_policy_json() -> Value {
    use crate::mempool as m;
    json!({
        "replacement": "full-rbf: a conflicting transaction replaces pooled ones iff it adds no new unconfirmed input, \
                        pays a higher fee rate than each direct conflict, an absolute fee >= the sum of every evicted \
                        transaction's fee plus the incremental relay fee on its own size, and evicts at most \
                        max_replacement_evictions transactions (BIP125 rules 2-6, no signalling)",
        "max_replacement_evictions": m::MAX_REPLACEMENT_EVICTIONS,
        "incremental_relay_fee_sat_per_byte": m::INCREMENTAL_RELAY_FEE_RATE,
        "min_relay_fee_sat_per_byte": m::MIN_RELAY_FEE_RATE,
        "unconfirmed_chains": true,
        "max_ancestors": m::MAX_ANCESTORS,
        "max_descendants": m::MAX_DESCENDANTS,
        "max_package_bytes": m::MAX_PACKAGE_BYTES,
        "block_template_selection": "ancestor-package fee rate (child pays for parent)",
        "orphan_pool": {
            "max_transactions": m::orphanage::MAX_ORPHAN_TXS,
            "max_bytes": m::orphanage::MAX_ORPHAN_BYTES,
            "max_per_peer": m::orphanage::MAX_ORPHANS_PER_PEER,
            "max_bytes_per_peer": m::orphanage::MAX_ORPHAN_BYTES_PER_PEER,
            "expiry_secs": m::orphanage::ORPHAN_EXPIRY_SECS,
            "max_inputs": m::orphanage::MAX_ORPHAN_INPUTS,
            "keyed_by": "wtxid; quotas per delivering connection",
        },
        "signature_budget": {
            "keyed_by": "delivering connection (gossip propagation_source)",
            "burst_input_signatures": m::relay::SIG_BUDGET_BURST,
            "refill_per_sec": m::relay::SIG_BUDGET_REFILL_PER_SEC,
            "refunded_on_admission": true,
        },
        "expiry_secs": m::MEMPOOL_EXPIRY_SECS,
        "max_tx_bytes": m::MAX_TX_SIZE,
    })
}

fn storage_err_response(e: &StorageError) -> Value {
    log::warn!("rpc: storage error (detail withheld from caller): {}", e);
    json!({ "error": "internal storage error", "code": "STORAGE_ERROR" })
}

/// The response for a failed explorer statistic: a storage failure gets the
/// sanitised L-5 response (its detail only reaches the log); cancellation,
/// not-ready and no-tip keep their plain message (HeavyGate never caches
/// any of them).
fn stats_err_response(e: &crate::analytics::StatsError) -> Value {
    match e {
        crate::analytics::StatsError::Storage(se) => storage_err_response(se),
        other => json!({ "error": other.to_string() }),
    }
}

/// Height of the selected tip — the number a confirmation count is relative to.
///
/// # Why this exists as a function
///
/// Three call sites computed confirmations as `node_state.block_count - height`,
/// subtracting a block's **height** from the DAG's **block count**. In a chain
/// those two numbers are the same and the bug is invisible; in a BlockDAG they
/// are not, because parallel blocks are kept rather than orphaned. Measured on
/// mainnet 2026-08-13: chain height 39,837, DAG block count 50,606 — an offset
/// of 10,769.
///
/// The consequence was not a cosmetic off-by-N. `gettxstatus` calls anything
/// with 100+ confirmations `final`, so **every mined transaction reported
/// final immediately**, and an exchange gating deposits on that field would
/// have credited at depth 1 while believing it waited. The failure was silent
/// and in the direction that costs the integrator money.
///
/// One definition, called three times — not three call sites each free to pick
/// a plausible-looking counter.
fn selected_tip_height(state: &AppState) -> u64 {
    let dag = state.dag.read();
    dag.selected_tip()
        .and_then(|h| dag.get_block_data(&h).map(|d| d.height))
        .unwrap_or(0)
}

/// Cache key of a `getblocktemplate` call: its params, and the parents and
/// header height the template would be built on
/// (`template::template_parents_and_height`, the template builder's own
/// choice), so anything that changes them misses the cache at once: a new
/// block, an `invalidateblock` / `reconsiderblock` (DAG-6: the tip SET is
/// unchanged, only which tips are valid), a parent's body arriving (a
/// header-only tip is not an eligible parent). The template's bits, blue
/// score, subsidy and UTXO view are functions of the parents and height.
/// Keyed by params alone, a template was served for up to 30 s after a new
/// block: parents a block behind, so an external miner kept building forks of
/// the tip (test/functional/mining_getblocktemplate_submitblock.py). Mempool
/// changes are not in the key: they show in the template within
/// `TEMPLATE_CACHE_TTL` (a pool-digest key missed on every admission, so a
/// miner polling a busy pool rebuilt the template on every call, and
/// computing the digest copied every pool txid).
///
/// This is the LOOKUP key, read under `dag.read()` only, before the build.
/// The builder takes the acceptance lock and chooses the parents again, so a
/// block accepted in between gives a template on other parents. A template
/// is therefore stored under the key of the parents and height it carries
/// ([`template_result_key`]), which equals this one only when nothing
/// changed in between.
fn template_cache_key(params: Option<&Value>, state: &AppState) -> String {
    let (parents, height) = {
        let dag = state.dag.read();
        crate::template::template_parents_and_height(&dag, &state.store)
    };
    template_cache_key_for(params, parents.iter().map(|p| p.as_slice()), height)
}

/// The template cache key of `params` and a template on `parents` (in
/// template order) at header `height`.
fn template_cache_key_for<'a>(params: Option<&Value>, parents: impl IntoIterator<Item = &'a [u8]>, height: u64) -> String {
    use sha3::{Digest as _, Sha3_256};
    // Order kept: the first parent is the template's selected parent.
    let mut h = Sha3_256::new();
    for p in parents {
        h.update(p);
    }
    format!("getblocktemplate|{}|parents={}|height={}",
        params.map(|p| p.to_string()).unwrap_or_default(), hex::encode(h.finalize()), height)
}

/// The key a built template is stored under: the `parents` and `height` it
/// was built on (its own fields), so a cache hit on a key only ever returns
/// a template on the parents that key names. Keyed by the lookup key, a
/// template built on a block X accepted during the build was stored under
/// the key of the parents before X, and after an `invalidateblock X` brought
/// those parents back, the next call within `TEMPLATE_CACHE_TTL` was served
/// a template on the invalidated X. `None` (not stored) for anything that is
/// not a template.
fn template_result_key(params: Option<&Value>, template: &Value) -> Option<String> {
    let parents = template.get("parents")?.as_array()?.iter()
        .map(|p| p.as_str().and_then(|h| hex::decode(h).ok()))
        .collect::<Option<Vec<Vec<u8>>>>()?;
    let height = template.get("height")?.as_u64()?;
    Some(template_cache_key_for(params, parents.iter().map(Vec::as_slice), height))
}

/// Run one dispatch `f` behind the bound its method needs (L-8 / H-R3-5):
/// `getblocktemplate` through its own gate (looked up by `template_cache_key`,
/// stored by `template_result_key`, `TEMPLATE_CACHE_TTL`,
/// `TEMPLATE_CACHE_MAX_KEYS`), the heavy analytics reads through the HeavyGate
/// (method|params key, `HEAVY_READ_CACHE_TTL`), everything else directly.
/// Separate gates: a public analytics scan holding the HeavyGate's single
/// permit must not answer a miner's template request "busy".
fn gated_dispatch<F: FnOnce() -> Value>(method: &str, params: Option<&Value>, state: &AppState, f: F) -> Value {
    if method == "getblocktemplate" {
        state.template_gate.run_keyed(template_cache_key(params, state), f,
            |template| template_result_key(params, template))
    } else if HeavyGate::is_heavy(method) {
        let key = format!("{}|{}", method, params.map(|p| p.to_string()).unwrap_or_default());
        state.heavy_gate.run(key, f)
    } else {
        f()
    }
}

async fn handle_rpc(
    State(state): State<AppState>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(req):    Json<Value>,
) -> (StatusCode, Json<Value>) {
    // L-11 (audit): a top-level JSON ARRAY (a JSON-RPC 2.0 batch request,
    // which this server does not implement) used to fall through silently:
    // `req["method"]` on a `Value::Array` indexes to `Null` (the `&str`
    // `Index` impl only matches objects), so `method` became the empty
    // string and dispatch's catch-all returned `"unknown method: "` with
    // HTTP 200 — a standards-conformant client sees a "success" response
    // that is actually nonsensical. Detect the shape explicitly and answer
    // with the JSON-RPC 2.0 code for it.
    if req.is_array() {
        crate::metrics::inc_rpc_request("batch", "invalid_request");
        log::info!("rpc denied ip={} reason=batch_request_unsupported", addr.ip());
        return (StatusCode::BAD_REQUEST, Json(batch_not_supported_response()));
    }

    let method = req["method"].as_str().unwrap_or("");
    // NET-13: bounded label for metrics/spans, truncated form for logs.
    let label = method_label(method);
    let method_log = method_for_log(method);
    // L-10 (audit): the `id` used to be echoed back completely unbounded —
    // a ~1 MiB `id` string in the request produced a ~1 MiB response, at
    // zero cost to the attacker and real memory pressure for the node.
    // JSON-RPC 2.0 itself expects `id` to be a string, number, or null;
    // `cap_echoed_id` enforces exactly that shape and bounds the string case.
    let id     = cap_echoed_id(req.get("id").cloned().unwrap_or(json!(null)));
    let params = req.get("params");

    let client_ip = addr.ip();
    let presented_key = auth::extract_api_key(&headers);

    // R3-audit H-R3-5: Host + Origin gate BEFORE auth/rate-limit. Refuses
    // DNS-rebinding (hostile hostname in Host) and browser-borne CSRF (an
    // Origin the operator did not allowlist; wildcard never covers writes).
    let host_hdr   = headers.get(axum::http::header::HOST).and_then(|v| v.to_str().ok());
    let origin_hdr = headers.get(axum::http::header::ORIGIN).and_then(|v| v.to_str().ok());
    if let Err(refusal) = auth::gate_browser_request(
        host_hdr,
        origin_hdr,
        method,
        &state.allowed_hosts,
        &state.allowed_origins,
    ) {
        crate::metrics::inc_rpc_request(label, "forbidden");
        log::info!("rpc denied ip={} method={} reason={:?} host={:?} origin={:?}",
            client_ip, method_log, refusal,
            host_hdr.map(|h| crate::network::truncate_utf8(h, 128)),
            origin_hdr.map(|o| crate::network::truncate_utf8(o, 128)));
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "jsonrpc": "2.0",
                "id":      id,
                "error":   { "code": -32003, "message": "forbidden: request refused by Host/Origin policy" },
            })),
        );
    }

    let decision = auth::authorize_with_read_policy(
        client_ip,
        method,
        presented_key,
        state.api_key.as_deref(),
        state.require_auth_for_writes,
        state.require_auth_for_reads,
        state.trust_private_ranges,
        state.trust_loopback,
        &state.rate_limiter,
    );

    match decision {
        auth::AuthDecision::Allow => {
            let start = std::time::Instant::now();
            // P1 (roadmap §2): per-request tracing span, correlated with the
            // existing `rpc_requests{method,status}` metric so a slow method is
            // traceable to a client. `.instrument()` (not an entered guard) is
            // the correct form across the `dispatch` await. Inert unless a
            // subscriber is installed (init lives in main.rs, not owned here).
            use tracing::Instrument;
            // The dispatch arms below do their work INLINE and BLOCKING:
            // parking_lot acquisitions on `node_state`/`dag` and synchronous
            // RocksDB reads, none of which yield. Running that directly on a
            // tokio worker means a writer holding `node_state` (main.rs:2303,
            // :2352, :2910, :3080) parks the worker for as long as it holds the
            // lock. With `#[tokio::main]` defaulting worker_threads to the core
            // count — 2 on the production box — two stalled requests park the
            // WHOLE runtime, so it stops accepting connections at all.
            //
            // Measured on the producer, 2026-08-09: getblockcount took 30.01s
            // and 20.42s back to back while createauxblock returned in 0.01s.
            // The pool proxy times out at 10s and retries ~1/s, so the accept
            // queue filled (129 pending against a backlog of 128) and the node
            // never recovered on its own — only a restart cleared it, which is
            // why a watchdog was papering over this.
            //
            // Hand the whole dispatch to the blocking pool so worker threads
            // stay free to accept and poll. `block_on` is legal here precisely
            // because a spawn_blocking thread is not a runtime worker.
            // NET-12: a cancellation flag per request; the inner timeout
            // below sets it, and every long loop of a heavy method checks
            // it, so a timed-out scan stops instead of running on.
            let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let mut d_state = state.clone();
            d_state.cancel = cancel.clone();
            let d_method = method.to_string();
            let d_params = params.cloned();
            let d_handle = tokio::runtime::Handle::current();
            let join_handle = tokio::task::spawn_blocking(move || {
                // R3-audit H-R3-5 / L-8: heavy O(chain) analytics reads and
                // getblocktemplate go through their gates — TTL cache + at
                // most one computation in flight per gate.
                gated_dispatch(&d_method, d_params.as_ref(), &d_state, || {
                    d_handle.block_on(dispatch(&d_method, d_params.as_ref(), &d_state))
                })
            });
            // L-9 (audit): the outer `TimeoutLayer` (tower-http) previously
            // was the ONLY thing standing between a stuck dispatch and a
            // permanently-occupied blocking-pool slot — and it drops the
            // RESPONSE future, which drops the `JoinHandle` value inline
            // above without ever calling `.abort()`. Dropping a
            // `tokio::task::JoinHandle` does NOT cancel the task it points
            // to: for `spawn_blocking`, the closure keeps running on its
            // blocking thread to completion regardless, so a timed-out
            // `getsupplydistribution` (H-6) kept loading the chain while a
            // fresh request was admitted in its place — the exact
            // "watchdog is papering over an unbounded background cost"
            // shape this file's own comments elsewhere warn about.
            //
            // Fix: race the dispatch against an INNER timeout, strictly
            // shorter than the outer `RPC_REQUEST_TIMEOUT_SECS`, so this
            // arm — not the outer layer's unconditional drop — is what
            // decides the outcome and can act on it. `abort_handle()` is
            // taken before the handle is consumed by `.instrument()` below,
            // so it stays independently usable to cancel from the other
            // `select!` arm.
            //
            // HONESTY: `.abort()` on an ALREADY-RUNNING blocking closure
            // cannot preempt it mid-execution (the OS thread runs the
            // closure to completion regardless — this is a `spawn_blocking`
            // limitation, not a bug in this fix); the queued case is where
            // this has full effect: a task that has not yet started
            // executing on the blocking pool is guaranteed to never run at
            // all once aborted. Either way, THIS request's response path
            // returns immediately at the inner deadline instead of holding
            // the connection until the outer layer's drop.
            let abort_handle = join_handle.abort_handle();
            let result = tokio::select! {
                r = join_handle.instrument(tracing::info_span!(
                    "rpc_request",
                    method = label,
                    client_ip = %client_ip,
                    id = %id,
                )) => {
                    r.unwrap_or_else(|e| {
                        log::error!("rpc dispatch task failed: {}", e);
                        json!({ "error": "internal dispatch failure" })
                    })
                }
                _ = tokio::time::sleep(DISPATCH_INNER_TIMEOUT) => {
                    abort_handle.abort();
                    cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                    log::warn!(
                        "rpc dispatch timed out for method={} ip={} after {:?}; aborted \
                         (queued work is cancelled; already-running work finishes in the \
                         background but this response does not wait for it)",
                        method_log, client_ip, DISPATCH_INNER_TIMEOUT
                    );
                    json!({ "error": "internal dispatch timeout" })
                }
            };
            let elapsed = start.elapsed();
            let elapsed_ms = elapsed.as_millis();
            crate::metrics::observe_rpc_latency(label, elapsed.as_secs_f64());
            crate::metrics::inc_rpc_request(label, "ok");
            log::debug!("rpc ok ip={} method={} took={}ms", client_ip, method_log, elapsed_ms);
            (
                StatusCode::OK,
                Json(json!({ "jsonrpc": "2.0", "id": id, "result": result })),
            )
        }
        auth::AuthDecision::Unauthorized => {
            crate::metrics::inc_rpc_request(label, "unauthorized");
            log::info!("rpc denied ip={} method={} reason=unauthorized", client_ip, method_log);
            // NET-16: slow down key guessing (async sleep: no worker blocked).
            tokio::time::sleep(FAILED_AUTH_DELAY).await;
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "jsonrpc": "2.0",
                    "id":      id,
                    "error":   { "code": -32001, "message": "unauthorized: valid X-API-Key required" },
                })),
            )
        }
        auth::AuthDecision::RateLimited => {
            crate::metrics::inc_rpc_request(label, "rate_limited");
            log::info!("rpc denied ip={} method={} reason=rate_limited", client_ip, method_log);
            (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({
                    "jsonrpc": "2.0",
                    "id":      id,
                    "error":   { "code": -32002, "message": "rate limit exceeded; retry after a minute" },
                })),
            )
        }
    }
}

/// `invalidateblock` / `reconsiderblock`: params `[block_hash_hex]`.
fn chain_admin_call(op: ChainAdminOp, params: Option<&Value>, state: &AppState) -> Value {
    let hex_str = params.and_then(|p| p.get(0)).and_then(|v| v.as_str()).unwrap_or("");
    let hash: [u8; 32] = match hex::decode(hex_str).ok().and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok()) {
        Some(h) => h,
        None => return json!({ "error": "expected one parameter: a 64-hex-character block hash" }),
    };
    match &state.chain_admin {
        None => json!({ "error": "invalidateblock/reconsiderblock not wired on this node" }),
        Some(hook) => match hook(op, hash) {
            Ok(v) => v,
            Err(e) => json!({ "error": e }),
        },
    }
}

async fn dispatch(method: &str, params: Option<&Value>, state: &AppState) -> Value {
    match method {
        "getnetworkinfo" => {
            let s = state.node_state.read();
            let pruned_h = state.store.pruned_height();
            json!({
                // The chain this node runs (`--testnet`), as set once at
                // start-up. Was the literal "mainnet" on every node
                // (test/functional/feature_test_build_guard.py).
                "network":         match crate::core::node_chain_id() {
                    crate::core::ChainId::Testnet => "testnet",
                    crate::core::ChainId::Mainnet => "mainnet",
                },
                "version":         s.version,
                // The hardening activation height this binary enforces on its
                // chain (builds before 0.1.1 do not report the field), so an
                // operator can confirm the upgrade (docs/RUNNING.md).
                "hardening_activation_height": crate::core::activation::hardening_activation_height(),
                "protocol":        PROTOCOL_VERSION,
                "net_protocol":    crate::network::PROTOCOL_VERSION,
                "blue_score":      s.tip_blue_score,
                "blocks":          s.block_count,
                "peers":           s.peer_count,
                "mempool":         s.mempool_size,
                "syncing":         s.is_syncing,
                // Honest-lag fields: `best_announced` is the highest blue_score
                // any CONNECTED peer claims (untrusted hint); `behind_by` is how
                // far our selected tip trails it. A node that gave up on an
                // unreachable frontier used to report syncing:false and NOTHING
                // else — operators and the explorer could not see real lag.
                // behind_by > 0 with syncing:false means "released by the lag
                // tolerance or gave up", not "provably at the network tip".
                "best_announced":  s.best_announced_blue_score,
                "behind_by":       s.best_announced_blue_score.saturating_sub(s.tip_blue_score),
                "chain":           "gnb",
                "pruned_height":   pruned_h,
            })
        }
        "getblockcount"  => json!(state.node_state.read().block_count),
        // MEM-6: the size plus the relay policy in force (docs/MEMPOOL.md).
        "getmempoolinfo" => json!({
            "size":                 state.node_state.read().mempool_size,
            "bytes":                state.mempool.size_bytes(),
            "rolling_min_fee_rate_sat_per_byte": state.mempool.rolling_min_fee_rate(),
            "policy":               mempool_policy_json(),
        }),

        "getblockhash" => {
            let height = params.and_then(|p| p.get(0)).and_then(|v| v.as_u64()).unwrap_or(0);
            match state.store.get_block_hash_at_height(height) {
                Ok(Some(h)) => json!(hex::encode(h)),
                Ok(None)    => json!({ "error": "height not found" }),
                Err(e)      => storage_err_response(&e),
            }
        }

        // ── Block explorer: full block with transaction details ──────
        "getblock" => {
            let hash_hex = params.and_then(|p| p.get(0)).and_then(|v| v.as_str()).unwrap_or("");
            let verbose  = params.and_then(|p| p.get(1)).and_then(|v| v.as_bool()).unwrap_or(false);
            match hex::decode(hash_hex).ok().and_then(|b| <[u8;32]>::try_from(b).ok()) {
                Some(hash) => match state.store.get_block(&hash) {
                    Ok(Some(b)) => {
                        let mut result = json!({
                            "hash":        hash_hex,
                            "height":      b.height,
                            "blue_score":  b.blue_score,
                            "tx_count":    b.transactions.len(),
                            "timestamp":   b.header.timestamp,
                            "bits":        format!("0x{:08x}", b.header.bits),
                            "nonce":       b.header.nonce,
                            "parents":     b.header.parents.iter().map(|p| hex::encode(p)).collect::<Vec<_>>(),
                            "merkle_root": hex::encode(b.header.merkle_root),
                            "size":        b.size_bytes(),
                            "pow":         crate::core::pow_algo(b.height).name(),
                        });
                        if crate::core::powit_active(b.height) {
                            result["powit"] = format_powit(&b.powit);
                        }
                        if verbose {
                            result["transactions"] = json!(b.transactions.iter().map(|tx| {
                                format_tx(tx)
                            }).collect::<Vec<_>>());
                        } else {
                            result["txids"] = json!(b.transactions.iter().map(|tx| {
                                hex::encode(tx.txid())
                            }).collect::<Vec<_>>());
                        }
                        result
                    },
                    Ok(None)  => json!({ "error": "not found" }),
                    Err(e)    => storage_err_response(&e),
                },
                None => json!({ "error": "invalid hash" }),
            }
        }

        // ── Block explorer: get block by height ──────────────────────
        "getblockbyheight" => {
            let height = params.and_then(|p| p.get(0)).and_then(|v| v.as_u64()).unwrap_or(0);
            let verbose = params.and_then(|p| p.get(1)).and_then(|v| v.as_bool()).unwrap_or(false);
            match state.store.get_block_hash_at_height(height) {
                Ok(Some(hash)) => match state.store.get_block(&hash) {
                    Ok(Some(b)) => {
                        let mut result = json!({
                            "hash":        hex::encode(hash),
                            "height":      b.height,
                            "blue_score":  b.blue_score,
                            "tx_count":    b.transactions.len(),
                            "timestamp":   b.header.timestamp,
                            "bits":        format!("0x{:08x}", b.header.bits),
                            "nonce":       b.header.nonce,
                            "parents":     b.header.parents.iter().map(|p| hex::encode(p)).collect::<Vec<_>>(),
                            "merkle_root": hex::encode(b.header.merkle_root),
                            "size":        b.size_bytes(),
                            "pow":         crate::core::pow_algo(b.height).name(),
                        });
                        if crate::core::powit_active(b.height) {
                            result["powit"] = format_powit(&b.powit);
                        }
                        if verbose {
                            result["transactions"] = json!(b.transactions.iter().map(|tx| {
                                format_tx(tx)
                            }).collect::<Vec<_>>());
                        } else {
                            result["txids"] = json!(b.transactions.iter().map(|tx| {
                                hex::encode(tx.txid())
                            }).collect::<Vec<_>>());
                        }
                        result
                    },
                    Ok(None)  => json!({ "error": "block data not found" }),
                    Err(e)    => storage_err_response(&e),
                },
                Ok(None) => json!({ "error": "height not found" }),
                Err(e)   => storage_err_response(&e),
            }
        }

        // ── Block explorer: recent blocks list ───────────────────────
        "getrecentblocks" => {
            let count = params.and_then(|p| p.get(0)).and_then(|v| v.as_u64()).unwrap_or(10)
                .min(50); // cap at 50
            // The DAG's block count is not a height: it counts parallel blocks
            // too, and on 2026-08-13 exceeded the chain height by 10,769. Using
            // it here made the scan start ~10k heights above anything that
            // exists and walk down through nothing.
            let tip_height = selected_tip_height(&state).saturating_add(1);
            let mut blocks = Vec::new();
            // Iterate ALL heights until we find enough blocks (DAG may have gaps)
            for h in (0..tip_height).rev() {
                if blocks.len() >= count as usize { break; }
                if let Ok(Some(hash)) = state.store.get_block_hash_at_height(h) {
                    if let Ok(Some(b)) = state.store.get_block(&hash) {
                        blocks.push(json!({
                            "hash":      hex::encode(hash),
                            "height":    b.height,
                            "tx_count":  b.transactions.len(),
                            "timestamp": b.header.timestamp,
                            "size":      b.size_bytes(),
                            "bits":      b.header.bits,
                        }));
                    }
                }
            }
            json!(blocks)
        }

        // ── Block explorer: transaction lookup (O(1) via TX index) ────
        "gettransaction" => {
            let txid_hex = params.and_then(|p| p.get(0)).and_then(|v| v.as_str()).unwrap_or("");
            let txid_bytes = match hex::decode(txid_hex).ok().and_then(|b| <[u8;32]>::try_from(b).ok()) {
                Some(b) => b,
                None    => return json!({ "error": "invalid txid" }),
            };
            // O(1) lookup via CF_TX_INDEX
            match state.store.get_tx_location(&txid_bytes) {
                Ok(Some((block_hash, height))) => {
                    let tip = selected_tip_height(&state);
                    match state.store.get_block(&block_hash) {
                        Ok(Some(block)) => {
                            let tx = block.transactions.iter().find(|t| t.txid() == txid_bytes);
                            match tx {
                                Some(tx) => json!({
                                    "txid":          txid_hex,
                                    "block_hash":    hex::encode(block_hash),
                                    "block_height":  height,
                                    "timestamp":     block.header.timestamp,
                                    "confirmations": tip.saturating_sub(height),
                                    "transaction":   format_tx(tx),
                                }),
                                None => json!({ "error": "tx index stale" }),
                            }
                        },
                        Ok(None) => json!({ "error": "block not found" }),
                        Err(e)   => storage_err_response(&e),
                    }
                },
                Ok(None) => json!({ "error": "transaction not found" }),
                Err(e)   => storage_err_response(&e),
            }
        }

        // ── Wallet: raw transaction bytes (WAL-1) ────────────────────
        //
        // Read-only. Returns the wire bytes (`to_wire_bytes(true)`) of a
        // transaction so a wallet can hash them, compare the result with
        // the txid of a UTXO it is about to spend, and read the output's
        // value from a source it does not have to trust. Outputs of the
        // genesis carryover have no creating transaction, and pruned nodes
        // lose old bodies: both answer with an error and the wallet treats
        // the input as unverified.
        "getrawtransaction" => {
            let txid_hex = params.and_then(|p| p.get(0)).and_then(|v| v.as_str()).unwrap_or("");
            let Some(txid) = hex::decode(txid_hex).ok().and_then(|b| <[u8; 32]>::try_from(b).ok()) else {
                return json!({ "error": "invalid txid" });
            };
            if let Some(entry) = state.mempool.get_entry(&txid) {
                return json!({
                    "txid":       hex::encode(txid),
                    "hex":        hex::encode(entry.tx.to_wire_bytes(true)),
                    "in_mempool": true,
                });
            }
            match state.store.get_tx_location(&txid) {
                Ok(Some((block_hash, height))) => match state.store.get_block(&block_hash) {
                    Ok(Some(block)) => match block.transactions.iter().find(|t| t.txid() == txid) {
                        Some(tx) => json!({
                            "txid":         hex::encode(txid),
                            "hex":          hex::encode(tx.to_wire_bytes(true)),
                            "block_hash":   hex::encode(block_hash),
                            "block_height": height,
                            "in_mempool":   false,
                        }),
                        None => json!({ "error": "tx index stale" }),
                    },
                    Ok(None) => json!({ "error": "transaction body not available (block pruned)" }),
                    Err(e)   => storage_err_response(&e),
                },
                Ok(None) => json!({ "error": "transaction not found" }),
                Err(e)   => storage_err_response(&e),
            }
        }

        // ── Wallet: balance query ────────────────────────────────────
        "getbalance" => {
            let addr = params.and_then(|p| p.get(0)).and_then(|v| v.as_str()).unwrap_or("");
            let addr_bytes = parse_address(addr);
            match addr_bytes {
                Some(ab) => match state.store.get_balance(&ab) {
                    // R3 (docs/specs/BLOCH-RPC-V4.md): satoshi amounts are
                    // decimal STRINGS on the wire — V4's supply exceeds both
                    // i64::MAX and JS Number.MAX_SAFE_INTEGER. Display-only
                    // `*_bloch` floats stay JSON numbers (documented lossy).
                    Ok((sats, utxo_count)) => json!({
                        "satoshis":   sats.to_string(),
                        "gnb":       sats as f64 / 1e8,
                        "utxo_count": utxo_count,
                        "address":    addr,
                    }),
                    Err(e) => storage_err_response(&e),
                },
                None => json!({ "error": "invalid address" }),
            }
        }

        // ── Chain: distinct on-chain wallets (addresses with a balance) ──
        "getaddresscount" => {
            // NET-12: one read of the incremental aggregates (was a scan of
            // the whole address index on every call).
            match crate::analytics::address_count_bounded(&state.store) {
                Ok((addrs, utxos)) => json!({
                    "addresses_with_balance": addrs,
                    "utxo_entries":           utxos,
                    "note": "distinct 20-byte addresses currently holding >=1 UTXO (on-chain wallets with a non-zero balance) and their UTXOs; addresses that spent to zero or never held a UTXO are not counted",
                }),
                Err(e) => stats_err_response(&e),
            }
        }

        // ── Wallet: list UTXOs for address (needed by wallet CLI) ────
        "getutxos" => {
            let addr = params.and_then(|p| p.get(0)).and_then(|v| v.as_str()).unwrap_or("");
            // Optional 2nd param: max UTXOs to return. A wallet with hundreds of
            // thousands of UTXOs (e.g. the carry-over founder set) otherwise serializes
            // a multi-MB response that overflows clients; a spender only needs enough
            // UTXOs to cover the amount, so it can pass a small limit.
            //
            // NET-12: the limit is applied WHILE walking the address index
            // (the old code loaded every UTXO of the address first), and a
            // request without a limit is capped at GETUTXOS_MAX. When the
            // walk stops early `truncated` is true and `utxo_count` /
            // `satoshis` cover the returned UTXOs only; `getbalance` gives
            // the address totals.
            // The wallets' send flow widens a truncated window to this cap
            // (`gnb_crypto::wallet::send::GETUTXOS_MAX_ROWS`, the same value).
            const GETUTXOS_MAX: usize = gnb_crypto::wallet::send::GETUTXOS_MAX_ROWS as usize;
            let limit = params.and_then(|p| p.get(1)).and_then(|v| v.as_u64())
                .map(|n| usize::try_from(n).unwrap_or(usize::MAX).min(GETUTXOS_MAX))
                .unwrap_or(GETUTXOS_MAX);
            // Single-key (gnb1q…, 20-byte script) or policy (gnb1m…, 33-byte
            // script) address. The address index is keyed by the FULL script,
            // so the lookup must use all of it (a 20-byte prefix never matches
            // a policy entry); results are still filtered on the full script.
            let script = crate::address::destination_script(addr).ok().map(|(_, spk)| spk);
            match script {
                Some(spk) => match state.store.get_utxos_for_address_limited(&spk, limit) {
                    Ok((utxos, truncated)) => {
                        let utxos: Vec<_> = utxos.into_iter()
                            .filter(|(_, _, o)| o.script_pubkey == spk)
                            .collect();
                        let total: u64 = utxos.iter().map(|(_, _, o)| o.value).fold(0u64, u64::saturating_add);
                        // R3: `value` is a satoshi amount → decimal string.
                        // An output of a coinbase also carries the coinbase's
                        // height: it is spendable only from height
                        // coinbase_height + COINBASE_MATURITY, and a wallet
                        // that cannot tell selected immature coinbase outputs
                        // and built transactions the node refuses
                        // (test/functional/wallet_coinbase_maturity.py).
                        let list: Vec<Value> = utxos.iter().map(|(txid, idx, out)| {
                            let mut row = json!({
                                "txid": hex::encode(txid), "index": idx,
                                "value": out.value.to_string(), "script_pubkey": hex::encode(&out.script_pubkey),
                            });
                            let coinbase_height = <[u8; 32]>::try_from(txid.as_slice()).ok()
                                .and_then(|t| state.store.get_coinbase_height(&t).ok().flatten());
                            if let Some(h) = coinbase_height {
                                row["coinbase_height"] = json!(h);
                            }
                            row
                        }).collect();
                        json!({
                            "address":    addr,
                            "utxo_count": list.len(),
                            "returned":   list.len(),
                            "truncated":  truncated,
                            "satoshis":   total.to_string(),
                            "gnb":       total as f64 / 1e8,
                            "utxos":      list,
                        })
                    },
                    Err(e) => storage_err_response(&e),
                },
                None => json!({ "error": "invalid address" }),
            }
        }

        "sendrawtransaction" => {
            let hex_tx = params.and_then(|p| p.get(0)).and_then(|v| v.as_str()).unwrap_or("");
            match hex::decode(hex_tx) {
                Err(_)   => json!({ "error": "invalid hex" }),
                // Sprint 1.d: Bitcoin-format tx bytes (replaces bincode).
                // Wallet clients send stratum_bytes(include_script_sig=true).
                // MEM-5: strict decode — trailing bytes are refused.
                Ok(raw)  => match crate::mempool::admission::decode_tx_strict(&raw) {
                    Err(_)  => json!({ "error": "deserialise failed" }),
                    Ok(tx)  => {
                        if tx.is_coinbase() { return json!({ "error": "coinbase not accepted" }); }
                        // MEM-1/4/5: the SAME admission function as gossip and
                        // reorg re-injection. Version and maturity are evaluated
                        // at the next block's height (the node's next template
                        // height, `pool_next_height`, also reported by
                        // getdaginfo) — never the DAG block COUNT, which on
                        // 2026-08-13 exceeded the chain height by 10,769 and
                        // made every coinbase look mature. P0: PQ signature
                        // verification is CPU-bound, so it runs on the blocking
                        // pool.
                        let next_height = crate::mempool::admission::pool_next_height(
                            &state.dag.read(), &state.store, &state.mempool);
                        let store_v = state.store.clone();
                        let mempool_v = state.mempool.clone();
                        let txid = tx.txid();
                        let admitted = tokio::task::spawn_blocking(move || {
                            let policy = crate::mempool::admission::AdmissionPolicy::relay(next_height);
                            crate::mempool::admission::admit(&store_v, &mempool_v, tx, &policy)
                        }).await;
                        match admitted {
                            // Not L-5: an admission verdict (double-spend, fee too
                            // low, dust, ...) the caller needs to fix their tx —
                            // not an internal/filesystem detail to withhold.
                            Err(e)      => json!({ "error": format!("verify task failed: {}", e) }),
                            Ok(Err(e))  => json!({ "error": e.to_string() }),
                            Ok(Ok(_))   => {
                                let _ = state.outbound_tx.try_send(NetworkMessage::NewTransaction {
                                    txid, tx_data: raw,
                                });
                                json!({ "txid": hex::encode(txid) })
                            }
                        }
                    }
                },
            }
        }

        // ── Phase 2: validateaddress ─────────────────────────────────
        "validateaddress" => {
            let addr = params.and_then(|p| p.get(0)).and_then(|v| v.as_str()).unwrap_or("");
            let is_mainnet = addr.starts_with(MAINNET_PREFIX);
            let is_testnet = addr.starts_with(TESTNET_PREFIX);
            let valid_prefix = is_mainnet || is_testnet;
            let stripped = addr.trim_start_matches(MAINNET_PREFIX).trim_start_matches(TESTNET_PREFIX);
            // Expect 40 hex (20-byte hash) + 8 hex (4-byte checksum) = 48 hex chars
            let valid_len = stripped.len() == 48;
            let valid_hex = hex::decode(stripped).is_ok();

            // Verify checksum
            let valid_checksum = if valid_prefix && valid_len && valid_hex {
                let bytes = hex::decode(stripped).unwrap_or_default();
                let payload = &bytes[..20];
                use sha3::{Sha3_256, Digest};
                let inner = Sha3_256::digest(payload);
                let outer = Sha3_256::digest(inner);
                &outer[..4] == &bytes[20..24]
            } else {
                false
            };

            let is_valid = valid_prefix && valid_len && valid_hex && valid_checksum;
            json!({
                "address":    addr,
                "isvalid":    is_valid,
                "network":    if is_mainnet { "mainnet" } else if is_testnet { "testnet" } else { "unknown" },
                "checksum":   valid_checksum,
            })
        }

        // ── Phase 2: estimatefee ─────────────────────────────────────
        "estimatefee" => {
            // MEM-6: a fee RATE (sat per 1,000 wire bytes, the unit of the
            // consensus minimum), never below the consensus minimum rate or the
            // mempool's rolling minimum, plus the resulting fee of a typical
            // one-input / two-output transaction, never below the consensus
            // minimum fee. (Previously: the median ABSOLUTE fee, defaulting to
            // 1,000 sat while the consensus minimum is 10,000 sat.)
            let rate = state.mempool.estimate_fee_rate_per_kb();
            let typical_size = Transaction::estimate_size(1, 2);
            let typical_fee = crate::core::tokenomics::min_tx_fee_sat(typical_size)
                .max((typical_size as u64).saturating_mul(rate).div_ceil(1000));
            json!({
                // R3: satoshi amounts → decimal strings.
                "feerate_sat_per_kb": rate.to_string(),
                "min_fee_sat":        crate::core::tokenomics::MIN_TX_FEE_SAT.to_string(),
                "typical_tx_bytes":   typical_size,
                "typical_tx_fee_sat": typical_fee.to_string(),
                // Legacy key: now the recommended ABSOLUTE fee for a typical
                // transaction (>= the consensus minimum).
                "feerate_sats":       typical_fee.to_string(),
                "feerate_gnb":        typical_fee as f64 / 1e8,
                "mempool_size":       state.mempool.size(),
                "note":               "fee rate in sat/kB of wire bytes (>= consensus minimum); typical_tx_fee_sat for a 1-in/2-out tx",
            })
        }

        // ── Phase 2: getrawmempool ───────────────────────────────────
        "getrawmempool" => {
            let verbose = params.and_then(|p| p.get(0)).and_then(|v| v.as_bool()).unwrap_or(false);
            if verbose {
                let entries = state.mempool.entries();
                let list: Vec<serde_json::Value> = entries.iter().map(|(txid, fee, added)| {
                    json!({
                        "txid":     hex::encode(txid),
                        // R3: satoshi amount → decimal string.
                        "fee":      fee.to_string(),
                        "fee_gnb": *fee as f64 / 1e8,
                        "time":     added,
                    })
                }).collect();
                json!({ "size": list.len(), "transactions": list })
            } else {
                let txids: Vec<String> = state.mempool.txids().iter().map(|t| hex::encode(t)).collect();
                json!({ "size": txids.len(), "txids": txids })
            }
        }

        // ── Phase 2: decoderawtransaction ────────────────────────────
        "decoderawtransaction" => {
            let hex_tx = params.and_then(|p| p.get(0)).and_then(|v| v.as_str()).unwrap_or("");
            match hex::decode(hex_tx) {
                Err(_)  => json!({ "error": "invalid hex" }),
                // Sprint 1.d: Bitcoin-format tx bytes.
                Ok(raw) => match Transaction::from_wire_bytes(&raw) {
                    Err(e)  => json!({ "error": format!("decode failed: {}", e) }),
                    Ok(tx)  => {
                        let mut result = format_tx(&tx);
                        result["size"] = json!(raw.len());
                        result
                    }
                },
            }
        }

        // ── Phase 2: getdaginfo ──────────────────────────────────────
        // ── B5f pool seam: getblocktemplate / submitblock ─────────────────
        //
        // Stratum V1/V2 shares cannot carry the Module-SIS solution vector
        // (main.rs refuses to start them), so pool software mines complete
        // SIS blocks and talks to the node over these two methods instead:
        //
        //   getblocktemplate  — everything needed to assemble a candidate
        //                       block: parents, height, blue_score, the
        //                       expected `bits` (computed EXACTLY like
        //                       accept_block: ASERT-Lattice from the genesis
        //                       anchor + parent timestamp), subsidy/vesting
        //                       amounts, and mempool transactions with fees.
        //   submitblock       — full block (Bitcoin wire format hex, i.e.
        //                       Block::to_wire_bytes) routed through the
        //                       same validation pipeline as gossiped blocks.
        //
        // The reference pool consuming this lives in pool/.
        "getblocktemplate" => {
            // Shared template builder (audit MEM-2 / DAG-2): parents = at most
            // MAX_PARENTS bodied, non-disqualified tips by blue work; height =
            // max parent height + 1 (accept_block's VULN-02 rule); expected
            // bits exactly as accept_block validates them; transactions as
            // whole ANCESTOR PACKAGES by package fee rate, parents before
            // children (MEM-6 child-pays-for-parent), under a byte budget
            // measured like the consensus size rule of the template's height,
            // reserving EXTERNAL_COINBASE_RESERVE bytes for the caller's
            // coinbase; every tx re-validated at the template's height against
            // the UTXO set plus the outputs of the transactions placed before
            // it (offenders evicted with their descendants). Fees are
            // recomputed. Each entry's `depends` lists its in-template parents
            // (BIP22: 1-based positions in `transactions`): a block built from
            // a subset of the entries must keep every dependency of every
            // entry it keeps.
            let tmpl = match crate::template::build_block_template(
                &state.dag, &state.store, &state.mempool,
                crate::template::EXTERNAL_COINBASE_RESERVE,
            ) {
                Ok(t) => t,
                Err(e) => return json!({ "error": e }),
            };
            let tx_entries = template_tx_entries(&tmpl);

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default().as_secs();
            // Hardening block rules (docs/CONSENSUS.md, "Block rules at the
            // hardening activation"): at/after the activation the coinbase
            // script_sig MUST start with `coinbase_script_sig_prefix` (80
            // bytes: tag, height, parents commitment, witness root of exactly
            // the listed transactions in this order), followed by at most
            // `max_coinbase_extra_bytes` miner bytes; the header Merkle root
            // uses the tagged tree; the size limit is measured on the wire
            // encoding. Below it, all three are as before.
            //
            // The WHOLE coinbase, measured with `size_rule`, must fit in
            // `coinbase_reserve`: the listed transactions may fill the rest of
            // the block. `max_coinbase_extra_bytes` already includes that
            // bound for a coinbase with one output whose script_pubkey is at
            // most `max_coinbase_script_pubkey_bytes` bytes (and the consensus
            // script_sig cap), so a miner that stays within both fields can
            // never produce a block over `max_block_size`.
            let commitment = tmpl.coinbase_commitment();
            let max_extra = crate::template::external_coinbase_max_extra(
                commitment.map(|c| c.len()).unwrap_or(0),
                tmpl.hardened,
                crate::template::EXTERNAL_COINBASE_RESERVE,
            );

            let witness_commitment = if crate::core::suffix_witness_commitment_required(tmpl.height) {
                let probe = crate::core::Block {
                    header: crate::core::BlockHeader { version: 1, parents: vec![],
                        merkle_root: crate::core::MerkleRoot::ZERO, timestamp: 0, bits: tmpl.bits, nonce: 0 },
                    transactions: std::iter::once(crate::core::Transaction {
                        version: 1, inputs: vec![], outputs: vec![], locktime: 0 })
                        .chain(tmpl.transactions.iter().map(|(t, _)| t.clone())).collect(),
                    blue_score: tmpl.blue_score, height: tmpl.height,
                    shielded_transactions: Vec::new(), powit: tmpl.powit.clone(),
                };
                hex::encode(probe.witness_commitment())
            } else {
                String::new()
            };
            let powit_hex = {
                let mut v = Vec::new();
                tmpl.powit.write_wire(&mut v);
                hex::encode(v)
            };
            let coinbase_outputs: Vec<Value> = tmpl.coinbase_outputs(Vec::new()).iter().map(|o| json!({
                "value": o.value.to_string(), "script_pubkey": hex::encode(&o.script_pubkey),
            })).collect();

            json!({
                "hardening_active":     tmpl.hardened,
                "hardening_activation_height": tmpl.activation_height,
                "merkle_rule":          if tmpl.hardened { "gnb-tagged-v1" } else { "sha256d-duplicate-last" },
                "size_rule":            if tmpl.hardened { "wire" } else { "bincode" },
                "coinbase_script_sig_prefix": commitment.map(hex::encode).unwrap_or_default(),
                "max_coinbase_extra_bytes": max_extra,
                "max_coinbase_script_pubkey_bytes": crate::template::EXTERNAL_COINBASE_MAX_SPK,
                // Siblings from the coinbase leaf to the header root (fold the
                // coinbase txid through them with the `merkle_rule`).
                "coinbase_merkle_branch": tmpl.coinbase_merkle_branch().iter().map(hex::encode).collect::<Vec<_>>(),
                "parents":              tmpl.parents.iter().map(hex::encode).collect::<Vec<_>>(),
                "height":               tmpl.height,
                "blue_score":           tmpl.blue_score,
                "bits":                 tmpl.bits,
                "cur_time":             now,
                "parent_time":          tmpl.parent_timestamp,
                // R3: satoshi amounts → decimal strings.
                "subsidy_sat":          tmpl.subsidy.to_string(),
                "total_fees":           tmpl.total_fees.to_string(),
                "transactions":         tx_entries,
                // The block's timestamp must be >= parent_time and at most
                // MAX_FUTURE_SECS ahead of the validator's clock.
                "min_time":             tmpl.parent_timestamp,
                // Size accounting: the whole block, measured as the consensus
                // rule measures it at this height (`size_rule`: bincode
                // `Block::size_bytes` before the activation, the wire encoding
                // `Block::to_wire_bytes` from it), must stay <= max_block_size;
                // the listed transactions leave coinbase_reserve bytes for the
                // WHOLE coinbase (in the same measure), which is what
                // max_coinbase_extra_bytes is derived from.
                "max_block_size":       crate::core::MAX_BLOCK_SIZE,
                "coinbase_reserve":     crate::template::EXTERNAL_COINBASE_RESERVE,
                "max_parents":          crate::core::MAX_PARENTS,
                // Proof of work: GnB-SMH v1 over the header preimage
                // (version u32le | n_parents u32le | parents | merkle_root |
                // timestamp u64le | bits u32le) and the u64 nonce; valid iff
                // the 32-byte output, big-endian, is < target(bits).
                // From powit_height the proof of work is GnB-SMH v3 (4 MiB);
                // "pow" names the function for THIS height.
                "pow":                  crate::core::pow_algo(tmpl.height).name(),
                "pow_log2_n":           match crate::core::pow_algo(tmpl.height) {
                    gnb_smh::Algo::V1 => gnb_smh::LOG2_N,
                    gnb_smh::Algo::V3 => gnb_smh::v3::LOG2_N,
                },
                "target":               hex::encode(crate::core::bits_to_target(tmpl.bits)),
                // This chain measures the block size on the wire encoding at
                // every height (`size_rule` above names the audit's regime).
                "chain_size_rule":      "wire",
                // From witness_commitment_height up to the hardening
                // activation the coinbase script_sig must END with these
                // bytes (tag ‖ Merkle root of the wtxids, the coinbase counted
                // as zero); see Block::commit_witnesses.
                "witness_commitment_height": crate::core::WITNESS_COMMITMENT_HEIGHT,
                "witness_commitment":   witness_commitment,
                // PoWit (from powit_height): the block must carry this section
                // (wire hex, `PowitBody::write_wire`) and its coinbase exactly
                // these outputs, the first paid to the miner's script (one per
                // witness share after it; the miner output is subsidy share +
                // fees, see `core::Block::coinbase_outputs`).
                "powit_height":         crate::core::powit_height().to_string(),
                "powit":                powit_hex,
                "coinbase_outputs":     coinbase_outputs,
            })
        }

        "submitblock" => {
            let block_hex = params.and_then(|p| p.get(0)).and_then(|v| v.as_str()).unwrap_or("");
            let bytes = match hex::decode(block_hex) {
                Ok(b)  => b,
                Err(_) => return json!({ "error": "invalid hex" }),
            };
            let block = match crate::core::Block::from_wire_bytes(&bytes) {
                Ok(b)  => b,
                Err(e) => return json!({ "error": format!("deserialise failed: {}", e) }),
            };
            match &state.submit_block {
                None => json!({ "error": "submitblock not wired on this node (started without a block-submission hook)" }),
                Some(hook) => match hook(block) {
                    Ok(hash_hex) => json!({ "accepted": true, "hash": hash_hex }),
                    Err(reason)  => json!({ "error": format!("rejected: {}", reason) }),
                },
            }
        }

        // Audit DAG-6: operator recovery (Bitcoin Core's invalidateblock /
        // reconsiderblock). Admin methods: never anonymous (auth::ADMIN_METHODS).
        "invalidateblock" => chain_admin_call(ChainAdminOp::Invalidate, params, state),
        "reconsiderblock" => chain_admin_call(ChainAdminOp::Reconsider, params, state),

        // submitpowititem [kind, hex]: kind 1 = witness share, 2 = attestation,
        // 3 = equivocation proof. Validated like a gossiped item, then relayed.
        "submitpowititem" => {
            let kind = params.and_then(|p| p.get(0)).and_then(|v| v.as_u64()).unwrap_or(0);
            let data = match params.and_then(|p| p.get(1)).and_then(|v| v.as_str()).map(hex::decode) {
                Some(Ok(d)) => d,
                _ => return json!({ "error": "usage: submitpowititem [kind, hex]" }),
            };
            if !(1..=3).contains(&kind) || data.len() > crate::network::MAX_WIRE_POWIT_ITEM {
                return json!({ "error": "bad kind or item too large" });
            }
            let kind = kind as u8;
            let res = {
                let dag = state.dag.read();
                crate::powit::admit_item(kind, &data, &dag, &state.store)
            };
            match res {
                Ok(()) => {
                    let id = crate::powit::item_id(kind, &data);
                    let _ = state.outbound_tx.try_send(NetworkMessage::NewPowitItem { id, kind, data });
                    json!({ "accepted": true, "id": hex::encode(id) })
                }
                Err(e) => json!({ "accepted": false, "error": e }),
            }
        }

        "getpowitinfo" => {
            let dag = state.dag.read();
            crate::powit::info_json(&dag, &state.store)
        }

        "getdaginfo" => {
            let dag = state.dag.read();
            let tips = dag.tips();
            let chain = dag.selected_chain();
            let tip = dag.selected_tip();
            let tip_data = tip.and_then(|h| dag.get_block_data(&h).cloned());
            // The header height of the next block mempool admission targets
            // (the node's next template height): wallets sign for it (version
            // 3 / sighash v3 from the hardening activation). Not always
            // tip_height + 1: a template that merges a tip with a greater DAG
            // height sits higher (DAG-8).
            let next_block_height = crate::mempool::admission::pool_next_height(&dag, &state.store, &state.mempool);
            // The activation height in force (the one block validation and
            // the template builder read) and whether the hardening rules
            // apply at next_block_height, as getblocktemplate reports them
            // for its template's height.
            let activation_height = crate::core::activation::hardening_activation_height();
            json!({
                "tip":            tip.map(|h| hex::encode(h)),
                "tip_blue_score": tip_data.as_ref().map(|d| d.blue_score).unwrap_or(0),
                "tip_blue_work":  tip_data.as_ref().map(|d| d.blue_work.to_string()).unwrap_or_default(),
                "tip_height":     tip_data.as_ref().map(|d| d.height).unwrap_or(0),
                "next_block_height": next_block_height,
                "hardening_activation_height": activation_height,
                "hardening_active": crate::core::block_rules::rules_active_at(next_block_height, activation_height),
                "block_count":    dag.block_count(),
                "tip_count":      tips.len(),
                "tips":           tips.iter().map(|h| hex::encode(h)).collect::<Vec<_>>(),
                "chain_length":   chain.len(),
                "k":              crate::core::GHOSTDAG_K,
            })
        }

                "listtransactions" => {
            let addr = params.and_then(|p| p.get(0)).and_then(|v| v.as_str()).unwrap_or("");
            let limit = params.and_then(|p| p.get(1)).and_then(|v| v.as_u64()).unwrap_or(20).min(1000) as usize;
            let start_height = params.and_then(|p| p.get(2)).and_then(|v| v.as_u64()).unwrap_or(0);
            let end_height = params.and_then(|p| p.get(3)).and_then(|v| v.as_u64())
                .unwrap_or_else(|| state.node_state.read().block_count);
            let offset = params.and_then(|p| p.get(4)).and_then(|v| v.as_u64()).unwrap_or(0) as usize;

            let addr_bytes = parse_address(addr);
            match addr_bytes {
                Some(ab) => {
                    let mut addr_hash = [0u8; 20];
                    if ab.len() >= 20 {
                        addr_hash.copy_from_slice(&ab[..20]);
                    } else {
                        return json!({ "error": "invalid address (too short)" });
                    }
                    match state.store.query_address_history(&addr_hash, start_height, end_height, limit, offset) {
                        Ok(entries) => {
                            let tip = selected_tip_height(&state);
                            let total = state.store.count_address_history(&addr_hash, start_height, end_height).unwrap_or(0);
                            let txs: Vec<serde_json::Value> = entries.iter().map(|e| {
                                let timestamp = state.store.get_block_timestamp_at_height(e.height).unwrap_or(None).unwrap_or(0);
                                json!({
                                    "txid":          hex::encode(&e.txid),
                                    "block_height":  e.height,
                                    "timestamp":     timestamp,
                                    "confirmations": tip.saturating_sub(e.height),
                                    "direction":     e.direction_str(),
                                    // R3: satoshi amount → decimal string.
                                    "amount_sats":   e.amount.to_string(),
                                    "amount_bloch":   e.amount as f64 / 1e8,
                                })
                            }).collect();
                            json!({
                                "address":         addr,
                                "count":           txs.len(),
                                "total_available": total,
                                "start_height":    start_height,
                                "end_height":      end_height,
                                "limit":           limit,
                                "offset":          offset,
                                "transactions":    txs,
                            })
                        }
                        Err(e) => storage_err_response(&e),
                    }
                }
                None => json!({ "error": "invalid address" }),
            }
        }

// ── INSERT: gettxsbyblock ──

        // ── Phase 2: getpeerinfo ─────────────────────────────────────
        "getpeerinfo" => {
            let s = state.node_state.read();
            json!({
                "peer_count": s.peer_count,
                "syncing":    s.is_syncing,
            })
        }

        "getpeers" => {
            let s = state.node_state.read();
            let peers: Vec<serde_json::Value> = s.peer_addresses.iter().map(|addr| {
                // Extract IP from multiaddr like /ip4/1.2.3.4/tcp/17110/p2p/12D3...
                let ip = addr.split('/').enumerate()
                    .find(|(i, seg)| *i > 0 && seg.parse::<std::net::Ipv4Addr>().is_ok())
                    .map(|(_, s)| s.to_string())
                    .unwrap_or_default();
                let peer_id = addr.split("/p2p/").last().unwrap_or("").to_string();
                json!({
                    "address": addr,
                    "ip": ip,
                    "peer_id": peer_id,
                })
            }).collect();
            json!({
                "peer_count": s.peer_count,
                "peers": peers,
            })
        }

        // ── Treasury (community dev fund) ───────────────────────────────
        // V2 (ADR-028): replaces V1 "gettreasury" with multi-pool report.
        // Returns subsidy split for the next block + per-pool address/balance,
        // gracefully reporting "pending_phase_6" for pools whose address
        // constants are still None.
        "getsupplyinfo" => {
            use crate::core::tokenomics as t;
            let current_height = selected_tip_height(&state);
            let next_height    = current_height.saturating_add(1);
            let subsidy        = t::block_subsidy_sat(next_height);
            let issued         = t::issued_through_sat(current_height);
            let next_halving   = (next_height / t::HALVING_INTERVAL + 1) * t::HALVING_INTERVAL;
            json!({
                "current_height":          current_height,
                "next_block_height":       next_height,
                // Amounts in base units as decimal strings (1 GNB = 10^8).
                "max_supply_sat":          t::MAX_SUPPLY_SAT.to_string(),
                "issued_sat":              issued.to_string(),
                "subsidy_per_block_sat":   subsidy.to_string(),
                "subsidy_per_block_gnb":   subsidy as f64 / 1e8,
                "halving_interval":        t::HALVING_INTERVAL,
                "next_halving_height":     next_halving,
                "last_subsidy_height":     t::LAST_SUBSIDY_HEIGHT_EXCLUSIVE - 1,
                "miner_share_bps":         10_000,
                "min_fee_rate_sat_per_kb": t::MIN_FEE_RATE_SAT_PER_KB.to_string(),
                "min_tx_fee_sat":          t::MIN_TX_FEE_SAT.to_string(),
            })
        }

        // ═════════════════════════════════════════════════════════════════════════════
// ═════════════════════════════════════════════════════════════════════════════
//
//      in src/rpc/mod.rs (last arm of the match in dispatch())
//
// ═════════════════════════════════════════════════════════════════════════════

        // ── Sprint B: Chain analytics ──────────────────────────────────────

        // NET-12: bounded — incremental aggregates plus an in-memory walk of
        // at most `analytics::STATS_WINDOW_MAX_BLOCKS` selected-chain blocks
        // (cancellable); was a decode of every stored block body per call.
        "getchainstats" => {
            match crate::analytics::chain_stats_bounded(&state.store, &state.dag, unix_now(), &state.cancel) {
                Ok(s) => json!({
                    "total_blocks":         s.total_blocks,
                    "chain_blocks":         s.chain_blocks,
                    "total_txs":            s.total_txs,
                    "avg_txs_per_block":    s.avg_txs_per_block,
                    "blocks_last_24h":      s.blocks_last_24h,
                    "txs_last_24h":         s.txs_last_24h,
                    "window_capped":        s.window_capped,
                    "avg_block_time_secs":  s.avg_block_time,
                    "avg_dag_block_interval_secs": s.avg_dag_block_interval,
                    "current_difficulty":   s.current_difficulty,
                    "hashrate_hs":          s.hashrate_estimate,
                    "hashrate_human":       format_hashrate(s.hashrate_estimate),
                    "note": "total_blocks: blocks in the DAG; chain_blocks/total_txs/*_last_24h: the applied selected chain (the ledger); avg_block_time_secs: interval between selected-chain blocks; hashrate_hs: from the interval between ALL DAG blocks (chain blocks and the blue and red blocks they merged, avg_dag_block_interval_secs) over the last 50 chain blocks",
                }),
                Err(e) => stats_err_response(&e),
            }
        }

        "getsupplydistribution" => explorer::get_supply_distribution(state),
        "getselectedchain"      => explorer::get_selected_chain(params, state),
        "getblockdag"           => explorer::get_block_dag(params, state),
        "gettransactionfull"    => explorer::get_transaction_full(params, state),
        "getdagwindow"          => explorer::get_dag_window(params, state),
        "getaddresshistory"     => explorer::get_address_history(params, state),
        "getrichlist"           => explorer::get_rich_list(params, state),
        "gethashrate" => {
            match crate::analytics::chain_stats_bounded(&state.store, &state.dag, unix_now(), &state.cancel) {
                Ok(s) => json!({
                    "hashrate_hs":          s.hashrate_estimate,
                    "hashrate_human":       format_hashrate(s.hashrate_estimate),
                    "avg_block_time_secs":  s.avg_block_time,
                    "avg_dag_block_interval_secs": s.avg_dag_block_interval,
                    "current_difficulty":   s.current_difficulty,
                    "note": "hashrate_hs counts every DAG block (chain blocks and the blue and red blocks they merged): hashes per block / avg_dag_block_interval_secs over the last 50 chain blocks",
                }),
                Err(e) => stats_err_response(&e),
            }
        }

        // NET-12: bounded walks of the selected chain (were full scans that
        // decoded every stored block body), also behind the HeavyGate.
        "getdifficultyhistory"    => explorer::get_difficulty_history(params, state),
        "getblocktimepercentiles" => explorer::get_block_time_percentiles(params, state),

        "gettxstatus" => {
            let txid_hex = params.and_then(|p| p.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let txid_bytes = match hex::decode(txid_hex) {
                Ok(b) if b.len() == 32 => b,
                _ => return json!({ "error": "invalid txid" }),
            };
            let mut txid_arr = [0u8; 32];
            txid_arr.copy_from_slice(&txid_bytes);

            // Check mempool first
            if state.mempool.contains(&txid_arr) {
                return json!({
                    "status":        "pending",
                    "in_mempool":    true,
                    "confirmations": 0,
                    "txid":          txid_hex,
                });
            }

            // Check storage
            match state.store.get_tx_location(&txid_arr) {
                Ok(Some((_block_hash, height))) => {
                    let tip = selected_tip_height(&state);
                    let confirmations = tip.saturating_sub(height) + 1;
                    json!({
                        "status":        if confirmations >= 100 { "final" } else { "confirmed" },
                        "in_mempool":    false,
                        "confirmations": confirmations,
                        "block_height":  height,
                        "txid":          txid_hex,
                    })
                }
                _ => json!({
                    "status":        "unknown",
                    "in_mempool":    false,
                    "confirmations": 0,
                    "txid":          txid_hex,
                })
            }
        }

        "getaddressinfo" => {
            let addr_str = params.and_then(|p| p.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let addr_bytes = match parse_address(addr_str) {
                Some(b) if b.len() == 20 => b,
                _ => return json!({ "error": "invalid address" }),
            };
            let mut addr_hash = [0u8; 20];
            addr_hash.copy_from_slice(&addr_bytes);

            match crate::analytics::address_info(&state.store, &state.mempool, addr_str, &addr_hash) {
                Ok(info) => json!({
                    "address":           info.address,
                    // R3: satoshi amounts → decimal strings.
                    "balance_sats":      info.balance_sats.to_string(),
                    "balance_gnb":      info.balance_gnb,
                    "utxo_count":        info.utxo_count,
                    "pending_incoming":  info.pending_incoming.to_string(),
                    "pending_outgoing":  info.pending_outgoing.to_string(),
                    "pool_role":         info.pool_role,
                }),
                Err(e) => json!({ "error": e }),
            }
        }

        "estimatefeeadvanced" => {
            let fee = crate::analytics::estimate_fee_advanced(&state.mempool);
            json!({
                // R3: satoshi amounts → decimal strings.
                "next_block_sats":  fee.next_block_sats.to_string(),
                "medium_priority":  fee.medium_priority.to_string(),
                "slow_priority":    fee.slow_priority.to_string(),
                "mempool_median":   fee.mempool_median.to_string(),
                "mempool_size":     fee.mempool_size,
                "recommended_gnb": format!("{:.8}", fee.medium_priority as f64 / 1e8),
            })
        }

        "getmempoolstats" => {
            let stats = crate::analytics::mempool_stats(&state.mempool);
            let buckets: Vec<Value> = stats.buckets.iter().map(|b| json!({
                "range":    b.range,
                "tx_count": b.tx_count,
            })).collect();
            json!({
                "size":        stats.size,
                // R3: satoshi amounts → decimal strings (`avg_fee` is a
                // documented-lossy float, so it stays a JSON number).
                "total_fees":  stats.total_fees.to_string(),
                "min_fee":     stats.min_fee.to_string(),
                "max_fee":     stats.max_fee.to_string(),
                "median_fee":  stats.median_fee.to_string(),
                "avg_fee":     stats.avg_fee,
                "buckets":     buckets,
            })
        }

        "validateaddressverbose" => {
            let addr_str = params.and_then(|p| p.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .unwrap_or("");

            match crate::address::Address::parse(addr_str) {
                Ok(a) => json!({
                    "valid":    true,
                    "address":  addr_str,
                    "network":  if a.is_mainnet() { "mainnet" } else { "testnet" },
                    "hash_hex": hex::encode(a.hash()),
                    "prefix":   if a.is_mainnet() { crate::core::MAINNET_PREFIX } else { crate::core::TESTNET_PREFIX },
                }),
                Err(e) => json!({
                    "valid":   false,
                    "address": addr_str,
                    "reason":  format!("{}", e),
                }),
            }
        }

        // ── End of Sprint B additions ──────────────────────────────────────

"gettxsbyblock" => {
            // Accept either hash (hex string, 64 chars) or height (number).
            let p0 = params.and_then(|p| p.get(0));
            let block_hash = match p0 {
                Some(v) if v.is_string() => {
                    let s = v.as_str().unwrap();
                    if s.len() == 64 {
                        hex::decode(s).ok().and_then(|b| {
                            let mut h = [0u8; 32];
                            if b.len() == 32 { h.copy_from_slice(&b); Some(h) } else { None }
                        })
                    } else {
                        // try parse as height-as-string
                        s.parse::<u64>().ok().and_then(|h| state.store.get_block_hash_at_height(h).ok().flatten())
                    }
                }
                Some(v) if v.is_u64() => {
                    let h = v.as_u64().unwrap();
                    state.store.get_block_hash_at_height(h).ok().flatten()
                }
                _ => None,
            };

            match block_hash {
                Some(bh) => {
                    match state.store.get_block(&bh) {
                        Ok(Some(block)) => {
                            let txs: Vec<serde_json::Value> = block.transactions.iter().map(|tx| {
                                let txid = tx.txid();
                                // Sprint 1.d: size is length of stratum (Bitcoin-format) bytes.
                                // include_script_sig=true matches what lives on the wire and on disk.
                                let size_bytes = tx.to_wire_bytes(true).len() as u32;
                                // Fee: sum(inputs_value) - sum(outputs_value). For coinbase, fee = 0 by convention.
                                let outputs_total: u64 = tx.outputs.iter().map(|o| o.value).sum();
                                let fee_sats: u64 = if tx.is_coinbase() {
                                    0
                                } else {
                                    let inputs_total: u64 = tx.inputs.iter().map(|inp| {
                                        state.store.get_utxo_including_spent(&inp.prev_txid, inp.prev_index)
                                            .ok().flatten().map(|o| o.value).unwrap_or(0)
                                    }).sum();
                                    inputs_total.saturating_sub(outputs_total)
                                };
                                json!({
                                    "txid":           hex::encode(&txid),
                                    "size_bytes":     size_bytes,
                                    "inputs_count":   tx.inputs.len(),
                                    "outputs_count":  tx.outputs.len(),
                                    // R3: satoshi amount → decimal string.
                                    "fee_sats":       fee_sats.to_string(),
                                    "is_coinbase":    tx.is_coinbase(),
                                })
                            }).collect();
                            json!({
                                "block_hash":      hex::encode(&bh),
                                "block_height":    block.height,
                                "block_timestamp": block.header.timestamp,
                                "count":           txs.len(),
                                "txs":             txs,
                            })
                        }
                        Ok(None) => json!({ "error": "block not found" }),
                        Err(e) => storage_err_response(&e),
                    }
                }
                None => json!({ "error": "invalid block identifier (expected hex hash or height)" }),
            }
        }

// ── INSERT: getaddressbalance_at_height ──

"getaddressbalance_at_height" => {
            let addr = params.and_then(|p| p.get(0)).and_then(|v| v.as_str()).unwrap_or("");
            let height = params.and_then(|p| p.get(1)).and_then(|v| v.as_u64()).unwrap_or(0);

            let addr_bytes = parse_address(addr);
            match addr_bytes {
                Some(ab) => {
                    let mut addr_hash = [0u8; 20];
                    if ab.len() >= 20 {
                        addr_hash.copy_from_slice(&ab[..20]);
                    } else {
                        return json!({ "error": "invalid address" });
                    }
                    // NET-12: streamed and cancellable (heavy method).
                    match state.store.balance_at_height_cancellable(&addr_hash, height, &state.cancel) {
                        Ok((balance, _)) => {
                            let tx_count = state.store.count_address_history(&addr_hash, 0, height).unwrap_or(0);
                            json!({
                                "address":               addr,
                                "height":                height,
                                // R3: satoshi amount → decimal string.
                                "balance_sats":          balance.to_string(),
                                "balance_gnb":          balance as f64 / 1e8,
                                "tx_count_up_to_height": tx_count,
                            })
                        }
                        Err(e) => storage_err_response(&e),
                    }
                }
                None => json!({ "error": "invalid address" }),
            }
        }

        // Bloch-SIS-Linux L3: attestation status (pluggable provider; reports
        // attested=false when no TEE is active).
        "getattestation" => {
            // Optional freshness nonce (params[0]) echoed into the report and,
            // for a real TEE, bound into the quote's report-data.
            let nonce = params.and_then(|p| p.get(0)).and_then(|v| v.as_str()).map(String::from);
            serde_json::to_value(crate::attestation::current_report(nonce))
                .unwrap_or_else(|e| json!({ "error": format!("attestation serialize: {}", e) }))
        }

        // NET-13: never echo an unbounded caller-supplied string.
        _ => json!({ "error": format!("unknown method: {}", method_for_log(method)) }),
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Parse a gnb1q/gnb1t address to 20-byte pubkey hash
/// Sprint K: Checksum-validated address parsing.
/// Delegates to `Address::parse()` from Sprint A — enforces full 54-char
/// checksummed format (gnb1q + 20-byte hash + 4-byte checksum, hex-encoded).
/// Rejects the legacy 46-char checksum-less form that the previous implementation
/// silently accepted.
fn parse_address(addr: &str) -> Option<Vec<u8>> {
    crate::address::Address::parse(addr)
        .ok()
        .map(|a| a.hash().to_vec())
}

/// Format a transaction for JSON output
/// The `transactions` entries of `getblocktemplate`: `txid`, `fee` (decimal
/// string, R3), `data` (wire hex) and `depends` — the 1-based positions of
/// the entry's in-template parents (`BlockTemplate::depends`, BIP22
/// semantics). A subset of the entries is mineable only if it is closed
/// under `depends` and keeps the listed order.
fn template_tx_entries(tmpl: &crate::template::BlockTemplate) -> Vec<Value> {
    tmpl.transactions.iter().zip(tmpl.depends()).map(|((tx, fee), depends)| {
        json!({
            "txid":    hex::encode(tx.txid()),
            // R3: satoshi amount → decimal string.
            "fee":     fee.to_string(),
            "data":    hex::encode(tx.to_wire_bytes(true)),
            "depends": depends,
        })
    }).collect()
}

/// A block's PoWit section for explorers: witness shares, KES-signed
/// attestations (with the epoch leaf each one used) and equivocation proofs.
fn format_powit(p: &crate::core::powit::PowitBody) -> Value {
    let cp = |c: &crate::core::powit::Checkpoint| json!({ "slot": c.height, "hash": hex::encode(c.hash) });
    let att = |a: &crate::core::powit::Attestation| json!({
        "witness":    hex::encode(a.key_id()),
        "source":     cp(&a.source),
        "target":     cp(&a.target),
        "kes_epoch":  a.sig.index,
        "kes_depth":  a.witness.depth,
        "kes_root":   hex::encode(a.witness.root),
        "sig_bytes":  a.sig.sig.len(),
    });
    json!({
        "shares": p.shares.iter().map(|s| json!({
            "id":       hex::encode(crate::core::witness_share::share_id(s)),
            "attested": hex::encode(s.attested),
            "witness":  hex::encode(s.witness),
            "payout":   hex::encode(&s.payout),
        })).collect::<Vec<_>>(),
        "attestations": p.attestations.iter().map(att).collect::<Vec<_>>(),
        "evidence": p.evidence.iter().map(|e| json!({
            "witness": hex::encode(e.a.key_id()), "a": att(&e.a), "b": att(&e.b),
        })).collect::<Vec<_>>(),
    })
}

fn format_tx(tx: &Transaction) -> Value {
    json!({
        "txid":     hex::encode(tx.txid()),
        "version":  tx.version,
        "coinbase": tx.is_coinbase(),
        "inputs":   tx.inputs.iter().map(|inp| json!({
            "prev_txid":  hex::encode(inp.prev_txid),
            "prev_index": inp.prev_index,
            "sequence":   inp.sequence,
        })).collect::<Vec<_>>(),
        "outputs":  tx.outputs.iter().enumerate().map(|(i, out)| json!({
            "index":         i,
            // R3 (docs/specs/BLOCH-RPC-V4.md): satoshi amount → decimal string.
            "value":         out.value.to_string(),
            "gnb":          out.value as f64 / 1e8,
            "script_pubkey": hex::encode(&out.script_pubkey),
        })).collect::<Vec<_>>(),
        "locktime": tx.locktime,
    })
}

/// Validate a transaction for mempool/broadcast acceptance (no pool context).
/// Returns the fee (total_in - total_out) on success.
///
/// Delegates to the shared admission rules (`mempool::admission`, audit
/// MEM-1/4/5): size, standardness (dust, zero-value, canonical limits,
/// MoneyRange), duplicate inputs, UTXO presence, coinbase maturity at
/// `next_block_height` (`0` skips it), consensus minimum fee and relay fee,
/// then the hybrid signatures. `sendrawtransaction` itself calls
/// `admission::admit`, which also runs the pool-relative checks.
#[allow(dead_code)]
fn validate_tx_for_mempool(tx: &Transaction, store: &Arc<Storage>, next_block_height: u64) -> Result<u64, String> {
    let policy = crate::mempool::admission::AdmissionPolicy {
        next_block_height,
        check_signatures: true,
        use_reject_filter: false,
    };
    crate::mempool::admission::check_transaction(store, None, tx, &policy).map_err(|e| e.to_string())
}


// ═════════════════════════════════════════════════════════════════════════════
// ═════════════════════════════════════════════════════════════════════════════
//
//      look for the "parse_address" helper (around line 560+)
//
// ═════════════════════════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────────────────────
// V4 rule R3 (docs/specs/BLOCH-RPC-V4.md): every satoshi-denominated field is a
// decimal STRING on the JSON-RPC wire. The V4 supply exceeds i64::MAX and is
// ~1000× JavaScript's Number.MAX_SAFE_INTEGER, so a JSON number silently
// corrupts large amounts in every browser client. Internally values stay u64.
// `format_tx` is the shared output formatter behind getblock / gettransaction /
// decoderawtransaction, so pinning it pins those three response shapes.
// ─────────────────────────────────────────────────────────────────────────────
// ── L-10 / L-11 regressions ─────────────────────────────────────────────────

#[cfg(test)]
mod l10_l11_id_and_batch_tests {
    use super::*;

    /// L-10 core regression: an oversized `id` string must be truncated,
    /// never echoed at full length.
    #[test]
    fn oversized_string_id_is_truncated() {
        let huge = "x".repeat(MAX_ECHOED_ID_LEN * 10);
        let capped = cap_echoed_id(Value::String(huge));
        match capped {
            Value::String(s) => assert!(
                s.len() <= MAX_ECHOED_ID_LEN,
                "capped id is {} bytes, expected <= {}", s.len(), MAX_ECHOED_ID_LEN
            ),
            other => panic!("expected a String, got {:?}", other),
        }
    }

    /// A short, legitimate id passes through unchanged.
    #[test]
    fn short_string_id_is_unchanged() {
        assert_eq!(cap_echoed_id(json!("req-42")), json!("req-42"));
    }

    /// Numbers and null are the spec-legitimate id shapes and pass through.
    #[test]
    fn number_and_null_ids_pass_through() {
        assert_eq!(cap_echoed_id(json!(42)), json!(42));
        assert_eq!(cap_echoed_id(json!(null)), json!(null));
    }

    /// A non-spec id shape (bool/array/object) is replaced with null rather
    /// than echoed — nothing legitimate sends these, and echoing an
    /// attacker-shaped structure back verbatim is unnecessary surface.
    #[test]
    fn non_scalar_ids_become_null() {
        assert_eq!(cap_echoed_id(json!(true)), json!(null));
        assert_eq!(cap_echoed_id(json!([1, 2, 3])), json!(null));
        assert_eq!(cap_echoed_id(json!({"a": 1})), json!(null));
    }

    /// Truncation must never split a multi-byte UTF-8 character — reusing
    /// `network::truncate_utf8` is what guarantees this; pin it here too so a
    /// future change to this call site cannot silently regress to a raw
    /// byte-index slice.
    #[test]
    fn truncation_is_utf8_safe() {
        // 300 copies of a 3-byte character comfortably straddles a naive
        // byte-256 cut point.
        let s: String = "€".repeat(300);
        let capped = cap_echoed_id(Value::String(s));
        match capped {
            Value::String(s) => {
                assert!(s.len() <= MAX_ECHOED_ID_LEN);
                assert!(std::str::from_utf8(s.as_bytes()).is_ok(), "must remain valid UTF-8");
            }
            other => panic!("expected a String, got {:?}", other),
        }
    }

    /// L-11 core regression: the batch-request response must be the
    /// JSON-RPC 2.0 Invalid Request code, not a 200 with a garbled method name.
    #[test]
    fn batch_response_is_invalid_request_code() {
        let v = batch_not_supported_response();
        assert_eq!(v["error"]["code"], json!(-32600));
        assert_eq!(v["jsonrpc"], json!("2.0"));
    }
}

// ── L-5 regression: storage errors never reach the caller verbatim ─────────

#[cfg(test)]
mod l5_storage_error_sanitization_tests {
    use super::*;

    /// The core L-5 property: whatever detail `StorageError` carries (here, a
    /// fabricated RocksDB-shaped message with a filesystem path, mirroring
    /// what `storage/mod.rs`'s real `.map_err(|e| StorageError::ReadFailed(e.to_string()))`
    /// sites would actually produce) must NOT appear anywhere in the JSON
    /// handed back to the RPC caller.
    #[test]
    fn caller_response_never_contains_the_storage_detail() {
        let sensitive = StorageError::ReadFailed(
            "IO error: /var/lib/bloch-data/CF_BLOCKS/000123.sst: No such file or directory".into(),
        );
        let resp = storage_err_response(&sensitive);
        let rendered = resp.to_string();
        assert!(
            !rendered.contains("/var/lib/bloch-data"),
            "filesystem path from the underlying storage error leaked into the RPC response: {}",
            rendered
        );
        assert!(
            !rendered.contains("CF_BLOCKS"),
            "column-family internal name leaked into the RPC response: {}",
            rendered
        );
    }

    /// Review finding (NET-12 regression of L-5): the explorer statistics
    /// (`getrichlist`, `getsupplydistribution`, `getaddresscount`,
    /// `getchainstats`, `gethashrate`) return a typed `StatsError`; a
    /// storage failure is answered with the sanitised response and its
    /// detail never reaches the caller. (`StatsError` is not `Serialize`
    /// and its `Display` of a storage failure carries no detail, so no
    /// handler can echo it.) Pre-fix they returned `e.to_string()` of the
    /// `StorageError` — e.g. a RocksDB message with the data-dir path.
    #[test]
    fn stats_storage_errors_are_sanitised() {
        use crate::analytics::StatsError;
        let sensitive = StatsError::Storage(StorageError::ReadFailed(
            "IO error: /var/lib/gnb/db/000123.sst: No such file or directory".into(),
        ));
        let r = stats_err_response(&sensitive);
        assert_eq!(r, json!({ "error": "internal storage error", "code": "STORAGE_ERROR" }));
        assert!(!r.to_string().contains("/var/lib"), "{r}");
        assert!(!sensitive.to_string().contains("/var/lib"), "Display carries no detail either");
        assert_eq!(stats_err_response(&StatsError::Cancelled), json!({ "error": "cancelled" }));
        assert!(stats_err_response(&StatsError::NotReady)["error"].as_str().unwrap().contains("not built"));
        assert!(stats_err_response(&StatsError::NoTip).get("code").is_none());
    }

    /// Every `StorageError` variant must produce the SAME stable response —
    /// nothing about which failure mode occurred (open/read/write/serialize)
    /// should be distinguishable from the response shape either.
    #[test]
    fn every_storage_error_variant_yields_the_identical_stable_response() {
        let variants = [
            StorageError::OpenFailed("detail a".into()),
            StorageError::CfNotFound("detail b".into()),
            StorageError::SerializeFailed("detail c".into()),
            StorageError::DeserializeFailed("detail d".into()),
            StorageError::WriteFailed("detail e".into()),
            StorageError::ReadFailed("detail f".into()),
        ];
        let responses: Vec<Value> = variants.iter().map(storage_err_response).collect();
        for r in &responses {
            assert_eq!(*r, responses[0], "every StorageError variant must map to the identical sanitized response");
        }
        assert_eq!(responses[0], json!({ "error": "internal storage error", "code": "STORAGE_ERROR" }));
    }
}

#[cfg(test)]
mod r3_amount_encoding_tests {
    use super::*;
    use crate::core::{TxInput, TxOutput};

    fn tx_with_output(value: u64) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: [9u8; 32], prev_index: 0, script_sig: vec![], sequence: u32::MAX,
            }],
            outputs: vec![TxOutput { value, script_pubkey: vec![5u8; 20] }],
            locktime: 0,
        }
    }

    #[test]
    fn tx_output_value_serializes_as_a_decimal_string() {
        let v = format_tx(&tx_with_output(354_617_540_000_000_000));
        let out = &v["outputs"][0];
        assert!(out["value"].is_string(), "R3: `value` must be a JSON string, got {}", out["value"]);
        assert_eq!(out["value"].as_str().unwrap(), "354617540000000000");
        // The display-only float companion stays a JSON number (lossy by design).
        assert!(out["gnb"].is_number(), "`gnb` stays a float");
    }

    #[test]
    fn amounts_past_the_javascript_safe_integer_survive_the_wire() {
        // A value above 2^53 round-trips exactly through the string form; the
        // same value as a JSON number is what R3 exists to prevent.
        let big = u64::MAX;
        let v = format_tx(&tx_with_output(big));
        let s = v["outputs"][0]["value"].as_str().expect("string amount");
        assert_eq!(s.parse::<u64>().unwrap(), big);
        assert!(big > 9_007_199_254_740_991, "test value must exceed MAX_SAFE_INTEGER");
    }
}

/// Format a hashrate in H/s into human-readable units (H/s, KH/s, MH/s, GH/s, TH/s, PH/s, EH/s).
fn format_hashrate(hs: f64) -> String {
    const UNITS: &[(&str, f64)] = &[
        ("EH/s", 1e18),
        ("PH/s", 1e15),
        ("TH/s", 1e12),
        ("GH/s", 1e9),
        ("MH/s", 1e6),
        ("KH/s", 1e3),
    ];
    for (label, threshold) in UNITS {
        if hs >= *threshold {
            return format!("{:.2} {}", hs / threshold, label);
        }
    }
    format!("{:.2} H/s", hs)
}


// ─────────────────────────────────────────────────────────────────────────────
// C-R3-2 (Round-2 audit, LEG2-intra-dup) — intra-transaction double-spend on
// the RPC admission path. `validate_tx_for_mempool` (sendrawtransaction) had
// NO duplicate-outpoint check at all: a tx listing the SAME outpoint N times
// had its value counted N times and was admitted with an N×-inflated fee.
// The gossip-path twins live in main.rs `intra_tx_dup_tests`; the euvm path
// was already covered (`euvm_admission_tests::intra_tx_double_spend_rejected`).
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod c_r3_2_intra_dup_tests {
    use super::*;
    use crate::core::{TxInput, TxOutput};
    use tempfile::TempDir;

    fn mk_store() -> (TempDir, Arc<Storage>) {
        let tmp = TempDir::new().expect("tempdir");
        let store = Arc::new(Storage::open(&tmp.path().join("db")).expect("storage"));
        (tmp, store)
    }

    /// A tx spending the SAME confirmed 100_000-sat outpoint `n` times, every
    /// input carrying a VALID hybrid signature over its own sighash — without
    /// the duplicate check nothing else rejects it.
    fn dup_input_tx(store: &Arc<Storage>, n: usize, out_value: u64) -> Transaction {
        use sha3::{Digest as _, Sha3_256};
        let (pk, sk) = crate::crypto::generate_keypair();
        let pk_hash = Sha3_256::digest(&pk)[..20].to_vec();
        let prev_txid = [0x42u8; 32];
        store.put_utxo(&prev_txid, 0,
            &TxOutput { value: 100_000, script_pubkey: pk_hash })
            .expect("put_utxo");

        let mut tx = Transaction {
            version: 1,
            inputs: (0..n).map(|_| TxInput {
                prev_txid, prev_index: 0, script_sig: vec![], sequence: u32::MAX,
            }).collect(),
            outputs: vec![TxOutput { value: out_value, script_pubkey: vec![7u8; 20] }],
            locktime: 0,
        };
        for i in 0..n {
            let sighash = tx.sighash(i, crate::core::node_chain_id());
            let sig = crate::crypto::sign(&sk, &sighash).expect("sign");
            tx.inputs[i].script_sig = Transaction::build_script_sig(&sig, &pk);
        }
        tx
    }

    /// sendrawtransaction admission: a 2-duplicate-input tx spending a 100k
    /// outpoint but emitting 150k must be refused. Without the fix it was
    /// ADMITTED with fee = 50_000 (the outpoint's value counted twice).
    #[test]
    fn rpc_path_refuses_intra_tx_duplicate_outpoint() {
        let (_tmp, store) = mk_store();
        let tx = dup_input_tx(&store, 2, 150_000);
        let err = validate_tx_for_mempool(&tx, &store, 0)
            .expect_err("intra-tx duplicate outpoint must be refused");
        assert!(err.contains("double-spend"), "got: {err}");
    }

    /// N=3 duplication is refused too (the check is set-based, not pairwise).
    #[test]
    fn rpc_path_refuses_triple_duplicate() {
        let (_tmp, store) = mk_store();
        let tx = dup_input_tx(&store, 3, 290_000);
        let err = validate_tx_for_mempool(&tx, &store, 0)
            .expect_err("intra-tx duplicate outpoint must be refused");
        assert!(err.contains("double-spend"), "got: {err}");
    }

    /// Control: the SAME signed shape with a single input and honest amounts
    /// is still admitted with the right fee.
    #[test]
    fn rpc_single_input_control_still_admitted() {
        let (_tmp, store) = mk_store();
        let tx = dup_input_tx(&store, 1, 70_000);
        let fee = validate_tx_for_mempool(&tx, &store, 0)
            .expect("valid single-input spend must be admitted");
        assert_eq!(fee, 30_000);
    }
}

// ── R3-audit H-R3-5 tests: CORS layer + heavy-read gate ─────────────────────
//
// The auth-layer refusal logic (Host/Origin/loopback/WRITE_METHODS) is
// unit-tested in `auth.rs`; these tests pin the two pieces that live here:
// the mounted CORS layer is NOT permissive, and the heavy-read gate bounds
// the O(chain) analytics methods.
#[cfg(test)]
mod h_r3_5_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{header, HeaderValue, Method, Request, StatusCode};
    use tower::util::ServiceExt; // oneshot

    fn router_with(origins: &[&str]) -> Router {
        let origins: Vec<String> = origins.iter().map(|s| s.to_string()).collect();
        Router::new()
            .route("/", axum::routing::post(|| async { "ok" }))
            .layer(build_cors_layer(&origins))
    }

    async fn preflight(router: Router, origin: &str) -> axum::http::Response<Body> {
        let req = Request::builder()
            .method(Method::OPTIONS)
            .uri("/")
            .header(header::ORIGIN, origin)
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "content-type")
            .body(Body::empty())
            .unwrap();
        router.oneshot(req).await.unwrap()
    }

    /// The core regression: with the default (empty) origin allowlist, a
    /// hostile page's preflight gets NO Access-Control-Allow-Origin grant.
    /// `CorsLayer::permissive()` echoed the origin back — this test FAILS on
    /// the pre-fix wiring.
    #[tokio::test]
    async fn default_config_grants_no_cors_to_any_origin() {
        let resp = preflight(router_with(&[]), "https://evil.example").await;
        assert!(
            resp.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none(),
            "no origin allowlisted, yet a CORS grant was emitted: {:?}",
            resp.headers()
        );
    }

    #[tokio::test]
    async fn allowlisted_origin_gets_cors_unlisted_does_not() {
        let router = router_with(&["https://wallet.posternlabs.com"]);
        let ok = preflight(router.clone(), "https://wallet.posternlabs.com").await;
        assert_eq!(
            ok.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
            Some(&HeaderValue::from_static("https://wallet.posternlabs.com")),
        );
        let bad = preflight(router, "https://evil.example").await;
        assert!(bad.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none(),
            "unlisted origin must not receive a CORS grant");
    }

    /// Simple (non-preflighted) POST: the response must carry no grant for an
    /// unlisted origin, so a browser page cannot read it.
    #[tokio::test]
    async fn simple_post_response_carries_no_grant_for_unlisted_origin() {
        let req = Request::builder()
            .method(Method::POST)
            .uri("/")
            .header(header::ORIGIN, "https://evil.example")
            .body(Body::empty())
            .unwrap();
        let resp = router_with(&[]).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK); // handler ran (gate lives in handle_rpc)
        assert!(resp.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
    }

    // ── HeavyGate ───────────────────────────────────────────────────

    #[test]
    fn heavy_methods_are_exactly_the_five_scanners() {
        for m in ["getsupplydistribution", "getchainstats", "gethashrate",
                  "getaddresscount", "getaddressbalance_at_height"] {
            assert!(HeavyGate::is_heavy(m), "{m} must be gated");
        }
        assert!(!HeavyGate::is_heavy("getblockcount"));
        assert!(!HeavyGate::is_heavy("sendrawtransaction"));
    }

    #[test]
    fn heavy_gate_serves_cache_instead_of_rescanning() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let gate = HeavyGate::new(std::time::Duration::from_secs(60));
        let scans = AtomicU32::new(0);
        for _ in 0..10 {
            let v = gate.run("getsupplydistribution|".into(), || {
                scans.fetch_add(1, Ordering::SeqCst);
                json!({"tiers": []})
            });
            assert_eq!(v, json!({"tiers": []}));
        }
        assert_eq!(scans.load(Ordering::SeqCst), 1,
            "10 identical heavy calls inside the TTL must run exactly 1 scan");
    }

    #[test]
    fn heavy_gate_refuses_concurrent_second_scan() {
        use std::sync::Arc as StdArc;
        let gate = StdArc::new(HeavyGate::new(std::time::Duration::from_secs(60)));
        let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let g2 = gate.clone();
        let t = std::thread::spawn(move || {
            g2.run("getchainstats|".into(), || {
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap(); // hold the scan permit
                json!({"total_blocks": 1})
            })
        });
        started_rx.recv().unwrap(); // first scan is in flight
        // A different heavy key cannot start a second concurrent scan.
        let v = gate.run("getsupplydistribution|".into(), || json!({"should": "not run"}));
        assert!(v.get("error").is_some(),
            "second concurrent heavy scan must be refused, got {v}");
        release_tx.send(()).unwrap();
        assert_eq!(t.join().unwrap(), json!({"total_blocks": 1}));
    }

    #[test]
    fn heavy_gate_cache_is_bounded() {
        let gate = HeavyGate::new(std::time::Duration::from_secs(3600));
        // Parameterised heavy method: attacker varies params to grow the map.
        for i in 0..(HEAVY_READ_CACHE_MAX_KEYS * 4) {
            gate.run(format!("getaddressbalance_at_height|[\"addr{i}\",1]"), || json!(i));
        }
        assert!(gate.cache.lock().len() <= HEAVY_READ_CACHE_MAX_KEYS,
            "cache must stay bounded under key churn");
    }
}

// ── 2026-10 audit regressions: NET-12, NET-13, NET-14, NET-15, WAL-1 ───────
#[cfg(test)]
mod audit_2026_10_rpc_tests {
    use super::*;
    use crate::core::{Block, BlockHeader, MerkleRoot, TxInput, TxOutput};
    use tempfile::TempDir;

    /// An AppState over a fresh store and a linear DAG of `n` chain blocks
    /// spaced 30 s apart (the last 10 gaps are 60 s).
    fn state_with_chain(n: u8) -> (TempDir, AppState) {
        let tmp = TempDir::new().expect("tempdir");
        let store = Arc::new(Storage::open(&tmp.path().join("db")).expect("storage"));
        let mut dag = GhostDAG::with_default_k();
        dag.add_genesis([0u8; 32], 1_000);
        let mut ts = 1_000u64;
        for i in 1..=n {
            ts += if i > n.saturating_sub(10) { 60 } else { 30 };
            dag.add_block([i; 32], vec![[i - 1; 32]], ts, 1).unwrap();
        }
        let (outbound_tx, _rx) = mpsc::channel(1);
        let state = AppState {
            node_state: Arc::new(RwLock::new(NodeState::default())),
            store,
            mempool: Arc::new(Mempool::new()),
            dag: Arc::new(RwLock::new(dag)),
            outbound_tx,
            api_key: None,
            require_auth_for_writes: false,
            require_auth_for_reads: false,
            rate_limiter: Arc::new(auth::RateLimiterSet::new(60, 5)),
            trust_private_ranges: false,
            allowed_origins: Arc::new(Vec::new()),
            allowed_hosts: Arc::new(Vec::new()),
            trust_loopback: false,
            heavy_gate: Arc::new(HeavyGate::new(HEAVY_READ_CACHE_TTL)),
            template_gate: Arc::new(HeavyGate::for_templates()),
            submit_block: None,
            cancel: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            chain_admin: None,
        };
        (tmp, state)
    }

    #[test]
    fn method_labels_are_bounded_and_logs_truncated() {
        assert_eq!(method_label("getblockcount"), "getblockcount");
        assert_eq!(method_label(&"x".repeat(1 << 20)), "unknown");
        assert_eq!(method_label("getBlockCount"), "unknown");
        let logged = method_for_log(&"\u{1b}[31m".repeat(10_000));
        assert!(logged.len() < 4 * MAX_LOGGED_METHOD_LEN, "{}", logged.len());
        assert!(!logged.contains('\u{1b}'), "control characters are escaped");
    }

    /// Every arm of `dispatch` is a known method (so it gets its own metrics
    /// label) and every known method has an arm.
    #[test]
    fn known_methods_list_matches_dispatch() {
        let src = include_str!("mod.rs");
        let start = src.find("async fn dispatch(").unwrap();
        let end = src[start..].find("// ── Helpers").unwrap() + start;
        let mut arms = std::collections::BTreeSet::new();
        for line in src[start..end].lines() {
            let t = line.trim_start();
            if let Some(rest) = t.strip_prefix('"') {
                if let Some(q) = rest.find('"') {
                    if rest[q + 1..].trim_start().starts_with("=>") {
                        arms.insert(rest[..q].to_string());
                    }
                }
            }
        }
        let known: std::collections::BTreeSet<String> = KNOWN_RPC_METHODS.iter().map(|s| s.to_string()).collect();
        assert_eq!(arms, known);
    }

    /// A cached `getblocktemplate` never outlives the chain it was built on:
    /// its key changes with a new block. A pool transaction does not change
    /// it (the template catches up within TEMPLATE_CACHE_TTL), so a miner
    /// polling a busy pool does not rebuild on every call. Functional
    /// counterpart: test/functional/mining_getblocktemplate_submitblock.py.
    /// (Invalidation and body arrival: the test below.)
    #[test]
    fn template_cache_key_follows_new_blocks_not_the_pool() {
        let (_tmp, state) = state_with_chain(3);
        let k0 = template_cache_key(None, &state);
        assert_eq!(k0, template_cache_key(None, &state), "stable while nothing changes");

        let tx = crate::core::Transaction {
            version: 1,
            inputs: vec![TxInput { prev_txid: [7; 32], prev_index: 0, script_sig: vec![1; 8], sequence: 0 }],
            outputs: vec![TxOutput { value: 10_000, script_pubkey: vec![2; 20] }],
            locktime: 0,
        };
        state.mempool.add(tx, 1_000_000).expect("pool accepts the fixture");
        assert_eq!(template_cache_key(None, &state), k0, "a pool change alone keeps the key");

        state.dag.write().add_block([9; 32], vec![[3; 32]], 2_000, 1).unwrap();
        assert_ne!(template_cache_key(None, &state), k0, "a new tip must miss the cached template");
        assert_ne!(template_cache_key(Some(&json!([{"x": 1}])), &state), template_cache_key(None, &state));
    }

    /// What a template build returns, as far as the cache reads it: the
    /// parents and height `template_parents_and_height` gives on the DAG at
    /// build time (the fields the builder copies from the template it built),
    /// and `n` to tell builds apart.
    fn fake_template(state: &AppState, n: u32) -> Value {
        let (parents, height) = {
            let dag = state.dag.read();
            crate::template::template_parents_and_height(&dag, &state.store)
        };
        json!({"template": n, "parents": parents.iter().map(hex::encode).collect::<Vec<_>>(), "height": height})
    }

    /// getblocktemplate has its own gate: while a public analytics scan
    /// holds the HeavyGate's permit, a template is still built (it used to
    /// be answered "busy"), and analytics are still refused; a second
    /// template call with the same tips is served from the template cache,
    /// a new tip rebuilds at once.
    #[test]
    fn template_requests_are_not_blocked_by_an_analytics_scan() {
        let (_tmp, state) = state_with_chain(3);
        let builds = std::cell::Cell::new(0u32);
        let build = || { builds.set(builds.get() + 1); fake_template(&state, builds.get()) };
        let scan = state.heavy_gate.scan.lock(); // an analytics scan in flight
        assert_eq!(gated_dispatch("getblocktemplate", None, &state, build)["template"], 1);
        let refused = gated_dispatch("getrichlist", None, &state, || json!({"should": "not run"}));
        assert!(refused["error"].as_str().unwrap_or("").contains("busy"), "{refused}");
        drop(scan);
        assert_eq!(gated_dispatch("getblocktemplate", None, &state, build)["template"], 1,
            "same tips: served from the template cache");
        state.dag.write().add_block([9; 32], vec![[3; 32]], 2_000, 1).unwrap();
        assert_eq!(gated_dispatch("getblocktemplate", None, &state, build)["template"], 2,
            "a new tip rebuilds at once");
        assert_eq!(builds.get(), 2);
        assert_eq!(gated_dispatch("getblockcount", None, &state, || json!(7)), json!(7));
        assert!(TEMPLATE_CACHE_TTL <= std::time::Duration::from_secs(5));
    }

    /// A template call that finds another template build in flight is told
    /// so, not that "another heavy analytics scan" is (the template gate
    /// answered with the analytics gate's text); analytics keep theirs.
    #[test]
    fn a_busy_template_gate_names_the_template_build() {
        let (_tmp, state) = state_with_chain(3);
        let build = state.template_gate.scan.lock(); // a template build in flight
        let busy = gated_dispatch("getblocktemplate", None, &state, || json!({"should": "not run"}));
        let text = busy["error"].as_str().unwrap_or("");
        assert!(text.starts_with("busy:") && text.contains("getblocktemplate"), "{busy}");
        assert!(!text.contains("analytics"), "{busy}");
        drop(build);
        let scan = state.heavy_gate.scan.lock();
        let busy = gated_dispatch("getrichlist", None, &state, || json!({"should": "not run"}));
        assert!(busy["error"].as_str().unwrap_or("").contains("analytics scan"), "{busy}");
        drop(scan);
    }

    /// The template key changes with every block, so the template gate keeps
    /// only fresh templates, and few: an expired one is dropped when the next
    /// is stored, and at most TEMPLATE_CACHE_MAX_KEYS are kept, the newest.
    /// With the analytics gate's eviction (only once 64 keys were reached), a
    /// node kept up to 63 dead templates of up to about 2 MB each for good.
    #[test]
    fn the_template_gate_keeps_only_a_few_fresh_templates() {
        let gate = HeavyGate::with_limits(std::time::Duration::from_millis(30), TEMPLATE_CACHE_MAX_KEYS, TEMPLATE_BUSY);
        gate.run("parents=a".into(), || json!(1));
        std::thread::sleep(std::time::Duration::from_millis(60));
        gate.run("parents=b".into(), || json!(2));
        assert_eq!(gate.cache.lock().keys().cloned().collect::<Vec<_>>(), vec!["parents=b".to_string()],
            "the expired template must be dropped when the next one is stored");

        let gate = HeavyGate::for_templates();
        const { assert!(TEMPLATE_CACHE_MAX_KEYS < HEAVY_READ_CACHE_MAX_KEYS) };
        for i in 0..(HEAVY_READ_CACHE_MAX_KEYS * 2) {
            gate.run(format!("parents={i}"), || json!(i));
        }
        let last = HEAVY_READ_CACHE_MAX_KEYS * 2 - 1;
        {
            let cache = gate.cache.lock();
            assert_eq!(cache.len(), TEMPLATE_CACHE_MAX_KEYS);
            assert!(cache.contains_key(&format!("parents={last}")), "the newest template is kept");
        }
        // ... and served while fresh.
        assert_eq!(gate.run(format!("parents={last}"), || json!("rebuilt")), json!(last));
    }

    #[test]
    fn bind_addresses_resolve_ipv4_ipv6_and_names() {
        assert!(resolve_bind_address("127.0.0.1", 17210).unwrap().is_ipv4());
        assert!(resolve_bind_address("::1", 17210).unwrap().is_ipv6());
        assert!(resolve_bind_address("[::1]", 17210).unwrap().is_ipv6());
        assert!(resolve_bind_address("localhost", 17210).is_ok());
        assert!(resolve_bind_address("not a host name", 17210).is_err());
    }

    /// NET-14: an RPC server whose port is taken returns instead of taking
    /// the node down with it.
    #[tokio::test]
    async fn rpc_server_bind_failure_returns() {
        let (_tmp, state) = state_with_chain(1);
        let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let config = RpcConfig { port: busy.local_addr().unwrap().port(), ..RpcConfig::default() };
        tokio::time::timeout(std::time::Duration::from_secs(10), start_rpc_server(
            config, state.node_state.clone(), state.store.clone(), state.mempool.clone(),
            state.dag.clone(), state.outbound_tx.clone(), None, None,
        )).await.expect("a failed bind must end the RPC task");
    }

    /// Review finding (getblocktemplate x MEM-6 CPFP): every transaction
    /// entry carries `depends`, the 1-based positions of its in-template
    /// parents (BIP22), so an external miner that keeps a subset of the
    /// entries can keep it closed under dependencies.
    #[test]
    fn getblocktemplate_entries_list_in_template_dependencies() {
        let tx = |ins: &[([u8; 32], u32)], tag: u8| Transaction {
            version: 1,
            inputs: ins.iter().map(|(t, i)| TxInput { prev_txid: *t, prev_index: *i, script_sig: vec![tag; 8], sequence: u32::MAX }).collect(),
            outputs: vec![TxOutput { value: 1_000, script_pubkey: vec![tag; 20] }, TxOutput { value: 1_000, script_pubkey: vec![tag; 20] }],
            locktime: 0,
        };
        let a = tx(&[([0xA0; 32], 0)], 1);
        let b = tx(&[(a.txid(), 0)], 2);
        let c = tx(&[([0xA1; 32], 0)], 3);
        let d = tx(&[(b.txid(), 1), (a.txid(), 1), (b.txid(), 0), ([0xA2; 32], 0)], 4);
        let tmpl = crate::template::BlockTemplate {
            parents: vec![[0; 32]], height: 1, blue_score: 1, bits: 0x2100_FFFF, parent_timestamp: 0,
            transactions: vec![(a.clone(), 10), (b.clone(), 20), (c.clone(), 30), (d.clone(), 40)],
            total_fees: 100, subsidy: 0, evicted: 0, tx_byte_budget: 0,
            activation_height: u64::MAX, hardened: false,
            powit: Default::default(),
        };
        let entries = template_tx_entries(&tmpl);
        let depends: Vec<Value> = entries.iter().map(|e| e["depends"].clone()).collect();
        assert_eq!(depends, vec![json!([]), json!([1]), json!([]), json!([1, 2])]);
        for (e, (t, fee)) in entries.iter().zip(&tmpl.transactions) {
            assert_eq!(e["txid"], hex::encode(t.txid()));
            assert_eq!(e["fee"], fee.to_string());
            assert_eq!(e["data"], hex::encode(t.to_wire_bytes(true)));
        }
    }

    /// Audit DAG-6: `invalidateblock` / `reconsiderblock` parse one block
    /// hash and reach the chain-admin hook with the right operation; a bad
    /// parameter never reaches it; an unwired node says so.
    #[tokio::test]
    async fn chain_admin_methods_reach_the_hook() {
        let (_tmp, mut state) = state_with_chain(1);
        let r = dispatch("invalidateblock", Some(&json!([hex::encode([7u8; 32])])), &state).await;
        assert!(r["error"].as_str().unwrap().contains("not wired"), "{r}");

        type Calls = parking_lot::Mutex<Vec<(ChainAdminOp, [u8; 32])>>;
        let calls: Arc<Calls> = Arc::default();
        let seen = calls.clone();
        state.chain_admin = Some(Arc::new(move |op, h| {
            seen.lock().push((op, h));
            Ok(json!({ "tip": hex::encode(h) }))
        }));
        let r = dispatch("invalidateblock", Some(&json!([hex::encode([7u8; 32])])), &state).await;
        assert_eq!(r["tip"], json!(hex::encode([7u8; 32])));
        let r = dispatch("reconsiderblock", Some(&json!([hex::encode([8u8; 32])])), &state).await;
        assert_eq!(r["tip"], json!(hex::encode([8u8; 32])));
        for bad in [json!([]), json!(["zz"]), json!([hex::encode([1u8; 31])])] {
            let r = dispatch("invalidateblock", Some(&bad), &state).await;
            assert!(r["error"].as_str().unwrap().contains("block hash"), "{r}");
        }
        assert_eq!(*calls.lock(), vec![
            (ChainAdminOp::Invalidate, [7u8; 32]),
            (ChainAdminOp::Reconsider, [8u8; 32]),
        ]);
    }

    /// WAL-1: `getrawtransaction` returns bytes that hash to the txid.
    #[tokio::test]
    async fn getrawtransaction_returns_bytes_that_hash_to_the_txid() {
        let (_tmp, state) = state_with_chain(1);
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxInput { prev_txid: [0; 32], prev_index: u32::MAX, script_sig: b"height:1".to_vec(), sequence: u32::MAX }],
            outputs: vec![TxOutput { value: 5, script_pubkey: vec![1; 20] }],
            locktime: 0,
        };
        let spend = Transaction {
            version: 1,
            inputs: vec![TxInput { prev_txid: [7; 32], prev_index: 1, script_sig: vec![9; 40], sequence: u32::MAX }],
            outputs: vec![TxOutput { value: 123_456, script_pubkey: vec![2; 20] }],
            locktime: 0,
        };
        let mut block = Block {
            header: BlockHeader { version: 1, parents: vec![[0; 32]], merkle_root: MerkleRoot::ZERO, timestamp: 1_030, bits: 0x2100_FFFF, nonce: 0 },
            transactions: vec![coinbase.clone(), spend.clone()],
            blue_score: 1, height: 1, shielded_transactions: vec![],
            powit: Default::default(),
        };
        block.header.merkle_root = block.body_merkle_root();
        state.store.put_block(&block).unwrap();
        for tx in [&coinbase, &spend] {
            state.store.put_tx_index(&tx.txid(), &block.block_hash(), 1).unwrap();
        }
        for tx in [&coinbase, &spend] {
            let r = dispatch("getrawtransaction", Some(&json!([hex::encode(tx.txid())])), &state).await;
            let raw = hex::decode(r["hex"].as_str().expect("hex")).unwrap();
            assert_eq!(Transaction::from_wire_bytes(&raw).unwrap().txid(), tx.txid());
            assert_eq!(r["block_height"], 1);
        }
        let r = dispatch("getrawtransaction", Some(&json!([hex::encode([3u8; 32])])), &state).await;
        assert!(r["error"].is_string());
        let r = dispatch("getrawtransaction", Some(&json!(["zz"])), &state).await;
        assert_eq!(r["error"], "invalid txid");
    }

    /// NET-12: `getutxos` stops at its limit while walking the index.
    #[tokio::test]
    async fn getutxos_applies_its_limit_while_iterating() {
        let (_tmp, state) = state_with_chain(1);
        let address = crate::address::Address::from_hash([4; 20], crate::address::Network::Mainnet);
        for i in 0..5u8 {
            state.store.put_utxo(&[i; 32], 0, &TxOutput { value: 1_000, script_pubkey: vec![4; 20] }).unwrap();
        }
        let (rows, more) = state.store.get_utxos_for_address_limited(&[4; 20], 2).unwrap();
        assert_eq!((rows.len(), more), (2, true));
        let (rows, more) = state.store.get_utxos_for_address_limited(&[4; 20], 5).unwrap();
        assert_eq!((rows.len(), more), (5, false));

        let r = dispatch("getutxos", Some(&json!([address.to_string(), 2])), &state).await;
        assert_eq!(r["returned"], 2);
        assert_eq!(r["truncated"], true);
        assert_eq!(r["satoshis"], "2000");
        let r = dispatch("getutxos", Some(&json!([address.to_string()])), &state).await;
        assert_eq!(r["returned"], 5);
        assert_eq!(r["truncated"], false);

        // An output of a coinbase carries its coinbase's height (wallets skip
        // immature ones); any other output carries no such field.
        state.store.put_coinbase_info(&[3; 32], 77).unwrap();
        let r = dispatch("getutxos", Some(&json!([address.to_string()])), &state).await;
        let rows = r["utxos"].as_array().unwrap();
        for row in rows {
            let expected = if row["txid"] == hex::encode([3u8; 32]) { json!(77) } else { Value::Null };
            assert_eq!(row["coinbase_height"], expected, "{row}");
        }
    }

    /// NET-12: the chain-walking statistics read only the requested window.
    #[tokio::test]
    async fn block_time_percentiles_walk_only_the_window() {
        let (_tmp, state) = state_with_chain(60);
        assert!(HeavyGate::is_heavy("getblocktimepercentiles"));
        assert!(HeavyGate::is_heavy("getdifficultyhistory"));
        let r = dispatch("getblocktimepercentiles", Some(&json!([10])), &state).await;
        assert_eq!(r["sample_size"], 10);
        assert_eq!(r["p50_secs"], 60);
        let r = dispatch("getblocktimepercentiles", Some(&json!([1000])), &state).await;
        assert_eq!(r["sample_size"], 60);
        assert_eq!(r["min_secs"], 30);
        // No stored bodies: the difficulty walk is bounded and empty.
        let r = dispatch("getdifficultyhistory", Some(&json!([500])), &state).await;
        assert_eq!(r["count"], 0);
    }

    /// NET-12: the explorer statistics read a bounded number of storage
    /// entries (counted by the store) whatever the number of holders; the
    /// answers match the UTXO set. Pre-fix `getrichlist` /
    /// `getsupplydistribution` / `getaddresscount` scanned the whole UTXO
    /// set and `getchainstats` / `gethashrate` decoded every block body.
    #[tokio::test]
    async fn net12_explorer_methods_read_bounded_entries() {
        let (_tmp, state) = state_with_chain(60);
        assert!(state.store.aggregates_ready());
        for i in 0..300u32 {
            let mut spk = vec![0u8; 20];
            spk[..4].copy_from_slice(&i.to_le_bytes());
            state.store.put_utxo(&[(i % 251) as u8; 32], i, &TxOutput { value: 1_000 + i as u64, script_pubkey: spk }).unwrap();
        }
        for (method, params, bound) in [
            ("getrichlist", json!([100, 0]), 102u64),
            ("getrichlist", json!([100, 200]), 302),
            ("getsupplydistribution", json!([]), 1),
            ("getaddresscount", json!([]), 1),
            ("getchainstats", json!([]), 5),
            ("gethashrate", json!([]), 5),
        ] {
            let r0 = state.store.storage_reads();
            let r = dispatch(method, Some(&params), &state).await;
            let reads = state.store.storage_reads() - r0;
            assert!(r.get("error").is_none(), "{method}: {r}");
            assert!(reads <= bound, "{method} {params}: {reads} reads > {bound}");
        }
        let r = dispatch("getrichlist", Some(&json!([100, 0])), &state).await;
        assert_eq!(r["holders"], 300);
        assert_eq!(r["items"].as_array().unwrap().len(), 100);
        assert_eq!(r["items"][0]["balance"], "1299");
        assert_eq!(r["items"][0]["rank"], 1);
        let r = dispatch("getrichlist", Some(&json!([10, 1_000_000_000u64])), &state).await;
        assert_eq!(r["offset"], crate::analytics::MAX_RICHLIST_OFFSET, "offset clamped");
        let r = dispatch("getaddresscount", None, &state).await;
        assert_eq!((r["addresses_with_balance"].as_u64(), r["utxo_entries"].as_u64()), (Some(300), Some(300)));
        let r = dispatch("getchainstats", None, &state).await;
        assert_eq!(r["total_blocks"], 61);
        // A cancelled request stops (and HeavyGate never caches the error).
        let mut cancelled = state.clone();
        cancelled.cancel = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let r = dispatch("getchainstats", None, &cancelled).await;
        assert_eq!(r["error"], "cancelled");
        let gate = HeavyGate::new(HEAVY_READ_CACHE_TTL);
        assert_eq!(gate.run("k".into(), || json!({ "error": "cancelled" }))["error"], "cancelled");
        assert_eq!(gate.run("k".into(), || json!(7)), json!(7), "the failure was not cached");
    }

    /// Review finding (chain_tail): a cancelled request is an ERROR for the
    /// two selected-chain walks, also when the flag was set while the
    /// request waited for the DAG lock, and HeavyGate never caches it — the
    /// next uncancelled call computes real values. Pre-fix `chain_tail`
    /// stopped silently and returned an empty tail: `{sample_size: 0,
    /// p50_secs: 0, ...}` and `{count: 0, points: []}` as successes, cached
    /// for 30 s.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn net12_cancelled_chain_walks_are_errors_and_never_cached() {
        let (_tmp, state) = state_with_chain(60);
        let mut cancelled = state.clone();
        cancelled.cancel = Arc::new(std::sync::atomic::AtomicBool::new(true));
        for m in ["getblocktimepercentiles", "getdifficultyhistory"] {
            let r = dispatch(m, Some(&json!([10])), &cancelled).await;
            assert_eq!(r["error"], "cancelled", "{m}: {r}");
        }
        // Exactly as the server runs a heavy method: HeavyGate around a
        // blocking dispatch, both states sharing one gate.
        let run = |st: AppState| {
            let h = tokio::runtime::Handle::current();
            tokio::task::spawn_blocking(move || {
                st.heavy_gate.clone().run("getblocktimepercentiles|[10]".into(), || {
                    h.block_on(dispatch("getblocktimepercentiles", Some(&json!([10])), &st))
                })
            })
        };
        let r = run(cancelled).await.unwrap();
        assert_eq!(r["error"], "cancelled");
        let r = run(state).await.unwrap();
        assert!(r.get("error").is_none(), "{r}");
        assert_eq!(r["sample_size"], 10, "computed, not served from a cached failure: {r}");
        assert_eq!(r["p50_secs"], 60);
    }

    /// MEM-6: `getmempoolinfo` reports the relay policy in force.
    #[tokio::test]
    async fn mem6_getmempoolinfo_reports_the_policy() {
        let (_tmp, state) = state_with_chain(1);
        let r = dispatch("getmempoolinfo", None, &state).await;
        assert_eq!(r["policy"]["max_replacement_evictions"], crate::mempool::MAX_REPLACEMENT_EVICTIONS);
        assert_eq!(r["policy"]["max_ancestors"], crate::mempool::MAX_ANCESTORS);
        assert_eq!(r["policy"]["unconfirmed_chains"], true);
        assert!(r["policy"]["replacement"].as_str().unwrap().starts_with("full-rbf"));
    }

    /// NET-15: explorer reads still work with storage access moved out of
    /// the DAG lock (and do not deadlock against a concurrent writer).
    #[tokio::test]
    async fn explorer_reads_release_the_dag_lock_before_storage() {
        let (_tmp, state) = state_with_chain(5);
        let r = dispatch("getselectedchain", Some(&json!([0, 3])), &state).await;
        assert_eq!(r["chain_length"], 6);
        assert_eq!(r["blocks"].as_array().unwrap().len(), 3);
        assert_eq!(r["blocks"][0]["height"], 5);
        let r = dispatch("getblockdag", Some(&json!([hex::encode([3u8; 32])])), &state).await;
        assert_eq!(r["colour"], "chain");
        assert_eq!(r["body"], false);
        assert_eq!(r["next_chain_block"], hex::encode([4u8; 32]));
        let r = dispatch("getblockdag", Some(&json!([hex::encode([0xEEu8; 32])])), &state).await;
        assert_eq!(r["error"], "block not found");
        // A writer can take the lock right after a read returns.
        drop(state.dag.try_write().expect("DAG lock must be free after an explorer read"));
    }

    /// CRY-3 / WAL-1: `getdaginfo` reports the height of the next block the
    /// mempool targets (`next_block_height`: the node's next template height,
    /// cached in the pool), which wallets sign for. It is not tip_height + 1
    /// when a template merges a tip with a greater DAG height (DAG-8). With no
    /// cached value it is computed (here: no bodied tip, so the selected tip's
    /// DAG height + 1).
    #[tokio::test]
    async fn getdaginfo_reports_the_pools_next_block_height() {
        let (_tmp, state) = state_with_chain(5);
        let r = dispatch("getdaginfo", None, &state).await;
        assert_eq!(r["tip_height"], 5);
        assert_eq!(r["next_block_height"], 6);
        state.mempool.set_next_height(9);
        let r = dispatch("getdaginfo", None, &state).await;
        assert_eq!(r["tip_height"], 5);
        assert_eq!(r["next_block_height"], 9, "the pool's next height, not tip_height + 1");
    }

    /// `getdaginfo` and `getnetworkinfo` report the hardening activation
    /// height in force (with no chain id set, as in every test: the mainnet
    /// height), and `getdaginfo` whether it applies at `next_block_height`,
    /// so an operator can confirm the upgrade (builds before 0.1.1 do not
    /// report it; docs/RUNNING.md).
    #[tokio::test]
    async fn rpc_reports_the_hardening_activation_height() {
        use crate::core::activation::{self, MAINNET_HARDENING_ACTIVATION_HEIGHT as MAINNET};
        let (_tmp, state) = state_with_chain(5);
        let r = dispatch("getnetworkinfo", None, &state).await;
        assert_eq!(r["hardening_activation_height"], MAINNET);
        let r = dispatch("getdaginfo", None, &state).await;
        assert_eq!(r["hardening_activation_height"], MAINNET);
        assert_eq!(r["hardening_active"], false, "next height 6 is below the mainnet activation");
        state.mempool.set_next_height(MAINNET - 1);
        let r = dispatch("getdaginfo", None, &state).await;
        assert_eq!(r["hardening_active"], false);
        state.mempool.set_next_height(MAINNET);
        let r = dispatch("getdaginfo", None, &state).await;
        assert_eq!(r["hardening_active"], true, "the activation height itself is hardened");
        let _g = activation::scoped_override(0);
        let r = dispatch("getdaginfo", None, &state).await;
        assert_eq!(r["hardening_activation_height"], 0);
    }
}

// ── Hardening block rules: getblocktemplate gives external miners the coinbase
//    layout and the Merkle rule of the template's height (package P1) ────────
#[cfg(test)]
mod block_rules_template_tests {
    use super::*;
    use crate::core::{self, activation, block_rules, Block, BlockHeader, MerkleRoot, TxInput, TxOutput};
    use tempfile::TempDir;

    /// An AppState whose DAG holds one bodied genesis (built under the
    /// calling thread's activation height).
    fn state_with_genesis() -> (TempDir, AppState) {
        let tmp = TempDir::new().expect("tempdir");
        let store = Arc::new(Storage::open(&tmp.path().join("db")).expect("storage"));
        let mut genesis = core::genesis_block();
        genesis.header.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() - 1_000;
        let gh = genesis.block_hash();
        store.put_block(&genesis).unwrap();
        let mut dag = GhostDAG::with_default_k();
        dag.add_genesis(gh, genesis.header.timestamp);
        let (outbound_tx, _rx) = mpsc::channel(1);
        let state = AppState {
            node_state: Arc::new(RwLock::new(NodeState::default())),
            store,
            mempool: Arc::new(Mempool::new()),
            dag: Arc::new(RwLock::new(dag)),
            outbound_tx,
            api_key: None,
            require_auth_for_writes: false,
            require_auth_for_reads: false,
            rate_limiter: Arc::new(auth::RateLimiterSet::new(60, 5)),
            trust_private_ranges: false,
            allowed_origins: Arc::new(Vec::new()),
            allowed_hosts: Arc::new(Vec::new()),
            trust_loopback: false,
            heavy_gate: Arc::new(HeavyGate::new(HEAVY_READ_CACHE_TTL)),
            template_gate: Arc::new(HeavyGate::for_templates()),
            submit_block: None,
            cancel: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            chain_admin: None,
        };
        (tmp, state)
    }

    fn hashes(v: &Value) -> Vec<[u8; 32]> {
        v.as_array().unwrap().iter()
            .map(|h| hex::decode(h.as_str().unwrap()).unwrap().try_into().unwrap())
            .collect()
    }

    /// Assemble a block the way an external miner does from the RPC fields
    /// alone: coinbase script_sig = prefix || own bytes, header root folded
    /// from the coinbase txid through `coinbase_merkle_branch`.
    fn external_block(t: &Value, extra: &[u8]) -> Block {
        let mut script_sig = hex::decode(t["coinbase_script_sig_prefix"].as_str().unwrap()).unwrap();
        script_sig.extend_from_slice(extra);
        let value: u64 = t["subsidy_sat"].as_str().unwrap().parse().unwrap();
        let coinbase = Transaction {
            version: 1,
            inputs: vec![TxInput { prev_txid: [0; 32], prev_index: u32::MAX, script_sig, sequence: u32::MAX }],
            outputs: vec![TxOutput { value, script_pubkey: vec![0x44; 20] }],
            locktime: 0,
        };
        let hardened = t["merkle_rule"] == "gnb-tagged-v1";
        let root = block_rules::merkle_root_from_coinbase_branch(
            &coinbase.txid(), &hashes(&t["coinbase_merkle_branch"]), hardened);
        Block {
            header: BlockHeader {
                version: 1, parents: hashes(&t["parents"]), merkle_root: root,
                timestamp: t["min_time"].as_u64().unwrap() + 1,
                bits: t["bits"].as_u64().unwrap() as u32, nonce: 0,
            },
            transactions: vec![coinbase],
            blue_score: t["blue_score"].as_u64().unwrap(),
            height: t["height"].as_u64().unwrap(),
            shielded_transactions: vec![],
            powit: Default::default(),
        }
    }

    /// The getblocktemplate cache key follows the template's PARENTS, not
    /// the DAG's tip set: `invalidateblock` / `reconsiderblock` (DAG-6) leave
    /// the tip set and block count unchanged but change which tips are
    /// parents, and a header-only tip becomes a parent only when its body
    /// arrives. Each of these misses the cache at once (keyed on the tips, a
    /// miner kept the invalidated parent for up to TEMPLATE_CACHE_TTL).
    /// A height-1 block on genesis `gh` (timestamp `gts`), told apart by `tag`.
    fn genesis_child(gh: [u8; 32], gts: u64, tag: u8) -> Block {
        Block {
            header: BlockHeader {
                version: 1, parents: vec![gh], merkle_root: MerkleRoot::default(),
                timestamp: gts + 60, bits: core::POW_LIMIT_BITS, nonce: tag as u64,
            },
            transactions: vec![Transaction {
                version: 1,
                inputs: vec![TxInput { prev_txid: [0; 32], prev_index: u32::MAX, script_sig: vec![tag; 8], sequence: u32::MAX }],
                outputs: vec![TxOutput { value: 1, script_pubkey: vec![0x44; 20] }],
                locktime: 0,
            }],
            blue_score: 1,
            height: 1,
            shielded_transactions: vec![],
            powit: Default::default(),
        }
    }

    #[test]
    fn template_cache_key_follows_invalidation_and_body_arrival() {
        let (_tmp, state) = state_with_genesis();
        let gh = state.dag.read().tips()[0];
        let gts = state.dag.read().get_block_data(&gh).map(|d| d.timestamp).unwrap_or(0);
        let child = |tag: u8| genesis_child(gh, gts, tag);
        let (a, b) = (child(1), child(2));
        let (ah, bh) = (a.block_hash(), b.block_hash());
        let parents_of = |state: &AppState| {
            let dag = state.dag.read();
            crate::template::template_parents_and_height(&dag, &state.store).0
        };

        // A bodied, B header-only: B is no parent, so its header changes
        // nothing; its body arriving does.
        state.store.put_block(&a).unwrap();
        state.dag.write().add_block(ah, vec![gh], gts + 60, 1).unwrap();
        let k_a = template_cache_key(None, &state);
        state.dag.write().add_block(bh, vec![gh], gts + 60, 1).unwrap();
        assert_eq!(parents_of(&state), vec![ah]);
        assert_eq!(template_cache_key(None, &state), k_a, "a header-only tip is no parent");
        state.store.put_block(&b).unwrap();
        let both = parents_of(&state);
        assert_eq!(both.len(), 2);
        let k_ab = template_cache_key(None, &state);
        assert_ne!(k_ab, k_a, "a parent's body arriving must miss the cached template");

        // invalidateblock A: same tips, same block count, other parents.
        let tips_before = state.dag.read().tips();
        state.dag.write().mark_invalid(ah);
        assert_eq!(state.dag.read().tips(), tips_before);
        assert_eq!(parents_of(&state), vec![bh]);
        let k_inv = template_cache_key(None, &state);
        assert_ne!(k_inv, k_ab, "an invalidated parent must miss the cached template");
        // reconsiderblock A: back to the first key.
        state.dag.write().reset_invalid_sets(std::iter::empty(), std::iter::empty());
        assert_eq!(parents_of(&state), both);
        assert_eq!(template_cache_key(None, &state), k_ab);
    }

    /// A template is cached under the parents it was BUILT on, not under the
    /// key read before the build. The race: a miner's call reads the key on
    /// [A]; block B is accepted while the build waits for the acceptance
    /// lock, so the template is built on [A, B]. Stored under the [A] key, an
    /// `invalidateblock B` (parents [A] again) within TEMPLATE_CACHE_TTL had
    /// the next call served the template on the invalidated B, which the node
    /// itself refuses. Now that call misses and builds on [A], and the
    /// template on [A, B] is served again only once B is reconsidered.
    #[test]
    fn a_template_is_cached_under_the_parents_it_was_built_on() {
        let (_tmp, state) = state_with_genesis();
        let gh = state.dag.read().tips()[0];
        let gts = state.dag.read().get_block_data(&gh).map(|d| d.timestamp).unwrap_or(0);
        let (a, b) = (genesis_child(gh, gts, 1), genesis_child(gh, gts, 2));
        let (ah, bh) = (a.block_hash(), b.block_hash());
        state.store.put_block(&a).unwrap();
        state.dag.write().add_block(ah, vec![gh], gts + 60, 1).unwrap();

        // What the builder returns: the parents and height it chose under the
        // acceptance lock (`build_block_template_with`), here read the same way.
        let built_on_current_parents = |n: u32| {
            let (parents, height) = {
                let dag = state.dag.read();
                crate::template::template_parents_and_height(&dag, &state.store)
            };
            json!({"build": n, "parents": parents.iter().map(hex::encode).collect::<Vec<_>>(), "height": height})
        };
        let parents_in = |t: &Value| hashes(&t["parents"]);

        let t1 = gated_dispatch("getblocktemplate", None, &state, || {
            // B is accepted between the key lookup and the build.
            state.store.put_block(&b).unwrap();
            state.dag.write().add_block(bh, vec![gh], gts + 60, 1).unwrap();
            built_on_current_parents(1)
        });
        assert_eq!(parents_in(&t1).len(), 2, "{t1}");
        assert!(parents_in(&t1).contains(&bh));

        // invalidateblock B: the parents are [A] again.
        state.dag.write().mark_invalid(bh);
        let t2 = gated_dispatch("getblocktemplate", None, &state, || built_on_current_parents(2));
        assert_eq!(t2["build"], 2, "the template on the invalidated B was served from [A]'s key: {t2}");
        assert_eq!(parents_in(&t2), vec![ah]);

        // reconsiderblock B: the template on [A, B] is that key's again.
        state.dag.write().reset_invalid_sets(std::iter::empty(), std::iter::empty());
        let t3 = gated_dispatch("getblocktemplate", None, &state, || built_on_current_parents(3));
        assert_eq!(t3["build"], 1, "{t3}");
        // And [A] again serves the template built on [A].
        state.dag.write().mark_invalid(bh);
        assert_eq!(gated_dispatch("getblocktemplate", None, &state, || built_on_current_parents(4))["build"], 2);
    }

    #[tokio::test]
    async fn getblocktemplate_returns_the_coinbase_layout_of_the_templates_height() {
        // From the activation: the 80-byte prefix, tagged root, wire size.
        {
            let _guard = activation::scoped_override(1);
            let (_tmp, state) = state_with_genesis();
            let t = dispatch("getblocktemplate", None, &state).await;
            assert_eq!(t["height"], 1, "{t}");
            assert_eq!(t["hardening_active"], true);
            assert_eq!(t["merkle_rule"], "gnb-tagged-v1");
            assert_eq!(t["size_rule"], "wire");
            let prefix = hex::decode(t["coinbase_script_sig_prefix"].as_str().unwrap()).unwrap();
            assert_eq!(prefix.len(), block_rules::COINBASE_COMMITMENT_LEN);
            assert_eq!(&prefix[..8], b"GNB-CB01");
            // The whole coinbase must fit the reserve: far below the
            // script_sig cap (9,920), which a full template has no room for.
            let max_extra = t["max_coinbase_extra_bytes"].as_u64().unwrap() as usize;
            assert_eq!(max_extra, crate::template::external_coinbase_max_extra(80, true, 1_000));
            assert!(max_extra > 700 && max_extra < 1_000 - 80, "{max_extra}");
            assert_eq!(t["max_coinbase_script_pubkey_bytes"], crate::template::EXTERNAL_COINBASE_MAX_SPK);
            let block = external_block(&t, &vec![0xE5; max_extra]);
            assert!(block.transactions[0].wire_size(true) <= t["coinbase_reserve"].as_u64().unwrap() as usize);
            assert_eq!(block_rules::check_block_hardened_at(&block, 1), Ok(()));
            assert_eq!(block.validate_structure_without_pow_at(1), Ok(()));
            let block = external_block(&t, b"pool-extranonce");
            assert_eq!(block_rules::check_block_hardened_at(&block, 1), Ok(()));
            assert_eq!(block.validate_structure_without_pow_at(1), Ok(()));
            assert_eq!(block.body_merkle_root(), block.header.merkle_root);
        }
        // Below it: no prefix, the legacy root and bincode size, as before.
        {
            let _guard = activation::scoped_override(activation::NEVER);
            let (_tmp, state) = state_with_genesis();
            let t = dispatch("getblocktemplate", None, &state).await;
            assert_eq!(t["hardening_active"], false, "{t}");
            assert_eq!(t["merkle_rule"], "sha256d-duplicate-last");
            assert_eq!(t["size_rule"], "bincode");
            assert_eq!(t["coinbase_script_sig_prefix"], "");
            let max_extra = t["max_coinbase_extra_bytes"].as_u64().unwrap() as usize;
            assert_eq!(max_extra, crate::template::external_coinbase_max_extra(0, false, 1_000));
            assert!(max_extra > 800 && max_extra < 1_000, "{max_extra}");
            let block = external_block(&t, &vec![0xE5; max_extra]);
            assert!(block.transactions[0].actual_size() <= t["coinbase_reserve"].as_u64().unwrap() as usize);
            assert_eq!(block.validate_structure_without_pow_at(activation::NEVER), Ok(()));
            let block = external_block(&t, b"height:1 pool");
            assert_eq!(block.validate_structure_without_pow_at(activation::NEVER), Ok(()));
            assert_eq!(block.header.merkle_root, core::Transaction::merkle_root(&block.transactions));
            assert_ne!(block.header.merkle_root, MerkleRoot::ZERO);
        }
    }
}
