//! Bloch-SIS Protocol — Storage (RocksDB)

pub mod indexer;
/// Audit NET-12: explorer aggregates maintained in the UTXO write batches.
pub mod aggregates;

use rocksdb::{DB, Options, ColumnFamilyDescriptor, IteratorMode};
use std::path::Path;
use crate::core::{Block, TxOutput};
use crate::consensus::{BlockHash, GhostdagData};

const CF_BLOCKS:     &str = "blocks";
const CF_UTXO:       &str = "utxo";
const CF_DAG:        &str = "dag";
const CF_BLUE_SCORE: &str = "blue_score";
const CF_META:       &str = "meta";
const CF_HEIGHT:     &str = "height";
const CF_TIMESTAMPS: &str = "timestamps";
const CF_ADDR_UTXO:  &str = "addr_utxo";  // address index: [20B addr][32B txid][4B idx] → empty
const CF_COINBASE:   &str = "coinbase";    // txid → height (for maturity check)
const CF_TX_INDEX:   &str = "tx_index";    // txid → [32B block_hash][8B height]
const CF_ADDR_TX_HISTORY: &str = "addr_tx_history";  // addr → chronological tx touches
const CF_UNDO:       &str = "undo";        // Sprint U.1: per-block undo data for reorg rollback
const CF_DAG_INTEGRITY: &str = "dag_integrity";  // Sprint Y (M-2): hash-chain over GhostdagData
const CF_REACHABILITY: &str = "reachability";    // Phase 1: durable interval-reachability index (non-consensus cache)
const CF_SHIELDED: &str = "shielded";            // audit COH-2: shielded-pool state + undo (layout: coherence::persist)

// ── PoBRS Column Families (Sprint 1.5) ─────────────────────────────────
// Persistence layer for the Proof-of-Blue-and-Red-Score subsystem.
// All keys use big-endian for u64/u32 to preserve lexicographic ordering
// on RocksDB iterators. Schema version stored in CF_POBRS_META.
pub(crate) const CF_POBRS_META:                &str = "pobrs_meta";                // key: ascii string  | value: bincode
pub(crate) const CF_POBRS_ORACLES:             &str = "pobrs_oracles";             // key: oracle_id 1B  | value: OracleRecord
pub(crate) const CF_POBRS_ORACLES_BY_PK:       &str = "pobrs_oracles_by_pk";       // key: pk 48B        | value: oracle_id 1B
pub(crate) const CF_POBRS_ORACLE_SNAPSHOTS:    &str = "pobrs_oracle_snapshots";    // key: height 8B BE  | value: OracleSetSnapshot (every 100 blocks)
pub(crate) const CF_POBRS_ORACLE_EVENTS:       &str = "pobrs_oracle_events";       // key: height 8B BE + seq 4B BE | value: OracleEvent
pub(crate) const CF_POBRS_ATTESTATIONS:        &str = "pobrs_attestations";        // key: wallet_hash 32B          | value: AttestationCore
pub(crate) const CF_POBRS_ATTESTATIONS_EXTRA:  &str = "pobrs_attestations_extra";  // key: wallet_hash 32B          | value: AttestationExtra
pub(crate) const CF_POBRS_ATTESTATION_HISTORY: &str = "pobrs_attestation_history"; // key: wallet_hash 32B + block 8B BE | value: AttestationCore
pub(crate) const CF_POBRS_MODELS:              &str = "pobrs_models";              // key: model_id 4B BE           | value: ModelRecord
pub(crate) const CF_POBRS_MODEL_PENDING:       &str = "pobrs_model_pending";       // key: update_id 8B BE         | value: PendingModelUpdate
pub(crate) const CF_POBRS_DISPUTES:            &str = "pobrs_disputes";            // key: wallet_hash 32B          | value: DisputeRecord
pub(crate) const CF_POBRS_TEE_PLATFORMS:       &str = "pobrs_tee_platforms";       // key: platform_byte 1B         | value: PlatformInfo

// ── Bonding CFs (Sprint 2.1.D, ADR-007 §4.7) ─────────────────────────────
pub(crate) const CF_BONDING_META:      &str = "bonding_meta";       // ascii string keys → bincode (schema_version, next_bond_id)
pub(crate) const CF_BONDING_REGISTRY:  &str = "bonding_registry";   // BondId 8B BE        → BondRecord (Day β)
pub(crate) const CF_BONDING_BY_UID:    &str = "bonding_by_uid";     // OperatorUid 32B     → BondId 8B BE
pub(crate) const CF_BONDING_BY_PUBKEY: &str = "bonding_by_pk";      // BlsPubkey 48B       → BondId 8B BE
pub(crate) const CF_BONDING_HISTORY:   &str = "bonding_history";    // BondId 8B BE        → Vec<SlashEvent>
pub(crate) const CF_PARTICIPATION:     &str = "participation";      // (epoch 8B BE, bond_id 8B BE) → ParticipationRecord

// ── FFG Column Families (Sprint 2.1) ───────────────────────────────────
// Persistence layer for the Friendly Finality Gadget committee subsystem.
// Schema version stored in CF_FFG_META.
pub(crate) const CF_FFG_META:                 &str = "ffg_meta";                 // key: ascii string  | value: u32 LE / bincode
pub(crate) const CF_FFG_COMMITTEE:            &str = "ffg_committee";            // key: epoch 8B BE   | value: bincode(Committee)
pub(crate) const CF_FFG_PENDING_COMMITTEE:    &str = "ffg_pending_committee";    // key: dkg_epoch 8B BE | value: bincode(PendingCommittee)

/// PoBRS schema version. Bumped when key/value layout changes incompatibly.
/// Stored as `CF_POBRS_META["schema_version"] = u32 LE`.
pub const POBRS_SCHEMA_VERSION: u32 = 1;

/// (key, value) rows read from a column family, in key order.
pub type KeyValueRows = Vec<(Vec<u8>, Vec<u8>)>;

fn encode<T: serde::Serialize>(v: &T) -> Result<Vec<u8>, StorageError> {
    bincode::serde::encode_to_vec(v, bincode::config::standard())
        .map_err(|e| StorageError::SerializeFailed(e.to_string()))
}

pub fn decode<T: serde::de::DeserializeOwned>(b: &[u8]) -> Result<T, StorageError> {
    bincode::serde::decode_from_slice(b, bincode::config::standard())
        .map(|(v, _)| v)
        .map_err(|e| StorageError::DeserializeFailed(e.to_string()))
}

/// `(txid, block_hash)`: one CF_TX_INDEX row (`Storage::tx_index_entries`).
pub type TxIndexEntry = ([u8; 32], [u8; 32]);

/// CF_UNDO key prefix of a [`PrunedBodyRecord`]. Undo records are keyed by
/// the bare 32-byte block hash; these keys are longer, so
/// `Storage::undo_block_hashes` never mistakes one for an undo record.
pub const PRUNED_BODY_PREFIX: &[u8] = b"pruned_body/";

/// CF_UNDO key of `hash`'s pruned-body record.
pub fn pruned_body_key(hash: &BlockHash) -> Vec<u8> {
    let mut k = PRUNED_BODY_PREFIX.to_vec();
    k.extend_from_slice(hash);
    k
}

/// CF_META key prefix of a hardened-body marker: `hardened_body/<hash>` (empty
/// value) is written, in the same batch that prunes the body, when the pruned
/// body passed every context-free hardening block rule as if active
/// (`accept::classify_stored_block` at activation 0). Those rules are gated
/// on the block's own header height only, so the marker answers "would this
/// body pass the start-up hardening recheck" for EVERY activation at or below
/// its height. The recheck reads it for a candidate whose body is gone
/// (re-audit B2-T1 follow-up): a body pruned after it was checked is not
/// disqualified when the recheck runs again under another activation height.
/// It lives in CF_META, which a chain-state rebuild never clears.
pub const HARDENED_BODY_PREFIX: &[u8] = b"hardened_body/";

/// CF_META key of `hash`'s hardened-body marker.
pub fn hardened_body_key(hash: &BlockHash) -> Vec<u8> {
    let mut k = HARDENED_BODY_PREFIX.to_vec();
    k.extend_from_slice(hash);
    k
}

/// What disconnecting a selected-chain block needs from its body, kept when
/// the body is pruned (audit DAG-6): the UTXO effects are reversed from the
/// undo record, which is never pruned; the address-history rows to delete and
/// whether the block carried shielded transactions are kept here.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PrunedBodyRecord {
    /// Header height of the pruned block.
    pub height: u64,
    /// The block carried shielded transactions.
    pub had_shielded: bool,
    /// Every CF_ADDR_TX_HISTORY key the block's connect wrote
    /// (`indexer::addr_history_keys`).
    pub addr_history_keys: Vec<Vec<u8>>,
}

/// Decode one exported UTXO row without silently omitting corrupt ledger data.
/// Historical exports retain their big-endian vout interpretation; canonical
/// exports are explicit and must never replace the published genesis artifact.
pub fn decode_snapshot_row(key: &[u8], value: &[u8], canonical_vout: bool)
    -> Result<(Vec<u8>, u32, u64, Vec<u8>), StorageError>
{
    if key.len() != 36 {
        return Err(StorageError::DeserializeFailed("UTXO snapshot key must be exactly 36 bytes".into()));
    }
    let suffix = [key[32], key[33], key[34], key[35]];
    let vout = if canonical_vout { u32::from_le_bytes(suffix) } else { u32::from_be_bytes(suffix) };
    let (output, used): (TxOutput, usize) = bincode::serde::decode_from_slice(value, bincode::config::standard())
        .map_err(|e| StorageError::DeserializeFailed(format!("UTXO snapshot value: {e}")))?;
    if used != value.len() {
        return Err(StorageError::DeserializeFailed("UTXO snapshot value has trailing bytes".into()));
    }
    Ok((key[..32].to_vec(), vout, output.value, output.script_pubkey))
}

pub struct Storage {
    db: DB,
    /// Audit DAG-10: the acceptance mutex. Every path that mutates chain
    /// state (block acceptance from gossip, the miner, RPC `submitblock`,
    /// orphan resurrection, start-up reconciliation) holds it for the whole
    /// accept → connect → commit pipeline, so tip snapshot, validation, DAG
    /// insertion and the atomic commit can never interleave. It lives on the
    /// store because the store is the one object every ingress path shares
    /// and every chain-state mutation goes through. Reentrant so a nested
    /// call on the same thread cannot self-deadlock.
    accept_lock: parking_lot::ReentrantMutex<()>,
    /// Memo of pure verdicts on stored block bodies ([`Storage::body_verdict`]).
    body_verdicts: parking_lot::Mutex<BodyVerdicts>,
    /// NET-12: serialises every read-modify-write of the explorer
    /// aggregates (`aggregates.rs`). Never held while taking `accept_lock`.
    agg_lock: parking_lot::Mutex<()>,
    /// NET-12: the aggregates are complete (cached `agg/version`).
    agg_ready: std::sync::atomic::AtomicBool,
    /// NET-12: number of storage reads served (diagnostics; lets tests prove
    /// that an RPC's cost does not grow with the chain).
    reads: std::sync::atomic::AtomicU64,
}

/// Upper bound on the entries of the body-verdict memo. Reaching it clears
/// the memo (the verdicts are recomputable; only the cost changes).
pub const BODY_VERDICT_MEMO_CAP: usize = 16_384;

/// The body-verdict memo ([`Storage::body_verdict`]).
#[derive(Default)]
struct BodyVerdicts {
    /// Block hash → (caller key, verdict on the body stored under that hash).
    map: std::collections::HashMap<[u8; 32], (u64, bool)>,
    /// Bumped by every body write or delete through this type, so a verdict
    /// computed while a body changed is not recorded.
    epoch: u64,
    /// Verdicts computed (memo misses), for tests and diagnostics.
    computed: u64,
}

impl Storage {
    fn with_db(db: DB) -> Self {
        Self {
            db,
            accept_lock: parking_lot::ReentrantMutex::new(()),
            body_verdicts: Default::default(),
            agg_lock: parking_lot::Mutex::new(()),
            agg_ready: std::sync::atomic::AtomicBool::new(false),
            reads: std::sync::atomic::AtomicU64::new(0),
        }
    }

    #[inline]
    fn note_reads(&self, n: u64) {
        self.reads.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
    }

    /// NET-12: total storage reads served by this handle so far (point
    /// reads plus iterator steps of the instrumented accessors).
    #[allow(dead_code)] // library API (tests, diagnostics)
    pub fn storage_reads(&self) -> u64 {
        self.reads.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Build the full column-family descriptor list. Shared by the read-write
    /// [`open`] and the read-only [`open_read_only`] paths so both agree on the
    /// exact schema (CF names + per-CF options) — the read-only replay harness
    /// must decode CF_DAG with the identical layout the node wrote.
    fn cf_descriptors() -> Vec<ColumnFamilyDescriptor> {
        let mut addr_utxo_opts = Options::default();
        addr_utxo_opts.set_prefix_extractor(rocksdb::SliceTransform::create_fixed_prefix(20));
        let cfs = vec![
            ColumnFamilyDescriptor::new(CF_BLOCKS,     Options::default()),
            ColumnFamilyDescriptor::new(CF_UTXO,       Options::default()),
            ColumnFamilyDescriptor::new(CF_DAG,        Options::default()),
            ColumnFamilyDescriptor::new(CF_BLUE_SCORE, Options::default()),
            ColumnFamilyDescriptor::new(CF_META,       Options::default()),
            ColumnFamilyDescriptor::new(CF_HEIGHT,     Options::default()),
            ColumnFamilyDescriptor::new(CF_TIMESTAMPS, Options::default()),
            ColumnFamilyDescriptor::new(CF_ADDR_UTXO,  addr_utxo_opts),
            ColumnFamilyDescriptor::new(CF_COINBASE,   Options::default()),
            ColumnFamilyDescriptor::new(CF_TX_INDEX,   Options::default()),
            {
                let mut opts = Options::default();
                opts.set_prefix_extractor(rocksdb::SliceTransform::create_fixed_prefix(20));
                ColumnFamilyDescriptor::new(CF_ADDR_TX_HISTORY, opts)
            },
            ColumnFamilyDescriptor::new(CF_UNDO,       Options::default()),
            ColumnFamilyDescriptor::new(CF_DAG_INTEGRITY, Options::default()),
            // Phase 1: durable reachability index. Key = 32B block hash,
            // value = encode_record() bytes. A rebuildable cache, never part of
            // the integrity chain; see docs/adr/ADR-035-durable-reachability-index.md.
            ColumnFamilyDescriptor::new(CF_REACHABILITY, Options::default()),
            // Audit COH-2: shielded-pool consensus state (commitment-tree
            // leaves, spent nullifiers, anchor window, per-block undo, tip),
            // written in the same WriteBatch as the UTXO changes.
            ColumnFamilyDescriptor::new(CF_SHIELDED, Options::default()),
            // ── PoBRS CFs (Sprint 1.5) ─────────────────────────────
            ColumnFamilyDescriptor::new(CF_POBRS_META,                Options::default()),
            ColumnFamilyDescriptor::new(CF_POBRS_ORACLES,             Options::default()),
            ColumnFamilyDescriptor::new(CF_POBRS_ORACLES_BY_PK,       Options::default()),
            ColumnFamilyDescriptor::new(CF_POBRS_ORACLE_SNAPSHOTS,    Options::default()),
            {
                // Event log: prefix by height (8B) for efficient range scans
                let mut opts = Options::default();
                opts.set_prefix_extractor(rocksdb::SliceTransform::create_fixed_prefix(8));
                ColumnFamilyDescriptor::new(CF_POBRS_ORACLE_EVENTS, opts)
            },
            ColumnFamilyDescriptor::new(CF_POBRS_ATTESTATIONS,        Options::default()),
            ColumnFamilyDescriptor::new(CF_POBRS_ATTESTATIONS_EXTRA,  Options::default()),
            {
                // Attestation history: prefix by wallet_hash (32B)
                let mut opts = Options::default();
                opts.set_prefix_extractor(rocksdb::SliceTransform::create_fixed_prefix(32));
                ColumnFamilyDescriptor::new(CF_POBRS_ATTESTATION_HISTORY, opts)
            },
            ColumnFamilyDescriptor::new(CF_POBRS_MODELS,              Options::default()),
            ColumnFamilyDescriptor::new(CF_POBRS_MODEL_PENDING,       Options::default()),
            ColumnFamilyDescriptor::new(CF_POBRS_DISPUTES,            Options::default()),
            ColumnFamilyDescriptor::new(CF_POBRS_TEE_PLATFORMS,       Options::default()),
            // ── Bonding CFs (Sprint 2.1.D, ADR-007 §4.7) ────────────
            ColumnFamilyDescriptor::new(CF_BONDING_META,      Options::default()),
            ColumnFamilyDescriptor::new(CF_BONDING_REGISTRY,  Options::default()),
            ColumnFamilyDescriptor::new(CF_BONDING_BY_UID,    Options::default()),
            ColumnFamilyDescriptor::new(CF_BONDING_BY_PUBKEY, Options::default()),
            ColumnFamilyDescriptor::new(CF_BONDING_HISTORY,   Options::default()),
            ColumnFamilyDescriptor::new(CF_PARTICIPATION,     Options::default()),
            // ── FFG CFs (Sprint 2.1) ───────────────────────────────
            ColumnFamilyDescriptor::new(CF_FFG_META,                  Options::default()),
            ColumnFamilyDescriptor::new(CF_FFG_COMMITTEE,             Options::default()),
            ColumnFamilyDescriptor::new(CF_FFG_PENDING_COMMITTEE,     Options::default()),
        ];
        cfs
    }

    pub fn open(path: &Path) -> Result<Self, StorageError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        opts.set_max_open_files(256);
        opts.set_write_buffer_size(64 * 1024 * 1024);
        let db = DB::open_cf_descriptors(&opts, path, Self::cf_descriptors())
            .map_err(|e| StorageError::OpenFailed(e.to_string()))?;
        let store = Self::with_db(db);
        store.init_aggregates_marker()?;
        Ok(store)
    }

    /// Open an existing snapshot **read-only**. RocksDB is opened with
    /// `open_cf_descriptors_read_only`, which acquires no write lock, creates
    /// nothing, and rejects every mutating call — so a live node can keep the
    /// same data-dir open while this handle inspects it. Used by the GhostDAG
    /// differential replay harness (`tests/ghostdag_replay_snapshot.rs`) to read
    /// CF_DAG without any risk of touching mined history.
    ///
    /// `path` is the node data-dir (the same directory passed to [`open`]).
    /// The DB must already exist; this never creates column families.
    pub fn open_read_only(path: &Path) -> Result<Self, StorageError> {
        let opts = Options::default();
        // A read-only open cannot create column families, so open only the
        // ones the snapshot has: a data-dir written before a CF was added
        // (e.g. `shielded`, audit COH-2) stays readable.
        let existing: std::collections::HashSet<String> = DB::list_cf(&opts, path)
            .map_err(|e| StorageError::OpenFailed(e.to_string()))?
            .into_iter()
            .collect();
        let descriptors: Vec<ColumnFamilyDescriptor> = Self::cf_descriptors()
            .into_iter()
            .filter(|d| existing.contains(d.name()))
            .collect();
        // `error_if_log_file_exist = false`: tolerate a live/unclean WAL so we
        // can inspect a running node's dir. Read-only mode never replays into or
        // mutates the primary.
        let db = DB::open_cf_descriptors_read_only(&opts, path, descriptors, false)
            .map_err(|e| StorageError::OpenFailed(e.to_string()))?;
        let store = Self::with_db(db);
        // Read-only: report the marker, never write it.
        let ready = store.get_meta("agg/version").ok().flatten()
            .is_some_and(|v| v.as_slice() == aggregates::AGG_VERSION.to_le_bytes());
        store.agg_ready.store(ready, std::sync::atomic::Ordering::Release);
        Ok(store)
    }

    /// Take the acceptance mutex (audit DAG-10). See the field documentation.
    pub fn acceptance_lock(&self) -> parking_lot::ReentrantMutexGuard<'_, ()> {
        self.accept_lock.lock()
    }

    /// Returns a reference to the underlying RocksDB instance. Used by
    /// `PobrsStorage` (Sprint 1.5 L2) to share the same DB connection
    /// without owning it. Safe because RocksDB handles internal concurrency.
    pub fn db(&self) -> &DB {
        &self.db
    }

    /// Write a block and all of its derived index rows atomically.
    ///
    /// P0 crash-consistency (roadmap §3.2): previously this issued 4+ separate
    /// `put_cf` calls (block body, height→hash, timestamp, per-tx address
    /// index). A crash between any two left height→hash pointing at a block
    /// body that wasn't there, or an un-indexed block. All writes now go
    /// through a single RocksDB `WriteBatch` committed with one `db.write`, so
    /// either the whole block lands or none of it does. Keys/values/CFs are
    /// byte-identical to the old path — this is a durability fix only, not a
    /// schema or wire change.
    pub fn put_block(&self, block: &Block) -> Result<(), StorageError> {
        let hash = block.block_hash();
        let cf_b = self.db.cf_handle(CF_BLOCKS).ok_or(StorageError::CfNotFound(CF_BLOCKS.into()))?;
        let cf_h = self.db.cf_handle(CF_HEIGHT).ok_or(StorageError::CfNotFound(CF_HEIGHT.into()))?;
        let cf_t = self.db.cf_handle(CF_TIMESTAMPS).ok_or(StorageError::CfNotFound(CF_TIMESTAMPS.into()))?;
        let cf_ai = self.db.cf_handle(CF_ADDR_TX_HISTORY).ok_or(StorageError::CfNotFound(CF_ADDR_TX_HISTORY.into()))?;

        let mut batch = rocksdb::WriteBatch::default();

        // Sprint 1.b: Bitcoin-format wire serialization (replaces pre-v0.6.0 bincode).
        // Block bytes on disk are now byte-identical to the canonical network
        // wire format, so a future direct-from-disk broadcast path can skip
        // re-encoding. Consensus-breaking; existing v0.5.x RocksDB data-dirs
        // are unreadable at v0.6.0+ and must be reset.
        batch.put_cf(&cf_b, &hash, &block.to_wire_bytes());
        batch.put_cf(&cf_h, &block.height.to_be_bytes(), &hash);
        batch.put_cf(&cf_t, &block.height.to_be_bytes(), &block.header.timestamp.to_le_bytes());

        // Sprint F: index address touches for each tx in this block. These were
        // previously best-effort (errors ignored). Folding them into the same
        // batch keeps the same entries but makes them crash-consistent with the
        // block body. An entry-computation error for one tx skips only that tx's
        // rows (matching the old best-effort semantics) rather than aborting.
        for (tx_idx, tx) in block.transactions.iter().enumerate() {
            match self.addr_index_entries(tx, block.height, tx_idx as u32) {
                Ok(entries) => {
                    for (key, val) in entries {
                        batch.put_cf(&cf_ai, &key, &val);
                    }
                }
                Err(e) => log::warn!("addr-index skipped for tx {}: {}", tx_idx, e),
            }
        }

        self.db.write(batch).map_err(|e| StorageError::WriteFailed(e.to_string()))?;
        self.forget_body_verdict(&hash);
        Ok(())
    }

    /// Persist ONLY the block body (CF_BLOCKS), keyed by block hash.
    ///
    /// Audit DAG-12: `put_block` also writes the height→hash and
    /// height→timestamp indexes and the address-history rows, which are
    /// SELECTED-CHAIN indexes. The acceptance pipeline stores every DAG block's
    /// body (fork-losers and disqualified blocks included, so they can be
    /// served and connected later) through this body-only write, and writes the
    /// chain indexes in the atomic connect batch (`stage_chain_index`) only for
    /// blocks that join the selected chain — so a fork-loser or a refused block
    /// can no longer overwrite `getblockhash`'s answer or the pruning cursor.
    pub fn put_block_body(&self, block: &Block) -> Result<(), StorageError> {
        let hash = block.block_hash();
        let cf_b = self.db.cf_handle(CF_BLOCKS).ok_or(StorageError::CfNotFound(CF_BLOCKS.into()))?;
        let written = self.db.put_cf(&cf_b, &hash, &block.to_wire_bytes())
            .map_err(|e| StorageError::WriteFailed(e.to_string()));
        self.forget_body_verdict(&hash);
        written
    }

    /// Delete a block body (CF_BLOCKS only). Used to drop the body of a block
    /// whose DAG insertion was rolled back (refused by policy), so nothing
    /// unreferenced is left behind.
    pub fn delete_block_body(&self, hash: &[u8; 32]) -> Result<(), StorageError> {
        let cf_b = self.db.cf_handle(CF_BLOCKS).ok_or(StorageError::CfNotFound(CF_BLOCKS.into()))?;
        let deleted = self.db.delete_cf(&cf_b, hash).map_err(|e| StorageError::WriteFailed(e.to_string()));
        self.forget_body_verdict(hash);
        deleted
    }

    /// A verdict `verdict(body)` on the body stored under `hash`, memoized per
    /// hash and `key`: `Ok(None)` when no body is stored (checked on every
    /// call, so a pruned or deleted body is never reported), otherwise the
    /// memoized verdict for `(hash, key)` or, on a miss, `verdict` applied to
    /// the decoded body and recorded. `verdict` MUST be a pure function of the
    /// body and `key` (one memo slot per hash: another `key` replaces it).
    /// Every body write or delete through this type (`put_block`,
    /// `put_block_body`, `delete_block_body`, `prune_blocks_below`) drops the
    /// hash's memo, and a verdict computed while a body changed is not
    /// recorded; a raw write through [`Storage::db`] bypasses the memo.
    /// A body that cannot be read or decoded is an error and is not memoized.
    ///
    /// Used by the block template's parent predicate
    /// (`template::template_parents_and_height_at`), which runs on every
    /// valid tip at every block acceptance: without the memo every call
    /// decoded and re-hashed (Merkle and witness roots) every tip body.
    pub fn body_verdict<F: FnOnce(&Block) -> bool>(
        &self,
        hash: &[u8; 32],
        key: u64,
        verdict: F,
    ) -> Result<Option<bool>, StorageError> {
        if !self.has_block_body(hash)? {
            return Ok(None);
        }
        let epoch = {
            let memo = self.body_verdicts.lock();
            if let Some(&(k, v)) = memo.map.get(hash) {
                if k == key {
                    return Ok(Some(v));
                }
            }
            memo.epoch
        };
        let Some(block) = self.get_block(hash)? else { return Ok(None) };
        let v = verdict(&block);
        let mut memo = self.body_verdicts.lock();
        memo.computed = memo.computed.wrapping_add(1);
        if memo.epoch == epoch {
            if memo.map.len() >= BODY_VERDICT_MEMO_CAP && !memo.map.contains_key(hash) {
                memo.map.clear();
            }
            memo.map.insert(*hash, (key, v));
        }
        Ok(Some(v))
    }

    /// Number of verdicts [`Storage::body_verdict`] computed (memo misses)
    /// since the store was opened. Diagnostics and tests (the `gnb` binary
    /// does not call it).
    #[allow(dead_code)]
    pub fn body_verdicts_computed(&self) -> u64 {
        self.body_verdicts.lock().computed
    }

    /// Drop the memoized body verdict of `hash` (its body was written or
    /// deleted).
    fn forget_body_verdict(&self, hash: &[u8; 32]) {
        let mut memo = self.body_verdicts.lock();
        memo.map.remove(hash);
        memo.epoch = memo.epoch.wrapping_add(1);
    }

    /// Whether a body is stored for `hash` (no decoding).
    pub fn has_block_body(&self, hash: &[u8; 32]) -> Result<bool, StorageError> {
        let cf = self.db.cf_handle(CF_BLOCKS).ok_or(StorageError::CfNotFound(CF_BLOCKS.into()))?;
        Ok(self.db.get_pinned_cf(&cf, hash)
            .map_err(|e| StorageError::ReadFailed(e.to_string()))?
            .is_some())
    }

    pub fn get_block(&self, hash: &[u8; 32]) -> Result<Option<Block>, StorageError> {
        self.note_reads(1);
        let cf = self.db.cf_handle(CF_BLOCKS).ok_or(StorageError::CfNotFound(CF_BLOCKS.into()))?;
        match self.db.get_cf(&cf, hash).map_err(|e| StorageError::ReadFailed(e.to_string()))? {
            Some(d) => Ok(Some(
                Block::from_wire_bytes(&d)
                    .map_err(StorageError::DeserializeFailed)?
            )),
            None    => Ok(None),
        }
    }

    pub fn get_block_hash_at_height(&self, height: u64) -> Result<Option<[u8; 32]>, StorageError> {
        self.note_reads(1);
        let cf = self.db.cf_handle(CF_HEIGHT).ok_or(StorageError::CfNotFound(CF_HEIGHT.into()))?;
        match self.db.get_cf(&cf, &height.to_be_bytes()).map_err(|e| StorageError::ReadFailed(e.to_string()))? {
            Some(d) if d.len() == 32 => { let mut h = [0u8;32]; h.copy_from_slice(&d); Ok(Some(h)) }
            _ => Ok(None),
        }
    }

    pub fn get_timestamp_at_height(&self, height: u64) -> Result<Option<u64>, StorageError> {
        self.note_reads(1);
        let cf = self.db.cf_handle(CF_TIMESTAMPS).ok_or(StorageError::CfNotFound(CF_TIMESTAMPS.into()))?;
        match self.db.get_cf(&cf, &height.to_be_bytes()).map_err(|e| StorageError::ReadFailed(e.to_string()))? {
            Some(d) if d.len() == 8 => Ok(Some(u64::from_le_bytes(d[..8].try_into().unwrap()))),
            _ => Ok(None),
        }
    }

    /// Create (or overwrite) one UTXO with its address-index row. NET-12:
    /// the explorer aggregates change in the SAME write batch.
    pub fn put_utxo(&self, txid: &[u8], index: u32, output: &TxOutput) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_UTXO).ok_or(StorageError::CfNotFound(CF_UTXO.into()))?;
        let key = utxo_key(txid, index);
        let _agg = self.agg_lock();
        let mut deltas = aggregates::HolderDeltas::default();
        if let Some(prev) = self.get_utxo(txid, index)? {
            deltas.remove(&prev);
        }
        deltas.add(output);
        let mut batch = rocksdb::WriteBatch::default();
        batch.put_cf(&cf, &key, &encode(output)?);

        // Address index: key = [20B address][32B txid][4B index], value = empty
        if output.script_pubkey.len() >= 20 {
            let cf_ai = self.db.cf_handle(CF_ADDR_UTXO).ok_or(StorageError::CfNotFound(CF_ADDR_UTXO.into()))?;
            let ai_key = addr_utxo_key(&output.script_pubkey, txid, index);
            batch.put_cf(&cf_ai, &ai_key, []);
        }
        self.stage_holder_deltas(&mut batch, &deltas)?;
        self.db.write(batch).map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    pub fn get_utxo(&self, txid: &[u8], index: u32) -> Result<Option<TxOutput>, StorageError> {
        self.note_reads(1);
        let cf = self.db.cf_handle(CF_UTXO).ok_or(StorageError::CfNotFound(CF_UTXO.into()))?;
        match self.db.get_cf(&cf, &utxo_key(txid, index)).map_err(|e| StorageError::ReadFailed(e.to_string()))? {
            Some(d) => Ok(Some(decode(&d)?)),
            None    => Ok(None),
        }
    }

    pub fn iter_all_blocks(&self) -> Vec<([u8; 32], crate::core::Block)> {
        let mut results = Vec::new();
        if let Some(cf) = self.db.cf_handle(CF_BLOCKS) {
            let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
            for item in iter {
                self.note_reads(1);
                if let Ok((key, val)) = item {
                    if key.len() == 32 {
                        let mut hash = [0u8; 32];
                        hash.copy_from_slice(&key);
                        // Sprint 1.b: Bitcoin-format decode (replaces bincode).
                        if let Ok(block) = crate::core::Block::from_wire_bytes(&val) {
                            results.push((hash, block));
                        }
                    }
                }
            }
        }
        results
    }

    /// Iterate the entire UTXO set in DETERMINISTIC order for snapshotting.
    ///
    /// Returns `(txid, vout, value, script_pubkey)` sorted by the raw CF_UTXO key,
    /// which is `txid ‖ vout_be` — so the order is a pure function of the set's
    /// contents, independent of insertion history, RocksDB compaction state, or
    /// which node produced it. Two honest nodes at the same height MUST produce
    /// byte-identical output; that is what makes a commitment over this meaningful.
    ///
    /// Why this exists: block bodies below `pruned_height` are deleted (see
    /// [`Self::prune_blocks_below`]) but the UTXO set is retained in full. On this
    /// fleet in 2026-07 that left ~95% of history unservable while every balance
    /// stayed intact and queryable — so the SET is recoverable even when the CHAIN
    /// that produced it is not. A snapshot taken here is the carry-over artifact
    /// for any migration, and the input to an assumeutxo-style bootstrap for fresh
    /// nodes that cannot sync from genesis because no archival peer has the bodies.
    ///
    /// Read-only friendly: pair with [`Self::open_read_only`] to snapshot a data-dir
    /// while the node keeps running on it.
    pub fn iter_utxos_sorted(&self) -> Result<Vec<(Vec<u8>, u32, u64, Vec<u8>)>, StorageError> {
        let cf = self.db.cf_handle(CF_UTXO).ok_or(StorageError::CfNotFound(CF_UTXO.into()))?;
        let mut out: Vec<(Vec<u8>, u32, u64, Vec<u8>)> = Vec::new();
        for item in self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start) {
            self.note_reads(1);
            let (key, val) = item.map_err(|e| StorageError::ReadFailed(e.to_string()))?;
            // Fail the whole export on corruption; a partial ledger cannot
            // be advertised as a complete carryover set. Preserve historical
            // vout decoding for reproducibility (Legacy M-3).
            out.push(decode_snapshot_row(&key, &val, false)?);
        }
        // RocksDB already yields keys in byte order; sort explicitly so the
        // guarantee is in THIS function rather than in an engine detail.
        out.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        Ok(out)
    }

    pub fn clear_utxos(&self) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_UTXO).ok_or(StorageError::CfNotFound(CF_UTXO.into()))?;
        let _agg = self.agg_lock();
        let mut deltas = aggregates::HolderDeltas::default();
        let mut batch = rocksdb::WriteBatch::default();
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        for item in iter {
            if let Ok((key, val)) = item {
                if let Ok(out) = decode::<TxOutput>(&val) {
                    deltas.remove(&out);
                }
                batch.delete_cf(&cf, &key);
            }
        }
        self.stage_holder_deltas(&mut batch, &deltas)?;
        self.db.write(batch).map_err(|e| StorageError::WriteFailed(e.to_string()))?;
        Ok(())
    }

    /// Delete one UTXO with its address-index row. NET-12: the explorer
    /// aggregates change in the SAME write batch.
    pub fn delete_utxo(&self, txid: &[u8], index: u32) -> Result<(), StorageError> {
        // Fetch the UTXO first to get the address for index cleanup
        let cf = self.db.cf_handle(CF_UTXO).ok_or(StorageError::CfNotFound(CF_UTXO.into()))?;
        let _agg = self.agg_lock();
        let mut deltas = aggregates::HolderDeltas::default();
        let mut batch = rocksdb::WriteBatch::default();
        if let Some(data) = self.db.get_cf(&cf, &utxo_key(txid, index))
            .map_err(|e| StorageError::ReadFailed(e.to_string()))?
        {
            if let Ok(output) = decode::<TxOutput>(&data) {
                if output.script_pubkey.len() >= 20 {
                    let cf_ai = self.db.cf_handle(CF_ADDR_UTXO).ok_or(StorageError::CfNotFound(CF_ADDR_UTXO.into()))?;
                    batch.delete_cf(&cf_ai, addr_utxo_key(&output.script_pubkey, txid, index));
                }
                deltas.remove(&output);
            }
        }
        batch.delete_cf(&cf, utxo_key(txid, index));
        self.stage_holder_deltas(&mut batch, &deltas)?;
        self.db.write(batch).map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    /// O(k) balance query via address index (was O(n) full UTXO scan)
    pub fn get_balance(&self, address_bytes: &[u8]) -> Result<(u64, usize), StorageError> {
        if address_bytes.len() < 20 {
            return Ok((0, 0)); // invalid address length
        }
        let cf_ai = self.db.cf_handle(CF_ADDR_UTXO).ok_or(StorageError::CfNotFound(CF_ADDR_UTXO.into()))?;
        let cf_utxo = self.db.cf_handle(CF_UTXO).ok_or(StorageError::CfNotFound(CF_UTXO.into()))?;
        let prefix = address_bytes.to_vec();

        let (mut total, mut count) = (0u64, 0usize);
        let iter = self.db.prefix_iterator_cf(&cf_ai, &prefix);
        for item in iter {
            self.note_reads(2);
            if let Ok((k, _)) = item {
                // Stop when prefix no longer matches
                if k.len() < address_bytes.len() || &k[..address_bytes.len()] != address_bytes { break; }
                // Extract txid + index from key: [20B addr][32B txid][4B idx]
                let expected_len = address_bytes.len() + 36;
                if k.len() == expected_len {
                    let utxo_k = k[address_bytes.len()..expected_len].to_vec(); // 32B txid + 4B index
                    if let Some(v) = self.db.get_cf(&cf_utxo, &utxo_k)
                        .map_err(|e| StorageError::ReadFailed(e.to_string()))?
                    {
                        if let Ok(out) = decode::<TxOutput>(&v) {
                            total = total.saturating_add(out.value);
                            count += 1;
                        }
                    }
                }
            }
        }
        Ok((total, count))
    }

    /// Count distinct addresses that currently hold at least one UTXO — i.e.
    /// the number of on-chain "wallets" with a non-zero balance. Iterates
    /// CF_ADDR_UTXO whose keys are `[20B addr][32B txid][4B idx]`; the distinct
    /// 20-byte address prefixes are the wallets. Also returns the total UTXO
    /// entry count. O(n) over the UTXO-address index.
    pub fn count_addresses_with_balance(&self) -> Result<(usize, usize), StorageError> {
        let cf_ai = self.db.cf_handle(CF_ADDR_UTXO)
            .ok_or(StorageError::CfNotFound(CF_ADDR_UTXO.into()))?;
        let mut set = std::collections::HashSet::<[u8; 20]>::new();
        let mut utxos = 0usize;
        for item in self.db.iterator_cf(&cf_ai, IteratorMode::Start) {
            self.note_reads(1);
            if let Ok((k, _)) = item {
                if k.len() >= 20 {
                    let mut addr = [0u8; 20];
                    addr.copy_from_slice(&k[..20]);
                    set.insert(addr);
                    utxos += 1;
                }
            }
        }
        Ok((set.len(), utxos))
    }

    /// O(k) UTXO lookup via address index (was O(n) full UTXO scan)
    /// UTXOs paying exactly `address_bytes`, the FULL script_pubkey (20-byte
    /// key hash or 33-byte policy script): the index key is
    /// `script ‖ txid ‖ index`, so a shorter prefix finds nothing.
    pub fn get_utxos_for_address(&self, address_bytes: &[u8]) -> Result<Vec<(Vec<u8>, u32, TxOutput)>, StorageError> {
        if address_bytes.len() < 20 {
            return Ok(vec![]);
        }
        let cf_ai = self.db.cf_handle(CF_ADDR_UTXO).ok_or(StorageError::CfNotFound(CF_ADDR_UTXO.into()))?;
        let cf_utxo = self.db.cf_handle(CF_UTXO).ok_or(StorageError::CfNotFound(CF_UTXO.into()))?;
        let prefix = address_bytes.to_vec();

        let mut result = Vec::new();
        let iter = self.db.prefix_iterator_cf(&cf_ai, &prefix);
        for item in iter {
            self.note_reads(2);
            if let Ok((k, _)) = item {
                let alen = address_bytes.len();
                if k.len() < alen || &k[..alen] != address_bytes { break; }
                let expected = alen + 36;
                if k.len() == expected {
                    let txid = k[alen..alen+32].to_vec();
                    let idx = u32::from_le_bytes(k[alen+32..expected].try_into().unwrap());
                    let utxo_k = k[alen..expected].to_vec();
                    if let Some(v) = self.db.get_cf(&cf_utxo, &utxo_k)
                        .map_err(|e| StorageError::ReadFailed(e.to_string()))?
                    {
                        if let Ok(out) = decode::<TxOutput>(&v) {
                            result.push((txid, idx, out));
                        }
                    }
                }
            }
        }
        Ok(result)
    }

    /// NET-12: [`Self::get_utxos_for_address`] that stops after `limit`
    /// entries while walking the address index, instead of loading every
    /// UTXO of the address first. Returns the UTXOs and whether more exist.
    pub fn get_utxos_for_address_limited(
        &self,
        address_bytes: &[u8],
        limit: usize,
    ) -> Result<(Vec<(Vec<u8>, u32, TxOutput)>, bool), StorageError> {
        if address_bytes.len() < 20 {
            return Ok((vec![], false));
        }
        let cf_ai = self.db.cf_handle(CF_ADDR_UTXO).ok_or(StorageError::CfNotFound(CF_ADDR_UTXO.into()))?;
        let cf_utxo = self.db.cf_handle(CF_UTXO).ok_or(StorageError::CfNotFound(CF_UTXO.into()))?;
        let alen = address_bytes.len();
        let expected = alen + 36;
        let mut result = Vec::new();
        for (k, _) in self.db.prefix_iterator_cf(&cf_ai, address_bytes).flatten() {
            self.note_reads(2);
            if k.len() < alen || &k[..alen] != address_bytes { break; }
            if k.len() != expected { continue; }
            let Some(v) = self.db.get_cf(&cf_utxo, &k[alen..expected])
                .map_err(|e| StorageError::ReadFailed(e.to_string()))? else { continue };
            let Ok(out) = decode::<TxOutput>(&v) else { continue };
            if result.len() == limit {
                return Ok((result, true));
            }
            let mut idx = [0u8; 4];
            idx.copy_from_slice(&k[alen + 32..expected]);
            result.push((k[alen..alen + 32].to_vec(), u32::from_le_bytes(idx), out));
        }
        Ok((result, false))
    }

    // ── DAG persistence ─────────────────────────────────────────────────────

    /// Persist GhostDAG data for a single block
    pub fn put_dag_data(&self, hash: &BlockHash, data: &GhostdagData) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_DAG).ok_or(StorageError::CfNotFound(CF_DAG.into()))?;
        self.db.put_cf(&cf, hash, &encode(data)?)
            .map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    /// Load GhostDAG data for a single block
    pub fn get_dag_data(&self, hash: &BlockHash) -> Result<Option<GhostdagData>, StorageError> {
        self.note_reads(1);
        let cf = self.db.cf_handle(CF_DAG).ok_or(StorageError::CfNotFound(CF_DAG.into()))?;
        match self.db.get_cf(&cf, hash).map_err(|e| StorageError::ReadFailed(e.to_string()))? {
            Some(d) => Ok(Some(decode(&d)?)),
            None    => Ok(None),
        }
    }

    // ── Sprint Y (M-2): GhostdagData integrity chain ──────────────────
    //
    // See `src/consensus/mod.rs::canonical_encode` and
    // `compute_integrity_hash` for the chain definition, and
    // `GhostDAG::load_persisted_validated` for the verifier.
    //
    // `put_dag_with_integrity` is the preferred write path: it looks up
    // the parent's integrity hash, computes this block's integrity, and
    // writes both CF_DAG and CF_DAG_INTEGRITY in a single WriteBatch so
    // they can never drift out of sync.
    //
    // The plain `put_dag_data` above is kept for backwards compatibility
    // and for call sites that have already computed integrity themselves.

    /// Persist GhostDAG data AND its integrity hash atomically.
    /// Returns the computed integrity hash (useful for logging / chaining).
    pub fn put_dag_with_integrity(
        &self,
        hash: &BlockHash,
        data: &GhostdagData,
    ) -> Result<[u8; 32], StorageError> {
        // 1. Parent lookup. Genesis uses all-zero parent integrity —
        //    matches the chain base convention in `load_persisted_validated`.
        let parent_integrity: [u8; 32] = match &data.selected_parent {
            Some(sp) => self.get_integrity_hash(sp)?.unwrap_or([0u8; 32]),
            None     => [0u8; 32],
        };

        // 2. Compute this block's chain link.
        let integrity = crate::consensus::compute_integrity_hash(hash, data, &parent_integrity);

        // 3. Atomic write. WriteBatch guarantees either both CFs are
        //    updated or neither, even if the process is killed mid-write.
        let cf_dag = self.db.cf_handle(CF_DAG)
            .ok_or(StorageError::CfNotFound(CF_DAG.into()))?;
        let cf_int = self.db.cf_handle(CF_DAG_INTEGRITY)
            .ok_or(StorageError::CfNotFound(CF_DAG_INTEGRITY.into()))?;

        let mut batch = rocksdb::WriteBatch::default();
        batch.put_cf(&cf_dag, hash, &encode(data)?);
        batch.put_cf(&cf_int, hash, &integrity);
        self.db.write(batch)
            .map_err(|e| StorageError::WriteFailed(e.to_string()))?;

        Ok(integrity)
    }

    /// Read a single block's integrity hash. `Ok(None)` if absent —
    /// the caller distinguishes between "pre-Sprint-Y database" (all
    /// absent) and "targeted deletion" (some absent) at load time.
    pub fn get_integrity_hash(&self, hash: &BlockHash) -> Result<Option<[u8; 32]>, StorageError> {
        let cf = self.db.cf_handle(CF_DAG_INTEGRITY)
            .ok_or(StorageError::CfNotFound(CF_DAG_INTEGRITY.into()))?;
        match self.db.get_cf(&cf, hash).map_err(|e| StorageError::ReadFailed(e.to_string()))? {
            Some(b) if b.len() == 32 => {
                let mut out = [0u8; 32];
                out.copy_from_slice(&b);
                Ok(Some(out))
            }
            Some(_) => Err(StorageError::DeserializeFailed(
                "CF_DAG_INTEGRITY entry has wrong length (not 32 bytes)".into()
            )),
            None => Ok(None),
        }
    }

    /// Persist an integrity hash directly. Used by `load_persisted_validated`
    /// during the self-heal migration from pre-Sprint-Y databases.
    pub fn put_integrity_hash(
        &self,
        hash: &BlockHash,
        integrity: &[u8; 32],
    ) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_DAG_INTEGRITY)
            .ok_or(StorageError::CfNotFound(CF_DAG_INTEGRITY.into()))?;
        self.db.put_cf(&cf, hash, integrity)
            .map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    /// Load every (block_hash → integrity_hash) record from CF_DAG_INTEGRITY.
    /// Returns an empty map on a pre-Sprint-Y database; the caller treats
    /// that as "self-heal on first boot".
    pub fn load_all_integrity_hashes(
        &self,
    ) -> Result<std::collections::HashMap<BlockHash, [u8; 32]>, StorageError> {
        let cf = self.db.cf_handle(CF_DAG_INTEGRITY)
            .ok_or(StorageError::CfNotFound(CF_DAG_INTEGRITY.into()))?;
        let mut map = std::collections::HashMap::new();
        for item in self.db.iterator_cf(&cf, IteratorMode::Start) {
            if let Ok((k, v)) = item {
                if k.len() == 32 && v.len() == 32 {
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&k);
                    let mut i = [0u8; 32];
                    i.copy_from_slice(&v);
                    map.insert(h, i);
                }
            }
        }
        Ok(map)
    }

    /// Load all persisted DAG data for full reconstruction on startup.
    /// Returns (hash, data) pairs in insertion order is NOT guaranteed —
    /// caller must handle topological insertion.
    pub fn load_all_dag_data(&self) -> Result<Vec<(BlockHash, GhostdagData)>, StorageError> {
        let cf = self.db.cf_handle(CF_DAG).ok_or(StorageError::CfNotFound(CF_DAG.into()))?;
        let mut entries = Vec::new();
        for item in self.db.iterator_cf(&cf, IteratorMode::Start) {
            if let Ok((k, v)) = item {
                if k.len() == 32 {
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(&k);
                    if let Ok(data) = decode::<GhostdagData>(&v) {
                        entries.push((hash, data));
                    }
                }
            }
        }
        Ok(entries)
    }

    // ── Durable reachability index (Phase 1) ────────────────────────────
    //
    // The interval-reachability index (`consensus::reachability::ReachabilityStore`)
    // is an O(1)/O(log n) DAG-ancestry cache. It is NOT consensus state — it is
    // never hashed into the integrity chain and can always be rebuilt by
    // replaying CF_DAG. To make it durable (and avoid an O(chain) rebuild every
    // boot) its per-block records live in CF_REACHABILITY, and — crucially —
    // each record delta is written in the SAME WriteBatch as the CF_DAG block it
    // derives from (`put_dag_with_integrity_and_reach`), so a crash can never
    // leave the index describing a block CF_DAG doesn't have, or vice-versa.
    //
    // The layout version + root live in CF_META under `reachability/meta/*`.

    /// Schema version for the CF_REACHABILITY record layout, mirrored from
    /// `consensus::reachability::REACHABILITY_RECORD_VERSION`. On boot a
    /// mismatch (or absent tag) forces a full rebuild from CF_DAG.
    pub const REACHABILITY_SCHEMA_VERSION: u32 =
        crate::consensus::reachability::REACHABILITY_RECORD_VERSION;

    /// Atomic CF_DAG + CF_DAG_INTEGRITY + CF_REACHABILITY write.
    ///
    /// Identical to [`put_dag_with_integrity`] for the DAG/integrity CFs, but
    /// additionally folds the reachability delta (`reach_upserts` /
    /// `reach_removals`, drained from `ReachabilityStore::take_persist_delta`)
    /// into the SAME `WriteBatch`. All-or-nothing: after a crash the block, its
    /// integrity link, and every reachability record touched by inserting it
    /// either all landed or none did.
    ///
    /// Used only when the reachability index is being maintained (Fast /
    /// armed-activation). On the live Legacy path the caller uses the plain
    /// [`put_dag_with_integrity`] and CF_REACHABILITY stays empty.
    pub fn put_dag_with_integrity_and_reach(
        &self,
        hash: &BlockHash,
        data: &GhostdagData,
        reach_upserts: &[(BlockHash, Vec<u8>)],
        reach_removals: &[BlockHash],
    ) -> Result<[u8; 32], StorageError> {
        let mut batch = rocksdb::WriteBatch::default();
        let integrity = self.stage_dag_entry(&mut batch, hash, data, reach_upserts, reach_removals)?;
        self.db.write(batch)
            .map_err(|e| StorageError::WriteFailed(e.to_string()))?;
        Ok(integrity)
    }

    /// Stage a block's CF_DAG entry, its integrity link and a reachability
    /// delta into `batch`, so a caller can commit them together with the
    /// chain-state change of the same block (one atomic write: a crash can
    /// never leave the UTXO set applied for a block CF_DAG does not know).
    /// The selected parent's integrity hash must already be committed.
    pub fn stage_dag_entry(
        &self,
        batch: &mut rocksdb::WriteBatch,
        hash: &BlockHash,
        data: &GhostdagData,
        reach_upserts: &[(BlockHash, Vec<u8>)],
        reach_removals: &[BlockHash],
    ) -> Result<[u8; 32], StorageError> {
        let parent_integrity: [u8; 32] = match &data.selected_parent {
            Some(sp) => self.get_integrity_hash(sp)?.unwrap_or([0u8; 32]),
            None     => [0u8; 32],
        };
        let integrity = crate::consensus::compute_integrity_hash(hash, data, &parent_integrity);

        let cf_dag = self.db.cf_handle(CF_DAG)
            .ok_or(StorageError::CfNotFound(CF_DAG.into()))?;
        let cf_int = self.db.cf_handle(CF_DAG_INTEGRITY)
            .ok_or(StorageError::CfNotFound(CF_DAG_INTEGRITY.into()))?;
        let cf_reach = self.db.cf_handle(CF_REACHABILITY)
            .ok_or(StorageError::CfNotFound(CF_REACHABILITY.into()))?;

        batch.put_cf(&cf_dag, hash, &encode(data)?);
        batch.put_cf(&cf_int, hash, &integrity);
        for (h, rec) in reach_upserts {
            batch.put_cf(&cf_reach, h, rec);
        }
        for h in reach_removals {
            batch.delete_cf(&cf_reach, h);
        }
        Ok(integrity)
    }

    // ── Batched chain-state staging (audit DAG-11) ─────────────────────
    //
    // The acceptance pipeline commits a block's UTXO effects, undo record,
    // CF_DAG + CF_DAG_INTEGRITY (+ CF_REACHABILITY) record, the selected-chain
    // indexes, the tip pointer and any invalid-block marks in ONE RocksDB
    // WriteBatch (see `reorg::connect_plan`). These helpers stage into a
    // caller-owned batch; nothing is visible until the caller commits it.

    /// Stage a block's CF_DAG + CF_DAG_INTEGRITY record (+ the reachability
    /// delta) into `batch`. Returns the staged integrity hash.
    ///
    /// Unlike `put_dag_with_integrity`, a missing selected-parent integrity
    /// record is an ERROR here (DAG-11): zero-filling it wrote a link that the
    /// boot-time chain check then rejected, turning a lost write into a fatal
    /// start-up error. `parent_integrity_override` lets the caller supply a
    /// parent integrity it staged in the same batch (lazy genesis record).
    pub fn stage_dag_record(
        &self,
        batch: &mut rocksdb::WriteBatch,
        hash: &BlockHash,
        data: &GhostdagData,
        reach_upserts: &[(BlockHash, Vec<u8>)],
        reach_removals: &[BlockHash],
        parent_integrity_override: Option<[u8; 32]>,
    ) -> Result<[u8; 32], StorageError> {
        let parent_integrity: [u8; 32] = match (&data.selected_parent, parent_integrity_override) {
            (_, Some(p)) => p,
            (Some(sp), None) => self.get_integrity_hash(sp)?.ok_or_else(|| {
                StorageError::ReadFailed(format!(
                    "integrity record of selected parent {} is missing; refusing to \
                     write a zero-filled chain link",
                    hex::encode(&sp[..8])
                ))
            })?,
            (None, None) => [0u8; 32],
        };
        let integrity = crate::consensus::compute_integrity_hash(hash, data, &parent_integrity);
        let cf_dag = self.db.cf_handle(CF_DAG).ok_or(StorageError::CfNotFound(CF_DAG.into()))?;
        let cf_int = self.db.cf_handle(CF_DAG_INTEGRITY)
            .ok_or(StorageError::CfNotFound(CF_DAG_INTEGRITY.into()))?;
        let cf_reach = self.db.cf_handle(CF_REACHABILITY)
            .ok_or(StorageError::CfNotFound(CF_REACHABILITY.into()))?;
        batch.put_cf(&cf_dag, hash, &encode(data)?);
        batch.put_cf(&cf_int, hash, &integrity);
        for (h, rec) in reach_upserts {
            batch.put_cf(&cf_reach, h, rec);
        }
        for h in reach_removals {
            batch.delete_cf(&cf_reach, h);
        }
        Ok(integrity)
    }

    /// Stage a CF_META write.
    pub fn stage_meta(&self, batch: &mut rocksdb::WriteBatch, key: &str, value: &[u8])
        -> Result<(), StorageError>
    {
        let cf = self.db.cf_handle(CF_META).ok_or(StorageError::CfNotFound(CF_META.into()))?;
        batch.put_cf(&cf, key.as_bytes(), value);
        Ok(())
    }

    /// Commit a caller-built batch atomically.
    pub fn write_batch(&self, batch: rocksdb::WriteBatch) -> Result<(), StorageError> {
        self.db.write(batch).map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    /// Stage the SELECTED-CHAIN indexes of a block being connected (DAG-12):
    /// height→hash, height→timestamp and the address-history rows. Input rows
    /// resolve the spent output through `spent` (the block's undo capture), so
    /// they are byte-identical to what `rollback_block` later un-indexes.
    pub fn stage_chain_index(
        &self,
        batch: &mut rocksdb::WriteBatch,
        block: &Block,
        spent: &std::collections::HashMap<([u8; 32], u32), TxOutput>,
    ) -> Result<(), StorageError> {
        let hash = block.block_hash();
        let cf_h = self.db.cf_handle(CF_HEIGHT).ok_or(StorageError::CfNotFound(CF_HEIGHT.into()))?;
        let cf_t = self.db.cf_handle(CF_TIMESTAMPS).ok_or(StorageError::CfNotFound(CF_TIMESTAMPS.into()))?;
        let cf_ai = self.db.cf_handle(CF_ADDR_TX_HISTORY)
            .ok_or(StorageError::CfNotFound(CF_ADDR_TX_HISTORY.into()))?;
        batch.put_cf(&cf_h, &block.height.to_be_bytes(), &hash);
        batch.put_cf(&cf_t, &block.height.to_be_bytes(), &block.header.timestamp.to_le_bytes());
        for (tx_idx, tx) in block.transactions.iter().enumerate() {
            let txid = tx.txid();
            for (vout, out) in tx.outputs.iter().enumerate() {
                if out.script_pubkey.len() >= 20 {
                    let mut addr = [0u8; 20];
                    addr.copy_from_slice(&out.script_pubkey[..20]);
                    batch.put_cf(&cf_ai,
                        indexer::make_key(&addr, block.height, tx_idx as u32, vout as u32),
                        indexer::make_value(&txid, indexer::DIR_OUT, out.value));
                }
            }
            if !tx.is_coinbase() {
                for (vin, inp) in tx.inputs.iter().enumerate() {
                    if let Some(prev) = spent.get(&(inp.prev_txid, inp.prev_index)) {
                        if prev.script_pubkey.len() >= 20 {
                            let mut addr = [0u8; 20];
                            addr.copy_from_slice(&prev.script_pubkey[..20]);
                            batch.put_cf(&cf_ai,
                                indexer::make_key(&addr, block.height, tx_idx as u32, 0x8000_0000 | vin as u32),
                                indexer::make_value(&txid, indexer::DIR_IN, prev.value));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Stage removal of a disconnected block's height→hash / height→timestamp
    /// rows, but only where they still point at this block (a block connected
    /// later in the same batch overwrites them in batch order). Address-history
    /// rows are un-indexed by the rollback staging itself.
    pub fn stage_chain_unindex(&self, batch: &mut rocksdb::WriteBatch, block: &Block)
        -> Result<(), StorageError>
    {
        self.stage_chain_unindex_at(batch, block.height, &block.block_hash())
    }

    /// [`stage_chain_unindex`](Self::stage_chain_unindex) from a height and a
    /// hash alone, for a block whose body was pruned (both come from its undo
    /// record), so a reorg of any depth can disconnect it (audit DAG-6).
    pub fn stage_chain_unindex_at(&self, batch: &mut rocksdb::WriteBatch, height: u64, hash: &BlockHash)
        -> Result<(), StorageError>
    {
        if self.get_block_hash_at_height(height)? == Some(*hash) {
            let cf_h = self.db.cf_handle(CF_HEIGHT).ok_or(StorageError::CfNotFound(CF_HEIGHT.into()))?;
            let cf_t = self.db.cf_handle(CF_TIMESTAMPS).ok_or(StorageError::CfNotFound(CF_TIMESTAMPS.into()))?;
            batch.delete_cf(&cf_h, height.to_be_bytes());
            batch.delete_cf(&cf_t, height.to_be_bytes());
        }
        Ok(())
    }

    // ── Shielded-pool state (audit COH-2; key layout in coherence::persist) ──

    /// Stage a CF_SHIELDED put.
    pub fn stage_shielded_put(&self, batch: &mut rocksdb::WriteBatch, key: &[u8], value: &[u8])
        -> Result<(), StorageError>
    {
        let cf = self.db.cf_handle(CF_SHIELDED).ok_or(StorageError::CfNotFound(CF_SHIELDED.into()))?;
        batch.put_cf(&cf, key, value);
        Ok(())
    }

    /// Stage a CF_SHIELDED delete.
    pub fn stage_shielded_delete(&self, batch: &mut rocksdb::WriteBatch, key: &[u8])
        -> Result<(), StorageError>
    {
        let cf = self.db.cf_handle(CF_SHIELDED).ok_or(StorageError::CfNotFound(CF_SHIELDED.into()))?;
        batch.delete_cf(&cf, key);
        Ok(())
    }

    /// Read one CF_SHIELDED value.
    pub fn get_shielded(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let cf = self.db.cf_handle(CF_SHIELDED).ok_or(StorageError::CfNotFound(CF_SHIELDED.into()))?;
        self.db.get_cf(&cf, key).map_err(|e| StorageError::ReadFailed(e.to_string()))
    }

    /// Every CF_SHIELDED (key, value) whose key starts with `prefix`, in key
    /// order.
    pub fn scan_shielded_prefix(&self, prefix: &[u8]) -> Result<KeyValueRows, StorageError> {
        let cf = self.db.cf_handle(CF_SHIELDED).ok_or(StorageError::CfNotFound(CF_SHIELDED.into()))?;
        let mut out = Vec::new();
        for item in self.db.iterator_cf(&cf, IteratorMode::From(prefix, rocksdb::Direction::Forward)) {
            let (k, v) = item.map_err(|e| StorageError::ReadFailed(e.to_string()))?;
            if !k.starts_with(prefix) {
                break;
            }
            out.push((k.to_vec(), v.to_vec()));
        }
        Ok(out)
    }

    // ── Chain-disqualified blocks (audit DAG-1) ─────────────────────────

    const INVALID_PREFIX: &'static [u8] = b"invalid_block/";

    fn invalid_key(hash: &BlockHash) -> Vec<u8> {
        let mut k = Self::INVALID_PREFIX.to_vec();
        k.extend_from_slice(hash);
        k
    }

    /// Stage a persistent "chain-disqualified" mark for `hash` with a short
    /// reason (diagnostics only — the mark itself is what is consensus-relevant
    /// for this node: the block is never selected or applied again).
    pub fn stage_invalid_block(&self, batch: &mut rocksdb::WriteBatch, hash: &BlockHash, reason: &str)
        -> Result<(), StorageError>
    {
        let cf = self.db.cf_handle(CF_META).ok_or(StorageError::CfNotFound(CF_META.into()))?;
        let mut r = reason.as_bytes().to_vec();
        r.truncate(256);
        batch.put_cf(&cf, Self::invalid_key(hash), r);
        Ok(())
    }

    /// Every persisted chain-disqualified block hash.
    pub fn load_invalid_blocks(&self) -> Result<Vec<BlockHash>, StorageError> {
        Ok(self.load_invalid_blocks_with_reasons()?.into_iter().map(|(h, _)| h).collect())
    }

    /// Every persisted chain-disqualified block hash with its recorded reason.
    pub fn load_invalid_blocks_with_reasons(&self) -> Result<Vec<(BlockHash, String)>, StorageError> {
        let cf = self.db.cf_handle(CF_META).ok_or(StorageError::CfNotFound(CF_META.into()))?;
        let mut out = Vec::new();
        let iter = self.db.iterator_cf(&cf, IteratorMode::From(Self::INVALID_PREFIX, rocksdb::Direction::Forward));
        for item in iter {
            let (k, v) = item.map_err(|e| StorageError::ReadFailed(e.to_string()))?;
            if !k.starts_with(Self::INVALID_PREFIX) {
                break;
            }
            if k.len() == Self::INVALID_PREFIX.len() + 32 {
                let mut h = [0u8; 32];
                h.copy_from_slice(&k[Self::INVALID_PREFIX.len()..]);
                out.push((h, String::from_utf8_lossy(&v).into_owned()));
            }
        }
        Ok(out)
    }

    /// Stage removal of the persisted chain-disqualified mark of `hash`
    /// (operator `reconsiderblock`, chain-state rebuild).
    pub fn stage_clear_invalid_block(&self, batch: &mut rocksdb::WriteBatch, hash: &BlockHash)
        -> Result<(), StorageError>
    {
        let cf = self.db.cf_handle(CF_META).ok_or(StorageError::CfNotFound(CF_META.into()))?;
        batch.delete_cf(&cf, Self::invalid_key(hash));
        Ok(())
    }

    /// The recorded reason a block was disqualified, if it was.
    pub fn invalid_block_reason(&self, hash: &BlockHash) -> Result<Option<String>, StorageError> {
        let cf = self.db.cf_handle(CF_META).ok_or(StorageError::CfNotFound(CF_META.into()))?;
        Ok(self.db.get_cf(&cf, Self::invalid_key(hash))
            .map_err(|e| StorageError::ReadFailed(e.to_string()))?
            .map(|v| String::from_utf8_lossy(&v).into_owned()))
    }

    /// Persist a full reachability snapshot + its version tag + root in one
    /// batch. Used after a boot-time rebuild to write the freshly-materialized
    /// index. Clears any stale records first so the CF exactly mirrors memory.
    pub fn store_reachability_snapshot(
        &self,
        records: &[(BlockHash, Vec<u8>)],
        root: Option<BlockHash>,
    ) -> Result<(), StorageError> {
        let cf_reach = self.db.cf_handle(CF_REACHABILITY)
            .ok_or(StorageError::CfNotFound(CF_REACHABILITY.into()))?;
        let cf_meta = self.db.cf_handle(CF_META)
            .ok_or(StorageError::CfNotFound(CF_META.into()))?;
        let mut batch = rocksdb::WriteBatch::default();
        // Wipe existing records (rebuild replaces the whole index).
        for item in self.db.iterator_cf(&cf_reach, IteratorMode::Start) {
            if let Ok((k, _)) = item { batch.delete_cf(&cf_reach, &k); }
        }
        for (h, rec) in records {
            batch.put_cf(&cf_reach, h, rec);
        }
        batch.put_cf(&cf_meta, b"reachability/meta/version",
                     &Self::REACHABILITY_SCHEMA_VERSION.to_le_bytes());
        match root {
            Some(r) => batch.put_cf(&cf_meta, b"reachability/meta/root", &r),
            None    => batch.delete_cf(&cf_meta, b"reachability/meta/root"),
        }
        self.db.write(batch).map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    /// Load every persisted `(block_hash, record_bytes)` from CF_REACHABILITY.
    pub fn load_all_reachability(&self) -> Result<Vec<(BlockHash, Vec<u8>)>, StorageError> {
        let cf = self.db.cf_handle(CF_REACHABILITY)
            .ok_or(StorageError::CfNotFound(CF_REACHABILITY.into()))?;
        let mut out = Vec::new();
        for item in self.db.iterator_cf(&cf, IteratorMode::Start) {
            if let Ok((k, v)) = item {
                if k.len() == 32 {
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&k);
                    out.push((h, v.to_vec()));
                }
            }
        }
        Ok(out)
    }

    /// Read the persisted reachability schema version, if present.
    pub fn get_reachability_version(&self) -> Result<Option<u32>, StorageError> {
        Ok(self.get_meta("reachability/meta/version")?
            .and_then(|b| b.as_slice().try_into().ok().map(u32::from_le_bytes)))
    }

    /// Read the persisted reachability root (genesis) hash, if present.
    pub fn get_reachability_root(&self) -> Result<Option<BlockHash>, StorageError> {
        Ok(self.get_meta("reachability/meta/root")?
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok()))
    }

    // ── Coinbase maturity tracking (FIX VULN-03) ────────────────────────

    /// Record that a txid is a coinbase transaction created at the given height.
    pub fn put_coinbase_info(&self, txid: &[u8; 32], height: u64) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_COINBASE).ok_or(StorageError::CfNotFound(CF_COINBASE.into()))?;
        self.db.put_cf(&cf, txid, &height.to_le_bytes())
            .map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    /// Get the height at which a coinbase transaction was created.
    /// Returns None if the txid is not a coinbase. A row that is not exactly
    /// 8 bytes is corrupted, an error: reading it as "not a coinbase" skipped
    /// the coinbase-maturity check (re-audit B1-T12).
    pub fn get_coinbase_height(&self, txid: &[u8; 32]) -> Result<Option<u64>, StorageError> {
        self.note_reads(1);
        let cf = self.db.cf_handle(CF_COINBASE).ok_or(StorageError::CfNotFound(CF_COINBASE.into()))?;
        match self.db.get_cf(&cf, txid).map_err(|e| StorageError::ReadFailed(e.to_string()))? {
            Some(d) => <[u8; 8]>::try_from(d.as_slice()).map(|b| Some(u64::from_le_bytes(b))).map_err(|_| {
                StorageError::DeserializeFailed(format!(
                    "coinbase-height row of {} has {} bytes (expected 8)", hex::encode(&txid[..8]), d.len()))
            }),
            None => Ok(None),
        }
    }

    /// Sprint U.2 — Remove a coinbase-info record. Used by rollback_block to
    /// unmark a coinbase whose creating block was reverted out of the chain.
    /// Idempotent: deleting a missing record is not an error.
    pub fn delete_coinbase_info(&self, txid: &[u8; 32]) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_COINBASE).ok_or(StorageError::CfNotFound(CF_COINBASE.into()))?;
        self.db.delete_cf(&cf, txid).map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    // ── Transaction index (O(1) tx lookup) ────────────────────────────

    /// Index a transaction: txid → (block_hash, block_height)
    pub fn put_tx_index(&self, txid: &[u8; 32], block_hash: &[u8; 32], height: u64) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_TX_INDEX).ok_or(StorageError::CfNotFound(CF_TX_INDEX.into()))?;
        let mut val = Vec::with_capacity(40);
        val.extend_from_slice(block_hash);
        val.extend_from_slice(&height.to_le_bytes());
        self.db.put_cf(&cf, txid, &val).map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    /// Stage a CF_TX_INDEX row (same layout as [`put_tx_index`](Self::put_tx_index)).
    pub fn stage_tx_index(&self, batch: &mut rocksdb::WriteBatch, txid: &[u8; 32], block_hash: &[u8; 32], height: u64)
        -> Result<(), StorageError>
    {
        let cf = self.db.cf_handle(CF_TX_INDEX).ok_or(StorageError::CfNotFound(CF_TX_INDEX.into()))?;
        let mut val = Vec::with_capacity(40);
        val.extend_from_slice(block_hash);
        val.extend_from_slice(&height.to_le_bytes());
        batch.put_cf(&cf, txid, &val);
        Ok(())
    }

    /// Stage a UTXO row and its address-index row (same layout as
    /// [`put_utxo`](Self::put_utxo)).
    pub fn stage_utxo(&self, batch: &mut rocksdb::WriteBatch, txid: &[u8], index: u32, output: &TxOutput)
        -> Result<(), StorageError>
    {
        let cf = self.db.cf_handle(CF_UTXO).ok_or(StorageError::CfNotFound(CF_UTXO.into()))?;
        batch.put_cf(&cf, utxo_key(txid, index), encode(output)?);
        if output.script_pubkey.len() >= 20 {
            let cf_ai = self.db.cf_handle(CF_ADDR_UTXO).ok_or(StorageError::CfNotFound(CF_ADDR_UTXO.into()))?;
            batch.put_cf(&cf_ai, addr_utxo_key(&output.script_pubkey, txid, index), [0u8; 0]);
        }
        Ok(())
    }

    /// Lookup transaction location: returns (block_hash, block_height). A
    /// row that is not 40 bytes is an error, never "not confirmed" (re-audit
    /// B1-T12: coinbase maturity and relative timelocks read this row while
    /// a block is connected, and an absent confirmation is not a verdict
    /// either way).
    pub fn get_tx_location(&self, txid: &[u8; 32]) -> Result<Option<([u8; 32], u64)>, StorageError> {
        self.note_reads(1);
        let cf = self.db.cf_handle(CF_TX_INDEX).ok_or(StorageError::CfNotFound(CF_TX_INDEX.into()))?;
        match self.db.get_cf(&cf, txid).map_err(|e| StorageError::ReadFailed(e.to_string()))? {
            Some(d) if d.len() == 40 => {
                let mut bh = [0u8; 32];
                bh.copy_from_slice(&d[..32]);
                let height = u64::from_le_bytes(d[32..40].try_into().unwrap());
                Ok(Some((bh, height)))
            }
            Some(d) => Err(StorageError::DeserializeFailed(format!(
                "tx-index row of {} has {} bytes (expected 40)", hex::encode(&txid[..8]), d.len()))),
            None => Ok(None),
        }
    }

    /// Sprint U.2 — Remove a tx_index entry. Used by rollback_block to unpoint
    /// a txid away from a block that's being reverted. Idempotent.
    pub fn delete_tx_index(&self, txid: &[u8; 32]) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_TX_INDEX).ok_or(StorageError::CfNotFound(CF_TX_INDEX.into()))?;
        self.db.delete_cf(&cf, txid).map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    pub fn put_meta(&self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_META).ok_or(StorageError::CfNotFound(CF_META.into()))?;
        self.db.put_cf(&cf, key.as_bytes(), value).map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    pub fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        self.note_reads(1);
        let cf = self.db.cf_handle(CF_META).ok_or(StorageError::CfNotFound(CF_META.into()))?;
        self.db.get_cf(&cf, key.as_bytes()).map_err(|e| StorageError::ReadFailed(e.to_string()))
    }

    // ── Sprint U.1: Undo data for reorg rollback ─────────────────────────
    //
    // Each connected block writes one UndoData record keyed by block hash,
    // deleted only when the block is rolled back. Undo records are NEVER
    // pruned: there is no reorg-depth limit (audit DAG-6), so a reorg of any
    // depth must be able to disconnect any connected block.

    /// Persist the undo record for a block. Should be called once per block,
    /// immediately after all UTXO/index mutations for that block complete.
    pub fn put_undo_data(&self, block_hash: &[u8; 32], data: &crate::core::UndoData)
        -> Result<(), StorageError>
    {
        let cf = self.db.cf_handle(CF_UNDO).ok_or(StorageError::CfNotFound(CF_UNDO.into()))?;
        // `UndoData::to_bytes`: the legacy encoding, plus the overwritten-rows
        // extension only when the block replaced something (audit VAL-2).
        let bytes = data.to_bytes().map_err(StorageError::SerializeFailed)?;
        self.db.put_cf(&cf, block_hash, &bytes)
            .map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    /// Fetch the undo record for a block. Returns Ok(None) if the block was
    /// accepted before U.1 landed, or if its undo record has been pruned.
    pub fn get_undo_data(&self, block_hash: &[u8; 32])
        -> Result<Option<crate::core::UndoData>, StorageError>
    {
        self.note_reads(1);
        let cf = self.db.cf_handle(CF_UNDO).ok_or(StorageError::CfNotFound(CF_UNDO.into()))?;
        match self.db.get_cf(&cf, block_hash).map_err(|e| StorageError::ReadFailed(e.to_string()))? {
            // Records written before the VAL-2 extension decode unchanged.
            Some(d) => Ok(Some(crate::core::UndoData::from_bytes(&d).map_err(StorageError::DeserializeFailed)?)),
            None    => Ok(None),
        }
    }

    /// True iff `block_hash` has an undo record (its effects are applied),
    /// without decoding it.
    pub fn has_undo_data(&self, block_hash: &[u8; 32]) -> Result<bool, StorageError> {
        let cf = self.db.cf_handle(CF_UNDO).ok_or(StorageError::CfNotFound(CF_UNDO.into()))?;
        Ok(self.db.get_pinned_cf(&cf, block_hash)
            .map_err(|e| StorageError::ReadFailed(e.to_string()))?
            .is_some())
    }

    /// Every block hash that has an undo record (i.e. whose UTXO effects are
    /// currently applied). Used by start-up reconciliation (DAG-11) to find
    /// blocks a pre-fix, non-atomic commit applied but never recorded in
    /// CF_DAG. Keys only; O(applied blocks).
    pub fn undo_block_hashes(&self) -> Result<Vec<[u8; 32]>, StorageError> {
        let cf = self.db.cf_handle(CF_UNDO).ok_or(StorageError::CfNotFound(CF_UNDO.into()))?;
        let mut out = Vec::new();
        for item in self.db.iterator_cf(&cf, IteratorMode::Start) {
            let (k, _) = item.map_err(|e| StorageError::ReadFailed(e.to_string()))?;
            if k.len() == 32 {
                let mut h = [0u8; 32];
                h.copy_from_slice(&k);
                out.push(h);
            }
        }
        Ok(out)
    }

    /// Remove an undo record (rollback). Never call it on a block that stays
    /// connected: with no reorg-depth limit (audit DAG-6) every connected
    /// block must remain disconnectable.
    pub fn delete_undo_data(&self, block_hash: &[u8; 32]) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_UNDO).ok_or(StorageError::CfNotFound(CF_UNDO.into()))?;
        self.db.delete_cf(&cf, block_hash).map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    /// Sprint U.2 — Reverse every mutation recorded in the block's UndoData.
    ///
    /// This is the storage-level primitive the reorg logic (U.3) will call for
    /// each block of the losing chain, in tip-toward-LCA order. It is purely
    /// about rolling back **state** (UTXO set, tx index, coinbase index,
    /// address indices, undo record itself) — it deliberately does NOT touch:
    ///
    ///   - CF_BLOCKS, CF_HEIGHT, CF_TIMESTAMPS: the block still exists as a
    ///     known DAG node; U.3 repoints selected-chain membership, not block
    ///     knowledge.
    ///   - CF_DAG: GhostDAG metadata for the block stays valid.
    ///   - Mempool: caller's job to re-inject invalidated txs if desired.
    ///
    /// # Order of operations (reversed from accept_block, with rationale)
    ///
    ///   1. Un-index addr_tx_history — needs the block body + spent lookup
    ///      from UndoData, both still intact at this point.
    ///   2. Restore spent UTXOs via put_utxo — also repopulates CF_ADDR_UTXO.
    ///   3. Delete created UTXOs via delete_utxo — also cleans CF_ADDR_UTXO.
    ///   4. Delete coinbase_info entries.
    ///   5. Delete tx_index entries.
    ///   6. Delete the UndoData record itself — final step, marks rollback
    ///      as complete and prevents accidental re-rollback.
    ///
    /// # Errors
    ///
    /// Returns Err if the undo record is missing or if the block body is
    /// missing. These are abnormal conditions: an accepted-post-U.1 block
    /// always has an undo record. (The batched reorg path,
    /// `reorg::connect_plan`, also handles a pruned body.)
    ///
    /// Individual inner ops use `let _ =` for idempotent sub-operations: if
    /// a delete target was never present (e.g. intra-block chains that
    /// weren't indexed) the rollback still makes progress rather than
    /// aborting halfway through.
    ///
    /// # Returns
    ///
    /// The `UndoData` that was applied, so callers can, e.g., re-inject
    /// invalidated transactions into the mempool or emit reorg events.
    pub fn rollback_block(&self, block_hash: &[u8; 32])
        -> Result<crate::core::UndoData, StorageError>
    {
        // 1. Load the undo record. Missing record = nothing to roll back;
        //    treat as error so caller can distinguish "already rolled back"
        //    (or "pre-U.1 block we can't roll back") from success.
        let hash_prefix = format!(
            "{:02x}{:02x}{:02x}{:02x}..",
            block_hash[0], block_hash[1], block_hash[2], block_hash[3]
        );
        let undo = self.get_undo_data(block_hash)?
            .ok_or_else(|| StorageError::ReadFailed(format!(
                "rollback_block: no undo data for block {}",
                hash_prefix
            )))?;

        // 2. Load the block body — needed for addr_tx_history unindex, which
        //    walks every transaction. Also serves as a sanity check that the
        //    block we're rolling back actually exists in storage.
        let block = self.get_block(block_hash)?
            .ok_or_else(|| StorageError::ReadFailed(format!(
                "rollback_block: block body missing for {}",
                hash_prefix
            )))?;

        // 3. Build a lookup from (prev_txid, prev_index) → spent TxOutput so
        //    unindex_tx_addresses can resolve input addresses without going
        //    through get_utxo_including_spent (which becomes stale as we
        //    mutate the UTXO set below).
        let mut spent_lookup: std::collections::HashMap<([u8; 32], u32), TxOutput> =
            std::collections::HashMap::with_capacity(undo.spent_utxos.len());
        for entry in &undo.spent_utxos {
            spent_lookup.insert((entry.prev_txid, entry.prev_index), entry.output.clone());
        }

        // 4. Un-index addr_tx_history (must run BEFORE UTXO mutations —
        //    see doc comment on ordering above).
        for (tx_idx, tx) in block.transactions.iter().enumerate() {
            // Best-effort: log on failure but keep going. A partial unindex
            // is still better than aborting mid-rollback.
            if let Err(e) = self.unindex_tx_addresses(
                tx, block.height, tx_idx as u32, &spent_lookup
            ) {
                log::warn!(
                    "rollback_block h={}: addr_tx_history unindex failed for tx {}: {}",
                    block.height, tx_idx, e
                );
            }
        }

        // 5. Restore spent UTXOs. put_utxo also rewrites the CF_ADDR_UTXO
        //    entry, so we don't have to handle that column family manually.
        for entry in &undo.spent_utxos {
            let _ = self.put_utxo(&entry.prev_txid, entry.prev_index, &entry.output);
        }

        // 6. Delete created UTXOs. delete_utxo also removes the CF_ADDR_UTXO
        //    entry if present.
        for (txid, idx) in &undo.created_utxo_keys {
            let _ = self.delete_utxo(txid, *idx);
        }
        //    VAL-2: restore the coins those outputs overwrote (same outpoint),
        //    so the UTXO set equals that of a node that never applied the block.
        for entry in &undo.overwritten.utxos {
            let _ = self.put_utxo(&entry.prev_txid, entry.prev_index, &entry.output);
        }

        // 7. Delete coinbase-info entries for any coinbase txs this block
        //    introduced. A reverted coinbase must not be treated as mature
        //    by downstream validation.
        for txid in &undo.coinbase_txids {
            let _ = self.delete_coinbase_info(txid);
        }
        for (txid, height) in &undo.overwritten.coinbase_heights {
            let _ = self.put_coinbase_info(txid, *height);
        }

        // 8. Delete tx_index entries. After rollback the txid is no longer
        //    locatable at this block — either the tx will land in a replacement
        //    block (and get re-indexed there by accept_block) or it reverts
        //    to the mempool.
        for txid in &undo.tx_index_keys {
            let _ = self.delete_tx_index(txid);
        }
        for (txid, block, height) in &undo.overwritten.tx_index {
            let _ = self.put_tx_index(txid, block, *height);
        }

        // 9. Finally, delete the undo record itself. Must be last: if any
        //    earlier step erred after we deleted this first, the caller
        //    would have no way to retry or to introspect the record.
        self.delete_undo_data(block_hash)?;

        // NET-12: the block left the connected chain (holder aggregates
        // already followed the put/delete calls above).
        self.note_block_disconnected(block_hash, undo.tx_index_keys.len() as u64)?;

        Ok(undo)
    }

    // ── Pruning ─────────────────────────────────────────────────────────

    /// Prune block bodies below `below_height`.
    /// Keeps: height→hash mapping, DAG data, TX index, UTXO set, undo records.
    /// Removes: full block data from CF_BLOCKS (saves ~90% of storage).
    /// Returns number of blocks pruned.
    ///
    /// Audit DAG-6: a reorg of ANY depth must be able to disconnect a pruned
    /// block (there is no reorg-depth limit). The UTXO effects come back from
    /// the undo record, which is never pruned; what the rollback still needed
    /// from the body — the address-history keys to un-index and whether the
    /// block carried shielded transactions — is recorded here, in the same
    /// batch as the body deletion, as a [`PrunedBodyRecord`].
    pub fn prune_blocks_below(&self, below_height: u64) -> Result<usize, StorageError> {
        let cf_blocks = self.db.cf_handle(CF_BLOCKS).ok_or(StorageError::CfNotFound(CF_BLOCKS.into()))?;
        let cf_height = self.db.cf_handle(CF_HEIGHT).ok_or(StorageError::CfNotFound(CF_HEIGHT.into()))?;
        let cf_undo = self.db.cf_handle(CF_UNDO).ok_or(StorageError::CfNotFound(CF_UNDO.into()))?;
        let cf_meta = self.db.cf_handle(CF_META).ok_or(StorageError::CfNotFound(CF_META.into()))?;
        let mut pruned = 0usize;

        for h in 0..below_height {
            let key = h.to_be_bytes();
            let Some(hash_bytes) = self.db.get_cf(&cf_height, key)
                .map_err(|e| StorageError::ReadFailed(e.to_string()))?
            else { continue };
            let Ok(hash) = <BlockHash>::try_from(hash_bytes.as_slice()) else { continue };
            // Only prune if block data exists
            let raw = match self.db.get_cf(&cf_blocks, hash)
                .map_err(|e| StorageError::ReadFailed(e.to_string()))?
            {
                Some(raw) => raw,
                None => continue,
            };
            let mut batch = rocksdb::WriteBatch::default();
            batch.delete_cf(&cf_blocks, hash);
            match Block::from_wire_bytes(&raw) {
                Ok(body) => {
                    let spent: std::collections::HashMap<([u8; 32], u32), TxOutput> = self
                        .get_undo_data(&hash)?
                        .map(|u| u.spent_utxos.into_iter()
                            .map(|e| ((e.prev_txid, e.prev_index), e.output))
                            .collect())
                        .unwrap_or_default();
                    let rec = PrunedBodyRecord {
                        height: body.height,
                        had_shielded: !body.shielded_transactions.is_empty(),
                        addr_history_keys: indexer::addr_history_keys(&body, &spent),
                    };
                    batch.put_cf(&cf_undo, pruned_body_key(&hash), encode(&rec)?);
                    // Re-audit B2-T1 follow-up: remember that this body passed
                    // the hardening block rules before it goes (see
                    // [`HARDENED_BODY_PREFIX`]).
                    if matches!(crate::accept::classify_stored_block(&body, 0),
                                crate::accept::StoredBlockCheck::Valid) {
                        batch.put_cf(&cf_meta, hardened_body_key(&hash), [0u8; 0]);
                    }
                }
                Err(e) => log::warn!(
                    "prune: body of {} does not decode ({}); pruned without a rollback record",
                    hex::encode(&hash[..8]), e
                ),
            }
            self.db.write(batch).map_err(|e| StorageError::WriteFailed(e.to_string()))?;
            self.forget_body_verdict(&hash);
            pruned += 1;
        }

        if pruned > 0 {
            self.put_meta("pruned_height", &below_height.to_le_bytes())?;
        }
        Ok(pruned)
    }

    /// True iff `hash`'s body was pruned after passing every context-free
    /// hardening block rule (see [`HARDENED_BODY_PREFIX`]).
    pub fn has_hardened_body_marker(&self, hash: &BlockHash) -> Result<bool, StorageError> {
        self.note_reads(1);
        let cf = self.db.cf_handle(CF_META).ok_or(StorageError::CfNotFound(CF_META.into()))?;
        self.db.get_cf(&cf, hardened_body_key(hash))
            .map(|v| v.is_some())
            .map_err(|e| StorageError::ReadFailed(e.to_string()))
    }

    /// The rollback record written when `hash`'s body was pruned, if any.
    pub fn get_pruned_body_record(&self, hash: &BlockHash) -> Result<Option<PrunedBodyRecord>, StorageError> {
        let cf = self.db.cf_handle(CF_UNDO).ok_or(StorageError::CfNotFound(CF_UNDO.into()))?;
        match self.db.get_cf(&cf, pruned_body_key(hash)).map_err(|e| StorageError::ReadFailed(e.to_string()))? {
            Some(d) => Ok(Some(decode(&d)?)),
            None => Ok(None),
        }
    }

    /// Stage removal of `hash`'s pruned-body record (the block is being
    /// disconnected; a later re-connect needs the body again anyway).
    pub fn stage_delete_pruned_body_record(&self, batch: &mut rocksdb::WriteBatch, hash: &BlockHash)
        -> Result<(), StorageError>
    {
        let cf = self.db.cf_handle(CF_UNDO).ok_or(StorageError::CfNotFound(CF_UNDO.into()))?;
        batch.delete_cf(&cf, pruned_body_key(hash));
        Ok(())
    }

    // ── Chain-state integrity (audit DAG-6 / DAG-11) ───────────────────

    /// SHA3-256 commitment to the whole UTXO set: every CF_UTXO row in key
    /// order, each fed as `len(key) ‖ key ‖ len(value) ‖ value` (u32 LE
    /// lengths). A pure function of the set's contents, so two nodes (or one
    /// node before and after a rebuild) hold the same UTXO set iff the
    /// digests are equal. O(UTXO set).
    pub fn utxo_set_digest(&self) -> Result<[u8; 32], StorageError> {
        use sha3::{Digest, Sha3_256};
        let cf = self.db.cf_handle(CF_UTXO).ok_or(StorageError::CfNotFound(CF_UTXO.into()))?;
        let mut h = Sha3_256::new();
        h.update(b"gnb/utxo-set/v1");
        for item in self.db.iterator_cf(&cf, IteratorMode::Start) {
            let (k, v) = item.map_err(|e| StorageError::ReadFailed(e.to_string()))?;
            h.update((k.len() as u32).to_le_bytes());
            h.update(&k);
            h.update((v.len() as u32).to_le_bytes());
            h.update(&v);
        }
        Ok(h.finalize().into())
    }

    /// Every `(txid, block_hash)` pair of CF_TX_INDEX (start-up chain-state
    /// check, DAG-11). O(indexed transactions).
    pub fn tx_index_entries(&self) -> Result<Vec<TxIndexEntry>, StorageError> {
        let cf = self.db.cf_handle(CF_TX_INDEX).ok_or(StorageError::CfNotFound(CF_TX_INDEX.into()))?;
        let mut out = Vec::new();
        for item in self.db.iterator_cf(&cf, IteratorMode::Start) {
            let (k, v) = item.map_err(|e| StorageError::ReadFailed(e.to_string()))?;
            if k.len() == 32 && v.len() >= 32 {
                let mut t = [0u8; 32];
                t.copy_from_slice(&k);
                let mut b = [0u8; 32];
                b.copy_from_slice(&v[..32]);
                out.push((t, b));
            }
        }
        Ok(out)
    }

    /// Stage the deletion of every row of the chain-state column families —
    /// UTXO set and its address index, coinbase heights, transaction index,
    /// undo and pruned-body records, the selected-chain height / timestamp
    /// indexes, the address history and the shielded-pool state with its
    /// per-block undo records (audit COH-2) — for a rebuild from blocks
    /// (DAG-11). Block bodies, GhostDAG data and CF_META are untouched (the
    /// NET-12 aggregates in CF_META are marked incomplete and recomputed by
    /// the rebuild itself). Returns the number of rows staged for deletion.
    pub fn stage_clear_chain_state(&self, batch: &mut rocksdb::WriteBatch) -> Result<usize, StorageError> {
        let mut n = 0usize;
        for name in [CF_UTXO, CF_ADDR_UTXO, CF_COINBASE, CF_TX_INDEX, CF_UNDO, CF_HEIGHT,
                     CF_TIMESTAMPS, CF_ADDR_TX_HISTORY, CF_SHIELDED] {
            let cf = self.db.cf_handle(name).ok_or(StorageError::CfNotFound(name.into()))?;
            for item in self.db.iterator_cf(&cf, IteratorMode::Start) {
                let (k, _) = item.map_err(|e| StorageError::ReadFailed(e.to_string()))?;
                batch.delete_cf(&cf, &k);
                n += 1;
            }
        }
        Ok(n)
    }

    /// Get the height below which blocks have been pruned
    pub fn pruned_height(&self) -> u64 {
        self.get_meta("pruned_height").ok().flatten()
            .and_then(|b| b.as_slice().try_into().ok().map(u64::from_le_bytes))
            .unwrap_or(0)
    }

    /// Sprint F: get block timestamp by height (used by listtransactions RPC).
    pub fn get_block_timestamp_at_height(&self, height: u64) -> Result<Option<u64>, StorageError> {
        let cf = self.db.cf_handle(CF_TIMESTAMPS).ok_or(StorageError::CfNotFound(CF_TIMESTAMPS.into()))?;
        match self.db.get_cf(&cf, &height.to_be_bytes()).map_err(|e| StorageError::ReadFailed(e.to_string()))? {
            Some(d) if d.len() == 8 => Ok(Some(u64::from_le_bytes(d.try_into().unwrap()))),
            _ => Ok(None),
        }
    }

    /// Sprint F: get tip height (highest block number).
    pub fn get_tip_height(&self) -> Result<u64, StorageError> {
        let cf = self.db.cf_handle(CF_HEIGHT).ok_or(StorageError::CfNotFound(CF_HEIGHT.into()))?;
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::End);
        for item in iter {
            let (k, _) = item.map_err(|e| StorageError::ReadFailed(e.to_string()))?;
            if k.len() == 8 {
                return Ok(u64::from_be_bytes(k.as_ref().try_into().unwrap()));
            }
        }
        Ok(0)
    }

}

/// `txid ‖ vout`, vout encoded LITTLE-endian. Every consensus read/write of a
/// UTXO goes through this SAME function on both sides (`get_utxo`,
/// `put_utxo`, `delete_utxo`), so the encoding round-trips correctly for
/// consensus purposes. Code that instead parses the RAW key bytes back into
/// a vout number for display/export (`iter_utxos_sorted`,
/// `bloch-snapshot-utxo`) has historically decoded that suffix BIG-endian —
/// a doc-drift bug documented at `iter_utxos_sorted` (Legacy M-3) — do not
/// "fix" this function's endianness without reading that comment first: the
/// published carry-over snapshot's SHAKE-256 root depends on the mismatch
/// staying exactly as it is today.
fn utxo_key(txid: &[u8], index: u32) -> Vec<u8> {
    let mut k = txid.to_vec(); k.extend_from_slice(&index.to_le_bytes()); k
}

/// Address index key: [20B address][32B txid][4B index] = 56 bytes
fn addr_utxo_key(address: &[u8], txid: &[u8], index: u32) -> Vec<u8> {
    let mut k = Vec::with_capacity(56);
    k.extend_from_slice(address);
    k.extend_from_slice(txid);
    k.extend_from_slice(&index.to_le_bytes());
    k
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("open: {0}")]        OpenFailed(String),
    #[error("cf: {0}")]          CfNotFound(String),
    #[error("serialize: {0}")]   SerializeFailed(String),
    #[error("deserialize: {0}")] DeserializeFailed(String),
    #[error("write: {0}")]       WriteFailed(String),
    #[error("read: {0}")]        ReadFailed(String),
}

impl From<rocksdb::Error> for StorageError {
    fn from(e: rocksdb::Error) -> Self { StorageError::ReadFailed(e.to_string()) }
}

// Sprint F — tests for address history indexer and related RPCs.
// (appended from scaffold; // instead of //! because this is not a module root)

#[cfg(test)]
mod sprint_f_tests {
    use super::*;
    use crate::core::{Block, BlockHeader, Transaction, TxInput, TxOutput};
    use crate::storage::indexer::{make_key, make_value, parse_key, parse_value, DIR_IN, DIR_OUT, ENTRY_SIZE};
    use tempfile::TempDir;

    fn mk_storage() -> (TempDir, Storage) {
        let tmp = TempDir::new().unwrap();
        let s = Storage::open(tmp.path()).unwrap();
        (tmp, s)
    }

    fn dummy_addr(byte: u8) -> [u8; 20] {
        [byte; 20]
    }

    fn mk_output(addr_byte: u8, value: u64) -> TxOutput {
        TxOutput {
            value,
            script_pubkey: vec![addr_byte; 20],
        }
    }

    fn mk_tx_coinbase(addr_byte: u8, value: u64) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: [0u8; 32],
                prev_index: 0xffffffff,
                script_sig: b"height:1".to_vec(),
                sequence: 0xffffffff,
            }],
            outputs: vec![mk_output(addr_byte, value)],
            locktime: 0,
        }
    }

    /// Policy outputs (33-byte scripts) are found by their full script, and
    /// a key-hash script that shares their first 20 bytes never mixes in.
    #[test]
    fn utxos_for_address_finds_policy_scripts() {
        let (_tmp, s) = mk_storage();
        let mut policy = vec![0x02u8];
        policy.extend_from_slice(&[0x55u8; 32]);
        let key_hash = policy[..20].to_vec();
        s.put_utxo(&[1u8; 32], 0, &TxOutput { value: 7, script_pubkey: policy.clone() }).unwrap();
        s.put_utxo(&[2u8; 32], 1, &TxOutput { value: 9, script_pubkey: key_hash.clone() }).unwrap();
        let p = s.get_utxos_for_address(&policy).unwrap();
        assert_eq!(p.len(), 1);
        assert_eq!((p[0].1, p[0].2.value), (0, 7));
        let k = s.get_utxos_for_address(&key_hash).unwrap();
        assert_eq!(k.len(), 1);
        assert_eq!((k[0].1, k[0].2.value), (1, 9));
    }

    #[test]
    fn key_value_encoding_roundtrip() {
        let addr = dummy_addr(0x42);
        let txid = [0x99u8; 32];

        let k = make_key(&addr, 100, 5, 2);
        let v = make_value(&txid, DIR_OUT, 1_000_000_000);

        assert_eq!(k.len(), 36);
        assert_eq!(v.len(), ENTRY_SIZE);

        let (pa, ph, pti, pii) = parse_key(&k).unwrap();
        assert_eq!(pa, addr);
        assert_eq!(ph, 100);
        assert_eq!(pti, 5);
        assert_eq!(pii, 2);

        let (ptxid, pdir, pamt) = parse_value(&v).unwrap();
        assert_eq!(ptxid, txid);
        assert_eq!(pdir, DIR_OUT);
        assert_eq!(pamt, 1_000_000_000);
    }

    #[test]
    fn key_ordering_is_chronological() {
        let addr = dummy_addr(0x11);
        let k1 = make_key(&addr, 10, 0, 0);
        let k2 = make_key(&addr, 100, 0, 0);
        let k3 = make_key(&addr, 1000, 0, 0);
        assert!(k1 < k2);
        assert!(k2 < k3);
    }

    #[test]
    fn parse_invalid_sizes_returns_none() {
        assert!(parse_key(&[0u8; 10]).is_none());
        assert!(parse_key(&[0u8; 50]).is_none());
        assert!(parse_value(&[0u8; 20]).is_none());
    }

    #[test]
    fn index_coinbase_adds_out_entry() {
        let (_tmp, store) = mk_storage();
        let tx = mk_tx_coinbase(0x42, 33 * 100_000_000);
        store.index_tx_addresses(&tx, 1, 0).unwrap();
        let entries = store.query_address_history(&dummy_addr(0x42), 0, 100, 10, 0).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].is_incoming());
        assert_eq!(entries[0].amount, 33 * 100_000_000);
        assert_eq!(entries[0].height, 1);
    }

    #[test]
    fn query_respects_height_range() {
        let (_tmp, store) = mk_storage();
        for h in 1..=10 {
            let tx = mk_tx_coinbase(0x55, 100);
            store.index_tx_addresses(&tx, h, 0).unwrap();
        }
        let mid = store.query_address_history(&dummy_addr(0x55), 3, 7, 100, 0).unwrap();
        assert_eq!(mid.len(), 5);
        assert_eq!(mid[0].height, 3);
        assert_eq!(mid[4].height, 7);
    }

    #[test]
    fn query_respects_limit_and_offset() {
        let (_tmp, store) = mk_storage();
        for h in 1..=20 {
            let tx = mk_tx_coinbase(0x77, 100);
            store.index_tx_addresses(&tx, h, 0).unwrap();
        }
        let page1 = store.query_address_history(&dummy_addr(0x77), 0, 1000, 5, 0).unwrap();
        let page2 = store.query_address_history(&dummy_addr(0x77), 0, 1000, 5, 5).unwrap();
        let page3 = store.query_address_history(&dummy_addr(0x77), 0, 1000, 5, 10).unwrap();

        assert_eq!(page1.len(), 5);
        assert_eq!(page2.len(), 5);
        assert_eq!(page3.len(), 5);

        // Pages should not overlap
        assert_eq!(page1[0].height, 1);
        assert_eq!(page2[0].height, 6);
        assert_eq!(page3[0].height, 11);
    }

    #[test]
    fn count_is_consistent_with_query() {
        let (_tmp, store) = mk_storage();
        for h in 1..=15 {
            let tx = mk_tx_coinbase(0xAA, 100);
            store.index_tx_addresses(&tx, h, 0).unwrap();
        }
        let count = store.count_address_history(&dummy_addr(0xAA), 0, 15).unwrap();
        assert_eq!(count, 15);
        let count_range = store.count_address_history(&dummy_addr(0xAA), 5, 10).unwrap();
        assert_eq!(count_range, 6);
    }

    #[test]
    fn balance_at_height_sums_incoming() {
        let (_tmp, store) = mk_storage();
        for h in 1..=5 {
            let tx = mk_tx_coinbase(0xBB, 100);
            store.index_tx_addresses(&tx, h, 0).unwrap();
        }
        // All incoming, balance at tip = 500
        let bal_tip = store.balance_at_height(&dummy_addr(0xBB), 5).unwrap();
        assert_eq!(bal_tip, 500);
        // At height 3, only 3 entries counted = 300
        let bal_3 = store.balance_at_height(&dummy_addr(0xBB), 3).unwrap();
        assert_eq!(bal_3, 300);
    }

    #[test]
    fn different_addresses_isolated() {
        let (_tmp, store) = mk_storage();
        let tx_a = mk_tx_coinbase(0xAA, 100);
        let tx_b = mk_tx_coinbase(0xBB, 200);
        store.index_tx_addresses(&tx_a, 1, 0).unwrap();
        store.index_tx_addresses(&tx_b, 1, 1).unwrap();

        let a = store.query_address_history(&dummy_addr(0xAA), 0, 100, 10, 0).unwrap();
        let b = store.query_address_history(&dummy_addr(0xBB), 0, 100, 10, 0).unwrap();

        assert_eq!(a.len(), 1);
        assert_eq!(a[0].amount, 100);
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].amount, 200);
    }

    #[test]
    fn empty_address_returns_empty() {
        let (_tmp, store) = mk_storage();
        let e = store.query_address_history(&dummy_addr(0x00), 0, 1000, 100, 0).unwrap();
        assert!(e.is_empty());
        let c = store.count_address_history(&dummy_addr(0x00), 0, 1000).unwrap();
        assert_eq!(c, 0);
        let b = store.balance_at_height(&dummy_addr(0x00), 1000).unwrap();
        assert_eq!(b, 0);
    }
}


#[cfg(test)]
mod snapshot_row_tests {
    use super::*;
    #[test]
    fn corrupted_rows_refuse_export_and_valid_rows_preserve_both_vout_modes() {
        let mut key = vec![7; 32];
        key.extend_from_slice(&1u32.to_le_bytes());
        let output = TxOutput { value: 42, script_pubkey: vec![3; 20] };
        let bytes = encode(&output).unwrap();
        assert_eq!(decode_snapshot_row(&key, &bytes, false).unwrap().1, 16_777_216);
        assert_eq!(decode_snapshot_row(&key, &bytes, true).unwrap().1, 1);
        assert!(decode_snapshot_row(&key[..35], &bytes, false).is_err());
        let mut long_key = key.clone(); long_key.push(0);
        assert!(decode_snapshot_row(&long_key, &bytes, false).is_err());
        assert!(decode_snapshot_row(&key, &[], false).is_err());
        let mut trailing = bytes; trailing.push(0);
        assert!(decode_snapshot_row(&key, &trailing, false).is_err());
    }
}

#[cfg(test)]
mod shielded_cf_tests {
    use super::*;

    /// Audit COH-2 added the `shielded` column family. A data-dir written
    /// before it still opens read-only (the replay harness inspects old
    /// snapshots), and a read-write open adds the family.
    #[test]
    fn data_dir_without_the_shielded_family_opens_read_only_and_upgrades() {
        let tmp = tempfile::tempdir().unwrap();
        {
            let mut opts = Options::default();
            opts.create_if_missing(true);
            opts.create_missing_column_families(true);
            let old: Vec<ColumnFamilyDescriptor> =
                Storage::cf_descriptors().into_iter().filter(|d| d.name() != CF_SHIELDED).collect();
            let db = DB::open_cf_descriptors(&opts, tmp.path(), old).unwrap();
            db.put_cf(&db.cf_handle(CF_META).unwrap(), b"tip_hash", [7u8; 32]).unwrap();
        }
        let ro = Storage::open_read_only(tmp.path()).expect("a pre-COH-2 data-dir opens read-only");
        assert_eq!(ro.get_meta("tip_hash").unwrap(), Some(vec![7u8; 32]));
        assert!(ro.get_shielded(b"T").is_err(), "the family does not exist read-only");
        drop(ro);
        let rw = Storage::open(tmp.path()).unwrap();
        assert_eq!(rw.get_shielded(b"T").unwrap(), None);
    }

    /// The upgrade is one-way (docs/RUNNING.md, "Upgrading and
    /// downgrading"): once this release has opened a data-dir, the open an
    /// earlier release performs (read-write, a fixed descriptor list without
    /// `shielded`) is refused by RocksDB, so a downgrade needs a pre-upgrade
    /// copy of the data directory or a resync.
    #[test]
    fn upgraded_data_dir_is_refused_by_the_open_of_an_earlier_release() {
        let tmp = tempfile::tempdir().unwrap();
        drop(Storage::open(tmp.path()).unwrap());
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let old: Vec<ColumnFamilyDescriptor> =
            Storage::cf_descriptors().into_iter().filter(|d| d.name() != CF_SHIELDED).collect();
        let err = DB::open_cf_descriptors(&opts, tmp.path(), old).expect_err("an earlier release cannot open it");
        assert!(err.to_string().contains("Column families not opened: shielded"), "{err}");
        drop(Storage::open(tmp.path()).expect("this release still opens it"));
    }
}

// ── Bloch Genesis-3 carryover ingestion ─────────────────────────────────────

impl Storage {
    /// Write a verified, converted carryover into the UTXO set in one atomic
    /// batch, together with the `carryover_sha3` marker. `snap` can only come
    /// from `core::carryover::verify_and_convert`, so every consensus check
    /// has already passed.
    pub fn ingest_carryover(
        &self,
        snap: &crate::core::carryover::VerifiedCarryover,
        locked: &[crate::core::vesting::Tranche],
    ) -> Result<u64, StorageError> {
        let _agg = self.agg_lock();
        let mut deltas = aggregates::HolderDeltas::default();
        for u in &snap.utxos {
            if let Some(prev) = self.get_utxo(&u.txid, u.vout)? {
                deltas.remove(&prev);
            }
            deltas.add(&u.output);
        }
        for t in locked {
            if let Some(prev) = self.get_utxo(&t.txid, t.vout)? {
                deltas.remove(&prev);
            }
            deltas.add(&t.output);
        }
        let mut batch = rocksdb::WriteBatch::default();
        self.stage_carryover(&mut batch, snap, locked)?;
        // NET-12: holder aggregates in the same batch.
        self.stage_holder_deltas(&mut batch, &deltas)?;
        self.db.write(batch).map_err(|e| StorageError::WriteFailed(e.to_string()))?;
        Ok((snap.utxos.len() + locked.len()) as u64)
    }

    /// Stage exactly the UTXO rows [`ingest_carryover`](Self::ingest_carryover)
    /// writes (the carryover UTXOs, the locked vesting tranches, their
    /// address-index rows and the `carryover_sha3` / `vesting_sha3` markers) into a caller-owned batch, WITHOUT the NET-12
    /// holder aggregates: `ingest_carryover` stages those itself, and the
    /// chain-state rebuild (audit DAG-11), which uses this to restore the
    /// genesis state, recomputes every aggregate once it has reconnected the
    /// chain (`Storage::rebuild_aggregates`).
    pub fn stage_carryover(
        &self,
        batch: &mut rocksdb::WriteBatch,
        snap: &crate::core::carryover::VerifiedCarryover,
        locked: &[crate::core::vesting::Tranche],
    ) -> Result<(), StorageError> {
        let cf_utxo = self.db.cf_handle(CF_UTXO)
            .ok_or(StorageError::CfNotFound(CF_UTXO.into()))?;
        let cf_ai = self.db.cf_handle(CF_ADDR_UTXO)
            .ok_or(StorageError::CfNotFound(CF_ADDR_UTXO.into()))?;
        let cf_meta = self.db.cf_handle(CF_META)
            .ok_or(StorageError::CfNotFound(CF_META.into()))?;
        for u in &snap.utxos {
            batch.put_cf(&cf_utxo, utxo_key(&u.txid, u.vout), encode(&u.output)?);
            batch.put_cf(&cf_ai, addr_utxo_key(&u.output.script_pubkey, &u.txid, u.vout), [0u8; 0]);
        }
        // Locked team and founder tranches (core::vesting), same batch: the
        // genesis ledger lands complete or not at all.
        for t in locked {
            batch.put_cf(&cf_utxo, utxo_key(&t.txid, t.vout), encode(&t.output)?);
            batch.put_cf(&cf_ai, addr_utxo_key(&t.output.script_pubkey, &t.txid, t.vout), [0u8; 0]);
        }
        batch.put_cf(&cf_meta, b"carryover_sha3", snap.sha3);
        batch.put_cf(&cf_meta, b"vesting_sha3", crate::core::vesting::VESTING_SPEC_SHA3);
        Ok(())
    }
}
