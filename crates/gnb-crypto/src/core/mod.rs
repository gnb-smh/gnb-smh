//! GnB core consensus types.
//!
//! GnB-SMH proof of work (sequential memory-hard SHAKE-256) · hybrid
//! ML-DSA-65 ‖ Falcon-1024 signatures · GhostDAG BlockDAG.

use sha2::Sha256;
use sha3::{Digest, Sha3_256};
use serde::{Serialize, Deserialize};

/// Monetary policy: 10,000,000 GNB hard cap, fair launch, consensus minimum fee.
pub mod tokenomics;

/// Bloch Genesis-3 carryover: verified, converted opening ledger.
pub mod carryover;
pub mod activation;

/// Sighash v2/v3, the transaction-version activation rule and the shared
/// input-script (witness + signature) rules (audit CRY-1/2/3, MEM-5).
pub mod sighash;

/// MoneyRange and canonical-encoding size helpers (audit VAL-11 / VAL-12).
pub mod limits;

// ── Network identity ─────────────────────────────────────────────────────────

pub const MAINNET_PREFIX:        &str  = "gnb1q";
pub const TESTNET_PREFIX:        &str  = "gnb1t";
/// P2P magic: "GNB1". Distinct from every Bloch network.
pub const NETWORK_MAGIC:         u32   = 0x474E_4231;

// ── Sighash domain (replay separation) ──────────────────────────────────────
//
// Sighash v2 (transactions whose version is not 3):
//   preimage = SIGHASH_DOMAIN(16) ‖ [SIGHASH_VERSION](1) ‖ chain_id.to_le_bytes()(4)
//              ‖ bincode(stripped_tx)
//   sighash  = SHA3-256(preimage)
// Sighash v3 (version-3 transactions, the only valid version at/after the
// hardening activation): see `sighash` (module) — commits the spent amounts
// and scripts and the signature suite, linear cost.
//
// The domain and the chain ids differ from Bloch's, so no signature made for a
// Bloch chain verifies on GnB and vice versa, even over coinciding outpoints.
pub const SIGHASH_DOMAIN:  [u8; 16] = *b"GNB-SIGHASH-v1\0\0";
pub const SIGHASH_VERSION: u8       = 0x01;

/// Chain-ID registry (u32, serialized little-endian). 0x474E = "GN".
/// An explicit consensus input derived from the node's network, never from a
/// transaction and never from a compile-time flag. New networks get a new
/// discriminant; never reuse one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum ChainId {
    Mainnet = 0x474E_0001,
    Testnet = 0x474E_0002,
}

impl ChainId {
    #[inline] pub const fn to_u32(self) -> u32 { self as u32 }
    #[inline] pub fn to_le_bytes(self) -> [u8; 4] { (self as u32).to_le_bytes() }

    pub const fn for_network(net: crate::address::Network) -> ChainId {
        match net {
            crate::address::Network::Mainnet => ChainId::Mainnet,
            crate::address::Network::Testnet => ChainId::Testnet,
        }
    }
}

// Process-wide chain-id used by consensus validation. Set once at node startup
// from the network selection; defaults to Mainnet if never set.
static NODE_CHAIN_ID: std::sync::OnceLock<ChainId> = std::sync::OnceLock::new();

/// Set the process-wide node chain-id (idempotent for the same value). Returns
/// `Err(existing)` if already set to a different value.
pub fn set_node_chain_id(id: ChainId) -> Result<(), ChainId> {
    match NODE_CHAIN_ID.set(id) {
        Ok(()) => Ok(()),
        Err(_) => {
            let cur = *NODE_CHAIN_ID.get().expect("OnceLock set");
            if cur == id { Ok(()) } else { Err(cur) }
        }
    }
}

/// The node-level chain-id. Defaults to Mainnet until `set_node_chain_id`.
pub fn node_chain_id() -> ChainId {
    *NODE_CHAIN_ID.get().unwrap_or(&ChainId::Mainnet)
}

// ── Consensus constants ─────────────────────────────────────────────────────

pub const GHOSTDAG_K:            usize = 10;
pub const HALVING_INTERVAL:      u64   = tokenomics::HALVING_INTERVAL;
pub const MAX_BLOCK_SIZE:        usize = 1_000_000;
pub const TARGET_BLOCK_TIME:     u64   = tokenomics::TARGET_BLOCK_TIME_SECS;
pub const PROTOCOL_VERSION:      u32   = 1;
pub const COINBASE_MATURITY:     u64   = 100;        // blocks before coinbase is spendable

/// Verify that none of `tx.inputs` references an immature coinbase output
/// (depth < `COINBASE_MATURITY`). `lookup_coinbase_height(txid)` returns the
/// height of a coinbase txid, or `None` for non-coinbase / unknown txids.
/// Shared by block validation and mempool admission.
pub fn check_coinbase_maturity<F>(
    tx: &Transaction,
    current_height: u64,
    mut lookup_coinbase_height: F,
) -> Result<(), String>
where
    F: FnMut(&[u8; 32]) -> Option<u64>,
{
    if current_height == 0 {
        return Ok(());
    }
    for (i, inp) in tx.inputs.iter().enumerate() {
        if let Some(cb_height) = lookup_coinbase_height(&inp.prev_txid) {
            let depth = current_height.saturating_sub(cb_height);
            if depth < COINBASE_MATURITY {
                return Err(format!(
                    "coinbase maturity: input {} references coinbase at h={}, only {} confirmations (need {})",
                    i, cb_height, depth, COINBASE_MATURITY
                ));
            }
        }
    }
    Ok(())
}
pub const DUST_THRESHOLD:        u64   = 546;        // minimum output value (base units)
/// Maximum timestamp drift into the future. Kept short (20 blocks) because
/// ASERT reads parent timestamps: a block stamped `MAX_FUTURE_SECS` ahead can
/// ease the next target by at most 2^(600/7200) ≈ 6%.
pub const MAX_FUTURE_SECS:       u64   = 600;
pub const DNS_SEED_DOMAIN: &str = "";
/// No public seed infrastructure yet; peers are supplied with --peer.
pub const DEFAULT_SEEDS: &[&str] = &[];

pub const CHECKPOINT_DEPTH:      u64   = 1_000;      // finality: reorgs deeper than this rejected
pub const PRUNING_DEPTH:         u64   = 10_000;     // block bodies pruned below tip - this

// Hybrid ML-DSA-65 ‖ Falcon-1024 sizes, including the 4-byte crypto-agility
// suite header. SIG_SIZE is an upper bound (Falcon is variable length) used
// for fee sizing only.
pub const PUBKEY_SIZE:  usize = 4 + 1952 + 1793; // 3749
pub const PRIVKEY_SIZE: usize = 4 + 4032 + 2305; // 6341
pub const SIG_SIZE:     usize = 4 + 3309 + 1462; // 4775

// ── Proof of work and difficulty ────────────────────────────────────────────
//
// PoW: GnB-SMH v1 (crate `gnb-smh`) over `BlockHeader::pow_preimage()` and the
// header's 64-bit nonce. A block is valid iff GnB-SMH(preimage, nonce), read as
// a big-endian 256-bit integer, is strictly below the target encoded by `bits`.
//
// Difficulty: ASERT anchored at the genesis block. The expected `bits` of a
// block is a pure function of its parent set: the LATEST timestamp over all
// parents (`difficulty_parent_timestamp`) and the block height
// max(parent heights) + 1 -- not the GhostDAG selected parent's timestamp or
// height (docs/CONSENSUS.md, "Difficulty input"). Miner and validator agree
// regardless of arrival order or parent order.

/// True when built with the `test-pow-limit` feature, which pins every
/// expected target to the pow limit so tests do not depend on the wall clock.
/// Consensus-breaking; the node refuses to start when this is set.
pub const TEST_POW_LIMIT: bool = cfg!(feature = "test-pow-limit");

/// Easiest target the chain accepts (≈ one evaluation per block).
pub const POW_LIMIT_BITS: u32 = 0x2100_FFFF;
/// ASERT half-life: two hours (240 blocks at 30 s).
pub const ASERT_HALFLIFE_SECS: i64 = 2 * 60 * 60;

/// The chain's ASERT parameters.
pub fn asert_params() -> gnb_smh::difficulty::AsertParams {
    gnb_smh::difficulty::AsertParams {
        target_spacing: TARGET_BLOCK_TIME as i64,
        halflife: ASERT_HALFLIFE_SECS,
        pow_limit: gnb_smh::difficulty::bits_to_target(POW_LIMIT_BITS),
    }
}

/// The chain's ASERT anchor: the genesis block.
pub fn asert_anchor() -> gnb_smh::difficulty::AsertAnchor {
    gnb_smh::difficulty::AsertAnchor {
        height: 0,
        bits: GENESIS_BITS,
        timestamp: GENESIS_TIMESTAMP as i64,
    }
}

/// Consensus minimum fee check for a non-coinbase transaction paying `fee`.
pub fn check_min_fee(tx: &Transaction, fee: u64) -> Result<(), String> {
    let size = tx.to_wire_bytes(true).len();
    let min = tokenomics::min_tx_fee_sat(size);
    if fee < min {
        return Err(format!("fee {fee} below consensus minimum {min} for a {size}-byte transaction"));
    }
    Ok(())
}

/// Timestamp the difficulty of a child block is computed from: the latest
/// timestamp among its parents. Pure function of the parent set, so every
/// node derives the same value regardless of arrival order.
pub fn difficulty_parent_timestamp<I: IntoIterator<Item = u64>>(parent_timestamps: I) -> u64 {
    parent_timestamps.into_iter().max().unwrap_or(GENESIS_TIMESTAMP)
}

/// Expected compact `bits` for a block at `height` (>= 1) whose parents'
/// latest timestamp is `parent_timestamp` (see `difficulty_parent_timestamp`). Single source of truth for the
/// validator, the internal miner and every block-template producer.
pub fn expected_bits(parent_timestamp: u64, height: u64) -> Result<u32, String> {
    #[cfg(feature = "test-pow-limit")]
    {
        let _ = (parent_timestamp, height);
        return Ok(target_to_bits(&bits_to_target(POW_LIMIT_BITS)));
    }
    #[allow(unreachable_code)]
    let parent_time = i64::try_from(parent_timestamp)
        .map_err(|_| format!("parent timestamp {parent_timestamp} out of range"))?;
    gnb_smh::difficulty::asert_next_bits(&asert_params(), &asert_anchor(), parent_time, height)
        .map_err(|e| e.to_string())
}

// ── BlockHeader ───────────────────────────────────────────────────────────────

/// Strongly-typed wrapper around a 32-byte merkle root.
///
/// Audit L-2 fix: previously `BlockHeader::merkle_root` was a bare
/// `[u8; 32]`, indistinguishable at the type level from block hashes,
/// txids, address hashes, and every other 32-byte identifier in the
/// system. The compiler could not catch a mix-up like
///
/// ```ignore
/// let b = lookup_block(&store, header.merkle_root); // wanted block_hash
/// ```
///
/// With `MerkleRoot`, that call is now a compile error.
///
/// ## Serialization invariant
///
/// `#[serde(transparent)]` guarantees that a `MerkleRoot(x)` serializes
/// as byte-identical output to the bare `[u8; 32]` `x`. This is
/// **critical for consensus** — the change must be invisible on the
/// wire, in RocksDB, and inside `BlockHeader::pow_bytes`. Any existing
/// block encoded with the pre-L-2 type decodes correctly with the
/// post-L-2 type, and vice versa. A dedicated round-trip test pins
/// this invariant (`merkle_root_serde_is_byte_identical_to_array`).
///
/// ## Usage
///
/// - `MerkleRoot::ZERO` — conventional all-zero root, used for empty
///   or placeholder blocks in tests.
/// - `MerkleRoot::from([u8; 32])` — convert a computed digest.
/// - `root.as_ref()` / `&root[..]` — obtain a byte slice for hashing,
///   serialization, or hex encoding without unwrapping the newtype.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MerkleRoot(pub [u8; 32]);

impl MerkleRoot {
    /// The all-zero root, used as a sentinel for empty tx lists.
    pub const ZERO: MerkleRoot = MerkleRoot([0u8; 32]);

    /// Expose the inner array. Prefer `as_ref()` for byte-slice
    /// operations — this accessor exists mainly for interop with
    /// storage code that stores/reads `[u8; 32]` keys.
    pub fn into_inner(self) -> [u8; 32] { self.0 }
}

impl Default for MerkleRoot {
    fn default() -> Self { Self::ZERO }
}

impl From<[u8; 32]> for MerkleRoot {
    fn from(bytes: [u8; 32]) -> Self { MerkleRoot(bytes) }
}

impl From<MerkleRoot> for [u8; 32] {
    fn from(m: MerkleRoot) -> Self { m.0 }
}

impl AsRef<[u8]> for MerkleRoot {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

impl std::ops::Deref for MerkleRoot {
    type Target = [u8; 32];
    fn deref(&self) -> &[u8; 32] { &self.0 }
}

// Show as hex in debug/display so log lines stay readable. Otherwise
// MerkleRoot([0xab, 0xcd, …]) dumps 32 decimal integers per line.
impl std::fmt::Debug for MerkleRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MerkleRoot({})", hex::encode(self.0))
    }
}

impl std::fmt::Display for MerkleRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    pub version:     u32,
    pub parents:     Vec<[u8; 32]>,
    pub merkle_root: MerkleRoot,
    pub timestamp:   u64,
    pub bits:        u32,
    pub nonce:       u64,
}

/// Maximum number of parents a header may reference.
pub const MAX_PARENTS: usize = 256;

impl BlockHeader {
    /// Canonical header serialization without the nonce — the `header` input
    /// of GnB-SMH. Every consensus field of the header is committed here.
    ///
    /// ```text
    ///   version      u32 LE
    ///   n_parents    u32 LE
    ///   parents      n × 32 bytes, in header order
    ///   merkle_root  32 bytes
    ///   timestamp    u64 LE
    ///   bits         u32 LE
    /// ```
    pub fn pow_preimage(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(4 + 4 + self.parents.len() * 32 + 32 + 8 + 4);
        b.extend_from_slice(&self.version.to_le_bytes());
        b.extend_from_slice(&(self.parents.len() as u32).to_le_bytes());
        for p in &self.parents { b.extend_from_slice(p); }
        b.extend_from_slice(self.merkle_root.as_ref());
        b.extend_from_slice(&self.timestamp.to_le_bytes());
        b.extend_from_slice(&self.bits.to_le_bytes());
        b
    }

    /// GnB-SMH output for this header (64 MiB, ~1M Keccak permutations).
    /// Expensive: use `Block::validate_pow`, which caches verified blocks.
    pub fn pow_hash(&self) -> [u8; 32] {
        gnb_smh::hash_thread_local(&self.pow_preimage(), self.nonce)
    }

    /// Cheap header digest used for DAG indexing: SHA3-256 over every header
    /// field including the nonce.
    pub fn dag_hash(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(self.pow_preimage());
        h.update(self.nonce.to_le_bytes());
        h.finalize().into()
    }

    /// Wire serialization: `pow_preimage` fields, then the nonce, then the
    /// DAG metadata carried with the block (blue_score, height).
    ///
    /// ```text
    ///   version u32 | varint n_parents | parents | merkle_root | timestamp u64
    ///   | bits u32 | nonce u64 | blue_score u64 | height u64
    /// ```
    pub fn to_wire_bytes(&self, blue_score: u64, height: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 9 + self.parents.len() * 32 + 32 + 8 + 4 + 8 + 8 + 8);
        out.extend_from_slice(&self.version.to_le_bytes());
        write_varint(&mut out, self.parents.len() as u64);
        for p in &self.parents {
            out.extend_from_slice(p);
        }
        out.extend_from_slice(self.merkle_root.as_ref());
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out.extend_from_slice(&self.bits.to_le_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out.extend_from_slice(&blue_score.to_le_bytes());
        out.extend_from_slice(&height.to_le_bytes());
        out
    }

    /// Parse a header from the front of `bytes`. Returns
    /// (header, blue_score, height, bytes consumed).
    pub fn read_wire_bytes(bytes: &[u8]) -> Result<(Self, u64, u64, usize), String> {
        let mut cur = Cursor::new(bytes);
        let version = read_u32_le(&mut cur).map_err(|e| format!("version: {e}"))?;
        let n = read_varint(&mut cur)?;
        if n > MAX_PARENTS as u64 {
            return Err(format!("implausible parent count {n}"));
        }
        let mut parents = Vec::with_capacity(n as usize);
        for _ in 0..n {
            parents.push(read_32(&mut cur).map_err(|e| format!("parents: {e}"))?);
        }
        let merkle_root = MerkleRoot(read_32(&mut cur).map_err(|e| format!("merkle_root: {e}"))?);
        let timestamp = read_u64_le(&mut cur).map_err(|e| format!("timestamp: {e}"))?;
        let bits = read_u32_le(&mut cur).map_err(|e| format!("bits: {e}"))?;
        let nonce = read_u64_le(&mut cur).map_err(|e| format!("nonce: {e}"))?;
        let blue_score = read_u64_le(&mut cur).map_err(|e| format!("blue_score: {e}"))?;
        let height = read_u64_le(&mut cur).map_err(|e| format!("height: {e}"))?;
        let header = BlockHeader { version, parents, merkle_root, timestamp, bits, nonce };
        Ok((header, blue_score, height, cur.position() as usize))
    }

    /// Parse exactly one header; trailing bytes are an error.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<(Self, u64, u64), String> {
        let (h, blue, height, used) = Self::read_wire_bytes(bytes)?;
        if used != bytes.len() {
            return Err(format!("trailing bytes after header: parsed {used} of {}", bytes.len()));
        }
        Ok((h, blue, height))
    }
}

// ── Transaction ───────────────────────────────────────────────────────────────

/// script_sig encoding: [4B sig_len][sig][4B pubkey_len][pubkey]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxInput {
    pub prev_txid:  [u8; 32],
    pub prev_index: u32,
    pub script_sig: Vec<u8>,
    pub sequence:   u32,
}

/// script_pubkey: 20-byte SHA3-256(pubkey)[0..20]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxOutput {
    pub value:         u64,
    pub script_pubkey: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub version:  u32,
    pub inputs:   Vec<TxInput>,
    pub outputs:  Vec<TxOutput>,
    pub locktime: u32,
}

use std::io::{Cursor, Read};

// ── Bitcoin-format varint + cursor helpers ─────────────────────────────────
// Used by Transaction::to_wire_bytes / from_wire_bytes so that external
// miners and the node agree on txid wire format.

fn write_varint(out: &mut Vec<u8>, n: u64) {
    if n < 0xFD {
        out.push(n as u8);
    } else if n <= 0xFFFF {
        out.push(0xFD);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xFFFF_FFFF {
        out.push(0xFE);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xFF);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

fn read_varint(cur: &mut Cursor<&[u8]>) -> Result<u64, String> {
    let mut tag = [0u8; 1];
    cur.read_exact(&mut tag).map_err(|_| "varint: unexpected EOF on tag".to_string())?;
    match tag[0] {
        0xFF => { let mut b = [0u8; 8]; cur.read_exact(&mut b).map_err(|_| "varint u64 EOF")?; Ok(u64::from_le_bytes(b)) }
        0xFE => { let mut b = [0u8; 4]; cur.read_exact(&mut b).map_err(|_| "varint u32 EOF")?; Ok(u32::from_le_bytes(b) as u64) }
        0xFD => { let mut b = [0u8; 2]; cur.read_exact(&mut b).map_err(|_| "varint u16 EOF")?; Ok(u16::from_le_bytes(b) as u64) }
        n    => Ok(n as u64),
    }
}

fn read_u32_le(cur: &mut Cursor<&[u8]>) -> Result<u32, String> {
    let mut b = [0u8; 4];
    cur.read_exact(&mut b).map_err(|_| "u32 EOF".to_string())?;
    Ok(u32::from_le_bytes(b))
}

fn read_u64_le(cur: &mut Cursor<&[u8]>) -> Result<u64, String> {
    let mut b = [0u8; 8];
    cur.read_exact(&mut b).map_err(|_| "u64 EOF".to_string())?;
    Ok(u64::from_le_bytes(b))
}

fn read_32(cur: &mut Cursor<&[u8]>) -> Result<[u8; 32], String> {
    let mut b = [0u8; 32];
    cur.read_exact(&mut b).map_err(|_| "32-byte EOF".to_string())?;
    Ok(b)
}

fn read_bytes(cur: &mut Cursor<&[u8]>, n: usize) -> Result<Vec<u8>, String> {
    let mut b = vec![0u8; n];
    cur.read_exact(&mut b).map_err(|_| format!("{}-byte EOF", n))?;
    Ok(b)
}

// ── Coherence C2: shielded-transaction (de)serialization ──────────────────────

fn write_shielded_tx(out: &mut Vec<u8>, tx: &coherence_core::ShieldedTx) {
    out.extend_from_slice(&tx.anchor);
    write_varint(out, tx.nullifiers.len() as u64);
    for nf in &tx.nullifiers { out.extend_from_slice(nf); }
    write_varint(out, tx.outputs.len() as u64);
    for o in &tx.outputs { out.extend_from_slice(o); }
    out.extend_from_slice(&tx.fee.to_le_bytes());
    write_varint(out, tx.proof.len() as u64);
    out.extend_from_slice(&tx.proof);
    write_varint(out, tx.binding_sig.len() as u64);
    out.extend_from_slice(&tx.binding_sig);
}

fn read_shielded_tx(cur: &mut Cursor<&[u8]>) -> Result<coherence_core::ShieldedTx, String> {
    let anchor = read_32(cur)?;
    let nf_n = read_varint(cur)?;
    if nf_n > 100_000 { return Err(format!("implausible nullifier count {}", nf_n)); }
    let mut nullifiers = Vec::with_capacity(nf_n.min(1024) as usize);
    for _ in 0..nf_n { nullifiers.push(read_32(cur)?); }
    let out_n = read_varint(cur)?;
    if out_n > 100_000 { return Err(format!("implausible output count {}", out_n)); }
    let mut outputs = Vec::with_capacity(out_n.min(1024) as usize);
    for _ in 0..out_n { outputs.push(read_32(cur)?); }
    let fee = read_u64_le(cur)?;
    let proof_len = read_varint(cur)?;
    if proof_len > 8_000_000 { return Err(format!("implausible proof length {}", proof_len)); }
    let proof = read_bytes(cur, proof_len as usize)?;
    let sig_len = read_varint(cur)?;
    if sig_len > 100_000 { return Err(format!("implausible binding_sig length {}", sig_len)); }
    let binding_sig = read_bytes(cur, sig_len as usize)?;
    Ok(coherence_core::ShieldedTx { anchor, nullifiers, outputs, fee, proof, binding_sig })
}

// ────────────────────────────────────────────────────────────────────────────

impl Transaction {
    /// Canonical stratum/Bitcoin-format serialization.
    ///
    /// Used for `txid()` (consensus-critical) and for stratum V1
    /// coinbase splitting. Unlike bincode, this format is stable
    /// across language implementations and matches the byte layout
    /// every external mining client (cgminer, cpuminer, Braiins OS)
    /// already knows how to produce.
    ///
    /// Layout (little-endian integers, varint for counts/lengths):
    ///
    /// ```text
    ///   version (4B LE)
    ///   input_count (varint)
    ///   for each input:
    ///     prev_txid (32B)
    ///     prev_index (4B LE)
    ///     [if include_script_sig: script_sig_len (varint), script_sig bytes]
    ///     sequence (4B LE)
    ///   output_count (varint)
    ///   for each output:
    ///     value (8B LE)
    ///     script_pubkey_len (varint)
    ///     script_pubkey bytes
    ///   locktime (4B LE)
    /// ```
    ///
    /// When `include_script_sig = false`, inputs' script_sig is
    /// omitted entirely (not just zero-length). This matches
    /// Bitcoin's SegWit wtxid convention and preserves the VULN-06
    /// malleability fix for non-coinbase transactions.
    pub fn to_wire_bytes(&self, include_script_sig: bool) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(&self.version.to_le_bytes());
        write_varint(&mut out, self.inputs.len() as u64);
        for inp in &self.inputs {
            out.extend_from_slice(&inp.prev_txid);
            out.extend_from_slice(&inp.prev_index.to_le_bytes());
            if include_script_sig {
                write_varint(&mut out, inp.script_sig.len() as u64);
                out.extend_from_slice(&inp.script_sig);
            }
            out.extend_from_slice(&inp.sequence.to_le_bytes());
        }
        write_varint(&mut out, self.outputs.len() as u64);
        for outp in &self.outputs {
            out.extend_from_slice(&outp.value.to_le_bytes());
            write_varint(&mut out, outp.script_pubkey.len() as u64);
            out.extend_from_slice(&outp.script_pubkey);
        }
        out.extend_from_slice(&self.locktime.to_le_bytes());
        out
    }

    /// Parse a Transaction from its stratum/Bitcoin-format serialization.
    /// Inverse of `to_wire_bytes(true)` — requires `include_script_sig=true`
    /// bytes since a round-trip without script_sig cannot recover the input's
    /// signature.
    ///
    /// Returns Err with a short diagnostic on malformed input.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, String> {
        let mut cur = Cursor::new(bytes);

        let version = read_u32_le(&mut cur)?;
        let in_count = read_varint(&mut cur)?;
        if in_count > 100_000 { return Err(format!("implausible input count {}", in_count)); }

        // SECURITY (audit M1): never pre-size from the untrusted count alone —
        // bound the pre-allocation by how many inputs the remaining bytes could
        // possibly hold (min input = 32+4+1+4 = 41 bytes). The Vec still grows
        // if the payload really is that large.
        let remaining = bytes.len().saturating_sub(cur.position() as usize);
        let mut inputs = Vec::with_capacity((in_count as usize).min(remaining / 41 + 1));
        for _ in 0..in_count {
            let prev_txid = read_32(&mut cur)?;
            let prev_index = read_u32_le(&mut cur)?;
            let sig_len = read_varint(&mut cur)?;
            if sig_len > 10_000 { return Err(format!("implausible script_sig length {}", sig_len)); }
            let script_sig = read_bytes(&mut cur, sig_len as usize)?;
            let sequence = read_u32_le(&mut cur)?;
            inputs.push(TxInput { prev_txid, prev_index, script_sig, sequence });
        }

        let out_count = read_varint(&mut cur)?;
        if out_count > 100_000 { return Err(format!("implausible output count {}", out_count)); }

        // SECURITY (audit M1): bound by remaining bytes (min output = 8+1 = 9 bytes).
        let remaining = bytes.len().saturating_sub(cur.position() as usize);
        let mut outputs = Vec::with_capacity((out_count as usize).min(remaining / 9 + 1));
        for _ in 0..out_count {
            let value = read_u64_le(&mut cur)?;
            let spk_len = read_varint(&mut cur)?;
            if spk_len > 10_000 { return Err(format!("implausible script_pubkey length {}", spk_len)); }
            let script_pubkey = read_bytes(&mut cur, spk_len as usize)?;
            outputs.push(TxOutput { value, script_pubkey });
        }

        let locktime = read_u32_le(&mut cur)?;

        Ok(Transaction { version, inputs, outputs, locktime })
    }

    /// Transaction ID. SHA-256d over stratum-format bytes.
    ///
    /// Non-coinbase: serialized WITHOUT script_sig to prevent
    /// third-party signature malleability (VULN-06 preservation).
    /// Coinbase: serialized WITH script_sig — the "height:N" encoding
    /// plus any stratum extranonce bytes are what make each coinbase
    /// unique; coinbase has no signature to malleate.
    ///
    /// **v0.6.0 change:** previously computed via bincode. Switched
    /// to stratum-format bytes so that external miners (which receive
    /// coinb1/coinb2 byte fragments via mining.notify) and the node
    /// agree on txids. Consensus-breaking, part of the AA.0 hard fork.
    pub fn txid(&self) -> [u8; 32] {
        let bytes = self.to_wire_bytes(self.is_coinbase());
        Sha256::digest(Sha256::digest(&bytes)).into()
    }

    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1
            && self.inputs[0].prev_txid == [0u8; 32]
            && self.inputs[0].prev_index == u32::MAX
    }

    /// Sighash (v2) for input at `index`, bound to `chain_id`.
    ///
    /// The digest of transactions whose version is not 3 (see the
    /// `core::sighash` module for the selection and the activation rule). Specified
    /// byte for byte in `docs/CONSENSUS.md` (the bincode body is re-derived
    /// by an independent encoder in `reference/gnb_sighash.py`) and pinned by
    /// golden vectors; it must never change. Costs O(size) per input, so
    /// O(size²) per transaction (bounded by the size limits, and invalid
    /// at/after the activation). An out-of-range `input_index` silently
    /// omits the marker (historical behaviour, kept for digest stability);
    /// [`Transaction::sighash_v2_checked`] reports it as an error instead.
    ///
    /// `chain_id` is an EXPLICIT consensus input threaded from the node's network
    /// (`ChainId::for_network` / `node_chain_id()`), never a compile-time flag and
    /// never taken from the transaction. Folding it into the preimage prevents
    /// cross-fork / testnet↔mainnet replay: the same signature bytes verify to a
    /// different 32-byte digest on another chain, so ML-DSA and Falcon both fail
    /// (design §1). This changes the signed bytes of every tx — a hard fork.
    pub fn sighash(&self, input_index: usize, chain_id: ChainId) -> [u8; 32] {
        let mut stripped = self.clone();
        for (i, inp) in stripped.inputs.iter_mut().enumerate() {
            inp.script_sig = if i == input_index {
                b"GNB_SIGHASH".to_vec()
            } else {
                vec![]
            };
        }
        // SIGHASH_ALL: the digest commits to version, locktime, every input's
        // outpoint (prev_txid/prev_index/sequence) and the signed input's index
        // (via the marker), and EVERY output — so signatures cannot be replayed
        // across txs (outpoints) nor have outputs redirected/tampered. The spent
        // UTXO's value is bound implicitly via its outpoint (the verifier looks it
        // up). `.expect` not `.unwrap_or_default`: a silent empty encoding would
        // make the sighash a FIXED constant (replayable signatures) — encoding an
        // owned struct into an in-memory Vec cannot fail, so fail loud if it ever
        // does rather than degrade security.
        //
        // The v1 body (the stripped-tx bincode blob, incl. the per-input marker)
        // is unchanged; v2 only prepends the fixed 21-byte domain+version+chain-id
        // prefix. All prefix fields are fixed-length and only the trailing bincode
        // blob is variable, so simple concatenation is unambiguous.
        let body = bincode::serde::encode_to_vec(&stripped, bincode::config::standard())
            .expect("Transaction is always serializable into an in-memory buffer");
        let mut h = Sha3_256::new();
        h.update(SIGHASH_DOMAIN);           // 16 bytes (fixed)
        h.update([SIGHASH_VERSION]);        //  1 byte  (fixed)
        h.update(chain_id.to_le_bytes());   //  4 bytes (fixed)
        h.update(&body);                    //  variable (v1 body, unchanged)
        h.finalize().into()
    }

    pub fn merkle_root(txs: &[Transaction]) -> MerkleRoot {
        if txs.is_empty() { return MerkleRoot::ZERO; }
        let mut hashes: Vec<[u8; 32]> = txs.iter().map(|t| t.txid()).collect();
        while hashes.len() > 1 {
            // `len() > 1` in the loop guard: `last()` is `Some` (hardened ratchet).
            if hashes.len() % 2 != 0 {
                if let Some(last) = hashes.last().copied() {
                    hashes.push(last);
                }
            }
            hashes = hashes.chunks(2).map(|p| {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&p[0]);
                buf[32..].copy_from_slice(&p[1]);
                Sha256::digest(Sha256::digest(buf)).into()
            }).collect();
        }
        MerkleRoot(hashes[0])
    }

    /// Parse sig + pubkey out of script_sig (historical, lenient framing:
    /// bytes after the public key are ignored). Owned copy of
    /// [`Self::parse_script_sig_borrowed`].
    pub fn parse_script_sig(script_sig: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
        Self::parse_script_sig_borrowed(script_sig).map(|(s, p)| (s.to_vec(), p.to_vec()))
    }

    /// The historical (sighash v2) witness framing
    /// `[u32 LE sig_len][sig][u32 LE pk_len][pk]`, borrowed. Bytes after the
    /// public key are IGNORED; this acceptance is consensus below the
    /// hardening activation and must not change.
    pub fn parse_script_sig_borrowed(script_sig: &[u8]) -> Option<(&[u8], &[u8])> {
        Self::parse_script_sig_prefix(script_sig).map(|(s, p, _)| (s, p))
    }

    /// The canonical witness framing: exactly
    /// `[u32 LE sig_len][sig][u32 LE pk_len][pk]` with no trailing bytes
    /// (CRY-1; consensus for version-3 transactions, relay policy at every
    /// height).
    pub fn parse_script_sig_exact(script_sig: &[u8]) -> Option<(&[u8], &[u8])> {
        match Self::parse_script_sig_prefix(script_sig) {
            Some((s, p, end)) if end == script_sig.len() => Some((s, p)),
            _ => None,
        }
    }

    /// (sig, pk, bytes consumed).
    fn parse_script_sig_prefix(script_sig: &[u8]) -> Option<(&[u8], &[u8], usize)> {
        // CRY-8: checked arithmetic. On 64-bit targets no sum below can
        // overflow (lengths are u32), so acceptance is unchanged; on 32-bit
        // targets a huge declared length now returns None instead of panicking.
        if script_sig.len() < 8 { return None; }
        let sig_len = usize::try_from(u32::from_le_bytes(script_sig[..4].try_into().ok()?)).ok()?;
        let sig_end = sig_len.checked_add(4)?;
        let pk_len_end = sig_end.checked_add(4)?;
        if script_sig.len() < pk_len_end { return None; }
        let sig = &script_sig[4..sig_end];
        let pk_len = usize::try_from(u32::from_le_bytes(
            script_sig[sig_end..pk_len_end].try_into().ok()?
        )).ok()?;
        let pk_end = pk_len_end.checked_add(pk_len)?;
        if script_sig.len() < pk_end { return None; }
        let pk = &script_sig[pk_len_end..pk_end];
        Some((sig, pk, pk_end))
    }

    /// Build script_sig from sig + pubkey
    pub fn build_script_sig(sig: &[u8], pubkey: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + sig.len() + pubkey.len());
        out.extend_from_slice(&(sig.len() as u32).to_le_bytes());
        out.extend_from_slice(sig);
        out.extend_from_slice(&(pubkey.len() as u32).to_le_bytes());
        out.extend_from_slice(pubkey);
        out
    }

    /// Sprint A: Estimate the serialized size of a transaction BEFORE signing.
    pub fn estimate_size(n_inputs: usize, n_outputs: usize) -> usize {
        const PER_INPUT:  usize = 4 + 32 + 4
                                  + 4 + crate::core::SIG_SIZE
                                  + 4 + crate::core::PUBKEY_SIZE;
        const PER_OUTPUT: usize = 8 + 4 + 20;
        const BASE:       usize = 4 + 4 + 4 + 4;
        BASE + (n_inputs * PER_INPUT) + (n_outputs * PER_OUTPUT)
    }

    /// Sprint A: Calculate fee given size and rate (sats per 1000 bytes).
    pub fn calc_fee(size_bytes: usize, fee_rate_per_kb: u64, min_fee: u64) -> u64 {
        let calculated = (size_bytes as u64).saturating_mul(fee_rate_per_kb) / 1000;
        calculated.max(min_fee)
    }

    /// Sprint A: Full fee estimation for a planned transaction.
    pub fn estimate_fee(n_inputs: usize, n_outputs: usize, fee_rate_per_kb: u64) -> u64 {
        let size = Self::estimate_size(n_inputs, n_outputs);
        Self::calc_fee(size, fee_rate_per_kb, 1000)
    }

    /// Sprint A: Actual serialized size of this transaction (after signing).
    pub fn actual_size(&self) -> usize {
        bincode::serde::encode_to_vec(self, bincode::config::standard())
            .map(|v| v.len())
            .unwrap_or(0)
    }

    /// Sprint A: Total value of outputs (None on overflow).
    pub fn total_output(&self) -> Option<u64> {
        self.outputs.iter()
            .try_fold(0u64, |acc, o| acc.checked_add(o.value))
    }

    /// Sprint A: Count distinct addresses in outputs.
    pub fn unique_output_addresses(&self) -> usize {
        use std::collections::HashSet;
        let addrs: HashSet<&[u8]> = self.outputs.iter()
            .map(|o| o.script_pubkey.as_slice())
            .collect();
        addrs.len()
    }
}

// ── Block ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub header:       BlockHeader,
    pub transactions: Vec<Transaction>,
    pub blue_score:   u64,
    pub height:       u64,
    /// Coherence: shielded (private) transactions in this block. Committed via
    /// `body_merkle_root` and serialized after the transparent transactions.
    #[serde(default)]
    pub shielded_transactions: Vec<coherence_core::ShieldedTx>,
}

/// Bounded cache of block ids whose GnB-SMH proof has been verified. A block
/// id commits to the full PoW preimage and nonce, so a hit is exactly as good
/// as re-running the 64 MiB evaluation. Entries are only inserted after a
/// successful verification.
struct PowCache {
    set: std::collections::HashSet<[u8; 32]>,
    order: std::collections::VecDeque<[u8; 32]>,
}

const POW_CACHE_CAPACITY: usize = 16_384;

fn pow_cache() -> &'static std::sync::Mutex<PowCache> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<PowCache>> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| {
        std::sync::Mutex::new(PowCache {
            set: std::collections::HashSet::new(),
            order: std::collections::VecDeque::new(),
        })
    })
}

impl Block {
    /// Block identity: SHA3-256 over a domain label, the PoW preimage and the
    /// nonce. Cheap, and distinct from the (expensive) PoW output.
    pub fn block_hash(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"GNB-BLOCK-ID-v1");
        h.update(self.header.pow_preimage());
        h.update(self.header.nonce.to_le_bytes());
        h.finalize().into()
    }

    /// Wire format:
    ///
    /// ```text
    ///   header       BlockHeader::to_wire_bytes(blue_score, height)
    ///   tx_count     varint
    ///   transactions Transaction::to_wire_bytes(true) × tx_count
    ///   sh_count     varint
    ///   shielded     shielded tx × sh_count
    /// ```
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut out = self.header.to_wire_bytes(self.blue_score, self.height);
        write_varint(&mut out, self.transactions.len() as u64);
        for tx in &self.transactions {
            out.extend_from_slice(&tx.to_wire_bytes(true));
        }
        write_varint(&mut out, self.shielded_transactions.len() as u64);
        for stx in &self.shielded_transactions {
            write_shielded_tx(&mut out, stx);
        }
        out
    }

    /// Strict inverse of `to_wire_bytes`: trailing bytes are rejected.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, String> {
        let (header, blue_score, height, header_len) = BlockHeader::read_wire_bytes(bytes)?;
        let body = &bytes[header_len..];
        let mut cur = Cursor::new(body);
        let tx_count = read_varint(&mut cur)?;
        if tx_count > 1_000_000 {
            return Err(format!("implausible tx count {}", tx_count));
        }
        // Bound the pre-allocation by the remaining bytes (a minimal tx is 10
        // bytes), never by the untrusted count alone.
        let remaining = body.len().saturating_sub(cur.position() as usize);
        let mut transactions = Vec::with_capacity((tx_count as usize).min(remaining / 10 + 1));
        let mut offset = cur.position() as usize;
        for i in 0..tx_count {
            let tx = Transaction::from_wire_bytes(&body[offset..])
                .map_err(|e| format!("tx[{}] parse: {}", i, e))?;
            offset += tx.to_wire_bytes(true).len();
            transactions.push(tx);
        }

        let mut sh_cur = Cursor::new(&body[offset..]);
        let sh_count = read_varint(&mut sh_cur).map_err(|e| format!("shielded count: {e}"))?;
        if sh_count > 100_000 {
            return Err(format!("implausible shielded count {}", sh_count));
        }
        let mut shielded_transactions = Vec::new();
        for i in 0..sh_count {
            shielded_transactions.push(
                read_shielded_tx(&mut sh_cur).map_err(|e| format!("shielded[{}]: {}", i, e))?);
        }
        offset += sh_cur.position() as usize;

        if offset != body.len() {
            return Err(format!("trailing bytes in block body: parsed {} of {}", offset, body.len()));
        }
        Ok(Block { header, transactions, blue_score, height, shielded_transactions })
    }

    /// Merkle commitment over the block body — transparent and shielded txs.
    /// With no shielded txs it equals `Transaction::merkle_root(transparent)`.
    pub fn body_merkle_root(&self) -> MerkleRoot {
        let tx_root = Transaction::merkle_root(&self.transactions);
        if self.shielded_transactions.is_empty() {
            return tx_root;
        }
        let mut sh = Sha3_256::new();
        sh.update(b"gnb:block:shielded:v1");
        for stx in &self.shielded_transactions {
            let mut buf = Vec::new();
            write_shielded_tx(&mut buf, stx);
            let h: [u8; 32] = Sha3_256::digest(&buf).into();
            sh.update(h);
        }
        let sh_root: [u8; 32] = sh.finalize().into();
        let mut c = Sha3_256::new();
        c.update(b"gnb:block:body:v1");
        c.update(tx_root.0);
        c.update(sh_root);
        MerkleRoot(c.finalize().into())
    }

    pub fn validate_merkle(&self) -> bool {
        self.body_merkle_root() == self.header.merkle_root
    }

    /// GnB-SMH proof of work: GnB-SMH(pow_preimage, nonce) < target(bits).
    ///
    /// Malformed or zero `bits` never validate. This checks the proof against
    /// the header's own `bits`; that `bits` equals the consensus-expected
    /// value is checked by the caller (`expected_bits`) — and should be
    /// checked first, since it is cheap and this is not.
    pub fn validate_pow(&self) -> bool {
        let target = match gnb_smh::difficulty::try_bits_to_target(self.header.bits) {
            Ok(t) => t,
            Err(_) => return false,
        };
        // POW-9 (audit): explicit `target <= pow_limit`. Unreachable today —
        // the largest decodable compact target IS the pow limit — but the
        // proof must never rely on that coincidence of the encoding: a future
        // change to the decoder or to POW_LIMIT_BITS must fail closed here,
        // before any evaluation is spent.
        if !Self::target_within_pow_limit(&target.0) {
            return false;
        }
        let id = self.block_hash();
        if let Ok(cache) = pow_cache().lock() {
            if cache.set.contains(&id) {
                return true;
            }
        }
        let ok = gnb_smh::verify(&self.header.pow_preimage(), self.header.nonce, &target);
        if ok {
            if let Ok(mut cache) = pow_cache().lock() {
                if cache.set.insert(id) {
                    cache.order.push_back(id);
                    if cache.order.len() > POW_CACHE_CAPACITY {
                        if let Some(old) = cache.order.pop_front() {
                            cache.set.remove(&old);
                        }
                    }
                }
            }
        }
        ok
    }

    /// POW-9: `target <= pow_limit` (both big-endian). Every target a valid
    /// block may claim must be at most the chain's pow limit; `validate_pow`
    /// checks it explicitly instead of relying on the compact encoding's range.
    pub fn target_within_pow_limit(target: &[u8; 32]) -> bool {
        *target <= bits_to_target(POW_LIMIT_BITS)
    }

    /// Basic coinbase format check (value is checked with fees in accept_block).
    pub fn validate_coinbase_format(&self) -> bool {
        if self.transactions.is_empty() { return false; }
        let cb = &self.transactions[0];
        if !cb.is_coinbase() { return false; }
        if self.transactions.iter().skip(1).any(|t| t.is_coinbase()) { return false; }
        true
    }

    /// Coinbase value rule. Called after computing the block's total fees.
    ///
    /// Fair launch: the coinbase has exactly one output, paid to an address of
    /// the miner's choice, worth at most `block_subsidy_sat(height) + fees`.
    /// Paying less burns the difference.
    pub fn validate_coinbase_value(&self, total_fees: u64) -> Result<(), &'static str> {
        if self.transactions.is_empty() { return Err("no transactions"); }
        let cb = &self.transactions[0];
        if cb.outputs.len() != 1 {
            return Err("coinbase must have 1 output (miner)");
        }
        // checked_add, not saturating_add: an overflowing sum must be rejected,
        // never clamped into "any value is allowed".
        let subsidy = tokenomics::block_subsidy_sat(self.height);
        let max_allowed = subsidy.checked_add(total_fees)
            .ok_or("coinbase reward computation overflowed (subsidy + fees)")?;
        if cb.outputs[0].value > max_allowed {
            return Err("miner coinbase output exceeds allowed amount");
        }
        Ok(())
    }

    /// Validate the timestamp is within acceptable bounds.
    /// `parent_timestamp`: the latest timestamp over all of the block's
    /// parents (the node passes the max; 0 for genesis).
    pub fn validate_timestamp(&self, parent_timestamp: u64) -> Result<(), &'static str> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if self.header.timestamp > now + MAX_FUTURE_SECS {
            return Err("timestamp too far in the future");
        }
        if self.header.timestamp < parent_timestamp {
            return Err("timestamp before parent");
        }
        Ok(())
    }

    /// Check all non-coinbase outputs meet the dust threshold.
    pub fn validate_dust(&self) -> Result<(), &'static str> {
        for tx in self.transactions.iter().skip(1) {
            for out in &tx.outputs {
                if out.value > 0 && out.value < DUST_THRESHOLD {
                    return Err("output below dust threshold");
                }
            }
        }
        Ok(())
    }

    /// Reject blocks with duplicate transactions (CVE-2012-2459: the merkle
    /// tree duplicates the last hash on odd levels, so [A, B, C] and
    /// [A, B, C, C] share a root).
    pub fn validate_no_duplicate_txs(&self) -> Result<(), &'static str> {
        use std::collections::HashSet;
        let mut seen = HashSet::with_capacity(self.transactions.len());
        for tx in &self.transactions {
            if !seen.insert(tx.txid()) {
                return Err("duplicate transaction in block (CVE-2012-2459)");
            }
        }
        Ok(())
    }

    /// Structural validation. Cheap checks run first; the proof of work runs
    /// last. Does NOT check coinbase value, fees, bits or height (those need
    /// consensus context).
    ///
    /// Exactly `validate_structure_without_pow()` followed by `validate_pow()`.
    /// Network ingress (NET-2) calls the two halves separately so the cheap
    /// contextual checks (expected bits, height, timestamp, or the orphan
    /// anti-DoS work floor) can run BETWEEN them, before the 64 MiB
    /// evaluation; the proof itself is still verified on every ingress path.
    pub fn validate_structure(&self) -> Result<(), &'static str> {
        self.validate_structure_without_pow()?;
        if !self.validate_pow()                       { return Err("invalid PoW"); }
        Ok(())
    }

    /// The cheap, context-free half of [`Block::validate_structure`]: parent
    /// count, size, merkle commitment, coinbase format, duplicate txs, dust.
    /// Does NOT verify the proof of work — a caller that uses this MUST call
    /// [`Block::validate_pow`] (directly or through the node's `accept_block`)
    /// before treating the block as valid.
    pub fn validate_structure_without_pow(&self) -> Result<(), &'static str> {
        if self.header.parents.len() > MAX_PARENTS   { return Err("too many parents"); }
        if self.size_bytes() > MAX_BLOCK_SIZE        { return Err("block too large"); }
        if !self.validate_merkle()                    { return Err("invalid merkle root"); }
        if !self.validate_coinbase_format()           { return Err("invalid coinbase format"); }
        self.validate_no_duplicate_txs()?;
        self.validate_dust()?;
        Ok(())
    }

    pub fn size_bytes(&self) -> usize {
        bincode::serde::encode_to_vec(self, bincode::config::standard()).map(|v| v.len()).unwrap_or(usize::MAX)
    }
}

#[cfg(test)]
mod structure_split_tests {
    //! NET-2 / POW-9 regressions: the cheap structural half is separable from
    //! the proof of work, and `validate_pow` checks `target <= pow_limit`.
    use super::*;

    fn block_with(bits: u32, nonce: u64) -> Block {
        let txs = vec![Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: [0u8; 32],
                prev_index: u32::MAX,
                script_sig: b"structure-split".to_vec(),
                sequence: u32::MAX,
            }],
            outputs: vec![TxOutput { value: 1, script_pubkey: vec![7u8; 20] }],
            locktime: 0,
        }];
        let mut b = Block {
            header: BlockHeader {
                version: 1,
                parents: vec![[0x11; 32]],
                merkle_root: MerkleRoot::ZERO,
                timestamp: GENESIS_TIMESTAMP,
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
    fn target_above_pow_limit_is_rejected() {
        assert!(!Block::target_within_pow_limit(&[0xFF; 32]), "target above the limit must fail");
        assert!(Block::target_within_pow_limit(&bits_to_target(POW_LIMIT_BITS)), "the limit itself is allowed");
        assert!(Block::target_within_pow_limit(&bits_to_target(GENESIS_BITS)));
        // One unit above the limit is already out of range.
        let mut above = bits_to_target(POW_LIMIT_BITS);
        let last = above.iter().rposition(|&b| b != 0xFF).expect("limit is not all-ones");
        above[last] = above[last].wrapping_add(1);
        for b in above.iter_mut().skip(last + 1) { *b = 0; }
        assert!(!Block::target_within_pow_limit(&above));
    }

    #[test]
    fn malformed_bits_never_validate_and_cost_no_evaluation() {
        // Negative-flag bits: rejected by the decoder before any evaluation.
        let b = block_with(0x0480_0001, 0);
        let t = std::time::Instant::now();
        assert!(!b.validate_pow());
        assert!(t.elapsed() < std::time::Duration::from_millis(50));
    }

    #[test]
    fn cheap_half_accepts_well_formed_block_regardless_of_pow() {
        // Hard target, arbitrary nonce: the PoW fails, the cheap half passes.
        let mut b = block_with(GENESIS_BITS, 0);
        while b.validate_pow() { b.header.nonce += 1; } // find a FAILING nonce
        assert_eq!(b.validate_structure_without_pow(), Ok(()));
        assert_eq!(b.validate_structure(), Err("invalid PoW"),
            "validate_structure must still verify the proof of work");
    }

    #[test]
    fn cheap_half_still_rejects_structural_faults() {
        let mut b = block_with(POW_LIMIT_BITS, 0);
        b.header.merkle_root = MerkleRoot([9u8; 32]);
        assert_eq!(b.validate_structure_without_pow(), Err("invalid merkle root"));
        let mut b = block_with(POW_LIMIT_BITS, 0);
        b.header.parents = vec![[1u8; 32]; MAX_PARENTS + 1];
        assert_eq!(b.validate_structure_without_pow(), Err("too many parents"));
        let mut b = block_with(POW_LIMIT_BITS, 0);
        b.transactions.clear();
        b.header.merkle_root = b.body_merkle_root();
        assert_eq!(b.validate_structure_without_pow(), Err("invalid coinbase format"));
    }
}

#[cfg(test)]
mod validate_coinbase_value_tests {
    use super::*;

    fn one_output_coinbase_block(height: u64, miner_value: u64) -> Block {
        Block {
            header: BlockHeader {
                version: 1,
                parents: vec![],
                merkle_root: MerkleRoot([0u8; 32]),
                timestamp: 0,
                bits: 0,
                nonce: 0,
            },
            transactions: vec![Transaction {
                version: 1,
                inputs: vec![TxInput {
                    prev_txid: [0u8; 32],
                    prev_index: u32::MAX,
                    script_sig: vec![],
                    sequence: u32::MAX,
                }],
                outputs: vec![TxOutput { value: miner_value, script_pubkey: vec![0u8; 20] }],
                locktime: 0,
            }],
            blue_score: 0,
            height,
            shielded_transactions: vec![],
        }
    }

    #[test]
    fn overflowing_subsidy_plus_fees_is_rejected_not_clamped() {
        let block = one_output_coinbase_block(1, u64::MAX);
        assert_eq!(
            block.validate_coinbase_value(u64::MAX),
            Err("coinbase reward computation overflowed (subsidy + fees)"),
        );
    }

    #[test]
    fn subsidy_plus_fees_is_the_exact_limit() {
        let subsidy = tokenomics::block_subsidy_sat(1);
        let fees = 1_000u64;
        assert_eq!(one_output_coinbase_block(1, subsidy + fees).validate_coinbase_value(fees), Ok(()));
        assert_eq!(
            one_output_coinbase_block(1, subsidy + fees + 1).validate_coinbase_value(fees),
            Err("miner coinbase output exceeds allowed amount"),
        );
    }

    #[test]
    fn genesis_height_pays_only_fees() {
        assert_eq!(one_output_coinbase_block(0, 0).validate_coinbase_value(0), Ok(()));
        assert!(one_output_coinbase_block(0, 1).validate_coinbase_value(0).is_err());
    }

    #[test]
    fn coinbase_must_have_exactly_one_output() {
        let mut b = one_output_coinbase_block(1, 1);
        b.transactions[0].outputs.push(TxOutput { value: 1, script_pubkey: vec![1u8; 20] });
        assert_eq!(b.validate_coinbase_value(0), Err("coinbase must have 1 output (miner)"));
    }
}

// ── Sprint U.1: Reorg undo data ───────────────────────────────────────────────
//
// Audit finding C-1: accept_block is forward-only. When a fork with higher
// blue work replaces the current selected chain, UTXOs mutated by the
// losing branch must be reverted. We persist an UndoData record per block
// so the eventual rollback_block() primitive (Sprint U.2) can replay the
// mutations in reverse. Kept in storage only while the block is within the
// finality window; records below finalized_height are pruned in Sprint U.3.

/// A single input consumed by a block that must be restored on rollback.
/// Captures the full pre-spend output so we can re-insert it verbatim.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UndoEntry {
    pub prev_txid:  [u8; 32],
    pub prev_index: u32,
    pub output:     TxOutput,
}

/// Everything accept_block mutated for a given block that rollback_block
/// needs to undo. Recorded on accept, replayed in reverse on reorg.
///
/// The four vectors mirror the four side effects in accept_block:
///   1. spent_utxos       — UTXOs deleted via delete_utxo (restore by re-put)
///   2. created_utxo_keys — UTXOs inserted via put_utxo    (undo by delete)
///   3. coinbase_txids    — coinbase rows in CF_COINBASE   (undo by delete)
///   4. tx_index_keys     — rows in CF_TX_INDEX            (undo by delete)
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct UndoData {
    pub block_hash:        [u8; 32],
    pub block_height:      u64,
    pub spent_utxos:       Vec<UndoEntry>,
    pub created_utxo_keys: Vec<([u8; 32], u32)>,
    pub coinbase_txids:    Vec<[u8; 32]>,
    pub tx_index_keys:     Vec<[u8; 32]>,
}

impl UndoData {
    pub fn new(block_hash: [u8; 32], block_height: u64) -> Self {
        Self {
            block_hash,
            block_height,
            spent_utxos:       Vec::new(),
            created_utxo_keys: Vec::new(),
            coinbase_txids:    Vec::new(),
            tx_index_keys:     Vec::new(),
        }
    }

    /// Total mutations recorded — useful for metrics & sanity tests.
    pub fn mutation_count(&self) -> usize {
        self.spent_utxos.len()
            + self.created_utxo_keys.len()
            + self.coinbase_txids.len()
            + self.tx_index_keys.len()
    }
}

// ── Genesis ───────────────────────────────────────────────────────────────────
//
// The GnB genesis state is the converted Bloch Genesis-3 carryover (see
// `carryover`), written into the UTXO set when the genesis is initialised; the
// genesis coinbase text commits to the snapshot's SHA3-256 and the conversion.
// No premine: the coinbase pays 0 to an unspendable all-zero script, so the
// first mined subsidy is at height 1. Its proof of work is a real GnB-SMH
// solution at GENESIS_BITS, found once by `gnb-mine-genesis` and baked below;
// the node refuses to start if the genesis does not validate.

/// Coinbase text of the genesis block.
pub const GENESIS_COINBASE_TEXT: &str =
    "GnB genesis 2026-10-08: Godel and Bell, GnB-SMH memory-hard PoW, 10M GNB cap. \
Carryover Bloch G3 terminal snapshot sha3 3d67246e94881a17d302b464f79fee55886d8068794e76fed43081117fbe308d \
3810744000 BLCH -> 1000000 GNB.";
/// Unix time of the genesis block (2026-10-08 03:11:32 UTC), the launch moment. Also the
/// ASERT anchor timestamp.
pub const GENESIS_TIMESTAMP: u64 = 1791429092;
/// Genesis difficulty and ASERT anchor bits: ≈ 4,500 evaluations per block,
/// i.e. 30 s at the launch hashrate (7 hosts × 11 threads ≈ 150 evaluations/s).
pub const GENESIS_BITS:      u32 = 0x1F0E_9036;
/// GnB-SMH nonce of the genesis block.
pub const GENESIS_NONCE:     u64 = 482;
/// `block_hash()` of the genesis block:
/// 837f7d5c832ae28370cd52baa969528753f619be2a4dd07d814a1a986c4201cd.
pub const GENESIS_EXPECTED_HASH: [u8; 32] = [
    0x83, 0x7f, 0x7d, 0x5c, 0x83, 0x2a, 0xe2, 0x83,
    0x70, 0xcd, 0x52, 0xba, 0xa9, 0x69, 0x52, 0x87,
    0x53, 0xf6, 0x19, 0xbe, 0x2a, 0x4d, 0xd0, 0x7d,
    0x81, 0x4a, 0x1a, 0x98, 0x6c, 0x42, 0x01, 0xcd,
];

/// Genesis block with explicit header parameters (used by the mining tool).
pub fn create_genesis_block_with(timestamp: u64, bits: u32, nonce: u64) -> Block {
    let coinbase = Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid:  [0u8; 32],
            prev_index: u32::MAX,
            script_sig: GENESIS_COINBASE_TEXT.as_bytes().to_vec(),
            sequence:   u32::MAX,
        }],
        outputs: vec![TxOutput { value: 0, script_pubkey: vec![0u8; 20] }],
        locktime: 0,
    };
    let merkle = Transaction::merkle_root(std::slice::from_ref(&coinbase));
    Block {
        header: BlockHeader {
            version: 1,
            parents: vec![],
            merkle_root: merkle,
            timestamp,
            bits,
            nonce,
        },
        transactions: vec![coinbase],
        blue_score: 0,
        height: 0,
        shielded_transactions: Vec::new(),
    }
}

/// The canonical GnB genesis block. Shared by mainnet and testnet; the two
/// networks are separated by chain id (sighash domain) and P2P identity.
pub fn genesis_block() -> Block {
    create_genesis_block_with(GENESIS_TIMESTAMP, GENESIS_BITS, GENESIS_NONCE)
}

// ── Difficulty helpers ────────────────────────────────────────────────────────
//
// Thin wrappers over `gnb_smh::difficulty` on plain big-endian byte arrays.

/// Decode compact `bits` into a big-endian target; malformed bits decode to
/// the all-zero target, which nothing meets (fail closed).
pub fn bits_to_target(bits: u32) -> [u8; 32] {
    gnb_smh::difficulty::bits_to_target(bits).0
}

/// Encode a big-endian target in compact form (rounds down).
pub fn target_to_bits(target: &[u8; 32]) -> u32 {
    gnb_smh::difficulty::target_to_bits(&gnb_smh::difficulty::Target(*target))
}

/// `hash < target`, both big-endian. Strict, as in GnB-SMH.
pub fn hash_meets_target(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    hash < target
}

/// Chain-work contribution of a block at `bits`: ≈ 2^256 / target (exact
/// definition: `gnb_smh::difficulty::work`), 0 for
/// malformed bits.
pub fn bits_to_work(bits: u32) -> u128 {
    gnb_smh::difficulty::work_from_bits(bits)
}

fn u256_to_f64(v: primitive_types::U256) -> f64 {
    v.0.iter().rev().fold(0.0, |acc, &limb| acc * 18_446_744_073_709_551_616.0 + limb as f64)
}

/// Human-facing difficulty: expected GnB-SMH evaluations per block relative
/// to the pow limit (difficulty 1 = `POW_LIMIT_BITS`).
pub fn difficulty_from_bits(bits: u32) -> f64 {
    use primitive_types::U256;
    let limit  = U256::from_big_endian(&bits_to_target(POW_LIMIT_BITS));
    let target = U256::from_big_endian(&bits_to_target(bits));
    if target.is_zero() {
        return f64::INFINITY;
    }
    u256_to_f64(limit) / u256_to_f64(target)
}

/// Inverse of [`difficulty_from_bits`]: target for a (fractional) difficulty,
/// never easier than the pow limit.
pub fn difficulty_to_target(diff: f64) -> [u8; 32] {
    use primitive_types::U256;
    let limit = U256::from_big_endian(&bits_to_target(POW_LIMIT_BITS));
    if !diff.is_finite() || diff <= 1.0 {
        return limit.to_big_endian();
    }
    // limit / diff with 2^-32 resolution on diff: (limit / round(diff * 2^32)) * 2^32.
    let scaled = (diff * 4_294_967_296.0).min(3.4e38) as u128;
    let t = (limit / U256::from(scaled.max(1))) << 32;
    t.min(limit).to_big_endian()
}

#[cfg(test)]
mod difficulty_tests {
    use super::*;

    #[test]
    fn pow_limit_is_difficulty_one() {
        assert!((difficulty_from_bits(POW_LIMIT_BITS) - 1.0).abs() < 1e-9);
        assert!(difficulty_from_bits(GENESIS_BITS) > 200.0);
        assert_eq!(difficulty_from_bits(0xFF00_FFFF), f64::INFINITY);
    }

    #[test]
    fn malformed_bits_fail_closed() {
        assert_eq!(bits_to_target(0x0480_0001), [0u8; 32]);
        assert_eq!(bits_to_work(0x0480_0001), 0);
        assert!(!hash_meets_target(&[0u8; 32], &bits_to_target(0x0480_0001)));
    }

    #[test]
    fn target_compare_is_strict() {
        let t = bits_to_target(GENESIS_BITS);
        assert!(!hash_meets_target(&t, &t));
    }

    #[test]
    #[cfg_attr(feature = "test-pow-limit", ignore = "test-pow-limit pins expected bits")]
    fn expected_bits_at_schedule_is_genesis_bits() {
        assert_eq!(expected_bits(GENESIS_TIMESTAMP, 1).unwrap(), GENESIS_BITS);
        assert_eq!(expected_bits(GENESIS_TIMESTAMP + 30 * 99, 100).unwrap(), GENESIS_BITS);
        // Late chain: the target eases toward the pow limit, never past it.
        let late = expected_bits(GENESIS_TIMESTAMP + 365 * 86_400, 1).unwrap();
        assert_eq!(late, target_to_bits(&bits_to_target(POW_LIMIT_BITS)));
        assert!(expected_bits(u64::MAX, 1).is_err());
    }

    #[test]
    fn genesis_block_shape() {
        let g = genesis_block();
        assert_eq!(g.height, 0);
        assert!(g.header.parents.is_empty());
        assert!(g.validate_merkle());
        assert!(g.validate_coinbase_format());
        assert_eq!(g.validate_coinbase_value(0), Ok(()));
        assert_eq!(g.transactions[0].outputs[0].value, 0);
    }

    #[test]
    fn genesis_pow_is_valid() {
        let g = genesis_block();
        assert!(g.validate_pow(), "genesis nonce does not meet GENESIS_BITS");
        if GENESIS_EXPECTED_HASH != [0u8; 32] {
            assert_eq!(g.block_hash(), GENESIS_EXPECTED_HASH);
        }
    }
}

// ── Roadmap #8 §1 — chain-id sighash replay regression ───────────────────────
#[cfg(test)]
mod chain_id_tests {
    use super::*;

    fn two_input_tx() -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![
                TxInput { prev_txid: [3u8; 32], prev_index: 0, script_sig: vec![], sequence: 0xffff_ffff },
                TxInput { prev_txid: [4u8; 32], prev_index: 1, script_sig: vec![], sequence: 0xffff_ffff },
            ],
            outputs: vec![TxOutput { value: 42, script_pubkey: vec![9u8; 20] }],
            locktime: 0,
        }
    }

    #[test]
    fn chain_id_registry_values() {
        assert_eq!(ChainId::Mainnet.to_u32(), 0x474E_0001);
        assert_eq!(ChainId::Testnet.to_u32(), 0x474E_0002);
        assert_eq!(ChainId::Mainnet.to_le_bytes(), [0x01, 0x00, 0x4E, 0x47]);
        assert_eq!(ChainId::for_network(crate::address::Network::Mainnet), ChainId::Mainnet);
        assert_eq!(ChainId::for_network(crate::address::Network::Testnet), ChainId::Testnet);
    }

    #[test]
    fn sighash_is_domain_and_chain_separated() {
        let tx = two_input_tx();
        // Distinct per chain-id.
        assert_ne!(tx.sighash(0, ChainId::Mainnet), tx.sighash(0, ChainId::Testnet),
                   "mainnet and testnet must sign different digests");
        // Still distinct per input index (v1 property preserved).
        assert_ne!(tx.sighash(0, ChainId::Mainnet), tx.sighash(1, ChainId::Mainnet));
    }

    /// The core invariant (design §4.3.4): a signature valid under Mainnet MUST
    /// be rejected when verified under Testnet — cross-chain replay ⇒ false.
    #[test]
    fn cross_chain_id_replay_is_rejected() {
        let tx = two_input_tx();
        let (pk, sk) = crate::crypto::generate_keypair();

        let h_main = tx.sighash(0, ChainId::Mainnet);
        let sig = crate::crypto::sign(&sk, &h_main).unwrap();

        // Same chain: accepts.
        assert!(crate::crypto::verify(&pk, &h_main, &sig),
                "a correctly chain-id'd signature must verify");
        // Replay onto testnet: the verifier recomputes with the Testnet domain →
        // a different digest → both ML-DSA and Falcon fail.
        let h_test = tx.sighash(0, ChainId::Testnet);
        assert!(!crate::crypto::verify(&pk, &h_test, &sig),
                "cross-chain-id replay MUST be rejected");
    }
}

