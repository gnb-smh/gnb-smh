//! GnB ledger v1: stateless validation, port of `reference/gnb_ledger.py` (normative).
//!
//! Validity is deterministic and needs no committee: a node holds only the two
//! 32-byte state roots, and every block travels with a witness bundle (not committed
//! by the header) carrying the spent records and an O(log n) sparse-Merkle witness
//! per touched key, each against the root left by the previous operation. Every
//! transaction gets exactly one outcome (accept, or reject with proof), so the
//! post-state root is a deterministic function of the pre-state root and the block.
//! Ordering is left to GnB-SMH over GhostDAG. No proof system is on this path.
//!
//! Must reproduce `reference/ledger_vectors.json`, including the error code of every
//! invalid case (see `tests/ledger_vectors.rs`).

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

pub const VERSION: u32 = 1;
pub const DEPTH: usize = 256;
pub const RECORD_LEN: usize = 49;
pub const HEADER_LEN: usize = 140;
// Placeholder limits until GnB's monetary and block-size parameters are fixed.
pub const MAX_MONEY: u64 = (1 << 63) - 1;
/// Per transaction.
pub const MAX_INPUTS: usize = 1024;
/// Per transaction.
pub const MAX_OUTPUTS: usize = 1024;
/// Per authorization entry (a hybrid key + signature is about 8.3 KB).
pub const MAX_AUTH_LEN: usize = 16_384;
/// Per block.
pub const MAX_TXS: usize = 65_536;
/// Per block: inputs + outputs of all transactions, i.e. witnesses to check.
pub const MAX_BLOCK_KEYS: usize = 16_384;
/// Per block: sum of transaction wire sizes.
pub const MAX_BLOCK_TX_BYTES: usize = 4_000_000;
pub const MAX_COINBASE_EXTRA: usize = 100;
pub const COINBASE_MATURITY: u64 = 100;

pub const TX_REGULAR: u8 = 0;
pub const TX_COINBASE: u8 = 1;

pub const ACCEPT: u8 = 0;
pub const REJECT_MISSING_INPUT: u8 = 1;
pub const REJECT_OUTPUT_EXISTS: u8 = 2;
pub const REJECT_CONTEXT: u8 = 3;

pub type Hash = [u8; 32];
pub const EMPTY: Hash = [0u8; 32];

const LABEL: &[u8] = b"GNB-LEDGER-v1/";

// ------------------------------------------------------------------------------ errors

/// Error codes shared with the Python reference; vectors pin them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    Header,
    Target,
    Pow,
    TxRoot,
    Isolation,
    WitnessFormat,
    NoncanonicalProof,
    WitnessMismatch,
    AcceptInvalid,
    RejectInvalid,
    Coinbase,
    StateCommitment,
}

impl ErrorCode {
    /// Permanent codes prove the committed block is invalid. The others mean the body or
    /// witness received does not fit the header: penalize the peer and fetch again.
    pub fn is_permanent(self) -> bool {
        matches!(
            self,
            ErrorCode::Header
                | ErrorCode::Target
                | ErrorCode::Pow
                | ErrorCode::Isolation
                | ErrorCode::Coinbase
                | ErrorCode::StateCommitment
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::Header => "header",
            ErrorCode::Target => "target",
            ErrorCode::Pow => "pow",
            ErrorCode::TxRoot => "tx-root",
            ErrorCode::Isolation => "isolation",
            ErrorCode::WitnessFormat => "witness-format",
            ErrorCode::NoncanonicalProof => "noncanonical-proof",
            ErrorCode::WitnessMismatch => "witness-mismatch",
            ErrorCode::AcceptInvalid => "accept-invalid",
            ErrorCode::RejectInvalid => "reject-invalid",
            ErrorCode::Coinbase => "coinbase",
            ErrorCode::StateCommitment => "state-commitment",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvalidBlock {
    pub code: ErrorCode,
    pub detail: &'static str,
}

impl std::fmt::Display for InvalidBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.detail)
    }
}

impl std::error::Error for InvalidBlock {}

fn err<T>(code: ErrorCode, detail: &'static str) -> Result<T, InvalidBlock> {
    Err(InvalidBlock { code, detail })
}

// ------------------------------------------------------------------------------ hashing

/// SHAKE-256 rate in bytes.
const RATE: usize = 136;

/// H(label, parts) = SHAKE256(enc("GNB-LEDGER-v1/" || label) || parts, 32).
///
/// Inputs shorter than one rate block (every tree, leaf, key and state hash) are
/// padded and permuted directly: one Keccak-f[1600] call, no hasher state. The
/// result is plain FIPS 202 SHAKE256; the unit test `fast_path_is_fips202` checks it.
fn h(label: &[u8], parts: &[&[u8]]) -> Hash {
    let prefix_len = (LABEL.len() + label.len()) as u32;
    let total = 4 + LABEL.len() + label.len() + parts.iter().map(|p| p.len()).sum::<usize>();
    if total < RATE {
        let mut block = [0u8; RATE];
        let mut pos = 0;
        for piece in [&prefix_len.to_le_bytes()[..], LABEL, label].into_iter().chain(parts.iter().copied()) {
            block[pos..pos + piece.len()].copy_from_slice(piece);
            pos += piece.len();
        }
        block[pos] ^= 0x1F; // SHAKE domain bits + first padding bit
        block[RATE - 1] ^= 0x80; // last padding bit
        let mut st = [0u64; 25];
        for (lane, chunk) in st.iter_mut().zip(block.chunks_exact(8)) {
            *lane ^= u64::from_le_bytes(chunk.try_into().unwrap());
        }
        keccak::f1600(&mut st);
        let mut out = [0u8; 32];
        for (chunk, lane) in out.chunks_exact_mut(8).zip(st.iter()) {
            chunk.copy_from_slice(&lane.to_le_bytes());
        }
        return out;
    }
    let mut s = Shake256::default();
    s.update(&prefix_len.to_le_bytes());
    s.update(LABEL);
    s.update(label);
    for p in parts {
        s.update(p);
    }
    let mut out = [0u8; 32];
    s.finalize_xof().read(&mut out);
    out
}

pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    h(b"node", &[left, right])
}

pub fn leaf_hash(key: &Hash, value: &Hash) -> Hash {
    h(b"leaf", &[key, value])
}

/// DEFAULTS[h]: root of an empty subtree of height h; DEFAULTS[256] is the empty root.
pub fn defaults() -> &'static [Hash; DEPTH + 1] {
    static D: OnceLock<[Hash; DEPTH + 1]> = OnceLock::new();
    D.get_or_init(|| {
        let mut d = [EMPTY; DEPTH + 1];
        for i in 0..DEPTH {
            d[i + 1] = node_hash(&d[i], &d[i]);
        }
        d
    })
}

pub fn empty_root() -> Hash {
    defaults()[DEPTH]
}

// ------------------------------------------------------------------------------ sparse Merkle tree

/// Bit of `key` that decides whether the path node at height `h` is a right child:
/// bit (255 - h) counted from the most significant bit of key[0].
pub fn path_bit(key: &Hash, h: usize) -> u8 {
    let i = 255 - h;
    (key[i >> 3] >> (7 - (i & 7))) & 1
}

pub type Siblings = Vec<Hash>; // always DEPTH entries, index = height

/// Root of the tree in which `key` holds `leaf` and its path has `siblings`.
pub fn root_from(key: &Hash, leaf: &Hash, siblings: &[Hash]) -> Hash {
    debug_assert_eq!(siblings.len(), DEPTH);
    let d = defaults();
    let mut cur = *leaf;
    for (hgt, s) in siblings.iter().enumerate() {
        cur = if cur == d[hgt] && *s == d[hgt] {
            d[hgt + 1]
        } else if path_bit(key, hgt) == 0 {
            node_hash(&cur, s)
        } else {
            node_hash(s, &cur)
        };
    }
    cur
}

/// 32-byte bitmap (bit h set iff sibling h is not DEFAULTS[h]; byte h>>3, bit h&7 from
/// the least significant) followed by the non-default siblings in increasing h.
pub fn encode_proof(siblings: &[Hash]) -> Vec<u8> {
    let d = defaults();
    let mut bitmap = [0u8; 32];
    let mut body = Vec::new();
    for (hgt, s) in siblings.iter().enumerate() {
        if *s != d[hgt] {
            bitmap[hgt >> 3] |= 1 << (hgt & 7);
            body.extend_from_slice(s);
        }
    }
    let mut out = bitmap.to_vec();
    out.extend_from_slice(&body);
    out
}

/// Strict decoder: a listed sibling equal to its default is rejected.
pub fn decode_proof(buf: &[u8], off: usize) -> Result<(Siblings, usize), InvalidBlock> {
    if buf.len() < off || buf.len() - off < 32 {
        return err(ErrorCode::WitnessFormat, "truncated proof bitmap");
    }
    let d = defaults();
    let bitmap = &buf[off..off + 32];
    let mut pos = off + 32;
    let mut siblings = Vec::with_capacity(DEPTH);
    for (hgt, default) in d.iter().enumerate().take(DEPTH) {
        if (bitmap[hgt >> 3] >> (hgt & 7)) & 1 == 1 {
            if buf.len() - pos < 32 {
                return err(ErrorCode::WitnessFormat, "truncated proof sibling");
            }
            let mut s = [0u8; 32];
            s.copy_from_slice(&buf[pos..pos + 32]);
            if s == *default {
                return err(ErrorCode::NoncanonicalProof, "default sibling listed");
            }
            siblings.push(s);
            pos += 32;
        } else {
            siblings.push(*default);
        }
    }
    Ok((siblings, pos))
}

/// 256-bit big-endian right shift, used for node ids (height, key >> height).
fn shr(k: &Hash, by: usize) -> Hash {
    let mut out = [0u8; 32];
    if by >= 256 {
        return out;
    }
    let (bytes, bits) = (by / 8, by % 8);
    for i in bytes..32 {
        let src = i - bytes;
        let mut v = k[src] >> bits;
        if bits > 0 && src > 0 {
            v |= k[src - 1] << (8 - bits);
        }
        out[i] = v;
    }
    out
}

/// Full tree for block producers and tests. Stores every non-default node on every
/// path, so it is for small sets only.
#[derive(Clone, Default)]
pub struct SparseMerkleTree {
    nodes: HashMap<(u16, Hash), Hash>,
}

impl SparseMerkleTree {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn root(&self) -> Hash {
        *self.nodes.get(&(DEPTH as u16, EMPTY)).unwrap_or(&empty_root())
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn siblings(&self, key: &Hash) -> Siblings {
        let d = defaults();
        (0..DEPTH)
            .map(|hgt| {
                let mut id = shr(key, hgt);
                id[31] ^= 1;
                *self.nodes.get(&(hgt as u16, id)).unwrap_or(&d[hgt])
            })
            .collect()
    }

    pub fn proof(&self, key: &Hash) -> Vec<u8> {
        encode_proof(&self.siblings(key))
    }

    /// Set the leaf at `key` (EMPTY deletes) and update the path to the root.
    pub fn set(&mut self, key: &Hash, leaf: &Hash) {
        let d = defaults();
        let mut cur = *leaf;
        self.put(0, *key, cur);
        for hgt in 0..DEPTH {
            let mut sib_id = shr(key, hgt);
            let right = sib_id[31] & 1 == 1;
            sib_id[31] ^= 1;
            let s = *self.nodes.get(&(hgt as u16, sib_id)).unwrap_or(&d[hgt]);
            cur = if cur == d[hgt] && s == d[hgt] {
                d[hgt + 1]
            } else if !right {
                node_hash(&cur, &s)
            } else {
                node_hash(&s, &cur)
            };
            self.put(hgt + 1, shr(key, hgt + 1), cur);
        }
    }

    fn put(&mut self, hgt: usize, prefix: Hash, value: Hash) {
        if value == defaults()[hgt] {
            self.nodes.remove(&(hgt as u16, prefix));
        } else {
            self.nodes.insert((hgt as u16, prefix), value);
        }
    }
}

// ------------------------------------------------------------------------------ transactions

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Outpoint {
    pub txid: Hash,
    pub vout: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxOut {
    pub amount: u64,
    pub owner: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tx {
    pub kind: u8,
    pub inputs: Vec<Outpoint>,
    pub outputs: Vec<TxOut>,
    /// Coinbase only: must equal the block height.
    pub height: u64,
    /// Coinbase only.
    pub extra: Vec<u8>,
    /// One entry per input; not covered by the txid.
    pub auth: Vec<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UtxoRecord {
    pub amount: u64,
    pub owner: Hash,
    pub height: u64,
    pub coinbase: bool,
}

impl UtxoRecord {
    pub fn encode(&self) -> [u8; RECORD_LEN] {
        let mut b = [0u8; RECORD_LEN];
        b[0..8].copy_from_slice(&self.amount.to_le_bytes());
        b[8..40].copy_from_slice(&self.owner);
        b[40..48].copy_from_slice(&self.height.to_le_bytes());
        b[48] = self.coinbase as u8;
        b
    }

    pub fn decode(b: &[u8]) -> Result<Self, InvalidBlock> {
        if b.len() != RECORD_LEN {
            return err(ErrorCode::WitnessFormat, "record length");
        }
        if b[48] > 1 {
            return err(ErrorCode::WitnessFormat, "record coinbase flag");
        }
        Ok(UtxoRecord {
            amount: u64::from_le_bytes(b[0..8].try_into().unwrap()),
            owner: b[8..40].try_into().unwrap(),
            height: u64::from_le_bytes(b[40..48].try_into().unwrap()),
            coinbase: b[48] == 1,
        })
    }
}

fn put_enc(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    out.extend_from_slice(b);
}

/// Canonical encoding covered by the txid (no authorization data).
pub fn tx_bytes(tx: &Tx) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.push(tx.kind);
    if tx.kind == TX_COINBASE {
        out.extend_from_slice(&tx.height.to_le_bytes());
        put_enc(&mut out, &tx.extra);
    }
    out.extend_from_slice(&(tx.inputs.len() as u32).to_le_bytes());
    for op in &tx.inputs {
        out.extend_from_slice(&op.txid);
        out.extend_from_slice(&op.vout.to_le_bytes());
    }
    out.extend_from_slice(&(tx.outputs.len() as u32).to_le_bytes());
    for o in &tx.outputs {
        out.extend_from_slice(&o.amount.to_le_bytes());
        out.extend_from_slice(&o.owner);
    }
    out
}

/// Wire encoding: tx_bytes || u32le(count) || enc(auth_i)...
pub fn tx_wire(tx: &Tx) -> Vec<u8> {
    let mut out = tx_bytes(tx);
    out.extend_from_slice(&(tx.auth.len() as u32).to_le_bytes());
    for a in &tx.auth {
        put_enc(&mut out, a);
    }
    out
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    code: ErrorCode,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8], code: ErrorCode) -> Self {
        Reader { buf, pos: 0, code }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], InvalidBlock> {
        if self.buf.len() - self.pos < n {
            return err(self.code, "truncated");
        }
        let b = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(b)
    }

    fn u8(&mut self) -> Result<u8, InvalidBlock> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, InvalidBlock> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, InvalidBlock> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn hash(&mut self) -> Result<Hash, InvalidBlock> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    fn proof(&mut self) -> Result<Siblings, InvalidBlock> {
        let (sibs, end) = decode_proof(self.buf, self.pos)?;
        self.pos = end;
        Ok(sibs)
    }

    fn done(&self) -> bool {
        self.pos == self.buf.len()
    }
}

/// Strict decoder; any malformed or trailing byte is an isolation error.
pub fn decode_tx_wire(buf: &[u8]) -> Result<Tx, InvalidBlock> {
    let mut r = Reader::new(buf, ErrorCode::Isolation);
    if r.u32()? != VERSION {
        return err(ErrorCode::Isolation, "tx version");
    }
    let kind = r.u8()?;
    if kind != TX_REGULAR && kind != TX_COINBASE {
        return err(ErrorCode::Isolation, "tx kind");
    }
    let (mut height, mut extra) = (0, Vec::new());
    if kind == TX_COINBASE {
        height = r.u64()?;
        let n = r.u32()? as usize;
        extra = r.take(n)?.to_vec();
    }
    let n_in = r.u32()? as usize;
    if n_in > MAX_INPUTS {
        return err(ErrorCode::Isolation, "too many inputs");
    }
    let mut inputs = Vec::with_capacity(n_in);
    for _ in 0..n_in {
        let txid = r.hash()?;
        let vout = r.u32()?;
        inputs.push(Outpoint { txid, vout });
    }
    let n_out = r.u32()? as usize;
    if n_out > MAX_OUTPUTS {
        return err(ErrorCode::Isolation, "too many outputs");
    }
    let mut outputs = Vec::with_capacity(n_out);
    for _ in 0..n_out {
        let amount = r.u64()?;
        let owner = r.hash()?;
        outputs.push(TxOut { amount, owner });
    }
    let n_auth = r.u32()? as usize;
    if n_auth > MAX_INPUTS {
        return err(ErrorCode::Isolation, "too many auth entries");
    }
    let mut auth = Vec::with_capacity(n_auth);
    for _ in 0..n_auth {
        let n = r.u32()? as usize;
        if n > MAX_AUTH_LEN {
            return err(ErrorCode::Isolation, "auth entry too long");
        }
        auth.push(r.take(n)?.to_vec());
    }
    if !r.done() {
        return err(ErrorCode::Isolation, "trailing bytes");
    }
    Ok(Tx { kind, inputs, outputs, height, extra, auth })
}

/// Identity of the transfer (no authorization data): what outpoints refer to.
pub fn txid(tx: &Tx) -> Hash {
    h(b"txid", &[&tx_bytes(tx)])
}

/// Identity of the exact wire bytes, authorization included: what the header commits to.
pub fn wtxid(wire: &[u8]) -> Hash {
    h(b"wtxid", &[wire])
}

pub fn outpoint_key(txid: &Hash, vout: u32) -> Hash {
    h(b"outpoint", &[txid, &vout.to_le_bytes()])
}

pub fn utxo_value(record: &UtxoRecord) -> Hash {
    h(b"utxo", &[&record.encode()])
}

pub fn utxo_leaf(key: &Hash, record: &UtxoRecord) -> Hash {
    leaf_hash(key, &utxo_value(record))
}

/// Context-free rules. A block containing a transaction that fails them is invalid.
pub fn check_tx_isolation(tx: &Tx) -> Result<(), InvalidBlock> {
    let iso = |d| err(ErrorCode::Isolation, d);
    if tx.kind != TX_REGULAR && tx.kind != TX_COINBASE {
        return iso("tx kind");
    }
    if tx.outputs.is_empty() || tx.outputs.len() > MAX_OUTPUTS {
        return iso("output count");
    }
    let mut total: u128 = 0;
    for o in &tx.outputs {
        if o.amount > MAX_MONEY {
            return iso("output");
        }
        total += o.amount as u128;
    }
    if total > MAX_MONEY as u128 {
        return iso("output sum");
    }
    if tx.kind == TX_REGULAR {
        if tx.inputs.is_empty() || tx.inputs.len() > MAX_INPUTS {
            return iso("input count");
        }
        let unique: HashSet<&Outpoint> = tx.inputs.iter().collect();
        if unique.len() != tx.inputs.len() {
            return iso("duplicate input");
        }
        if tx.auth.len() != tx.inputs.len() {
            return iso("auth count");
        }
        if tx.auth.iter().any(|a| a.len() > MAX_AUTH_LEN) {
            return iso("auth entry too long");
        }
        if tx.height != 0 || !tx.extra.is_empty() {
            return iso("coinbase fields on a regular tx");
        }
    } else {
        if !tx.inputs.is_empty() || !tx.auth.is_empty() {
            return iso("coinbase with inputs");
        }
        if tx.extra.len() > MAX_COINBASE_EXTRA {
            return iso("coinbase extra");
        }
    }
    Ok(())
}

// ------------------------------------------------------------------------------ authorization

pub type AuthFn = fn(&Tx, &[UtxoRecord]) -> bool;

/// TEST ONLY: owner of outputs spendable by revealing `secret`.
pub fn test_owner(secret: &[u8]) -> Hash {
    h(b"test-owner", &[secret])
}

/// TEST ONLY, NOT SECURE: input i is authorized iff auth[i] hashes to its owner. It binds
/// nothing about the transaction. GnB uses hybrid ML-DSA-65 || Falcon-1024 signatures.
pub fn test_preimage_auth(tx: &Tx, records: &[UtxoRecord]) -> bool {
    tx.auth.len() == records.len()
        && tx.auth.iter().zip(records).all(|(a, r)| test_owner(a) == r.owner)
}

// ------------------------------------------------------------------------------ state transition

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct State {
    pub utxo_root: Hash,
    /// Reserved for the shielded pool; unchanged in v1.
    pub nullifier_root: Hash,
}

impl State {
    pub fn genesis() -> Self {
        State { utxo_root: empty_root(), nullifier_root: empty_root() }
    }

    pub fn commitment(&self) -> Hash {
        h(b"state", &[&self.utxo_root, &self.nullifier_root])
    }
}

#[derive(Clone, Copy)]
pub struct Context {
    pub height: u64,
    pub subsidy: u64,
    pub coinbase_maturity: u64,
    pub auth: AuthFn,
}

/// Fee if the context rules pass (maturity, value, authorization), else None.
pub fn context_fee(tx: &Tx, records: &[UtxoRecord], ctx: &Context) -> Option<u128> {
    for r in records {
        if r.coinbase && (ctx.height as u128) < r.height as u128 + ctx.coinbase_maturity as u128 {
            return None;
        }
    }
    let total_in: u128 = records.iter().map(|r| r.amount as u128).sum();
    let total_out: u128 = tx.outputs.iter().map(|o| o.amount as u128).sum();
    if total_in < total_out || !(ctx.auth)(tx, records) {
        return None;
    }
    Some(total_in - total_out)
}

pub fn check_block_txs(txs: &[Tx], ctx: &Context) -> Result<(), InvalidBlock> {
    if txs.is_empty() || txs.len() > MAX_TXS {
        return err(ErrorCode::Isolation, "transaction count");
    }
    for (i, tx) in txs.iter().enumerate() {
        check_tx_isolation(tx)?;
        if (tx.kind == TX_COINBASE) != (i == 0) {
            return err(ErrorCode::Isolation, "coinbase must be first and only first");
        }
    }
    let keys: usize = txs.iter().map(|t| t.inputs.len() + t.outputs.len()).sum();
    if keys > MAX_BLOCK_KEYS {
        return err(ErrorCode::Isolation, "too many inputs and outputs in the block");
    }
    if txs[0].height != ctx.height {
        return err(ErrorCode::Isolation, "coinbase height");
    }
    Ok(())
}

fn check_present(root: &Hash, op: &Outpoint, rec: &[u8], sibs: &[Hash]) -> Result<Hash, InvalidBlock> {
    let key = outpoint_key(&op.txid, op.vout);
    let value = h(b"utxo", &[rec]);
    if root_from(&key, &leaf_hash(&key, &value), sibs) != *root {
        return err(ErrorCode::WitnessMismatch, "spent output not in the tree");
    }
    Ok(key)
}

fn create(root: &Hash, tid: &Hash, vout: u32, record: &UtxoRecord, sibs: &[Hash]) -> Result<Hash, InvalidBlock> {
    let key = outpoint_key(tid, vout);
    if root_from(&key, &EMPTY, sibs) != *root {
        return err(ErrorCode::WitnessMismatch, "new output key already present");
    }
    Ok(root_from(&key, &utxo_leaf(&key, record), sibs))
}

/// Stateless transition. Regular transactions in order, then the coinbase (txs[0])
/// last so it can claim the fees accepted in the same block.
pub fn apply_block_txs(state: &State, txs: &[Tx], witness: &[u8], ctx: &Context) -> Result<(State, Vec<bool>), InvalidBlock> {
    check_block_txs(txs, ctx)?;
    let mut r = Reader::new(witness, ErrorCode::WitnessFormat);
    if r.u32()? as usize != txs.len() {
        return err(ErrorCode::WitnessFormat, "entry count");
    }
    let mut root = state.utxo_root;
    let mut fees: u128 = 0;
    let mut accepted = vec![false; txs.len()];

    for (idx, tx) in txs.iter().enumerate().skip(1) {
        let tid = txid(tx);
        match r.u8()? {
            ACCEPT => {
                let mut records = Vec::with_capacity(tx.inputs.len());
                for op in &tx.inputs {
                    let rec = r.take(RECORD_LEN)?;
                    records.push(UtxoRecord::decode(rec)?);
                    let sibs = r.proof()?;
                    let key = check_present(&root, op, rec, &sibs)?;
                    root = root_from(&key, &EMPTY, &sibs);
                }
                let fee = match context_fee(tx, &records, ctx) {
                    Some(f) => f,
                    None => return err(ErrorCode::AcceptInvalid, "accepted tx fails context rules"),
                };
                for (o, out) in tx.outputs.iter().enumerate() {
                    let sibs = r.proof()?;
                    let rec = UtxoRecord { amount: out.amount, owner: out.owner, height: ctx.height, coinbase: false };
                    root = create(&root, &tid, o as u32, &rec, &sibs)?;
                }
                fees += fee;
                accepted[idx] = true;
            }
            REJECT_MISSING_INPUT => {
                let i = r.u32()? as usize;
                if i >= tx.inputs.len() {
                    return err(ErrorCode::WitnessFormat, "input index");
                }
                let sibs = r.proof()?;
                let key = outpoint_key(&tx.inputs[i].txid, tx.inputs[i].vout);
                if root_from(&key, &EMPTY, &sibs) != root {
                    return err(ErrorCode::WitnessMismatch, "claimed-missing input is present");
                }
            }
            REJECT_OUTPUT_EXISTS => {
                let o = r.u32()? as usize;
                if o >= tx.outputs.len() {
                    return err(ErrorCode::WitnessFormat, "output index");
                }
                let value = r.hash()?;
                let sibs = r.proof()?;
                let key = outpoint_key(&tid, o as u32);
                if root_from(&key, &leaf_hash(&key, &value), &sibs) != root {
                    return err(ErrorCode::WitnessMismatch, "claimed-existing output is absent");
                }
            }
            REJECT_CONTEXT => {
                let mut records = Vec::with_capacity(tx.inputs.len());
                for op in &tx.inputs {
                    let rec = r.take(RECORD_LEN)?;
                    records.push(UtxoRecord::decode(rec)?);
                    let sibs = r.proof()?;
                    check_present(&root, op, rec, &sibs)?;
                }
                if context_fee(tx, &records, ctx).is_some() {
                    return err(ErrorCode::RejectInvalid, "rejected tx passes context rules");
                }
            }
            _ => return err(ErrorCode::WitnessFormat, "unknown tag"),
        }
    }

    let cb = &txs[0];
    let tag = r.u8()?;
    if tag != ACCEPT && tag != REJECT_OUTPUT_EXISTS {
        return err(ErrorCode::WitnessFormat, "coinbase entry must be ACCEPT or a collision proof");
    }
    // Every regular outcome above is proven, so `fees` is forced: an overclaim is the block's fault.
    let claimed: u128 = cb.outputs.iter().map(|o| o.amount as u128).sum();
    if claimed > ctx.subsidy as u128 + fees {
        return err(ErrorCode::Coinbase, "claims more than subsidy plus fees");
    }
    let cid = txid(cb);
    if tag == REJECT_OUTPUT_EXISTS {
        // A coinbase whose output key is already taken can never be applied; this entry lets a
        // relaying node prove it, so the block is marked invalid rather than its relayers blamed.
        let o = r.u32()? as usize;
        if o >= cb.outputs.len() {
            return err(ErrorCode::WitnessFormat, "output index");
        }
        let value = r.hash()?;
        let sibs = r.proof()?;
        let key = outpoint_key(&cid, o as u32);
        if root_from(&key, &leaf_hash(&key, &value), &sibs) != root {
            return err(ErrorCode::WitnessMismatch, "claimed-existing coinbase output is absent");
        }
        return err(ErrorCode::Coinbase, "coinbase output already exists");
    }
    for (o, out) in cb.outputs.iter().enumerate() {
        let sibs = r.proof()?;
        let rec = UtxoRecord { amount: out.amount, owner: out.owner, height: ctx.height, coinbase: true };
        root = create(&root, &cid, o as u32, &rec, &sibs)?;
    }
    accepted[0] = true;
    if !r.done() {
        return err(ErrorCode::WitnessFormat, "trailing bytes");
    }
    Ok((State { utxo_root: root, nullifier_root: state.nullifier_root }, accepted))
}

// ------------------------------------------------------------------------------ header and block

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub version: u32,
    /// Commitment to the GhostDAG parents (consensus layer).
    pub parents_root: Hash,
    pub tx_root: Hash,
    pub state_commitment: Hash,
    pub timestamp: u64,
    /// Big-endian 256-bit target.
    pub target: Hash,
}

impl Header {
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[0..4].copy_from_slice(&self.version.to_le_bytes());
        b[4..36].copy_from_slice(&self.parents_root);
        b[36..68].copy_from_slice(&self.tx_root);
        b[68..100].copy_from_slice(&self.state_commitment);
        b[100..108].copy_from_slice(&self.timestamp.to_le_bytes());
        b[108..140].copy_from_slice(&self.target);
        b
    }

    pub fn decode(b: &[u8]) -> Result<Self, InvalidBlock> {
        if b.len() != HEADER_LEN {
            return err(ErrorCode::Header, "length");
        }
        Ok(Header {
            version: u32::from_le_bytes(b[0..4].try_into().unwrap()),
            parents_root: b[4..36].try_into().unwrap(),
            tx_root: b[36..68].try_into().unwrap(),
            state_commitment: b[68..100].try_into().unwrap(),
            timestamp: u64::from_le_bytes(b[100..108].try_into().unwrap()),
            target: b[108..140].try_into().unwrap(),
        })
    }
}

/// Binary tree over wtxids (so authorization is committed), odd node promoted unchanged,
/// count committed at the top.
pub fn tx_root(wtxids: &[Hash]) -> Hash {
    let mut level: Vec<Hash> = wtxids.to_vec();
    while level.len() > 1 {
        let mut next: Vec<Hash> = level.chunks_exact(2).map(|p| h(b"txnode", &[&p[0], &p[1]])).collect();
        if level.len() % 2 == 1 {
            next.push(*level.last().unwrap());
        }
        level = next;
    }
    let top = level.first().copied().unwrap_or(EMPTY);
    h(b"txroot", &[&(wtxids.len() as u32).to_le_bytes(), &top])
}

pub fn block_id(header: &[u8], nonce: u64) -> Hash {
    h(b"block", &[header, &nonce.to_le_bytes()])
}

/// Header stage for consensus; every failure is permanent. `sp` is reused across calls and
/// must be the canonical size (panics otherwise: a wrong size would make valid blocks look
/// invalid, and that verdict is cached). Nodes cache the result per block id, so a header
/// replayed with a junk body or witness costs no second GnB-SMH evaluation.
pub fn validate_header(header: &[u8], nonce: u64, sp: &mut crate::Scratchpad, max_target: &Hash) -> Result<Header, InvalidBlock> {
    assert_eq!(sp.log2_n(), crate::LOG2_N, "consensus header validation requires the canonical scratchpad");
    validate_header_any_size(header, nonce, sp, max_target)
}

/// Same checks at whatever scratchpad size `sp` has. For tests and experiments only.
pub fn validate_header_any_size(header: &[u8], nonce: u64, sp: &mut crate::Scratchpad, max_target: &Hash) -> Result<Header, InvalidBlock> {
    let hdr = Header::decode(header)?;
    if hdr.version != VERSION {
        return err(ErrorCode::Header, "version");
    }
    if hdr.target == EMPTY || hdr.target > *max_target {
        return err(ErrorCode::Target, "out of range");
    }
    let out = crate::hash_with(sp, header, nonce);
    if !crate::meets_target(&out, &hdr.target) {
        return err(ErrorCode::Pow, "above target");
    }
    Ok(hdr)
}

/// Body stage. The transactions must hash to the header's tx_root before anything in them
/// is judged: a mismatch is transient, a committed body that breaks a rule is permanent.
pub fn validate_body<W: AsRef<[u8]>>(
    parent: &State,
    hdr: &Header,
    tx_wires: &[W],
    witness: &[u8],
    ctx: &Context,
) -> Result<(State, Vec<bool>), InvalidBlock> {
    let ids: Vec<Hash> = tx_wires.iter().map(|w| wtxid(w.as_ref())).collect();
    if tx_root(&ids) != hdr.tx_root {
        return err(ErrorCode::TxRoot, "mismatch");
    }
    let bytes: usize = tx_wires.iter().map(|w| w.as_ref().len()).sum();
    if bytes > MAX_BLOCK_TX_BYTES {
        return err(ErrorCode::Isolation, "block size");
    }
    let txs = tx_wires.iter().map(|w| decode_tx_wire(w.as_ref())).collect::<Result<Vec<_>, _>>()?;
    let (state, accepted) = apply_block_txs(parent, &txs, witness, ctx)?;
    if state.commitment() != hdr.state_commitment {
        return err(ErrorCode::StateCommitment, "mismatch");
    }
    Ok((state, accepted))
}

/// Header stage (canonical size), then body stage.
#[allow(clippy::too_many_arguments)]
pub fn validate_block<W: AsRef<[u8]>>(
    parent: &State,
    header: &[u8],
    nonce: u64,
    tx_wires: &[W],
    witness: &[u8],
    ctx: &Context,
    sp: &mut crate::Scratchpad,
    max_target: &Hash,
) -> Result<(State, Vec<bool>), InvalidBlock> {
    let hdr = validate_header(header, nonce, sp, max_target)?;
    validate_body(parent, &hdr, tx_wires, witness, ctx)
}

/// `validate_block` at whatever scratchpad size `sp` has. For tests and experiments only.
#[allow(clippy::too_many_arguments)]
pub fn validate_block_any_size<W: AsRef<[u8]>>(
    parent: &State,
    header: &[u8],
    nonce: u64,
    tx_wires: &[W],
    witness: &[u8],
    ctx: &Context,
    sp: &mut crate::Scratchpad,
    max_target: &Hash,
) -> Result<(State, Vec<bool>), InvalidBlock> {
    let hdr = validate_header_any_size(header, nonce, sp, max_target)?;
    validate_body(parent, &hdr, tx_wires, witness, ctx)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(i: u64) -> Hash {
        h(b"unit-key", &[&i.to_le_bytes()])
    }

    #[test]
    fn fast_path_is_fips202() {
        // Every input length around the one-block boundary, against the sha3 crate.
        for n in 0..200usize {
            let data: Vec<u8> = (0..n).map(|i| (i * 31 + 7) as u8).collect();
            let fast = h(b"x", &[&data]);
            let mut s = Shake256::default();
            let label_len = (LABEL.len() + 1) as u32;
            s.update(&label_len.to_le_bytes());
            s.update(LABEL);
            s.update(b"x");
            s.update(&data);
            let mut expected = [0u8; 32];
            s.finalize_xof().read(&mut expected);
            assert_eq!(fast, expected, "data length {n}");
        }
    }

    #[test]
    fn shr_matches_path_bits() {
        let k = key(42);
        for hgt in 0..DEPTH {
            assert_eq!(shr(&k, hgt)[31] & 1, path_bit(&k, hgt), "height {hgt}");
        }
        assert_eq!(shr(&k, 256), EMPTY);
    }

    #[test]
    fn tree_proofs_track_random_operations() {
        let mut t = SparseMerkleTree::new();
        let mut live: HashMap<Hash, Hash> = HashMap::new();
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        for step in 0..300u64 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let k = key(x % 90);
            let (sibs, end) = decode_proof(&t.proof(&k), 0).unwrap();
            assert_eq!(end, t.proof(&k).len());
            let current = live.get(&k).map(|v| leaf_hash(&k, v)).unwrap_or(EMPTY);
            assert_eq!(root_from(&k, &current, &sibs), t.root(), "step {step}");
            let new_leaf = if live.contains_key(&k) && x % 3 == 0 {
                live.remove(&k);
                EMPTY
            } else {
                let v = h(b"unit-value", &[&step.to_le_bytes()]);
                live.insert(k, v);
                leaf_hash(&k, &v)
            };
            let expected = root_from(&k, &new_leaf, &sibs);
            t.set(&k, &new_leaf);
            assert_eq!(t.root(), expected, "step {step}");
        }
        for k in live.keys().copied().collect::<Vec<_>>() {
            t.set(&k, &EMPTY);
        }
        assert_eq!(t.root(), empty_root());
        assert_eq!(t.node_count(), 0);
    }

    #[test]
    fn noncanonical_and_truncated_proofs_are_rejected() {
        let mut t = SparseMerkleTree::new();
        let (a, b) = (key(1), key(2));
        t.set(&a, &leaf_hash(&a, &EMPTY));
        t.set(&b, &leaf_hash(&b, &EMPTY));
        let p = t.proof(&a);
        assert!(p.len() > 32);
        for cut in [0, 31, p.len() - 1] {
            assert_eq!(decode_proof(&p[..cut], 0).unwrap_err().code, ErrorCode::WitnessFormat);
        }
        // list a default sibling at height 0 explicitly
        let (sibs, _) = decode_proof(&p, 0).unwrap();
        let h0 = (0..DEPTH).find(|&i| sibs[i] == defaults()[i]).unwrap();
        let mut bad = p[..32].to_vec();
        bad[h0 >> 3] |= 1 << (h0 & 7);
        for (i, s) in sibs.iter().enumerate() {
            if *s != defaults()[i] || i == h0 {
                bad.extend_from_slice(s);
            }
        }
        assert_eq!(decode_proof(&bad, 0).unwrap_err().code, ErrorCode::NoncanonicalProof);
    }

    fn ctx() -> Context {
        Context { height: 1, subsidy: 0, coinbase_maturity: COINBASE_MATURITY, auth: test_preimage_auth }
    }

    fn cb() -> Tx {
        Tx { kind: TX_COINBASE, inputs: vec![], outputs: vec![TxOut { amount: 0, owner: EMPTY }], height: 1, extra: vec![], auth: vec![] }
    }

    #[test]
    fn block_key_limit() {
        let per_tx = MAX_OUTPUTS + 1;
        let n = MAX_BLOCK_KEYS / per_tx + 1;
        let mut txs = vec![cb()];
        for i in 0..n {
            txs.push(Tx {
                kind: TX_REGULAR,
                inputs: vec![Outpoint { txid: [i as u8; 32], vout: 0 }],
                outputs: vec![TxOut { amount: 0, owner: EMPTY }; MAX_OUTPUTS],
                height: 0,
                extra: vec![],
                auth: vec![vec![]],
            });
        }
        let e = check_block_txs(&txs, &ctx()).unwrap_err();
        assert_eq!(e.code, ErrorCode::Isolation);
        assert!(e.code.is_permanent());
        txs.pop();
        check_block_txs(&txs, &ctx()).unwrap();
    }

    #[test]
    fn auth_entry_length() {
        let mut tx = Tx {
            kind: TX_REGULAR,
            inputs: vec![Outpoint { txid: EMPTY, vout: 0 }],
            outputs: vec![TxOut { amount: 1, owner: EMPTY }],
            height: 0,
            extra: vec![],
            auth: vec![vec![0; MAX_AUTH_LEN]],
        };
        check_tx_isolation(&tx).unwrap();
        assert_eq!(decode_tx_wire(&tx_wire(&tx)).unwrap(), tx);
        tx.auth[0].push(0);
        assert_eq!(check_tx_isolation(&tx).unwrap_err().code, ErrorCode::Isolation);
        assert_eq!(decode_tx_wire(&tx_wire(&tx)).unwrap_err().code, ErrorCode::Isolation);
    }

    #[test]
    fn block_bytes_limit_is_checked_after_tx_root() {
        let filler = Tx {
            kind: TX_REGULAR,
            inputs: vec![Outpoint { txid: EMPTY, vout: 0 }],
            outputs: vec![TxOut { amount: 1, owner: EMPTY }],
            height: 0,
            extra: vec![],
            auth: vec![vec![0; MAX_AUTH_LEN]],
        };
        let mut wires = vec![tx_wire(&cb())];
        wires.extend(std::iter::repeat(tx_wire(&filler)).take(MAX_BLOCK_TX_BYTES / MAX_AUTH_LEN + 1));
        let ids: Vec<Hash> = wires.iter().map(|w| wtxid(w)).collect();
        let good = Header { version: 1, parents_root: EMPTY, tx_root: tx_root(&ids), state_commitment: EMPTY, timestamp: 0, target: [0x80; 32] };
        let e = validate_body(&State::genesis(), &good, &wires, &[], &ctx()).unwrap_err();
        assert_eq!((e.code, e.code.is_permanent()), (ErrorCode::Isolation, true));
        let wrong = Header { tx_root: EMPTY, ..good };
        let e = validate_body(&State::genesis(), &wrong, &wires, &[], &ctx()).unwrap_err();
        assert_eq!((e.code, e.code.is_permanent()), (ErrorCode::TxRoot, false));
    }

    #[test]
    #[should_panic(expected = "canonical scratchpad")]
    fn consensus_header_check_refuses_a_test_sized_scratchpad() {
        let mut sp = crate::Scratchpad::new(4);
        let _ = validate_header(&[0u8; HEADER_LEN], 0, &mut sp, &[0xff; 32]);
    }

    #[test]
    fn tx_wire_roundtrip_and_strictness() {
        let tx = Tx {
            kind: TX_REGULAR,
            inputs: vec![Outpoint { txid: key(1), vout: 3 }],
            outputs: vec![TxOut { amount: 5, owner: key(2) }],
            height: 0,
            extra: vec![],
            auth: vec![b"secret".to_vec()],
        };
        let w = tx_wire(&tx);
        assert_eq!(decode_tx_wire(&w).unwrap(), tx);
        let mut trailing = w.clone();
        trailing.push(0);
        assert_eq!(decode_tx_wire(&trailing).unwrap_err().code, ErrorCode::Isolation);
        assert_eq!(decode_tx_wire(&w[..w.len() - 1]).unwrap_err().code, ErrorCode::Isolation);
    }
}
