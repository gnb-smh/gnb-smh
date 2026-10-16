//! Shared pieces of the fuzz targets: a byte reader that turns the fuzzer's
//! input into structured values, and INDEPENDENT reference implementations of
//! the consensus encodings and hashes the targets compare the library with.
//!
//! The references are written from the specifications (`docs/CONSENSUS.md`,
//! the module documentation of `core::block_rules` / `core::sighash`,
//! `reference/*.py`), never by calling the library function they check. Where
//! a reference needs a primitive (SHA-256, SHA3-256) it uses the hash crates
//! directly.
#![allow(dead_code)]

use gnb_crypto::core::powit::PowitBody;
use gnb_crypto::core::{powit_height, Block, BlockHeader, Transaction, TxInput, TxOutput};
use sha2::{Digest as _, Sha256};
use sha3::Sha3_256;

// ── Input reader ─────────────────────────────────────────────────────────────

/// Reads structured values off the fuzz input; past the end every read
/// returns zeros, so any input decodes to some value.
pub struct Input<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Input<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Input { data, at: 0 }
    }
    pub fn is_empty(&self) -> bool {
        self.at >= self.data.len()
    }
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.at)
    }
    pub fn u8(&mut self) -> u8 {
        let b = self.data.get(self.at).copied().unwrap_or(0);
        self.at += 1;
        b
    }
    pub fn bool(&mut self) -> bool {
        self.u8() & 1 == 1
    }
    pub fn u16(&mut self) -> u16 {
        u16::from_le_bytes([self.u8(), self.u8()])
    }
    pub fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.arr::<4>())
    }
    pub fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.arr::<8>())
    }
    pub fn arr<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        for b in out.iter_mut() {
            *b = self.u8();
        }
        out
    }
    /// A value in `0..n` (`0` when `n == 0`).
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        (self.u16() as usize) % n
    }
    /// `len` bytes (zero-padded past the end).
    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.u8()).collect()
    }
    /// A length-prefixed byte string of at most `max` bytes.
    pub fn var_bytes(&mut self, max: usize) -> Vec<u8> {
        let n = self.below(max + 1);
        self.bytes(n)
    }
    /// Everything not read yet.
    pub fn rest(&mut self) -> &'a [u8] {
        let r = self.data.get(self.at..).unwrap_or(&[]);
        self.at = self.data.len();
        r
    }
}

/// A transaction generated from the input (bounded sizes).
pub fn gen_tx(inp: &mut Input, max_in: usize, max_out: usize, max_script: usize) -> Transaction {
    let n_in = inp.below(max_in + 1);
    let n_out = inp.below(max_out + 1);
    Transaction {
        version: inp.u32(),
        inputs: (0..n_in)
            .map(|_| TxInput {
                prev_txid: inp.arr(),
                prev_index: inp.u32(),
                script_sig: inp.var_bytes(max_script),
                sequence: inp.u32(),
            })
            .collect(),
        outputs: (0..n_out).map(|_| TxOutput { value: inp.u64(), script_pubkey: inp.var_bytes(max_script) }).collect(),
        locktime: inp.u32(),
    }
}

// ── Reference wire encoding (Bitcoin CompactSize varints) ────────────────────

pub fn ref_compact_size(out: &mut Vec<u8>, n: u64) {
    match n {
        0..=0xFC => out.push(n as u8),
        0xFD..=0xFFFF => {
            out.push(0xFD);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xFFFF_FFFF => {
            out.push(0xFE);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            out.push(0xFF);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

/// `Transaction::to_wire_bytes(with_script_sig)` from its specification.
pub fn ref_tx_wire(tx: &Transaction, with_script_sig: bool) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&tx.version.to_le_bytes());
    ref_compact_size(&mut out, tx.inputs.len() as u64);
    for i in &tx.inputs {
        out.extend_from_slice(&i.prev_txid);
        out.extend_from_slice(&i.prev_index.to_le_bytes());
        if with_script_sig {
            ref_compact_size(&mut out, i.script_sig.len() as u64);
            out.extend_from_slice(&i.script_sig);
        }
        out.extend_from_slice(&i.sequence.to_le_bytes());
    }
    ref_compact_size(&mut out, tx.outputs.len() as u64);
    for o in &tx.outputs {
        out.extend_from_slice(&o.value.to_le_bytes());
        ref_compact_size(&mut out, o.script_pubkey.len() as u64);
        out.extend_from_slice(&o.script_pubkey);
    }
    out.extend_from_slice(&tx.locktime.to_le_bytes());
    out
}

/// `BlockHeader::to_wire_bytes(blue_score, height)` from its specification.
pub fn ref_header_wire(h: &BlockHeader, blue_score: u64, height: u64) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&h.version.to_le_bytes());
    ref_compact_size(&mut out, h.parents.len() as u64);
    for p in &h.parents {
        out.extend_from_slice(p);
    }
    out.extend_from_slice(&h.merkle_root.0);
    out.extend_from_slice(&h.timestamp.to_le_bytes());
    out.extend_from_slice(&h.bits.to_le_bytes());
    out.extend_from_slice(&h.nonce.to_le_bytes());
    out.extend_from_slice(&blue_score.to_le_bytes());
    out.extend_from_slice(&height.to_le_bytes());
    out
}

/// `Block::to_wire_bytes()` from its specification.
pub fn ref_block_wire(b: &Block) -> Vec<u8> {
    let mut out = ref_header_wire(&b.header, b.blue_score, b.height);
    ref_compact_size(&mut out, b.transactions.len() as u64);
    for tx in &b.transactions {
        out.extend_from_slice(&ref_tx_wire(tx, true));
    }
    ref_compact_size(&mut out, b.shielded_transactions.len() as u64);
    for s in &b.shielded_transactions {
        out.extend_from_slice(&s.anchor);
        ref_compact_size(&mut out, s.nullifiers.len() as u64);
        for n in &s.nullifiers {
            out.extend_from_slice(n);
        }
        ref_compact_size(&mut out, s.outputs.len() as u64);
        for o in &s.outputs {
            out.extend_from_slice(o);
        }
        out.extend_from_slice(&s.fee.to_le_bytes());
        ref_compact_size(&mut out, s.proof.len() as u64);
        out.extend_from_slice(&s.proof);
        ref_compact_size(&mut out, s.binding_sig.len() as u64);
        out.extend_from_slice(&s.binding_sig);
    }
    if b.height >= powit_height() {
        out.extend_from_slice(&ref_powit_wire(&b.powit));
    }
    out
}

/// The PoWit section a block's wire encoding ends with from `powit_height()`
/// (and that the v2 body root commits to): three counted lists, witness
/// shares, attestations and equivocation proofs. The framing is re-derived
/// here; each item keeps its own wire encoding (`to_wire_bytes`, decoded by
/// `Block::from_wire_bytes` on the untrusted inputs of `block_parse`,
/// `block_rules` and `wire_roundtrip`).
pub fn ref_powit_wire(p: &PowitBody) -> Vec<u8> {
    let mut out = Vec::new();
    ref_compact_size(&mut out, p.shares.len() as u64);
    for s in &p.shares {
        out.extend_from_slice(&s.to_wire_bytes());
    }
    ref_compact_size(&mut out, p.attestations.len() as u64);
    for a in &p.attestations {
        out.extend_from_slice(&a.to_wire_bytes());
    }
    ref_compact_size(&mut out, p.evidence.len() as u64);
    for e in &p.evidence {
        out.extend_from_slice(&e.to_wire_bytes());
    }
    out
}

/// The PoWit section's commitment: SHA3-256("GNB-POWIT-v1/body" ‖ section).
pub fn ref_powit_root(p: &PowitBody) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"GNB-POWIT-v1/body");
    h.update(ref_powit_wire(p));
    h.finalize().into()
}

pub fn sha256d(b: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(b)).into()
}

pub fn sha3(b: &[u8]) -> [u8; 32] {
    Sha3_256::digest(b).into()
}

/// Reference txid: SHA-256d of the wire encoding, `script_sig`s included for
/// a coinbase only (one input spending `([0; 32], u32::MAX)`).
pub fn ref_is_coinbase(tx: &Transaction) -> bool {
    tx.inputs.len() == 1 && tx.inputs[0].prev_txid == [0u8; 32] && tx.inputs[0].prev_index == u32::MAX
}

pub fn ref_txid(tx: &Transaction) -> [u8; 32] {
    sha256d(&ref_tx_wire(tx, ref_is_coinbase(tx)))
}

pub fn ref_wtxid(tx: &Transaction) -> [u8; 32] {
    sha256d(&ref_tx_wire(tx, true))
}

// ── Reference tagged hashing and Merkle trees (block_rules, VAL-10) ─────────

/// `SHA-256(SHA-256(tag) || SHA-256(tag) || msg)`.
pub fn ref_tagged(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let t = Sha256::digest(tag);
    let mut pre = Vec::with_capacity(64 + msg.len());
    pre.extend_from_slice(&t);
    pre.extend_from_slice(&t);
    pre.extend_from_slice(msg);
    Sha256::digest(&pre).into()
}

/// Tagged Merkle root, written as the RFC 6962-style recursive split (the
/// left subtree holds the largest power of two strictly below `n` leaves).
/// For trees whose odd last node is carried up unchanged level by level this
/// is the same tree; the library computes it level by level, so the two are
/// independent formulations of one definition.
pub fn ref_tagged_root(ids: &[[u8; 32]]) -> [u8; 32] {
    fn subtree(ids: &[[u8; 32]]) -> [u8; 32] {
        if ids.len() == 1 {
            return ref_tagged(b"GnB/merkle/leaf", &ids[0]);
        }
        let mut k = 1usize;
        while k * 2 < ids.len() {
            k *= 2;
        }
        let mut msg = [0u8; 64];
        msg[..32].copy_from_slice(&subtree(&ids[..k]));
        msg[32..].copy_from_slice(&subtree(&ids[k..]));
        ref_tagged(b"GnB/merkle/node", &msg)
    }
    if ids.is_empty() {
        return [0u8; 32];
    }
    subtree(ids)
}

/// Legacy (pre-activation) root: Bitcoin's `ComputeMerkleRoot`, in place:
/// SHA-256d over pairs, the last node of an odd level paired with itself.
pub fn ref_legacy_root(ids: &[[u8; 32]]) -> [u8; 32] {
    if ids.is_empty() {
        return [0u8; 32];
    }
    let mut v: Vec<[u8; 32]> = ids.to_vec();
    let mut n = v.len();
    while n > 1 {
        let mut w = 0;
        let mut i = 0;
        while i < n {
            let r = if i + 1 < n { v[i + 1] } else { v[i] };
            let mut msg = [0u8; 64];
            msg[..32].copy_from_slice(&v[i]);
            msg[32..].copy_from_slice(&r);
            v[w] = sha256d(&msg);
            w += 1;
            i += 2;
        }
        n = w;
    }
    v[0]
}

/// `parents_commitment` from the specification.
pub fn ref_parents_commitment(parents: &[[u8; 32]]) -> [u8; 32] {
    let mut msg = (parents.len() as u32).to_le_bytes().to_vec();
    for p in parents {
        msg.extend_from_slice(p);
    }
    ref_tagged(b"GnB/coinbase/parents", &msg)
}

/// Witness root: the tagged root over `[0^32, wtxid(tx_1), ...]`.
pub fn ref_witness_root(txs: &[Transaction]) -> [u8; 32] {
    let ids: Vec<[u8; 32]> =
        txs.iter().enumerate().map(|(i, t)| if i == 0 { [0u8; 32] } else { ref_wtxid(t) }).collect();
    ref_tagged_root(&ids)
}

/// The 80-byte coinbase commitment.
pub fn ref_commitment(height: u64, parents: &[[u8; 32]], txs: &[Transaction]) -> [u8; 80] {
    let mut c = [0u8; 80];
    c[..8].copy_from_slice(b"GNB-CB01");
    c[8..16].copy_from_slice(&height.to_le_bytes());
    c[16..48].copy_from_slice(&ref_parents_commitment(parents));
    c[48..80].copy_from_slice(&ref_witness_root(txs));
    c
}

/// Structural equality of two values through their serde encoding (the
/// consensus types do not implement `PartialEq`).
pub fn same<T: serde::Serialize>(a: &T, b: &T) -> bool {
    let cfg = bincode::config::standard();
    bincode::serde::encode_to_vec(a, cfg).expect("encode") == bincode::serde::encode_to_vec(b, cfg).expect("encode")
}
