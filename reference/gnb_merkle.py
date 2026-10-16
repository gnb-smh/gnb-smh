"""GnB block rules of the hardening activation -- executable reference.

Normative definition of the encodings `crates/gnb-crypto/src/core/block_rules.rs`
implements (docs/CONSENSUS.md, "Block rules at the hardening activation");
`merkle_vectors.json` (written by gen_merkle_vectors.py) pins both and
`crates/gnb-crypto/tests/merkle_vectors.rs` checks the Rust code against it.

    sha256d(b)            = SHA-256(SHA-256(b))
    tagged_hash(tag, m)   = SHA-256(SHA-256(tag) || SHA-256(tag) || m)

Transaction wire encoding (`Transaction::to_wire_bytes`), little-endian
integers, Bitcoin varints for counts and lengths:

    version u32 | varint n_in | n_in x (prev_txid 32 | prev_index u32
      | [varint len | script_sig]  -- only when the script_sig is included
      | sequence u32) | varint n_out | n_out x (value u64 | varint len
      | script_pubkey) | locktime u32

    txid  = sha256d(wire(include_script_sig = is_coinbase))
    wtxid = sha256d(wire(include_script_sig = True))

A coinbase has exactly one input, prev_txid = 32 zero bytes and
prev_index = 0xffffffff.

Rules for a block at header height h, with activation height A, apply iff
h >= 1 and h >= A:

  * header Merkle root: tagged tree over the txids (leaf / node tags below,
    an odd last node is carried up unchanged); before: Bitcoin's SHA-256d tree
    that pairs an odd last node with itself;
  * no transaction whose txid preimage is exactly 64 bytes;
  * the coinbase script_sig starts with the 80-byte commitment
        "GNB-CB01" | u64le(h) | parents_commitment(header parents)
        | witness_root(block transactions)
    followed by any miner bytes (the script_sig stays <= 10,000 bytes);
  * witness_root = tagged tree over [32 zero bytes, wtxid(tx_1), ..., wtxid(tx_n)].
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

MERKLE_LEAF_TAG = b"GnB/merkle/leaf"
MERKLE_NODE_TAG = b"GnB/merkle/node"
PARENTS_TAG = b"GnB/coinbase/parents"
COINBASE_COMMITMENT_TAG = b"GNB-CB01"
COINBASE_COMMITMENT_LEN = 80
COINBASE_WTXID = bytes(32)
FORBIDDEN_TXID_PREIMAGE_LEN = 64
MAX_SCRIPT_SIG_SIZE = 10_000
MAINNET_HARDENING_ACTIVATION_HEIGHT = 110_000
ZERO32 = bytes(32)


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def sha256d(b: bytes) -> bytes:
    return sha256(sha256(b))


def tagged_hash(tag: bytes, msg: bytes) -> bytes:
    t = sha256(tag)
    return sha256(t + t + msg)


def rules_active_at(height: int, activation_height: int) -> bool:
    """The genesis (height 0) is never subject to the hardening rules."""
    return height >= 1 and height >= activation_height


# ── Transactions ─────────────────────────────────────────────────────────────

def varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


@dataclass
class TxIn:
    prev_txid: bytes
    prev_index: int
    script_sig: bytes
    sequence: int = 0xFFFFFFFF


@dataclass
class TxOut:
    value: int
    script_pubkey: bytes


@dataclass
class Tx:
    version: int
    inputs: list = field(default_factory=list)
    outputs: list = field(default_factory=list)
    locktime: int = 0

    def is_coinbase(self) -> bool:
        return (len(self.inputs) == 1 and self.inputs[0].prev_txid == ZERO32
                and self.inputs[0].prev_index == 0xFFFFFFFF)

    def wire(self, include_script_sig: bool) -> bytes:
        out = struct.pack("<I", self.version) + varint(len(self.inputs))
        for i in self.inputs:
            out += i.prev_txid + struct.pack("<I", i.prev_index)
            if include_script_sig:
                out += varint(len(i.script_sig)) + i.script_sig
            out += struct.pack("<I", i.sequence)
        out += varint(len(self.outputs))
        for o in self.outputs:
            out += struct.pack("<Q", o.value) + varint(len(o.script_pubkey)) + o.script_pubkey
        return out + struct.pack("<I", self.locktime)

    def txid_preimage(self) -> bytes:
        return self.wire(self.is_coinbase())

    def txid(self) -> bytes:
        return sha256d(self.txid_preimage())

    def wtxid(self) -> bytes:
        return sha256d(self.wire(True))


def is_forbidden_64(tx: Tx) -> bool:
    return len(tx.txid_preimage()) == FORBIDDEN_TXID_PREIMAGE_LEN


# ── Merkle trees ─────────────────────────────────────────────────────────────

def legacy_merkle_root(ids: list) -> bytes:
    if not ids:
        return ZERO32
    level = list(ids)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [sha256d(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def merkle_leaf(i: bytes) -> bytes:
    return tagged_hash(MERKLE_LEAF_TAG, i)


def merkle_node(left: bytes, right: bytes) -> bytes:
    return tagged_hash(MERKLE_NODE_TAG, left + right)


def _tagged_next(level: list) -> list:
    nxt = [merkle_node(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
    if len(level) % 2:
        nxt.append(level[-1])  # odd last node: carried up unchanged
    return nxt


def tagged_merkle_root(ids: list) -> bytes:
    if not ids:
        return ZERO32
    level = [merkle_leaf(i) for i in ids]
    while len(level) > 1:
        level = _tagged_next(level)
    return level[0]


def merkle_root(ids: list, hardened: bool) -> bytes:
    return tagged_merkle_root(ids) if hardened else legacy_merkle_root(ids)


def coinbase_merkle_branch(ids: list, hardened: bool) -> list:
    """Siblings of position 0 bottom-up (ids[0] does not influence them)."""
    if len(ids) < 2:
        return []
    level = [merkle_leaf(i) for i in ids] if hardened else list(ids)
    branch = []
    while len(level) > 1:
        branch.append(level[1])
        if hardened:
            level = _tagged_next(level)
        else:
            if len(level) % 2:
                level.append(level[-1])
            level = [sha256d(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return branch


def fold_coinbase_branch(coinbase_txid: bytes, branch: list, hardened: bool) -> bytes:
    cur = merkle_leaf(coinbase_txid) if hardened else coinbase_txid
    for s in branch:
        cur = merkle_node(cur, s) if hardened else sha256d(cur + s)
    return cur


# ── Coinbase commitment ──────────────────────────────────────────────────────

# From this height (core::POWIT_HEIGHT_MAINNET) the header root commits to the
# v2 block body: the transaction root, the shielded section and the PoWit
# section (`Block::body_merkle_root_at`). The reference blocks carry neither
# shielded transactions nor PoWit items, so both sections are empty.
POWIT_HEIGHT_MAINNET = 10_000
_EMPTY_SHIELDED_ROOT = hashlib.sha3_256(b"gnb:block:shielded:v1").digest()
_EMPTY_POWIT_ROOT = hashlib.sha3_256(b"GNB-POWIT-v1/body" + b"\x00\x00\x00").digest()


def header_root(tx_root: bytes, height: int) -> bytes:
    """The header Merkle root of a block at `height` whose transaction root
    is `tx_root` (no shielded transactions, empty PoWit section)."""
    if height < POWIT_HEIGHT_MAINNET:
        return tx_root
    return hashlib.sha3_256(b"gnb:block:body:v2" + tx_root + _EMPTY_SHIELDED_ROOT + _EMPTY_POWIT_ROOT).digest()


def parents_commitment(parents: list) -> bytes:
    return tagged_hash(PARENTS_TAG, struct.pack("<I", len(parents)) + b"".join(parents))


def witness_root(txs: list) -> bytes:
    ids = [COINBASE_WTXID if i == 0 else t.wtxid() for i, t in enumerate(txs)]
    return tagged_merkle_root(ids)


def coinbase_commitment(height: int, parents: list, wroot: bytes) -> bytes:
    c = COINBASE_COMMITMENT_TAG + struct.pack("<Q", height) + parents_commitment(parents) + wroot
    assert len(c) == COINBASE_COMMITMENT_LEN
    return c


def check_coinbase_commitment(height: int, parents: list, txs: list) -> str | None:
    """None when valid, else the reason (the Rust error strings' meaning)."""
    ss = txs[0].inputs[0].script_sig
    if len(ss) < COINBASE_COMMITMENT_LEN:
        return "missing"
    if ss[0:8] != COINBASE_COMMITMENT_TAG:
        return "tag"
    if ss[8:16] != struct.pack("<Q", height):
        return "height"
    if ss[16:48] != parents_commitment(parents):
        return "parents"
    if ss[48:80] != witness_root(txs):
        return "witness"
    return None
