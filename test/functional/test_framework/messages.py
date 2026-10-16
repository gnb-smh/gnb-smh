"""GnB consensus encodings in pure Python, for building and inspecting blocks.

Mirrors crates/gnb-crypto/src/core/mod.rs (wire formats, block id) and
core/block_rules.rs (hardening rules: tagged Merkle tree, coinbase
commitment); the normative references are reference/gnb_merkle.py and
docs/CONSENSUS.md. The node is the judge: every block the tests build here is
accepted or rejected by the real `submitblock` path.

Transaction wire (`Transaction::to_wire_bytes`), little-endian, Bitcoin
varints:
    version u32 | varint n_in | n_in x (prev_txid 32 | prev_index u32
      | [varint len | script_sig] | sequence u32) | varint n_out
      | n_out x (value u64 | varint len | script_pubkey) | locktime u32
    txid  = sha256d(wire(include_script_sig = is_coinbase))
    wtxid = sha256d(wire(include_script_sig = True))

Block wire (`Block::to_wire_bytes`):
    version u32 | varint n_parents | parents | merkle_root 32 | timestamp u64
      | bits u32 | nonce u64 | blue_score u64 | height u64
      | varint n_tx | txs (wire, script_sig included) | varint n_shielded (0)
    block id  = SHA3-256("GNB-BLOCK-ID-v1" || pow_preimage || nonce u64le)
    pow_preimage = version u32 | n_parents u32 | parents | merkle_root
                   | timestamp u64 | bits u32
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

ZERO32 = bytes(32)
COINBASE_PREV_INDEX = 0xFFFFFFFF

MERKLE_LEAF_TAG = b"GnB/merkle/leaf"
MERKLE_NODE_TAG = b"GnB/merkle/node"
PARENTS_TAG = b"GnB/coinbase/parents"
COINBASE_COMMITMENT_TAG = b"GNB-CB01"
COINBASE_COMMITMENT_LEN = 80
BLOCK_ID_TAG = b"GNB-BLOCK-ID-v1"

MAINNET_PREFIX = "gnb1q"
TESTNET_PREFIX = "gnb1t"


# ── Hashes and encodings ─────────────────────────────────────────────────────

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def sha256d(b: bytes) -> bytes:
    return sha256(sha256(b))


def sha3_256(b: bytes) -> bytes:
    return hashlib.sha3_256(b).digest()


def tagged_hash(tag: bytes, msg: bytes) -> bytes:
    t = sha256(tag)
    return sha256(t + t + msg)


def ser_varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ValueError("truncated")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self.take(8))[0]

    def varint(self) -> int:
        b = self.take(1)[0]
        if b < 0xFD:
            return b
        if b == 0xFD:
            return struct.unpack("<H", self.take(2))[0]
        if b == 0xFE:
            return struct.unpack("<I", self.take(4))[0]
        return struct.unpack("<Q", self.take(8))[0]

    def done(self) -> bool:
        return self.pos == len(self.data)


# ── Addresses ────────────────────────────────────────────────────────────────

def address_checksum(h: bytes) -> bytes:
    return sha3_256(sha3_256(h))[:4]


def hash_to_address(h: bytes, testnet: bool = True) -> str:
    assert len(h) == 20
    return (TESTNET_PREFIX if testnet else MAINNET_PREFIX) + (h + address_checksum(h)).hex()


def address_to_script_pubkey(addr: str) -> bytes:
    """The 20-byte pubkey hash an address pays to (checksum verified)."""
    for prefix in (TESTNET_PREFIX, MAINNET_PREFIX):
        if addr.startswith(prefix):
            raw = bytes.fromhex(addr[len(prefix):])
            if len(raw) != 24 or address_checksum(raw[:20]) != raw[20:]:
                raise ValueError(f"bad address {addr!r}")
            return raw[:20]
    raise ValueError(f"bad address prefix {addr!r}")


# ── Transactions ─────────────────────────────────────────────────────────────

@dataclass
class TxIn:
    prev_txid: bytes
    prev_index: int
    script_sig: bytes = b""
    sequence: int = 0xFFFFFFFF


@dataclass
class TxOut:
    value: int
    script_pubkey: bytes


@dataclass
class Tx:
    version: int = 1
    inputs: list = field(default_factory=list)
    outputs: list = field(default_factory=list)
    locktime: int = 0

    def is_coinbase(self) -> bool:
        return (len(self.inputs) == 1 and self.inputs[0].prev_txid == ZERO32
                and self.inputs[0].prev_index == COINBASE_PREV_INDEX)

    def serialize(self, include_script_sig: bool = True) -> bytes:
        out = struct.pack("<I", self.version) + ser_varint(len(self.inputs))
        for i in self.inputs:
            out += i.prev_txid + struct.pack("<I", i.prev_index)
            if include_script_sig:
                out += ser_varint(len(i.script_sig)) + i.script_sig
            out += struct.pack("<I", i.sequence)
        out += ser_varint(len(self.outputs))
        for o in self.outputs:
            out += struct.pack("<Q", o.value) + ser_varint(len(o.script_pubkey)) + o.script_pubkey
        return out + struct.pack("<I", self.locktime)

    def txid(self) -> bytes:
        return sha256d(self.serialize(self.is_coinbase()))

    def wtxid(self) -> bytes:
        return sha256d(self.serialize(True))

    def txid_hex(self) -> str:
        return self.txid().hex()

    @classmethod
    def read(cls, r: Reader) -> "Tx":
        version = r.u32()
        inputs = []
        for _ in range(r.varint()):
            prev = r.take(32)
            idx = r.u32()
            ss = r.take(r.varint())
            seq = r.u32()
            inputs.append(TxIn(prev, idx, ss, seq))
        outputs = []
        for _ in range(r.varint()):
            value = r.u64()
            spk = r.take(r.varint())
            outputs.append(TxOut(value, spk))
        return cls(version, inputs, outputs, r.u32())

    @classmethod
    def deserialize(cls, data: bytes) -> "Tx":
        r = Reader(data)
        tx = cls.read(r)
        if not r.done():
            raise ValueError("trailing bytes after transaction")
        return tx


def create_coinbase(value: int, script_pubkey: bytes, script_sig: bytes) -> Tx:
    """The node's coinbase shape (template::miner_coinbase): version 1, one
    null input, one output."""
    return Tx(1, [TxIn(ZERO32, COINBASE_PREV_INDEX, script_sig)], [TxOut(value, script_pubkey)], 0)


# ── Merkle trees and the coinbase commitment (hardening rules) ───────────────

def legacy_merkle_root(ids: list) -> bytes:
    """Bitcoin's SHA-256d tree (odd last node paired with itself): the rule
    below the hardening activation."""
    if not ids:
        return ZERO32
    level = list(ids)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [sha256d(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def _tagged_next(level: list) -> list:
    nxt = [tagged_hash(MERKLE_NODE_TAG, level[i] + level[i + 1]) for i in range(0, len(level) - 1, 2)]
    if len(level) % 2:
        nxt.append(level[-1])
    return nxt


def tagged_merkle_root(ids: list) -> bytes:
    if not ids:
        return ZERO32
    level = [tagged_hash(MERKLE_LEAF_TAG, i) for i in ids]
    while len(level) > 1:
        level = _tagged_next(level)
    return level[0]


def fold_coinbase_branch(coinbase_txid: bytes, branch: list) -> bytes:
    """Header root from the coinbase txid and getblocktemplate's
    `coinbase_merkle_branch` (tagged rule)."""
    cur = tagged_hash(MERKLE_LEAF_TAG, coinbase_txid)
    for s in branch:
        cur = tagged_hash(MERKLE_NODE_TAG, cur + s)
    return cur


def parents_commitment(parents: list) -> bytes:
    return tagged_hash(PARENTS_TAG, struct.pack("<I", len(parents)) + b"".join(parents))


def witness_root(txs: list) -> bytes:
    return tagged_merkle_root([ZERO32 if i == 0 else t.wtxid() for i, t in enumerate(txs)])


def coinbase_commitment(height: int, parents: list, txs: list) -> bytes:
    c = COINBASE_COMMITMENT_TAG + struct.pack("<Q", height) + parents_commitment(parents) + witness_root(txs)
    assert len(c) == COINBASE_COMMITMENT_LEN
    return c


# ── Blocks ───────────────────────────────────────────────────────────────────

@dataclass
class Block:
    version: int = 1
    parents: list = field(default_factory=list)
    merkle_root: bytes = ZERO32
    timestamp: int = 0
    bits: int = 0
    nonce: int = 0
    blue_score: int = 0
    height: int = 0
    txs: list = field(default_factory=list)

    def pow_preimage(self) -> bytes:
        return (struct.pack("<II", self.version, len(self.parents)) + b"".join(self.parents)
                + self.merkle_root + struct.pack("<QI", self.timestamp, self.bits))

    def hash(self) -> bytes:
        return sha3_256(BLOCK_ID_TAG + self.pow_preimage() + struct.pack("<Q", self.nonce))

    def hash_hex(self) -> str:
        return self.hash().hex()

    def serialize(self) -> bytes:
        out = struct.pack("<I", self.version) + ser_varint(len(self.parents)) + b"".join(self.parents)
        out += self.merkle_root + struct.pack("<QIQQQ", self.timestamp, self.bits, self.nonce,
                                              self.blue_score, self.height)
        out += ser_varint(len(self.txs)) + b"".join(t.serialize(True) for t in self.txs)
        return out + ser_varint(0)  # no shielded transactions

    def tagged_root(self) -> bytes:
        return tagged_merkle_root([t.txid() for t in self.txs])

    def legacy_root(self) -> bytes:
        return legacy_merkle_root([t.txid() for t in self.txs])

    def commit(self, extra: bytes = b"") -> None:
        """Write the hardening coinbase commitment (+ `extra` miner bytes) and
        the tagged header Merkle root, as `template::assemble_block` does."""
        cb = self.txs[0].inputs[0]
        cb.script_sig = coinbase_commitment(self.height, self.parents, self.txs) + extra
        self.merkle_root = self.tagged_root()

    @classmethod
    def deserialize(cls, data: bytes) -> "Block":
        r = Reader(data)
        version = r.u32()
        parents = [r.take(32) for _ in range(r.varint())]
        merkle_root = r.take(32)
        timestamp, bits, nonce, blue_score, height = r.u64(), r.u32(), r.u64(), r.u64(), r.u64()
        txs = [Tx.read(r) for _ in range(r.varint())]
        if r.varint() != 0:
            raise ValueError("shielded transactions are not supported here")
        if not r.done():
            raise ValueError("trailing bytes after block")
        return cls(version, parents, merkle_root, timestamp, bits, nonce, blue_score, height, txs)


def block_from_template(tmpl: dict, script_pubkey: bytes, *, extra: bytes = b"",
                        txs: list | None = None, coinbase_value: int | None = None,
                        timestamp: int | None = None) -> Block:
    """A complete candidate block for a `getblocktemplate` result.

    `txs` (default: the template's transactions, in order) are placed after
    the coinbase; the coinbase pays `coinbase_value` (default subsidy + the
    template's fees) to `script_pubkey`. On a hardened template the coinbase
    script_sig is the commitment followed by `extra`, and the header root is
    the tagged tree. Nonce 0; see `TestNode.submit_block` for the search."""
    if txs is None:
        txs = [Tx.deserialize(bytes.fromhex(t["data"])) for t in tmpl["transactions"]]
    if coinbase_value is None:
        coinbase_value = int(tmpl["subsidy_sat"]) + int(tmpl["total_fees"])
    parents = [bytes.fromhex(p) for p in tmpl["parents"]]
    ts = timestamp if timestamp is not None else max(int(tmpl["cur_time"]), int(tmpl["min_time"]))
    coinbase = create_coinbase(coinbase_value, script_pubkey, extra)
    block = Block(version=1, parents=parents, timestamp=ts, bits=int(tmpl["bits"]), nonce=0,
                  blue_score=int(tmpl["blue_score"]), height=int(tmpl["height"]),
                  txs=[coinbase] + list(txs))
    if tmpl.get("hardening_active"):
        block.commit(extra)
    else:
        block.merkle_root = block.legacy_root()
    return block
