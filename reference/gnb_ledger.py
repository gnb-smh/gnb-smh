"""GnB ledger v1 -- stateless validation reference (normative).

Validity is deterministic and needs no committee: every node checks every block
holding only the two 32-byte state roots. Ordering stays probabilistic: it comes
from GnB-SMH proof-of-work over GhostDAG and is not touched here.

How a node validates without the UTXO set:

* The state is a SHAKE-256 sparse Merkle tree (depth 256) of unspent outputs,
  plus a second tree reserved for shielded-pool nullifiers. The node keeps only
  their roots; the header commits to both.
* A block travels with a witness bundle: for each transaction, the spent output
  records and an O(log n) Merkle witness per touched key, each against the root
  left by the previous operation. About 1 KB per key at 2^30 outputs. The header
  commits to the bundle's hash (witness_root), so a damaged bundle is detected by
  one hash before any proof is checked, and a bad committed bundle makes the block
  permanently invalid: a peer cannot make a node redo the proof checks of one
  block id with a different bad bundle.
* The header commits to every transaction byte, authorization included (the
  transaction root is built over wtxids), and every transaction gets exactly one
  outcome that the witness must prove: ACCEPT, or REJECT with a proof (an input
  is absent, an output key already exists, or a context rule fails). Neither the
  producer nor a relaying peer has any discretion: the post-state root is a
  deterministic function of the pre-state root and the committed block.
* No proof system is on this path. Recursive STARK proofs, when added, serve sync
  and pruning only; a missing prover can never stall block acceptance.

Faults come in two classes (InvalidBlock.permanent). Permanent ones prove the block
itself is invalid: mark its id invalid. Transient ones only show that the body or
the witness received does not hash to the header's commitments: penalize the peer
and fetch again.

Encodings are little-endian, enc(b) = u32le(len(b)) || b, and every hash is
H(label, data) = SHAKE256(enc("GNB-LEDGER-v1/" + label) || data, 32).

Spend authorization is pluggable. `test_preimage_auth` exists only for tests and
vectors and is NOT secure; GnB spends are authorized by the hybrid
ML-DSA-65 || Falcon-1024 signature scheme, outside this reference.

This file is the normative definition. Other implementations must reproduce
ledger_vectors.json exactly, including which error code each invalid case raises.
"""

from __future__ import annotations

import dataclasses
import hashlib
import struct
from dataclasses import dataclass, field
from typing import Callable, Sequence

VERSION = 1
DEPTH = 256
HASH_LEN = 32
RECORD_LEN = 49
HEADER_LEN = 172

# Placeholder limits until GnB's monetary and block-size parameters are fixed.
MAX_MONEY = (1 << 63) - 1
MAX_INPUTS = 1024              # per transaction
MAX_OUTPUTS = 1024             # per transaction
MAX_AUTH_LEN = 16_384          # per authorization entry (a hybrid key + signature is ~8.3 KB)
MAX_TXS = 65_536               # per block
MAX_BLOCK_KEYS = 16_384        # per block: inputs + outputs of all transactions = witnesses to check
MAX_BLOCK_TX_BYTES = 4_000_000 # per block: sum of transaction wire sizes
MAX_COINBASE_EXTRA = 100
# Per block: the committed witness bundle (consensus cap, audit LED-1). A bundle
# above it is refused before it is hashed, so no attempt costs more hashing than
# this; a block whose committed bundle is larger can never be validated. One
# maximal transaction (1,024 inputs and 1,024 outputs, every proof at full depth,
# about 17 MB) plus a maximal coinbase always fit.
MAX_WITNESS_BYTES = 32 * 1024 * 1024
COINBASE_MATURITY = 100

TX_REGULAR = 0
TX_COINBASE = 1

ACCEPT = 0
REJECT_MISSING_INPUT = 1
REJECT_OUTPUT_EXISTS = 2
REJECT_CONTEXT = 3

_LABEL = b"GNB-LEDGER-v1/"


def enc(b: bytes) -> bytes:
    return struct.pack("<I", len(b)) + b


def _prefix(label: bytes) -> bytes:
    return enc(_LABEL + label)


_P_NODE = _prefix(b"node")
_P_LEAF = _prefix(b"leaf")
_P_OUTPOINT = _prefix(b"outpoint")
_P_UTXO = _prefix(b"utxo")
_P_TXID = _prefix(b"txid")
_P_WTXID = _prefix(b"wtxid")
_P_TXNODE = _prefix(b"txnode")
_P_TXROOT = _prefix(b"txroot")
_P_STATE = _prefix(b"state")
_P_BLOCK = _prefix(b"block")
_P_WITNESS = _prefix(b"witness")
_P_TEST_OWNER = _prefix(b"test-owner")


def _h(prefix: bytes, *parts: bytes) -> bytes:
    return hashlib.shake_256(prefix + b"".join(parts)).digest(HASH_LEN)


class InvalidBlock(Exception):
    """Raised with one of the shared error codes below; vectors pin the code.

    Permanent codes prove the committed block is invalid; the witness bundle is
    committed too, so a malformed, forged or stale committed bundle is permanent.
    Transient codes mean the body or witness received does not hash to the header's
    commitments (tx_root, witness_root), or the witness received is larger than any
    committed bundle may be (witness-size: it is refused before it is hashed, so it
    cannot be attributed to the header): the block may still be valid."""

    CODES = (
        "header", "target", "pow", "tx-root", "witness-size", "witness-commitment", "isolation",
        "witness-format", "noncanonical-proof", "witness-mismatch", "accept-invalid",
        "reject-invalid", "coinbase", "state-commitment",
    )
    PERMANENT = frozenset({
        "header", "target", "pow", "isolation", "witness-format", "noncanonical-proof",
        "witness-mismatch", "accept-invalid", "reject-invalid", "coinbase", "state-commitment",
    })

    def __init__(self, code: str, detail: str = ""):
        assert code in self.CODES, code
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code

    @property
    def permanent(self) -> bool:
        return self.code in self.PERMANENT


# --------------------------------------------------------------------------- sparse Merkle tree
#
# Leaves sit at height 0, the root at height 256. A key's path is read from its most
# significant bit: at height h the path node is a left child iff bit (255 - h) of the
# key, counted from the most significant bit of key[0], is 0.
# An absent leaf is EMPTY (32 zero bytes); a present one is H(leaf, key || value).
# DEFAULTS[h] is the root of an empty subtree of height h.

EMPTY = bytes(HASH_LEN)


def node_hash(left: bytes, right: bytes) -> bytes:
    return _h(_P_NODE, left, right)


DEFAULTS = [EMPTY]
for _ in range(DEPTH):
    DEFAULTS.append(node_hash(DEFAULTS[-1], DEFAULTS[-1]))
EMPTY_ROOT = DEFAULTS[DEPTH]


def leaf_hash(key: bytes, value: bytes) -> bytes:
    return _h(_P_LEAF, key, value)


def path_bit(key: bytes, h: int) -> int:
    i = 255 - h
    return (key[i >> 3] >> (7 - (i & 7))) & 1


def root_from(key: bytes, leaf: bytes, siblings: Sequence[bytes]) -> bytes:
    """Root of the tree in which `key` holds `leaf` and its path has these siblings."""
    cur = leaf
    for h in range(DEPTH):
        s = siblings[h]
        d = DEFAULTS[h]
        if cur == d and s == d:          # both children empty: no hashing needed
            cur = DEFAULTS[h + 1]
        elif path_bit(key, h) == 0:
            cur = node_hash(cur, s)
        else:
            cur = node_hash(s, cur)
    return cur


def encode_proof(siblings: Sequence[bytes]) -> bytes:
    """32-byte bitmap (bit h set iff sibling h is not DEFAULTS[h]; byte h>>3, bit h&7
    from the least significant), then the non-default siblings in increasing h."""
    bitmap = bytearray(32)
    body = []
    for h, s in enumerate(siblings):
        if s != DEFAULTS[h]:
            bitmap[h >> 3] |= 1 << (h & 7)
            body.append(s)
    return bytes(bitmap) + b"".join(body)


def proof_len(buf: bytes, off: int = 0) -> int:
    if len(buf) - off < 32:
        raise InvalidBlock("witness-format", "truncated proof bitmap")
    return 32 + 32 * sum(bin(b).count("1") for b in buf[off:off + 32])


def decode_proof(buf: bytes, off: int = 0) -> tuple[list[bytes], int]:
    """Strict decoder: a listed sibling equal to its default is rejected (one encoding per proof)."""
    if len(buf) - off < 32:
        raise InvalidBlock("witness-format", "truncated proof bitmap")
    bitmap = buf[off:off + 32]
    pos = off + 32
    siblings = []
    for h in range(DEPTH):
        if (bitmap[h >> 3] >> (h & 7)) & 1:
            s = buf[pos:pos + 32]
            if len(s) != 32:
                raise InvalidBlock("witness-format", "truncated proof sibling")
            if s == DEFAULTS[h]:
                raise InvalidBlock("noncanonical-proof", f"default sibling listed at height {h}")
            siblings.append(s)
            pos += 32
        else:
            siblings.append(DEFAULTS[h])
    return siblings, pos


class SparseMerkleTree:
    """Full tree for block producers and tests. Stores every non-default node on every
    path, so it is for small sets only; a production store must compress single-leaf
    chains. Node id: (height h, key >> h)."""

    def __init__(self) -> None:
        self._nodes: dict[tuple[int, int], bytes] = {}

    def root(self) -> bytes:
        return self._nodes.get((DEPTH, 0), EMPTY_ROOT)

    def leaf(self, key: bytes) -> bytes:
        return self._nodes.get((0, int.from_bytes(key, "big")), EMPTY)

    def siblings(self, key: bytes) -> list[bytes]:
        k = int.from_bytes(key, "big")
        return [self._nodes.get((h, (k >> h) ^ 1), DEFAULTS[h]) for h in range(DEPTH)]

    def proof(self, key: bytes) -> bytes:
        return encode_proof(self.siblings(key))

    def set(self, key: bytes, leaf: bytes) -> None:
        k = int.from_bytes(key, "big")
        cur = leaf
        self._put(0, k, cur)
        for h in range(DEPTH):
            s = self._nodes.get((h, (k >> h) ^ 1), DEFAULTS[h])
            if cur == DEFAULTS[h] and s == DEFAULTS[h]:
                cur = DEFAULTS[h + 1]
            elif (k >> h) & 1 == 0:
                cur = node_hash(cur, s)
            else:
                cur = node_hash(s, cur)
            self._put(h + 1, k >> (h + 1), cur)

    def _put(self, h: int, prefix: int, value: bytes) -> None:
        if value == DEFAULTS[h]:
            self._nodes.pop((h, prefix), None)
        else:
            self._nodes[(h, prefix)] = value


# --------------------------------------------------------------------------- transactions

@dataclass(frozen=True)
class Outpoint:
    txid: bytes
    vout: int


@dataclass(frozen=True)
class TxOut:
    amount: int
    owner: bytes


@dataclass(frozen=True)
class Tx:
    kind: int
    inputs: tuple[Outpoint, ...] = ()
    outputs: tuple[TxOut, ...] = ()
    height: int = 0          # coinbase only: must equal the block height
    extra: bytes = b""       # coinbase only
    auth: tuple[bytes, ...] = ()   # one entry per input; not covered by the txid
    parents_root: bytes = EMPTY    # coinbase only: must equal the header's parents_root


@dataclass(frozen=True)
class UtxoRecord:
    amount: int
    owner: bytes
    height: int
    coinbase: bool

    def encode(self) -> bytes:
        return (struct.pack("<Q", self.amount) + self.owner + struct.pack("<Q", self.height)
                + bytes([1 if self.coinbase else 0]))

    @staticmethod
    def decode(b: bytes) -> "UtxoRecord":
        if len(b) != RECORD_LEN:
            raise InvalidBlock("witness-format", "record length")
        if b[48] not in (0, 1):
            raise InvalidBlock("witness-format", "record coinbase flag")
        return UtxoRecord(struct.unpack_from("<Q", b, 0)[0], b[8:40],
                          struct.unpack_from("<Q", b, 40)[0], b[48] == 1)


def tx_bytes(tx: Tx) -> bytes:
    """Canonical encoding covered by the txid (no authorization data)."""
    out = [struct.pack("<I", VERSION), bytes([tx.kind])]
    if tx.kind == TX_COINBASE:
        out += [struct.pack("<Q", tx.height), tx.parents_root, enc(tx.extra)]
    out.append(struct.pack("<I", len(tx.inputs)))
    for op in tx.inputs:
        out += [op.txid, struct.pack("<I", op.vout)]
    out.append(struct.pack("<I", len(tx.outputs)))
    for o in tx.outputs:
        out += [struct.pack("<Q", o.amount), o.owner]
    return b"".join(out)


def tx_wire(tx: Tx) -> bytes:
    """Wire encoding: tx_bytes || u32le(count) || enc(auth_i)..."""
    return tx_bytes(tx) + struct.pack("<I", len(tx.auth)) + b"".join(enc(a) for a in tx.auth)


class _Reader:
    def __init__(self, buf: bytes, code: str) -> None:
        self.buf, self.pos, self.code = buf, 0, code

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.buf):
            raise InvalidBlock(self.code, "truncated")
        b = self.buf[self.pos:self.pos + n]
        self.pos += n
        return b

    def u8(self) -> int:
        return self.take(1)[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self.take(8))[0]

    def proof(self) -> list[bytes]:
        sibs, end = decode_proof(self.buf, self.pos)
        self.pos = end
        return sibs

    def done(self) -> bool:
        return self.pos == len(self.buf)


def decode_tx_wire(buf: bytes) -> Tx:
    """Strict decoder; any malformed or trailing byte is an isolation error."""
    r = _Reader(buf, "isolation")
    if r.u32() != VERSION:
        raise InvalidBlock("isolation", "tx version")
    kind = r.u8()
    if kind not in (TX_REGULAR, TX_COINBASE):
        raise InvalidBlock("isolation", "tx kind")
    height, extra, parents_root = 0, b"", EMPTY
    if kind == TX_COINBASE:
        height = r.u64()
        parents_root = r.take(32)
        extra = r.take(r.u32())
    n_in = r.u32()
    if n_in > MAX_INPUTS:
        raise InvalidBlock("isolation", "too many inputs")
    inputs = tuple(Outpoint(r.take(32), r.u32()) for _ in range(n_in))
    n_out = r.u32()
    if n_out > MAX_OUTPUTS:
        raise InvalidBlock("isolation", "too many outputs")
    outputs = tuple(TxOut(r.u64(), r.take(32)) for _ in range(n_out))
    n_auth = r.u32()
    if n_auth > MAX_INPUTS:
        raise InvalidBlock("isolation", "too many auth entries")
    auth = []
    for _ in range(n_auth):
        n = r.u32()
        if n > MAX_AUTH_LEN:
            raise InvalidBlock("isolation", "auth entry too long")
        auth.append(r.take(n))
    if not r.done():
        raise InvalidBlock("isolation", "trailing bytes")
    return Tx(kind, inputs, outputs, height, extra, tuple(auth), parents_root)


def txid(tx: Tx) -> bytes:
    """Identity of the transfer (no authorization data): what outpoints refer to."""
    return _h(_P_TXID, tx_bytes(tx))


def wtxid(wire: bytes) -> bytes:
    """Identity of the exact wire bytes, authorization included: what the header commits to."""
    return _h(_P_WTXID, wire)


def outpoint_key(txid_: bytes, vout: int) -> bytes:
    return _h(_P_OUTPOINT, txid_, struct.pack("<I", vout))


def utxo_value(record: UtxoRecord) -> bytes:
    return _h(_P_UTXO, record.encode())


def utxo_leaf(key: bytes, record: UtxoRecord) -> bytes:
    return leaf_hash(key, utxo_value(record))


def check_tx_isolation(tx: Tx) -> None:
    """Context-free rules. A block containing a transaction that fails them is invalid."""
    if tx.kind not in (TX_REGULAR, TX_COINBASE):
        raise InvalidBlock("isolation", "tx kind")
    if not 1 <= len(tx.outputs) <= MAX_OUTPUTS:
        raise InvalidBlock("isolation", "output count")
    total = 0
    for o in tx.outputs:
        if not 0 <= o.amount <= MAX_MONEY or len(o.owner) != 32:
            raise InvalidBlock("isolation", "output")
        total += o.amount
    if total > MAX_MONEY:
        raise InvalidBlock("isolation", "output sum")
    if tx.kind == TX_REGULAR:
        if not 1 <= len(tx.inputs) <= MAX_INPUTS:
            raise InvalidBlock("isolation", "input count")
        if len(set(tx.inputs)) != len(tx.inputs):
            raise InvalidBlock("isolation", "duplicate input")
        if len(tx.auth) != len(tx.inputs):
            raise InvalidBlock("isolation", "auth count")
        if any(len(a) > MAX_AUTH_LEN for a in tx.auth):
            raise InvalidBlock("isolation", "auth entry too long")
        if tx.height != 0 or tx.extra or tx.parents_root != EMPTY:
            raise InvalidBlock("isolation", "coinbase fields on a regular tx")
        for op in tx.inputs:
            if len(op.txid) != 32 or not 0 <= op.vout < 1 << 32:
                raise InvalidBlock("isolation", "outpoint")
    else:
        if tx.inputs or tx.auth:
            raise InvalidBlock("isolation", "coinbase with inputs")
        if len(tx.extra) > MAX_COINBASE_EXTRA:
            raise InvalidBlock("isolation", "coinbase extra")
        if len(tx.parents_root) != 32:
            raise InvalidBlock("isolation", "coinbase parents root")


# --------------------------------------------------------------------------- authorization

AuthFn = Callable[[Tx, Sequence[UtxoRecord]], bool]


def test_owner(secret: bytes) -> bytes:
    """TEST ONLY: owner of outputs spendable by revealing `secret`."""
    return _h(_P_TEST_OWNER, secret)


def test_preimage_auth(tx: Tx, records: Sequence[UtxoRecord]) -> bool:
    """TEST ONLY, NOT SECURE: input i is authorized iff auth[i] hashes to its owner.
    It binds nothing about the transaction, so anyone who sees it can replay it."""
    return len(tx.auth) == len(records) and all(
        test_owner(a) == r.owner for a, r in zip(tx.auth, records))


# --------------------------------------------------------------------------- state transition

@dataclass(frozen=True)
class State:
    utxo_root: bytes = EMPTY_ROOT
    nullifier_root: bytes = EMPTY_ROOT    # reserved for the shielded pool; unchanged in v1

    def commitment(self) -> bytes:
        return _h(_P_STATE, self.utxo_root, self.nullifier_root)


@dataclass(frozen=True, kw_only=True)
class Context:
    height: int
    subsidy: int
    auth: AuthFn = field(compare=False)      # required: there is deliberately no default
    coinbase_maturity: int = COINBASE_MATURITY
    # The block's parents_root. validate_body sets it from the header; callers of
    # apply_block_txs / FullNode.build pass the parents_root the block will carry.
    parents_root: bytes = EMPTY


def context_fee(tx: Tx, records: Sequence[UtxoRecord], ctx: Context) -> int | None:
    """Fee if the context rules pass (maturity, value, authorization), else None."""
    for r in records:
        if r.coinbase and ctx.height < r.height + ctx.coinbase_maturity:
            return None
    total_in = sum(r.amount for r in records)
    total_out = sum(o.amount for o in tx.outputs)
    if total_in < total_out:
        return None
    if not ctx.auth(tx, records):
        return None
    return total_in - total_out


def check_block_txs(txs: Sequence[Tx], ctx: Context) -> None:
    if not 1 <= len(txs) <= MAX_TXS:
        raise InvalidBlock("isolation", "transaction count")
    for i, tx in enumerate(txs):
        check_tx_isolation(tx)
        if (tx.kind == TX_COINBASE) != (i == 0):
            raise InvalidBlock("isolation", "coinbase must be first and only first")
    if sum(len(t.inputs) + len(t.outputs) for t in txs) > MAX_BLOCK_KEYS:
        raise InvalidBlock("isolation", "too many inputs and outputs in the block")
    if txs[0].height != ctx.height:
        raise InvalidBlock("isolation", "coinbase height")
    # Coinbase uniqueness: the coinbase commits to the block's height AND its parent
    # set, so two blocks can share a coinbase (and its output keys) only if they are
    # built on the very same parents at the same height by the same payee with the
    # same extra: a choice of their own producer, not something another miner can
    # force on them without mining a sibling block that pays them.
    if txs[0].parents_root != ctx.parents_root:
        raise InvalidBlock("isolation", "coinbase parents root")


def apply_block_txs(state: State, txs: Sequence[Tx], witness: bytes, ctx: Context, *,
                    merged: bool = False) -> tuple[State, list[bool]]:
    """Stateless transition. Regular transactions are processed in order, then the
    coinbase (txs[0]) last, so it can claim the fees accepted in the same block.
    Every proof is checked against the root left by the previous operation.

    merged=True applies a block of a chain block's MERGESET (not its selected
    parent chain) under the mergeset coinbase-collision rule (audit LED-1): a
    merged block whose coinbase output already exists -- an identical coinbase at
    the same height on the same parents, i.e. a twin of a block applied before
    it -- forfeits its coinbase. Its coinbase entry is then REJECT_OUTPUT_EXISTS
    proving that one of its output keys holds exactly the record this coinbase
    would create; no coinbase output is created, its other outcomes stand, and
    the merging block stays valid. Without merged the same entry makes the block
    invalid (coinbase), as before."""
    check_block_txs(txs, ctx)
    r = _Reader(witness, "witness-format")
    if r.u32() != len(txs):
        raise InvalidBlock("witness-format", "entry count")
    root = state.utxo_root
    fees = 0
    accepted = [False] * len(txs)

    def spend(op: Outpoint, rec_bytes: bytes, sibs: list[bytes], cur: bytes, update: bool) -> bytes:
        key = outpoint_key(op.txid, op.vout)
        if root_from(key, leaf_hash(key, _H_UTXO(rec_bytes)), sibs) != cur:
            raise InvalidBlock("witness-mismatch", "spent output not in the tree")
        return root_from(key, EMPTY, sibs) if update else cur

    for idx in range(1, len(txs)):
        tx = txs[idx]
        tid = txid(tx)
        tag = r.u8()
        if tag == ACCEPT:
            records = []
            for op in tx.inputs:
                rec_bytes = r.take(RECORD_LEN)
                records.append(UtxoRecord.decode(rec_bytes))
                root = spend(op, rec_bytes, r.proof(), root, update=True)
            fee = context_fee(tx, records, ctx)
            if fee is None:
                raise InvalidBlock("accept-invalid", f"tx {idx} fails context rules")
            for o, out in enumerate(tx.outputs):
                root = _create(root, tid, o, UtxoRecord(out.amount, out.owner, ctx.height, False), r.proof())
            fees += fee
            accepted[idx] = True
        elif tag == REJECT_MISSING_INPUT:
            i = r.u32()
            if i >= len(tx.inputs):
                raise InvalidBlock("witness-format", "input index")
            key = outpoint_key(tx.inputs[i].txid, tx.inputs[i].vout)
            if root_from(key, EMPTY, r.proof()) != root:
                raise InvalidBlock("witness-mismatch", "claimed-missing input is present")
        elif tag == REJECT_OUTPUT_EXISTS:
            o = r.u32()
            if o >= len(tx.outputs):
                raise InvalidBlock("witness-format", "output index")
            value = r.take(32)
            key = outpoint_key(tid, o)
            if root_from(key, leaf_hash(key, value), r.proof()) != root:
                raise InvalidBlock("witness-mismatch", "claimed-existing output is absent")
        elif tag == REJECT_CONTEXT:
            records = []
            for op in tx.inputs:
                rec_bytes = r.take(RECORD_LEN)
                records.append(UtxoRecord.decode(rec_bytes))
                spend(op, rec_bytes, r.proof(), root, update=False)
            if context_fee(tx, records, ctx) is not None:
                raise InvalidBlock("reject-invalid", f"tx {idx} passes context rules")
        else:
            raise InvalidBlock("witness-format", "unknown tag")

    cb = txs[0]
    tag = r.u8()
    if tag not in (ACCEPT, REJECT_OUTPUT_EXISTS):
        raise InvalidBlock("witness-format", "coinbase entry must be ACCEPT or a collision proof")
    # Every regular outcome above is proven, so `fees` is forced: an overclaim is the block's fault.
    # The one exception is a merged twin forfeiting its coinbase (checked below): it mints nothing,
    # and its identical coinbase claimed the twin's fees when the twin was applied -- the same fees
    # that make this block's own transactions fail now, so its `fees` here can be 0.
    if (sum(o.amount for o in cb.outputs) > ctx.subsidy + fees
            and not (merged and tag == REJECT_OUTPUT_EXISTS)):
        raise InvalidBlock("coinbase", "claims more than subsidy plus fees")
    cid = txid(cb)
    if tag == REJECT_OUTPUT_EXISTS:
        # A coinbase whose output key is already taken can never be applied. This entry lets a
        # relaying node prove it, so the block is marked invalid rather than its relayers blamed.
        o = r.u32()
        if o >= len(cb.outputs):
            raise InvalidBlock("witness-format", "output index")
        value = r.take(32)
        key = outpoint_key(cid, o)
        if root_from(key, leaf_hash(key, value), r.proof()) != root:
            raise InvalidBlock("witness-mismatch", "claimed-existing coinbase output is absent")
        if not merged:
            raise InvalidBlock("coinbase", "coinbase output already exists")
        # Mergeset rule: the twin of an applied block forfeits its coinbase. The
        # existing output must be exactly what this coinbase would create. A
        # forfeit is exempt from the claim check above: nothing is minted, and
        # the identical coinbase holding the output passed it when applied.
        out = cb.outputs[o]
        if value != utxo_value(UtxoRecord(out.amount, out.owner, ctx.height, True)):
            raise InvalidBlock("coinbase", "colliding output is not an identical coinbase output")
        if not r.done():
            raise InvalidBlock("witness-format", "trailing bytes")
        return State(root, state.nullifier_root), accepted
    for o, out in enumerate(cb.outputs):
        root = _create(root, cid, o, UtxoRecord(out.amount, out.owner, ctx.height, True), r.proof())
    accepted[0] = True
    if not r.done():
        raise InvalidBlock("witness-format", "trailing bytes")
    return State(root, state.nullifier_root), accepted


def _H_UTXO(rec_bytes: bytes) -> bytes:
    return _h(_P_UTXO, rec_bytes)


def _create(root: bytes, tid: bytes, vout: int, record: UtxoRecord, sibs: list[bytes]) -> bytes:
    key = outpoint_key(tid, vout)
    if root_from(key, EMPTY, sibs) != root:
        raise InvalidBlock("witness-mismatch", "new output key already present")
    return root_from(key, utxo_leaf(key, record), sibs)


# --------------------------------------------------------------------------- header and block

@dataclass(frozen=True)
class Header:
    parents_root: bytes      # commitment to the GhostDAG parents (consensus layer)
    tx_root: bytes
    witness_root: bytes      # witness_commitment(bundle)
    state_commitment: bytes
    timestamp: int
    target: int
    version: int = VERSION

    def encode(self) -> bytes:
        return (struct.pack("<I", self.version) + self.parents_root + self.tx_root
                + self.witness_root + self.state_commitment + struct.pack("<Q", self.timestamp)
                + self.target.to_bytes(32, "big"))

    @staticmethod
    def decode(b: bytes) -> "Header":
        if len(b) != HEADER_LEN:
            raise InvalidBlock("header", "length")
        return Header(b[4:36], b[36:68], b[68:100], b[100:132], struct.unpack_from("<Q", b, 132)[0],
                      int.from_bytes(b[140:172], "big"), struct.unpack_from("<I", b, 0)[0])


def witness_commitment(witness: bytes) -> bytes:
    """What the header's witness_root commits to: the exact bundle bytes."""
    return _h(_P_WITNESS, witness)


def tx_root(wtxids: Sequence[bytes]) -> bytes:
    """Binary tree over wtxids (so authorization is committed), odd node promoted
    unchanged, count committed at the top."""
    level = list(wtxids)
    while len(level) > 1:
        nxt = [_h(_P_TXNODE, level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return _h(_P_TXROOT, struct.pack("<I", len(wtxids)), level[0] if level else EMPTY)


def block_id(header_bytes: bytes, nonce: int) -> bytes:
    return _h(_P_BLOCK, header_bytes, struct.pack("<Q", nonce))


def validate_header(header_bytes: bytes, nonce: int, *, log2_n: int | None = None,
                    max_target: int = (1 << 256) - 1) -> Header:
    """Header stage: every failure is permanent. Nodes cache the result per block id, so
    a header replayed with a junk body or witness costs no second GnB-SMH evaluation.
    log2_n=None means the canonical GnB-SMH size; tests pass a small value."""
    import gnb_smh

    hdr = Header.decode(header_bytes)
    if hdr.version != VERSION:
        raise InvalidBlock("header", "version")
    if not 1 <= hdr.target <= max_target:
        raise InvalidBlock("target", "out of range")
    out = gnb_smh.gnb_smh(header_bytes, nonce, gnb_smh.LOG2_N if log2_n is None else log2_n)
    if not gnb_smh.meets_target(out, hdr.target):
        raise InvalidBlock("pow")
    return hdr


def validate_body(parent: State, hdr: Header, tx_wires: Sequence[bytes], witness: bytes,
                  ctx: Context) -> tuple[State, list[bool]]:
    """Body stage. The transactions must hash to the header's tx_root and the bundle to
    its witness_root before anything in them is judged: a mismatch is transient (wrong
    body or bundle for this header), while a committed body or bundle that breaks a
    rule is permanent. So a bad bundle costs one hash per attempt, and the proof checks
    of a block id run to completion at most once. Peers' oversized bodies should be
    cut at the network layer; hashing here is linear in what was received, and a
    witness above MAX_WITNESS_BYTES is refused before it is hashed (transient: it
    cannot be the committed bundle of a valid block)."""
    if tx_root([wtxid(w) for w in tx_wires]) != hdr.tx_root:
        raise InvalidBlock("tx-root")
    if len(witness) > MAX_WITNESS_BYTES:
        raise InvalidBlock("witness-size", "bundle exceeds MAX_WITNESS_BYTES")
    if witness_commitment(witness) != hdr.witness_root:
        raise InvalidBlock("witness-commitment")
    if sum(len(w) for w in tx_wires) > MAX_BLOCK_TX_BYTES:
        raise InvalidBlock("isolation", "block size")
    txs = [decode_tx_wire(w) for w in tx_wires]
    ctx = dataclasses.replace(ctx, parents_root=hdr.parents_root)
    new_state, accepted = apply_block_txs(parent, txs, witness, ctx)
    if new_state.commitment() != hdr.state_commitment:
        raise InvalidBlock("state-commitment")
    return new_state, accepted


def validate_block(parent: State, header_bytes: bytes, nonce: int, tx_wires: Sequence[bytes],
                   witness: bytes, ctx: Context, *, log2_n: int | None = None,
                   max_target: int = (1 << 256) - 1) -> tuple[State, list[bool]]:
    """Header stage, then body stage."""
    hdr = validate_header(header_bytes, nonce, log2_n=log2_n, max_target=max_target)
    return validate_body(parent, hdr, tx_wires, witness, ctx)


# --------------------------------------------------------------------------- block producer

class FullNode:
    """Holds the whole UTXO set and produces witness bundles. The validator never
    needs this; block producers and bridge nodes do."""

    def __init__(self) -> None:
        self.tree = SparseMerkleTree()
        self.utxos: dict[bytes, UtxoRecord] = {}

    def state(self) -> State:
        return State(self.tree.root(), EMPTY_ROOT)

    def insert(self, key: bytes, record: UtxoRecord) -> None:
        self.tree.set(key, utxo_leaf(key, record))
        self.utxos[key] = record

    def build(self, txs: Sequence[Tx], ctx: Context, *, merged: bool = False
              ) -> tuple[bytes, list[bool], int]:
        """Decide every outcome exactly as the validator will, apply it, and return
        (witness bundle, accepted flags, fees of the accepted transactions)."""
        check_block_txs(txs, ctx)
        parts = [struct.pack("<I", len(txs))]
        fees = 0
        accepted = [False] * len(txs)
        for idx in range(1, len(txs)):
            tx = txs[idx]
            tid = txid(tx)
            keys = [outpoint_key(op.txid, op.vout) for op in tx.inputs]
            missing = next((i for i, k in enumerate(keys) if k not in self.utxos), None)
            if missing is not None:
                parts += [bytes([REJECT_MISSING_INPUT]), struct.pack("<I", missing),
                          self.tree.proof(keys[missing])]
                continue
            records = [self.utxos[k] for k in keys]
            fee = context_fee(tx, records, ctx)
            if fee is None:
                parts.append(bytes([REJECT_CONTEXT]))
                for k, rec in zip(keys, records):
                    parts += [rec.encode(), self.tree.proof(k)]
                continue
            out_keys = [outpoint_key(tid, o) for o in range(len(tx.outputs))]
            existing = next((o for o, k in enumerate(out_keys) if k in self.utxos), None)
            if existing is not None:
                k = out_keys[existing]
                parts += [bytes([REJECT_OUTPUT_EXISTS]), struct.pack("<I", existing),
                          utxo_value(self.utxos[k]), self.tree.proof(k)]
                continue
            parts.append(bytes([ACCEPT]))
            for k, rec in zip(keys, records):
                parts += [rec.encode(), self.tree.proof(k)]
                self.tree.set(k, EMPTY)
                del self.utxos[k]
            for o, (k, out) in enumerate(zip(out_keys, tx.outputs)):
                parts.append(self.tree.proof(k))
                self.insert(k, UtxoRecord(out.amount, out.owner, ctx.height, False))
            fees += fee
            accepted[idx] = True
        cb = txs[0]
        overclaim = sum(o.amount for o in cb.outputs) > ctx.subsidy + fees
        cid = txid(cb)
        out_keys = [outpoint_key(cid, o) for o in range(len(cb.outputs))]
        taken = next((o for o, k in enumerate(out_keys) if k in self.utxos), None)
        # A merged twin forfeiting its coinbase is exempt from the claim check
        # (see apply_block_txs); every other coinbase is held to it.
        if overclaim and not (merged and taken is not None):
            raise InvalidBlock("coinbase", "claims more than subsidy plus fees")
        if taken is not None:
            if not merged:
                raise InvalidBlock("coinbase", "coinbase output already exists")
            # Mergeset rule: a twin of an applied block forfeits its coinbase.
            k = out_keys[taken]
            parts += [bytes([REJECT_OUTPUT_EXISTS]), struct.pack("<I", taken),
                      utxo_value(self.utxos[k]), self.tree.proof(k)]
        else:
            parts.append(bytes([ACCEPT]))
            for k, out in zip(out_keys, cb.outputs):
                parts.append(self.tree.proof(k))
                self.insert(k, UtxoRecord(out.amount, out.owner, ctx.height, True))
            accepted[0] = True
        bundle = b"".join(parts)
        if len(bundle) > MAX_WITNESS_BYTES:
            raise InvalidBlock("witness-size", "bundle exceeds MAX_WITNESS_BYTES: include fewer transactions")
        return bundle, accepted, fees


if __name__ == "__main__":
    print(f"empty root  {EMPTY_ROOT.hex()}")
    print(f"genesis commitment {State().commitment().hex()}")
