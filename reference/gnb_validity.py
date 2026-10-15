"""GnB transaction and block validity -- executable reference of every
NON-signature consensus rule (and the mempool relay policy) that the
data-driven vectors pin (reference/tx_vectors.json, reference/block_vectors.json;
docs/testing/VECTORS.md).

Written from docs/CONSENSUS.md with no Rust in the loop. It builds on the
other references: `gnb_merkle` (wire encoding, txid / wtxid, Merkle trees,
coinbase commitment, 64-byte rule), `gnb_sighash` (both digests, the version
rule and policy) and `gnb_difficulty` (compact bits). What it does NOT do is
signature mathematics (ML-DSA-65 / Falcon-1024 verification): every rule
around it -- witness framing, canonical signature encoding, the public-key
hash, the digest a signature must cover -- is modelled, and the signature
check itself is reported as "not evaluated".

Rule order follows the node: a block applies each structural rule to every
transaction before the next rule (`Block::validate_structure_without_pow_at`,
then `limits::check_block_context_free`), then connects the transactions one
by one (`accept::validate_block_in_view`). The first failing rule names the
error class (the classes are listed in docs/testing/VECTORS.md).
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

import gnb_difficulty as df
import gnb_merkle as mk
import gnb_sighash as sh

# ── Consensus constants (docs/CONSENSUS.md, docs/MONETARY-POLICY.md) ─────────

SAT_PER_GNB = 100_000_000
MAX_SUPPLY_SAT = 10_000_000 * SAT_PER_GNB
HALVING_INTERVAL = 4 * 365 * 2_880
INITIAL_SUBSIDY_SAT = (MAX_SUPPLY_SAT - MAX_SUPPLY_SAT // 10) // (2 * HALVING_INTERVAL)
COINBASE_MATURITY = 100
DUST_THRESHOLD = 546
MIN_TX_FEE_SAT = 10_000
MIN_FEE_RATE_SAT_PER_KB = 2_000
MAX_BLOCK_SIZE = 1_000_000
MAX_PARENTS = 256
MAX_SCRIPT_LEN = 10_000
MAX_TX_INPUTS = 100_000
MAX_TX_OUTPUTS = 100_000
MAX_BLOCK_TXS = 1_000_000
MAX_SHIELDED_TXS = 100_000
POW_LIMIT_BITS = 0x2100FFFF
HARDENED_POW_LIMIT_BITS = 0x1F0E9036  # the genesis target
BLOCK_ID_DOMAIN = b"GNB-BLOCK-ID-v1"

# Relay policy (node/src/mempool).
MAX_TX_SIZE = 400 * 1024
MIN_RELAY_FEE_RATE = 1  # base units per bincode byte

# Signature formats (docs/CONSENSUS.md, "Witnesses").
ENVELOPE_MAGIC = b"\xb1\x0c"
SUITE_HYBRID = 0x0001
SUITE_MLDSA_ONLY = 0x0002
MLDSA_PK_LEN = 1952
MLDSA_SIG_LEN = 3309
FALCON_PK_LEN = 1793
FALCON1024_SIG_MAX = 1462  # compact encoding bound (PQClean CRYPTO_BYTES)
FALCON1024_HEADER = 0x30 + 10
FALCON_NONCE_LEN = 40
RAW_HYBRID_PK_LEN = MLDSA_PK_LEN + FALCON_PK_LEN

assert INITIAL_SUBSIDY_SAT == 107_020_547


def subsidy(height: int) -> int:
    if height == 0 or height // HALVING_INTERVAL >= 64:
        return 0
    return INITIAL_SUBSIDY_SAT >> (height // HALVING_INTERVAL)


def min_fee(wire_size: int) -> int:
    return max(MIN_TX_FEE_SAT, -(-wire_size * MIN_FEE_RATE_SAT_PER_KB // 1000))


def tx_rules_active(height: int, activation: int) -> bool:
    """The transaction-rule predicate (version rule, and in the mempool also
    the 64-byte rule)."""
    return height >= activation


def block_rules_active(height: int, activation: int) -> bool:
    return mk.rules_active_at(height, activation)


# ── Decoding (Transaction::from_wire_bytes, Block::from_wire_bytes) ──────────

class DecodeError(ValueError):
    pass


class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise DecodeError("unexpected end of data")
        b = self.data[self.pos:self.pos + n]
        self.pos += n
        return b

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self.take(8))[0]

    def varint(self) -> int:
        """Bitcoin varint; a non-minimal encoding is accepted here and caught
        by the canonical re-encoding check."""
        tag = self.take(1)[0]
        if tag == 0xFF:
            return self.u64()
        if tag == 0xFE:
            return self.u32()
        if tag == 0xFD:
            return struct.unpack("<H", self.take(2))[0]
        return tag


def read_tx(r: Reader) -> mk.Tx:
    version = r.u32()
    n_in = r.varint()
    if n_in > MAX_TX_INPUTS:
        raise DecodeError("implausible input count")
    inputs = []
    for _ in range(n_in):
        txid = r.take(32)
        index = r.u32()
        n = r.varint()
        if n > MAX_SCRIPT_LEN:
            raise DecodeError("implausible script_sig length")
        inputs.append(mk.TxIn(txid, index, r.take(n), r.u32()))
    n_out = r.varint()
    if n_out > MAX_TX_OUTPUTS:
        raise DecodeError("implausible output count")
    outputs = []
    for _ in range(n_out):
        value = r.u64()
        n = r.varint()
        if n > MAX_SCRIPT_LEN:
            raise DecodeError("implausible script_pubkey length")
        outputs.append(mk.TxOut(value, r.take(n)))
    return mk.Tx(version, inputs, outputs, r.u32())


def decode_tx_strict(b: bytes) -> mk.Tx:
    """The node decodes gossip / RPC transactions strictly: the bytes must be
    the canonical encoding (no trailing byte, minimal varints)."""
    tx = read_tx(Reader(b))
    if tx.wire(True) != b:
        raise DecodeError("non-canonical transaction encoding")
    return tx


@dataclass
class Header:
    version: int
    parents: list
    merkle_root: bytes
    timestamp: int
    bits: int
    nonce: int

    def pow_preimage(self) -> bytes:
        return (struct.pack("<II", self.version, len(self.parents)) + b"".join(self.parents) + self.merkle_root
                + struct.pack("<QI", self.timestamp, self.bits))


@dataclass
class Block:
    header: Header
    txs: list
    blue_score: int
    height: int

    def wire(self) -> bytes:
        h = self.header
        out = struct.pack("<I", h.version) + mk.varint(len(h.parents)) + b"".join(h.parents) + h.merkle_root
        out += struct.pack("<QIQQQ", h.timestamp, h.bits, h.nonce, self.blue_score, self.height)
        out += mk.varint(len(self.txs)) + b"".join(t.wire(True) for t in self.txs)
        return out + mk.varint(0)  # no shielded transactions

    def block_hash(self) -> bytes:
        return hashlib.sha3_256(BLOCK_ID_DOMAIN + self.header.pow_preimage()
                                + struct.pack("<Q", self.header.nonce)).digest()


def decode_block(b: bytes) -> Block:
    r = Reader(b)
    version = r.u32()
    n = r.varint()
    if n > MAX_PARENTS:
        raise DecodeError("implausible parent count")
    parents = [r.take(32) for _ in range(n)]
    merkle_root = r.take(32)
    timestamp, bits, nonce, blue, height = r.u64(), r.u32(), r.u64(), r.u64(), r.u64()
    body = b[r.pos:]
    rb = Reader(body)
    count = rb.varint()
    if count > MAX_BLOCK_TXS:
        raise DecodeError("implausible tx count")
    offset = rb.pos
    txs = []
    for _ in range(count):
        tx = read_tx(Reader(body[offset:]))
        # The Rust decoder advances by the CANONICAL length of each
        # transaction (a non-minimal varint inside one misaligns the rest).
        offset += len(tx.wire(True))
        txs.append(tx)
    rs = Reader(body[offset:])
    n_shielded = rs.varint()
    if n_shielded > MAX_SHIELDED_TXS:
        raise DecodeError("implausible shielded count")
    if n_shielded:
        raise NotImplementedError("shielded transactions are not modelled by this reference")
    if offset + rs.pos != len(body):
        raise DecodeError("trailing bytes in block body")
    return Block(Header(version, parents, merkle_root, timestamp, bits, nonce), txs, blue, height)


# ── bincode-2 "standard" sizes (the block-size measure below the activation) ─

def tx_bincode(tx: mk.Tx) -> bytes:
    v = sh.bincode_varint
    out = v(tx.version) + v(len(tx.inputs))
    for i in tx.inputs:
        out += i.prev_txid + v(i.prev_index) + v(len(i.script_sig)) + i.script_sig + v(i.sequence)
    out += v(len(tx.outputs))
    for o in tx.outputs:
        out += v(o.value) + v(len(o.script_pubkey)) + o.script_pubkey
    return out + v(tx.locktime)


def block_bincode_size(b: Block) -> int:
    v = sh.bincode_varint
    h = b.header
    n = len(v(h.version)) + len(v(len(h.parents))) + 32 * len(h.parents) + 32
    n += len(v(h.timestamp)) + len(v(h.bits)) + len(v(h.nonce))
    n += len(v(len(b.txs))) + sum(len(tx_bincode(t)) for t in b.txs)
    return n + len(v(b.blue_score)) + len(v(b.height)) + len(v(0))


# ── Witnesses and signature encodings ───────────────────────────────────────

def parse_witness(ss: bytes):
    """`[u32 sig_len][sig][u32 pk_len][pk]` -> (sig, pk, end) or None."""
    if len(ss) < 8:
        return None
    sig_len = struct.unpack("<I", ss[:4])[0]
    if len(ss) < sig_len + 8:
        return None
    pk_len = struct.unpack("<I", ss[4 + sig_len:8 + sig_len])[0]
    end = 8 + sig_len + pk_len
    if len(ss) < end:
        return None
    return ss[4:4 + sig_len], ss[8 + sig_len:end], end


def parse_witness_lenient(ss: bytes):
    """Below the activation: bytes after the public key are ignored."""
    w = parse_witness(ss)
    return None if w is None else (w[0], w[1])


def parse_witness_exact(ss: bytes):
    w = parse_witness(ss)
    return None if w is None or w[2] != len(ss) else (w[0], w[1])


def falcon_compact_len(enc: bytes):
    """Length-only mirror of PQClean's comp_decode for Falcon-1024 (1,024
    coefficients, sign / 7 low bits / unary high bits); None if malformed."""
    acc = 0
    bits = 0
    used = 0
    for _ in range(1024):
        if used >= len(enc):
            return None
        acc = ((acc << 8) | enc[used]) & 0xFFFFFFFF
        used += 1
        first = acc >> bits
        sign = first & 128
        magnitude = first & 127
        while True:
            if bits == 0:
                if used >= len(enc):
                    return None
                acc = ((acc << 8) | enc[used]) & 0xFFFFFFFF
                used += 1
                bits = 8
            bits -= 1
            if (acc >> bits) & 1:
                break
            magnitude += 128
            if magnitude > 2047:
                return None
        if sign and magnitude == 0:
            return None
    if acc & ((1 << bits) - 1):
        return None
    return used


def is_canonical_falcon(sig: bytes) -> bool:
    if len(sig) > FALCON1024_SIG_MAX or len(sig) <= 1 + FALCON_NONCE_LEN or sig[0] != FALCON1024_HEADER:
        return False
    enc = sig[1 + FALCON_NONCE_LEN:]
    return falcon_compact_len(enc) == len(enc)


def envelope(b: bytes):
    if len(b) < 4 or b[:2] != ENVELOPE_MAGIC:
        return None
    return struct.unpack("<H", b[2:4])[0], b[4:]


def is_canonical_signature(sig: bytes) -> bool:
    env = envelope(sig)
    if env is None:
        return False
    suite, body = env
    if suite == SUITE_HYBRID:
        return len(body) > MLDSA_SIG_LEN and is_canonical_falcon(body[MLDSA_SIG_LEN:])
    if suite == SUITE_MLDSA_ONLY:
        return len(body) == MLDSA_SIG_LEN
    return False


def is_hybrid_public_key(pk: bytes) -> bool:
    if len(pk) == RAW_HYBRID_PK_LEN:
        return True  # raw carry-over key
    env = envelope(pk)
    suite, body = env if env is not None else (SUITE_HYBRID, pk)
    return suite == SUITE_HYBRID and len(body) == RAW_HYBRID_PK_LEN


def pubkey_hash(pk: bytes) -> bytes:
    return hashlib.sha3_256(pk).digest()[:20]


def signature_suite(ss: bytes) -> int:
    """The suite id sighash v3 commits for an input: the signature
    envelope's, or 0x0001 when there is none."""
    w = parse_witness_lenient(ss)
    env = envelope(w[0]) if w else None
    return env[0] if env else SUITE_HYBRID


# ── The UTXO view ───────────────────────────────────────────────────────────

@dataclass
class View:
    utxos: dict = field(default_factory=dict)          # (txid, vout) -> mk.TxOut
    coinbase_heights: dict = field(default_factory=dict)  # txid -> height
    # The transaction index: every coin's creating txid (mempool admission
    # refuses a transaction that is already confirmed).
    confirmed_txids: set = field(default_factory=set)


class Invalid(Exception):
    def __init__(self, cls: str):
        super().__init__(cls)
        self.cls = cls


class Outcome:
    """`signatures`: (tx, input index, digest version, spent outputs) of every
    signature the rules required but this reference did not verify."""

    def __init__(self):
        self.signatures = []


# ── Transaction rules ───────────────────────────────────────────────────────

def money_add(a: int, b: int) -> int:
    s = a + b
    if s > MAX_SUPPLY_SAT:
        raise Invalid("value-out-of-range")
    return s


def tx_money_range(tx: mk.Tx) -> int:
    total = 0
    for o in tx.outputs:
        if o.value > MAX_SUPPLY_SAT:
            raise Invalid("value-out-of-range")
        total = money_add(total, o.value)
    return total


def check_input_scripts(tx: mk.Tx, prevouts: list, height: int, activation: int, out: Outcome) -> None:
    """Version rule, witnesses, public-key hashes (the signatures themselves
    are recorded in `out`, not verified)."""
    rule = sh.version_rule(tx.version, height, activation)
    if rule == "invalid":
        raise Invalid("bad-version")
    for i, (inp, prev) in enumerate(zip(tx.inputs, prevouts)):
        if rule == "v2":
            w = parse_witness_lenient(inp.script_sig)
            if w is None:
                raise Invalid("witness-malformed")
        else:
            w = parse_witness_exact(inp.script_sig)
            if w is None or not is_canonical_signature(w[0]):
                raise Invalid("witness-non-canonical")
        if pubkey_hash(w[1]) != prev.script_pubkey:
            raise Invalid("pubkey-mismatch")
    for i in range(len(tx.inputs)):
        out.signatures.append((tx, i, rule, prevouts))


def connect_tx(tx: mk.Tx, view: View, earlier: dict, spent_in_block: set, height: int, activation: int,
               same_block_coinbase, out: Outcome) -> int:
    """`validate_tx_in_view`: one non-coinbase transaction of a block at
    `height`; returns the fee."""
    if same_block_coinbase is not None and any(i.prev_txid == same_block_coinbase for i in tx.inputs):
        raise Invalid("same-block-coinbase")
    if height != 0:
        for i in tx.inputs:
            cbh = view.coinbase_heights.get(i.prev_txid)
            if cbh is not None and max(0, height - cbh) < COINBASE_MATURITY:
                raise Invalid("immature-coinbase")
    local = set()
    prevouts = []
    total_in = 0
    for i in tx.inputs:
        op = (i.prev_txid, i.prev_index)
        if op in spent_in_block or op in local:
            raise Invalid("double-spend")
        local.add(op)
        coin = earlier.get(op) or view.utxos.get(op)
        if coin is None:
            raise Invalid("missing-input")
        total_in = money_add(total_in, coin.value)
        prevouts.append(coin)
    check_input_scripts(tx, prevouts, height, activation, out)
    spent_in_block |= local
    total_out = tx_money_range(tx)
    if total_in < total_out:
        raise Invalid("inputs-below-outputs")
    fee = total_in - total_out
    if fee < min_fee(len(tx.wire(True))):
        raise Invalid("min-fee")
    return fee


def connect_block(b: Block, view: View, activation: int, out: Outcome) -> None:
    """`validate_block_in_view_at`: BIP30 and the same-block coinbase rule
    from the activation, every transaction, the coinbase value."""
    hardened = block_rules_active(b.height, activation)
    if hardened:
        for tx in b.txs:
            txid = tx.txid()
            if any((txid, j) in view.utxos for j in range(len(tx.outputs))):
                raise Invalid("bip30")
    same_cb = b.txs[0].txid() if hardened and b.txs else None
    earlier, spent, fees = {}, set(), 0
    for i, tx in enumerate(b.txs):
        if i > 0:
            fees = money_add(fees, connect_tx(tx, view, earlier, spent, b.height, activation, same_cb, out))
        if hardened and i == 0:
            continue
        txid = tx.txid()
        for j, o in enumerate(tx.outputs):
            earlier[(txid, j)] = o
    cb = b.txs[0]
    if len(cb.outputs) != 1:
        raise Invalid("coinbase-output-count")
    allowed = subsidy(b.height) + fees
    if allowed >= 1 << 64 or cb.outputs[0].value > allowed:
        raise Invalid("coinbase-value")


# ── Block rules ─────────────────────────────────────────────────────────────

COMMITMENT_CLASSES = {"missing": "cb-commitment-missing", "tag": "cb-commitment-tag", "height": "cb-height",
                      "parents": "cb-parents", "witness": "witness-commitment"}


def merkle_root_at(b: Block, activation: int) -> bytes:
    return mk.merkle_root([t.txid() for t in b.txs], block_rules_active(b.height, activation))


def check_structure(b: Block, activation: int) -> None:
    """`Block::validate_structure_without_pow_at` (and the redundant
    `block_rules::check_block_hardened_at`)."""
    hardened = block_rules_active(b.height, activation)
    if len(b.header.parents) > MAX_PARENTS:
        raise Invalid("too-many-parents")
    size = len(b.wire()) if hardened else block_bincode_size(b)
    if size > MAX_BLOCK_SIZE:
        raise Invalid("block-size")
    if merkle_root_at(b, activation) != b.header.merkle_root:
        raise Invalid("bad-merkle-root")
    if not b.txs or not b.txs[0].is_coinbase() or any(t.is_coinbase() for t in b.txs[1:]):
        raise Invalid("coinbase-format")
    if hardened:
        if any(mk.is_forbidden_64(t) for t in b.txs):
            raise Invalid("tx-64-bytes")
        reason = mk.check_coinbase_commitment(b.height, b.header.parents, b.txs)
        if reason is not None:
            raise Invalid(COMMITMENT_CLASSES[reason])
    ids = [t.txid() for t in b.txs]
    if len(set(ids)) != len(ids):
        raise Invalid("duplicate-tx")
    for t in b.txs[1:]:
        if any(0 < o.value < DUST_THRESHOLD for o in t.outputs):
            raise Invalid("dust")


def check_pow_limit(b: Block, activation: int) -> None:
    try:
        target = df.bits_to_target(b.header.bits)
    except df.BitsError:
        raise Invalid("bad-bits")
    limit = HARDENED_POW_LIMIT_BITS if block_rules_active(b.height, activation) else POW_LIMIT_BITS
    if target > df.bits_to_target(limit):
        raise Invalid("pow-limit")


def check_context_free(b: Block) -> None:
    """`limits::check_block_context_free` (the encoding caps hold for every
    decoded block): MoneyRange of every output, transaction and the block."""
    total = 0
    for t in b.txs:
        total = money_add(total, tx_money_range(t))


def validate_block(b: Block, view: View, activation: int, scope: str, pow_mode: str, out: Outcome) -> None:
    if scope == "full":
        check_structure(b, activation)
        if pow_mode in ("limit", "full"):
            check_pow_limit(b, activation)
        check_context_free(b)
    connect_block(b, view, activation, out)


def tx_context_free(b: Block, activation: int) -> None:
    """The per-transaction subset of the structural rules (tx vectors)."""
    if not b.txs[0].is_coinbase() or any(t.is_coinbase() for t in b.txs[1:]):
        raise Invalid("coinbase-format")
    if block_rules_active(b.height, activation) and any(mk.is_forbidden_64(t) for t in b.txs[1:]):
        raise Invalid("tx-64-bytes")
    for t in b.txs[1:]:
        if any(0 < o.value < DUST_THRESHOLD for o in t.outputs):
            raise Invalid("dust")
    check_context_free(b)


# ── Mempool admission (relay policy) ────────────────────────────────────────

def admission(tx: mk.Tx, view: View, height: int, activation: int, out: Outcome) -> None:
    """`admission::check_transaction` with relay policy (signatures on), for
    the next block at `height`: raises Invalid(class) on refusal."""
    if tx.is_coinbase():
        raise Invalid("coinbase-format")
    if not tx.inputs:
        raise Invalid("non-standard-no-inputs")
    if not tx.outputs:
        raise Invalid("non-standard-no-outputs")
    if len(tx.wire(True)) > MAX_TX_SIZE or len(tx_bincode(tx)) > MAX_TX_SIZE:
        raise Invalid("non-standard-size")
    if tx.txid() in view.confirmed_txids:
        raise Invalid("already-confirmed")
    tx_money_range(tx)
    for o in tx.outputs:
        if 0 < o.value < DUST_THRESHOLD:
            raise Invalid("dust")
        if o.value == 0:
            raise Invalid("non-standard-zero-value")
    for inp in tx.inputs:
        w = parse_witness_exact(inp.script_sig)
        if w is None or not is_canonical_signature(w[0]):
            raise Invalid("non-standard-witness")
        if not is_hybrid_public_key(w[1]):
            raise Invalid("non-standard-suite")
    policy = sh.version_policy(tx.version, height, activation)
    if policy == "invalid":
        raise Invalid("bad-version")
    if policy == "non-standard":
        raise Invalid("non-standard-version")
    if tx_rules_active(height, activation) and mk.is_forbidden_64(tx):
        raise Invalid("tx-64-bytes")
    seen = set()
    for i in tx.inputs:
        op = (i.prev_txid, i.prev_index)
        if op in seen:
            raise Invalid("double-spend")
        seen.add(op)
    prevouts, total_in = [], 0
    for i in tx.inputs:
        coin = view.utxos.get((i.prev_txid, i.prev_index))
        if coin is None:
            raise Invalid("missing-input")
        total_in = money_add(total_in, coin.value)
        prevouts.append(coin)
    if height != 0:
        for i in tx.inputs:
            cbh = view.coinbase_heights.get(i.prev_txid)
            if cbh is not None and max(0, height - cbh) < COINBASE_MATURITY:
                raise Invalid("immature-coinbase")
    total_out = tx_money_range(tx)
    if total_in < total_out:
        raise Invalid("inputs-below-outputs")
    fee = total_in - total_out
    if fee < min_fee(len(tx.wire(True))):
        raise Invalid("min-fee")
    if fee < len(tx_bincode(tx)) * MIN_RELAY_FEE_RATE:
        raise Invalid("low-relay-fee")
    check_input_scripts(tx, prevouts, height, activation, out)
