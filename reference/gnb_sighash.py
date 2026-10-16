"""GnB transaction signature digests -- executable reference specification.

The normative definition of the two sighash versions and of the v3
component-bound signature messages (docs/CONSENSUS.md, "Transaction
signatures"). `crates/gnb-crypto/src/core/sighash.rs` (v3),
`Transaction::sighash` in `crates/gnb-crypto/src/core/mod.rs` (v2) and
`crypto::bound_component_message` must reproduce `sighash_vectors.json`
exactly (`crates/gnb-crypto/tests/sighash_vectors.rs`). Written from the
specification with no serialization library: every byte is spelled out here.

    python3 reference/gnb_sighash.py      # regenerate sighash_vectors.json

The output is deterministic (the random cases come from SHAKE-256 of a fixed
label), so CI regenerates the file and diffs it.

Selection (consensus, `core::sighash::check_tx_version`; `version_rule`
below): the header height h of the containing block and the transaction's
own `version` select the digest of a non-coinbase transaction.
    h <  activation: every version (3 included) is valid -> sighash v2 with
                     the historical lenient witness rule (exactly the
                     pre-upgrade rule: no split before the flag day);
    h >= activation: version 3 -> sighash v3 with the canonical witness;
                     any other version is invalid.
Relay policy (`core::sighash::check_tx_version_standard`; `version_policy`
below) additionally refuses version >= 3 below the activation as
non-standard. `version_rule` vectors pin both.

Sighash v2 (historical; must never change):

    preimage = "GNB-SIGHASH-v1\\0\\0" (16) || 0x01 || chain_id u32 LE || body
    body     = the hand-written WIRE encoding of the transaction (`wire`,
               `Transaction::to_wire_bytes(true)`) with
               script_sig := "GNB_SIGHASH" on the signed input and
               script_sig := "" on every other input
               (this chain since cc5c450: no consensus value depends on
               serde/bincode; the bincode notes below describe the
               pre-reset encoding and are kept for reference only)
    sighash  = SHA3-256(preimage)

    bincode-2 standard: structs are their fields in order; u8 is one byte;
    u32/u64 use the variable-length encoding below; [u8; 32] is 32 raw bytes;
    Vec<u8> and Vec<T> are varint(len) followed by the elements.
        v <= 250            -> v                     (1 byte)
        v <= 0xFFFF         -> 0xFB || u16 LE        (3 bytes)
        v <= 0xFFFF_FFFF    -> 0xFC || u32 LE        (5 bytes)
        otherwise           -> 0xFD || u64 LE        (9 bytes)
    Transaction = version u32, inputs Vec<TxInput>, outputs Vec<TxOutput>, locktime u32
    TxInput     = prev_txid [u8; 32], prev_index u32, script_sig Vec<u8>, sequence u32
    TxOutput    = value u64, script_pubkey Vec<u8>
    An out-of-range input index puts no marker anywhere (historical quirk;
    no valid signature is ever made for one).

Sighash v3 (CRY-3; linear cost):

    list_hash(tag, count, items) = SHA3-256(u8 len(tag) || tag || u32 LE count || items)
    hash_prevouts  = list_hash("GNB-SIGHASH-v3/prevouts",  n_in,  prev_txid || prev_index u32 LE ...)
    hash_sequences = list_hash("GNB-SIGHASH-v3/sequences", n_in,  sequence u32 LE ...)
    hash_amounts   = list_hash("GNB-SIGHASH-v3/amounts",   n_in,  spent value u64 LE ...)
    hash_scripts   = list_hash("GNB-SIGHASH-v3/scripts",   n_in,  u32 LE len || spent script_pubkey ...)
    hash_outputs   = list_hash("GNB-SIGHASH-v3/outputs",   n_out, value u64 LE || u32 LE len || script_pubkey ...)
    preimage (195 bytes) =
        "GNB-SIGHASH-v3\\0\\0" (16) || 0x03 || chain_id u32 LE || version u32 LE
        || locktime u32 LE || hash_prevouts || hash_sequences || hash_amounts
        || hash_scripts || hash_outputs || input_index u32 LE || suite_id u16 LE
    sighash_v3 = SHA3-256(preimage)
    input_index >= n_in is an ERROR (never a digest); the spent list must have
    exactly n_in entries.

v3 component messages (CRY-2): component c (0x01 ML-DSA-65, 0x02
Falcon-1024) of a suite-s signature signs

    "GNB-TXSIG-v3" (12) || s u16 LE || c || sighash_v3 (32)    (47 bytes)
"""

from __future__ import annotations

import hashlib
import json
import pathlib
from dataclasses import dataclass, field

HERE = pathlib.Path(__file__).resolve().parent

CHAIN_MAINNET = 0x474E0001
CHAIN_TESTNET = 0x474E0002

SIGHASH_V2_DOMAIN = b"GNB-SIGHASH-v1\x00\x00"
SIGHASH_V2_VERSION = 0x02   # this chain: the wire-body v2 (cc5c450)
SIGHASH_V2_MARKER = b"GNB_SIGHASH"

SIGHASH_V3_DOMAIN = b"GNB-SIGHASH-v3\x00\x00"
SIGHASH_V3_VERSION = 0x03
SIGHASH_V3_PREIMAGE_LEN = 195
TAG_PREVOUTS = b"GNB-SIGHASH-v3/prevouts"
TAG_SEQUENCES = b"GNB-SIGHASH-v3/sequences"
TAG_AMOUNTS = b"GNB-SIGHASH-v3/amounts"
TAG_SCRIPTS = b"GNB-SIGHASH-v3/scripts"
TAG_OUTPUTS = b"GNB-SIGHASH-v3/outputs"

TX_SIG_COMPONENT_DOMAIN = b"GNB-TXSIG-v3"
COMPONENT_MLDSA65 = 0x01
COMPONENT_FALCON1024 = 0x02

SUITE_HYBRID = 0x0001
SUITE_MLDSA_ONLY = 0x0002

U32_MAX = (1 << 32) - 1
U64_MAX = (1 << 64) - 1

assert len(SIGHASH_V2_DOMAIN) == 16 and len(SIGHASH_V3_DOMAIN) == 16
assert len(TX_SIG_COMPONENT_DOMAIN) == 12


@dataclass
class TxIn:
    prev_txid: bytes
    prev_index: int
    script_sig: bytes = b""
    sequence: int = U32_MAX


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


class SighashError(ValueError):
    """`kind`: InputIndexOutOfRange or SpentOutputCount (the Rust variants)."""

    def __init__(self, kind: str):
        super().__init__(kind)
        self.kind = kind


def u16(v: int) -> bytes:
    return v.to_bytes(2, "little")


def u32(v: int) -> bytes:
    return v.to_bytes(4, "little")


def u64(v: int) -> bytes:
    return v.to_bytes(8, "little")


def sha3(b: bytes) -> bytes:
    return hashlib.sha3_256(b).digest()


# ── Wire format (Transaction::to_wire_bytes(true)), used only to carry the
#    vectors' transactions: Bitcoin-style varints. ─────────────────────────────

def btc_varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + u16(n)
    if n <= U32_MAX:
        return b"\xfe" + u32(n)
    return b"\xff" + u64(n)


def wire(tx: Tx) -> bytes:
    out = u32(tx.version) + btc_varint(len(tx.inputs))
    for i in tx.inputs:
        out += i.prev_txid + u32(i.prev_index) + btc_varint(len(i.script_sig)) + i.script_sig + u32(i.sequence)
    out += btc_varint(len(tx.outputs))
    for o in tx.outputs:
        out += u64(o.value) + btc_varint(len(o.script_pubkey)) + o.script_pubkey
    return out + u32(tx.locktime)


# ── Sighash v2 ───────────────────────────────────────────────────────────────

def bincode_varint(v: int) -> bytes:
    if v <= 250:
        return bytes([v])
    if v <= 0xFFFF:
        return b"\xfb" + u16(v)
    if v <= U32_MAX:
        return b"\xfc" + u32(v)
    return b"\xfd" + u64(v)


def v2_body(tx: Tx, input_index: int) -> bytes:
    out = u32(tx.version) + btc_varint(len(tx.inputs))
    for i, inp in enumerate(tx.inputs):
        ss = SIGHASH_V2_MARKER if i == input_index else b""
        out += inp.prev_txid + u32(inp.prev_index) + btc_varint(len(ss)) + ss + u32(inp.sequence)
    out += btc_varint(len(tx.outputs))
    for o in tx.outputs:
        out += u64(o.value) + btc_varint(len(o.script_pubkey)) + o.script_pubkey
    return out + u32(tx.locktime)


def v2_preimage(tx: Tx, input_index: int, chain_id: int) -> bytes:
    return SIGHASH_V2_DOMAIN + bytes([SIGHASH_V2_VERSION]) + u32(chain_id) + v2_body(tx, input_index)


def sighash_v2(tx: Tx, input_index: int, chain_id: int) -> bytes:
    return sha3(v2_preimage(tx, input_index, chain_id))


# ── Sighash v3 ───────────────────────────────────────────────────────────────

def list_hash(tag: bytes, count: int, items: bytes) -> bytes:
    return sha3(bytes([len(tag)]) + tag + u32(count) + items)


def v3_hashes(tx: Tx, spent: list) -> dict:
    if len(spent) != len(tx.inputs):
        raise SighashError("SpentOutputCount")
    n = len(tx.inputs)
    return {
        "hash_prevouts": list_hash(TAG_PREVOUTS, n, b"".join(i.prev_txid + u32(i.prev_index) for i in tx.inputs)),
        "hash_sequences": list_hash(TAG_SEQUENCES, n, b"".join(u32(i.sequence) for i in tx.inputs)),
        "hash_amounts": list_hash(TAG_AMOUNTS, n, b"".join(u64(s.value) for s in spent)),
        "hash_scripts": list_hash(TAG_SCRIPTS, n, b"".join(u32(len(s.script_pubkey)) + s.script_pubkey for s in spent)),
        "hash_outputs": list_hash(TAG_OUTPUTS, len(tx.outputs),
                                  b"".join(u64(o.value) + u32(len(o.script_pubkey)) + o.script_pubkey for o in tx.outputs)),
    }


def v3_preimage(tx: Tx, spent: list, input_index: int, suite: int, chain_id: int) -> bytes:
    h = v3_hashes(tx, spent)
    if not 0 <= input_index < len(tx.inputs):
        raise SighashError("InputIndexOutOfRange")
    p = (SIGHASH_V3_DOMAIN + bytes([SIGHASH_V3_VERSION]) + u32(chain_id) + u32(tx.version) + u32(tx.locktime)
         + h["hash_prevouts"] + h["hash_sequences"] + h["hash_amounts"] + h["hash_scripts"] + h["hash_outputs"]
         + u32(input_index) + u16(suite))
    assert len(p) == SIGHASH_V3_PREIMAGE_LEN
    return p


def sighash_v3(tx: Tx, spent: list, input_index: int, suite: int, chain_id: int) -> bytes:
    return sha3(v3_preimage(tx, spent, input_index, suite, chain_id))


def version_rule(version: int, height: int, activation: int) -> str:
    """Consensus rule for a non-coinbase transaction in a block at header
    height `height`: "v2", "v3" or "invalid" (`check_tx_version`)."""
    if height < activation:
        return "v2"
    return "v3" if version == 3 else "invalid"


def version_policy(version: int, height: int, activation: int) -> str:
    """Relay policy for the next block at `height`: the consensus verdict, or
    "non-standard" for version >= 3 below the activation
    (`check_tx_version_standard`)."""
    verdict = version_rule(version, height, activation)
    if verdict == "v2" and version >= 3:
        return "non-standard"
    return verdict


def component_message(suite: int, component: int, digest: bytes) -> bytes:
    assert len(digest) == 32
    m = TX_SIG_COMPONENT_DOMAIN + u16(suite) + bytes([component]) + digest
    assert len(m) == 47
    return m


# ── Vector generation ────────────────────────────────────────────────────────

class Rng:
    """SHAKE-256 counter-mode stream: identical on every platform and Python."""

    def __init__(self, label: bytes):
        self.label = label
        self.i = 0

    def bytes(self, n: int) -> bytes:
        self.i += 1
        return hashlib.shake_256(self.label + self.i.to_bytes(8, "little")).digest(n)

    def below(self, n: int) -> int:
        return int.from_bytes(self.bytes(40), "little") % n


def h32(tag: int) -> bytes:
    return bytes([tag]) * 32


def tx_json(tx: Tx) -> str:
    return wire(tx).hex()


def spent_json(spent: list) -> list:
    return [{"value": str(s.value), "script_pubkey": s.script_pubkey.hex()} for s in spent]


def base_cases() -> list:
    """(name, tx_for_v2, tx_for_v3, spent, chain_id, indices)."""
    cases = []
    one = Tx(1, [TxIn(h32(0x11), 0, b"\x01\x02", 0xFFFFFFFF)], [TxOut(100_000_000, h32(0x22)[:20])], 0)
    one_spent = [TxOut(150_000_000, h32(0x33)[:20])]
    cases.append(("one input, one output", one, one_spent, CHAIN_MAINNET, [0]))

    two = Tx(1, [TxIn(h32(0x01), 7, b"sig-a", 1), TxIn(h32(0x02), 0xFFFF, b"sig-b", 0xFFFFFFFE)],
             [TxOut(5_000, h32(0x0A)[:20]), TxOut(546, h32(0x0B)[:20])], 12345)
    two_spent = [TxOut(4_000, h32(0x0C)[:20]), TxOut(2_000, h32(0x0D)[:20])]
    cases.append(("two inputs, two outputs", two, two_spent, CHAIN_MAINNET, [0, 1]))
    cases.append(("two inputs, testnet chain id", two, two_spent, CHAIN_TESTNET, [1]))

    empty = Tx(1, [TxIn(h32(0x00), 0, b"", 0)], [TxOut(0, b"")], 0)
    cases.append(("empty scripts and zero values", empty, [TxOut(0, b"")], CHAIN_MAINNET, [0]))

    maxed = Tx(U32_MAX, [TxIn(h32(0xFF), U32_MAX, b"\xff" * 9, U32_MAX)], [TxOut(U64_MAX, b"\xff" * 20)], U32_MAX)
    cases.append(("maximum field values", maxed, [TxOut(U64_MAX, b"\xff" * 20)], CHAIN_MAINNET, [0]))

    long_scripts = Tx(1, [TxIn(h32(0x5C), 3, b"w" * 300, 5)],
                      [TxOut(251, bytes(range(256)) * 39 + bytes(16)), TxOut(65_536, b"\x01" * 251)], 251)
    assert len(long_scripts.outputs[0].script_pubkey) == 10_000
    cases.append(("long scripts (10,000-byte output script)", long_scripts,
                  [TxOut(0xFFFF_FFFF, b"\x07" * 300)], CHAIN_MAINNET, [0]))

    n = 300
    many = Tx(1, [TxIn(bytes([i % 256]) * 31 + bytes([i // 256]), i, b"s" * (i % 3), U32_MAX - i) for i in range(n)],
              [TxOut(1_000 + i, bytes([i]) * 20) for i in range(3)], 0)
    many_spent = [TxOut(10_000 * (i + 1), bytes([0xA0 + i % 16]) * 20) for i in range(n)]
    cases.append(("300 inputs", many, many_spent, CHAIN_MAINNET, [0, 250, 299]))
    return cases


def random_cases() -> list:
    rng = Rng(b"gnb-sighash-vectors/random")
    out = []
    for k in range(12):
        n_in = 1 + rng.below(6)
        n_out = 1 + rng.below(4)
        tx = Tx(rng.below(1 << 32),
                [TxIn(rng.bytes(32), rng.below(1 << 32), rng.bytes(rng.below(40)), rng.below(1 << 32))
                 for _ in range(n_in)],
                [TxOut(rng.below(1 << 64), rng.bytes(rng.below(60))) for _ in range(n_out)],
                rng.below(1 << 32))
        spent = [TxOut(rng.below(1 << 64), rng.bytes(rng.below(60))) for _ in range(n_in)]
        chain = CHAIN_MAINNET if rng.below(2) == 0 else CHAIN_TESTNET
        out.append((f"random #{k}", tx, spent, chain, [rng.below(n_in)]))
    return out


def with_version(tx: Tx, version: int) -> Tx:
    return Tx(version, tx.inputs, tx.outputs, tx.locktime)


class Tables:
    """Transactions and spent-output lists, stored once and referenced by id."""

    def __init__(self):
        self.txs, self.spent = {}, {}

    def tx(self, tx: Tx) -> str:
        h = tx_json(tx)
        for k, v in self.txs.items():
            if v == h:
                return k
        k = f"tx{len(self.txs)}"
        self.txs[k] = h
        return k

    def outs(self, spent: list) -> str:
        j = spent_json(spent)
        for k, v in self.spent.items():
            if v == j:
                return k
        k = f"spent{len(self.spent)}"
        self.spent[k] = j
        return k


def build() -> dict:
    t = Tables()
    v2, v3, errors, messages = [], [], [], []
    for name, tx, spent, chain, indices in base_cases() + random_cases():
        for i in indices:
            v2.append({"name": name, "chain_id": chain, "tx": t.tx(tx), "input_index": i,
                       "preimage_len": len(v2_preimage(tx, i, chain)), "sighash": sighash_v2(tx, i, chain).hex()})
        # v3 vectors use version 3 (the only version the v3 digest is used
        # for), except the random cases, which keep an arbitrary version: the
        # digest is defined for any value of the field.
        t3 = tx if name.startswith("random") else with_version(tx, 3)
        suites = [SUITE_HYBRID, SUITE_MLDSA_ONLY, 0x0000, 0xFFFF] if name == "one input, one output" else [SUITE_HYBRID]
        for i in indices:
            for suite in suites:
                h = v3_hashes(t3, spent)
                pre = v3_preimage(t3, spent, i, suite, chain)
                v3.append({"name": name, "chain_id": chain, "tx": t.tx(t3), "spent": t.outs(spent),
                           "input_index": i, "suite": suite,
                           **{k: v.hex() for k, v in h.items()},
                           "preimage": pre.hex(), "sighash": sha3(pre).hex()})
    # Historical v2 quirk, pinned so it can never change silently.
    two = base_cases()[1][1]
    v2.append({"name": "out-of-range index (historical: no marker)", "chain_id": CHAIN_MAINNET,
               "tx": t.tx(two), "input_index": 2,
               "preimage_len": len(v2_preimage(two, 2, CHAIN_MAINNET)), "sighash": sighash_v2(two, 2, CHAIN_MAINNET).hex()})
    # v3 errors.
    t3 = with_version(two, 3)
    two_spent = base_cases()[1][2]
    for name, spent, i, kind in [
        ("index equal to the input count", two_spent, 2, "InputIndexOutOfRange"),
        ("index far out of range", two_spent, U32_MAX, "InputIndexOutOfRange"),
        ("one spent output for two inputs", two_spent[:1], 0, "SpentOutputCount"),
        ("three spent outputs for two inputs", two_spent + two_spent[:1], 0, "SpentOutputCount"),
    ]:
        try:
            sighash_v3(t3, spent, i, SUITE_HYBRID, CHAIN_MAINNET)
            raise AssertionError("expected an error")
        except SighashError as e:
            assert e.kind == kind
        errors.append({"name": name, "chain_id": CHAIN_MAINNET, "tx": t.tx(t3), "spent": t.outs(spent),
                       "input_index": i, "suite": SUITE_HYBRID, "error": kind})
    # Component messages over the first v3 digest, for every suite/component.
    d = bytes.fromhex(v3[0]["sighash"])
    for suite in (SUITE_HYBRID, SUITE_MLDSA_ONLY):
        for comp in (COMPONENT_MLDSA65, COMPONENT_FALCON1024):
            messages.append({"suite": suite, "component": comp, "digest": d.hex(),
                             "message": component_message(suite, comp, d).hex()})
    # Version rule (consensus) and version policy (relay), on both sides of
    # the activation; heights are decimal strings (u64).
    rules = []
    for act in (0, 100, U64_MAX):
        for height in (0, 99, 100, 101, U64_MAX - 1, U64_MAX):
            for version in (0, 1, 2, 3, 4, U32_MAX):
                rules.append({"version": version, "height": str(height), "activation": str(act),
                              "consensus": version_rule(version, height, act),
                              "policy": version_policy(version, height, act)})
    return {
        "description": "GnB sighash v2 and v3 golden vectors (reference/gnb_sighash.py). "
                       "Vectors name a transaction in `transactions` (hex of Transaction::to_wire_bytes(true)) "
                       "and a spent-output list in `spent_outputs`; u64 values are decimal strings.",
        "transactions": t.txs,
        "spent_outputs": t.spent,
        "constants": {
            "chain_mainnet": CHAIN_MAINNET, "chain_testnet": CHAIN_TESTNET,
            "sighash_v2_domain": SIGHASH_V2_DOMAIN.hex(), "sighash_v3_domain": SIGHASH_V3_DOMAIN.hex(),
            "sighash_v3_preimage_len": SIGHASH_V3_PREIMAGE_LEN,
            "tags": {"prevouts": TAG_PREVOUTS.decode(), "sequences": TAG_SEQUENCES.decode(),
                     "amounts": TAG_AMOUNTS.decode(), "scripts": TAG_SCRIPTS.decode(), "outputs": TAG_OUTPUTS.decode()},
            "component_domain": TX_SIG_COMPONENT_DOMAIN.decode(),
        },
        "v2": v2,
        "v3": v3,
        "v3_errors": errors,
        "component_messages": messages,
        "version_rule": rules,
    }


def main() -> None:
    doc = build()
    path = HERE / "sighash_vectors.json"
    path.write_text(json.dumps(doc, indent=1) + "\n")
    print(f"wrote {path.name}: {len(doc['v2'])} v2, {len(doc['v3'])} v3, "
          f"{len(doc['v3_errors'])} error, {len(doc['component_messages'])} component-message, "
          f"{len(doc['version_rule'])} version-rule vectors")


if __name__ == "__main__":
    main()
