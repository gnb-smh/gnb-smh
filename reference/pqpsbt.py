"""Independent, stdlib-only GnB PQ-PSBT v1 codec; see docs/PQ-PSBT.md.

This implements the frozen byte contract, not the Rust PQ-PSBT algorithm.
It never signs or verifies PQ signatures, queries a node, or decides consensus.
BIP174's Signer section motivates authenticating supplied previous transactions;
BIP370 distinguishes format version from transaction version. Neither is this
format's wire encoding: https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
and https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys

MAGIC = b"GNBPSBT\xff"
MAX_BINARY = 8 * 1024 * 1024
# Canonical JSON hex payloads cost <= 2 * binary bytes. Fixed metadata is
# bounded by 256 + 64*(256 + 7*(128 + 16*11) + 7*64) = 181504 bytes;
# reserve 256 KiB. See the executable bound in pqpsbt_test.py and format doc.
MAX_JSON = 2 * MAX_BINARY + 256 * 1024
MAX_TX = 1_000_000
MAX_POLICY = 65_536
MAX_TREE = 262_144
MAX_SCRIPT = 10_000
MAX_SIGNATURE = 8_192
MAX_IO = 64
U64_MAX = (1 << 64) - 1
TOP = ("format", "version", "network", "transaction", "policy", "tree", "branch", "inputs")
INPUT = ("value", "script", "previous_tx", "derivations", "signatures")
DERIVATION = ("key_index", "fingerprint", "path")
SIGNATURE = ("key_index", "signature")


class Invalid(ValueError):
    """Malformed or inconsistent PQ-PSBT; not a consensus verdict."""


def require(condition, message):
    if not condition:
        raise Invalid(message)


def number(value, maximum, name="integer"):
    require(type(value) is int and 0 <= value <= maximum, name)
    return value


def fields(value, names):
    require(type(value) is dict and set(value) == set(names), "object fields")


def sequence(value, maximum, name="array"):
    require(type(value) is list and len(value) <= maximum, name)
    return value


def unhex(value, maximum):
    require(type(value) is str and len(value) <= 2 * maximum, "hex length")
    require(len(value) % 2 == 0 and re.fullmatch("[0-9a-f]*", value) is not None, "hex syntax")
    return bytes.fromhex(value)


def decimal(value):
    require(type(value) is str and len(value) <= 20, "decimal length")
    require(re.fullmatch("0|[1-9][0-9]*", value) is not None, "decimal syntax")
    return number(int(value), U64_MAX, "decimal overflow")


def integer(value, size):
    return number(value, (1 << (size * 8)) - 1).to_bytes(size, "little")


def blob(value):
    return integer(len(value), 4) + value


class Reader:
    def __init__(self, data):
        self.data = memoryview(data)
        self.offset = 0

    def take(self, count):
        require(count <= len(self.data) - self.offset, "truncated")
        start = self.offset
        self.offset += count
        return self.data[start:self.offset].tobytes()

    def uint(self, size):
        return int.from_bytes(self.take(size), "little")

    def count(self, size, maximum):
        value = self.uint(size)
        require(value <= maximum, "count limit")
        return value

    def blob(self, maximum):
        # Check declared length and remaining bytes before copying/allocating.
        return self.take(self.count(4, maximum))

    def compact(self, maximum):
        first = self.uint(1)
        if first < 253:
            value = first
        else:
            size = {253: 2, 254: 4, 255: 8}[first]
            value = self.uint(size)
            require(value >= {2: 253, 4: 65536, 8: 4294967296}[size], "nonminimal CompactSize")
        require(value <= maximum, "CompactSize limit")
        return value

    def end(self):
        require(self.offset == len(self.data), "trailing bytes")


def compact(value):
    number(value, U64_MAX)
    for marker, size, maximum in ((None, 1, 252), (253, 2, 65535), (254, 4, 4294967295), (255, 8, U64_MAX)):
        if value <= maximum:
            return (b"" if marker is None else bytes([marker])) + integer(value, size)
    raise AssertionError("unreachable")


def transaction_bytes(tx, *, strip=False):
    out = bytearray(integer(tx["version"], 4) + compact(len(tx["inputs"])))
    for inp in tx["inputs"]:
        script = inp["script"]
        out += inp["txid"] + integer(inp["index"], 4)
        if not strip:
            out += compact(len(script)) + script
        out += integer(inp["sequence"], 4)
    out += compact(len(tx["outputs"]))
    for output in tx["outputs"]:
        out += integer(output["value"], 8) + compact(len(output["script"])) + output["script"]
    return bytes(out + integer(tx["locktime"], 4))


def transaction(data, *, unsigned=False):
    require(len(data) <= MAX_TX, "transaction size")
    r = Reader(data)
    version = r.uint(4)
    inputs = []
    for _ in range(r.compact(MAX_IO if unsigned else 100_000)):
        inputs.append({"txid": r.take(32), "index": r.uint(4), "script": r.take(r.compact(114_834)), "sequence": r.uint(4)})
    outputs = []
    for _ in range(r.compact(MAX_IO if unsigned else 100_000)):
        outputs.append({"value": r.uint(8), "script": r.take(r.compact(MAX_SCRIPT))})
    result = {"version": version, "inputs": inputs, "outputs": outputs, "locktime": r.uint(4)}
    r.end()
    require(transaction_bytes(result) == data, "noncanonical transaction")
    if unsigned:
        require(all(not inp["script"] for inp in inputs), "signed input")
    return result


def transaction_id(tx):
    ins = tx["inputs"]
    coinbase = len(ins) == 1 and ins[0]["txid"] == bytes(32) and ins[0]["index"] == 0xffffffff
    data = transaction_bytes(tx, strip=not coinbase)
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def policy(data):
    require(len(data) <= MAX_POLICY, "policy size")
    r = Reader(data)
    require(r.uint(1) == 1, "policy version")
    threshold = r.uint(1)
    count = r.count(1, 7)
    require(1 <= threshold <= count, "policy threshold")
    keys = [r.blob(8192) for _ in range(count)]
    require(len(set(keys)) == count, "duplicate policy key")
    # Existing public-key framing: legacy body 3745, or 4-byte suite envelope.
    require(all(len(key) == 3745 or (len(key) == 3749 and key[:4] == b"\xb1\x0c\x01\x00") for key in keys), "hybrid public key shape")
    after, older = r.uint(4), r.uint(4)
    r.end()
    return {"threshold": threshold, "keys": keys, "after": after, "older": older}


def policy_script(data):
    return b"\x02" + hashlib.sha3_256(b"GNB-POLICY-v1" + data).digest()


def tree_script(data, branch, selected):
    r = Reader(data)
    require(r.uint(1) == 2, "tree version")
    count = r.count(1, 4)
    require(2 <= count and branch < count, "tree branch")
    branches = [r.blob(MAX_POLICY) for _ in range(count)]
    r.end()
    for item in branches:
        policy(item)
    require(branches[branch] == selected, "selected policy mismatch")
    leaves = [hashlib.sha3_256(b"GNB-POLICY-v2/leaf" + item).digest() for item in branches]
    while len(leaves) not in (2, 4):
        leaves.append(hashlib.sha3_256(b"GNB-POLICY-v2/empty").digest())
    while len(leaves) > 1:
        leaves = [hashlib.sha3_256(b"GNB-POLICY-v2/node" + leaves[i] + leaves[i + 1]).digest() for i in range(0, len(leaves), 2)]
    return policy_script(bytes([2, count]) + leaves[0])


def validate(document):
    """Validate a programmatic object too; return it in canonical field order."""
    fields(document, TOP)
    require(document["format"] == "gnb-pqpsbt", "format")
    require(number(document["version"], 65535) == 1, "version")
    require(document["network"] in ("mainnet", "testnet"), "network")
    raw_tx = unhex(document["transaction"], MAX_TX)
    tx = transaction(raw_tx, unsigned=True)
    raw_policy = unhex(document["policy"], MAX_POLICY)
    p = policy(raw_policy)
    require(tx["version"] in (1, 3), "transaction version")
    require(tx["inputs"] and tx["outputs"], "empty transaction")
    outpoints = [(item["txid"], item["index"]) for item in tx["inputs"]]
    require(len(set(outpoints)) == len(outpoints), "duplicate outpoint")
    require(not (len(outpoints) == 1 and outpoints[0] == (bytes(32), 0xffffffff)), "coinbase spend")
    require(tx["locktime"] >= p["after"], "policy absolute locktime")
    for output in tx["outputs"]:
        script = output["script"]
        require(len(script) == 20 or (len(script) == 33 and script[0] == 2), "output script")
        require(output["value"] >= 546, "dust output")
    output_total = sum(item["value"] for item in tx["outputs"])
    require(output_total <= U64_MAX, "output sum overflow")
    if document["tree"] is None:
        require(document["branch"] is None, "branch without tree")
        expected_script = policy_script(raw_policy)
    else:
        raw_tree = unhex(document["tree"], MAX_TREE)
        require(raw_tree, "empty tree")
        branch = number(document["branch"], 254, "branch")
        expected_script = tree_script(raw_tree, branch, raw_policy)
    inputs = sequence(document["inputs"], MAX_IO)
    require(len(inputs) == len(tx["inputs"]), "input count mismatch")
    normalized = []
    for position, inp in enumerate(inputs):
        fields(inp, INPUT)
        decimal(inp["value"])
        require(unhex(inp["script"], MAX_SCRIPT) == expected_script, "input policy script")
        if inp["previous_tx"] is not None:
            previous = unhex(inp["previous_tx"], MAX_TX)
            require(previous, "empty previous transaction")
            prev = transaction(previous)
            outpoint = tx["inputs"][position]
            require(transaction_id(prev) == outpoint["txid"], "previous transaction hash")
            require(outpoint["index"] < len(prev["outputs"]), "previous output index")
            spent = prev["outputs"][outpoint["index"]]
            require(spent["value"] == int(inp["value"]) and spent["script"] == expected_script, "previous output mismatch")
        derivations = []
        signatures = []
        for name, target, names in (("derivations", derivations, DERIVATION), ("signatures", signatures, SIGNATURE)):
            last = -1
            for item in sequence(inp[name], 7):
                fields(item, names)
                index = number(item["key_index"], len(p["keys"]) - 1, "key index")
                require(index > last, "key index order")
                last = index
                if name == "derivations":
                    require(len(unhex(item["fingerprint"], 4)) == 4, "fingerprint")
                    for child in sequence(item["path"], 16):
                        number(child, 0xffffffff, "child index")
                else:
                    require(unhex(item["signature"], MAX_SIGNATURE), "empty signature")
                target.append({key: item[key] for key in names})
        normalized.append({"value": inp["value"], "script": inp["script"], "previous_tx": inp["previous_tx"], "derivations": derivations, "signatures": signatures})
    input_total = sum(int(item["value"]) for item in inputs)
    require(input_total <= U64_MAX, "input sum overflow")
    require(input_total >= output_total, "negative fee")
    # Count encoded bytes before constructing the complete output buffer.
    size = 26 + len(raw_tx) + len(raw_policy) + (0 if document["tree"] is None else len(raw_tree))
    for inp in normalized:
        size += 18 + len(inp["script"]) // 2 + (0 if inp["previous_tx"] is None else len(inp["previous_tx"]) // 2)
        size += sum(6 + 4 * len(item["path"]) for item in inp["derivations"])
        size += sum(5 + len(item["signature"]) // 2 for item in inp["signatures"])
    require(size <= MAX_BINARY, "complete binary size")
    return {key: normalized if key == "inputs" else document[key] for key in TOP}


def encode(document):
    doc = validate(document)
    out = bytearray(MAGIC + integer(1, 2) + bytes([("mainnet", "testnet").index(doc["network"])]))
    for name in ("transaction", "policy", "tree"):
        out += blob(bytes.fromhex(doc[name]) if doc[name] is not None else b"")
    out += bytes([255 if doc["branch"] is None else doc["branch"]]) + integer(len(doc["inputs"]), 2)
    for inp in doc["inputs"]:
        out += integer(int(inp["value"]), 8) + blob(bytes.fromhex(inp["script"]))
        out += blob(b"" if inp["previous_tx"] is None else bytes.fromhex(inp["previous_tx"]))
        out += bytes([len(inp["derivations"])])
        for item in inp["derivations"]:
            out += bytes([item["key_index"]]) + bytes.fromhex(item["fingerprint"]) + bytes([len(item["path"])])
            for child in item["path"]:
                out += integer(child, 4)
        out += bytes([len(inp["signatures"])])
        for item in inp["signatures"]:
            out += bytes([item["key_index"]]) + blob(bytes.fromhex(item["signature"]))
    require(len(out) <= MAX_BINARY, "complete binary size")
    return bytes(out)


def decode(data):
    require(type(data) is bytes and len(data) <= MAX_BINARY, "complete binary size")
    r = Reader(data)
    require(r.take(8) == MAGIC, "magic")
    require(r.uint(2) == 1, "version")
    network = r.uint(1)
    require(network < 2, "network")
    raw_tx, raw_policy, raw_tree = r.blob(MAX_TX), r.blob(MAX_POLICY), r.blob(MAX_TREE)
    branch = r.uint(1)
    require(bool(raw_tree) == (branch != 255), "tree/branch presence")
    inputs = []
    for _ in range(r.count(2, MAX_IO)):
        value, script, previous = str(r.uint(8)), r.blob(MAX_SCRIPT), r.blob(MAX_TX)
        derivations = []
        for _ in range(r.count(1, 7)):
            index, fingerprint = r.uint(1), r.take(4)
            path = [r.uint(4) for _ in range(r.count(1, 16))]
            derivations.append({"key_index": index, "fingerprint": fingerprint.hex(), "path": path})
        signatures = []
        for _ in range(r.count(1, 7)):
            signatures.append({"key_index": r.uint(1), "signature": r.blob(MAX_SIGNATURE).hex()})
        inputs.append({"value": value, "script": script.hex(), "previous_tx": previous.hex() if previous else None, "derivations": derivations, "signatures": signatures})
    r.end()
    return validate({"format": "gnb-pqpsbt", "version": 1, "network": ("mainnet", "testnet")[network], "transaction": raw_tx.hex(), "policy": raw_policy.hex(), "tree": raw_tree.hex() if raw_tree else None, "branch": None if branch == 255 else branch, "inputs": inputs})


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON field")
        result[key] = value
    return result


def json_integer(text):
    require(len(text) <= 20 and not text.startswith("-"), "JSON unsigned integer")
    return int(text)


def reject_json_number(_):
    raise Invalid("JSON noninteger number")


def from_json(text):
    require(type(text) is str and len(text) <= MAX_JSON, "JSON size")
    try:
        require(len(text.encode("utf-8")) <= MAX_JSON, "JSON byte size")
        obj = json.loads(text, object_pairs_hook=unique_object, parse_int=json_integer, parse_float=reject_json_number, parse_constant=reject_json_number)
        result = validate(obj)
        encode(result)  # JSON must also fit the binary envelope.
        return result
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise Invalid("invalid JSON") from error


def to_json(document):
    doc = validate(document)
    encode(doc)
    text = json.dumps(doc, separators=(",", ":"), ensure_ascii=True)
    require(len(text) <= MAX_JSON, "JSON size")
    return text


def check_case(case):
    try:
        require(type(case) is dict and len(case) == 1, "case fields")
        if "binary" in case:
            doc = decode(unhex(case["binary"], MAX_BINARY))
        elif "json" in case:
            doc = from_json(case["json"])
        else:
            raise Invalid("case encoding")
        canonical = json.dumps(doc, separators=(",", ":"), ensure_ascii=True)
        require(len(canonical) <= MAX_JSON, "JSON size")
        return {"accepted": True, "binary": encode(doc).hex(), "document": doc, "json": canonical}
    except Invalid:
        return {"accepted": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jsonl", action="store_true", help="bounded differential oracle: one binary/json case per line")
    args = parser.parse_args()
    if not args.jsonl:
        parser.error("use --jsonl")
    # A protocol line contains JSON-escaped JSON, so allow its bounded framing.
    while line := sys.stdin.readline(2 * MAX_JSON + 1025):
        require(len(line) <= 2 * MAX_JSON + 1024, "oracle line size")
        try:
            case = json.loads(line, object_pairs_hook=unique_object, parse_int=json_integer, parse_float=reject_json_number, parse_constant=reject_json_number)
            result = check_case(case)
        except (Invalid, json.JSONDecodeError, RecursionError):
            result = {"accepted": False}
        print(json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    main()
