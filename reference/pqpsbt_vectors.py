"""Deterministic synthetic PQ-PSBT vectors, independently generated in Python.

No private keys, valid PQ signatures, network access or Rust codec calls.
`--check` compares the complete regenerated file byte for byte, without writing.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path

import pqpsbt as p

HERE = Path(__file__).resolve().parent
VECTOR_FILE = HERE / "pqpsbt_vectors.json"
SEED = b"GnB PQ-PSBT independent reference v1 / 2026-10"
SEEDED_PAIRS = 32


def synthetic_policy(count=1, threshold=1, *, after=0, label=b"policy", legacy=False):
    keys = []
    for index in range(count):
        body = hashlib.shake_256(SEED + label + bytes([index])).digest(3745)
        keys.append(body if legacy else b"\xb1\x0c\x01\x00" + body)
    return bytes([1, threshold, count]) + b"".join(p.blob(key) for key in keys) + p.integer(after, 4) + bytes(4)


def make_document(*, version=3, count=1, outputs=1, value=100_000, key_count=1, threshold=1, previous=False, coinbase=False, legacy=False, tree_count=0, label=b"base"):
    policy = synthetic_policy(key_count, threshold, label=label, legacy=legacy)
    tree = None
    branch = None
    if tree_count:
        branches = [policy] + [synthetic_policy(label=label + bytes([i])) for i in range(1, tree_count)]
        tree = bytes([2, tree_count]) + b"".join(p.blob(item) for item in branches)
        branch = tree_count - 1
        policy = branches[branch]
        script = p.tree_script(tree, branch, policy)
    else:
        script = p.policy_script(policy)
    tx_inputs = []
    inputs = []
    for index in range(count):
        prev = None
        txid = hashlib.sha256(SEED + label + p.integer(index, 4)).digest()
        if previous:
            prev_tx = {"version": 1, "inputs": [{"txid": bytes(32) if coinbase else txid, "index": 0xffffffff if coinbase else index, "script": b"synthetic previous witness", "sequence": 0xffffffff}], "outputs": [{"value": value, "script": script}], "locktime": 0}
            prev = p.transaction_bytes(prev_tx).hex()
            txid = p.transaction_id(prev_tx)
        tx_inputs.append({"txid": txid, "index": 0, "script": b"", "sequence": 0xffffffff})
        inputs.append({"value": str(value), "script": script.hex(), "previous_tx": prev, "derivations": [], "signatures": []})
    tx = {"version": version, "inputs": tx_inputs, "outputs": [{"value": 546, "script": bytes([i % 256]) * 20} for i in range(outputs)], "locktime": 0}
    return {"format": "gnb-pqpsbt", "version": 1, "network": "mainnet", "transaction": p.transaction_bytes(tx).hex(), "policy": policy.hex(), "tree": tree.hex() if tree else None, "branch": branch, "inputs": inputs}


def unchecked_frame(doc):
    """Spec-based malformed-vector assembler; deliberately does no validation."""
    result = bytearray(p.MAGIC + p.integer(doc["version"], 2) + bytes([0 if doc["network"] == "mainnet" else 1]))
    for field in ("transaction", "policy", "tree"):
        result += p.blob(bytes.fromhex(doc[field]) if doc[field] is not None else b"")
    result += bytes([255 if doc["branch"] is None else doc["branch"]]) + p.integer(len(doc["inputs"]), 2)
    for inp in doc["inputs"]:
        result += p.integer(int(inp["value"]), 8) + p.blob(bytes.fromhex(inp["script"])) + p.blob(bytes.fromhex(inp["previous_tx"]) if inp["previous_tx"] is not None else b"")
        result += bytes([len(inp["derivations"])])
        for item in inp["derivations"]:
            result += bytes([item["key_index"]]) + bytes.fromhex(item["fingerprint"]) + bytes([len(item["path"])]) + b"".join(p.integer(child, 4) for child in item["path"])
        result += bytes([len(inp["signatures"])])
        for item in inp["signatures"]:
            result += bytes([item["key_index"]]) + p.blob(bytes.fromhex(item["signature"]))
    return bytes(result)


def changed_tx(doc, update):
    result = copy.deepcopy(doc)
    tx = p.transaction(bytes.fromhex(result["transaction"]))
    update(tx)
    result["transaction"] = p.transaction_bytes(tx).hex()
    return result


def generate():
    accepted, rejected_binary, rejected_json = [], [], []

    def accept(name, doc):
        encoded = p.encode(doc)
        assert encoded == unchecked_frame(doc)
        assert p.decode(encoded) == doc
        accepted.append({"name": name, "binary": encoded.hex(), "document": doc, "canonical_json": p.to_json(doc)})

    def reject_binary(name, data):
        assert p.check_case({"binary": data.hex()}) == {"accepted": False}, name
        rejected_binary.append({"name": name, "binary": data.hex()})

    def reject_json(name, text):
        assert p.check_case({"json": text}) == {"accepted": False}, name
        rejected_json.append({"name": name, "json": text})

    def reject_doc(name, doc):
        reject_binary(name, unchecked_frame(doc))
        reject_json(name, json.dumps(doc, separators=(",", ":")))

    base = make_document()
    accept("v3-mainnet-one-input", base)
    for name, opts in (("v1-bound-previous", {"version": 1, "previous": True}), ("v1-updater-without-previous", {"version": 1}), ("v3-bound-previous-noncoinbase", {"previous": True}), ("v3-bound-previous-coinbase", {"previous": True, "coinbase": True}), ("v3-u64-max-exact", {"value": p.U64_MAX}), ("v3-legacy-public-key-shape", {"legacy": True}), ("v3-64-inputs-outputs", {"count": 64, "outputs": 64}), ("v3-two-of-three", {"key_count": 3, "threshold": 2})):
        accept(name, make_document(**opts))
    for count in (2, 3, 4):
        accept(f"tree-{count}-last-branch", make_document(tree_count=count))
    many = make_document(key_count=7, threshold=7)
    many["network"] = "testnet"
    many["inputs"][0]["derivations"] = [{"key_index": i, "fingerprint": f"{i:08x}", "path": [0, 0x7fffffff, 0x80000000, 0xffffffff] * 4} for i in range(7)]
    many["inputs"][0]["signatures"] = [{"key_index": i, "signature": (bytes([i + 1]) * (8192 if i == 6 else 1)).hex()} for i in range(7)]
    accept("metadata-and-signature-boundaries", many)
    binary = p.encode(base)
    reject_binary("magic", b"X" + binary[1:])
    reject_binary("format-version", binary[:8] + b"\x02\x00" + binary[10:])
    reject_binary("network", binary[:10] + b"\x02" + binary[11:])
    reject_binary("trailing", binary + b"\x00")
    for size in (0, 7, 9, 10, 14, 15, 32, len(binary) - 1):
        reject_binary(f"truncated-{size}", binary[:size])
    tx_end = 15 + len(bytes.fromhex(base["transaction"]))
    policy_end = tx_end + 4 + len(bytes.fromhex(base["policy"]))
    for name, prefix, maximum in (("transaction", binary[:11], p.MAX_TX), ("policy", binary[:tx_end], p.MAX_POLICY), ("tree", binary[:policy_end], p.MAX_TREE)):
        reject_binary(f"{name}-declared-too-large", prefix + p.integer(maximum + 1, 4))
        reject_binary(f"{name}-declared-u32-max", prefix + b"\xff" * 4)
    metadata = policy_end + 7
    reject_binary("input-count-65", binary[:policy_end + 5] + p.integer(65, 2))
    reject_binary("script-declared-too-large", binary[:metadata + 8] + p.integer(p.MAX_SCRIPT + 1, 4))
    prev_offset = metadata + 12 + 33
    reject_binary("previous-declared-too-large", binary[:prev_offset] + p.integer(p.MAX_TX + 1, 4))
    deriv_offset = prev_offset + 4
    reject_binary("derivation-count-8", binary[:deriv_offset] + b"\x08")
    reject_binary("path-count-17", binary[:deriv_offset] + b"\x01\x00" + bytes(4) + b"\x11")
    reject_binary("signature-count-8", binary[:deriv_offset] + b"\x00\x08")
    reject_binary("signature-declared-too-large", binary[:deriv_offset] + b"\x00\x01\x00" + p.integer(8193, 4))
    for name, update in (("tx-version-2", lambda tx: tx.update(version=2)), ("zero-inputs", lambda tx: tx.update(inputs=[])), ("zero-outputs", lambda tx: tx.update(outputs=[])), ("signed-unsigned-input", lambda tx: tx["inputs"][0].update(script=b"x")), ("dust-output", lambda tx: tx["outputs"][0].update(value=545)), ("invalid-output-script", lambda tx: tx["outputs"][0].update(script=b"x")), ("output-over-input", lambda tx: tx["outputs"][0].update(value=100001)), ("coinbase-unsigned", lambda tx: tx["inputs"][0].update(txid=bytes(32), index=0xffffffff))):
        reject_doc(name, changed_tx(base, update))
    for name, raw in (("tx-trailing", bytes.fromhex(base["transaction"]) + b"\x00"), ("tx-nonminimal-count", bytes.fromhex(base["transaction"])[:4] + b"\xfd\x01\x00" + bytes.fromhex(base["transaction"])[5:]), ("tx-count-overflow", bytes(4) + b"\xff" + b"\xff" * 8)):
        doc = copy.deepcopy(base)
        doc["transaction"] = raw.hex()
        reject_doc(name, doc)
    two = make_document(count=2)
    reject_doc("duplicate-outpoints", changed_tx(two, lambda tx: tx["inputs"].__setitem__(1, copy.deepcopy(tx["inputs"][0]))))
    two["inputs"][0]["value"] = str(p.U64_MAX)
    reject_doc("input-sum-overflow", two)
    two_out = make_document(outputs=2, value=p.U64_MAX)
    reject_doc("output-sum-overflow", changed_tx(two_out, lambda tx: tx["outputs"][0].update(value=p.U64_MAX)))
    for name, field, value in (("input-value-mismatch", "value", "99999"), ("previous-hash-mismatch", "previous_tx", base["transaction"])):
        doc = make_document(previous=True)
        doc["inputs"][0][field] = value
        reject_doc(name, doc)
    for name, mutate in (("missing-input", lambda d: d.update(inputs=[])), ("script-policy-mismatch", lambda d: d["inputs"][0].update(script=(b"\x02" + bytes(32)).hex())), ("empty-signature", lambda d: d["inputs"][0].update(signatures=[{"key_index": 0, "signature": ""}])), ("key-out-of-range", lambda d: d["inputs"][0].update(signatures=[{"key_index": 1, "signature": "01"}])), ("signature-duplicate", lambda d: d["inputs"][0].update(signatures=[{"key_index": 0, "signature": "01"}] * 2)), ("derivation-duplicate", lambda d: d["inputs"][0].update(derivations=[{"key_index": 0, "fingerprint": "00000000", "path": []}] * 2)), ("branch-without-tree", lambda d: d.update(branch=0)), ("policy-trailing", lambda d: d.update(policy=d["policy"] + "00"))):
        doc = copy.deepcopy(base)
        mutate(doc)
        reject_doc(name, doc)
    doc = make_document(tree_count=3)
    doc["branch"] = 3
    reject_doc("tree-branch-out-of-range", doc)
    doc["branch"] = 0
    reject_doc("tree-selected-policy-mismatch", doc)
    for name, update in (("tx-65-inputs", lambda tx: tx.update(inputs=tx["inputs"] * 65)), ("tx-65-outputs", lambda tx: tx.update(outputs=tx["outputs"] * 65))):
        reject_doc(name, changed_tx(base, update))
    for name, transform in (("policy-version", lambda b: b"\x02" + b[1:]), ("policy-zero-threshold", lambda b: b[:1] + b"\x00" + b[2:]), ("policy-eight-keys", lambda b: b[:2] + b"\x08" + b[3:]), ("policy-wrong-suite", lambda b: b[:9] + b"\x02" + b[10:])):
        doc = copy.deepcopy(base)
        doc["policy"] = transform(bytes.fromhex(doc["policy"])).hex()
        reject_doc(name, doc)
    duplicate = synthetic_policy()
    doc = copy.deepcopy(base)
    doc["policy"] = (b"\x01\x01\x02" + duplicate[3:-8] * 2 + duplicate[-8:]).hex()
    reject_doc("duplicate-policy-keys", doc)
    for name, field in (("signature-descending", "signatures"), ("derivation-descending", "derivations")):
        doc = copy.deepcopy(many)
        doc["inputs"][0][field].reverse()
        reject_doc(name, doc)
    doc = make_document(previous=True)
    reject_doc("previous-output-index-out-of-range", changed_tx(doc, lambda tx: tx["inputs"][0].update(index=1)))
    doc = make_document(previous=True)
    doc["inputs"][0]["previous_tx"] += "00"
    reject_doc("previous-trailing", doc)
    doc = copy.deepcopy(base)
    timed = synthetic_policy(after=1)
    doc["policy"] = timed.hex()
    doc["inputs"][0]["script"] = p.policy_script(timed).hex()
    reject_doc("policy-locktime-not-met", doc)
    for name, child in (("path-negative", -1), ("path-overflow", 1 << 32), ("path-boolean", True)):
        doc = copy.deepcopy(base)
        doc["inputs"][0]["derivations"] = [{"key_index": 0, "fingerprint": "00000000", "path": [child]}]
        reject_json(name, json.dumps(doc))
    for amount in ("00", "+1", "-1", "1.0", "1e3", " 1", str(1 << 64), 100000):
        doc = copy.deepcopy(base)
        doc["inputs"][0]["value"] = amount
        reject_json(f"decimal-{amount!r}", json.dumps(doc))
    for name, mutate in (("unknown-field", lambda d: d.update(verified=True)), ("missing-field", lambda d: d.pop("tree")), ("uppercase-hex", lambda d: d.update(policy=d["policy"].upper())), ("odd-hex", lambda d: d.update(policy=d["policy"] + "0")), ("empty-tree", lambda d: d.update(tree="", branch=0)), ("empty-previous", lambda d: d["inputs"][0].update(previous_tx="")), ("boolean-version", lambda d: d.update(version=True)), ("string-key-index", lambda d: d["inputs"][0].update(signatures=[{"key_index": "0", "signature": "01"}])), ("float-key-index", lambda d: d["inputs"][0].update(signatures=[{"key_index": 0.0, "signature": "01"}])), ("boolean-key-index", lambda d: d["inputs"][0].update(signatures=[{"key_index": False, "signature": "01"}]))):
        doc = copy.deepcopy(base)
        mutate(doc)
        reject_json(name, json.dumps(doc))
    text = p.to_json(base)
    reject_json("duplicate-top-field", '{"network":"testnet",' + text[1:])
    reject_json("duplicate-nested-field", text.replace('"value":"100000"', '"value":"1","value":"100000"'))
    reject_json("duplicate-escaped-field", '{"net\\u0077ork":"testnet",' + text[1:])
    reject_json("json-trailing", text + "0")
    reject_json("json-nan", text.replace('"version":1', '"version":NaN'))
    # Bounded differential corpus: 32 seeded accepted + 32 paired rejections.
    for i in range(SEEDED_PAIRS):
        data = hashlib.shake_256(SEED + p.integer(i, 4)).digest(32)
        doc = make_document(count=1 + data[0] % 3, outputs=1 + data[1] % 3, value=100_000 + int.from_bytes(data[2:8], "little"), label=data)
        doc["network"] = ("mainnet", "testnet")[data[8] & 1]
        doc["inputs"][0]["derivations"] = [{"key_index": 0, "fingerprint": data[9:13].hex(), "path": [int.from_bytes(data[13:17], "little")]}]
        accept(f"seeded-{i:02d}", doc)
        bad = p.encode(doc)
        mutation = i % 8
        if mutation == 0:
            bad += data[:1]
        elif mutation == 1:
            bad = bad[:10] + bytes([2 + data[17] % 254]) + bad[11:]
        elif mutation == 2:
            bad = bad[:len(bad) - 1 - data[17]]
        elif mutation == 3:
            bad = bad[:11] + p.integer(p.MAX_TX + 1 + data[17], 4) + bad[15:]
        else:
            mutated = copy.deepcopy(doc)
            if mutation == 4:
                mutated["inputs"][0]["derivations"][0]["key_index"] = 1
            elif mutation == 5:
                mutated["inputs"][0]["script"] = (b"\x02" + data).hex()
            elif mutation == 6:
                mutated["inputs"][0]["derivations"] *= 2
            else:
                mutated = changed_tx(mutated, lambda tx: tx.update(version=2))
            bad = unchecked_frame(mutated)
        reject_binary(f"seeded-{i:02d}-mutation", bad)
    return {"schema": 1, "seed": SEED.decode(), "seeded_cases": SEEDED_PAIRS * 2, "scope": "structural codec; synthetic public key/signature bytes; no PQ verification or consensus verdict", "accepted": accepted, "rejected_binary": rejected_binary, "rejected_json": rejected_json}


def render():
    return json.dumps(generate(), indent=2, ensure_ascii=True) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    text = render()
    if args.check:
        if VECTOR_FILE.read_text() != text:
            raise SystemExit("PQ-PSBT vectors differ: regenerate with reference/pqpsbt_vectors.py")
    else:
        VECTOR_FILE.write_text(text)
    vectors = json.loads(text)
    print(f"PQ-PSBT: {len(vectors['accepted'])} accepted, {len(vectors['rejected_binary'])} binary rejected, {len(vectors['rejected_json'])} JSON rejected; {vectors['seeded_cases']} seeded cases included")


if __name__ == "__main__":
    main()
