"""Compare the Python oracle with a prebuilt Rust address_v2_oracle binary.

Only local synthetic public address data is used. No builds or network calls.
Each corpus case is decoded, and each positive case is separately encoded.
Bounded JSON-envelope cases also compare null/absent semantics, unknown-field
rejection, missing fields and invalid field types.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

import address_v2 as a
import address_v2_vectors as v


def envelope_requests():
    address = "gnb1zqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdaq6uw"
    decode = {"op": "decode", "address": address}
    encode = {"op": "encode", "network": "mainnet", "kind": "single-key", "hash_hex": "00" * 20}
    cases = [
        ("control-decode", decode, True),
        ("control-encode", encode, True),
        ("decode-null-expected-network", {**decode, "expected_network": None}, True),
        ("decode-unknown-field", {**decode, "unknown": 1}, False),
        ("encode-unknown-field", {**encode, "unknown": 1}, False),
    ]
    for index, value in enumerate([None, [], "decode", {}, {"op": None}, {"op": "other"}]):
        cases.append((f"invalid-object-or-op-{index}", value, False))
    for field in ("op", "address"):
        cases.append((f"decode-missing-{field}", {key: value for key, value in decode.items() if key != field}, False))
    for field in encode:
        cases.append((f"encode-missing-{field}", {key: value for key, value in encode.items() if key != field}, False))
    for index, value in enumerate([None, False, 7, [], {}]):
        cases.append((f"decode-address-type-{index}", {**decode, "address": value}, False))
        for field in ("network", "kind", "hash_hex"):
            cases.append((f"encode-{field}-type-{index}", {**encode, field: value}, False))
    for index, value in enumerate([False, 7, [], {}, "unknown"]):
        cases.append((f"decode-expected-network-type-{index}", {**decode, "expected_network": value}, False))
    result = []
    for name, request, accepted in cases:
        expected = a.oracle(request)
        if expected["ok"] != accepted:
            raise AssertionError("Python disagrees with envelope contract: " + name)
        result.append(("envelope/" + name, request, expected))
    return result


def requests():
    result = []
    for case in json.loads(v.VECTOR_FILE.read_text())["cases"]:
        request = {"op": "decode", "address": case["address"]}
        if "expected_network" in case:
            request["expected_network"] = case["expected_network"]
        expected = a.oracle(request)
        if expected["ok"] != case["valid"]:
            raise AssertionError("Python disagrees with corpus: " + case["name"])
        if case["valid"]:
            fields = {field: case[field] for field in ("network", "kind", "hash_hex", "script_hex")}
            if expected != {"ok": True, "address": case["canonical"], **fields}:
                raise AssertionError("Python disagrees with corpus bytes: " + case["name"])
        result.append((case["name"] + "/decode", request, expected))
        if case["valid"]:
            request = {"op": "encode", **{field: case[field] for field in ("network", "kind", "hash_hex")}}
            encoded = a.oracle(request)
            if encoded != expected:
                raise AssertionError("Python encoder disagrees with corpus: " + case["name"])
            result.append((case["name"] + "/encode", request, encoded))
    return result + envelope_requests()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rust_oracle", type=Path, help="prebuilt local address_v2_oracle executable")
    args = parser.parse_args()
    binary = args.rust_oracle.resolve(strict=True)
    rows = requests()
    serialized = "".join(json.dumps(request, separators=(",", ":")) + "\n" for _, request, _ in rows)
    proc = subprocess.run([str(binary)], input=serialized, text=True, capture_output=True, timeout=60, check=True)
    replies = proc.stdout.splitlines()
    if len(replies) != len(rows):
        raise SystemExit(f"Rust emitted {len(replies)} replies for {len(rows)} requests")
    for (name, _, expected), line in zip(rows, replies):
        actual = json.loads(line)
        if actual != expected:
            raise SystemExit(f"Divergence in {name}: Python={expected!r}; Rust={actual!r}")
    print(json.dumps({
        "requests": len(rows), "divergences": 0,
        "envelope_requests": len(envelope_requests()),
        "corpus_sha256": hashlib.sha256(v.VECTOR_FILE.read_bytes()).hexdigest(),
        "rust_binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "python_oracle_sha256": hashlib.sha256(Path(a.__file__).read_bytes()).hexdigest(),
    }, sort_keys=True))


if __name__ == "__main__":
    main()
