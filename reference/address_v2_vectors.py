"""Deterministic, offline address-v2 corpus generator; no Rust codec calls.

Expected verdicts are assigned from construction rules, not decoder output.
`--check` compares the complete regenerated JSON bytes without writing.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import address_v2 as a

VECTOR_FILE = Path(__file__).with_name("address_v2_vectors.json")
SEED = b"GnB independent address-v2 corpus / 2026-10 / v1"


def generate():
    cases = []

    def accepted(name, address, network, kind, payload, expected_network=None):
        case = {
            "name": name, "address": address, "valid": True,
            "network": network, "kind": kind, "hash_hex": payload.hex(),
            "script_hex": (payload if kind == "single-key" else b"\x02" + payload).hex(),
            "canonical": address.lower(),
        }
        if expected_network is not None:
            case["expected_network"] = expected_network
        cases.append(case)

    def rejected(name, address, rule, expected_network=None):
        case = {"name": name, "address": address, "valid": False, "rule": rule}
        if expected_network is not None:
            case["expected_network"] = expected_network
        cases.append(case)

    for network, hrp in a.HRPS.items():
        for kind, (tag, length) in a.KINDS.items():
            label = network + "-" + kind
            patterns = [bytes(length), bytes([255]) * length, bytes(range(length)), bytes([0xA5]) * length]
            patterns += [hashlib.shake_256(SEED + label.encode("ascii") + bytes([i])).digest(length) for i in range(12)]
            for index, payload in enumerate(patterns):
                address = a.encode(network, kind, payload)
                for upper in (False, True):
                    accepted(f"{label}-{index:02d}-{'upper' if upper else 'lower'}", address.upper() if upper else address, network, kind, payload, network)

            payload = bytes(range(length))
            data = [2, tag] + a._hash_words(payload)
            address = a.encode(network, kind, payload)
            other = "testnet" if network == "mainnet" else "mainnet"
            rejected(label + "-wrong-expected-network", address, "expected-network", other)
            rejected(label + "-hrp-replaced", a.HRPS[other] + address[len(hrp):], "checksum-binds-hrp")
            rejected(label + "-old-bech32", a._encode_words(hrp, data, constant=1), "bech32m-only")
            rejected(label + "-unknown-hrp", a._encode_words("unknown", data), "known-hrp")
            rejected(label + "-mixed-case-hrp", address[0].upper() + address[1:], "uniform-case")
            rejected(label + "-mixed-case-data", address[:len(hrp) + 1] + address[len(hrp) + 1:].upper(), "uniform-case")
            for version in (0, 1, 3, 31):
                rejected(f"{label}-version-{version}", a._encode_words(hrp, [version] + data[1:]), "version-2")
            for unknown_kind in (2, 31):
                rejected(f"{label}-kind-{unknown_kind}", a._encode_words(hrp, [2, unknown_kind] + data[2:]), "known-kind")
            for bad_length in sorted({0, 1, 19, 21, 31, 33} - {length}):
                words = [2, tag] + a._hash_words(bytes(bad_length))
                rejected(f"{label}-hash-length-{bad_length}", a._encode_words(hrp, words), "exact-hash-length")
            for absent in ([], [2]):
                rejected(f"{label}-metadata-{len(absent)}", a._encode_words(hrp, absent), "two-metadata-words")
            rejected(label + "-extra-zero-word", a._encode_words(hrp, data + [0]), "strict-padding-or-length")
            rejected(label + "-truncated-word", a._encode_words(hrp, data[:-1]), "strict-padding-or-length")
            if kind == "policy":
                for padding in (1, 2, 4, 8, 15):
                    rejected(f"{label}-nonzero-padding-{padding}", a._encode_words(hrp, data[:-1] + [data[-1] | padding]), "zero-padding")

            # Each position is changed once, including the HRP and separator.
            # This is a finite typo sample, not a proof of every error pattern.
            for position, character in enumerate(address):
                replacement = "p" if character == "q" else "q"
                bad = address[:position] + replacement + address[position + 1:]
                rejected(f"{label}-one-character-{position:02d}", bad, "one-character-typo")
            for position in (0, len(hrp), len(hrp) + 3, len(address) - 1):
                rejected(f"{label}-delete-{position:02d}", address[:position] + address[position + 1:], "deleted-character")
                rejected(f"{label}-insert-{position:02d}", address[:position] + "q" + address[position:], "inserted-character")
            for suffix, value in (("space", " "), ("tab", "\t"), ("newline", "\n"), ("nul", "\x00"), ("non-ascii", "é")):
                rejected(label + "-suffix-" + suffix, address + value, "printable-ascii-and-length")

    for name, address in (
        ("empty", ""), ("missing-separator", "gnbzqqqqqq"),
        ("empty-hrp", a._encode_words("", [2, 0])),
        ("too-long-91", "gnb1" + "q" * 87),
        ("invalid-data-character", "gnb1ziqqqqqq"),
        ("short-checksum", "gnb1zqqqq"),
    ):
        rejected(name, address, "v2-framing")
    return {
        "format": "gnb-address-v2-v1", "seed_hex": SEED.hex(),
        "description": "GnB v2 application vectors; generic BIP350 vectors are separate Python tests.",
        "cases": cases,
    }


def serialized():
    return (json.dumps(generate(), indent=2, ensure_ascii=True) + "\n").encode("ascii")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    contents = serialized()
    if args.check:
        if VECTOR_FILE.read_bytes() != contents:
            raise SystemExit("address-v2 vectors differ; regenerate and review")
    else:
        VECTOR_FILE.write_bytes(contents)
    cases = generate()["cases"]
    valid = sum(case["valid"] for case in cases)
    print(f"{len(cases)} vectors: {valid} accepted, {len(cases) - valid} rejected; sha256={hashlib.sha256(contents).hexdigest()}")


if __name__ == "__main__":
    main()
