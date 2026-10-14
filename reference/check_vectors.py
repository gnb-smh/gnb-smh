"""Recompute every vector in test_vectors.json and difficulty_vectors.json with
the references (gnb_smh.py, gnb_difficulty.py) and compare.

Exit status 0 when all match. Used by CI; the two log2_n = 19 vectors take a few
seconds each in pure Python.
"""

import json
import pathlib
import sys

import gen_difficulty_vectors
import gnb_smh as ref

HERE = pathlib.Path(__file__).resolve().parent


def main() -> int:
    doc = json.loads((HERE / "test_vectors.json").read_text())
    failures = 0
    for v in doc["vectors"]:
        header = bytes.fromhex(v["header_hex"])
        nonce = int(v["nonce"])
        log2_n = v["log2_n"]
        if ref.seed(header, nonce, log2_n).hex() != v["seed_hex"]:
            print(f"FAIL seed log2_n={log2_n} nonce={nonce}")
            failures += 1
            continue
        out = ref.gnb_smh(header, nonce, log2_n).hex()
        ok = out == v["out_hex"]
        failures += not ok
        print(f"{'ok  ' if ok else 'FAIL'} log2_n={log2_n} nonce={nonce} {out}")
    print(f"{len(doc['vectors']) - failures}/{len(doc['vectors'])} vectors match")

    # Difficulty: compact bits, chain work, ASERT, GnB's expected bits.
    stored = json.loads((HERE / "difficulty_vectors.json").read_text())
    fresh = gen_difficulty_vectors.build()
    for section in ("compact", "targets", "asert", "gnb_expected_bits"):
        bad = sum(a != b for a, b in zip(stored[section], fresh[section]))
        bad += abs(len(stored[section]) - len(fresh[section]))
        failures += bad
        print(f"{'ok  ' if not bad else 'FAIL'} difficulty {section}: "
              f"{len(fresh[section]) - bad}/{len(fresh[section])} match")
    if stored.get("gnb") != fresh["gnb"]:
        print("FAIL difficulty constants")
        failures += 1
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
