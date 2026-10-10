"""Recompute every vector in test_vectors.json with the reference and compare.

Exit status 0 when all match. Used by CI; the two log2_n = 19 vectors take a few
seconds each in pure Python.
"""

import json
import pathlib
import sys

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
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
