"""Generate test_vectors.json from the reference implementation."""

import json
import struct
import sys
import time

import gnb_smh as ref

CASES = [
    (b"", 0),
    (b"gnb", 0),
    (b"gnb", 1),
    (bytes(range(80)), 0xFFFFFFFFFFFFFFFF),
    (b"\x00" * 200, 0x0123456789ABCDEF),
]


def intermediates(header: bytes, nonce: int, log2_n: int):
    n = 1 << log2_n
    mask = n - 1
    x0 = ref.seed(header, nonce, log2_n)
    x = x0
    v = [b""] * n
    for i in range(n):
        v[i] = x
        x = ref.step(ref.TAG_FILL, i, x)
    x_fill = x
    for i in range(n):
        j = int.from_bytes(x[:8], "little") & mask
        y = (int.from_bytes(x, "little") ^ int.from_bytes(v[j], "little")).to_bytes(ref.BLOCK, "little")
        x = ref.step(ref.TAG_MIX, i, y)
    out = ref.shake256(ref.enc(ref.DS_FINAL) + x, 32)
    assert out == ref.gnb_smh(header, nonce, log2_n)
    return x0, x_fill, x, out


def main():
    vectors = []
    # log2_n = 1 and 2: the whole pipeline (seed, fill, data-dependent mix,
    # final digest) in a handful of Keccak permutations, so the vectors also
    # run under Miri, on the 32-bit and big-endian targets
    # (docs/testing/SANITIZERS.md). 10 and 19: the native cross-check.
    for log2_n in (1, 2, 10, 19):
        cases = CASES[1:3] if log2_n == 19 else CASES
        for header, nonce in cases:
            t0 = time.perf_counter()
            x0, xf, xm, out = intermediates(header, nonce, log2_n)
            print(f"log2_n={log2_n} nonce={nonce} {out.hex()} ({time.perf_counter() - t0:.2f}s)", file=sys.stderr)
            vectors.append({
                "log2_n": log2_n,
                "header_hex": header.hex(),
                "nonce": str(nonce),
                "seed_hex": x0.hex(),
                "x_after_fill_hex": xf.hex(),
                "x_after_mix_hex": xm.hex(),
                "out_hex": out.hex(),
            })
    doc = {
        "algorithm": "GnB-SMH (Gödel and Bell Sequential Memory-Hard)",
        "version": ref.VERSION,
        "block_bytes": ref.BLOCK,
        "canonical_log2_n": ref.LOG2_N,
        "note": "nonce is a decimal string (u64). out is compared to the target as a big-endian integer.",
        "vectors": vectors,
    }
    with open(sys.argv[1] if len(sys.argv) > 1 else "test_vectors.json", "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write("\n")


if __name__ == "__main__":
    main()
