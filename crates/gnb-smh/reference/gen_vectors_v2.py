"""Generate test_vectors_v2.json from the v2 draft reference."""

import json
import sys

import gnb_smh_v2 as ref

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
        x = ref.step(ref.TAG_MIX, i, bytes(a ^ b for a, b in zip(x, v[j])))
    out = ref.sha256(ref.enc(ref.DS_FINAL) + x)
    assert out == ref.gnb_smh_v2(header, nonce, log2_n)
    return x0, x_fill, x, out


def main():
    vectors = []
    for log2_n in (4, 13):
        for header, nonce in CASES:
            x0, xf, xm, out = intermediates(header, nonce, log2_n)
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
        "algorithm": "GnB-SMH v2 draft (SHA-256, single-compression steps)",
        "version": ref.VERSION,
        "block_bytes": ref.BLOCK,
        "canonical_log2_n": ref.LOG2_N,
        "note": "DRAFT, not consensus. nonce is a decimal string (u64); out is compared big-endian.",
        "vectors": vectors,
    }
    with open(sys.argv[1] if len(sys.argv) > 1 else "test_vectors_v2.json", "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write("\n")


if __name__ == "__main__":
    main()
