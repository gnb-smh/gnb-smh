"""GnB-SMH v3 (draft) -- data-dependent multi-pass fill (Argon2d-style), SHAKE-256.

DRAFT, NOT CONSENSUS. Executable reference specification.

v1 (scrypt ROMix) fills memory with a plain hash chain, so an attacker can
keep 1 block in k and recompute any missing one with at most k-1 hashes
(linear time-memory trade-off). v3 makes every block depend on the previous
block AND on a block chosen by the previous block's content, over several
passes: a dropped block needs its two inputs, which may themselves be dropped,
so recomputation cascades (Argon2d-style penalty). The same data-dependent
reads force a quantum (Grover) attacker to hold the whole scratchpad in QRAM.

    out = gnb_smh_v3(header, nonce)          # 32 bytes, valid iff be256(out) < target

    X0 = SHAKE256(enc(DS_SEED) || u8(log2_n) || u8(passes) || enc(header) || u64le(nonce), 128)
    V[0] = X0
    pass 0:  for i in 1..N:   r = u64le(V[i-1][0..8]) mod i
                              V[i] = SHAKE256(V[i-1] || V[r] || u32le(i) || u8(0), 128)
    pass p:  for i in 0..N:   prev = V[(i-1) mod N];  r = u64le(prev[0..8]) mod N
                              V[i] = SHAKE256(prev || V[r] || u32le(i) || u8(p), 128)
    out = SHAKE256(enc(DS_FINAL) || V[N-1], 32)

Parameters (v3 draft): BLOCK = 128 B, LOG2_N = 15 (4 MiB), PASSES = 2.
Each step absorbs 261 bytes: 2 Keccak-f[1600] permutations.
"""

from __future__ import annotations

import hashlib
import struct

VERSION = 3
BLOCK = 128
LOG2_N = 15
PASSES = 2
MIN_LOG2_N = 1
MAX_LOG2_N = 30

DS_SEED = b"GNB-SMH-v3/seed"
DS_FINAL = b"GNB-SMH-v3/final"


def shake256(data: bytes, outlen: int) -> bytes:
    return hashlib.shake_256(data).digest(outlen)


def enc(b: bytes) -> bytes:
    return struct.pack("<I", len(b)) + b


def _check(log2_n: int, passes: int) -> None:
    if not MIN_LOG2_N <= log2_n <= MAX_LOG2_N:
        raise ValueError("log2_n out of range")
    if not 1 <= passes <= 255:
        raise ValueError("passes out of range")


def seed(header: bytes, nonce: int, log2_n: int = LOG2_N, passes: int = PASSES) -> bytes:
    _check(log2_n, passes)
    if not 0 <= nonce < 1 << 64:
        raise ValueError("nonce must fit in u64")
    return shake256(enc(DS_SEED) + bytes([log2_n, passes]) + enc(header) + struct.pack("<Q", nonce), BLOCK)


def step(prev: bytes, ref: bytes, i: int, p: int) -> bytes:
    """SHAKE256(prev || ref || u32le(i) || u8(p), 128): 261-byte input.

    Domain separation: seed inputs start with the fixed 19-byte enc(DS_SEED)
    and final inputs have 148 bytes; a step input is 261 bytes and starts with
    a SHAKE output, which matches enc(DS_SEED) with probability ~2^-152.
    """
    return shake256(prev + ref + struct.pack("<I", i) + bytes([p]), BLOCK)


def trace(header: bytes, nonce: int, log2_n: int = LOG2_N, passes: int = PASSES):
    n = 1 << log2_n
    v = [b""] * n
    v[0] = seed(header, nonce, log2_n, passes)
    x0 = v[0]
    for i in range(1, n):
        r = int.from_bytes(v[i - 1][:8], "little") % i
        v[i] = step(v[i - 1], v[r], i, 0)
    after_pass0 = v[n - 1]
    for p in range(1, passes):
        for i in range(n):
            prev = v[(i - 1) % n]
            r = int.from_bytes(prev[:8], "little") % n
            v[i] = step(prev, v[r], i, p)
    out = shake256(enc(DS_FINAL) + v[n - 1], 32)
    return x0, after_pass0, v[n - 1], out


def gnb_smh_v3(header: bytes, nonce: int, log2_n: int = LOG2_N, passes: int = PASSES) -> bytes:
    return trace(header, nonce, log2_n, passes)[3]


if __name__ == "__main__":
    import json
    import sys
    import time

    if len(sys.argv) > 1 and sys.argv[1] == "vectors":
        cases = [(b"", 0), (b"gnb", 0), (b"gnb", 1), (bytes(range(80)), 0xFFFFFFFFFFFFFFFF),
                 (b"\x00" * 200, 0x0123456789ABCDEF)]
        vecs = []
        for log2_n, passes in ((4, 1), (4, 3), (15, 2)):
            for header, nonce in cases:
                s, a0, last, out = trace(header, nonce, log2_n, passes)
                vecs.append({"log2_n": log2_n, "passes": passes, "header_hex": header.hex(),
                             "nonce": str(nonce), "seed_hex": s.hex(), "after_pass0_hex": a0.hex(),
                             "last_hex": last.hex(), "out_hex": out.hex()})
        doc = {"algorithm": "GnB-SMH v3 draft (Argon2d-style fill, SHAKE-256)", "version": VERSION,
               "block_bytes": BLOCK, "canonical_log2_n": LOG2_N, "canonical_passes": PASSES,
               "note": "DRAFT, not consensus. nonce is a decimal string (u64); out compared big-endian.",
               "vectors": vecs}
        with open(sys.argv[2], "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2)
            f.write("\n")
    else:
        t0 = time.perf_counter()
        print(gnb_smh_v3(b"gnb", 0).hex(), f"{time.perf_counter() - t0:.2f}s")
