"""GnB-SMH v1 (Gödel and Bell Sequential Memory-Hard) -- executable reference specification.

Proof-of-work for the GnB chain (a fork of Bloch). Structure: scrypt ROMix
(Percival 2009; RFC 7914) instantiated with single-permutation SHAKE-256
calls (FIPS 202).

This file is the normative definition. Any other implementation must
reproduce test_vectors.json byte for byte.

    out = gnb_smh(header, nonce)                 # 32 bytes
    valid  <=>  int.from_bytes(out, "big") < target,   1 <= target <= 2^256 - 1
    work(target) = floor(2^256 / target)

Parameters (v1):
    BLOCK  = 128 bytes          one scratchpad block
    LOG2_N = 19                 N = 2^19 blocks -> 64 MiB scratchpad
    SHAKE-256 calls per evaluation = 2N + 2 = 1,048,578, one dependent chain
"""

from __future__ import annotations

import hashlib
import struct

VERSION = 1
BLOCK = 128
LOG2_N = 19          # canonical v1 parameter (consensus)
MIN_LOG2_N = 1       # range accepted for tests and experiments only
MAX_LOG2_N = 30

DS_SEED = b"GNB-SMH-v1/seed"
DS_FINAL = b"GNB-SMH-v1/final"
TAG_FILL = 0x01
TAG_MIX = 0x02


def shake256(data: bytes, outlen: int) -> bytes:
    return hashlib.shake_256(data).digest(outlen)


def enc(b: bytes) -> bytes:
    """Length-prefixed encoding: u32 little-endian length || bytes."""
    if len(b) >= 1 << 32:
        raise ValueError("field too long")
    return struct.pack("<I", len(b)) + b


def _check(log2_n: int) -> None:
    if not MIN_LOG2_N <= log2_n <= MAX_LOG2_N:
        raise ValueError(f"log2_n must be in [{MIN_LOG2_N}, {MAX_LOG2_N}]")


def seed(header: bytes, nonce: int, log2_n: int = LOG2_N) -> bytes:
    """X_0 = SHAKE256(enc(DS_SEED) || u8(log2_n) || enc(header) || u64le(nonce), 128)."""
    _check(log2_n)
    if not 0 <= nonce < 1 << 64:
        raise ValueError("nonce must fit in u64")
    msg = enc(DS_SEED) + bytes([log2_n]) + enc(header) + struct.pack("<Q", nonce)
    return shake256(msg, BLOCK)


def step(tag: int, i: int, x: bytes) -> bytes:
    """One inner call: SHAKE256(x || u32le(i) || u8(tag), 128).

    The input is exactly 133 bytes, so the call absorbs in a single
    Keccak-f[1600] permutation (rate 136) and squeezes 128 <= 136 bytes
    without a second permutation. x comes first so it fills Keccak lanes
    0..15; lane 16 carries i, the tag and the SHAKE padding.

    Domain separation: x is always a SHAKE-256 output, while the seed and
    final inputs start with a fixed 19- or 20-byte label encoding. An inner
    input can equal another call's input only if some output starts with
    that label, probability about 2^-152 per call.
    """
    assert len(x) == BLOCK
    return shake256(x + struct.pack("<I", i) + bytes([tag]), BLOCK)


def gnb_smh(header: bytes, nonce: int, log2_n: int = LOG2_N) -> bytes:
    _check(log2_n)
    n = 1 << log2_n
    mask = n - 1
    x = seed(header, nonce, log2_n)

    # Phase 1 -- fill: a hash chain of length N; V[i] = X_i.
    v = [b""] * n
    for i in range(n):
        v[i] = x
        x = step(TAG_FILL, i, x)

    # Phase 2 -- mix: N data-dependent reads, each step depends on the last.
    for i in range(n):
        j = int.from_bytes(x[:8], "little") & mask
        y = (int.from_bytes(x, "little") ^ int.from_bytes(v[j], "little")).to_bytes(BLOCK, "little")
        x = step(TAG_MIX, i, y)

    # Finalization.
    return shake256(enc(DS_FINAL) + x, 32)


def meets_target(out: bytes, target: int) -> bool:
    """Valid iff the 256-bit big-endian integer of `out` is strictly below `target`."""
    if not 1 <= target < 1 << 256:
        raise ValueError("target must be in [1, 2^256 - 1]")
    return int.from_bytes(out, "big") < target


def work(target: int) -> int:
    """Expected attempts to meet `target`: floor(2^256 / target)."""
    if not 1 <= target < 1 << 256:
        raise ValueError("target must be in [1, 2^256 - 1]")
    return (1 << 256) // target


if __name__ == "__main__":
    import sys
    import time

    log2_n = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    t0 = time.perf_counter()
    h = gnb_smh(b"gnb", 0, log2_n)
    dt = time.perf_counter() - t0
    print(f"log2_n={log2_n} out={h.hex()} time={dt:.3f}s")
