"""GnB-SMH v2 (draft) -- SHA-256, ASIC-friendly, Grover-hostile proof-of-work.

DRAFT, NOT CONSENSUS. Executable reference specification for a candidate
successor of GnB-SMH v1. Same scrypt ROMix structure (Percival 2009;
RFC 7914), instantiated with single-compression SHA-256 calls (FIPS 180-4)
and a scratchpad small enough to live in on-chip SRAM.

    out = gnb_smh_v2(header, nonce)              # 32 bytes
    valid  <=>  int.from_bytes(out, "big") < target,   1 <= target <= 2^256 - 1

Parameters (v2 draft):
    BLOCK  = 32 bytes           one scratchpad block = one SHA-256 state
    LOG2_N = 13                 N = 2^13 blocks -> 256 KiB scratchpad
    SHA-256 compressions per evaluation = 2N + 2 = 16,386, one dependent chain

Design goals:
    * ASIC: one SHA-256 core + 256 KiB SRAM per lane; no DRAM, no bandwidth wall.
    * Verification: ~2 ms on one CPU core (v1: ~0.5 s), so a forged proof is cheap
      to reject.
    * Quantum (Grover): each Grover iteration must run 16,386 dependent SHA-256
      compressions reversibly AND address 256 KiB in superposition (QRAM),
      because every mix read index depends on the running state.
"""

from __future__ import annotations

import hashlib
import struct

VERSION = 2
BLOCK = 32
LOG2_N = 13          # canonical v2 draft parameter
MIN_LOG2_N = 1
MAX_LOG2_N = 30

DS_SEED = b"GNB-SMH-v2/seed"
DS_FINAL = b"GNB-SMH-v2/final"
TAG_FILL = 0x01
TAG_MIX = 0x02


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def enc(b: bytes) -> bytes:
    """Length-prefixed encoding: u32 little-endian length || bytes."""
    if len(b) >= 1 << 32:
        raise ValueError("field too long")
    return struct.pack("<I", len(b)) + b


def _check(log2_n: int) -> None:
    if not MIN_LOG2_N <= log2_n <= MAX_LOG2_N:
        raise ValueError(f"log2_n must be in [{MIN_LOG2_N}, {MAX_LOG2_N}]")


def seed(header: bytes, nonce: int, log2_n: int = LOG2_N) -> bytes:
    """X_0 = SHA256(enc(DS_SEED) || u8(log2_n) || enc(header) || u64le(nonce))."""
    _check(log2_n)
    if not 0 <= nonce < 1 << 64:
        raise ValueError("nonce must fit in u64")
    return sha256(enc(DS_SEED) + bytes([log2_n]) + enc(header) + struct.pack("<Q", nonce))


def step(tag: int, i: int, x: bytes) -> bytes:
    """One inner call: SHA256(x || u32le(i) || u8(tag)).

    The input is exactly 37 bytes (<= 55), so with SHA-256 padding it is a
    single 64-byte block: one compression from the standard IV.

    Domain separation: x is always a SHA-256 output. A seed input has 37
    bytes only for a 5-byte header, and then it starts with the fixed 19-byte
    encoding of DS_SEED; the final input is 52 bytes. An inner input equals a
    seed input only if some output starts with those 19 bytes, probability
    about 2^-152 per call.
    """
    assert len(x) == BLOCK
    return sha256(x + struct.pack("<I", i) + bytes([tag]))


def gnb_smh_v2(header: bytes, nonce: int, log2_n: int = LOG2_N) -> bytes:
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
        y = bytes(a ^ b for a, b in zip(x, v[j]))
        x = step(TAG_MIX, i, y)

    return sha256(enc(DS_FINAL) + x)


def meets_target(out: bytes, target: int) -> bool:
    if not 1 <= target < 1 << 256:
        raise ValueError("target must be in [1, 2^256 - 1]")
    return int.from_bytes(out, "big") < target


if __name__ == "__main__":
    import sys
    import time

    log2_n = int(sys.argv[1]) if len(sys.argv) > 1 else LOG2_N
    t0 = time.perf_counter()
    h = gnb_smh_v2(b"gnb", 0, log2_n)
    print(f"log2_n={log2_n} out={h.hex()} time={time.perf_counter() - t0:.3f}s")
