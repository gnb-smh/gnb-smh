"""Witness size of the GnB ledger sparse Merkle tree versus the number of live keys.

A proof is a 32-byte bitmap plus one 32-byte sibling per non-empty sibling subtree on
the key's path. For n uniformly random keys that count is about log2(n) plus a small
constant; this script measures it directly (sorted keys + bisection, no hashing).

    python3 analysis/witness_size.py
"""

from __future__ import annotations

import bisect
import math
import random
import statistics


def siblings_on_path(sorted_keys: list[int], k: int) -> int:
    count = 0
    for h in range(256):
        p = (k >> h) ^ 1
        lo, hi = p << h, (p + 1) << h
        if bisect.bisect_left(sorted_keys, lo) < bisect.bisect_left(sorted_keys, hi):
            count += 1
    return count


def main() -> None:
    rng = random.Random(1)
    print(f"{'live keys':>12} {'present: siblings':>18} {'bytes':>7} {'absent: siblings':>17} {'bytes':>7}")
    rows = []
    for log_n in (10, 14, 17, 20):
        keys = sorted(rng.getrandbits(256) for _ in range(1 << log_n))
        present = [siblings_on_path(keys, rng.choice(keys)) for _ in range(300)]
        absent = [siblings_on_path(keys, rng.getrandbits(256)) for _ in range(300)]
        mp, ma = statistics.mean(present), statistics.mean(absent)
        rows.append((log_n, mp, ma))
        print(f"{'2^%d' % log_n:>12} {mp:>18.2f} {32 + 32 * mp:>7.0f} {ma:>17.2f} {32 + 32 * ma:>7.0f}")
    # each doubling of n adds one level; extrapolate from the largest measurement
    log_n, mp, ma = rows[-1]
    for target in (26, 30, 32):
        ep, ea = mp + (target - log_n), ma + (target - log_n)
        print(f"{'2^%d (extrap.)' % target:>12} {ep:>18.2f} {32 + 32 * ep:>7.0f} {ea:>17.2f} {32 + 32 * ea:>7.0f}")
    print(f"\nconstant c in siblings ~ log2(n) + c: present {mp - log_n:+.2f}, absent {ma - log_n:+.2f}"
          f" (log2 e = {math.log2(math.e):.2f})")


if __name__ == "__main__":
    main()
