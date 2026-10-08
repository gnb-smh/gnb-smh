# GnB-SMH v1 — Gödel and Bell Sequential Memory-Hard

The proof-of-work of GnB, a hard fork of Bloch: it replaces Bloch-SIS-PoW. scrypt's ROMix structure
instantiated with single-permutation SHAKE-256 (FIPS 202): a 64 MiB
scratchpad and 2^20 SHAKE-256 calls in one dependent chain per nonce.

Status: research prototype for testnet and external review. Not audited.
The full specification and security analysis live in the GnB-SMH spec doc.

## Layout

| Path | What it is |
| --- | --- |
| `reference/gnb_smh.py` | Normative definition (Python standard library only) |
| `reference/gen_vectors.py` | Regenerates `test_vectors.json` with intermediates |
| `reference/test_vectors.json` | 7 vectors: log2_n = 10 (5) and 19 (2) |
| `src/lib.rs` | The crate (`#![forbid(unsafe_code)]`): evaluation, scratchpad, verification |
| `src/difficulty.rs` | Compact targets, chain work, ASERT |
| `src/bin/smh-bench.rs` | Benchmark and toy miner |
| `tests/vectors.rs` | Cross-check against the Python vectors |
| `analysis/stats.py` | Geometric-fit and bit-balance sanity tests (small N only) |

## Run

From the repository root:

```sh
python3 crates/gnb-smh/reference/gnb_smh.py 19     # one evaluation in Python (~2-5 s)
cargo test --release -p gnb-smh                    # unit tests + Python vector cross-check
./target/release/smh-bench verify 19 21            # median verification time
./target/release/smh-bench mine 8 6 4000 1 > crates/gnb-smh/analysis/mine_log2n8_bits6.csv
python3 crates/gnb-smh/analysis/stats.py
```

## Definition

```
X = SHAKE256(enc("GNB-SMH-v1/seed") || u8(19) || enc(header) || u64le(nonce), 128)
for i in 0..N-1:  V[i] = X;  X = SHAKE256(X || u32le(i) || 0x01, 128)
for i in 0..N-1:  j = u64le(X[0..8]) mod N;  X = SHAKE256((X xor V[j]) || u32le(i) || 0x02, 128)
out = SHAKE256(enc("GNB-SMH-v1/final") || X, 32)
valid  <=>  be256(out) < target,   1 <= target <= 2^256 - 1,   work = floor(2^256 / target)
```

`enc(b) = u32le(len(b)) || b`. `header` is the canonical header serialization without the nonce.
