# GnB-SMH v1 — Gödel and Bell Sequential Memory-Hard

The proof-of-work of GnB, a hard fork of Bloch. scrypt's ROMix structure instantiated
with single-permutation SHAKE-256 (FIPS 202): a 64 MiB scratchpad and 2^20 SHAKE-256
calls in one dependent chain per nonce.

Status: research prototype for testnet and external review. Not audited.
The full specification and security analysis are kept in a separate draft and will be
added under `docs/`.

## Layout

| Path | What it is |
| --- | --- |
| `reference/gnb_smh.py` | Normative definition (Python standard library only) |
| `reference/gen_vectors.py` | Regenerates `test_vectors.json` with intermediates |
| `reference/check_vectors.py` | Recomputes every vector and compares (used by CI) |
| `reference/test_vectors.json` | 7 vectors: log2_n = 10 (5) and 19 (2) |
| `rust/` | Crate `gnb-smh` (`#![forbid(unsafe_code)]`) + `smh-bench` binary |
| `analysis/stats.py` | Geometric-fit and bit-balance sanity tests (small N only) |

## Run

```sh
python3 reference/check_vectors.py              # Python reference against the vectors
python3 reference/gnb_smh.py 19                 # one evaluation, canonical size (~2-5 s in Python)
cd rust && cargo test --release                 # unit tests + cross-check against the Python vectors
./target/release/smh-bench verify 19 21         # median verification time
./target/release/smh-bench mine 8 6 4000 1 > ../analysis/mine_log2n8_bits6.csv
python3 ../analysis/stats.py
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

## License

Dual-licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.
