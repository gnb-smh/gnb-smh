# GnB-SMH v1 — Gödel and Bell Sequential Memory-Hard

The proof-of-work of GnB, a hard fork of Bloch. scrypt's ROMix structure instantiated
with single-permutation SHAKE-256 (FIPS 202): a 64 MiB scratchpad and 2^20 SHAKE-256
calls in one dependent chain per nonce.

This repository also holds the **GnB ledger v1**: stateless validation without a committee.
Every node checks every block holding only two 32-byte state roots; each block travels with
O(log n) sparse-Merkle witnesses (about 1 KB per touched key at 2^30 outputs), and every
transaction outcome must be proven, so validity is deterministic while ordering stays with
the proof-of-work. See [`docs/LEDGER.md`](docs/LEDGER.md).

Status: research prototype for testnet and external review. Not audited.
The full GnB-SMH specification and security analysis are kept in a separate draft and will
be added under `docs/`.

## Layout

| Path | What it is |
| --- | --- |
| `reference/gnb_smh.py` | GnB-SMH normative definition (Python standard library only) |
| `reference/gen_vectors.py` | Regenerates `test_vectors.json` with intermediates |
| `reference/check_vectors.py` | Recomputes every PoW vector and compares (used by CI) |
| `reference/test_vectors.json` | 7 PoW vectors: log2_n = 10 (5) and 19 (2) |
| `reference/gnb_ledger.py` | Ledger normative definition: sparse Merkle tree, transactions, witness bundle, validation |
| `reference/gen_ledger_vectors.py` | Regenerates `ledger_vectors.json` (deterministic) |
| `reference/ledger_vectors.json` | 5 valid blocks, 23 single-fault invalid blocks with error code and fault class, tree vectors |
| `reference/test_ledger.py` | Ledger tests, including a producer-versus-validator differential test |
| `rust/` | Crate `gnb-smh` (`#![forbid(unsafe_code)]`): PoW, `ledger` module, `smh-bench` binary |
| `docs/LEDGER.md` | Ledger specification |
| `analysis/stats.py` | Geometric-fit and bit-balance sanity tests for the PoW (small N only) |
| `analysis/witness_size.py` | Measured witness size versus number of live outputs |

## Run

```sh
python3 reference/check_vectors.py              # PoW reference against the vectors
python3 reference/test_ledger.py                # ledger reference tests
python3 reference/gnb_smh.py 19                 # one evaluation, canonical size (~2-5 s in Python)
python3 analysis/witness_size.py                # witness size up to 2^20 live outputs
cd rust && cargo test --release                 # unit tests + cross-checks against both vector files
./target/release/smh-bench verify 19 21         # median PoW verification time
./target/release/smh-bench witness              # time to check one ledger witness
./target/release/smh-bench mine 8 6 4000 1 > ../analysis/mine_log2n8_bits6.csv
python3 ../analysis/stats.py
```

## GnB-SMH definition

```
X = SHAKE256(enc("GNB-SMH-v1/seed") || u8(19) || enc(header) || u64le(nonce), 128)
for i in 0..N-1:  V[i] = X;  X = SHAKE256(X || u32le(i) || 0x01, 128)
for i in 0..N-1:  j = u64le(X[0..8]) mod N;  X = SHAKE256((X xor V[j]) || u32le(i) || 0x02, 128)
out = SHAKE256(enc("GNB-SMH-v1/final") || X, 32)
valid  <=>  be256(out) < target,   1 <= target <= 2^256 - 1,   work = floor(2^256 / target)
```

`enc(b) = u32le(len(b)) || b`. `header` is the canonical header serialization without the nonce
(the ledger defines it: 140 bytes, see `docs/LEDGER.md`).

## License

Dual-licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.
