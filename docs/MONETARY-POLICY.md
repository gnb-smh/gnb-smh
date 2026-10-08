# GNB monetary policy

Consensus rules, defined in `crates/gnb-crypto/src/core/tokenomics.rs` and
`crates/gnb-crypto/src/core/carryover.rs`.

## Hard cap: 10,000,000 GNB

| Allocation | Share | Amount |
| --- | --- | --- |
| Bloch Genesis-3 carryover | 10% | 1,000,000 GNB (999,999.99789793 issued after rounding) |
| Mining | 90% | 9,000,000 GNB (8,999,998.51392253 issued after rounding) |
| **Total issued** | | **9,999,998.51182046 GNB** |

No premine, no founder allocation, no pools.

## Mining subsidy

- Initial subsidy 1.07020547 GNB per block (floor(9,000,000 GNB / (2 × 4,204,800))).
- Halving every 4,204,800 blocks (4 × 365 days at 30 s), by integer right
  shift in base units.
- The subsidy reaches zero after 27 halvings (height 113,529,600, about 108
  years) and stays zero. There is no tail emission.
- The genesis block pays nothing; mining starts at height 1.
- The coinbase has exactly one output, worth at most subsidy + fees, paid to
  an address of the miner's choice. 100% of fees go to the miner.

## Fees

Every non-coinbase transaction must pay, by consensus,

```text
min_fee = max(10,000, ceil(size_bytes × 2,000 / 1,000))   base units
        = max(0.0001 GNB, 0.00002 GNB per kB)
```

A typical one-input, two-output transaction (hybrid ML-DSA-65 + Falcon-1024
signature and public key, about 8.6 kB) pays at least about 0.00017 GNB. When
the subsidy is exhausted, fees are the only miner revenue, and this floor
keeps it from going to zero.

## Bloch Genesis-3 carryover

The genesis ledger is the Bloch Genesis-3 terminal snapshot, the same file
Bloch Genesis-4 opened with (`genesis/bloch-g3-carryover.tsv.gz`):

| | |
| --- | --- |
| Rows | 452,726 |
| Total | 3,810,744,000 BLCH |
| SHA3-256 (uncompressed) | `3d67246e94881a17d302b464f79fee55886d8068794e76fed43081117fbe308d` |
| SHA-256 (uncompressed) | `84ddbbac2afdd5c78618096a7d4f66cf5b04a3e5757a03fe90550e50096183f6` |

Conversion, per output: `gnb = floor(blch × 1,000,000 GNB / 3,810,744,000 BLCH)`,
same owner hash. A Genesis-3 block reward of 8,400 BLCH becomes 2.20429396 GNB.

- One row of value 0 converts to nothing and is dropped: 452,725 UTXOs are
  written.
- 38 rows carry vout `16777216`, a Bloch exporter defect (`1` written
  little-endian, read big-endian). GnB records them at vout `1`, the real
  Genesis-3 outpoint.
- The genesis coinbase text commits to the snapshot hash and the conversion.
- A node's first boot requires `--carryover-snapshot`; the file is verified
  (hash, rows, totals, converted totals) before anything is written, and the
  node refuses to start on any mismatch.

### Owners

Addresses are 20-byte public-key hashes and the address checksum covers only
the hash, so a Bloch address `bloch1q<hash><checksum>` is the GnB address
`gnb1q<hash><checksum>`. Wallet key derivation is unchanged from Bloch: the
same seed or keystore yields the same keys, which sign GnB transactions under
the GnB sighash domain. Signatures never replay between the two chains.
