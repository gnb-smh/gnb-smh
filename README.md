# GnB — Gödel and Bell

GnB is a post-quantum proof-of-work BlockDAG. It is a hard fork of the Bloch
codebase (the Genesis-3 proof-of-work node), with its proof of work replaced by
**GnB-SMH**, a sequential memory-hard function over SHAKE-256, and a new
genesis that carries the Bloch Genesis-3 ledger over at a fixed conversion.

| | |
| --- | --- |
| Proof of work | GnB-SMH v1: scrypt ROMix structure on single-permutation SHAKE-256, 64 MiB scratchpad, 2^20 dependent Keccak-f[1600] calls per evaluation |
| Consensus | GhostDAG (k = 10), 30-second target spacing |
| Difficulty | ASERT anchored at genesis, 2-hour half-life, computed per block from its parents |
| Signatures | Hybrid ML-DSA-65 ‖ Falcon-1024 |
| Supply | Hard cap 10,000,000 GNB: 10% Bloch carryover, 90% mining |
| Unit | 1 GNB = 10^8 base units; addresses `gnb1q…` (mainnet), `gnb1t…` (testnet) |

Status: pre-release. Not audited.

## Layout

| Path | What it is |
| --- | --- |
| `crates/gnb-smh` | The proof of work: GnB-SMH v1, compact targets, ASERT. Includes the normative Python reference and test vectors |
| `crates/gnb-crypto` | Consensus types (blocks, transactions, genesis, carryover, monetary policy), signatures, wallet |
| `crates/coherence-core` | Shielded-pool primitives carried in the block format |
| `node` | The `gnb` full node, `gnb-cli`, `gnb-wallet`, `gnb-mine-genesis` |
| `genesis/` | The Bloch Genesis-3 terminal snapshot the genesis ledger is built from |
| `docs/` | Protocol notes: [consensus](docs/CONSENSUS.md), [monetary policy and carryover](docs/MONETARY-POLICY.md), [running a node](docs/RUNNING.md) |

## Build and test

```sh
cargo build --release
cargo test --release --workspace
```

The toolchain is pinned in `rust-toolchain.toml`.

## Run a node

```sh
gunzip -k genesis/bloch-g3-carryover.tsv.gz
./target/release/gnb --carryover-snapshot genesis/bloch-g3-carryover.tsv \
    --mine --miner-address gnb1q... --peer /ip4/<seed>/tcp/17110
```

The first boot verifies the snapshot against the consensus constants and
writes the converted ledger before block 0. See [docs/RUNNING.md](docs/RUNNING.md).

## Relationship to Bloch

GnB keeps Bloch's block format, GhostDAG, transaction model, signatures,
wallet key derivation and network stack, and changes:

- **Proof of work:** GnB-SMH instead of Bloch-SIS / SHA-256d. No AuxPoW, no
  Stratum (Stratum V1/V2 are SHA-256d ASIC protocols).
- **Network identity:** chain ids `0x474E0001` / `0x474E0002`, sighash domain
  `GNB-SIGHASH-v1`, P2P topics `gnb/*`, magic `GNB1`, ports 17110 (P2P),
  17210 (RPC), 17310 (metrics). No signature or block is valid on both chains.
- **History:** no Bloch flag days or height-gated legacy rules. Every rule
  that Bloch activated at a height applies from GnB genesis.
- **Ledger:** genesis state is the Bloch Genesis-3 terminal snapshot converted
  to 1,000,000 GNB. Owners keep their keys; `bloch1q<hash><checksum>` becomes
  `gnb1q<hash><checksum>`.

## License

The node and `gnb-crypto` are AGPL-3.0-or-later, as inherited from Bloch
(see `LICENSE`). `crates/gnb-smh` is MIT OR Apache-2.0.
