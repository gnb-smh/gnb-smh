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
| `crates/gnb-wallet-wasm` | Browser wallet core (keystores, coin selection, hybrid signing) for `wasm32-wasip1` |
| `site/`, `worker/` | gnb-smh.com: site, explorer (`/explorer`) and web wallet (`/wallet`), served by a Cloudflare Worker that also proxies the read-only explorer API |
| `deploy/` | Node and explorer-API systemd units and install scripts |
| `genesis/` | The Bloch Genesis-3 terminal snapshot the genesis ledger is built from |
| `crates/pqcrypto-internals`, `crates/libp2p-yamux` | Vendored forks (patched in through `[patch.crates-io]`), workspace members so their guard tests run |
| `node/fuzz` | cargo-fuzz targets (own workspace, nightly): wire decoders, difficulty, PoW and signature verify, Merkle paths, mempool |
| `docs/` | Protocol notes: [consensus](docs/CONSENSUS.md), [monetary policy and carryover](docs/MONETARY-POLICY.md), [running a node](docs/RUNNING.md), [ledger v1](docs/LEDGER.md) |
| `reference/`, `rust/`, `analysis/` | Standalone GnB-SMH v1 reference implementation and GnB ledger v1 (see below) |

## Build and test

```sh
cargo build --release
cargo test --workspace --locked
# The consensus crates in their own invocations: in a workspace-wide run the
# node's dev-only `test-pow-limit` feature is unified into gnb-crypto and pins
# every expected target to the pow limit.
cargo test -p gnb-smh --locked
cargo test -p gnb-crypto --locked
cargo clippy --workspace --all-targets --locked
cargo deny check && cargo audit
```

CI (`.github/workflows/ci.yml`) runs all of these, the Python references, the
standalone `rust/` crate, the vendored-crate and Falcon guards, and nightly the
fuzz targets.

The toolchain is pinned in `rust-toolchain.toml`.

## Run a node

```sh
gunzip -k genesis/bloch-g3-carryover.tsv.gz
./target/release/gnb --carryover-snapshot genesis/bloch-g3-carryover.tsv \
    --mine --miner-address gnb1q... --peer /ip4/<seed>/tcp/17110
```

The first boot verifies the snapshot against the consensus constants and
writes the converted ledger before block 0. See [docs/RUNNING.md](docs/RUNNING.md).

## Web wallet

[gnb-smh.com/wallet](https://gnb-smh.com/wallet) opens GnB and Bloch
keystores (a `bloch1q…` keystore opens as the same `gnb1q…` address), creates
new wallets, and sends and receives GNB. Decryption (Argon2id, AES-256-GCM)
and signing run in WebAssembly inside the page; the private key never leaves
the WebAssembly memory and nothing secret is uploaded. The page is served with
a strict Content-Security-Policy (same-origin scripts only, no framing).
Rebuild the core with `scripts/build-wallet-wasm.sh` (needs a wasi-sdk).

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

## Reference implementation and ledger v1

`reference/`, `rust/` and `analysis/` hold a standalone GnB-SMH v1 reference and the
**GnB ledger v1**: stateless validation without a committee. Every node checks every
block holding only two 32-byte state roots; each block travels with O(log n)
sparse-Merkle witnesses (about 1 KB per touched key at 2^30 outputs), and every
transaction outcome must be proven. Specification: [`docs/LEDGER.md`](docs/LEDGER.md).
Research prototype, not yet wired into the node.

| Path | What it is |
| --- | --- |
| `reference/gnb_smh.py` | GnB-SMH normative definition (Python standard library only) |
| `reference/check_vectors.py`, `test_vectors.json` | 7 PoW vectors and the checker of both vector files |
| `reference/gnb_difficulty.py` | Difficulty normative definition: compact bits, chain work, ASERT, GnB's difficulty input |
| `reference/gen_difficulty_vectors.py`, `difficulty_vectors.json` | Compact, chain-work, ASERT and multi-parent expected-bits vectors, checked by `crates/gnb-smh` and `crates/gnb-crypto` |
| `reference/gnb_ledger.py` | Ledger normative definition: sparse Merkle tree, transactions, witness bundle, validation |
| `reference/gen_ledger_vectors.py`, `ledger_vectors.json` | 5 valid and 25 single-fault invalid blocks, tree vectors |
| `reference/test_ledger.py` | Ledger tests, including a producer-versus-validator differential test |
| `rust/` | Standalone crate (`#![forbid(unsafe_code)]`, outside the workspace): PoW, `ledger` module, `smh-bench` |
| `analysis/` | PoW statistics and measured witness size versus live outputs |

```sh
python3 reference/check_vectors.py      # Python 3.10 or newer
python3 reference/test_ledger.py
cd rust && cargo test --release --locked
```

## License

The node and `gnb-crypto` are AGPL-3.0-or-later, as inherited from Bloch
(see `LICENSE`). `crates/gnb-smh`, `reference/`, `rust/` and `analysis/` are MIT OR Apache-2.0
(see `LICENSE-APACHE` and `LICENSE-MIT`).
