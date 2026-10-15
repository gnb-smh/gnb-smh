# Running a GnB node

## Requirements

- 64-bit Linux or macOS, Rust toolchain from `rust-toolchain.toml`.
- Memory: ~1 GB for the node plus 64 MiB per mining thread.
- Ports: 17110/tcp (P2P) open to peers. RPC (17210) and metrics (17310) bind
  to 127.0.0.1 by default.

## First boot

```sh
cargo build --release --bin gnb
gunzip -k genesis/bloch-g3-carryover.tsv.gz
./target/release/gnb --data-dir ./gnb-data \
    --carryover-snapshot genesis/bloch-g3-carryover.tsv \
    --peer /ip4/<seed-ip>/tcp/17110
```

The node verifies the snapshot, writes the 452,725 carryover UTXOs, verifies
the genesis proof of work and starts syncing. Later boots only need
`--data-dir`; a data-dir from another chain or genesis is refused.

## Mining

```sh
./target/release/gnb --data-dir ./gnb-data --mine \
    --miner-address gnb1q... --mine-threads 8 --peer /ip4/<seed-ip>/tcp/17110
```

A node given `--peer`/`--dns-seed` waits until it has seen the network tip
before it mines, so it never forks from genesis.

## Genesis

`gnb-mine-genesis` recomputes the genesis nonce. It is only needed if the
genesis constants in `crates/gnb-crypto/src/core/mod.rs` change, which is a
new chain.

## RPC

JSON-RPC on 127.0.0.1:17210. Useful methods: `getblockcount`, `getdaginfo`,
`getblocktemplate`, `submitblock`, `getsupplyinfo`, `getbalance`,
`sendrawtransaction`. See `node/src/rpc/mod.rs`.

## Chain selection and operator recovery

The node always follows the best valid chain of the blocks it holds, at any
depth: there is no reorg-depth limit and no finality checkpoint. A reorg of
more than 1,000 blocks is logged at error level ("DEEP REORG committed") and
counted in `gnb_deep_reorgs_total`; it is never refused.

To leave a chain anyway (for example while an incident is investigated), or
to return to it:

```sh
GNB_RPC_API_KEY=<key> gnb-cli invalidateblock <block-hash>
GNB_RPC_API_KEY=<key> gnb-cli reconsiderblock <block-hash>
```

`invalidateblock` disqualifies the block and every block whose selected chain
passes through it, rolls the node back past it if needed and moves to the
best remaining chain. `reconsiderblock` removes the marks of the block, of its
selected-chain ancestors and of its selected-chain descendants, then lets the
node re-evaluate (a block that really is invalid is disqualified again). Both
are persisted and survive restarts, and they are the RPC methods of the same
name (parameter: the block hash in hex). They are never served to an
anonymous caller: they need the configured API key (`--rpc-api-key` /
`--rpc-api-key-file`) or a trusted caller (`--rpc-trust-loopback`).

On a pruned node (the default; not `--archive`) the chain to move to may
contain blocks whose bodies were pruned: for example, `invalidateblock` on the
first block of a fork the node followed in a reorg deeper than the pruning
depth, or `reconsiderblock` after an `invalidateblock` that rolled the node
back through pruned blocks. The call then changes nothing and returns an error
saying how many block bodies it is re-fetching from the peers (at most 4,096
per call, nearest the new tip first). Repeat the same call once they have
arrived (a few seconds to minutes, depending on the count); each retry
requests the next missing bodies, until the call succeeds. Only bodies the
node requested this way are accepted.

## Chain-state check at start-up

At every start the node checks its chain state for the footprint of an
interrupted or failed commit written by releases before the 2026-10 audit
fixes (UTXO effects of a block without its undo record). If it finds one it
rebuilds the UTXO set and its indexes from the block bodies, which needs the
carryover snapshot:

```sh
./target/release/gnb --data-dir ./gnb-data \
    --carryover-snapshot genesis/bloch-g3-carryover.tsv
```

Without `--carryover-snapshot`, or on a pruned node whose old block bodies are
gone, it refuses to start and says why; resync from a fresh `--data-dir` (or
from an archival node's data dir). Data dirs written by this release cannot
produce the footprint: every chain move is committed in one atomic batch.
