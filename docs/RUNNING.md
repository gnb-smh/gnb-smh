# Running a GnB node

## Hardening activation: upgrade before mainnet height 110,000

> **Every mainnet node and miner must run this release before the chain
> reaches height 110,000.** The deadline is the height: watch `getdaginfo`
> `next_block_height`. On the ASERT schedule (genesis time + 110,000 × 30 s)
> that is **2026-11-18 07:07 UTC**, but the chain runs ahead of the schedule
> by about 240 blocks (2 h) per doubling of the network hashrate above about
> 600 GnB-SMH v3 evaluations/s (8 h early at 16 times that), so do not wait
> for the date.

- From height 110,000 the consensus rules of the 2026-10-14 audit apply on
  mainnet (`docs/CONSENSUS.md`, "Activation"; testnet and regtest apply them
  from genesis). The height is `MAINNET_HARDENING_ACTIVATION_HEIGHT` in
  `crates/gnb-crypto/src/core/activation.rs`.
- A node that has not upgraded by then keeps the old rules: it accepts
  blocks and transactions the upgraded nodes reject (and the reverse), so it
  splits from the upgraded network at the activation block and follows a
  separate chain.
- Check the upgrade on each node: `getnetworkinfo` reports `version` 0.1.1
  and `hardening_activation_height` 110000, and `getdaginfo` the same height
  and `hardening_active` for `next_block_height` (builds before 0.1.1 do not
  report the height there; `getblocktemplate` does). Peers see the identify
  agent `gnb/0.1.1/...`; the RPC does not list peers' agents (`getpeerinfo`
  reports only counts), so network-wide adoption cannot be read from one
  node.
- Miners: a template for the activation block and after must come from an
  upgraded node. `getblocktemplate` reports `hardening_activation_height`
  (110000 on mainnet) and `hardening_active` for the template's height.
- Wallets sign version-3 transactions from the activation height on; a
  wallet built before this release (including a web-wallet core compiled
  with another height) signs version 1 there, which every upgraded node
  refuses. The committed web-wallet core (`site/wallet/gnb_wallet.wasm`)
  compiles the height in; the site must be deployed from this release before
  the activation.
- Transactions signed before the activation (version 1) that are still
  unconfirmed when `next_block_height` reaches 110,000 are dropped from every
  upgraded node's mempool and refused from then on (no transaction is valid
  under both regimes: `docs/CONSENSUS.md`, "Transaction signatures" and
  "Which height"). Services holding pending or pre-signed payments must
  sign them again, as version 3, after the activation.
- Release check (before tagging, by whoever ships it): read the mainnet tip
  (`getdaginfo` `tip_height`, `next_block_height`) and the current `bits`
  (`getblocktemplate`) from a mainnet node. The tip must be well below
  110,000, and (110,000 - `next_block_height`) × the observed block interval
  is the real time left. If the template's `bits` are easier than
  `0x1f03a40d`, the genesis target shifted for GnB-SMH v3 (network hashrate
  below about 600 v3 evaluations/s), blocks after the activation slow to
  about 30 s × (that target's work / current work) until the hashrate rises
  (POW-3, `docs/CONSENSUS.md`, "Activation"): record the expected interval
  here, or reconsider the timing.
- If the release ships later than planned, or the chain is too close to the
  height, the height must be moved again before the chain reaches it: the
  constant `MAINNET_HARDENING_ACTIVATION_HEIGHT`, its copies in
  `crates/gnb-crypto/tests/gen_consensus_vectors.rs` (`MAINNET_ACT`),
  `reference/gnb_validity.py` (`HARDENING_ACTIVATION_HEIGHT`),
  `reference/gnb_merkle.py` and `reference/gnb_difficulty.py`
  (`MAINNET_HARDENING_ACTIVATION_HEIGHT`), the regenerated
  `reference/{tx,block,merkle,difficulty}_vectors.json` (with their
  generators), a rebuilt and re-pinned web-wallet core
  (`scripts/build-wallet-wasm.sh`, then deploy the site), a new node package
  version, and these notes (see the module documentation of `activation.rs`).

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

Transaction relay and mempool policy (unconfirmed chains, child-pays-for-parent
templates, full-RBF, orphan transactions): `docs/MEMPOOL.md`;
`getmempoolinfo` reports the parameters in force.

The explorer statistics (`getchainstats`, `gethashrate`, `getrichlist`,
`getsupplydistribution`, `getaddresscount`) are served from aggregates the
node keeps in the same write batches as its UTXO set. A data directory
written by an older node gets them built once at start-up (log line
"NET-12: explorer aggregates rebuilt …", one pass over the UTXO set and the
undo records); until then those methods answer with an error instead of
scanning. Every start-up also checks that the stored aggregates describe the
connected chain on disk (block count and a fingerprint of the connected
blocks against the undo records) and rebuilds them when they do not, instead
of serving stale statistics. (An older release can no longer move the chain
of an upgraded data directory forward: see "Upgrading and downgrading".)
`hashrate_hs` counts every DAG block (the selected-chain blocks and the blue
and red blocks they merge, `avg_dag_block_interval_secs`);
`avg_block_time_secs` is the interval between selected-chain blocks. A
storage failure behind any of these methods is answered with the generic
`STORAGE_ERROR` response; the detail only goes to the node's log.

The node serves plain HTTP. To reach a remote node, put a TLS reverse proxy in
front of its RPC port or use an SSH tunnel
(`ssh -L 17210:127.0.0.1:17210 host`). Both CLI wallets speak HTTPS (audit
WAL-7): `gnb-cli --rpc-url https://node.example …` or
`gnb-wallet --rpc https://node.example …`. They verify the certificate chain
against the Mozilla roots (`webpki-roots`) and check the host name. For a
private CA or a self-signed certificate, pass the trust anchor with
`gnb-cli --rpc-ca ca.pem` or set `GNB_RPC_CA=ca.pem` for `gnb-wallet`.
`GNB_RPC_API_KEY` is sent over HTTPS to any host, but over plain HTTP only
to loopback addresses. Each call has one 30-second deadline covering name
resolution, connect, the TLS handshake, the request and the response; every
socket read and write gets only the time left, so a server that stalls or
drips its answer cannot hold the wallet longer than that.

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
best remaining chain. `reconsiderblock` reconsiders the marks of the block, of
its selected-chain ancestors and of its selected-chain descendants and lets the
node re-evaluate: operator marks (and marks a block only inherited from a
marked ancestor) are removed; a block the node found invalid itself keeps its
mark unless it is re-validated — a block that failed the hardening block rules
at start-up (stored by an older release) only if its stored body now passes
them, a block that failed in its chain context only when the move connects it
after validating it again (a block that really is invalid is disqualified
again; a block the move cannot connect yet, for example because its stored
body is rejected and dropped or a body below it must be re-fetched, keeps its
mark: run `reconsiderblock` again once the body is back). Both
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
per call, nearest the new tip first; the node keeps at most 1,024 body
requests in flight and sends the next ones as bodies arrive, so the transfer
never crowds out its other block requests). Repeat the same call once they have
arrived (a few seconds to minutes, depending on the count); each retry
requests the next missing bodies, until the call succeeds. Ordinary block
acceptance needs no retry: when a heavier chain needs pruned bodies, the node
accepts its blocks, fetches the bodies and moves to it once they are back.
The transactions of blocks rolled back from pruned bodies cannot be put back
into the mempool (docs/MEMPOOL.md, section 6); their senders must rebroadcast
them. A body of a block the node already holds is accepted only while the node waits
for it (it requested it, or the body it had was rejected) and only as the
answer to its own request; it is checked like a new block (height implied by
its parents, difficulty, timestamp, proof of work, the witness commitment
rules) before it is stored.

## Chain-state check at start-up

At every start the node checks its chain state for the footprint of an
interrupted or failed commit written by releases before the 2026-10 audit
fixes (UTXO effects of a block without its undo record), after the repairs the
start-up reconciliation makes on its own. If it finds one it rebuilds the
chain state from the block bodies — the UTXO set and its indexes, the undo
records, the shielded-pool state and the explorer statistics — which needs the
carryover snapshot:

```sh
./target/release/gnb --data-dir ./gnb-data \
    --carryover-snapshot genesis/bloch-g3-carryover.tsv
```

Without `--carryover-snapshot`, or on a pruned node whose old block bodies are
gone, it refuses to start and says why; resync from a fresh `--data-dir` (or
from an archival node's data dir). This includes a data dir last written by a
release from before blocks carried undo records: its applied blocks cannot be
rolled back, so the state is rebuilt (an archival node) or resynced (a pruned
node). Data dirs written by this release cannot
produce the footprint: every chain move is committed in one atomic batch.

## Upgrading and downgrading

The upgrade to a release that keeps the shielded-pool state on disk (audit
COH-2) is one-way. From its first start the data directory holds the
RocksDB column family `shielded`. Every earlier release opens its database
read-write with a fixed list of column families that does not name it, and
RocksDB refuses that open (`Invalid argument: Column families not opened:
shielded`), so the earlier release stops at start-up. To downgrade, restore a
copy of the data directory taken before the upgrade (with the node stopped)
or resynchronize from a new data directory.

## Wallet keystores (audit CRY-7)

Every front end writes keystore **v3**, which authenticates the network and
the address in the AES-GCM associated data. Older **v2** files, from Bloch
or from GnB before the fix, authenticate neither: editing `gnb1q…` to
`gnb1t…` in a v2 file still loads the key for the other network. The CLIs
therefore unlock a v2 keystore for spending (`gnb-cli send`) or signing
(`gnb-wallet send` / `sign`) only when the network is stated with `--mainnet`
or `--testnet`. The stored address must be a valid address of that network
and match the decrypted key, and the file's `network` field must not name the
other network. The file is then rewritten as v3 under the same password,
but only once the command went ahead: after the send was checked and
confirmed (`send`) or the message was signed (`sign`); an aborted command
leaves the v2 file as it was. Before the rewrite the original v2 file is
copied byte for byte to a new `<file>.v2.bak` (`<file>.v2.bak.1`, `.2`, …
if that name is taken; an existing backup is never overwritten), mode 0600
and fsynced; if the copy cannot be written, nothing is rewritten. Keep that
copy if you use the key elsewhere: **Bloch wallets and GnB releases before
keystore v3 read only version-2 keystores** and cannot open the v3 file.
The rewrite itself is atomic (temp file, fsync, rename), mode 0600, and the
new bytes are decrypted and checked before they replace the old file. A v3
keystore needs no flag, but a stated network must match it. The library
calls are `Keypair::unlock_for_spending` (verify in memory, then
`PendingKeystoreMigration::commit`), `Keypair::load_for_spending` (both at
once) and, for front ends without a filesystem,
`Keypair::unlock_for_spending_bytes` (a front end that stores the v3 JSON
must also keep, or offer for download, the original v2 bytes).
