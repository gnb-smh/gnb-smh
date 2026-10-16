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

Use one data dir per network. Mainnet and testnet (`--testnet`) share the
genesis block, so the genesis check alone cannot tell their data dirs apart;
the data dir records the chain id of the network it was first started on
(CF_META `chain_id`; a data dir from an earlier release is marked with the
network of its first start under this release), and a node of the other
network refuses it with "this data dir belongs to chain id ...". The two
networks also use different gossip topics and sync protocols, and a node
disconnects a peer of the other network after the identify exchange
(docs/CONSENSUS.md, "Networks").

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

Heights in `getblockhash`, `getblockbyheight`, `getrecentblocks`,
`getblock` given a number, the address history (`listtransactions`'
`block_height`, `getaddressbalance_at_height`) and the pruning cursor
(`pruned_height`) are positions on the applied selected chain: the DAG
height, 0 for the genesis and one more per selected-parent step (audit DAG-8),
like Bitcoin Core's active-chain heights. `getblockhash N` names exactly one
block, the selected-chain block at position N. A block's header height
(`getblock`'s `height`, the height its difficulty and coinbase commitment
use) can be larger than its position when it merges a parent with a greater
DAG height; header heights can repeat along the selected chain, which is why
the indexes are not keyed by them. A data dir from an earlier release (keyed
by header height, where two chain blocks could share a row) is migrated once
at start-up (log line "DAG-8: selected-chain indexes migrated …"), before
reconciliation moves the chain, over the chain reconciliation leaves applied
(the block it re-tips to when it rolls back blocks that have UTXO effects but
no DAG record). The address history of a block whose body is stored is
rebuilt from the body; that of a pruned block is moved to its position, from
its pruned-body record, or, for a body pruned by a release before that
record existed, from the rows themselves (each attributed to its block
through the transaction index; a record naming them is written so that a
later reorg deletes them). A row that an earlier release had overwritten
with another block's, or that cannot be attributed to a block, cannot be
recovered and is reported as lost.

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

### Supply audit: `gettxoutsetinfo` (audit VAL-11)

`gettxoutsetinfo` is the counterpart of Bitcoin Core's method of the same
name. It reads the whole UTXO set and every undo record in one RocksDB
snapshot (a block connected meanwhile is wholly in the answer or not at all)
and answers:

| Field | Meaning |
|---|---|
| `height`, `bestblock` | the applied tip and its chain position |
| `txouts`, `total_amount_sat` | unspent outputs and their total |
| `hash_serialized` | SHA3-256 of the UTXO rows in key order (domain `gnb/utxo-set/v1`; each row `u32 LE len ‖ key ‖ u32 LE len ‖ value`). Two nodes with the same set report the same hash; compare it across nodes at the same `bestblock` |
| `applied_blocks`, `chain_ok` | blocks with an undo record (the connected chain, genesis excluded), and whether that is exactly `height` |
| `expected.carryover_sat` | the genesis ledger (the verified Bloch carryover) |
| `expected.subsidy_sat` | the subsidy of every connected block, at the header height its coinbase was checked against |
| `expected.max_supply_sat` | carryover + subsidy: the most the set may hold |
| `expected.schedule_issued_sat` | `issued_through_sat(height)`, the schedule through the tip's position, an upper bound of `subsidy_sat` |
| `unclaimed_sat` | `max_supply_sat - total_amount_sat`, `null` when the set holds more |
| `supply_ok` | the set holds no more than `max_supply_sat` and every row decodes |
| `aggregates` | the scan's count and total over address (20-byte) scripts against the aggregates the node keeps in the same write batches as the UTXO set |
| `ok` | all of the above hold |

`unclaimed_sat` is value that can never be spent, and is expected to be
positive and to grow: a miner that claims less than subsidy plus fees burns
the difference (consensus allows it); before the hardening activation a
transaction that recreated an existing outpoint replaced the older coin
(BIP30, audit VAL-2); and value that enters the shielded pool leaves the
transparent set (no shielded transaction is valid while the pool is
inactive). Fees are not issuance: they move value from transaction outputs
to the coinbase. Outputs paying unspendable scripts (the genesis coinbase
creates none) stay in the set and in the total, as in Core. A total above
`max_supply_sat` (`supply_ok: false`) means inflation or a corrupted set; an
aggregates mismatch with the supply bound intact means a UTXO row changed
outside the node (disk corruption, an edited data dir). Either way stop the
node and resync from a fresh `--data-dir` (or an archival node's data dir):
the node has no `-reindex-chainstate` yet, and the start-up rebuild of
"Chain-state check at start-up" only runs when it finds an interrupted
commit.

The method is in the heavy class (one computation at a time; a result is
cached for 30 s per applied tip, so a block connected or disconnected since
is never answered from the cache, and `bestblock` says which chain it
describes) and is
cancelled at the RPC deadline (25 s inside the 30 s request timeout),
answering `{"error":"cancelled"}`; it never blocks block acceptance.

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

Before anything else the node verifies the integrity chain over its stored
GhostDAG records. A data dir written by a release from before the 2026-10
audit fixes can fail it without any tampering: that release ignored a failed
DAG write and zero-filled the missing parent link of the next block. The
node then repairs the records instead of refusing to start (audit DAG-11): a
record consistent with its own integrity hash is kept and relinked, a
missing or corrupted record is recomputed from the stored block header with
the consensus code, and a block that cannot be recomputed (its body is gone
too) is dropped together with its descendants and fetched again from peers.
The log says how many blocks were relinked, recomputed and dropped, and the
next start verifies strictly. If a block that would be dropped is applied
(on a pruned node, a lost record in the pruned range), the UTXO set cannot be
repaired in place and the node refuses to start: resync from a fresh
`--data-dir` (or an archival node's data dir).

If start-up reconciliation cannot connect the best valid chain (a storage
error), the node refuses to start ("Refusing to start: the best valid chain
cannot be connected"), as Bitcoin Core does when it fails to connect the
best block at init; fix the cause it names (disk space, permissions) and
restart. Later acceptances always connect from the applied tip recorded on
disk, so a move that failed once is retried by the next block.

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
