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

## Directed sync (`/gnb/sync/1`) and misbehaving peers

Block, header, frontier and peer-address requests go to one peer at a time
over the directed `/gnb/sync/1` request-response protocol. None of the
limits below changes which blocks are valid; they are node-local and apply
from the first start of this release (re-audit B1-T2, B1-T3, B1-T6, B1-T18,
B2-T5, B2-T6, B2-T7, NET-9, NET-10; code in `node/src/network/{pull,serve,
misbehaviour,sync_rr}.rs`).

As a client the node:

- accepts an answer only if it answers the request it was sent for: a block
  or "not found" for the requested hash, at most the requested number of
  headers and none below the requested blue score, tips for a tips request,
  addresses for an address request, or Busy. Any other answer is a protocol
  violation: it is dropped, the request goes to another peer, and the peer
  is penalized;
- sends a block request first to the peer whose answer announced the block,
  never twice to the same peer, to at most 8 peers, with a growing delay
  from the third attempt on (250 ms doubling, at most 4 s), and drops it
  after 10 minutes or once every connected peer has answered it; a
  "not found" ranks the answering peer down (it is taken back if nobody has
  the block), and a peer that keeps answering uselessly is asked only when
  no better peer could take the request at all;
- keeps each peer's cooldown, scores and rotation slot when it disconnects
  (up to 1,024 peers), so reconnecting does not clear a stall cooldown
  (60 s, doubling for repeat offenders up to 16 minutes);
- lets the answers of one peer start at most 1,024 of the 4,096 queued
  block requests and at most 64 of the 512 frontier tips in flight, and
  always admits its own requests (orphan parents, the 30 s nudge);
- counts a "not found" toward abandoning an advertised frontier tip only
  from a peer it dialed, and forgets an abandoned tip after one hour.

As a server it answers on two background workers (not on the network
event loop), each answer costing O(log n + limit) whatever the size of the
DAG; requests wait in a bounded queue (32 per peer, 512 in all) served
round-robin across peers. Per peer it answers at most 64 block requests in
a burst then 8 per second, 16 header requests then 2 per second, 8 tips
requests then one per 2 s, 4 address requests then one per 10 s, and 256
requests per second in all; a peer whose unwritten answers reach 4 MiB, or
all peers' 64 MiB, gets Busy without the answer being computed. An answer
not written within 15 s is dropped, and a connection keeps at most 64
directed-sync streams open. Blocks are sent as stored. The tips answer is
the selected tip and the best other valid tips by blue work, at most 256,
never a chain-disqualified block; releases before this one sent every DAG
leaf, which upgraded requesters refuse without penalty. `getdaginfo` no
longer walks the selected chain.

Misbehaviour from every source feeds one decaying per-peer score (the
gossipsub application score; each offence -100, decaying 10 % a minute): an
invalid gossip frame the node rejects, a wire-rule violation on gossip or
on `/gnb/sync/1`, a malformed request, a wrong answer, an invalid block
sent as the answer to the node's own request, an invalid orphan
transaction. At -400 (four offences in a short time; also gossipsub's
graylist threshold) the peer is disconnected and its identity refused for
24 hours (up to 4,096 identities remembered). Bitcoin Core disconnects and
discourages a misbehaving peer the same way; it also discourages the
address, which this release does not do.

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
