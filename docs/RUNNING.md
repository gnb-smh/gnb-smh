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

## Peers and connections

Connection management follows Bitcoin Core's `CConnman` / `addrman` design
(audit NET-11, re-audit B1-T8 and B1-T9); the code is in
`node/src/network/{connmgr,addrbook,gossip_gate,pex_validator}.rs`.

Settings:

- `--peer <multiaddr>` (repeatable): a manual connection (Core's
  `-addnode`). It is dialed at start-up and re-dialed every 30 s while it is
  not connected (an entry without `/p2p/<id>` is re-dialed while no manual
  connection is up). It never uses an automatic outbound slot. A host name is
  resolved by the node; like an IP literal given here, it may resolve to a
  private or loopback address (docker / LAN setups) whatever
  `--allow-private-peers` says, but never into an invalid range (unspecified,
  multicast, documentation, link-local such as 169.254.169.254, …). The
  30 s re-dial resolves names on a separate task (at most 10 s per lookup),
  so a configured host that is down or slow to resolve never stalls the
  node's network loop.
- `--dns-seed <host[:port]>` (repeatable, opt-in): resolved at start-up and
  dialed as manual connections. Answers that are not routable public
  addresses are ignored unless `--allow-private-peers` is set.
- `--max-peers <n>` (default 50): the INBOUND slots. Outbound slots come on
  top of them and cannot be used by inbound connections.
- `--allow-private-peers`: dev/test only. Accepts loopback, RFC 1918, CGNAT,
  ULA and link-local IPv6 addresses in the address tables.
- `--enable-mdns`: zero-config LAN discovery (off by default).

Outbound connections. The node keeps 8 full-relay and 2 block-relay-only
outbound connections (Core's 8 + 2), whatever the inbound count, and opens
at most one automatic outbound connection per second to fill a free slot
(full-relay slots first, then block-relay-only). Addresses come from the
address tables, half the time from the tried table and half from the new
table; at most one automatic outbound peer per netgroup (an IPv4 /16, an
IPv6 /32; an IPv6 literal that embeds an IPv4 — `::ffff:a.b.c.d`, 6to4,
Teredo, NAT64 — counts as that IPv4's /16); an address tried in the last 10
minutes is not tried again. Small-network fallback (not in Core, which
relies on seeds; this network ships with none): when neither table holds a
candidate outside the netgroups already used, a full-relay slot may take a
peer in a used netgroup, up to 4 automatic outbound peers per netgroup, so
nodes hosted in one /16 still connect to each other after a restart.
Block-relay-only slots never relax the one-per-netgroup rule.

Inbound connections. When a new inbound connection finds the `--max-peers`
slots full, an existing inbound peer is evicted, chosen as Core's
`SelectNodeToEvict` does: the peers in 4 netgroups picked by a secret key,
the 8 lowest-latency peers (libp2p ping), the 4 that most recently delivered
a new transaction, the 4 that most recently delivered a new block, and the
longest-connected half of the rest are protected; the most recently
connected peer of the netgroup with the most remaining peers is evicted.
With fewer than 21 inbound peers everyone is protected and the newcomer is
refused. At the transport level a node accepts `--max-peers` + 1 inbound
connections (the extra one is the newcomer under evaluation), at most 2
connections per peer, and `max(2 × max-peers, max-peers + 32)` connections in
all.

Address tables. Peer exchange (`GetPeers` over `/gnb/sync/1`) carries IP
literals only — host names are refused, and so is any address that is not a
routable public address once an embedded IPv4 is taken into account (so
`/ip6/::ffff:127.0.0.1/…` is refused like `/ip4/127.0.0.1/…`). A received
address goes into the in-memory **new** table (1,024 slots: 64 buckets of
16); a successful outbound connection moves it to the **tried** table
(1,000 slots: 125 buckets of 8), saved every minute as `known_peers.json`.
Bucket and slot are chosen by a keyed hash (a secret derived from the node's
P2P identity key, never sent anywhere), as in Core's addrman: the addresses
one peer's netgroup sends can only reach 4 of the 64 new buckets, and one
netgroup can hold at most 16 tried entries. A full tried bucket never evicts
on the spot: the occupant is tested first by a feeler connection and kept if
it answers (Core's test-before-evict); it is also kept, and the newcomer
dropped, if its feeler fails but it connected successfully in the last 4
hours (Core's `ADDRMAN_REPLACEMENT`; entries loaded from `known_peers.json`
count as successful at start-up). Addresses are read only from the answer to
the node's own `GetPeers`; a `Peers` answer to any other request is ignored. The node asks for addresses only on
its outbound full-relay and manual connections and answers only inbound
peers, once per connection, from a sample of the tried table cached for 21
to 27 hours (Core's getaddr cache), so asking repeatedly reveals no more of
the table. 20 addresses per answer and 100 per 5 minutes per answering peer
are read.

Feelers. While every outbound slot is full, the node opens a short-lived
"feeler" connection about every 2 minutes (exponentially distributed): to a
tried-table occupant awaiting a collision test, else to a random new-table
address. A feeler carries no gossip and none of the node's requests, and is
closed about a second after it is established (once the remote has finished
its side of the connection setup, as Core waits for the version handshake);
a new-table address that answered moves to the tried table.

Block-relay-only connections and anchors. The 2 block-relay-only
connections carry no gossip at all (no transactions, no addresses, no block
announcements): gossipsub never sees them, so they cannot be found through
transaction or address relay. The node learns blocks over them by polling
the peer's frontier (`GetTips` every 30 s) and pulling what it lacks. Their
addresses are saved in `anchors.json` (at most 2) whenever that set changes;
at start-up the file is read once, deleted, and its peers are re-dialed
first as block-relay-only connections (Core's `anchors.dat`). Nothing the
node publishes crosses a block-relay-only connection (the remote treats it
as an ordinary inbound peer without gossip and does not poll us), so these
peers are left out of the peer count the node reports (RPC `peers`, and the
miner's wait-for-peers check): a node connected only to its anchors does not
mine as if it were on the network.

External address. A peer-reported observed address becomes the node's
advertised address only when peers in 3 different netgroups report it.

Differences from Bitcoin Core, by design or not yet done: no AS-map (netgroups
are IP prefixes); no Tor / I2P / CJDNS networks, so no protection quota for
them; the new table is not persisted and a new-table address is dropped once
dialed (no attempt counters); an occupied keyed slot probes to the next free
slot of the same bucket (bucket bounds unchanged; avoids losing addresses to
collisions at this table size); block-relay-only peers do not push blocks to
us (we poll them every 30 s); no extra rotating block-relay-only peer or
stale-tip extra outbound connection; anchors are written when the set
changes rather than at shutdown (the node has no orderly network shutdown).

Block-relay-only connections carry no PoWit items either: witness shares,
attestations and equivocation proofs (`NewPowitItem`) are gossiped on the
transaction topic, and gossipsub never sees those connections. A PoWit item
accepted from a peer does not count as a novel transaction for the inbound
eviction protection (Core protects for novel blocks and transactions only).

Transaction privacy: transactions are gossiped from the node that creates
them; the origin IP is not hidden (the unused Dandelion++ sketch was removed,
NET-17). The P2P transport (`/gnb/pq/2.0.0`, `docs/P2P.md`) authenticates
each peer with its Ed25519 libp2p key and its hybrid ML-DSA-65 ‖ Falcon-1024
key, and derives session keys from ML-KEM-768 and X25519.

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
