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

### Remote RPC through a proxy or tunnel (audit B2-T11)

A reverse proxy or a tunnel delivers every remote request from loopback, so
the node cannot tell its operator from anyone the proxy serves by the
connection alone. Any setup that exposes the RPC port this way MUST:

1. set an API key (`--rpc-api-key-file <file>`) and require it for writes
   (`--rpc-require-auth-for-writes`), so `sendrawtransaction`, `submitblock`
   and the administrative methods need the key (Bitcoin Core never serves
   RPC without credentials);
2. NOT use `--rpc-trust-loopback`. The node never extends that trust to a
   request that carries a forwarding header, but a proxy that adds none (a
   raw TCP forward, an SSH tunnel from another user) would make every remote
   caller an administrator;
3. have the proxy set `X-Forwarded-For` (or `X-Real-IP` / `Forwarded`).

A request carrying any forwarding header (`X-Forwarded-For`, `X-Real-IP`,
`True-Client-IP`, `CF-Connecting-IP`, `Forwarded`, ... : `FORWARDING_HEADERS`
in `node/src/rpc/auth.rs`) is treated as a remote request even when it
arrives from loopback: it is rate-limited in the bucket of the client the
nearest proxy names (the last `X-Forwarded-For` entry; a header the node
cannot parse shares one "unknown" bucket) and it is never a trusted caller.
Direct loopback callers without such a header (the operator's `gnb-cli`, a
co-located pool) keep the loopback exemption. The header is never trusted for
authorization: it can only take trust away.

`submitblock` runs the cheap checks first (structure without the proof of
work, known parents, height, expected bits, timestamp) and evaluates the
64 MiB proof of work last, as gossip ingress does, so an invalid submission
costs no proof evaluation unless it is otherwise a valid next block.

### Request bodies (audit B1-T4)

RPC request bodies are capped at 1 MiB, except `submitblock`, whose body
carries the block as hex (twice its wire size): it may be up to 4 MiB, room
for a full 1,000,000-byte block. At most four bodies above 1 MiB are read at
a time (the rest are answered HTTP 503, JSON-RPC -32005, "busy"); a body
that is not `submitblock` and exceeds 1 MiB is answered HTTP 413. Bitcoin Core
accepts bodies up to 32 MiB.

### Anonymous transaction submissions (audit B1-T10)

`sendrawtransaction` from a caller that is not trusted (no API key, not a
trusted direct caller) is charged to one node-wide budget by its size before
its signatures are verified: 2,000,000 bytes, refilled at 50,000 bytes per
second. An admitted transaction is refunded, so the budget only runs out
under transactions the node refuses (a flood of forged signatures relayed
by the explorer API, from any number of addresses). While it is exhausted,
anonymous submissions are answered "busy: ..."; callers presenting the API
key are never charged.

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
`gnb1t…` (and the `network` field) in a v2 file used to load the key for the
other network. Every path that opens a keystore therefore authenticates the
network (re-audit CRY-7): a v3 file proves its own; a v2 file opens only for
a network the caller states, on every path, not only for spending:
`gnb-cli send`, `keyinfo` and `importfounder` (`--mainnet` / `--testnet`),
`gnb-wallet send`, `sign`, `address` and `pubkey` (same flags), the web
wallet's `open` (the page states mainnet), and the library
(`Keypair::from_encrypted_bytes_on` / `load_encrypted_on`;
`from_encrypted_bytes` / `load_encrypted` open v3 files only). The stored
address must be a valid address of that network and match the decrypted
key, and the file's `network` field must not name the other network; an HD
wallet refuses to import a key of the other network. When it is unlocked
for spending or signing, a v2 file is then rewritten as v3 under the same password,
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

### Address checksum and the network (CRY-7)

A GnB address is `gnb1q` (mainnet) or `gnb1t` (testnet) followed by the hex
of the 20-byte key hash and a 4-byte checksum, `SHA3-256(SHA3-256(hash))[..4]`.
The checksum does not cover the prefix, so `gnb1q…` and `gnb1t…` forms of one
hash both pass `Address::parse`. A new address version whose checksum commits
to the network (bech32m-style) was evaluated and is **not** introduced:

- it could only be emitted where every consumer parses it, and they do not:
  every released GnB wallet and node, the Bloch wallets that share these keys,
  the explorer and its API (`^gnb1[qt][0-9a-f]{48}$`), the Cloudflare Worker's
  path filter and third-party integrations would all reject it, so a payment
  to a new-format address from any of them fails;
- parsing both forms while emitting only the old one adds nothing: the old
  form would stay the one users copy;
- the risk it would remove is already closed where it matters: every payment
  path compares the destination's network with the wallet's own network,
  which is authenticated (keystore v3, keyfile v1, or the network the caller
  states for a v2 file): `TxBuilder::build_payment`, `Wallet` payments,
  `gnb-cli send`, `gnb-wallet send` and the web wallet's `pay` refuse a
  destination of the other network, and the node's `--miner-address` uses
  `Address::parse_for_network`. A prefix typo therefore fails before anything
  is signed, and a transaction signed for one chain is invalid on the other
  (the chain id is in every sighash).

Read-only RPC methods (`getbalance`, `getutxos`, `validateaddress`) accept
either prefix for the same hash; `validateaddress` reports the prefix's
network.
