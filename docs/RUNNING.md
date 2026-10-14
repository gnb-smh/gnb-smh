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
