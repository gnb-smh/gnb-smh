# Explorer API deployment

`gnb_explorer_api.py` sits between the Cloudflare Worker (`worker/index.js`)
and the node's loopback JSON-RPC. The Worker only talks to `https://` origins
listed in its `GNB_ORIGINS` variable and authenticates with the `X-GnB-Key`
shared secret, so the origin must be reachable over TLS. Two supported
layouts (audit findings WAL-2 and WAL-4):

## A. Cloudflare Tunnel (recommended)

The API listens on `127.0.0.1:2086` only (the service default) and
`cloudflared` publishes it through an outbound, authenticated tunnel.
Nothing listens on a public address and no firewall rule is needed.

1. `install -m 0755 gnb_explorer_api.py /opt/gnb/bin/`
2. Shared secret: `install -m 0640 -o root -g gnb /dev/stdin /etc/gnb/explorer-api.key`
   (at least 32 random characters); the API refuses a group-writable or
   world-accessible key file.
3. `install -m 0644 gnb-explorer-api.service /etc/systemd/system/`
4. Create the tunnel and its DNS route (see the header of
   `cloudflared-gnb-explorer.service`), install `cloudflared-config.example.yml`
   as `/etc/cloudflared/gnb-explorer.yml` with your tunnel id and hostname,
   and install the unit.
5. `systemctl enable --now gnb-explorer-api cloudflared-gnb-explorer`
6. Add `https://<tunnel hostname>` to the Worker's `GNB_ORIGINS`
   (`wrangler secret put GNB_ORIGINS`) and the key to `GNB_API_KEY`.

## B. Direct TLS behind a Cloudflare-only firewall

Set `GNB_API_BIND=0.0.0.0`, `GNB_API_PORT=2087` (a port Cloudflare proxies
for HTTPS) and `GNB_API_TLS_CERT` / `GNB_API_TLS_KEY` (for example a
Cloudflare Origin CA certificate) in the service, then restrict the port to
Cloudflare's edge:

    sudo sh firewall-cloudflare.sh 2087 cloudflare-ips-v4.txt

Refresh `cloudflare-ips-v4.txt` from https://www.cloudflare.com/ips-v4 first.
The API refuses to serve plain HTTP on a non-loopback address.

## Limits

Per connection: `GNB_API_TIMEOUT` (per read, default 10 s) and
`GNB_API_DEADLINE` (whole connection, default 30 s). At most
`GNB_API_MAX_CONNECTIONS` (64) connections are served at once; more are
refused immediately. Requests are rate-limited per original client
(`X-GnB-Client-IP`, set by the Worker from `CF-Connecting-IP`):
`GNB_API_RATE_PER_MIN` reads (240) and `GNB_API_POST_PER_MIN` broadcasts (6).

Run `--archive` on the nodes behind the explorer if possible: wallets verify
UTXO values against the creating transaction (`getrawtransaction`), which a
pruning node cannot serve for old outputs.

Tests: `python3 -m unittest deploy/explorer-api/test_gnb_explorer_api.py`.
