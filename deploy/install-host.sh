#!/bin/sh
# Install or upgrade a GnB mining node on this host (Ubuntu, run as a sudoer).
#   install-host.sh <gnb-binary> <carryover.tsv> <miner-address> <threads> [peer-multiaddr ...]
# Idempotent. The Bloch services on the host are not touched.
#
# Operator input never reaches a shell or the systemd environment file
# unvalidated (audit OPS-3): the miner address must be alphanumeric, threads a
# decimal number, and every peer a multiaddr (/ followed by [A-Za-z0-9./:_-]).
# None of these can carry a newline, quote, `$`, backslash or space, so a
# value cannot add lines to /etc/gnb/gnb.env (e.g. LD_PRELOAD=...) or change
# how systemd parses it. The file is written with printf, not a heredoc.
set -eu
die() { echo "install-host.sh: $*" >&2; exit 2; }
[ $# -ge 4 ] || die "usage: install-host.sh <gnb-binary> <carryover.tsv> <miner-address> <threads> [peer-multiaddr ...]"
BIN=$1; SNAP=$2; ADDR=$3; THREADS=$4; shift 4

[ -f "$BIN" ] || die "binary '$BIN' not found"
[ -f "$SNAP" ] || [ -f /opt/gnb/carryover.tsv ] || die "snapshot '$SNAP' not found"
case $ADDR in
  *[!A-Za-z0-9]*) die "miner address must be alphanumeric (empty: do not mine)" ;;
esac
case $THREADS in
  ''|*[!0-9]*) die "threads must be a decimal number" ;;
esac
PEERS=
for p in "$@"; do
  case $p in
    /*) ;;
    *) die "peer '$p' is not a multiaddr (must start with /)" ;;
  esac
  case $p in
    *[!A-Za-z0-9./:_-]*) die "peer '$p' contains characters outside a multiaddr" ;;
  esac
  PEERS=${PEERS:+$PEERS }$p
done

id -u gnb >/dev/null 2>&1 || sudo useradd --system --home /var/lib/gnb --shell /usr/sbin/nologin gnb
sudo install -d -o root -g root -m 755 /opt/gnb/bin /etc/gnb
sudo install -d -o gnb -g gnb -m 750 /var/lib/gnb
sudo install -o root -g root -m 755 "$BIN" /opt/gnb/bin/gnb
sudo install -o root -g root -m 755 "$(dirname "$0")/gnb-launch" /opt/gnb/bin/gnb-launch
sudo install -o root -g root -m 644 "$(dirname "$0")/gnb-node.service" /etc/systemd/system/gnb-node.service
# The snapshot must be readable by the service (ProtectHome hides /home).
[ -f /opt/gnb/carryover.tsv ] || sudo install -o root -g root -m 644 "$SNAP" /opt/gnb/carryover.tsv
# Read by systemd (PID 1, root) only: root-owned, mode 600.
printf 'GNB_CARRYOVER=/opt/gnb/carryover.tsv\nGNB_MINER_ADDRESS=%s\nGNB_MINE_THREADS=%s\nGNB_PEERS="%s"\n' \
  "$ADDR" "$THREADS" "$PEERS" | sudo install -o root -g root -m 600 /dev/stdin /etc/gnb/gnb.env
sudo ufw allow 17110/tcp comment 'GnB P2P' >/dev/null
sudo systemctl daemon-reload
sudo systemctl enable gnb-node >/dev/null 2>&1
sudo systemctl restart gnb-node
sleep 3
systemctl is-active gnb-node
