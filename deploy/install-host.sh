#!/bin/sh
# Install or upgrade a GnB mining node on this host (Ubuntu, run as a sudoer).
#   install-host.sh <gnb-binary> <carryover.tsv> <miner-address> <threads> [peer-multiaddr ...]
# Idempotent. The Bloch services on the host are not touched.
set -eu
BIN=$1; SNAP=$2; ADDR=$3; THREADS=$4; shift 4
PEERS="$*"
id -u gnb >/dev/null 2>&1 || sudo useradd --system --home /var/lib/gnb --shell /usr/sbin/nologin gnb
sudo install -d -o root -g root -m 755 /opt/gnb/bin /etc/gnb
sudo install -d -o gnb -g gnb -m 750 /var/lib/gnb
sudo install -o root -g root -m 755 "$BIN" /opt/gnb/bin/gnb
sudo install -o root -g root -m 755 "$(dirname "$0")/gnb-launch" /opt/gnb/bin/gnb-launch
sudo install -o root -g root -m 644 "$(dirname "$0")/gnb-node.service" /etc/systemd/system/gnb-node.service
# The snapshot must be readable by the service (ProtectHome hides /home).
[ -f /opt/gnb/carryover.tsv ] || sudo install -o root -g root -m 644 "$SNAP" /opt/gnb/carryover.tsv
sudo tee /etc/gnb/gnb.env >/dev/null <<ENV
GNB_CARRYOVER=/opt/gnb/carryover.tsv
GNB_MINER_ADDRESS=$ADDR
GNB_MINE_THREADS=$THREADS
GNB_PEERS=$PEERS
ENV
sudo ufw allow 17110/tcp comment 'GnB P2P' >/dev/null
sudo systemctl daemon-reload
sudo systemctl enable gnb-node >/dev/null 2>&1
sudo systemctl restart gnb-node
sleep 3
systemctl is-active gnb-node
