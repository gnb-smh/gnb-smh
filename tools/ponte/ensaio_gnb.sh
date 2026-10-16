#!/bin/bash
# GnB-side rehearsal of the Bloch bridge v1 on a local testnet:
#   lock -> 3 signers verify the lock -> (simulated finalized burn) -> release built ->
#   3 signers verify and co-sign -> broadcast -> confirmed -> a replay is refused.
#
# usage: ensaio_gnb.sh <dir> <rpc-port> <user-address> <l2-0xaddress> <lock GNB> <burn sats>
#   <dir> holds vault.json, pw (wallet password), w/{user,s1..s5}-testnet.json
# The burn is simulated here (burn.json); in the joint rehearsal the Bloch half writes it.
set -euo pipefail
D=$1; PORT=$2; USER_ADDR=$3; L2=$4; LOCK_GNB=$5; BURN_SATS=$6
cd ~/repos/github/gnb-smh
CLI=./target/release/gnb-cli
SIG="python3 tools/ponte/signatario_gnb.py"
export GNB_WALLET_PASSWORD="$(head -1 "$D/pw")"
step() { echo; echo "== $*"; }

step "1. lock $LOCK_GNB GNB for $L2"
LOCK=$($CLI --rpc-port "$PORT" vaultlock "$D/w/user-testnet.json" "$D/vault.json" "$LOCK_GNB" "$L2")
echo "$LOCK"
TXID=$(echo "$LOCK" | python3 -c "import sys,json; print(json.load(sys.stdin)['lock_txid'])")

step "2. wait for the lock to be PoWit-finalized"
until $CLI --rpc-port "$PORT" vaultchecklock "$D/vault.json" "$TXID" --finalized | grep -q '"ok":true'; do sleep 5; done

step "3. three signers verify the lock on their own node (finalized rule)"
for s in 1 2 3; do
  $SIG lock --vault "$D/vault.json" --txid "$TXID" --finalized --rpc-port "$PORT" --cli "$CLI" \
       --journal "$D/journal-s$s" | python3 -c "import sys,json; f=json.load(sys.stdin); print('signer $s:', f['ok'], f['amount'], f['l2_recipient'], 'h', f['gnb_block_height'])"
done

step "4. simulated finalized burn (Bloch half) of $BURN_SATS sats to $USER_ADDR"
BURN_ID=$(python3 -c "import hashlib; print(hashlib.sha3_256(b'ensaio-burn-$TXID').hexdigest())")
cat > "$D/burn.json" <<EOF
{"burn_id": "$BURN_ID", "gnb_recipient": "$USER_ADDR", "amount_sats": "$BURN_SATS", "finalized": true,
 "l2_block": 0, "l2_tx": "simulated"}
EOF
cat "$D/burn.json"

step "5. build the release from the lock's vault output"
LOCK_SATS=$(echo "$LOCK" | python3 -c "import sys,json; print(json.load(sys.stdin)['amount'])")
$CLI vaultrelease "$D/vault.json" "$BURN_ID" "$USER_ADDR" "$BURN_SATS" --utxo "$TXID:0:$LOCK_SATS" --out "$D/release.json"

step "6. three signers verify and co-sign"
for s in 1 2 3; do
  OUT=$($SIG release --vault "$D/vault.json" --spend "$D/release.json" --burn "$D/burn.json" \
       --key "$D/w/s$s-testnet.json" --password-file "$D/pw" --rpc-port "$PORT" --cli "$CLI" \
       --journal "$D/journal-s$s")
  echo "$OUT" | python3 -c "import sys,json; r=json.load(sys.stdin); print('signer $s signed:', r['signed'], 'fee', r['fee'])"
  MARKER=$(echo "$OUT" | python3 -c "import sys,json; print(json.load(sys.stdin)['burn_marker'])")
done

step "7. broadcast"
$CLI --rpc-port "$PORT" policysend "$D/release.json"

step "8. wait until the release is mined (burn marker $MARKER on chain)"
until $CLI --rpc-port "$PORT" getutxos "$MARKER" 2>/dev/null | grep -q '"utxo_count": [1-9]'; do sleep 5; done
$CLI --rpc-port "$PORT" getutxos "$USER_ADDR" | python3 -c "import sys,json; d=json.load(sys.stdin); print('user balance', d['gnb'], 'GNB')"
$CLI --rpc-port "$PORT" vaultutxos "$D/vault.json" | python3 -c "import sys,json; d=json.load(sys.stdin); print('vault balance', d['gnb'], 'GNB in', d['utxo_count'], 'utxo(s)')"

step "9. replay: build a second release for the same burn; a fresh signer must refuse it"
VAULT_UTXO=$($CLI --rpc-port "$PORT" vaultutxos "$D/vault.json" | python3 -c "
import sys,json; u=json.load(sys.stdin)['utxos'][0]; print(f\"{u['txid']}:{u['index']}:{u['value']}\")")
$CLI vaultrelease "$D/vault.json" "$BURN_ID" "$USER_ADDR" "$BURN_SATS" --utxo "$VAULT_UTXO" --out "$D/replay.json"
if $SIG release --vault "$D/vault.json" --spend "$D/replay.json" --burn "$D/burn.json" \
     --key "$D/w/s4-testnet.json" --password-file "$D/pw" --rpc-port "$PORT" --cli "$CLI" --journal "$D/journal-s4"; then
  echo "REPLAY WAS SIGNED (bug)"; exit 1
else
  echo "replay refused, as required"
fi
