#!/usr/bin/env python3
"""GnB half of the Bloch bridge signer: verifies everything on ITS OWN GnB node, then signs.

Same rule as devnet4's atestador.py: nothing received is trusted. The signer rebuilds or
re-reads every fact from its own GnB node and refuses on any mismatch. Keys and limits are
fixed once (vault.json, config); there is no periodic signing.

  lock     verify a lock and print the facts for the mint message (signed by the Bloch half)
    python3 signatario_gnb.py lock --vault vault.json --txid TXID [--finalized] [--min-conf 1000]
           [--min-amount SATS] [--rpc-port 17210] [--cli PATH] [--journal DIR]

  release  co-sign a vault release for a burn the Bloch half verified as finalized
    python3 signatario_gnb.py release --vault vault.json --spend REL.json --burn BURN.json
           --key SIGNER_WALLET.json --password-file FILE [--rpc-port 17210] [--cli PATH] [--journal DIR]

BURN.json (from the Bloch half, after it read the burn at the L2 `finalized` level):
  {"burn_id": "<32-byte hex>", "gnb_recipient": "gnb1…", "amount_sats": "<u64>", "finalized": true,
   "l2_block": <n>, "l2_tx": "<hash>"}

Checks before `lock` reports ok:
  1. the node is on the vault's network (chain id) and not stale (tip < MAX_TIP_AGE old);
  2. `gnb-cli vaultchecklock`: exact lock shape (vault in output 0, 20-byte destination
     marker of exactly 546 in output 1), amount ≥ minimum, and depth (≥ N confirmations, or
     at/below the PoWit finalized block with --finalized).

Checks before `release` signs:
  1. the same node checks;
  2. the burn is marked finalized by the Bloch half and its fields are well formed;
  3. this signer never signed a different release for this burn (local journal);
  4. `gnb-cli vaultcheckrelease`: inputs are vault outputs as THIS node sees them, the shape
     is exact (payout to the burn's recipient, the burn marker, change to the vault), the
     vault is debited by exactly the burned amount, the fee is capped, and no release with
     this burn's marker exists on chain;
  5. only then `gnb-cli policysign`.
Any refusal prints {"signed": false, "reason": …} and exits 1.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

MAX_TIP_AGE = 30 * 60  # seconds; GnB targets 30 s blocks
CHAIN_IDS = {'mainnet': '0x474E0001', 'testnet': '0x474E0002'}


def option(name, default=None):
    args = sys.argv[2:]
    if name in args:
        return args[args.index(name) + 1]
    if default is None:
        refuse(f'{name} is required')
    return default


def flag(name):
    return name in sys.argv[2:]


def refuse(reason, **detail):
    print(json.dumps({'signed': False, 'ok': False, 'reason': reason, **detail}, indent=2))
    raise SystemExit(1)


def rpc(port, method, params=None):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or []}).encode()
    req = urllib.request.Request(f'http://127.0.0.1:{port}', data=body, headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            out = json.loads(r.read())
    except Exception as e:  # noqa: BLE001 - any transport failure is a refusal
        refuse(f'GnB node RPC {method} failed: {e}')
    if out.get('error'):
        refuse(f'GnB node RPC {method}: {out["error"]}')
    return out.get('result')


def cli(argv, env=None):
    done = subprocess.run([str(a) for a in argv], capture_output=True, text=True, env=env)
    return done.returncode, done.stdout.strip(), done.stderr.strip()


def check_node(port, vault):
    """The node follows the vault's network and is not stale."""
    info = rpc(port, 'getnetworkinfo')
    want = CHAIN_IDS.get(vault['network'])
    if info.get('chain_id') != want:
        refuse('the GnB node is on another network', node=info.get('chain_id'), vault=want)
    if info.get('syncing'):
        refuse('the GnB node is still syncing')
    dag = rpc(port, 'getdaginfo')
    tip = rpc(port, 'getblock', [dag['tip']])
    age = time.time() - int(tip['timestamp'])
    if age > MAX_TIP_AGE:
        refuse(f'the GnB node tip is {int(age)} s old (stalled node)', tip_height=dag['tip_height'])
    return dag['tip_height']


def journal_path(journal, kind, key):
    d = Path(journal) / kind
    d.mkdir(parents=True, exist_ok=True)
    return d / f'{key}.json'


def cmd_lock():
    vault_path = option('--vault')
    vault = json.loads(Path(vault_path).read_text())
    txid = option('--txid').lower()
    port = int(option('--rpc-port', '17210'))
    gnb_cli = option('--cli', 'gnb-cli')
    tip_height = check_node(port, vault)
    argv = [gnb_cli, '--rpc-port', port, 'vaultchecklock', vault_path, txid,
            '--min-conf', option('--min-conf', '1000'), '--min-amount', option('--min-amount', '0')]
    if flag('--finalized'):
        argv.append('--finalized')
    code, out, err = cli(argv)
    try:
        verdict = json.loads(out)
    except json.JSONDecodeError:
        refuse('vaultchecklock gave no verdict', stderr=err[-800:])
    if not verdict.get('ok'):
        refuse(verdict.get('reason', 'lock check failed'), lock=verdict)
    facts = {
        'ok': True,
        'gnb_chain_id': CHAIN_IDS[vault['network']],
        'vault': vault['address'],
        'lock_txid': verdict['lock_txid'],
        'lock_vout': 0,
        'amount': verdict['amount'],
        'l2_recipient': verdict['l2_recipient'],
        'gnb_block_hash': verdict['block_hash'],
        'gnb_block_height': verdict['block_height'],
        'confirmations': verdict['confirmations'],
        'rule': 'powit-finalized' if flag('--finalized') else f'confirmations>={option("--min-conf", "1000")}',
        'checked_at_tip': tip_height,
    }
    j = journal_path(option('--journal', 'journal-gnb'), 'locks', f'{txid}-0')
    if j.exists():
        prev = json.loads(j.read_text())
        if (prev['amount'], prev['l2_recipient']) != (facts['amount'], facts['l2_recipient']):
            refuse('this lock was reported before with different facts', before=prev, now=facts)
    else:
        j.write_text(json.dumps(facts, indent=2))
    print(json.dumps(facts, indent=2))


def cmd_release():
    vault_path = option('--vault')
    vault = json.loads(Path(vault_path).read_text())
    spend = option('--spend')
    burn = json.loads(Path(option('--burn')).read_text())
    port = int(option('--rpc-port', '17210'))
    gnb_cli = option('--cli', 'gnb-cli')
    check_node(port, vault)

    if burn.get('finalized') is not True:
        refuse('the burn is not finalized on the L2 (per the Bloch half)')
    burn_id = str(burn.get('burn_id', '')).lower().removeprefix('0x')
    if len(burn_id) != 64 or any(c not in '0123456789abcdef' for c in burn_id):
        refuse('burn_id must be 32-byte hex')
    recipient = str(burn.get('gnb_recipient', ''))
    if not recipient.startswith('gnb1'):
        refuse('gnb_recipient must be a gnb1… address')
    amount = str(burn.get('amount_sats', ''))
    if not amount.isdigit():
        refuse('amount_sats must be a decimal string')

    # One release per burn, ever, from this signer.
    spend_bytes = Path(spend).read_bytes()
    j = journal_path(option('--journal', 'journal-gnb'), 'releases', burn_id)
    tx_hex = json.loads(spend_bytes)['tx']
    if j.exists() and json.loads(j.read_text()).get('tx') != tx_hex:
        refuse('this signer already signed a different release for this burn')

    code, out, err = cli([gnb_cli, '--rpc-port', port, 'vaultcheckrelease', vault_path, spend, burn_id,
                          recipient, amount])
    try:
        verdict = json.loads(out)
    except json.JSONDecodeError:
        refuse('vaultcheckrelease gave no verdict', stderr=err[-800:])
    if not verdict.get('ok'):
        refuse(verdict.get('reason', 'release check failed'))

    # Sign: the key never leaves this machine; the password comes from a file.
    env = dict(os.environ)
    env['GNB_WALLET_PASSWORD'] = Path(option('--password-file')).read_text().splitlines()[0].strip()
    code, out, err = cli([gnb_cli, 'policysign', spend, option('--key')], env=env)
    if code:
        refuse('policysign failed', stderr=err[-800:])
    j.write_text(json.dumps({'tx': tx_hex, 'burn': burn, 'signed_at': int(time.time())}, indent=2))
    print(json.dumps({'signed': True, 'burn_id': burn_id, 'fee': verdict['fee'],
                      'burn_marker': verdict['burn_marker'], 'policysign': out.splitlines()[-1:]}, indent=2))


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ('lock', 'release'):
        print(__doc__)
        raise SystemExit(2)
    {'lock': cmd_lock, 'release': cmd_release}[sys.argv[1]]()


if __name__ == '__main__':
    main()
