# Multisig and timelocks

GnB has no script language. A script interpreter is the largest consensus
attack surface Bitcoin has, so GnB instead defines exactly two output types
(`crates/gnb-crypto/src/core/policy.rs`):

| Output script | Address | Spent by |
| --- | --- | --- |
| 20 bytes: `SHA3-256(pubkey)[..20]` | `gnb1q…` / `gnb1t…` | one hybrid ML-DSA-65 ‖ Falcon-1024 signature |
| 33 bytes: `0x02 ‖ SHA3-256("GNB-POLICY-v1" ‖ policy)` | `gnb1m…` / `gnb1n…` | the policy plus `m` signatures |

Any other output script is invalid (it used to be an unspendable burn).

## Spend policies

A policy is:

- **m-of-n multisig**: 1 ≤ m ≤ n ≤ 7 distinct hybrid keys (each 3,749 bytes);
- **`after`** (absolute timelock): spendable only by a transaction whose
  `locktime ≥ after`. `0` = none;
- **`older`** (relative timelock): spendable only `older` blocks after the
  output confirmed. `0` = none.

The output commits only to the policy's hash. The spender reveals the policy
and exactly `m` signatures, tagged with strictly increasing key indices, in
the strict enveloped canonical form. Encodings are canonical, so one policy
has one hash.

## Transaction locktime

`locktime` is a block height: a transaction is valid only in a block at
height ≥ `locktime` (`0` is always valid). It applies to every transaction,
not only to policy spends.

## Validation

One implementation (`node/src/blockval.rs`) serves block validation, reorgs,
`sendrawtransaction`, gossip admission and block templates. Templates are
built only from transactions valid together at the template height, and
invalid mempool entries are evicted, so a time-locked or conflicting
transaction can never make a mined block invalid.

The hash of a block does not commit to signatures (the txid excludes
`script_sig`). Failures that depend on the revealed witness (policy,
signatures) therefore reject the copy received but never mark the block
invalid. Timelock failures are checked after the policy matches the
committed output, so they are failures over committed data.

## Witness sizes

A policy witness carries the whole policy (every key) plus `m` signatures, so
it grows with both `n` and `m`. Measured (`node/tests/policy_spend_transport.rs`):

| Policy | Witness (`script_sig`) |
| --- | --- |
| 1-of-1 | 8,361 B |
| 1-of-2 | 12,112 B |
| 2-of-3 | 20,455 B |
| 3-of-5 | 32,547 B |
| 7-of-7 | 58,402 B |

The transaction decoder accepts a `script_sig` up to
`MAX_SCRIPT_SIG_LEN` = `policy::MAX_POLICY_WITNESS_LEN` (114,768 B), the
largest witness the policy parser can accept. Before this limit was tied to
the parser it was 10,000 B, so every policy with more than one key was valid
by consensus but could not be relayed, mined or stored. That test round-trips
each shape through the transaction and block wire formats, storage, the
mempool and block validation.

## Using it (`gnb-cli`)

```sh
# Each participant: export the public key.
gnb-cli pubkey alice.json > alice.pub

# Anyone: 2-of-3 address, each deposit locked for 144 blocks (~72 min).
gnb-cli policyaddress 2 alice.pub bob.pub carol.pub --older 144
#   address: gnb1m…   policy: 0102…   ← keep the policy hex

# Fund it like any address.
gnb-cli send wallet.json gnb1m… 10

# List its UTXOs.
gnb-cli getutxos gnb1m…

# Anyone: unsigned spend (change returns to the policy).
gnb-cli policyspend policy.hex gnb1q… 1.5 --utxo TXID:VOUT:SATS --out spend.json

# Each signer, on their own machine (the spend file travels, keys do not).
gnb-cli policysign spend.json alice.json
gnb-cli policysign spend.json carol.json

# Anyone: combine and broadcast.
gnb-cli policysend spend.json
```

`policysign` prints the outputs before asking for the password; check them.
