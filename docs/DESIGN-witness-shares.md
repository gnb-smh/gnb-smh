# Witness shares (draft, not consensus)

Code: `crates/gnb-crypto/src/core/witness_share.rs` (6 unit tests). Nothing in
block validation uses it yet; activation would be a hard fork.

## What it rewards

Proven custody of recent block data, witnesses included. A *witness share*
is a GnB-SMH proof 16× easier than a block that attests a block `B` from the
last 16 heights. Each nonce selects 8 pseudo-random 64-byte chunks of `B`'s
transaction stream (every transaction's wire bytes, signatures included), and
those bytes are part of the PoW input. Without `B`'s full data you cannot try
a single nonce, so blind (SPV) mining earns nothing.

```
stream(B) = wire(tx_0) ‖ wire(tx_1) ‖ …                      64-byte chunks
idx_k     = SHA3(DS_IDX ‖ attested ‖ SHA3(payout) ‖ nonce ‖ k) mod n_chunks
preimage  = enc(DS_POW) ‖ attested ‖ witness_root(B) ‖ SHA3(payout) ‖ bits ‖ chunk[idx_0..7]
valid    <=> GnB-SMH(preimage, nonce) < 16 × target(bits of B)
```

The payout script is inside the preimage, so a share cannot be stolen by
re-pointing its payout.

## Money

| Parameter | Value |
| --- | --- |
| Pool for shares | 20% of the block subsidy |
| Slots per block | 16 (`MAX_SHARES_PER_BLOCK`) |
| Attester per share | 90% of a slot ≈ 0.01204 GNB at the initial subsidy |
| Miner inclusion bonus | 10% of a slot per included share |
| Empty slots | not issued (the cap stays an upper bound) |

The miner gets 80% of the subsidy + fees + 10% of every slot it fills, so
including someone else's share always pays more than dropping it, and
dropping it never moves the attester's money to the miner.

## Block rules (when activated)

- at most 16 shares; no duplicate `share_id`;
- each attests a block at height `h-16 … h-1` with the same `bits`;
- each meets the share target; the coinbase pays every payout its amount.

## Cost and prerequisite

Each share is one GnB-SMH verification. With v1 (64 MiB, ~0.5 s) 16 shares
add ~8 s per block, which is too much: activation needs the faster
verification of SMH v1.5 (4 MiB, ~30 ms → ~0.5 s per full block).

## Open

- Share gossip and mempool (shares travel separately until included).
- Whether share work counts in fork choice (not in this draft: shares pay,
  they do not vote).
- Wiring into `validate_coinbase_value` and the template.
