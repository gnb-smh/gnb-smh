# PoW + PoWit (Proof of Witnesses) — draft, not consensus

A pure proof-of-work chain (no stake, no appointed validators) in which the
miners who *proved custody of the chain's witness data* over the last week
deterministically form the set that finalizes checkpoints with post-quantum
signatures. Built from three pieces:

| Piece | Status |
| --- | --- |
| Block PoW: GnB-SMH v3 (4 MiB, Argon2d-style fill) | draft, `crates/gnb-smh/src/v3.rs` |
| Witness shares (custody proof + reward) | draft, `crates/gnb-crypto/src/core/witness_share.rs` |
| Witness set + checkpoint attestations + finality rule | this document (not implemented) |

## 1. Block PoW: GnB-SMH v3

```
V[0] = SHAKE256(seed(header, nonce))
pass 0: V[i] = SHAKE256(V[i-1] ‖ V[r] ‖ i ‖ 0),  r = V[i-1] mod i
pass p: V[i] = SHAKE256(V[i-1] ‖ V[r] ‖ i ‖ p),  r = V[i-1] mod N
out  = SHAKE256(DS_FINAL ‖ V[N-1])        N = 2^15 blocks of 128 B (4 MiB), 2 passes
```

| | v1 (live) | v3 draft |
| --- | --- | --- |
| Memory | 64 MiB | 4 MiB |
| Verify (Mac, 1 core) | 527 ms | 90 ms |
| Fill | plain hash chain (linear TMTO) | each block depends on a content-chosen earlier block (cascading TMTO, as Argon2d) |
| Grover | needs 64 MiB QRAM, 1M sequential steps | needs 4 MiB QRAM, 65k steps of 2 permutations; dropping memory to save QRAM cascades |

The hash is replaceable: the same structure with SHA-256 is a one-function
change (see v2). Off-the-shelf Bitcoin ASICs still cannot run it.

## 2. Witness shares (implemented as a draft)

A GnB-SMH proof 16× easier than a block that attests one of the last 16
blocks; every nonce pulls 8 random 64-byte chunks of that block's
transactions (signatures included) into the PoW input. 20% of the subsidy
pays up to 16 shares per block. See `DESIGN-witness-shares.md`.

## 3. The witness set (deterministic, from the DAG)

- Epoch = 720 blocks (~6 h). Window K = 28 epochs (~7 days).
- Weight of a key in epoch e = total work of its shares included in blocks
  of epochs e-K … e-1. Keys are the PQ public keys behind the payout scripts.
- W_e = the 256 heaviest keys (ties by key hash). Every node computes the
  same W_e from the selected chain: no registration, no stake, no vote.

## 4. Checkpoint attestations

- Checkpoint every 60 blocks: the selected-chain block at that blue score.
- Each member of W_e signs `DS ‖ chain_id ‖ e ‖ checkpoint hash ‖ blue score`
  with its hybrid ML-DSA-65 ‖ Falcon-1024 key.
- Attestations are gossiped and included in blocks (inclusion bonus, like shares).
- **Final** when blocks carry attestations worth ≥ 2/3 of W_e's weight.
  Nodes never reorg away a final checkpoint.

## 5. Accountability without stake

Share rewards mature only after K epochs (escrow). Two signatures by one key
for different checkpoints at the same height are an equivocation proof:
any block may include it; the key's escrowed rewards are burned and it is
excluded from W for K epochs.

## 6. Liveness fallback

If no checkpoint finalizes for 1,000 blocks, the chain keeps running as pure
PoW under the depth-finality rule (`CHECKPOINT_DEPTH`) until attestations
resume. Finality can stall; block production cannot.

## What it buys against a 51% attacker

| Attacker | Bitcoin | PoW + PoWit |
| --- | --- | --- |
| Rents >50% hashrate for hours | Can reorg as deep as its lead allows | Reorgs at most the ~60 blocks after the last final checkpoint |
| Rents >50% for days | Same, deeper | Same bound; it is still a minority of the 7-day witness weight |
| Holds >1/3 of the 7-day witness weight | — | Can stall finality (chain keeps running) |
| Holds >2/3 of the 7-day witness weight | — | Controls finality; equivocating burns its escrow |
| Mines without the data (SPV mining) | Allowed | Earns no shares, never enters W |

Honest limits:

- This does not make a sustained majority harmless; nothing permissionless
  can. It moves the bar from *hashrate now* to *proven contribution over
  the last week*, and makes reverting finalized history cost the escrow.
- Long-range forks that rebuild W from far back are stopped by nodes already
  online and, for new nodes, by `MIN_CHAIN_WORK` and the release checkpoint
  (weak subjectivity).
- Unreviewed design; parameters (K, epoch, 2/3, 256) need simulation.
