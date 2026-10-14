# GnB consensus

## Block header and proof of work

```text
BlockHeader { version u32, parents [hash32], merkle_root hash32, timestamp u64, bits u32, nonce u64 }

pow_preimage = version u32le | n_parents u32le | parents | merkle_root | timestamp u64le | bits u32le
pow          = GnB-SMH-v1(header = pow_preimage, nonce)          // 32 bytes
valid       <=> be256(pow) < target(bits)
block_hash   = SHA3-256("GNB-BLOCK-ID-v1" | pow_preimage | nonce u64le)
```

GnB-SMH v1 is specified in `crates/gnb-smh/README.md`; the Python file in
`crates/gnb-smh/reference/` is normative and the Rust crate reproduces its
vectors byte for byte. One evaluation costs 64 MiB and about 0.5 s on one core
of a current x86-64 or Apple CPU (`smh-bench verify 19`). Verified block ids are
cached, so a block's proof is evaluated once per node.

`bits` is the Bitcoin compact encoding. Malformed encodings never validate.
The easiest allowed target is `POW_LIMIT_BITS = 0x2100ffff`.

## Difficulty

ASERT (aserti3-2d construction) anchored at the genesis block:

```text
parent_time = max(timestamp of every parent)
exponent    = (parent_time - genesis_time - 30 * (height - 1)) / 7200     // 16.16 fixed point
target      = genesis_target * 2^exponent, clamped to [1, pow_limit]
```

`expected_bits` is a pure function of the block's parents and height, so every
node computes the same value regardless of arrival order. It is enforced for
every block, before the proof of work is evaluated.

Block timestamps must be at least the latest parent timestamp and at most
600 s ahead of the validator's clock, which bounds the easing a miner can
obtain from a future timestamp to about 6%.

## Acceptance order

`accept_block` runs the cheap checks first and the proof of work last:

1. not already known; parents present in the DAG;
2. height = max parent height + 1;
3. `bits == expected_bits(parents, height)`;
4. timestamp bounds;
5. GnB-SMH proof (64 MiB, cached by block id);
6. transactions (signatures, double spends, coinbase maturity at the block's
   consensus height, consensus minimum fee), coinbase value.

Structural checks (size, merkle root, coinbase shape, duplicates, dust) run
before `accept_block` on every ingress path.

## GhostDAG

k = 10. The exact interval-index ("Fast") coloring applies from genesis.

## GhostDAG rules, ledger semantics and the hardening activation

The 2026-10-14 audit found that fork choice ignored merged blue work (DAG-3),
that the live coloring broke the k-cluster rule (DAG-4), and that per-block
cost was unbounded (DAG-7). The fixes change consensus results, so they take
effect at a scheduled height. Blocks below that height keep the old rules
exactly, and their stored `GhostdagData` stays valid.

### Activation

| Network | Hardening activation height |
| --- | --- |
| mainnet | 110,000 (`MAINNET_HARDENING_ACTIVATION_HEIGHT`) |
| testnet | 0 (from genesis) |
| regtest | 0 (from genesis) |

A rule applies to block B iff `height(B) >= activation`. Here `height(B)` is
`GhostdagData::height`, the selected parent's height + 1, which depends only
on B's parents. The schedule is defined in
`crates/gnb-crypto/src/core/activation.rs`, and the node derives it from its
chain id (`--testnet`). A process with no chain id set, such as a unit or
integration test, follows the mainnet schedule. Tests choose a regime
explicitly with `GhostDAG::with_k_and_activation(k, h)`. Later rule changes
should reuse the same height and module.

Below the activation, every rule in this section is replaced by the
pre-activation rule named with it. That pre-activation behaviour is proven
bit-identical to the code that produced the existing chain by
`node/tests/fix_ghostdag_preactivation_identity.rs`.

### Selected parent and fork choice

The selected parent of B is the parent with the largest `(blue_work,
blue_score, hash)`. The selected tip is the tip with the largest
`(blue_work, blue_score, hash)`. These rules are unchanged at every height.

### Blue work

```text
blue_work(genesis) = 0
blue_work(B)       = blue_work(sp) + Σ work(m) for m in mergeset_blues(B) + work(B)   // at/after activation
blue_work(B)       = blue_work(sp) + work(B)                                          // before activation
work(B)            = work_from_bits(B.bits)
```

After activation, `blue_work(B)` is the total work of `blue(B) ∪ {B}`.
Kaspa's blue work is the work of `blue(B)`. GnB has always counted the block's
own work, so GnB's value equals Kaspa's plus `work(B)`. `blue_work(sp)`
already includes the selected parent's own work, so the sum covers the
selected parent, which Kaspa stores as `mergeset_blues[0]`. For a block that
merges no blue, both formulas give the same value, so there is no jump at the
boundary.

### Coloring

`mergeset(B) = past(B) \ past(sp) \ {sp}`. Candidates are processed in a fixed
topological order: ancestors first, and among blocks that are ready at the
same time, lower hash first. With `blue` = blue(sp) ∪ {sp} ∪ the candidates
already colored blue, candidate c is blue iff:

1. |anticone(c) ∩ blue| ≤ k, and
2. every x in anticone(c) ∩ blue has |anticone(x) ∩ blue| + 1 ≤ k.

After activation, both counts range over the full blue anticone, including
selected-chain blocks: exact PHANTOM/GHOSTDAG, so blue(B) is a k-cluster.
`mergeset_blues` excludes the selected parent, so it holds at most k blocks,
and `blue_score(B) = blue_score(sp) + |mergeset_blues(B)| + 1 = |blue(B)|`.
`blues_anticone_sizes` records the exact |anticone(x) ∩ blue(B)| for the
selected parent, the new blues and every older blue whose count grew.
`node/tests/fix_ghostdag_exact_coloring.rs` checks this against a
brute-force implementation of the definition.

Before activation the old walk is used. It never counts selected-chain blocks
below the selected parent, and it restarts older blues' anticone counts at 0,
so it can color blue a block with more than k blues in its anticone.

### Mergeset size and merge depth (after activation)

- `|mergeset(B)| + 1 ≤ MAX_MERGESET_SIZE = 180`. The "+ 1" counts the
  selected parent, as Kaspa does. 180 is Kaspa's production limit. With
  k = 10, at most 11 entries are blue, which leaves room for a post-partition
  merge and bounds one block's coloring to 179 candidates. A larger mergeset
  is rejected with `MergesetTooLarge` before any coloring work.
- Merge depth: let R be the highest selected-chain block of B with
  `blue_score(R) ≤ blue_score(B) - MERGE_DEPTH`, where `MERGE_DEPTH = 360`
  (3 hours at 30 s, under the 1,000-block finality depth). Every red in B's
  mergeset must be R itself, in the future of R, or in the past of a blue in
  B's mergeset that is in the future of R (Kaspa's "kosherizing" rule).
  Otherwise B is rejected with `MergeDepthViolation`. Blues need no check: a
  blue that deep would have more than k blues in its anticone.

A rejected block is not inserted. Since `MAX_PARENTS` (256) exceeds the
mergeset limit, block templates must choose parents with
`GhostDAG::select_parents_for_template(&bodied_tips, MAX_PARENTS)`. It puts the
selected parent first, adds the other tips by decreasing blue work while the
mergeset fits, and drops tips that would break the merge depth. Before
activation it returns the heaviest `MAX_PARENTS` tips.

### Ledger semantics: selected-chain-only

This is the specification at every height, before and after the activation.

- The UTXO set at the selected tip is the result of applying, in order from
  genesis, the blocks of the selected chain (the tip, its selected parent, and
  so on). Each block contributes its transactions and its coinbase.
- Blocks that are merged, blue or red, but are not on the selected chain
  change nothing. Their transactions are not applied, their outputs do not
  exist, and their coinbases pay nothing. A transaction is confirmed only when
  a selected-chain block includes it. A parallel block's transactions stay
  unconfirmed until a selected-chain block includes them.
- A reorg moves the UTXO set by rolling back and applying blocks along the old
  and new selected chains (`node/src/reorg.rs`). Mergesets are never applied.

GhostDAG therefore decides which chain is selected (blue work, after
activation including merged blues) and the blue scores. It never moves value.
After activation, honest parallel blocks add weight to the honest chain in
fork choice, but their miners are still not paid. The mergeset transaction
rules sketched in `docs/LEDGER.md` section 7 are not implemented. Adopting
them would be a further consensus change with its own activation.

### Per-block cost (all heights, output-preserving)

These changes leave every result unchanged and apply at all heights:

- The mergeset comes from the reachability index in O(|mergeset|), not from
  O(|past|) `compute_past`.
- The pre-activation walk stops after k + 1 anticone blues and skips
  selected-chain blocks that merged nothing.
- Reachability reindexing computes subtree sizes once per reindex instead of
  once per visited node.

At the audit's 12,000-block scenario (dev profile), these changes reduced a
deep side block from 10–26 s to 50–84 ms, a genesis sibling that forces a
reindex from 46 s to 0.1 s, and the 1,000-block side-chain merge from 35 s to
29 ms. After activation, that merge is rejected in under 1 ms.

## Mining

The built-in miner (`gnb --mine --miner-address gnb1q…`) uses one 64 MiB
scratchpad per thread (`--mine-threads`, default all CPUs), mines on the
bodied tips, rebuilds its template every 64 nonces per thread, and aborts a
round as soon as a new tip arrives. External miners use `getblocktemplate`
(which returns the preimage fields, `bits`, `target` and `min_time`) and
`submitblock`.
