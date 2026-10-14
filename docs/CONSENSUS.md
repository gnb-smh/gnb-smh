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

ASERT (aserti3-2d construction) anchored at the genesis block
(`genesis_time = 1791429092`, `genesis_target = target(0x1f0e9036)`, spacing
30 s, half-life 7200 s, `pow_limit = target(0x2100ffff)`). The normative
executable definition is `reference/gnb_difficulty.py`; its vectors
(`reference/difficulty_vectors.json`) are checked by `reference/check_vectors.py`,
`crates/gnb-smh/tests/difficulty_vectors.rs` and
`crates/gnb-crypto/tests/difficulty_vectors.rs`.

### Difficulty input

For a block `B` with parent set `P` (each parent's `height` and `timestamp` as
stored in the DAG):

```text
parent_time = max(p.timestamp for p in P)       // the LATEST parent timestamp
height      = max(p.height for p in P) + 1      // must equal B.height
bits(B)     = expected_bits(parent_time, height)
```

Both inputs are taken over ALL parents. Neither is the GhostDAG selected
parent's: the selected parent is the parent with the highest blue work, which
need not be the parent with the latest timestamp or the greatest height. The
rule is order-independent and deterministic, but it differs from the DAG's
own notion of height: GhostDAG stores `height = selected_parent.height + 1`
for every block, and the difficulty height above is computed from those
stored parent heights. So block validity (the `height` and `bits` checks)
depends on the parents' GhostDAG-derived heights, and a block that merges a
deep side branch is scheduled from its highest parent.

### ASERT step

```text
ahead    = parent_time - genesis_time - 30 * (height - 1)
exponent = floor(ahead * 65536 / 7200)        // 16.16 fixed point, rounds toward -infinity
shifts   = floor(exponent / 65536);   frac = exponent mod 65536
factor   = 65536 + ((195766423245049*frac + 971821376*frac^2 + 5127*frac^3 + 2^47) >> 48)
target   = floor(genesis_target * factor * 2^(shifts - 16)), clamped to [1, pow_limit]
bits     = compact(target)                     // keeps the top 3 bytes: rounds down
```

The product `genesis_target * factor` is exact and the net shift is applied
once, as in aserti3-2d. The exponent rounds toward negative infinity, which
differs from BCHN's aserti3-2d (C++ `/` truncates toward zero) by one unit of
2^-16 half-life when `ahead` is negative and `ahead * 65536` is not a
multiple of 7200. The intermediates are i128 and the timestamp an i64; a
parent timestamp above i64::MAX makes `expected_bits` fail, so no block can
carry it.

`expected_bits` is a pure function of the block's parents, so every node
computes the same value regardless of arrival order. It is enforced for every
block, before the proof of work is evaluated.

### Chain work

Each block contributes

```text
work(target) = max(floor((2^128 - 1) / (floor(target / 2^128) + 1)), 1),   work(0) = 0
```

to blue work (`gnb_smh::difficulty::work`, u128). This approximates
2^256 / target: it never exceeds floor(2^256 / target) or Bitcoin Core's
floor(2^256 / (target + 1)), is monotone in the target, saturates at
2^128 - 1 for targets below 2^128, and is within one part in 2^64 of the
exact value for every target at or above 2^192. Implementations must use this
formula, not floor(2^256 / target), or they compute different blue work.

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

k = 10. Blocks below the hardening activation height use the interval-index
("Fast") coloring, which is applied from genesis but does not count the whole
selected chain in a candidate's anticone. From the activation height (mainnet
110,000; testnet and regtest 0) the exact GHOSTDAG coloring, Kaspa blue work
and the mergeset limits below apply.

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

The applied chain (the UTXO set, see "Ledger semantics" below) is the
selected-parent chain of the best block, in that order, that is valid in its
own selected-chain context. Blocks that fail connect-time validation, and
every block whose selected-parent chain passes through one, are disqualified
and never selected.

There is no reorg-depth limit and no finality checkpoint (audit DAG-6). The
former 1,000-block `MAX_REORG_DEPTH` and the `finalized_height` gate compared
a fork with the node's own history, so nodes that received the same blocks in
different orders could end on different chains. As in Bitcoin Core (no depth
limit, no checkpoints), a node ends on the best valid chain of the blocks it
holds, whatever their arrival order and however deep the fork. What bounds
merging objectively is the merge depth below, a function of each block's
past. Reorgs deeper than 1,000 selected-chain blocks are logged and counted
(`gnb_deep_reorgs_total`), never refused. Undo records are kept for every
connected block and a pruned body leaves a rollback record, so a reorg of any
depth also works on a pruned node. A pruned node that reorganized away from
blocks whose bodies it had pruned and needs them again (the old chain became
the heaviest once more) re-fetches exactly those bodies from its peers before
it connects them; nothing is written in between.

An operator can override the choice, node-locally and persistently, with the
RPCs `invalidateblock <hash>` (disqualify the block and every block whose
selected chain passes through it, and move to the best remaining chain) and
`reconsiderblock <hash>` (remove those marks for the block, its
selected-chain ancestors and descendants, and re-evaluate); see
`docs/RUNNING.md`. These are not consensus rules.

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
  (3 hours at 30 s). Every red in B's
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

What remained proportional to the DAG is the reachability reindex that one
genesis sibling or one deep side block triggers on insertion (about 100 ms at
12,000 blocks, dev profile) and, before activation, the coloring walk for a
candidate that forks deep. Neither block is inserted any more unless a chain
carrying enough work backs it: the node-local anti-DoS work rule below runs
before the proof of work, storage or insertion of every block whose parents
are known. GhostDAG's results and the reachability index are unchanged by
it. Measured in `node/tests/fix_ghostdag_dag7_perf.rs` (80 such blocks,
dev profile): 747 ms of insertions at 12,000 blocks become 0.5 ms of
refusals.

### Anti-DoS work rule (node-local policy, not consensus)

Audit POW-3. Blocks on deep forks can be nearly free (absolute-schedule ASERT).
A node therefore stores and processes a block B whose parents are all in its
DAG only if, with `T` = the blue work of the selected-chain block 360
(`ANTI_DOS_WINDOW_BLOCKS` = `MERGE_DEPTH`) below its selected tip (0 for a
shorter chain) and `lb(B)` = the largest parent blue work + `work(B)`, a lower
bound of B's blue work:

1. `lb(B) ≥ T`; or
2. `lb(B)` + the work of an orphan chain announced on top of B reaches `T`
   (the orphans are buffered or were evicted from the bounded orphan pool;
   each passed the orphan bits floor and its proof of work); or
3. a buffered orphan whose own lower bound reaches `T` needs B as a parent;
   such blocks more than 1,000 blocks below the tip are rationed (4, then one
   per 30 s).

Otherwise B is ignored without penalty. A chain that carries the work is
always accepted (this is Bitcoin's anti-DoS work threshold, with the orphan
pool as the header buffer), so for honest data the final chain is the same
with or without the rule.

## Mining

The built-in miner (`gnb --mine --miner-address gnb1q…`) uses one 64 MiB
scratchpad per thread (`--mine-threads`, default all CPUs), mines on the
bodied tips, rebuilds its template every 64 nonces per thread, and aborts a
round as soon as a new tip arrives. External miners use `getblocktemplate`
(which returns the preimage fields, `bits`, `target` and `min_time`) and
`submitblock`.
