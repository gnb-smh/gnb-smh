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
The easiest allowed target is `POW_LIMIT_BITS = 0x2100ffff` below the
hardening activation and the genesis target `0x1f0e9036` at and after it
(see "Block rules at the hardening activation", POW-3).

## Difficulty

ASERT (aserti3-2d construction) anchored at the genesis block
(`genesis_time = 1791429092`, `genesis_target = target(0x1f0e9036)`, spacing
30 s, half-life 7200 s, `pow_limit = target(pow_limit_bits_at(height))`:
`target(0x2100ffff)` below the hardening activation, `genesis_target` at and
after it). The normative
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
target   = floor(genesis_target * factor * 2^(shifts - 16)), clamped to [1, pow_limit_at(height)]
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
5. at/after the hardening activation: the context-free block rules (wire
   size, tagged Merkle root, no 64-byte transaction, coinbase commitment),
   before the block is stored;
6. GnB-SMH proof (64 MiB, cached by block id);
7. transactions (signatures, double spends, coinbase maturity at the block's
   consensus height, consensus minimum fee, and at/after the activation
   BIP30 and no same-block coinbase spend), coinbase value.

Structural checks (size, merkle root, coinbase shape, duplicates, dust, and
at/after the activation the 64-byte rule and the coinbase commitment) run
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
should reuse the same height and module. The block and transaction rules of
the same activation ("Block rules at the hardening activation" below) compare
the header height `B.height` instead, as the activation module prescribes for
rules checked before a block reaches GhostDAG.

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
`submitblock`. `getblocktemplate` also returns the rules of the template's
height: `hardening_active`, `merkle_rule` (`sha256d-duplicate-last` or
`gnb-tagged-v1`), `size_rule` (`bincode` or `wire`),
`coinbase_script_sig_prefix` (the 80-byte coinbase commitment for exactly the
listed transactions in that order, empty before the activation),
`max_coinbase_extra_bytes`, `max_coinbase_script_pubkey_bytes`, and
`coinbase_merkle_branch` (the siblings from the coinbase leaf to the header
root under `merkle_rule`).

The listed transactions may fill the block up to `max_block_size` minus a
framing bound minus `coinbase_reserve` (1,000 bytes), so the WHOLE coinbase,
measured with `size_rule`, must fit in `coinbase_reserve`.
`max_coinbase_extra_bytes` (the miner bytes allowed after the prefix) already
includes that bound: it is the largest number of extra bytes for which a
coinbase with one input and one output whose `script_pubkey` is at most
`max_coinbase_script_pubkey_bytes` (64) bytes, with every other field at its
widest encoding, fits in `coinbase_reserve`, capped by the 10,000-byte
`script_sig` limit (`template::external_coinbase_max_extra`). That is 794
bytes at/after the activation (wire measure, 80-byte prefix) and 869 bytes
before it (bincode measure, no prefix). A coinbase within both fields never
pushes a block built from the template over `max_block_size`.

## Block rules at the hardening activation

The 2026-10-14 audit found block-validity gaps that need a consensus change:
duplicate coinbase txids could overwrite a coin and make rollbacks diverge
(VAL-2), a block could spend its own coinbase (VAL-3), the Merkle tree had no
domain separation and no 64-byte rule (VAL-10), nothing committed to witness
bytes (CRY-1), the block-size limit used a different encoding than fees
(VAL-12), and the pow limit allowed blocks worth one evaluation (POW-3). The
rules below take effect at the same hardening activation height as the
GhostDAG rules (mainnet 110,000; testnet and regtest 0). The code is
`crates/gnb-crypto/src/core/block_rules.rs` and `validate_block_in_view` in
`node/src/accept.rs`. The executable reference is `reference/gnb_merkle.py`
(pow limit: `reference/gnb_difficulty.py`). The golden vectors in
`reference/merkle_vectors.json` and `reference/difficulty_vectors.json`
(section `hardening_pow_limit`) are checked by
`crates/gnb-crypto/tests/merkle_vectors.rs`,
`crates/gnb-crypto/tests/difficulty_vectors.rs` and
`reference/check_vectors.py`.

### Which height

These are block and transaction rules. They compare the block's HEADER
height `B.height`, which `accept_block` requires to equal
`max(parent DAG heights) + 1` (see "Difficulty input"), not
`GhostdagData::height`. A rule applies to B iff

```text
B.height >= 1  and  B.height >= activation_height
```

The genesis block (height 0) is a constant checked by its hash and proof, and
it is never subject to these rules. Mempool admission, block templates and
`getblocktemplate` use the height of the block being built (the selected tip's
DAG height + 1, the template's header height). Below the activation every rule
in this section is absent, and the old behaviour is reproduced bit for bit.
`node/tests/fix_block_rules.rs` runs each rule in both regimes.

### Hashes

```text
sha256d(m)          = SHA-256(SHA-256(m))
tagged_hash(tag, m) = SHA-256(SHA-256(tag) || SHA-256(tag) || m)      // BIP-340 construction
```

Tags are ASCII strings without a terminator:

| tag | SHA-256(tag) |
| --- | --- |
| `GnB/merkle/leaf` | `f5374e50a66ea5c3d4dd804b6b56ea72f76cc838936f6cf8fdf41de204cfbb39` |
| `GnB/merkle/node` | `d3a90495918b57c20ec960f8474e5273b173a4f60bb5f914eec9dcbe3b4df3ef` |
| `GnB/coinbase/parents` | `d8bddbf4dc09ba30778915646735c84bea68357e54cbd7a2755981cf08a9ebdd` |

`txid` is unchanged: `sha256d(to_wire_bytes(include_script_sig =
is_coinbase))`. It covers the `script_sig` only for a coinbase. Every
transaction also has a witness id, which covers every `script_sig`:

```text
wtxid(tx) = sha256d(to_wire_bytes(include_script_sig = true))
```

`to_wire_bytes` is the encoding documented on `Transaction::to_wire_bytes`
(version u32le, varint input count, inputs, varint output count, outputs,
locktime u32le).

### Header Merkle root (VAL-10)

From the activation, `header.merkle_root` is the tagged tree over the
transaction ids in block order. With shielded transactions present it is
combined as before (`gnb:block:body:v1`).

```text
root([])        = 32 zero bytes
level_0         = [ tagged_hash("GnB/merkle/leaf", txid_i) for each transaction i ]
level_{k+1}     = pair level_k left to right:
                    (l, r)      -> tagged_hash("GnB/merkle/node", l || r)
                    a last node without a partner is carried up UNCHANGED
root            = the single node left
```

A single transaction's root is its leaf hash (not its txid). Leaves and inner
nodes cannot be confused, and no node is ever paired with itself. So
`[.., x]` and `[.., x, x]` (CVE-2012-2459) have different roots, and a block
whose transaction list was mutated by duplicating a tail no longer matches its
header. Example: `root([0^32, 0^32]) =
1a90316515bd8a4deade0bb85be8daa5bcd23ccfa1274793622730e72d847326` (the
legacy root of the same list is `e2f61c3f…974e8cf9`).

Before the activation the root is Bitcoin's: `sha256d(l || r)` over the txids,
with the last node of an odd level paired with itself
(`Transaction::merkle_root`, unchanged). There the duplicate-transaction rule
is what rejects a mutated list.

### 64-byte transactions (VAL-10)

From the activation, a block containing a transaction whose txid preimage
(`to_wire_bytes(is_coinbase)`) is exactly 64 bytes is invalid. For a
non-coinbase transaction that is one input and one output with a 5-byte
`script_pubkey`. Mempool admission refuses such a transaction when the next
block is at or above the activation, and templates evict it. Wallet payments
use 20-byte scripts and can never have this size.

### Coinbase commitment (VAL-2 BIP34, CRY-1)

From the activation, the coinbase `script_sig` must start with exactly these
80 bytes, followed by 0 to 9,920 arbitrary miner bytes (the existing
10,000-byte `script_sig` cap):

```text
offset size field
 0      8   "GNB-CB01"                               (47 4e 42 2d 43 42 30 31)
 8      8   B.height, u64 little-endian              (the header height)
16     32   parents_commitment = tagged_hash("GnB/coinbase/parents",
                u32le(n_parents) || parent_0 || ... || parent_{n-1})   (header order)
48     32   witness_root = tagged Merkle root (as above) over
                [ 32 zero bytes, wtxid(tx_1), ..., wtxid(tx_n) ]       (block order;
                position 0 is the coinbase, which cannot commit to itself)
```

Each field is fixed-width, so there is exactly one valid encoding. Any other
tag, a height that differs from `B.height` (`bad-cb-height`), another parent
list or order, another witness root, or a shorter `script_sig` is invalid.
The coinbase still has exactly one output. The commitment sits inside the
coinbase `script_sig`, which the coinbase txid covers, so the block id covers
it: block id → `pow_preimage` → `merkle_root` → coinbase txid → `script_sig`.

**Witness commitment (CRY-1).** Non-coinbase txids exclude `script_sig`, so
before the activation a relay could pad or replace witnesses without changing
the block id. That changed the block's size and fee verdicts, and with the
persisted invalid-block marks it could get an honest block id disqualified.
From the activation every witness byte is committed. `accept_block` checks the
commitment after the height check and before the proof of work, before the
block is stored, and before any signature work. A copy whose witnesses were
altered in transit is therefore refused without being stored or marked
invalid, and the honest copy of the same id is still accepted. Making the
witness encoding itself canonical is a separate rule (package P2).

**Uniqueness of coinbase txids (VAL-2).** The header height alone does NOT
make coinbases unique on GnB. The header height is `max(parent DAG heights) +
1`, and the DAG height follows the selected parent, so a block that merges a
long side branch can have a header height above its own DAG height. Its
selected-chain descendants then repeat lower and equal header heights (DAG-8,
`GhostdagData::height`). The commitment therefore also covers the parent list.
Within one selected chain every two applied blocks are ancestor and
descendant, and a block's parent set can never equal an ancestor's: the
ancestor would have to be its own ancestor. So every coinbase applied from
the activation on has a distinct `script_sig`, and therefore a distinct
txid. A coinbase applied before the activation could equal a later one only
if it committed to the hash of its own block or of one of that block's
descendants, which is a hash cycle. BIP30 below is the rule that guarantees
safety in any case.

### No overwrite of an unspent coin (VAL-2 BIP30)

From the activation, a block is invalid if any output `(txid, i)` of any of
its transactions, the coinbase included, is an UNSPENT coin in the state of
its selected parent. This is checked against that state before any of the
block's transactions is applied, as in Bitcoin Core's `bad-txns-BIP30`. The
rule is part of `validate_block_in_view`, the one function behind extension,
reorg and re-validation.

**Undo (all heights).** A block applied before the activation can still
overwrite a coin. Its undo record now stores the replaced rows (the coin, its
coinbase-height row and its tx-index row), and rollback deletes the block's
own rows and then restores them. A node that applied and disconnected such a
block therefore ends with the same UTXO set as a node that never applied it.
This changes no validity verdict, so it applies at every height. Stored
encoding: the legacy record (bincode, standard config, six fields), byte
identical when nothing was replaced, followed by `"UDX1"` and
`bincode(UndoOverwrites)` only when something was. Records already on disk
decode unchanged.

### No spend of the same block's coinbase (VAL-3)

From the activation, the outputs of a block's coinbase are not spendable
within that block. They are not in the in-block prevout map, and an input
that names the coinbase txid is a coinbase-maturity violation. Before the
activation the old behaviour stays. The extension and reorg paths already
share `validate_block_in_view`, so they agree in both regimes. A block from
the activation that spends its own coinbase also cannot carry a valid coinbase
commitment: the commitment covers the spend's wtxid, which covers the coinbase
txid, which covers the commitment. Mempool admission and templates never
produce such a spend, because a coinbase can be referenced only after its
block is connected, and it is then immature.

### Block size (VAL-12)

From the activation, `MAX_BLOCK_SIZE = 1,000,000` bytes is compared with the
canonical wire encoding `Block::to_wire_bytes` (`Block::wire_size`). That is
the encoding transaction fee rates and the minimum fee use, so witness bytes
count as they do for fees. Before the activation it is compared with the
bincode encoding `Block::size_bytes`, as before. Templates budget with the
measure of their own height.

### Pow limit (POW-3)

From the activation, the pow limit that clamps the expected ASERT target, and
that `validate_pow` enforces before evaluating a proof, is the genesis
target:

```text
pow_limit_bits_at(h) = 0x1f0e9036 (GENESIS_BITS)   if h >= 1 and h >= activation
                       0x2100ffff (POW_LIMIT_BITS)  otherwise
```

Choice: Bitcoin's convention, the pow limit equals the genesis difficulty.
`POW_LIMIT_BITS` is the largest decodable target. One GnB-SMH evaluation
meets it with probability 65535/65536 (`work() = 1`), so a fork from any
parent that is far enough behind the ASERT schedule produces unlimited
near-free blocks (POW-3). The genesis target costs about 4,500 evaluations
(`work = 4500`). No code relies on a difficulty easier than genesis. The
genesis bits were calibrated to the launch hashrate, about 150 evaluations/s;
the miner, the templates and the validator all derive bits from the same
`expected_bits`; and the only ways to reach an easier target are a network
hashrate below the launch calibration or a chain behind schedule, which is
exactly the attack. Consequences: from the activation, block times stretch
in proportion if the network hashrate falls below about 150 evaluations/s.
A testnet with one 4-thread miner (about 8 evaluations/s) produces a block
roughly every 9 minutes. At the activation height itself the target steps
back to at most the genesis target if the chain was running easier.
`expected_bits_at(parent_time, height, activation)` is the real ASERT rule
for any activation height. The dev-only `test-pow-limit` feature pins every
target to `POW_LIMIT_BITS` and is rejected by the node binary.
