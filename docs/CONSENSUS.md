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

k = 10. The exact interval-index ("Fast") coloring applies from genesis.

## Mining

The built-in miner (`gnb --mine --miner-address gnb1q…`) uses one 64 MiB
scratchpad per thread (`--mine-threads`, default all CPUs), mines on the
bodied tips, rebuilds its template every 64 nonces per thread, and aborts a
round as soon as a new tip arrives. External miners use `getblocktemplate`
(which returns the preimage fields, `bits`, `target` and `min_time`) and
`submitblock`.
