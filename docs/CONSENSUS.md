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

## Mining

The built-in miner (`gnb --mine --miner-address gnb1q…`) uses one 64 MiB
scratchpad per thread (`--mine-threads`, default all CPUs), mines on the
bodied tips, rebuilds its template every 64 nonces per thread, and aborts a
round as soon as a new tip arrives. External miners use `getblocktemplate`
(which returns the preimage fields, `bits`, `target` and `min_time`) and
`submitblock`.
