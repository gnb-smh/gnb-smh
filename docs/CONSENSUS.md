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

No ingress path (P2P, `submitblock`, the built-in miner) evaluates the proof of
work before the contextual checks. `accept_block` runs the cheap checks first
and the proof of work last:

1. not already known; not recorded invalid, and no parent recorded invalid;
   parents present in the DAG;
2. height = max parent height + 1;
3. `bits == expected_bits(parents, height)`;
4. timestamp bounds;
5. GnB-SMH proof (64 MiB, cached by block id);
6. transactions and coinbase value, against the UTXO state of the block's
   **selected parent** (below).

Structural checks (size, merkle root, coinbase shape, duplicates, dust) run
before `accept_block` on every ingress path, without the proof of work.

### Transaction rules

One implementation (`node/src/blockval.rs`) is used on every path: block
acceptance, reorgs, and in-memory branch validation. In block order:

- each input exists in the state, is not spent twice in the transaction or the
  block, its pubkey hashes to the output's `script_pubkey`, and its hybrid
  ML-DSA-65 ‖ Falcon-1024 signature verifies;
- inputs ≥ outputs (checked arithmetic) and the fee meets the consensus
  minimum;
- `locktime` is a block height: the transaction is valid only in a block at
  height ≥ `locktime`;
- outputs are a 20-byte key hash or a 33-byte spend policy
  ([multisig and timelocks](MULTISIG.md)); a policy input must reveal the
  committed policy, satisfy its timelocks and carry `m` valid signatures;
- a transaction may spend outputs of earlier transactions in the same block,
  never its own or a later one's;
- no transaction may create an outpoint that is still unspent (BIP30), so a
  copy of another block's coinbase cannot overwrite its output;
- no output below the dust threshold (546 base units), checked per
  transaction on every path (mempool, templates, blocks);
- no input may reference a coinbase with fewer than 100 confirmations,
  including the block's own coinbase;
- the coinbase pays at most subsidy + fees.

### Canonical encodings

Every consensus byte string has exactly one accepted form:

- varints (counts and lengths) are canonical CompactSize; a value encoded
  in more bytes than needed is refused;
- a single-key witness is exactly `len ‖ signature ‖ len ‖ pubkey`, no
  trailing bytes; its Falcon-1024 half must use the compact encoding
  (`crypto::verify_canonical`), never PQClean's zero-padded alternate;
  enveloped and legacy raw (carried-over Bloch) keys both remain valid;
- policy witnesses are strictly parsed and canonical (see MULTISIG.md);
- ML-DSA-65 signatures must satisfy the FIPS 204 bound |z| < γ1 − β on every
  coefficient, checked by GnB before the library (the linked PQClean-based
  verifier accepts 41 Wycheproof vectors that violate it; see
  `crates/gnb-crypto/tests/wycheproof_mldsa65.rs`);
- the sighash (version 2) is SHA3-256 over the domain, the version, the
  chain id and the stripped transaction in the hand-written wire format, and
  the block size limit (1,000,000 bytes) counts the wire encoding. No
  consensus value depends on serde or bincode.

### Witness commitment

From height 5,000 (`WITNESS_COMMITMENT_HEIGHT`) the coinbase `script_sig`
must end with `|wc:` followed by the Merkle root of the block's wtxids
(SHA-256d of each transaction's wire encoding including `script_sig`; the
coinbase counts as 32 zero bytes). The txid still excludes witnesses (no
third-party malleability), but the block hash now covers them: a copy of a
block with any witness altered fails the structure check (hashing only,
before any signature check), and a committed witness that fails verification
marks the block invalid. `getblocktemplate` returns the bytes as
`witness_commitment`.

### Mergeset size

A block may merge at most 64 blocks besides its selected chain
(`MERGESET_SIZE_LIMIT`; with k = 10 an honest mergeset stays near k).

### Which state a block is validated against

- **Selected parent = current tip:** the committed UTXO set.
- **Selected parent on another branch:** the branch state is rebuilt in
  memory (roll back the tip to the common ancestor, re-apply the branch, every
  re-applied block re-validated) and discarded after the check. Nothing is
  written. Branches forking more than `CHECKPOINT_DEPTH` (1,000) blocks below
  the tip are rejected.
- **Reorg:** every block of the new chain is re-validated against the
  incrementally reorged state before the single atomic commit.

A block is stored, indexed and inserted into the DAG only after it passes.

### Atomic state changes

Extending the chain writes every UTXO, coinbase-index, tx-index and undo
mutation and the `tip_hash` in one RocksDB `WriteBatch`. A reorg commits its
whole rollback and re-apply in one batch. A failure leaves storage unchanged.

### Recorded invalid blocks

A block that breaks a rule over data its hash commits to (missing or
double-spent input, value, maturity, coinbase value) is recorded invalid in
`meta` and rejected on sight afterwards, together with every descendant.

The txid, and so the merkle root and the block hash, does not commit to
`script_sig`. A copy of a valid block with a corrupted signature has the same
hash. Failures that depend on `script_sig` (signature, pubkey binding, the
size-based minimum fee) and storage read errors therefore reject the copy
received but are **never** recorded, so the honest copy is still accepted.

### Orphans

A block whose parents are unknown cannot have its difficulty checked exactly.
Before its proof of work is evaluated, before it is buffered and before its
parents are requested, it must pass:

1. timestamp at most 600 s ahead;
2. `target(bits) ≤ target(expected_bits(block.timestamp, height))`. ASERT
   eases monotonically with the parent timestamp, and a parent is never later
   than its child, so this is the easiest difficulty any valid block at that
   height can have;
3. at most 2^8 times easier than the current tip's next block (policy);
4. the proof of work.

The orphan pool holds at most 10,000 blocks and 128 MiB, evicting the lowest
height first.

## Finality and minimum chain work

Block acceptance runs one block at a time (a global lock, like Bitcoin
Core's `cs_main`). Each block's DAG entry is written in the same atomic batch
as the chain-state change it causes, and at startup the node checks that the
committed tip is the DAG's selected tip.

A synced node does not reorg more than `CHECKPOINT_DEPTH` (1,000) blocks,
records `finalized_height = tip − 1,000`, and prunes block bodies older than
10,000 blocks.

All three apply only once the selected tip's `blue_work` reaches
`MIN_CHAIN_WORK` (`crates/gnb-crypto/src/core/mod.rs`). ASERT eases the
difficulty for a chain behind schedule, so a long low-work chain from genesis
is cheap to build. A new node fed such a chain during initial sync would,
without this rule, finalize it and never reach the honest chain. Below the
minimum it keeps every reorg open. The value names no block (unlike a
checkpoint); it is set at each release somewhat below the live chain's work,
and is `0` before a chain exists.

## GhostDAG

k = 10. The exact interval-index ("Fast") coloring applies from genesis.

## Mining

The built-in miner (`gnb --mine --miner-address gnb1q…`) uses one 64 MiB
scratchpad per thread (`--mine-threads`, default all CPUs), mines on the
bodied tips, rebuilds its template every 64 nonces per thread, and aborts a
round as soon as a new tip arrives. External miners use `getblocktemplate`
(which returns the preimage fields, `bits`, `target` and `min_time`) and
`submitblock`.
