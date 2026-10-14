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
6. transactions (version rule, witnesses and signatures as specified in
   "Transaction signatures" below, double spends, coinbase maturity at the
   block's consensus height, consensus minimum fee), coinbase value.

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

## Transaction signatures (sighash v2 and v3, hardening activation)

The audit found that the signature digest was whatever a serialization
library emitted and did not commit to the spent amounts or scripts (CRY-3,
WAL-1), that its cost was quadratic in the transaction size (MEM-5), that a
hybrid signature could be split into a valid ML-DSA-only signature (CRY-2),
and that witnesses were malleable (CRY-1). The fixes below change validity, so
the consensus parts take effect at the hardening activation height (mainnet
110,000; testnet and regtest 0). The rules live in
`crates/gnb-crypto/src/core/sighash.rs`; the node applies them through one
function, `mempool::admission::verify_input_scripts`, which block acceptance
and connect (`accept::validate_tx_inputs`), reorg connect, the template
self-check and mempool admission all call.

### Which height

A transaction rule compares the HEADER height `h` of the block that contains
the transaction (`Block::height`, which `accept_block` requires to equal the
largest parent height + 1). Mempool admission uses the height of the next
block on the selected tip (selected tip height + 1); templates use their own
height; wallets use the node's `getdaginfo` `tip_height` + 1.

### Version rule (consensus, non-coinbase transactions)

| | version 0, 1, 2 | version 3 | version ≥ 4 |
| --- | --- | --- | --- |
| `h` < activation | valid: sighash v2, lenient witness | valid: sighash v2, lenient witness (non-standard) | valid: sighash v2, lenient witness (non-standard) |
| `h` ≥ activation | invalid | valid: sighash v3, canonical witness | invalid |

(`core::sighash::check_tx_version`.) Below the activation the version is
ignored: every transaction, version 3 included, is verified exactly as before
the upgrade, with sighash v2 and the historical lenient witness rules. From
the activation only version 3 is valid, and it uses sighash v3, the canonical
witness and component-bound signatures. Coinbase transactions are not signed
and keep no version rule.

Rationale. Nodes that predate the upgrade ignore the version and accept a
non-coinbase version-3 transaction signed over the v2 digest. If upgraded
nodes refused it below the activation, anyone could split the network before
the flag day: submit such a transaction to a non-upgraded node, wait for a
non-upgraded miner to mine it, and upgraded nodes would disqualify that block
and its selected-chain descendants while old nodes extended it. So consensus
below the activation stays exactly the old rule, and version ≥ 3 below the
activation is refused only by relay POLICY
(`core::sighash::check_tx_version_standard`, error strings starting with
`non-standard-version`): upgraded nodes never admit, relay or mine one, and
wallets write version 1 there. Consequences:

- A version-3 transaction signed over the v3 digest is invalid below the
  activation (its signatures are checked against the v2 digest), and one
  signed over the v2 digest is invalid from the activation. No transaction
  is valid under both regimes.
- A pooled transaction always passed the policy at the pool's next height,
  so the pool never holds a version-3 transaction verified under v2.
  Re-injection of a disconnected block's transactions at/after the
  activation re-verifies their input scripts (a version-3 transaction mined
  below it was checked under v2 only).
- The node's verified-signature cache is keyed by the chain id, the regime
  (sighash v2 or v3) and whether the activation is in force at the height,
  the wtxid and every spent output (value and script), so a cached "valid"
  never answers for another digest version, prevout set or height regime.

`node/tests/fix_signatures.rs`
(`never_activated_regime_reproduces_the_old_verdicts`,
`pre_activation_version_3_with_the_v2_digest_is_valid_but_non_standard`)
proves the pre-activation verdicts unchanged.

Consensus error strings for this rule start with `bad-txns-version`.

### Sighash v2 (historical; unchanged)

```text
preimage = "GNB-SIGHASH-v1\0\0" (16 bytes) ‖ 0x01 ‖ chain_id u32 LE ‖ body
body     = bincode-2 "standard" encoding of the transaction in which the
           signed input's script_sig is "GNB_SIGHASH" (11 bytes) and every
           other input's script_sig is empty
sighash  = SHA3-256(preimage)
```

The bincode-2 standard encoding, spelled out so the digest no longer depends
on the library:

```text
Transaction = varint(version) ‖ varint(n_inputs) ‖ TxInput* ‖ varint(n_outputs) ‖ TxOutput* ‖ varint(locktime)
TxInput     = prev_txid (32 raw bytes) ‖ varint(prev_index) ‖ varint(len) ‖ script_sig ‖ varint(sequence)
TxOutput    = varint(value) ‖ varint(len) ‖ script_pubkey
varint(v)   = v                     if v ≤ 250
            = 0xFB ‖ u16 LE(v)      if v ≤ 0xFFFF
            = 0xFC ‖ u32 LE(v)      if v ≤ 0xFFFF_FFFF
            = 0xFD ‖ u64 LE(v)      otherwise
```

An out-of-range input index puts the marker nowhere (historical; no signature
is ever made for one). The cost is O(size) per input, O(size²) per
transaction, bounded by the size limits; v2 is invalid from the activation.
Chain ids: mainnet `0x474E0001`, testnet `0x474E0002`.

### Sighash v3

```text
list_hash(tag, count, items) = SHA3-256( u8 len(tag) ‖ tag ‖ u32 LE count ‖ items )

hash_prevouts  = list_hash("GNB-SIGHASH-v3/prevouts",  n_in,  for each input:  prev_txid (32) ‖ prev_index u32 LE)
hash_sequences = list_hash("GNB-SIGHASH-v3/sequences", n_in,  for each input:  sequence u32 LE)
hash_amounts   = list_hash("GNB-SIGHASH-v3/amounts",   n_in,  for each input:  spent value u64 LE)
hash_scripts   = list_hash("GNB-SIGHASH-v3/scripts",   n_in,  for each input:  u32 LE len ‖ spent script_pubkey)
hash_outputs   = list_hash("GNB-SIGHASH-v3/outputs",   n_out, for each output: value u64 LE ‖ u32 LE len ‖ script_pubkey)

preimage (195 bytes) =
      "GNB-SIGHASH-v3\0\0" (16) ‖ 0x03 (1) ‖ chain_id u32 LE (4)
    ‖ version u32 LE (4) ‖ locktime u32 LE (4)
    ‖ hash_prevouts ‖ hash_sequences ‖ hash_amounts ‖ hash_scripts ‖ hash_outputs  (5 × 32)
    ‖ input_index u32 LE (4) ‖ suite_id u16 LE (2)
sighash_v3 = SHA3-256(preimage)
```

- The "spent" value and script of input i are those of the output it spends
  (from the UTXO set, or from an earlier transaction of the same block).
- `input_index` must be below `n_in`; otherwise there is no digest and the
  input is invalid. A wrong number of spent outputs is likewise an error.
- `suite_id` is the suite in the signature's envelope.
- The five list hashes are computed once per transaction, so signing or
  verifying all inputs hashes O(size) bytes.
- The digest commits to every spent amount and script: a wallet told a wrong
  value or script signs a transaction every node rejects (WAL-1).
- The witness (`script_sig`) is not committed, as before.

### Signature binding

Sighash v2 signatures (legacy binding): every component signs the 32-byte
digest verbatim (`crypto::verify`, unchanged).

Sighash v3 signatures (bound): component `c` of a suite-`s` signature signs

```text
"GNB-TXSIG-v3" (12) ‖ s u16 LE ‖ c (1) ‖ sighash_v3 (32)          (47 bytes)
c = 0x01 for ML-DSA-65, 0x02 for Falcon-1024
```

Suite 0x0001 (hybrid) signature body: `mldsa_sig (3,309) ‖ falcon_sig`; both
components must verify, each over its own message. Suite 0x0002 body: the
3,309-byte ML-DSA-65 signature over its message. A key of one suite never
verifies a signature of another. Because the suite is in every component
message (and in the digest), stripping the Falcon half of a hybrid signature
and relabelling it 0x0002 never verifies (`crypto::verify_bound`).

### Witnesses

`script_sig` = `[u32 LE sig_len][sig][u32 LE pk_len][pk]`, and the public key
must hash to the spent output: `SHA3-256(pk)[0..20] == script_pubkey`.

- Below the activation (sighash v2, every version; unchanged): bytes after
  `pk` are ignored; `sig` may lack the envelope (it is then read as hybrid)
  and its Falcon half may use the 1,280-byte zero-padded form.
- From the activation (version 3, sighash v3): the canonical witness is
  required. `script_sig` is exactly the framing above with no trailing bytes,
  and `sig` has its single canonical encoding
  (`crypto::is_canonical_signature_encoding`): the 4-byte envelope
  `B1 0C ‖ suite u16 LE` is present and names suite 0x0001 or 0x0002; for
  0x0001 the Falcon half is the COMPACT encoding (header byte 0x3A, 40-byte
  nonce, exactly framed coefficients, zero padding bits, nothing after it, at
  most 1,462 bytes); for 0x0002 the body is exactly 3,309 bytes.
- The PUBLIC key is never required to carry an envelope: genesis carry-over
  addresses commit to the raw 3,745-byte hybrid key, which keeps verifying as
  suite 0x0001 (exact length decides; an enveloped key is 4 bytes longer).

The block-level witness commitment is specified separately.

### Suite 0x0002 (ML-DSA-65 only)

Consensus-valid at every height: outputs may already be locked to 0x0002 keys
(anyone could lock funds to such a key before this change), and making the
suite invalid would freeze them. It is non-standard: mempool admission refuses
every input whose key is not hybrid (`crypto::is_hybrid_public_key`), and
wallets never sign with such a key. A holder of a 0x0002 output needs a miner
to include the spend directly.

### Relay policy (all heights)

Mempool admission (gossip, RPC; not reorg re-injection of already-mined
transactions) additionally requires, at every height, the canonical witness of
every input and a hybrid public key. Transactions are admitted only if valid
and standard for the next block's height: below the activation version ≥ 3 is
non-standard, at/after it only version 3 is valid. After every connect,
pooled transactions whose version is invalid or non-standard at the new next
height are evicted (a version-1 transaction admitted for block H-1 is mined in
H-1 or evicted when the next block is H); the template self-check applies the
version rule and policy at the template height.

### Signers

Every signer (the `gnb-crypto` wallet API, `gnb-cli send`, `gnb-wallet send`,
`WalletClient::send`, the browser wallet core) learns the next block's height
from the node (`getdaginfo`: `tip_height` + 1) and produces version 3 with
sighash v3 and bound signatures at/after the activation of its chain, and
version 1 with sighash v2 below it. Without the height they refuse to sign.
Below the activation, wallets still fetch the previous transactions to verify
claimed values; under v3 that is unnecessary.

### Vectors

`reference/gnb_sighash.py` is the normative reference for both digests and the
component messages. `reference/sighash_vectors.json` holds its golden vectors:
many inputs, empty scripts, maximum field values, long scripts, every suite
id, both chain ids, the out-of-range and spent-count errors, and random
transactions, plus `version_rule` vectors: the consensus verdict
(`v2` / `v3` / `invalid`) and the relay-policy verdict (adding
`non-standard`) for versions 0, 1, 2, 3, 4 and 2³²−1 at heights around
activations 0, 100 and `NEVER`. `crates/gnb-crypto/tests/sighash_vectors.rs`
pins them, and CI regenerates the file and diffs it.

## Mining

The built-in miner (`gnb --mine --miner-address gnb1q…`) uses one 64 MiB
scratchpad per thread (`--mine-threads`, default all CPUs), mines on the
bodied tips, rebuilds its template every 64 nonces per thread, and aborts a
round as soon as a new tip arrives. External miners use `getblocktemplate`
(which returns the preimage fields, `bits`, `target` and `min_time`) and
`submitblock`.
