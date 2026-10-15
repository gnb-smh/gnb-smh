# Data-driven consensus vectors

`reference/tx_vectors.json` and `reference/block_vectors.json` pin transaction
and block validity in both regimes of the hardening activation, the way
Bitcoin Core's `src/test/data/tx_valid.json`, `tx_invalid.json` and
`script_tests.json` pin Bitcoin's rules. Each case is data: bytes, the UTXO
state they are evaluated against, a height, an explicit activation height,
and the expected verdict with the class of the rule that rejects it. A
change to a consensus rule changes a verdict and fails the runners, whatever
code path the change went through.

| What | Where |
| --- | --- |
| Transaction vectors (185 cases) | `reference/tx_vectors.json` |
| Block vectors (96 cases) | `reference/block_vectors.json` |
| Generator (deterministic Rust, seeded keys and signatures) | `crates/gnb-crypto/tests/gen_consensus_vectors.rs` |
| Runner through gnb-crypto (real pow limit, explicit chain ids) | `crates/gnb-crypto/tests/consensus_vectors.rs` |
| Runner through the node (connect path, mempool admission, testnet) | `node/tests/consensus_vectors.rs` |
| Shared loader and error-class mapping | `crates/gnb-crypto/tests/consensus_vectors_common/mod.rs` |
| Independent Python check (no Rust) | `reference/check_consensus_vectors.py` over `reference/gnb_validity.py`, `gnb_merkle.py`, `gnb_sighash.py`, `gnb_difficulty.py` |
| CI | `python-reference` (Python check), `consensus-crates` (gnb-crypto runner; regenerate and `git diff --exit-code`), `workspace-test` (node runner) |

```text
cargo test -p gnb-crypto --test consensus_vectors                     # gnb-crypto runner
cargo test -p gnb --test consensus_vectors                            # node runner
python3 reference/check_consensus_vectors.py                          # Python check
cargo test -p gnb-crypto --test gen_consensus_vectors -- --ignored    # the generator reproduces the files
GNB_WRITE_VECTORS=1 cargo test -p gnb-crypto --test gen_consensus_vectors -- --ignored   # rewrite them
```

## Three independent judges

1. **The generator writes the expected verdicts by hand.** Next to every
   construction (`c.valid(..)`, `c.invalid(.., "min-fee")`) the expected
   verdict, class and mempool verdict are literals. The generator never calls
   a validation function to decide a verdict, and boundary values (dust 546,
   maturity 100, minimum fee `max(10,000, ceil(size x 2,000 / 1,000))`, the
   subsidy schedule, `MAX_SUPPLY_SAT`, the 1,000,000-byte limit, the
   10,000-byte script cap) come from the generator's own constants, not from
   the code under test. Regenerating after a rule change therefore does not
   move a vector; the runners fail instead. The one exception is mining: the
   `pow: full` case finds its nonce with `Block::validate_pow`.
2. **The Rust runners** check every verdict through the functions the node
   runs (see "Evaluation" below), and every recorded derived value (txid,
   wtxid, sighash digests, roots, sizes) against the current code.
3. **The Python check** re-derives every derived value and every
   non-signature verdict from the specification (`docs/CONSENSUS.md`), with
   its own decoder, Merkle trees, commitment, both sighash digests, bincode
   size model, Falcon compact-encoding parser and validity rules
   (`reference/gnb_validity.py`). It cannot verify ML-DSA-65 / Falcon-1024
   signatures, so a case whose class is `bad-signature` must pass every other
   rule in Python, and every other class must be exactly the first rule
   Python sees fail. It also re-derives every mempool verdict.

Deliberately corrupting a vector (an expected class, a digest, a size, a
policy verdict) makes the Python check fail; so does a rule flipped in the
code for the Rust runners (see "Effectiveness").

## Determinism

Keys come from `crypto::generate_keypair_from_seed(SHA3-256("gnb-consensus-vectors/key/<name>"))`.
Every signature is made inside `pqcrypto_internals::with_seeded_rng_scope`
with a seed derived from the case label, so ML-DSA-65's hedged signing and
Falcon-1024's nonce and sampler are deterministic; Falcon is pinned to
PQClean's integer-only `clean` variant, which is bit-exact across platforms.
The JSON is written by a small ordered emitter (no dependence on
`serde_json` features). CI regenerates both files and diffs them.

Keys (`keys` in both files): `A`, `B`, `C` (hybrid suite 0x0001, enveloped
public keys), `A-raw` (key A's raw 3,745-byte public key, as a genesis
carry-over address commits to it) and `A-mldsa-only` (a suite-0x0002 key made
of key A's ML-DSA-65 half, which is what the split-and-relabel attack of
CRY-2 needs).

## Regimes and heights

Every case carries `activation_height` and `height` (decimal strings). The
regime is `pre-activation` iff `height < activation_height` (the block rules
additionally never apply at height 0; no case uses it). Most cases use
activation height 1,000 with heights 999 (pre) and 1,000 (post: the boundary
itself). Further cases use the mainnet schedule (109,999 / 110,000), the
testnet schedule (activation 0, height 1), "never" (`18446744073709551615`)
and heights around the halving at 4,204,800.

`network` is `mainnet` or `testnet` (the chain id signatures commit to). The
node's chain id is process-wide, so the node runner evaluates the testnet
cases in a child process of its own test binary.

## `tx_vectors.json`

```text
{
  "format": "gnb-consensus-tx-vectors/1",
  "description", "generator", "constants", "keys",
  "cases": [ {
    "id":                 "witness/one-trailing-byte/pre",
    "description":        what the case is and why the verdict holds,
    "network":            "mainnet" | "testnet",
    "activation_height":  "1000",
    "height":             "999",                 header height of the evaluation block
    "regime":             "pre-activation" | "post-activation",
    "prevouts": [ {                              the UTXO view, exactly
       "txid", "vout", "amount" (decimal), "script_pubkey",
       "is_coinbase", "coinbase_height" (decimal or null),
       "source": "utxo" | "block-coinbase" } ],
    "tx":                 wire hex (Transaction::to_wire_bytes(true)),
    "expected": { "verdict": "valid" | "invalid", "error_class": null | class },
    "policy":   { "verdict": "accept" | "reject", "error_class": null | class },
    "derived":  null (undecodable) | { "txid", "wtxid", "wire_size", "txid_preimage_size",
                 "digests": [ { "input", "sighash_v2", "sighash_v3_suite", "sighash_v3" | null } ] }
  } ]
}
```

**Evaluation.** The transaction is decoded strictly (the bytes must be the
canonical encoding: no trailing byte, minimal varints; the node's gossip and
RPC decoder `admission::decode_tx_strict`). It is then the only
non-coinbase transaction of a block `[wrapper coinbase, tx]` at `height`. The
wrapper coinbase has version 1, one input (32 zero bytes, index 0xffffffff,
script_sig `constants.wrapper_coinbase_script_sig`, sequence 0xffffffff), one
output and locktime 0; the output pays the `block-coinbase` prevout (whose
txid is then the wrapper coinbase's), or 0 to 20 zero bytes. The rules,
in the node's order:

1. the per-transaction context-free block rules: not coinbase-shaped
   (`Block::validate_coinbase_format`), at/after the activation not 64 bytes
   (`block_rules::check_tx_not_64_bytes`), no dust (`Block::validate_dust`),
   encoding caps and MoneyRange (`limits::check_block_context_free`);
2. connection, `accept::validate_block_in_view_classified_at` (the function
   behind block extension, reorg and re-validation) on a RocksDB store holding
   exactly the `utxo` prevouts: at/after the activation BIP30 and no spend of
   the block's own coinbase; coinbase maturity; double spends; missing
   inputs; input MoneyRange; the version rule; witnesses; public-key hashes;
   signatures (sighash v2 or v3 as the version rule selects); value; the
   consensus minimum fee; the coinbase value.

The block-level rules of the wrapper (Merkle root, commitment, size) are the
block vectors' subject.

`expected` is the consensus verdict and the class of the FIRST rule that
fails. Invalid cases are built to violate one rule where the rules allow it
(otherwise the class is the first in the order above, which the Python check
reproduces).

`policy` is mempool admission (`admission::check_transaction`, relay policy,
signatures on) for a block at `height`, on the same store, in which every
`utxo` prevout's txid is also indexed as a confirmed transaction (a node
applies every coin together with its creating transaction). A
consensus-invalid case is always refused (`error_class` null: the reason is
not pinned); a consensus-valid case is accepted or refused for the named
policy class.

`derived.digests` are the sighash v2 digest of every input under the
network's chain id and the sighash v3 digest (spent outputs from `prevouts`;
suite = the signature envelope's, 0x0001 when there is none; null when an
input's coin is not in `prevouts`). The Python check recomputes them with
`reference/gnb_sighash.py`.

## `block_vectors.json`

```text
{
  "format": "gnb-consensus-block-vectors/1",
  "description", "generator", "constants", "keys",
  "cases": [ {
    "id", "description", "network" ("mainnet"), "activation_height", "height", "regime",
    "scope":    "full" | "connect",
    "pow":      "skip" | "limit" | "full",
    "prevouts": [ ... ]                      the parent state's UTXO view, as above
    "block":    wire hex (Block::to_wire_bytes)
      or "block_parts": [ { "hex", "repeat" } ]   concatenation of each part repeated (1 MB blocks)
    "expected": { "verdict", "error_class" },
    "derived":  null (undecodable) | { "block_hash", "txids", "legacy_merkle_root", "tagged_merkle_root",
                "witness_root", "parents_commitment", "subsidy", "wire_size", "bincode_size" }
  } ]
}
```

**Evaluation** (scope `full`): `Block::from_wire_bytes`;
`Block::validate_structure_without_pow_at` (parent count, size measure of the
regime, header Merkle root of the regime, coinbase format, at/after the
activation the 64-byte rule and the coinbase commitment, duplicate
transactions, dust); `block_rules::check_block_hardened_at`; the pow limit
(`pow: limit`: the bits decode and the target is within the pow limit of the
height, `pow_limit_bits_at`; `pow: full`: also the GnB-SMH proof,
`Block::validate_pow`); `limits::check_block_context_free`; then
`accept::validate_block_in_view_classified_at` against a store holding the
prevouts. Scope `connect` decodes and runs the last step only: it pins VAL-3
(no spend of the block's own coinbase) at/after the activation, which a
complete block cannot reach because its coinbase commitment would have to
commit to itself (the matching `full` case shows the commitment rejecting
it).

Not part of the block vectors: the header-chain context `accept_block`
checks against the DAG (parents known, height = max parent height + 1,
expected ASERT bits, timestamps; `reference/difficulty_vectors.json` pins
ASERT) and the GnB-SMH proof except in the one mined case. The node's test
build pins `validate_pow`'s limit (`test-pow-limit`), so the gnb-crypto
runner, built without it, evaluates `validate_pow` with the real limit for
every pow-limit case.

## Error classes

Consensus classes (`expected.error_class`; the node string the runners map
from in `consensus_vectors_common::classify`):

| Class | Rule | Node error (contains) |
| --- | --- | --- |
| `decode` | the bytes are not a canonical encoding: truncated, trailing bytes, non-minimal varint, a count or length above the decoder caps (100,000 inputs / outputs, 10,000-byte scripts, 256 parents) | decoder error |
| `coinbase-format` | first transaction not a coinbase, or a second coinbase-shaped transaction, or no transactions | `invalid coinbase format` |
| `tx-64-bytes` | at/after the activation, a txid preimage of exactly 64 bytes (VAL-10) | `64-byte transaction` |
| `dust` | a non-coinbase output with 0 < value < 546 | `below dust threshold` |
| `value-out-of-range` | MoneyRange: an output, an output sum, an input sum or the block total above `MAX_SUPPLY_SAT` (VAL-11) | `MAX_SUPPLY_SAT`, `overflows u64` |
| `bip30` | at/after the activation, an output at the outpoint of an unspent coin (VAL-2) | `BIP30` |
| `same-block-coinbase` | at/after the activation, a spend of the block's own coinbase (VAL-3) | `spends the coinbase of its own block` |
| `immature-coinbase` | a coinbase spent before depth 100 | `coinbase maturity` |
| `double-spend` | an outpoint spent twice in a transaction or a block | `double-spend` |
| `missing-input` | the outpoint is not in the view nor created earlier in the block | `UTXO ... not found` |
| `bad-version` | at/after the activation, version != 3 | `bad-txns-version` |
| `witness-malformed` | below the activation, the lenient witness framing does not parse | `malformed script_sig` |
| `witness-non-canonical` | at/after the activation, not exactly `[u32 sig_len][sig][u32 pk_len][pk]` or not the canonical signature encoding | `non-canonical` |
| `pubkey-mismatch` | SHA3-256(public key)[0..20] differs from the coin's script | `pubkey mismatch` |
| `bad-signature` | a signature does not verify under the digest and binding of the regime | `invalid signature` |
| `inputs-below-outputs` | outputs exceed inputs | `inputs ... < outputs ...` |
| `min-fee` | fee below `max(10,000, ceil(wire size x 2,000 / 1,000))` | `below consensus minimum` |
| `block-size` | above 1,000,000 bytes: bincode below the activation, wire encoding from it (VAL-12) | `block too large` |
| `bad-merkle-root` | the header root is not the regime's root (legacy below, tagged from the activation) | `invalid merkle root` |
| `duplicate-tx` | the same txid twice (CVE-2012-2459) | `duplicate transaction in block` |
| `cb-commitment-missing`, `cb-commitment-tag`, `cb-height`, `cb-parents`, `witness-commitment` | the 80-byte coinbase commitment: shorter than 80 bytes, wrong tag, wrong height, wrong parent list, wrong witness root (VAL-2, CRY-1) | `coinbase commitment missing`, `bad coinbase commitment tag`, `bad-cb-height`, `bad coinbase parents commitment`, `bad witness commitment` |
| `coinbase-output-count` | the coinbase does not have exactly one output | `coinbase must have 1 output` |
| `coinbase-value` | the coinbase claims more than subsidy + fees | `miner coinbase output exceeds allowed amount` |
| `pow-limit` | the target is above the pow limit of the height (POW-3) | runner (`pow_limit_bits_at`) |
| `bad-bits` | the compact bits do not decode | runner (`try_bits_to_target`) |

Policy classes (`policy.error_class`, consensus-valid cases only):
`non-standard-witness` (a non-canonical witness below the activation),
`non-standard-version` (version >= 3 below the activation),
`non-standard-suite` (a suite-0x0002 key), `non-standard-zero-value`,
`non-standard-no-outputs`, `missing-input` (an unconfirmed coin: the block's
own coinbase), `already-confirmed` (the txid is already in the transaction
index).

## Coverage

Transactions (185: 97 pre-activation, 88 post-activation; 65 valid):

| Area | Cases | What |
| --- | --- | --- |
| `basic/` | 10 | honest signers of both regimes; 1-3 inputs; the mainnet (109,999 / 110,000), testnet (0) and never schedules |
| `struct/` | 15 | no outputs (valid, non-standard), no inputs, coinbase-shaped transaction, missing input, null outpoint in a 2-input transaction, duplicate inputs, two vouts of one txid, lock time and sequence not enforced |
| `decode/` | 8 | truncated, trailing byte, non-minimal varint, empty, input / output count above the cap, 10,001-byte script_sig and script_pubkey |
| `size/` | 6 | a 10,000-byte script_sig (lenient padding: valid pre, non-canonical post), a 10,000-byte output script, 300 outputs |
| `value/`, `fee/`, `dust/` | 29 | MoneyRange of outputs, output sums, `u64::MAX`, the `MAX_SUPPLY_SAT` boundary, prevout amounts and sums; inputs below outputs; zero fee; fee exactly the minimum and one below (fixed point over the variable Falcon length); witness padding raising the minimum; dust 1 / 545 / 546; zero-value outputs |
| `maturity/` | 12 | depth 100 / 99 / 0 (a parallel block's coinbase) / negative, a second immature input, a carry-over coin at height 1, the block's own coinbase (valid pre, `same-block-coinbase` post) |
| `version/` | 18 | versions 0, 1, 2, 3, 4, 2^32-1 in both regimes; version 3 over the wrong digest in each regime; the mainnet boundary; never-activated |
| `sig/` | 26 | wrong amount and wrong script (v2 does not commit: valid; v3 does: invalid), another input's amount, wrong input index, the v2 out-of-range marker quirk, testnet signature on mainnet, components swapped between inputs, component ids swapped, legacy binding over a v3 digest and bound binding over a v2 digest, a digest with another suite id, tampered ML-DSA and Falcon nonce bytes, another key's signature, a key that does not hash to the coin, a bad second input |
| `net/` | 5 | testnet-signed on testnet (both regimes), mainnet-signed on testnet, the testnet schedule |
| `suite/` | 16 | split-and-relabel of a hybrid signature to 0x0002 (valid pre: the CRY-2 weakness kept below the activation; invalid post), genuine 0x0002 spends (valid, non-standard), cross-suite key/signature pairs, relabelled to reserved 0x0000 / 0xffff and unknown 0x0003, a 3,310-byte 0x0002 body |
| `raw/` | 8 | raw carry-over public keys with enveloped and raw signatures, and the address committing to the exact key encoding |
| `witness/` | 22 | trailing bytes, signature without envelope, Falcon in the 1,280-byte zero-padded form (valid pre, non-canonical post), an extra non-zero Falcon byte, truncated Falcon, empty signature, sig_len beyond the script, empty and 7-byte script_sigs, pk_len one short |
| `tx64/` | 8 | 63 / 64 / 65-byte txid preimages in both regimes; the mainnet boundary |
| `bip30/` | 2 | an output on an unspent coin's outpoint (valid pre, invalid post) |

Blocks (96: 40 pre-activation, 56 post-activation; 33 valid):

| Area | Cases | What |
| --- | --- | --- |
| `basic/`, `order/` | 10 | coinbase only, coinbase and spend, a spend of an earlier transaction in the block, the reverse order, two transactions spending one coin |
| `merkle/`, `dup/` | 10 | the other regime's root, a zero root, a three-transaction block and its CVE-2012-2459 mutation (duplicate-tx pre, bad root post), a duplicated transaction |
| `coinbase/` | 23 | not first, two coinbases, no transactions, two / zero outputs, subsidy + 1, subsidy + fees (exact and + 1), paying zero, above `MAX_SUPPLY_SAT`, the halving at 4,204,800 |
| `commitment/`, `structure/` | 17 | two parents; script_sig of 79 bytes; bad tag; height + 1 and big-endian; parents reordered and dropped; witness root zero, over txids, and with the coinbase's own wtxid; 10,000-byte script_sig (valid) and one byte more (decode); a wrong commitment ignored pre; the mainnet boundary; 256 parents (valid) and 257 (decode) |
| `same-block-coinbase/` | 3 | valid pre; `connect` scope post; `full` scope post (the commitment cannot match) |
| `pow/` | 11 | 0x2100ffff mined and evaluated pre, refused post; the genesis target exactly and one unit above, in both regimes; the mainnet boundary; four malformed bits |
| `size/` | 6 | 1 MB blocks: wire 1,000,001 with bincode below (valid pre, invalid post), wire exactly 1,000,000 (valid post), bincode 1,000,001 with wire below (invalid pre, valid post), bincode exactly 1,000,000 (valid pre) |
| `value/`, `maturity/`, `sig/`, `tx64/`, `bip30/`, `version/`, `witness/` | 16 | the transaction rules inside a block: dust, an immature spend, a bad signature, a 64-byte transaction, BIP30 on a spend's and on the coinbase's output, the version rule, a padded witness under the same block id (valid pre, witness commitment post) |

`crates/gnb-crypto/tests/consensus_vectors.rs::vector_coverage` fails if a
class, a policy class, a network x regime pair, a version x regime pair, a
raw key or a 0x0002 key disappears from the files.

## Adding a case

Add it to the generator, next to its neighbours, with the verdict, class and
mempool verdict you expect as literals; keep it to one violated rule when the
rules allow it. Regenerate with `GNB_WRITE_VECTORS=1`, run the three judges,
and review the JSON diff (an existing case must not change unless the change
is the point). A new rejection string must be classified in
`consensus_vectors_common::classify` (the runners panic on an unknown one)
and, for Python, produced by `reference/gnb_validity.py`.

## Effectiveness

Each rule below was flipped in the code, one at a time (anchored source
edits); both Rust runners were rebuilt and run, then the code was restored
and the tree checked clean. All 16 mutations made at least one runner fail,
naming the cases (2026-10-15 run; the baseline passed in the same build).
The Python check does not read the Rust code, so it is unaffected by these
and is exercised instead by corrupting the files (13 corruptions, each
reported).

| Mutation | Runner | Cases that fail |
| --- | --- | --- |
| dust threshold off by one (546 is dust) | both | `dust/output-546/*`, `value/output-u64-max/*` (its second output is 546), the 1 MB blocks of 546-unit outputs |
| coinbase maturity off by one (depth 99 accepted) | node | `maturity/depth-99/*` (consensus and mempool), `maturity/immature-coinbase-spend-in-block/*` |
| VAL-3 removed (same-block coinbase) | node | `maturity/same-block-coinbase/post`, `same-block-coinbase/post/connect` |
| 64-byte rule measured with script_sig | both | gnb-crypto: the recorded txid preimage size of 175 cases; node: `tx64/64-byte-transaction/post`, `tx64/mainnet-boundary/110000`, `tx64/64-byte-transaction-in-block/post` |
| version 2 accepted from the activation | both | `version/v2-sighash-v2/post` |
| canonical witness accepts trailing bytes | both | `witness/one-trailing-byte/post`, `witness/1000-trailing-bytes/post`, `witness/pk-length-one-short/post`, `size/script-sig-10000-bytes/post`, and the mempool verdicts of the padded pre-activation cases |
| sighash v3 verifier ignores the signature's suite | both | `suite/mldsa-only-0x0002-spend/post` |
| BIP30 removed | node | `bip30/output-overwrites-an-unspent-coin/post`, both block `bip30/*/post` |
| minimum fee off by one | node | `fee/exact-minimum/*` (consensus and mempool) |
| tagged Merkle tree pairs an odd node with itself | both | gnb-crypto: tagged and witness roots of 25 block cases; node: the 5 post-activation blocks with an odd transaction count |
| coinbase may not claim the full subsidy + fees | node | 27 block cases |
| block size measured on bincode from the activation | both | `size/bincode-1000001-wire-below/post` |
| hardened pow limit = the old pow limit | both | `pow/pow-limit-bits-from-the-activation`, `pow/genesis-target-plus-one-from-the-activation`, `pow/mainnet-110000-pow-limit-bits` |
| commitment height also accepted big-endian | both | `commitment/height-big-endian/post` |
| lenient witness framing made exact below the activation | both | `witness/one-trailing-byte/pre`, `witness/1000-trailing-bytes/pre`, `size/script-sig-10000-bytes/pre`, `fee/witness-padding-raises-the-minimum/pre`, `witness/padded-witness-same-block-id/pre` |
| MoneyRange allows `MAX_SUPPLY_SAT + 1` | node | `value/output-above-max-supply/*`, `value/prevout-above-max-supply/*`, `coinbase/above-max-supply/*` (the gnb-crypto runner leaves the input-side MoneyRange to the node runner and does not see this one) |

## Findings while building the vectors

- Mempool admission does not apply BIP30 (an output on the outpoint of an
  unspent coin), which block validation applies from the activation. It is
  unreachable: a coin at `(txid, i)` exists only if a transaction with that
  txid was applied, which spent that transaction's inputs (a non-coinbase
  txid commits to them) and wrote its transaction-index row, and admission
  refuses an already-confirmed txid and spent inputs; a coinbase is never
  admitted. The policy store of the vectors models the transaction index, and
  `bip30/output-overwrites-an-unspent-coin/pre` pins the `already-confirmed`
  refusal.
- Pinned pre-activation behaviour that is easy to forget: sighash v2 does not
  commit to the spent amount or script (WAL-1), so a signer told a wrong
  amount still signs a valid transaction; a hybrid signature split and
  relabelled to suite 0x0002 verifies (CRY-2); lock time and sequence are not
  enforced at any height; a transaction with no outputs is consensus-valid.
