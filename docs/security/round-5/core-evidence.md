# R5 static public descriptor core evidence

Production commit: `326e292`. Base package contract: `35ccd62`. Native target
`/private/tmp/gnb-r5-target-descriptor-core`, codegen units 139, debug 0,
incremental 0, two build jobs, Cargo locked/offline. The root integration
package owns the full separate crypto run, node suite, actual WASM rebuild,
repins, CI and three independent reviews. This package assigns no score.

## Reproduction and fixture corrections

The tests-only sequence is `b2fb43b`, `f925d0d`, `09dc947`. The original
dispatcher has no public descriptor operation. The first run also exposed an
incorrect positive-control address (missing its legacy checksum); that fixture
was replaced with output from the existing encoder. Its log is retained and
does not count as a successful positive-control reproduction.

The next run passed the legacy control and failed both new operations as
`unknown op descriptor`. During the first production draft, the synthetic key
fixture was found to have the enveloped length (3749 bytes), rather than the
raw length (3745). The fixture was corrected and now asserts the pre-existing
`is_hybrid_public_key` predicate before dispatch. Both original production
files were restored from `f925d0d`, the corrected test at `09dc947` was run,
and only then was the production draft reinstated. That original-code run
passed the legacy control and failed the two new-operation assertions at
runtime, exit 101. The new descriptor module was not exported/compiled in that
run. The earlier mistaken fixture is not credited as a valid-key test.

Command (with the environment above):

```
cargo test -p gnb-wallet-wasm --test public_descriptors --locked --offline
```

`baseline-valid-key.log` records the credited 1-pass/2-fail original-code run.
Every original log, including fixture mistakes, is identified by SHA256 in
`core-evidence.json`.

## Implemented behavior and scoped tests

`crates/gnb-crypto/src/wallet/descriptor.rs` is the shared implementation. Its
private typed fields prevent constructing unchecked descriptors/pools. Exact
key bytes, key/branch order and the existing script constructors are preserved.
The eight-symbol checksum follows BIP380; the module cites its primary source
and does not extend the BIP's shorter-length error guarantees to PQ text.

`crates/gnb-crypto/tests/public_descriptors.rs` passed 11 tests:

- `bip380_checksum_matches_primary_fixed_vector` checks the primary BIP vector.
- `both_networks_and_all_kinds_preserve_existing_script_identities` checks the
  existing scripts and both address encodings for pkh, policy and tree.
- `exact_key_bytes_and_branch_order_are_not_normalized` preserves raw/envelope
  identity and current distinct-byte policy semantics; PF-4 remains open.
- Grammar, checksums, integer/key/branch limits, complete descriptor size,
  pool count/byte limits, canonical field order, raw duplicate/unknown JSON
  fields, unique scripts, network mismatch and public-only actions have
  positive and negative cases in the remaining focused tests.

The explicit oracle test target passed 2 tests; Cargo's default example
compilation alone would not establish this:

```
cargo test -p gnb-crypto --test public_descriptors --example descriptor_oracle --locked --offline
cargo build -p gnb-crypto --example descriptor_oracle --locked --offline
```

The host WASM test target passed 4 tests. It calls the actual existing Rust
dispatcher, including public pool export/restoration. A live random session
is preserved across valid descriptor requests and raw JSON attempts containing
both `op:descriptor` and `op:wipe` in each order, including an escaped duplicate
field name. Session actions are refused under the public operation. A legacy
duplicate-field control retains its original last-field-wins behavior.

The routing probe adds one linear JSON scan to `call_bytes`. It ignores values
outside `op` without constructing another Value tree or copying password/phrase
values; operation identification examines every `op` occurrence. Only requests
mentioning the new operation use the duplicate-aware request parser. This is
not a claim that every existing wallet path has no copies of secrets.

The oracle uses the real shared API, returning `{ok:true,result:...}` or
`{ok:false}`. Its separate JSON-lines transport budget is 8 MiB per line; an
oversized line is drained without retaining its remainder. This transport
budget is not a consensus rule or a descriptor-size change.

## Independent comparison

The reference package, without reading the new Rust parser, ran 490 requests:
362 fixed cases and 128 generated with seed `0x474e424435`. It observed 122
acceptances, 368 rejections and zero divergences. Accepted results, including
the exact canonical bundle string, were compared completely; negative cases
compare the verdict. This is not full-consensus differential coverage.

The prebuilt oracle SHA256 was
`aca9de614c159e7ccd7b63891f5e27cfb68b0c36ce8d1c395b3a0ff6e838b49a`.
The independent log is `/private/tmp/gnb-r5-reference-evidence/differential.log`,
SHA256 `9196f9f1195374741e4c72e5e04bf617494f76c0b27612889be4ac1288594bff`;
the reference evidence is versioned separately at commit `9724599`.

## Production reversals

`replay-core-reversals.py` executes seven focused production reversals, each
followed by a restored pass, without changing either final test file:
dispatcher, checksum comparison, request-network comparison, raw pool-byte
limit, duplicate-aware pool decoding, pool-script uniqueness, and the raw
WASM operation gate. Failures must be test assertion failures (exit 101 plus
`test result: FAILED`), not build errors. The replay manifest contains the
14 commands/results/log hashes, source hashes and unchanged test hashes.
The script restores original production bytes in `finally` and refuses an
existing output directory.

```
python3 docs/security/round-5/replay-core-reversals.py --output /private/tmp/gnb-r5-core-replay-fresh
```

## Limits of this delivery

This is the public descriptor foundation of technology item 4.2. It restores
public identities, not spending keys, balances, history or an indexed node
wallet. No wildcard/xpub derivation, new policy language, consensus activation,
signing, broadcasting, transport or bridge change is included. A tree's info
always reports its policy-tree activation prerequisite. Raw/enveloped key
distinctness is unchanged. Inherited findings remain open. Full integration
and independent three-lens reviews are outside this package's test results.
