# Round 2 — wire-metadata regression fixture

Base: `f607e077f035733509aa9a6c549ee36b26f61870` (merged PR #10).
Package branch: `codex/security-r2-wire-fixture`; codegen-units: **37**.
Integration branch: `codex/security-round-2-20261016`; codegen-units: **41**.

## Observed failure and acceptance

The prior push CI run `38908791122` failed the existing
`block_accepted_from_gossip_and_served_from_storage_is_accepted_by_a_fresh_node`
test at `node/tests/fix_wire_metadata.rs:216`: the oversize-negative case
returned `Known` for `blue_score 0`. The same target passed in the local
full-node invocation. This is an observed nondeterministic test failure;
its cause must be demonstrated, not assumed.

Reproduce a deterministic fixture in which the oversize negative case reaches
the known-block path before changing its setup. Preserve the exact 1,000,000
and 1,000,001-byte boundary checks, valid-copy acceptance/storage consistency
and every blue-score variant. Correct only the test fixture if the observed
failure is explained by its already-known identifier. Do not change production
ingress, validation, consensus, dependencies, timeouts or ignored-test policy.

Record red execution, corrected green execution, and a test-fix reversal that
fails again while preserving the deterministic setup. Submit the final diff
to three independent review lenses. A separate full node/crypto invocation,
references, site/deploy, functional results and CI remain integration gates.
No numerical score is assigned by the implementer.

## Demonstrated cause and test-only correction

The original builder signs the spend separately for the limit and limit+1
fixtures. The spend's `script_sig` is excluded from its txid; the coinbase's
`script_sig` is included. A one-byte difference in the randomized spend
signature can therefore produce two different wire sizes with the same outputs,
same coinbase padding, same Merkle root, and same block id. This is not a hash
collision: the committed preimages are identical.

A bounded probe using the original `sized_block` found seed `[1; 32]`. Applying
that thread-local PQClean RNG scope to the complete existing test reproduced
the CI failure without changing either size builder or ingress:

| Original fixture | Wire bytes | Coinbase script bytes | Spend script bytes |
| --- | ---: | ---: | ---: |
| At the limit | 1,000,000 | 25 | 8,339 |
| Above the limit | 1,000,001 | 25 | 8,340 |

Both ids in the red execution were
`55932dff8a38760e21d8eb9b9cae1a08c1806904ebb13d57269c5cb7c535710a`;
both spend txids were
`6f482d9c55331dbb63798345be041e58fc6c0bac1558c5d5e159d9010e295fc9`.
The receiver already held that block. `handle_block_gated` takes the known-DAG
path, and `restore_body` returns `Known` for the unsolicited copy before size
validation. The original assertion failed with `blue_score 0: Known`.

The corrected oversize fixture clones the accepted block, appends one byte to
the coinbase script, recomputes its commitment/root using the existing helper,
and records its new id in the existing test-only PoW cache. Its signed spend is
byte-identical to the already-validated original. Explicit preconditions require
exactly 1,000,001 bytes, unchanged spend bytes, a distinct id, and absence of that
id from the receiver's DAG. Both oversize blue-score copies must keep the same
new id and exact size, and still return `Invalid` containing `block too large`.
The resulting coinbase/spend lengths are 26/8,339. The coinbase's length prefix
stays below the 253-byte varint boundary; the size assertion also guards this.

All original acceptance/storage/UTXO assertions remain, including acceptance of
the 1,000,000-byte copies for blue scores `0`, `251`, `70_000`, and `u64::MAX`,
and oversize rejection for `0` and the derived score. No test is ignored and no
production source, dependency, consensus rule, ingress order, or WASM artifact
changes. The fixed seed is scoped to synthetic test keys/signatures only.

## Focused execution and provenance

Focused execution uses Rust 1.94.1 on native x86_64 macOS, `rustc --test` with
`-C codegen-units=37`, and output directory
`/private/tmp/gnb-security-target-r2-wire`. It reuses the exact dependency
archives recorded by the previous Cargo integration-test fingerprint
`gnb-80795dac089e2d1c/test-integration-test-fix_wire_metadata.json` in
`/private/tmp/gnb-security-target-integration/debug/.fingerprint`.

The selected `gnb` archive is `libgnb-f1243b52910c3c94.rlib`, SHA-256
`475045890bab19e1044f50b25631eeb7f768602413ec0ca9c56a06e87b242df8`.
The helper `/private/tmp/gnb-r2-wire-build.py` matches each direct dependency's
Cargo fingerprint and records its archive SHA-256, the test source SHA-256,
compiler version, and complete compiler command in a JSON build manifest.
`git diff 91bb719 f607e07 -- node/src crates Cargo.toml Cargo.lock node/Cargo.toml`
is empty; the only paths changed between those revisions are four round-1
Markdown reports. Thus the reused production libraries have identical source
and dependency inputs to this package's base. This focused linking is not a
replacement for a Cargo integration build or CI.

Evidence files are under `/private/tmp/gnb-r2-wire-`:

- `seed-probe.log`: original builder, seed 1, same-id boundary pair.
- `red.log`: complete seeded original test, exit 101, `blue_score 0: Known`.
- `green.log`: corrected target, all 4 tests passed, 0 failed/ignored.
- `red-source.rs`, `green-source.rs`, `red.patch`, `fix-only.patch`: setup and
  fix separation. Reversal preserves the fixed-seed wrapper and diagnostics.
- Corresponding `*-build.json` manifests preserve compiler/archive provenance.

| Execution | Result | Duration |
| --- | --- | ---: |
| Original builder with fixed seed (`red.log`) | Exit 101; 1 failed: `blue_score 0: Known` | 41.61 s |
| Corrected target (`green.log`) | Exit 0; all 4 passed, none ignored | 49.84 s |
| Fix-only reversal (`reversal.log`) | Exit 101; 1 failed: `blue_score 0: Known` | 33.91 s |
| Restored target (`restored.log`) | Exit 0; all 4 passed, none ignored | 31.76 s |

The red/reversal test sources share SHA-256
`621edb5a1d69fd1305236002ae634697108876a65818689662ceb729cc14416a`;
the green/restored sources share SHA-256
`b3b4ff8ca8a1d6f35b497f736517a2dab0323228c035904d80f62ddfc0f0889a`.
Only the oversize construction and its new precondition assertions were
reversed; the seeded wrapper, diagnostics, and original verdict assertions
stayed in place. Block ids vary between invocations because the original
genesis fixture uses the current time; the within-pair identity and signature
lengths reproduce deterministically. `git diff --check` passes.

Mandatory Cargo integration/CI gate (not replaced by the focused runs):

```sh
CARGO_BUILD_JOBS=2 CARGO_PROFILE_DEV_CODEGEN_UNITS=37 \
CARGO_PROFILE_TEST_CODEGEN_UNITS=37 \
CARGO_TARGET_DIR=/private/tmp/gnb-security-target-r2-wire \
cargo test --locked -p gnb --test fix_wire_metadata -- --nocapture
```
