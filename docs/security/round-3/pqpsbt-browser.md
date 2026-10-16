# PQ-PSBT browser bindings and wallet build delivery

Base `f06b7f8dc05af107fd16f2cebdd89d62a360662a`; branch
`codex/technology-pqpsbt-browser`. Reserved native codegen-units **71** and
target `/private/tmp/gnb-technology-target-pqpsbt-browser`. JavaScript tests
use Node 22 and the actual pinned WASM binary. Reproducible WASM release
builds retain the repository's release profile and CI toolchain settings.

Add explicit public-data `pqpsbt(request)` and session-key
`signPqPsbt(hex, network, nextHeight, maxFee)` bindings to the existing loader.
The document stays an exact JSON string or binary hex across the boundary;
the wrapper must not parse and reserialize it before the strict Rust parser.
Keys stay inside each separate WASM instance.

Before editing production, add an executable offline 2-of-3 flow test through
the existing loader and observe the absent operation fail. Keep its existing
create/address operation as a positive control. After the shared core is
integrated and rebuilt, exercise create/import, binary/JSON round-trip,
separate signers, combine, incomplete-signature refusal, finalization and
extraction. Check explicit network/height/fee context and refusal of malformed
or conflicting documents. Disable fetch after initial loading: this proves
the tested signing exchange needs no network, not that inputs are currently
unspent or that a transaction was mined. No production wallet UI is added.

## Build evidence requirement

A baseline rebuild using the unmodified `scripts/build-wallet-wasm.sh`, Rust
1.94.1 and official wasi-sdk 25 on macOS produced SHA-256
`e4059d91355c96875ae461bb554e841a2154b5e6248b028ac6ba1c7d2b53d673`;
the committed Linux-CI-verified binary has
`1537c685477f4de1b71166d7932d8c0d2b5b97ab82d250f79486130e14165274`.
Both have 871,324 bytes. The mismatch is preserved as **R3-BUILD-1, open**;
its cause and cross-host reproducibility are not established. The local SDK
archive hash is `55e3ff3fee1a15678a16eeccba0129276c9f6be481bc9c283e7f9f65bf055c11`.
Build output and both binaries are under `/private/tmp/gnb-r3-wasm-repro`
and `/private/tmp/gnb-r3-wallet-baseline-build.log`. Only generated files from
that baseline experiment were restored; the user's SDK symlink was untouched.

Preserve the existing Linux CI rebuild/pin comparison as a failing gate on
mismatch. Add an artifact containing a successfully rebuilt binary and a
manifest of source revision, lockfile hash, Rust version, target, SDK version
and SDK hash. Publish the artifact even when the subsequent comparison fails,
so an authorized maintainer can obtain that exact build, inspect the manifest,
repin with the existing script and then require a fresh green comparison.
Build failure must not upload an unrebuilt old binary as a successful result.
Do not silently replace the pin in CI, relax its comparison, or claim this
delivery mechanism fixes cross-host reproducibility.

## Execution evidence (before final integration)

`site/tests/wallet-pqpsbt.test.mjs` first ran against the committed baseline
loader and binary. Its create/address controls succeeded; the first new
operation failed at runtime with `pqpsbt is not a function` (exit 1,
`/private/tmp/gnb-pqpsbt-browser-red.log`). This is evidence of an unsupported
feature, not a security defect in the old binary.

After the core's initial commit `26a4212` and the browser bindings, the actual
WASM was rebuilt with the repository script and SDK 25. The 2-of-3 test passed
(one test, zero failures, `/private/tmp/gnb-pqpsbt-browser-green.log`). It also
checks strict fee/network/activation context, integer precision, incomplete
signatures, conflicting unsigned transactions, duplicate JSON fields,
trailing bytes, locked signers and public finalization after wiping keys.

The production-only reversal restored the old `core.js`, retaining the exact
final test and new binary: exit 1 at the missing operation. Restoring the
bindings gave exit 0. Snapshots, logs and hashes are in
`/private/tmp/gnb-pqpsbt-browser-reversal/manifest.json`. Test SHA-256:
`48aa58f6ab7802f3529ff20c9f931a6cce640aea62f0787f5943459eef51a5c9`.
The provisional macOS WASM hash is
`b833c3fc3d65d3e20814dd5875c34e55efd1215dc0a2fb2cecb0686e37bae091`;
it is retained outside git for evidence and is not the final release pin.
The final core revisions require another build and test run.

Independent review then found missing fee and monetary-range checks in the
signer/finalizer. Two new browser subtests were run against the preserved
provisional binary before its correction. Both failed with `Missing expected
exception`, while the original complete 2-of-3 positive control passed
(`/private/tmp/gnb-pqpsbt-browser-money-red.log`, exit 1). The cases use zero
fee and values above `MAX_SUPPLY_SAT`; they generate real signatures inside
WASM and do not broadcast a transaction. A final rebuilt binary must pass
both refusals as well as the positive flow. This extends the test file beyond
the earlier recorded SHA; its final hash will be recorded after integration.

The CI YAML parses locally. Its artifact upload and unchanged comparison
gate still require execution on GitHub. Three review lenses, final Linux
rebuild/repin and full integration/CI remain required. No numerical score is
assigned here.
