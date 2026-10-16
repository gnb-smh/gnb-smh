# Round 3 validation record

This record distinguishes intermediate builds from the final reviewed PR.
No final integrated pass or merge readiness is established yet.

## Canonical WASM build delivery

The first branch CI run is
[38927549806](https://github.com/tiagobeltraoacioli-sketch/gnb-smh/actions/runs/38927549806),
at `fefb54bf7f293e752c953f134917395bda336410`. It intentionally retained the
previous committed binary while the new wallet source was rebuilt. The site
tests and WASM pin gate failed; the Python reference job passed. These
intermediate failures are not a green PR result.

The WASM job successfully rebuilt through `scripts/build-wallet-wasm.sh`,
uploaded `wallet-wasm-fefb54bf7f293e752c953f134917395bda336410`, and failed the
unchanged comparison against the old pin. The downloaded artifact and
manifest are under `/private/tmp/gnb-r3-linux-wallet-fefb54b`. The coordinator
checked the manifest's exact revision, Linux x86_64 host, Rust
`1.94.1 (e408947bf 2026-03-25)`, `wasm32-wasip1` target and wasi-sdk 25 archive
hash. Both the lockfile and build-script hashes match the Git blobs at that
revision. The binary's computed SHA-256 matches the manifest:
`a155c7b8ae879cca5e483685d18a5fb4d8e65698771b3e13ce800b658e975beb`.

This demonstrates successful artifact delivery despite a failing pin gate.
It does not resolve the separate macOS/Linux baseline mismatch R3-BUILD-1.
The intermediate artifact was not repinned: independent review identified
additional wallet checks that require another source build. A final pin
needs a fresh successful comparison and actual site/WASM tests.

## Review corrections and their limits

The independent verdict reviewer reproduced finalization of a fee-zero v3
document in the provisional WASM built from the initial core package. Its
real signed transaction was 8,440 bytes; the existing consensus minimum was
16,880 base units. No transaction was broadcast. This is a wallet
finalization failure, not a change to node consensus. Source inspection also
identified aggregate size after signing and monetary-range checks for
reproduction. Seven native regressions then failed before production changes.
The corrected core at `8cdb075` reuses the existing MoneyRange/minimum-fee
helpers and commits a signed candidate only after validation. Eleven
production-only reversals failed as expected and restored sources exactly.
The restored separate crypto suite passed 468 tests with four existing
ignores; WASM host passed 9/9. Drivers, hashes and manifests are versioned
alongside the package brief.

The verdict reviewer reran its original monetary harness against the final
Linux WASM: fee-zero and out-of-range cases refused, valid control signed and
finalized, exit 0. Only those two findings were closed by that reassessment.
The separate witness-size task was rejected by automatic review for possible
cybersecurity risk and stopped; that finding and the second core review lens
remain open. No retry, alternative reproduction or production fix was made
for that rejected task.

The final compiled source was rebuilt in CI run `38931632695`, yielding
SHA-256 `4571dbc61ed91468fc8841f60af55fc0a9a49065d82ffb00391f44007075e3a7`.
The coordinator checked its manifest and unchanged compiled source, copied
the artifact and ran the build script's explicit pin/SRI stage. The actual
browser test passed all four reported tests; a final wrapper-only reversal
failed and exact restoration passed again. See the versioned
[build manifest](wallet-wasm-build.json) and
[browser reversal manifest](wallet-browser-reversal.json).

## Reference, site and deployment checks

The check batch at `69faece` passed the PoW/consensus/PQ-PSBT/ledger Python
references, release tooling, deployment-file and functional-harness tests.
The first explorer run failed all 16 setup calls and one site test failed
because the sandbox denied loopback socket binding (`PermissionError/EPERM`).
Those logs are retained under `/private/tmp/gnb-r3-integrated-checks` and are
not recorded as product regressions or valid negative tests.

An authorized rerun of only those two suites at `cfaacec` passed:
**site 37/37**, **explorer 16/16**, no skips. Logs and results are under
`/private/tmp/gnb-r3-services-retry`. The source difference between those two
revisions is documentation only. Deployment checks retain their three
Linux-only skips on macOS; the Linux CI job is a separate platform check.

Final node, separate crypto, Python, site/deploy, functional, review and
exact-head CI results will be recorded after integration. Earlier round 2
platform failures remain in the scorecard and are not erased by these
intermediate checks.
