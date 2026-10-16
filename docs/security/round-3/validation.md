# Round 3 validation record

This record distinguishes intermediate builds from the final reviewed PR.
The branch CI is green for the revision identified below. Local failures and
the incomplete review remain open; no merge readiness is established.

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

## Integrated node failure and separate crypto result

The integrated driver began at `03757cc`, with codegen-units 59 and isolated
target `/private/tmp/gnb-security-target-r3-integration`. Later commits changed
documentation, browser fixtures/pins and two CLI unit fixtures, not native
production. The ordinary `cargo test -p gnb --locked --offline` invocation
exited 101 after 1,172.08 seconds: **1,464 passed, one failed, seven ignored**
across 66 completed summaries. It stopped in `peer_addr_churn_lab` before
36 integration binaries seen in round 2 and the doc-tests were reached.
This is not a full node pass.

**R3-NODE-1 remains open, cause undetermined.**
`live_connection_persists_only_canonical_addrs` observed an empty address
list after its existing 70-second wait and failed at
`node/tests/peer_addr_churn_lab.rs:313`. The independent read-only triage
found that the harness does not first establish a connection event, discards
the network task result and maps file-read/JSON errors to an empty list.
The output therefore does not distinguish connection, identification,
persistence or file-read failures. The test and network module are unchanged
from the baseline; that does not establish or exclude a causal relationship
to the transport change. No production or fixture correction was made.

The coordinator ran only that existing test in the same Cargo-built binary,
`peer_addr_churn_lab-fcf5ee4894b9578e`, with `--exact --nocapture`:
**one passed**, exit 0, 71.10 seconds. The original failure and isolated pass
are both retained in `/private/tmp/gnb-r3-integration/node.log` and
`/private/tmp/gnb-r3-peer-persistence-isolated.log`. The pass does not prove
intermittence, explain the failure or close the finding.

The separate `cargo test -p gnb-crypto --locked --offline` invocation
completed with exit 0 in 277.69 seconds: **468 passed, zero failed, four
ignored** across twelve summaries. Functional build succeeded and the
14-scenario live run completed as recorded below. Remaining node coverage and
CI results are recorded separately; earlier round 2 platform failures remain
in the scorecard.

At head `7f72e1b`, fork run
[38935414889](https://github.com/tiagobeltraoacioli-sketch/gnb-smh/actions/runs/38935414889)
completed **successfully**: 15 jobs succeeded, including workspace tests,
separate consensus crates, functional, Miri, sanitizers, site/deploy,
references, i686 crates and the fresh Linux WASM rebuild/pin comparison.
The full-node i686 and fuzz jobs were skipped by their existing event
conditions on this push. A PR event additionally runs the fuzz job. This is
not proof of the requested complete platform matrix or cross-host byte
reproducibility. Later documentation-only changes still require their own
PR-head CI; a prior green run does not replace it.

## Completion of initially unexecuted node targets

After the functional run finished, the continuation driver used Cargo
metadata to enumerate every integration target and compare it with the
initial run's reached targets. It selected the **38 not yet reached**
(36 already present in round 2 and the two new PQ-PSBT targets), reran the
complete `peer_addr_churn_lab` binary, and ran `gnb-cli` with its final unit
fixtures. The source revision was `7f72e1b`, still codegen-units 59, and Cargo
used `--no-fail-fast` without a test-name filter.

The continuation passed: **307 passed, zero failed, one ignored**, 40
summaries, exit 0, 169.07 seconds. The peer-address binary passed all five
tests. The subsequent explicit `cargo test -p gnb --locked --offline --doc`
completed with exit 0 in 4.01 seconds, reporting zero doc-tests. The dedicated
stream, upgrade and transport-convergence targets are included in the
completed continuation. Together the invocations reached every declared
integration target; their overlapping CLI/peer tests must not be counted as
new distinct tests. The initial node exit 101 remains a failed complete-suite
attempt, not a green run assembled by adding later passes. R3-NODE-1 remains
open without a cause or production correction.

Exact commands, target lists and log hashes are retained in
`/private/tmp/gnb-r3-node-continuation/results.json` and the versioned
[integrated validation manifest](integrated-validation.json). The runtime
driver is `/private/tmp/gnb-r3-finish-node-tests.py`; it made no source edits.

## Local live functional result

The runner completed **all 14 scenarios: 13 passed, zero skipped, one failed**,
exit 1, 661.54 seconds including cache/start-state preparation. It used one
scenario at a time and the unchanged 300-second per-scenario deadline.
The full results/log are under `/private/tmp/gnb-r3-integration`; failed node
logs are retained under `/private/tmp/gnb-r3-functional`.

`feature_partition_heal.py` failed in 49.5 seconds. Its node log again records
`Address already in use (os error 48)` when reconnecting after restart, before
the existing convergence deadline. R1-FUNC-1 remains open; the successful
Linux functional job does not explain or fix the local result.

`mining_full_template.py` passed in 180.2 seconds. This includes its actual
large-template assertions, rather than stopping during prerequisite mining.
R2-FUNC-3 was therefore **not reproduced in this run**. No production fix was
made. This run used one scenario at a time whereas round 2 used two; that
difference alone does not establish the cause of the earlier timeout.
The earlier 300-second timeout and its unexecuted assertions remain recorded.

All other local scenarios passed: activation, restart persistence,
invalidation, test-build guard, transaction relay/replacement, ordinary
mining, block propagation, invalid blocks/transactions, RPC authentication,
UTXO-set information and coinbase maturity. These 14 live scenarios are
separate from the 22 harness unit tests; their counts are not combined.
