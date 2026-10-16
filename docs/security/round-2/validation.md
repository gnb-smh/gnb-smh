# Round 2 execution evidence

## Starting evidence

- [Round 1 execution record](../round-1/validation.md): local full node
  1,714 test executions passed (eight ignored); separate crypto 448 passed
  (four ignored); references, site/Worker/wallet, explorer and release tools
  passed. Local macOS functional run: 13 passed, one failed, zero skipped.
- [Push CI 38908791122](https://github.com/gnb-smh/gnb-smh/actions/runs/38908791122)
  for `ce7d60b084cb9436b6b278b6569ecd3258ec6ad3` concluded **failure** in
  `workspace-test`. The failure is
  `block_accepted_from_gossip_and_served_from_storage_is_accepted_by_a_fresh_node`
  at `node/tests/fix_wire_metadata.rs:216`: `blue_score 0: Known`.
  Miri, i686, WASM reproducibility and the Linux functional job passed in that
  run; these successes do not override the failing overall result.
- The owner merged PR #10 while final PR checks were still running. The
  merge's success is not a testing result. No mainnet activation was added.
- [Merge CI 38911370624](https://github.com/gnb-smh/gnb-smh/actions/runs/38911370624)
  for `f607e077f035733509aa9a6c549ee36b26f61870` subsequently completed
  successfully (observed 2026-10-16 14:11 UTC). All executed jobs passed;
  `fuzz` and `i686-node` were skipped by event filters. The preceding PR
  run's fuzz job was still running at that observation. This does not erase
  the separate push-CI or local macOS functional failures.
- The [merge functional job](https://github.com/gnb-smh/gnb-smh/actions/runs/38911370624/job/117007762302)
  log was also inspected, rather than relying only on its green status:
  all 14 named scenarios were `Passed`, none `Skipped`; the summary reports
  249 seconds. `mining_full_template.py` was the longest scenario at 146
  seconds; `feature_partition_heal.py` passed in 25.2 seconds for the entire
  scenario. This is Linux baseline evidence, not a measurement of
  the fixed shared deadline or closure of the macOS finding.
- [PR CI 38909984512](https://github.com/gnb-smh/gnb-smh/actions/runs/38909984512)
  for `ce7d60b084cb9436b6b278b6569ecd3258ec6ad3` subsequently completed
  **successfully**, including `fuzz / fuzz` (observed 2026-10-16 14:25 UTC).
  The event-filtered `i686-node` job remained skipped. This later success
  does not establish green CI at the time of merge or invalidate the
  earlier same-SHA push failure that motivated the fixture correction.

## Package and integration results

Wire package `0f674831826e5c9128b6659695a4edfbf17065f4` and functional package
`36c33cb8f0f9278f9cd37de0de2dbca5b7c76011` were reviewed independently by
`review_verdict`, `review_paths` and `evidence_baseline`. All three found no
blocking issue within their package scopes. The first two independently ran
the 22 Python unit tests and confirmed the same 14 selected functional scripts;
all three inspected the diffs and red/green/reversal logs. None independently
executed Cargo or the live functional suite in that review. Focused `rustc`
linking and its archive provenance are documented in [wire-fixture.md](wire-fixture.md),
and do not replace a Cargo build.

After those reviews, the packages were integrated as `2797222` and `b425436`
on the merge base `f607e077`. The integrated checks use isolated target
`/private/tmp/gnb-security-target-r2-integration`, codegen-units **41**,
Rust/Cargo 1.94.1, Python 3.12.15 and Node.js 22.23.3. Node and crypto tests
run in separate Cargo invocations. The functional binaries are explicitly
built with `test-pow-limit`; the runner snapshots them and verifies that they
refuse mainnet before executing scenarios.

### Integrated revision `b425436`

The script and per-command logs are retained at
`/private/tmp/gnb-r2-run-checks.py` and `/private/tmp/gnb-r2-integrated-checks/`.
`results.json` records the exact full revision and each exit code.

| Check | Result |
| --- | --- |
| PoW/difficulty/Merkle/GhostDAG Python references | Passed |
| Consensus Python reference | 197 transaction cases, 118 block cases, 4,830 checks; zero failures |
| Python ledger | 23 passed |
| Site, Worker and wallet JavaScript | 33 passed; zero skipped |
| Explorer API | 16 passed |
| Deployment checks | Five passed; three platform-dependent skips (systemd/ShellCheck); Linux CI required |
| Minimum-chain-work release tooling | 10 passed |
| Functional harness unit tests | 22 passed; zero skipped |
| Full `gnb` Cargo invocation | Exit 0; 1,714 test executions passed, zero failed, eight existing ignores across 103 target summaries |
| Separate `gnb-crypto` Cargo invocation | Exit 0; 448 passed, zero failed, four existing ignores across 11 target summaries |
| Test-only functional binary build | Exit 0; explicit `test-pow-limit` build |
| 14 live functional scenarios | In progress at draft publication |

The node count includes repeated unit suites in different targets, not 1,714
distinct scenarios. Its corrected `fix_wire_metadata` target passed all four
tests with zero failures or ignores through Cargo, in the isolated CGU41 build.
The full node command/log and exit code are retained in
`/private/tmp/gnb-r2-integration/{node.log,crypto.log,functional-build.log,results.json}`.
Pending rows describe
the publication-time state and must not be inferred to have passed.

Do not infer passing tests from compilation, source definitions, workflow
configuration or an earlier revision. Preserve failures and skipped counts.
Green CI for the exact proposed head is required before the next merge.
