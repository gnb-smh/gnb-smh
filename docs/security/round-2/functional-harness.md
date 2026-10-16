# Round 2 — functional harness acceptance

Base: `f607e077f035733509aa9a6c549ee36b26f61870`.
Package: `codex/security-r2-functional-harness`; reserved codegen-units: **43**
if Cargo is needed. This package is Python/CI test infrastructure.

## Scope and acceptance

1. The functional runner currently labels passed-or-skipped scenarios as
   passed and allows an all-skipped CI run to succeed. Reproduce with unit
   tests exercising the existing runner logic, then report passed/skipped/
   failed separately and require all requested CI scenarios to execute and
   pass. Preserve intentional local skips through an explicit mode distinction.
2. R1-FUNC-2: the partition scenario's peer waits are outside its nominal
   30-second deadline. Reproduce this with a controlled clock and the real
   harness wait logic, then enforce a shared deadline including peer waits
   and settling. Keep the 30-second value; do not weaken it to hide the
   separate macOS TCP reconnection failure R1-FUNC-1.

Tests must fail by a meaningful assertion on unchanged behavior, not merely
because a new function/option does not exist. Keep production Rust, consensus,
wallet/WASM, dependencies and ignored-test lists unchanged. Do not claim the
macOS transport failure is fixed. If the scenario is aligned with the documented
identified-peer contract, explain and test the fixture change separately.

Record red/green and reversals of the harness corrections with the final
regression setup retained. Require three independent reviews and the full
integration gates before the next PR is marked complete. Do not assign a score.

## Reproduction and implementation

All evidence logs and the reversal driver remain outside the repository at
`/private/tmp/gnb-r2-functional-evidence`. No Rust build was needed.

The initial `red.log` ran 11 tests on unchanged harness code: three positive
controls passed and eight assertions failed. Tests call the actual
`test_runner.main`, `Job.poll`, `Job.finish`, `PartitionHealTest.run_test`,
`wait_for_peers`, `sync_blocks` and `wait_until`. Only external subprocesses,
node state/RPC results and the clock are simulated. The partition fixture
stops after the real scenario has accepted convergence and checked branch
tips/blocks; it does not duplicate or substitute its wait logic.

| Reproduced behavior | Regression test in `test/functional/unit/test_harness.py` | Red observation |
| --- | --- | --- |
| All scenarios skipped returned success | `test_all_skipped_is_not_a_successful_ci_run` | Return 0, `ALL: 2/2 passed` for two exit-77 processes |
| A pass plus a skip returned success | `test_mixed_pass_skip_is_not_complete` | Return 0, `ALL: 2/2 passed` |
| Summary counted skips as passes | `test_skip_is_reported_separately_from_pass` | Missing `1 passed, 1 skipped, 0 failed` |
| A late peer connection passed the partition scenario | `test_late_peer_connection_cannot_pass_heal` | Accepted at 33 seconds |
| Sequential peer observations and settling escaped the budget | `test_peer_waits_and_settle_share_the_heal_deadline` | Accepted at 31 seconds |
| A late successful sync RPC passed | `test_slow_successful_sync_observation_cannot_pass_late` | Accepted at 31 seconds |
| Generic wait accepted a late true predicate | `test_wait_does_not_accept_a_predicate_returning_after_timeout` | No timeout assertion after 31 seconds with a 30-second budget |
| Poll sleep exceeded the remaining budget | `test_poll_sleep_is_bounded_by_remaining_time` | Slept 0.25 seconds for a 0.1-second budget |

The runner now distinguishes passed, skipped and failed results. Strict mode
is the default and is explicit as `--ci` in the workflow. A skip fails this
mode and its log is printed. `--allow-skips` is an explicit local mode,
incompatible with `--ci`; it accepts skips while still reporting their true
count and rejecting genuine failures. No scenario or ignored-test list was
removed or reduced.

The partition now calculates one monotonic deadline from
`HEAL_TIMEOUT * TIMEOUT_FACTOR`. `HEAL_TIMEOUT` remains **30** and CI uses
the default factor **1**. The explicit slow-machine factor is applied once;
the inner peer waits, two-second mesh settling and block synchronization
share the deadline and cannot extend it. `wait_until` checks both before and
after a predicate and caps each polling sleep by the remaining time.

This is an **acceptance deadline**: a synchronous predicate/RPC already in
progress may return after the deadline, but its late result cannot pass.
There is no claim of interrupting blocking I/O or returning exactly at 30
seconds. The runner's existing process timeout is the outer termination
bound. R1-FUNC-1 (macOS TCP reconnect `EADDRINUSE`) remains **open**; peer
addresses and restart topology were not changed by this package.

## Verification and reversal

`python3 -B -m unittest discover -s test/functional/unit -v` passed all
**22 tests** (`green.log` and final `restored-green.log`). Controls cover
normal successful convergence, real failures, strict CI skips, explicit
local skips, conflicting mode flags, an expired deadline, preserved error
diagnostics and relative timeout scaling. With factor 2, convergence at 45
seconds passes and a connection first visible at 61 seconds fails at 60:
the factor neither disappears nor multiplies again inside each wait.

The workflow runs the unit suite before building nodes and uses `--ci` for
live functional scenarios. `test_runner.py --list` still lists the same 14
scenarios. This package does not claim that the live suite or remote CI is
green; those are integration gates, and R1-FUNC-1 may still fail there.

Five isolated reversals retained the final tests and fixture setup. Each
failed by assertion, not a missing API/option or import error. A `finally`
block restored the changed file and checked its SHA-256 against the saved
final bytes. After all reversals, the final 22-test suite passed again.

| Reversed harness correction | Failure with final test setup | Evidence log |
| --- | --- | --- |
| Runner summary and success policy | Strict all-skipped/mixed runs returned 0; separate-count assertions failed (seven assertion failures across nine test methods/subtests). | `reverse-runner.log` |
| Partition's shared deadline wiring | Real scenario again accepted at 33 and 31 seconds. | `reverse-partition-deadline.log` |
| Peer-wait deadline propagation and bounded settling | Final sync rejected late results, but peer waits reached 33 and 31 seconds instead of stopping at 30. | `reverse-peer-deadline.log` |
| Post-predicate deadline check | A slow true predicate and the real scenario's late RPC result passed at 31 seconds. | `reverse-late-success.log` |
| Remaining-time polling sleep | A 0.1-second wait again advanced the fake clock by 0.25 seconds. | `reverse-poll-sleep.log` |

No security score is assigned by this implementation. Independent reviews
and the complete round integration remain required.
