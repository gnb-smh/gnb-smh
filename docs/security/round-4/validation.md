# Round 4 integrated validation

The [machine-readable record](integrated-validation.json) retains commands,
source notes, result codes and hashes of local logs. No failed run was changed
to success by a later partial run. All local node/functional checks used
isolated test directories; no existing user node or miner was stopped.

| Execution | Result |
| --- | --- |
| `cargo test -p gnb --locked --offline --no-fail-fast` | Exit 101; 1,771 passed, one failed, eight ignored, 105 summaries |
| Separate `cargo test -p gnb-crypto --locked --offline` | Exit 0; 479 passed, zero failed, four ignored, 14 summaries |
| `cargo test -p gnb-crypto --example address_v2_oracle` | Exit 0; 5/5 |
| Rust/Python address comparison | 672 requests, zero divergences; 502-case corpus unchanged |
| Functional build with `test-pow-limit` | Exit 0; exclusively local testnet artifacts |
| Functional harness, jobs=1, timeout=300 | Exit 1; 12 passed, zero skipped, two failed, 14/14 completed in 736 seconds |
| Canonical Linux WASM, complete site suite | 67 passed, zero failed/skipped |
| Explorer API, complete discovery | 21 passed |
| References/deployment/release/harness | Ten command groups exited 0; platform-only deploy checks retain their reported skips |
| Address fuzz-target typecheck, CGU131 | Exit 0; no fuzz input campaign performed locally |

Cargo totals count executions across targets, including repeated test modules
and the isolated testnet subprocess. They are not 1,771 distinct functional
scenarios. The functional inventory is 14 scripts.

The native driver started at `2cb9980`. Node production stayed unchanged during
the run. The only later node diff was the repeated-prefix regression test;
the log explicitly shows that final test executing. The oracle adapter was
updated before the separate crypto invocation. Default Cargo tests do not
execute example unit tests, so the five adapter tests have their own command
and log. No build or compiler failure is counted as a reproduced code defect.

## Open failures

- **R4-NODE-1:** `ingress_processor_tests::the_sweep_fetches_a_bounded_number_of_waiting_bodies`
  failed at `node/src/main.rs:3626`: observed 14, expected 30. That binary
  recorded 521 passes/one failure. Cause undetermined; no directed
  reproduction, production change or security-severity inference is credited.
- **R1-FUNC-1:** `feature_partition_heal.py` failed after restart, with
  `EADDRINUSE` in node logs; runner duration 49.0 seconds. This retains the
  inherited macOS observation and does not establish its cause.
- **R4-FUNC-1:** `feature_restart_persistence.py:62` failed in
  `wait_for_peers`, at the peer subscription/mesh settling deadline after
  restart; runner duration 71.8 seconds. No cause or corrective change was
  established. It remains a new validation finding.

`mining_full_template.py` passed in 193.3 seconds; this does not explain the
older jobs=2 timeout. The peer-persistence target passed in this run; that
does not explain or close R3-NODE-1. No timeout, safety assertion or ordinary
test was disabled to obtain those results.

## Artifact and CI provenance

The local macOS build used the normal build script and WASI SDK25; its hash
was `f17b140c82a5b8325da5d60a7d864430954f328f2cd30bd1b2fd77a3527c16c1`.
Initial fork CI 38946123375 on `9226dad` failed the Linux-versus-pin check;
all other applicable jobs subsequently passed. The Linux artifact and
[manifest](wasm-linux-build.json) were downloaded, hashes checked, and compiled
source compared with the current tree before installation. Both entry-point
pins and SRI were refreshed using the script. The canonical hash is
`f184981b63377d286dabd792d375e2f2daaa337d27c7a50bb64c96d5f3d4b0d5`.

Fresh [CI 38948115956](https://github.com/tiagobeltraoacioli-sketch/gnb-smh/actions/runs/38948115956)
on `1f55f934833fbdcff9d835072d05a5766934f087` completed successfully, including
the unchanged rebuild comparison and workspace job. Later commits only
consolidate review and validation documentation. The final PR-head status
and PR-event fuzz/mutation jobs must still be evaluated separately. Push-event
skips of fuzz/i686-node are not successful executions of those jobs.
R3-BUILD-1 remains open: canonical Linux delivery does not resolve the
cross-host byte difference or prove an equal-verdict platform matrix.

See the [three independent reviews](README.md#independent-review) and the
[independent scorecard](scorecard.md). Those reviews and bounded reversals do not constitute
external audit, whole-repository approval, or permission to skip failed gates.
