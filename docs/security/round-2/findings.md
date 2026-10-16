# Round 2 findings

This record distinguishes a reviewed package correction from completed
integration and CI. The broad security goal is still open; this round makes
no production security-verdict change and assigns no numerical score.

| Item | Status at integration | Evidence / remaining gate |
| --- | --- | --- |
| R2-TEST-1: nondeterministic wire-size negative fixture returned `Known` | Corrected and reviewed; full Cargo passed; final CI pending | Fixed-seed original fails; corrected target passes 4/4; correction-only reversal fails by the same verdict; restored target passes 4/4. The integrated Cargo target also passed 4/4. Exact boundaries, unchanged valid spend and unknown negative-case id remain asserted. |
| R1-FUNC-2: separate waits escaped the advertised heal deadline | Corrected and reviewed; 22 harness tests passed; final CI pending | Real scenario and wait helpers reject late peer, settling and sync observations under a controlled clock; five harness reversals distinguish each correction. Deadline is 30 seconds at CI factor 1; an explicit factor is applied once. The local live scenario refused at 30.003 seconds, rather than healing successfully. |
| R2-TEST-2: functional skips counted as passes and allowed false CI success | Corrected and reviewed; unit/integration accounting verified; final CI pending | Real runner tests cover all-skipped, mixed and all-passed runs. Strict CI rejects skips; explicit local skip mode reports them separately and still rejects actual failures. The live run accurately reports 12 passed, zero skipped and two failed. |
| R1-FUNC-1: macOS partition/reconnect failed with `EADDRINUSE` | **Open** | No network or peer-address correction is included. The earlier failure and documented manual-peer fallback remain in the [round 1 record](../round-1/findings.md). A passing Linux run cannot close this macOS finding. |
| R2-FUNC-3: full-template scenario timed out during preparation | **Open; cause unknown** | The unchanged 300-second outer limit interrupted generation at height 275, before the required 289 and before the large-template assertions. Two independent reviewers confirmed progress and the stage from logs; no cause was established. No timeout increase or source correction was made. See [validation](validation.md). |

The deadline covers the observation of equal selected tip and valid tips.
Subsequent state/UTXO checks are required but are outside that deadline.
Synchronous RPC calls are not cancelled at expiry; a late result cannot pass.
The runner's separate process timeout was not exercised by the new unit suite.
`sees_peer` uses connection history from the current process run, so it does
not prove a connection is still active. These are explicit evidence limits,
not newly reproduced production defects.

The [round 1 open backlog](../round-1/findings.md) and original acceptance
criteria remain: PoWit accountability/quorum/convergence and activation,
network/resource bounds, cryptographic and wallet/bridge work, complete
differential coverage, platform matrix, formal model and external assessment.
Previously blocked PoWit/R7 reproduction packages were not retried in this
round. The one-day activation request has not been converted into a production
activation constant; a fresh tip and rollout margin are required first.

The next merge requires the complete validation record and green CI for its
exact head. Independent external audit and a bug-bounty program remain
recommended before any relaunch or bridge release.
