# Round 4 — additive network-bound addresses (partial program delivery)

This round implements CRY-7 / technology 4.5 within the boundaries described
in [ADDRESS-V2](../../ADDRESS-V2.md). It does not establish superiority over
Bitcoin Core or close the wider security/technology program. No independent
numerical score has been assigned. See the [independent scorecard](scorecard.md) for category
evidence and inherited findings.

The implementation began at round-3 head
`7d6a67eafa93cf7935ecedb50d601486aca4cff7`. Its merge into main,
`d1549fb4a7347d0c7172dfad035b107ec100427c`, has the same tree and was subsequently
merged into the round-4 branch. Codegen units are isolated per package; the
integration target uses 97 and the additional address-fuzzer typecheck 131.

## Delivered scope and its limits

| Package | Evidence | Boundary |
| --- | --- | --- |
| Address codec | [core brief](address-core.md), [reversals](address-core-reversals.json) | Bech32m aliases resolve to unchanged single-key/policy scripts; legacy output remains default |
| Independent specification | [reference brief](address-reference.md), [oracle correction](address-oracle-evidence.json) | 502 vectors and 672 JSON requests, not a million-case campaign or a full consensus oracle |
| RPC/CLI | [frontend brief](address-frontends.md), [evidence](address-frontends-evidence.json) | Read RPCs now require the node's network; CLI already enforced destination network; no consensus-rule change |
| Browser/Worker/API | [web brief](address-web-paths.md), [policy correction](policy-ui-reversal.json) | Both address kinds are recognized; policy wallet watching and indexed policy history remain unsupported |
| WASM/pins | [wallet brief](address-browser.md), [reversals](address-wasm-reversals.json), [generator regression](pin-generator-reversal.json) | Actual local WASM payments at H-1/H; no broadcast or full browser/live-node journey |
| Secondary wallet wiring | [brief](wallet-secondary.md), [final reversals](wallet-secondary-attempt-reversals.json) | Real callbacks/WASM now receive height, selected previous transactions and explicit creation/open network |

All production fixes followed runtime reproduction with positive controls.
The independent reviewers found and then rechecked additional UI, oracle and
wallet wiring issues. Historical manifests retain their original source and
test hashes; subsequent test strengthening has separate manifests.

## Independent review

- [Verdict consistency](review-verdict.md).
- [Input paths and variants](review-paths.md).
- [Test strength and evidence](review-tests.md).

These are independent internal agent reviews, not an external professional
audit. They do not approve the whole repository, a mainnet relaunch or a bridge.

## Release and validation gates

The canonical Linux wallet was built by the unmodified comparison workflow
in [run 38946123375](https://github.com/tiagobeltraoacioli-sketch/gnb-smh/actions/runs/38946123375)
from `9226dadf88033b3ca10bebd459512b1889d18062`. Its
[manifest](wasm-linux-build.json) identifies source, lockfile, build script,
Rust and WASI SDK. The downloaded binary hash and compiled source equality
were verified before repinning both wallet entry points. The new Linux hash
is `f184981b63377d286dabd792d375e2f2daaa337d27c7a50bb64c96d5f3d4b0d5`.

The first run failed the comparison with the local macOS artifact. The fresh
run [38948115956](https://github.com/tiagobeltraoacioli-sketch/gnb-smh/actions/runs/38948115956)
passed all applicable jobs, including the comparison, after the explicit repin (completed/success).
This run tested `1f55f934833fbdcff9d835072d05a5766934f087`; subsequent changes
only consolidate review and validation documentation. The known R3 cross-host byte mismatch remains
open; using the canonical artifact does not explain or repair it. The gate
was not weakened.

Local final site tests passed 67/67 and explorer API tests passed 21/21.
The full native node run completed with 1,771 passing executions, one failure
and eight ignores across 105 summaries; `--no-fail-fast` retained all targets.
The separate crypto invocation passed 479 tests with four existing ignores.
The oracle example passed 5/5 and the integrated differential matched all 672
requests. Address-fuzzer typecheck passed; it was not a fuzz campaign.

All 14 functional scenarios completed with jobs=1 and timeout=300 unchanged:
12 passed, none skipped, two failed. Partition/restart binding (R1-FUNC-1)
and peer settling after restart (R4-FUNC-1) remain open, as does the node
ingress assertion R4-NODE-1. There is no claim that the full local suite is
green. [Validation](validation.md) and the [machine-readable record](integrated-validation.json)
retain the commands, hashes and distinctions. Final CI and PR checks remain
separate gates; CI success does not erase these local failures.

PR #12 was merged at `2026-10-16T17:21:34Z`; its CI run 38938993837 finished
successfully only at `17:58:20Z`. The green result afterward does not satisfy
the required ordering of completed CI before merge. No PR merge was performed
by this round's coordinator.

Previously blocked PoWit/R7 and excessive-witness tasks remain incomplete
following automatic approval-review rejections for cybersecurity risk. They
were not retried or routed through these address packages. The new local
suite failure does not establish its cause or a new exploit.

Independent external audit and a bug-bounty program remain required before
any relaunch, consensus activation or bridge release. This round schedules
no activation and changes no consensus transaction or block verdict.
