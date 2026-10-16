# Round 3 review ledger

These are package reviews, not a final round approval or numerical score.
All three transport reviewers inspected source, test artifacts and logs;
none claimed an independent Cargo rerun.

## Transport key ownership

Reviewed implementation `4ef8664f1261d0147e42d72ca1eab1bdac87f9f2`, integrated
as `8787ee2`. Evidence-only follow-up `54fd8ddab304bb417b8fe88e196123b9bd4670bc`,
integrated as `fbefc3d`; the follow-up changes neither implementation nor tests.

| Lens / reviewer | Finding and conclusion |
| --- | --- |
| Verdict safety / `review_verdict` | No actionable objection. Same HKDF inputs, labels, bytes and role directions; direct protected-owner transfers; authentication, framing, counters and consensus unchanged. Independently recomputed both vectors. |
| Path and cost coverage / `review_paths` | No actionable objection. Handshake errors occur before derivation; after derivation no await/error path extracts unprotected arrays. No new allocation, cryptographic operation or peer-dependent work; cleanup is fixed-size. Reviewed resolved zeroize implementations and existing stream destruction. |
| Test strength / `evidence_baseline` | Limited approval with no blocking source/test issue. Runtime regression checks the actual return types; vector, live cleanup and non-Copy controls have appropriate limits. The initial source-snapshot/driver gap is now closed by independent inspection of the controlled replay, including exact production-only reversal, final-test preservation and restoration. This is not an independent Cargo rerun. |

The engineer supplied a [controlled replay](transport-key-ownership.md) with
[driver](replay-transport-key-ownership.py) and
[manifest](transport-key-ownership-replay.json). The coordinating engineer
separately checked all ten snapshot hashes and both log hashes against the
manifest; reversed `mod.rs` equals its base, and reversed `upgrade.rs` equals
its base plus the unchanged final test suffix. Corrected and restored files
are byte-identical. The replay has exit 101 with four passing controls and
the expected runtime failure, followed by exit 0 with all five tests passing.
The independent assessor subsequently repeated those artifact checks and
inspected the driver and runtime assertions. All ten snapshot byte counts and
hashes, both log hashes, the Git base bytes, and the restored bytes at integrated
implementation `8787ee2967ab49626d965fb5d86d5e18f408c497` agree. The committed
driver and manifest also match their saved copies. Manifest SHA-256:
`2b6b509f6c1aa359b6419dd8494a45705ef49dfd4235797551f31f7240a5ba3a`.
The source/test provenance gap is therefore closed; the conclusion and limits
are recorded in the [independent scorecard](scorecard.md). This follow-up is
not another Cargo execution or final round approval.

All reviewers retain the same limits: this protects repository-owned derived
keys and stream fields. It does not prove erasure of compiler/register copies,
HKDF/cipher internals, upstream Copy secrets or callers' retained arrays, and
does not lock pages. CRY-4 remains partially resolved.

## PQ-PSBT packages

### Core, Python format and browser

Core production is `8cdb075`, integrated as `342e2f4`; evidence follow-up
`921e68f` is integrated as `582fbab`. Independent Python/specification commits
`a39e599` and `78fd072` are integrated as `1f6e829` and `0d97904`.
Browser tests/bindings are `fefb54b` plus `cb01e58`; final artifact/pin evidence
is `69faece`.

| Lens / reviewer | Finding and conclusion |
| --- | --- |
| Verdict safety / `r3_review_verdict` | Independently reproduced missing minimum-fee and MoneyRange checks in real WASM, with a valid positive control. After the fixes, reran the same harness against the verified Linux binary: both invalid cases refused, valid control signed/finalized, exit 0. Those two findings are closed in this scope; no global approval is inferred. Neither finding demonstrates a node-consensus split or loss of funds. Structural codec acceptance remains separate from signer checks. |
| Entry-path coverage / `r3_review_paths` | **Incomplete.** Automatic review rejected the additional witness-size reproduction task for possible cybersecurity risk. The task was stopped; no replacement attempt or fix was made. The finding remains open and this lens is not approved. |
| Test strength / `r3_review_tests` | Inspected test logic, source hashes, production-only mutations and logs without executing tests. Final core provenance gaps were closed: ten in-scope entries of the eleven-reversal manifest were checked, including candidate-state restoration; the restored full crypto log has 468 passes/four ignores and WASM host has 9/9. The 204 vectors plus 512 mutations support only the scoped codec comparison. Final browser evidence was subsequently checked: test hash `17b842…`, Linux binary/pin `4571dbc6…`, wrapper-only reversal and restored 4/4 agree. This does not complete the missing second lens. |

The shared-source fixes preserve consensus validation and structural format
rules. They add MoneyRange and the absolute fee floor before key callbacks,
the exact existing minimum-fee rule after witness construction, and an atomic
candidate validation before replacing a signed document. Full node input
availability, relay policy and long-lived secret handling are separate limits.
The common-signers restriction inherited from `PolicySpend` is documented.
The final Linux build does not resolve R3-BUILD-1 cross-host reproducibility.

### CLI/RPC frontends

Implementation `c3a6140` is integrated as `03757cc`; test/evidence follow-up
`1758dee` is integrated as `ec208a5`, without production changes. These reviewers read the
fixed commit and existing evidence; none ran new probes or changed production.

| Lens / reviewer | Finding and conclusion |
| --- | --- |
| Verdict/authorization / `r3_review_verdict` | No new blocking issue identified in the inspected frontend. Network, activation, selected UTXOs, amounts/scripts, maturity/relative locks, previous transactions and shared signing review precede the key callback. Preview precedes confirmation/key loading. RPC requires explicit authentication even on trusted local connections and exposes only public roles. |
| Entry-path coverage / `r3_frontend_paths` | No path found bypassing those checks. Legacy/PQ input converge on the same preflight; `--yes` skips confirmation only; missing selected rows fail closed. Snapshot checks do not reserve inputs. Positive signing tests use a helper/RPC fixture, not a complete live-node/TTY unlock-and-write journey. |
| Test strength / `r3_review_tests` | Baseline CLI/metadata failures and two production-only reversals are real; setup EPERM and fixture WouldBlock failures are excluded. Found and subsequently verified closure of two fixture gaps: coherent H-1/H snapshots now require the exact version rejection, and RPC parameters are checked. Follow-up manifest hashes match 15 CLI unit passes and restored CLI 3/RPC 7 passes. Production and the tests actually run in the reversals remain unchanged. Permit timeout while work continues is not dynamically tested; occupied/success/error cleanup are tested. |

The 64-selection storage measurements bound new metadata work; the old code
did not provide this feature and the reversal does not demonstrate an old
storage-cost violation. These measurements are not a resolved pre-existing
DoS finding. Round integration and exact-head CI remain separate gates.

## Build evidence follow-up

`evidence_baseline` independently compared the two retained baseline WASM
artifacts for R3-BUILD-1. Both contain 871,324 bytes, but their SHA-256 hashes
differ; the committed snapshot matches the baseline Git artifact. The
coordinator reports the local rebuild used Rust 1.94.1 and WASI SDK 25 on macOS.
The retained comparison fails by equality assertion. This assessor did not
rebuild WASM or identify the cause. The [scorecard](scorecard.md) preserves
this open reproducibility gap alongside successful Linux baseline CI; it
does not claim wallet-verdict or consensus divergence and assigns no cause
to unreviewed PQ-PSBT changes.
