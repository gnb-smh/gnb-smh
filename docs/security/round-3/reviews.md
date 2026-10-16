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
| Test strength / `evidence_baseline` | Limited approval with no blocking source/test issue. Runtime regression checks the actual return types; vector, live cleanup and non-Copy controls have appropriate limits. Initial reversal artifacts lacked a source snapshot/driver, so exact production-only provenance required a follow-up. |

The engineer supplied a [controlled replay](transport-key-ownership.md) with
[driver](replay-transport-key-ownership.py) and
[manifest](transport-key-ownership-replay.json). The coordinating engineer
separately checked all ten snapshot hashes and both log hashes against the
manifest; reversed `mod.rs` equals its base, and reversed `upgrade.rs` equals
its base plus the unchanged final test suffix. Corrected and restored files
are byte-identical. The replay has exit 101 with four passing controls and
the expected runtime failure, followed by exit 0 with all five tests passing.
This inspection is independent of the implementing agent but is not another
Cargo execution or the independent assessor's final scorecard update.

All reviewers retain the same limits: this protects repository-owned derived
keys and stream fields. It does not prove erasure of compiler/register copies,
HKDF/cipher internals, upstream Copy secrets or callers' retained arrays, and
does not lock pages. CRY-4 remains partially resolved.

## PQ-PSBT packages

Core/WASM, CLI/RPC and independent Python format packages are in implementation.
Their final three-lens reviews and integration results are not yet available.
