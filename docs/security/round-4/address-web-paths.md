# R4 address v2 web paths

Base: `7d6a67eafa93cf7935ecedb50d601486aca4cff7`. Worktree:
`gnb-r4-address-web-paths`; branch `codex/r4-address-web-paths`.
Reserved codegen-units: **103** (this package runs JavaScript/Python only).

Scope: syntax gates, both explorer search/routes, both wallet watch links,
Worker forwarding, and standalone explorer API carryover normalization.
No default address generation, storage format, consensus, WASM, pin or bridge
change. The RPC/WASM codec remains authoritative for address validity; the
local carryover table must verify Bech32m before deriving its legacy key.

Acceptance: runtime tests first fail on the original source with legacy
controls passing; both network/kind aliases and uniform uppercase are recognized;
mixed case/markup/separators are rejected; explorers resolve aliases through
`validateaddress`; single-key wallet links resolve through WASM; policy watch
and indexed policy history remain unsupported. Carryover aliases retain
network/identity and never silently return an empty balance for a known key.
Tests use bounded public data and no network attack simulation.
Production-only reversals retain final tests unchanged and restore exact bytes.

Reference: [BIP350](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki)
and `docs/ADDRESS-V2.md` from independent reference commit `a8e8b78`.
Review and integration evidence will be recorded after implementation.

## Implementation and evidence

Production/test commit: `8525a0e64ee1b4f2f244ab0d2cb952ffc4c3bb2c`.
No Rust source or compiled artifact changed in this package.

- `site/assets/safe.js`: bounded syntax gate accepts both network/kind forms
  and uniform uppercase. It explicitly does not verify checksum. Mixed-case
  v2 is never lowercased before validation; legacy/hash search keeps its old
  case normalization.
- Both explorers call `validateaddress` for v2 before classifying prefixes
  or querying by legacy identity; invalid results never reach the data query.
- Both watch-link boot paths give the untouched alias to WASM and enter
  watch state with its canonical result. The existing watch input already
  calls the same WASM normalizer and required no routing change.
- Worker accepts the same syntax and forwards unchanged. The Python API's
  parameter gate is syntax-only; its local carryover lookup additionally
  verifies Bech32m and zero padding and derives the existing network-bound
  legacy identity. This decoder is embedded in the deployed script, with
  no dependency on the uninstalled `reference/` tree.

Before production edits, the focused JS run had one passing legacy control
and six runtime assertion failures. Python had five methods: two passed;
three failed (eight subtest ValueErrors for valid v2 rejected by the old gate,
four assertions including an empty carryover result for a known identity).
The final tests strengthened uppercase legacy search controls; a regression
introduced during implementation was observed and corrected before freezing.

`address-web-reversals.json` records seven separate production-file reversals,
then all production files together reverted to the baseline. Each returned
exit 1 with a runtime assertion failure. Final baseline JS: one pass/six fail;
final baseline Python: two methods pass/three fail. The final test files were
unchanged throughout; production was restored byte for byte. Restored suites:
**7/7 JS, 5/5 Python**, no skips. Replayer and hashes are versioned here; raw
logs are local `/private/tmp/gnb-r4-address-web-reversals/` artifacts.

Broader validation at this package's source revision:

| Check | Result |
| --- | --- |
| Explorer API `unittest discover` | 21/21 pass after loopback permission retry |
| Site `node --test site/tests/*.test.mjs` | 42 pass, 2 fail, no skips |
| Site loopback fixture retry | 2/2 pass |
| Site remaining failure | stale SRI after JS changes; integration must repin |
| `git diff --check` | pass |

The first attempt `node --test site/tests/` was a test-launch failure
(`MODULE_NOT_FOUND`), not a regression reproduction. The API's sandbox run
failed 16 socket binds with EPERM; the five new socket-free methods passed.
The site's one socket fixture likewise failed EPERM and passed after an
explicitly authorized loopback retry. All original negative logs and their
hashes remain in `address-web-validation.json`; these are not a claim of a
fully green site suite before integration repins its SRI.

## Limits and integration requirements

These routing tests execute real source functions/event handlers in a VM with
DOM and RPC/WASM adapters; they do not establish a live browser/node/WASM
journey. The independent WASM and RPC packages must supply the normalizer and
`validateaddress.canonical_address` contract, then rebuild/repin and rerun the
integrated suite. Add `python3 deploy/explorer-api/test_address_v2.py -v` to CI;
the existing explicit API test command does not discover this new test file.

No bridge vault configuration/parser changes are included; those legacy-only
paths are outside this package. The stale `CORE_SHA256` in wallet `main.js`
was reported to the integration owner, who owns all WASM/pin work. Independent
three-lens review and final CI are pending; no category score is assigned.

## Independent review correction (R4-V1)

The verdict reviewer reproduced a false capability in the original mock:
`getaddresshistory` and WASM `normalize` were both simulated as accepting
policy addresses, although their real contracts are single-key. A faithful
RPC stub produced 6 pass/1 fail; replacing the wallet stub with the actual
pinned WASM produced 4 pass/3 fail. Logs are
`/private/tmp/gnb-r4-review-policy-ui-red.log` and
`/private/tmp/gnb-r4-review-web-real-authorities-red.log`.

The main explorer now recognizes a policy address and displays that policy
history is unavailable before calling the single-key history index. The
other explorer retains its existing policy UTXO view. No fabricated empty
history or balance is rendered. Watch tests now execute the real pinned
WASM: single-key aliases enter watch state; both legacy and v2 policies
return to the gate. Policy wallet support was not added and is not claimed.
This is a low-severity integration/test finding, not a consensus or signing
bypass. The focused final suite passes 7/7. Production-only removal of the
new page guard fails the unchanged final test and exact restoration passes;
`policy-ui-reversal.json` records hashes and outcomes. Earlier package
manifests remain historical evidence for their recorded source/test bytes.
