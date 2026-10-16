# Round 4 address-v2 WASM wallet package

Base: `7d6a67eafa93cf7935ecedb50d601486aca4cff7` (draft PR #12).
Worktree: `/Users/tiagobulhoes/worktrees/gnb-r4-address-browser`.
Native codegen-units: **101**, isolated target
`/private/tmp/gnb-r4-target-address-browser`. Integration uses CGU97 separately.
This package is not part of the frozen round-3 PR.

Scope: the existing WASM normalization/payment boundary and both served
wallet entry-point pins. Browser routing, Worker and explorer API paths
have a separate package (`address-web-paths.md`). Bech32m addresses name exactly
the existing script and network. Legacy output remains the default; an
explicit conversion may request Bech32m. No consensus or activation changes.

Reproduce the missing paths with bounded offline tests and the committed
round-3 WASM before production changes. Keep a legacy positive control.
Test both sides of the existing transaction activation for actual WASM
payment, with synthetic local keys/UTXOs and no broadcast. Network mismatch
must still be refused. Compare actual decoded outputs, not only strings.
Python vectors are generated independently of the Rust codec. Format
syntax gates are not cryptographic or checksum validation claims.

Acceptance: public aliases normalize to the same legacy identity; valid
v2 paths reach the existing service; wrong network/checksum and malformed
inputs are refused at the authoritative boundary; legacy paths remain.
The compiled wallet must be rebuilt via `scripts/build-wallet-wasm.sh` and
repinned, with the fresh CI comparison retained. The known cross-host build
gap from round 3 remains open. Three independent review lenses and
production-only reversal precede integration. Previously rejected PoWit,
R7 and excessive-witness tasks are excluded and must not be retried.

Baseline on unchanged production `7d6a67e`: the original combined browser
suite (test commit `201e0f0`) had one legacy control pass and five runtime
failures. After separating web tests, the final WASM baseline also has one
pass and five runtime failures: v2 normalization (`BadPrefix`), ignored
explicit rendering format, stale `main.js` pin (integrity error), and real
v2 payment (`BadPrefix`) at both H-1=17499 and H=17500. Each payment's legacy
control first passed independent Python decoding of the version, amount
and destination script. No transactions were broadcast.

Commands: Node 22.23.3 `--test site/tests/address-v2-wasm.test.mjs`;
log `/private/tmp/gnb-r4-address-wasm-red.log`, exit 1, 1 pass/5 fail.
The stale-pin finding is an availability defect, not evidence of accepting
untrusted WASM. Its existing integrity check failed closed.

The shared core codec was imported through `4b32fb6`. The WASM binding now
accepts an explicit `legacy`/`bech32m` normalization format; absent format
keeps legacy output. The JS wrapper forwards it. Payment uses the existing
shared parser and network check with no signing or transaction-rule change.
The build script repins both `app.js` and `main.js`.

Local rebuild: `WASI_SDK=/private/tmp/gnb-r3-wasi-sdk-25
CARGO_TARGET_DIR=/private/tmp/gnb-r4-target-address-browser
scripts/build-wallet-wasm.sh`. Final local binary SHA-256:
`f17b140c82a5b8325da5d60a7d864430954f328f2cd30bd1b2fd77a3527c16c1`.
The focused test above passed **6/6**, including actual signed transactions
independently decoded by Python at both heights and wrong-network refusal.
Logs: `/private/tmp/gnb-r4-address-wasm-build-final.log` and
`/private/tmp/gnb-r4-address-wasm-green.log`. This is a macOS artifact; the
known R3 cross-host byte mismatch remains open, and final delivery requires
the existing canonical Linux rebuild/comparison gate.

Status: local focused implementation checks pass; production-only reversals,
independent reviews, integrated suite and canonical CI rebuild remain pending.
No acceptance or score claim.

Production-only reversals were subsequently completed at `299389a`:
removing the Rust format arm (with an actual script rebuild), JS forwarding,
or alternate-page pin each causes 5 pass/1 fail with the same final tests.
All restored controls pass 6/6. `address-wasm-reversals.json` records eight
executions (three failures, three passing controls and two rebuilds), hashes,
and exact restoration. `replay-address-wasm.py` reproduces this offline.

The test-strength review identified a separate generator coverage gap:
checking already-pinned artifacts did not exercise the script's second pin
update. `site/tests/wallet-build-pin.test.mjs` now executes the actual script
with `--pin-only` in a disposable file fixture with both pins stale. Removing
only `pin_entry site/wallet/main.js CORE_SHA256` fails that unchanged test;
restoration passes. See `pin-generator-reversal.json`. This adds regression
coverage; it does not claim a new production vulnerability.

Integrated site and API checks passed 50 and 21 tests respectively at the
pre-secondary-wallet-fix snapshot. The path reviewer then reproduced missing
height forwarding and ignored testnet creation in `main.js`/`core.js`; those
medium findings remain open until their separate package and three reviews
finish. Passing the pin test does not prove both full wallet journeys.
