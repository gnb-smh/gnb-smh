# Round 4 address-v2 browser and explorer package

Base: `7d6a67eafa93cf7935ecedb50d601486aca4cff7` (draft PR #12).
Worktree: `/Users/tiagobulhoes/worktrees/gnb-r4-address-browser`.
Native codegen-units: **101**, isolated target
`/private/tmp/gnb-r4-target-address-browser`. Integration uses CGU97 separately.
This package is not part of the frozen round-3 PR.

Scope: the existing WASM normalization/payment boundary, browser address
routes and syntax checks, Worker carryover paths and explorer-API address
parameters/carryover identity. Additive Bech32m addresses must name exactly
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

Status: brief and baseline tests only; no implementation or acceptance claim.
