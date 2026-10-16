# Round 3 validation record

This record distinguishes intermediate builds from the final reviewed PR.
No final integrated pass or merge readiness is established yet.

## Canonical WASM build delivery

The first branch CI run is
[38927549806](https://github.com/tiagobeltraoacioli-sketch/gnb-smh/actions/runs/38927549806),
at `fefb54bf7f293e752c953f134917395bda336410`. It intentionally retained the
previous committed binary while the new wallet source was rebuilt. The site
tests and WASM pin gate failed; the Python reference job passed. These
intermediate failures are not a green PR result.

The WASM job successfully rebuilt through `scripts/build-wallet-wasm.sh`,
uploaded `wallet-wasm-fefb54bf7f293e752c953f134917395bda336410`, and failed the
unchanged comparison against the old pin. The downloaded artifact and
manifest are under `/private/tmp/gnb-r3-linux-wallet-fefb54b`. The coordinator
checked the manifest's exact revision, Linux x86_64 host, Rust
`1.94.1 (e408947bf 2026-03-25)`, `wasm32-wasip1` target and wasi-sdk 25 archive
hash. Both the lockfile and build-script hashes match the Git blobs at that
revision. The binary's computed SHA-256 matches the manifest:
`a155c7b8ae879cca5e483685d18a5fb4d8e65698771b3e13ce800b658e975beb`.

This demonstrates successful artifact delivery despite a failing pin gate.
It does not resolve the separate macOS/Linux baseline mismatch R3-BUILD-1.
The intermediate artifact was not repinned: independent review identified
additional wallet checks that require another source build. A final pin
needs a fresh successful comparison and actual site/WASM tests.

## Review findings awaiting correction and retest

The independent verdict reviewer reproduced finalization of a fee-zero v3
document in the provisional WASM built from the initial core package. Its
real signed transaction was 8,440 bytes; the existing consensus minimum was
16,880 base units. No transaction was broadcast. This is a wallet
finalization failure, not a change to node consensus. Source inspection also
identified aggregate size after signing and monetary-range checks for
reproduction. Production fixes must follow their failing regression tests.

Final node, separate crypto, Python, site/deploy, functional, review and
exact-head CI results will be recorded after integration. Earlier round 2
platform failures remain in the scorecard and are not erased by these
intermediate checks.
