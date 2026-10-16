# Round 4: address frontends (CRY-7 / technology 4.5)

Base: `7d6a67eafa93cf7935ecedb50d601486aca4cff7`.
Worktree: `gnb-r4-address-frontends`; branch `codex/r4-address-frontends`.
The package uses `CARGO_PROFILE_DEV_CODEGEN_UNITS=83` and
`CARGO_PROFILE_TEST_CODEGEN_UNITS=83`, with target directory
`/private/tmp/gnb-r4-target-address-frontends`. Crypto tests are invoked
separately from node tests.

## Scope and acceptance

Inspect and reproduce network handling in existing RPC and CLI address paths.
Only bounded, ordinary address fixtures are used. Change a deficient behavior
only after a runtime assertion fails on the frozen production code. Preserve
existing address generation, display and persistent identity. The additive core
API will parse Bech32m addresses (HRPs `gnb`/`tgnb`, format word 2, kind word 0
or 1) into the existing script, and expose explicit `to_bech32m()` methods.

Acceptance:

- RPC address queries reject the other network before storage access.
- Existing accepted legacy aliases and new v2 aliases resolve to the same
  script/index identity, without additional balance or UTXO records.
- Existing CLI destination checks keep rejecting the wrong network, and accept
  equivalent v2 forms through the shared core parser.
- A public, explicit conversion path exposes v2 without changing defaults.
- Positive controls, exact rejection behavior, production-only reversal and
  source/log hashes support the delivered result.
- Three independent review lenses remain required before integration approval.

## Initial inventory (not yet runtime findings)

`getbalance`, `getaddressinfo`, `getaddresshistory`, `listtransactions` and
`getaddressbalance_at_height` use `parse_address`, which discards the parsed
network. `getutxos` also discards the network from `destination_script`.
`validateaddress` has a separate legacy-only decoder, while
`validateaddressverbose` uses `Address::parse` without an expected network.

CLI `checked_destination` and `destination_on` already compare destination and
wallet/spend network; those protections are not presumed defective. Proposed
conversion surface: an additive `bech32m` result field from the existing
`validateaddress` and `validateaddressverbose` methods, only for valid addresses
on the node's network. Existing CLI `validateaddress` reaches the first method.

No consensus, activation, wallet persistence, core, Python, WASM or browser
source is owned by this package. Previously blocked PoWit, R7 and witness tasks
are excluded.
