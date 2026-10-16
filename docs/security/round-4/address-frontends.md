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

## Runtime reproduction and implementation

The unchanged production baseline plus test harness at
`23237fff9531cba78461fd4a6b6c2d748564ad2c` produced 2 passing controls and 6
runtime RPC failures (`address_frontends` filter, exit 101). Correct-network
queries, legacy alias identity and malformed inputs are positive controls.
All six single-key queries accepted the other network; `getutxos` also accepted
the other network's policy address and selected-input lookup. The latter read
storage 6 times and returned a UTXO rather than rejecting the network. The
isolated testnet process reproduced the reverse direction. The old validator
accepted the other network, the basic validator rejected an otherwise supported
Bloch alias, and the v2/explicit conversion feature was absent.

This is a mismatch with the requested new RPC policy, **not** a demonstrated
consensus defect or signing bypass: `docs/RUNNING.md` documented the old
cross-network read behavior. The baseline CLI suite passed 15 existing tests,
including its network protections; only the 2 new v2 destination tests failed
at runtime with invalid-address errors. A legacy CLI network bypass was not
reproduced and no CLI production logic changed.

After those executions this branch imported core commits `40c321b`, `cf40773`
and `4b32fb6` (local cherry-picks `4f8ec88`, `2557286`, `606cbb6`). The RPC
implementation uses one network check for queries and both validators. It
checks `getutxos` before snapshot storage reads and retains the full policy
script as the index key. Balance/history APIs remain single-key only. The
validators expose `canonical_address` and `bech32m` without changing `address`
echoing, normal address generation or persistent data. Their validity field
means validity for the node's network; `checksum` remains syntactic.

Focused RPC tests passed 8/8 and the complete CLI unit binary passed 17/17.
The RPC matrix was then strengthened with wrong-network v2 variants on both
networks. Production-only reversal and independent reviews are still pending;
these focused results do not stand in for the integrated node suite or CI.

Scope limits: RPC tests exercise the real dispatcher with storage fixtures and
a separate process for testnet. CLI tests exercise its actual destination
helpers; they do not claim a new live TTY/keystore signing journey. Policy
balances/history and default v2 generation are not added. No score is assigned
by this package's implementer.
