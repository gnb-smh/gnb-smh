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
controls passing; all four network/kind aliases and uniform uppercase route;
mixed case/markup/separators are rejected; explorers resolve aliases through
`validateaddress`; wallet links resolve through WASM; carryover aliases retain
network/identity and never silently return an empty balance for a known key.
Tests use bounded public data and no network attack simulation.
Production-only reversals retain final tests unchanged and restore exact bytes.

Reference: [BIP350](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki)
and `docs/ADDRESS-V2.md` from independent reference commit `a8e8b78`.
Review and integration evidence will be recorded after implementation.
