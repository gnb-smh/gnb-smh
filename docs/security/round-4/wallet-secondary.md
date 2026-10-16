# Round 4 secondary-wallet review findings

Base `70ca8a2`; worktree `gnb-r4-wallet-secondary-fix`, branch
`codex/r4-wallet-secondary-fix`. Reserved CGU **127**, isolated native target
`/private/tmp/gnb-r4-target-wallet-secondary` (no compiled changes planned).

Scope: medium findings **R4-PATH-1** and **R4-PATH-2** in `site/wallet/main.js` payment review and
`site/wallet/core.js` creation/network bindings. Only ordinary synthetic local
keys, previous transactions and API records are used. No broadcast or external
network request; no consensus, Rust, WASM binary, pin or bridge change.

Reproduce each defect with the actual pinned WASM before production edits.
Test the real secondary-controller callbacks at H-1/H, legacy/v2 destinations,
failed/malformed DAG next height (no tip-height inference), network mismatch,
coinbase maturity and unavailable previous transactions. The latter require
visible disclosure and an explicit user acknowledgement as in the primary
wallet. Mainnet default creation, recovery words and encrypted keystores must
remain compatible. Test explicit testnet creation and keystore reopening.

Acceptance includes final production-only reversals with tests unchanged,
three independent review lenses, integrated site checks and JS integrity
repinning by the round coordinator. No numerical score or release claim.

Baseline before production changes: Node 22.23.3
`--test site/tests/wallet-secondary.test.mjs`, exit 1, **2 pass / 13 fail**.
The actual core accepted the synthetic previous transactions at H-1/H, and
mainnet create/words/keystore recovery passed. Actual controller payment review
failed with `invalid next_height`; testnet creation returned `gnb1q`; the
wrapper ignored an explicitly requested testnet network when opening a mainnet
keystore, and the testnet gate entered that mainnet key. The latter is a related
medium network-binding/UI defect, not a cryptographic format change.
Log: `/private/tmp/gnb-r4-wallet-secondary-red-final.log`.

Test-first commit: `f330d6e`. Production and final tests: `8be30ee`.
The payment callback obtains `getdaginfo.next_block_height`, rejects missing
or malformed metadata before planning, rechecks maturity, fetches only the
planned pre-activation previous transactions and passes the same target height
to plan/pay. Its review discloses unchecked values and disables confirmation
until the user explicitly acknowledges them. Supplied previous bytes still
undergo the unchanged Rust checks. At H it uses the existing v3 commitment.

The JS wrapper now forwards an explicitly typed creation flag and optional
expected network for keystore opening. Existing no-argument creation and
two-argument opening keep mainnet behavior, including recovery words. The
secondary open callback selects the node's network. This uses the existing
Rust testnet key path (encrypted-keystore backup, no recovery words) without
changing cryptography, keystore format or compiled WASM.

Initial focused checks passed **15/15**. Existing `wallet-core.test.mjs` plus
the new test suite passed **23/23**, before one final strengthening of the
mixed-maturity assertion. These are ordinary local signed-data journeys;
they do not establish real-browser layout, live-node admission, broadcast,
network trust or complete bridge support. The tests execute real registered
controller callbacks and the actual pinned WASM inside a minimal DOM adapter.

Primary `app.js` still has a `tip_height + 1` fallback. That separate source
path is unchanged and has not been reproduced or resolved by this package.
The round coordinator must repin JS integrity metadata and run the integrated
site suite. Three independent review lenses remain required; no CI or release
approval is implied by the local checks.

## Final production-only reversal evidence

Run `python3 docs/security/round-4/replay-wallet-secondary.py /path/to/node`
in a dedicated worktree. The script restores production in `finally`, checks
the unchanged final test SHA-256, and records the exact failed test names and
log hashes in `wallet-secondary-reversals.json`.

| Production fragment restored to baseline | Passed | Failed | Exit |
| --- | ---: | ---: | ---: |
| Payment controller send region | 7 | 9 | 1 |
| `create` wrapper | 13 | 3 | 1 |
| `open` wrapper and network callsite | 11 | 5 | 1 |
| Complete correction restored | 16 | 0 | 0 |

All failures were runtime assertions of the intended missing behavior, with
the actual WASM loaded successfully. The final test file remained
`ed0b407363b624da4050cab3df251b6babe762766beef810e545d4b8ae980939`
through all four runs. Production was restored byte for byte. These reversals
support the three bounded fixes; they are not a full mutation-testing claim.

| Local log | SHA-256 |
| --- | --- |
| `/private/tmp/gnb-r4-wallet-secondary-red-final.log` | `0e5c30f36c8c871f778c97f9b6e9da5a462ef80ded3978fce9314541b4e07de3` |
| `/private/tmp/gnb-r4-wallet-secondary-compatible.log` | `5d2f0065ee83cc707f70ddd71e2d4459f5739f9b4eec1b0ab4f6fca45b6f1578` |
| `/private/tmp/gnb-r4-wallet-secondary-reversal-restored.log` | `2cd3952b2e1a598fd0056c158e5510136278324cbf7c241476b75a4b78d37078` |

Local implementation status: corrected with final focused tests **16/16**;
independent re-review and round integration are pending. No PR/push/merge.
