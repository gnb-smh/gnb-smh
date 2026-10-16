# Round 4 secondary-wallet review findings

Base `70ca8a2`; worktree `gnb-r4-wallet-secondary-fix`, branch
`codex/r4-wallet-secondary-fix`. Reserved CGU **127**, isolated native target
`/private/tmp/gnb-r4-target-wallet-secondary` (no compiled changes planned).

Scope: medium review findings in `site/wallet/main.js` payment review and
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

Status: test-first implementation in progress. Primary `app.js` still has a
`tip_height + 1` fallback; this package does not claim to fix that separate path.
