# Round 3: transport key ownership and wallet tooling

Integration base: `f06b7f8dc05af107fd16f2cebdd89d62a360662a`, the merge of
PR #11. Branch `codex/security-round-3-20261016`; integration codegen-units
**59**, isolated target `/private/tmp/gnb-security-target-r3-integration`.
The final local round-2 evidence is preserved in [round 2](../round-2/validation.md):
node and separate crypto tests passed, while two macOS functional scenarios
failed. Subsequent successful remote runs do not erase those failures.

The user's technology-evolution instruction extends the original security
program. Its baseline is this same commit. Current packages are the narrow
CRY-4 transport ownership correction and PQ-PSBT/policy input verification.
Each package has its own worktree, brief and reproduction. Three review lenses
are required; the PQ-PSBT coverage lens is incomplete after an automatic
review rejection, as recorded in the review ledger.
No consensus production change or new activation is included at this point.

## Expanded acceptance ledger

| Technology front | Required outcome | Current status |
| --- | --- | --- |
| Synchronization | Verified headers, parallel PoW, constrained assumevalid, snapshot/background validation, compact blocks, safe pruning; measured 100,000-block IBD | Unimplemented in this round; prompt claims and performance estimates are not new measurements |
| Programmability | Hashlocks, composable policy language, complete timelocks, sighash modes, restricted covenants and tested payment channels | Open; consensus changes require specification, Python vectors, activation and every producer's boundary tests |
| Consensus | Accountable/convergent finality, deterministic mergeset application and rewards/undo, monotone activation height and platform evidence | Open; previously rejected PoWit reproduction tasks have not been retried |
| Wallet tools | PQ-PSBT roles across CLI/RPC/WASM, verified signer inputs/fee preview, descriptors, offline flow, coin selection/fee tooling, network-bound addresses and bridge checks | PQ-PSBT and online policy preflight implemented, with review/integration limits recorded; other requirements remain open |

The technology prompt supplies weights for only four of eleven categories
(10%, 10%, 15%, 5%). The remaining weights and a pinned comparator/rubric
are not established. Its approximate scores are user-supplied starting
assumptions, not independent findings. Neither technology nor security gains
a numerical score merely from completing a package.

The one-day activation preference remains recorded, but the previously
considered height 18,720 is not a scheduled production activation. Before
any consensus change, reread the actual tip and agree a rollout margin;
include only ready, independently reviewed changes. External consensus audit,
adversarial testnet validation and bug bounty remain required by the new
prompt before mainnet activation, and recommended before relaunch/bridge.

## Delivery status

Implementation and review are in progress. The Linux WASM was rebuilt and
repinned with actual browser tests; a fresh CI comparison remains required.
Full integration, independent scorecards and exact-head CI remain gates.
No PR for this round has been opened and no completion claim is made.
