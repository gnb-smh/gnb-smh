# Security hardening — round 1

Base: `7b02dccbaa9c9dac15b2a18c72c32fc29b2acb3c` (2026-10-16).
Integration branch: `codex/security-round-1-20261016`.

This round does not establish superiority over Bitcoin Core. The supplied
category values are hypotheses, not independently established ratings. See
[the independent evidence inventory](scorecard.md). No production age is
part of the assessment.

## Delivery rules

For each fix, first run a regression against unchanged production code and
observe the specified failure. Resource-limit tests count work or retained
data; elapsed time alone is insufficient. High and critical changes also
require a production-only reversal that makes the regression fail, followed
by restoration. Review separately for verdict consistency, input-path and
resource-limit coverage, and regression strength. Do not merge before the
complete CI run is green for the exact proposed commit.

Test `gnb` and `gnb-crypto` in separate Cargo invocations: the node's
`test-pow-limit` feature otherwise changes the crypto tests' ASERT path.
Rebuild and repin the wallet through `scripts/build-wallet-wasm.sh` whenever
compiled wallet code changes. Keep reports as text; do not commit binary
reports or machine-local logs.

## Packages

| Package | Worktree branch | codegen-units | Scope / status |
| --- | --- | ---: | --- |
| RPC | `codex/security-r1-rpc` | 19 | B1-R2-9..11; measured red/green, five production-only reversals, three final reviews; integrated as `91bb719` |
| Network | `codex/security-r1-network` | 17 | PEX portion of B1-R2-7; incomplete, automated review interrupted the assigned agent |
| PoWit | `codex/security-r1-powit` | 23 | No production changes; automated review blocked the assigned reproduction task |
| Test isolation | `codex/security-r1-test-isolation` | 31 | Reproduced global test-activation ordering failure; narrow Miri/FFI test compatibility correction |
| Integration | `codex/security-round-1-20261016` | 29 | Test-isolation and RPC packages integrated; full validation in progress |

Each package has a distinct target directory and uses at most two Cargo
build jobs. The original checkout is not used for integration.

## Activation 2 decision record

The owner requested a one-day update window on 2026-10-16. A read of
`https://gnb-smh.com/api/getdaginfo` during this session returned selected
tip height 15,628, blue work 34,065,753, first-hardening height 17,500 and
`hardening_active: false`. This is a single public explorer reading, not an
independent multi-node agreement check or a new trusted checkpoint.

At 2026-10-16 11:39:01 UTC, the ASERT schedule height was
`floor((now - 1_791_685_648) / 30) = 15_503`. Taking the greater of that
height and the observed selected tip, adding 2,880 blocks, and rounding up
to a 720-block epoch gives candidate **18,720**. Its schedule timestamp is
`1_791_685_648 + 18_720 * 30 = 1_792_247_248`, or
**2026-10-17 14:27:28 UTC / 11:27:28 America/Sao_Paulo**.

This is a candidate, not an activated or released consensus change. Block
production can reach a height earlier or later than its ASERT schedule.
Before integrating consensus changes, reread the live tip and confirm the
remaining update window. A candidate that is already too close must not be
silently reused. Testnet and regtest use height zero for the new rules.

All old verdicts below the eventual height must remain bit-identical. New
rules require byte-level specification, generated acceptance/rejection
vectors checked by Python, shared validation across entry paths, and valid
producer output at H-1 and H. No guessed release checkpoint is authorized
by the timing decision.

## Remaining acceptance gates

The full request remains open: accountable PoWit and quorum, partition
convergence and persistence, bounded state, a checked formal model, complete
Rust/Python differential coverage above 10^7 cases per CI round, the native
platform matrix, remaining R7/mempool/wallet/bridge items, crypto migration
and constant-time evidence, 150 functional scenarios, 100 fuzz targets,
release reproducibility and supply-chain gates. The independent inventory
records the evidence already present; existence of a test is not a passing
run, and a passing regression is not resolution of its whole category.

Release and bridge launch still require an external independent audit and a
bug-bounty program. Internal agents do not substitute for either.
