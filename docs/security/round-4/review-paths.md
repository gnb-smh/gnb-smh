# Independent review: address-v2 paths and variants

Reviewer: `/root/r4_review_paths`, lens 2. Initial production revision:
`796825e` (diff from `7d6a67e`). Follow-up `4037bba` was independently
reviewed and tested in this worktree as `dce646b`. Review target uses CGU109
and `/private/tmp/gnb-r4-target-review-paths`; no production edits were made
by this reviewer. This is a bounded address-format review, not an audit of
the entire wallet or a claim that the round is ready for deployment.

**Current local status:** the follow-up review below supersedes the initial
open statuses. R4-PATH-1, R4-PATH-2 and the related R4-PATH-5 opening variant
are corrected by `8be30ee` in the exercised paths; R4-PATH-4 is corrected by
`04b9348`. Integration, reversal evidence and CI are separate delivery gates.

## Findings

### R4-PATH-1 — medium, open: secondary wallet cannot review a payment

`site/wallet/main.js:314` calls `c.pay(st.spendable, to, amount, "0")`
without the next-block height. `site/wallet/core.js:88` converts the absent
argument to the string `"undefined"`; the actual WASM parser at
`crates/gnb-wallet-wasm/src/lib.rs:424` refuses it as `invalid next_height`.
The served `site/wallet/index.html` loads this entry point. Restoring its
WASM pin makes it load, but does not restore its payment workflow.

Runtime reproduction executes the real `viewSend` source and its registered
Review callback in a minimal DOM adapter, with the pinned WASM, a generated
local key and one synthetic UTXO. A control payment using the same key,
recipient and coins with explicit height 17500 succeeds as version 3.
The actual callback displays `Error: invalid next_height`, without a
confirmation action. No transaction is broadcast and no secret is logged.
This is a pre-existing caller/core API mismatch exposed by the corrected pin,
not a Bech32m or consensus-validation defect. Both legacy and v2 recipients
use the same missing-height call.

Required resolution: obtain the actual target height, preserve maturity and
previous-transaction validation, and test this callback at H-1 and H with
real WASM. A test that calls `core.pay` directly with an explicit height does
not cover the UI caller. Until corrected, the two served wallet payment
journeys must not be described as complete.

### R4-PATH-2 — medium, open: secondary testnet creation ignores the network

`site/wallet/main.js:239` calls `c.create(net.testnet)` and presents generation
for the node's network. `site/wallet/core.js:77` declares `create: () => ...`
and forwards no network. With the actual pinned WASM, `c.create(true)` returns
a `gnb1q` mainnet address. This is also a pre-existing caller/core mismatch,
not a new address checksum failure. The reviewer did not establish any
wrong-network spend acceptance or loss of funds. The established defect is
incorrect network selection in the displayed creation workflow.

Required resolution: pass an explicit supported network through the creation
API, or explicitly restrict that served UI's supported network. Test the
real create callback and the resulting key/address network.

### R4-PATH-3 — low, corrected by 4037bba: tests invented policy capabilities

The initial web adapter fabricated successful policy-address normalization,
although WASM `normalize` accepts only single-key `Address::parse`. The main
explorer also queried the single-key history RPC for policy destinations.
The follow-up now invokes real WASM for watch tests, verifies policy refusal,
and displays an explicit unavailable-history message before querying the
main explorer's history RPC. The second explorer retains its supported full
script `getutxos` route. The revised seven web tests pass. This corrects the
capability claim; policy wallet support and policy history are not implemented.

### R4-PATH-4 — low, open at reviewed revision: oracle request-envelope drift

Independent runtime requests confirm two differences outside the 630-case
address corpus: an extra field on decode is rejected by Python but accepted
by Rust; explicit `expected_network: null` is accepted by Python but rejected
by Rust. The address codec itself agrees on the existing bounded corpus.
The coordinator reported an envelope follow-up in progress; that follow-up
has not yet been reviewed in this report revision.

## Positive evidence and limits

- The Rust codec shares the same destination script mapping for both kinds
  and networks. Legacy formatting/serialization remain the default. The
  single-key and policy public APIs reject the opposite kind. Focused Rust
  integration tests passed 7/7, including 20,274 single-character candidates.
- A fresh CGU109 Rust oracle build compared 630 requests with the independent
  Python corpus: zero differences. Binary SHA-256:
  `494f1e1dd132ba76933442c8dce58afc5272190bafe1bf094a1a5cdfb733c0c4`.
- Python reference tests passed 13/13; standalone explorer alias tests passed
  5/5. An additional comparison of the deployed carryover decoder against all
  502 address strings yielded 132 accepts and 370 rejections, zero differences
  after omitting caller-specific network context. The four changed verdicts
  relative to the corpus's 128 positives are valid other-network addresses;
  this standalone carryover decoder has no caller network parameter.
- Initial focused web/WASM tests passed 13/13 despite R4-PATH-1, demonstrating
  the missing actual-send-callback coverage. After 4037bba the web tests passed
  7/7, including real-WASM policy refusal. Actual WASM payment tests cover
  mainnet H-1/H and wrong-network recipient rejection, not a live browser,
  node RPC or broadcast journey.
- Reviewed RPC paths use network checks before the address-index queries;
  indices retain hash/script identity rather than indexing address strings.
  Both networks have process-isolated RPC tests. This reviewer read those
  tests but did not rebuild/run the node suite independently.
- Worker and API shape checks are explicitly routing gates, not checksum
  authorities. Local carryover validates checksum/padding itself. Prefix-only
  bridge configuration paths remain outside this package and unchanged.
- Pin changes protect both served entry points, and the build script refuses
  a failed pin replacement. The reviewed artifact is the locally rebuilt
  macOS binary. Canonical Linux rebuild/comparison and final CI remain the
  coordinator's delivery gates; this report does not attest CI green.

No DoS campaign, PoWit/R7 test, excessive-witness task, production network
operation, PR, push or merge was performed by this reviewer.

## Local reproducibility records

Node 22.23.3 was used. The focused Rust invocation was separate from any node
invocation: `cargo test -p gnb-crypto --locked --offline --test address_v2
--test address_v2_render`. The new UI observations are reproduced by
`node /private/tmp/gnb-r4-review-main-wallet.mjs <review-worktree>`.
These local records do not replace a permanent failing regression test.

| Artifact | SHA-256 |
| --- | --- |
| `/private/tmp/gnb-r4-review-main-wallet.mjs` | `867ff637d62a265545113c35ab70138da1a26449371f945c3b642f21bc287e8a` |
| `/private/tmp/gnb-r4-review-main-wallet.log` | `64f29adacd06be01676b6017c9859323de4426ee5f8d3ee6fe66792cae266538` |
| `/private/tmp/gnb-r4-review-paths-node.log` | `fa1224d372b474fb95e14fba01162e7902300a0048fb2b9e61e8bd66b1af1b8b` |
| `/private/tmp/gnb-r4-review-paths-web-followup.log` | `e7cba33934c5bb0419eb7554be24186fb24350e2053bd3da1e66753883bd14f3` |
| `/private/tmp/gnb-r4-review-paths-crypto.log` | `880031abd80fa927fed0bcd565e308df2e2feca53e31231c9a62efb082bcc628` |

No numerical score is assigned. The open UI findings and the pending oracle
follow-up prevent an unconditional path-coverage approval at this revision.

## Follow-up review: secondary wallet and oracle

Reviewed test-first commit `f330d6e`, production correction `8be30ee`, oracle
correction `04b9348` and its evidence `27b22d4`. These were applied only in
the reviewer's own worktree (local reviewed head `4c749a3`); the implementer's
live reversal worktree was not read or changed. No production modification
was authored by this reviewer.

**R4-PATH-1: corrected locally.** `main.js:297` requires a positive, exact,
safe-integer `getdaginfo.next_block_height`; it does not infer that value from
the tip. `main.js:342` rechecks maturity, plans the selected inputs, fetches
the version-1 previous transactions and passes the same height/data to real
WASM signing. The actual Review callbacks pass for both legacy and v2
recipients at H-1=17499 and H=17500. The supplied tip height deliberately
disagrees, making a tip-based substitute observable. Missing/malformed height,
lookup failure, immature-only rows, another-network recipients and invalid
provided previous bytes do not reach a successful payment/confirmation.

Unavailable version-1 previous transactions remain explicitly unverified.
The actual review markup shows this status, disables confirmation, and the
handler itself refuses a click without the acknowledgement. The tests call
that handler directly as well as the disabled DOM button; neither triggers
the broadcast adapter. This is the existing disclosed-unverified-input policy,
not proof of chain unspentness or authenticity of an unavailable transaction.

**R4-PATH-2: corrected locally.** `core.js:81` forwards the boolean testnet
selection to the existing Rust implementation. Real testnet creation returns
`gnb1t`, downloads an encrypted keystore and reopens to the same identity.
The mainnet default still returns a 24-word recovery phrase and preserves
keystore/phrase recovery. Testnet uses the existing random-key path without
a recovery phrase; no testnet phrase capability is claimed.

**R4-PATH-5: medium related opening variant, corrected locally.** The old
wrapper also ignored an explicit expected network during `open`, and the
secondary gate omitted it. `core.js:75` now forwards only an explicit supported
network, while `main.js:227` selects the node's network. The real testnet gate
refuses the synthetic mainnet keystore; the mainnet gate accepts that keystore,
and the testnet gate accepts its own testnet keystore. Mistyped create/open
arguments are refused without replacing the existing session. The package's
test-first baseline records the former wrong-network acceptance; this review
independently ran the corrected real-WASM rejection and positive controls.

The combined secondary-wallet, address-WASM and web suites passed **29/29**
(16 secondary journey cases, 6 address-WASM cases, 7 routing cases), zero
skips. They execute real controllers and WASM with a small DOM/API adapter,
not a full browser or live node. An additional independent testnet Review
callback used a newly created testnet key, a v2 testnet recipient and string
`next_block_height: "1"` with an inconsistent tip 999. It produced version 3
with committed amounts, called only `getdaginfo`, and made zero broadcasts.
No external network request or broadcast was made in these checks.

**R4-PATH-4: corrected locally.** The oracle now rejects unknown request fields
and treats an absent/null expected network identically. Five oracle unit tests
passed in a separate `gnb-crypto` invocation. A freshly rebuilt CGU109 example
compared **672 requests**, including 42 envelope cases, with **zero differences**.
Its SHA-256 is
`45ce573c1b943f28c2aaa93f04589aa7ed58b47f48dbab7a12c032b921cfa857`.
The original 502-vector address corpus is unchanged. This is bounded
differential evidence, not continuous fuzzing or proof beyond the corpus.

| Follow-up artifact | SHA-256 |
| --- | --- |
| `/private/tmp/gnb-r4-review-paths-secondary-green.log` | `1d577d48716f07f99e50b5de41259311d6e917dcf20dd20714613888352ddbd0` |
| `/private/tmp/gnb-r4-review-paths-oracle-followup.log` | `8e57dc46a0e1367738e16d6cd098cb62c09b0c7b9fe3acb2ef2e868e4f1b97e4` |
| `/private/tmp/gnb-r4-review-paths-oracle-followup-differential.log` | `5a31a531f3cd4a2ba85856ec797971d91084410a5d72192e25479e7d349a9b8b` |
| `/private/tmp/gnb-r4-review-secondary-testnet.mjs` | `4f4f017e8fa530dd11a9b093fbe8250eeddde762ec9677a2bfc6fb6be1eb9327` |
| `/private/tmp/gnb-r4-review-secondary-testnet.log` | `4810dbec7545ac4884f986a8d5fdf547bde6602509413dca78c0562dc48154e0` |

No further blocking path defect was found within this bounded follow-up.
This closes the identified local caller/codec mismatches for lens 2, subject
to unchanged final code, the package's production-only reversals and integrated
validation. The primary wallet's separate tip-height fallback and legacy-only
bridge UI were not changed or approved by this follow-up. No global readiness,
CI-green or numerical-score assertion is made.
