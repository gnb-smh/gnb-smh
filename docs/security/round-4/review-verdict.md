# Round 4 independent review: verdict consistency

Reviewer: `/root/r4_review_verdict`, 2026-10-16. Reviewed integration candidate
`2cb9980` against base `7d6a67e`, plus wallet candidate `299389a` and its tests
from `60b3c7e`. Worktree `gnb-r4-review-verdict`; native Cargo target
`/private/tmp/gnb-r4-target-review-verdict`, dev/test codegen-units **107**,
debug information and incremental compilation disabled. No production file
was changed by this reviewer. Only public synthetic addresses and local
transactions were exercised; no broadcast or external service was used.

**Initial disposition: changes requested for the two low-severity findings below.**
The follow-up at the end records their closure and two separately confirmed
medium-severity UI findings; initial observations are preserved.
No numeric score or whole-round acceptance is assigned. No consensus verdict
change or wrong-script mapping was identified in the reviewed diff and finite
tests. That observation is not an exhaustive proof or approval of other work.

## R4-V1: policy UI routes and mocks disagree with real capabilities — low, open

`site/explorer.js:101` normalizes a v2 alias and always calls
`getaddresshistory` at line 106. Its new route accepts both kinds at line 159.
However, `node/src/rpc/explorer.rs:524` calls the single-key parser at
`node/src/rpc/mod.rs:2625`; policy destinations intentionally remain invalid
for balance/history methods, as documented in `docs/RUNNING.md`.

The original web test passes because its RPC mock returns history success
for any address. `site/tests/address-v2-web-paths.test.mjs:86` accepts either a
history or UTXO call, so it does not establish a functional policy page.
With the same actual explorer functions and a mock that faithfully rejects
policy `getaddresshistory`, the ordinary single-key control passes and the
policy assertion fails: the sequence is `validateaddress` →
`getaddresshistory(gnb1m...)`; rendering is `Error: invalid address`. No UTXO
request is made. Command:

```sh
node --test /private/tmp/gnb-r4-review-verdict-policy-route.mjs
```

Result: exit 1, **1 passed / 1 failed**. This is a bounded UI reproduction,
not a live-node integration test. The endpoint's single-key restriction was
also inspected directly in the dispatcher and its tests.

The same package's watch tests at lines 104–108 model policy normalization as
successful, but actual wallet `Address::parse` intentionally accepts only
single-key destinations. With the exact `299389a` WASM and loader, both
policy legacy/v2 normalization reject. Executing both actual boot functions
with that loader enters watch mode for the single-key control and returns to
the gate for policy v2 (**2/2 observational tests passed**). Thus those mocked
policy watch assertions must not be cited as real wallet support.

Minimal resolution: expose a clear unsupported-policy-history state in the
first explorer without querying a single-key index, or use a dedicated UTXO
view without claiming history. Keep wallet watch capability explicitly
single-key and test policy refusal/fallback using the real WASM. Do not extend
consensus or invent policy history to satisfy the mock. The second explorer
already uses the full-script `getutxos` path.

Impact is unavailable/misleading UI coverage, not demonstrated fund loss,
signing bypass, acceptance of an invalid transaction, or a network mix-up.

## R4-V2: JSON oracle adapters disagree outside the corpus — low, open

The Rust oracle `crates/gnb-crypto/examples/address_v2_oracle.rs:33` ignores
unknown fields and treats a present `expected_network: null` as invalid.
The Python adapter `reference/address_v2.py:139` rejects unknown fields, and
line 141 treats a null expected network like the omitted field.

Built this candidate's Rust oracle locally. For the ordinary zero-hash
single-key decode, both implementations return exactly the same object.
Three additional bounded requests reproduce different `ok` verdicts:

| Request modification | Python | Rust |
| --- | --- | --- |
| Decode with `expected_network: null` | accept | reject |
| Decode with `unknown: 1` | reject | accept |
| Valid encode with `unknown: 1` | reject | accept |

The comparison assertion exits 1; exact requests/responses are retained in
`/private/tmp/gnb-r4-review-verdict-oracle-shape.json`. In contrast, the existing
corpus differential passes **630 requests / 0 divergences** because it never
uses those request shapes. That count is valid only for its present corpus.

Minimal resolution: specify one request-envelope contract, align both
adapters, and add these shape variants plus the positive control to the
executable differential. Keep the Rust decode path calling the production
unified destination parser. This finding concerns testing infrastructure;
it does not demonstrate any different address checksum, output script, or
consensus verdict between implementations.

## Checked boundaries and compatibility

- The Rust v2 selector is disjoint from exact legacy prefixes. Both public
  parsers reject the other kind; `destination_script` returns the existing
  20-byte hash or `02 || policy_hash`. Encoding, length, padding, mixed-case,
  checksum and network checks agree on the finite vector corpus. Uniform
  uppercase maps to the same canonical lowercase v2 output.
- Existing `Display`, serde fields and legacy encodings are unchanged.
  `address_v2` golden tests cover both networks, policy and single-key
  scripts, legacy hex case and Bloch alias identity. Changes do not touch
  transaction serialization, sighashes, script validation or activation.
- RPC network checks share `require_rpc_address_network` before their address
  indices; `getutxos` retains the complete policy script. The intentional
  cross-network read-policy change is documented. CLI production behavior
  is unchanged and shares the core parser/network checks. I inspected the
  dispatcher/CLI tests; I did not independently rerun the full node suite.
- JavaScript/Worker routing is explicitly syntax-only. Alias normalization
  in the explorers calls the RPC; carryover has its own bounded checksum
  decoder because it does not query the node. Standalone API tests passed
  for both networks/kinds and preserved legacy table identity.
- Wallet `normalize` keeps legacy output by default and only renders v2 on
  an explicit format request. Unknown/nonstring format values are rejected.
  Actual WASM payments at heights 17499 and 17500 decode through the Python
  reference to the expected unchanged scripts/amounts and versions 1/3;
  a testnet recipient is refused by the mainnet wallet. These local offline
  tests use synthetic UTXOs and do not establish chain unspentness.
- Build-script changes pin both served wallet entry points. I ran the
  exact candidate binary/loader copied out of git into an isolated temporary
  tree, not a newly rebuilt binary. Canonical Linux reconstruction and fresh
  CI comparison remain required; the documented R3 cross-host issue remains.
- Added CI steps run the independent reference, vector regeneration, the
  Rust/Python differential and standalone API tests. I did not assert a green
  round-4 CI run or verify every platform in the requested long-term matrix.

## Independent executions

All Rust commands used `--locked --offline`, package `gnb-crypto`, and this
review's target/CGU; no `gnb` and `gnb-crypto` tests shared an invocation.

| Execution | Result |
| --- | --- |
| `cargo test -p gnb-crypto --test address_v2 --test address_v2_render` | exit 0; 4 + 3 passed |
| `cargo test -p gnb-crypto --lib address::bech32m` | exit 0; 4 passed |
| `python3 reference/address_v2_test.py -v` | exit 0; 13 passed |
| `python3 reference/address_v2_differential.py <review oracle>` | exit 0; 630 requests / 0 corpus divergences |
| `node --test site/tests/address-v2-web-paths.test.mjs` | exit 0; 7 passed, subject to R4-V1 mock limitation |
| `python3 deploy/explorer-api/test_address_v2.py -v` | exit 0; 5 passed |
| Candidate WASM suite plus real policy-normalize rejection | exit 0; 6 existing + 1 reviewer check passed |
| Both actual wallet boot functions using candidate WASM | exit 0; 2 capability checks passed |
| Policy explorer route with faithful RPC rejection | exit 1; 1 control passed / 1 failed |
| Oracle request-envelope equality | exit 1; control agreed / 3 divergences |

Node version: 22.23.3. The WASM temporary suite changes only fixture paths to
read the frozen candidate and local Python reference, plus the stated
policy-rejection check. Production-only reversals are the implementers'
separate evidence; this lens does not assert they ran merely from inspection.
No prior automatically rejected PoWit, R7 or excessive-witness task was
retried. Full integration, the other review lenses, canonical CI and findings
closure are still required before delivery acceptance.

### Evidence hashes

- crypto tests: `/private/tmp/gnb-r4-review-verdict-crypto.log` — SHA-256 `87b2224d5c856cdc1e1c35e7dd113e3a2771ce48d1db10af0b427d4f579f56f4`.
- codec unit tests: `/private/tmp/gnb-r4-review-verdict-bech32m.log` — SHA-256 `baa42f0251fc61c94da3d8662af20d04048cafb7746327dfedf541c2eff199e5`.
- reference: `/private/tmp/gnb-r4-review-verdict-python.log` — SHA-256 `7fbd9309a535f01b422d08b8d875e1c6ae8c66ebaf040d96508fe36d22e6b087`.
- differential: `/private/tmp/gnb-r4-review-verdict-differential.log` — SHA-256 `52117b672f6ee130a4bcebf8c0d7906aa07de10e3538e1a598fc2745056111ed`.
- web tests: `/private/tmp/gnb-r4-review-verdict-web.log` — SHA-256 `ffcb25c3f98310117cc978e21c8cae19a0a24208b0d66ff4739aa5566f16d374`.
- API tests: `/private/tmp/gnb-r4-review-verdict-api.log` — SHA-256 `e106cd416361d7d3832e5fc173f8e74d8f8849477c9153136632dace49a0ab62`.
- WASM tests: `/private/tmp/gnb-r4-review-verdict-wasm.log` — SHA-256 `1f0e7c3f45b23526b0ddc37144d4223ebf3a2c4a0b2644f63ad902cdfa399dc8`.
- policy route reproduction: `/private/tmp/gnb-r4-review-verdict-policy-route.log` — SHA-256 `a6f5036e8ae6602970356b89c4b540bbb233a72be52917e12f3a40646366fe36`.
- real WASM watch checks: `/private/tmp/gnb-r4-review-verdict-real-watch.log` — SHA-256 `934e47dbe843b453ea726d05a06fba6f7653ce2d77d3ff89164b18865999d470`.
- oracle request divergence: `/private/tmp/gnb-r4-review-verdict-oracle-shape.json` — SHA-256 `d64d70454f030ca88da14566a9e43a1af792613ec484ad8d2bd99409831a856a`.

## Follow-up: original findings resolved; secondary wallet findings confirmed

Reviewed `4037bba`, `04b9348` and `27b22d4` as integrated at `f1b3abe`.
Those existing commits were merged into this reviewer worktree without
editing production; the report's initial evidence is retained above.

**R4-V1 resolved within the documented capability scope.** The main explorer
now renders an explicit policy-history-unavailable message before attempting
the single-key index. It does not assert an empty history or that the valid
address is invalid. The tests enforce that no history query occurs for that
kind. Both watch boot adapters now call the real pinned WASM and correctly
assert policy rejection/fallback. Independently reran the revised web suite:
**7 passed, exit 0**. Policy history and policy wallet watch support remain
unimplemented, as the corrected tests and UI now state.

**R4-V2 resolved for the specified JSON-envelope contract.** The Rust adapter
now rejects unknown fields and matches the Python null/absent network
semantics. The documented contract includes required fields/types, and the
differential adds 42 envelope requests, including all three reviewer cases.
Independently ran the updated driver against the supplied candidate binary:
**672 requests, 42 envelope cases, zero differences, exit 0**. Its reported
SHA-256 is `c0837c304051f6716ab58c102b1918eb150c5f92f2b4ddc2242b7fc338bfeb40`,
matching the coordinator's frozen artifact. Also independently compiled and
ran the example unit tests in the reviewer's CGU107 target: **5 passed,
exit 0**. Neither result claims arbitrary JSON grammar fuzz coverage.

As the second reviewer for `review-paths.md` findings, I inspected the actual
caller and independently ran only bounded local fixtures with real WASM:

- **R4-PATH-1 — medium, confirmed open.** The actual `viewSend` Review callback
  in `site/wallet/main.js:314` omits `nextHeight`; the wrapper serializes
  `undefined`, and the WASM returns `invalid next_height`. The identical local
  key, single synthetic UTXO and recipient produce a v3 payment with an
  explicit height 17500, proving the fixture itself is usable. The callback
  shows the error and no confirmation button. The reproduction completed
  successfully because it asserts the observed defect; it does not claim a
  working UI. This is an availability/integration failure, not acceptance of
  an invalid transaction or demonstrated fund loss.
- **R4-PATH-2 — medium, confirmed open.** Beyond rerunning the initial direct
  wrapper observation, I executed the actual registered `#create` callback
  (`site/wallet/main.js:239`) using the real WASM and real keystore export.
  A mainnet control produces `gnb1q`; setting `net.testnet=true` still produces
  `gnb1q` and enters key mode. Both download calls were captured locally, not
  written or transmitted; no secrets were logged. The existing wrapper's
  zero-argument `create` drops the boolean. This confirms the displayed
  testnet creation workflow selects the wrong network, but does not establish
  a wrong-network spending bypass.

Commands use Node 22.23.3:

```sh
node /private/tmp/gnb-r4-review-main-wallet.mjs <review-worktree>
node /private/tmp/gnb-r4-review-verdict-create-callback.mjs <review-worktree>
```

Both observational scripts exit 0 on `f1b3abe` while asserting the defects.
No broadcast was attempted; the payment adapter rejects any broadcast call.
A new correction package is pending. Its actual UI callbacks must be tested
with the real core, including H-1/H, explicit selected network and existing
maturity/previous-output checks before these findings can close. Merely
passing direct-core address tests cannot close these caller defects.

Current verdict: the two original low findings are resolved; the two medium
secondary-wallet findings remain open at this reviewed revision. Canonical
Linux WASM reconstruction, final integrated/native tests and CI remain
separate delivery requirements. No numerical score or overall approval.

Follow-up evidence SHA-256:

- `/private/tmp/gnb-r4-review-verdict-web-followup.log` — `6653947bfcc2a781ac8369f2863d12b718ab0f6daa3d9ecedacc51c558f01e93`.
- `/private/tmp/gnb-r4-review-verdict-oracle-followup.log` — `5dd16c7ad56c7f2d5f62764187db7a206eeca6529a1b68f1fb0d7ba8b2d50d50`.
- `/private/tmp/gnb-r4-review-verdict-oracle-followup-unit.log` — `d4ea69e342ba65384c766cd90f3074049bf0bcad30d2ffff8bcf364e688bf99f`.
- `/private/tmp/gnb-r4-review-verdict-secondary-confirm.log` — `64f29adacd06be01676b6017c9859323de4426ee5f8d3ee6fe66792cae266538`.
- `/private/tmp/gnb-r4-review-verdict-create-callback.mjs` — `de3dbe542889f15fb09a54267af2c717b7188966154a114a6232f7f8a93dd05c`.
- `/private/tmp/gnb-r4-review-verdict-create-callback.log` — `a046f8495c72af930c6c2731b2f6a4d323b1929b5dc3b31f31413720a2dda0af`.

## Secondary-wallet correction review

Reviewed the frozen test-first package `f330d6e` and correction `8be30ee`
(local cherry-picks `a19005e` / `3e4d740` on this review branch), not the
implementer's temporary reversal state. The production diff changes only
`site/wallet/main.js` and `site/wallet/core.js`; Rust consensus, signing and
WASM bytes are unchanged by this correction. I did not edit production.

**R4-PATH-1 resolved in the secondary payment workflow.** The actual Review
callback now obtains `getdaginfo.next_block_height`, validates it as a positive
safe integer, and uses that exact height for maturity selection, planning and
payment. Failed/missing/malformed height data produces no plan or signature;
it does not infer a height from the tip. Selected v1 previous transactions
are fetched and passed to the real core. Invalid supplied bytes are refused;
unavailable records remain visibly unverified. The confirmation starts
disabled and its handler separately refuses to proceed without the explicit
acknowledgement. Mainnet H-1/H tests exercise the actual callback and real
WASM for both legacy and v2 recipients, with verified inputs and no broadcast.

**R4-PATH-2 resolved for explicit testnet creation.** The wrapper forwards a
strict boolean `testnet` argument. Actual secondary create/download/open
callbacks produce and recover the same testnet identity. Mainnet remains the
default, including its 24 recovery words and keystore/phrase round trips.
The existing Rust testnet path generates a random key backed up by its
keystore; this review does not claim testnet recovery-phrase support.

**Related open-network variant resolved.** The secondary open callback states
the selected node network; the shared wrapper validates and forwards it.
A mainnet keystore is rejected under explicit testnet context by both the
wrapper and actual gate journey. Correct-network opening still succeeds.
This reaches the existing authenticated network check in Rust rather than
relabeling a decrypted key. Invalid network/create argument types fail before
changing the current session. The primary caller's default remains mainnet.

Independent executions (Node 22.23.3, all local and synthetic):

- `node --test site/tests/wallet-secondary.test.mjs`: **16 passed, exit 0**.
  Includes positive fixture controls, actual H-1/H callbacks, wrong-network
  refusal, absent/invalid next height, maturity boundary and malformed
  coinbase metadata, missing/invalid previous transactions, acknowledgement,
  creation and authenticated reopening.
- `node --test site/tests/address-v2-web-paths.test.mjs
  site/tests/address-v2-wasm.test.mjs`: **13 passed, exit 0**. This checks the
  existing address/watch/payment behavior against the shared wrapper change.
- Three additional reviewer variants: **3 passed, exit 0**. An exact decimal
  string height is normalized correctly; a one-satoshi discrepancy between a
  supplied previous transaction and the claimed UTXO value refuses signing;
  a real testnet key at height 1 produces v3 for both testnet representations
  and refuses a mainnet recipient. These run the same real secondary callback
  with ordinary local chain fixtures, not a live node or browser.

The first run of the additional variants had 18 passes and one failed
assertion: my error-message regex omitted the actual message's words
`refusing to sign`. Production already refused that mismatched value and
created no payment. I corrected only the temporary test's wording assertion
and reran the three reviewer variants. Both logs are preserved; this was not
an additional production defect or a failed production correction.

No broadcast was performed; generated keys and keystores were confined to
local fixtures and not logged. The DOM adapter is not a full browser. The
primary wallet's separate height-fallback behavior, bridge workflows and
live-node synchronization are outside this correction review. Final SRI
refresh, canonical Linux WASM/CI, integrated native suites and the other
review lenses remain required. Those delivery gates are not implied by the
local closure of these specific findings. No score or consensus activation
change is asserted.

Correction-review evidence SHA-256:

- `/private/tmp/gnb-r4-review-verdict-secondary-fixed.log` — `4f2b4b5dc282aeb1ad7e83bd76970a34545259e88343969d3e9afec96ca3018e`.
- `/private/tmp/gnb-r4-review-verdict-address-followup.log` — `978e961e896940ff4d6cadc370ae224db8a7e492e48f0916ce4cd97baae3c1e9`.
- `/private/tmp/gnb-r4-review-verdict-secondary-variants.mjs` — `deb9754572bb0e0e723996f4257cba216caae4f591c5b8630ac48abf685f3fbe`.
- `/private/tmp/gnb-r4-review-verdict-secondary-variants.log` — `9a5a60057ac021a0d49bf20734b75cea922fc6bc162366aa18d124090c787f14`.
- `/private/tmp/gnb-r4-review-verdict-secondary-variants-fixed.log` — `5a2d8dc21e31de6a7e9af7beea3f85eeb6d6c64b0ab79f522c75574789a42703`.
