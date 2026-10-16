# Round 4 independent review: test strength

Reviewer: `/root/r4_review_tests` (not a package implementer). Initial scope:
`7d6a67eafa93cf7935ecedb50d601486aca4cff7..6d9a719ac14f972dd030bd05af22f1c3161873e4`.
Follow-up reviewed and executed: `4037bba` (policy UI/test correction).
The separate WASM reversal evidence at `0ecdd9a` was inspected without changing
the package worktree. Review worktree: `gnb-r4-review-tests`; reserved CGU113
was not used because this review did not rebuild Rust.

## Findings and disposition

1. **R4 test gap: policy UI mocks overstated capabilities — corrected in
   `4037bba`.** At `6d9a719`, the watch-test adapter returned a legacy policy
   address from `normalize`, although the actual WASM normalizer only accepts
   `Address::parse` (single-key). The explorer adapter also returned history
   for policy addresses, although RPC history indexes remain single-key only.
   Those passing tests did not establish the claimed paths. The follow-up
   uses the pinned WASM for watch normalization, rejects legacy and v2 policy
   watch inputs, makes the RPC adapter reject policy history, and asserts an
   explicit unsupported-history result in the primary explorer. The second
   explorer retains policy UTXO queries. I independently reran both affected
   suites: 13 tests passed, no skips. See
   `site/tests/address-v2-web-paths.test.mjs:22`, `:40`, `:102`, and `:121`.

2. **Pin-generator coverage — corrected in `319f20b`; rechecked below.**
   `site/tests/address-v2-wasm.test.mjs:51` proves both committed pins load the
   committed binary. The reversal at `0ecdd9a` replaces the alternate pin,
   which correctly fails that test. It does not remove the new
   `pin_entry site/wallet/main.js CORE_SHA256` invocation from the build
   script; current pins can remain correct with that generator change removed.
   A bounded `--pin-only` fixture starting with two stale pins can protect this
   maintenance behavior, with a production-script reversal. This is a test
   gap, not a reproduced production security defect.

3. **RPC replay portability — corrected in `319f20b`; rechecked below.**
   `address-frontends.md:103` names original package baseline `23237fff...`,
   which is not an ancestor of the integrated review snapshot. A fresh clone
   containing only the delivered branch may not have that object. Integrated
   commit `ce61d7e` provides the equivalent test-only RPC production snapshot;
   use it in the replay command while retaining the original ID as historical
   provenance. I confirmed byte equality of `node/src/rpc/mod.rs` and
   `node/src/rpc/explorer.rs` between those two commits. This does not
   invalidate the locally verified log evidence.

4. **JSON oracle envelope coverage — corrected in `04b9348`; rechecked below.** The 630-request
   comparison at the initial snapshot covers the 502 address cases and 128
   positive encodes. Python's separate malformed-request tests are not sent
   to Rust by `address_v2_differential.py:18`. Consequently that comparison
   cannot establish agreement on JSON field/type handling. Another review
   reported this discrepancy; the coordinator is preparing the correction.
   The existing address-corpus result remains limited to its actual requests.

No new high/critical production finding was established by this lens. This is
not approval of the broader program or a numerical score.

## Evidence checked

- Core public regressions use APIs present before the production change;
  baseline runtime result is 1 legacy control passed / 3 v2 failures. Golden
  tests check legacy strings, scripts, networks, JSON and bincode. Rendering
  uses fixed independent values. Generic BIP350 vectors and recomputed-checksum
  padding/metadata cases supplement round trips; this is not only self-testing
  an encoder against its own decoder.
- Core reversals retain the final test bytes. Full entry-point reversal gives
  1 pass / 3 failures; removing checksum, padding and case checks gives 2, 1
  and 1 failures respectively. The diagnostic reversal gives 1 failure.
  The recorded restored runs pass. These guard deletions are a finite mutation
  sample, not a complete mutation-testing campaign.
- RPC tests call the real dispatcher, use funded storage fixtures, test both
  networks (testnet in a separate process), and assert zero storage reads on
  wrong-network rejection. The baseline reached runtime failures; reversal
  of the network guard gives 5 pass / 4 failures, baseline RPC gives 2 pass /
  7 failures, and restoration gives 9 pass / 0 failures. CLI tests call the
  actual destination helpers; 15 legacy controls and 2 v2 failures preceded
  implementation. They do not establish a live CLI/TTY/keystore workflow.
- Web reversals cover each changed source file and the combined baseline.
  Original mock-based policy acceptance claims are superseded by finding 1;
  those historical green logs must not be used as policy-wallet evidence.
  Worker tests prove forwarding and syntax routing, not checksum verification.
  The API carryover tests exercise the deployed decoder, including nonzero
  payloads and valid-checksum malformed encodings.
- The WASM tests load the actual pinned binary. They call the real payment
  operation at H-1=17499 and H=17500, with legacy controls, and independently
  decode the version, first output amount and destination script in Python.
  They reject the opposite-network destination. This proves the address-to-
  output mapping through signing; the Python decoder is not an independent
  signature verifier and the synthetic UTXOs do not prove chain unspentness.
- I verified all **45 log references** in the five existing JSON evidence
  documents against their local SHA-256 values. Some references are repeated;
  45 is not a distinct test/run count. I read the relevant runtime failures
  and test summaries. I also verified all **8 WASM reversal/build logs** from
  `0ecdd9a`: 3 runtime failures, 3 restored/control runs with 6/6 tests, and
  2 successful script builds. Its test-file hash matches this review snapshot.
  I did not rerun the Rust or WASM rebuild reversals independently.
- All current core source/test files named by the core evidence and reversal
  manifests match their recorded hashes. The two final RPC production files
  and the RPC/CLI test files likewise match the frontend reversal manifest.
  This connects those archived test runs to the files reviewed here; the
  pending oracle follow-up will require its own updated provenance.

## Independent focused execution

Commands ran in the review worktree at `4037bba`, using Node 22.23.3 and local
Python. No node connections or transactions were broadcast.

| Command | Observed result | Local log SHA-256 |
| --- | --- | --- |
| `node --test site/tests/address-v2-wasm.test.mjs site/tests/address-v2-web-paths.test.mjs` | 13 passed, 0 failures/skips | `9d6fb2a571fc89ef70fdab5fa063eb0f9c5909a2192634151c4965a2381a9dd2` |
| `python3 reference/address_v2_test.py -v` | 13 passed | `6882489351578e56cab16269c1efc11ed64dc0fa946d42f26995d20471746731` |
| `python3 reference/address_v2_vectors.py --check` | 502 vectors reproduced | `4ffe3027ccffaa7ca64b79f812f95cd8d745b82994e44ee159c6dd72a3b69903` |
| `python3 deploy/explorer-api/test_address_v2.py -v` | 5 passed | `75d41ef30d155308874cbb612be680112e90babba07877411386d0f1bedfc8eb` |

The four logs are `/private/tmp/gnb-r4-review-tests-{site,reference,vectors,api}.log`.
An additional independent, temporary check fed the corpus to deployed
`carryover_of`: all 128 accepted aliases mapped to the expected legacy identity
and all 370 applicable negative cases raised `ValueError`. Four caller-specific
`expected_network` cases were excluded because this lookup accepts either
network without a caller-specified network. The temporary check is supplementary
review evidence, not a versioned CI test. Its log is
`/private/tmp/gnb-r4-review-tests-api-corpus.log`, SHA-256
`fa2ead8f7483796e86a08cf2d3fdfaf35a0130db1605a2f03fc1c0ce391dd8f1`.

## Scope of acceptance

The reviewed CI diff actually invokes the Python reference, vector regeneration,
Rust/Python comparison and new explorer-API test. Existing site glob discovery
includes the new browser tests. Wiring a job is not evidence that a run passed.
No final round-4 CI run, full integrated node/crypto suite or canonical Linux
WASM comparison was available to this review at this snapshot. Those gates
remain coordinator-owned. The full core result in package evidence is separate
from these focused reviewer executions, and earlier permission/setup failures
remain preserved as such.

The finite corpus and 20,274 single-character substitutions do not establish
the requested ten-million-case consensus differential, full platform matrix,
or complete reference coverage. End-to-end live browser/node behavior, policy
wallet support and the known cross-host WASM byte mismatch remain outside the
proved result. No Bitcoin comparison or numerical category score is assigned.
Previously automatically rejected PoWit, R7 and excessive-witness tasks were
excluded; none was retried by this review.

## Follow-up review at integration snapshot `9226dad`

The follow-ups above are closed within their stated scope. Package commits
`04b9348` / `27b22d4` are integrated as `b1172ae` / `f1b3abe`;
the pin/replay follow-up is `319f20b`. I imported those exact changes into the
isolated review worktree, without modifying production.

- **Generator:** `wallet-build-pin.test.mjs` invokes the actual build script
  with `--pin-only` in an isolated directory containing both entry points with
  stale pins and a synthetic file. The expected hash is independently computed;
  both resulting pins must match, and the file must remain unchanged. This
  tests pin generation and does not pretend the fixture is executable WASM.
  My independent execution passed 1/1, log
  `/private/tmp/gnb-r4-review-tests-pin-generator.log`, SHA-256
  `2f33d685fa79e6c2346ee091c3944d9f42d0f565fb7f094ea972cfa6992dfb35`.
  I verified the test/source hashes and all three logs in
  `pin-generator-reversal.json`. Removing only the second `pin_entry` line
  yields 0 pass / 1 runtime assertion failure; restored and initial controls
  each pass 1/1. No test bytes changed during that recorded reversal.
- **RPC replay:** the documented baseline is now reachable `ce61d7e`, whose
  two production files I previously confirmed byte-identical to the original
  package baseline. Original run provenance remains preserved.
- **Oracle:** the final adapter's five tests retain an ordinary successful
  decode/encode control and cover the three exact disagreements. The
  differential additionally sends the 42 envelope requests to the actual
  Rust executable; it checks both verdicts and complete positive responses.
  I verified source hashes, all seven evidence logs, the independent original
  reproduction record, and both reversal logs. The reversal reaches 2 pass /
  3 runtime failures and restoration reaches 5 pass / 0 failures with identical
  tests. My fresh execution of the differential using the recorded Rust binary
  passed **672 requests, zero divergences**, with binary SHA-256
  `c0837c304051f6716ab58c102b1918eb150c5f92f2b4ddc2242b7fc338bfeb40`.
  Log `/private/tmp/gnb-r4-review-tests-envelope-differential.log`, SHA-256
  `5dd16c7ad56c7f2d5f62764187db7a206eeca6529a1b68f1fb0d7ba8b2d50d50`.
  This was an independent execution of the comparison, not an independent
  rebuild of the Rust artifact.

Two additional delivery details were reported to the coordinator:

1. **CI example-test execution is missing at `9226dad`.** Local
   `cargo metadata --locked --offline --no-deps --format-version 1` reports
   `address_v2_oracle` as `kind: ["example"]`, `test: false`. Cargo's local
   help distinguishes `--example` from the default test selection. The CI
   job currently builds the example and runs the differential, but has no
   `cargo test -p gnb-crypto --locked --example address_v2_oracle` invocation.
   Add that explicit command if the five Rust unit tests are to be a gate.
   The 672-request differential already executes the three corrected envelope
   scenarios; this gap does not erase that narrower coverage.
2. **New oracle replay portability:** `replay-address-oracle.py` hardcodes
   original package baseline `4b32fb6`, outside the delivered branch's
   ancestry. Integrated `887bd0b` has a byte-identical baseline adapter,
   independently confirmed with `git show`. Use a reachable baseline in the
   replay driver while retaining the original ID in archived evidence.

The path review has also reported two medium findings in the secondary wallet
(missing height forwarding and ignored testnet creation). They are under a
separate correction package and are **not closed by this addendum**. Pin and
address-codec checks do not establish both complete wallet journeys. The full
integration/CI/canonical-WASM gates and broader limitations above still apply.
