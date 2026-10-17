# Round 5 independent test-strength review

Reviewer: `/root/r5_review_tests`, independent of the implementation agents.
Base: `2848dcf6bd89a85afe4828042227c9a2c2b433f0`.
Reviewed integration: `0cb572b` (including the CLI/RPC production change).
Review worktree: `codex/r5-review-tests`; native CGU 179 was reserved but no
native build was performed by this reviewer.

Status: complete for the reviewed package, including final CLI/RPC production
and targeted reversals. The integrated live functional result and CI remain
separate pending gates, not inferred passes.
No new production defect was confirmed by this lens. This is a review of the
static public descriptor package, not a score or a finding that GnB exceeds BTC.

## Reproduction and controls

The credited core baseline is `baseline-valid-key.log`, not the earlier runs
with malformed fixtures. Its SHA256 matches `core-evidence.json`; the existing
normalization control passes and both new descriptor operations fail at runtime
with `unknown op descriptor`. The fixture checks the pre-existing hybrid public
key predicate before dispatch (`crates/gnb-wallet-wasm/tests/public_descriptors.rs:6`).
Synthetic public byte shapes establish accepted serialization, not possession,
signature validity or spendability. That limitation is explicit in the tests.

I inspected the CLI and RPC baseline logs supplied by the frontend implementer:

| Baseline | Result | SHA256 |
| --- | --- | --- |
| `/private/tmp/gnb-r5-frontends-cli-baseline.log` | one legacy control passed; six new CLI tests failed | `1c3982a4ffc16eddcf63b5a22d7593408377605c96233533207aa3110e9fcdbf` |
| `/private/tmp/gnb-r5-frontends-rpc-baseline.log` | one legacy control passed; four new RPC tests failed | `39fd0cad8ed05772e6d718e3380dbc1097bf223ceb74ca96d0b48b906701a557` |

The RPC child-process failure is also printed in its parent's log; it is not an
additional distinct scenario. The new live functional baseline receipt and its
four file hashes also match. That run passed `getbalance` before failing at the
missing `getdescriptorinfo`; it was run by the integrator, not this reviewer.

## Test strength by path

- Core identity tests compare descriptors with the existing address/policy/tree
  constructors, preserve raw/envelope bytes and ordering, and check both address
  encodings (`crates/gnb-crypto/tests/public_descriptors.rs:34`, `:72`). The
  BIP380 fixed vector at `:27` provides an external checksum control. These are
  stronger than create/parse roundtrips alone.
- Grammar negatives are also inspected under an otherwise valid checksum
  (`public_descriptors.rs:108`). Pool tests include a valid 64-entry control,
  65-entry refusal, an exact 1,048,576-byte valid JSON input and rejection with
  one extra byte (`:245`). Duplicate fields, escaped duplicate names, network
  mismatch, unknown fields, trailing bytes and duplicate scripts are covered.
- The raw WASM test starts a disposable real session, checks the public result,
  submits duplicate `op` in both orders and an escaped duplicate, and checks the
  same session after each attempt. A legacy last-field-wins control is retained
  (`crates/gnb-wallet-wasm/tests/public_descriptors.rs:66`).
- Actual pinned-WASM browser tests exercise both networks, all three kinds,
  public pool restoration in a fresh instance, and the absence of a signing
  session after import (`site/tests/wallet-descriptor.test.mjs:26`). The pkh
  script is checked with Node's independent SHA3 implementation. Policy/tree
  browser checks are roundtrips; their independent byte comparisons are in
  the Rust/Python campaign, not duplicated in the browser test.
- R5-VERDICT-1's final tests cover both an own serialization hook and a poisoned
  inherited hook, retaining a live session after restoring the prototype
  (`wallet-descriptor.test.mjs:81`, `:95`). The original ordinary-`op` cases did
  not cover this variant; the new tests close that regression gap. They do not
  claim protection against arbitrary JavaScript executed by a hostile caller.
- CLI tests invoke the real binary with closed stdin and no API-key environment.
  Positive controls precede refusal cases; export/import compares exact bundle
  bytes and order, existing destination contents remain unchanged, and the Unix
  symlink target remains unchanged (`node/tests/descriptor_cli.rs:47`, `:69`,
  `:105`, `:151`). The symlink test is Unix-only, so seven tests on macOS/Linux
  must not be reported as seven Windows cases.
- RPC tests use fixed independently generated checksums, all kinds and both
  networks, and verify zero storage reads. Testnet runs in a separate process
  to avoid process-global network contamination. Router tests retain the existing
  read-auth behavior (`node/tests/support/descriptor_rpc.rs:12`, `:62`, `:85`).
- The live functional test pins its pkh script, address and checksum from the
  independent fixture, then compares CLI/RPC, funds the public identity, imports
  its pool and checks balance/UTXO observation (`test/functional/wallet_descriptor_restore.py:17`,
  `:32`). This tests identity restoration, not spending-key recovery, ownership,
  historical scanning or persistent watch-only indexing.

The independent Python campaign compares full accepted responses, including the
canonical bundle string, and compares rejection verdicts without diagnostic text
(`reference/descriptor_differential.py:18`). It checks frozen request/response
SHA256 pins before comparing the oracle. The 362 fixed plus 128 generated
requests are finite coverage, not 10^7 requests or complete consensus coverage.
I verified the reference source hashes and all seven embedded log hashes in the
receipt; I did not rerun the Rust/Python campaign.

## Production reversals inspected

I read `replay-core-reversals.py`, `replay-descriptor-frontends.py` and the
receipts, and recomputed the logs' SHA256 values. The seven core pairs each
contain an assertion failure in a running test (exit 101), followed by a restored
pass (exit 0): dispatcher, checksum comparison, request-network comparison,
raw pool size, duplicate-aware pool parsing, unique pool scripts and the raw
WASM operation gate. All 14 log hashes, two original source hashes and two final
test hashes match `core-reversals.json`. The replay restores production bytes
in `finally`; no changed test file was credited.

The whole-JS binding reversal has one legacy control passing and six new tests
failing, then seven passing after restoration. Its hashes match `js-reversal.json`.
This demonstrates binding integration; removing the entire method alone would
not establish the serialization-hook correction's strength.

For that specific correction, I separately checked
`/private/tmp/gnb-r5-frontends-tojson-reversal.json` and both logs. Restoring only
the old binding at `f79421b` produces one passing control and two failures with
`wallet is locked`; restoring the correction gives three passes. Log hashes are
`dc20b355ea1cd0a96418e173498652a87c264c0bb1f20bf8586138d11d7b1f54`
and `033537e49824a86757f29555819219e571cff085cb843b3b13b579128f9999b5`.
The final unchanged test SHA256 is
`c87deea0b0950f86561781b4690a0d89c10825ac5e9e84bdc251f30ab3f17e36`.
The implementers/integrator executed these reversals; I inspected their evidence.

The frontend final receipt `/private/tmp/gnb-r5-frontends-final/results.json`
also matches its logs: CLI 7/7, RPC 5/5 and the known-method inventory test 1/1,
all exit 0. I verified both later frontend reversal manifests and all four log
hashes; their final test hashes match this review tree:

| Reversal | Old production | Restored production |
| --- | --- | --- |
| CLI binding | 1 passed / 6 failed, exit 101, `Unknown command: descriptor` | 7 passed, exit 0 |
| RPC binding | 1 passed / 4 failed, exit 101, missing `getdescriptorinfo` | 5 passed, exit 0 |

Receipts: `/private/tmp/gnb-r5-frontends-reversal-cli/results.json` and
`/private/tmp/gnb-r5-frontends-reversal-rpc/results.json`. CLI log hashes:
`52a9a4486563ac9a0286abe74b456e7de8f8eefb30d14e6bea87151c15116ff0`
and `b24a234987a70cced6d49e1bb5b12fff0969863d3e41050183bd1595bef8d417`.
RPC log hashes:
`4acb5c02a4dbd58d70b99515f0f2d16cb310d3d535db22b5e5517c34e91db460`
and `612092213206117c57904e9b183514a0f638c50ac751ef6bec51ec6beb7f4bb4`.

The implementer also isolated the output-file guard: replacing only
`create_new(true)` with `create(true).truncate(true)` leaves five CLI tests
passing and fails the existing-file and symlink tests at their refusal
assertions. Restoration passes all seven. I checked
`/private/tmp/gnb-r5-frontends-file-guard/results.json`, the unchanged final CLI
test hash and the logs:
`67e5bf3dda88627b5b948ccba6971839b6967a36ec85b8476aa26792238830b4`
(mutated, exit 101) and
`f1c2cb2485622ca7d040cf32d0777ae0f7d6ad2c3c42e38978aa2543e889c31c`
(restored, exit 0). The author's restored CLI source equals the reviewed
integration source. This targeted check establishes sensitivity to the
non-overwrite protection, beyond the whole-command reversal.

## Evidence limits and remaining gates

The descriptor-length test uses text that is also grammatically invalid
(`crates/gnb-crypto/tests/public_descriptors.rs:168`). It establishes refusal,
but does not isolate the early size guard or measure the cost saved by it.
By contrast, the pool's exact-size positive control and size-guard reversal
isolate its raw-byte rejection. No descriptor CPU/allocation DoS bound should
be inferred from these tests.

`descriptor_json` checks rejection, network binding and accepted-result
roundtrips. Its twelve classified seeds have a stable-test replay, but the
fuzzer does not call Python or establish independent script equivalence
(`node/fuzz/fuzz_targets/descriptor_json.rs:30`,
`node/tests/descriptor_seed_corpus.rs:5`). Differential comparison is a separate
CI step. Configuring this target is not evidence of a completed fuzz campaign.
Seven selected reversals are not a zero-surviving-mutants result for the diff.

Final integration, the new live functional pass, CI, canonical WASM release
checks and inherited findings remain the integrator's gates. No inherited
finding is closed by this review. Previously rejected PoWit/R7/excessive-witness
tasks were neither reopened nor executed.

## Checks executed by this reviewer

At `0cb572b`, without production changes:

- Node 22.23.3: `node --test site/tests/wallet-descriptor.test.mjs` — 7 passed,
  0 failed, 0 skipped, exit 0.
- Python 3.12.15: `python3 reference/descriptor_test.py` — 13 passed, exit 0.
- Python reference recomputation of all six hardcoded RPC fixture checksums
  (three kinds on each network) — exact match.
- Read-only SHA256 verification of the receipts and files described above.

The browser run used the actual pinned artifact SHA256
`d6dc794e7be5f4dfca7f4da05719f05adc4c762a93acd1b396e3a183bdc22569`.
No native Rust suite, reversal replay, live node, fuzz campaign or CI execution
is attributed to this reviewer.
