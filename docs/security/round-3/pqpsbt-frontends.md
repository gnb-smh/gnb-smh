# PQ-PSBT CLI/RPC and online policy-signing package

Base `f06b7f8dc05af107fd16f2cebdd89d62a360662a`; branch
`codex/technology-pqpsbt-frontends`. Codegen-units **61**, debug information
off, incremental off, normal Cargo target
`/private/tmp/gnb-technology-target-pqpsbt-frontends`. The shared core is being
implemented separately in `gnb-technology-pqpsbt`; do not edit its source.

## Reproduce before fixing

The existing `policysign` loads an untrusted spend JSON and then a wallet,
without using the configured RPC target to verify inputs/height/network or
showing a verified fee. Use synthetic fixtures and an existing CLI entry point
to show an actual runtime assertion failure before production changes. A
missing new API or compilation failure is not red evidence. Keep independent
positive controls and production-only reversals for any high finding.

## Scope

Implement CLI public-data PQ-PSBT role operations and online `policysign`
using the shared wallet core. Legacy policy-spend files may be imported into
PQ-PSBT, but their claims must be independently checked before opening a
keystore or invoking a signing callback. Fetch the node's network and next
block height and each selected unspent output, check values/scripts/outpoints,
fetch/hash full previous transactions for v1, and reject RPC errors, missing
or spent inputs, mismatches and v1 at the existing activation. Use existing
height/version functions. Do not alter partially signed transaction versions.
No consensus production change or new activation belongs in this package.

Show every input, input/output totals, actual fee and change before signing;
format base units exactly, with checked arithmetic. Apply a strict maximum
fee and explicit override, retaining a sensible default. Derivation labels
are not proof of ownership/change. A truncated getutxos response cannot prove
an absent input is unspent; fail closed when an input cannot be confirmed.
Coinbase maturity and policy locks must not be falsely reported as satisfied.
The observations are an online snapshot, not a reservation against a later
reorganization or spend.

Add a bounded, authenticated RPC entry point for public-data operations only
by delegating to the core implementation. Do not load/import wallet private
keys into RPC or expose signing. Preserve existing access/rate/body limits,
and test actual dispatch and refusal of private-key operations. Avoid adding
an RPC operation that performs an unbounded number of signature checks.

## Shared API contract

Module `gnb_crypto::wallet::pqpsbt` (re-exported through `gnb::wallet`):

- `PqPsbt { spend: PolicySpend, inputs: Vec<InputData> }`.
- `InputData { prevout: TxOutput, previous_tx: Option<Vec<u8>>, derivations: Vec<Derivation> }`.
- `Derivation { key_index: u8, fingerprint: [u8; 4], path: Vec<u32> }`.
- `from_policy_spend`, `from_bytes`/`to_bytes`, `from_json`/`to_json`,
  `update_input`, `combine`, `review`, `sign`, `finalize`.
- `SignContext { network: Network, next_height: u64, max_fee: u64 }`.
- `Review` exposes `total_inputs`, `total_outputs`, `fee`, `change`,
  `previous_transactions_verified`; `Finalized::extract() -> Transaction`.
- `public_request(&serde_json::Value)` supports public role operations;
  exact request schema must be coordinated with the core engineer.

Pass original JSON strings to the strict PQ-PSBT parser; do not first convert
the document to `Value`, which loses duplicate-key information. Surface
names/schema remain subject to explicit coordination before implementation.

## Acceptance

Unit and CLI/dispatch tests cover positive signing, 2-of-3 round trips,
failures before key access, network/height H-1/H, unavailable inputs, changed
values/scripts, fee limits, malformed responses, integer boundaries and
bounded requests. Cite the applicable signer/role defenses in BIP174/370.
Retain raw logs/source hashes and a replayable reversal driver. Three reviews,
full integration and CI are separate gates; no score is assigned by implementers.

## Frontend contract and migration

`gnb-cli pqpsbt request.json` runs an offline public role request. Requests use
`action` (`create`, `encode`, `decode`, `update`, `combine`, `review`,
`finalize`, `extract`) and the shared core's exact fields. A document is a
JSON **string** in `json`, `spend_json` or `input_json`, or canonical lowercase
binary `hex`; parsing a document into a JSON object first loses duplicate-key
information and is rejected. `network`, `next_height` and `max_fee` are needed
for review/finalization/extraction; heights and fees are decimal strings in
base units. `max_fee` is a ceiling, not a fee estimator. No public role imports
secret keys or signs.

`gnb-cli policysign document.json wallet.json [--max-fee GNB] [--yes]`
uses the configured RPC target for online preflight. Its default fee ceiling
is 0.02 GNB (2,000,000 base units), overridden only by the explicit option.
The preview lists every input and output, exact totals, actual fee, ceiling,
and change to the identical policy script. `--yes` skips the confirmation
prompt only; it does not skip preflight, preview, or any fee/height check.
Keystore access occurs afterward. Network and activation must agree with the
signer's compiled network rules, and v1 signing is refused at mainnet height
17,500; an imported transaction's version is never rewritten.

Legacy `PolicySpend` JSON is parsed strictly and converted into the core
PQ-PSBT object internally. A successful legacy-input command writes legacy
JSON again, allowing staged migration with existing `policysend`. A PQ-PSBT
JSON input remains PQ-PSBT JSON. Full previous transactions for legacy v1
signing are fetched and verified anew on every online signing pass; the
legacy file format cannot retain that metadata. Offline finalization uses
`pqpsbt` requests and does not broadcast a transaction.

The checks follow the public-data checks and preview responsibilities of the
[BIP174 signer role](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#signer)
and the separation of [BIP370 roles](https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki#roles).
GnB PQ-PSBT is a separate custom format, not a claim of Bitcoin PSBT binary
interoperability. Derivation labels never prove ownership or change.

## Online observation and cost boundaries

The optional third `getutxos` parameter is an array of at most 64 unique
`{"txid":"32-byte hex","index":u32}` outpoints. It adds `tip` and
`next_block_height` to the result and adds `spent_in_mempool` and
`confirmations_at_next_block` only to returned selected rows. It retains the
existing bounded address-index window and ordinary response by default.
Malformed/duplicate/over-limit selections fail before storage reads.

Mempool spends use the existing outpoint index. Confirmations use the same
consensus helper as admission, including selected-chain depth after the
activation. The applied storage tip must agree with the in-memory selected
tip; the response refuses a change of tip or next height during its lookup.
The CLI compares those values with getdaginfo both before and after all
preflight requests. A missing input in the 10,000-row maximum window is
refused, even if truncation could explain its absence. The implementation
checks selected coinbase maturity and relative locks; it does not claim that
these observations reserve the inputs against a subsequent spend or reorg.

The `pqpsbt` RPC method requires an explicit configured API key even for
trusted loopback/private callers. Existing Host/Origin, pre-auth budgets and
the 1 MiB ordinary request-body limit remain in force. RPC public operations
are capped at four inputs and sixteen present partial signatures before
cryptographic verification. A dedicated one-permit gate is owned by the
blocking worker, released on success/error, and remains held if an outer
response deadline expires while work is still running. Signature work is
performed by the existing blocking dispatch without holding node/DAG locks.
The offline core has larger limits and supports documents the RPC refuses.

The core's test-only counters on the actual verification functions measured
48 calls for four inputs with sixteen valid partials (three finalization
passes), and zero when either transport count limit was exceeded. These are
strict signature-verifier function invocations, not individual lattice
primitive calls. Frontend router tests also exercised the full positive budget,
refusal, authentication, body limit and permit release; timing is local
evidence, not a production latency promise.

## Evidence status

Baseline base `f06b7f8dc05af107fd16f2cebdd89d62a360662a`, with only
regression tests added, reproduced both absent defenses before any production
change or core import:

- `/private/tmp/gnb-pqpsbt-frontends-red-confirmed.log`: existing RPC command
  positive control passed; `policysign` failed the expected assertion with
  zero RPC calls and a wallet-password prompt (1 passed, 1 failed).
- `/private/tmp/gnb-pqpsbt-metadata-red.log`: the ordinary UTXO lookup positive
  control passed; optional metadata was absent and 65 selections were accepted
  (2 failed tests).
- `/private/tmp/gnb-pqpsbt-frontends-red-source-hashes.json` records source/log
  hashes. The first attempt hit sandbox bind EPERM and the second exposed a
  macOS nonblocking-socket fixture bug; neither counts as reproduction. The
  corrected fixture explicitly restores blocking mode and passed its control
  under an authorized local-socket run.

Imported core revisions are `26a4212`, `68f4a91`, and `8cdb075`; the last adds
MoneyRange/minimum-fee and atomic-signing checks after independent review.
The frontend does not maintain its own serializer or verifier.

Current green evidence (normal Cargo, isolated CGU61 target):

- `/private/tmp/gnb-pqpsbt-cli-entry-green-final.log`: 2 CLI preflight/control
  tests plus 1 public 2-of-3 role round trip passed.
- `/private/tmp/gnb-pqpsbt-cli-unit-final.log`: all 15 CLI binary tests passed,
  including 11 new policy-preflight tests.
- `/private/tmp/gnb-pqpsbt-rpc-complete.log`: 7 frontend RPC tests passed.
- `/private/tmp/gnb-pqpsbt-utxo-regressions.log`: 5 UTXO tests passed, including
  the existing iteration-bound/default contract.
- `/private/tmp/gnb-pqpsbt-dispatch-registry.log`: dispatch registry test passed.

For 80 returned ordinary UTXOs, default reads were 240. Selecting 64 added
66 reads before activation (306 total) and 258 after activation (498 total).
The tests count real storage reads, use consensus selected-depth metadata,
and refuse malformed/duplicate/65-input selections before storage access.
The positive full RPC finalization measured approximately 157–211 ms in these
local runs. This is not a production latency guarantee; the hard work bound
is the core's actual count of at most 48 verification calls and single flight.

`node/tests/support/pqpsbt_reversal.py` is the hash-guarded production-only
reversal driver. It preserves the final tests and restores source bytes in
`finally`, recording pre/reversed/restored hashes and runtime return codes.
Both reversals executed at production revision `c3a6140`: the CLI control
passed and the regression failed (1/1); four metadata tests failed for the
removed contract. Both runs returned 101 after executing runtime assertions.
The driver returned success, preserved test sources, and restored both source
hashes exactly. Restored green logs are
`/private/tmp/gnb-pqpsbt-cli-restored-green.log` (2+1 passed) and
`/private/tmp/gnb-pqpsbt-rpc-restored-green.log` (7 passed).

Review then strengthened the H-1/H unit fixture: getdaginfo and getutxos now
report matching height/hash at 17,500, and the assertion requires
`bad-txns-version` for version 1 at that height. The valid 17,499 control and
original transaction bytes remain. The fixture now also asserts the actual
RPC parameters: the policy script/network-derived address, exact selected
outpoints and window limit, and selected previous-transaction txids. These
are coverage improvements, not newly reproduced production defects. All 15
CLI tests passed again in
`/private/tmp/gnb-pqpsbt-cli-reviewed-params-green.log`. This test-only follow-up does
not alter production or any test executed by the reversal filters.

Hashes, exact runtime summaries and the restoration manifest are retained in
[`pqpsbt-frontends-evidence.json`](pqpsbt-frontends-evidence.json). The gate's
permit retention after an outer deadline follows ownership in the existing
blocking worker; this package did not add a runtime expiration/cancellation
scenario, and does not equate response timeout with cancellation of I/O.
Real synthetic-key callback signing and the CLI guard against premature
wallet access were exercised; an interactive encrypted-keystore/TTY password
journey was not executed in this package.

Three independent reviews, full integration and CI remain separate pending
gates; this package does not assign an audit score. Blocked PoWit/R7
reproductions were not resumed by this frontend test scope.
