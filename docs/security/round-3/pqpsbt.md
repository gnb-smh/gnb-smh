# PQ-PSBT and policy signing package

Baseline: `f06b7f8dc05af107fd16f2cebdd89d62a360662a`. Worktree
`gnb-technology-pqpsbt`, branch `codex/technology-pqpsbt-foundation`.
Use normal Cargo with codegen-units **53**, debug information off,
incremental off, and isolated target `/private/tmp/gnb-technology-target-pqpsbt`.
Run `gnb-crypto` separately from `gnb`. This brief is an implementation
assignment, not an assertion that the acceptance criteria have passed.

## Intended behavior

Implement the wallet interchange and signing flow requested in technology
front 4.1. A versioned binary PQ-PSBT and equivalent JSON carry the unsigned
transaction, chain/network, input values and scripts, policy/tree information,
optional derivation metadata, and partial signatures indexed by policy key.
Implement explicit creator, updater, signer, combiner, finalizer and extractor
roles, reusing existing transaction, policy, signature and sighash rules.
Reject conflicting metadata or signatures when combining; never silently
choose between contradictory claims. Describe supported input kinds precisely.
Do not claim general heterogeneous-input support if only the current
single-policy/tree spending flow is implemented.

The signer validates all input data before invoking any signing callback.
For v1, require and hash the complete previous transaction and compare its
selected output; v3 commits the values and scripts with the existing sighash.
The online `policysign` additionally fetches inputs from its own configured
node, rejects missing/spent/mismatched inputs, checks network and next block
height, shows each input, total input/output, effective fee and change, and
applies an explicit fee ceiling. Reject policy v1 at the existing hardening
activation. Do not rewrite a partially signed transaction's version. Reuse
the current activation/version functions and test H-1/H; no new consensus
rule or activation constant belongs in this package.

An offline signer cannot prove that an output is currently unspent. Its
interface must distinguish authenticated previous-transaction contents from
the online node's current UTXO observation; do not manufacture a verified
flag from untrusted JSON. Derivation metadata alone does not prove ownership
or that an output is change. Never include private keys in the format.

## Reproduction and format requirements

Before production edits, demonstrate the current missing behavior through
an executable test against an existing entry point (for a new operation,
an external interface test can show unsupported operation). Missing imports
or compilation errors are not reproductions. For existing signing defects,
use synthetic local keys and fixtures and observe an actual assertion fail.
Keep positive controls and document exact baseline, commands and output.

Specify the binary encoding byte for byte in a wallet-format document, with
magic, version, fixed integer endianness, bounded lengths/counts, duplicate
and unknown-field policy, canonical representation and trailing-byte rule.
Bound input before allocations and before signature verification. Preserve
exact unsigned transaction bytes and reject noncanonical/trailing transaction
encodings at the new wallet boundary without changing consensus decoders.
JSON must preserve large integer values exactly and reject duplicate fields
and aliases that could change key-index identity. Revalidate programmatically
constructed objects before signing/finalizing, not only during decoding.

Use [BIP174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki)
for role separation, previous-transaction binding and input-map validation,
and [BIP370](https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki)
for explicit versioning and transaction-field commitments. This is a distinct
GnB format, not Bitcoin PSBT wire compatibility. Cite the relevant defenses
in code comments after inspecting primary sources. A reproducible vector
generator and independent Python codec/checker must agree with Rust on
acceptance, rejection and exact bytes; run the comparison in CI.

## Delivery gates

Provide CLI, RPC (public-data operations only; never import a private key into
the node) and WASM entry points using the shared wallet implementation. Test
2-of-3 signing through serialize/combine/finalize/extract, mutation rejection,
incomplete signatures, mismatched previous transactions, fees and activation
boundaries. Add parser/property or differential fuzz coverage appropriate to
the implemented format. Rebuild and re-pin WASM using
`scripts/build-wallet-wasm.sh` when compiled sources change.

Record production-only reversal for reproduced signing defects, retaining
final tests. Capture source hashes and restoration in a replayable driver.
Three independent reviews and integration/CI are required before claiming
completion. Any deferred role, surface or acceptance test remains explicitly
partial. No numerical rating or BTC superiority claim is assigned here.

## Frozen v1 codec contract for independent implementation

Binary fields in order (integers unsigned little-endian): magic 8 bytes
`47 4e 42 50 53 42 54 ff`; format version u16 = 1; network u8 = 0 mainnet,
1 testnet; unsigned transaction `blob32`; policy `blob32`; tree `blob32`
(empty when absent); branch u8 (`ff` iff tree absent); input count u16.
`blob32` is u32 byte length followed by exactly that many bytes.

Each input in transaction order: value u64; locking script `blob32`;
previous transaction `blob32` (empty means absent); derivation count u8;
each derivation: key index u8, fingerprint 4 bytes, path length u8, that
many u32 child indices; signature count u8; each signature: key index u8,
signature `blob32`. Both key-index lists must be strictly increasing.
No trailing bytes, unknown versions, unknown networks, duplicate keys or
unknown fields. This format does not retain unknown extension fields.

Limits checked before variable binary-field allocation: complete binary
8 MiB; JSON `2 * 8 MiB + 256 KiB` (17,039,360 bytes); transaction/previous transaction 1,000,000 bytes;
policy 65,536 bytes; tree 262,144 bytes; locking script 10,000 bytes;
64 inputs and 64 outputs in the unsigned transaction; 7 derivations and
7 signatures per input; 16 child indices per derivation; signature 8,192
bytes (at least one byte). Monetary sums use checked u64 arithmetic; this
wallet codec adds no MAX_SUPPLY bound. Transaction decoding must consume all bytes and re-encode identically.
Every unsigned input has an empty script_sig. Inputs all spend the same
policy/tree branch; heterogeneous policies/single-key inputs are unsupported.

Equivalent JSON object fields: `format` = `gnb-pqpsbt`, `version` = 1,
`network` = `mainnet` or `testnet`, `transaction` = unsigned hex, `policy`
= policy hex, `tree` = hex or null, `branch` = integer or null, `inputs`
= array. Each input has `value` (canonical decimal string), `script`
(hex), `previous_tx` (hex or null), `derivations` (array), `signatures`
(array). Derivation fields: `key_index`, `fingerprint` (8 hex characters),
`path` (array of u32 numbers). Signature fields: `key_index`, `signature`
(hex). Key indices are JSON integer numbers, never string aliases. All
listed fields are required; no extra fields. Hex is lowercase with an
even number of characters. Decimal strings are `0` or a nonzero digit
followed by digits, within u64. JSON object order and whitespace are not
significant; serializers emit the stated field order with compact JSON.

The fee ceiling is an absolute satoshi ceiling, without the minimum-fee
exception of the other wallet's FeePolicy. Network, next block height and
maximum fee are supplied explicitly by the signing caller, not trusted from
the document. v1 requires previous transactions hashed against outpoints;
v3 needs committed value/script pairs. Any supplied previous transaction is
checked even for v3. Neither mode proves current unspentness offline.

## Initial reproduction and foundation status

Before production edits on the stated baseline, the test
`pqpsbt_policy_signer_checks_all_amounts_before_the_signing_callback` failed
with one signing callback instead of zero after changing an input amount to
one satoshi. The runtime WASM test
`pqpsbt_public_decode_reaches_the_format_parser` failed with `unknown op pqpsbt`.
Both used existing entry points and synthetic local data. Logs are retained
outside the repository in `/private/tmp/gnb-pqpsbt-evidence`.

The initial foundation includes a strict structural codec, bounded public
roles, contextual signing/finalization and the WASM dispatcher. Host tests
cover 2-of-3 signing, exact round trips, duplicate fields, malformed input,
strict fee/network checks and the existing H-1/H version boundary. This is
an intermediate integration commit: independent vectors, broader tests,
production reversal, frontend integration, canonical WASM rebuild, independent
review and CI are still delivery gates. No completed PF-2 or rating is claimed.

## Additional validation and boundary correction

The initial 16 MiB JSON cap was insufficient for equivalence at the binary
limit. A valid 8,388,607-byte binary produces 16,777,697 bytes of canonical
JSON. The first attempted fixture had one 900,000-byte script_sig and failed
setup at the existing transaction decoder; it is not counted as reproduction.
The corrected fixture uses nine previous transactions, each with 100 bounded
script_sigs, and distinct outpoints. Its old-cap test failed at the asserted
JSON property. Before publication, the owner approved increasing only the
JSON cap to `2 * MAX_BYTES + 256 KiB`; binary admission remains 8 MiB.
Hex payload contributes at most twice the binary size. A conservative bound
on JSON names, punctuation and numeric metadata is
`256 + 64 * (256 + 7 * (128 + 16 * 11) + 7 * 64) = 181,504` bytes,
below the 262,144-byte margin. The independent Python construction measures
121,337 bytes of maximum metadata. Both input and output guards remain.
`pqpsbt_binary_limit_preserves_equivalent_bounded_json` proves the concrete
boundary round trip and refusal above the new JSON cap.

Unknown public-request fields were separately reproduced: a valid decode
request with `private_key` metadata was accepted. A central per-action
allowlist now rejects unknown/secret fields. Documents remain exact strings
so duplicate document fields cannot be erased by an intermediate JSON map.

Focused host execution: 10 core unit tests and two integration tests passed;
WASM host suite: nine tests passed. Independent Python vectors (45 accepted,
95 rejected binary, 64 rejected JSON) all match Rust verdicts, binary bytes,
and literal compact JSON. Another 512 seeded binary mutations agree with the
Python JSONL oracle; 95 are accepted controls. These 716 comparisons are a
bounded wallet-format differential, not a full-consensus or 10^7-case claim.
The reference and its expected vectors were authored independently in a
separate package and were not modified to match Rust output.

Actual strict signature-verifier calls are measured by a test-only,
thread-local counter at the existing crypto entry points, including the
final consensus witness check. Two partial signatures cause six calls.
At the proposed RPC frontend limit, four inputs and 16 valid partials cause
48 calls (all partials, selected witnesses, final witness verification).
The same request exceeding either the input or signature budget causes zero
calls. This measures signature-verifier invocations, not individual lattice
primitive calls, request latency or the frontend's HTTP admission behavior.

The format supports only one policy or one selected tree branch across all
inputs. Offline review checks structure, supplied previous-transaction
contents, explicit network/height, absolute locktime, activation and strict
fee ceiling. It does not establish current unspentness, coinbase maturity or
relative input age; the online frontend owns those node observations. The
finalizer keeps the existing PolicySpend choice of the threshold lowest-index
signers common to every input. RPC scheduling, node-backed policysign, browser
wrappers and canonical WASM build/pins are separate integration packages.

## Independent review findings and correction

Independent review subsequently found missing pure transaction checks and
non-atomic growth at the binary limit. Seven native regression tests were
added before changing production: all seven failed by assertion while nine
existing controls passed (`review-findings-red.log`). They demonstrate an
input above MoneyRange, output above MoneyRange, separate input/output sums
above MoneyRange, zero fee reaching a signing callback, a fully signed
transaction whose exact fee is rejected by `core::check_min_fee` nevertheless
finalizing, and signing a maximum-size document successfully while making it
unserializable. These are findings in the new implementation, not claims
against the original baseline. Review classified the finalizer validity gap
as a medium issue; no rating improvement is inferred from discovering it.

The shared review now calls `core::limits::check_tx_money_range` and
`core::limits::money_add`, and rejects fees below `MIN_TX_FEE_SAT` before any
signing callback. No witness-size estimate is used in preflight. Finalization
calls the existing `core::check_min_fee` with the actual final transaction
and reviewed fee. The signed candidate is validated in full before replacing
the original document; failure leaves the original bytes unchanged. No
transaction is automatically rewritten. Decoder acceptance remains structural
u64 with the same independently generated vectors; MoneyRange and the fee
checks belong to review/sign/finalize, not the interchange parser.

The fixes passed 17 focused core tests. In the measured finalizer fixture,
fee 10,000 sat was refused against a 41,082-sat shared minimum for the actual
20,541-byte witness transaction (Falcon sizes may vary across runs). At the
binary limit, nine signing callbacks complete, then candidate validation
returns an error and preserves the original serializable document byte for
byte. The codec differential remains unchanged.

Two test-infrastructure findings were also reproduced. The mutation driver
narrowed the PRNG state before modulo, producing offsets 41 and 89 for
32/64-bit conversion models (seed 20,070,770,068,898,388; length 97). Both
models exercise the same arithmetic as the generator; reducing in u64 before
conversion now agrees across widths. This is a deterministic arithmetic
model test, not a claimed native i686 execution.

The new WASM host signing test cannot run in Miri because it calls PQClean
C. Actual native Miri execution failed at
`PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair`; the same narrow `cfg_attr(miri,
ignore = ...)` used by existing FFI tests was then added. Native Miri's WASM
library suite passes four tests and skips five explicitly unsupported FFI
cases. Native and real-WASM signing tests remain mandatory. The i686 Miri
attempt stopped before test execution because `i686-linux-gnu-gcc` is absent
on this macOS host; that is a setup limitation, not runtime reproduction or
an i686 green claim.

## Explicit open acceptance and relay limitations

Independent review reported a further case in which mandatory repeated
policy witnesses already exceed the final transaction size bound before any
signature is added. The additional reproduction/implementation task was
stopped after automatic approval review rejected that action for possible
cybersecurity risk. This engineer did not write or run a new Cargo regression
for that scenario and made no production change for it. Existing reviewer
evidence is preserved; the finding and associated acceptance remain open.
It must not be counted as resolved by the separate 8 MiB candidate-atomicity
fix above.

The node's default 400 KiB relay policy is separate from this format's
1,000,000-byte transaction bound. Structural import and finalization do not
guarantee local relay admission. No relay-policy rule was changed or added
by this package. Final integration, canonical Linux WASM rebuild/pin,
independent review and CI remain the coordinating round's delivery gates.

## Production reversals and retained evidence

All eleven production reversals were repeated against final source commit
`8cdb075d4dabb4f478a2f7624eb2b5f316baadab`. Each changed only its production
hunk, retained final test bodies/instrumentation, failed at runtime, and
restored the exact original source hash. Cases: legacy signing shape,
public WASM dispatch, explicit fee ceiling, pre-crypto transport budget,
request field allowlist, sufficient JSON cap, session network binding,
shared MoneyRange checks, absolute fee floor, exact final fee and validation
of the signed candidate. The MoneyRange reversal separately trips the
input, output, input-sum and output-sum regressions. The candidate reversal
records callback count, successful/failed return, serializability and byte
identity. The Miri-only test attribute also has a separate runtime reversal
and restored native Miri green; it is test configuration, not production.

Evidence is retained outside the repository at
`/private/tmp/gnb-pqpsbt-evidence/`. The replayable production driver is
`replay_reversals.py` (SHA256
`27e6f9be2d2260223ead313146b5fc8e68c6a6175c9cbf247ecfd04c1879cb7e`).
`source-and-reversal-manifest.json` (SHA256
`05c13adbf26bcfd7a94158b5ad4581fe521b8dfcfad9865c81addfe51980376c`)
records the baseline/source commit, individual source hashes, driver hashes,
reversal manifest hashes and final reversal-log hashes. The authoritative
production reversal manifest is `reversal-final-manifest.json`; the initial
seven-case run is superseded by the final eleven-case rerun.

Commands use normal Cargo with the environment at the top of this brief.
The complete crypto command is `cargo test --locked -p gnb-crypto -- --nocapture`;
the WASM host command is `cargo test --locked -p gnb-wallet-wasm -- --nocapture`.
The crypto run uses `GNB_PQPSBT_REFERENCE_DIR` only to read the independently
committed reference worktree before round integration. The committed test's
default path is repository `reference/`; absence is an error, never a skip.
Initial sandbox failures in three existing HTTP tests were `PermissionDenied`
at `TcpListener`, then passed with loopback permission. No production code
was changed to address the sandbox.

## Final restored-source validation and durable replay

After all reversals restored the source bytes recorded for `8cdb075`, the
complete separate `gnb-crypto` invocation passed 437 unit tests, 30 integration
tests and one doctest: 468 passed, zero failed and four pre-existing ignores
(one unit, one vector generator and two doctests). This includes the 204
independent vectors and 512 seeded differential cases, with exact binary and
canonical JSON comparison, plus the pointer-width arithmetic regression.
The complete WASM host suite passed nine tests with no ignores. Restored
native Miri passed four tests with five explicit FFI ignores, including the
new signing test described above; it does not establish i686 Miri coverage.
These are local results, not a claim of green round CI or final WASM pinning.

The repository retains the exact executed drivers and small manifests:

- [Production replay driver](pqpsbt-replay-reversals.py), byte-identical to
  `replay_reversals.py` and its SHA256 recorded above.
- [Eleven production reversals](pqpsbt-reversals.json), including each
  changed/restored source hash, command and observed runtime failure.
- [Source and reversal evidence](pqpsbt-evidence.json), including the driver,
  manifest and external reversal-log hashes.
- [Miri configuration replay](pqpsbt-replay-miri.py) and its
  [restoration manifest](pqpsbt-miri-reversal.json).
- [Final test-log hashes](pqpsbt-test-log-hashes.json), identifying the full
  restored-source runs and the later review-finding red/green logs.

The production driver deliberately preserves the paths used in the measured
run: source worktree `/Users/tiagobulhoes/worktrees/gnb-technology-pqpsbt`,
output directory `/private/tmp/gnb-pqpsbt-evidence` (create it beforehand), and
Cargo target `/private/tmp/gnb-technology-target-pqpsbt`. Prepare a disposable
checkout of `8cdb075` there and compare its source hashes with the evidence
manifest before execution; documentation-only additions do not affect those
hashes. Use the repository toolchain with dependencies available. The driver
sets CGU 53, debug information off, incremental compilation off and two build
jobs. Run `python3 docs/security/round-3/pqpsbt-replay-reversals.py` for all
eleven cases, or append `--case <name>` for one case from its manifest. It
temporarily changes production hunks and restores them in `finally`; do not
run concurrent edits or builds against that checkout. Test bodies and
instrumentation remain unchanged. Retain historical logs before replay,
because output names are reused. The script checks mutation anchors and
restoration, but source-hash verification is a prerequisite, not a claim
that the script automatically validates every baseline file.

The separate Miri driver expects a disposable source checkout at
`/private/tmp/gnb-pqpsbt-miri-source` with the recorded final sources, output
directory above, and target `/private/tmp/gnb-technology-pqpsbt-miri-native`.
It uses installed `nightly` with Miri/rust-src, native host execution,
`-Zmiri-permissive-provenance`, CGU 53 and one build job. The measured checkout
was based on `68f4a91` with the final `8cdb075` core and WASM files copied from
Git; the production of the selected crate matches the recorded final hashes.
It removes only the new test's Miri ignore attribute, observes the unsupported
foreign-function error, restores the exact file and runs the full native
Miri library suite. It neither tests nor replays the stopped witness-size
finding. Neither driver includes its probe, binary snapshots or large logs.
