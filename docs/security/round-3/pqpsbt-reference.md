# Independent PQ-PSBT format reference

Base `f06b7f8dc05af107fd16f2cebdd89d62a360662a`; branch
`codex/technology-pqpsbt-reference`. Reserved codegen-units **67** and target
`/private/tmp/gnb-technology-target-pqpsbt-reference` if Cargo is needed.
The principal implementation is pure Python, independent of Rust codec calls.

The wallet core engineer in `gnb-technology-pqpsbt` will supply the exact
version-1 byte layout. Implement a Python encoder/decoder and deterministic
vector generator/checker from that specification. Write `docs/PQ-PSBT.md`
with byte-level rules, explicit limits and supported policy/tree scope.
Do not infer missing byte rules or silently match Rust bugs. Raise any
disagreement as a finding and coordinate a deliberate specification fix.

Cover accepted and rejected encodings, canonical transaction bytes,
length/count/overflow bounds, duplicate fields/indices, truncation/trailing
data, unknown versions, exact decimal amounts and JSON/binary equivalence.
Vectors must be deterministic and checked from both languages in CI. Add
bounded seeded differential cases; report their actual count without claiming
the broader ten-million-case consensus target. The reference does not verify
post-quantum signatures unless it actually implements/calls an independent
verifier; clearly separate structural validation from signature verification.

Inspect primary BIP174/370 sources for role and input-binding rationale;
GnB's new format is distinct and must not claim Bitcoin PSBT compatibility.
Record reproduction of absent public operations from the core package and
test the reference independently with deliberate invalid controls. No
consensus rule or activation is changed. The engineer may edit only
`reference/pqpsbt*`, new PQ-PSBT vectors, `docs/PQ-PSBT.md`, this brief, and
the narrowly scoped Python-reference CI step, coordinating workflow changes
with root. Three independent reviews and integrated execution remain required.

## Implemented reference package

Implemented `reference/pqpsbt.py`, deterministic generator
`reference/pqpsbt_vectors.py`, corpus `reference/pqpsbt_vectors.json`, tests
`reference/pqpsbt_test.py` and the byte-level document `docs/PQ-PSBT.md`.
Only one four-line step was added to the existing `python-reference` CI job;
no pre-existing checks or other jobs were changed. The core engineer owns the
Rust test consuming the same manifest in the workspace suite. The Python CLI
also accepts bounded JSONL cases for a process-based differential caller.

The implementation was written from the frozen layout and the existing
transaction/policy framing, without reading/copying the new Rust PQ-PSBT
codec or calling Rust. Primary BIP174 and BIP370 texts were read; their role,
previous-transaction binding and version-separation rationale is cited in the
code/document. GnB intentionally has a different wire encoding and rejects
unknown extensions/conflicting combination claims.

Structural decoder semantics were clarified with the core engineer before
being added: tx versions 1/3; 1–64 inputs/outputs; non-coinbase; distinct
outpoints; empty unsigned witnesses; supported output scripts and 546-satoshi
minimum; selected policy locktime/script binding; u64 amounts and checked
sums with inputs covering outputs; optional previous transactions authenticated
against outpoints and selected outputs; strictly ordered, in-range metadata
indices; signature length 1–8,192. No additional MAX_SUPPLY limit was inferred.
The signer alone requires complete previous transactions for v1 and receives
network/height/maximum-fee context. The codec does not infer current UTXO
status, derive keys, sign or verify PQ signatures.

A real representation-boundary finding was raised before changing the
contract: a valid binary at 8 MiB expands above the initially proposed 16 MiB
JSON limit, defeating full representation equivalence. An initial discussion
considered independent representation limits; before publication, root instead
explicitly required complete canonical JSON equivalence and approved the
core/reference change below. No expected fixture verdict was changed to fit
Rust, and the 8 MiB binary limit is unchanged.

The final JSON cap is **17,039,360 bytes = 2 × 8 MiB + 256 KiB**. Hex payloads
cost at most twice the binary size. A conservative upper bound for metadata is
`256 + 64*(256 + 7*(128 + 16*11) + 7*64) = 181,504 < 262,144`. The format doc
explains every term; an independent lexical construction in the tests measures
121,337 bytes at the maximum field counts/decimal widths, below that bound.
The runtime boundary test constructs a valid binary of exactly 8,388,608 bytes,
round-trips its canonical JSON (larger than 16 MiB but below the derived cap),
and rejects one extra binary byte. Parsing and serialization retain explicit
checks against the new JSON cap. This is a deliberate pre-publication contract
correction agreed with root and the core engineer, not an unexplained increase.

## Local evidence (Python 3.12.15)

Interpreter:
`/Users/tiagobulhoes/.local/share/uv/python/cpython-3.12.15-macos-x86_64-none/bin/python3`.
Run from this worktree:

```sh
python3 reference/pqpsbt_test.py
python3 reference/pqpsbt_vectors.py --check
```

Actual results with that interpreter: **18 tests passed**, zero skips;
**45 accepted, 95 binary rejected, 64 JSON rejected**, 204 corpus cases total.
Exactly 64 of those cases are the bounded seeded differential corpus
(32 accepted and 32 paired mutations). Seeded mutations span trailing bytes,
network tags, truncation, length bounds, key indices, input scripts, duplicate
derivations and transaction versions. This is not ten-million-case testing.

The independent tests check exact bytes and JSON equivalence for every
accepted case, every committed rejection, deterministic regeneration, every
truncation prefix of the basic accepted binary, process-oracle results,
pre-parse total-size guards, declared-length checks before copying, programmatic
object revalidation, exact u64 decimals, previous-transaction witness/txid
semantics, tree commitments and the full binary size boundary plus the derived JSON-overhead proof.

Logs in `/private/tmp/gnb-pqpsbt-reference-evidence/`:

- `python-green.log`: 18/18, exit 0.
- `reproducible.log`: full corpus regeneration matched, exit 0.
- `duplicate-control-red.log`: an intentional runtime replacement of the
  duplicate-field detector with ordinary last-value-wins dictionary creation
  made the committed duplicate-field regression fail, exit 1. This was an
  executed assertion failure, not a compilation/import error.
- `duplicate-control-green.log`: identical regression with the actual detector
  restored passed, exit 0. The control driver is `sensitivity_control.py` in
  that evidence directory; `--broken` enables the deliberate defect. No source
  mutation or production-code reversal was needed for this reference control.
- `json-limit-red.log`: running the final binary/JSON round-trip test with the
  old 16 MiB limit restored at runtime failed on the actual JSON serialization
  (`Invalid: JSON size`, one executed test error, exit 1). This is a format
  limit failure, not an import/compilation error.
- `json-limit-green.log`: the identical boundary test with the approved derived
  limit passed, exit 0; driver `json_limit_control.py` accepts `--old-limit`
  for the negative control. The full 18-test suite also passes with the new cap.

The genuine pre-implementation core baseline evidence was inspected, not
rerun by this engineer: `/private/tmp/gnb-pqpsbt-evidence/wasm-red.log` contains
an executed assertion failure for the missing public `pqpsbt` operation;
`legacy-red.log` contains an executed assertion failure because an inconsistent
import reached a signing callback (observed 1, expected 0). Both reached their
test bodies after successful compilation. Those are core baseline reproductions;
the reference's duplicate-field sensitivity control is a separate test claim.

Rust/Python integrated execution, three independent reviews and CI remain
required before claiming the overall PQ-PSBT package complete. This reference
commit does not claim those pending gates or cryptographic signature validity.

## First cross-language execution

The core engineer executed `crates/gnb-crypto/tests/pqpsbt_vectors.rs` against
this reference through `GNB_PQPSBT_REFERENCE_DIR` while the packages were still
in separate worktrees. The reviewed log
`/private/tmp/gnb-pqpsbt-evidence/differential.log` reports **2 tests passed,
zero skips**: all **204** committed corpus verdicts agree, with exact binary
round trips and equivalent JSON objects, plus **512** additional seeded binary
mutations with identical Rust/Python verdicts and bytes (**95 accepted**).
The mutation test retains at least 64 positive controls. These are 716 bounded
case comparisons, not 716 unique fixtures or a broad fuzzing claim. This
engineer inspected the log and test source; execution was by the core engineer.
Canonical JSON field-order checking was separately requested because
object-value equality alone does not check the serializer's stated output
order. The final fixture adds `canonical_json` for each accepted document;
the JSONL oracle also returns a literal canonical `json` string.

The final core execution is recorded separately in
`/private/tmp/gnb-pqpsbt-evidence/all-pqpsbt-green.log`: **10 unit tests and
2 integration tests passed**, zero skips, including the derived JSON cap and
literal canonical JSON comparison in the 204-vector/512-mutation differential.
The test source was inspected to confirm both literal comparisons. The original
`differential.log` is intentionally preserved as the first-run evidence. These
Rust commands were executed by the core engineer, not rerun by this reference
engineer. Final integrated CI and independent-review gates remain pending.
