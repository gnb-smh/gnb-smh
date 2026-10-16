# Independent descriptor reference evidence

The independent reference is complete for the frozen static public descriptor
contract. No new Rust parser source was read. Sources were the round contract,
BIP380 primary specification and the existing key-shape, script and address
formats. The package reserved native codegen-units 149 and performed no Rust
build. It called the core package's prebuilt oracle as an external executable.

Sequence:

1. `a8821cf`: brief and contract tests only. This does not claim that a missing
   Python module reproduces a product failure; core owns the runtime feature-gap
   reproduction through the existing WASM dispatcher.
2. `0cb5993`: independent codec, public pool, specification, vectors and driver.
3. `d78a6c2`: deterministic generated comparison campaign, additional contract
   test and documentation. Fixed vector pins are unchanged.

## Results

| Check | Actual result |
| --- | --- |
| Python reference unit suite | 13 passed, 0 failed |
| Deterministic fixed-vector regeneration | identical (`--check`, exit 0) |
| Fixed corpus | 362 requests: 58 accepted, 304 rejected |
| Generated campaign | 128 requests, seed 306255643701 (`0x474e424435`) |
| Rust/Python differential | 490 requests: 122 accepted, 368 rejected; 0 divergences |
| Python compilation | all five modules compile |
| Working diff whitespace check | passed |

The differential compares complete accepted responses, including exact
scripts, checksums, both address forms, canonical bundle strings and pool
entries. Rejections compare verdict only; diagnostic wording is not normative.
It first verifies SHA256 pins for each fixed request and full Python response,
then exercises the seeded generated cases independently of those pins.

The final local differential ran in 170.359 seconds using Python 3.9.6 and the
prebuilt Rust oracle from core production revision `326e292`. Its binary SHA256
was `aca9de614c159e7ccd7b63891f5e27cfb68b0c36ce8d1c395b3a0ff6e838b49a`.
The fixed corpus SHA256 was
`c89da6ace011f18aa2cf81da9ce7700d093b268a99676f544baab36ed83c0c77`.
The generated request stream SHA256 was
`c08bd6d6133854b9a5b20195cd25e1bd4d5e2ad52d8d6031fe96659bbaff4760`.

Commands, exact source/log hashes, preserved text logs and results are in
[reference-evidence.json](reference-evidence.json). The first checks recorded
12 tests before the generated-campaign test was added; the final run records
all 13. Both records are retained, with their respective source revisions.
The final differential checks the unchanged fixed pins as well as the new
campaign. No failure was hidden or converted to a skip.

## Coverage and limits

Coverage includes both networks and all three kinds; exact raw/enveloped key
identities and raw keys beginning with envelope magic; threshold/key-count/u32
bounds; key and branch order; 3-leaf tree padding; BIP380's primary checksum
example; checksum mutations; noncanonical grammar both at creation and under
an otherwise valid checksum; explicit operation/network checks; outer JSON and
pool duplicate fields; canonical public-pool roundtrips; and descriptor, entry
count and raw UTF-8 pool byte bounds. The maximum accepted pool input includes
whitespace up to exactly 1,048,576 bytes; one additional byte is rejected.

Synthetic public key fixtures only satisfy the existing format predicate.
They do not prove cryptographic validity, possession or spendability. The
seeded campaign is a bounded generated comparison, not a coverage-guided fuzz
run, a 10^7-case claim or a full-consensus differential proof. Canonical output
and executable comparisons do not establish final integration CI, rebuilt WASM
correctness or completion of independent three-lens review.

This remains partial technology item 4.2. It adds no derivation, wildcard,
private-key recovery, balance/history index, spending language or consensus
activation. PF-4 and inherited findings remain open. No score or superiority
claim is assigned by the implementer.
