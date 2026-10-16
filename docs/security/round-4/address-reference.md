# Round 4 package: independent address-v2 reference

- Worktree: `gnb-r4-address-reference`.
- Branch: `codex/r4-address-reference`.
- Base: `7d6a67eafa93cf7935ecedb50d601486aca4cff7`.
- Reserved Rust `codegen-units`: 89; this package uses only Python and builds
  no Rust artifacts.
- Scope: CRY-7 / technology 4.5, the additive Bech32m address-v2 contract.

## Acceptance criteria

The specification defines every HRP, metadata word, hash byte, padding bit,
checksum constant, script mapping and rejection rule. An independent Python
implementation and reproducible generator produce accepted and rejected
vectors with expected network/kind/hash/script bytes. Tests include generic
BIP350 vectors separately from GnB application rules. A local JSON-lines
oracle and a driver compare the corpus against a separately built Rust codec.

No transaction, consensus, signature, legacy encoder or key derivation changes
belong to this package. No network requests, secrets or fuzzing of live nodes
are part of the reference tests. CI integration belongs to the round coordinator.

## Independence and reproduction boundary

The implementer read the public contract, BIP173/BIP350 and the **baseline**
`crates/gnb-crypto/src/address.rs` only to verify the existing 20-byte single-key
and 33-byte policy scripts. The new Rust v2 implementation was not read or
copied. Four independently generated zero-hash vectors were supplied to the
Rust engineer before their production edit for a runtime missing-feature test
through the existing parser API.

The reference is a new executable specification, not a production bug fix.
Its own initial missing-module/compile state would not count as defect
reproduction and is not claimed as such. Runtime baseline reproduction and
production-only reversal evidence belong to the core package.

## Evidence at package completion

The completed reference run passes 13 Python tests, covering all 502
corpus cases: 128 accepted and 374 rejected. There are seven generic BIP350
valid vectors, 14 generic BIP350 invalid vectors and seven BIP173 valid
Bech32 vectors that the Bech32m decoder must reject. Finite typo samples are
not a comprehensive fuzz campaign.

Corpus SHA-256:
`26c1d23ebeb765961bcab1930f0555b9c54252e750d7be139b713191d8d0ee1c`.

Reproduction commands:

```sh
python3 reference/address_v2_test.py -v
python3 reference/address_v2_vectors.py --check
python3 reference/address_v2_differential.py /path/to/address_v2_oracle
```

The differential command compares 630 requests (502 decodes plus 128 positive
encodes) and reports hashes. Its presence is not evidence that the Rust
comparison passed; the coordinator must retain an actual successful run after
integration. Independent review and CI are also separate gates. No security
or technology score is assigned by this package's implementer.

An initial 503-case corpus included a valid legacy address as a rejection by
the v2-only reference. Before differential use, that case was moved into a
Python-only scope test, allowing the Rust oracle to call its public unified
parser directly without a v2 syntax gate. Compatibility with legacy addresses
remains a separate production test obligation, not part of the v2 oracle's
claims.
