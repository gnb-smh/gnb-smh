# Wycheproof ML-DSA-65 verification vectors

- Source: https://github.com/C2SP/wycheproof, `testvectors_v1/mldsa_65_verify_test.json`
- Upstream commit (last change to the file): 613a2e44cb645a9890e49f8d8798cd59ef38379b 2026-08-17T17:14:50Z
- Retrieved: 2026-10-12
- SHA-256 of the vendored file `wycheproof-mldsa65-verify.json`: `49ac366d76115eab56b7116f10d06e288e6f23fe6cfb90b26bfb2d731a8d1e02`
- License: Apache License 2.0 (Wycheproof project).

210 tests in 25 groups: 77 valid and 126 invalid with an empty context, plus
2 valid and 5 invalid with a non-empty context. Flags include boundary
conditions, infinity-norm violations, invalid hint encodings, zero and
wrong-length public keys, and modified signatures.

`tests/wycheproof_mldsa65.rs` checks every empty-context case through the
consensus wrapper `crypto::verify` (ML-DSA-65-only suite envelope) and every
case, with its context, through `pqcrypto_mldsa::mldsa65` directly. Both must
give the Wycheproof verdict on every case, on every target and CPU. These are
third-party known answers: a match shows agreement with the standard's edge
cases, not an audit.

The vectors found that PQClean's AVX2 ML-DSA-65, which `pqcrypto-mldsa`'s
default features select at run time on AVX2 CPUs, differs from FIPS 204 on
42 cases: it accepts 41 signatures whose z violates the infinity norm and
refuses tcId 161 (UseHint with r0 = 0), while the clean implementation (i686,
wasm32, x86_64 without AVX2) agrees with Wycheproof. Every build therefore
links the clean implementation only (docs/testing/SANITIZERS.md, F6).
