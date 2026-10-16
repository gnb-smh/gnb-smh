#!/bin/sh
# PQClean "clean variant only" guard for Falcon-1024 and ML-DSA-65, cited by
# node/Cargo.toml, crates/gnb-crypto/Cargo.toml and
# crates/gnb-crypto/src/crypto/mod.rs.
#
# Falcon-1024 signing must use PQClean's `clean` variant (integer-emulated
# floating point, constant time, bit-exact on every platform). pqcrypto-falcon's
# default features `avx2` / `neon` compile and dispatch to native-FP variants.
#
# ML-DSA-65 verification is consensus and must give one verdict on every node:
# pqcrypto-mldsa's default features `avx2` / `neon` compile PQClean's AVX2 and
# AArch64 ML-DSA and dispatch to them (AVX2 at run time, per CPU), and the AVX2
# verifier is not FIPS 204 (no z bound; UseHint at r0 = 0), so AVX2 and
# non-AVX2 nodes split on crafted signatures (Wycheproof tcId 161).
#
# Cargo features are additive across the workspace, so one member re-enabling
# defaults would switch every build. This guard fails when:
#   1. the resolved feature graph enables `avx2`, `neon` or `default` on
#      pqcrypto-falcon or pqcrypto-mldsa for any workspace member
#      (target-independent check);
#   2. the symbol-level tripwire tests in gnb-crypto
#      (`falcon_native_fp_variants_are_not_linked`,
#      `mldsa_avx2_and_aarch64_variants_are_not_linked`) find an AVX2/AARCH64
#      symbol of either scheme in the linked test binary.
# Run from the repository root: sh scripts/falcon-clean-guard.sh
set -eu

for crate in pqcrypto-falcon pqcrypto-mldsa; do
  tree=$(cargo tree --workspace --locked --target all -e features -i "$crate")
  if printf '%s\n' "$tree" | grep -Eq "$crate feature \"(avx2|neon|default)\""; then
    printf '%s\n' "$tree" | grep -E "$crate feature \"(avx2|neon|default)\"" >&2
    echo "falcon-clean-guard: $crate native (avx2/neon) features are enabled" >&2
    exit 1
  fi
  echo "falcon-clean-guard: feature graph ok (no avx2/neon/default on $crate)"
done

cargo test -p gnb-crypto --locked --lib -- --exact \
  crypto::falcon::tests::falcon_native_fp_variants_are_not_linked \
  crypto::mldsa_one_verdict::mldsa_avx2_and_aarch64_variants_are_not_linked 2>&1 \
  | tee /dev/stderr | grep -q "test result: ok. 2 passed"
echo "falcon-clean-guard: symbol tripwires ok (Falcon-1024, ML-DSA-65)"
