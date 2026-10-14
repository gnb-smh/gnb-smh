#!/bin/sh
# Falcon "clean variant only" guard, cited by node/Cargo.toml,
# crates/gnb-crypto/Cargo.toml and crates/gnb-crypto/src/crypto/mod.rs.
#
# Falcon-1024 signing must use PQClean's `clean` variant (integer-emulated
# floating point, constant time, bit-exact on every platform). pqcrypto-falcon's
# default features `avx2` / `neon` compile and dispatch to native-FP variants;
# Cargo features are additive across the workspace, so one member re-enabling
# defaults would switch every build. This guard fails when:
#   1. the resolved feature graph enables `avx2` or `neon` on pqcrypto-falcon
#      for any workspace member (target-independent check);
#   2. the symbol-level tripwire test in gnb-crypto
#      (`falcon_native_fp_variants_are_not_linked`) finds an AVX2/AARCH64
#      Falcon symbol in the linked test binary.
# Run from the repository root: sh scripts/falcon-clean-guard.sh
set -eu

tree=$(cargo tree --workspace --locked --target all -e features -i pqcrypto-falcon)
if printf '%s\n' "$tree" | grep -Eq 'pqcrypto-falcon feature "(avx2|neon|default)"'; then
  printf '%s\n' "$tree" | grep -E 'pqcrypto-falcon feature "(avx2|neon|default)"' >&2
  echo "falcon-clean-guard: pqcrypto-falcon native floating-point features are enabled" >&2
  exit 1
fi
echo "falcon-clean-guard: feature graph ok (no avx2/neon/default on pqcrypto-falcon)"

cargo test -p gnb-crypto --locked --lib falcon_native_fp_variants_are_not_linked 2>&1 \
  | tee /dev/stderr | grep -q "test result: ok. 1 passed"
echo "falcon-clean-guard: symbol tripwire ok"
