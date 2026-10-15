#!/bin/sh
# Sanitizer, Miri and 32-bit runs of the consensus crates. The CI jobs
# `sanitizers`, `miri` and `i686` call this script; docs/testing/SANITIZERS.md
# documents every mode and its last local results.
#
#   sh scripts/sanitizers.sh asan        AddressSanitizer + LeakSanitizer over the Rust code AND
#                                        the PQClean C code the pqcrypto build scripts compile
#                                        (nightly, clang)
#   sh scripts/sanitizers.sh ubsan       UndefinedBehaviorSanitizer over that C code, no recovery
#                                        (gcc + libubsan)
#   sh scripts/sanitizers.sh ubsan-noavx2
#                                        the UBSan ML-DSA tests on an emulated CPU without AVX2
#                                        (qemu-user), so the CLEAN ML-DSA C code runs
#   sh scripts/sanitizers.sh miri        Miri: consensus arithmetic (gnb-smh, gnb-crypto core),
#                                        the unsafe code of pqcrypto-internals (nightly + miri)
#   sh scripts/sanitizers.sh miri-cross  Miri: gnb-smh on a 32-bit (i686) and a big-endian (s390x)
#                                        target; the wallet's wasm C ABI on i686 (gcc-multilib)
#   sh scripts/sanitizers.sh i686        the consensus crates' and the wasm wallet core's full test
#                                        suites on i686-unknown-linux-gnu (pinned toolchain,
#                                        gcc-multilib)
#
# Each mode builds into its own directory, $SANITIZER_TARGET_DIR/<mode>
# (default target/sanitizers/<mode>), so sanitizer flags never reach the
# normal build. Each crate is tested in its OWN cargo invocation: gnb-crypto
# must not see the node's `test-pow-limit` dev feature (POW-5).
set -eu
cd "$(dirname "$0")/.."

mode=${1:-}
root=${SANITIZER_TARGET_DIR:-$PWD/target/sanitizers}
# A pinned nightly (asan, Miri): a nightly without Miri, or a rustc change to
# -Zsanitizer, must not change the result with no change in the repository.
# CI sets the same value (SANITIZER_NIGHTLY in .github/workflows/ci.yml); bump
# both on purpose.
nightly=${SANITIZER_NIGHTLY:-nightly-2026-10-14}
host=x86_64-unknown-linux-gnu

# Every PQClean archive the build scripts produced must reference the
# sanitizer runtime: proves that the C flags reached the C compiler.
assert_c_instrumented() { # <target dir> <undefined-symbol prefix>
  n=0
  for a in $(find "$1" -name '*.a' -path '*pqcrypto*' | sort); do
    n=$((n + 1))
    if ! nm "$a" 2>/dev/null | grep -q " U $2"; then
      echo "sanitizers: $a is not instrumented (no $2 reference)" >&2
      exit 1
    fi
  done
  if [ "$n" -lt 3 ]; then
    echo "sanitizers: expected the PQClean C archives under $1, found $n" >&2
    exit 1
  fi
  echo "sanitizers: all $n PQClean C archives reference $2"
}

# Runs a test command; fails unless it exits 0 AND its `test result:` lines
# add up to at least <min> passed tests. A filter that no longer matches (a
# renamed module), a new cfg_attr(miri, ignore) or a test that stops being
# compiled would otherwise leave a green job that checked nothing. The
# minimums are the current counts: lower one only together with the change
# that removes those tests.
expect_passed() { # <min passed> <command...>
  min=$1
  shift
  mkdir -p "$root"
  log="$root/expect-passed.log"
  { rc=0; "$@" 2>&1 || rc=$?; echo "$rc" >"$log.rc"; } | tee "$log"
  rc=$(cat "$log.rc")
  if [ "$rc" -ne 0 ]; then
    exit "$rc"
  fi
  passed=$(sed -n 's/.*test result:.* \([0-9][0-9]*\) passed;.*/\1/p' "$log" | awk '{ n += $1 } END { print n + 0 }')
  if [ "$passed" -lt "$min" ]; then
    echo "sanitizers: $passed tests passed, expected at least $min: $*" >&2
    exit 1
  fi
  echo "sanitizers: $passed tests passed (at least $min expected): $*"
}

asan() {
  export CARGO_TARGET_DIR="$root/asan"
  # --target keeps the flags off build scripts and proc macros. std is not
  # rebuilt (-Zbuild-std is not required: the crates' own code and the C code
  # are instrumented, std's allocator is intercepted by the runtime).
  export RUSTFLAGS="-Zsanitizer=address"
  export RUSTDOCFLAGS="-Zsanitizer=address"
  # clang emits the instrumentation; the runtime is the one rustc links.
  export CC_x86_64_unknown_linux_gnu=clang
  export CFLAGS_x86_64_unknown_linux_gnu="-fsanitize=address -fno-omit-frame-pointer"
  export ASAN_OPTIONS="detect_leaks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_string_checks=1"
  for p in gnb-smh gnb-crypto pqcrypto-internals; do
    cargo +"$nightly" test --locked --target "$host" -p "$p"
  done
  assert_c_instrumented "$CARGO_TARGET_DIR" __asan_report
}

ubsan_env() {
  export CARGO_TARGET_DIR="$root/ubsan"
  export CC_x86_64_unknown_linux_gnu=gcc
  export CFLAGS_x86_64_unknown_linux_gnu="-fsanitize=undefined -fno-sanitize-recover=all -fno-omit-frame-pointer"
  # rustc links with -nodefaultlibs, so the driver does not add the runtime.
  export RUSTFLAGS="-C link-arg=-lubsan"
  export RUSTDOCFLAGS="-C link-arg=-lubsan"
  export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"
}

ubsan() {
  ubsan_env
  # gnb-smh has no C code; gnb-crypto runs ML-DSA-65 and Falcon-1024 through
  # pqcrypto-mldsa / pqcrypto-falcon and the vendored common code.
  for p in gnb-crypto pqcrypto-internals; do
    cargo test --locked --target "$host" -p "$p"
  done
  assert_c_instrumented "$CARGO_TARGET_DIR" __ubsan_handle
}

# The UBSan test binary of <test target> (cargo --lib / --test <name> args),
# built with the ubsan mode's flags if it is not there yet.
ubsan_test_bin() {
  cargo test --locked --target "$host" -p gnb-crypto "$@" --no-run --message-format=json \
    | sed -n 's/.*"executable":"\([^"]*\)".*/\1/p' | tail -n 1
}

# On an AVX2 machine pqcrypto-mldsa dispatches ML-DSA to its AVX2 code at run
# time, so the ubsan and asan modes never execute the clean ML-DSA C code that
# non-AVX2 x86_64 nodes run and that is compiled into the wasm32 wallet.
# qemu's Nehalem model has no AVX2: is_x86_feature_detected!("avx2") is false
# there and the same UBSan binaries take the clean path.
ubsan_noavx2() {
  ubsan_env
  lib=$(ubsan_test_bin --lib)
  acvp=$(ubsan_test_bin --test acvp_mldsa)
  for b in "$lib" "$acvp"; do
    [ -x "$b" ] || { echo "sanitizers: missing UBSan test binary '$b'" >&2; exit 1; }
  done
  cd crates/gnb-crypto # where cargo runs this crate's tests
  # Hybrid ML-DSA-65 + Falcon-1024 key generation, signing, verification and
  # KATs (crypto::), the wallet code that signs transactions with it, and the
  # official ACVP ML-DSA-65 vectors: about 35 s under emulation (all 280 lib
  # tests: ~10 min, mostly keystore KDFs with no ML-DSA in them).
  expect_passed 63 qemu-x86_64 -cpu Nehalem "$lib" \
    crypto:: wallet::payment:: wallet::legacy_sign_tests:: wallet::sighash_v3_signers::
  expect_passed 3 qemu-x86_64 -cpu Nehalem "$acvp"
}

miri() {
  export CARGO_TARGET_DIR="$root/miri"
  export MIRIFLAGS="${MIRIFLAGS:--Zmiri-strict-provenance}"
  # Tests that cannot run under Miri carry #[cfg_attr(miri, ignore = "<why>")].
  expect_passed 24 cargo +"$nightly" miri test --locked -p gnb-smh
  expect_passed 29 cargo +"$nightly" miri test --locked -p gnb-crypto --lib -- \
    core::limits:: core::tokenomics:: core::block_rules:: core::sighash:: core::activation::
  # Library tests only: tests/vendor_pin.rs reads files (Miri isolation) and
  # has no unsafe code.
  expect_passed 15 cargo +"$nightly" miri test --locked -p pqcrypto-internals --lib
}

miri_cross() {
  export CARGO_TARGET_DIR="$root/miri"
  export MIRIFLAGS="${MIRIFLAGS:--Zmiri-strict-provenance}"
  # gnb-smh has no C code, so Miri can interpret it for any target. Its Python
  # PoW vectors (log2_n <= 2) check every byte-order site on s390x.
  for t in i686-unknown-linux-gnu s390x-unknown-linux-gnu; do
    expect_passed 24 cargo +"$nightly" miri test --locked -p gnb-smh --target "$t"
  done
  # The wasm wallet's C ABI (gnb_alloc / gnb_call / gnb_free) packs a 32-bit
  # pointer into a u64, so its round trip runs on a 32-bit target. Its
  # dependencies' build scripts compile the PQClean C for i686 (gcc-multilib);
  # Miri never runs it (the signing test is ignored under Miri). Pointers
  # cross the ABI as integers (as from JavaScript): permissive provenance.
  export MIRIFLAGS=-Zmiri-permissive-provenance
  expect_passed 3 cargo +"$nightly" miri test --locked -p gnb-wallet-wasm --target i686-unknown-linux-gnu --lib
}

i686() {
  export CARGO_TARGET_DIR="$root/i686"
  # gnb-wallet-wasm: the wasm32 wallet core, the 32-bit consumer of gnb-crypto
  # (CRY-8), and its C ABI round trip (32-bit pointers only).
  for p in gnb-smh gnb-crypto coherence-core pqcrypto-internals gnb-wallet-wasm; do
    cargo test --locked --target i686-unknown-linux-gnu -p "$p"
  done
}

case "$mode" in
  asan) asan ;;
  ubsan) ubsan ;;
  ubsan-noavx2) ubsan_noavx2 ;;
  miri) miri ;;
  miri-cross) miri_cross ;;
  i686) i686 ;;
  *)
    echo "usage: sh scripts/sanitizers.sh asan|ubsan|ubsan-noavx2|miri|miri-cross|i686" >&2
    exit 2
    ;;
esac
