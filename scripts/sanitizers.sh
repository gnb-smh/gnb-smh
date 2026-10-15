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
#   sh scripts/sanitizers.sh miri        Miri: consensus arithmetic (gnb-smh, gnb-crypto core),
#                                        the unsafe code of pqcrypto-internals (nightly + miri)
#   sh scripts/sanitizers.sh miri-cross  Miri: gnb-smh on a 32-bit (i686) and a big-endian (s390x)
#                                        target
#   sh scripts/sanitizers.sh i686        the consensus crates' full test suites on
#                                        i686-unknown-linux-gnu (pinned toolchain, gcc-multilib)
#
# Each mode builds into its own directory, $SANITIZER_TARGET_DIR/<mode>
# (default target/sanitizers/<mode>), so sanitizer flags never reach the
# normal build. Each crate is tested in its OWN cargo invocation: gnb-crypto
# must not see the node's `test-pow-limit` dev feature (POW-5).
set -eu
cd "$(dirname "$0")/.."

mode=${1:-}
root=${SANITIZER_TARGET_DIR:-$PWD/target/sanitizers}
nightly=${SANITIZER_NIGHTLY:-nightly}
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

ubsan() {
  export CARGO_TARGET_DIR="$root/ubsan"
  export CC_x86_64_unknown_linux_gnu=gcc
  export CFLAGS_x86_64_unknown_linux_gnu="-fsanitize=undefined -fno-sanitize-recover=all -fno-omit-frame-pointer"
  # rustc links with -nodefaultlibs, so the driver does not add the runtime.
  export RUSTFLAGS="-C link-arg=-lubsan"
  export RUSTDOCFLAGS="-C link-arg=-lubsan"
  export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"
  # gnb-smh has no C code; gnb-crypto runs ML-DSA-65 and Falcon-1024 through
  # pqcrypto-mldsa / pqcrypto-falcon and the vendored common code.
  for p in gnb-crypto pqcrypto-internals; do
    cargo test --locked --target "$host" -p "$p"
  done
  assert_c_instrumented "$CARGO_TARGET_DIR" __ubsan_handle
}

miri() {
  export CARGO_TARGET_DIR="$root/miri"
  export MIRIFLAGS="${MIRIFLAGS:--Zmiri-strict-provenance}"
  # Tests that cannot run under Miri carry #[cfg_attr(miri, ignore = "<why>")].
  cargo +"$nightly" miri test --locked -p gnb-smh
  cargo +"$nightly" miri test --locked -p gnb-crypto --lib -- \
    core::limits:: core::tokenomics:: core::block_rules:: core::sighash:: core::activation::
  # Library tests only: tests/vendor_pin.rs reads files (Miri isolation) and
  # has no unsafe code.
  cargo +"$nightly" miri test --locked -p pqcrypto-internals --lib
}

miri_cross() {
  export CARGO_TARGET_DIR="$root/miri"
  export MIRIFLAGS="${MIRIFLAGS:--Zmiri-strict-provenance}"
  # gnb-smh has no C code, so Miri can interpret it for any target.
  for t in i686-unknown-linux-gnu s390x-unknown-linux-gnu; do
    cargo +"$nightly" miri test --locked -p gnb-smh --target "$t"
  done
}

i686() {
  export CARGO_TARGET_DIR="$root/i686"
  for p in gnb-smh gnb-crypto coherence-core pqcrypto-internals; do
    cargo test --locked --target i686-unknown-linux-gnu -p "$p"
  done
}

case "$mode" in
  asan) asan ;;
  ubsan) ubsan ;;
  miri) miri ;;
  miri-cross) miri_cross ;;
  i686) i686 ;;
  *)
    echo "usage: sh scripts/sanitizers.sh asan|ubsan|miri|miri-cross|i686" >&2
    exit 2
    ;;
esac
