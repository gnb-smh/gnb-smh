# Sanitizers, Miri and 32-bit testing

This page documents the dynamic-analysis checks of the consensus crates: what
each one runs, how it is configured, how to run it, and what it found. Every
mode is one command, `sh scripts/sanitizers.sh <mode>`, and the CI jobs
`sanitizers`, `miri` and `i686` (`.github/workflows/ci.yml`) call exactly
that command.

| Mode | What runs | CI job | Result (local run, 2026-10-15) |
| --- | --- | --- | --- |
| `asan` | AddressSanitizer + LeakSanitizer over the test suites of `gnb-smh`, `gnb-crypto` (alone) and `pqcrypto-internals`, with the Rust code and the PQClean C code instrumented | `sanitizers` | pass; one leak report (in two tests, F1), fixed |
| `ubsan` | UndefinedBehaviorSanitizer over the PQClean C code, under the `gnb-crypto` and `pqcrypto-internals` test suites | `sanitizers` | pass; no report |
| `ubsan-noavx2` | the UBSan ML-DSA, wallet-signing, ACVP and Wycheproof tests on qemu's Nehalem CPU (no AVX2): the same binaries on a second CPU, so a CPU-dependent ML-DSA verdict fails (F6) | `sanitizers` | pass; no report |
| `ubsan-noavx2-full` | every `gnb-crypto` lib and integration test, under UBSan, on qemu's Nehalem CPU | `sanitizers` (nightly schedule and manual dispatch only) | pass; no report (363 tests) |
| `miri` | Miri over the pure-Rust consensus arithmetic and the unsafe RNG override | `miri` | pass; no undefined behaviour |
| `miri-cross` | Miri over `gnb-smh` (including the Python PoW vectors) on `i686` (32-bit) and `s390x` (big-endian), and over the wasm wallet's C ABI on `i686` | `miri` | pass |
| `i686` | the full test suites of `gnb-smh`, `gnb-crypto`, `coherence-core`, `pqcrypto-internals` and `gnb-wallet-wasm` on `i686-unknown-linux-gnu` | `i686` | pass; one failure (a 64-bit assumption in a test, F2), fixed; a concurrent run exposed a temp-file race between test processes (F3), fixed; the wallet's `minfee` truncated sizes on 32-bit targets (F4), fixed |
| `i686-node` | every test target of the node (`gnb`: lib, bins, integration tests) on `i686-unknown-linux-gnu`, RocksDB and the other C/C++ dependencies built for 32 bits | `i686-node` (nightly schedule and manual dispatch only) | pass after fix F5 (1230 tests); `cargo test` there also rewrote the committed fuzz corpus, fixed |
| (default) | node lib tests with debug assertions and overflow checks | `workspace-test` | pass (288 tests; 324 on the merged PR branch); now guarded by a test |
| (local only) | parking_lot deadlock detection over the node's lock-using tests | none (needs new dependencies, see [Deadlock detection](#deadlock-detection)) | no deadlock in 288 lib and 58 integration tests; positive control detected |

Local environment of the results below: Ubuntu 24.04, x86_64 with AVX2;
pinned toolchain 1.94.1; nightly `nightly-2026-10-14` (`rustc
1.101.0-nightly (822182db4 2026-10-13)`) with the matching Miri; clang
18.1.3; gcc 13.3.0 with `gcc-multilib`; qemu-user 8.2.

The nightly is pinned: the script defaults to `nightly-2026-10-14` and CI
sets the same `SANITIZER_NIGHTLY`, so a nightly without Miri, or a rustc
change to `-Zsanitizer`, cannot change a result without a change in the
repository. Bump both on purpose (`SANITIZER_NIGHTLY=nightly-<date> sh
scripts/sanitizers.sh <mode>` tries a newer one locally).

The Miri modes and `ubsan-noavx2` select tests by name filter or by
`cfg_attr(miri, ignore)`, so a renamed module could leave a green step that
ran nothing (`0 passed` exits 0). Each of those commands therefore runs
through `expect_passed <minimum>`, which sums the `N passed` of every `test
result:` line and fails below the minimum; the minimums are the current
counts (below).

A test that Miri cannot finish does not fail: it runs until the CI job's
timeout (the `miri` jobs of merge commit `299a718`, whose two `core::limits`
cap tests build 10^5 to 10^6 elements, were still in their host step after
115 minutes). Every Miri command therefore also runs under `timeout(1)`
(`with_miri_timeout`, `SANITIZER_MIRI_TIMEOUT` seconds, default 1800, about
four times the slowest command, `gnb-smh` with its v2/v3 vectors), which
stops the whole process group and names the remedy, `cfg_attr(miri, ignore =
"<why>")` or a smaller input under `cfg(miri)`. A test that calls the
PQClean C code needs the same attribute; it fails at once under Miri
(unsupported foreign call) rather than hanging.

Each mode builds into its own directory, `$SANITIZER_TARGET_DIR/<mode>`
(default `target/sanitizers/<mode>`), so sanitizer flags never reach the
normal build, and each crate is tested in its own cargo invocation:
`gnb-crypto` must not see the node's `test-pow-limit` dev feature (POW-5), so
the real ASERT path runs.

## AddressSanitizer and LeakSanitizer (`asan`)

```sh
rustup toolchain install nightly-2026-10-14 --profile minimal
sh scripts/sanitizers.sh asan
```

Configuration (all set by the script):

| Setting | Value | Why |
| --- | --- | --- |
| `RUSTFLAGS`, `RUSTDOCFLAGS` | `-Zsanitizer=address` | instruments the Rust code of every crate in the graph and links the ASan runtime into test binaries and doctests |
| `--target` | `x86_64-unknown-linux-gnu` | keeps the flag off build scripts and proc macros |
| `CC_x86_64_unknown_linux_gnu` | `clang` | clang emits the same instrumentation ABI as the runtime rustc links |
| `CFLAGS_x86_64_unknown_linux_gnu` | `-fsanitize=address -fno-omit-frame-pointer` | instruments the C code the `pqcrypto-*` build scripts compile with the `cc` crate |
| `ASAN_OPTIONS` | `detect_leaks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_string_checks=1` | leak checking at exit, use-after-return, stricter string interceptors |
| `-Zbuild-std` | not used | not required: the crates and the C code are instrumented, and the runtime intercepts `malloc`/`free`/`memcpy`, so std's heap and copies are checked; only accesses *inside* std's own code are not |

The C code covered is every PQClean archive the build scripts produce: the
vendored `pqcrypto-internals` common code (`fips202.c`, `aes.c`, `sha2.c`,
`nistseedexpander.c`, `sp800-185.c`, the AVX2 `keccak4x`), and from the
`pqcrypto-mldsa` / `pqcrypto-falcon` crates ML-DSA-44/65/87 (clean; the AVX2
archives too before F6) and Falcon-512/1024 (clean, padded and unpadded). After the tests the script
checks that each of these archives references `__asan_report_*` and fails
otherwise, so a build change that silently drops the C flags fails CI.
`pqcrypto-mldsa` and `pqcrypto-falcon` cannot be tested as packages here
(`cargo test -p` refuses non-members with dev-dependencies); their C code runs
under the `gnb-crypto` suite, which generates keys, signs and verifies with
both algorithms (including the ACVP ML-DSA vectors and the Falcon round-3
submission vectors).

Result: all suites pass with no ASan or LSan report after fix F1
(`gnb-smh`: 19 unit, 5 integration; `gnb-crypto`: 280 unit (1 ignored), 21
integration, doctests; `pqcrypto-internals`: 17 unit (1 ignored helper), 2
integration, 2 doctests). On the merged PR branch: `gnb-smh` 26 unit, 5
integration; `gnb-crypto` 338 unit (1 ignored), 25 integration (1 ignored),
doctests; `pqcrypto-internals` unchanged; no report (see
[On the merged PR branch](#on-the-merged-pr-branch)).

Positive controls (each mutation was reverted after the run):

- C: `keccak_inc_absorb` in `cfiles/fips202.c` reading one byte past the
  input (`i < mlen + (mlen > 0)`) is reported in
  `acvp_mldsa::production_signer_interoperates_with_an_official_acvp_keypair`
  as `global-buffer-overflow ... READ of size 1 ... in keccak_inc_absorb`,
  called from `PQCLEAN_MLDSA65_AVX2_crypto_sign_signature_ctx`.
- Rust: building the FFI slice in `PQCRYPTO_RUST_randombytes` with `len + 1`
  is reported in `seeded_is_deterministic` as `stack-buffer-overflow ...
  WRITE of size 1` from `ChaCha20Rng::fill_bytes`.

Limits:

- Writes made by the kernel are invisible to ASan. With the same `len + 1`
  mutation, `default_behavior_is_random` (OS entropy: the buffer is filled by
  the `getrandom` system call) passes under ASan. Miri reports it (below).
- Until F6, `pqcrypto-mldsa` dispatched ML-DSA to its AVX2 code at run time
  on an AVX2 machine, so the clean ML-DSA code was linked and instrumented
  but not executed by this job. Since F6 every build links the clean ML-DSA
  code only, like Falcon (`scripts/falcon-clean-guard.sh` guards both), and
  this job executes it; `ubsan-noavx2` (next section) runs it again on a CPU
  without AVX2.

## UndefinedBehaviorSanitizer for the C code (`ubsan`)

```sh
sh scripts/sanitizers.sh ubsan     # pinned toolchain; gcc and libubsan
```

The C code is compiled by gcc with `-fsanitize=undefined
-fno-sanitize-recover=all -fno-omit-frame-pointer`, so the first report
aborts the test binary; `UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1`.
rustc links with `-nodefaultlibs`, so the gcc driver does not add the UBSan
runtime by itself: the script links it with `-C link-arg=-lubsan` (the first
attempt, with `-C link-arg=-fsanitize=undefined`, failed to link with
undefined `__ubsan_handle_*_abort` symbols). gcc is used instead of clang
because clang's UBSan runtime (`libclang-rt-18-dev`) is not installed by
default on Ubuntu, while `libubsan` ships with gcc. The script checks that
every PQClean archive references `__ubsan_handle_*`.

Rust code has no UBSan: Rust's own overflow checks (on in every test profile,
see below) and Miri cover the Rust side.

Result: `gnb-crypto` (280 unit, 21 integration, doctests; 338 and 25 on the
merged PR branch) and `pqcrypto-internals` pass with no report.

Positive control: changing the shift in `keccak_inc_absorb` to
`8 * ((s_inc[25] + i) & 0x0F)` is reported as `cfiles/fips202.c:459:55:
runtime error: shift exponent 64 is too large for 64-bit type 'long unsigned
int'` and fails the test run.

### ML-DSA without AVX2 (`ubsan-noavx2`)

```sh
sudo apt-get install qemu-user
sh scripts/sanitizers.sh ubsan      # builds the UBSan test binaries
sh scripts/sanitizers.sh ubsan-noavx2
```

The `ubsan` binaries run under `qemu-x86_64 -cpu Nehalem`, a CPU model
without AVX/AVX2, where `is_x86_feature_detected!("avx2")` is false. Until
F6 that made `pqcrypto-mldsa` take its clean ML-DSA C code instead of the
AVX2 code the `ubsan` step ran; since F6 every build runs the clean code, and
this mode runs the same binaries on a second CPU, so an ML-DSA verdict that
depends on the CPU (F6: Wycheproof tcId 161) fails one of the two runs.
Selection (from `crates/gnb-crypto`, where cargo runs its tests): the
`gnb-crypto` lib tests `crypto::` (hybrid key generation, signing,
verification, KATs, the FIPS 204 UseHint verdicts of
`crypto::mldsa_one_verdict`), `wallet::payment::`,
`wallet::legacy_sign_tests::`, `wallet::sighash_v3_signers::` (67 passed, 1
ignored; minimum 67), the `acvp_mldsa` integration test (the official ACVP
ML-DSA-65 vectors; 3 passed; minimum 3) and `wycheproof_mldsa65` (the
Wycheproof ML-DSA-65 vectors through the library and the consensus wrapper;
2 passed; minimum 2). About 35 s locally before F6; the whole lib suite took 575 s under
emulation (280 passed, no report; mostly keystore KDFs with no ML-DSA in
them), so it is not in the per-push job; the whole suite is its own mode,
`ubsan-noavx2-full`, which CI runs nightly (next section).

### The whole `gnb-crypto` suite without AVX2 (`ubsan-noavx2-full`)

```sh
sh scripts/sanitizers.sh ubsan-noavx2-full   # builds the UBSan test binaries if needed
```

Every `gnb-crypto` lib and integration test binary (the `ubsan` mode's
binaries, listed by `cargo test --no-run`) runs to completion under `qemu-x86_64
-cpu Nehalem`, from `crates/gnb-crypto`; `expect_passed` sums all of them
(minimum 363). CI: a step of the `sanitizers` job that runs only on the
nightly schedule and on manual dispatch (`if: github.event_name ==
'schedule' || github.event_name == 'workflow_dispatch'`), so pushes do not
pay the emulation time.

Result (local, merged PR branch): pass, no UBSan report: 338 lib tests (1
ignored) and the 25 integration tests (1 ignored) of the eight integration
binaries; the lib binary takes 319 s under emulation, the rest about 30 s.

Positive control (on a scratch copy, `[patch.crates-io]` to a copy of
`pqcrypto-mldsa` 0.1.2): a signed overflow added to
`PQCLEAN_MLDSA65_CLEAN_ntt` (`volatile int32_t p = 0x7fffffff; p = p +
(a[0] != 0x7fffffff);`, no effect on the results) is reported by
`ubsan-noavx2` as `ml-dsa-65/clean/ntt.c:54:67: runtime error: signed
integer overflow: 1 + 2147483647 cannot be represented in type 'int'` in
`PQCLEAN_MLDSA65_CLEAN_ntt` <- `PQCLEAN_MLDSA65_CLEAN_poly_ntt`, by both the
lib and the ACVP binary, while the same UBSan binaries run natively (AVX2,
what the `ubsan` step does) pass, 63 and 3 tests.

## Miri (`miri`, `miri-cross`)

```sh
rustup toolchain install nightly-2026-10-14 --profile minimal --component miri,rust-src
sh scripts/sanitizers.sh miri
sudo apt-get install gcc-multilib   # miri-cross: gnb-wallet-wasm's build scripts compile C for i686
sh scripts/sanitizers.sh miri-cross
```

`MIRIFLAGS=-Zmiri-strict-provenance` (`-Zmiri-permissive-provenance` for
the wasm wallet's ABI, whose pointers cross as integers, as they do from
JavaScript); isolation stays on (no file system or clock access). What runs
(minimum passed-test count of each command in brackets):

| Crate | Tests | Notes |
| --- | --- | --- |
| `gnb-smh` | every unit test (compact bits, chain work, ASERT including the AUD-1 wide multiply and shift, the lane-level Keccak step, the scratchpad, the v2 SHA-256 draft and v3), `tests/difficulty_vectors.rs`, `tests/vectors.rs` (the Python PoW vectors with log2_n = 1 and 2), `tests/vectors_v2.rs` and `tests/vectors_v3.rs` (the log2_n = 4 vectors) [36] | the log2_n = 10 and 19 PoW vectors and the large v2/v3 vectors skipped, `canonical_entry_points_match_the_reference_vector` ignored (below) |
| `gnb-crypto` | `core::limits`, `core::tokenomics`, `core::block_rules` (Merkle roots, coinbase branch, coinbase commitment, witness root), `core::sighash`, `core::activation` [42] | six tests ignored (below) |
| `pqcrypto-internals` | the library tests: the `unsafe extern "C"` RNG entry point and the thread-local seeded-RNG stack, including guard drops after TLS destruction [15] | the two re-exec tests ignored |
| `gnb-smh` on `i686-unknown-linux-gnu` and `s390x-unknown-linux-gnu` | the same `gnb-smh` tests on a 32-bit and a big-endian target, including the whole PoW pipeline against the Python reference [30 each] | `miri-cross`; std for the target is built by `cargo miri setup` |
| `gnb-wallet-wasm` on `i686-unknown-linux-gnu` | the lib tests, among them `c_abi_roundtrip_on_32_bit`: `gnb_alloc` / `gnb_call` / `gnb_free` as `site/wallet/core.js` calls them, plus `minfee` on 32 bits [3] | `miri-cross`; `create_export_open_roundtrip_and_pay` ignored (PQClean C) |

Result: no undefined behaviour (`gnb-smh` 19 unit, 4 difficulty-vector
tests and the PoW vector test, `gnb-crypto` 29 tests, `pqcrypto-internals` 15
tests). The `miri` mode takes about 6 minutes locally (363 s with the
dependencies already built; Miri's own timings: `gnb-smh` unit tests 80 s,
difficulty vectors 60 s, PoW vectors 41 s, the `gnb-crypto` selection 185 s,
`pqcrypto-internals` 11 s). On the merged PR branch: `gnb-smh` 25 unit (1
ignored), 4 and 1; `gnb-crypto` 42 (5 ignored); `pqcrypto-internals` 15; no
undefined behaviour; 393 s (the `gnb-crypto` selection 291 s).

Hashing is what limits Miri: one Keccak-f[1600] permutation takes about
0.4 s and one SHA-256 compression about 0.2 s (measured: the full
`step_matches_shake256`, 400 lane-level steps plus 400 SHAKE256 calls, took
364 s; the 17-leaf coinbase-branch test did not finish in 20 minutes). The hash-heavy tests therefore run smaller under
`cfg(miri)` and in full natively, and the ones that cannot be made small are
ignored with the reason in the attribute:

| Test | Under Miri | Why |
| --- | --- | --- |
| `gnb-smh` `step_matches_shake256` | 3 trials (200 natively) | Keccak cost |
| `gnb-smh` `nonce_and_header_change_output` | 2-block scratchpad (256 natively) | Keccak cost; both phases and both tags still run |
| `gnb-smh` `low_anchor_bits_match_legacy_order` | 132-point grid over the same ranges (~132,000 natively) | ~0.45 s per point (bit-by-bit legacy shifts) |
| `gnb-smh` `tests/difficulty_vectors.rs` | the vector file is parsed once per binary | 35 s per parse; natively unchanged |
| `gnb-crypto` Merkle tests (`legacy_root_is_bit_identical_...`, `duplicate_last_mutation_...`, `coinbase_branch_reproduces_the_root`) | trees up to 5 leaves (17 natively) | SHA-256 cost; empty, single, odd and even levels and a carried-up node are still covered |
| `gnb-smh` `matches_python_reference` | the 10 vectors with log2_n = 1 and 2 (all 17 natively); fails if fewer than 10 ran | log2_n = 10 and 19 cost 2^11 and 2^20 Keccak permutations per vector; log2_n <= 2 is at most 8 inner permutations and still runs seed, fill, data-dependent mix and final digest |
| `gnb-smh` `v2::tests::step_matches_sha256` | 3 trials (200 natively) | SHA-256 cost (~0.2 s per compression) |
| `gnb-smh` `v2::tests::nonce_and_header_change_output` | 2-block scratchpad (256 natively) | SHA-256 cost; both phases and both tags still run |
| `gnb-smh` `v3::tests::inputs_change_output` | 4-block scratchpad (64 natively), 30 s | two Keccak permutations per step; pass 0, the later passes and their wrap-around predecessor still run |
| `gnb-smh` `v2_matches_python_reference` (`tests/vectors_v2.rs`) | the 5 vectors with log2_n = 4 (all 10 natively); fails if fewer than 5 ran | log2_n = 13 is 16,384 compressions per vector, about an hour each under Miri; log2_n = 4 still runs seed, fill, data-dependent mix and final digest |
| `gnb-smh` `v3_matches_python_reference` (`tests/vectors_v3.rs`) | the 5 log2_n = 4 one-pass vectors and the first log2_n = 4 three-pass vector (all 15 natively); fails if fewer than 6 ran | log2_n = 15 is 2^16 steps (2^17 permutations) per vector, about 15 hours each under Miri; the small ones still run the seed, pass 0, the later passes and the final digest |
| `gnb-crypto` `v3_cost_is_linear_in_the_input_count` | ignored | ~300 Keccak permutations of byte counting; its arithmetic also runs in `v3_commits_to_every_field` |
| `gnb-smh` `canonical_entry_points_match_the_reference_vector` | ignored | five canonical evaluations (log2_n = 19, 64 MiB, ~2^20 Keccak permutations each); the log2_n <= 2 Python vectors run the same pipeline under Miri |
| `gnb-crypto` `core::sighash` `v3_scripts_verify_and_every_fault_is_rejected`, `v2_scripts_verify_below_the_activation` | ignored | hybrid key generation and signing through the PQClean C code, which Miri cannot execute |
| `gnb-crypto` `core::limits` `block_count_caps_are_inclusive` | ignored | blocks of 1,000,000 transactions and 100,000 shielded transactions: still running after 17 minutes under Miri; `check_block_canonical_limits` runs under Miri in the other cap tests |
| `gnb-crypto` `core::limits` `transaction_count_caps_are_inclusive` | ignored | 100,000 inputs and 100,000 outputs, cloned: still running after 9 minutes under Miri; `check_tx_canonical_limits` runs under Miri in the other tests of the module |
| `gnb-crypto` `core::limits` `count_and_size_caps_match_the_wire_parser` (fuzzing merge) | ignored | builds, encodes and parses a block of 1,000,000 transactions (`block_count_caps_are_inclusive` only builds and checks it and was still running after 17 minutes under Miri), transactions of 100,000 inputs and outputs and an 8 MB proof; the parser and `check_*_canonical_limits` run under Miri in `limits_match_the_wire_parser` and the other tests of the module |
| `pqcrypto-internals` `os_rng_failure_aborts_instead_of_failing_open`, `null_buffer_aborts_instead_of_failing_open` | ignored | they re-execute the test binary (`std::process::Command`), which Miri does not support |
| `pqcrypto-internals` `tests/vendor_pin.rs` | not run (`--lib`) | reads files (isolation); no unsafe code |

Not selected at all: FFI signing and verification (Miri cannot execute C),
and anything that opens RocksDB (the node).

`miri-cross` takes about 5 to 6 minutes locally (308 s and 331 s in two
runs with the target sysroots cached); on each of i686 and s390x the 19 unit, 4 difficulty-vector
tests and the PoW vector test (10 vectors) pass, and `gnb-wallet-wasm` passes
3 tests on i686 (1 ignored). No undefined behaviour. On the merged PR branch:
25 unit (1 ignored), 4 and 1 on each target, the wallet's 3; 408 s including
the two target sysroots.

Positive controls:

- Building the FFI slice with `len + 1` in `PQCRYPTO_RUST_randombytes` is
  reported by Miri in `default_behavior_is_random` as `Undefined Behavior:
  constructing invalid value of type &mut [u8]: encountered a dangling
  reference (going beyond the bounds of its allocation)` at the
  `slice::from_raw_parts_mut` call, the case ASan misses.
- Wasm wallet ABI (each reverted): leaking `gnb_call`'s output as an
  unshrunk `Vec` (capacity larger than the length later passed to
  `gnb_free`) passes natively on i686 and is reported by Miri as
  `incorrect layout on deallocation: ... has size 32 and alignment 1, but
  gave size 22`; `gnb_free` with capacity `len + 1`, and `gnb_alloc` without
  `.max(1)` (a dangling pointer for an empty request), are reported by Miri
  as dangling references (natively they crash).
- Endianness: each of four byte-order slips in `gnb-smh` passes every
  native test on x86_64, the Python reference vectors included
  (little-endian hides them), and fails `matches_python_reference` under Miri
  on s390x (`cargo miri test -p gnb-smh --target s390x-unknown-linux-gnu
  --test vectors`, 6 to 12 s): `u64::from_ne_bytes` in `bytes_to_lanes`
  ("fill log2_n=1 nonce=0"), `nonce.to_ne_bytes()` in `seed` ("seed log2_n=1
  nonce=1"), `len.to_ne_bytes()` in `enc` ("seed log2_n=1 nonce=0") and
  `to_ne_bytes` in `lanes_to_bytes` (also caught by `step_matches_shake256`).
  The first three were invisible to Miri until the log2_n = 1 and 2 vectors
  existed: the only independent PoW check, `tests/vectors.rs`, was ignored
  under Miri, and the unit tests compare outputs only with each other
  (review finding; the reviewer's own log2_n = 1 known answer for
  `(b"gnb", 0)`, `62665881...45d7af5`, is one of the new vectors).

## 32-bit build and tests (`i686`)

```sh
sudo apt-get install gcc-multilib
rustup target add i686-unknown-linux-gnu
sh scripts/sanitizers.sh i686
```

The audit's CRY-8 class is arithmetic that is safe with a 64-bit `usize` and
overflows or truncates with a 32-bit one (i686, and the wasm32 browser
wallet, which uses `gnb-crypto`). The job runs the complete test suites of
`gnb-smh`, `gnb-crypto`, `coherence-core`, `pqcrypto-internals` and
`gnb-wallet-wasm` (the wasm32 wallet core itself) on
`i686-unknown-linux-gnu`, PQClean C included (`gcc -m32`). The difficulty,
Merkle and sighash vector suites pass there, so compact bits, ASERT, chain
work, both Merkle trees and both sighash versions are bit-identical on 32-
and 64-bit targets. On a 32-bit target `gnb-wallet-wasm` also compiles
`c_abi_roundtrip_on_32_bit`, which drives `gnb_alloc` / `gnb_call` /
`gnb_free` exactly as `site/wallet/core.js` does (the `(ptr << 32) | len`
packing holds only for 32-bit pointers).

Result: all pass after fixes F2 and F4. The node is the `i686-node` mode
(next section).

### The node on i686 (`i686-node`)

```sh
sudo apt-get install g++-multilib clang libclang-dev   # RocksDB (C++) and its bindgen, for 32 bits
rustup target add i686-unknown-linux-gnu
sh scripts/sanitizers.sh i686-node
```

Every test target of `gnb` (the lib, the binaries, every integration test;
the crate has no doctests) on `i686-unknown-linux-gnu`, with RocksDB,
zstd, lz4, bzip2, zlib and the PQClean C compiled for 32 bits. Above all,
the node's decoders of untrusted input must give a 32-bit build the verdicts
a 64-bit build gives. CI: job
`i686-node`, on the nightly schedule and on manual dispatch only
(locally about 10 minutes to build the lib and binary tests, RocksDB
included, and 11 more to build and run the integration tests).

Result: one failure (F5, a 32-bit decoding difference in the gossip and
sync codecs), fixed; then all pass: the lib (326 tests), the `gnb` binary
(350), `gnb-cli` (3) and the 69 integration targets (551 passed, 8 ignored),
1230 tests in all, with the committed fuzz seed corpus unchanged after the
run (`parser_corpus_floor` regenerates it; on i686 it used to write a
different one, see the follow-ups below).

## Debug assertions and overflow checks

The node's lib tests already run with debug assertions and overflow checks:
the dev/test profile enables debug assertions, `overflow-checks` follows
them, and the root `Cargo.toml` overrides only `opt-level` per package. The
release profile sets `overflow-checks = true` explicitly. `cargo test -p gnb
--lib` passes (288 tests; 324 on the merged PR branch). Two tests now keep it that way:

- `node/src/lib.rs` `build_profile_tests::test_build_traps_integer_overflow_and_debug_assertions`;
- `gnb-smh` `tests::integer_overflow_panics_in_this_profile`, which CI also
  runs with `--release` (job `consensus-crates`).

Mutation checks: `[profile.dev.package.gnb] overflow-checks = false` and,
separately, `debug-assertions = false` (a `debug_assert!` that must fire)
fail the node test; `CARGO_PROFILE_DEV_OVERFLOW_CHECKS=false` and, with
`--release`, `CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS=false` fail the gnb-smh
test.

## Deadlock detection

The node takes `parking_lot` locks on its consensus paths (the acceptance
`ReentrantMutex` in `Storage`, the DAG `RwLock`, the mempool and RPC locks).
`parking_lot`'s `deadlock_detection` feature cannot be enabled in this
repository without changing `Cargo.lock`: it adds eight packages
(`addr2line 0.25.1`, `backtrace 0.3.76`, `fixedbitset 0.4.2`,
`gimli 0.32.3`, `miniz_oxide 0.8.9`, `object 0.37.3`, `petgraph 0.6.5`,
`rustc-demangle 0.1.28`), and the second `miniz_oxide` (next to 0.9.1) would
also need a `deny.toml` exception (`multiple-versions = "deny"`). It is
therefore not in CI; adding it is a dependency decision for the maintainers.

Local experiment (not committed), on an exported copy of this tree with its
own lockfile and target directory:

1. `node/Cargo.toml` `[dev-dependencies]`:
   `parking_lot = { version = "0.12", features = ["deadlock_detection"] }`
   (feature unification turns detection on for every `parking_lot` lock the
   node takes in test builds, `ReentrantMutex` and `RwLock` included);
2. a watchdog started before `main` in each test binary (`node/src/lib.rs`
   for the lib tests, `node/tests/fix_common/mod.rs` for the `fix_*`
   integration tests):

   ```rust
   #[used]
   #[link_section = ".init_array"]
   static START: extern "C" fn() = start;
   extern "C" fn start() {
       std::thread::spawn(|| loop {
           std::thread::sleep(std::time::Duration::from_millis(250));
           let cycles = parking_lot::deadlock::check_deadlock();
           if !cycles.is_empty() {
               for (i, threads) in cycles.iter().enumerate() {
                   for t in threads {
                       eprintln!("DEADLOCK cycle {i}: {:?}\n{:?}", t.thread_id(), t.backtrace());
                   }
               }
               std::process::abort();
           }
       });
   }
   ```

Results:

| Run | Result |
| --- | --- |
| Positive control: two threads take two `parking_lot::Mutex`es in opposite order | the watchdog prints `DEADLOCK DETECTED: 1 cycle(s)` with both threads and aborts (SIGABRT) |
| `cargo test -p gnb --lib` (acceptance lock, DAG, store, mempool, RPC scan gate, ...) | 288 passed; repeated 10 times, no deadlock |
| `fix_dag10_11_12_commit` (six threads accepting conflicting siblings, then their children, into one node), `fix_dag1_acceptance`, `fix_mempool_template`, `fix_block_rules` | 58 passed, no deadlock |
| `concurrent_acceptance_equals_sequential_acceptance` alone, 30 times | no deadlock |

Limits: the detector sees only `parking_lot` locks (not `std::sync` or
`tokio` locks) and only cycles that actually form while it runs; it is not a
lock-order analysis, so a rare interleaving that never occurred in these runs
is not ruled out.

## Findings

| Id | Tool | Finding | Root cause | Fix |
| --- | --- | --- | --- | --- |
| F1 | LeakSanitizer | 80 bytes in 5 allocations leaked by `scoped_rng_cleans_forgotten_nested_guards_on_return_and_unwind` and `scoped_rng_cleanup_survives_outer_guard_removed_inside_closure` (`pqcrypto-internals`) | The tests simulate a forgotten guard with `std::mem::forget`; the scope cleanup drops the stack entry's `Rc<()>`, the forgotten guard's clone is never dropped. Test-only: `with_seeded_rng` is private and `with_seeded_rng_scope` never forgets a guard; the `gnb-crypto` run reports no leak | The tests park such guards in `ManuallyDrop` and reclaim them after the scope. The late drops run over a live sentinel override, which must still be the only entry and still yield the first bytes of its ChaCha20 stream afterwards (a first version checked the stack length over an empty stack, which no wrong `drop` could change). Still fail when the scope cleanup is broken (`truncate` replaced by `remove`); `SeededRngGuard::drop` clearing or popping the stack when its entry is gone fails `scoped_rng_cleanup_survives_outer_guard_removed_inside_closure` at the sentinel check |
| F2 | i686 | `min_fee_has_a_floor_and_scales_with_size` failed: it expected `min_tx_fee_sat(usize::MAX)` to saturate at `u64::MAX / 1000` | The test assumed a 64-bit `usize`; with 32 bits the u64 product does not saturate and the function correctly returns the exact fee. The function computes in u64 on every target, so fees agree on 32- and 64-bit platforms | The test asserts the exact fee of the largest 32-bit size on every target and the saturating value only on 64-bit targets |
| F3 | concurrent runs | `wallet::legacy_keystore_tests::save_load_roundtrip_still_works` failed with "No such file or directory" in the i686 run while the UBSan suite ran the same test in another process | Seven keystore tests (`wallet::legacy_keystore_tests` x4, `hd_wallet::tests` x3) write a fixed file name in the shared temp directory and delete it at start and end, so two test processes delete each other's file. Reproduced by running one test binary twice at once, 15 times: 15 of 30 runs failed for one test, 1 of 30 for another | The names carry the process id (as the neighbouring tests already do); 0 of 30 concurrent runs fail for each of the seven. Matters for parallel sanitizer runs and for `cargo mutants -j N` |
| F4 | review (code reading), confirmed on `i686` | The wasm wallet's `minfee` request quoted the floor fee for a size of 2^32 bytes or more on 32-bit targets: 2^32 + 100 was priced as 100 bytes (10,000 instead of 8,589,934,792) | CRY-8: `size as usize` wraps modulo 2^32 where `usize` has 32 bits (wasm32, i686); `gnb-wallet-wasm` was in none of the 32-bit runs | `usize::try_from(size)`, error "`size` too large". `minfee_does_not_truncate_sizes_on_32_bit_targets` and `c_abi_roundtrip_on_32_bit` fail on i686 with the old cast (fee "10000") and pass after; on x86_64 the old cast passes. Low impact: such sizes are absurd |
| F5 | `i686-node` | `network::tests::wire_decode_rejects_multi_gb_declared_vec` failed on i686: a gossip frame whose `block_data` declares 8 GiB (a 9-byte varint, then nothing) decoded as a `NewBlock` with an empty `block_data` | bincode 2.0.1's serde bridge reads every sequence and map length with `usize::decode` (`varint_decode_usize`: `u64 as usize`), so on a 32-bit target a declared length of 2^32 * k + n decodes as n. A frame that every 64-bit node refuses (it announces more bytes than it carries) decoded on a 32-bit node into a different message; the `/gnb/sync/1` codec decodes the same way. P2P framing only: no consensus encoding is decoded with bincode from untrusted input | The gossip and sync decoders require the canonical encoding: the decoded message must re-encode to the frame (`WireDecodeError::NonCanonical`, a penalized protocol violation, except for `NewBlock` and `NewTransaction` frames, which releases without the rule relay, so they are dropped without penalty: docs/CONSENSUS.md, "Wire encoding"; `InvalidData` on the sync path). The same rule refuses non-minimal varints on every target (byte-distinct frames of one message, each a fresh gossip message id: the NET-7 de-duplication bypass without trailing bytes), which the fuzzing package (merged after this one, docs/testing/FUZZING.md) found independently; its code (commit `f471e83`) is used verbatim so that its merge is clean. `wire_decode_requires_the_canonical_encoding` and `non_canonical_frames_are_rejected` fail on x86_64 without the check (non-minimal tag, integer and length forms decode) and pass with it; `wire_decode_rejects_multi_gb_declared_vec` fails on i686 without it and passes with it |
| F6 | `i686`, confirmed on x86_64 under `qemu-x86_64 -cpu Nehalem` | After the merge of the relaunched mainnet line, `wycheproof_mldsa65` failed on i686: the consensus wrapper ACCEPTED Wycheproof tcId 161 (a valid ML-DSA-65 signature under an all-zero public key), which the test expected it to refuse, and the library disagreed with Wycheproof on none of the 42 cases it was pinned to disagree on. The same x86_64 test binary gives the i686 verdicts on a CPU without AVX2 | `pqcrypto-mldsa`'s default features compile PQClean's AVX2 (x86_64, except Windows) and AArch64 ML-DSA and dispatch to them, AVX2 at run time per CPU; everything else (i686, wasm32, x86_64 without AVX2, Windows) runs `clean`. The AVX2 verifier is not FIPS 204: it never checks ‖z‖∞ < γ1 − β (41 Wycheproof cases accepted; the wrapper already refused them, `mldsa65_z_within_bound`) and `use_hint_avx` treats r0 = 0 as positive, so h = 1 gives (r1 + 1) mod 16 where FIPS 204 Algorithm 40 gives (r1 − 1) mod 16. Under a public key with t1 = 0 (any ρ), z = 0 gives w'_approx = 0 for every challenge, so ANYONE can make a signature that AVX2 nodes refuse and all others accept (w1 = 15 at a hinted coefficient, tcId 161) or the reverse (w1 = 1): lock coins to such a key (in a standard hybrid key with a genuine Falcon half, so the spend relays) and spend them, and the network splits by CPU. An honest signer's hints sit where |r0| ≥ β, never at r0 = 0, so both implementations agree on honest signatures (and on every KAT) | Every build links the clean implementation only: `pqcrypto-mldsa` with `default-features = false` in `gnb-crypto` and `gnb` (as Falcon since F1), so the verdict is FIPS 204 everywhere: tcId 161 accepted, its AVX2 twin refused. `crypto::mldsa_one_verdict::use_hint_at_r0_zero_follows_fips_204` crafts both signatures for two t1 = 0 keys and checks them through every consensus path (library, suite 0x0002 legacy and canonical, hybrid suite 0x0001, wallet verifier, sighash v3 `verify_bound` of both suites); `mldsa_avx2_and_aarch64_variants_are_not_linked` is the symbol tripwire, and `scripts/falcon-clean-guard.sh` checks the feature graph of both crates. With the AVX2 code linked, on an AVX2 CPU: the verdict test fails ("FIPS 204: (0 - 1) mod 16"; every path refuses the FIPS signature and accepts its AVX2 twin) and the tripwire fails; the same binary on qemu's Nehalem passes the verdict test. `wycheproof_mldsa65` now requires the Wycheproof verdict on all 210 cases from the library and on all 203 empty-context cases from the wrapper, and runs in `ubsan-noavx2` too |

No memory error, no C undefined behaviour and no Rust undefined behaviour
was found in the code under test. F4, F5 and F6 are the defects in shipped
code (F4 low impact; F5 affects only 32-bit builds of the node, which
accepted some frames that 64-bit nodes refuse; F6 is a consensus split
between nodes on AVX2 CPUs and all other nodes, open to anyone, at every
height of the relaunched mainnet, see
[After the relaunched mainnet merge](#after-the-relaunched-mainnet-merge)).

## Review follow-ups (2026-10-15)

A review of this work found five gaps; each is closed above:

1. The big-endian claim of `miri-cross` covered only `lanes_to_bytes`: the
   PoW vectors were ignored under Miri. Now the log2_n = 1 and 2 Python
   vectors run under Miri on s390x and i686 (Miri section, positive
   controls).
2. The F1 late-drop check could not fail (it ran over an empty stack). It
   now runs over a live sentinel override (F1 row).
3. The clean ML-DSA C code never ran under a sanitizer in CI: new mode
   `ubsan-noavx2` and CI step.
4. Miri steps could pass with zero tests, and the nightly was not pinned:
   `expect_passed` minimums, `nightly-2026-10-14`.
5. `gnb-wallet-wasm` (the 32-bit consumer, with the only other first-party
   `unsafe`) was in no run: now in `i686` and, for its C ABI, in
   `miri-cross`; F4 fixed.

## On the merged PR branch

This work was written on `b6a2976` and merged into the PR branch (`299a718`)
after the node-local mempool and RPC policy package (P4), the shielded pool,
ledger, wallet transport and libp2p 0.57 package (P5), the node-local chain
selection package (P3), and the mutation-testing and consensus-vector
packages (the fuzzing package was merged after it). Every mode
was re-run on the merged tree (same environment, `nightly-2026-10-14`, own
target directories):

| Mode | Result on the merged tree |
| --- | --- |
| `asan` | pass, no ASan or LSan report: `gnb-smh` 26 unit, 5 integration; `gnb-crypto` 338 unit (1 ignored), 25 integration (1 ignored), doctests; `pqcrypto-internals` 17, 2, 2; all 12 PQClean archives instrumented (180 s with the build) |
| `ubsan` | pass, no report: `gnb-crypto` 338 unit, 25 integration, doctests; `pqcrypto-internals`; all 12 archives instrumented |
| `ubsan-noavx2` | pass: 63 (1 ignored) and 3 |
| `miri` | pass, no undefined behaviour: 30, 42 and 15 (393 s) |
| `miri-cross` | pass: 30 on i686 and 30 on s390x, `gnb-wallet-wasm` 3 (408 s) |
| `i686` | pass: `gnb-smh` 26 + 5; `gnb-crypto` 338 unit + 25 integration; `coherence-core` 12 unit + 17 integration; `pqcrypto-internals` 17 + 2 + 2; `gnb-wallet-wasm` 4 |

What the merge changed:

- Five of the PR branch's newer tests cannot run under Miri and now carry
  `cfg_attr(miri, ignore = "<why>")` (Miri table above): the canonical
  GnB-SMH entry-point test, the two end-to-end sighash script tests (PQClean
  C) and the two `core::limits` cap tests that build 10^5 to 10^6 elements.
  The two cap tests were still running after 17 and 9 minutes when stopped;
  with them the `miri` job would have outgrown its timeout. A sixth,
  `core::limits::count_and_size_caps_match_the_wire_parser`, came with the
  fuzzing merge (see [After the fuzzing merge](#after-the-fuzzing-merge)).
- The minimums are the merged counts: `gnb-smh` 30 (host, i686, s390x; was
  24), the `gnb-crypto` selection 42 (was 29).
- F4 changes the browser wallet core, which the PR branch rebuilds
  reproducibly and pins (CI job `wasm-reproducible`, audit WAL-5):
  `site/wallet/gnb_wallet.wasm` was rebuilt with `scripts/build-wallet-wasm.sh`
  (1.94.1, wasi-sdk 25) and `WASM_SHA256` and the SRI hashes were updated.
  Through `site/wallet/core.js`, the previously shipped core priced
  `minFee(2^32 + 100)` at 10000; the rebuilt one refuses it ("`size` too
  large").

### After the merge: CI on GitHub and the open issues

The PR branch was pushed after the merge, so the new jobs have run on
GitHub (results read from the Actions API; the job logs themselves were not
reachable from the local environment):

| Commit | `sanitizers` | `miri` | `i686` | `wasm-reproducible` | `consensus-crates` (with the release overflow step) |
| --- | --- | --- | --- | --- | --- |
| `299a718` (the merge), push and pull-request runs | pass (about 5 minutes) | no result: the host step was still running after 115 minutes when last checked (the two `core::limits` cap tests, see above), under the job timeout of then 120 minutes | pass | pass | pass |
| `48a2d42` (Miri selection and minimums), push and pull-request runs | pass | pass: host step 6.1 and 4.6 minutes, cross step 5.7 and 4.3 minutes; the steps run `expect_passed` with the minimums 30 / 42 / 15 and 30 / 30 / 3 | pass | pass | pass |

`wasm-reproducible` rebuilt the wallet core on fresh runners (no cache step,
wasi-sdk 25 downloaded and checked) and matched the committed binary and
`WASM_SHA256` on both commits: the local re-pin did not depend on the local
wasi-sdk copy or on a warm target directory.

Local re-runs through the script with the new minimums: `miri` passed (30,
42 and 15 passed; 471 s with a cold target directory, and 364 s again with
the final script, time bound included), `miri-cross` passed with the time
bound (30 on i686, 30 on s390x, 3 for the wallet; 400 s). Positive control
of the time bound: `SANITIZER_MIRI_TIMEOUT=20 sh scripts/sanitizers.sh miri`
stops the `gnb-smh` command after 20 s with exit status 124 and the remedy
message, and no Miri process is left running.

Follow-ups made here:

- The Miri time bound (`with_miri_timeout`, above) and a `miri` job timeout
  of 75 minutes (was 120): a test Miri cannot finish now fails its step after
  30 minutes with the remedy, instead of holding the job.
- `ubsan-noavx2-full` (every `gnb-crypto` test without AVX2) and
  `i686-node` (the node on 32 bits) run nightly and on manual dispatch; both
  passed locally through the script (above), neither has run on GitHub yet.
  `i686-node` found F5, and that `cargo test` on i686 rewrote the committed
  fuzz seed corpus (`node/tests/parser_corpus_floor.rs` reduced its random
  numbers with `as usize`); the generator now reduces in `u64` and writes
  the same corpus on both widths.
- `expect_passed` logs to a file per script run: two modes run at once over
  one `SANITIZER_TARGET_DIR` truncated each other's shared log, which lost
  `test result:` lines and failed a passing run (seen locally: 338 counted
  of 363 passed).

Still open, by decision: `parking_lot` deadlock detection is not in CI. It
needs eight new lockfile packages and a `deny.toml` exception (see
[Deadlock detection](#deadlock-detection)); that is a dependency decision for
the maintainers.

### After the fuzzing merge

- The fuzzing package (merge `f312057`) added
  `core::limits::count_and_size_caps_match_the_wire_parser`, which is in the
  `miri` selection (`core::limits::`) and builds, encodes and parses a block
  of 1,000,000 transactions. It carries `cfg_attr(miri, ignore = "<why>")`
  (`91f5477`) like the other cap tests: the selection now has six ignored
  tests (Miri table above).
- `miri` re-run locally through the script on the tree after that merge and
  its review fixes (`nightly-2026-10-14`, own target directory): pass, no
  undefined behaviour; `gnb-smh` 25 unit (1 ignored), 4 and 1; the
  `gnb-crypto` selection 42 passed, 6 ignored; `pqcrypto-internals` 15 (3
  ignored); 417 s, the `gnb-crypto` selection 291 s. The minimums (30 / 42 /
  15) are unchanged.
- The node on i686, for the targets the fuzzing merge added or changed
  (`cargo test --target i686-unknown-linux-gnu -p gnb --lib --test
  fuzz_seed_corpus --test fuzz_regressions --test parser_corpus_floor --test
  wire_decoder_fuzz --test fix_net_ingress`, not the whole `i686-node`
  mode): pass, 327 unit tests, 5, 3, 6, 3 and 14; the committed seed corpus
  is reproduced unchanged on 32 bits (`fuzz_seed_corpus` regenerates it and
  compares).

## After the relaunched mainnet merge

The PR branch merged `origin/main`, the relaunched mainnet line, up to
`820c102` (merge `0a60b20`). Two jobs then failed on `main` itself and on the
PR branch, both through tests `main` added after `e3e45df`:

- `i686`: `wycheproof_mldsa65` (added in `279067f`, "FIPS 204 z bound
  (Wycheproof)") failed. On i686 the library disagreed with Wycheproof on
  none of the 42 cases the test pinned it to disagree on, and the consensus
  wrapper accepted tcId 161. The test had been written on an AVX2 machine and
  pinned the AVX2 code's verdicts: this is F6, a consensus split between
  nodes on AVX2 CPUs and all other nodes (Findings). The same x86_64 test
  binary gives the i686 verdicts under `qemu-x86_64 -cpu Nehalem`.
- `miri`, step "Miri (host)": failed after 30 minutes. Not undefined
  behaviour: the step ran exactly 30:00 and ended with exit status 124
  (Actions API), the `with_miri_timeout` bound of 1800 s on its first
  command, `cargo miri test -p gnb-smh`. `main` added GnB-SMH v2 (draft,
  `2ceb287`) and v3 (`40d3751`, the proof of work from the PoWit activation
  height) with unit tests and Python reference vectors, none of them reduced
  under Miri: `tests/vectors_v2.rs` has five log2_n = 13 vectors (16,384
  SHA-256 compressions each, about an hour apiece under Miri) and
  `tests/vectors_v3.rs` five log2_n = 15 vectors (2^17 Keccak permutations
  each, about 15 hours apiece); the v2 and v3 unit tests at their native
  sizes took 10 minutes under Miri. The `gnb-crypto` and
  `pqcrypto-internals` commands of the step never ran on GitHub, and
  `miri-cross` (the same `gnb-smh` tests on i686 and s390x) would have
  stopped the same way.

Fixes: F6 (Findings), and the new `gnb-smh` tests run smaller under
`cfg(miri)`, like the v1 ones (Miri table): the five log2_n = 4 v2 vectors,
the five log2_n = 4 one-pass v3 vectors and one three-pass one (each test
fails if fewer ran), smaller scratchpads and fewer trials in the unit tests.
`gnb-smh` has no unsafe code (`forbid(unsafe_code)`), and every code path of
v2 and v3 still runs under Miri, against the Python reference on s390x and
i686 too. The `gnb-smh` minimum of `miri` and `miri-cross` is now 36 (29
unit, 4 difficulty-vector tests, and the v1, v2 and v3 vector tests).

The web-wallet core links `gnb-crypto` and so `pqcrypto-mldsa`: it was
rebuilt with `scripts/build-wallet-wasm.sh` (1.94.1, wasi-sdk 25, checked
download) and re-pinned (`WASM_SHA256`, SRI). It ran the clean ML-DSA code
before as well (wasm32 has no AVX2 build); the binary changes with the crate
features. The same script on the unchanged PR head `0a7127f` reproduced the
committed binary (`bd335806...`) in this environment.

Local results on the fixed tree (x86_64 with AVX2, the environment above;
the Miri times are wall-clock with other builds running in parallel):

| Mode or command | Result |
| --- | --- |
| `miri`: `gnb-smh` | pass, no undefined behaviour: 29 unit (1 ignored), 4, 1, 1 and 1 (36); 421 s (unit tests 125 s, difficulty vectors 101 s, v1 vectors 38 s, v2 vectors 18 s, v3 vectors 136 s) |
| `miri`: the `gnb-crypto` selection | pass, no undefined behaviour: 44 passed, 6 ignored (minimum 42); 576 s with the build |
| `miri`: `pqcrypto-internals` | pass: 15 passed, 3 ignored |
| `miri-cross` | pass, no undefined behaviour: `gnb-smh` 36 on i686 (409 s) and 36 on s390x (421 s), the v2 and v3 vectors matching the Python reference on both; `gnb-wallet-wasm` 3 (1 ignored) on i686 |
| `i686` | pass: `gnb-smh` 30 unit, 4, 1, 1, 1; `gnb-crypto` 404 unit (1 ignored) and its integration tests (`wycheproof_mldsa65` 2 of them), doctests; `coherence-core` 12, 3, 1, 8, 5; `pqcrypto-internals` 17, 2, 2; `gnb-wallet-wasm` 4 |
| `gnb-crypto`, x86_64 with AVX2 | pass: 404 unit (1 ignored), every integration test, doctests |
| `gnb` `kat_mldsa65`, `sprint_s_crypto_sizes`, x86_64 | pass: 4 and 4 (the seeded ML-DSA-65 golden key hashes are unchanged with the clean code) |
| `ubsan-noavx2` selection on qemu's Nehalem (the plain debug binaries, not the UBSan build) | pass: 67 (1 ignored), 3 and 2 |
| `scripts/falcon-clean-guard.sh` | pass; with `node/Cargo.toml` back on the default features of `pqcrypto-mldsa`, the feature-graph check reports `avx2`, `neon` and `default` |

Not re-run here: the `asan`, `ubsan`, `ubsan-noavx2` and
`ubsan-noavx2-full` modes with their instrumented builds (disk space); they
now execute the clean ML-DSA C code on the AVX2 runner as well, the code
`ubsan-noavx2` already ran under UBSan. The AArch64 variant was never
executed here (no AArch64 toolchain): by its source it checks the z bound and
implements UseHint as FIPS 204 does, and it is no longer linked.
