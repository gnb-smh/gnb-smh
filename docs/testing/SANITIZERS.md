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
| `ubsan-noavx2` | the UBSan ML-DSA, wallet-signing and ACVP tests on qemu's Nehalem CPU (no AVX2), so the clean ML-DSA C code runs | `sanitizers` | pass; no report |
| `miri` | Miri over the pure-Rust consensus arithmetic and the unsafe RNG override | `miri` | pass; no undefined behaviour |
| `miri-cross` | Miri over `gnb-smh` (including the Python PoW vectors) on `i686` (32-bit) and `s390x` (big-endian), and over the wasm wallet's C ABI on `i686` | `miri` | pass |
| `i686` | the full test suites of `gnb-smh`, `gnb-crypto`, `coherence-core`, `pqcrypto-internals` and `gnb-wallet-wasm` on `i686-unknown-linux-gnu` | `i686` | pass; one failure (a 64-bit assumption in a test, F2), fixed; a concurrent run exposed a temp-file race between test processes (F3), fixed; the wallet's `minfee` truncated sizes on 32-bit targets (F4), fixed |
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
`pqcrypto-mldsa` / `pqcrypto-falcon` crates ML-DSA-44/65/87 (clean and AVX2)
and Falcon-512/1024 (clean, padded and unpadded). After the tests the script
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
- On an AVX2 machine `pqcrypto-mldsa` dispatches ML-DSA to its AVX2 code at
  run time, so the clean ML-DSA code is linked and instrumented but not
  executed by this job. It runs natively in the `i686` job (no AVX2 build) and
  under UBSan on an emulated CPU without AVX2 (`ubsan-noavx2`, next section).
  Falcon is always the clean variant (`scripts/falcon-clean-guard.sh`).

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

### The clean ML-DSA code without AVX2 (`ubsan-noavx2`)

```sh
sudo apt-get install qemu-user
sh scripts/sanitizers.sh ubsan      # builds the UBSan test binaries
sh scripts/sanitizers.sh ubsan-noavx2
```

The `ubsan` binaries run under `qemu-x86_64 -cpu Nehalem`, a CPU model
without AVX/AVX2, where `is_x86_feature_detected!("avx2")` is false and
`pqcrypto-mldsa` takes the clean ML-DSA C code: the code non-AVX2 x86_64
nodes run and the code compiled into the wasm32 wallet. Selection (from
`crates/gnb-crypto`, where cargo runs its tests): the `gnb-crypto` lib tests
`crypto::` (hybrid key generation, signing, verification, KATs),
`wallet::payment::`, `wallet::legacy_sign_tests::`,
`wallet::sighash_v3_signers::` (63 passed, 1 ignored; minimum 63) and the
`acvp_mldsa` integration test (the official ACVP ML-DSA-65 vectors; 3
passed; minimum 3). About 35 s locally; the whole lib suite took 575 s under
emulation (280 passed, no report; mostly keystore KDFs with no ML-DSA in
them), so it is not in CI.

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
| `gnb-smh` | every unit test (compact bits, chain work, ASERT including the AUD-1 wide multiply and shift, the lane-level Keccak step, the scratchpad), `tests/difficulty_vectors.rs` and `tests/vectors.rs` (the Python PoW vectors with log2_n = 1 and 2) [30] | the log2_n = 10 and 19 PoW vectors skipped, `canonical_entry_points_match_the_reference_vector` ignored (below) |
| `gnb-crypto` | `core::limits`, `core::tokenomics`, `core::block_rules` (Merkle roots, coinbase branch, coinbase commitment, witness root), `core::sighash`, `core::activation` [42] | five tests ignored (below) |
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
| `gnb-crypto` `v3_cost_is_linear_in_the_input_count` | ignored | ~300 Keccak permutations of byte counting; its arithmetic also runs in `v3_commits_to_every_field` |
| `gnb-smh` `canonical_entry_points_match_the_reference_vector` | ignored | five canonical evaluations (log2_n = 19, 64 MiB, ~2^20 Keccak permutations each); the log2_n <= 2 Python vectors run the same pipeline under Miri |
| `gnb-crypto` `core::sighash` `v3_scripts_verify_and_every_fault_is_rejected`, `v2_scripts_verify_below_the_activation` | ignored | hybrid key generation and signing through the PQClean C code, which Miri cannot execute |
| `gnb-crypto` `core::limits` `block_count_caps_are_inclusive` | ignored | blocks of 1,000,000 transactions and 100,000 shielded transactions: still running after 17 minutes under Miri; `check_block_canonical_limits` runs under Miri in the other cap tests |
| `gnb-crypto` `core::limits` `transaction_count_caps_are_inclusive` | ignored | 100,000 inputs and 100,000 outputs, cloned: still running after 9 minutes under Miri; `check_tx_canonical_limits` runs under Miri in the other tests of the module |
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

Result: all pass after fixes F2 and F4. The node itself was not built for
i686 (RocksDB would need a 32-bit C++ toolchain; not attempted).

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

No memory error, no C undefined behaviour and no Rust undefined behaviour
was found in the code under test. F4 is the one defect in shipped code (low
impact).

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

This work was written on `b6a2976` and merged into the PR branch after the
mempool/relay, networking/storage and block-ingress packages and the
mutation, fuzzing, consensus-vector and functional-test packages. Every mode
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
  with them the `miri` job would have outgrown its timeout.
- The minimums are the merged counts: `gnb-smh` 30 (host, i686, s390x; was
  24), the `gnb-crypto` selection 42 (was 29).
- F4 changes the browser wallet core, which the PR branch rebuilds
  reproducibly and pins (CI job `wasm-reproducible`, audit WAL-5):
  `site/wallet/gnb_wallet.wasm` was rebuilt with `scripts/build-wallet-wasm.sh`
  (1.94.1, wasi-sdk 25) and `WASM_SHA256` and the SRI hashes were updated.
  Through `site/wallet/core.js`, the previously shipped core priced
  `minFee(2^32 + 100)` at 10000; the rebuilt one refuses it ("`size` too
  large").
