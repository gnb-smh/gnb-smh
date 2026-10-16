# CRY-4 package: ownership of derived transport keys

Prepared while round 2 integration runs. Base `b425436fbb5c24f215c8b85a08a0fb4ec557292e`;
round 3 cannot be represented as merged or complete before its own integration
and final CI. Package branch `codex/security-r3-transport-key-ownership`;
codegen-units **47**, isolated Cargo target
`/private/tmp/gnb-security-target-r3-transport-key-ownership`.

## Scope and acceptance

The read-only inventory found `derive_keys` returns two `[u8; 32]` values
without a drop-cleaning owner, although the final transport streams already
clean their owned keys. Reproduce this narrow ownership gap first with a
meaningful regression on the existing function. Preserve HKDF bytes, labels,
direction, session separation and on-wire protocol. Do not alter consensus,
ML-KEM algorithms/dependencies, wallet/WASM, mlock policy, or unrelated transport
behavior. Do not access real keys or operator configuration.

A candidate correction transfers derived keys through non-Copy cleaning owners
into stream fields. It must not extract another unprotected intermediate array
at the ownership boundary. Retain compatible constructors where needed.
Use only synthetic fixed inputs in tests. Verify original bytes through a fixed
vector before and after; test cleanup while an object is still alive, not by
reading freed memory. A static non-Copy assertion and a runtime needs-drop
regression describe language-level ownership, not proof of every physical copy
made by a compiler or a claim of locked pages.

Record red execution before production edits, green execution, and production-
only reversal with final tests retained. Reference the applicable Bitcoin Core
defense in a comment using a verified primary source; do not equate this narrow
cleanup correction with its locked memory allocator. Require three independent
review lenses and complete integration/CI before delivery.

CRY-4 remains partial: upstream ML-KEM Copy secret types, compatibility-returned
buffers, long-lived key memory locking, and any other documented ownership gaps
need separate evidence and packages. No numerical rating is assigned here.

## Reproduction setup

Before production changes, five unit tests were appended under
`transport::upgrade::key_ownership_tests`: a fixed HKDF vector, runtime
`needs_drop::<T>()` with `T` inferred from both actual `derive_keys` results,
explicit cleanup while the derived values are still alive, a static non-`Copy` guard, and
compatibility constructors with live stream-key/counter cleanup. These five
tests remain unchanged through correction and production-only reversal.
The original production prefix of
`node/src/transport/upgrade.rs` is unchanged (SHA-256
`2038f579f42fff3ba0a9915e21f5bb70ca88caad914396eb5ea0ddd193bb6339`).

The fixed vector is independently computed using Python's standard-library
HMAC/SHA256, without calling the Rust implementation:

```python
import hashlib, hmac
ikm = bytes([0x11]) * 32 + bytes([0x22]) * 32
prk = hmac.new(bytes([0x33]) * 32, ikm, hashlib.sha256).digest()
for label in (b"GNB-P2P-PQ-v2 i->r", b"GNB-P2P-PQ-v2 r->i"):
    print(hmac.new(prk, label + b"\x01", hashlib.sha256).hexdigest())
```

Expected i→r:
`4ca4d1006ae9b125877421bc7632274ea469c97ceb75f41c18c0e6ed3929a2b1`.
Expected r→i:
`efd7e891049eae42a4f374f12c1ec00eade6344bbd2ae07805e763ab5949ecc9`.

All Cargo commands use:

```sh
export CARGO_TARGET_DIR=/private/tmp/gnb-security-target-r3-transport-key-ownership
export CARGO_PROFILE_DEV_CODEGEN_UNITS=47 CARGO_PROFILE_DEV_DEBUG=0
export CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1
cargo test --locked -p gnb --lib transport::upgrade::key_ownership_tests -- --nocapture
```

The Core reference was checked against the primary source:
[Bitcoin Core v29.0 secure_allocator::deallocate](https://github.com/bitcoin/bitcoin/blob/v29.0/src/support/allocators/secure.h#L34-L39)
cleans the allocation before freeing it. Only that cleanup principle applies
here; its locked-pool allocator is not implemented by `Zeroizing`.

The static non-`Copy` guard uses two overlapping candidates: all types have a
marker implementation for `()`, and `Copy` types also have one for `u8`.
Inferring the marker succeeds only when the type is not `Copy`. A standalone
`rustc` control using the resolved `zeroize 1.8.2` dependency compiled for
`Zeroizing<[u8; 32]>` and rejected `[u8; 32]` with E0283 (multiple applicable
implementations); `/private/tmp/gnb-r3-static-copy-control.log` records the
negative control. This guards the exact owner type used by the correction;
the runtime regression separately inspects the actual function results. The
static guard alone is not evidence about `derive_keys`' return type.

The ownership claim is limited to repository-owned derived-key outputs and
their stream fields. It does not establish erasure of compiler-created moves,
registers, HKDF/HMAC or cipher-internal state, upstream ML-KEM secret values,
or copies retained by callers of the public array-taking constructors. It
provides neither page locking nor a change to the lifetime of long-lived
identity/wallet keys. Cleanup assertions inspect live values only.

The first setup build exposed a test-only API typo (`std::mem::needs_drop_val`
does not exist). It is preserved in
`/private/tmp/gnb-r3-key-ownership-setup-compile-error.log` and is not counted as
runtime red evidence. The test was corrected to infer `T` through a borrowed
value and call `std::mem::needs_drop::<T>()`, still before production edits.

## Correction

`derive_keys` initializes each output as `Zeroizing<[u8; 32]>` before HKDF
writes it. Both handshake roles move those owners through private
`from_owned_key` constructors into `TxStream`/`RxStream` fields of the same
type. No protected key is dereferenced into another bare array at this
boundary. The public array-taking `new` constructors remain compatible and
immediately wrap their argument. Existing stream `Zeroize`/`ZeroizeOnDrop`
behavior, counters, HKDF inputs/labels, role direction and wire protocol are
preserved. No dependency, consensus, wallet or WASM source changes are made.

The final five-test block has SHA-256
`1c33c262b38efd8b21b276ef4b2bd666356081975192330ad67d2fac86cca9cd`.
Its static assertions cover the exact protected owner type and both streams;
the runtime `needs_drop` test infers the actual return types of `derive_keys`.
The fixed vector and live cleanup tests run unchanged on the original and
corrected implementations.

## Local validation

Native macOS x86_64; `rustc 1.94.1 (e408947bf 2026-03-25)` and Cargo 1.94.1.
All package tests used normal Cargo, the isolated target and the environment
above, including a cold native dependency build. No dependency artifacts were
copied or manually linked from round 2. The verbose red command confirms
`rustc --test -C codegen-units=47 -C strip=debuginfo`.

| Stage | Result | Log under `/private/tmp/` |
| --- | --- | --- |
| Original production, final five tests | 4 pass, 1 expected failure; exit 101 | `gnb-r3-key-ownership-red.log` |
| Correction | 5 pass; exit 0 | `gnb-r3-key-ownership-green.log` |
| Production-only reversal, final tests retained | 4 pass, 1 expected failure; exit 101 | `gnb-r3-key-ownership-reversal.log` |
| Exact correction restored, all transport unit tests | 13 pass; exit 0 | `gnb-r3-key-ownership-restored-transport.log` |
| Existing cipher/framing and handshake suites | 9 + 13 pass; exit 0 | `gnb-r3-key-ownership-existing-transport.log` |

Both runtime failures are `derived_keys_require_drop_cleanup`: actual
`(false, false)` versus required `(true, true)`. The fixed vector, static guard
and live cleanup tests pass in both red executions. Neither failure was caused
by a missing new API or a compile-time guard. For reversal, the two production
files were restored from the base, retaining the final test suffix byte for
byte; the corrected files were then restored byte for byte from saved copies.

The final restored commands are:

```sh
cargo test --locked -p gnb --lib transport:: -- --nocapture
cargo test --locked -p gnb --test sprint_a1_transport_tests --test sprint_a2_upgrade_tests -- --nocapture
```

All 35 selected tests pass, including bidirectional handshake traffic and
independence of separate sessions. No tests were skipped, weakened or removed;
the new unit module adds five tests. `git diff --check` passes. Existing
unrelated compiler warnings remain outside this package's scope.

Three independent reviews, complete round-3 integration and final remote CI
remain required. These local package checks do not complete CRY-4 as a whole.
