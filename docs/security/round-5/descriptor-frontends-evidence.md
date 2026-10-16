# Descriptor frontend evidence

This package adds public static descriptor entry points, not secret backup
recovery, derivation paths, a chain scan, or a persistent wallet index. It changes
no block/transaction verdict, activation height, or output script format. No
score or overall Bitcoin Core comparison follows from these tests.

Native builds used `codegen-units=151`, `debug=0`, `incremental=0`, two build
jobs, and `/private/tmp/gnb-r5-target-descriptor-frontends`. `gnb-crypto` full
tests and complete node/site integration are separate coordinator-owned gates.

## Reproduce before implementation

Production at base `35ccd62` was preserved while CLI and RPC tests compiled.
The only initial RPC source edit included the new test module under `cfg(test)`.
Test-only commits began at `ea98d9c`; final native tests were present by
`c6b86bd`. The existing help/validation controls passed. The six CLI cases failed
with `Unknown command: descriptor`; four RPC cases failed because the methods
were unknown. These were runtime assertions, not missing Rust APIs or build
errors. Core dependency commits were imported only after both runs finished.
Native wiring was then committed in `0898b01`.

| Entry point | Old production | Final focused run |
|---|---:|---:|
| Actual `gnb-cli` binary | 1 passed, 6 failed | 7 passed |
| RPC dispatch/router, including isolated testnet process | 1 passed, 4 failed | 5 passed |
| RPC method registry matches dispatch | Existing gate | 1 passed |
| Initial actual pinned WASM/JS suite | 1 passed, 4 failed | Full suite owned by integration |

The initial JS suite had five tests. Before the binding existed, four failed
with `descriptor is not a function`; after binding-only `f79421b`, the unchanged
old WASM rejected four requests as `unknown op descriptor`. Both historical
logs are retained. Two serialization-hook regressions later expanded the final
site suite to seven tests; its final count must not be applied retroactively to
the original baseline.

Native tests check both networks, pkh/policy/tree identities, legacy/Bech32m
aliases, exact arguments and checksum requirements, real public-pool files,
wrong-network refusal, duplicate bundle fields, input byte limits, and existing
file/symlink preservation. RPC inspection performs zero instrumented storage
reads and follows the existing read-auth policy. The new RPC params are arrays
of one string; this package makes no new duplicate-field guarantee about the
legacy outer JSON-RPC envelope.

## Independent finding R5-VERDICT-1

The verdict reviewer found that a caller-owned JavaScript `toJSON()` function
could replace the spread request during serialization with `{op:"wipe"}`.
The session was cleared despite the fixed `op` property. This is a local
JavaScript object/function capability; the reproducer does not establish remote
execution or protection against arbitrary code in getters.

Test-only `4d83579` reproduced both an own hook and an inherited
`Object.prototype.toJSON` hook using a real unlocked WASM session: one legacy
control passed and both cases failed with `wallet is locked`. The inherited
hook was restored in `finally` before querying the session again.

Fix `2ba4c6a` uses a null-prototype envelope, refuses an own `toJSON` field and
forces the public operation after copying input. Only `descriptor()` changed;
existing bindings were not silently included in this claim. With the final
test bytes unchanged, restoring the vulnerable binding yielded 1 passed / 2
failed; restoring the fix yielded 3 passed / 0 failed. These focused checks use
the existing session operations and do not replace the integration's full
descriptor-WASM tests.

## Production reversals and file guard

`replay-descriptor-frontends.py` restores pre-feature CLI/RPC production from
public ancestor `2848dcf6bd89a85afe4828042227c9a2c2b433f0` while retaining the final
tests. CLI reversal yielded 1 passed / 6 failed, then 7 passed
after restoration. RPC reversal yielded 1 passed / 4 failed, then 5 passed
after restoration. Tests' before/after SHA-256 values are identical.

The file guard also receives a separate mutation check: replacing
`create_new(true)` with `create(true).truncate(true)` must fail both the existing
file and symlink cases. This distinguishes preservation of existing output from
the mere presence of the new command. Results and hashes are in the JSON receipt.

Replay requires an explicitly named, fresh output directory and restores source
in `finally`. Preflight checks confirmed missing/existing output paths refuse
before changing production; an existing sentinel and all source hashes stayed
unchanged. The JS replay needs the final WASM installed by the prescribed build
script and is run by integration. No binary or pin is modified by this package.

See `descriptor-frontends-evidence.json` for commands, exits, test and log hashes,
native reversal records, and the file-guard mutation receipt. Local raw logs
remain under `/private/tmp/gnb-r5-frontends-*`; the committed replay allows the
same runtime checks on another checkout.
