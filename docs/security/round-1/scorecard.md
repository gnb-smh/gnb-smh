# Round 1 independent evidence baseline

- Assessor: independent evidence assessor, task `/root/evidence_baseline`.
- Assessed revision: `7b02dccbaa9c9dac15b2a18c72c32fc29b2acb3c`.
- Method: read-only inspection of repository source and CI configuration, with source-list counting and weighted arithmetic. This assessor did **not execute tests**, reproduce exploits, generate attack payloads, or change implementation code. Root-agent executions and their results are recorded separately; they are not results of this assessment.
- Evidence boundary: a test definition demonstrates an intended check, and a workflow demonstrates a configured check. Neither alone demonstrates a passing run, effective branch protection, exhaustive coverage, or a numerical security rating. Line references below identify the assessed revision and may move in subsequent edits.

## Categories and supplied values

Both numeric columns are **supplied, unverified inputs**, not this assessor's ratings. No new numerical rating is assigned. The supplied benchmark has no pinned version or evidence-based scoring rubric, so these inputs cannot substantiate comparative security or superiority claims.

| Category | Weight | Supplied benchmark (unverified) | Supplied initial project (unverified) | Verifiable existing source evidence |
| --- | ---: | ---: | ---: | --- |
| Consensus determinism | 25% | 9.5 | 5.5 | `fast_coloring_is_deterministic` compares canonical metadata from independent DAG builds ([node/tests/ghostdag_differential.rs:322](../../../node/tests/ghostdag_differential.rs#L322)). `dag6_deep_fork_converges_whatever_the_arrival_order` checks fork choice, UTXO equality and restart persistence ([node/tests/fix_chain_selection.rs:215](../../../node/tests/fix_chain_selection.rs#L215)). |
| Network/RPC resource safety | 20% | 8.5 | 5.5 | `client_caps_in_flight_per_peer` ([node/tests/fix_net_peer_policy.rs:95](../../../node/tests/fix_net_peer_policy.rs#L95)); `large_bodies_are_bounded_in_number` ([node/src/rpc/mod.rs:3774](../../../node/src/rpc/mod.rs#L3774)); `anonymous_transaction_verification_is_bounded_node_wide` ([node/src/rpc/mod.rs:3906](../../../node/src/rpc/mod.rs#L3906)). These checks do not establish a deployment-wide performance guarantee. |
| Block/transaction monetary validation | 10% | 9.5 | 7.5 | `subsidy_schedule_stays_within_the_mining_allocation` and `total_output_matches_u128_sum` ([audit/consistency/tests/amount_consistency.rs:40](../../../audit/consistency/tests/amount_consistency.rs#L40), [same file:85](../../../audit/consistency/tests/amount_consistency.rs#L85)); `coinbase_maturity_counts_selected_chain_blocks_from_the_activation` ([node/tests/fix_connect_rules.rs:472](../../../node/tests/fix_connect_rules.rs#L472)). |
| Mempool | 10% | 9 | 6.5 | `mem5_signature_work_is_last_and_budgeted_per_connection` and `mem6_full_rbf_rules` ([node/tests/fix_mempool_policy.rs:201](../../../node/tests/fix_mempool_policy.rs#L201), [same file:1070](../../../node/tests/fix_mempool_policy.rs#L1070)); `invariant_holds_under_random_ops` ([node/tests/mempool_index_prop.rs:64](../../../node/tests/mempool_index_prop.rs#L64)). |
| Cryptography | 10% | 9 | 7.5 | `official_acvp_external_pure_context_verification_matches_all_group3_results` asserts 15 fixture cases ([crates/gnb-crypto/tests/acvp_mldsa.rs:26](../../../crates/gnb-crypto/tests/acvp_mldsa.rs#L26)). `linked_library_matches_wycheproof_on_every_case` uses a hash-pinned 210-case fixture ([crates/gnb-crypto/tests/wycheproof_mldsa65.rs:67](../../../crates/gnb-crypto/tests/wycheproof_mldsa65.rs#L67)). `falcon1024_rejects_tamper_wrong_key_wrong_message` supplies additional negative checks ([node/tests/kat_falcon1024.rs:78](../../../node/tests/kat_falcon1024.rs#L78)). |
| Testing consistency | 10% | 9.5 | 7.5 | `exhaustive_decode_matches_bitcoin_core_derive_target` checks 587,202,560 compact values plus larger-exponent samples against a local reference port ([audit/consistency/tests/compact_differential.rs:39](../../../audit/consistency/tests/compact_differential.rs#L39)); `random_cases_match_the_python_reference` ([audit/consistency/tests/pow_reference_differential.rs:60](../../../audit/consistency/tests/pow_reference_differential.rs#L60)). Separate consensus-crate invocations prevent workspace feature unification from masking real ASERT checks ([.github/workflows/ci.yml:130](../../../.github/workflows/ci.yml#L130)). |
| Defensive code | 5% | 8.5 | 7 | `test_build_traps_integer_overflow_and_debug_assertions` ([node/src/lib.rs:110](../../../node/src/lib.rs#L110)); `floor_netmsg_decode_no_panic` ([node/tests/parser_corpus_floor.rs:333](../../../node/tests/parser_corpus_floor.rs#L333)). CI additionally invokes a release-profile overflow-check test ([.github/workflows/ci.yml:157](../../../.github/workflows/ci.yml#L157)). |
| Fuzz/CI/supply chain | 5% | 9.5 | 6.5 | `committed_seeds_are_reproducible` ([node/tests/fuzz_seed_corpus.rs:615](../../../node/tests/fuzz_seed_corpus.rs#L615)); `cargo_deny_covers_every_feature_and_ci_pins_the_tools` ([node/tests/supply_chain_lockfile_guard.rs:181](../../../node/tests/supply_chain_lockfile_guard.rs#L181)). CI runs cargo-deny/audit with specified tool versions ([.github/workflows/ci.yml:306](../../../.github/workflows/ci.yml#L306)). |
| Wallet | 5% | 8 | 6.5 | `send_detects_a_lied_utxo_value_and_does_not_broadcast` ([crates/gnb-crypto/src/wallet/client.rs:794](../../../crates/gnb-crypto/src/wallet/client.rs#L794)); `gnb_call_path_wipes_request_and_response_secrets` ([crates/gnb-wallet-wasm/src/lib.rs:746](../../../crates/gnb-wallet-wasm/src/lib.rs#L746)); browser test `loadCore refuses a missing or wrong pin` ([site/tests/wallet-core.test.mjs:23](../../../site/tests/wallet-core.test.mjs#L23)); WASM reproducibility CI ([.github/workflows/ci.yml:221](../../../.github/workflows/ci.yml#L221)). |

## Exact weighted arithmetic

The weights sum to `100`. For the supplied values only:

```text
weighted total = sum(weight × supplied category value) / 100

benchmark = (25×9.5 + 20×8.5 + 10×9.5 + 10×9 + 10×9
             + 10×9.5 + 5×8.5 + 5×9.5 + 5×8) / 100
          = 907.5 / 100
          = 9.075 / 10

initial   = (25×5.5 + 20×5.5 + 10×7.5 + 10×6.5 + 10×7.5
             + 10×7.5 + 5×7 + 5×6.5 + 5×6.5) / 100
          = 637.5 / 100
          = 6.375 / 10
```

These totals are arithmetic results, not validated ratings. The inspected evidence is insufficient to assign fresh numerical scores without category-specific acceptance criteria, execution evidence and a pinned, equally assessed comparator.

## Source counts and configured coverage

There are **14 functional scenarios** in `ALL_TESTS` ([test/functional/test_runner.py:39](../../../test/functional/test_runner.py#L39)): `mining_full_template`, `feature_partition_heal`, `p2p_block_propagation`, `feature_activation_testnet`, `feature_restart_persistence`, `feature_invalidateblock`, `p2p_invalid_blocks_txs`, `wallet_coinbase_maturity`, `mempool_tx_relay`, `mempool_replacement`, `mining_getblocktemplate_submitblock`, `rpc_gettxoutsetinfo`, `rpc_auth`, and `feature_test_build_guard`. This counts named scripts, not individual assertions or execution results. Functional CI builds with the test-only `test-pow-limit` feature ([.github/workflows/ci.yml:183](../../../.github/workflows/ci.yml#L183)).

There are **24 fuzz targets**, counted from the `[[bin]]` declarations ([node/fuzz/Cargo.toml:105](../../../node/fuzz/Cargo.toml#L105)): `tx_parse`, `block_parse`, `header_parse`, `netmsg_decode`, `handshake_decode`, `pow_decode`, `pow_verify`, `merkle_path`, `mempool_ops`, `block_rules`, `sighash`, `witness_parse`, `wire_roundtrip`, `undo_decode`, `keystore_decode`, `address_parse`, `sync_rr_codec`, `accept_dag`, `sync_decode`, `pq_handshake_decode`, `block_validate`, `tx_validate`, `policy_witness_decode`, and `script_sig_verify`. Fuzz CI checks target-count and corpus presence, and fails unsuccessful target runs ([.github/workflows/fuzz.yml:75](../../../.github/workflows/fuzz.yml#L75)); configured budgets are 60 seconds per target on PR/nightly and 600 seconds weekly. Target count and time budget do not measure coverage completeness.

All workflow runners are Ubuntu. Configured checks include workspace tests, independent Python references, the separate consistency harness, Rust+C ASan/LSan, C UBSan, QEMU Nehalem without AVX2, i686 consensus/wallet tests, scheduled/manual full-node i686 tests, Miri on i686/s390x, browser-wallet JavaScript tests and WASM reproducibility ([.github/workflows/ci.yml:25](../../../.github/workflows/ci.yml#L25), [sanitizer/platform jobs:338](../../../.github/workflows/ci.yml#L338)). Miri excludes incompatible tests and enforces minimum passed-test counts ([scripts/sanitizers.sh:63](../../../scripts/sanitizers.sh#L63)). This is not full-node big-endian or native ARM/macOS/Windows coverage.

## Missing or incomplete acceptance gates

1. The functional runner treats **skips as success**, with no minimum passed-scenario requirement, and its final count labels passed-or-skipped scenarios as passed ([test/functional/test_runner.py:209](../../../test/functional/test_runner.py#L209)).
2. Full-node i686 and the full non-AVX2 cryptography suite run only on schedule/manual dispatch, not as PR gates ([.github/workflows/ci.yml:368](../../../.github/workflows/ci.yml#L368), [same file:404](../../../.github/workflows/ci.yml#L404)). No native ARM/macOS/Windows job is defined in the inspected workflows.
3. Mutation scope covers selected consensus modules; it does not establish mutation adequacy for node networking/RPC, mempool or wallet implementation ([.cargo/mutants.toml:14](../../../.cargo/mutants.toml#L14)). PR mutation work covers only changed in-scope lines ([.github/workflows/mutants.yml:68](../../../.github/workflows/mutants.yml#L68)).
4. Clippy warnings are explicitly nonfatal ([.github/workflows/ci.yml:301](../../../.github/workflows/ci.yml#L301)). This is a maintenance gate limitation, not evidence that any particular warning is a vulnerability.
5. `cargo-fuzz` has no version pin ([.github/workflows/fuzz.yml:59](../../../.github/workflows/fuzz.yml#L59)); workflow actions use release tags, and runners use `ubuntu-latest`. Pinned Rust nightlies and several other tools therefore do not make the entire CI environment immutable.
6. Passing artifacts for this SHA, required-status/branch-protection enforcement, a category-level acceptance rubric, and a pinned benchmark revision remain unverified. Existing bounded-operation tests do not independently establish a measured production workload/hardware resource envelope.

## Prioritized safe maintenance follow-up

These are proposals, not completed fixes or executed checks. They require no exploit reproduction.

1. **Make functional pass/skip accounting explicit and enforce the required CI scenario set.** Preserve intentional local skip support, but fail CI when a required scenario is skipped and report passed/skipped counts separately. The existing runner's status accounting is directly inspectable; validate an isolated status-accounting regression without launching nodes, then use the existing 14-scenario functional suite for integration evidence. This closes a potential false-green acceptance path.
2. **Pin the fuzz tool and guard that pin.** Select an exact `cargo-fuzz` release already validated by the maintainer's environment, then extend the existing source-policy checks in `ci_workflow_triggers` or `supply_chain_lockfile_guard` to reject an unversioned tool. Validate with the existing Rust integration-test targets and the configured fuzz build. Do not choose a release number without verification. The unversioned baseline is reproducible through static workflow inspection.
3. **Triage the existing Clippy warning surface and choose an enforceable lint gate.** Run the existing Clippy command with `-- -D warnings` to enumerate the gap, fix mechanical warnings separately from behavioral changes, and gate the agreed scope. Existing lint-based reproduction command: `cargo clippy --workspace --all-targets --locked -- -D warnings`. No claim is made here that this command passes or fails; the assessor did not execute it.

No comparative superiority claim follows from this inventory.

## Independent assessment of the round's RPC package

Assessor: `/root/evidence_baseline`. Assessed package:
`59738aa121237a9d8a669c177e4911c769c309f6`; integrated as `91bb719`.
This follow-up inspected source, instrumentation, reversal driver, byte
snapshots and execution logs. The assessor did not execute tests.

| Category affected | New evidence | Boundary of the evidence |
| --- | --- | --- |
| Network/RPC resource safety | `r7_rpc_rejects_key_flood_before_body_and_hash_work` ([node/src/rpc/mod.rs:3747](../../../node/src/rpc/mod.rs#L3747)): real router, admitted-prefix controls, 822,400 → 24,672 hashed bytes and 100 → three body polls. Mapped identity/auth controls ([node/src/rpc/auth.rs:1088](../../../node/src/rpc/auth.rs#L1088)). | Per-source burst/refill limits; not a global concurrency or CPU bound. Valid-key operator requests also consume the documented admission budget. |
| Network/RPC resource safety | `r7_getaddressinfo_storage_work_is_independent_of_confirmed_utxos` and `r7_getaddressinfo_does_not_scan_during_aggregate_rebuild` ([node/src/rpc/mod.rs:3777](../../../node/src/rpc/mod.rs#L3777)): 512 → at most one instrumented storage read; zero during rebuild. | Empty mempool in these dispatch tests. Correct balance and count are positive controls. |
| Mempool / testing consistency | `r7_pending_balance_does_not_clone_mempool_payloads` ([node/src/mempool/mod.rs:1462](../../../node/src/mempool/mod.rs#L1462)): 524,928 → zero payload bytes at the instrumented history-copy point, with correct totals and one lookup per input. | Not a measurement of all allocations or peak memory. Work remains O(total mempool inputs + outputs). |

All five corrections have regressions that failed when only their production
implementation was reversed. Final tests and measurement probes were retained.
The four restored production files match their snapshots and reviewed commit
byte for byte. Logs show 11/11 focused regressions and 131/131 RPC tests passing.
The initial reject-all and unmeasured-body gaps were corrected with positive
controls and a direct body-poll counter. The real-clock refill still permits
test instability if the executor pauses beyond the refill interval.

The assessor found no blocking test-strength finding in the final package.
The baseline inventory remains valid; this new evidence does not demonstrate
improvements in the other categories. Integrated tests and CI were pending at
this assessment; their later execution belongs in [validation.md](validation.md).
Without an equivalent rubric and versioned comparator, no new numerical score
or superiority claim is assigned.

The subsequent integrated macOS functional run passed 13 of 14 scenarios,
with zero skips and a failure in `feature_partition_heal.py`. Independent
read-only diagnoses by `/root/test_isolation` and `/root/review_paths` identify
a mismatch between its two required reconnections and the documented fallback
for manual addresses without `/p2p/<id>` ([docs/RUNNING.md:248](../../../docs/RUNNING.md#L248),
[node/src/network/mod.rs:2562](../../../node/src/network/mod.rs#L2562)), triggered
by TCP `Address already in use` errors after restart. This is new negative
execution evidence for network/platform testing, recorded as open R1-FUNC-1;
it does not prove a consensus split. The scenario's final UTXO/convergence
assertions were not reached. See [validation.md](validation.md). A green Linux
run would not establish a green macOS platform matrix.

The second reviewer also found that the nominal 30-second convergence bound
is not an absolute deadline: peer waits have separate 60-second limits before
the remaining-time calculation ([feature_partition_heal.py:82](../../../test/functional/feature_partition_heal.py#L82),
[test_framework.py:219](../../../test/functional/test_framework/test_framework.py#L219)).
This remains open as R1-FUNC-2. Even a passing existing scenario does not prove
the advertised 30-second bound.
