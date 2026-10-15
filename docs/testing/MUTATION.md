# Mutation testing of the consensus code

Mutation testing changes the code under test in small, mechanical ways (an
operator, a comparison, a return value) and runs the test suite against each
change. A change the tests still pass ("missed", a *surviving mutant*) is a
behaviour of the consensus code that no test pins down. This page records how
the consensus crates of GnB were mutation-tested with
[cargo-mutants](https://mutants.rs), what survived at commit `b6a2976`, the
tests that now kill every non-equivalent survivor, and the mutants that are
provably equivalent to the original code.

Target: **0 non-equivalent surviving mutants** in the scope below.
Result: **0 non-equivalent survivors.** Of the 180 mutants that survived at
`b6a2976` (31 in gnb-smh, 149 in gnb-crypto), 171 are now killed by new tests
and 9 are equivalent (E1-E5 below; they are the only mutants still missed).
The largest gap found: at `b6a2976` no gnb-crypto test failed if
`verify_input_signatures` accepted every signature or `pubkey_hash_matches`
accepted every public key (the crate's own tests never verified a signed
transaction end to end; the node crate's tests are outside this measurement).

## Scope

| crate / file | in scope | not in scope (why) |
| --- | --- | --- |
| `crates/gnb-smh/src/lib.rs` | all (GnB-SMH v1, `verify*`, `hash*`) | — |
| `crates/gnb-smh/src/difficulty.rs` | all (compact bits, chain work, ASERT) | — |
| `crates/gnb-smh/src/bin/smh-bench.rs` | — | benchmark/toy-miner binary; linked into nothing, prints wall-clock timings only |
| `crates/gnb-crypto/src/core/block_rules.rs` | all | — |
| `crates/gnb-crypto/src/core/sighash.rs` | all | — |
| `crates/gnb-crypto/src/core/limits.rs` | all | — |
| `crates/gnb-crypto/src/core/activation.rs` | all | — |
| `crates/gnb-crypto/src/core/tokenomics.rs` | all | — |
| `crates/gnb-crypto/src/core/carryover.rs` | all | — |
| `crates/gnb-crypto/src/core/mod.rs` | every consensus function: chain id, size constants, difficulty wrappers and `expected_bits*`, ASERT parameters, `validate_pow` and the pow-limit checks, the proof cache, coinbase format/value, Merkle roots, txid/wtxid, wire encodings and parsers, size measures (`wire_size`, `size_bytes`), `parse_script_sig*`, `check_coinbase_maturity`, `check_min_fee`, the structural checks, `UndoData` encoding, `Transaction::actual_size` (the pre-activation size of one transaction: the node's mempool admission and the miner's coinbase reserve use it) | the pre-signing fee estimators and output statistics (`Transaction::estimate_size`, `calc_fee`, `estimate_fee`, `total_output`, `unique_output_addresses`: used by the wallet and the advisory `estimatefee` RPC, never by validation, mempool admission or the block template), the human-facing difficulty float (`difficulty_from_bits`, `difficulty_to_target`, `u256_to_f64`: RPC/explorer display), `Debug`/`Display` of `MerkleRoot` |

The scope, the exclusions and the equivalent mutants are encoded once, in
`.cargo/mutants.toml` (`examine_globs`, `exclude_re`), which every run below
and CI use. In-scope mutants: 280 in gnb-smh (272 after excluding the
equivalent ones), 719 in gnb-crypto at `b6a2976` (720 at the head of this
branch, extracting `PowCache::insert` added one; 719 after excluding the
equivalent one). `Transaction::actual_size` (2 mutants) was first excluded
as a wallet helper and put back in scope after review, when it turned out
to be the size measure the node's mempool admission and coinbase reserve
use; the full runs below were made without it (717 and 718 mutants), and its
two mutants were run separately at `b6a2976` and at the head.

## Method

- Tool: cargo-mutants 27.1.0, `--test-tool cargo`, two jobs (`-j 2`),
  mutants in source order (`--no-shuffle`).
- Each package is tested with **its own tests only** (cargo-mutants' default:
  the tests of the package that contains the mutated file), in its own
  invocation. gnb-crypto is never tested together with the node crate `gnb`,
  whose dev-dependency feature `test-pow-limit` would pin every expected
  target and hide the real ASERT path.
- Tests run: unit and integration tests (`cargo test --tests`, no doctests).
  The gnb-crypto wallet/keystore tests (`wallet::`, `hd_wallet::`: Argon2 and
  HD derivation, ~30 s per run) are skipped (`-- --skip wallet::`); skipping
  tests can only turn a caught mutant into a missed one, never the reverse,
  so the numbers below are conservative.
- Per-mutant test timeout: 5x the measured baseline test time, at least 60 s
  (`timeout_multiplier`, `minimum_test_timeout` in `.cargo/mutants.toml`).
- Outcomes: *caught* (a test failed), *missed* (all tests passed: a
  survivor), *unviable* (the mutant does not compile, e.g. `Default::default()`
  for a type without `Default`), *timeout* (the test run did not finish within
  the timeout: the mutant hangs a test, e.g. it turns a loop into an endless
  one; the tests did not pass, so the mutant is detected — every timeout is
  listed and explained below, and the gate fails on any other).
- Every survivor was either killed by a new test that checks a specific
  behaviour (an exact boundary, an exact byte layout, an independent
  reference value, a real signature that must or must not verify) or shown
  to be equivalent (no input distinguishes it from the original; table
  below). Equivalent mutants are excluded in `.cargo/mutants.toml`, matched by
  file, function and operator (not by line number), so CI fails on any *new*
  survivor.

### Commands

```sh
# Full scope, as CI runs it. scripts/mutants-gate.sh wraps cargo-mutants and
# fails on any missed mutant. Each crate in its own invocation:
scripts/mutants-gate.sh out-smh    -p gnb-smh    --test-tool cargo -j 2 --no-shuffle
scripts/mutants-gate.sh out-crypto -p gnb-crypto --test-tool cargo -j 2 --no-shuffle   # or --shard k/n

# Only the mutants on lines a branch changes (the PR-time run):
git diff origin/main...HEAD > pr.diff
scripts/mutants-gate.sh out-pr -p gnb-crypto --in-diff pr.diff --test-tool cargo -j 2

# List the scope without running anything:
cargo mutants -p gnb-crypto --list

# Check that the equivalent-mutant exclusions still exclude exactly E1-E5:
scripts/mutants-equivalent-check.sh
```

Parallel runs (`-j 2` and more) need a separate target directory for each
build copy, which is cargo-mutants' default (`<copy>/target`). With
`CARGO_TARGET_DIR` set, every copy builds into the one shared directory and a
job can run the test binary built from another job's mutant, so a mutant can
be recorded as caught by the wrong binary. `scripts/mutants-gate.sh` unsets
the variable; when calling `cargo mutants` directly, unset it too (or use
`-j 1`).

The runs recorded here were made on a shared 4-CPU machine under
`nice -n 15` with `RUST_TEST_THREADS=2`, `CARGO_BUILD_JOBS=2`,
`CARGO_PROFILE_DEV_DEBUG=0`, `CARGO_INCREMENTAL=0` and a private scratch and
target directory (`TMPDIR`, cargo-mutants' own build copies):

- **before**: a `git archive`-style export of `b6a2976` with the same
  `.cargo/mutants.toml` (minus the equivalent-mutant exclusions);
  gnb-smh in one run, gnb-crypto in three slices (`--shard 0/3`, `1/3`,
  `2/3`). The `1/3` slice was interrupted by a machine restart after 192 of
  its 239 mutants; the remaining 47 and the one mutant whose test run the
  restart killed were run afterwards by exact name (`--re '^<name>$'`).
- **after**: gnb-smh at `5b4731e` (its last change) without the exclusions,
  so the equivalent mutants show up as missed; gnb-crypto on a snapshot of
  commit `3b95f40` (the gnb-crypto tests; the gnb-crypto code is that of
  `b6a2976` except `PowCache::insert`, extracted unchanged from
  `Block::validate_pow`), the whole scope in one run.

## Results

### Summary

| package | mutants | caught | missed | unviable | timeout |
| --- | ---: | ---: | ---: | ---: | ---: |
| gnb-smh, before (`b6a2976`) | 280 | 240 | 31 | 9 | 0 |
| gnb-smh, after | 280 | 263 | 8 (all equivalent) | 9 | 0 |
| gnb-crypto, before (`b6a2976`) | 717 | 499 | 149 | 47 | 22 |
| gnb-crypto, after | 718 | 665 | 1 (E5, equivalent) | 47 | 5 |

### Per file

Counts are caught / missed / unviable / timeout.

| file | mutants | before | after |
| --- | ---: | --- | --- |
| `gnb-smh/src/lib.rs` | 64 | 45 / 16 / 3 / 0 | 58 / 3 (E1) / 3 / 0 |
| `gnb-smh/src/difficulty.rs` | 216 | 195 / 15 / 6 / 0 | 205 / 5 (E2-E4) / 6 / 0 |
| `gnb-crypto/src/core/mod.rs` | 406 / 407 | 272 / 98 / 26 / 10 | 381 / 0 / 26 / 0 |
| `gnb-crypto/src/core/block_rules.rs` | 80 | 64 / 7 / 1 / 8 | 75 / 0 / 1 / 4 |
| `gnb-crypto/src/core/sighash.rs` | 46 | 29 / 12 / 5 / 0 | 41 / 0 / 5 / 0 |
| `gnb-crypto/src/core/limits.rs` | 50 | 26 / 24 / 0 / 0 | 50 / 0 / 0 / 0 |
| `gnb-crypto/src/core/activation.rs` | 16 | 8 / 3 / 2 / 3 | 14 / 0 / 2 / 0 |
| `gnb-crypto/src/core/tokenomics.rs` | 56 | 43 / 1 / 11 / 1 | 43 / 1 (E5) / 11 / 1 |
| `gnb-crypto/src/core/carryover.rs` | 63 | 57 / 4 / 2 / 0 | 61 / 0 / 2 / 0 |
| **total** | 997 / 998 | 739 / 180 / 56 / 22 | 928 / 9 (E1-E5) / 56 / 5 |

`core/mod.rs` has one mutant more after the change: `PowCache::insert ->
()` (the eviction comparison moved from `Block::validate_pow` into
`PowCache::insert` with its three mutants).

### Timeouts

After the new tests, 5 mutants time out. Each one makes a loop endless, and
each log shows the test binary started (for three of them, tests had already
failed) before the run hung, so they are detected, not survivors. They are
the only timeouts the gate accepts: `.cargo/mutants-timeouts.txt` lists them
(by name without line and column, each at most once), and
`scripts/mutants-gate.sh` fails on any other timed-out mutant. A mutant that
only makes the tests slower (a disabled proof cache, a quadratic Merkle path)
or that a new unbounded test loop turns into a hang is not evidence that a
test detects it, so it must not pass as one:

| mutant | why the tests hang |
| --- | --- |
| `block_rules.rs` `tagged_merkle_root`, `legacy_merkle_root`: `while level.len() > 1` -> `>= 1` (2) | a level of one node never shrinks: every non-empty id list loops forever |
| the same loops, `> 1` -> `== 1` (2) | a one-transaction block (the genesis, most test blocks) loops forever |
| `tokenomics.rs` `issued_through_sat`: `epoch += 1` -> `epoch *= 1` | `epoch` stays 0; for a small height the loop runs ~10^11 times before the sum overflows |

At `b6a2976`, 22 mutants timed out: these 5, 16 that hung only because two
existing tests searched for a nonce with an unbounded loop (`while
b.validate_pow() { nonce += 1 }`, `while !b.validate_pow() { ... }`) — any
mutant that pins `validate_pow`, collapses the block id (`block_hash`, so the
proof cache answers for every nonce), or moves the pow limit (`bits_to_target`,
`pow_limit_target_for_height`, `pow_limit_bits_at`, the activation predicates
`is_active_at`, `hardening_activation_height`, `rules_active_at`) made that
loop endless — and one (`parse_script_sig_prefix -> Some((.., .., 0))`, the
first mutant of a slice on a loaded machine, 65 s against 24-43 s for its
siblings) that the after run catches in 14 s. The two loops are now bounded
(the first searches 16 nonces for one that FAILS at the genesis target, which
each nonce does with probability 1 - 1/4,500; the second searches 32 nonces
for one that passes at the pow-limit target, which almost every nonce does), so
those 16 mutants fail the tests instead of hanging them and count as caught.

## Survivors at `b6a2976` and the tests that kill them

The tests are in the module of the code they test (`#[cfg(test)]`), the
`core/mod.rs` ones in `core/consensus_tests.rs`; `set_node_chain_id` is tested
in its own process (`crates/gnb-crypto/tests/node_chain_id.rs`) because setting
the node chain id is irreversible.

### gnb-smh (31 survivors: 23 killed, 8 equivalent)

| code | surviving mutants | killed by |
| --- | --- | --- |
| `hash`, `hash_thread_local`, `verify`, `verify_with` | 7: constant outputs, `verify -> true/false`, `==` -> `!=` in the zero-target guard | `lib.rs` `canonical_entry_points_match_the_reference_vector`: the canonical vector (log2_n 19, "gnb", nonce 0) through every entry point; valid exactly at `out < target` (`out + 1` passes, `out` fails, zero target fails) |
| `Scratchpad::log2_n`, `Scratchpad::bytes` | 6 | `scratchpad_reports_its_parameter_and_size` |
| `difficulty::meets_target` | 5 | `meets_target_is_strict_big_endian` |
| `Target::as_bytes` | 2 | `target_accessors_round_trip` |
| `Display` of `BitsError`, `AsertError` | 2 | `error_messages` |
| `asert_next_target`: `out > pow_limit` -> `out == pow_limit` | 1 | `asert_clamps_a_representable_target_above_the_limit` (a target one half-life behind an anchor at the limit: representable, above the limit, clamped) |
| `lane16`, `target_to_bits`, `work`, `asert_next_target` (`>` -> `>=`) | 8 | equivalent: E1-E4 |

### gnb-crypto (149 survivors)

| code | surviving mutants | killed by |
| --- | --- | --- |
| `set_node_chain_id` | 2: `-> Ok(())`, `==` -> `!=` | `tests/node_chain_id.rs` `node_chain_id_is_set_once_and_selects_the_activation_schedule` (set once, idempotent, a different id refused with the one already set; drives the activation height but not a signer's) |
| `PUBKEY_SIZE`, `PRIVKEY_SIZE`, `SIG_SIZE` (`+` -> `-`, `*`) | 9 | `key_and_signature_size_constants_match_the_suite` (the lengths of a real hybrid key pair, `max_signature_len`) |
| `check_coinbase_maturity` | 5 | `coinbase_maturity_boundary_is_exact` (99 confirmations refused with the exact message, 100 accepted; height 0 and non-coinbase inputs skipped) |
| `check_min_fee` | 4 | `min_fee_boundary_is_inclusive` |
| `MerkleRoot::into_inner`, `From` both ways, `Deref` | 6 | `merkle_root_newtype_is_transparent` |
| `BlockHeader::pow_hash`, `BlockHeader::dag_hash` | 4 | `genesis_header_digests_match_the_python_reference` (pow preimage, DAG hash, block id and GnB-SMH output of the genesis header, computed with `reference/gnb_smh.py`) |
| `BlockHeader::read_wire_bytes` (parent cap), `BlockHeader::from_wire_bytes` (trailing bytes) | 3 | `header_wire_round_trip_and_parent_cap` |
| wire-parser caps: `read_shielded_tx` (12), `Transaction::from_wire_bytes` (4), `Block::from_wire_bytes` (4) | 20 | `wire_parser_caps_are_exact` (every count/length cap at the cap and one above it, with the exact error) |
| `Transaction::is_coinbase` (`&&` -> `\|\|`) | 1 | `coinbase_shape_is_exact` |
| `Transaction::parse_script_sig_prefix` (`< 8`, `< pk_len_end`) | 4 | `script_sig_framing_boundaries` (the 8-byte empty witness, an empty key at the end, every truncation point, trailing bytes) |
| `Block::validate_merkle -> true` | 1 | `merkle_validation_compares_with_the_header` |
| the proof cache's eviction `order.len() > POW_CACHE_CAPACITY` (in `Block::validate_pow` at `b6a2976`, now `PowCache::insert`) | 3 | `pow_cache_is_a_bounded_fifo` |
| `Block::validate_timestamp` | 9 | `timestamp_bounds_are_inclusive` (equal to the parent allowed, exactly `MAX_FUTURE_SECS` ahead allowed) |
| `Block::validate_dust` | 6 | `dust_threshold_is_exact_and_skips_the_coinbase` |
| `Block::validate_no_duplicate_txs -> Ok(())` | 1 | `duplicate_transactions_are_rejected` |
| `Block::validate_structure_without_pow_at`: `MAX_PARENTS`, `MAX_BLOCK_SIZE` | 3 | `parent_count_limit_is_inclusive`, `block_size_limit_is_inclusive_under_both_measures` (a block of exactly 1,000,000 bytes under each regime's measure passes, one byte more fails) |
| `Block::size_bytes` | 2 | `size_bytes_is_the_bincode_length` |
| `UndoOverwrites::is_empty`, `UndoData::mutation_count`, `UndoData::from_bytes` | 2 + 8 + 3 | `undo_extension_is_written_for_each_single_overwrite`, `undo_mutation_count_sums_the_four_lists`, `undo_trailing_bytes_are_classified` |
| `hash_meets_target` | 2 | `difficulty_wrappers` |
| `sighash.rs` `pubkey_hash_matches` (3), `check_input_witnesses` (4), `verify_input_signatures` (4), among them `verify_input_signatures -> Ok(())` (no signature checked), `pubkey_hash_matches -> true` (any key accepted for any script) and the prevout/witness count checks | 11 | `v3_scripts_verify_and_every_fault_is_rejected`, `v2_scripts_verify_below_the_activation`: real hybrid (ML-DSA-65 + Falcon-1024) signatures over a two-input transaction verify, and each single fault (other chain id, v3 signature checked as v2, legacy version at the activation, changed spent amount, signature of the other input, foreign key, missing prevout, trailing framing byte, missing suite envelope) is rejected with its own error |
| `Display for SighashError` | 1 | `sighash_error_messages` |
| `block_rules.rs` `rules_active -> true/false` | 2 | `process_wide_predicate_follows_the_override` |
| `check_coinbase_commitment`: `len < 80` -> `<= 80` | 1 | `commitment_check_boundaries` (exactly the 80-byte commitment is valid) |
| `block_size_for_rules -> 0/1`; `check_block_hardened_at` size `>` -> `==`, `>=` | 4 | `block_size_limit_is_inclusive_under_both_measures` |
| `limits.rs` `check_block_money_range` (shielded fee) | 1 | `shielded_fee_is_in_the_money_range` |
| `check_tx_canonical_limits` input/output counts | 4 | `transaction_count_caps_are_inclusive` |
| `check_block_canonical_limits`: transaction and shielded counts, the four per-shielded-transaction caps and the `\|\|` between them | 19 | `block_count_caps_are_inclusive`, `shielded_field_caps_are_inclusive` (each field at its cap passes, one over fails, one field at a time) |
| `activation.rs` `hardening_activation_height_for_signer -> 0/1` | 2 | `signer_height_follows_the_signer_chain_and_the_override` |
| `hardening_active_at -> true` | 1 | `process_wide_predicate_uses_the_process_wide_height` |
| `carryover.rs` `parse_and_convert`: `bad += 1` -> `*=` (malformed and duplicate rows), the summary threshold `bad > 5` -> `>=`, `==` | 4 | `failure_report_names_five_lines_then_summarises` |
| `tokenomics.rs` `min_tx_fee_sat`: `>` -> `>=` | 1 | equivalent: E5 |

The new tests also pin behaviour no mutant had flagged yet (ASERT parameters
and anchor, `difficulty_parent_timestamp`, varint boundaries, wire round
trips of every field, txid/wtxid preimages, the witness-root layout, every
error of `check_block_hardened_at`, the 64th-halving shift guard and issuance
at epoch edges, carryover totals and `verify_and_convert`'s five checks).

## Equivalent mutants

No input distinguishes these mutants from the original code; they are
excluded in `.cargo/mutants.toml`, between the `BEGIN/END equivalent mutants`
markers. The patterns match by file, function and operator (E4 also by
column), so they would also exclude a new mutant that a later edit adds to one
of these functions. `scripts/mutants-equivalent-check.sh` (CI) therefore lists
the scope with and without that block (`cargo mutants --list`, nothing is
built) and checks that the block removes exactly the nine mutants of
`.cargo/mutants-equivalent.txt` (names without line and column, repeats
counted); any new mutant inside a pattern, or a documented one that a pattern
no longer matches, fails it.

| id | mutant(s) | why it is equivalent |
| --- | --- | --- |
| E1 | `gnb-smh/src/lib.rs` `lane16`: each of the three `\|` -> `^` in `(i as u64) \| (tag << 32) \| (0x1F << 40) \| (0x80 << 56)` | The four operands occupy disjoint bits: `i` (a `u32`) bits 0-31; `tag` is one of the private constants `TAG_FILL = 1`, `TAG_MIX = 2` (the only callers), so `tag << 32` is within bits 32-33; `0x1F << 40` bits 40-44; `0x80 << 56` bit 63. On disjoint bits OR and XOR are the same function. |
| E2 | `gnb-smh/src/difficulty.rs` `target_to_bits`: the two `\|` -> `^` in `(at(idx) << 16) \| (at(idx+1) << 8) \| at(idx+2)` and the one in `(exponent << 24) \| (mantissa & 0x007F_FFFF)` | Bytes shifted to bits 16-23, 8-15 and 0-7 are disjoint. `exponent <= 33`, so `exponent << 24` is within bits 24-29, and the masked mantissa within bits 0-22: disjoint again. |
| E3 | `gnb-smh/src/difficulty.rs` `work`: `hi = (hi << 8) \| x` -> `^` | The low 8 bits of `hi << 8` are zero and `x` is a byte: disjoint. |
| E4 | `gnb-smh/src/difficulty.rs` `asert_next_target`: `if out > params.pow_limit { out = params.pow_limit }` -> `>=` | When `out == pow_limit` the mutant assigns `pow_limit` to `out`, which already holds it. |
| E5 | `gnb-crypto/src/core/tokenomics.rs` `min_tx_fee_sat`: `if by_size > MIN_TX_FEE_SAT { by_size } else { MIN_TX_FEE_SAT }` -> `>=` | At `by_size == MIN_TX_FEE_SAT` both branches return the same value. |

## CI

`.github/workflows/ci.yml`:

- **`mutants`** (weekly, Sunday 04:41 UTC, and on `workflow_dispatch`): the
  whole scope, gnb-smh in one job and gnb-crypto in four shards
  (`--shard k/4`), each through `scripts/mutants-gate.sh`. The job fails on
  any missed mutant, on any timeout not in `.cargo/mutants-timeouts.txt`, on
  a baseline failure and on any other cargo-mutants error; the known hangs
  are reported as warnings. The gnb-smh job also runs
  `scripts/mutants-equivalent-check.sh`. The `mutants.out` directory
  (per-mutant logs and diffs) is uploaded as an artifact.
- **`mutants-diff`** (every pull request): only the mutants on lines the PR
  changes, `git diff origin/<base>...HEAD` passed to `--in-diff`, for each
  crate, with the same gate (missed mutants and unknown timeouts fail), after
  `scripts/mutants-equivalent-check.sh`. A PR that changes no in-scope line
  tests no mutant and passes in seconds; one that changes consensus code must
  come with tests that catch its mutants.

The gate was checked locally both ways: with the exclusions it passes on the
mutants of `lane16` and `target_to_bits` (27 caught, the 6 equivalent ones
not run) and of `min_tx_fee_sat` (3 caught, E5 not run); on the `b6a2976`
export it fails (exit 1) on the surviving `pubkey_hash_matches` mutant. A
diff that touches no in-scope Rust line exits 0 without building anything.
The timeout allow-list was checked the same way: the five known hangs plus
the two `actual_size` mutants pass the gate (exit 0: 5 timeouts, the rest
caught), and the `issued_through_sat` hang alone, with its line removed from
a copy of `.cargo/mutants-timeouts.txt`, fails it (exit 1, the mutant named).
That run was started with `CARGO_TARGET_DIR` set to a shared directory; the
logs show each build copy running its own `<copy>/target/debug/deps` test
binary. `scripts/mutants-equivalent-check.sh` passes on this tree and fails
(exit 1, the drifted mutant named) on two simulated edits: a new `|` in
`work` (a tenth mutant inside the E3 pattern) and the E4 clamp moved into a
block (the documented mutant no longer matched at column 12).

cargo-mutants is pinned (`cargo-mutants@27.1.0`) so that a new release's new
mutation operators do not fail an unrelated run; bumping it is a deliberate
change that re-checks the scope.

## When CI reports a survivor

1. Read the mutant's diff and log in the uploaded `mutants.out`.
2. If some input distinguishes the mutant from the original code, add a test
   that checks that behaviour (an exact boundary, a byte layout, a reference
   value) and confirm it fails against the mutant:
   `cargo mutants -p <crate> --re '^<mutant name>$'`.
3. Only if no input can distinguish it, add a row to the equivalent-mutant
   table above with the argument, an `exclude_re` entry inside the
   equivalent-mutant block of `.cargo/mutants.toml` that matches that mutant
   and as little else as possible, and the mutant's name (without line and
   column) to `.cargo/mutants-equivalent.txt`.
4. A timeout that is not a known hang fails the gate too. If the mutant
   really makes a loop endless, explain it in the Timeouts table and add it to
   `.cargo/mutants-timeouts.txt`; if it only slows the tests down, add a test
   that fails against it instead.
