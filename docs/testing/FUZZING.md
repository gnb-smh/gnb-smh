# Fuzzing

GnB-SMH fuzzes its untrusted-input parsers, its consensus encodings and its
block-acceptance pipeline with [cargo-fuzz] (libFuzzer, coverage-guided)
under AddressSanitizer. The crate is `node/fuzz`: its own workspace (excluded
from the root one, so nightly-only sanitizer flags never reach the consensus
build), one binary per target in `node/fuzz/fuzz_targets/`, one seed corpus
per target in `node/fuzz/corpus/<target>/`.

[cargo-fuzz]: https://github.com/rust-fuzz/cargo-fuzz

Most targets do more than "never panics": they compare the library with an
independent implementation written from the specification in the target
(`fuzz_targets/common/mod.rs` and the targets themselves), or check a
round-trip, canonicality or sensitivity property. A property violation is an
assertion failure, which libFuzzer reports as a crash like any panic.

## Targets

| Target | Entry points | What it checks |
| --- | --- | --- |
| `tx_parse` | `Transaction::from_wire_bytes` | no panic; decode/encode is a fixed point; txid stable |
| `block_parse` | `Block::from_wire_bytes` | no panic; decode/encode is a fixed point |
| `header_parse` | `BlockHeader::from_wire_bytes` | no panic; fixed point; a trailing byte is refused |
| `netmsg_decode` | `network::decode_wire_message` (gossip frames) | no panic; an accepted frame obeys every field bound (restated in the target) and is the canonical encoding of its message (one frame per message: gossipsub message ids are SHA-256 of the frame) |
| `handshake_decode` | transport `HandshakeInit` / `HandshakeResp` decode | no panic (16 KiB limit, bincode standard configuration, as `read_msg`) |
| `pow_decode` | compact bits, chain work, ASERT (`gnb_smh::difficulty`) | no panic; bits round down and are stable; work monotone; ASERT equals an independent U512 implementation of aserti3-2d |
| `pow_verify` | GnB-SMH on small scratchpads, `crypto::verify` | no panic; strict `out < target`; malformed bits never validate; the hybrid verifier returns a bool on arbitrary keys and signatures |
| `merkle_path` | `coherence_core::verify_path` | no panic; wrong-length paths and indices above the tree depth never verify |
| `mempool_ops` | `Mempool` add / remove / remove_confirmed op stream | the `txs` / `spent` / rate-index invariant after every operation |
| `block_rules` | `core::block_rules` (VAL-2, VAL-10, VAL-12, CRY-1) | tagged Merkle root equals an RFC 6962-style recursive reference; legacy root equals Bitcoin's in-place `ComputeMerkleRoot`; coinbase branch folds back to the root and ignores position 0; a duplicated last id changes the tagged root; on blocks decoded from untrusted bytes: wire encoding and `wire_size`, txid, wtxid, header roots, witness root, parents commitment and the 80-byte coinbase commitment equal the references; the 64-byte rule fires exactly on 64-byte txid preimages; the commitment verdict (which field fails) equals a reference parser; a block repaired to the specification is accepted, and altering any committed field (commitment byte, height, parent list, a witness, a truncated commitment, an extra transaction) is rejected while the miner's extra bytes are free |
| `sighash` | `Transaction::sighash`, `sighash_v2_checked`, `sighash_v3`, `SighashV3Precomputed` | no panic for any transaction, index or spent-output count; v2 equals an independent hand-written bincode encoding of the stripped transaction (and the bincode crate); v3 equals an independent 195-byte preimage; v3 errors exactly on a spent-output count mismatch or an out-of-range index; changing any single committed field (version, locktime, chain, suite, index, prevout, sequence, spent amount, spent script, output value or script) changes the v3 digest; no `script_sig` changes either digest |
| `witness_parse` | `parse_script_sig{,_borrowed,_exact}`, `build_script_sig`, `sighash::canonical_witness`, `check_input_witnesses` | the parsers equal a reference parser (lenient and exact); exact round trip of `build_script_sig`; trailing bytes refused by the exact parser only; the canonical-witness and per-regime witness rules agree with the framing and `is_canonical_signature_encoding`; genuine canonical hybrid signatures altered by the input exercise the envelope and Falcon compact-encoding checks |
| `wire_roundtrip` | `Transaction` / `BlockHeader` / `Block` wire encoding, `admission::decode_tx_strict` | generated values: the encoding equals an independent encoder, `wire_size` its length, `decode(encode(x)) == x` exactly when `x` is within the parser caps (values at and one past each cap are generated), every proper prefix and one extra byte are refused; untrusted bytes: the strict decoders are the exact inverse of the encoder (`decode(b) = x` implies `encode(x) == b`) |
| `undo_decode` | `UndoData::{from_bytes, to_bytes}` | no panic; decode/encode fixed point; a record without overwrites is byte-identical to the legacy six-field record; the legacy prefix decodes alone; an empty extension is normalised away; trailing garbage and a truncated extension are refused |
| `keystore_decode` | keyfile v1/v2 (`EncryptedKeyfile`, `Wallet::from_encrypted_bytes`), keystore v2/v3 (`Keypair::from_encrypted_bytes`) | arbitrary JSON: no panic, decrypt driven to completion with cheap Argon2 parameters, parameters over the bounds refused before any KDF; library-written keyfiles (fast parameters) round-trip and refuse a wrong password and any altered AEAD-bound field; a keystore v3 written by an independent implementation of the format loads to the same key pair and refuses an altered network, address, version, ciphertext or KDF output length |
| `address_parse` | `Address::parse`, `parse_for_network`, `FromStr`, `Display` | verdict (value or error kind) equals a reference parser; the canonical form round-trips and differs only by hex case and the Bloch alias; `parse_for_network` accepts the own network only; a one-digit change is `BadChecksum`; a prefix swap keeps the hash (documented residual) |
| `sync_rr_codec` | `/gnb/sync/1` frames: `decode_request`, `decode_response`, `encode_frame`, `check_nonempty_frame`, and the libp2p codec `BlochSyncCodec` (`read_request` / `read_response` / `write_request` / `write_response`) over an in-memory stream | no panic; every refusal is `InvalidData` (penalized) and an empty frame `UnexpectedEof` (not penalized); accepted frames obey every bound and are canonical; both transports enforce the same bounds (a response accepted here passes the gossip decoder, a gossip pull accepted there is accepted here); generated messages round-trip exactly when within bounds; reading a stream through the codec is exactly `check_nonempty_frame` + the decoder on its first 4 MiB, writing is `encode_frame` and reads back, and a stream over the 4 MiB read cap (a valid frame followed by padding) is a penalized refusal |
| `accept_dag` | `accept::accept_block` (behind `validate_structure`) on a RocksDB `Storage` in a temporary directory with a real `GhostDAG` | small arbitrary DAGs (up to 6 sealed blocks, PoW-cheap through the crate's `test-pow-limit` feature) with signed spends of funded outputs, conflicting spends, spend chains, version 1 and 3 transactions, broken signatures, missing inputs and deliberate faults (coinbase over-claim, wrong height, wrong bits, timestamp before a parent, duplicated transaction), under the hardening activation never / from genesis / inside the DAG; no panic, and two different arrival orders of the same block set (orphans retried) end with the same selected tip, applied tip, UTXO set digest and DAG block set; optionally a reload from storage (`reconcile_on_startup`) keeps that state |

The seed corpora of eight of the nine original targets are generated (and
replayed on stable Rust) by `node/tests/parser_corpus_floor.rs`; those of
`header_parse` and of the nine targets added in October 2026 by
`node/tests/fuzz_seed_corpus.rs`, which also
checks that every committed `seed_*` file is reproducible and replays every
corpus file (seeds and crash regressions `regress_*`) through the parsing
entry points on stable Rust. Each corpus stays below 200 KB.

## Defects found

Both are fixed at their root cause, with regression tests and the crashing
input committed to the target's corpus (`regress_*`).

1. **Non-minimal CompactSize varints accepted by the wire decoders; block
   transactions framed by their re-encoded length** (`wire_roundtrip`,
   strict-inverse property). `read_varint` accepted `FD 05 00` for 5 (and the
   5- and 9-byte forms of small values), so every block, header and
   transaction had many byte encodings although `Block::from_wire_bytes` is
   documented as the strict inverse of `to_wire_bytes`; each variant of a
   `NewBlock` payload was also a distinct gossip message. Worse,
   `Block::from_wire_bytes` advanced past each transaction by
   `tx.to_wire_bytes(true).len()`, fewer bytes than the transaction decoder
   had consumed for a non-minimal encoding, and parsed the rest of the block
   from inside that transaction (a crafted block with script length
   `FD 0C 00` and a locktime ending `FD 00` decoded "successfully" that way).
   Fixed in `core/mod.rs`: only minimal varints are accepted (Bitcoin Core's
   `ReadCompactSize` rule) and the block decoder frames each transaction by
   the bytes consumed (`Transaction::read_wire_bytes`). The encoders always
   wrote minimal varints, so nothing produced or stored changes; block ids,
   txids and roots commit to decoded values, so this is not a validity rule.
   The reproducer came from a seed written to probe the property (a header
   with a `FD 01 00` parent count); a 200-second run without that seed did not
   rediscover it. Tests: `core::wire_canonical_tests`,
   `node/tests/fuzz_regressions.rs::header_with_a_non_minimal_parent_count_is_refused`.
2. **Non-canonical gossip and sync frames accepted (bincode non-minimal
   varints)** (`netmsg_decode`, canonical-frame property; found in about two
   seconds from the original seed corpus). bincode's decoder accepts a value
   in a longer varint form (`FC 1F 00 00 00` for 31), so one message had many
   byte encodings. Gossipsub message ids are SHA-256 of the frame, so each
   variant was a fresh message id: the de-duplication bypass that audit NET-7
   closed for trailing bytes, reopened through the varints. The `/gnb/sync/1`
   codec had the same gap. Fixed in `network/mod.rs` (`decode_wire_message`
   refuses a frame that is not the re-encoding of its message:
   `WireDecodeError::NonCanonical`, a penalized protocol violation) and
   `network/sync_rr.rs` (`decode_request` / `decode_response`, `InvalidData`).
   Tests: `node/tests/fuzz_regressions.rs`.

Each fix was checked by mutation: disabling it makes its regression tests
fail.

The campaign also showed that `header_parse` had no seed corpus (its
directory did not exist: libFuzzer refused to start with it, and CI created
it empty); `fuzz_seed_corpus.rs` now generates one.

## Campaign results (October 2026)

Every target ran under ASan (`cargo +nightly fuzz build`: release, debug
assertions and overflow checks, LeakSanitizer on) for 600 s, `accept_dag` for
1,800 s, starting from its committed corpus, with `nice -n 15 -jobs=1
-workers=1 -rss_limit_mb=2048 -timeout=120`, two targets at a time on a shared
4-core machine that was also running other builds and mutation tests (the
exec rates are lower bounds). Built with nightly `cargo 1.101.0-nightly
(2026-10-07)` and cargo-fuzz 0.13.2. The binaries were built from the tree
with both fixes above in place; the later runs (`header_parse`,
`undo_decode`, `address_parse`, `sync_rr_codec`) were rebuilt from the
committed tree (the library code did not change in between, only `#[cfg(test)]`
code). `cov` / `ft` are libFuzzer's covered edges and features at the end of
the run (whole binary), `corpus` the corpus it ended with.

| Target | Seconds | Executions | exec/s | cov | ft | Corpus (units) | Peak RSS (MB) | Findings |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `tx_parse` | 600 | 11,433,892 | 19,024 | 380 | 1,121 | 124 | 531 | none |
| `block_parse` | 600 | 14,014,853 | 23,319 | 561 | 1,865 | 225 | 478 | none |
| `header_parse` | 600 | 46,196,287 | 76,865 | 255 | 439 | 39 | 436 | none (first run: no corpus directory, see above) |
| `netmsg_decode` | 600 | 20,998,230 | 34,938 | 1,126 | 2,641 | 269 | 156 | none after fix 2 (found it in ~2 s before) |
| `handshake_decode` | 600 | 13,945,696 | 23,204 | 231 | 489 | 110 | 93 | none |
| `pow_decode` | 600 | 34,419,600 | 57,270 | 519 | 1,002 | 201 | 487 | none |
| `pow_verify` | 600 | 2,744,125 | 4,565 | 274 | 335 | 61 | 405 | none |
| `merkle_path` | 600 | 11,406,970 | 18,979 | 112 | 137 | 24 | 528 | none |
| `mempool_ops` | 600 | 290,038 | 482 | 1,151 | 6,188 | 548 | 514 | none |
| `block_rules` | 600 | 504,144 | 838 | 2,003 | 6,156 | 307 | 477 | none |
| `sighash` | 600 | 1,813,337 | 3,017 | 962 | 3,042 | 223 | 480 | none |
| `witness_parse` | 600 | 2,215,323 | 3,686 | 852 | 1,625 | 147 | 404 | none |
| `wire_roundtrip` | 600 | 500,821 | 833 | 1,548 | 4,886 | 480 | 432 | none after fix 1 |
| `undo_decode` | 600 | 2,074,054 | 3,451 | 1,389 | 4,037 | 395 | 334 | none |
| `keystore_decode` | 600 | 1,437,930 | 2,392 | 5,482 | 14,025 | 2,332 | 476 | none |
| `address_parse` | 600 | 4,318,981 | 7,186 | 626 | 1,151 | 88 | 555 | none |
| `sync_rr_codec` | 600 | 119,432 | 198 | 2,325 | 5,852 | 558 | 558 | none |
| `accept_dag` | 1,800 | 703 | 0.4 | 8,080 | 27,021 | 264 | 535 | none (one 10 s slow-unit report, not a timeout) |

No crash, leak, timeout or out-of-memory input after the two fixes.
`sync_rr_codec` also ran 600 s before it drove the libp2p codec (527,601
executions, 877 exec/s, cov 2,033, no finding); the codec checks raised its
coverage to 2,325 edges and lowered the rate (every frame is also read
through the codec, and the read-cap check builds 4 MiB streams).

`accept_dag` is slow by construction: every block it has not built before
costs one GnB-SMH evaluation (a 64 MiB scratchpad) to seal, which dominates
under ASan and coverage instrumentation (13 of 15 stack samples of a running
campaign were in `gnb_smh::hash_with`, the other two in RocksDB opening its
temporary databases). An input of up to six blocks took 2.6 s on average and
up to 10 s; libFuzzer reports a unit of 10 s or more as `slow-unit` (the
per-input timeout is 120 s). Replaying a sample of 42 inputs of its final
corpus (158 blocks; activation never, from genesis, inside the DAG and at the
mainnet height) shows the pipeline both accepting and rejecting, for many
different reasons: of 145 deliveries in the first arrival order, 71 were
accepted; the others were rejected for a missing UTXO (17), an invalid
selected parent (17), a duplicated transaction (11), a wrong height (10), a
timestamp before a parent (9), a coinbase over-claim (4), an invalid
signature (body rejected without poisoning the block id, 3), an invalid proof
of work (2) and a transaction version not allowed at the height (1).

### Do the targets detect what they are meant to detect?

Besides the two real defects (whose fixes were each checked by disabling
them: the regression tests then fail), each new target was rebuilt from a
scratch copy in which its independent reference or harness (the test side,
never the library) was altered, and run over its committed corpus. A
differential assertion that never ran, or compared values that do not depend
on the input, would not notice; each target stopped with the expected
assertion within seconds:

| Target | Test side altered | Detected after | Assertion |
| --- | --- | ---: | --- |
| `block_rules` | witness root over txids instead of wtxids | 1 s | `witness root` |
| `sighash` | v3 spent scripts hashed without their length prefix | 1 s | `sighash v3 differs from the specification` |
| `witness_parse` | reference claims the whole `script_sig` is consumed | < 1 s | `exact parser differs from the reference` |
| `wire_roundtrip` | CompactSize single-byte form ends at 0xFB | 3 s | `transaction encoding differs from the reference` |
| `undo_decode` | legacy record fields in another order | 1 s | legacy record equality |
| `keystore_decode` | independent v3 writer omits the network byte of the associated data | 1 s | `library refuses a keystore v3 written to the specification` |
| `address_parse` | reference checks 3 of the 4 checksum bytes | < 1 s | `parse differs from the reference` |
| `sync_rr_codec` | expected read result without `check_nonempty_frame` | 1 s | `read_request: error kinds differ` |
| `accept_dag` | arrival order B never retries a block whose parent is unknown | 9 s | `arrival order changed the outcome` |

## Known limits

* CI starts every run from the committed seeds: the corpus a run grows is
  not kept (only crash reproducers are uploaded), so the weekly campaign does
  not accumulate coverage from week to week.
* `accept_dag` executes one input every 2.6 s on average (above): the
  60-second pull-request run sees about twenty DAGs, the weekly 10-minute
  run a few hundred.
* The async read of the sync codec is driven over an in-memory stream; the
  libp2p substream and muxer underneath are not fuzzed.
* `keystore_decode` drives the decryption to completion only for Argon2
  parameters up to 64 KiB / 2 passes / 2 lanes (larger ones are checked at
  the parsing and bounds layer only).

## Reproducing

Prerequisites: a nightly toolchain, `cargo install cargo-fuzz`, and clang /
libclang for `librocksdb-sys`.

```sh
cp Cargo.lock node/fuzz/Cargo.lock      # start from the audited lockfile
cd node/fuzz
cargo +nightly fuzz build               # every target, ASan, debug assertions
cargo +nightly fuzz list

# One target over its committed corpus (new inputs go to the first directory):
mkdir -p /tmp/new
cargo +nightly fuzz run sighash /tmp/new corpus/sighash -- \
    -max_total_time=600 -rss_limit_mb=2048 -timeout=120 -print_final_stats=1

# Replay one input (a CI artifact, or a corpus file):
cargo +nightly fuzz run wire_roundtrip corpus/wire_roundtrip/regress_nonminimal_parent_count

# Minimize a crash, or the corpus:
cargo +nightly fuzz tmin <target> <crash file>
cargo +nightly fuzz cmin <target>
```

The campaign above ran each binary directly (`target/x86_64-unknown-linux-gnu/
release/<target>`) with `nice -n 15 <binary> -jobs=1 -workers=1
-rss_limit_mb=2048 -max_total_time=600 -timeout=120 -print_final_stats=1
-artifact_prefix=<dir>/ <scratch corpus> corpus/<target>`.

Regenerate the generated seeds after changing a generator:

```sh
GNB_WRITE_FUZZ_SEEDS=1 cargo test -p gnb --test fuzz_seed_corpus   # new targets
cargo test -p gnb --test parser_corpus_floor generate_seed_corpus  # original targets
```

## Continuous integration

`.github/workflows/fuzz.yml` builds every target on nightly with ASan and runs
each one over its committed corpus. `ci.yml` calls it on every pull request
and in the nightly run with 60 seconds per target; its own weekly schedule
(Sunday) runs 10 minutes per target, and a manual run takes the time as an
input. A crash, leak, timeout (120 s per input) or out-of-memory input (2 GB)
fails the job, and every reproducer libFuzzer wrote is uploaded as the
`fuzz-artifacts` artifact.
