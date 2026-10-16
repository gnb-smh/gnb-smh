# Round 4 package: opt-in network-bound addresses

Base: `7d6a67eafa93cf7935ecedb50d601486aca4cff7`.
Worktree: `gnb-r4-address-core`; branch: `codex/r4-address-core`.
`CARGO_PROFILE_DEV_CODEGEN_UNITS=79`, `CARGO_PROFILE_TEST_CODEGEN_UNITS=79`,
`CARGO_TARGET_DIR=/private/tmp/gnb-r4-target-address-core`, incremental disabled.

## Scope and contract

Add an opt-in address string codec to `gnb-crypto::address`. Existing `Display`,
binary/serde representation, legacy acceptance, scripts, transactions and all
consensus rules remain unchanged. `Address::to_bech32m()` and
`PolicyAddress::to_bech32m()` render the new form. Their existing parsers accept
the matching new kind; `destination_script` accepts both kinds.

The network HRP is `gnb` (mainnet) or `tgnb` (testnet). Data words start with
5-bit format version `2`, then kind `0` (20-byte single-key hash) or `1`
(32-byte policy hash), followed by the hash converted 8-to-5 bits with zero
padding. The checksum is Bech32m. Decoding rejects unknown HRPs, versions and
kinds, wrong hash length, excessive/nonzero padding, mixed case, non-ASCII
characters, and strings longer than 90 bytes. Uniform uppercase and lowercase
are accepted; encoding emits lowercase. This is a GnB application format,
not a Bitcoin witness-address format. The checksum detects transcription
errors; it does not authenticate a sender or a secret.

The checksum and case rules follow [BIP 350](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki)
and [BIP 173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki).
Bech32m includes the HRP in its checksum and addresses the insertion weakness
described in BIP 350. No dependency is needed for this bounded codec; official
generic checksum vectors and an independent Python codec check its behavior.

## Acceptance and evidence plan

1. Before production edits, run new tests against the existing `Address::parse`,
   `PolicyAddress::parse` and `destination_script` APIs. New-v2 acceptance must
   fail at runtime while fixed legacy controls pass.
2. Check legacy fixed strings, serde bytes, uppercase-hex legacy acceptance,
   wrong-prefix/checksum rejection, and same-network/script mapping.
3. Test format, kind, hash length, padding, case and network binding with fixed
   vectors and bounded single-character mutations. Compare independent Python
   vectors with the Rust public API.
4. Run `cargo test -p gnb-crypto` separately from any node test invocation.
5. Restore production to the base revision with tests unchanged, confirm the
   new acceptance test fails, restore exact production bytes, and rerun green.
   Preserve source/test hashes, commands, exits, and logs in an evidence manifest.
6. Independent reviewers assess verdict paths, entry-path variants and test
   strength before integration. This package alone does not close RPC/wallet
   integration or any overall scorecard category.

No prior automatically rejected PoWit, R7 or witness-size task is in scope.

## Results

The initial regression commit `40c321b` used only existing public APIs. Against
unchanged production from the base, the legacy control passed and all three
v2 acceptance tests failed at runtime with `BadPrefix` (exit 101). The exact
regression file remains unchanged, SHA-256
`02e1772e7001592f45f730a774a502dee747a01bf55fc30fd5a86f7dcf2a4302`.

Implementation `cf40773` adds a private codec and opt-in renderers. Four codec
unit tests, including the complete official generic BIP 350 checksum vectors,
supplement the public API tests.
`address_v2_render` checks the four independent zero-hash vectors and all 20,274
single-character substitutions using ASCII 33–126 on those strings. A diagnostic-only followup
`4b32fb6` rejects incorrect decoded hash lengths with `BadEncoding`, instead of
misusing the legacy character-count `BadLength` error. Its new public-API test
first failed at runtime with `BadLength { got: 19, expected: 20 }`, then passed;
accepted/rejected strings did not change. Final focused tests: 7 passed.

Production-only reversals are recorded in
[`address-core-reversals.json`](address-core-reversals.json). Restoring the entire
`address.rs` entry point to the base produced 1 passing legacy control and 3
failing v2 tests. Removing the checksum, padding and mixed-case checks produced
2, 1 and 1 runtime failures respectively. Restoring the former length diagnostic
produced 1 failure. Restored runs passed: 4 original public tests, 4 codec unit
tests and 3 rendering/diagnostic tests. The driver checks exact test bytes and
inline test-region hashes throughout, restores production in `finally`, and
asserts all final source hashes equal their starting values.

Run the replay with a fresh output path to retain previous evidence:

```sh
python3 docs/security/round-4/replay-address-core.py \
  --worktree /path/to/checkout --target /tmp/address-core-target \
  --output /tmp/address-core-replay-new
```

The independent Python implementation at `a8e8b78` agreed with the Rust public
destination parser and explicit renderers on 630 requests from its 502-case
corpus (128 accepted / 374 rejected). The Rust oracle has no v2 prefilter;
legacy compatibility is checked separately by the unchanged Rust golden test.
The baseline corpus SHA-256 is
`26c1d23ebeb765961bcab1930f0555b9c54252e750d7be139b713191d8d0ee1c`.

The full `gnb-crypto` invocation on `cf40773` initially stopped with 438 passed,
3 failed and 1 ignored: all failures were existing local-socket tests denied
`bind` by the sandbox (`EPERM`, `wallet/http_rpc.rs:476`). Repeating the exact
suite with local-socket permission and unchanged sources passed 478 tests,
with 4 existing ignores. Logs for both outcomes are retained. Final revision
`4b32fb6` passed the full separate `gnb-crypto` invocation: **479 passed,
4 existing ignores, 0 failures**. Rebuilding the final Rust oracle and repeating
the independent comparison again produced **630 requests, 0 divergences**.
Exact source/log/artifact hashes and commands are recorded in
[`address-core-evidence.json`](address-core-evidence.json).

## Integration limits

This package does not prove RPC, CLI, WASM, browser or index-key integration.
Those are separate packages, and the WASM still requires its canonical rebuild
and pin at integration. No network or consensus activation is needed for this
opt-in text representation because the underlying hashes and scripts are
unchanged; legacy single-key checksums remain network-independent.

The `address_parse` fuzz target was maintained for the new API/error variant:
its independent legacy comparison remains intact, and v2 receives round-trip,
network and single-character invariants. This maintenance is not a newly
reproduced defect or an independent v2 oracle. The latter is the Python
differential. The dedicated fuzz workspace type-check is an integration check,
not claimed by this package's `gnb-crypto` tests. Repository-wide `AddressError`
match inventory found only this target's exhaustive cloning match requiring
the new variant. Independent three-lens review and release CI remain required.
