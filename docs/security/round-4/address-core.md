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

Pending implementation and runtime checks.
