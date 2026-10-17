# Round 5 descriptor package contract

Base: `2848dcf6bd89a85afe4828042227c9a2c2b433f0` (PR 13 merged after its CI).
The base tree equals reviewed R4 head `366e75f`. All inherited findings remain
open. This is a partial delivery of technology item 4.2, not a new score.

## Scope and exclusions

Implement static, public-only descriptors for existing output scripts and a
bounded public descriptor pool that can be exported and restored. Shared Rust
logic serves offline CLI, node RPC and WASM. An independent Python reference
derives the same scripts, addresses and checksums from generated vectors.
No consensus, activation, signature, derivation algorithm, transport, bridge
or existing wallet-file format is changed. No signing or broadcasting is added.
No wildcard/xpub/private-key descriptors or new policy language are claimed.
Public pool restoration restores public identities, not spending keys, chain
history, current balances, or a persistent node wallet index.

Do not reopen previously rejected PoWit/R7 or excessive-witness work. Ordinary
integration suites retain their existing failures; do not investigate the R4
ingress assertion as a new route to those tasks.

## Static text format (freeze before independent implementations)

```
descriptor = body "#" checksum
body       = "gnbd1(" network "," expression ")"
network    = "mainnet" | "testnet"
expression = pkh | policy | tree
pkh        = "pkh(" KEY ")"
policy     = "policy(" threshold "," after "," older "," KEY ("," KEY)* ")"
tree       = "tree(" policy "," policy ("," policy){0,2} ")"
```

`KEY` is lowercase hex encoding of an existing accepted hybrid public-key
representation (raw or a valid current hybrid suite envelope). Preserve every
key byte: never silently normalize raw/enveloped keys to a different script.
Private keys, xpubs, paths, wildcards, whitespace and uppercase text are refused.
Unsigned integers use minimal decimal (`0` or a nonzero digit followed by
digits); threshold is 1..=key count, at most 7 keys; after/older are u32.
Tree branches number 2..=4 and preserve their input order. Existing policy
validation is reused without changing it, including its current distinct-key
semantics; this package does not close PF-4.

The checksum is exactly the eight-character BIP380 descriptor checksum over
the complete ASCII body, including network and `gnbd1`. Its alphabet, expansion,
polymod and final xor follow the primary specification:
https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki . Cite this source
in the implementation. This is not a Bitcoin-compatible script/key language.
Require a checksum for import/inspection. Creation takes a checksum-free body.
Reject any extra delimiter, trailing data or noncanonical spelling.
Maximum complete descriptor length: 262,144 ASCII bytes. Do not extend BIP380's
shorter-length multi-error guarantees to our largest PQ descriptors. A checksum
detects mistakes; it does not authenticate the source of a public key.

Script derivation is existing GnB behavior: pkh = SHA3-256(exact KEY bytes)[:20];
policy = existing SpendPolicy::script_pubkey(); tree = existing
PolicyTree::script_pubkey(). All fields and branch/key order are unchanged.
Both legacy and opt-in Bech32m address renderings are returned. Tree description
does not establish that spending it is activated on the caller's chain.

## Shared API

Implement `gnb_crypto::wallet::descriptor::public_request(&serde_json::Value)`
returning `Result<Value, String>`, plus typed bounded codec/pool helpers.
Every request is an object with an explicit `network` (mainnet/testnet) and
`action`. Reject unknown fields and wrong types. An optional `op` must be
exactly `descriptor`; WASM/JS bindings force that value, never trust a caller
to redirect the public operation to a session-key operation.

Actions and their other allowed fields:

| action | input | output |
| --- | --- | --- |
| create | `body`: string without checksum | descriptor info |
| inspect | `descriptor`: checksummed string | descriptor info |
| export | `descriptors`: array of checksummed strings | pool response |
| import | `bundle`: string containing the pool JSON | pool response |
| pool | `public_keys`: array of lowercase public-key hex strings | pkh pool response |

Descriptor info has `descriptor`, `network`, `kind` (pkh/policy/tree),
`script_pubkey` (lowercase hex), `address` (legacy), `bech32m`, and
`requires_policy_tree_activation` (true only for tree). The request network
must equal the descriptor/pool network. All paths use the same codec and
validation; no parallel frontend parser.

The pool's canonical compact JSON has exactly this field order and schema:
`{"format":"gnb-watch-only-v1","network":"mainnet","descriptors":[...]}`.
The pool response is `{"bundle":<canonical JSON string>,"count":N,"entries":[info...]}`.
Preserve descriptor order. Require 1..=64 entries, a maximum of 1,048,576 UTF-8
bytes for the complete pool JSON, a consistent network, and unique scripts.
Unknown/duplicate JSON fields, unsupported format, empty/excess lists, extra
bytes or duplicate identities are rejected. Check raw input byte length before
deserializing. A pool contains public descriptors only, never secrets. No new
derivation is performed: offline owners supply already-derived public keys.

RPC: expose inspect/derive functionality on the node network and reject other
networks. CLI: offline descriptor creation/inspection and public-pool file
export/import, with bounded reads and safe non-overwriting output. WASM: the
same public operations without requiring or changing an unlocked session.
Keep product behavior explicit about public-only restoration and activation.

## Ownership and acceptance

| Package | Owner files | Native CGU / target |
| --- | --- | --- |
| Core | wallet descriptor module, wallet module export, Rust WASM dispatch/host tests, Rust oracle, focused tests, own evidence | 139 / `/private/tmp/gnb-r5-target-descriptor-core` |
| Reference | independent Python codec/generator/tests, `docs/DESCRIPTORS.md`, own evidence | 149 reserved; Python only |
| Frontends | node RPC/CLI wiring/tests, JS public binding/tests, usage guide, own evidence | 151 / `/private/tmp/gnb-r5-target-descriptor-frontends` |
| Integration | final actual WASM rebuild/pins, CI wiring, functional test, aggregate evidence | 157 / `/private/tmp/gnb-r5-target-integration` |

Each implementation package writes a brief and test-only commit first. Core
must demonstrate missing functionality with runtime assertions through the
existing `gnb_wallet_wasm::handle` dispatcher (positive legacy control plus
new descriptor requests fail as unknown operations) BEFORE production edits.
Missing newly invented Rust APIs/compile errors do not count as reproduction.
Reference may develop independently from this contract and old script specs;
it must not read the new Rust parser. Frontend missing RPC/CLI operation checks
must also fail at runtime before wiring. Preserve the tests and logs.

Test both networks and all three descriptor kinds, existing byte identities,
checksum/grammar boundaries, public pool export/import and wrong network. Add
fixed independent vectors and a generated Rust/Python comparison. Restore an
exported public pool through actual CLI/WASM paths; do not substitute mocks for
the codec. Show that an arbitrary public operation cannot call signing/wipe.
Bound descriptors/pools and test limits without reviving excluded tasks.

After implementation, independent verdict/path/test-strength reviewers inspect
all packages. Production reversals keep final tests unchanged and demonstrate
runtime failures, then restore. Core crypto tests remain separate from node
tests. Root rebuilds WASM through `scripts/build-wallet-wasm.sh`, repins and
runs the full integration suites. Do not hide failed gates or infer scores.
