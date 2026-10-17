# Round 5 independent verdict and identity review

Reviewer: `/root/r5_review_verdict`, independent of the implementation agents.
Base: `2848dcf6bd89a85afe4828042227c9a2c2b433f0`.
Core, reference and browser review point: `0dc3bdb3b8a30f2966ddde7cabbf274206d1e87b`.
Browser correction reviewed: integration commits `c5ceb22` and `21dff0d`.
Final CLI/RPC production reviewed:
`0cb572ba01dc69865ad29b21fa87a4b1abb5714a` (frontend original `0898b01`).
Status: this verdict/identity lens is complete for the scoped descriptor
package. The browser finding below is resolved in the new descriptor binding;
no additional verdict or identity finding was identified in the final CLI/RPC
diff. This is not approval of the whole round, its CI, native reversals or
unrelated inherited findings.

## Finding R5-VERDICT-1 — browser serialization can redirect the public operation

Severity: low. This violates the new public-binding/session-integrity contract;
it is not evidence of remote code execution or a separate authorization boundary.
A caller able to supply a function-bearing JavaScript object normally already
has access to the returned core object.

At `site/wallet/core.js:105`, spreading `request` before assigning
`op: "descriptor"` retains an own `toJSON` method. The private `call` function
then calls `JSON.stringify`, which invokes that method and can serialize a
different operation. I reproduced this against the actual pinned WASM at the
review point, after creating a disposable local signing session:

```javascript
core.descriptor({
  action: "pool", network: "mainnet", public_keys: [],
  toJSON() { return { op: "wipe" }; }
});
```

Observed response: `{"locked":true}`. A subsequent `core.address()` threw
`wallet is locked`. No production source was changed for this reproduction.
The checked-in existing test at `site/tests/wallet-descriptor.test.mjs:55`
only varies the ordinary `op` data property, so it does not catch this case.

The correction constructs a null-prototype envelope, refuses an own `toJSON`
field and then forces `op: "descriptor"`. This prevents the serialization
hook from replacing the top-level operation. Final tests at
`site/tests/wallet-descriptor.test.mjs:81` and `:95` retain a live disposable
session through both the own and inherited-hook variants. I ran all seven
browser descriptor tests after applying the integrated correction: 7 passed.
This does not protect against arbitrary code executed by a hostile caller or
getter, and does not change or close concerns in older public bindings.

I also inspected the frontend author's production reversal receipt and logs
(`/private/tmp/gnb-r5-frontends-tojson-reversal.json`): reverting only the
correction to binding `f79421b` gives 1 positive control passed and 2 session
tests failed with `wallet is locked`; restoration gives 3 passed. The final
test file remains SHA256
`c87deea0b0950f86561781b4690a0d89c10825ac5e9e84bdc251f30ab3f17e36`.
I independently recomputed and matched the reverted log SHA256
`dc20b355ea1cd0a96418e173498652a87c264c0bb1f20bf8586138d11d7b1f54`
and restored log SHA256
`033537e49824a86757f29555819219e571cff085cb843b3b13b579128f9999b5`.
The frontend author ran this reversal; I reviewed it, rather than rerunning it.

## Reviewed invariants

- The production diff introduces a wallet codec and dispatcher entry, not a
  block/transaction/activation/signature rule. Descriptor script derivation at
  `crates/gnb-crypto/src/wallet/descriptor.rs:243` calls the existing address,
  `SpendPolicy` and `PolicyTree` functions. There is no new consensus verdict.
- Descriptor fields are private, construction validates the fixed-depth
  grammar, and all policy leaves use `SpendPolicy::new` before building a tree
  (`descriptor.rs:145`, `descriptor.rs:183`, `descriptor.rs:190`).
- Raw and envelope public key bytes are preserved. The existing hybrid shape
  predicate is reused (`descriptor.rs:92`); no canonical key conversion or
  distinct-key consensus change is introduced. The raw/envelope and branch
  order regression at `crates/gnb-crypto/tests/public_descriptors.rs:72`
  explicitly retains PF-4 rather than claiming it is fixed.
- The raw descriptor request parser refuses duplicate top-level fields before
  `Value` erases them (`descriptor.rs:455`). The WASM probe inspects every `op`
  occurrence and routes a request mentioning `descriptor` through that strict
  parser (`descriptor.rs:542`, `crates/gnb-wallet-wasm/src/lib.rs:158`). Legacy
  requests without that marker keep the prior parser. This adds a linear JSON
  scan and is not a claim that all legacy request handling is hardened.
- The shared public dispatcher allows only the five declared data operations
  and never accesses a signing session (`descriptor.rs:409`). Pool import
  rejects duplicate/unknown JSON fields and checks the raw pool byte bound
  before deserialization (`descriptor.rs:333`).
- Python derives policy/tree hashes from explicit old-format bytes, independently
  of the new Rust codec (`reference/descriptor.py:132`). The differential driver
  compares complete accepted responses and rejection verdicts, not error text
  (`reference/descriptor_differential.py:49`). Its finite corpus does not prove
  complete consensus equivalence, 10^7 cases or a score improvement.

## Checks actually executed by this reviewer

Using Python 3.12.15 in this review worktree:

- `python3 reference/descriptor_test.py`: 13 passed, 0 failed.
- `python3 reference/descriptor_vectors.py --check`: `descriptor vectors:
  reproducible`, exit 0.
- Node 22.23.3: `node --test site/tests/wallet-descriptor.test.mjs`: 5 passed,
  0 failed, against actual WASM SHA256
  `d6dc794e7be5f4dfca7f4da05719f05adc4c762a93acd1b396e3a183bdc22569`.
- The disposable-session `toJSON` reproduction above executed separately and
  demonstrated the missing regression despite the existing five tests passing.
- After integrated test/fix commits `c5ceb22` and `21dff0d`, the same full
  Node command passed 7/7 against the unchanged real WASM artifact.

No native Rust build, full suite, production reversal or CI run is attributed
to this reviewer. No numeric score or Bitcoin-superiority conclusion is given.

## Final CLI/RPC addendum

I read the exact production diff in `0cb572b`, its surrounding dispatch and
argument handling, and the frontend tests. The CLI path at
`node/src/bin/gnb-cli.rs:1138` requires an explicit network, accepts only the
five frozen actions and exact positional argument count, and returns before
the ordinary RPC call path. `RpcTarget::new` constructs configuration without
connecting to a node. The CLI has no key loading or signing operation here.

The existing bounded reader at `node/src/bin/gnb-cli.rs:1116` reads at most
`limit + 1` bytes and rejects oversize input before descriptor/bundle parsing.
The bundle remains raw JSON text through `public_request`, so duplicate pool
fields are not lost in a frontend `Value`. Export/pool inputs are typed arrays
of strings; all descriptor, network, script-identity and pool validation stays
in the shared codec. Output creation at `node/src/bin/gnb-cli.rs:1178` uses
`create_new(true)` after validation, refusing an existing destination or symlink.
The code reports write/sync errors; it does not promise atomic completed-file
publication or recovery after a partial I/O failure.

Both RPC methods call `inspect_rpc_descriptor` at `node/src/rpc/mod.rs:2612`.
That helper requires exactly one string parameter, binds the request to the
node's configured `ChainId`, and forces the shared `inspect` action. It neither
accepts a caller-selected action/network nor accesses storage or wallet state.
`deriveaddresses` renders the legacy address from that same inspection result.
Both names are included in `KNOWN_RPC_METHODS` and retain the existing read
authentication policy. This package does not change or claim strict duplicate
rejection for the old JSON-RPC envelope parser.

I reviewed the frontend author's receipts in
`/private/tmp/gnb-r5-frontends-final/results.json`, read the actual passing test
summaries, and recomputed each log hash:

| Frontend-authored execution | Result | Log SHA256 |
| --- | --- | --- |
| `cargo test -p gnb --test descriptor_cli --locked --offline -- --nocapture` | 7 passed | `3d2930974be7825732673d7f94dac2641ad4f369833a1c18913a628065c562e3` |
| `cargo test -p gnb --lib descriptor_rpc --locked --offline -- --nocapture` | 5 passed | `15a3586ba3d6306c9bed0743e169277eeba57fdee1aefe23232eaafe818b3b21` |
| `cargo test -p gnb --lib known_methods_list_matches_dispatch --locked --offline` | 1 passed | `2d5c72e8259c1843e1c55663519236454bce378f7e4ee2e60905ebe2c4e715a0` |

These are reviewed third-party executions, not native tests I ran. Native
frontend production reversals and whole-round integration remain the root
engineer's delivery gates; this addendum does not assert their completion.
