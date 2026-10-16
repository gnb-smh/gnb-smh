# Round 5 independent verdict and identity review

Reviewer: `/root/r5_review_verdict`, independent of the implementation agents.
Base: `2848dcf6bd89a85afe4828042227c9a2c2b433f0`.
Core, reference and browser review point: `0dc3bdb3b8a30f2966ddde7cabbf274206d1e87b`.
Browser correction reviewed: integration commits `c5ceb22` and `21dff0d`.
Status: partial; final CLI/RPC production remains pending. The browser finding
below is resolved in the new descriptor binding.

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
