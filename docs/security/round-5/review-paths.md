# Round 5 independent review: coverage and entry paths

Reviewer: `r5_review_paths`, independent of the implementation packages.
Review base: `2848dcf6bd89a85afe4828042227c9a2c2b433f0`.
Initial candidate: `0dc3bdb3b8a30f2966ddde7cabbf274206d1e87b`.
The JavaScript follow-up is integration commits `c5ceb22` and `21dff0d`,
reviewed on isolated worktree head `1fd117c` (identical cherry-picked changes).
Native CLI/RPC production is implementation commit `0898b01`, integrated as
`0cb572b` and reviewed on isolated worktree head `f9201bf` (same production diff).

## Scope and current result

This lens traces each public entry into the shared descriptor codec, checks
network and identity consistency, and examines rejection variants and resource
bounds. It does not evaluate the excluded PoWit/R7 or excessive-witness work,
score the project, or claim consensus coverage from wallet descriptor tests.

No additional defect has been identified in the reviewed core, reference,
WASM, repaired JavaScript, CLI or RPC paths. `R5-VERDICT-1` was reported by the separate
verdict reviewer: an own or inherited JavaScript `toJSON` hook could replace
the public request with a session operation. This review checked the fix and
additional variants; the original reproduction and production reversal belong
to that finding's implementation/integration evidence, not to this reviewer.

## Paths inspected

| Path | Observed behavior and coverage |
| --- | --- |
| `Descriptor::create` / `parse` | Fixed-depth grammar, ASCII and canonical number/key spelling, complete input consumption, descriptor size bound, mandatory eight-character checksum on inspection. Network is part of the checksum body. |
| Script construction | Single-key script hashes the exact accepted key representation. Policy and tree scripts call the existing constructors. Raw/enveloped identity and key/branch order remain unchanged. This does not close PF-4 or activate tree spending. |
| `PublicPool::from_descriptors` / `from_public_keys` | Nonempty 1–64 entries, aggregate size checks, common network and uniqueness by complete script bytes. Entry order is retained. The final canonical JSON byte bound is checked too. |
| `PublicPool::from_bundle` | Raw UTF-8 byte length is checked before JSON parsing. Typed serde decoding rejects unknown and duplicate fields, including decoded escaped field names; schema/network validation precedes use. JSON whitespace is accepted and canonicalized, not confused with descriptor whitespace. |
| `request_from_json` / `public_request` | Raw adapters retain duplicate-field detection; a pre-parsed `Value` explicitly cannot recover duplicate history. Action-specific fields and types are checked by the shared API, including the optional forced operation and explicit network. Nested objects are not valid descriptor/key fields. |
| WASM raw bytes / host dispatch | The routing probe scans every top-level `op` occurrence, including escaped JSON spelling; a descriptor mention selects strict request parsing. This adds one linear scan to legacy requests, without cloning their value tree. Existing legacy last-wins parsing is deliberately retained when no descriptor operation is present. |
| JavaScript `descriptor()` | The fixed path creates a null-prototype envelope, refuses an own enumerable `toJSON` field, and sets `op` after copying the request. It does not add signing, key import or persistence. The old `pqpsbt` binding was not changed or awarded new coverage by this package. |
| CLI dispatch / input | The command returns from the offline branch before RPC execution. Explicit mutually exclusive network flags are required. `read_public_document` reads at most limit+1 bytes and rejects invalid UTF-8; descriptor files use the descriptor bound and pool/list files use the pool bound. Array inputs deserialize as strings only, while imported bundle JSON remains raw for shared duplicate-field checks. |
| CLI output | The shared codec must succeed before the destination is created. `OpenOptions::create_new(true)` refuses existing files and output symlinks atomically, avoiding a check-then-overwrite race. `write_all` and `sync_all` errors fail the command. This is not a promise of transactional file contents or parent-directory durability after a crash. |
| RPC dispatch / authentication | Both methods accept exactly one descriptor string, derive the network from `node_chain_id`, and call the same `public_request` inspect action. The methods are included in the known-method set and use existing read-auth/rate/body handling. They do not use storage, key sessions, wallet imports or chain scans; tests cover storage-read counts and the read-auth router. |
| Independent Python / vectors | The Python codec builds policy/tree bytes independently and uses the pre-existing independent address implementation. The differential adapter compares full accepted results and rejection verdicts, checks pinned request/response hashes, and separately counts generated requests. This is finite descriptor coverage, not full consensus equivalence or 10^7 cases. |
| Fuzz target / CI wiring | `descriptor_json` calls the real raw request parser and shared API, then checks inspection, network rejection and pool round trips. Twelve seeds include accept and reject controls. The reusable workflow discovers every Cargo target, so the new target is not omitted by a fixed list. A configured target is not a completed fuzz campaign. |
| Functional test | `wallet_descriptor_restore.py` fixes a checksum/script/address from the independent corpus, verifies CLI and RPC identity, funds the resulting address, and checks observation after public-pool restoration. It does not claim restored signing keys, spending capability, history or a persistent node wallet index. |

The native RPC keeps the pre-existing HTTP body limit and JSON-RPC envelope
policy; the new raw strict descriptor request parser is not represented as a
replacement for the existing RPC envelope parser. No consensus verdict path,
activation height, signing algorithm or derivation algorithm was edited by
the descriptor production commits reviewed here.

## Checks executed by this reviewer

Executed in `/Users/tiagobulhoes/worktrees/gnb-r5-review-paths`, using Python
3.12.15 and Node 22.23.3. No Rust build, node process, full suite or new fuzz
campaign was run by this reviewer; native CGU 173 remained unused.

- `python3 reference/descriptor_test.py -v`: 13 tests passed.
- `python3 reference/descriptor_vectors.py --check`: passed; vectors reproducible.
- `node --test site/tests/wallet-descriptor.test.mjs`: the initial candidate's
  five tests passed; after the two JavaScript follow-up commits, all seven
  tests passed against the actual pinned WASM.
- Three additional manual JavaScript variants used the actual pinned WASM and
  a temporary test wallet session: a non-enumerable own `toJSON` was ignored,
  a direct request-prototype `toJSON` was ignored, and an own enumerable
  `__proto__` data field containing a hook was rejected as unknown. The first
  two returned the expected public address; all three retained the session.
  These checks are supplemental review observations, not committed regression
  tests or mutation-test credit.

## Remaining gates and limits

The coverage/entry-path source review is complete with no additional blocking
finding. Aggregate native/functional results, exact final-head CI, production
reversal evidence, and final served-artifact provenance remain integration gates.
This review does not close inherited findings, establish byte reproducibility
across macOS/Linux, or supply an independent numerical score. The feature is
a static public descriptor/pool foundation, not complete descriptor wallet,
Miniscript, public PQ derivation, hardware-wallet support or chain rescan.
