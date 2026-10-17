# Round 5: public descriptors and public pool restoration

This round implements a bounded, static public descriptor format for the three
existing output forms: single key, threshold/timelock policy and policy tree.
The checksum binds the complete body, including its network. Exact serialized
public-key bytes and existing scripts are preserved. Shared Rust validation
serves the offline CLI, node inspection RPCs and the WASM public operation.

This is a partial delivery of technology item 4.2. It restores public identities
from a portable pool, not private keys, balances, history or a persistent node
wallet index. It adds no wildcard/xpub derivation, hardware-wallet protocol,
hashlock, new policy language or consensus activation. A described tree does
not imply that spending it is activated. PF-4's existing serialized-key identity
semantics remain unchanged.

- [Frozen contract and package ownership](descriptor-contract.md)
- [Format specification](../../DESCRIPTORS.md)
- [Offline CLI, RPC and browser usage](../../DESCRIPTORS-USAGE.md)
- [Integration brief](integration-brief.md) and [live baseline receipt](functional-baseline.json)
- [Core brief](core-brief.md), [reference brief](reference-brief.md)
- [Integrated validation receipt](integrated-validation.json), [live restoration result](functional-final.json)
- [Independent scorecard](scorecard.md) and reviews of [identity](review-verdict.md),
  [entry paths](review-paths.md) and [test strength](review-tests.md)
- [Canonical Linux artifact provenance](wasm-linux-build.json)

The runtime baseline first passes an existing address/balance control and then
fails on the missing descriptor operation. The live-node reproduction is
`wallet_descriptor_restore.py`; the WASM host and frontend packages keep their
own baseline and production-reversal evidence. Failed fixture/setup attempts
are recorded separately and are not credited as reproductions.

The independent Python implementation produces frozen cases and a separate
seeded generated campaign. CI compares complete accepted responses and rejection
verdicts with the Rust JSONL oracle. A new libFuzzer target checks the public JSON
entry point, pool round trips and network separation. This does not establish
the requested full-consensus differential coverage or ten million cases.

The prior round's unresolved native/functional observations, cross-host WASM
byte mismatch, broader secret lifetime work, excluded finality/network work and
bridge findings remain open. Component passes do not close their causes.
No implementer assigns a numerical score or claims superiority to Bitcoin Core.
External independent audit and a bug-bounty program remain required before a
relaunch or bridge deployment.

Local integration completed: node 1,790 passed / zero failed / eight ignored;
separate crypto 490 / zero / four; WASM host 13 / zero / zero; canonical Linux
browser artifact 74 / zero / zero. These are executed-test totals, not distinct
functional scenarios. The complete functional run is **14 passed / one failed**
of fifteen: inherited R1-FUNC-1 (`EADDRINUSE` when reconnecting after a partition)
remains open. The new descriptor scenario passed in 5.1 seconds in that run.
The local functional gate is therefore not green. CI on another platform does
not erase this failure, and subsequent passes of other inherited failing tests
do not establish their causes or close those findings.
