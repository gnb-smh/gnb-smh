# Round 1 findings ledger

This ledger separates reported concerns from demonstrated failures. No
category is considered resolved because one package passes. The original
request remains the acceptance scope; this first package selection does
not remove its other requirements.

| Item | Status at this checkpoint | Evidence / next requirement |
| --- | --- | --- |
| B1-R2-9, authentication work before admission | Corrected and integrated; final CI pending | Real-router regression: 822,400 to 24,672 key bytes hashed; 100 to three body polls, with admitted-request controls. Public-helper and HTTP production-only reversals fail. |
| B1-R2-10, mapped IPv4 rate buckets | Corrected and integrated; final CI pending | Native/mapped equality, distinct-source, mapped-proxy and loopback authorization controls pass; production-only canonicalization reversal fails. |
| B1-R2-11, address-info cost | Corrected and integrated; final CI pending | Empty-mempool query: 512 confirmed-storage reads to at most one; zero reads during aggregate rebuild. Pending totals retain zero cloned transaction bytes versus 524,928 previously. Both production-only reversals fail. |
| B1-R2-7, PEX limiter | Incomplete; not integrated | Assigned agent was interrupted by automatic review while preparing the package. No resolution claim. |
| R1-TEST-1, process-global activation in unit tests | Corrected in package; final integration CI pending | Exact canonicality red/green, separate integrated crypto 448 passed, three independent static/log reviews. Production consensus is untouched. |
| R1-TEST-2, Miri and signing FFI | Reproduced in base CI; narrow compatibility correction pending validation | Existing test invokes unsupported PQClean FFI under Miri. Native/i686 signing test and Miri ABI count must remain. |
| R1-FUNC-1, restart/reconnect in macOS partition test | Open; two independent diagnoses, no production correction | `feature_partition_heal.py` timed out waiting for node2 to reconnect to node1 after both dials reported `Address already in use` (OS error 48). The existing documented policy for manual addresses without `/p2p/<id>` retries only while no manual connection/dial exists: reconnecting n0 suppresses n1. The fixture and functional documentation require a stronger topology than that contract. TCP cause remains unproven; no consensus-divergence conclusion follows. |
| R1-FUNC-2, partition test's nominal 30-second bound | Open; independent static test-strength finding | `feature_partition_heal.py:82-84` waits for peers using independent 60-second timeouts before `sync_blocks(max(1, remaining))`. A passing run need not prove the claimed absolute 30-second heal bound. Requires a harness regression and a shared deadline; no timing claim is made from the current test. |
| R1-REVIEW-1, router regression admits reject-all behavior | Test controls corrected and executed | First three malformed requests reach JSON parsing (400); the next 97 are refused (429). All 11 focused regressions pass after restoring production. |
| R1-REVIEW-2, body-read ordering unmeasured | Cost measurement added and executed | Body-stream poll counter: 100 before correction, three afterward; HTTP-only reversal again polls 100 and fails. |
| R1-REVIEW-3, mapped proxy identity before source selection | Reproduced, corrected and reviewed in auth package | Two tests failed before mapped-peer normalization; 70 auth tests pass afterward, including protected mapped-loopback credentials. All three final full-package reviews found no blocking issue. |
| R1-REVIEW-4, pre-auth budget and operator availability | Explicit policy change, documented and tested | All remote/proxied requests consume the pre-auth source budget, including valid-key polling and block submission. Default burst/refill is 65/minute; block submission is admitted at token 65 and refused at 66. Operators must size quotas for combined traffic. No MEM-5 resolution claim. |
| PoWit accountability, membership, quorum, finalized-prefix witness set, pin convergence/persistence, state bounds and formal model | Reported requirements; no new reproduction in this round | Automatic review blocked the delegated reproduction task. No production changes or completion claims. |
| B1-R2-1..6, B1-R2-8; versioned verified headers, byte budgets, netgroups, assumevalid and live discouragement | Not re-evaluated by this round | Baseline tests in the scorecard are evidence inventory only. |
| B2-R2-0, PF-4, LED-1, DAG-8, mergeset transaction semantics and B2-R2-3..6 | Not re-evaluated by this round | Require exact reproductions and the consensus activation workflow whenever verdicts change. |
| MEM-5, wanted transaction requests, package relay and CPFP | Not re-evaluated by this round | Shared quotas, reconnect behavior and relay accounting require measured tests. |
| Maintained PQ replacements, constant-time checks, Wycheproof expansion, CRY-4 and CRY-7 | Not re-evaluated by this round | Existing vector tests are recorded, not equivalent to complete migration or side-channel evidence. |
| PF-2, BR-1..6, BR-11, sidechain integrity and multisig exchange format | Not re-evaluated by this round | Wallet test-harness repair does not resolve wallet/bridge design findings. |
| Functional/differential counts, platform matrix, mutation/coverage gates, clippy, unsafe boundaries, fuzz/release/SBOM/vet | Targets not met by available evidence | Source inventory finds 14 functional scenarios and 24 fuzz targets; native platform and release gates remain incomplete. |

The independently calculated supplied-score totals are 6.375 and 9.075;
neither is a newly validated rating. No final security score is assigned
until the evidence supports one. There is no claim that the project's
security exceeds the comparator.
