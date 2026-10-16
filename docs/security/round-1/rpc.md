# Round 1 RPC package

Base: `7b02dcc`. Branch: `codex/security-r1-rpc`. Isolated worktree:
`gnb-security-r1-rpc`. Both dev and test `codegen-units=19`; two build jobs;
target directory `/private/tmp/gnb-security-target-rpc`.

## Scope and acceptance

Node-local RPC admission and read-only analytics. No consensus verdict,
activation, transaction encoding, wallet, or WASM changes.

| Item | Attack and acceptance criterion |
| --- | --- |
| B1-R2-9 | Repeated oversized wrong API keys, including malformed JSON that never reaches method authorization. Bound measured key-hashing bytes by a source budget applied before hashing/body parsing. Exercise the real router and the public authorization API. |
| B1-R2-10 | IPv4 and its IPv4-mapped IPv6 spelling share one rate budget; different mapped IPv4 clients retain independent budgets. Native IPv6 retains /64 aggregation. |
| B1-R2-11 | `getaddressinfo` with an empty mempool reads at most one stored holder aggregate regardless of confirmed UTXO count. Pending totals visit inputs/outputs without retaining cloned transaction payloads or sorting history. |

## Method

Write and run measured attack regressions against unchanged production code;
record failing output outside the repository. Apply the narrow fixes, run
the regressions and affected suites, then revert only the production edits
and require the same regressions to fail before restoring them. Independent
reviews cover verdict safety, attack coverage and regression strength.

## Evidence

Execution logs and the reversal driver are outside the repository, under
`/private/tmp/gnb-rpc-evidence`. This package assigns no security score.

| Stage | Observed result |
| --- | --- |
| `auth-red.log` | Four new auth regressions failed against unchanged production auth: 830,624 bytes hashed for 100 invalid keys; native/mapped quota duplication; unrelated mapped-source collision; correct-key pre-auth bypass. The self-contained auth module was compiled with `rustc --test`, codegen-units 19 and the exact dependency rlibs built by Cargo. |
| `auth-mapped-peer-red.log` | Independent review added two tests before the mapped-peer fix. Both failed: mapped local/trusted-private proxy peers collapsed clients into the proxy quota, and mapped loopback did not preserve native loopback policy. |
| `red.log` | Full-node Cargo test executed with auth fixes already present but HTTP handler, analytics and pending aggregation unchanged. The router hashed 822,400 bytes and polled 100 body chunks; address info read 512 storage rows for 256 confirmed UTXOs and an empty mempool; pending totals copied 524,928 payload bytes for 32 transactions. These three measured regressions failed. |
| Invalid fixture in `red.log` | The initial aggregate-unavailable test failed its setup assertion because a fresh store already had ready aggregates. This was **not** counted as a security reproduction. |
| `rebuild-red.log` | Corrected fixture used the real `stage_aggregates_incomplete` / `write_batch` path. With analytics production still unchanged, the measured read-bound assertion failed: two reads instead of zero. |
| `green.log` | All 11 focused `r7_` regressions passed. The real router hashed 24,672 bytes and polled only three body chunks; the first three malformed requests still reached JSON parsing and returned HTTP 400, and the remaining 97 returned HTTP 429. |
| `rpc-suite.log` / `rpc-suite-unsandboxed.log` | The sandboxed run passed 130 tests and failed only a local socket bind with `PermissionDenied`. The approved run outside the sandbox passed all 131 RPC tests. No code was changed to accommodate the sandbox. |

The Cargo command is `cargo test --locked -p gnb --lib r7_ -- --nocapture`,
with the environment specified above. The affected suite uses the same
command with filter `rpc::`. Full-node integration, separate `gnb-crypto`
tests, functional tests and remote CI belong to the round integration; the
package does not claim those passed from its focused local tests.

## Implemented bounds and semantics

* `admit_before_auth` uses a separate per-source budget before key hashing
  and body polling, including malformed requests. Its effective rate and
  burst are `max(reads/min, 1) + max(writes/min, 1)`, saturating at `u32::MAX`.
  Named clients of a trusted proxy retain independent quotas; an unknown
  forwarded client shares the proxy-address quota. The existing map cap,
  eviction and shared overflow buckets also bound this new limiter's state.
* Valid proxied keys skip method buckets, but **cannot** bypass the pre-auth
  budget. Exhausting the default 65-token burst refuses every method,
  including `submitblock`; operators must size quotas for combined polling
  and submission traffic. The boundary test proves a block is admitted at
  token 65 and refused at token 66. The direct-loopback rate exemption and
  opt-in authentication trust remain separate; neither turns a forwarded
  client into a trusted caller.
* Mapped IPv4 is canonicalized at source, trust and rate boundaries; native
  IPv6 is grouped by /64 only for rate limits. Mapped loopback still needs
  an API key for protected methods when `trust_loopback_auth=false`.
* `getaddressinfo` uses the atomic holder aggregate: at most one confirmed
  balance read, independent of confirmed UTXO count. During an aggregate
  rebuild it returns the existing not-ready message with zero storage reads.
* Pending totals use O(total inputs + outputs) work, at most one lookup per
  input, constant auxiliary space and zero retained transaction payload
  copies. Full-script address matching, absent lookup/missing UTXO handling
  and checked `u64` sums are preserved. The history API still returns full
  transactions; its positive control checks that the copy probe is live.

Bitcoin Core references are its early `ClientAllowed` / bounded `WorkQueue`
before RPC authentication in
[`httpserver.cpp`](https://github.com/bitcoin/bitcoin/blob/v30.0/src/httpserver.cpp#L275-L316)
and mapped-IPv4 classification in
[`CNetAddr::SetLegacyIPv6`](https://github.com/bitcoin/bitcoin/blob/master/src/netaddress.cpp).
Core does not expose an equivalent arbitrary-address aggregate endpoint;
the holder optimization reuses this node's existing atomic aggregate.

## Review and limitations

Independent reviews identified and prompted the real-body poll probe,
admitted-prefix controls, the explicit operator availability boundary,
mapped proxy-peer normalization and the mapped-loopback authentication
controls. They also identified the initial unavailable-aggregate fixture
error; its corrected failing run is recorded separately above.

The limiter uses `DefaultClock` and continuous refill. The low-quota flood
tests execute below their 20-second refill interval on this host; a runner
paused beyond that interval can replenish tokens. These are measured burst
regressions, not a wall-clock-independent formal proof. No global transaction
verification scheduler or MEM-5 isolation claim is made by this package.

## Production-only reversals

Each reversal changed only the indicated production hunk. Final tests and
their measurement probes stayed in place; the other corrections stayed
enabled. The driver restored the original file bytes in a `finally` block,
then compared SHA-256 digests. All four production files were checked
byte-for-byte against their pre-reversal snapshots after the last case.

| Reversed production hunk | Expected failing regression / measured result | Log |
| --- | --- | --- |
| Public `authorize_request` pre-auth admission | `r7_forwarded_key_hash_work_is_bounded` failed; correct-key and per-client quota controls also failed. | `auth-reverse-auth.log` |
| Mapped-IP canonicalization (helper returns original IP) | `r7_mapped_proxy_peers_preserve_client_budgets` failed; alias, distinct-source and explicit-loopback controls also failed. | `auth-reverse-mapped.log` |
| Early HTTP admission | `r7_rpc_rejects_key_flood_before_body_and_hash_work` failed with 822,400 key bytes hashed and 100 body chunks polled. | `reverse-http.log` |
| Holder lookup/readiness guard (restored confirmed-UTXO scan) | Both `r7_getaddressinfo_*` dispatch regressions failed: 512 reads with ready aggregates; two reads during rebuilding. | `reverse-holder.log` |
| Streaming pending totals (restored history collection) | `r7_pending_balance_does_not_clone_mempool_payloads` failed with 524,928 copied payload bytes. | `reverse-pending.log` |

All five reversal runs exited with test failure (101), not compilation
failure. After restoring the final production bytes, all 11 focused
regressions passed again (`restored-green.log`). No numerical rating or
Bitcoin superiority claim is made by the implementer.
