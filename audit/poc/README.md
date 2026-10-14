# Audit proof-of-concept tests

Tests written during the 2026-10-14 code audit
(`audit/GnB-SMH-Code-Audit-2026-10-14.pdf`). Each test **passes while the
finding it demonstrates is present**, so they are kept out of the project's
own test directories: adding them there would make the suites fail once the
defects are fixed.

The directory layout mirrors the repository. To run them, copy them into
place and test one crate at a time (testing `gnb-crypto` in the same cargo
invocation as the node enables the node's dev-only `test-pow-limit` feature
in `gnb-crypto`, see finding POW-5):

```sh
cp -r audit/poc/crates audit/poc/node .
cargo test --release --locked -p gnb-smh        --test audit_poc_pow
cargo test --release --locked -p gnb-crypto     --test audit_poc_crypto --test audit_poc_wallet --test audit_poc_pow
cargo test --release --locked -p coherence-core --test audit_poc_coherence
cargo test --release --locked -p gnb --test audit_poc_dag --test audit_poc_mempool \
    --test audit_poc_validation --test audit_poc_net -- --test-threads=1
```

| File | Tests | Findings demonstrated |
| --- | --- | --- |
| `crates/gnb-smh/tests/audit_poc_pow.rs` | 10 | Extra Python vectors, exhaustive pow-limit proof, ASERT bounds, non-canonical bits, 24.27 h free-block threshold, `work()` vs spec (POW-3, POW-6, POW-9) |
| `crates/gnb-crypto/tests/audit_poc_pow.rs` | 5 | PoW on self-declared bits, wire-height overflow, free deep-fork blocks, timestamp rules (NET-2, POW-2, POW-3) |
| `crates/gnb-crypto/tests/audit_poc_crypto.rs` | 11 | Witness malleation under one block id, separable suites, silent Falcon failure, network-blind checksum; controls for the AND combiner, replay protection, sighash encoder, seeded RNG scope, Falcon clean tripwire (CRY-1, CRY-2, CRY-5, CRY-7) |
| `crates/gnb-crypto/tests/audit_poc_wallet.rs` | 6 | Signing with lied UTXO values, no fee cap, mnemonic not wiped, keystore network not authenticated, coin selection (WAL-1, CRY-4, CRY-7, WAL-6) |
| `crates/coherence-core/tests/audit_poc_coherence.rs` | 3 | Spend statement without authority, no value bridge, unbound binding signature (COH-1) |
| `node/tests/audit_poc_dag.rs` | 9 | Arrival-order split, >256 tips, blue work, k-cluster violation, restart tips, reorg-cap divergence, height mismatch, stale conflicting tx, DAG insertion timings (DAG-1..DAG-9) |
| `node/tests/audit_poc_validation.rs` | 11 | Split from tip-state validation, BIP30, same-block coinbase spend, crash atomicity, template poisoning, witness malleation, PoW before bits, size limits; includes a verbatim copy of `accept_block` guarded line by line against `node/src/main.rs` (DAG-1, VAL-2, VAL-3, DAG-11, MEM-1..3, CRY-1, NET-2, VAL-12) |
| `node/tests/audit_poc_mempool.rs` | 5 | Oversized template, dust template, stale conflict, large-tx poisoning, quadratic sighash cost (MEM-1, MEM-2, MEM-3, MEM-5) |
| `node/tests/audit_poc_net.rs` | 13 | Height overflow panic, trailing-byte dedup bypass, free invalid PoW, orphan admission, map saturation, pull-peer capture, frontier blow-up, metric labels, live relay/IBD/rate-limit penalties (POW-2, NET-2..NET-13) |
