# Consistency harness

`consistency/` is an independent test harness for the consensus arithmetic,
kept in its own Cargo workspace. It checks GnB-SMH against external oracles:
Bitcoin Core vectors and ports, BCHN aserti3-2d, rust-bitcoin, and the
normative Python references in `reference/`. It covers compact targets, ASERT,
Merkle roots, amounts, PoW and chain work.

```sh
cd audit/consistency && cargo test --release --locked
```

CI runs it in the `audit-harness` job. `consistency/scripts/mutants_vs_harness.py`
re-runs cargo-mutants survivors of `gnb-smh` against the harness.
