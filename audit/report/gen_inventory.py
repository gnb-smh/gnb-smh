#!/usr/bin/env python3
"""Inventory every test module in the repository for the audit report.

    python3 audit/report/gen_inventory.py   # writes audit/report/inputs/test_inventory.json

Counts `#[test]`, `#[tokio::test]` and proptest functions per file (inline
`#[cfg(test)]` modules and integration tests), Python tests, the audit
harness and the audit proof-of-concept tests, and attaches the property
each module checks (from the audit's module-by-module review).
"""
import json
import os
import re

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUT = os.path.join(os.path.dirname(__file__), "inputs", "test_inventory.json")

PURPOSE = {
    # proof of work and difficulty
    "crates/gnb-smh/src/lib.rs": "Keccak step equals SHAKE-256; big-endian target compare; nonce/header sensitivity; log2_n bounds; canonical-parameter assert",
    "crates/gnb-smh/src/difficulty.rs": "Malformed compact bits rejected; round trip; round-down; work monotone; ASERT on-schedule, half-life, monotone fraction, clamps, extreme inputs",
    "crates/gnb-smh/tests/vectors.rs": "7 normative Python vectors with intermediates (cross-implementation)",
    "rust/src/lib.rs": "Duplicate of the gnb-smh unit tests in the standalone crate (the only Rust tests CI runs)",
    "rust/tests/vectors.rs": "Python PoW vectors against the standalone crate",
    "node/src/pow/mod.rs": "Mine then verify; malformed bits; stop flag",
    # consensus
    "node/src/consensus/mod.rs": "GhostDAG basics, tips, error paths (15) and proptests: determinism, parent-order independence, blue-score monotonicity, topological order on DAGs of <= 17 blocks (5)",
    "node/src/consensus/reachability.rs": "Ancestry queries, persistence round trip, delta drain",
    "node/src/reorg.rs": "Column families exist, write-error propagation, depth-cap boundary, batch atomicity",
    "node/src/main.rs": "Address parsing; submission gating (structure, self-mined, deep-reorg tip poisoning, below-finality fork-loser, bits); intra-tx duplicate inputs, minimum fee, template fee inflation; out-of-order same-block spends",
    "node/tests/ghostdag_differential.rs": "Legacy (bounded BFS) vs fast interval-index coloring produce byte-identical GhostdagData",
    "node/tests/ghostdag_replay_snapshot.rs": "Replay of a real Bloch snapshot (all ignored: needs external data)",
    "node/tests/reachability_persistence.rs": "Durable reachability index: reload and rebuild equivalence, migration",
    "node/tests/reorg_hardening.rs": "Reorg aborts and restores on invalid fork blocks; A->B->A byte symmetry; mempool re-injection counts",
    "node/tests/sprint_u1_undo_data.rs": "Undo-record CRUD and encoding",
    "node/tests/sprint_u2_rollback.rs": "rollback_block restores exact prior UTXO state",
    "node/tests/sprint_u3_reorg.rs": "Common-ancestor search, reorg plan shapes, execution",
    "node/tests/sprint_u4_reorg_e2e.rs": "Disposition logic end to end (without transaction validation)",
    "node/tests/sprint_ee_convergence.rs": "Bare GhostDAG converges under different arrival orders",
    "node/tests/sprint_dd_mined_undo.rs": "Locally mined blocks write undo data and can be rolled back",
    "node/tests/dst_harness.rs": "Deterministic-simulation skeleton; equivocation on a bare GhostDAG",
    "node/tests/sprint_gg_pre_ibd_mining.rs": "is_syncing gating of the miner before IBD",
    "node/tests/sprint_y_integrity_chain.rs": "Hash-chained integrity of persisted GhostdagData detects tampering",
    # validation / storage / monetary
    "crates/gnb-crypto/src/core/mod.rs": "Coinbase value (overflow rejected, exact limit, genesis, one output); difficulty and genesis PoW; chain-id sighash separation and cross-chain replay",
    "crates/gnb-crypto/src/core/tokenomics.rs": "Subsidy schedule examples, issuance below cap, minimum fee",
    "crates/gnb-crypto/src/core/carryover.rs": "Bloch Genesis-3 carryover conversion, vout fixes, duplicate and malformed rows (shipped-snapshot test ignored)",
    "crates/gnb-crypto/src/types/heights.rs": "Height newtype arithmetic",
    "crates/gnb-crypto/src/util.rs": "Bounded file reads; atomic 0600 writes",
    "node/src/storage/mod.rs": "Address-history index and snapshot rows (no UTXO/undo atomicity tests)",
    "node/tests/security_audit.rs": "Coinbase value, maturity helper, dust, duplicate-transaction Merkle (CVE-2012-2459), PoW/bits/timestamp checks",
    "node/tests/sprint_v1_quickwins.rs": "Disabled: the whole file is compiled out with #![cfg(any())]",
    "node/tests/sprint_bb_merkle_newtype.rs": "MerkleRoot newtype: serialization invariance and Merkle basics",
    "node/tests/sprint1d_tx_wire.rs": "Transaction wire format round trip",
    "node/tests/sprint1b_storage_migration.rs": "Block storage round trip; corrupt bytes yield errors",
    "node/tests/coherence_block_serde.rs": "Shielded transactions survive the block wire format and are Merkle-bound",
    # crypto
    "crates/gnb-crypto/src/crypto/mod.rs": "Sign/verify round trips, seed determinism, diversified addresses (12); Falcon canonical vs padded encoding, native-FP symbol tripwire, clean seeded KAT (4); KAT module: primitive offsets, legacy/magic ambiguity, strict verifiers, ML-DSA goldens, AND-combiner tamper matrix, hedging, suite isolation, no-panic fuzz loops (19)",
    "crates/gnb-crypto/src/address.rs": "Address format, checksum, length and prefix rejection",
    "crates/pqcrypto-internals/src/lib.rs": "Seeded-RNG scope cleanup on return and unwind, nesting, TLS teardown, determinism, fail-closed abort on RNG failure (runs only outside the workspace)",
    "crates/pqcrypto-internals/tests/vendor_pin.rs": "SHA-256 pins of every vendored PQClean C file and exact file set (cannot run in place)",
    "crates/gnb-crypto/tests/acvp_mldsa.rs": "Official NIST ACVP ML-DSA-65 sigVer cases (15) and keyGen tc26 interoperability",
    "crates/gnb-crypto/tests/falcon_submission.rs": "Official Falcon round-3 verify vectors; hybrid signature with an official Falcon half",
    "node/tests/kat_falcon1024.rs": "Falcon-1024 sizes, round trip, rejection, malformed input",
    "node/tests/kat_mldsa65.rs": "FIPS 204 sizes, seeded golden, rejection, malformed input",
    "node/tests/kat_address.rs": "Self-generated address vectors",
    "node/tests/sighash_security.rs": "Sighash commits to outputs, outpoints and input index (relative comparisons); txid excludes script_sig",
    "node/tests/sprint_b6_hybrid_sig.rs": "Hybrid signature end to end through script_sig; both halves required",
    "node/tests/sprint_s_crypto_sizes.rs": "Hybrid size constants are consistent",
    "node/tests/sprint_t1_seed_determinism.rs": "Seeded key generation is stable and does not leak into later random key generation",
    "node/tests/sprint_k_address_tests.rs": "Strict checksummed address parsing",
    # wallet
    "crates/gnb-crypto/src/wallet/mod.rs": "Seed versions, sign/verify, build_tx change and network (16); legacy keystore KDF bounds, nonce shape, weak passwords, redaction, signed-message domain (14); transaction boundaries, coin-selection inputs, exact decimals, Bloch keystore compatibility (10)",
    "crates/gnb-crypto/src/wallet/encryption.rs": "Keyfile round trips, wrong password, AAD/version tamper, length guards, password policy",
    "crates/gnb-crypto/src/wallet/seed.rs": "BIP39 official vectors, passphrase, V1 pinning",
    "crates/gnb-crypto/src/wallet/disclosure.rs": "Disclosure bundles: tamper, splice, canonical encoding, no secrets",
    "crates/gnb-crypto/src/wallet/client.rs": "RPC client input, HTTP budget, redirect refusal, envelope and id checks (2 tests are tautological)",
    "crates/gnb-crypto/src/wallet/http_rpc.rs": "HTTP framing, slow-drip budget, error redaction",
    "crates/gnb-crypto/src/wallet/cli.rs": "CLI amounts, network, UTXO rows, canonical flags",
    "crates/gnb-crypto/src/hd_wallet/mod.rs": "HD wallet round trip, v1/v2 compatibility, derived-key authentication (17); recovery limits, preflight, import consistency (17)",
    "crates/gnb-wallet-wasm/src/lib.rs": "Create, export, open and pay on the host (not on wasm32)",
    "node/src/bin/gnb-cli.rs": "Send-command input validation",
    # mempool, shielded pool, attestation, ledger
    "node/tests/sprint_n_mempool_tests.rs": "Mempool::add structural checks: duplicate, empty, conflict, oversize, coinbase, removal (no signatures)",
    "node/tests/mempool_index_prop.rs": "Seeded random operation sequences preserve fee-rate index invariants and ordering",
    "crates/coherence-core/src/lib.rs": "Shielded primitives: determinism, Merkle round trips, inflation and forgery, count binding, position guard, nullifier-set order independence, domain separation",
    "crates/coherence-core/tests/known_unsafe_v1_authorization.rs": "Characterises the known CR-01 authorization gap and the duplicate-leaf mitigation",
    "crates/coherence-core/tests/fuzz_robustness.rs": "80,000 random Merkle-path verifications never panic",
    "node/src/coherence/mod.rs": "Shielded pool validate/apply, exact undo, LIFO order, anchor bound, atomic double-spend rejection",
    "node/src/coherence/verifier.rs": "Fail-closed RejectAll verifier, public-value binding, vkey pin, mock-prover refusal",
    "node/tests/coherence_invariants.rs": "Property test over 2,000 random blocks: no double spend, atomicity, consistency (proof check mocked)",
    "node/src/attestation/mod.rs": "Attestation verify() fails closed; nonce, digest, TEE and verity checks",
    "rust/src/ledger.rs": "Ledger v1: FIPS-202 fast path, random SMT operations vs proofs, non-canonical and truncated proofs, limits, wire strictness",
    "rust/tests/ledger_vectors.rs": "Rust vs Python ledger vectors: 6 SMT steps, 3 proofs, 5 valid blocks, 23 single-fault invalid blocks with error codes",
    "reference/test_ledger.py": "Python ledger vectors, random SMT operations, limits, producer-vs-validator differential over 25 random blocks",
    "reference/check_vectors.py": "Python reference reproduces the 7 PoW vectors",
    # networking, sync, RPC
    "node/src/network/mod.rs": "Wire decode bounds, penalties, PEX handling, connection limits",
    "node/src/network/sync_rr.rs": "Directed sync codec bounds, trailing-byte rejection, request limiter, pull-peer selection",
    "node/src/network/pex_validator.rs": "Peer-exchange address validation",
    "node/src/transport/stream.rs": "KyberStream framing and limits",
    "node/src/sync/parent_fetch.rs": "Orphan-parent fetch scheduling, backoff and give-up",
    "node/src/dandelion.rs": "Dandelion stem/fluff logic (module has no callers)",
    "node/src/metrics/mod.rs": "Prometheus metric registration and labels",
    "node/src/analytics/mod.rs": "Chain analytics helpers",
    "node/src/rpc/mod.rs": "RPC handlers, CORS layer, heavy-read gate",
    "node/src/rpc/auth.rs": "API-key validation, constant-time compare, Host/Origin gate, rate limiting, IPv6 /64 aggregation",
    "node/tests/sprint_a1_transport_tests.rs": "ML-DSA handshake and AEAD primitives (the handshake is not used by the live transport)",
    "node/tests/sprint_a2_stream_tests.rs": "KyberStream framing round trip",
    "node/tests/sprint_a2_upgrade_tests.rs": "libp2p upgrade integration (2 tamper tests ignored)",
    "node/tests/sprint_p_pex_tests.rs": "PEX validator, limiter and cap",
    "node/tests/sprint_m_auth_tests.rs": "RPC authentication decisions and rate limits",
    "node/tests/sync_frontier.rs": "Frontier reconciliation unit tests",
    "node/tests/sync_locator.rs": "Block locator construction",
    "node/tests/sync_peer_state.rs": "Per-peer chain-state table (pins the monotonic hints exploited in NET-6)",
    "node/tests/sync_wire.rs": "GetTips/Tips wire frames and shared bounds",
    "node/tests/frontier_sync.rs": "Deterministic simulation of the IBD release gate",
    "node/tests/announce_then_pull.rs": "Live two-swarm directed pull",
    "node/tests/backfill_flood_lab.rs": "Measurement lab for deep-backfill insertion cost (618 s)",
    "node/tests/peer_addr_churn_lab.rs": "Peer-address graylist mechanics (3 live)",
    "node/tests/sprint_ee_transport_convergence.rs": "Live two-node convergence, equivocation and inbound cap",
    "node/tests/wire_decoder_fuzz.rs": "SplitMix-generated inputs (20,000 cases) never panic the block/tx/header decoders",
    "node/tests/wire_roundtrip_props.rs": "Pseudo-random round trips of consensus wire formats (not proptest)",
    "node/tests/parser_corpus_floor.rs": "Replays the node/fuzz seed corpora through the parsers (no coverage-guided fuzzing exists)",
    "crates/libp2p-yamux/src/lib.rs": "Vendored yamux config (runs only outside the workspace)",
    "crates/libp2p-yamux/tests/lockfile_guard.rs": "Exactly one yamux >= 0.13.10 in Cargo.lock (cannot run in place)",
}

AUDIT_PURPOSE = {
    "audit/consistency/tests/compact_core_vectors.rs": "Bitcoin Core bignum_SetCompact and CheckProofOfWork vectors applied to GnB",
    "audit/consistency/tests/compact_differential.rs": "Exhaustive 587,202,560-value decode differential vs Core SetCompact/DeriveTarget; encode vs Core GetCompact and rust-bitcoin (proptest)",
    "audit/consistency/tests/asert_differential.rs": "ASERT vs the aserti3-2d (BCHN) fixed-point step; bounds, monotonicity, half-life, extreme inputs, saturation finding AUD-1",
    "audit/consistency/tests/merkle_consistency.rs": "Merkle root vs rust-bitcoin and Core; CVE-2012-2459 collision; block id excludes signatures",
    "audit/consistency/tests/amount_consistency.rs": "CVE-2010-5139 overflow detection; subsidy schedule within allocation; fee function totality",
    "audit/consistency/tests/pow_reference_differential.rs": "GnB-SMH vs normative Python on 96 random cases; scratchpad reuse; per-thread pad",
    "audit/consistency/tests/pow_check_semantics.rs": "Strict PoW boundary vs Core's <=; verify(); chain work vs Core GetBlockProof",
}


def count_tests(text):
    plain = len(re.findall(r"#\[test\]", text))
    tokio = len(re.findall(r"#\[tokio::test", text))
    blocks = re.findall(r"proptest!\s*\{(.*?)\n\}", text, re.S)
    prop = sum(len(re.findall(r"\bfn\s+\w+\s*\(", b)) for b in blocks)
    tagged = sum(len(re.findall(r"#\[test\]", b)) for b in blocks)
    ignored = len(re.findall(r"#\[ignore", text))
    return plain + tokio + prop - tagged, prop, tokio, ignored


def kind_tags(path, text, prop, tokio):
    tags = []
    if prop or "proptest" in text:
        tags.append("property")
    if tokio:
        tags.append("async")
    if re.search(r"\.json|KAT|ACVP|vectors", text):
        tags.append("vectors")
    if "python3" in text or "reference/" in text:
        tags.append("differential")
    if "corpus" in text:
        tags.append("corpus")
    return ", ".join(tags) or "unit"


def main():
    rows = []
    for dp, dn, fn in os.walk(ROOT):
        dn[:] = [d for d in dn if d not in ("target", ".git", "node_modules")]
        for f in sorted(fn):
            p = os.path.join(dp, f)
            rel = os.path.relpath(p, ROOT)
            if f.endswith(".rs"):
                text = open(p, encoding="utf-8", errors="replace").read()
                is_test_file = "/tests/" in "/" + rel
                if not is_test_file and "#[cfg(test)]" not in text:
                    continue
                total, prop, tokio, ign = count_tests(text)
                if total == 0 and not is_test_file:
                    continue
                if "audit_poc_" in f:
                    kind = "audit-poc"
                elif rel.startswith("audit/"):
                    kind = "audit-harness"
                else:
                    kind = "integration" if is_test_file else "inline"
                purpose = PURPOSE.get(rel) or AUDIT_PURPOSE.get(rel, "")
                if kind == "audit-poc":
                    purpose = "Reviewer proof-of-concept: each passing test demonstrates a finding or confirms a control"
                rows.append(dict(path=rel, kind=kind, tests=total, ignored=ign,
                                 tags=kind_tags(rel, text, prop, tokio), purpose=purpose))
            elif rel.startswith("reference/") and f.endswith(".py") and (f.startswith("test_") or f == "check_vectors.py"):
                text = open(p, encoding="utf-8").read()
                n = len(re.findall(r"^\s*def test_\w+", text, re.M)) or 7
                rows.append(dict(path=rel, kind="python", tests=n, ignored=0, tags="vectors, differential",
                                 purpose=PURPOSE.get(rel, "")))
    rows.sort(key=lambda r: (r["kind"], r["path"]))
    missing = [r["path"] for r in rows if not r["purpose"]]
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=1)
    by = {}
    for r in rows:
        by.setdefault(r["kind"], [0, 0])
        by[r["kind"]][0] += 1
        by[r["kind"]][1] += r["tests"]
    print(by)
    if missing:
        print("no purpose:", missing)


if __name__ == "__main__":
    main()
