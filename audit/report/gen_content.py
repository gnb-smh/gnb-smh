#!/usr/bin/env python3
"""Write the narrative, scorecard, component, metrics and test-run data files.

    python3 audit/report/gen_content.py

All numbers here were produced during the audit (see Appendix C for the
commands). Standard library only.
"""
import json
import os

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "inputs")


def dump(name, obj):
    with open(os.path.join(DATA, name), "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=1, ensure_ascii=False)


GNB_COMMIT = "125e9e51d09347f474ddc17fc862d66de69498f6"
BTC_COMMIT = "f13ae519de94394314cd63a27924b0998ac65d45"

# ── Scorecard ────────────────────────────────────────────────────────────────
CATS = [
    dict(name="Consensus correctness and cross-node determinism", weight=25, gnb=2.0, btc=9.5,
         why="GnB: PoW, compact targets and ASERT are exact and deterministic (exhaustive and differential evidence), but blocks are validated against the local tip (DAG-1), coinbase uniqueness and same-block maturity are missing (VAL-2, VAL-3) and the reorg cap is node-local (DAG-6), so honest nodes can split permanently. Core: connect-time validation in parent context, BIP30/34, no local reorg cap; mainnet timewarp mitigation (BIP-94) is still limited to testnet4/regtest."),
    dict(name="Network and RPC DoS resistance", weight=20, gnb=1.5, btc=8.5,
         why="GnB: one frame panics the processor (POW-2); gossip is relayed before validation and the ~0.8 s PoW runs on self-declared bits (NET-2); orphan pool and deep forks are nearly free (POW-3, POW-4); honest peers are penalised (NET-4, NET-5). Decoders are well bounded and RPC binds to loopback. Core: validation before relay, cheap PoW first, headers presync, misbehaviour scoring, addrman, per-peer download limits."),
    dict(name="Block and transaction validation, monetary integrity", weight=10, gnb=5.0, btc=9.5,
         why="GnB: checked arithmetic everywhere, CVE-2010-5139, CVE-2012-2459 and CVE-2018-17144 classes covered, coinbase value and carryover verified; same-block coinbase spend, no witness commitment, no MoneyRange, size rules split across encodings. Core: CheckTransaction/CheckTxInputs/ConnectBlock with MoneyRange, mutation detection and witness commitment."),
    dict(name="Mempool and block-production liveness", weight=10, gnb=1.5, btc=9.0,
         why="GnB: one dust transaction or ~116 ordinary ones make every template invalid (MEM-1, MEM-2); conflicts never leave the pool (MEM-3); template parents can exceed MAX_PARENTS (DAG-2). Core: standardness before script checks, removeConflicts/removeForReorg/Expire, weight-bounded templates checked with TestBlockValidity."),
    dict(name="Cryptographic implementation", weight=10, gnb=6.5, btc=9.0,
         why="GnB: hybrid ML-DSA-65 AND Falcon-1024 with exact-length parsing, constant-time clean Falcon, fail-closed RNG, chain-id sighash, official ACVP and round-3 vectors; but consensus accepts witness malleation, suites are separable, sighash has no amount commitment and secrets are not zeroized. Core: libsecp256k1 with exhaustive and constant-time tests, strict encodings, BIP143/341 sighash, secure allocator. Post-quantum readiness is noted but not scored (it depends on assumptions about future adversaries, not on code)."),
    dict(name="Test depth and consistency testing", weight=10, gnb=4.0, btc=9.5,
         why="GnB: ~900 tests incl. proptests, KAT/ACVP vectors and Python differentials, all passing; but the state layer and the binary-only message processor are untested, a test file is compiled out, the real ASERT path is disabled by feature unification, and 37 mutants survive in gnb-smh. Core: 900 unit cases, 285 functional scripts, data-driven vectors (tx_valid/invalid, sighash, script_tests)."),
    dict(name="Defensive coding, memory and arithmetic safety", weight=5, gnb=6.0, btc=8.5,
         why="GnB: memory-safe Rust, #![forbid(unsafe_code)] in consensus crates, 3 unsafe sites in production (FFI), overflow-checks in release; but reachable overflow panics, swallowed write errors and no acceptance lock. Core: C++ mitigated by sanitizers, 1,696 thread-safety annotations, Assert/Assume/CHECK_NONFATAL discipline."),
    dict(name="Fuzzing, CI, release engineering and supply chain", weight=5, gnb=1.0, btc=9.5,
         why="GnB: CI never compiles the workspace; no fuzz harness (corpora only); deny.toml fails its own policy; reachable advisories ignored; vendored guards cannot run. Core: 26 CI configurations (ASan/UBSan/integer, MSan, TSan, valgrind, fuzz, tidy, cross-arch), 206 fuzz targets, lint suite."),
    dict(name="Wallet and key management", weight=5, gnb=5.5, btc=8.0,
         why="GnB: Argon2id 256 MiB and AES-256-GCM with authenticated parameters, 0600 atomic files, strict wallet CSP; but signers trust API-supplied values without a fee cap, the web origin link is plaintext, explorer pages lack CSP and escaping. Core: values from own chain state, amount-committing sighash, -maxtxfee, waste-based coin selection, secure allocator (weaker, GPU-friendly KDF)."),
]


def weighted(key):
    return round(sum(c[key] * c["weight"] for c in CATS) / 100.0, 2)


SCORE = dict(
    categories=CATS,
    gnb_total=weighted("gnb"),
    btc_total=weighted("btc"),
    total_note="Weighted mean of the category scores. Each category score is the lead auditor's calibration of the reviewers' 0-10 component scores against the findings and positive controls in this report.",
)

# ── Components (GnB vs Bitcoin Core) ─────────────────────────────────────────
COMPONENTS = [
    dict(title="7.1 Proof of work and difficulty",
         rows=[
             ["Design", "GnB-SMH v1: scrypt-ROMix structure over single-permutation SHAKE-256, 64 MiB, 2^20 dependent Keccak-f[1600] calls; ASERT (aserti3-2d construction) anchored at genesis, 2 h half-life, 30 s spacing; pow limit `0x2100ffff`", "SHA-256d; 2016-block retarget clamped to x4; pow limit with 32 spare bits; `PermittedDifficultyTransition`"],
             ["Verified correct", "Compact codec identical to Core on all 587,202,560 decodable-exponent values; ASERT bit-identical to the aserti3-2d fixed-point step on more than 350,000 cases; Rust = Python reference on 103 inputs; strict `out < target`; timestamps >= latest parent and <= now + 600 s bound easing to 5.96% and exclude timewarp", "`DeriveTarget`/`CheckProofOfWorkImpl`; MTP rule; BIP-94 timewarp fix only on testnet4/regtest"],
             ["Weaknesses", "PoW runs on self-declared bits before cheap checks (NET-2); free blocks on deep forks (POW-3); work() differs from spec (POW-6); latent ASERT saturation for high anchors (AUD-1); difficulty tests masked by `test-pow-limit` (POW-5)", "Mainnet timewarp still possible in consensus"],
             ["Tests", "gnb-smh 14 unit + 1 vector test, 7 Python vectors, 3 node pow tests; mutation score 82.6% (176/213)", "pow_tests.cpp (15 cases), arith_uint256_tests.cpp, headers_sync_chainwork_tests.cpp; fuzz `pow`, `pow_transition`, `headers_sync_state`, `p2p_headers_presync`; feature_minchainwork.py, mining_basic.py"],
             ["Score (GnB / Core)", "6 correctness, 3 defensive, 3 tests", "9 / 9 / 9"],
         ]),
    dict(title="7.2 Chain selection, GhostDAG and reorganisation",
         rows=[
             ["Design", "GhostDAG k = 10 with reachability index; selected-parent chain applied to the UTXO set; `MAX_REORG_DEPTH` = 1,000 and a local finality height", "Longest most-work chain; `ActivateBestChain`, `ConnectTip`/`DisconnectTip`; no reorg-depth limit"],
             ["Verified correct", "Deterministic, parent-order-independent tie-breaks (proptests); atomic reorg WriteBatch with re-validation; integrity hash chain checked at boot; reachability self-check against brute force", "`CheckBlockIndex` invariants; `InvalidateBlock`/`PreciousBlock`; `m_chainstate_mutex` + `cs_main`"],
             ["Weaknesses", "Validation against the local tip splits honest nodes (DAG-1); blue work ignores merged blues and merged blocks never reach the ledger (DAG-3); k-cluster violation (DAG-4); node-local reorg cap (DAG-6); unbounded per-block cost (DAG-7); no acceptance lock (DAG-10); non-atomic extension commit (DAG-11)", "None material at the code level reviewed"],
             ["Tests", "~120 tests incl. 5 proptests; convergence tests bypass state validation; differential compares two implementations with the same bug", "validation_chainstatemanager_tests.cpp (12), validation_block_tests.cpp (10-thread ordering); fuzz `block_index_tree`, `chain`, `connect_block`; feature_block.py, rpc_invalidateblock.py, feature_chain_tiebreaks.py"],
             ["Score (GnB / Core)", "2 / 4 / 4", "9 / 9 / 9"],
         ],
         note="GHOSTDAG adds coloring, reachability reindexing, mergesets and multi-parent templates. Kaspa bounds that surface with mergeset-size, parent-count, merge-depth and finality-point rules; GnB has none of them and, because merged blue work is not counted, gains none of the DAG's security benefit. The complexity is therefore scored as attack surface."),
    dict(title="7.3 Block and transaction validation, UTXO set and storage",
         rows=[
             ["Design", "UTXO model; txid excludes script_sig; Merkle over txids (Bitcoin construction); RocksDB column families; undo records", "UTXO model with segwit witness commitment; LevelDB coins view with head-block markers"],
             ["Verified correct", "Checked sums (inputs, outputs, fees, subsidy + fees); unconditional duplicate-input check; same-block later-output spends blocked; duplicate-tx rule; one coinbase at index 0 with one output <= subsidy + fees; carryover snapshot verified (SHA3, 452,726 rows, 99,999,999,789,793 sat)", "MoneyRange; BIP30/34; `IsBlockMutated`; `DisconnectBlock` with unclean handling; `ReplayBlocks`"],
             ["Weaknesses", "No BIP30/34 (VAL-2); same-block coinbase spend (VAL-3); witness malleation (CRY-1); non-atomic commit (DAG-11); size rules split (VAL-12); no 64-byte-tx rule (VAL-10)", "Historical: CVE-2010-5139, CVE-2012-2459, CVE-2018-17144 (all fixed)"],
             ["Tests", "~110 targeted single-node regressions; sprint_v1_quickwins.rs compiled out; shipped-snapshot test ignored; no crash or fork-context tests", "transaction_tests (16), coins_tests (15); tx_valid.json and tx_invalid.json; fuzz `transaction`, `block`, `coins_view`, `connect_block`, `utxo_total_supply`; feature_block.py, feature_dbcrash.py, p2p_mutated_blocks.py"],
             ["Score (GnB / Core)", "2 / 5 / 3", "9 / 9 / 10"],
         ]),
    dict(title="7.4 Signatures, sighash and addresses",
         rows=[
             ["Design", "Hybrid ML-DSA-65 AND Falcon-1024 (`clean` integer variant), 4-byte suite envelope; SHA3 sighash with 16-byte domain, version and chain id; 160-bit address hash with 4-byte SHA3d checksum", "ECDSA/Schnorr on secp256k1; legacy, BIP143 and BIP341 sighash; bech32/bech32m"],
             ["Verified correct", "AND semantics with exact-length parsing; strict ML-DSA hint and Falcon compact decoding; fail-closed RNG, no C fallback; seeded RNG scoped to key generation; official ACVP and round-3 vectors", "Strict DER, low-S, NULLFAIL; sign-then-verify; secure allocator; exhaustive and constant-time library tests"],
             ["Weaknesses", "Lenient consensus verifier and no witness commitment (CRY-1); separable suites (CRY-2); no amount commitment, library-defined preimage (CRY-3); no zeroization (CRY-4); unchecked Falcon signer (CRY-5); network-blind checksum (CRY-7)", "Classical-only signatures (threat-model difference, not scored)"],
             ["Tests", "~140 tests; 15 ACVP sigVer cases; 3 Falcon round-3 vectors; no pinned sighash vectors", "sighash.json (500 vectors), script_tests.json (1,258); fuzz `signature_checker`, `script_interpreter`, `key`, `sighash_cache`"],
             ["Score (GnB / Core)", "7 / 6 / 4", "9 / 9 / 9"],
         ]),
    dict(title="7.5 Peer-to-peer networking and synchronisation",
         rows=[
             ["Design", "libp2p gossipsub (signed, strict), directed request-response sync, Kyber768 + Ed25519 transport upgrade, PEX", "Custom P2P with v2 encrypted transport (BIP324), headers-first sync, addrman, compact blocks"],
             ["Verified correct", "Decoders bounded before allocation (`with_limit`, per-field caps); directed sync rejects trailing bytes; handshake capped at 16 KiB; connection limits; SHA-256 message ids", "Validation before relay; `Misbehaving`; headers presync; per-peer in-transit limits; inbound eviction"],
             ["Weaknesses", "Remote panic (POW-2); relay before validation (NET-2); orphan memory (POW-4); misattributed penalties (NET-4, NET-5); IBD latch (NET-6); O(N^2) amplification (NET-7); unbounded maps (NET-8, NET-10); eclipse exposure (NET-11)", "None material at the code level reviewed"],
             ["Tests", "~430 tests incl. live swarms; no proptest, no coverage-guided fuzzing; message processor (main.rs) untested", "63 p2p_*.py functional tests; fuzz `process_message`, `process_messages`, `addrman`, `connman`, `net`, `p2p_transport_serialization`, `bip324_cipher_roundtrip`"],
             ["Score (GnB / Core)", "2 / 5 / 4", "8 / 9 / 9"],
         ]),
    dict(title="7.6 RPC, explorer and web front end",
         rows=[
             ["Design", "axum JSON-RPC on loopback with API key, rate limits and CORS; Python explorer API; Cloudflare Worker proxy; browser wallet (WASM)", "libevent HTTP RPC with cookie or rpcauth; no explorer or browser wallet"],
             ["Verified correct", "Loopback default; key validation and constant-time compare; Host/Origin gate; body, concurrency and timeout caps; wallet CSP, COOP, frame-ancestors", "Cookie file permissions, HMAC rpcauth, 250 ms auth-failure delay, work-queue limits"],
             ["Weaknesses", "Plaintext origin link with shared secret (WAL-2); explorer XSS sinks without CSP (WAL-3); API slowloris (WAL-4); full-chain scans (NET-12); unbounded metric labels (NET-13)", "Not applicable for web surfaces"],
             ["Tests", "auth.rs 54 and sprint_m_auth 18 tests; no HTTP end-to-end, JS, Worker or explorer-API tests", "rpc_bind.py, interface_http.py, rpc_whitelist.py; fuzz `http_request`, `rpc`"],
             ["Score (GnB / Core)", "4 / 6 / 4", "9 / 9 / 9"],
         ]),
    dict(title="7.7 Mempool and block production",
         rows=[
             ["Design", "Fee-rate index with count and byte caps, first-seen, no orphans, no RBF; internal CPU miner and getblocktemplate", "Cluster mempool, RBF, orphanage, package relay; weight-bounded BlockAssembler"],
             ["Verified correct", "O(log n) index with invariant checker; checked sums; spawn_blocking for verification; self-mined blocks go through the full acceptance path (fail-safe)", "Standardness, removeConflicts, removeForReorg, Expire, TrimToSize, TestBlockValidity"],
             ["Weaknesses", "MEM-1, MEM-2 (Critical), MEM-3, MEM-4, MEM-5 (High), MEM-6, MEM-7", "None material at the code level reviewed"],
             ["Tests", "14 tests on the data structure only; gossip admission untested", "mempool_tests, miner_tests; fuzz `tx_pool`, `tx_pool_standard`, `tx_package_eval`, `rbf`, `package_rbf`, `txorphan`; 20 mempool_*.py"],
             ["Score (GnB / Core)", "3 / 4 / 3", "9 / 9 / 10"],
         ]),
    dict(title="7.8 Wallet and key management",
         rows=[
             ["Design", "Hybrid PQ keys per index derived with SHA3; Argon2id + AES-256-GCM keystores; CLI, light wallet, WASM browser wallet", "Descriptor wallets, BIP32, SQLite; SHA-512-iterated KDF + AES-256-CBC"],
             ["Verified correct", "Argon2id 256 MiB t=4 p=4, bounded untrusted KDF parameters, fresh nonces, authenticated v1 keyfiles, 0600 atomic writes, BIP39 vectors, prior audit findings CR-05/06/07/10 fixed", "Values from own chain state, -maxtxfee, waste-based selection (BnB, CoinGrinder, knapsack, SRD)"],
             ["Weaknesses", "WAL-1, WAL-2 (High); WAL-3, WAL-4; WAL-5, WAL-6, CRY-4, CRY-7", "KDF is not memory-hard"],
             ["Tests", "~153 Rust tests; no JS, Worker, Python or wasm32-target tests", "83 wallet unit cases; 13 wallet fuzz targets (`crypter`, `coinselection_*`, `coin_grinder`, `scriptpubkeyman`, `wallet_create_transaction`, ...); 68 wallet_*.py"],
             ["Score (GnB / Core)", "6 / 7 / 5", "7 / 8 / 9"],
         ]),
    dict(title="7.9 Shielded pool, attestation and ledger v1 (inactive in consensus)",
         rows=[
             ["Status", "Shielded spends rejected (`RejectAll`); attestation not used for trust; ledger v1 is a research prototype outside the node", "No equivalents"],
             ["Findings", "COH-1 (Critical if enabled), COH-2 (latent), LED-1 (sound SMT; open items), ATT-1", "-"],
             ["Tests", "coherence 43 tests (proofs mocked); ledger 12 Rust + 11 Python tests with 28 single-fault vectors", "-"],
         ]),
    dict(title="7.10 Build, CI and supply chain",
         rows=[
             ["CI", "Python reference + standalone `rust/` crate only; no workspace build, clippy, deny, audit, fuzz, sanitizer or Miri job", "26 CI configurations, lint suite, fuzzing with sanitizers, previous-release compatibility"],
             ["Dependencies", "cargo-audit: 11 advisories (5 not compiled, 6 reachable); deny.toml stale and failing; PQClean crates unmaintained upstream; dead blst/secp256k1 deps", "Few vendored subtrees (secp256k1, leveldb, crc32c, minisketch) with guix reproducible builds"],
             ["Positive", "Pinned toolchain, exact PQ crate pins, vendored-source hash pins, yamux advisory fork with lockfile guard (both guards pass when run in isolation)", "-"],
             ["Score (GnB / Core)", "1", "10"],
         ]),
]

# ── Metrics ──────────────────────────────────────────────────────────────────
METRICS = dict(
    size=dict(
        headers=["Code base", "Code lines", "Comment lines", "Files", "Notes"],
        w=["30%", "12%", "12%", "8%", "38%"],
        rows=[
            ["GnB `node/src`", "15,882", "6,688", "36", "Full node, RPC, P2P, sync, storage; includes inline tests"],
            ["GnB `crates/gnb-crypto/src`", "9,170", "2,410", "19", "Consensus types, signatures, wallet"],
            ["GnB `crates/gnb-smh/src`", "652", "118", "3", "PoW and difficulty"],
            ["GnB `crates/coherence-core/src`", "549", "202", "1", "Shielded-pool primitives (inactive)"],
            ["GnB `crates/gnb-wallet-wasm/src`", "188", "27", "1", "Browser wallet core"],
            ["GnB vendored Rust (`pqcrypto-internals`, `libp2p-yamux`)", "623", "331", "2", "Plus vendored PQClean C sources"],
            ["GnB `rust/` standalone reference", "1,270", "126", "3", "PoW + ledger v1 prototype"],
            ["GnB integration tests (`*/tests`)", "8,769", "2,552", "56", "Excluding audit proof-of-concept files"],
            ["GnB Python reference", "1,465", "-", "8", "Normative PoW and ledger definitions"],
            ["GnB production vs test lines (all Rust)", "19,013 / 18,181", "-", "-", "Non-blank, non-comment; inline `#[cfg(test)]` counted as test"],
            ["Bitcoin Core `src` (excl. tests, bench, qt, vendored)", "138,245", "37,026", "674", "C++"],
            ["Bitcoin Core `src/test` (unit, fuzz, util)", "62,572", "10,499", "326", "of which fuzz 20,399 lines in 152 files"],
            ["Bitcoin Core `src/wallet/test`", "5,004", "821", "31", ""],
            ["Bitcoin Core `test/functional`", "73,085", "-", "331", "Python, 285 test scripts"],
            ["Bitcoin Core `src/secp256k1`", "52,819", "9,121", "124", "Vendored subtree with its own exhaustive tests"],
        ]),
    assets=dict(
        headers=["Assurance asset", "GnB-SMH (125e9e5)", "Bitcoin Core (f13ae51)"],
        w=["28%", "36%", "36%"],
        rows=[
            ["Unit and integration tests", "101 modules, ~900 test functions (884 Rust, 18 Python incl. vectors); 1,040 executions in the workspace run", "900 Boost test cases plus 113 secp256k1 test groups"],
            ["Property-based tests", "5 GhostDAG proptests; seeded random tests (mempool index, SMT, wire round trips)", "Pervasive in fuzz targets; randomized unit tests"],
            ["Coverage-guided fuzzing", "None (5 seed corpora replayed by a stable-Rust test; referenced cargo-fuzz targets do not exist)", "206 fuzz targets (libFuzzer/AFL++/honggfuzz) with external corpora"],
            ["Functional / multi-node tests", "A few live two-swarm tests; no framework", "285 functional test scripts (63 p2p, 20 mempool, 68 wallet)"],
            ["Data-driven vectors", "7 PoW vectors, ledger vectors (28 blocks), 15 ACVP ML-DSA, 3 Falcon round-3, address vectors", "tx_valid/tx_invalid, sighash.json (500), script_tests.json (1,258), key_io, base58, bip341 vectors"],
            ["Sanitizers / dynamic analysis", "None in CI", "ASan+UBSan+integer, MSan, TSan, valgrind, fuzz with sanitizers"],
            ["Static analysis in CI", "None (no clippy, no cargo-deny, no cargo-audit job)", "clang-tidy, IWYU, 15 lint scripts, thread-safety analysis"],
            ["Cross-implementation reference", "Python normative PoW and ledger; no reference for difficulty, GhostDAG or validation", "Consensus is the implementation; extensive vectors"],
            ["Invariant checkers", "Reachability self-check at boot; integrity hash chain; mempool index check", "`CheckBlockIndex`, `CTxMemPool::check`, `-checkblocks`"],
        ]),
    hazards=dict(
        headers=["Indicator (production code, excluding tests)", "GnB-SMH", "Comment"],
        w=["38%", "14%", "48%"],
        rows=[
            ["`unsafe` occurrences", "3", "2 FFI exports in the WASM wallet, 1 FFI randomness override; consensus crates use `#![forbid(unsafe_code)]`"],
            ["`.unwrap()` / `.expect(`", "48 / 54", "Mostly metrics registration, start-up and tests of invariants; no attacker-reachable unwrap found by reviewers"],
            ["`panic!` / `unreachable!` / `todo!`", "3 / 0 / 0", "In the shielded verifier stub"],
            ["Integer `as` casts", "263", "Reviewed on consensus paths; one 32-bit overflow note (CRY-8)"],
            ["`checked_*` / `saturating_*` calls", "120", "Consistent checked arithmetic on value sums"],
            ["Release `overflow-checks`", "on", "Fail-closed on overflow, but turns unchecked arithmetic on peer data into panics (POW-2)"],
            ["Bitcoin Core comparators", "-", "718 `Assert`, 571 `Assume`, 208 `CHECK_NONFATAL`, 2,620 `assert`, 1,696 thread-safety annotations"],
        ]),
    tooling=dict(
        headers=["Tool", "Result"],
        w=["26%", "74%"],
        rows=[
            ["cargo test (workspace, release, locked)", "61 binaries, 1,040 executions passed, 0 failed, 10 ignored (36 min; node module tests run under both the library and binary targets)"],
            ["cargo test (`rust/` standalone)", "18 passed, 0 failed"],
            ["Vendored crates (isolated copies)", "pqcrypto-internals 17 + 2 passed (1 ignored); libp2p-yamux 2 + 2 passed; cannot run in place (AUD-2)"],
            ["Python reference", "check_vectors.py 7/7; test_ledger.py 11/11; ledger vectors regenerate byte-identically"],
            ["Audit consistency harness", "35 tests in 7 modules, all passing (Section 5)"],
            ["Reviewer proof-of-concept tests", "73 tests in 9 files, all passing; each passing test demonstrates its finding"],
            ["cargo-mutants 27.1.0 (gnb-smh)", "222 mutants: 176 caught, 37 missed, 9 unviable (82.6%); the audit harness kills 15 of the 37; the other 22 are equivalent (12) or in non-consensus accessors and Display impls (10)"],
            ["cargo-audit 0.22.2", "11 vulnerabilities: quinn-proto x5 (lockfile only, not compiled), rustls 0.23.45 x4 (reachable), hickory-proto 0.25.2 x2 (reachable, ignored in deny.toml); 6 unmaintained warnings (bincode, paste, pqcrypto-falcon, pqcrypto-mldsa, pqcrypto-kyber, ...). The standalone `rust/` crate: none"],
            ["cargo-deny 0.20.2", "bans ok, sources ok, licenses FAILED (first-party AGPL crates not allowed); 5 unmatched and 2 unnecessary skips; 15 license entries never encountered"],
            ["cargo clippy (workspace, all targets)", "Fails: 1 deny-by-default lint (`absurd_extreme_comparisons` at node/src/consensus/mod.rs:687; the activation constant is 0, so the gate documented as `u64::MAX` is always on) plus 130 warnings before the build stopped (node 91, gnb-crypto 18 in library targets; mostly needless borrows, complex types, redundant closures). Clippy is not run in CI"],
        ]),
)

# ── Narrative ────────────────────────────────────────────────────────────────
COVER = [
    ["Subject", "GnB-SMH (Gödel and Bell): post-quantum proof-of-work BlockDAG, repository `gnb-smh/gnb-smh`"],
    ["Commit audited", f"`{GNB_COMMIT}` (main, 2026-10-10)"],
    ["Comparison baseline", f"Bitcoin Core master `{BTC_COMMIT}` (2026-10-14)"],
    ["Report date", "14 October 2026"],
    ["Scope", "All Rust crates (node, gnb-crypto, gnb-smh, coherence-core, gnb-wallet-wasm, vendored pqcrypto-internals and libp2p-yamux), the standalone `rust/` crate, Python references, web wallet, explorer, Worker, deployment scripts and CI"],
    ["Method", "Line-by-line manual review in seven areas; execution of every test suite; independent consistency harness against Bitcoin Core, BCHN and rust-bitcoin oracles; mutation testing; dependency audit"],
    ["Explicitly excluded", "Hashrate, adoption, market, decentralisation and any property that depends on network participation"],
    ["Toolchain", "rustc 1.94.1; cargo-audit 0.22.2 (RustSec DB 2026-10-14); cargo-deny 0.20.2; cargo-mutants 27.1.0; proptest 1.11; rust-bitcoin 0.32; Python 3.13"],
    ["Prepared with", "Claude Code (AI-assisted code audit). Findings are code observations with file:line evidence; they are not a guarantee of absence of other defects."],
]

SECTIONS = [
    ["exec", "1. Executive summary"],
    ["scope", "2. Scope, methodology and limitations"],
    ["inventory", "3. System overview and code inventory"],
    ["results", "4. Test execution and tooling results"],
    ["harness", "5. Independent consistency harness"],
    ["findings", "6. Findings"],
    ["components", "7. Component comparison with Bitcoin Core"],
    ["bugclasses", "8. Historical Bitcoin bug classes applied to GnB"],
    ["scorecard", "9. Comparative security scorecard"],
    ["roadmap", "10. Remediation roadmap"],
    ["appA", "Appendix A. GnB test-module inventory"],
    ["appB", "Appendix B. Bitcoin Core security and consistency test modules referenced"],
    ["appC", "Appendix C. Reproduction commands"],
]

BUGCLASS_ROWS = [
    ["Value overflow (CVE-2010-5139)", "`MoneyRange` in CheckTransaction/CheckTxInputs/ConnectBlock", "`checked_add` on inputs, outputs, fees, subsidy + fees (main.rs:2065,2723,2752; core:957); harness confirms detection", "Protected (no MoneyRange, VAL-11)"],
    ["Duplicate inputs (CVE-2018-17144)", "tx_check.cpp duplicate-input set", "Unconditional per-transaction set (main.rs:2704-2716); reorg path re-checks", "Protected"],
    ["Merkle duplicate tail (CVE-2012-2459)", "`ComputeMerkleRoot(&mutated)`, BLOCK_MUTATED, no invalid caching", "Same tree (harness: identical to rust-bitcoin); `validate_no_duplicate_txs`; no invalid-id cache", "Protected"],
    ["64-byte transaction ambiguity", "`IsBlockMutated` rejects 64-byte txs", "None (VAL-10)", "Partial (light clients)"],
    ["Witness / signature malleation", "Strict DER, low-S, NULLFAIL; witness commitment", "txid excludes script_sig but no witness commitment; lenient verifier (CRY-1)", "Exposed"],
    ["Duplicate coinbase (BIP30/BIP34)", "BIP30 checks and BIP34 height", "None (VAL-2)", "Exposed"],
    ["Coinbase maturity", "`CheckTxInputs` for every spend", "Bypassed for same-block spends (VAL-3); gossip uses DAG count (MEM-4)", "Exposed"],
    ["Timewarp", "BIP-94 on testnet4/regtest only (mainnet still exposed)", "Absolute ASERT, timestamps >= latest parent and <= now + 600 s", "Protected (better than Core mainnet)"],
    ["Compact target negative/overflow encodings", "`DeriveTarget` flags", "Identical accept set (exhaustive 587 M-value differential)", "Protected"],
    ["Low-difficulty header/block spam", "Headers presync, MinimumChainWork, anti-DoS threshold", "PoW on self-declared bits, orphan pool, free deep forks (NET-2, POW-3, POW-4)", "Exposed"],
    ["Consensus depending on a serialization library (cf. 2013 BDB fork)", "Hand-specified serialization", "Sighash body is bincode 2 serde output (CRY-3); block size measured in bincode (VAL-12)", "Partial"],
    ["Remote crash from peer data", "Fuzzed message processing, checked arithmetic", "Overflow panic on wire height (POW-2)", "Exposed"],
    ["Orphan / memory exhaustion (cf. CVE-2018-17145)", "Bounded orphanage, per-peer limits", "10,000 x ~1 MB orphan blocks admitted on self-declared bits (POW-4)", "Exposed"],
    ["Crash consistency of chainstate", "DB_HEAD_BLOCKS marker + ReplayBlocks", "Extension commit non-atomic, errors ignored (DAG-11)", "Exposed"],
    ["Eclipse attacks", "addrman buckets, anchors, feelers, eviction", "Arbitrary eviction, unsolicited dials (NET-11)", "Exposed"],
]

ROADMAP = [
    ["Phase 0: before any value is at stake", "POW-2 (checked arithmetic on peer integers, drop wire height); NET-2 (validate before relay, cheap checks before PoW, peer penalties); MEM-1 and MEM-2 (shared standardness, byte-budgeted and self-checked templates); DAG-1 (accept with stateless/contextual checks, validate transactions on connect)"],
    ["Phase 1: consensus and liveness", "VAL-2, VAL-3 (coinbase uniqueness and same-block maturity in one shared rule set); DAG-6, DAG-3, DAG-4 (objective finality, blue work over mergeset blues, exact GHOSTDAG); MEM-3, MEM-4, MEM-5; POW-3, POW-4, DAG-2, DAG-7 (anti-DoS work threshold, bounded parents and mergesets, no orphan admission on self-declared bits); DAG-10, DAG-11 (acceptance lock, one WriteBatch per block); NET-4 to NET-7"],
    ["Phase 2: assurance", "CI that builds and tests the workspace with and without `test-pow-limit`, clippy -D warnings, cargo-deny, cargo-audit; cargo-fuzz targets for every wire decoder, `NewBlock`/`NewTransaction` handling, compact/ASERT, mempool and GhostDAG insertion; a multi-node functional test framework (two nodes, conflicting siblings, reorgs, crash restarts); adopt `audit/consistency` in CI; pin sighash, ASERT and work vectors in the Python reference; re-enable `sprint_v1_quickwins.rs`"],
    ["Phase 3: protocol hardening (hard fork)", "Witness commitment and canonical witnesses (CRY-1); sighash v3 committing to spent amounts and scripts with a specified byte layout (CRY-3, WAL-1); suite binding (CRY-2); tagged Merkle hashing (VAL-10); network-binding address checksum (CRY-7); lower pow limit (POW-3); fix `work()` to the specification (POW-6)"],
    ["Web and operations", "TLS or authenticated tunnel to the explorer origin, fixed cache TTLs, HSTS (WAL-2); site-wide CSP and escaping (WAL-3); API timeouts and firewalling (WAL-4); pinned reproducible WASM (WAL-5); wallet fee ceilings (WAL-1); systemd sandboxing (OPS-3)"],
]

APPB = [
    ["Unit tests (src/test)", "pow_tests.cpp (15 cases), arith_uint256_tests.cpp (`bignum_SetCompact`), headers_sync_chainwork_tests.cpp, merkle_tests.cpp, sighash_tests.cpp + data/sighash.json, script_tests.cpp + data/script_tests.json, transaction_tests.cpp (16) + data/tx_valid.json, data/tx_invalid.json, coins_tests.cpp (15), validation_block_tests.cpp, validation_chainstatemanager_tests.cpp (12), blockchain_tests.cpp, txvalidationcache_tests.cpp, mempool_tests.cpp, miner_tests.cpp, denialofservice_tests.cpp, addrman_tests.cpp, net_tests.cpp, key_tests.cpp"],
    ["Wallet unit tests (src/wallet/test)", "coinselector_tests.cpp and 17 further files (83 cases)"],
    ["Fuzz targets (src/test/fuzz, 206 in total)", "`pow`, `pow_transition`, `headers_sync_state`, `p2p_headers_presync`, `process_message`, `process_messages`, `addrman`, `connman`, `net`, `node_eviction`, `p2p_transport_serialization`, `bip324_cipher_roundtrip`, `block`, `block_header`, `block_index`, `block_index_tree`, `chain`, `connect_block`, `coins_view`, `coinscache_sim`, `utxo_total_supply`, `utxo_snapshot`, `transaction`, `decode_tx`, `merkle`, `tx_pool`, `tx_pool_standard`, `tx_package_eval`, `ephemeral_package_eval`, `rbf`, `package_rbf`, `txorphan`, `txorphan_protected`, `txorphanage_sim`, `signature_checker`, `script_interpreter`, `sighash_cache`, `key`, `crypter`, `coinselection_bnb`, `coinselection_knapsack`, `coinselection_srd`, `coin_grinder`, `scriptpubkeyman`, `wallet_create_transaction`, `http_request`, `rpc`, `addition_overflow`, `multiplication_overflow`"],
    ["Functional tests (test/functional, 285 scripts)", "feature_block.py, feature_minchainwork.py, feature_dbcrash.py, feature_chain_tiebreaks.py, feature_assumeutxo.py, mining_basic.py, p2p_invalid_block.py, p2p_invalid_tx.py, p2p_invalid_messages.py, p2p_unrequested_blocks.py, p2p_headers_sync_with_minchainwork.py, p2p_mutated_blocks.py, p2p_ibd_stalling.py, p2p_addr_relay.py, p2p_eviction.py, p2p_orphan_handling.py, mempool_reorg.py, mempool_expiry.py, mempool_limit.py, mempool_spend_coinbase.py, mempool_dust.py, rpc_invalidateblock.py, rpc_bind.py, interface_http.py, and 68 wallet_*.py"],
    ["CI configurations (ci/test)", "00_setup_env_native_asan.sh (address, integer, undefined, float-divide-by-zero), _msan, _tsan, _valgrind, _fuzz, _fuzz_with_msan, _fuzz_with_valgrind, _tidy, _iwyu, _previous_releases, _nowallet, _alpine_musl, _chimera_lto, arm, s390x (big-endian), i686, riscv, win64, macOS, FreeBSD/NetBSD/OpenBSD cross"],
    ["Static analysis and lint", "src/.clang-tidy (bugprone, performance, modernize, misc-no-recursion), test/lint (15 scripts: circular dependencies, includes, locale, shell, python, docs, subtrees)"],
    ["secp256k1 subtree", "tests.c (113 test groups), tests_exhaustive.c, ctime_tests.c (constant-time checks under valgrind)"],
]

APPC = [
    ["GnB workspace tests", "`cargo test --release --locked --workspace --lib --bins --test <each tracked test> --no-fail-fast`"],
    ["Standalone crate", "`cd rust && cargo test --release --locked`"],
    ["Python reference", "`python3 reference/check_vectors.py && python3 reference/test_ledger.py && python3 reference/gen_ledger_vectors.py && git diff --exit-code reference/ledger_vectors.json`"],
    ["Consistency harness", "`cd audit/consistency && cargo test --release -- --nocapture`"],
    ["Mutation testing", "`cargo mutants -p gnb-smh --file crates/gnb-smh/src/difficulty.rs --file crates/gnb-smh/src/lib.rs --output OUT`, then `python3 audit/consistency/scripts/mutants_vs_harness.py OUT/mutants.out WORKDIR`"],
    ["Proof-of-concept tests", "Copy `audit/poc/<crate>/tests/*.rs` into the matching crate's `tests/` directory, then `cargo test --release --locked -p <crate> --test <name>` (see audit/poc/README.md)"],
    ["Dependency audit", "`cargo audit --db <advisory-db> --no-fetch`; `cargo deny --offline check bans licenses sources`"],
    ["Bitcoin Core metrics", f"`git clone --depth 1 https://github.com/bitcoin/bitcoin` at `{BTC_COMMIT}`; counts by grep over src/test, src/test/fuzz (`FUZZ_TARGET`), test/functional and ci/test"],
    ["This report", "`python3 audit/report/gen_inventory.py && python3 audit/report/gen_content.py && python3 audit/report/build_report.py && node audit/report/print_pdf.cjs audit/report/out/report.html audit/GnB-SMH-Code-Audit-2026-10-14.pdf`"],
]

HARNESS_ROWS = [
    ["compact_core_vectors.rs (3)", "Bitcoin Core `bignum_SetCompact` (20 vectors) and `CheckProofOfWork_test_*` rejections", "GnB accepts exactly the values Core's `DeriveTarget` accepts, decodes them to the same integers and re-encodes like `GetCompact`"],
    ["compact_differential.rs (5)", "Exhaustive sweep of every compact value with exponent 0..=34 (587,202,560 values) plus a sample of every larger exponent; 200,000-case proptests against Core `GetCompact` and rust-bitcoin `Target::to_compact_lossy` / `from_compact`", "Zero differences. 268,435,424 encodings are accepted by both; 17,694,689 of them are non-canonical, which is safe only because consensus compares `bits` to `expected_bits` as a u32"],
    ["asert_differential.rs (8)", "Port of the BCHN `CalculateASERT` fixed-point step (512-bit, no truncation) with GnB's anchor convention; 100,000-case proptests on real and random anchors; 152,358-point deterministic sweep", "Compact bits identical, full 256-bit targets identical; monotone in time; bounded to [1, pow_limit]; exact doubling per half-life; no panic on any (height, timestamp). Found AUD-1 (saturation for anchors near 2^256)"],
    ["merkle_consistency.rs (4)", "rust-bitcoin `merkle_tree::calculate_root` and a port of Core `ComputeMerkleRoot`", "Roots identical; CVE-2012-2459 collision reproduced (GnB relies on its duplicate-transaction rule); block id unchanged when only signature bytes change"],
    ["amount_consistency.rs (5)", "CVE-2010-5139 construction; closed-form schedule", "Overflow detected; total mining issuance 899,999,851,392,253 sat of 900,000,000,000,000 allocated (1.486 GNB never issued by rounding); fee function total over usize"],
    ["pow_reference_differential.rs (3)", "Normative `reference/gnb_smh.py`", "96 random cases (header lengths 0-399, any u64 nonce, log2_n 1-12) and one canonical (2^19) case identical; reused and per-thread scratchpads leak no state"],
    ["pow_check_semantics.rs (7)", "Core `CheckProofOfWorkImpl` and `GetBitsProof`", "GnB's strict `out < target` pinned (Core accepts `hash == target`); `work()` never overstates and is within 2^-64 of Core for every reachable target, but differs from the Python specification (POW-6)"],
]


def p(*t):
    return {"t": "p", "v": list(t)}


def main():
    blocks = []
    blocks.append(dict(id="exec", title="1. Executive summary", kind="", page_break=False, content=[
        {"t": "box", "cls": "verdict", "v": [
            "**Verdict.** At commit `125e9e5` GnB-SMH is not safe to secure value on a public network. The audit confirmed **5 Critical** and **19 High** findings, all five re-verified in the code by the lead auditor and each demonstrated by an executable proof-of-concept test. On a weighted, code-only scorecard GnB-SMH scores **3.1 / 10** against **9.1 / 10** for Bitcoin Core.",
            "The cryptographic and arithmetic building blocks are good and, in places, exemplary; the failures are in how blocks and transactions flow through the node: what state a block is validated against, what a peer can make a node do before any proof of work is checked, and what the miner assembles."]},
        {"t": "scorebig"},
        {"t": "h3", "v": "What is strong"},
        {"t": "ul", "v": [
            "**Proof-of-work arithmetic is exact.** The compact-target codec accepts and decodes exactly what Bitcoin Core accepts across all 587,202,560 values with a decodable exponent; ASERT is bit-identical to the aserti3-2d fixed-point construction on more than 350,000 cases; GnB-SMH in Rust equals the normative Python definition on 103 inputs; timestamps are bounded so that timewarp is impossible (better than Bitcoin mainnet today).",
            "**Signatures are combined correctly.** The hybrid scheme requires both ML-DSA-65 and Falcon-1024, parses every component at exact length, uses the constant-time integer Falcon variant, fails closed on randomness errors, and binds the sighash to a domain and a chain id.",
            "**Arithmetic hygiene and memory safety.** Value sums use checked arithmetic throughout (CVE-2010-5139, CVE-2012-2459 and CVE-2018-17144 classes are covered); consensus crates forbid `unsafe`; production code has 3 `unsafe` sites, all FFI; release builds keep overflow checks.",
            "**The existing tests pass.** 1,040 test executions in 61 binaries, the standalone crate, the vendored guards (in isolation) and the Python references all pass. The ledger-v1 sparse Merkle tree prototype showed no soundness defect.",
        ]},
        {"t": "h3", "v": "What breaks"},
        {"t": "ul", "v": [
            "**Consensus state model (DAG-1, VAL-2, VAL-3, DAG-6).** Every block, including parallel DAG blocks, is validated against the node's current tip UTXO set, so two honest nodes that see two sibling blocks containing the same mempool transaction in opposite order reject each other's branch forever. Duplicate coinbases, same-block coinbase spends and a node-local reorg cap add miner-triggerable splits.",
            "**Unauthenticated network denial of service (POW-2, NET-2).** One gossip frame with `height = u64::MAX` panics the block processor on every node it reaches; junk blocks are relayed before validation and each costs every node a full 64 MiB proof-of-work evaluation (~0.8 s) against attacker-chosen bits, with no penalty.",
            "**Block production liveness (MEM-1, MEM-2).** A single gossiped dust transaction, or about 116 ordinary pending transactions, makes every template produced by the stock miner and `getblocktemplate` consensus-invalid.",
            "**Assurance.** CI never compiles or tests the node workspace, there is no fuzzing harness, one test file is compiled out, feature unification disables the real ASERT path in workspace tests, and the dependency policy fails its own checks.",
        ]},
        {"t": "table", "h": ["Severity", "Count", "Meaning"], "w": ["14%", "10%", "76%"], "cls": "compact", "rows": [
            ["Critical", "5", "Network-wide consensus failure or zero-cost network-wide halt reachable without special privileges"],
            ["High", "19", "Miner- or peer-triggerable split, liveness failure, significant DoS, or realistic loss of funds"],
            ["Medium", "12", "Exploitable under specific conditions or with bounded impact"],
            ["Low", "24", "Defence in depth, latent defects, hygiene"],
            ["Info", "10", "Observations, inactive components, documentation drift"],
        ]},
    ]))
    blocks.append(dict(id="scope", title="2. Scope, methodology and limitations", kind="", page_break=True, content=[
        p("The audit covers the complete repository at commit `125e9e5` and compares it with Bitcoin Core master at commit `f13ae51`. It is **code-only**: findings and scores are based on source code, tests and tool output. Nothing in this report depends on hashrate, miner or user adoption, market conditions, decentralisation, or other properties that only exist once a network is used; where an attack needs proof of work, the report states the work required by the code (for example, one evaluation at the pow limit) rather than its cost in hardware."),
        {"t": "h3", "v": "Method"},
        {"t": "ul", "v": [
            "**Manual review.** Seven reviewers each read every line of one area: proof of work and difficulty; GhostDAG, chain selection and reorganisation; block and transaction validation, UTXO set and storage; cryptography and signatures; P2P, sync, RPC and explorer; wallets and web front end; mempool, shielded pool, attestation, ledger v1 and deployment. Each finding is traced to `file:line` and labelled *Confirmed by test*, *Confirmed by reading* or *Plausible*.",
            "**Verification.** Every Critical finding and the High findings that drive the verdict were re-read in the code by the lead auditor; duplicates reported by several reviewers were merged and are marked as independently reproduced. Severities were calibrated across areas.",
            "**Execution.** All of GnB's own suites were built and run in release mode, plus 73 proof-of-concept tests written during the audit (Appendix C explains how to run them; they live in `audit/poc` so that they do not alter the project's suites).",
            "**Independent consistency testing.** A separate crate, `audit/consistency`, applies Bitcoin Core's own vectors, line-for-line ports of Core and BCHN routines, and rust-bitcoin as oracles to GnB's consensus arithmetic (Section 5).",
            "**Mutation testing and dependency audit.** cargo-mutants on the PoW and difficulty crate; cargo-audit against the RustSec database of 14 October 2026; cargo-deny against the project's own policy.",
            "**Bitcoin Core comparison.** For each component the corresponding Core files, tests, fuzz targets and CI jobs at `f13ae51` were identified and counted directly from the source tree.",
        ]},
        {"t": "h3", "v": "Severity scale"},
        {"t": "table", "h": ["Severity", "Definition used"], "w": ["15%", "85%"], "cls": "compact", "rows": [
            ["Critical", "Permanent divergence of honest nodes, or a network-wide halt or crash that any unauthenticated peer can trigger at negligible cost"],
            ["High", "A split or liveness failure that a miner or peer can trigger, a significant amplified DoS, a realistic path to loss of funds, or a missing assurance control that hides Critical defects"],
            ["Medium", "Exploitable under specific conditions, bounded impact, or a latent consensus risk"],
            ["Low", "Defence in depth, hygiene, latent defects in inactive code"],
            ["Info", "Observations without direct security impact"],
        ]},
        {"t": "h3", "v": "Scoring"},
        p("The scorecard (Section 9) has nine categories weighted by their importance to the safety of a proof-of-work currency node. Each reviewer scored its component 0-10 for GnB and for the matching Bitcoin Core component; the lead auditor calibrated these against the findings and positive controls. Bitcoin Core was not re-audited: its scores reflect the code, tests and CI present at `f13ae51` and its known open issues (for example, the timewarp mitigation is not active on mainnet)."),
        {"t": "h3", "v": "Limitations"},
        {"t": "ul", "v": [
            "No live network was attacked. Network findings were demonstrated in-process or with local multi-node swarms.",
            "`accept_block` and the message processor live in the node binary (`main.rs`) and cannot be linked from tests. Two proof-of-concept files therefore contain a verbatim copy of that code, guarded by a test that checks the copy line by line against `main.rs`.",
            "No formal verification and no review of third-party crates beyond the advisory database and the FFI boundary of the post-quantum libraries.",
            "Timings were measured on a shared 4-core container and are indicative only.",
        ]},
    ]))
    blocks.append(dict(id="inventory", title="3. System overview and code inventory", kind="", page_break=True, content=[
        p("GnB is a hard fork of the Bloch BlockDAG node. It keeps Bloch's block format, GhostDAG consensus (k = 10), UTXO transaction model, hybrid ML-DSA-65 + Falcon-1024 signatures and libp2p network stack, replaces the proof of work with GnB-SMH (a sequential memory-hard SHAKE-256 function using 64 MiB per evaluation) and ASERT difficulty, and starts from a genesis that carries over the Bloch Genesis-3 ledger. A shielded pool, remote attestation and a stateless ledger (v1) are present but inactive in consensus."),
        {"t": "metrics", "key": "size"},
        p("GnB is roughly a seventh of Bitcoin Core's size, but the BlockDAG adds machinery (coloring, reachability, mergesets, multi-parent templates) that a longest-chain node does not have. Bitcoin Core's test code exceeds its production code when functional tests are included; GnB's test lines are about equal to its production lines, but concentrated in unit tests."),
        {"t": "h3", "v": "Assurance assets"},
        {"t": "metrics", "key": "assets"},
        {"t": "h3", "v": "Panic and unsafe surface (production code)"},
        {"t": "metrics", "key": "hazards"},
    ]))
    blocks.append(dict(id="results", title="4. Test execution and tooling results", kind="", page_break=True, content=[
        p("Every suite in the repository was executed. All pass; the defects in Section 6 exist because the suites do not exercise the relevant paths, not because tests fail."),
        {"t": "metrics", "key": "tooling"},
        {"t": "h3", "v": "Mutation testing of the PoW and difficulty crate"},
        p("cargo-mutants generated 222 mutants of `crates/gnb-smh/src/{lib,difficulty}.rs`. The crate's own tests killed 176 of 213 viable mutants (82.6%). Among the 37 survivors were consensus-relevant changes: the strict PoW comparison (`<` to `<=`), `verify` and `hash` returning constants, `work` and a schedule off-by-one. Re-running the survivors against the audit harness killed 15 more, including all of those; the remaining 22 are equivalent mutants (bit-disjoint `|` vs `^`, zero-iteration loop bounds, clamp-on-equality) or mutate non-consensus accessors and `Display` implementations. With the harness, every non-equivalent consensus mutant in the crate is detected."),
    ]))
    blocks.append(dict(id="harness", title="5. Independent consistency harness", kind="", page_break=True, content=[
        p("`audit/consistency` is a stand-alone crate (its own workspace, so the project's manifests and lockfile are untouched) that treats Bitcoin Core, BCHN and rust-bitcoin as reference implementations of the arithmetic GnB inherits from them. It uses `proptest` for property-based cases, `bitcoin` 0.32 (rust-bitcoin) as a crate oracle, `primitive-types` for 256/512-bit oracles, and the normative Python definition of GnB-SMH. All 35 tests pass."),
        {"t": "table", "h": ["Module (tests)", "Oracle", "Result"], "w": ["22%", "34%", "44%"], "cls": "compact", "rows": HARNESS_ROWS},
        p("The harness is also the reason two findings exist: it measured the `work()` deviation from the specification (POW-6) and found the ASERT saturation for anchors near the pow limit (AUD-1). It should be adopted in CI; it runs in about 30 seconds in release mode."),
    ]))
    blocks.append(dict(id="findings", title="6. Findings", kind="", page_break=True, content=[
        p("Findings are ordered by severity. Each lists its location, the evidence status, a concrete failure scenario where applicable, the corresponding Bitcoin Core control, and a recommendation. Identifiers name the review area: POW (proof of work), DAG (GhostDAG and reorg), VAL (validation and storage), CRY (cryptography), NET (P2P, sync, RPC), WAL (wallet and web), MEM (mempool), COH (shielded pool), LED (ledger v1), ATT (attestation), OPS (CI and operations), AUD (found by the audit harness)."),
        {"t": "findings_summary"},
        {"t": "h3", "v": "Detailed findings"},
        {"t": "findings"},
    ]))
    blocks.append(dict(id="components", title="7. Component comparison with Bitcoin Core", kind="", page_break=True, content=[
        p("Each table compares a GnB component with its Bitcoin Core counterpart on design, verified-correct behaviour, weaknesses found, tests and the reviewers' scores (consensus correctness / defensive coding / test depth, 0-10)."),
        {"t": "components"},
    ]))
    blocks.append(dict(id="bugclasses", title="8. Historical Bitcoin bug classes applied to GnB", kind="", page_break=True, content=[
        p("Bitcoin's history provides a checklist of consensus and denial-of-service defect classes. The table records, for each, how Bitcoin Core defends against it today and whether GnB's code does."),
        {"t": "table", "h": ["Bug class", "Bitcoin Core protection", "GnB code", "Status"], "w": ["20%", "27%", "38%", "15%"], "cls": "compact", "rows": BUGCLASS_ROWS},
    ]))
    blocks.append(dict(id="scorecard", title="9. Comparative security scorecard", kind="", page_break=True, content=[
        p("Scores are 0-10 per category (10 = no material weakness found, strong preventive controls and deep tests). The weighted totals summarise code-level security only."),
        {"t": "scorebig"},
        {"t": "scorecard"},
        {"t": "box", "v": [
            "**Comparative note.** GnB-SMH and Bitcoin Core differ by about six points on this scale. The gap is not in cryptographic primitives or arithmetic, where GnB is competitive and in places ahead (memory-safe language, absolute-schedule difficulty that rules out timewarp, post-quantum signatures), but in the parts that took Bitcoin Core a decade of incidents to harden: connect-time validation in the correct chain context, anti-DoS ordering before expensive work, peer accounting, mempool maintenance, crash consistency, and an assurance pipeline (fuzzing, sanitizers, functional tests) that exercises all of it continuously. Closing the five Critical findings and building that pipeline are prerequisites for any further comparison."]},
    ]))
    blocks.append(dict(id="roadmap", title="10. Remediation roadmap", kind="", page_break=False, content=[
        {"t": "table", "h": ["Phase", "Items"], "w": ["24%", "76%"], "cls": "compact", "rows": ROADMAP},
    ]))
    blocks.append(dict(id="appA", title="Appendix A. GnB test-module inventory", kind="", page_break=True, content=[
        p("Every test module in the repository, with the number of test functions and the security or consistency property it checks. *Kind* is derived heuristically from each file's code: property (proptest or seeded random), vectors (official or pinned data files), differential (cross-implementation), corpus (seed replay), async (tokio), unit (none of these)."),
        {"t": "h3", "v": "A.1 Inline unit-test modules (`#[cfg(test)]`)"},
        {"t": "inventory", "kind": "inline"},
        {"t": "h3", "v": "A.2 Integration test files"},
        {"t": "inventory", "kind": "integration"},
        {"t": "h3", "v": "A.3 Python reference tests"},
        {"t": "inventory", "kind": "python"},
        {"t": "h3", "v": "A.4 Audit consistency harness (this audit)"},
        {"t": "inventory", "kind": "audit-harness"},
        {"t": "h3", "v": "A.5 Audit proof-of-concept tests (this audit, in `audit/poc`)"},
        {"t": "inventory", "kind": "audit-poc"},
    ]))
    blocks.append(dict(id="appB", title="Appendix B. Bitcoin Core security and consistency test modules referenced", kind="", page_break=True, content=[
        p("All paths are relative to the Bitcoin Core tree at `f13ae51` and were checked to exist."),
        {"t": "table", "h": ["Category", "Modules"], "w": ["24%", "76%"], "cls": "compact", "rows": APPB},
    ]))
    blocks.append(dict(id="appC", title="Appendix C. Reproduction commands", kind="", page_break=False, content=[
        {"t": "table", "h": ["Step", "Command"], "w": ["24%", "76%"], "cls": "compact", "rows": APPC},
    ]))

    narrative = dict(cover_meta=COVER, sections=SECTIONS, blocks=blocks)
    dump("narrative.json", narrative)
    dump("scorecard.json", SCORE)
    dump("components.json", COMPONENTS)
    dump("metrics.json", METRICS)
    dump("test_runs.json", dict(headers=["Suite", "Result"], rows=[]))
    print("scores", SCORE["gnb_total"], SCORE["btc_total"])


if __name__ == "__main__":
    main()
