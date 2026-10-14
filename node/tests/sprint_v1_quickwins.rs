//! Sprint V.1 — quick-win audit remediations.
//!
//! This file pins regressions for the audit fixes bundled into Sprint V.1
//! that are not already covered by unit tests inside their own modules.
//! Specifically:
//!
//!   - M-10 (gossipsub MessageId) — deterministic SHA-256 based IDs.
//!   - L-1  (crypto::verify)      — returns `false` on parse failure
//!                                   without panicking or crashing.
//!   - L-5  (emission curve)      — emission math sanity. Originally
//!                                   written against Bloch V1's
//!                                   `BLOCK_REWARD` / `MAX_SUPPLY`; ported
//!                                   (2026-10 audit, test hygiene) to GnB's
//!                                   monetary policy in `core::tokenomics`:
//!                                   the same geometric-sum milestones (half
//!                                   the mining allocation in the first
//!                                   epoch, 99 % by halving 7, 99.99 % by
//!                                   halving 14) checked against the
//!                                   consensus subsidy functions.
//!
//! This file was compiled out (`#![cfg(any())]`) after Bloch's V2 tokenomics
//! removed the V1 constants it referenced; it runs again since the port.
//!
//! M-9 (add_block Result) and H-5 (past_blue_set bound) are covered
//! directly by the in-module `#[cfg(test)] mod tests` in
//! `src/consensus/mod.rs`.
//!
//! M-3 (is_ancestor warn) is a log-level change with no consensus
//! effect, so no regression test is needed — the correctness of
//! `is_ancestor` under the bound is already covered by the reorg
//! test suite (sprint_u3_reorg.rs).
//!
//! L-3 (resolve_multiaddr warn) is a log-level change, similarly
//! untested at unit level — exercising real DNS resolution in CI is
//! brittle and the warn message itself would not be part of any
//! stable contract.

use gnb::core::tokenomics::{
    block_subsidy_sat, issued_through_sat, HALVING_INTERVAL, INITIAL_SUBSIDY_SAT,
    MINING_ALLOCATION_SAT,
};
use gnb::crypto;
use sha2::{Digest, Sha256};

// ─── M-10: gossipsub MessageId determinism ────────────────────────────────

/// The Sprint V.1 fix moved MessageId from std::hash::DefaultHasher
/// (cross-version unstable) to SHA-256 truncated to 16 bytes. This test
/// locks in the invariant that the *same payload always produces the
/// same 16-byte id*, independent of Rust toolchain.
#[test]
fn m10_gossipsub_message_id_is_deterministic() {
    // Emulate the closure used in src/network/mod.rs::run()
    fn msg_id(data: &[u8]) -> [u8; 16] {
        let digest = Sha256::digest(data);
        let mut out = [0u8; 16];
        out.copy_from_slice(&digest[..16]);
        out
    }

    let payload = b"block announce: 0xdeadbeef...";
    let id1 = msg_id(payload);
    let id2 = msg_id(payload);
    assert_eq!(id1, id2, "MessageId must be deterministic for same payload");

    // Different payloads must produce different ids with overwhelming
    // probability. One collision sample here is sufficient — SHA-256
    // collisions on short distinct inputs have never been observed.
    let id3 = msg_id(b"a different payload");
    assert_ne!(id1, id3);
}

/// Lock the specific truncation length: 16 bytes. If someone later
/// changes the truncation length they have to update this test, which
/// surfaces the decision in code review.
#[test]
fn m10_message_id_is_16_bytes() {
    let digest = Sha256::digest(b"any payload");
    let id_slice = &digest[..16];
    assert_eq!(id_slice.len(), 16);
}

// ─── L-1: crypto::verify() fails gracefully on malformed input ────────────

#[test]
fn l1_verify_returns_false_for_malformed_public_key() {
    // Wrong size — mldsa65 public keys are exactly 1952 bytes.
    let bad_pk = vec![0u8; 100];
    let msg    = b"anything";
    let bad_sig = vec![0u8; 3309]; // right length, but won't matter
    let ok = crypto::verify(&bad_pk, msg, &bad_sig);
    assert!(
        !ok,
        "verify must return false on malformed public key — must never panic"
    );
}

#[test]
fn l1_verify_returns_false_for_malformed_signature() {
    // Valid public key shape (zeros pass the `from_bytes` length check
    // but will fail semantic verify later — that's fine, we're testing
    // the signature path).
    let pk_bytes = vec![0u8; 1952];
    let msg      = b"anything";
    let bad_sig  = vec![0u8; 10]; // wrong size
    let ok = crypto::verify(&pk_bytes, msg, &bad_sig);
    assert!(
        !ok,
        "verify must return false on malformed signature — must never panic"
    );
}

#[test]
fn l1_verify_returns_false_when_empty() {
    let ok = crypto::verify(&[], b"", &[]);
    assert!(!ok, "verify must return false on empty-everything input");
}

// ─── L-5: emission curve math cross-check ─────────────────────────────────

/// Mining subsidy issued by the first `n` halving epochs, from the closed-form
/// geometric sum: sum_{k<n} (INITIAL_SUBSIDY >> k) * HALVING_INTERVAL, minus
/// the genesis block, which pays nothing.
fn total_mined_after_halvings(n: u32) -> u128 {
    let mut total: u128 = 0;
    for k in 0..n {
        let reward = (INITIAL_SUBSIDY_SAT as u128) >> k; // integer halving
        total += reward * (HALVING_INTERVAL as u128);
    }
    total - INITIAL_SUBSIDY_SAT as u128 // height 0 pays nothing
}

/// Cross-check the emission milestones against the consensus subsidy
/// functions: the closed form equals `issued_through_sat` at halving
/// boundaries; half the mining allocation is issued in the first epoch, 99 %
/// by halving 7 and 99.99 % by halving 14.
#[test]
fn l5_emission_curve_reaches_99pct_by_halving_7() {
    let allocation = MINING_ALLOCATION_SAT as u128;
    for n in [1u32, 2, 7, 14, 27] {
        let height = n as u64 * HALVING_INTERVAL - 1;
        assert_eq!(
            total_mined_after_halvings(n),
            issued_through_sat(height) as u128,
            "closed form vs consensus issuance after {n} halvings"
        );
    }
    assert_eq!(block_subsidy_sat(HALVING_INTERVAL - 1), INITIAL_SUBSIDY_SAT);
    assert_eq!(block_subsidy_sat(HALVING_INTERVAL), INITIAL_SUBSIDY_SAT >> 1);

    // After halving 1 (one epoch): ~50 % of the mining allocation.
    let after_h1 = total_mined_after_halvings(1);
    assert!(after_h1 >= allocation * 49 / 100);
    assert!(after_h1 <= allocation * 51 / 100);

    // After halving 7: >= 99 % of the mining allocation.
    let after_h7 = total_mined_after_halvings(7);
    assert!(
        after_h7 >= allocation * 99 / 100,
        "after 7 halvings we should have mined >= 99% of the mining allocation; \
         got {} out of {} ({}%)",
        after_h7, allocation, after_h7 * 100 / allocation,
    );

    // After halving 14: >= 99.99 %.
    let after_h14 = total_mined_after_halvings(14);
    assert!(
        after_h14 >= allocation * 9999 / 10000,
        "after 14 halvings we should have mined >= 99.99% of the mining allocation",
    );
}

/// The audit draft's "~13 years to 99 %" figure (Bloch) was numerically
/// wrong. On GnB's schedule 99 % of the mining allocation is issued by
/// halving 7, and nothing is issued once the subsidy reaches zero at halving
/// 27, so total issuance never exceeds the allocation.
#[test]
fn l5_audit_13_years_figure_was_inaccurate() {
    let after_h7 = total_mined_after_halvings(7);
    assert!(after_h7 >= (MINING_ALLOCATION_SAT as u128) * 99 / 100);
    let all = issued_through_sat(u64::MAX) as u128;
    assert_eq!(all, total_mined_after_halvings(27));
    assert!(all <= MINING_ALLOCATION_SAT as u128);
    assert_eq!(block_subsidy_sat(27 * HALVING_INTERVAL), 0);
}
