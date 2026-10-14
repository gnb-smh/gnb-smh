//! GnB-SMH proof-of-work adapter: the seam between the block layer and the
//! `gnb-smh` crate.
//!
//! - Validation goes through `Block::validate_pow` (gnb-crypto), which runs
//!   GnB-SMH v1 at the canonical 64 MiB parameter and caches verified block ids.
//! - Difficulty goes through [`expected_bits`], ASERT anchored at genesis, a
//!   pure function of the parent set: the latest timestamp over ALL parents
//!   and the height max(parent heights) + 1 (not the GhostDAG selected
//!   parent's; see docs/CONSENSUS.md). The validator, the internal miner and
//!   `getblocktemplate` all call it.
//! - Mining here is a plain CPU search: one 64 MiB scratchpad per thread,
//!   disjoint nonce ranges, cooperative stop flag.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};


/// Chain-work contribution of a block at compact `bits` (≈ 2^256 / target;
/// exact definition: `gnb_smh::difficulty::work`).
#[inline]
pub fn work_from_bits(bits: u32) -> u128 {
    gnb_crypto::core::bits_to_work(bits)
}

/// Expected `bits` for the block at `height` (= max parent height + 1) whose
/// parents' LATEST timestamp is `parent_timestamp` (see
/// `core::difficulty_parent_timestamp`). CONSENSUS-CRITICAL: miner and
/// validator must call exactly this.
#[inline]
pub fn expected_bits(parent_timestamp: u64, height: u64) -> Result<u32, String> {
    gnb_crypto::core::expected_bits(parent_timestamp, height)
}

/// Verify a (preimage, nonce) pair against compact `bits`.
pub fn verify(pow_preimage: &[u8], nonce: u64, bits: u32) -> bool {
    match gnb_smh::difficulty::try_bits_to_target(bits) {
        Ok(target) => gnb_smh::verify(pow_preimage, nonce, &target),
        Err(_) => false,
    }
}

/// Single-threaded search over `[start_nonce, start_nonce + max_attempts)`.
pub fn mine(pow_preimage: &[u8], bits: u32, start_nonce: u64, max_attempts: u64) -> Option<u64> {
    mine_parallel(pow_preimage, bits, start_nonce, max_attempts, 1, None)
}

/// Search with `threads` workers, each over a disjoint nonce range of
/// `attempts_per_thread` nonces starting at `start_nonce + k * attempts_per_thread`.
/// Returns the first nonce found, or `None` when every worker exhausts its
/// range or `stop` is raised. Memory: `threads` × 64 MiB.
pub fn mine_parallel(
    pow_preimage: &[u8],
    bits: u32,
    start_nonce: u64,
    attempts_per_thread: u64,
    threads: usize,
    stop: Option<&AtomicBool>,
) -> Option<u64> {
    let target = gnb_smh::difficulty::try_bits_to_target(bits).ok()?;
    let threads = threads.max(1);
    let found = AtomicBool::new(false);
    let winner = AtomicU64::new(0);
    std::thread::scope(|s| {
        for k in 0..threads {
            let found = &found;
            let winner = &winner;
            let target = &target;
            s.spawn(move || {
                let mut sp = gnb_smh::Scratchpad::new(gnb_smh::LOG2_N);
                let base = start_nonce.wrapping_add((k as u64).wrapping_mul(attempts_per_thread));
                for i in 0..attempts_per_thread {
                    if found.load(Ordering::Relaxed) || stop.is_some_and(|f| f.load(Ordering::Relaxed)) {
                        return;
                    }
                    let nonce = base.wrapping_add(i);
                    let out = gnb_smh::hash_with(&mut sp, pow_preimage, nonce);
                    if gnb_smh::difficulty::meets_target(&out, target) {
                        if !found.swap(true, Ordering::AcqRel) {
                            winner.store(nonce, Ordering::Release);
                        }
                        return;
                    }
                }
            });
        }
    });
    found.load(Ordering::Acquire).then(|| winner.load(Ordering::Acquire))
}

#[cfg(test)]
mod tests {
    use super::*;
    use gnb_crypto::core::POW_LIMIT_BITS;

    #[test]
    fn mined_nonce_verifies_and_matches_block_validation() {
        // At the pow limit almost every evaluation passes, so this is one or
        // two 64 MiB evaluations.
        let mut block = gnb_crypto::core::genesis_block();
        block.header.bits = POW_LIMIT_BITS;
        let pre = block.header.pow_preimage();
        let nonce = mine_parallel(&pre, POW_LIMIT_BITS, 0, 16, 2, None).expect("pow limit is trivially mineable");
        assert!(verify(&pre, nonce, POW_LIMIT_BITS));
        block.header.nonce = nonce;
        assert!(block.validate_pow());
    }

    #[test]
    fn malformed_bits_never_mine_or_verify() {
        assert_eq!(mine(b"x", 0xFF00_FFFF, 0, 4), None);
        assert!(!verify(b"x", 0, 0xFF00_FFFF));
        assert_eq!(work_from_bits(0xFF00_FFFF), 0);
    }

    #[test]
    fn stop_flag_aborts() {
        let stop = AtomicBool::new(true);
        // An essentially impossible target with the stop flag already raised.
        assert_eq!(mine_parallel(b"x", 0x0300_0001, 0, u64::MAX, 2, Some(&stop)), None);
    }
}
