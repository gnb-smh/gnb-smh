//! Scheduled activation of consensus-rule changes ("hardening" upgrade).
//!
//! Audit 2026-10-14 found consensus bugs whose fixes change the result of
//! validation (GhostDAG blue work, k-cluster coloring, mergeset and
//! merge-depth limits, and further rules added later). A node cannot simply
//! switch to the corrected rules: every block already on the chain was
//! validated, colored and stored under the old rules, and a node replaying or
//! extending that history must reach the same `GhostdagData` and the same
//! verdicts as every other node. The fixes therefore activate at a scheduled
//! height:
//!
//! | network | activation height |
//! | --- | --- |
//! | mainnet | [`MAINNET_HARDENING_ACTIVATION_HEIGHT`] = 110,000 (about 30 days after the release at 30 s blocks) |
//! | testnet | [`TESTNET_HARDENING_ACTIVATION_HEIGHT`] = 0 (active from genesis) |
//! | regtest | [`REGTEST_HARDENING_ACTIVATION_HEIGHT`] = 0 (active from genesis) |
//!
//! A gated rule applies to a block iff `block_height >= activation_height`
//! ([`is_active_at`]). Below the activation height the old behaviour must be
//! reproduced *exactly*, including its bugs.
//!
//! # Which height
//!
//! Each gated rule must document which height it compares. The GhostDAG rules
//! (`node/src/consensus/mod.rs`) compare `GhostdagData::height` of the block
//! being added, i.e. `selected_parent.height + 1`. That value is a pure
//! function of the block's parents and the DAG, so every node gates the same
//! block the same way regardless of arrival order. A rule that runs before the
//! block reaches GhostDAG (for example a structural or transaction rule) should
//! use the header height checked by `accept_block`; mixing the two on one rule
//! is a consensus bug.
//!
//! # How to use it
//!
//! Production code reads the process-wide value once, where it builds its
//! long-lived state, and keeps it:
//!
//! ```
//! use gnb_crypto::core::activation;
//! let activation_height = activation::hardening_activation_height();
//! # let block_height = 0u64;
//! if activation::is_active_at(block_height, activation_height) {
//!     // new rule
//! } else {
//!     // old rule, bit-identical to the pre-activation code
//! }
//! ```
//!
//! [`hardening_activation_height`] derives the height from the node's chain id
//! (`super::set_node_chain_id`, called once at startup from `--testnet`).
//! Code that needs to test both regimes should take the activation height as a
//! parameter (as `GhostDAG::with_k_and_activation` does) instead of reading
//! the global, and call the `*_for_*` / [`is_active_at`] helpers. Where that is
//! impractical, [`scoped_override`] sets a per-thread value for the duration of
//! a test.
//!
//! # When no chain id was set
//!
//! Unit and integration tests never call `set_node_chain_id`, and
//! `node_chain_id()` then reports Mainnet. [`hardening_activation_height`]
//! follows the same rule and returns the **mainnet** height. Consequences:
//!
//! - every existing test, which builds DAGs far below 110,000, keeps exercising
//!   the old rules and keeps passing unchanged;
//! - a binary that forgot to set its chain id behaves like a mainnet node, the
//!   conservative choice (it never applies the new rules early);
//! - tests of the new rules must opt in explicitly, with an activation-height
//!   parameter (0 = new rules from genesis, [`NEVER`] = old rules forever) or
//!   with [`scoped_override`].
//!
//! # Adding another gated rule
//!
//! 1. Reuse this height unless the rule genuinely needs a separate schedule;
//!    one coordinated upgrade is easier to deploy and reason about than
//!    several.
//! 2. Gate it with [`is_active_at`] on a documented height (see above).
//! 3. Keep the old code path untouched below the height and prove it with a
//!    replay test that runs the old path with the activation height set to
//!    [`NEVER`].
//! 4. Add the rule to the activation section of `docs/CONSENSUS.md`.
//!
//! Changing [`MAINNET_HARDENING_ACTIVATION_HEIGHT`] after release is a
//! coordinated network upgrade in its own right: lowering it below the tip of
//! any node's chain re-validates history under new rules and can split the
//! network. Raising it is safe only before the old value is reached.

use std::cell::Cell;

use super::ChainId;

/// Mainnet activation height of the hardening rules (about 30 days after the
/// release at 30 s blocks: 30 * 86,400 / 30 = 86,400 blocks on top of the
/// chain height at release, rounded up).
pub const MAINNET_HARDENING_ACTIVATION_HEIGHT: u64 = 110_000;

/// Testnet activates the hardening rules from genesis.
pub const TESTNET_HARDENING_ACTIVATION_HEIGHT: u64 = 0;

/// Regtest activates the hardening rules from genesis.
pub const REGTEST_HARDENING_ACTIVATION_HEIGHT: u64 = 0;

/// An activation height that is never reached: old rules forever. Use it in
/// tests that prove the pre-activation behaviour is unchanged.
pub const NEVER: u64 = u64::MAX;

/// The networks an activation schedule is defined for. `ChainId` has no
/// regtest discriminant yet; a future regtest chain id maps to
/// [`ActivationNetwork::Regtest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActivationNetwork {
    Mainnet,
    Testnet,
    Regtest,
}

impl From<ChainId> for ActivationNetwork {
    fn from(id: ChainId) -> Self {
        match id {
            ChainId::Mainnet => ActivationNetwork::Mainnet,
            ChainId::Testnet => ActivationNetwork::Testnet,
        }
    }
}

/// Hardening activation height for a network.
pub const fn hardening_activation_height_for_network(net: ActivationNetwork) -> u64 {
    match net {
        ActivationNetwork::Mainnet => MAINNET_HARDENING_ACTIVATION_HEIGHT,
        ActivationNetwork::Testnet => TESTNET_HARDENING_ACTIVATION_HEIGHT,
        ActivationNetwork::Regtest => REGTEST_HARDENING_ACTIVATION_HEIGHT,
    }
}

/// Hardening activation height for a chain id.
pub const fn hardening_activation_height_for_chain(id: ChainId) -> u64 {
    match id {
        ChainId::Mainnet => MAINNET_HARDENING_ACTIVATION_HEIGHT,
        ChainId::Testnet => TESTNET_HARDENING_ACTIVATION_HEIGHT,
    }
}

/// `true` iff a rule with activation height `activation_height` applies to a
/// block at `height`. The single definition of "at or above activation".
#[inline]
pub const fn is_active_at(height: u64, activation_height: u64) -> bool {
    height >= activation_height
}

thread_local! {
    static THREAD_OVERRIDE: Cell<Option<u64>> = const { Cell::new(None) };
}

/// The process-wide hardening activation height.
///
/// Order of precedence:
/// 1. a [`scoped_override`] active on the calling thread (tests only);
/// 2. the node's chain id, if `set_node_chain_id` was called;
/// 3. otherwise the mainnet height, matching `node_chain_id()`'s default (see
///    the module documentation for why).
pub fn hardening_activation_height() -> u64 {
    if let Some(h) = THREAD_OVERRIDE.with(|c| c.get()) {
        return h;
    }
    match super::NODE_CHAIN_ID.get() {
        Some(id) => hardening_activation_height_for_chain(*id),
        None => MAINNET_HARDENING_ACTIVATION_HEIGHT,
    }
}

/// Activation height for code that knows the chain it signs for but is not a
/// node (wallets and other transaction signers never call
/// `set_node_chain_id`, so [`hardening_activation_height`] would answer with
/// the mainnet schedule for a testnet wallet). Order of precedence: a
/// [`scoped_override`] on the calling thread (tests that move the boundary
/// for node and wallet together), otherwise the schedule of `id`.
pub fn hardening_activation_height_for_signer(id: ChainId) -> u64 {
    if let Some(h) = THREAD_OVERRIDE.with(|c| c.get()) {
        return h;
    }
    hardening_activation_height_for_chain(id)
}

/// `true` iff the hardening rules apply at `height` under the process-wide
/// activation height. Prefer [`is_active_at`] with a stored height in code
/// that must be testable in both regimes.
pub fn hardening_active_at(height: u64) -> bool {
    is_active_at(height, hardening_activation_height())
}

/// Guard returned by [`scoped_override`]; restores the previous value on drop.
#[must_use = "the override ends when the guard is dropped"]
pub struct OverrideGuard {
    previous: Option<u64>,
}

impl Drop for OverrideGuard {
    fn drop(&mut self) {
        let prev = self.previous;
        THREAD_OVERRIDE.with(|c| c.set(prev));
    }
}

/// Override [`hardening_activation_height`] on the **calling thread** until
/// the returned guard is dropped. Intended for tests: test threads run in
/// parallel and a per-thread value cannot leak into another test. It does not
/// reach work spawned onto other threads, and state that captured the height
/// before the override (for example an existing `GhostDAG`) keeps its value.
/// Never call it from node code.
pub fn scoped_override(activation_height: u64) -> OverrideGuard {
    let previous = THREAD_OVERRIDE.with(|c| c.replace(Some(activation_height)));
    OverrideGuard { previous }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule_matches_the_decision() {
        assert_eq!(MAINNET_HARDENING_ACTIVATION_HEIGHT, 110_000);
        assert_eq!(TESTNET_HARDENING_ACTIVATION_HEIGHT, 0);
        assert_eq!(REGTEST_HARDENING_ACTIVATION_HEIGHT, 0);
        assert_eq!(hardening_activation_height_for_chain(ChainId::Mainnet), 110_000);
        assert_eq!(hardening_activation_height_for_chain(ChainId::Testnet), 0);
        for net in [ActivationNetwork::Mainnet, ActivationNetwork::Testnet, ActivationNetwork::Regtest] {
            let via_chain = match net {
                ActivationNetwork::Mainnet => Some(ChainId::Mainnet),
                ActivationNetwork::Testnet => Some(ChainId::Testnet),
                ActivationNetwork::Regtest => None,
            };
            if let Some(id) = via_chain {
                assert_eq!(ActivationNetwork::from(id), net);
                assert_eq!(
                    hardening_activation_height_for_network(net),
                    hardening_activation_height_for_chain(id)
                );
            }
        }
        assert_eq!(hardening_activation_height_for_network(ActivationNetwork::Regtest), 0);
    }

    #[test]
    fn boundary_is_inclusive() {
        assert!(!is_active_at(109_999, MAINNET_HARDENING_ACTIVATION_HEIGHT));
        assert!(is_active_at(110_000, MAINNET_HARDENING_ACTIVATION_HEIGHT));
        assert!(is_active_at(0, 0));
        assert!(!is_active_at(u64::MAX - 1, NEVER));
    }

    #[test]
    fn unset_chain_id_defaults_to_mainnet_and_override_is_scoped() {
        // The gnb-crypto unit tests never set the chain id.
        if chain_id_unset() {
            assert_eq!(hardening_activation_height(), MAINNET_HARDENING_ACTIVATION_HEIGHT);
        }
        let before = hardening_activation_height();
        {
            let _g = scoped_override(0);
            assert_eq!(hardening_activation_height(), 0);
            assert!(hardening_active_at(0));
            {
                let _inner = scoped_override(NEVER);
                assert_eq!(hardening_activation_height(), NEVER);
            }
            assert_eq!(hardening_activation_height(), 0);
            // Another thread does not see this thread's override.
            let other = std::thread::spawn(hardening_activation_height).join().unwrap();
            assert_eq!(other, before);
        }
        assert_eq!(hardening_activation_height(), before);
    }

    /// Signers follow their own chain's schedule (never the node's global),
    /// unless a test override is active on the thread.
    #[test]
    fn signer_height_follows_the_signer_chain_and_the_override() {
        assert_eq!(hardening_activation_height_for_signer(ChainId::Mainnet), MAINNET_HARDENING_ACTIVATION_HEIGHT);
        assert_eq!(hardening_activation_height_for_signer(ChainId::Testnet), TESTNET_HARDENING_ACTIVATION_HEIGHT);
        let _g = scoped_override(7);
        assert_eq!(hardening_activation_height_for_signer(ChainId::Mainnet), 7);
        assert_eq!(hardening_activation_height_for_signer(ChainId::Testnet), 7);
    }

    #[test]
    fn process_wide_predicate_uses_the_process_wide_height() {
        let _g = scoped_override(1_000);
        assert!(!hardening_active_at(0));
        assert!(!hardening_active_at(999));
        assert!(hardening_active_at(1_000));
        assert!(hardening_active_at(u64::MAX));
        if chain_id_unset() {
            drop(_g);
            assert!(!hardening_active_at(MAINNET_HARDENING_ACTIVATION_HEIGHT - 1));
            assert!(hardening_active_at(MAINNET_HARDENING_ACTIVATION_HEIGHT));
        }
    }

    fn chain_id_unset() -> bool {
        super::super::NODE_CHAIN_ID.get().is_none()
    }
}
