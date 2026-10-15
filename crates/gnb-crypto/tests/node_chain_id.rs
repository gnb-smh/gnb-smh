//! The process-wide node chain id (`core::set_node_chain_id`), in its own
//! test process: setting it is irreversible, so it cannot run inside the
//! library's unit-test binary, whose tests rely on the unset (mainnet)
//! default.

use gnb_crypto::core::{self, activation, ChainId};

#[test]
fn node_chain_id_is_set_once_and_selects_the_activation_schedule() {
    assert_eq!(core::node_chain_id(), ChainId::Mainnet, "unset: mainnet");
    assert_eq!(activation::hardening_activation_height(), activation::MAINNET_HARDENING_ACTIVATION_HEIGHT);

    assert_eq!(core::set_node_chain_id(ChainId::Testnet), Ok(()));
    assert_eq!(core::node_chain_id(), ChainId::Testnet);
    // Idempotent for the same value; a different value is refused and
    // reports the one already set.
    assert_eq!(core::set_node_chain_id(ChainId::Testnet), Ok(()));
    assert_eq!(core::set_node_chain_id(ChainId::Mainnet), Err(ChainId::Testnet));
    assert_eq!(core::node_chain_id(), ChainId::Testnet);

    // The node's chain id now drives the process-wide activation height...
    assert_eq!(activation::hardening_activation_height(), activation::TESTNET_HARDENING_ACTIVATION_HEIGHT);
    assert!(activation::hardening_active_at(1));
    assert!(core::block_rules::rules_active(1));
    assert!(!core::block_rules::rules_active(0), "never the genesis");
    // ...but not a signer's, which follows the chain it signs for.
    assert_eq!(
        activation::hardening_activation_height_for_signer(ChainId::Mainnet),
        activation::MAINNET_HARDENING_ACTIVATION_HEIGHT
    );
    // A thread override still wins over the node's chain id.
    let _g = activation::scoped_override(activation::NEVER);
    assert_eq!(activation::hardening_activation_height(), activation::NEVER);
}
