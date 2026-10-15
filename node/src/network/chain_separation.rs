//! Wire separation between networks (audit POW-9 residual).
//!
//! Mainnet and testnet share the genesis block and the ASERT anchor
//! (`docs/CONSENSUS.md`, "Networks"), so nothing in a block tells the two
//! chains apart below the mainnet hardening activation except the rules
//! themselves. Transactions are domain-separated by the chain id in every
//! sighash (v2 and v3). The peer-to-peer layer must be too: Bitcoin Core
//! gives each network its own message start bytes (`pchMessageStart`,
//! `src/kernel/chainparams.cpp`), and a node drops any connection whose
//! frames carry another network's magic before it parses anything.
//!
//! The libp2p equivalent is the protocol identifiers: the gossip topics, the
//! directed-sync stream protocol and the identify protocol version all name
//! the network, so a node of one network never subscribes to, requests from
//! or serves the other's frames, and a peer that identifies with another
//! network's protocol version is disconnected ([`same_network`]). Mainnet
//! keeps the identifiers it has always used (deployed nodes stay
//! compatible); testnet gets its own.

use libp2p::StreamProtocol;

use crate::core::ChainId;

/// The protocol identifiers of one network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainProtocols {
    /// identify protocol version (`identify::Config::new`).
    pub identify: &'static str,
    /// gossipsub topic of `NewBlock` frames.
    pub blocks_topic: &'static str,
    /// gossipsub topic of `NewTransaction` frames.
    pub txs_topic: &'static str,
    /// gossipsub topic of the other gossip frames.
    pub sync_topic: &'static str,
    /// request-response protocol of the directed sync (`sync_rr`).
    pub sync_protocol: StreamProtocol,
}

/// Mainnet: the identifiers every released node uses.
pub const MAINNET: ChainProtocols = ChainProtocols {
    identify: "/gnb/1.0.0",
    blocks_topic: super::TOPIC_BLOCKS,
    txs_topic: super::TOPIC_TXS,
    sync_topic: super::TOPIC_SYNC,
    sync_protocol: super::sync_rr::SYNC_PROTOCOL,
};

/// Testnet: every identifier names the network.
pub const TESTNET: ChainProtocols = ChainProtocols {
    identify: "/gnb-testnet/1.0.0",
    blocks_topic: "gnb-testnet/blocks/1",
    txs_topic: "gnb-testnet/txs/1",
    sync_topic: "gnb-testnet/sync/1",
    sync_protocol: StreamProtocol::new("/gnb-testnet/sync/1"),
};

/// The protocol identifiers of `chain`.
pub const fn chain_protocols(chain: ChainId) -> ChainProtocols {
    match chain {
        ChainId::Mainnet => MAINNET,
        ChainId::Testnet => TESTNET,
    }
}

/// `true` iff a peer whose identify protocol version is `theirs` runs the
/// network `ours` describes. Anything else (another network, or a peer that
/// does not speak GnB at all) is disconnected on identify.
pub fn same_network(ours: &ChainProtocols, theirs: &str) -> bool {
    theirs == ours.identify
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(p: &ChainProtocols) -> [&str; 5] {
        [p.identify, p.blocks_topic, p.txs_topic, p.sync_topic, p.sync_protocol.as_ref()]
    }

    /// Mainnet keeps its deployed identifiers byte for byte.
    #[test]
    fn mainnet_identifiers_are_the_deployed_ones() {
        assert_eq!(
            fields(&chain_protocols(ChainId::Mainnet)),
            ["/gnb/1.0.0", "gnb/blocks/1", "gnb/txs/1", "gnb/sync/1", "/gnb/sync/1"]
        );
    }

    /// No identifier of one network is an identifier of the other.
    #[test]
    fn networks_share_no_identifier() {
        let (main, test) = (chain_protocols(ChainId::Mainnet), chain_protocols(ChainId::Testnet));
        let (m, t) = (fields(&main), fields(&test));
        for a in m {
            assert!(!t.contains(&a), "{a} is used by both networks");
        }
        let mut all: Vec<&str> = m.iter().chain(t.iter()).copied().collect();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), 10, "every identifier is distinct");
    }

    #[test]
    fn identify_from_another_network_is_refused() {
        assert!(same_network(&MAINNET, "/gnb/1.0.0"));
        assert!(!same_network(&MAINNET, "/gnb-testnet/1.0.0"));
        assert!(same_network(&TESTNET, "/gnb-testnet/1.0.0"));
        assert!(!same_network(&TESTNET, "/gnb/1.0.0"));
        assert!(!same_network(&MAINNET, ""));
        assert!(!same_network(&MAINNET, "/ipfs/0.1.0"));
    }
}
