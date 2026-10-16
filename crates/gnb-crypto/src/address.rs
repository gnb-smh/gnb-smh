//! Bloch-SIS Protocol — Unified Address type
//!
//! Replaces scattered `[u8; 20]`, `Vec<u8>`, `String` address handling
//! with a single ergonomic type. Works in all three forms:
//!
//!   - On-chain: 20-byte hash (`&[u8; 20]`)
//!   - User-facing: "gnb1q..." / "gnb1t..." string with checksum
//!   - Raw bytes: 24-byte payload (20 hash + 4 checksum)
//!
//! All validation, parsing, and display logic lives here. Other modules
//! should take `&Address` instead of `&[u8]`.

use serde::{Serialize, Deserialize};
use sha3::{Sha3_256, Digest};
use thiserror::Error;

use crate::core::{MAINNET_PREFIX, TESTNET_PREFIX};

/// Bloch address prefixes. A Bloch address and a GnB address with the same
/// 20-byte hash and checksum belong to the same key.
pub const LEGACY_BLOCH_MAINNET_PREFIX: &str = "bloch1q";
pub const LEGACY_BLOCH_TESTNET_PREFIX: &str = "bloch1t";

/// Map a Bloch address string to its GnB form (same hash and checksum);
/// anything else is returned unchanged.
pub fn normalize_legacy_address(s: &str) -> String {
    if let Some(rest) = s.strip_prefix(LEGACY_BLOCH_MAINNET_PREFIX) {
        format!("{MAINNET_PREFIX}{rest}")
    } else if let Some(rest) = s.strip_prefix(LEGACY_BLOCH_TESTNET_PREFIX) {
        format!("{TESTNET_PREFIX}{rest}")
    } else {
        s.to_string()
    }
}

// ── Policy addresses (multisig / timelocks, core::policy) ─────────────────────

/// Prefix of a mainnet policy address.
pub const POLICY_MAINNET_PREFIX: &str = "gnb1m";
/// Prefix of a testnet policy address.
pub const POLICY_TESTNET_PREFIX: &str = "gnb1n";

/// Address of a spend policy: `prefix ‖ hex(hash32 ‖ checksum4)`, where the
/// checksum is `SHA3-256(SHA3-256(prefix ‖ hash))[..4]` — it covers the
/// network prefix, so a mainnet policy address cannot be mistyped into a
/// valid testnet one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PolicyAddress {
    hash: [u8; 32],
    network: Network,
}

impl PolicyAddress {
    pub fn from_policy(policy: &crate::core::policy::SpendPolicy, network: Network) -> Self {
        Self { hash: policy.hash(), network }
    }

    /// Address of any policy output script (`0x02 ‖ hash`), e.g. a policy tree.
    pub fn from_script(script: &[u8], network: Network) -> Option<Self> {
        if script.len() != crate::core::policy::POLICY_SPK_LEN || script[0] != crate::core::policy::POLICY_TAG {
            return None;
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&script[1..]);
        Some(Self { hash, network })
    }

    pub fn network(&self) -> Network {
        self.network
    }

    /// The 33-byte output script (`0x02 ‖ hash`).
    pub fn script_pubkey(&self) -> Vec<u8> {
        let mut s = vec![crate::core::policy::POLICY_TAG];
        s.extend_from_slice(&self.hash);
        s
    }

    fn prefix(network: Network) -> &'static str {
        match network {
            Network::Mainnet => POLICY_MAINNET_PREFIX,
            Network::Testnet => POLICY_TESTNET_PREFIX,
        }
    }

    fn checksum(network: Network, hash: &[u8; 32]) -> [u8; 4] {
        let mut h = Sha3_256::new();
        h.update(Self::prefix(network).as_bytes());
        h.update(hash);
        let outer = Sha3_256::digest(h.finalize());
        [outer[0], outer[1], outer[2], outer[3]]
    }

    pub fn parse(s: &str) -> Result<Self, AddressError> {
        let (network, payload) = if let Some(rest) = s.strip_prefix(POLICY_MAINNET_PREFIX) {
            (Network::Mainnet, rest)
        } else if let Some(rest) = s.strip_prefix(POLICY_TESTNET_PREFIX) {
            (Network::Testnet, rest)
        } else {
            return Err(AddressError::BadPrefix);
        };
        if payload.len() != 72 {
            return Err(AddressError::BadLength { got: payload.len(), expected: 72 });
        }
        let bytes = hex::decode(payload).map_err(|_| AddressError::BadHex)?;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes[..32]);
        if bytes[32..36] != Self::checksum(network, &hash) {
            return Err(AddressError::BadChecksum);
        }
        Ok(Self { hash, network })
    }

    /// [`Self::parse`] requiring the address to belong to `network` (CRY-7).
    /// The checksum already commits to the prefix, so only a well-formed
    /// address of the other network reaches the comparison.
    pub fn parse_for_network(s: &str, network: Network) -> Result<Self, AddressError> {
        let address = Self::parse(s)?;
        if address.network != network {
            return Err(AddressError::WrongNetwork { expected: network, got: address.network });
        }
        Ok(address)
    }
}

impl std::fmt::Display for PolicyAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut payload = self.hash.to_vec();
        payload.extend_from_slice(&Self::checksum(self.network, &self.hash));
        write!(f, "{}{}", Self::prefix(self.network), hex::encode(payload))
    }
}

/// Parse any payable address — single-key (`gnb1q…`/`gnb1t…`, Bloch forms
/// accepted) or policy (`gnb1m…`/`gnb1n…`) — into its network and output
/// script.
pub fn destination_script(s: &str) -> Result<(Network, Vec<u8>), AddressError> {
    if s.starts_with(POLICY_MAINNET_PREFIX) || s.starts_with(POLICY_TESTNET_PREFIX) {
        let a = PolicyAddress::parse(s)?;
        return Ok((a.network(), a.script_pubkey()));
    }
    let a = Address::parse(s)?;
    Ok((a.network(), a.hash().to_vec()))
}

/// [`destination_script`] of an address that must belong to `network`
/// (CRY-7): the output script, or [`AddressError::WrongNetwork`] for a
/// well-formed address of the other network. Every consumer that knows its
/// chain (the node's RPC, wallets, the policy and vault tools) decodes
/// through this or [`Address::parse_for_network`], as Bitcoin Core decodes
/// every address with the chain parameters of the running network
/// (`DecodeDestination`), never network-agnostically.
pub fn destination_script_for_network(s: &str, network: Network) -> Result<Vec<u8>, AddressError> {
    let (got, script) = destination_script(s)?;
    if got != network {
        return Err(AddressError::WrongNetwork { expected: network, got });
    }
    Ok(script)
}

// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    pub fn prefix(&self) -> &'static str {
        match self {
            Network::Mainnet => MAINNET_PREFIX,
            Network::Testnet => TESTNET_PREFIX,
        }
    }

    /// The network of a chain id (inverse of `ChainId::for_network`).
    pub const fn for_chain(id: crate::core::ChainId) -> Network {
        match id {
            crate::core::ChainId::Mainnet => Network::Mainnet,
            crate::core::ChainId::Testnet => Network::Testnet,
        }
    }

    /// Lower-case name: "mainnet" or "testnet".
    pub const fn name(&self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Testnet => "testnet",
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address {
    hash: [u8; 20],
    network: Network,
}

impl Address {
    /// Create an address from a known-good 20-byte pubkey hash.
    pub fn from_hash(hash: [u8; 20], network: Network) -> Self {
        Self { hash, network }
    }

    /// Borrow the 20-byte pubkey hash component of the address.
    pub fn hash_bytes(&self) -> &[u8; 20] {
        &self.hash
    }

    /// Derive an address from a raw ML-DSA-65 public key.
    pub fn from_pubkey(pubkey: &[u8], network: Network) -> Self {
        let digest = Sha3_256::digest(pubkey);
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&digest[..20]);
        Self { hash, network }
    }

    /// Parse a user-facing address string (gnb1q... or gnb1t...). Bloch
    /// addresses (bloch1q... / bloch1t...) name the same owner — the checksum
    /// covers only the hash — and are accepted as their GnB equivalent.
    /// Validates: prefix, hex format, length, and checksum.
    ///
    /// Syntax only, for EITHER network: the checksum does not cover the
    /// prefix, so the other network's prefix on the same hash parses too.
    /// Code that knows its chain (anything that pays, answers for, or
    /// indexes an address of one chain) must use [`Self::parse_for_network`]
    /// or [`destination_script_for_network`] instead (CRY-7).
    pub fn parse(s: &str) -> Result<Self, AddressError> {
        let normalized = normalize_legacy_address(s);
        let s = normalized.as_str();
        let (network, payload) = if let Some(rest) = s.strip_prefix(MAINNET_PREFIX) {
            (Network::Mainnet, rest)
        } else if let Some(rest) = s.strip_prefix(TESTNET_PREFIX) {
            (Network::Testnet, rest)
        } else {
            return Err(AddressError::BadPrefix);
        };

        // Payload is hex of 20-byte hash + 4-byte checksum = 48 hex chars.
        if payload.len() != 48 {
            return Err(AddressError::BadLength { got: payload.len(), expected: 48 });
        }

        let bytes = hex::decode(payload).map_err(|_| AddressError::BadHex)?;
        if bytes.len() != 24 {
            return Err(AddressError::BadLength { got: bytes.len(), expected: 24 });
        }

        let mut hash = [0u8; 20];
        hash.copy_from_slice(&bytes[..20]);
        let expected_checksum = &bytes[20..24];

        // Verify checksum: SHA3-256(SHA3-256(hash))[0..4]
        let inner = Sha3_256::digest(&hash);
        let outer = Sha3_256::digest(&inner);
        let actual_checksum = &outer[..4];

        if expected_checksum != actual_checksum {
            return Err(AddressError::BadChecksum);
        }

        Ok(Self { hash, network })
    }

    /// Parse an address and require it to belong to `network` (CRY-7).
    ///
    /// The 4-byte checksum covers only the 20-byte hash, NOT the prefix, so
    /// `gnb1q…` and `gnb1t…` forms of the same hash both pass [`Self::parse`].
    /// Every place that turns a user-supplied address into a script_pubkey
    /// for a specific chain (node `--miner-address`, wallet recipients) must
    /// therefore compare the network explicitly; this helper does that.
    ///
    /// Residual risk (documented, unchanged for interoperability): the
    /// checksum format itself is not network-bound, so a prefix typo between
    /// gnb1q and gnb1t is not caught by the checksum. It is caught by this
    /// network comparison wherever the expected network is known; binding the
    /// prefix into the checksum (bech32m-style) needs a new address version.
    pub fn parse_for_network(s: &str, network: Network) -> Result<Self, AddressError> {
        let address = Self::parse(s)?;
        if address.network != network {
            return Err(AddressError::WrongNetwork { expected: network, got: address.network });
        }
        Ok(address)
    }

    /// The 20-byte pubkey hash (for storage, script_pubkey, etc.)
    pub fn hash(&self) -> &[u8; 20] {
        &self.hash
    }

    /// Network enum.
    pub fn network(&self) -> Network {
        self.network
    }

    /// Is this a mainnet address?
    pub fn is_mainnet(&self) -> bool {
        matches!(self.network, Network::Mainnet)
    }

    /// Is this a testnet address?
    pub fn is_testnet(&self) -> bool {
        matches!(self.network, Network::Testnet)
    }

}

/// User-facing string form with checksum: `prefix ‖ hex(hash ‖ SHA3d(hash)[..4])`.
///
/// This is the ONE definition of the address string. It used to live in an
/// inherent `to_string(&self)` that `Display` called, which shadowed the
/// blanket `ToString` impl (clippy `inherent_to_string_shadow_display`, a
/// deny-level lint that the CI clippy gate stops on). `addr.to_string()`
/// still works everywhere and produces byte-identical output, now through
/// `Display`.
impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = Sha3_256::digest(&self.hash);
        let outer = Sha3_256::digest(&inner);
        let checksum = &outer[..4];
        let mut payload = self.hash.to_vec();
        payload.extend_from_slice(checksum);
        write!(f, "{}{}", self.network.prefix(), hex::encode(&payload))
    }
}

impl std::str::FromStr for Address {
    type Err = AddressError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AddressError {
    #[error("invalid prefix (expected gnb1q or gnb1t)")]
    BadPrefix,
    #[error("invalid length: got {got} chars, expected {expected}")]
    BadLength { got: usize, expected: usize },
    #[error("invalid hex encoding")]
    BadHex,
    #[error("checksum mismatch")]
    BadChecksum,
    #[error("address is for {got:?}, expected {expected:?}")]
    WrongNetwork { expected: Network, got: Network },
}

// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;

    #[test]
    fn roundtrip_pubkey_address() {
        let (pk, _) = crypto::generate_keypair();
        let addr = Address::from_pubkey(&pk, Network::Mainnet);
        let as_str = addr.to_string();
        let parsed = Address::parse(&as_str).unwrap();
        assert_eq!(addr, parsed);
    }

    #[test]
    fn mainnet_address_starts_with_gnb1q() {
        let addr = Address::from_hash([0u8; 20], Network::Mainnet);
        assert!(addr.to_string().starts_with("gnb1q"));
    }

    #[test]
    fn testnet_address_starts_with_gnb1t() {
        let addr = Address::from_hash([0u8; 20], Network::Testnet);
        assert!(addr.to_string().starts_with("gnb1t"));
    }

    #[test]
    fn parse_rejects_bad_prefix() {
        let result = Address::parse("bc1qabc123");
        assert!(matches!(result, Err(AddressError::BadPrefix)));
    }

    #[test]
    fn parse_rejects_bad_checksum() {
        let mut addr_str = Address::from_hash([0u8; 20], Network::Mainnet).to_string();
        // Flip one char of the checksum
        let last = addr_str.len() - 1;
        let new_char = if addr_str.as_bytes()[last] == b'0' { '1' } else { '0' };
        addr_str.replace_range(last..last+1, &new_char.to_string());
        let result = Address::parse(&addr_str);
        assert!(matches!(result, Err(AddressError::BadChecksum)));
    }

    #[test]
    fn parse_rejects_bad_length() {
        let result = Address::parse("gnb1qshort");
        assert!(matches!(result, Err(AddressError::BadLength { .. })));
    }

    #[test]
    fn parse_for_network_rejects_the_other_prefix_with_a_valid_checksum() {
        let main = Address::from_hash([0x42; 20], Network::Mainnet).to_string();
        let swapped = main.replacen("gnb1q", "gnb1t", 1);
        // The checksum does not cover the prefix (documented residual risk)...
        assert!(Address::parse(&swapped).is_ok());
        // ...so callers that know their network must reject the swap.
        assert_eq!(
            Address::parse_for_network(&swapped, Network::Mainnet),
            Err(AddressError::WrongNetwork { expected: Network::Mainnet, got: Network::Testnet }),
        );
        assert!(Address::parse_for_network(&main, Network::Mainnet).is_ok());
        assert!(Address::parse_for_network(&swapped, Network::Testnet).is_ok());
    }

    #[test]
    fn treasury_address_parses() {
        // Treasury vault address (genesis-locked, see TOKENOMICS_V1.md §8)
        let s = "gnb1q89747fe8bda0f0fbad1f107d9852bb5523d446e0db89ce31";
        let addr = Address::parse(s).unwrap();
        assert!(addr.is_mainnet());
        assert_eq!(addr.to_string(), s);
    }

    #[test]
    fn policy_address_roundtrips_and_binds_the_network() {
        use crate::core::policy::SpendPolicy;
        let keys: Vec<Vec<u8>> = (0..2).map(|_| crate::crypto::generate_keypair().0).collect();
        let p = SpendPolicy::new(2, keys, 0, 0).unwrap();
        let main = PolicyAddress::from_policy(&p, Network::Mainnet);
        let s = main.to_string();
        assert!(s.starts_with("gnb1m") && s.len() == 5 + 72);
        assert_eq!(PolicyAddress::parse(&s).unwrap(), main);
        assert_eq!(destination_script(&s).unwrap(), (Network::Mainnet, p.script_pubkey()));
        // Same hash and checksum under the testnet prefix: refused.
        let swapped = s.replacen("gnb1m", "gnb1n", 1);
        assert_eq!(PolicyAddress::parse(&swapped), Err(AddressError::BadChecksum));
        // One flipped hex digit: refused.
        let mut bad = s.clone().into_bytes();
        bad[10] = if bad[10] == b'0' { b'1' } else { b'0' };
        assert!(PolicyAddress::parse(std::str::from_utf8(&bad).unwrap()).is_err());
    }

    /// CRY-7: the network-bound decoders accept exactly their own network,
    /// for single-key and policy addresses alike.
    #[test]
    fn destination_script_for_network_refuses_the_other_network() {
        use crate::core::policy::SpendPolicy;
        let single = |n| Address::from_hash([3u8; 20], n).to_string();
        assert_eq!(destination_script_for_network(&single(Network::Mainnet), Network::Mainnet), Ok(vec![3u8; 20]));
        assert_eq!(destination_script_for_network(&single(Network::Testnet), Network::Mainnet),
                   Err(AddressError::WrongNetwork { expected: Network::Mainnet, got: Network::Testnet }));
        let keys: Vec<Vec<u8>> = (0..2).map(|_| crate::crypto::generate_keypair().0).collect();
        let p = SpendPolicy::new(1, keys, 0, 0).unwrap();
        let policy = |n| PolicyAddress::from_policy(&p, n).to_string();
        assert_eq!(destination_script_for_network(&policy(Network::Testnet), Network::Testnet), Ok(p.script_pubkey()));
        assert_eq!(destination_script_for_network(&policy(Network::Testnet), Network::Mainnet),
                   Err(AddressError::WrongNetwork { expected: Network::Mainnet, got: Network::Testnet }));
        assert_eq!(PolicyAddress::parse_for_network(&policy(Network::Mainnet), Network::Testnet),
                   Err(AddressError::WrongNetwork { expected: Network::Testnet, got: Network::Mainnet }));
        assert!(destination_script_for_network("gnb1zzz", Network::Mainnet).is_err());
        for n in [Network::Mainnet, Network::Testnet] {
            assert_eq!(Network::for_chain(crate::core::ChainId::for_network(n)), n);
        }
    }

    #[test]
    fn destination_script_accepts_single_key_addresses() {
        let a = Address::from_hash([7u8; 20], Network::Testnet);
        assert_eq!(destination_script(&a.to_string()).unwrap(), (Network::Testnet, vec![7u8; 20]));
        assert!(destination_script("gnb1zzz").is_err());
    }
}
