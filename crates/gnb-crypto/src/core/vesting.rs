//! Locked team and founder allocations in the genesis ledger.
//!
//! Each allocation (`tokenomics::TEAM_ALLOCATION_SAT`,
//! `tokenomics::FOUNDER_ALLOCATION_SAT`) is written into the genesis ledger
//! as [`VESTING_TRANCHES`] outputs. Tranche `k` pays to a spend policy
//! (`core::policy`) over the beneficiary's keys with the absolute timelock
//! `after = vesting_unlock_height(k)`: 1 year with nothing spendable, then one
//! tranche per month for 3 years. Before its height a tranche cannot be spent
//! by anyone, the beneficiary included — the lock is a consensus rule.
//!
//! - Founder: one key (1-of-1).
//! - Team: an m-of-n multisig.
//!
//! The keys live in `genesis/vesting.json` (embedded at build time). Its
//! SHA3-256 is the consensus constant [`VESTING_SPEC_SHA3`]: changing the
//! keys is a deliberate two-place edit and a new chain. While the file is
//! `pending`, no genesis ledger can be created and nodes refuse to start.
//!
//! The outputs have synthetic outpoints (no transaction creates them, like the
//! carryover): `txid = SHA3-256("GNB-VESTING-v1" ‖ role ‖ k ‖ policy hash)`,
//! `vout = 0`.

use serde::Deserialize;
use sha3::{Digest, Sha3_256};

use super::policy::SpendPolicy;
use super::tokenomics::{
    vesting_tranche_value, vesting_unlock_height, FOUNDER_ALLOCATION_SAT, TEAM_ALLOCATION_SAT,
    VESTING_TRANCHES,
};
use super::TxOutput;

/// The embedded key specification.
pub const VESTING_SPEC: &str = include_str!("../../genesis/vesting.json");

/// SHA3-256 of [`VESTING_SPEC`]; must match (checked before any use).
pub const VESTING_SPEC_SHA3: [u8; 32] = [
    0xe2, 0x48, 0x28, 0xc3, 0xcc, 0x6d, 0x56, 0xfe, 0x63, 0x55, 0x81, 0xb8, 0x21, 0x4a, 0xf8, 0x73,
    0x3f, 0x4b, 0x06, 0x07, 0x84, 0xd1, 0x3b, 0xd9, 0x2f, 0x2d, 0x55, 0x89, 0x40, 0xd9, 0x0d, 0x20,
];

const DOMAIN: &[u8] = b"GNB-VESTING-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Founder,
    Team,
}

impl Role {
    fn tag(self) -> u8 {
        match self {
            Role::Founder => b'F',
            Role::Team => b'T',
        }
    }
    pub fn allocation(self) -> u64 {
        match self {
            Role::Founder => FOUNDER_ALLOCATION_SAT,
            Role::Team => TEAM_ALLOCATION_SAT,
        }
    }
}

/// One locked output of the genesis ledger.
#[derive(Debug, Clone)]
pub struct Tranche {
    pub role: Role,
    /// 1-based tranche number.
    pub k: u32,
    pub unlock_height: u64,
    pub policy: SpendPolicy,
    pub txid: [u8; 32],
    pub vout: u32,
    pub output: TxOutput,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SpecFile {
    founder: String,
    team: TeamSpec,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TeamSpec {
    threshold: u8,
    pubkeys: Vec<String>,
}

/// Parsed beneficiaries: founder key, team threshold and keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VestingKeys {
    pub founder: Vec<u8>,
    pub team_threshold: u8,
    pub team: Vec<Vec<u8>>,
}

/// Parse a specification (`{"founder": hex, "team": {"threshold": m, "pubkeys": [hex…]}}`).
pub fn parse_spec(text: &str) -> Result<VestingKeys, String> {
    let f: SpecFile = serde_json::from_str(text)
        .map_err(|e| format!("vesting spec is not configured or malformed: {}", e))?;
    let hex_key = |h: &str| hex::decode(h.trim()).map_err(|_| "vesting spec: key is not hex".to_string());
    let keys = VestingKeys {
        founder: hex_key(&f.founder)?,
        team_threshold: f.team.threshold,
        team: f.team.pubkeys.iter().map(|k| hex_key(k)).collect::<Result<_, _>>()?,
    };
    // Validate both policies once (hybrid keys, distinct, sane threshold).
    SpendPolicy::new(1, vec![keys.founder.clone()], 1, 0).map_err(|e| format!("founder key: {}", e))?;
    SpendPolicy::new(keys.team_threshold, keys.team.clone(), 1, 0).map_err(|e| format!("team policy: {}", e))?;
    if keys.team.contains(&keys.founder) {
        return Err("the founder key must not also be a team key".into());
    }
    Ok(keys)
}

/// All locked outputs for `keys`: 36 founder tranches, then 36 team tranches.
pub fn tranches(keys: &VestingKeys) -> Result<Vec<Tranche>, String> {
    let mut out = Vec::with_capacity(2 * VESTING_TRANCHES as usize);
    for role in [Role::Founder, Role::Team] {
        for k in 1..=VESTING_TRANCHES {
            let unlock_height = vesting_unlock_height(k);
            let after = u32::try_from(unlock_height).map_err(|_| "unlock height exceeds u32")?;
            let policy = match role {
                Role::Founder => SpendPolicy::new(1, vec![keys.founder.clone()], after, 0),
                Role::Team => SpendPolicy::new(keys.team_threshold, keys.team.clone(), after, 0),
            }.map_err(|e| format!("{:?} tranche {}: {}", role, k, e))?;
            let mut h = Sha3_256::new();
            h.update(DOMAIN);
            h.update([role.tag()]);
            h.update(k.to_le_bytes());
            h.update(policy.hash());
            let txid: [u8; 32] = h.finalize().into();
            let output = TxOutput {
                value: vesting_tranche_value(role.allocation(), k),
                script_pubkey: policy.script_pubkey(),
            };
            out.push(Tranche { role, k, unlock_height, policy, txid, vout: 0, output });
        }
    }
    Ok(out)
}

/// The consensus locked outputs from the embedded specification, after
/// checking it against [`VESTING_SPEC_SHA3`].
pub fn genesis_tranches() -> Result<Vec<Tranche>, String> {
    let digest: [u8; 32] = Sha3_256::digest(VESTING_SPEC.as_bytes()).into();
    if digest != VESTING_SPEC_SHA3 {
        return Err("genesis/vesting.json does not match VESTING_SPEC_SHA3".into());
    }
    tranches(&parse_spec(VESTING_SPEC)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::tokenomics::{FOUNDER_ALLOCATION_SAT, TEAM_ALLOCATION_SAT};

    fn spec_json(founder: &[u8], m: u8, team: &[Vec<u8>]) -> String {
        serde_json::json!({
            "founder": hex::encode(founder),
            "team": { "threshold": m, "pubkeys": team.iter().map(hex::encode).collect::<Vec<_>>() },
        }).to_string()
    }

    #[test]
    fn embedded_spec_matches_its_consensus_hash() {
        let digest: [u8; 32] = Sha3_256::digest(VESTING_SPEC.as_bytes()).into();
        assert_eq!(digest, VESTING_SPEC_SHA3, "update VESTING_SPEC_SHA3 together with genesis/vesting.json");
    }

    #[test]
    fn tranches_lock_every_unit_of_both_allocations() {
        let founder = crate::crypto::generate_keypair().0;
        let team: Vec<Vec<u8>> = (0..3).map(|_| crate::crypto::generate_keypair().0).collect();
        let keys = parse_spec(&spec_json(&founder, 2, &team)).unwrap();
        let t = tranches(&keys).unwrap();
        assert_eq!(t.len(), 72);
        let sum = |r: Role| t.iter().filter(|x| x.role == r).map(|x| x.output.value).sum::<u64>();
        assert_eq!(sum(Role::Founder), FOUNDER_ALLOCATION_SAT);
        assert_eq!(sum(Role::Team), TEAM_ALLOCATION_SAT);
        for x in &t {
            assert_eq!(x.policy.after as u64, x.unlock_height, "locked until its height");
            assert!(x.unlock_height > 1_051_200, "nothing unlocks in the first year");
            assert_eq!(x.output.script_pubkey, x.policy.script_pubkey());
            match x.role {
                Role::Founder => assert_eq!((x.policy.threshold, x.policy.pubkeys.len()), (1, 1)),
                Role::Team => assert_eq!((x.policy.threshold, x.policy.pubkeys.len()), (2, 3)),
            }
        }
        let mut ids: Vec<_> = t.iter().map(|x| x.txid).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 72, "outpoints are distinct");
    }

    #[test]
    fn malformed_or_unsafe_specs_are_refused() {
        let founder = crate::crypto::generate_keypair().0;
        let team: Vec<Vec<u8>> = (0..3).map(|_| crate::crypto::generate_keypair().0).collect();
        assert!(parse_spec(r#"{"status":"pending"}"#).is_err());
        assert!(parse_spec(&spec_json(&founder, 4, &team)).is_err(), "threshold above n");
        assert!(parse_spec(&spec_json(&founder, 0, &team)).is_err(), "zero threshold");
        assert!(parse_spec(&spec_json(&team[0], 2, &team)).is_err(), "founder inside the team");
        let mut short = founder.clone();
        short.truncate(100);
        assert!(parse_spec(&spec_json(&short, 2, &team)).is_err(), "not a hybrid key");
    }

    #[test]
    fn genesis_coinbase_commits_to_the_keys() {
        assert!(crate::core::GENESIS_COINBASE_TEXT.contains(&hex::encode(VESTING_SPEC_SHA3)),
                "re-mine the genesis after changing genesis/vesting.json");
    }

    #[test]
    fn pending_spec_blocks_genesis() {
        // The shipped file is still pending: no genesis ledger can be built.
        if VESTING_SPEC.contains("\"pending\"") {
            assert!(genesis_tranches().is_err());
        }
    }
}
