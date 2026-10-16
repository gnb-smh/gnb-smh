//! GnB side of the Bloch bridge v1: vault, lock and release shapes.
//!
//! See `docs/SIDECHAIN-BLOCH.md`. Pure functions: the signer program and
//! `gnb-cli` use them so that what a signer checks is exactly what the tools
//! build. Nothing here is a consensus rule; the vault is an ordinary policy
//! tree output (consensus from `core::powit_height()`).
//!
//! Invariant: a lock adds exactly `amount` to the vault, and a release
//! removes exactly the burned amount (payout + marker + fee), so the vault's
//! balance tracks the wGnB supply.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::address::Network;
use crate::core::policy::{PolicyTree, SpendPolicy};
use crate::core::{TxOutput, DUST_THRESHOLD};

/// Value of a marker output (destination on a lock, burn id on a release).
pub const MARKER_VALUE: u64 = DUST_THRESHOLD;
/// Largest fee a release may take out of the burned amount (0.01 GNB).
pub const MAX_RELEASE_FEE: u64 = 1_000_000;
/// Branch indices of a vault tree.
pub const RELEASE_BRANCH: u8 = 0;
pub const RECOVERY_BRANCH: u8 = 1;

const DS_RELEASE: &[u8] = b"GNB-RELEASE-v1";

/// A vault definition, fixed once at deployment and published.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vault {
    pub version: u32,
    pub network: String,
    /// `PolicyTree::encode()`, hex.
    pub tree: String,
    /// Output script (hex) and address of the vault.
    pub script: String,
    pub address: String,
    pub release_threshold: u8,
    pub signers: usize,
    pub recovery_threshold: u8,
    pub recovery_keys: usize,
    /// Relative timelock (blocks) on the recovery branch.
    pub recovery_older: u32,
}

impl Vault {
    /// Branch 0: `k`-of-signers, no timelock. Branch 1: `r`-of-recovery,
    /// spendable `older` blocks after each deposit confirmed.
    pub fn create(network: Network, k: u8, signers: Vec<Vec<u8>>, r: u8, recovery: Vec<Vec<u8>>, older: u32)
        -> Result<Self, String>
    {
        if older == 0 {
            return Err("the recovery branch needs a relative timelock (older > 0)".into());
        }
        let n = signers.len();
        let s = recovery.len();
        let release = SpendPolicy::new(k, signers, 0, 0).map_err(|e| format!("release branch: {e}"))?;
        let recover = SpendPolicy::new(r, recovery, 0, older).map_err(|e| format!("recovery branch: {e}"))?;
        if release.pubkeys.iter().any(|p| recover.pubkeys.contains(p)) {
            return Err("a key may not be both a signer and a recovery key".into());
        }
        let tree = PolicyTree::new(vec![release, recover]).map_err(|e| format!("tree: {e}"))?;
        let script = tree.script_pubkey();
        let address = crate::address::PolicyAddress::from_script(&script, network)
            .map(|a| a.to_string())
            .ok_or("vault script is not a policy script")?;
        Ok(Vault {
            version: 1,
            network: match network { Network::Mainnet => "mainnet", Network::Testnet => "testnet" }.into(),
            tree: hex::encode(tree.encode()),
            script: hex::encode(&script),
            address,
            release_threshold: k,
            signers: n,
            recovery_threshold: r,
            recovery_keys: s,
            recovery_older: older,
        })
    }

    pub fn network(&self) -> Network {
        if self.network == "mainnet" { Network::Mainnet } else { Network::Testnet }
    }

    /// The policy tree, checked against the published script.
    pub fn tree(&self) -> Result<PolicyTree, String> {
        let tree = PolicyTree::decode(&hex::decode(&self.tree).map_err(|_| "vault tree hex")?)
            .map_err(|e| format!("vault tree: {e}"))?;
        if hex::encode(tree.script_pubkey()) != self.script {
            return Err("vault tree does not match its published script".into());
        }
        Ok(tree)
    }

    pub fn script(&self) -> Result<Vec<u8>, String> {
        hex::decode(&self.script).map_err(|_| "vault script hex".into())
    }
}

/// A lock found in a transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lock {
    /// Base units added to the vault (output 0).
    pub amount: u64,
    /// L2 (EVM) recipient, from the marker in output 1.
    pub l2_recipient: [u8; 20],
}

/// Outputs of a lock transaction (change is appended by the wallet).
pub fn lock_outputs(vault_script: &[u8], amount: u64, l2_recipient: [u8; 20]) -> Vec<TxOutput> {
    vec![
        TxOutput { value: amount, script_pubkey: vault_script.to_vec() },
        TxOutput { value: MARKER_VALUE, script_pubkey: l2_recipient.to_vec() },
    ]
}

/// Parse a lock from a transaction's outputs, exact shape only: output 0
/// pays the vault, output 1 is the 20-byte destination marker worth exactly
/// `MARKER_VALUE` (not all zero), and no other output pays the vault.
pub fn parse_lock(outputs: &[TxOutput], vault_script: &[u8], min_amount: u64) -> Result<Lock, String> {
    let o0 = outputs.first().ok_or("no outputs")?;
    let o1 = outputs.get(1).ok_or("no destination marker (output 1)")?;
    if o0.script_pubkey != vault_script {
        return Err("output 0 does not pay the vault".into());
    }
    if o0.value < min_amount {
        return Err(format!("lock amount {} below the minimum {}", o0.value, min_amount));
    }
    if o1.script_pubkey.len() != 20 || o1.value != MARKER_VALUE {
        return Err("output 1 is not a destination marker (20 bytes, exactly 546)".into());
    }
    if o1.script_pubkey.iter().all(|b| *b == 0) {
        return Err("destination marker is the zero address".into());
    }
    if outputs.iter().skip(2).any(|o| o.script_pubkey == vault_script) {
        return Err("more than one output pays the vault".into());
    }
    let mut l2 = [0u8; 20];
    l2.copy_from_slice(&o1.script_pubkey);
    Ok(Lock { amount: o0.value, l2_recipient: l2 })
}

/// The 20-byte marker a release carries for `burn_id`.
pub fn release_marker(burn_id: &[u8; 32]) -> [u8; 20] {
    let mut h = Sha3_256::new();
    h.update(DS_RELEASE);
    h.update(burn_id);
    let d = h.finalize();
    let mut m = [0u8; 20];
    m.copy_from_slice(&d[..20]);
    m
}

/// The fixed outputs of a release paying `payout` to `recipient` for
/// `burn_id` (change to the vault is appended by `PolicySpend::new_branch`).
pub fn release_outputs(recipient: &[u8], payout: u64, burn_id: &[u8; 32]) -> Vec<TxOutput> {
    vec![
        TxOutput { value: payout, script_pubkey: recipient.to_vec() },
        TxOutput { value: MARKER_VALUE, script_pubkey: release_marker(burn_id).to_vec() },
    ]
}

/// What a signer checks before co-signing a release. `inputs` are the
/// spent outputs (value, script) as read from the signer's own node.
pub fn check_release(
    tx_outputs: &[TxOutput],
    inputs: &[(u64, Vec<u8>)],
    vault_script: &[u8],
    recipient: &[u8],
    burn_amount: u64,
    burn_id: &[u8; 32],
) -> Result<u64, String> {
    if inputs.is_empty() {
        return Err("no inputs".into());
    }
    if inputs.iter().any(|(_, s)| s != vault_script) {
        return Err("an input is not a vault output".into());
    }
    let n = tx_outputs.len();
    if !(2..=3).contains(&n) {
        return Err("a release has exactly 2 or 3 outputs".into());
    }
    let payout = &tx_outputs[0];
    let marker = &tx_outputs[1];
    if payout.script_pubkey != recipient {
        return Err("output 0 does not pay the burn's recipient".into());
    }
    if marker.script_pubkey != release_marker(burn_id) || marker.value != MARKER_VALUE {
        return Err("output 1 is not this burn's marker".into());
    }
    if n == 3 && tx_outputs[2].script_pubkey != vault_script {
        return Err("output 2 (change) does not return to the vault".into());
    }
    let in_total = inputs.iter().try_fold(0u64, |t, (v, _)| t.checked_add(*v)).ok_or("input overflow")?;
    let out_total = tx_outputs.iter().try_fold(0u64, |t, o| t.checked_add(o.value)).ok_or("output overflow")?;
    let fee = in_total.checked_sub(out_total).ok_or("outputs exceed inputs")?;
    if fee > MAX_RELEASE_FEE {
        return Err(format!("fee {fee} above the maximum {MAX_RELEASE_FEE}"));
    }
    // The vault loses exactly the burned amount: payout + marker + fee.
    let taken = payout.value.checked_add(MARKER_VALUE).and_then(|v| v.checked_add(fee)).ok_or("overflow")?;
    if taken != burn_amount {
        return Err(format!("release takes {taken} from the vault, the burn was {burn_amount}"));
    }
    Ok(fee)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;

    fn vault() -> (Vault, Vec<(Vec<u8>, Vec<u8>)>, Vec<(Vec<u8>, Vec<u8>)>) {
        let signers: Vec<_> = (0..3).map(|_| crypto::generate_keypair()).collect();
        let cold: Vec<_> = (0..2).map(|_| crypto::generate_keypair()).collect();
        let v = Vault::create(Network::Testnet, 2, signers.iter().map(|k| k.0.clone()).collect(),
                              1, cold.iter().map(|k| k.0.clone()).collect(), 1_000).unwrap();
        (v, signers, cold)
    }

    #[test]
    fn vault_roundtrips_and_refuses_bad_definitions() {
        let (v, signers, _) = vault();
        let t = v.tree().unwrap();
        assert_eq!(t.branches[0].threshold, 2);
        assert_eq!(t.branches[1].older, 1_000);
        assert!(v.address.starts_with("gnb1"));
        let mut tampered = v.clone();
        tampered.script = hex::encode([2u8; 33]);
        assert!(tampered.tree().is_err(), "published script must match the tree");
        let k: Vec<Vec<u8>> = signers.iter().map(|k| k.0.clone()).collect();
        assert!(Vault::create(Network::Testnet, 2, k.clone(), 1, vec![k[0].clone()], 10).is_err(), "shared key");
        assert!(Vault::create(Network::Testnet, 2, k.clone(), 1, vec![crypto::generate_keypair().0], 0).is_err(),
                "recovery needs older");
    }

    #[test]
    fn lock_shape_is_exact() {
        let (v, _, _) = vault();
        let vs = v.script().unwrap();
        let l2 = [0xAB; 20];
        let good = lock_outputs(&vs, 5_000_000, l2);
        assert_eq!(parse_lock(&good, &vs, 1_000_000).unwrap(), Lock { amount: 5_000_000, l2_recipient: l2 });
        let mut with_change = good.clone();
        with_change.push(TxOutput { value: 9_999, script_pubkey: vec![1; 20] });
        assert!(parse_lock(&with_change, &vs, 0).is_ok());
        // Every deviation is refused.
        assert!(parse_lock(&good, &vs, 6_000_000).is_err(), "below minimum");
        let mut b = good.clone(); b[1].value = 547;
        assert!(parse_lock(&b, &vs, 0).is_err(), "marker value");
        let mut b = good.clone(); b[1].script_pubkey = vec![1; 33];
        assert!(parse_lock(&b, &vs, 0).is_err(), "marker size");
        let mut b = good.clone(); b[1].script_pubkey = vec![0; 20];
        assert!(parse_lock(&b, &vs, 0).is_err(), "zero address");
        let b = vec![good[1].clone(), good[0].clone()];
        assert!(parse_lock(&b, &vs, 0).is_err(), "vault not first");
        let mut b = good.clone(); b.push(good[0].clone());
        assert!(parse_lock(&b, &vs, 0).is_err(), "second vault output");
    }

    #[test]
    fn release_check_enforces_shape_and_exact_burn() {
        let (v, _, _) = vault();
        let vs = v.script().unwrap();
        let burn = [7u8; 32];
        let recipient = vec![0x11; 20];
        let fee = 70_000;
        let burn_amount = 3_000_000;
        let payout = burn_amount - MARKER_VALUE - fee;
        let mut outs = release_outputs(&recipient, payout, &burn);
        outs.push(TxOutput { value: 10_000_000 - burn_amount, script_pubkey: vs.clone() });
        let inputs = vec![(10_000_000u64, vs.clone())];
        assert_eq!(check_release(&outs, &inputs, &vs, &recipient, burn_amount, &burn), Ok(fee));
        // Wrong burn, recipient, amount, foreign input, change elsewhere, big fee.
        assert!(check_release(&outs, &inputs, &vs, &recipient, burn_amount, &[8u8; 32]).is_err());
        assert!(check_release(&outs, &inputs, &vs, &[0x22; 20], burn_amount, &burn).is_err());
        assert!(check_release(&outs, &inputs, &vs, &recipient, burn_amount + 1, &burn).is_err());
        assert!(check_release(&outs, &[(10_000_000, vec![5; 20])], &vs, &recipient, burn_amount, &burn).is_err());
        let mut b = outs.clone(); b[2].script_pubkey = vec![3; 20];
        assert!(check_release(&b, &inputs, &vs, &recipient, burn_amount, &burn).is_err());
        let mut b = outs.clone(); b[2].value -= 2_000_000;
        assert!(check_release(&b, &inputs, &vs, &recipient, burn_amount, &burn).is_err(), "fee too high");
        assert_ne!(release_marker(&burn), release_marker(&[8u8; 32]));
    }
}
