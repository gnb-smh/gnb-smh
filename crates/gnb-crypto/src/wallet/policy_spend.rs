//! Multi-party spending from a policy address (multisig / timelocks).
//!
//! Flow, each step on the machine that holds what it needs:
//!
//! 1. [`PolicySpend::new`] — anyone: picks the outputs, fixes amount, change
//!    (back to the policy) and a fee that covers the largest possible witness,
//!    and produces an unsigned spend.
//! 2. [`PolicySpend::sign`] — each signer, with their own keystore: adds a
//!    signature for every input. The secret key never leaves that machine;
//!    only the spend file travels.
//! 3. [`PolicySpend::finalize`] — anyone: once `threshold` signers have
//!    signed, builds the witnesses and returns the broadcastable transaction.
//!
//! The transaction (and so every sighash) is fixed at step 1; signatures
//! cannot be applied to a different transaction.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::address::Network;
use crate::core::policy::{PolicyWitness, SpendPolicy};
use crate::core::{self, ChainId, Transaction, TxInput, TxOutput};
use crate::crypto;

/// An in-progress spend from one policy.
#[derive(Debug, Clone)]
pub struct PolicySpend {
    pub network: Network,
    pub policy: SpendPolicy,
    pub tx: Transaction,
    /// Per input: key index → signature.
    pub signatures: Vec<BTreeMap<u8, Vec<u8>>>,
}

#[derive(Serialize, Deserialize)]
struct SpendFile {
    network: String,
    policy: String,
    tx: String,
    signatures: Vec<BTreeMap<String, String>>,
}

/// Upper bound on a policy witness (sets the fee before anyone signs).
pub fn max_witness_size(policy: &SpendPolicy) -> usize {
    1 + 4 + policy.encode().len() + 1 + policy.threshold as usize * (1 + 4 + core::SIG_SIZE)
}

impl PolicySpend {
    /// Unsigned spend of `inputs` (`(txid, vout, value)`, all locked by
    /// `policy`) paying `amount` to `to_script`, change back to the policy.
    /// The fee is raised to the consensus minimum for the largest possible
    /// witnesses; sub-dust change is left to the fee.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        network: Network,
        policy: SpendPolicy,
        inputs: &[([u8; 32], u32, u64)],
        to_script: Vec<u8>,
        amount: u64,
        fee: u64,
        locktime: u32,
    ) -> Result<Self, String> {
        if inputs.is_empty() {
            return Err("no inputs".into());
        }
        if core::policy::output_kind(&to_script).is_none() {
            return Err("unsupported destination script".into());
        }
        if amount < core::DUST_THRESHOLD {
            return Err(format!("amount below the dust threshold ({} base units)", core::DUST_THRESHOLD));
        }
        if policy.after != 0 && locktime < policy.after {
            return Err(format!("policy is time-locked until height {}: set locktime ≥ {}", policy.after, policy.after));
        }
        let total = inputs.iter().try_fold(0u64, |t, (_, _, v)| t.checked_add(*v))
            .ok_or("input total overflows")?;
        let mut tx = Transaction {
            version: 1,
            inputs: inputs.iter().map(|(txid, vout, _)| TxInput {
                prev_txid: *txid, prev_index: *vout, script_sig: Vec::new(), sequence: u32::MAX,
            }).collect(),
            outputs: vec![
                TxOutput { value: amount, script_pubkey: to_script },
                TxOutput { value: 0, script_pubkey: policy.script_pubkey() },
            ],
            locktime,
        };
        // Size with the largest possible witnesses → minimum fee.
        let witness_upper = max_witness_size(&policy) * inputs.len();
        let size = tx.to_wire_bytes(true).len() + witness_upper;
        let fee = fee.max(core::tokenomics::min_tx_fee_sat(size));
        let change = total.checked_sub(amount).and_then(|r| r.checked_sub(fee))
            .ok_or_else(|| format!("insufficient funds: {} available, {} + fee {} needed", total, amount, fee))?;
        if change >= core::DUST_THRESHOLD {
            tx.outputs[1].value = change;
        } else {
            tx.outputs.pop(); // sub-dust change goes to the fee
        }
        Ok(Self { network, policy, tx, signatures: vec![BTreeMap::new(); inputs.len()] })
    }

    pub fn chain_id(&self) -> ChainId {
        ChainId::for_network(self.network)
    }

    /// Fee this spend pays (needs the input values it was built from).
    pub fn outputs_total(&self) -> u64 {
        self.tx.outputs.iter().map(|o| o.value).sum()
    }

    /// Add `public_key`'s signature (made by `sign`) to every input.
    /// Returns the key's index in the policy.
    pub fn sign(
        &mut self,
        public_key: &[u8],
        sign: impl Fn(&[u8]) -> Result<Vec<u8>, String>,
    ) -> Result<u8, String> {
        let idx = self.policy.pubkeys.iter().position(|k| k == public_key)
            .ok_or("this key is not part of the policy")? as u8;
        let chain_id = self.chain_id();
        for i in 0..self.tx.inputs.len() {
            let sighash = self.tx.sighash(i, chain_id);
            let sig = sign(&sighash)?;
            if !crypto::verify_enveloped_canonical(public_key, &sighash, &sig) {
                return Err("produced signature does not verify (wrong key or non-canonical encoding)".into());
            }
            self.signatures[i].insert(idx, sig);
        }
        Ok(idx)
    }

    /// Distinct signers that signed every input.
    pub fn signers(&self) -> Vec<u8> {
        let mut common: Option<Vec<u8>> = None;
        for m in &self.signatures {
            let keys: Vec<u8> = m.keys().copied().collect();
            common = Some(match common {
                None => keys,
                Some(c) => c.into_iter().filter(|k| keys.contains(k)).collect(),
            });
        }
        common.unwrap_or_default()
    }

    /// Build the witnesses from the `threshold` lowest-indexed signers.
    pub fn finalize(&self) -> Result<Transaction, String> {
        let need = self.policy.threshold as usize;
        let signers = self.signers();
        if signers.len() < need {
            return Err(format!("{} of {} required signatures", signers.len(), need));
        }
        let chosen = &signers[..need];
        let mut tx = self.tx.clone();
        let chain_id = self.chain_id();
        for (i, input) in tx.inputs.iter_mut().enumerate() {
            let sighash = self.tx.sighash(i, chain_id);
            let mut signatures = Vec::with_capacity(need);
            for k in chosen {
                let sig = self.signatures[i][k].clone();
                if !crypto::verify_enveloped_canonical(&self.policy.pubkeys[*k as usize], &sighash, &sig) {
                    return Err(format!("signature of key {} on input {} does not verify", k, i));
                }
                signatures.push((*k, sig));
            }
            input.script_sig = PolicyWitness { policy: self.policy.clone(), signatures }.encode();
        }
        Ok(tx)
    }

    pub fn to_json(&self) -> Result<String, String> {
        let file = SpendFile {
            network: match self.network { Network::Mainnet => "mainnet", Network::Testnet => "testnet" }.into(),
            policy: hex::encode(self.policy.encode()),
            tx: hex::encode(self.tx.to_wire_bytes(true)),
            signatures: self.signatures.iter().map(|m| {
                m.iter().map(|(k, v)| (k.to_string(), hex::encode(v))).collect()
            }).collect(),
        };
        serde_json::to_string_pretty(&file).map_err(|e| e.to_string())
    }

    pub fn from_json(s: &str) -> Result<Self, String> {
        let f: SpendFile = serde_json::from_str(s).map_err(|e| format!("spend file: {}", e))?;
        let network = match f.network.as_str() {
            "mainnet" => Network::Mainnet,
            "testnet" => Network::Testnet,
            other => return Err(format!("unknown network {}", other)),
        };
        let policy = SpendPolicy::decode(&hex::decode(&f.policy).map_err(|_| "policy hex")?)
            .map_err(|e| format!("policy: {}", e))?;
        let tx = Transaction::from_wire_bytes(&hex::decode(&f.tx).map_err(|_| "tx hex")?)?;
        if f.signatures.len() != tx.inputs.len() {
            return Err("signature list does not match the inputs".into());
        }
        let mut signatures = Vec::with_capacity(f.signatures.len());
        for m in f.signatures {
            let mut out = BTreeMap::new();
            for (k, v) in m {
                let k: u8 = k.parse().map_err(|_| "signature key index")?;
                if k as usize >= policy.pubkeys.len() {
                    return Err("signature key index out of range".into());
                }
                out.insert(k, hex::decode(&v).map_err(|_| "signature hex")?);
            }
            signatures.push(out);
        }
        // The change output, if any, must return to this policy.
        if let Some(change) = tx.outputs.get(1) {
            if change.script_pubkey != policy.script_pubkey() {
                return Err("change output does not return to the policy".into());
            }
        }
        Ok(Self { network, policy, tx, signatures })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup(m: u8, n: usize, after: u32) -> (Vec<(Vec<u8>, Vec<u8>)>, SpendPolicy) {
        let keys: Vec<(Vec<u8>, Vec<u8>)> = (0..n).map(|_| crypto::generate_keypair()).collect();
        let policy = SpendPolicy::new(m, keys.iter().map(|k| k.0.clone()).collect(), after, 0).unwrap();
        (keys, policy)
    }

    #[test]
    fn two_of_three_flow_through_json_produces_a_valid_witness() {
        let (keys, policy) = setup(2, 3, 0);
        let spend = PolicySpend::new(Network::Testnet, policy.clone(), &[([1u8; 32], 0, 5_000_000)],
                                     vec![9u8; 20], 1_000_000, 0, 0).unwrap();
        // Signer 2, then signer 0, each on "their own machine" (via JSON).
        let mut s = PolicySpend::from_json(&spend.to_json().unwrap()).unwrap();
        assert_eq!(s.sign(&keys[2].0, |m| crypto::sign(&keys[2].1, m).map_err(|e| format!("{e:?}"))).unwrap(), 2);
        let mut s = PolicySpend::from_json(&s.to_json().unwrap()).unwrap();
        assert!(s.finalize().is_err(), "one signature is not enough");
        s.sign(&keys[0].0, |m| crypto::sign(&keys[0].1, m).map_err(|e| format!("{e:?}"))).unwrap();
        let tx = PolicySpend::from_json(&s.to_json().unwrap()).unwrap().finalize().unwrap();

        let w = PolicyWitness::decode(&tx.inputs[0].script_sig).unwrap();
        assert_eq!(w.policy, policy);
        assert_eq!(w.signatures.iter().map(|(k, _)| *k).collect::<Vec<_>>(), vec![0, 2]);
        // Change returns to the policy; fee covers the minimum for the real size.
        assert_eq!(tx.outputs[1].script_pubkey, policy.script_pubkey());
        let fee = 5_000_000 - tx.outputs.iter().map(|o| o.value).sum::<u64>();
        assert!(fee >= core::tokenomics::min_tx_fee_sat(tx.to_wire_bytes(true).len()));
    }

    #[test]
    fn an_outside_key_cannot_sign() {
        let (_keys, policy) = setup(1, 2, 0);
        let (pk, sk) = crypto::generate_keypair();
        let mut s = PolicySpend::new(Network::Mainnet, policy, &[([1u8; 32], 0, 5_000_000)],
                                     vec![9u8; 20], 1_000_000, 0, 0).unwrap();
        assert!(s.sign(&pk, |m| crypto::sign(&sk, m).map_err(|e| format!("{e:?}"))).is_err());
    }

    #[test]
    fn a_timelocked_policy_needs_a_matching_locktime() {
        let (_keys, policy) = setup(1, 1, 700);
        assert!(PolicySpend::new(Network::Mainnet, policy.clone(), &[([1u8; 32], 0, 5_000_000)],
                                 vec![9u8; 20], 1_000_000, 0, 699).is_err());
        assert!(PolicySpend::new(Network::Mainnet, policy, &[([1u8; 32], 0, 5_000_000)],
                                 vec![9u8; 20], 1_000_000, 0, 700).is_ok());
    }

    #[test]
    fn a_spend_file_with_redirected_change_is_refused() {
        let (_keys, policy) = setup(1, 2, 0);
        let s = PolicySpend::new(Network::Mainnet, policy, &[([1u8; 32], 0, 5_000_000)],
                                 vec![9u8; 20], 1_000_000, 0, 0).unwrap();
        let mut f: serde_json::Value = serde_json::from_str(&s.to_json().unwrap()).unwrap();
        let mut tx = s.tx.clone();
        tx.outputs[1].script_pubkey = vec![6u8; 20];
        f["tx"] = serde_json::Value::String(hex::encode(tx.to_wire_bytes(true)));
        assert!(PolicySpend::from_json(&f.to_string()).is_err());
    }
}
