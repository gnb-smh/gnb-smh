//! Spend policies: m-of-n multisig with absolute and relative timelocks.
//!
//! GnB has no general script language, by design: a script interpreter is
//! the largest consensus attack surface Bitcoin has. Instead there are exactly
//! two output types:
//!
//! | `script_pubkey` | Spent by |
//! | --- | --- |
//! | 20 bytes: `SHA3-256(pubkey)[..20]` | one hybrid signature (`len‖sig‖len‖pk`) |
//! | 33 bytes: `0x02 ‖ SHA3-256("GNB-POLICY-v1" ‖ policy)` | a [`PolicyWitness`] revealing the policy and `threshold` signatures |
//!
//! A [`SpendPolicy`] is:
//!
//! - `threshold`-of-`pubkeys` hybrid ML-DSA-65 ‖ Falcon-1024 keys (1 ≤ m ≤ n ≤
//!   [`MAX_POLICY_KEYS`], keys distinct, each a hybrid key);
//! - `after`: absolute timelock — spendable only by a transaction whose
//!   `locktime ≥ after`, and a transaction is only valid in a block at height
//!   `≥ locktime`. `0` = none;
//! - `older`: relative timelock — spendable only `older` blocks after the
//!   output was confirmed. `0` = none.
//!
//! Encodings are canonical and strictly parsed (fixed field order, explicit
//! lengths, no trailing bytes), so one policy has exactly one hash and one
//! witness byte string per signature set.

use sha3::{Digest, Sha3_256};

/// Maximum keys in one policy (a hybrid key is 3,749 bytes).
pub const MAX_POLICY_KEYS: usize = 7;

/// First byte of a policy `script_pubkey` and of a policy witness.
pub const POLICY_TAG: u8 = 0x02;

/// Length of a policy `script_pubkey`.
pub const POLICY_SPK_LEN: usize = 33;

/// Length of a single-key (P2PKH-style) `script_pubkey`.
pub const PKH_SPK_LEN: usize = 20;

/// Policy encoding version.
const POLICY_VERSION: u8 = 1;
const POLICY_DOMAIN: &[u8] = b"GNB-POLICY-v1";

/// Upper bound on one encoded signature (hybrid ML-DSA-65 ‖ Falcon-1024,
/// enveloped, with Falcon's variable length): generous, rejects absurd input.
const MAX_SIG_LEN: usize = 8 * 1024;
/// Upper bound on one encoded public key.
const MAX_PK_LEN: usize = 8 * 1024;

/// The two output types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputKind {
    /// Single hybrid key, 20-byte hash.
    PubkeyHash,
    /// Spend policy, 32-byte hash.
    Policy,
}

/// Classify a `script_pubkey`; `None` for anything else (not a valid output).
pub fn output_kind(script_pubkey: &[u8]) -> Option<OutputKind> {
    match script_pubkey.len() {
        PKH_SPK_LEN => Some(OutputKind::PubkeyHash),
        POLICY_SPK_LEN if script_pubkey[0] == POLICY_TAG => Some(OutputKind::Policy),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    BadVersion,
    BadThreshold,
    TooManyKeys,
    DuplicateKey,
    NotHybridKey(usize),
    Truncated,
    TrailingBytes,
    TooLarge,
    BadTag,
    WrongSignatureCount { got: usize, want: usize },
    KeyIndexOrder,
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// An m-of-n multisig with optional absolute and relative timelocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendPolicy {
    pub threshold: u8,
    pub pubkeys: Vec<Vec<u8>>,
    /// Absolute timelock (block height); 0 = none.
    pub after: u32,
    /// Relative timelock (blocks since the output confirmed); 0 = none.
    pub older: u32,
}

impl SpendPolicy {
    /// Build and validate a policy.
    pub fn new(threshold: u8, pubkeys: Vec<Vec<u8>>, after: u32, older: u32) -> Result<Self, PolicyError> {
        let p = Self { threshold, pubkeys, after, older };
        p.check()?;
        Ok(p)
    }

    fn check(&self) -> Result<(), PolicyError> {
        let n = self.pubkeys.len();
        if n > MAX_POLICY_KEYS {
            return Err(PolicyError::TooManyKeys);
        }
        if self.threshold == 0 || self.threshold as usize > n {
            return Err(PolicyError::BadThreshold);
        }
        for (i, k) in self.pubkeys.iter().enumerate() {
            if !crate::crypto::is_hybrid_public_key(k) {
                return Err(PolicyError::NotHybridKey(i));
            }
            if self.pubkeys[..i].contains(k) {
                return Err(PolicyError::DuplicateKey);
            }
        }
        Ok(())
    }

    /// Canonical encoding: `version ‖ m ‖ n ‖ (u32le len ‖ key)* ‖ after u32le ‖ older u32le`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![POLICY_VERSION, self.threshold, self.pubkeys.len() as u8];
        for k in &self.pubkeys {
            out.extend_from_slice(&(k.len() as u32).to_le_bytes());
            out.extend_from_slice(k);
        }
        out.extend_from_slice(&self.after.to_le_bytes());
        out.extend_from_slice(&self.older.to_le_bytes());
        out
    }

    /// Strict decoding of [`encode`](Self::encode); validates the policy.
    pub fn decode(bytes: &[u8]) -> Result<Self, PolicyError> {
        let mut r = Reader(bytes);
        if r.u8()? != POLICY_VERSION {
            return Err(PolicyError::BadVersion);
        }
        let threshold = r.u8()?;
        let n = r.u8()? as usize;
        if n > MAX_POLICY_KEYS {
            return Err(PolicyError::TooManyKeys);
        }
        let mut pubkeys = Vec::with_capacity(n);
        for _ in 0..n {
            pubkeys.push(r.bytes(MAX_PK_LEN)?.to_vec());
        }
        let after = r.u32()?;
        let older = r.u32()?;
        r.end()?;
        Self::new(threshold, pubkeys, after, older)
    }

    /// `SHA3-256("GNB-POLICY-v1" ‖ encode())`.
    pub fn hash(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(POLICY_DOMAIN);
        h.update(self.encode());
        h.finalize().into()
    }

    /// The 33-byte output script paying to this policy.
    pub fn script_pubkey(&self) -> Vec<u8> {
        let mut s = Vec::with_capacity(POLICY_SPK_LEN);
        s.push(POLICY_TAG);
        s.extend_from_slice(&self.hash());
        s
    }
}

/// The `script_sig` of an input spending a policy output: the policy itself
/// and exactly `threshold` signatures, each tagged with the index of its key,
/// indices strictly increasing.
///
/// Encoding: `0x02 ‖ u32le len ‖ policy ‖ u8 count ‖ (u8 index ‖ u32le len ‖ sig)*`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyWitness {
    pub policy: SpendPolicy,
    /// `(key index, signature)`, strictly increasing indices.
    pub signatures: Vec<(u8, Vec<u8>)>,
}

impl PolicyWitness {
    pub fn encode(&self) -> Vec<u8> {
        let policy = self.policy.encode();
        let mut out = vec![POLICY_TAG];
        out.extend_from_slice(&(policy.len() as u32).to_le_bytes());
        out.extend_from_slice(&policy);
        out.push(self.signatures.len() as u8);
        for (idx, sig) in &self.signatures {
            out.push(*idx);
            out.extend_from_slice(&(sig.len() as u32).to_le_bytes());
            out.extend_from_slice(sig);
        }
        out
    }

    /// Strict decoding: valid policy, exactly `threshold` signatures,
    /// strictly increasing in-range key indices, no trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, PolicyError> {
        let mut r = Reader(bytes);
        if r.u8()? != POLICY_TAG {
            return Err(PolicyError::BadTag);
        }
        let policy = SpendPolicy::decode(r.bytes(MAX_POLICY_KEYS * (MAX_PK_LEN + 4) + 16)?)?;
        let count = r.u8()? as usize;
        if count != policy.threshold as usize {
            return Err(PolicyError::WrongSignatureCount { got: count, want: policy.threshold as usize });
        }
        let mut signatures = Vec::with_capacity(count);
        let mut prev: Option<u8> = None;
        for _ in 0..count {
            let idx = r.u8()?;
            if idx as usize >= policy.pubkeys.len() || prev.is_some_and(|p| idx <= p) {
                return Err(PolicyError::KeyIndexOrder);
            }
            prev = Some(idx);
            signatures.push((idx, r.bytes(MAX_SIG_LEN)?.to_vec()));
        }
        r.end()?;
        Ok(Self { policy, signatures })
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], PolicyError> {
        if self.0.len() < n {
            return Err(PolicyError::Truncated);
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8, PolicyError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, PolicyError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("4 bytes")))
    }
    fn bytes(&mut self, max: usize) -> Result<&'a [u8], PolicyError> {
        let len = self.u32()? as usize;
        if len > max {
            return Err(PolicyError::TooLarge);
        }
        self.take(len)
    }
    fn end(&self) -> Result<(), PolicyError> {
        if self.0.is_empty() { Ok(()) } else { Err(PolicyError::TrailingBytes) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(n: usize) -> Vec<Vec<u8>> {
        (0..n).map(|_| crate::crypto::generate_keypair().0).collect()
    }

    #[test]
    fn policy_roundtrips_and_hash_is_stable() {
        let p = SpendPolicy::new(2, keys(3), 1_000, 144).unwrap();
        let back = SpendPolicy::decode(&p.encode()).unwrap();
        assert_eq!(p, back);
        assert_eq!(p.hash(), back.hash());
        let spk = p.script_pubkey();
        assert_eq!(spk.len(), POLICY_SPK_LEN);
        assert_eq!(output_kind(&spk), Some(OutputKind::Policy));
        assert_eq!(output_kind(&[7u8; 20]), Some(OutputKind::PubkeyHash));
        assert_eq!(output_kind(&[7u8; 32]), None);
        assert_eq!(output_kind(&{ let mut s = spk.clone(); s[0] = 0x03; s }), None);
    }

    #[test]
    fn any_field_change_changes_the_hash() {
        let k = keys(3);
        let base = SpendPolicy::new(2, k.clone(), 0, 0).unwrap().hash();
        assert_ne!(base, SpendPolicy::new(3, k.clone(), 0, 0).unwrap().hash());
        assert_ne!(base, SpendPolicy::new(2, k.clone(), 1, 0).unwrap().hash());
        assert_ne!(base, SpendPolicy::new(2, k.clone(), 0, 1).unwrap().hash());
        let mut swapped = k.clone();
        swapped.swap(0, 1);
        assert_ne!(base, SpendPolicy::new(2, swapped, 0, 0).unwrap().hash(), "key order is committed");
    }

    #[test]
    fn invalid_policies_are_refused() {
        let k = keys(MAX_POLICY_KEYS + 1);
        assert_eq!(SpendPolicy::new(0, k[..2].to_vec(), 0, 0), Err(PolicyError::BadThreshold));
        assert_eq!(SpendPolicy::new(3, k[..2].to_vec(), 0, 0), Err(PolicyError::BadThreshold));
        assert_eq!(SpendPolicy::new(1, k.clone(), 0, 0), Err(PolicyError::TooManyKeys));
        assert_eq!(SpendPolicy::new(1, vec![k[0].clone(), k[0].clone()], 0, 0), Err(PolicyError::DuplicateKey));
        let mut short = k[0].clone();
        short.truncate(short.len() - 1793); // ML-DSA half only
        assert_eq!(SpendPolicy::new(1, vec![short], 0, 0), Err(PolicyError::NotHybridKey(0)));
    }

    #[test]
    fn decoding_is_strict() {
        let p = SpendPolicy::new(1, keys(2), 5, 6).unwrap();
        let mut b = p.encode();
        b.push(0);
        assert_eq!(SpendPolicy::decode(&b), Err(PolicyError::TrailingBytes));
        let b = p.encode();
        assert_eq!(SpendPolicy::decode(&b[..b.len() - 1]), Err(PolicyError::Truncated));
        let mut b = p.encode();
        b[0] = 9;
        assert_eq!(SpendPolicy::decode(&b), Err(PolicyError::BadVersion));
    }

    #[test]
    fn witness_requires_exactly_threshold_sigs_in_increasing_order() {
        let p = SpendPolicy::new(2, keys(3), 0, 0).unwrap();
        let w = |sigs: Vec<(u8, Vec<u8>)>| PolicyWitness { policy: p.clone(), signatures: sigs }.encode();
        assert!(PolicyWitness::decode(&w(vec![(0, vec![1]), (2, vec![2])])).is_ok());
        assert!(matches!(PolicyWitness::decode(&w(vec![(0, vec![1])])),
                         Err(PolicyError::WrongSignatureCount { got: 1, want: 2 })));
        assert!(matches!(PolicyWitness::decode(&w(vec![(0, vec![1]), (1, vec![1]), (2, vec![1])])),
                         Err(PolicyError::WrongSignatureCount { .. })));
        assert_eq!(PolicyWitness::decode(&w(vec![(2, vec![1]), (0, vec![2])])), Err(PolicyError::KeyIndexOrder));
        assert_eq!(PolicyWitness::decode(&w(vec![(1, vec![1]), (1, vec![2])])), Err(PolicyError::KeyIndexOrder));
        assert_eq!(PolicyWitness::decode(&w(vec![(0, vec![1]), (3, vec![2])])), Err(PolicyError::KeyIndexOrder));
        let mut b = w(vec![(0, vec![1]), (2, vec![2])]);
        b.push(0);
        assert_eq!(PolicyWitness::decode(&b), Err(PolicyError::TrailingBytes));
    }
}
