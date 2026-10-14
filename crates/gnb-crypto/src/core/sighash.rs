//! Transaction signature digests and input-script rules (audit CRY-1, CRY-2,
//! CRY-3, MEM-5, WAL-1).
//!
//! Two digests exist. The transaction's own `version` field selects one:
//!
//! | `tx.version` | digest | component binding |
//! | --- | --- | --- |
//! | 3 | sighash v3 ([`SighashV3Precomputed`]) | each component signs `crypto::bound_component_message` |
//! | anything else | sighash v2 ([`Transaction::sighash`]) | every component signs the digest verbatim |
//!
//! and the hardening activation (`core::activation`) decides which versions a
//! non-coinbase transaction in a block may have ([`check_tx_version`]): below
//! the activation height version 3 is invalid (nodes that predate it cannot
//! verify a v3 digest) and every other version keeps the historical v2 rules
//! bit for bit; at and after it only version 3 is valid. The height compared
//! is the header height of the block containing the transaction
//! (`Block::height`, validated by `accept_block`); mempool and wallets use the
//! height of the next block.
//!
//! # Sighash v3 (byte-exact; normative text in `docs/CONSENSUS.md`)
//!
//! ```text
//! list_hash(tag, items) = SHA3-256( u8 len(tag) ‖ tag ‖ u32 LE count ‖ items )
//!
//! hash_prevouts   = list_hash("GNB-SIGHASH-v3/prevouts",  for each input:  prev_txid(32) ‖ prev_index u32 LE)
//! hash_sequences  = list_hash("GNB-SIGHASH-v3/sequences", for each input:  sequence u32 LE)
//! hash_amounts    = list_hash("GNB-SIGHASH-v3/amounts",   for each input:  spent value u64 LE)
//! hash_scripts    = list_hash("GNB-SIGHASH-v3/scripts",   for each input:  u32 LE len ‖ spent script_pubkey)
//! hash_outputs    = list_hash("GNB-SIGHASH-v3/outputs",   for each output: value u64 LE ‖ u32 LE len ‖ script_pubkey)
//!
//! preimage (195 bytes) =
//!     "GNB-SIGHASH-v3\0\0" (16) ‖ 0x03 (1) ‖ chain_id u32 LE (4)
//!   ‖ tx.version u32 LE (4) ‖ tx.locktime u32 LE (4)
//!   ‖ hash_prevouts ‖ hash_sequences ‖ hash_amounts ‖ hash_scripts ‖ hash_outputs (5 × 32)
//!   ‖ input_index u32 LE (4) ‖ suite_id u16 LE (2)
//! sighash_v3 = SHA3-256(preimage)
//! ```
//!
//! `count` is the number of inputs (outputs for `hash_outputs`). The five
//! list hashes are computed once per transaction, so signing or verifying
//! every input costs O(transaction size) in total (BIP143/BIP341-style
//! precomputation; closes the MEM-5 quadratic residual). `input_index` must
//! be below the input count: an out-of-range index is an error
//! ([`SighashError::InputIndexOutOfRange`]), never a different digest.
//! `suite_id` is the suite of the signature (its envelope).
//!
//! Reference implementation and golden vectors: `reference/gnb_sighash.py`,
//! `reference/sighash_vectors.json` (pinned by `tests/sighash_vectors.rs`).

use sha3::{Digest, Sha3_256};

use super::{activation, ChainId, Transaction, TxOutput};
use crate::crypto;

/// Transaction version that selects sighash v3.
pub const TX_VERSION_V3: u32 = 3;
/// Version signers give non-coinbase transactions below the activation
/// height (the historical wallet output; any version other than 3 selects
/// sighash v2).
pub const TX_VERSION_LEGACY: u32 = 1;

/// First 16 bytes of every sighash v3 preimage.
pub const SIGHASH_V3_DOMAIN: [u8; 16] = *b"GNB-SIGHASH-v3\0\0";
/// Sighash version byte of a v3 preimage.
pub const SIGHASH_V3_VERSION: u8 = 0x03;
/// Length of a sighash v3 preimage: 16 + 1 + 4 + 4 + 4 + 5 × 32 + 4 + 2.
pub const SIGHASH_V3_PREIMAGE_LEN: usize = 195;

/// List-hash tags of sighash v3 (each hashed with a one-byte length prefix).
pub const TAG_PREVOUTS: &[u8] = b"GNB-SIGHASH-v3/prevouts";
pub const TAG_SEQUENCES: &[u8] = b"GNB-SIGHASH-v3/sequences";
pub const TAG_AMOUNTS: &[u8] = b"GNB-SIGHASH-v3/amounts";
pub const TAG_SCRIPTS: &[u8] = b"GNB-SIGHASH-v3/scripts";
pub const TAG_OUTPUTS: &[u8] = b"GNB-SIGHASH-v3/outputs";

/// Which digest (and component binding) a transaction's signatures use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SighashVersion {
    /// Historical digest ([`Transaction::sighash`]); components sign it verbatim.
    V2,
    /// [`SighashV3Precomputed::digest`]; components sign bound messages.
    V3,
}

impl SighashVersion {
    /// The digest a transaction version selects (no height gate).
    pub const fn for_tx_version(version: u32) -> Self {
        if version == TX_VERSION_V3 { SighashVersion::V3 } else { SighashVersion::V2 }
    }
}

/// The version a signer gives a non-coinbase transaction targeting a block
/// at `height`: 3 at/after the activation, [`TX_VERSION_LEGACY`] below it.
pub const fn tx_version_for_height(height: u64, activation_height: u64) -> u32 {
    if activation::is_active_at(height, activation_height) { TX_VERSION_V3 } else { TX_VERSION_LEGACY }
}

/// Consensus rule: the version of a NON-COINBASE transaction in a block at
/// header height `height`. Returns the digest the version selects.
///
/// * below the activation: version 3 is invalid, every other version is
///   valid and uses sighash v2 (the historical rule, unchanged);
/// * at/after the activation: only version 3 is valid.
///
/// Error strings start with `bad-txns-version`.
pub fn check_tx_version(version: u32, height: u64, activation_height: u64) -> Result<SighashVersion, String> {
    if activation::is_active_at(height, activation_height) {
        if version == TX_VERSION_V3 {
            Ok(SighashVersion::V3)
        } else {
            Err(format!(
                "bad-txns-version: version {version} is invalid at height {height} \
                 (only version 3 is valid at/after the hardening activation height {activation_height})"
            ))
        }
    } else if version == TX_VERSION_V3 {
        Err(format!(
            "bad-txns-version: version 3 is invalid at height {height}, below the hardening \
             activation height {activation_height}"
        ))
    } else {
        Ok(SighashVersion::V2)
    }
}

/// Why a digest could not be computed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SighashError {
    /// The signed input index is not below the input count.
    InputIndexOutOfRange { index: usize, inputs: usize },
    /// Sighash v3 needs exactly one spent output per input.
    SpentOutputCount { spent: usize, inputs: usize },
    /// A count or length does not fit the u32 the preimage encodes it in.
    TooLarge(&'static str),
}

impl std::fmt::Display for SighashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SighashError::InputIndexOutOfRange { index, inputs } =>
                write!(f, "sighash input index {index} out of range ({inputs} inputs)"),
            SighashError::SpentOutputCount { spent, inputs } =>
                write!(f, "sighash v3 needs one spent output per input ({spent} for {inputs} inputs)"),
            SighashError::TooLarge(what) => write!(f, "sighash: {what} does not fit in u32"),
        }
    }
}

impl std::error::Error for SighashError {}

fn u32_len(n: usize, what: &'static str) -> Result<u32, SighashError> {
    u32::try_from(n).map_err(|_| SighashError::TooLarge(what))
}

/// SHA3-256 that counts the bytes it absorbs (cost accounting for MEM-5).
struct CountingHasher {
    h: Sha3_256,
    n: usize,
}

impl CountingHasher {
    fn tagged(tag: &[u8], count: u32) -> Self {
        let mut c = CountingHasher { h: Sha3_256::new(), n: 0 };
        // Tags are short constants; their length fits a byte.
        c.put(&[tag.len() as u8]);
        c.put(tag);
        c.put(&count.to_le_bytes());
        c
    }

    fn put(&mut self, b: &[u8]) {
        self.n = self.n.saturating_add(b.len());
        self.h.update(b);
    }

    fn finish(self, total: &mut usize) -> [u8; 32] {
        *total = total.saturating_add(self.n);
        self.h.finalize().into()
    }
}

/// The per-transaction part of sighash v3, computed once and shared by every
/// input's digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SighashV3Precomputed {
    pub tx_version: u32,
    pub locktime: u32,
    pub n_inputs: usize,
    pub hash_prevouts: [u8; 32],
    pub hash_sequences: [u8; 32],
    pub hash_amounts: [u8; 32],
    pub hash_scripts: [u8; 32],
    pub hash_outputs: [u8; 32],
    /// Bytes absorbed by the five list hashes. Linear in the transaction size;
    /// every per-input digest then hashes exactly [`SIGHASH_V3_PREIMAGE_LEN`]
    /// bytes (diagnostics and the MEM-5 cost tests).
    pub hashed_bytes: usize,
}

impl SighashV3Precomputed {
    /// Precompute the list hashes of `tx` spending `spent` (one output per
    /// input, in input order: the value and `script_pubkey` each input spends).
    pub fn new(tx: &Transaction, spent: &[TxOutput]) -> Result<Self, SighashError> {
        if spent.len() != tx.inputs.len() {
            return Err(SighashError::SpentOutputCount { spent: spent.len(), inputs: tx.inputs.len() });
        }
        let n_in = u32_len(tx.inputs.len(), "input count")?;
        let n_out = u32_len(tx.outputs.len(), "output count")?;
        let mut total = 0usize;

        let mut h = CountingHasher::tagged(TAG_PREVOUTS, n_in);
        for inp in &tx.inputs {
            h.put(&inp.prev_txid);
            h.put(&inp.prev_index.to_le_bytes());
        }
        let hash_prevouts = h.finish(&mut total);

        let mut h = CountingHasher::tagged(TAG_SEQUENCES, n_in);
        for inp in &tx.inputs {
            h.put(&inp.sequence.to_le_bytes());
        }
        let hash_sequences = h.finish(&mut total);

        let mut h = CountingHasher::tagged(TAG_AMOUNTS, n_in);
        for s in spent {
            h.put(&s.value.to_le_bytes());
        }
        let hash_amounts = h.finish(&mut total);

        let mut h = CountingHasher::tagged(TAG_SCRIPTS, n_in);
        for s in spent {
            h.put(&u32_len(s.script_pubkey.len(), "spent script_pubkey length")?.to_le_bytes());
            h.put(&s.script_pubkey);
        }
        let hash_scripts = h.finish(&mut total);

        let mut h = CountingHasher::tagged(TAG_OUTPUTS, n_out);
        for o in &tx.outputs {
            h.put(&o.value.to_le_bytes());
            h.put(&u32_len(o.script_pubkey.len(), "output script_pubkey length")?.to_le_bytes());
            h.put(&o.script_pubkey);
        }
        let hash_outputs = h.finish(&mut total);

        Ok(SighashV3Precomputed {
            tx_version: tx.version,
            locktime: tx.locktime,
            n_inputs: tx.inputs.len(),
            hash_prevouts,
            hash_sequences,
            hash_amounts,
            hash_scripts,
            hash_outputs,
            hashed_bytes: total,
        })
    }

    /// The 195-byte preimage of input `input_index` signed under `suite`.
    pub fn preimage(
        &self,
        input_index: usize,
        suite: u16,
        chain_id: ChainId,
    ) -> Result<[u8; SIGHASH_V3_PREIMAGE_LEN], SighashError> {
        if input_index >= self.n_inputs {
            return Err(SighashError::InputIndexOutOfRange { index: input_index, inputs: self.n_inputs });
        }
        let index = u32_len(input_index, "input index")?;
        let mut p = [0u8; SIGHASH_V3_PREIMAGE_LEN];
        let mut at = 0usize;
        let mut put = |b: &[u8]| {
            p[at..at + b.len()].copy_from_slice(b);
            at += b.len();
        };
        put(&SIGHASH_V3_DOMAIN);
        put(&[SIGHASH_V3_VERSION]);
        put(&chain_id.to_le_bytes());
        put(&self.tx_version.to_le_bytes());
        put(&self.locktime.to_le_bytes());
        put(&self.hash_prevouts);
        put(&self.hash_sequences);
        put(&self.hash_amounts);
        put(&self.hash_scripts);
        put(&self.hash_outputs);
        put(&index.to_le_bytes());
        put(&suite.to_le_bytes());
        debug_assert_eq!(at, SIGHASH_V3_PREIMAGE_LEN);
        Ok(p)
    }

    /// Sighash v3 of input `input_index` signed under `suite`.
    pub fn digest(&self, input_index: usize, suite: u16, chain_id: ChainId) -> Result<[u8; 32], SighashError> {
        Ok(Sha3_256::digest(self.preimage(input_index, suite, chain_id)?).into())
    }
}

impl Transaction {
    /// Sighash v3 of one input (see the module documentation). Precomputes
    /// the list hashes on every call: to sign or verify several inputs, build
    /// one [`SighashV3Precomputed`] and call its `digest`.
    pub fn sighash_v3(
        &self,
        spent: &[TxOutput],
        input_index: usize,
        suite: u16,
        chain_id: ChainId,
    ) -> Result<[u8; 32], SighashError> {
        SighashV3Precomputed::new(self, spent)?.digest(input_index, suite, chain_id)
    }

    /// [`Transaction::sighash`] (v2) with the input index range-checked.
    pub fn sighash_v2_checked(&self, input_index: usize, chain_id: ChainId) -> Result<[u8; 32], SighashError> {
        if input_index >= self.inputs.len() {
            return Err(SighashError::InputIndexOutOfRange { index: input_index, inputs: self.inputs.len() });
        }
        Ok(self.sighash(input_index, chain_id))
    }
}

// ── Witnesses (CRY-1, canonical-witness half) ───────────────────────────────

/// The canonical witness rule: `script_sig` is EXACTLY
/// `[u32 LE sig_len][sig][u32 LE pk_len][pk]` with no trailing bytes, and
/// `sig` is the canonical suite-enveloped encoding
/// (`crypto::is_canonical_signature_encoding`: mandatory envelope, compact
/// Falcon half, exact ML-DSA length). The PUBLIC key is not required to be
/// enveloped: genesis carry-over addresses commit to raw keys.
///
/// Consensus for every version-3 transaction (so for every non-coinbase
/// transaction at/after the activation); relay policy at every height.
pub fn canonical_witness(script_sig: &[u8]) -> Result<Witness<'_>, String> {
    let (sig, pk) = Transaction::parse_script_sig_exact(script_sig)
        .ok_or_else(|| "non-canonical script_sig framing (expected exactly \
                         [u32 sig_len][sig][u32 pk_len][pk])".to_string())?;
    if !crypto::is_canonical_signature_encoding(sig) {
        return Err("non-canonical signature encoding (envelope missing, unknown suite, \
                    padded or malformed Falcon half, or wrong ML-DSA length)".into());
    }
    Ok((sig, pk))
}

fn pubkey_hash_matches(pk: &[u8], script_pubkey: &[u8]) -> bool {
    Sha3_256::digest(pk)[..20] == *script_pubkey
}

/// One parsed witness: `(signature, public key)`, borrowed from `script_sig`.
pub type Witness<'a> = (&'a [u8], &'a [u8]);

/// Parse every input's witness under the rules of `version` and check that
/// its public key hashes to the spent `script_pubkey` (`prevouts[i]`).
/// No signature math.
///
/// * V2 (historical, unchanged): the lenient `Transaction::parse_script_sig`
///   framing (trailing bytes ignored), any signature encoding the verifier
///   accepts.
/// * V3: [`canonical_witness`].
pub fn check_input_witnesses<'a>(
    tx: &'a Transaction,
    prevouts: &[TxOutput],
    version: SighashVersion,
) -> Result<Vec<Witness<'a>>, String> {
    if prevouts.len() != tx.inputs.len() {
        return Err(format!("{} prevouts for {} inputs", prevouts.len(), tx.inputs.len()));
    }
    let mut out = Vec::with_capacity(tx.inputs.len());
    for (i, (inp, prev)) in tx.inputs.iter().zip(prevouts).enumerate() {
        let (sig, pk) = match version {
            SighashVersion::V2 => Transaction::parse_script_sig_borrowed(&inp.script_sig)
                .ok_or_else(|| format!("malformed script_sig at input {}", i))?,
            SighashVersion::V3 => canonical_witness(&inp.script_sig)
                .map_err(|e| format!("input {i}: {e}"))?,
        };
        if !pubkey_hash_matches(pk, &prev.script_pubkey) {
            return Err(format!("pubkey mismatch at input {}", i));
        }
        out.push((sig, pk));
    }
    Ok(out)
}

/// Verify the signature of every input. `witnesses` comes from
/// [`check_input_witnesses`] with the same `version`.
///
/// * V2: `crypto::verify(pk, tx.sighash(i, chain_id), sig)` (historical).
/// * V3: `crypto::verify_bound(pk, d_i, sig)` with
///   `d_i = sighash_v3(i, suite(sig))` from ONE precomputation (linear).
pub fn verify_input_signatures(
    tx: &Transaction,
    prevouts: &[TxOutput],
    witnesses: &[Witness<'_>],
    version: SighashVersion,
    chain_id: ChainId,
) -> Result<(), String> {
    if witnesses.len() != tx.inputs.len() {
        return Err(format!("{} witnesses for {} inputs", witnesses.len(), tx.inputs.len()));
    }
    match version {
        SighashVersion::V2 => {
            for (i, (sig, pk)) in witnesses.iter().enumerate() {
                let sighash = tx.sighash(i, chain_id);
                if !crypto::verify(pk, &sighash, sig) {
                    return Err(format!("invalid signature at input {}", i));
                }
            }
        }
        SighashVersion::V3 => {
            let pre = SighashV3Precomputed::new(tx, prevouts).map_err(|e| e.to_string())?;
            for (i, (sig, pk)) in witnesses.iter().enumerate() {
                let suite = crypto::split_envelope(sig)
                    .map(|(s, _)| s)
                    .ok_or_else(|| format!("input {i}: signature has no suite envelope"))?;
                let digest = pre.digest(i, suite, chain_id).map_err(|e| e.to_string())?;
                if !crypto::verify_bound(pk, &digest, sig) {
                    return Err(format!("invalid signature at input {}", i));
                }
            }
        }
    }
    Ok(())
}

/// The complete input-script rule of a non-coinbase transaction in a block at
/// header height `height` (no cache): version rule, witnesses, signatures.
/// The node's `mempool::admission::verify_input_scripts` is this function
/// plus a verified-signature cache; wallets use it to self-check.
pub fn verify_tx_scripts(
    tx: &Transaction,
    prevouts: &[TxOutput],
    chain_id: ChainId,
    height: u64,
    activation_height: u64,
) -> Result<SighashVersion, String> {
    let version = check_tx_version(tx.version, height, activation_height)?;
    let witnesses = check_input_witnesses(tx, prevouts, version)?;
    verify_input_signatures(tx, prevouts, &witnesses, version, chain_id)?;
    Ok(version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::TxInput;

    fn tx_with(n_in: usize, n_out: usize, version: u32) -> (Transaction, Vec<TxOutput>) {
        let tx = Transaction {
            version,
            inputs: (0..n_in).map(|i| TxInput {
                prev_txid: [(i % 251) as u8; 32],
                prev_index: i as u32,
                script_sig: vec![0xAB; 64],
                sequence: u32::MAX - i as u32,
            }).collect(),
            outputs: (0..n_out).map(|i| TxOutput { value: 1_000 + i as u64, script_pubkey: vec![i as u8; 20] }).collect(),
            locktime: 7,
        };
        let spent = (0..n_in).map(|i| TxOutput { value: 50_000 + i as u64, script_pubkey: vec![0x5A; 20] }).collect();
        (tx, spent)
    }

    #[test]
    fn version_rule_is_gated_at_the_activation_height() {
        let h = 100;
        for v in [0u32, 1, 2, 4, u32::MAX] {
            assert_eq!(check_tx_version(v, h - 1, h), Ok(SighashVersion::V2), "v{v} below activation");
            assert!(check_tx_version(v, h, h).unwrap_err().starts_with("bad-txns-version"));
        }
        assert!(check_tx_version(3, h - 1, h).unwrap_err().starts_with("bad-txns-version"));
        assert_eq!(check_tx_version(3, h, h), Ok(SighashVersion::V3));
        assert_eq!(check_tx_version(3, u64::MAX, h), Ok(SighashVersion::V3));
        // NEVER: the historical rule forever (every version but 3 is v2).
        assert_eq!(check_tx_version(1, u64::MAX - 1, activation::NEVER), Ok(SighashVersion::V2));
        assert_eq!(tx_version_for_height(h - 1, h), TX_VERSION_LEGACY);
        assert_eq!(tx_version_for_height(h, h), TX_VERSION_V3);
        assert_eq!(SighashVersion::for_tx_version(3), SighashVersion::V3);
        assert_eq!(SighashVersion::for_tx_version(2), SighashVersion::V2);
    }

    #[test]
    fn out_of_range_index_is_an_error_never_a_digest() {
        let (tx, spent) = tx_with(2, 1, 3);
        let pre = SighashV3Precomputed::new(&tx, &spent).unwrap();
        assert!(pre.digest(1, 1, ChainId::Mainnet).is_ok());
        assert_eq!(pre.digest(2, 1, ChainId::Mainnet),
            Err(SighashError::InputIndexOutOfRange { index: 2, inputs: 2 }));
        assert_eq!(tx.sighash_v2_checked(2, ChainId::Mainnet),
            Err(SighashError::InputIndexOutOfRange { index: 2, inputs: 2 }));
        assert_eq!(SighashV3Precomputed::new(&tx, &spent[..1]),
            Err(SighashError::SpentOutputCount { spent: 1, inputs: 2 }));
    }

    #[test]
    fn v3_commits_to_every_field() {
        let (tx, spent) = tx_with(3, 2, 3);
        let d = |t: &Transaction, s: &[TxOutput], i: usize, suite: u16, c: ChainId| t.sighash_v3(s, i, suite, c).unwrap();
        let base = d(&tx, &spent, 1, 1, ChainId::Mainnet);
        assert_ne!(base, d(&tx, &spent, 0, 1, ChainId::Mainnet), "input index");
        assert_ne!(base, d(&tx, &spent, 1, 2, ChainId::Mainnet), "suite id");
        assert_ne!(base, d(&tx, &spent, 1, 1, ChainId::Testnet), "chain id");
        let mut s = spent.clone(); s[2].value += 1;
        assert_ne!(base, d(&tx, &s, 1, 1, ChainId::Mainnet), "another input's spent amount");
        let mut s = spent.clone(); s[0].script_pubkey[0] ^= 1;
        assert_ne!(base, d(&tx, &s, 1, 1, ChainId::Mainnet), "another input's spent script");
        let mut t = tx.clone(); t.locktime += 1;
        assert_ne!(base, d(&t, &spent, 1, 1, ChainId::Mainnet), "locktime");
        let mut t = tx.clone(); t.inputs[2].sequence ^= 1;
        assert_ne!(base, d(&t, &spent, 1, 1, ChainId::Mainnet), "sequence");
        let mut t = tx.clone(); t.inputs[0].prev_index ^= 1;
        assert_ne!(base, d(&t, &spent, 1, 1, ChainId::Mainnet), "prevout");
        let mut t = tx.clone(); t.outputs[1].value += 1;
        assert_ne!(base, d(&t, &spent, 1, 1, ChainId::Mainnet), "output value");
        let mut t = tx.clone(); t.outputs[1].script_pubkey.push(0);
        assert_ne!(base, d(&t, &spent, 1, 1, ChainId::Mainnet), "output script");
        // The witness is not committed (txid-style, segwit-like).
        let mut t = tx.clone(); t.inputs[1].script_sig.clear();
        assert_eq!(base, d(&t, &spent, 1, 1, ChainId::Mainnet), "script_sig is not committed");
    }

    /// MEM-5: signing/verifying every input of a v3 transaction hashes
    /// O(size) bytes; the v2 digest hashes O(size) bytes PER input. Counted,
    /// not timed, so the test is deterministic.
    #[test]
    fn v3_cost_is_linear_in_the_input_count() {
        let cost_v3 = |n: usize| {
            let (tx, spent) = tx_with(n, 2, 3);
            let pre = SighashV3Precomputed::new(&tx, &spent).unwrap();
            for i in 0..n {
                let p = pre.preimage(i, 1, ChainId::Mainnet).unwrap();
                assert_eq!(p.len(), SIGHASH_V3_PREIMAGE_LEN);
            }
            pre.hashed_bytes + n * SIGHASH_V3_PREIMAGE_LEN
        };
        let (c50, c500) = (cost_v3(50), cost_v3(500));
        // Linear: 10x the inputs costs (at most a little over) 10x the bytes.
        assert!(c500 <= 11 * c50, "v3 cost {c50} -> {c500} is not linear");
        assert!(c500 >= 9 * c50);

        // v2 for comparison: every input re-encodes the whole stripped tx.
        let cost_v2 = |n: usize| {
            let (tx, _) = tx_with(n, 2, 1);
            let body = bincode::serde::encode_to_vec(&tx, bincode::config::standard()).unwrap().len();
            n * body
        };
        assert!(cost_v2(500) >= 90 * cost_v2(50), "v2 is quadratic");
    }

    #[test]
    fn exact_witness_framing() {
        let sig = vec![1u8; 10];
        let pk = vec![2u8; 7];
        let w = Transaction::build_script_sig(&sig, &pk);
        assert_eq!(Transaction::parse_script_sig_exact(&w), Some((&sig[..], &pk[..])));
        let mut trailing = w.clone();
        trailing.push(0);
        assert_eq!(Transaction::parse_script_sig_exact(&trailing), None);
        // The historical parser ignores the trailing byte.
        assert_eq!(Transaction::parse_script_sig(&trailing), Some((sig.clone(), pk.clone())));
        assert_eq!(Transaction::parse_script_sig_borrowed(&trailing), Some((&sig[..], &pk[..])));
        assert_eq!(Transaction::parse_script_sig_exact(&w[..w.len() - 1]), None);
        assert!(canonical_witness(&w).is_err(), "a non-enveloped signature is not canonical");
    }
}
