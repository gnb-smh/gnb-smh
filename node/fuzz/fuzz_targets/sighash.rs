//! Transaction signature digests (`core::sighash`, audit CRY-1/CRY-2/MEM-5)
//! on arbitrary transactions, spent outputs, input indices, suites and chains.
//!
//! * Nothing panics, whatever the index (in or out of range) or the number of
//!   spent outputs.
//! * Sighash v2 (`Transaction::sighash`) equals an independent hand-written
//!   WIRE encoding of the stripped transaction (`reference/gnb_sighash.py`'s
//!   `v2_body`: this chain's v2 since cc5c450, version byte 0x02; the bincode
//!   body of the earlier v2 is no longer signed), hashed with the v2 prefix,
//!   for every index (an out-of-range index omits the marker); the library's
//!   encoder produces the same body. `sighash_v2_checked` is `Ok(sighash)`
//!   exactly for an index below the input count. No `script_sig` is
//!   committed.
//! * Sighash v3 equals an independent implementation of the 195-byte preimage
//!   of the specification; it is an error exactly when the spent-output count
//!   differs from the input count or the index is out of range.
//! * Changing any single committed field (version, locktime, chain, suite,
//!   index, one prevout / sequence / spent amount / spent script / output)
//!   changes the v3 digest; changing a `script_sig` never does.
#![no_main]

mod common;

use common::*;
use gnb_crypto::core::sighash::{SighashError, SighashV3Precomputed, SIGHASH_V3_PREIMAGE_LEN};
use gnb_crypto::core::{ChainId, Transaction, TxOutput};
use libfuzzer_sys::fuzz_target;

fn chain(b: bool) -> ChainId {
    if b {
        ChainId::Testnet
    } else {
        ChainId::Mainnet
    }
}

/// `v2_body` of the reference: the wire encoding of the transaction with
/// every `script_sig` emptied except the signed input's, which is the marker.
fn ref_v2_body(tx: &Transaction, index: usize) -> Vec<u8> {
    let mut stripped = tx.clone();
    for (i, inp) in stripped.inputs.iter_mut().enumerate() {
        inp.script_sig = if i == index { b"GNB_SIGHASH".to_vec() } else { vec![] };
    }
    ref_tx_wire(&stripped, true)
}

fn ref_v2(tx: &Transaction, index: usize, c: ChainId) -> [u8; 32] {
    let mut pre = b"GNB-SIGHASH-v1\0\0".to_vec();
    pre.push(0x02);
    pre.extend_from_slice(&c.to_u32().to_le_bytes());
    pre.extend_from_slice(&ref_v2_body(tx, index));
    sha3(&pre)
}

fn list_hash(tag: &[u8], count: usize, items: &[u8]) -> [u8; 32] {
    let mut m = vec![tag.len() as u8];
    m.extend_from_slice(tag);
    m.extend_from_slice(&(count as u32).to_le_bytes());
    m.extend_from_slice(items);
    sha3(&m)
}

fn ref_v3(tx: &Transaction, spent: &[TxOutput], index: usize, suite: u16, c: ChainId) -> Option<[u8; 32]> {
    if spent.len() != tx.inputs.len() || index >= tx.inputs.len() {
        return None;
    }
    let mut prevouts = Vec::new();
    let mut seqs = Vec::new();
    for i in &tx.inputs {
        prevouts.extend_from_slice(&i.prev_txid);
        prevouts.extend_from_slice(&i.prev_index.to_le_bytes());
        seqs.extend_from_slice(&i.sequence.to_le_bytes());
    }
    let mut amounts = Vec::new();
    let mut scripts = Vec::new();
    for s in spent {
        amounts.extend_from_slice(&s.value.to_le_bytes());
        scripts.extend_from_slice(&(s.script_pubkey.len() as u32).to_le_bytes());
        scripts.extend_from_slice(&s.script_pubkey);
    }
    let mut outs = Vec::new();
    for o in &tx.outputs {
        outs.extend_from_slice(&o.value.to_le_bytes());
        outs.extend_from_slice(&(o.script_pubkey.len() as u32).to_le_bytes());
        outs.extend_from_slice(&o.script_pubkey);
    }
    let n = tx.inputs.len();
    let mut p = b"GNB-SIGHASH-v3\0\0".to_vec();
    p.push(0x03);
    p.extend_from_slice(&c.to_u32().to_le_bytes());
    p.extend_from_slice(&tx.version.to_le_bytes());
    p.extend_from_slice(&tx.locktime.to_le_bytes());
    p.extend_from_slice(&list_hash(b"GNB-SIGHASH-v3/prevouts", n, &prevouts));
    p.extend_from_slice(&list_hash(b"GNB-SIGHASH-v3/sequences", n, &seqs));
    p.extend_from_slice(&list_hash(b"GNB-SIGHASH-v3/amounts", n, &amounts));
    p.extend_from_slice(&list_hash(b"GNB-SIGHASH-v3/scripts", n, &scripts));
    p.extend_from_slice(&list_hash(b"GNB-SIGHASH-v3/outputs", tx.outputs.len(), &outs));
    p.extend_from_slice(&(index as u32).to_le_bytes());
    p.extend_from_slice(&suite.to_le_bytes());
    assert_eq!(p.len(), SIGHASH_V3_PREIMAGE_LEN);
    Some(sha3(&p))
}

fn lib_v3(tx: &Transaction, spent: &[TxOutput], index: usize, suite: u16, c: ChainId) -> Option<[u8; 32]> {
    let one_shot = tx.sighash_v3(spent, index, suite, c);
    let pre = SighashV3Precomputed::new(tx, spent);
    let via_pre = pre.as_ref().map_err(Clone::clone).and_then(|p| p.digest(index, suite, c));
    assert_eq!(one_shot, via_pre, "sighash_v3 differs from the precomputed digest");
    match &one_shot {
        Err(SighashError::SpentOutputCount { spent: s, inputs }) => {
            assert_eq!((*s, *inputs), (spent.len(), tx.inputs.len()));
            assert_ne!(spent.len(), tx.inputs.len());
        }
        Err(SighashError::InputIndexOutOfRange { index: i, inputs }) => {
            assert_eq!((*i, *inputs), (index, tx.inputs.len()));
            assert!(index >= tx.inputs.len());
        }
        Err(e) => panic!("unexpected sighash v3 error {e:?}"),
        Ok(_) => {
            let p = pre.unwrap();
            assert_eq!(p.n_inputs, tx.inputs.len());
            assert_eq!(p.preimage(index, suite, c).map(|x| sha3(&x)), one_shot);
        }
    }
    one_shot.ok()
}

fuzz_target!(|data: &[u8]| {
    let mut inp = Input::new(data);
    let index = inp.below(12);
    let suite = inp.u16();
    let c = chain(inp.bool());
    let field = inp.u8();
    let pick = inp.u16() as usize;
    let delta = inp.u8() | 1;
    // Spent outputs: usually one per input, sometimes not.
    let mismatch = inp.u8().is_multiple_of(8);
    let tx = gen_tx(&mut inp, 8, 6, 48);
    let n_spent = if mismatch { inp.below(9) } else { tx.inputs.len() };
    let spent: Vec<TxOutput> =
        (0..n_spent).map(|_| TxOutput { value: inp.u64(), script_pubkey: inp.var_bytes(40) }).collect();

    // ── v2 ────────────────────────────────────────────────────────────────
    let body = ref_v2_body(&tx, index);
    let mut stripped = tx.clone();
    for (i, x) in stripped.inputs.iter_mut().enumerate() {
        x.script_sig = if i == index { b"GNB_SIGHASH".to_vec() } else { vec![] };
    }
    assert_eq!(stripped.to_wire_bytes(true), body, "hand-written wire body differs from the library encoder");
    let v2 = tx.sighash(index, c);
    assert_eq!(v2, ref_v2(&tx, index, c), "sighash v2 differs from the reference digest");
    match tx.sighash_v2_checked(index, c) {
        Ok(d) => {
            assert!(index < tx.inputs.len());
            assert_eq!(d, v2);
        }
        Err(SighashError::InputIndexOutOfRange { .. }) => assert!(index >= tx.inputs.len()),
        Err(e) => panic!("unexpected v2 error {e:?}"),
    }
    // No script_sig is committed by v2.
    if !tx.inputs.is_empty() {
        let mut w = tx.clone();
        let j = pick % w.inputs.len();
        w.inputs[j].script_sig.push(delta);
        assert_eq!(w.sighash(index, c), v2, "a script_sig changed the v2 digest");
    }

    // ── v3 ────────────────────────────────────────────────────────────────
    let v3 = lib_v3(&tx, &spent, index, suite, c);
    assert_eq!(v3, ref_v3(&tx, &spent, index, suite, c), "sighash v3 differs from the specification");
    let Some(base) = v3 else { return };

    // Any single committed field changed: a different digest.
    let (mut t, mut s, mut idx, mut su, mut ch) = (tx.clone(), spent.clone(), index, suite, c);
    let n_in = t.inputs.len();
    let j = pick % n_in;
    match field % 13 {
        0 => t.version ^= delta as u32,
        1 => t.locktime ^= delta as u32,
        2 => ch = chain(c == ChainId::Mainnet),
        3 => su ^= delta as u16,
        4 => {
            if n_in < 2 {
                return;
            }
            idx = (index + 1 + pick % (n_in - 1)) % n_in;
        }
        5 => t.inputs[j].prev_txid[pick % 32] ^= delta,
        6 => t.inputs[j].prev_index ^= delta as u32,
        7 => t.inputs[j].sequence ^= delta as u32,
        8 => s[j].value ^= delta as u64,
        9 => {
            // spent script: change a byte, or its length
            if s[j].script_pubkey.is_empty() || pick & 1 == 1 {
                s[j].script_pubkey.push(delta);
            } else {
                let k = pick % s[j].script_pubkey.len();
                s[j].script_pubkey[k] ^= delta;
            }
        }
        10 => {
            if t.outputs.is_empty() {
                return;
            }
            let k = pick % t.outputs.len();
            t.outputs[k].value ^= delta as u64;
        }
        11 => {
            if t.outputs.is_empty() || pick & 1 == 1 {
                t.outputs.push(TxOutput { value: delta as u64, script_pubkey: vec![] });
            } else {
                let k = pick % t.outputs.len();
                t.outputs[k].script_pubkey.push(delta);
            }
        }
        _ => {
            // Not committed: a script_sig. Same digest.
            t.inputs[j].script_sig.push(delta);
            assert_eq!(lib_v3(&t, &s, idx, su, ch), Some(base), "a script_sig changed the v3 digest");
            return;
        }
    }
    let changed = lib_v3(&t, &s, idx, su, ch).expect("still well-formed");
    assert_ne!(changed, base, "changing committed field {} kept the v3 digest", field % 13);
});
