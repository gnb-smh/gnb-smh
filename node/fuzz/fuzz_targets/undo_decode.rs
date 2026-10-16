//! `UndoData` stored encoding (`core::UndoData::{to_bytes, from_bytes}`):
//! the legacy bincode record and the extended record
//! (`legacy || "UDX1" || bincode(UndoOverwrites)`, audit VAL-2 undo fix).
//!
//! * `from_bytes` never panics on arbitrary bytes and refuses every trailing
//!   byte that is not a well-formed extension;
//! * a decoded record re-encodes and decodes to the same record, and an
//!   extension with nothing in it is dropped on re-encoding (the stored form
//!   of "nothing overwritten" is the legacy record);
//! * generated records round-trip; one without overwrites is encoded exactly
//!   as the legacy six-field bincode record (backward compatibility with
//!   records written before the extension existed: an older binary reads it);
//!   the legacy prefix of an extended record decodes alone to the same six
//!   fields with nothing overwritten.
#![no_main]

mod common;

use common::*;
use gnb_crypto::core::{TxOutput, UndoData, UndoEntry, UndoOverwrites, UNDO_EXTENSION_MAGIC};
use libfuzzer_sys::fuzz_target;

/// The six legacy fields, as the pre-extension binaries encoded them.
#[derive(serde::Serialize)]
struct Legacy<'a> {
    block_hash: [u8; 32],
    block_height: u64,
    spent_utxos: &'a Vec<UndoEntry>,
    created_utxo_keys: &'a Vec<([u8; 32], u32)>,
    coinbase_txids: &'a Vec<[u8; 32]>,
    tx_index_keys: &'a Vec<[u8; 32]>,
}

fn legacy_bytes(u: &UndoData) -> Vec<u8> {
    let l = Legacy {
        block_hash: u.block_hash,
        block_height: u.block_height,
        spent_utxos: &u.spent_utxos,
        created_utxo_keys: &u.created_utxo_keys,
        coinbase_txids: &u.coinbase_txids,
        tx_index_keys: &u.tx_index_keys,
    };
    bincode::serde::encode_to_vec(&l, bincode::config::standard()).unwrap()
}

/// Structural equality including the `#[serde(skip)]` extension.
fn same_undo(a: &UndoData, b: &UndoData) -> bool {
    legacy_bytes(a) == legacy_bytes(b) && same(&a.overwritten, &b.overwritten)
}

fn entry(inp: &mut Input) -> UndoEntry {
    UndoEntry {
        prev_txid: inp.arr(),
        prev_index: inp.u32(),
        output: TxOutput { value: inp.u64(), script_pubkey: inp.var_bytes(30) },
    }
}

fn gen_undo(inp: &mut Input) -> UndoData {
    let mut u = UndoData::new(inp.arr(), inp.u64());
    for _ in 0..inp.below(4) {
        u.spent_utxos.push(entry(inp));
    }
    for _ in 0..inp.below(4) {
        u.created_utxo_keys.push((inp.arr(), inp.u32()));
    }
    for _ in 0..inp.below(3) {
        u.coinbase_txids.push(inp.arr());
    }
    for _ in 0..inp.below(3) {
        u.tx_index_keys.push(inp.arr());
    }
    if inp.bool() {
        for _ in 0..inp.below(3) {
            u.overwritten.utxos.push(entry(inp));
        }
        for _ in 0..inp.below(3) {
            u.overwritten.coinbase_heights.push((inp.arr(), inp.u64()));
        }
        for _ in 0..inp.below(3) {
            u.overwritten.tx_index.push((inp.arr(), inp.arr(), inp.u64()));
        }
    }
    u
}

fn check_decoded(bytes: &[u8], u: &UndoData) {
    let again = u.to_bytes().expect("a decoded record re-encodes");
    let back = UndoData::from_bytes(&again).expect("a re-encoded record decodes");
    assert!(same_undo(&back, u), "decode(encode(decode(b))) != decode(b)");
    // The stored form: legacy alone iff nothing was overwritten.
    let legacy = legacy_bytes(u);
    if u.overwritten.is_empty() {
        assert_eq!(again, legacy);
    } else {
        assert!(again.starts_with(&legacy));
        assert_eq!(&again[legacy.len()..legacy.len() + 4], &UNDO_EXTENSION_MAGIC);
    }
    // When the input starts with the canonical legacy record, anything after
    // it was a well-formed extension (bincode itself also accepts
    // non-minimal varints, so the legacy prefix of `bytes` may be longer).
    if bytes.len() > legacy.len() && bytes.starts_with(&legacy) {
        assert_eq!(&bytes[legacy.len()..legacy.len() + 4], &UNDO_EXTENSION_MAGIC, "a trailing non-extension was accepted");
    }
}

fuzz_target!(|data: &[u8]| {
    let mut inp = Input::new(data);
    if inp.u8() & 1 == 0 {
        // Untrusted stored bytes.
        let bytes = inp.rest();
        if let Ok(u) = UndoData::from_bytes(bytes) {
            check_decoded(bytes, &u);
        }
        return;
    }
    let u = gen_undo(&mut inp);
    let enc = u.to_bytes().expect("encode");
    let back = UndoData::from_bytes(&enc).expect("a generated record decodes");
    assert!(same_undo(&back, &u), "decode(encode(undo)) != undo");
    let legacy = legacy_bytes(&u);
    assert!(enc.starts_with(&legacy), "the legacy fields are not a prefix of the stored record");
    let alone = UndoData::from_bytes(&legacy).expect("the legacy prefix decodes alone");
    assert!(same_undo(&alone, &UndoData { overwritten: UndoOverwrites::default(), ..u.clone() }));
    if u.overwritten.is_empty() {
        assert_eq!(enc, legacy, "a record without overwrites is not the legacy record");
    }
    // An empty extension is accepted and normalised away.
    let mut empty_ext = legacy.clone();
    empty_ext.extend_from_slice(&UNDO_EXTENSION_MAGIC);
    empty_ext.extend_from_slice(&bincode::serde::encode_to_vec(UndoOverwrites::default(), bincode::config::standard()).unwrap());
    let e = UndoData::from_bytes(&empty_ext).expect("empty extension");
    assert!(e.overwritten.is_empty());
    // Trailing garbage (not the magic) and a truncated extension are refused.
    let junk = inp.u8();
    let mut bad = enc.clone();
    bad.push(junk);
    assert!(UndoData::from_bytes(&bad).is_err(), "a trailing byte after the record was accepted");
    if enc.len() > legacy.len() {
        let mut cut = enc.clone();
        cut.pop();
        assert!(UndoData::from_bytes(&cut).is_err(), "a truncated extension was accepted");
    }
});
