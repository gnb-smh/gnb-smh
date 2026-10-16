//! Wire encoding round trips of `Transaction`, `BlockHeader` and `Block`
//! (consensus encodings: txids, the Merkle roots and the block-size rule are
//! computed from them).
//!
//! Generated values (`x`):
//! * `encode(x)` equals an independent encoder written from the format
//!   specification, and `wire_size` equals its length;
//! * `decode(encode(x)) == x` exactly when `x` obeys the parser caps
//!   (`limits::check_*_canonical_limits`, which promise that round trip);
//!   values at and one past the script-length caps (10,000 bytes) and the
//!   parent cap (256) are generated on purpose. The count and size caps
//!   (inputs, outputs, block and shielded transactions, nullifiers, shielded
//!   outputs, proof and binding signature) take 100 KB to 10 MB to reach and
//!   are not generated here: the unit test
//!   `core::limits::tests::count_and_size_caps_match_the_wire_parser`
//!   checks each of them at and one past its cap;
//! * every proper prefix of `encode(x)` is refused, and so is one extra byte
//!   for the decoders that promise to be strict (`Block`, `BlockHeader`, the
//!   gossip/RPC transaction decoder `admission::decode_tx_strict`).
//!
//! Untrusted bytes (`b`):
//! * the strict decoders are the inverse of the encoder: `decode(b) = x`
//!   implies `encode(x) == b` (one encoding per value: no malleable copies,
//!   and the framing of a block's transactions is the framing of the
//!   transaction decoder);
//! * a decoded value obeys the canonical limits and decodes again from its
//!   encoding to the same value.
#![no_main]

mod common;

use common::*;
use gnb::mempool::admission::decode_tx_strict;
use gnb_crypto::core::limits::{check_block_canonical_limits, check_tx_canonical_limits};
use gnb_crypto::core::{Block, BlockHeader, MerkleRoot, Transaction, TxInput};
use libfuzzer_sys::fuzz_target;

/// A length near a parser cap now and then, small otherwise.
fn len_near(inp: &mut Input, cap: usize, small: usize) -> usize {
    match inp.u8() % 16 {
        0 => cap,
        1 => cap + 1,
        _ => inp.below(small + 1),
    }
}

fn gen_tx_caps(inp: &mut Input) -> Transaction {
    let mut tx = gen_tx(inp, 4, 4, 24);
    // Occasionally push one script to (or past) its 10,000-byte cap.
    match inp.u8() % 24 {
        0 if !tx.inputs.is_empty() => {
            let n = len_near(inp, 10_000, 0).max(9_999);
            tx.inputs[0].script_sig = vec![0xA5; n];
        }
        1 if !tx.outputs.is_empty() => {
            let n = len_near(inp, 10_000, 0).max(9_999);
            tx.outputs[0].script_pubkey = vec![0x5A; n];
        }
        2 => {
            // varint boundaries of the script length (0xFC / 0xFD, 0xFFFF)
            let n = [0xFC, 0xFD, 0xFE, 0xFF, 0x100][inp.below(5)];
            tx.inputs.push(TxInput { prev_txid: [3; 32], prev_index: 1, script_sig: vec![1; n], sequence: 2 });
        }
        _ => {}
    }
    tx
}

fn gen_header(inp: &mut Input) -> (BlockHeader, u64, u64) {
    let n = len_near(inp, 256, 4);
    let h = BlockHeader {
        version: inp.u32(),
        parents: (0..n).map(|i| if i < 8 { inp.arr() } else { [i as u8; 32] }).collect(),
        merkle_root: MerkleRoot(inp.arr()),
        timestamp: inp.u64(),
        bits: inp.u32(),
        nonce: inp.u64(),
    };
    (h, inp.u64(), inp.u64())
}

fn gen_block(inp: &mut Input) -> Block {
    let (header, blue_score, height) = gen_header(inp);
    let n_tx = inp.below(4);
    let transactions = (0..n_tx).map(|_| gen_tx_caps(inp)).collect();
    let n_sh = inp.below(3);
    let shielded_transactions = (0..n_sh)
        .map(|_| coherence_core::ShieldedTx {
            anchor: inp.arr(),
            nullifiers: (0..inp.below(3)).map(|_| inp.arr()).collect(),
            outputs: (0..inp.below(3)).map(|_| inp.arr()).collect(),
            fee: inp.u64(),
            proof: inp.var_bytes(64),
            binding_sig: inp.var_bytes(32),
        })
        .collect();
    // The PoWit section is empty, as on every block the node builds below
    // `powit_height()` and on its templates without witness items; from
    // `powit_height()` it is still encoded (three zero counts) and checked
    // against the reference. Non-empty sections come from the untrusted
    // inputs (mode 3).
    Block { header, transactions, blue_score, height, shielded_transactions, powit: Default::default() }
}

fn prefixes_refused<T>(enc: &[u8], decode: impl Fn(&[u8]) -> Result<T, String>, cut: usize) {
    if enc.is_empty() {
        return;
    }
    for n in [0, cut % enc.len(), enc.len() - 1] {
        assert!(decode(&enc[..n]).is_err(), "a {n}-byte prefix of a {}-byte encoding decoded", enc.len());
    }
}

fn check_tx(tx: &Transaction, cut: usize) {
    let enc = tx.to_wire_bytes(true);
    assert_eq!(enc, ref_tx_wire(tx, true), "transaction encoding differs from the reference");
    assert_eq!(tx.wire_size(true), enc.len());
    assert_eq!(tx.to_wire_bytes(false), ref_tx_wire(tx, false));
    let fits = check_tx_canonical_limits(tx).is_ok();
    match Transaction::from_wire_bytes(&enc) {
        Ok(back) => {
            assert!(fits, "a transaction over the canonical limits decoded");
            assert!(same(&back, tx), "decode(encode(tx)) != tx");
            assert_eq!(back.txid(), tx.txid());
            assert!(same(&decode_tx_strict(&enc).expect("strict decode of a canonical encoding"), tx));
        }
        Err(e) => assert!(!fits, "a transaction within the limits failed to round-trip: {e}"),
    }
    prefixes_refused(&enc, Transaction::from_wire_bytes, cut);
    let mut longer = enc.clone();
    longer.push(0);
    assert!(decode_tx_strict(&longer).is_err(), "strict decoder accepted a trailing byte");
}

fn check_header(h: &BlockHeader, blue: u64, height: u64, cut: usize) {
    let enc = h.to_wire_bytes(blue, height);
    assert_eq!(enc, ref_header_wire(h, blue, height), "header encoding differs from the reference");
    match BlockHeader::from_wire_bytes(&enc) {
        Ok((back, b2, h2)) => {
            assert!(h.parents.len() <= 256, "a header over MAX_PARENTS decoded");
            assert!(same(&back, h) && (b2, h2) == (blue, height), "decode(encode(header)) != header");
            assert_eq!(back.pow_preimage(), h.pow_preimage());
        }
        Err(e) => assert!(h.parents.len() > 256, "a header within the limits failed to round-trip: {e}"),
    }
    prefixes_refused(&enc, |b| BlockHeader::from_wire_bytes(b).map(|_| ()), cut);
    let mut longer = enc.clone();
    longer.push(0);
    assert!(BlockHeader::from_wire_bytes(&longer).is_err(), "header decoder accepted a trailing byte");
}

fn check_block(b: &Block, cut: usize) {
    let enc = b.to_wire_bytes();
    assert_eq!(enc, ref_block_wire(b), "block encoding differs from the reference");
    assert_eq!(b.wire_size(), enc.len(), "Block::wire_size differs from the encoding length");
    let fits = check_block_canonical_limits(b).is_ok();
    match Block::from_wire_bytes(&enc) {
        Ok(back) => {
            assert!(fits, "a block over the canonical limits decoded");
            assert!(same(&back, b), "decode(encode(block)) != block");
            assert_eq!(back.block_hash(), b.block_hash());
        }
        Err(e) => assert!(!fits, "a block within the limits failed to round-trip: {e}"),
    }
    prefixes_refused(&enc, Block::from_wire_bytes, cut);
    let mut longer = enc.clone();
    longer.push(0);
    assert!(Block::from_wire_bytes(&longer).is_err(), "block decoder accepted a trailing byte");
}

fuzz_target!(|data: &[u8]| {
    let mut inp = Input::new(data);
    let mode = inp.u8();
    let cut = inp.u16() as usize;
    match mode % 4 {
        0 => {
            let tx = gen_tx_caps(&mut inp);
            check_tx(&tx, cut);
        }
        1 => {
            let (h, blue, height) = gen_header(&mut inp);
            check_header(&h, blue, height, cut);
        }
        2 => {
            let b = gen_block(&mut inp);
            check_block(&b, cut);
        }
        _ => {
            // Untrusted bytes through every strict decoder.
            let bytes = inp.rest();
            if let Ok(b) = Block::from_wire_bytes(bytes) {
                assert_eq!(b.to_wire_bytes(), bytes, "Block::from_wire_bytes accepted a non-canonical encoding");
                assert!(check_block_canonical_limits(&b).is_ok());
                check_block(&b, cut);
            }
            if let Ok((h, blue, height)) = BlockHeader::from_wire_bytes(bytes) {
                assert_eq!(h.to_wire_bytes(blue, height), bytes, "BlockHeader::from_wire_bytes accepted a non-canonical encoding");
                check_header(&h, blue, height, cut);
            }
            if let Ok(tx) = decode_tx_strict(bytes) {
                assert_eq!(tx.to_wire_bytes(true), bytes, "decode_tx_strict accepted a non-canonical encoding");
            }
            if let Ok(tx) = Transaction::from_wire_bytes(bytes) {
                // The lenient decoder may stop early; what it decoded is a
                // value with a canonical encoding of its own.
                assert!(check_tx_canonical_limits(&tx).is_ok());
                check_tx(&tx, cut);
            }
        }
    }
});
