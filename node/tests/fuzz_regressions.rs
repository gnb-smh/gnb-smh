//! Regressions for defects found by the cargo-fuzz campaign (node/fuzz,
//! docs/testing/FUZZING.md). Each test pins the minimized crashing input the
//! fuzzer reported (also committed as `fuzz/corpus/<target>/regress_*`) and
//! the root-cause property it violated.

use gnb::core::{Block, BlockHeader, MerkleRoot, Transaction, TxInput, TxOutput};

/// `wire_roundtrip` crash: a header whose parent count is `FD 01 00` decoded
/// to the header encoded with `01`. Every wire decoder now refuses
/// non-minimal varints (unit tests `wire_canonical_tests` in gnb-crypto cover
/// each field and the block framing).
#[test]
fn header_with_a_non_minimal_parent_count_is_refused() {
    let crash = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/fuzz/corpus/wire_roundtrip/regress_nonminimal_parent_count"))
        .expect("committed crash input");
    // Mode byte 3 (untrusted bytes), two cut bytes, then the header.
    assert_eq!(crash[0] % 4, 3);
    assert!(BlockHeader::from_wire_bytes(&crash[3..]).is_err(), "the fuzzer's header is still accepted");

    let h = BlockHeader { version: 1, parents: vec![[0x33; 32]], merkle_root: MerkleRoot([0x44; 32]), timestamp: 9, bits: 0x2100_FFFF, nonce: 7 };
    let enc = h.to_wire_bytes(1, 1);
    let mut wide = enc[..4].to_vec();
    wide.extend_from_slice(&[0xFD, 0x01, 0x00]);
    wide.extend_from_slice(&enc[5..]);
    assert!(BlockHeader::from_wire_bytes(&enc).is_ok());
    assert!(BlockHeader::from_wire_bytes(&wide).is_err());

    // The same through a block and a transaction.
    let tx = Transaction {
        version: 1,
        inputs: vec![TxInput { prev_txid: [1; 32], prev_index: 0, script_sig: vec![9; 4], sequence: 0 }],
        outputs: vec![TxOutput { value: 1, script_pubkey: vec![2; 20] }],
        locktime: 0,
    };
    let b = Block { header: h, transactions: vec![tx], blue_score: 1, height: 1, shielded_transactions: vec![] };
    let enc = b.to_wire_bytes();
    assert_eq!(Block::from_wire_bytes(&enc).unwrap().to_wire_bytes(), enc);
    let mut wide = enc[..4].to_vec();
    wide.extend_from_slice(&[0xFD, 0x01, 0x00]);
    wide.extend_from_slice(&enc[5..]);
    assert!(Block::from_wire_bytes(&wide).is_err());
}
