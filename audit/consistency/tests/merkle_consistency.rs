//! Transaction Merkle tree: GnB vs Bitcoin Core vs rust-bitcoin.
//!
//! GnB reuses Bitcoin's construction (double SHA-256, duplicate the last hash
//! on odd levels). These tests show that the roots are bit-identical to
//! rust-bitcoin's `merkle_tree::calculate_root` and to a port of Core's
//! `ComputeMerkleRoot` (src/consensus/merkle.cpp), and therefore that GnB
//! inherits CVE-2012-2459: distinct transaction lists share one root. Core
//! reports such lists through the `mutated` out-parameter and refuses to cache
//! them as invalid; GnB's `merkle_root` has no such signal.
//!
//! They also document that a non-coinbase txid excludes `script_sig`, so the
//! header (and block id) does not commit to signatures.

use bitcoin::hashes::Hash;
use bitcoin::TxMerkleNode;
use gnb_audit_consistency::core_compute_merkle_root;
use gnb_crypto::core::{Block, BlockHeader, MerkleRoot, Transaction, TxInput, TxOutput};
use proptest::prelude::*;

fn tx(seed: u8, sig: &[u8]) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid: [seed; 32],
            prev_index: seed as u32,
            script_sig: sig.to_vec(),
            sequence: u32::MAX,
        }],
        outputs: vec![TxOutput { value: 1_000 + seed as u64, script_pubkey: vec![seed; 20] }],
        locktime: 0,
    }
}

fn btc_root(txids: &[[u8; 32]]) -> [u8; 32] {
    bitcoin::merkle_tree::calculate_root(txids.iter().map(|t| TxMerkleNode::from_byte_array(*t)))
        .map(|r| r.to_byte_array())
        .unwrap_or([0u8; 32])
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    #[test]
    fn merkle_root_matches_rust_bitcoin_and_core(seeds in proptest::collection::vec(any::<u8>(), 1..70)) {
        let txs: Vec<Transaction> = seeds.iter().enumerate()
            .map(|(i, s)| { let mut t = tx(*s, b""); t.locktime = i as u32; t })
            .collect();
        let txids: Vec<[u8; 32]> = txs.iter().map(|t| t.txid()).collect();
        let gnb = Transaction::merkle_root(&txs).0;
        prop_assert_eq!(gnb, btc_root(&txids));
        prop_assert_eq!(gnb, core_compute_merkle_root(txids).0);
    }
}

#[test]
fn cve_2012_2459_duplicate_tail_collides() {
    let (a, b, c) = (tx(1, b""), tx(2, b""), tx(3, b""));
    let honest = vec![a.clone(), b.clone(), c.clone()];
    let mutated = vec![a.clone(), b.clone(), c.clone(), c.clone()];
    assert_eq!(Transaction::merkle_root(&honest), Transaction::merkle_root(&mutated));
    let ids = |v: &[Transaction]| v.iter().map(|t| t.txid()).collect::<Vec<_>>();
    assert!(!core_compute_merkle_root(ids(&honest)).1);
    assert!(core_compute_merkle_root(ids(&mutated)).1, "Core flags the duplicate as mutated");

    // Six transactions: duplicating the last two also collides.
    let six: Vec<_> = (10..16).map(|s| tx(s, b"")).collect();
    let mut eight = six.clone();
    eight.push(six[4].clone());
    eight.push(six[5].clone());
    assert_eq!(Transaction::merkle_root(&six), Transaction::merkle_root(&eight));
    assert!(core_compute_merkle_root(ids(&eight)).1);

    // Same header, same block id, two different bodies.
    let header = BlockHeader {
        version: 1,
        parents: vec![[7u8; 32]],
        merkle_root: Transaction::merkle_root(&honest),
        timestamp: 1_800_000_000,
        bits: 0x2100_ffff,
        nonce: 0,
    };
    let b1 = Block { header: header.clone(), transactions: honest, blue_score: 0, height: 1,
                     shielded_transactions: vec![] };
    let b2 = Block { header, transactions: mutated, blue_score: 0, height: 1,
                     shielded_transactions: vec![] };
    assert!(b1.validate_merkle() && b2.validate_merkle());
    assert_eq!(b1.block_hash(), b2.block_hash());
}

#[test]
fn block_id_does_not_commit_to_signatures() {
    // Non-coinbase txids are computed without script_sig (anti-malleability),
    // so the Merkle root, the header and the block id are identical for two
    // bodies that differ only in signature bytes.
    let honest = vec![tx(1, b"valid-signature-bytes")];
    let forged = vec![tx(1, b"garbage")];
    assert_eq!(honest[0].txid(), forged[0].txid());
    assert_eq!(Transaction::merkle_root(&honest), Transaction::merkle_root(&forged));
    let header = BlockHeader {
        version: 1,
        parents: vec![[9u8; 32]],
        merkle_root: Transaction::merkle_root(&honest),
        timestamp: 1_800_000_000,
        bits: 0x2100_ffff,
        nonce: 0,
    };
    let b1 = Block { header: header.clone(), transactions: honest, blue_score: 0, height: 1,
                     shielded_transactions: vec![] };
    let b2 = Block { header, transactions: forged, blue_score: 0, height: 1,
                     shielded_transactions: vec![] };
    assert!(b1.validate_merkle() && b2.validate_merkle());
    assert_eq!(b1.block_hash(), b2.block_hash());
}

#[test]
fn empty_body_root_is_zero() {
    assert_eq!(Transaction::merkle_root(&[]), MerkleRoot::ZERO);
}
