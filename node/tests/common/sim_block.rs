//! Carry an arbitrary test payload inside a REAL block.
//!
//! The network edge verifies every received block's structure and GnB-SMH
//! proof of work before relaying it (`network::pow_gate`). Transport tests
//! that only care about mesh delivery wrap their payload in a block with a
//! valid structure and a valid proof at the test pow limit (one evaluation),
//! and unwrap it on the receiving side. The payload's hash is committed in
//! the coinbase output, so distinct payloads give distinct block ids.

use gnb::core::{self, Block, BlockHeader, MerkleRoot, Transaction, TxInput, TxOutput};
use sha3::{Digest, Sha3_256};

pub fn wrap(payload: &[u8]) -> Vec<u8> {
    let mut b = block_for(payload, core::POW_LIMIT_BITS);
    let pre = b.header.pow_preimage();
    b.header.nonce = gnb::pow::mine(&pre, b.header.bits, b.height, 0, 256).expect("solve at the pow limit");
    b.to_wire_bytes()
}

/// A structurally valid block whose proof of work does NOT verify: `bits`
/// harder than the floor (passes the precheck), nonce chosen to fail.
pub fn wrap_with_invalid_pow(payload: &[u8]) -> Vec<u8> {
    let mut b = block_for(payload, core::GENESIS_BITS);
    while b.validate_pow() {
        b.header.nonce += 1;
    }
    b.to_wire_bytes()
}

fn block_for(payload: &[u8], bits: u32) -> Block {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let coinbase = Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid: [0u8; 32],
            prev_index: u32::MAX,
            script_sig: payload.to_vec(),
            sequence: u32::MAX,
        }],
        outputs: vec![TxOutput { value: 0, script_pubkey: Sha3_256::digest(payload).to_vec() }],
        locktime: 0,
    };
    let mut b = Block {
        header: BlockHeader {
            version: 1,
            parents: vec![[0x11u8; 32]],
            merkle_root: MerkleRoot::ZERO,
            timestamp: now,
            bits,
            nonce: 0,
        },
        transactions: vec![coinbase],
        blue_score: 1,
        height: 1,
        shielded_transactions: Vec::new(), powit: Default::default(),
    };
    b.header.merkle_root = b.body_merkle_root();
    b
}

pub fn unwrap(bytes: &[u8]) -> Option<Vec<u8>> {
    let b = Block::from_wire_bytes(bytes).ok()?;
    Some(b.transactions.first()?.inputs.first()?.script_sig.clone())
}
