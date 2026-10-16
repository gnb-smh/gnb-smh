//! Policy spends must survive every transport, not only in-memory validation.
//!
//! The wire decoder used to cap `script_sig` at 10,000 bytes, so any policy
//! with more than one key (1-of-2: ~12 KB, 2-of-3: ~20 KB) was valid by
//! consensus but could not be relayed, mined or stored — the team's 2-of-3
//! vesting tranches among them. Each m-of-n up to 7-of-7 here goes through the
//! transaction wire format, the block wire format, storage, the mempool, and
//! block validation of the decoded copy.

use gnb::address::Network;
use gnb::blockval::validate_block_transactions;
use gnb::core::policy::{SpendPolicy, MAX_POLICY_KEYS, MAX_POLICY_WITNESS_LEN};
use gnb::core::{create_genesis_block_with, Block, Transaction, TxInput, TxOutput, MAX_SCRIPT_SIG_LEN};
use gnb::crypto;
use gnb::mempool::Mempool;
use gnb::storage::Storage;
use gnb::wallet::policy_spend::PolicySpend;

const PREV: [u8; 32] = [7u8; 32];
const VALUE: u64 = 10_000_000;

fn policy_spend(m: u8, n: usize) -> (SpendPolicy, Transaction) {
    let keys: Vec<_> = (0..n).map(|_| crypto::generate_keypair()).collect();
    let policy = SpendPolicy::new(m, keys.iter().map(|k| k.0.clone()).collect(), 0, 0).unwrap();
    let mut spend = PolicySpend::new(Network::Mainnet, policy.clone(), &[(PREV, 0, VALUE)],
                                     vec![1u8; 20], 1_000_000, 0, 0).unwrap();
    // Sign with the last m keys, so key indices other than 0..m are exercised.
    for k in keys.iter().skip(n - m as usize) {
        spend.sign(&k.0, |msg| crypto::sign(&k.1, msg).map_err(|e| format!("{e:?}"))).unwrap();
    }
    (policy, spend.finalize().unwrap())
}

fn block_with(tx: &Transaction) -> Block {
    let mut b = create_genesis_block_with(0, 0x2100_FFFF, 0);
    b.height = 1;
    b.transactions.push(tx.clone());
    b.header.merkle_root = Transaction::merkle_root(&b.transactions);
    b
}

#[test]
fn script_sig_cap_covers_the_largest_policy_witness() {
    assert_eq!(MAX_SCRIPT_SIG_LEN, MAX_POLICY_WITNESS_LEN);
    assert!(MAX_SCRIPT_SIG_LEN >= 100_000, "7 keys + 7 signatures must fit");
}

#[test]
fn every_policy_spend_round_trips_through_wire_block_storage_and_mempool() {
    let tmp = tempfile::TempDir::new().unwrap();
    let store = Storage::open(tmp.path()).unwrap();

    let shapes: Vec<(u8, usize)> = vec![(1, 1), (1, 2), (2, 3), (3, 5), (MAX_POLICY_KEYS as u8, MAX_POLICY_KEYS)];
    for (m, n) in shapes {
        let (policy, tx) = policy_spend(m, n);
        let witness = tx.inputs[0].script_sig.len();
        assert!(witness <= MAX_SCRIPT_SIG_LEN, "{m}-of-{n}: witness {witness} B over the cap");

        // Transaction wire format.
        let decoded = Transaction::from_wire_bytes(&tx.to_wire_bytes(true))
            .unwrap_or_else(|e| panic!("{m}-of-{n} ({witness} B): tx decode failed: {e}"));
        assert_eq!(decoded.to_wire_bytes(true), tx.to_wire_bytes(true), "{m}-of-{n}: tx changed in transit");

        // Block wire format (P2P relay) and storage.
        let block = block_with(&tx);
        let back = Block::from_wire_bytes(&block.to_wire_bytes())
            .unwrap_or_else(|e| panic!("{m}-of-{n}: block decode failed: {e}"));
        assert_eq!(back.transactions[1].to_wire_bytes(true), tx.to_wire_bytes(true));
        store.put_block(&block).unwrap();
        let stored = store.get_block(&block.block_hash()).unwrap().expect("stored block");
        assert_eq!(stored.transactions[1].to_wire_bytes(true), tx.to_wire_bytes(true), "{m}-of-{n}: storage round trip");

        // The decoded copy still validates by consensus.
        let spk = policy.script_pubkey();
        let utxo = move |t: &[u8; 32], i: u32| -> Result<Option<TxOutput>, String> {
            Ok((*t == PREV && i == 0).then(|| TxOutput { value: VALUE, script_pubkey: spk.clone() }))
        };
        let none = |_: &[u8; 32]| -> Result<Option<u64>, String> { Ok(None) };
        let mut validated = back.clone();
        validated.transactions[0] = Transaction {
            version: 1,
            inputs: vec![TxInput { prev_txid: [0u8; 32], prev_index: u32::MAX,
                                   script_sig: b"cb".to_vec(), sequence: u32::MAX }],
            outputs: vec![TxOutput { value: 1_000, script_pubkey: vec![2u8; 20] }],
            locktime: 0,
        };
        validate_block_transactions(&validated, &utxo, &none, &none)
            .unwrap_or_else(|e| panic!("{m}-of-{n}: decoded spend rejected: {e:?}"));

        // Mempool admission (size and fee-rate gates).
        Mempool::new().add(decoded, VALUE - 1_000_000)
            .unwrap_or_else(|e| panic!("{m}-of-{n}: mempool rejected: {e:?}"));
        println!("{m}-of-{n}: witness {witness} B, ok");
    }
}

#[test]
fn oversized_script_sig_is_still_refused() {
    let tx = Transaction {
        version: 1,
        inputs: vec![TxInput { prev_txid: PREV, prev_index: 0,
                               script_sig: vec![0u8; MAX_SCRIPT_SIG_LEN + 1], sequence: u32::MAX }],
        outputs: vec![TxOutput { value: 1, script_pubkey: vec![1u8; 20] }],
        locktime: 0,
    };
    assert!(Transaction::from_wire_bytes(&tx.to_wire_bytes(true)).is_err());
}
