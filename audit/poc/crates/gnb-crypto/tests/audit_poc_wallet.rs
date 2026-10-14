//! Audit proof-of-concept tests (wallet / key-management area).
//!
//! Each test documents an observed property of the CURRENT code. A test that
//! passes here CONFIRMS the audit finding named in its doc comment (the
//! asserted behaviour is the weakness), unless the comment says it is a
//! positive control.

use gnb_crypto::address::{Address, Network};
use gnb_crypto::core::{ChainId, TxOutput};
use gnb_crypto::wallet::encryption::EncryptedKeyfile;
use gnb_crypto::wallet::{generate_keypair, Keypair, TxBuilder, Utxo, Wallet, WalletError};

const SAT: u64 = 100_000_000;

/// WAL-1: the signature does not commit to the value of the coins it spends,
/// and the builders take UTXO values from the (untrusted) RPC/explorer as-is.
///
/// Two very different "views" of the same coin produce a byte-identical
/// unsigned transaction and identical per-input sighashes:
///   view A (honest-looking): coin = 1.0005 GNB -> amount 1 GNB + fee 0.0005
///   view B (the truth):      coin = 100 GNB    -> amount 1 GNB + fee 99 GNB
/// The wallet shows/thinks A; the network evaluates B. A data source that
/// under-reports values therefore makes the user sign away the difference as
/// fee, and the signer has no way to detect it.
#[test]
fn wal1_sighash_is_independent_of_spent_amounts_and_builder_trusts_rpc_values() {
    let kp = generate_keypair(false);
    let my_spk = kp.address_bytes();
    let dest = Address::from_hash([7u8; 20], Network::Mainnet);
    let dest_hex = hex::encode(dest.hash());
    let txid = vec![0xAB; 32];

    // What a lying API reports.
    let lied = vec![(txid.clone(), 0u32, TxOutput { value: SAT + 50_000, script_pubkey: my_spk.clone() })];
    let tx_lied = TxBuilder::build(&kp, &lied, &dest_hex, SAT, 50_000).unwrap();
    assert_eq!(tx_lied.outputs.len(), 1, "no change output: the wallet believes the coin is used up");
    let outputs_total: u64 = tx_lied.outputs.iter().map(|o| o.value).sum();

    // The coin's real value on chain (the node looks it up by outpoint).
    let real_value = 100 * SAT;
    let implied_fee = real_value - outputs_total;
    assert_eq!(implied_fee, 99 * SAT, "99 GNB silently become miner fee");

    // The sighash covers only the transaction body (outpoints + outputs), so a
    // view of the same coin with any other value yields the same digest.
    let other_view = vec![(txid, 0u32, TxOutput { value: real_value, script_pubkey: my_spk })];
    // Build with a fee that makes view B produce the same outputs.
    let tx_truth = TxBuilder::build(&kp, &other_view, &dest_hex, SAT, real_value - SAT).unwrap();
    assert_eq!(tx_truth.outputs.len(), tx_lied.outputs.len());
    assert_eq!(tx_truth.outputs[0].value, tx_lied.outputs[0].value);
    assert_eq!(tx_truth.outputs[0].script_pubkey, tx_lied.outputs[0].script_pubkey);
    assert_eq!(tx_truth.sighash(0, ChainId::Mainnet), tx_lied.sighash(0, ChainId::Mainnet));
    assert_eq!(tx_truth.to_wire_bytes(false), tx_lied.to_wire_bytes(false));

    // And the lied-about transaction carries a valid signature for that digest.
    let (sig, pk) = gnb_crypto::core::Transaction::parse_script_sig(&tx_lied.inputs[0].script_sig).unwrap();
    assert!(gnb_crypto::crypto::verify(&pk, &tx_lied.sighash(0, ChainId::Mainnet), &sig));
}

/// WAL-1 (cont.): `Wallet::build_tx` has no maximum-fee guard and spends every
/// UTXO it is handed; `WalletClient::send` feeds it a node-chosen absolute fee.
#[test]
fn wal1_build_tx_accepts_fee_equal_to_almost_all_inputs() {
    let (wallet, _) = Wallet::generate(Network::Testnet).unwrap();
    let dest = Address::from_hash([9u8; 20], Network::Testnet);
    let utxos = vec![
        Utxo { txid: [1; 32], index: 0, output: TxOutput { value: 50 * SAT, script_pubkey: wallet.address().hash().to_vec() } },
        Utxo { txid: [2; 32], index: 0, output: TxOutput { value: 50 * SAT, script_pubkey: wallet.address().hash().to_vec() } },
    ];
    // Pay 1 satoshi, "fee" 99.99999999 GNB: accepted without complaint.
    let tx = wallet.build_tx(utxos, &dest, 1, 100 * SAT - 1).unwrap();
    assert_eq!(tx.inputs.len(), 2, "all supplied UTXOs are spent, no selection");
    assert_eq!(tx.outputs.len(), 1);
    assert_eq!(tx.outputs[0].value, 1);
}

/// WAL-7: the keystore format written by gnb-cli `newwallet`, postern-wallet
/// `new` and the web wallet `export` (legacy `EncryptedKeystore` v2) does not
/// authenticate its network. The address checksum does not cover the prefix,
/// so editing the stored address from gnb1q… to gnb1t… still loads, and the
/// key then signs under the testnet chain-id.
#[test]
fn wal7_legacy_keystore_network_prefix_is_not_authenticated() {
    let kp = generate_keypair(false);
    assert!(kp.address.starts_with("gnb1q"));
    let password = "Audit-PoC-password-17!";
    let json = kp.to_encrypted_json(password).unwrap();
    let flipped_addr = format!("gnb1t{}", &kp.address[5..]);
    let tampered = json.replace(&kp.address, &flipped_addr);
    assert_ne!(tampered, json);

    let loaded = Keypair::from_encrypted_bytes(tampered.as_bytes(), password)
        .expect("tampered network prefix is accepted");
    assert_eq!(loaded.address, flipped_addr);
    assert_eq!(loaded.public_key, kp.public_key);
    // The stored `network` JSON field still says "mainnet"; nothing checks it.
    assert!(tampered.contains("\"network\": \"mainnet\""));
}

/// Positive control for WAL-7: the newer `EncryptedKeyfile` v1 binds the
/// network and public key into the AES-GCM AAD, so the same edit fails.
#[test]
fn wal7_control_v1_keyfile_binds_network_in_aad() {
    let params = gnb_crypto::wallet::encryption::KdfParams { m_cost: 1024, t_cost: 1, p_cost: 1 };
    let mut kf = EncryptedKeyfile::encrypt_with_params(b"secret", b"public", Network::Mainnet,
        "Audit-PoC-password-17!", params).unwrap();
    kf.network = gnb_crypto::wallet::encryption::NetworkStr::Testnet;
    assert!(matches!(kf.decrypt("Audit-PoC-password-17!"), Err(WalletError::WrongPassword)));
}

/// WAL-6: the `bip39` crate is built without its `zeroize` feature, so the
/// `Mnemonic` held for the whole lifetime of `HdWallet` (and every temporary
/// one created by `SeedPhrase::{generate,parse}` and `HdWallet::{create,
/// recover,load}`) has no destructor: its word indices are never wiped.
#[test]
fn wal6_bip39_mnemonic_has_no_wiping_destructor() {
    assert!(!std::mem::needs_drop::<bip39::Mnemonic>(),
        "bip39::Mnemonic now has a Drop impl - finding WAL-6 would be fixed");
    // The HD wallet exposes that type as a public field.
    fn _field_type(w: &gnb_crypto::hd_wallet::HdWallet) -> &bip39::Mnemonic { &w.mnemonic }
}

/// WAL-8: the legacy builder's smallest-first greedy selection maximises the
/// number of ~8.5 kB post-quantum inputs, and change at or below 546 sat is
/// silently added to the fee (the web wallet reports only the requested fee).
#[test]
fn wal8_smallest_first_selection_and_silent_dust_to_fee() {
    let kp = generate_keypair(false);
    let spk = kp.address_bytes();
    let dest_hex = hex::encode([5u8; 20]);
    // One 10 GNB coin and ten 0.2 GNB coins; paying 1 GNB.
    let mut utxos = vec![(vec![0xEE; 32], 0u32, TxOutput { value: 10 * SAT, script_pubkey: spk.clone() })];
    for i in 0..10u8 {
        utxos.push((vec![i; 32], 0, TxOutput { value: SAT / 5, script_pubkey: spk.clone() }));
    }
    let tx = TxBuilder::build(&kp, &utxos, &dest_hex, SAT, 10_000).unwrap();
    assert_eq!(tx.inputs.len(), 6, "six small inputs chosen instead of the single large coin");
    let size = tx.to_wire_bytes(true).len();
    assert!(size > 45_000, "~{} bytes for a 1 GNB payment", size);

    // Dust change: inputs - amount - fee = 546 -> dropped, real fee = 10_546.
    let exact = vec![(vec![0xEF; 32], 0u32, TxOutput { value: SAT + 10_000 + 546, script_pubkey: spk })];
    let tx = TxBuilder::build(&kp, &exact, &dest_hex, SAT, 10_000).unwrap();
    assert_eq!(tx.outputs.len(), 1);
    let real_fee = SAT + 10_000 + 546 - tx.outputs[0].value;
    assert_eq!(real_fee, 10_546);
}
