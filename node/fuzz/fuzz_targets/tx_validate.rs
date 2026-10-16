#![no_main]
//! Decode a transaction, then run the full per-transaction rule set against a
//! UTXO view that pays every input to the key or policy its witness reveals,
//! so fuzzed bytes reach signature and policy verification (an empty view
//! would stop at "missing input"). Also checks the wire encoding round-trips.
//! Must reject or accept, never panic.
use libfuzzer_sys::fuzz_target;
use gnb::core::{policy::PolicyWitness, Transaction, TxOutput};
use sha3::{Digest, Sha3_256};

fuzz_target!(|data: &[u8]| {
    let Ok(tx) = Transaction::from_wire_bytes(data) else { return };
    let wire = tx.to_wire_bytes(true);
    let again = Transaction::from_wire_bytes(&wire).expect("re-encoding must decode");
    assert_eq!(again.to_wire_bytes(true), wire, "wire encoding must round-trip");

    let spk_for = |script_sig: &[u8]| -> Vec<u8> {
        if let Some((_, pk)) = Transaction::parse_script_sig(script_sig) {
            Sha3_256::digest(&pk)[..20].to_vec()
        } else if let Ok(w) = PolicyWitness::decode(script_sig) {
            w.policy.script_pubkey()
        } else {
            vec![0u8; 20]
        }
    };
    let views: Vec<_> = tx.inputs.iter()
        .map(|i| ((i.prev_txid, i.prev_index), spk_for(&i.script_sig)))
        .collect();
    let utxo = |t: &[u8; 32], i: u32| -> Result<Option<TxOutput>, String> {
        Ok(views.iter().find(|(o, _)| *o == (*t, i))
            .map(|(_, spk)| TxOutput { value: u64::MAX / 4, script_pubkey: spk.clone() }))
    };
    let confirm = |_: &[u8; 32]| -> Result<Option<u64>, String> { Ok(Some(0)) };
    let ctx = gnb::blockval::SpendContext { height: 10_000_000, confirm_height: &confirm };
    let _ = gnb::blockval::validate_tx_inputs(&tx, &utxo, None, &ctx);
});
