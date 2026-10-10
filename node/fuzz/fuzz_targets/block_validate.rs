#![no_main]
//! Parse, then run the context-free structural checks and the full
//! transaction rule set against an empty UTXO view. Exercises the consensus
//! validation code on attacker-shaped blocks; it must reject, never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(block) = gnb::core::Block::from_wire_bytes(data) {
        if block.validate_structure_cheap().is_ok() {
            let utxo = |_: &[u8; 32], _: u32| Ok(None);
            let coinbase = |_: &[u8; 32]| Ok(None);
            let _ = gnb::blockval::validate_block_transactions(&block, &utxo, &coinbase);
        }
    }
});
