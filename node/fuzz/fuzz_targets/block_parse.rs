#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = gnb::core::BlockHeader::from_wire_bytes(data);
    if let Ok(block) = gnb::core::Block::from_wire_bytes(data) {
        let _ = block.block_hash();
    }
});
