//! `coherence_core::verify_path` on untrusted proofs. Input layout (as in the
//! seed corpus): leaf (32) | root (32) | index (u64 le) | path (32 bytes each).
//! Never panics; a path of the wrong length and an index with bits above the
//! tree depth never verify (the second would let one note be spent under many
//! nullifiers).
#![no_main]

use coherence_core::{verify_path, TREE_DEPTH};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 72 {
        return;
    }
    let leaf: [u8; 32] = data[0..32].try_into().unwrap();
    let root: [u8; 32] = data[32..64].try_into().unwrap();
    let index = u64::from_le_bytes(data[64..72].try_into().unwrap());
    let path: Vec<[u8; 32]> = data[72..].chunks_exact(32).map(|c| c.try_into().unwrap()).collect();
    let ok = verify_path(&leaf, index, &path, &root);
    if path.len() != TREE_DEPTH || index >> TREE_DEPTH != 0 {
        assert!(!ok, "malformed proof verified");
    }
    if ok {
        let high = index | (1u64 << TREE_DEPTH);
        assert!(!verify_path(&leaf, high, &path, &root), "index above the tree depth verified");
    }
});
