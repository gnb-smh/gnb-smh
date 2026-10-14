//! Stateful mempool fuzzing: an op stream of add / remove / remove_confirmed
//! decoded from the input drives a real `Mempool`, and after every op the
//! three-way `txs` <-> `spent` <-> `rate_index` invariant
//! (`Mempool::debug_check_invariants`) must hold. Same op VM as
//! `floor_mempool_ops_no_panic` in node/tests/parser_corpus_floor.rs, which
//! replays the seed corpus on stable.
#![no_main]

use gnb::core::{Transaction, TxInput, TxOutput};
use gnb::mempool::Mempool;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mp = Mempool::new();
    let mut i = 0usize;
    let mut live: Vec<[u8; 32]> = Vec::new();
    let next = |i: &mut usize| {
        let b = data.get(*i).copied().unwrap_or(0);
        *i += 1;
        b
    };
    let mut ops = 0;
    while i < data.len() && ops < 2048 {
        ops += 1;
        match next(&mut i) % 3 {
            0 => {
                let n_in = 1 + (next(&mut i) % 3) as usize;
                let inputs = (0..n_in)
                    .map(|_| {
                        let mut txid = [0u8; 32];
                        for b in txid.iter_mut() {
                            *b = next(&mut i);
                        }
                        TxInput {
                            prev_txid: txid,
                            prev_index: next(&mut i) as u32,
                            script_sig: vec![0u8; 8],
                            sequence: 0xffff_ffff,
                        }
                    })
                    .collect();
                let tx = Transaction {
                    version: 1,
                    inputs,
                    outputs: vec![TxOutput { value: 1_000, script_pubkey: vec![1u8; 20] }],
                    locktime: 0,
                };
                if let Ok(txid) = mp.add(tx, 100_000 + next(&mut i) as u64) {
                    live.push(txid);
                }
            }
            1 => {
                if !live.is_empty() {
                    let idx = (next(&mut i) as usize) % live.len();
                    let txid = live.swap_remove(idx);
                    mp.remove(&txid);
                }
            }
            _ => {
                let n = (next(&mut i) % 4) as usize;
                let mut batch = Vec::new();
                for _ in 0..n {
                    if live.is_empty() {
                        break;
                    }
                    let idx = (next(&mut i) as usize) % live.len();
                    batch.push(live.swap_remove(idx));
                }
                mp.remove_confirmed(&batch);
            }
        }
        mp.debug_check_invariants().expect("mempool invariant");
    }
});
