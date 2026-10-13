//! Benchmark and toy miner for GnB-SMH.
//!
//! smh-bench verify [log2_n] [iters]        time per evaluation (single thread)
//! smh-bench v2 [log2_n] [iters]           time per v2-draft (SHA-256) evaluation
//! smh-bench perm [count]                   raw Keccak-f[1600] permutations per second
//! smh-bench mine <log2_n> <zero_bits> <blocks> [threads]
//!                                          find blocks at a fixed target; prints attempts per block

use gnb_smh::{hash_with, meets_target, Scratchpad, LOG2_N};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// target = 2^(256 - bits), big-endian: valid iff the top `bits` bits of out are zero.
fn target_with_zero_bits(bits: u32) -> [u8; 32] {
    assert!((1..=255).contains(&bits));
    let pos = 256 - bits as usize; // bit index counted from the least significant bit
    let mut t = [0u8; 32];
    t[31 - pos / 8] = 1u8 << (pos % 8);
    t
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("v2") => {
            use gnb_smh::v2;
            let log2_n: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(v2::LOG2_N);
            let iters: u32 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(200);
            let mut sp = v2::Scratchpad::new(log2_n);
            let _ = v2::hash_with(&mut sp, b"warmup", 0);
            let mut samples = Vec::new();
            for k in 0..iters {
                let t0 = Instant::now();
                std::hint::black_box(v2::hash_with(&mut sp, b"bench-header", k as u64));
                samples.push(t0.elapsed().as_secs_f64());
            }
            samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let median = samples[samples.len() / 2];
            let calls = 2.0 * (1u64 << log2_n) as f64 + 2.0;
            println!(
                "v2 log2_n={log2_n} memory={} KiB median={:.3}ms min={:.3}ms ns/compression={:.1} evals/s/core={:.0}",
                sp.bytes() >> 10,
                median * 1e3,
                samples[0] * 1e3,
                median * 1e9 / calls,
                1.0 / median
            );
        }
        Some("perm") => {
            let count: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(10_000_000);
            let mut st = [0u64; 25];
            let t0 = Instant::now();
            for _ in 0..count {
                keccak::f1600(&mut st);
            }
            let dt = t0.elapsed().as_secs_f64();
            println!(
                "keccak-f[1600]: {count} perms in {dt:.3}s = {:.1} ns/perm (checksum {:x})",
                dt * 1e9 / count as f64,
                st[0]
            );
        }
        Some("mine") => {
            let log2_n: u32 = args[2].parse().unwrap();
            let bits: u32 = args[3].parse().unwrap();
            let blocks: u64 = args[4].parse().unwrap();
            let threads: usize = args.get(5).and_then(|s| s.parse().ok()).unwrap_or(1);
            let target = target_with_zero_bits(bits);
            let t0 = Instant::now();
            for b in 0..blocks {
                // Each "block" has a distinct header; attempts counted until first success.
                let header = format!("toy-block-{b}").into_bytes();
                let found = Arc::new(AtomicBool::new(false));
                let attempts = Arc::new(AtomicU64::new(0));
                let winner = Arc::new(AtomicU64::new(u64::MAX));
                std::thread::scope(|s| {
                    for t in 0..threads {
                        let (found, attempts, winner, header) =
                            (found.clone(), attempts.clone(), winner.clone(), header.clone());
                        s.spawn(move || {
                            let mut sp = Scratchpad::new(log2_n);
                            let mut nonce = t as u64;
                            while !found.load(Ordering::Relaxed) {
                                let out = hash_with(&mut sp, &header, nonce);
                                attempts.fetch_add(1, Ordering::Relaxed);
                                if meets_target(&out, &target) {
                                    found.store(true, Ordering::Relaxed);
                                    winner.store(nonce, Ordering::Relaxed);
                                }
                                nonce += threads as u64;
                            }
                        });
                    }
                });
                println!(
                    "{b},{},{}",
                    attempts.load(Ordering::Relaxed),
                    winner.load(Ordering::Relaxed)
                );
            }
            eprintln!("mined {blocks} blocks in {:.2}s", t0.elapsed().as_secs_f64());
        }
        _ => {
            let log2_n: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(LOG2_N);
            let iters: u32 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(10);
            let t_alloc = Instant::now();
            let mut sp = Scratchpad::new(log2_n);
            let alloc = t_alloc.elapsed().as_secs_f64();
            // Warm-up (touches every page once).
            let _ = hash_with(&mut sp, b"warmup", 0);
            let mut samples = Vec::new();
            let mut last = [0u8; 32];
            for k in 0..iters {
                let t0 = Instant::now();
                last = hash_with(&mut sp, b"bench-header", k as u64);
                samples.push(t0.elapsed().as_secs_f64());
            }
            samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let median = samples[samples.len() / 2];
            let calls = 2.0 * (1u64 << log2_n) as f64 + 2.0;
            println!(
                "log2_n={log2_n} memory={} MiB alloc={:.1}ms median={:.1}ms min={:.1}ms max={:.1}ms ns/call={:.1} last={}",
                sp.bytes() >> 20,
                alloc * 1e3,
                median * 1e3,
                samples[0] * 1e3,
                samples[samples.len() - 1] * 1e3,
                median * 1e9 / calls,
                last.iter().map(|b| format!("{b:02x}")).collect::<String>()
            );
        }
    }
}
