//! Mine the GnB genesis block's GnB-SMH nonce.
//!
//! The genesis block is fully determined by constants in
//! `crates/gnb-crypto/src/core/mod.rs` (coinbase text, timestamp, bits); only
//! its nonce has to be found. This tool searches for it with every core and
//! prints the constants to paste back:
//!
//! ```text
//! gnb-mine-genesis                     # use the baked timestamp and bits
//! gnb-mine-genesis --threads 8
//! gnb-mine-genesis --timestamp 1791331200 --bits 0x2000ffff
//! ```
//!
//! Changing the coinbase text, the timestamp or the bits invalidates
//! `GENESIS_NONCE`, and the node refuses to start until it is re-mined.

use clap::Parser;
use gnb::core::{self, create_genesis_block_with};
use std::time::Instant;

#[derive(Parser)]
#[command(name = "gnb-mine-genesis")]
#[command(about = "Find GENESIS_NONCE for the GnB genesis block (GnB-SMH)")]
struct Cli {
    /// Genesis timestamp (unix seconds). Defaults to core::GENESIS_TIMESTAMP.
    #[arg(long)]
    timestamp: Option<u64>,
    /// Compact difficulty bits (0x-prefixed hex or decimal). Defaults to
    /// core::GENESIS_BITS.
    #[arg(long, value_parser = parse_u32_hex_or_dec)]
    bits: Option<u32>,
    /// Worker threads (64 MiB each). Defaults to all logical CPUs.
    #[arg(long)]
    threads: Option<usize>,
    /// First nonce to try.
    #[arg(long, default_value_t = 0)]
    start_nonce: u64,
}

fn parse_u32_hex_or_dec(s: &str) -> Result<u32, String> {
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16).map_err(|e| e.to_string()),
        None => s.parse().map_err(|e: std::num::ParseIntError| e.to_string()),
    }
}

fn main() {
    let cli = Cli::parse();
    let timestamp = cli.timestamp.unwrap_or(core::GENESIS_TIMESTAMP);
    let bits = cli.bits.unwrap_or(core::GENESIS_BITS);
    let threads = cli
        .threads
        .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1))
        .max(1);

    let template = create_genesis_block_with(timestamp, bits, 0);
    let preimage = template.header.pow_preimage();
    println!("GnB genesis search");
    println!("  coinbase   : {}", core::GENESIS_COINBASE_TEXT);
    println!("  timestamp  : {timestamp}");
    println!("  bits       : 0x{bits:08x} (difficulty {:.2})", core::difficulty_from_bits(bits));
    println!("  merkle     : {}", template.header.merkle_root);
    println!("  threads    : {threads} (64 MiB each)");

    let t0 = Instant::now();
    let mut start = cli.start_nonce;
    const CHUNK: u64 = 256;
    let nonce = loop {
        if let Some(n) = gnb::pow::mine_parallel(&preimage, bits, start, CHUNK, threads, None) {
            break n;
        }
        start = start.wrapping_add(CHUNK * threads as u64);
        println!("  … {} nonces tried, {:.0} s", start - cli.start_nonce, t0.elapsed().as_secs_f64());
    };

    let block = create_genesis_block_with(timestamp, bits, nonce);
    assert!(block.validate_pow(), "found nonce must validate");
    let hash = block.block_hash();
    println!();
    println!("Found in {:.1} s. Paste into crates/gnb-crypto/src/core/mod.rs:", t0.elapsed().as_secs_f64());
    println!();
    println!("pub const GENESIS_TIMESTAMP: u64 = {timestamp};");
    println!("pub const GENESIS_BITS:      u32 = 0x{bits:08X};");
    println!("pub const GENESIS_NONCE:     u64 = {nonce};");
    println!("pub const GENESIS_EXPECTED_HASH: [u8; 32] = {};", rust_bytes(&hash));
    println!();
    println!("genesis block hash: {}", hex::encode(hash));
}

fn rust_bytes(b: &[u8; 32]) -> String {
    let parts: Vec<String> = b.iter().map(|x| format!("0x{x:02x}")).collect();
    let lines: Vec<String> = parts.chunks(8).map(|c| format!("    {},", c.join(", "))).collect();
    format!("[\n{}\n]", lines.join("\n"))
}
