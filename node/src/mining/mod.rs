//! GnB CPU miner helpers over full block headers (GnB-SMH).

use crate::core::BlockHeader;
use log::info;

pub struct MineResult {
    pub found: bool,
    pub nonce: u64,
}

/// Mine `header` (of a block at `height`) in place using all available cores.
/// `max_attempts` applies per thread.
pub fn mine_block(header: &mut BlockHeader, height: u64, max_attempts: u64) -> MineResult {
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let preimage = header.pow_preimage();
    match crate::pow::mine_parallel(&preimage, header.bits, height, header.nonce, max_attempts, threads, None) {
        Some(nonce) => {
            header.nonce = nonce;
            info!("Block mined! nonce={} ({} threads)", nonce, threads);
            MineResult { found: true, nonce }
        }
        None => MineResult { found: false, nonce: header.nonce },
    }
}
