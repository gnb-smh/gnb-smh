//! Tip-change notifications.

/// Event pushed on a broadcast channel when the DAG accepts a new selected
/// tip, so block-template consumers (the internal miner, RPC long-poll
/// clients) can rebuild their work.
#[derive(Clone, Debug)]
pub struct TipChanged {
    pub hash:       [u8; 32],
    pub height:     u64,
    pub blue_score: u64,
    pub parents:    Vec<[u8; 32]>,
    pub bits:       u32,
}
