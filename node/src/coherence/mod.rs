//! Coherence — shielded pool (node integration).
//!
//! The pure primitives — notes, SHAKE-256 commitments/nullifiers, the Merkle
//! accumulator, and `check_spend` (the exact statement a spend proof attests
//! to, version 2 since audit COH-1) — live in the lean `coherence-core` crate.
//! This module re-exports them and adds the node-only consensus state (anchor
//! history + nullifier set), the in-place apply/undo engine, and (in
//! [`persist`]) its RocksDB persistence.
//!
//! # State handling (audit COH-2)
//!
//! Shielded state follows the applied selected chain exactly like the UTXO
//! set: the acceptance pipeline applies a block's shielded transactions only
//! when the block joins the selected chain, disconnects them when a reorg
//! removes it, and writes the changes (commitment-tree leaves, spent
//! nullifiers, anchor window, a per-block undo record, the shielded tip) in
//! the SAME RocksDB WriteBatch as the block's UTXO changes. The node reloads
//! the state at start-up ([`ShieldedPool::load`]). Applying a block costs
//! `O(outputs × TREE_DEPTH + nullifiers)`: no clone of the tree or the
//! nullifier set, and an incremental tree (`coherence_core::CommitmentTree`).
//!
//! Zero-security testnet: no privacy claim until audited (Coherence C4). The
//! node's only compiled proof verifier is `RejectAll`, so no shielded
//! transaction is accepted today.

pub use coherence_core::*;

pub mod verifier;
pub use verifier::ShieldedVerifier;

pub mod persist;

use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};

/// How many recent commitment-tree roots are accepted as spend anchors.
pub const ANCHOR_HISTORY: usize = 100;

/// The shielded-pool state a node maintains and validates against.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ShieldedState {
    anchors: VecDeque<[u8; 32]>,
    spent_nullifiers: HashSet<[u8; 32]>,
}

/// Why a shielded tx is rejected at the consensus layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxError {
    UnknownAnchor,
    DuplicateNullifierInTx([u8; 32]),
    DoubleSpend([u8; 32]),
    ProofInvalid,
    /// The block's outputs do not fit in the commitment tree
    /// (`coherence_core::TREE_CAPACITY` leaves).
    TreeFull,
    /// Reorg wants to disconnect a block older than the bounded in-memory
    /// journal of [`ShieldedEngine::disconnect_block`]. (The node's persisted
    /// path has no such horizon: undo records live in RocksDB.)
    ReorgBeyondUndoHorizon,
    /// Disconnect was asked to undo a block that is NOT the top of the
    /// in-memory journal. We refuse rather than silently corrupt the state.
    /// `{expected}` vs the actual top block id.
    ReorgOrderMismatch { expected: [u8; 32], found: [u8; 32] },
    /// An undo record does not describe the current state (tree shorter than
    /// the recorded length, or a recorded nullifier not spent): the persisted
    /// state is corrupt.
    InconsistentUndo(String),
}

/// How many recently-applied blocks the in-memory convenience journal of
/// [`ShieldedEngine::apply_block`] / [`ShieldedEngine::disconnect_block`]
/// keeps. The node does not use the journal: its undo records are persisted.
pub const MAX_REORG_UNDO: usize = 128;

/// Everything needed to exactly reverse one applied block (reorg undo).
/// Persisted per shielded block by the node (see [`persist`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockUndo {
    /// Commitment-tree size before the block.
    pub tree_len: u64,
    /// The nullifiers the block spent, in block order.
    pub nullifiers: Vec<[u8; 32]>,
    /// The anchor window before the block, oldest first (≤ ANCHOR_HISTORY).
    pub anchors_before: Vec<[u8; 32]>,
}

/// What [`ShieldedEngine::undo`] removed, so a disconnect can itself be
/// reverted exactly (an aborted reorg).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockRedo {
    leaves: Vec<[u8; 32]>,
    nullifiers: Vec<[u8; 32]>,
    anchors_after: VecDeque<[u8; 32]>,
}

/// Canonical view of an engine's consensus state, for equality checks
/// (restart and reorg round-trip tests, start-up verification).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShieldedSnapshot {
    pub leaves: Vec<[u8; 32]>,
    pub anchors: Vec<[u8; 32]>,
    /// Sorted.
    pub nullifiers: Vec<[u8; 32]>,
}

impl ShieldedState {
    pub fn new() -> Self { Self::default() }

    /// Record a new tree root as an acceptable anchor (bounded history).
    pub fn record_anchor(&mut self, root: [u8; 32]) {
        if self.anchors.contains(&root) { return; }
        self.anchors.push_back(root);
        while self.anchors.len() > ANCHOR_HISTORY { self.anchors.pop_front(); }
    }

    pub fn knows_anchor(&self, a: &[u8; 32]) -> bool { self.anchors.contains(a) }
    pub fn is_spent(&self, nf: &[u8; 32]) -> bool { self.spent_nullifiers.contains(nf) }

    /// Validate a shielded tx WITHOUT seeing the witness: the anchor must be
    /// recent, every nullifier unseen (and unique within the tx), and the
    /// proof must verify. `verify_proof` is pluggable — the node's
    /// `ShieldedVerifier`, or a closure in tests.
    pub fn validate<F>(&self, tx: &ShieldedTx, verify_proof: F) -> Result<(), TxError>
    where
        F: Fn(&SpendPublic, &[u8]) -> bool,
    {
        if !self.knows_anchor(&tx.anchor) {
            return Err(TxError::UnknownAnchor);
        }
        let mut seen = HashSet::new();
        for nf in &tx.nullifiers {
            if !seen.insert(*nf) {
                return Err(TxError::DuplicateNullifierInTx(*nf));
            }
            if self.spent_nullifiers.contains(nf) {
                return Err(TxError::DoubleSpend(*nf));
            }
        }
        if !verify_proof(&tx.public(), &tx.proof) {
            return Err(TxError::ProofInvalid);
        }
        Ok(())
    }

    /// Apply an already-validated tx: mark its nullifiers spent.
    pub fn apply(&mut self, tx: &ShieldedTx) {
        for nf in &tx.nullifiers { self.spent_nullifiers.insert(*nf); }
    }
}

/// The shielded pool's consensus state: the commitment tree (whose root is
/// the current anchor) plus the `ShieldedState` (anchor history + nullifier
/// set), with an optional bounded in-memory undo journal for callers that do
/// not persist undo records themselves.
#[derive(Debug, Clone)]
pub struct ShieldedEngine {
    tree: CommitmentTree,
    state: ShieldedState,
    /// In-memory convenience journal for `apply_block` / `disconnect_block`,
    /// bounded by MAX_REORG_UNDO. Not used by the node's persisted path.
    journal: VecDeque<([u8; 32], BlockUndo)>,
}

impl Default for ShieldedEngine {
    fn default() -> Self { Self::new() }
}

impl ShieldedEngine {
    pub fn new() -> Self {
        let tree = CommitmentTree::new();
        let mut state = ShieldedState::new();
        state.record_anchor(tree.root()); // the empty-tree root is a valid anchor
        Self { tree, state, journal: VecDeque::new() }
    }

    /// Rebuild an engine from persisted parts. Fails if the anchor window is
    /// empty, too long, or does not contain the tree's current root (every
    /// applied transaction records the root it produced).
    pub fn from_parts(
        leaves: Vec<[u8; 32]>,
        anchors: Vec<[u8; 32]>,
        nullifiers: impl IntoIterator<Item = [u8; 32]>,
    ) -> Result<Self, String> {
        if leaves.len() as u64 > TREE_CAPACITY {
            return Err("persisted commitment tree exceeds its capacity".into());
        }
        let tree = CommitmentTree::from_leaves(leaves);
        if anchors.is_empty() || anchors.len() > ANCHOR_HISTORY {
            return Err(format!("persisted anchor window has {} entries", anchors.len()));
        }
        if !anchors.contains(&tree.root()) {
            return Err("persisted anchor window does not contain the commitment-tree root".into());
        }
        let state = ShieldedState {
            anchors: anchors.into_iter().collect(),
            spent_nullifiers: nullifiers.into_iter().collect(),
        };
        Ok(Self { tree, state, journal: VecDeque::new() })
    }

    /// The current anchor (commitment-tree root) new spends should reference.
    pub fn anchor(&self) -> [u8; 32] { self.tree.root() }
    pub fn is_spent(&self, nf: &[u8; 32]) -> bool { self.state.is_spent(nf) }
    /// Number of note commitments in the tree.
    pub fn tree_len(&self) -> u64 { self.tree.len() as u64 }
    /// The anchor window, oldest first.
    pub fn anchors(&self) -> Vec<[u8; 32]> { self.state.anchors.iter().copied().collect() }

    /// The leaves from position `from` on (the outputs a block appended).
    fn snapshot_leaves_from(&self, from: u64) -> Vec<[u8; 32]> {
        self.tree.leaves().get(from as usize..).map(<[_]>::to_vec).unwrap_or_default()
    }

    /// Canonical copy of the consensus state (tests, start-up checks).
    pub fn snapshot(&self) -> ShieldedSnapshot {
        let mut nullifiers: Vec<[u8; 32]> = self.state.spent_nullifiers.iter().copied().collect();
        nullifiers.sort_unstable();
        ShieldedSnapshot { leaves: self.tree.leaves().to_vec(), anchors: self.anchors(), nullifiers }
    }

    /// Validate and apply a block's shielded txs IN PLACE and **atomically**:
    /// every tx validates against the accumulating state (an intra-block
    /// double spend fails the block); on any failure the block's partial
    /// effects are reverted and the state is exactly as before. On success
    /// the nullifiers are spent, the output commitments appended, each
    /// resulting root recorded as an anchor, and the undo record returned.
    /// Cost `O(outputs × TREE_DEPTH + nullifiers)` plus one copy of the
    /// bounded anchor window.
    pub fn apply_txs<F>(&mut self, txs: &[ShieldedTx], verify_proof: F) -> Result<BlockUndo, TxError>
    where
        F: Fn(&SpendPublic, &[u8]) -> bool,
    {
        let tree_len = self.tree_len();
        let anchors_before = self.anchors();
        let mut spent: Vec<[u8; 32]> = Vec::new();
        let mut failure = None;
        for tx in txs {
            if let Err(e) = self.state.validate(tx, &verify_proof) {
                failure = Some(e);
                break;
            }
            if (tx.outputs.len() as u64) > self.tree.remaining_capacity() {
                failure = Some(TxError::TreeFull);
                break;
            }
            self.state.apply(tx);
            spent.extend_from_slice(&tx.nullifiers);
            for cm in &tx.outputs { self.tree.append(*cm); }
            self.state.record_anchor(self.tree.root());
        }
        let undo = BlockUndo { tree_len, nullifiers: spent, anchors_before };
        match failure {
            None => Ok(undo),
            Some(e) => {
                self.revert_apply(&undo);
                Err(e)
            }
        }
    }

    /// Exact inverse of a successful [`apply_txs`](Self::apply_txs) that is
    /// still on top of the state (no checks; internal use).
    fn revert_apply(&mut self, undo: &BlockUndo) {
        self.tree.truncate(undo.tree_len as usize);
        for nf in &undo.nullifiers { self.state.spent_nullifiers.remove(nf); }
        self.state.anchors = undo.anchors_before.iter().copied().collect();
    }

    /// Reverse an applied block (reorg disconnect), tip-first, from its undo
    /// record. Checks the record describes the current state first; on error
    /// nothing changes. Returns what was removed so the disconnect can be
    /// reverted with [`redo`](Self::redo).
    pub fn undo(&mut self, undo: &BlockUndo) -> Result<BlockRedo, TxError> {
        if undo.tree_len > self.tree_len() {
            return Err(TxError::InconsistentUndo(format!(
                "undo record expects {} leaves, the tree has {}", undo.tree_len, self.tree_len())));
        }
        if let Some(nf) = undo.nullifiers.iter().find(|nf| !self.state.is_spent(nf)) {
            return Err(TxError::InconsistentUndo(format!(
                "undo record un-spends {} which is not spent", hex::encode(&nf[..8]))));
        }
        if undo.anchors_before.is_empty() || undo.anchors_before.len() > ANCHOR_HISTORY {
            return Err(TxError::InconsistentUndo("undo record has a malformed anchor window".into()));
        }
        let redo = BlockRedo {
            leaves: self.tree.leaves()[undo.tree_len as usize..].to_vec(),
            nullifiers: undo.nullifiers.clone(),
            anchors_after: self.state.anchors.clone(),
        };
        self.revert_apply(undo);
        Ok(redo)
    }

    /// Re-apply a block removed by [`undo`](Self::undo) (an aborted reorg).
    pub fn redo(&mut self, redo: BlockRedo) {
        for cm in redo.leaves { self.tree.append(cm); }
        for nf in redo.nullifiers { self.state.spent_nullifiers.insert(nf); }
        self.state.anchors = redo.anchors_after;
    }

    // ── in-memory convenience journal (tests, tools) ─────────────────────────

    /// [`apply_txs`](Self::apply_txs) and remember the undo record under
    /// `block_id` in the bounded in-memory journal. Returns the number of txs.
    pub fn apply_block<F>(&mut self, block_id: [u8; 32], txs: &[ShieldedTx], verify_proof: F) -> Result<usize, TxError>
    where
        F: Fn(&SpendPublic, &[u8]) -> bool,
    {
        let undo = self.apply_txs(txs, verify_proof)?;
        self.journal.push_back((block_id, undo));
        if self.journal.len() > MAX_REORG_UNDO { self.journal.pop_front(); }
        Ok(txs.len())
    }

    /// Reverse the most recent journaled block, which must be `expected`
    /// (`ReorgOrderMismatch` otherwise, `ReorgBeyondUndoHorizon` if the
    /// journal is empty). Disconnect tip-first.
    pub fn disconnect_block(&mut self, expected: [u8; 32]) -> Result<(), TxError> {
        match self.journal.back() {
            None => return Err(TxError::ReorgBeyondUndoHorizon),
            Some((top, _)) if *top != expected =>
                return Err(TxError::ReorgOrderMismatch { expected, found: *top }),
            Some(_) => {}
        }
        let (_, undo) = self.journal.pop_back().expect("checked non-empty above");
        self.undo(&undo).map(|_| ())
    }

    /// How many journaled blocks can currently be undone.
    pub fn undo_depth(&self) -> usize { self.journal.len() }

    /// Validate a tx against the current committed state WITHOUT applying it —
    /// same per-tx checks as block acceptance (anchor recent, nullifiers unseen
    /// + unique within the tx, proof verifies). Used for mempool admission.
    pub fn validate_tx<F>(&self, tx: &ShieldedTx, verify_proof: F) -> Result<(), TxError>
    where
        F: Fn(&SpendPublic, &[u8]) -> bool,
    {
        self.state.validate(tx, verify_proof)
    }
}

/// Pending shielded transactions awaiting inclusion in a block. Admission
/// rejects anything the chain would reject (anchor/nullifier/proof) AND anything
/// that conflicts with an already-pending tx (a nullifier claimed twice), so the
/// selected set is internally consistent by construction. Proof verification is
/// pluggable — the node's verifier (RejectAll), or a closure in tests.
#[derive(Debug, Default, Clone)]
pub struct ShieldedMempool {
    txs: Vec<ShieldedTx>,
    pending_nullifiers: HashSet<[u8; 32]>,
}

impl ShieldedMempool {
    pub fn new() -> Self { Self::default() }
    pub fn len(&self) -> usize { self.txs.len() }
    pub fn is_empty(&self) -> bool { self.txs.is_empty() }

    /// Admit a shielded tx into the pool. Rejects unknown anchor, a nullifier
    /// already spent on-chain OR claimed by a pending tx (mempool double-spend),
    /// a duplicate nullifier within the tx, or a failing proof.
    pub fn admit<F>(&mut self, tx: ShieldedTx, engine: &ShieldedEngine, verify_proof: F)
        -> Result<(), TxError>
    where
        F: Fn(&SpendPublic, &[u8]) -> bool,
    {
        engine.validate_tx(&tx, verify_proof)?;
        for nf in &tx.nullifiers {
            if self.pending_nullifiers.contains(nf) {
                return Err(TxError::DoubleSpend(*nf));
            }
        }
        for nf in &tx.nullifiers { self.pending_nullifiers.insert(*nf); }
        self.txs.push(tx);
        Ok(())
    }

    /// Select up to `max` pending txs for a block (insertion order; internally
    /// conflict-free by construction).
    pub fn select(&self, max: usize) -> Vec<ShieldedTx> {
        self.txs.iter().take(max).cloned().collect()
    }

    /// Drop pending txs whose nullifiers were included on-chain (or otherwise
    /// invalidated), freeing those nullifiers for eviction accounting.
    pub fn remove_included(&mut self, included: &[ShieldedTx]) {
        let mut gone: HashSet<[u8; 32]> = HashSet::new();
        for tx in included {
            for nf in &tx.nullifiers { gone.insert(*nf); }
        }
        if gone.is_empty() { return; }
        let mut kept = Vec::with_capacity(self.txs.len());
        for tx in std::mem::take(&mut self.txs) {
            if tx.nullifiers.iter().any(|nf| gone.contains(nf)) {
                for nf in &tx.nullifiers { self.pending_nullifiers.remove(nf); }
            } else {
                kept.push(tx);
            }
        }
        self.txs = kept;
    }
}

/// The node's shielded pool: the committed `ShieldedEngine`, the pending
/// `ShieldedMempool`, the proof verifier, and the block the committed state
/// corresponds to (the shielded tip, persisted with it — see [`persist`]).
#[derive(Debug, Default, Clone)]
pub struct ShieldedPool {
    pub engine: ShieldedEngine,
    pub mempool: ShieldedMempool,
    /// How shielded proofs are verified. `RejectAll` is the only verifier
    /// compiled into the node (see `verifier`).
    pub verifier: ShieldedVerifier,
    /// The applied selected-chain tip the engine state corresponds to. `None`
    /// for a pool not loaded from storage (tests): no order check is made
    /// until the first committed plan sets it.
    tip: Option<[u8; 32]>,
}

impl ShieldedPool {
    /// An empty pool (genesis state) with the configured verifier. The node
    /// itself uses [`ShieldedPool::load`].
    pub fn new() -> Self {
        Self {
            engine: ShieldedEngine::new(),
            mempool: ShieldedMempool::new(),
            verifier: ShieldedVerifier::from_env(),
            tip: None,
        }
    }

    /// The selected-chain block the committed shielded state corresponds to.
    pub fn tip(&self) -> Option<[u8; 32]> { self.tip }

    /// In-memory convenience: apply a block's shielded txs with the pool's
    /// configured verifier (`RejectAll` in the node) and journal it.
    pub fn apply_block_self(&mut self, block_id: [u8; 32], txs: &[ShieldedTx]) -> Result<usize, TxError> {
        // Disjoint field borrows so the verifier can be read while the engine is
        // mutated.
        let Self { engine, mempool, verifier, .. } = self;
        let n = engine.apply_block(block_id, txs, |p, pf| verifier.verify(p, pf))?;
        mempool.remove_included(txs);
        Ok(n)
    }

    /// In-memory convenience: reverse the journaled block `expected`
    /// (tip-first; see [`ShieldedEngine::disconnect_block`]).
    pub fn disconnect_block_self(&mut self, expected: [u8; 32]) -> Result<(), TxError> {
        self.engine.disconnect_block(expected)
    }

    pub fn anchor(&self) -> [u8; 32] { self.engine.anchor() }
    pub fn mempool_len(&self) -> usize { self.mempool.len() }

    /// Admit a tx into the mempool (validated against the committed engine).
    pub fn admit<F>(&mut self, tx: ShieldedTx, verify_proof: F) -> Result<(), TxError>
    where
        F: Fn(&SpendPublic, &[u8]) -> bool,
    {
        self.mempool.admit(tx, &self.engine, verify_proof)
    }

    /// In-memory convenience: apply a block's shielded txs to the engine
    /// (journaled), then evict them from the mempool. Err (block rejected) if
    /// any tx fails; the engine is unchanged on failure (atomic), and the
    /// mempool is only touched on success.
    pub fn apply_block<F>(&mut self, block_id: [u8; 32], txs: &[ShieldedTx], verify_proof: F) -> Result<usize, TxError>
    where
        F: Fn(&SpendPublic, &[u8]) -> bool,
    {
        let n = self.engine.apply_block(block_id, txs, verify_proof)?;
        self.mempool.remove_included(txs);
        Ok(n)
    }

    /// Select up to `max` pending txs for block construction.
    pub fn select_for_block(&self, max: usize) -> Vec<ShieldedTx> {
        self.mempool.select(max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_tx(anchor: [u8; 32], nfs: Vec<[u8; 32]>) -> ShieldedTx {
        ShieldedTx { anchor, nullifiers: nfs, outputs: vec![], fee: 0, proof: vec![1], binding_sig: vec![] }
    }

    #[test]
    fn shielded_state_accepts_valid_and_rejects_bad() {
        let mut st = ShieldedState::new();
        let anchor = [0x55u8; 32];
        st.record_anchor(anchor);
        let ok = |_p: &SpendPublic, _pf: &[u8]| true;
        let bad = |_p: &SpendPublic, _pf: &[u8]| false;

        let tx = dummy_tx(anchor, vec![[1u8; 32], [2u8; 32]]);
        assert_eq!(st.validate(&tx, ok), Ok(()));
        assert_eq!(st.validate(&dummy_tx([9u8; 32], vec![[3u8; 32]]), ok), Err(TxError::UnknownAnchor));
        assert!(matches!(
            st.validate(&dummy_tx(anchor, vec![[1u8; 32], [1u8; 32]]), ok),
            Err(TxError::DuplicateNullifierInTx(_))));
        assert_eq!(st.validate(&tx, bad), Err(TxError::ProofInvalid));

        st.apply(&tx);
        assert!(matches!(
            st.validate(&dummy_tx(anchor, vec![[1u8; 32]]), ok),
            Err(TxError::DoubleSpend(_))));
    }

    fn tx_with(anchor: [u8; 32], nfs: Vec<[u8; 32]>, outs: Vec<[u8; 32]>) -> ShieldedTx {
        ShieldedTx { anchor, nullifiers: nfs, outputs: outs, fee: 0, proof: vec![1], binding_sig: vec![] }
    }

    #[test]
    fn disconnect_block_exactly_reverses_apply() {
        let ok = |_p: &SpendPublic, _pf: &[u8]| true;
        let mut eng = ShieldedEngine::new();
        let root0 = eng.anchor();
        let id_a = [0xAA; 32];

        // Apply a block: spend a nullifier + append two note commitments.
        eng.apply_block(id_a, &[tx_with(root0, vec![[1u8; 32]], vec![[10u8; 32], [11u8; 32]])], ok).unwrap();
        let a1 = eng.anchor();
        assert_ne!(a1, root0);
        assert!(eng.is_spent(&[1u8; 32]));
        assert_eq!(eng.undo_depth(), 1);

        // Disconnect it → the shielded state returns EXACTLY to genesis.
        eng.disconnect_block(id_a).unwrap();
        assert_eq!(eng.anchor(), root0, "commitment-tree root reverts");
        assert!(!eng.is_spent(&[1u8; 32]), "nullifier is un-spent");
        assert_eq!(eng.undo_depth(), 0);
        // Soundness: the reverted branch's anchor is no longer accepted, so a
        // note that only existed on the reverted branch can't be spent.
        assert_eq!(eng.apply_block([0xBB; 32], &[tx_with(a1, vec![[2u8; 32]], vec![])], ok),
                   Err(TxError::UnknownAnchor));
    }

    #[test]
    fn disconnect_is_lifo_and_bounded() {
        let ok = |_p: &SpendPublic, _pf: &[u8]| true;
        let mut eng = ShieldedEngine::new();
        let r0 = eng.anchor();
        let (id_a, id_b) = ([0xA1; 32], [0xB2; 32]);
        eng.apply_block(id_a, &[tx_with(eng.anchor(), vec![[1u8; 32]], vec![[10u8; 32]])], ok).unwrap();
        let ra = eng.anchor();
        eng.apply_block(id_b, &[tx_with(ra, vec![[2u8; 32]], vec![[20u8; 32]])], ok).unwrap();
        assert_eq!(eng.undo_depth(), 2);

        eng.disconnect_block(id_b).unwrap(); // undo the tip (block B) only
        assert_eq!(eng.anchor(), ra);
        assert!(eng.is_spent(&[1u8; 32]) && !eng.is_spent(&[2u8; 32]));
        eng.disconnect_block(id_a).unwrap(); // undo block A
        assert_eq!(eng.anchor(), r0);
        assert!(!eng.is_spent(&[1u8; 32]));
        // Nothing left → beyond the undo horizon (caller must full-resync).
        assert_eq!(eng.disconnect_block(id_a), Err(TxError::ReorgBeyondUndoHorizon));
    }

    #[test]
    fn disconnect_refuses_wrong_block_order() {
        // AUDIT (Finding 1): apply happens in arrival order across branches, so
        // the undo top may not be the block a reorg wants to undo. Disconnecting
        // the WRONG id must error, not silently corrupt state.
        let ok = |_p: &SpendPublic, _pf: &[u8]| true;
        let mut eng = ShieldedEngine::new();
        let (id_a, id_b) = ([0xA1; 32], [0xB2; 32]);
        eng.apply_block(id_a, &[tx_with(eng.anchor(), vec![[1u8; 32]], vec![[10u8; 32]])], ok).unwrap();
        let anchor_after_a = eng.anchor();
        eng.apply_block(id_b, &[tx_with(eng.anchor(), vec![[2u8; 32]], vec![[20u8; 32]])], ok).unwrap();
        // Ask to undo A while B is on top → refused, state untouched.
        assert!(matches!(eng.disconnect_block(id_a),
                         Err(TxError::ReorgOrderMismatch { .. })));
        assert_eq!(eng.undo_depth(), 2, "nothing was popped");
        assert!(eng.is_spent(&[2u8; 32]), "B's effect is intact");
        // The correct tip-first order still works.
        eng.disconnect_block(id_b).unwrap();
        assert_eq!(eng.anchor(), anchor_after_a);
    }

    #[test]
    fn anchor_history_is_bounded() {
        let mut st = ShieldedState::new();
        for i in 0..(ANCHOR_HISTORY as u32 + 10) {
            let mut a = [0u8; 32];
            a[..4].copy_from_slice(&i.to_le_bytes());
            st.record_anchor(a);
        }
        assert!(!st.knows_anchor(&[0u8; 32]));
        let mut last = [0u8; 32];
        last[..4].copy_from_slice(&(ANCHOR_HISTORY as u32 + 9).to_le_bytes());
        assert!(st.knows_anchor(&last));
    }

    // Proof verification is SP1/FRI in production; the engine tests mock it to
    // exercise the CONSENSUS logic (anchors, nullifiers, tree, atomicity).
    fn tx(anchor: [u8; 32], nfs: Vec<[u8; 32]>, outs: Vec<[u8; 32]>) -> ShieldedTx {
        ShieldedTx { anchor, nullifiers: nfs, outputs: outs, fee: 0, proof: vec![1], binding_sig: vec![] }
    }

    #[test]
    fn engine_applies_shield_then_spend_and_advances_anchor() {
        let mut eng = ShieldedEngine::new();
        let ok = |_p: &SpendPublic, _pf: &[u8]| true;

        let a0 = eng.anchor();
        // Shield: mint one output commitment (no nullifiers), anchored at a0.
        assert_eq!(eng.apply_block([0x01; 32], &[tx(a0, vec![], vec![[0xAA; 32]])], ok), Ok(1));
        let a1 = eng.anchor();
        assert_ne!(a0, a1, "appending a commitment must advance the anchor");

        // Spend: burn a nullifier, anchored at the now-known a1.
        let nf = [0xBB; 32];
        assert_eq!(eng.apply_block([0x02; 32], &[tx(a1, vec![nf], vec![])], ok), Ok(1));
        assert!(eng.is_spent(&nf));
    }

    #[test]
    fn engine_rejects_intra_block_double_spend_atomically() {
        let mut eng = ShieldedEngine::new();
        let ok = |_p: &SpendPublic, _pf: &[u8]| true;
        let a = eng.anchor();
        let nf = [0xCC; 32];
        let before = eng.anchor();
        // Two txs spending the SAME nullifier in one block → whole block rejected.
        let r = eng.apply_block([0x03; 32], &[tx(a, vec![nf], vec![]), tx(a, vec![nf], vec![])], ok);
        assert!(matches!(r, Err(TxError::DoubleSpend(_))));
        // Atomic: nothing was committed.
        assert!(!eng.is_spent(&nf));
        assert_eq!(eng.anchor(), before);
    }

    #[test]
    fn shielded_mempool_admits_and_rejects() {
        let eng = ShieldedEngine::new();
        let a = eng.anchor();
        let ok = |_p: &SpendPublic, _pf: &[u8]| true;
        let bad = |_p: &SpendPublic, _pf: &[u8]| false;
        let mut mp = ShieldedMempool::new();

        // valid admission
        assert_eq!(mp.admit(tx(a, vec![[1u8; 32]], vec![]), &eng, ok), Ok(()));
        assert_eq!(mp.len(), 1);

        // same nullifier already pending → mempool double-spend
        assert!(matches!(
            mp.admit(tx(a, vec![[1u8; 32]], vec![]), &eng, ok),
            Err(TxError::DoubleSpend(_))));
        assert_eq!(mp.len(), 1);

        // unknown anchor + failing proof rejected, pool unchanged
        assert_eq!(mp.admit(tx([9u8; 32], vec![[2u8; 32]], vec![]), &eng, ok), Err(TxError::UnknownAnchor));
        assert_eq!(mp.admit(tx(a, vec![[3u8; 32]], vec![]), &eng, bad), Err(TxError::ProofInvalid));
        assert_eq!(mp.len(), 1);

        // select for a block, then drop once included
        assert_eq!(mp.select(10).len(), 1);
        mp.remove_included(&[tx(a, vec![[1u8; 32]], vec![])]);
        assert!(mp.is_empty());
        // the freed nullifier can be admitted again
        assert_eq!(mp.admit(tx(a, vec![[1u8; 32]], vec![]), &eng, ok), Ok(()));
    }
}
