//! Shared fixtures for the 2026-10 audit-fix regression tests (`fix_*.rs`).
//!
//! Every helper drives the REAL library code: blocks go through
//! `gnb::accept::accept_block` (the same function main.rs's gossip, miner,
//! RPC and orphan paths call), sealed with a genuine GnB-SMH proof
//! (dev builds enable `test-pow-limit`, so one evaluation suffices).
#![allow(dead_code)]

use std::sync::Arc;

use gnb::coherence::ShieldedPool;
use gnb::consensus::{BlockHash, GhostDAG};
use gnb::core::{self, Block, BlockHeader, MerkleRoot, Transaction, TxInput, TxOutput};
use gnb::mempool::Mempool;
use gnb::rpc::NodeState;
use gnb::storage::Storage;
use gnb::{accept, crypto, pow, tip};
use parking_lot::RwLock;
use sha3::{Digest, Sha3_256};
use tempfile::TempDir;
use tokio::sync::broadcast;

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub struct Node {
    pub _tmp: TempDir,
    pub path: std::path::PathBuf,
    pub dag: Arc<RwLock<GhostDAG>>,
    pub store: Arc<Storage>,
    pub mempool: Arc<Mempool>,
    pub node_state: Arc<RwLock<NodeState>>,
    pub shielded: Arc<RwLock<ShieldedPool>>,
    pub tip_tx: broadcast::Sender<tip::TipChanged>,
}

pub struct Key {
    pub pk: Vec<u8>,
    pub sk: Vec<u8>,
    pub spk: Vec<u8>,
}

pub fn key() -> Key {
    let (pk, sk) = crypto::generate_keypair();
    let spk = Sha3_256::digest(&pk)[..20].to_vec();
    Key { pk, sk, spk }
}

pub fn coinbase(tag: &str, value: u64, spk: Vec<u8>) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid: [0u8; 32],
            prev_index: u32::MAX,
            script_sig: tag.as_bytes().to_vec(),
            sequence: u32::MAX,
        }],
        outputs: vec![TxOutput { value, script_pubkey: spk }],
        locktime: 0,
    }
}

/// A signed spend of `(prev_txid, prev_index)` paying `outputs`.
pub fn signed_spend(k: &Key, inputs: &[([u8; 32], u32)], outputs: Vec<TxOutput>) -> Transaction {
    let mut tx = Transaction {
        version: 1,
        inputs: inputs.iter().map(|(t, i)| TxInput {
            prev_txid: *t, prev_index: *i, script_sig: vec![], sequence: u32::MAX,
        }).collect(),
        outputs,
        locktime: 0,
    };
    for i in 0..tx.inputs.len() {
        let sighash = tx.sighash(i, core::node_chain_id());
        let sig = crypto::sign(&k.sk, &sighash).expect("sign");
        tx.inputs[i].script_sig = Transaction::build_script_sig(&sig, &k.pk);
    }
    tx
}

/// A signed spend for a block at header height `height`, under the rules of
/// that height (process-wide activation height, i.e. the calling thread's
/// `scoped_override`): below the hardening activation exactly
/// [`signed_spend`] (version 1, sighash v2); at/after it version 3 with
/// sighash v3 and bound signatures (`core::sighash`), which commit to
/// `spent` (the outputs the inputs spend, in input order).
pub fn signed_spend_at(
    k: &Key,
    inputs: &[([u8; 32], u32)],
    spent: &[TxOutput],
    outputs: Vec<TxOutput>,
    height: u64,
) -> Transaction {
    let act = core::activation::hardening_activation_height();
    let version = core::sighash::tx_version_for_height(height, act);
    if version != core::sighash::TX_VERSION_V3 {
        return signed_spend(k, inputs, outputs);
    }
    let mut tx = Transaction {
        version,
        inputs: inputs.iter().map(|(t, i)| TxInput {
            prev_txid: *t, prev_index: *i, script_sig: vec![], sequence: u32::MAX,
        }).collect(),
        outputs,
        locktime: 0,
    };
    let suite = crypto::public_key_suite(&k.pk).expect("enveloped public key");
    let pre = core::sighash::SighashV3Precomputed::new(&tx, spent).expect("one spent output per input");
    for i in 0..tx.inputs.len() {
        let digest = pre.digest(i, suite, core::node_chain_id()).expect("input index in range");
        let sig = crypto::sign_bound(&k.sk, &digest).expect("sign");
        tx.inputs[i].script_sig = Transaction::build_script_sig(&sig, &k.pk);
    }
    tx
}

pub fn out(value: u64, spk: &[u8]) -> TxOutput {
    TxOutput { value, script_pubkey: spk.to_vec() }
}

pub fn mk_genesis(ts: u64) -> Block {
    Block {
        header: BlockHeader {
            version: 1, parents: vec![], merkle_root: MerkleRoot::ZERO,
            timestamp: ts, bits: core::GENESIS_BITS, nonce: 0,
        },
        transactions: vec![coinbase("genesis", 0, vec![0u8; 20])],
        blue_score: 0, height: 0, shielded_transactions: Vec::new(),
        powit: Default::default(),
    }
}

/// A node at `genesis` whose UTXO set holds `utxos` (models carryover
/// outputs), initialised the way main() initialises a fresh data dir.
pub fn node_with(genesis: &Block, utxos: &[([u8; 32], u32, TxOutput)]) -> Node {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("db");
    let store = Arc::new(Storage::open(&path).unwrap());
    let dag = Arc::new(RwLock::new(GhostDAG::with_default_k()));
    let gh = genesis.block_hash();
    store.put_block(genesis).unwrap();
    store.put_meta("genesis_hash", &gh).unwrap();
    store.put_meta("tip_hash", &gh).unwrap();
    dag.write().add_genesis(gh, genesis.header.timestamp);
    let gd = dag.read().get_block_data(&gh).cloned().unwrap();
    store.put_dag_with_integrity(&gh, &gd).unwrap();
    let _ = dag.write().reach_take_delta();
    store.store_reachability_snapshot(&dag.read().reach_export_all(), dag.read().reach_root()).unwrap();
    for (t, i, o) in utxos {
        store.put_utxo(t, *i, o).unwrap();
    }
    let (tip_tx, _) = broadcast::channel::<tip::TipChanged>(64);
    Node {
        _tmp: tmp,
        path,
        dag,
        store,
        mempool: Arc::new(Mempool::new()),
        node_state: Arc::new(RwLock::new(NodeState::default())),
        shielded: Arc::new(RwLock::new(ShieldedPool::new())),
        tip_tx,
    }
}

/// The real acceptance path, preceded by the structural gate every ingress
/// path runs (`validate_structure`).
pub fn accept(n: &Node, b: &Block) -> Result<BlockHash, String> {
    b.validate_structure().map_err(|e| format!("structural validation: {e}"))?;
    accept::accept_block(
        b, b.block_hash(), b.height, &n.dag, &n.store, &n.mempool, &n.node_state,
        Some(&n.tip_tx), &n.shielded,
    )
}

/// Write the coinbase commitment and the header Merkle root `b` needs under
/// the rules of its header height (`core::block_rules`, process-wide
/// activation height, i.e. the calling thread's `scoped_override`): at/after
/// the hardening activation the coinbase `script_sig` becomes
/// `commitment || <its current bytes>` and the root is the tagged tree; below
/// it nothing but the legacy root changes.
pub fn commit_block(b: &mut Block) {
    if core::block_rules::rules_active(b.height) {
        let c = core::block_rules::expected_coinbase_commitment(b);
        if let Some(input) = b.transactions.first_mut().and_then(|cb| cb.inputs.first_mut()) {
            let extra = std::mem::take(&mut input.script_sig);
            input.script_sig = core::block_rules::coinbase_script_sig(&c, &extra);
        }
    }
    b.header.merkle_root = b.body_merkle_root();
}

/// Build a block on `parents` (known to `dag_of`) carrying `txs`, with the
/// header height / bits the consensus rules require, the coinbase commitment
/// and Merkle root of that height (`commit_block`), and seal it. `pred`
/// constrains the block hash (tie-break control).
pub fn mk_block_where(
    dag_of: &Node,
    parents: Vec<BlockHash>,
    txs: Vec<Transaction>,
    pred: impl Fn(&BlockHash) -> bool,
) -> Block {
    let (height, parent_ts) = {
        let d = dag_of.dag.read();
        let h = parents.iter().map(|p| d.get_block_data(p).expect("parent known").height).max().unwrap() + 1;
        let ts = parents.iter().map(|p| d.get_block_data(p).unwrap().timestamp).max().unwrap();
        (h, ts)
    };
    let bits = pow::expected_bits(parent_ts, height).unwrap();
    let mut b = Block {
        header: BlockHeader {
            version: 1,
            parents,
            merkle_root: Transaction::merkle_root(&txs),
            timestamp: parent_ts + 1,
            bits,
            nonce: 0,
        },
        transactions: txs,
        blue_score: height,
        height,
        shielded_transactions: Vec::new(),
        powit: Default::default(),
    };
    commit_block(&mut b);
    loop {
        if pred(&b.block_hash()) && b.validate_pow() {
            return b;
        }
        b.header.nonce += 1;
    }
}

pub fn mk_block(dag_of: &Node, parents: Vec<BlockHash>, txs: Vec<Transaction>) -> Block {
    mk_block_where(dag_of, parents, txs, |_| true)
}

/// Coinbase-only child of `parent` paying the full subsidy.
pub fn empty_child(dag_of: &Node, parent: BlockHash, tag: &str) -> Block {
    let h = dag_of.dag.read().get_block_data(&parent).unwrap().height + 1;
    mk_block(dag_of, vec![parent], vec![coinbase(tag, core::tokenomics::block_subsidy_sat(h), vec![0xC0; 20])])
}

pub fn sel_tip(n: &Node) -> Option<BlockHash> {
    n.dag.read().selected_tip()
}

pub fn applied_tip(n: &Node) -> Option<BlockHash> {
    n.store.get_meta("tip_hash").unwrap().map(|v| <[u8; 32]>::try_from(v.as_slice()).unwrap())
}

/// Snapshot of the UTXO entries for `outpoints` (None = absent).
pub fn utxo_snapshot(n: &Node, outpoints: &[([u8; 32], u32)]) -> Vec<Option<(u64, Vec<u8>)>> {
    outpoints.iter()
        .map(|(t, i)| n.store.get_utxo(t, *i).unwrap().map(|o| (o.value, o.script_pubkey)))
        .collect()
}

/// Reload the DAG from CF_DAG exactly as main() does after a restart, then
/// run the start-up reconciliation.
pub fn restart(n: &mut Node) {
    let mut d = GhostDAG::with_default_k();
    let entries = n.store.load_all_dag_data().unwrap();
    let im = n.store.load_all_integrity_hashes().unwrap();
    d.load_persisted_validated(entries, im).expect("integrity chain verifies");
    let records = n.store.load_all_reachability().unwrap();
    let root = n.store.get_reachability_root().unwrap();
    if records.len() == d.block_count() {
        d.reach_load_records(&records, root).unwrap();
    } else {
        d.rebuild_reachability_from_store().unwrap();
    }
    n.dag = Arc::new(RwLock::new(d));
    // As main() does: reload the persisted shielded state (audit COH-2).
    n.shielded = Arc::new(RwLock::new(ShieldedPool::load(&n.store).expect("shielded state loads")));
    accept::reconcile_on_startup(&n.dag, &n.store, &n.shielded).expect("reconcile");
}
