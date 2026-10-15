//! The real block-acceptance pipeline (`gnb::accept::accept_block`, behind the
//! structural gate every ingress path runs, `Block::validate_structure`) on a
//! RocksDB `Storage` in a temporary directory with a real `GhostDAG`, driven
//! by small arbitrary DAGs of sealed, PoW-cheap blocks (`test-pow-limit` is on
//! in this crate: one GnB-SMH evaluation per block, cached by block id).
//!
//! The input chooses the hardening activation height (never, from genesis, or
//! inside the DAG), up to `MAX_BLOCKS` blocks, each block's parents (any
//! earlier block, invalid ones included), its transactions from a pool of
//! signed spends of four funded outputs (two conflicting families, chains of
//! spends, version 3 or 1, a broken signature, a missing input), and
//! deliberate faults (coinbase over-claim, wrong height, wrong bits,
//! timestamp before a parent, a duplicated transaction). The wrong-bits
//! block is sealed at its own (wrong but easy) target, so it is refused by
//! `accept_block`'s difficulty rule, not by the proof-of-work check.
//!
//! Not covered here: with `test-pow-limit` the expected bits are always the
//! pre-activation pow limit and `validate_pow` enforces that limit at every
//! height, so neither the ASERT schedule nor the hardened pow limit of audit
//! POW-3 (the genesis target) is exercised by this target, under any of its
//! activation regimes. Both are covered by gnb-crypto's own tests (run
//! without the feature: `expected_bits_at`, `pow_limit_bits_at`,
//! `validate_pow` at the hardened limit); the ASERT arithmetic is also
//! fuzzed by `pow_decode` (with the pre-activation pow limit only).
//!
//! The same block set is delivered to two fresh nodes in two different
//! arrival orders (the build order and an input-chosen permutation; a block
//! whose parent is unknown waits and is retried, as the orphan pool does).
//! Asserted (audit DAG-1, "arrival-order independence"):
//! * no panic anywhere in the pipeline;
//! * both nodes end with the same selected tip, the same applied tip, the
//!   same UTXO set (digest of every entry) and the same DAG block set;
//! * a block built with a wrong height, a timestamp before a parent, wrong
//!   difficulty bits or a duplicated transaction is in neither node's DAG
//!   (refused whatever the arrival order);
//! * optionally, a node reloaded from its own storage (`reconcile_on_startup`,
//!   as after a restart) ends in that same state.
#![no_main]

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use common::*;
use gnb::accept;
use gnb::coherence::ShieldedPool;
use gnb::consensus::GhostDAG;
use gnb::core::{self, activation, block_rules, sighash, Block, BlockHeader, MerkleRoot, Transaction, TxInput, TxOutput};
use gnb::crypto;
use gnb::mempool::Mempool;
use gnb::pow;
use gnb::rpc::NodeState;
use gnb::storage::Storage;
use libfuzzer_sys::fuzz_target;
use parking_lot::RwLock;

const MAX_BLOCKS: usize = 6;
const GENESIS_TS: u64 = 1_750_000_000;
const FUND_VALUE: u64 = 100_000_000;
const STEP_FEE: u64 = 100_000;
const N_FUNDS: u8 = 4;

struct Key {
    pk: Vec<u8>,
    sk: Vec<u8>,
    spk: Vec<u8>,
    suite: u16,
}

fn key() -> &'static Key {
    static K: OnceLock<Key> = OnceLock::new();
    K.get_or_init(|| {
        let (pk, sk) = crypto::generate_keypair_from_seed(&[0xA5u8; 64]).expect("seeded keygen");
        let spk = sha3(&pk)[..20].to_vec();
        let suite = crypto::public_key_suite(&pk).expect("enveloped key");
        Key { pk, sk, spk, suite }
    })
}

fn genesis() -> Block {
    Block {
        header: BlockHeader {
            version: 1,
            parents: vec![],
            merkle_root: MerkleRoot::ZERO,
            timestamp: GENESIS_TS,
            bits: core::GENESIS_BITS,
            nonce: 0,
        },
        transactions: vec![Transaction {
            version: 1,
            inputs: vec![TxInput { prev_txid: [0; 32], prev_index: u32::MAX, script_sig: b"genesis".to_vec(), sequence: u32::MAX }],
            outputs: vec![TxOutput { value: 0, script_pubkey: vec![0; 20] }],
            locktime: 0,
        }],
        blue_score: 0,
        height: 0,
        shielded_transactions: vec![],
    }
}

fn fund(i: u8) -> ([u8; 32], u32, TxOutput) {
    ([0xF0 + i; 32], 0, TxOutput { value: FUND_VALUE, script_pubkey: key().spk.clone() })
}

/// A transaction of the pool: family `(fund, variant)` at chain depth `depth`
/// (depth 0 spends the funded output, depth d spends output 0 of depth d-1).
/// Variant 0 is version 3, variant 1 version 1; the two variants of a fund
/// conflict. The witness is signed with the digest the block height selects
/// (`v3_digest`), so the same txid can carry either witness.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct Slot {
    fund: u8,
    variant: u8,
    depth: u8,
    fault: Fault,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Fault {
    None,
    BadSignature,
    MissingInput,
}

fn unsigned(s: Slot) -> (Transaction, TxOutput) {
    let version = if s.variant == 0 { sighash::TX_VERSION_V3 } else { 1 };
    let (prev_txid, prev_index, spent) = if s.fault == Fault::MissingInput {
        ([0xDD; 32], 7, TxOutput { value: FUND_VALUE, script_pubkey: key().spk.clone() })
    } else if s.depth == 0 {
        let (t, i, o) = fund(s.fund);
        (t, i, o)
    } else {
        let (prev, _) = unsigned(Slot { depth: s.depth - 1, fault: Fault::None, ..s });
        (prev.txid(), 0, prev.outputs[0].clone())
    };
    let value = spent.value - STEP_FEE;
    let tx = Transaction {
        version,
        inputs: vec![TxInput { prev_txid, prev_index, script_sig: vec![], sequence: u32::MAX }],
        outputs: vec![TxOutput { value, script_pubkey: key().spk.clone() }],
        locktime: 0,
    };
    (tx, spent)
}

/// Deterministically signed (seeded RNG) and memoised across executions, so
/// block ids repeat and the proof-of-work cache keeps the target fast.
fn signed(s: Slot, v3_digest: bool) -> Transaction {
    static CACHE: OnceLock<Mutex<HashMap<(Slot, bool), Transaction>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(t) = cache.lock().unwrap().get(&(s, v3_digest)) {
        return t.clone();
    }
    let k = key();
    let (mut tx, spent) = unsigned(s);
    let seed = sha3(format!("{s:?}{v3_digest}").as_bytes());
    let sig = pqcrypto_internals::with_seeded_rng_scope(&seed, || {
        if v3_digest {
            let pre = sighash::SighashV3Precomputed::new(&tx, std::slice::from_ref(&spent)).unwrap();
            let d = pre.digest(0, k.suite, core::node_chain_id()).unwrap();
            crypto::sign_bound(&k.sk, &d).unwrap()
        } else {
            crypto::sign(&k.sk, &tx.sighash(0, core::node_chain_id())).unwrap()
        }
    });
    let mut sig = sig;
    if s.fault == Fault::BadSignature {
        let i = sig.len() / 2;
        sig[i] ^= 0x01;
    }
    tx.inputs[0].script_sig = Transaction::build_script_sig(&sig, &k.pk);
    cache.lock().unwrap().insert((s, v3_digest), tx.clone());
    tx
}

#[derive(Clone)]
struct Built {
    block: Block,
    hash: [u8; 32],
    /// A fault every node must refuse, whatever the arrival order: a wrong
    /// header height, a timestamp before a parent, wrong difficulty bits, a
    /// duplicated transaction. (A coinbase over-claim is not one of them: the
    /// block stays in the DAG, disqualified at connect time, audit DAG-1.)
    must_refuse: Option<&'static str>,
}

/// Build up to MAX_BLOCKS sealed blocks from the input.
fn build(inp: &mut Input, genesis: &Block) -> Vec<Built> {
    // (hash, header height, timestamp) of every block a later one may name.
    let mut known: Vec<([u8; 32], u64, u64)> = vec![(genesis.block_hash(), 0, GENESIS_TS)];
    let mut out = Vec::new();
    let n = 1 + inp.below(MAX_BLOCKS);
    for _ in 0..n {
        if inp.is_empty() && !out.is_empty() {
            break;
        }
        // Parents: 1..=3 distinct known blocks.
        let n_par = 1 + inp.below(3);
        let mut parents: Vec<[u8; 32]> = Vec::new();
        let (mut height, mut parent_ts) = (0u64, 0u64);
        for _ in 0..n_par {
            let (h, ph, ts) = known[inp.below(known.len())];
            if !parents.contains(&h) {
                parents.push(h);
                height = height.max(ph + 1);
                parent_ts = parent_ts.max(ts);
            }
        }
        let flags = inp.u8();
        let mut header_height = height;
        if flags % 23 == 1 {
            header_height += 1; // wrong height
        }
        // Few distinct timestamps: blocks recur across inputs and the proof of
        // work cache (keyed by block id) keeps the target fast.
        let ts = if flags % 23 == 2 { parent_ts.saturating_sub(1) } else { parent_ts + 1 + inp.below(4) as u64 };
        let expected = pow::expected_bits(parent_ts, header_height).expect("expected bits");
        let mut bits = expected;
        if flags % 23 == 3 {
            // Wrong bits that still seal: a target within the pow limit that
            // one or two evaluations meet (one mantissa unit below the limit,
            // or half of it), so the block passes the proof-of-work check of
            // `validate_structure` and reaches `accept_block`'s difficulty
            // rule ("invalid difficulty"). A target as hard as the genesis
            // target would almost never seal, and its block would only ever
            // be refused as "invalid PoW".
            bits = if flags & 0x40 == 0 { 0x2100_FFFE } else { 0x2100_8000 };
            assert_ne!(bits, expected, "the wrong-bits fault must not be the expected bits");
        }
        let hardened = block_rules::rules_active(header_height);

        // Transactions.
        let mut txs: Vec<Transaction> = Vec::new();
        let mut fees = 0u64;
        for _ in 0..inp.below(3) {
            let c = inp.u8();
            let fault = match c % 11 {
                9 => Fault::BadSignature,
                10 => Fault::MissingInput,
                _ => Fault::None,
            };
            let slot = Slot { fund: (c >> 4) % N_FUNDS, variant: (c >> 6) & 1, depth: (c / 3) % 3, fault };
            txs.push(signed(slot, activation::hardening_active_at(header_height)));
            fees += STEP_FEE;
        }
        let duplicated = flags % 23 == 4 && !txs.is_empty();
        if duplicated {
            txs.push(txs[0].clone()); // duplicate transaction
        }
        let mut cb_value = core::tokenomics::block_subsidy_sat(header_height);
        if flags & 0x80 != 0 {
            cb_value += fees;
        }
        if flags % 23 == 5 {
            cb_value += 1; // over-claim (connect-time failure)
        }
        let tag = inp.u8();
        let mut all = vec![Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev_txid: [0; 32],
                prev_index: u32::MAX,
                script_sig: format!("fuzz:{}:{tag}", out.len()).into_bytes(),
                sequence: u32::MAX,
            }],
            outputs: vec![TxOutput { value: cb_value, script_pubkey: vec![0xC0 ^ tag; 20] }],
            locktime: 0,
        }];
        all.extend(txs);
        let mut b = Block {
            header: BlockHeader { version: 1, parents, merkle_root: MerkleRoot::ZERO, timestamp: ts, bits, nonce: 0 },
            transactions: all,
            blue_score: header_height,
            height: header_height,
            shielded_transactions: vec![],
        };
        if hardened {
            let c = block_rules::expected_coinbase_commitment(&b);
            let extra = std::mem::take(&mut b.transactions[0].inputs[0].script_sig);
            b.transactions[0].inputs[0].script_sig = block_rules::coinbase_script_sig(&c, &extra);
        }
        b.header.merkle_root = b.body_merkle_root();
        // Seal every block, the wrong-bits fault included (its target is
        // within the pow limit and met after about two tries at worst).
        let mut tries = 0;
        while !b.validate_pow() && tries < 64 {
            b.header.nonce += 1;
            tries += 1;
        }
        let hash = b.block_hash();
        known.push((hash, header_height, ts));
        let must_refuse = match flags % 23 {
            1 => Some("a wrong height"),
            2 => Some("a timestamp before its parent"),
            3 => Some("wrong difficulty bits"),
            4 if duplicated => Some("a duplicated transaction"),
            _ => None,
        };
        out.push(Built { block: b, hash, must_refuse });
    }
    out
}

struct Node {
    _tmp: tempfile::TempDir,
    dag: Arc<RwLock<GhostDAG>>,
    store: Arc<Storage>,
    mempool: Arc<Mempool>,
    node_state: Arc<RwLock<NodeState>>,
    shielded: Arc<RwLock<ShieldedPool>>,
}

fn new_node(genesis: &Block) -> Node {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let store = Arc::new(Storage::open(&tmp.path().join("db")).expect("open storage"));
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
    for i in 0..N_FUNDS {
        let (t, idx, o) = fund(i);
        store.put_utxo(&t, idx, &o).unwrap();
    }
    Node {
        _tmp: tmp,
        dag,
        store,
        mempool: Arc::new(Mempool::new()),
        node_state: Arc::new(RwLock::new(NodeState::default())),
        shielded: Arc::new(RwLock::new(ShieldedPool::new())),
    }
}

fn deliver(n: &Node, b: &Built) -> Result<[u8; 32], String> {
    b.block.validate_structure().map_err(|e| format!("structural validation: {e}"))?;
    accept::accept_block(
        &b.block, b.hash, b.block.height, &n.dag, &n.store, &n.mempool, &n.node_state, None, &n.shielded,
    )
}

/// `ACCEPT_DAG_LOG=1` prints every delivery verdict of the first arrival
/// order to stderr (`accept_dag A b<i>: ok | <rejection>`), to see which
/// rules a corpus reaches when replaying it.
fn verbose() -> bool {
    static V: OnceLock<bool> = OnceLock::new();
    *V.get_or_init(|| std::env::var_os("ACCEPT_DAG_LOG").is_some())
}

/// Deliver `blocks` in `order`; a block with an unknown parent waits and is
/// retried after every round that accepted something (the orphan pool).
fn run(n: &Node, blocks: &[Built], order: &[usize]) -> Vec<String> {
    let mut log = Vec::new();
    let mut pending: Vec<usize> = order.to_vec();
    loop {
        let mut waiting = Vec::new();
        let mut progress = false;
        for &i in &pending {
            match deliver(n, &blocks[i]) {
                Err(e) if e.contains("unknown parent") => waiting.push(i),
                r => {
                    progress = true;
                    log.push(format!("b{i}: {}", r.map(|_| "ok".to_string()).unwrap_or_else(|e| e)));
                }
            }
        }
        if waiting.is_empty() || !progress {
            break;
        }
        pending = waiting;
    }
    log
}

#[derive(Debug, PartialEq, Eq)]
struct State {
    selected_tip: Option<[u8; 32]>,
    applied_tip: Option<[u8; 32]>,
    utxo_digest: [u8; 32],
    utxo_count: usize,
    dag_blocks: Vec<bool>,
}

fn state(n: &Node, blocks: &[Built]) -> State {
    let utxos = n.store.iter_utxos_sorted().expect("utxo iteration");
    let mut enc = Vec::new();
    for (t, i, v, s) in &utxos {
        enc.extend_from_slice(t);
        enc.extend_from_slice(&i.to_le_bytes());
        enc.extend_from_slice(&v.to_le_bytes());
        enc.extend_from_slice(&(s.len() as u32).to_le_bytes());
        enc.extend_from_slice(s);
    }
    let d = n.dag.read();
    State {
        selected_tip: d.selected_tip(),
        applied_tip: n.store.get_meta("tip_hash").unwrap().map(|v| v.as_slice().try_into().unwrap()),
        utxo_digest: sha3(&enc),
        utxo_count: utxos.len(),
        dag_blocks: blocks.iter().map(|b| d.has_block(&b.hash)).collect(),
    }
}

/// Reload the DAG from storage as `main()` does after a restart.
fn restart(n: &mut Node) {
    let mut d = GhostDAG::with_default_k();
    let entries = n.store.load_all_dag_data().unwrap();
    let im = n.store.load_all_integrity_hashes().unwrap();
    d.load_persisted_validated(entries, im).expect("integrity chain verifies after a restart");
    let records = n.store.load_all_reachability().unwrap();
    let root = n.store.get_reachability_root().unwrap();
    if records.len() == d.block_count() {
        d.reach_load_records(&records, root).unwrap();
    } else {
        d.rebuild_reachability_from_store().unwrap();
    }
    n.dag = Arc::new(RwLock::new(d));
    n.shielded = Arc::new(RwLock::new(ShieldedPool::new()));
    accept::reconcile_on_startup(&n.dag, &n.store, &n.shielded).expect("reconcile after a restart");
}

fuzz_target!(|data: &[u8]| {
    let mut inp = Input::new(data);
    let act = match inp.u8() % 4 {
        0 => activation::NEVER,
        1 => 0,
        2 => 1 + inp.below(3) as u64,
        _ => activation::MAINNET_HARDENING_ACTIVATION_HEIGHT,
    };
    let do_restart = inp.u8() % 4 == 0;
    let _act = activation::scoped_override(act);
    let g = genesis();
    let blocks = build(&mut inp, &g);

    // Two arrival orders: build order, and a permutation from the input.
    let natural: Vec<usize> = (0..blocks.len()).collect();
    let mut perm = natural.clone();
    for i in (1..perm.len()).rev() {
        let j = inp.below(i + 1);
        perm.swap(i, j);
    }
    if perm == natural {
        perm.reverse();
    }

    let a = new_node(&g);
    let log_a = run(&a, &blocks, &natural);
    if verbose() {
        for l in &log_a {
            eprintln!("accept_dag A {l}");
        }
    }
    let mut b = new_node(&g);
    let log_b = run(&b, &blocks, &perm);
    let (sa, sb) = (state(&a, &blocks), state(&b, &blocks));
    assert_eq!(
        sa, sb,
        "arrival order changed the outcome (activation {act})\norder A {natural:?}: {log_a:#?}\norder B {perm:?}: {log_b:#?}"
    );
    for (i, blk) in blocks.iter().enumerate() {
        if let Some(fault) = blk.must_refuse {
            assert!(
                !sa.dag_blocks[i] && !sb.dag_blocks[i],
                "b{i} with {fault} was accepted (activation {act})\norder A {natural:?}: {log_a:#?}\norder B {perm:?}: {log_b:#?}"
            );
        }
    }
    if do_restart {
        restart(&mut b);
        let sr = state(&b, &blocks);
        assert_eq!(sr, sb, "a restart changed the outcome (activation {act}); order {perm:?}: {log_b:#?}");
    }
});
