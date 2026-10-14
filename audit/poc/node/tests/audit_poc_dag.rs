//! AUDIT PoC — GhostDAG / DAG ordering / chain selection / reorg (reviewer DAG).
//!
//! Proof-of-concept tests for findings DAG-1 .. DAG-8 of the code-only audit.
//! Each test drives the REAL library code (`gnb::consensus::GhostDAG`,
//! `gnb::storage::Storage`, `gnb::reorg::*`, `gnb::core::Block`).
//!
//! `accept_block` lives in the binary crate (src/main.rs) and cannot be linked
//! from an integration test, so DAG-1 and DAG-6 use a MIRROR of the exact steps
//! `accept_block` performs (cited by line). The mirror keeps the original order
//! of operations: parents known -> tx input lookup against the node's single
//! UTXO set -> dag.add_block -> disposition -> apply / reorg / remove_block.
//!
//! Run: cargo test --release --locked -p gnb --test audit_poc_dag -- --nocapture --test-threads=1

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;

use gnb::consensus::reachability::brute_force_is_ancestor;
use gnb::consensus::{BlockHash, GhostDAG};
use gnb::core::{Block, BlockHeader, Transaction, TxInput, TxOutput, MAX_PARENTS};
use gnb::mempool::Mempool;
use gnb::reorg::{
    apply_block_utxo_mutations, compute_reorg_plan, execute_reorg, ERR_REORG_DEPTH,
    MAX_REORG_DEPTH,
};
use gnb::storage::Storage;
use tempfile::TempDir;

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────────────

fn hx(tag: u8, i: u64) -> BlockHash {
    let mut h = [0u8; 32];
    h[0] = tag;
    h[1..9].copy_from_slice(&i.to_be_bytes());
    h
}

fn coinbase(height: u64, tag: u64) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid: [0u8; 32],
            prev_index: u32::MAX,
            script_sig: format!("cb:{}:{}", height, tag).into_bytes(),
            sequence: u32::MAX,
        }],
        outputs: vec![TxOutput { value: 1_000, script_pubkey: vec![0xC0; 20] }],
        locktime: 0,
    }
}

fn spend(prev_txid: [u8; 32], prev_index: u32, value: u64) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev_txid,
            prev_index,
            // Signature bytes are irrelevant: the mirrored lookup fails BEFORE
            // validate_tx_inputs reaches signature verification (main.rs:2719
            // precedes main.rs:2742).
            script_sig: vec![0xAA; 8],
            sequence: u32::MAX,
        }],
        outputs: vec![TxOutput { value, script_pubkey: vec![0x22; 20] }],
        locktime: 0,
    }
}

fn block(parents: Vec<BlockHash>, height: u64, nonce: u64, txs: Vec<Transaction>) -> Block {
    Block {
        header: BlockHeader {
            version: 1,
            parents,
            merkle_root: gnb::core::MerkleRoot::ZERO,
            timestamp: 1_800_000_000 + height,
            bits: 0x2100_ffff,
            nonce,
        },
        transactions: txs,
        blue_score: height,
        height,
        shielded_transactions: Vec::new(),
    }
}

struct Node {
    _tmp: TempDir,
    store: Storage,
    dag: GhostDAG,
    mempool: Mempool,
}

fn node(genesis: BlockHash, seed_utxo: Option<([u8; 32], u32, TxOutput)>) -> Node {
    let tmp = TempDir::new().unwrap();
    let store = Storage::open(tmp.path()).unwrap();
    if let Some((txid, idx, out)) = seed_utxo {
        store.put_utxo(&txid, idx, &out).unwrap();
    }
    let mut dag = GhostDAG::with_default_k();
    dag.add_genesis(genesis, 0);
    Node { _tmp: tmp, store, dag, mempool: Mempool::new() }
}

/// Mirror of the tx-input resolution done by accept_block for EVERY block,
/// including blocks that will end up as fork-losers:
///   main.rs:2061-2066  -> validate_tx_in_block_with_maturity (main.rs:2824)
///   main.rs:2863-2882  -> lookup = earlier-in-block outputs, else store.get_utxo
///   main.rs:2706-2721  -> double-spend set + "UTXO ... not found"
fn mirror_input_lookup(store: &Storage, b: &Block) -> Result<(), String> {
    let mut spent_in_block: HashSet<([u8; 32], u32)> = HashSet::new();
    for (i, tx) in b.transactions.iter().enumerate().skip(1) {
        let earlier: HashMap<([u8; 32], u32), TxOutput> = b.transactions[..i]
            .iter()
            .flat_map(|t| {
                let id = t.txid();
                t.outputs.iter().enumerate().map(move |(j, o)| ((id, j as u32), o.clone()))
            })
            .collect();
        let mut local: HashSet<([u8; 32], u32)> = HashSet::new();
        for inp in &tx.inputs {
            let op = (inp.prev_txid, inp.prev_index);
            if spent_in_block.contains(&op) || !local.insert(op) {
                return Err("double-spend".into());
            }
            let found = earlier.contains_key(&op)
                || store.get_utxo(&inp.prev_txid, inp.prev_index).unwrap().is_some();
            if !found {
                return Err(format!(
                    "UTXO {}:{} not found",
                    hex::encode(&inp.prev_txid[..8]),
                    inp.prev_index
                ));
            }
            spent_in_block.insert(op);
        }
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum Disp {
    Extension,
    ForkLoser,
    Reorg,
}

/// Mirror of accept_block's ordering (main.rs:1985-2333), minus PoW / bits /
/// timestamp (identical on every node) and minus signature checks (which run
/// after the lookup that fails here).
fn mirror_accept(n: &mut Node, b: &Block) -> Result<Disp, String> {
    let h = b.block_hash();
    if n.dag.has_block(&h) {
        return Err("already in DAG".into()); // main.rs:1985
    }
    for p in &b.header.parents {
        if !n.dag.has_block(p) {
            return Err("unknown parent (orphan)".into()); // main.rs:2004 / 1139
        }
    }
    mirror_input_lookup(&n.store, b)?; // main.rs:2061 — BEFORE add_block
    let old = n.dag.selected_tip(); // main.rs:2077
    n.dag
        .add_block(h, b.header.parents.clone(), b.header.timestamp, 1)
        .map_err(|e| e.to_string())?; // main.rs:2096
    n.store.put_block(b).unwrap(); // main.rs:2120
    let new = n.dag.selected_tip(); // main.rs:2154
    let sp = n.dag.get_block_data(&h).and_then(|d| d.selected_parent);
    let disp = match (old, new) {
        (Some(o), Some(nw)) if nw == o => Disp::ForkLoser,
        (Some(o), Some(nw)) if nw == h => {
            if sp == Some(o) { Disp::Extension } else { Disp::Reorg }
        }
        _ => {
            n.dag.remove_block(&h);
            return Err("unexpected".into());
        }
    };
    match disp {
        Disp::ForkLoser => {}
        Disp::Extension => apply_block_utxo_mutations(&n.store, b)?, // main.rs:2230
        Disp::Reorg => {
            let plan = compute_reorg_plan(&n.dag, &old.unwrap(), &new.unwrap())
                .ok_or("no plan")?;
            if let Err(e) = execute_reorg(&n.store, &n.mempool, &plan) {
                n.dag.remove_block(&h); // main.rs:2290
                return Err(e);
            }
        }
    }
    Ok(disp)
}

// ─────────────────────────────────────────────────────────────────────────────
// DAG-1 (Critical): fork blocks are validated against the CURRENT selected-chain
// UTXO set, so DAG membership depends on arrival order. Two honest nodes that
// see two parallel blocks carrying the SAME mempool transaction in opposite
// order each reject the other's block forever -> permanent chain split.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn dag1_same_tx_in_parallel_blocks_splits_honest_nodes_permanently() {
    let g = hx(0xEE, 0);
    let u_txid = [0x55u8; 32];
    let u_out = TxOutput { value: 50_000, script_pubkey: vec![0x11; 20] };
    let mut x = node(g, Some((u_txid, 0, u_out.clone())));
    let mut y = node(g, Some((u_txid, 0, u_out)));

    // One ordinary mempool transaction T spending U. Two miners working on the
    // same tip both include it (the normal case for parallel DAG blocks).
    let t = spend(u_txid, 0, 40_000);
    let a1 = block(vec![g], 1, 1, vec![coinbase(1, 1), t.clone()]);
    let b1 = block(vec![g], 1, 2, vec![coinbase(1, 2), t.clone()]);
    let (a1h, b1h) = (a1.block_hash(), b1.block_hash());

    // X sees a1 first, Y sees b1 first.
    assert_eq!(mirror_accept(&mut x, &a1), Ok(Disp::Extension));
    assert_eq!(mirror_accept(&mut y, &b1), Ok(Disp::Extension));
    let ex = mirror_accept(&mut x, &b1).unwrap_err();
    let ey = mirror_accept(&mut y, &a1).unwrap_err();
    println!("X rejects b1: {ex}\nY rejects a1: {ey}");
    assert!(ex.contains("not found") && ey.contains("not found"));

    // A pure GhostDAG (what sprint_ee_convergence / dst_harness test) would
    // accept BOTH siblings on both nodes and converge. Here X keeps extending a1.
    let a2 = block(vec![a1h], 2, 3, vec![coinbase(2, 3)]);
    assert_eq!(mirror_accept(&mut x, &a2), Ok(Disp::Extension));

    // Y gets a2: orphan -> fetches a1 -> a1 is rejected again (U is spent in
    // Y's UTXO set) -> a2 can never connect, no matter how heavy X's side gets.
    for _round in 0..3 {
        assert!(mirror_accept(&mut y, &a2).unwrap_err().contains("orphan"));
        assert!(mirror_accept(&mut y, &a1).unwrap_err().contains("not found"));
    }
    assert!(x.dag.has_block(&a1h) && !x.dag.has_block(&b1h));
    assert!(y.dag.has_block(&b1h) && !y.dag.has_block(&a1h));
    let wx = x.dag.get_block_data(&x.dag.selected_tip().unwrap()).unwrap().blue_work;
    let wy = y.dag.get_block_data(&y.dag.selected_tip().unwrap()).unwrap().blue_work;
    assert!(wx > wy, "X's side is strictly heavier, yet Y can never adopt it");
    assert_ne!(x.dag.selected_tip(), y.dag.selected_tip());
    println!("DAG-1 CONFIRMED: permanent split X tip={} (work {wx}) vs Y tip={} (work {wy})",
        hex::encode(&x.dag.selected_tip().unwrap()[..4]),
        hex::encode(&y.dag.selected_tip().unwrap()[..4]));
}

// ─────────────────────────────────────────────────────────────────────────────
// DAG-2 (High): no MAX_PARENTS cap when building templates. The built-in miner
// (main.rs:1560,1654) and getblocktemplate (rpc/mod.rs:1108) use ALL bodied
// tips as parents; validate_structure rejects > MAX_PARENTS (core/mod.rs:1011)
// and the wire decoder refuses them (core/mod.rs:366). 257 cheap side tips
// therefore make every template invalid: a network-wide mining halt.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn dag2_more_than_max_parents_tips_make_every_template_invalid() {
    let g = hx(0xEE, 0);
    let mut dag = GhostDAG::with_default_k();
    dag.add_genesis(g, 0);
    let mut prev = g;
    for i in 1..=20u64 {
        let h = hx(1, i);
        dag.add_block(h, vec![prev], i, 1_000).unwrap();
        prev = h;
    }
    // Attacker: one anchor block deep in history, then 300 leaf children.
    // (Each would be a valid fork-loser; they never need to win.)
    let anchor = hx(2, 0);
    dag.add_block(anchor, vec![hx(1, 3)], 100, 1).unwrap();
    for i in 0..(MAX_PARENTS as u64 + 44) {
        dag.add_block(hx(3, i), vec![anchor], 101, 1).unwrap();
    }
    let tips = dag.bodied_tips(|_| true); // what the miner / GBT use
    println!("tips used as template parents: {}", tips.len());
    assert!(tips.len() > MAX_PARENTS);

    let template = block(tips.clone(), 21, 0, vec![coinbase(21, 0)]);
    assert_eq!(template.validate_structure(), Err("too many parents"));
    assert!(Block::from_wire_bytes(&template.to_wire_bytes()).is_err());
    // The honest selected tip is unaffected, so the tips persist: nobody can
    // merge them with a <=256-parent block built by the stock miner.
    assert_eq!(dag.selected_tip(), Some(prev));
    println!("DAG-2 CONFIRMED: template with {} parents rejected by validate_structure", tips.len());
}

// ─────────────────────────────────────────────────────────────────────────────
// DAG-3 (High, design deviation): blue_work = selected_parent.blue_work + OWN
// work (consensus/mod.rs:1066); merged blue blocks add nothing. Fork choice is
// therefore "heaviest single selected-parent chain", not GHOSTDAG's most blue
// work. A tip whose past holds 16 blue blocks loses to a bare 11-block chain.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn dag3_fork_choice_ignores_merged_blue_work() {
    let g = hx(0xEE, 0);
    let mut dag = GhostDAG::with_default_k();
    dag.add_genesis(g, 0);
    // Honest DAG: 5 rounds of (L_i, R_i) parallel + M_i merging both.
    let mut prev = g;
    for i in 1..=5u64 {
        let (l, r, m) = (hx(0x10, i), hx(0x11, i), hx(0x12, i));
        dag.add_block(l, vec![prev], i, 1).unwrap();
        dag.add_block(r, vec![prev], i, 1).unwrap();
        let d = dag.add_block(m, vec![l, r], i, 1).unwrap();
        assert_eq!(d.mergeset_blues.len(), 1, "sibling merged as blue");
        prev = m;
    }
    let honest_tip = prev;
    // Competing bare chain of 11 blocks (fewer blocks than the 15 honest ones).
    let mut c = g;
    for i in 1..=11u64 {
        let h = hx(0x20, i);
        dag.add_block(h, vec![c], i, 1).unwrap();
        c = h;
    }
    let hd = dag.get_block_data(&honest_tip).unwrap().clone();
    let cd = dag.get_block_data(&c).unwrap().clone();
    println!("honest tip: blue_score={} blue_work={} | bare chain: blue_score={} blue_work={}",
        hd.blue_score, hd.blue_work, cd.blue_score, cd.blue_work);
    assert!(hd.blue_score > cd.blue_score, "honest past has more blue blocks");
    // Kaspa: blue_work(B) = blue_work(sp) + sum(work of mergeset_blues incl. sp)
    // => honest = 15, bare = 11. GnB: honest = 10, bare = 11.
    assert_eq!(hd.blue_work, 10);
    assert_eq!(cd.blue_work, 11);
    assert_eq!(dag.selected_tip(), Some(c), "bare chain wins fork choice");
    println!("DAG-3 CONFIRMED: fork choice ignores 5 merged blue blocks");
}

// ─────────────────────────────────────────────────────────────────────────────
// DAG-4 (Medium): the Fast coloring omits selected-chain blocks (other than the
// immediate selected parent) from the candidate's anticone count, because
// GnB strips the selected parent from mergeset_blues (consensus/mod.rs:1313)
// while the bounded chain walk (consensus/mod.rs:1344-1361) was written for
// Kaspa, where mergeset_blues[0] IS the selected parent. Historical blues'
// anticone sizes are also reset to 0 per block (consensus/mod.rs:1299).
// Result: a side block forked 30 chain blocks deep is coloured BLUE with k=10.
// ─────────────────────────────────────────────────────────────────────────────

/// Exact PHANTOM/GHOSTDAG greedy colouring (paper Alg.1, Kaspa semantics),
/// using brute-force ancestry. blue(B) = blue(sp) ∪ {sp} ∪ chosen mergeset blues.
fn reference_blue_set(dag: &GhostDAG, b: &BlockHash, k: usize,
                      memo: &mut HashMap<BlockHash, HashSet<BlockHash>>) -> HashSet<BlockHash> {
    if let Some(s) = memo.get(b) { return s.clone(); }
    let d = dag.get_block_data(b).unwrap().clone();
    let mut blue = match d.selected_parent {
        None => HashSet::new(),
        Some(sp) => { let mut s = reference_blue_set(dag, &sp, k, memo); s.insert(sp); s }
    };
    if let Some(sp) = d.selected_parent {
        let anti = |x: &BlockHash, y: &BlockHash| x != y
            && !brute_force_is_ancestor(&dag.store, x, y)
            && !brute_force_is_ancestor(&dag.store, y, x);
        // same candidate order GnB uses: mergeset_blues ∪ reds in topo/hash order
        let mut cands: Vec<BlockHash> = d.mergeset_blues.iter().chain(d.mergeset_reds.iter()).cloned().collect();
        cands = topo(dag, cands);
        let _ = sp;
        for c in cands {
            let ac: Vec<BlockHash> = blue.iter().filter(|x| anti(&c, *x)).cloned().collect();
            if ac.len() > k { continue; }
            let ok = ac.iter().all(|bb| blue.iter().filter(|x| anti(bb, *x)).count() + 1 <= k);
            if ok { blue.insert(c); }
        }
    }
    memo.insert(*b, blue.clone());
    blue
}

/// Same tie-broken Kahn order as consensus::topological_sort.
fn topo(dag: &GhostDAG, blocks: Vec<BlockHash>) -> Vec<BlockHash> {
    let set: HashSet<BlockHash> = blocks.iter().cloned().collect();
    let mut indeg: HashMap<BlockHash, usize> = HashMap::new();
    let mut rev: HashMap<BlockHash, Vec<BlockHash>> = HashMap::new();
    for &b in &blocks {
        indeg.entry(b).or_insert(0);
        for p in &dag.get_block_data(&b).unwrap().parents {
            if set.contains(p) { *indeg.entry(b).or_insert(0) += 1; rev.entry(*p).or_default().push(b); }
        }
    }
    let mut start: Vec<BlockHash> = indeg.iter().filter(|(_, &d)| d == 0).map(|(h, _)| *h).collect();
    start.sort_unstable();
    let mut q: VecDeque<BlockHash> = start.into();
    let mut out = vec![];
    while let Some(b) = q.pop_front() {
        out.push(b);
        if let Some(ch) = rev.get(&b) {
            let mut nx = vec![];
            for c in ch { let d = indeg.get_mut(c).unwrap(); *d -= 1; if *d == 0 { nx.push(*c); } }
            nx.sort_unstable();
            q.extend(nx);
        }
    }
    out
}

#[test]
fn dag4_fast_coloring_violates_k_cluster() {
    let k = gnb::core::GHOSTDAG_K;
    let g = hx(0xEE, 0);
    let mut dag = GhostDAG::with_default_k(); // production path (Fast from h=0)
    dag.add_genesis(g, 0);
    let mut prev = g;
    for i in 1..=30u64 {
        let h = hx(1, i);
        dag.add_block(h, vec![prev], i, 1_000).unwrap();
        prev = h;
    }
    let side = hx(9, 1);
    dag.add_block(side, vec![g], 1, 1_000).unwrap();
    let m = hx(9, 2);
    let d = dag.add_block(m, vec![prev, side], 31, 1_000).unwrap();
    // True anticone of `side` inside blue(M) = 30 chain blocks.
    let anticone_blues = (1..=30u64)
        .filter(|i| {
            let c = hx(1, *i);
            !brute_force_is_ancestor(&dag.store, &c, &side)
                && !brute_force_is_ancestor(&dag.store, &side, &c)
        })
        .count();
    println!("side block anticone ∩ blue(sp) = {anticone_blues} (k = {k}); GnB colours it {}",
        if d.mergeset_blues.contains(&side) { "BLUE" } else { "red" });
    assert!(anticone_blues > k);
    assert!(d.mergeset_blues.contains(&side), "k-cluster violated: deep side block coloured blue");

    // Differential vs exact GHOSTDAG on random small DAGs (same candidate
    // order, same selected parent): count blocks whose blue set differs.
    let mut seed: u64 = 0x5EED_0F_DA6;
    let mut rnd = || { seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; seed };
    let mut mismatches = 0usize;
    for _ in 0..40 {
        let kk = 2usize;
        let mut dag = GhostDAG::with_k(kk);
        dag.add_genesis(hx(0, 0), 0);
        let mut ids = vec![hx(0, 0)];
        for i in 1..24u64 {
            let nparents = 1 + (rnd() % 3) as usize;
            let lo = ids.len().saturating_sub(6);
            let span = ids.len() - lo;
            let mut ps: Vec<BlockHash> = (0..nparents)
                .map(|_| ids[lo + (rnd() as usize) % span])
                .collect();
            ps.sort(); ps.dedup();
            let h = hx(0x40, i);
            dag.add_block(h, ps, i, 1).unwrap();
            ids.push(h);
        }
        let mut memo = HashMap::new();
        for h in &ids[1..] {
            let d = dag.get_block_data(h).unwrap().clone();
            let reference = reference_blue_set(&dag, h, kk, &mut memo);
            let mut gnb_blue: HashSet<BlockHash> = HashSet::new();
            let mut cur = Some(*h);
            while let Some(c) = cur {
                let cd = dag.get_block_data(&c).unwrap();
                gnb_blue.extend(cd.mergeset_blues.iter().cloned());
                if let Some(sp) = cd.selected_parent { gnb_blue.insert(sp); }
                cur = cd.selected_parent;
            }
            if gnb_blue != reference { mismatches += 1; let _ = d; }
        }
    }
    println!("random-DAG differential vs exact GHOSTDAG (k=2): {mismatches} blocks with a different blue set");
    assert!(mismatches > 0);
    println!("DAG-4 CONFIRMED");
}

// ─────────────────────────────────────────────────────────────────────────────
// DAG-5 (Low): load_persisted / load_persisted_validated insert in blue_score
// order (consensus/mod.rs:895, 953), which is not a topological order for
// NON-selected parents. A non-selected parent with a higher blue_score than its
// child is re-inserted AFTER the child and becomes a "tip" again on restart.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn dag5_restart_resurrects_interior_block_as_tip() {
    let g = hx(0xEE, 0);
    let mut dag = GhostDAG::with_k(1);
    dag.add_genesis(g, 0);
    let s1 = hx(1, 1);
    dag.add_block(s1, vec![g], 1, 1_000).unwrap(); // heavy single block
    let mut q = g;
    for i in 1..=10u64 {
        let h = hx(2, i);
        dag.add_block(h, vec![q], i, 1).unwrap(); // light long chain
        q = h;
    }
    let b = hx(3, 1);
    dag.add_block(b, vec![s1, q], 11, 1).unwrap();
    let bs_b = dag.get_block_data(&b).unwrap().blue_score;
    let bs_q = dag.get_block_data(&q).unwrap().blue_score;
    println!("child B blue_score={bs_b}, its non-selected parent Q10 blue_score={bs_q}");
    assert!(bs_q > bs_b);
    let before: HashSet<BlockHash> = dag.tips().into_iter().collect();

    let entries: Vec<(BlockHash, _)> = dag.store.data.iter().map(|(h, d)| (*h, d.clone())).collect();
    let mut reloaded = GhostDAG::with_k(1);
    reloaded.load_persisted(entries);
    let after: HashSet<BlockHash> = reloaded.tips().into_iter().collect();
    println!("tips before restart: {}, after: {}", before.len(), after.len());
    assert!(after.contains(&q) && !before.contains(&q), "interior block resurrected as a tip");
    println!("DAG-5 CONFIRMED");
}

// ─────────────────────────────────────────────────────────────────────────────
// DAG-6 (High): MAX_REORG_DEPTH (reorg.rs:42,809) is a node-local, history-
// dependent rule. A node that saw the honest chain first refuses a heavier
// fork deeper than 1000 blocks; a node that received the same blocks
// interleaved (e.g. fresh IBD, or a partition peer) follows the heavier fork.
// Same block set, different final selected chain: permanent split.
// ─────────────────────────────────────────────────────────────────────────────

/// Mirror of the DAG side of accept_block's Reorg arm: plan, depth cap via the
/// REAL execute_reorg refusal (checked before any storage access), undo.
fn dag_only_accept(dag: &mut GhostDAG, store: &Storage, mp: &Mempool,
                   h: BlockHash, parents: Vec<BlockHash>, work: u128) -> Result<(), String> {
    if parents.iter().any(|p| !dag.has_block(p)) { return Err("orphan".into()); }
    let old = dag.selected_tip();
    dag.add_block(h, parents, 0, work).map_err(|e| e.to_string())?;
    let new = dag.selected_tip();
    if new == Some(h) && old.is_some() && dag.get_block_data(&h).unwrap().selected_parent != old {
        let plan = compute_reorg_plan(dag, &old.unwrap(), &h).ok_or("no plan")?;
        if plan.to_rollback.len() as u64 > MAX_REORG_DEPTH {
            let e = execute_reorg(store, mp, &plan).unwrap_err();
            dag.remove_block(&h);
            return Err(e);
        }
    }
    Ok(())
}

#[test]
fn dag6_reorg_depth_cap_splits_nodes_by_arrival_order() {
    let g = hx(0xEE, 0);
    let n = MAX_REORG_DEPTH + 101; // 1101
    let honest: Vec<BlockHash> = (1..=n).map(|i| hx(0x30, i)).collect();
    let fork: Vec<BlockHash> = (1..=n).map(|i| hx(0x31, i)).collect();
    let tmp = TempDir::new().unwrap();
    let store = Storage::open(tmp.path()).unwrap();
    let mp = Mempool::new();

    // Node X: honest chain first, heavier fork later.
    let mut x = GhostDAG::with_default_k();
    x.add_genesis(g, 0);
    for i in 0..n as usize {
        dag_only_accept(&mut x, &store, &mp, honest[i], vec![if i == 0 { g } else { honest[i - 1] }], 1).unwrap();
    }
    let mut refused = 0;
    let mut first_err = String::new();
    for i in 0..n as usize {
        if let Err(e) = dag_only_accept(&mut x, &store, &mp, fork[i], vec![if i == 0 { g } else { fork[i - 1] }], 2) {
            if first_err.is_empty() { first_err = e; }
            refused += 1;
        }
    }
    // Node Z: the SAME blocks, interleaved.
    let mut z = GhostDAG::with_default_k();
    z.add_genesis(g, 0);
    for i in 0..n as usize {
        dag_only_accept(&mut z, &store, &mp, honest[i], vec![if i == 0 { g } else { honest[i - 1] }], 1).unwrap();
        dag_only_accept(&mut z, &store, &mp, fork[i], vec![if i == 0 { g } else { fork[i - 1] }], 2).unwrap();
    }
    println!("X first refusal: {first_err}; X refused {refused} fork blocks");
    assert!(first_err.contains(ERR_REORG_DEPTH));
    assert_eq!(x.selected_tip(), Some(honest[n as usize - 1]));
    assert_eq!(z.selected_tip(), Some(fork[n as usize - 1]));
    println!("DAG-6 CONFIRMED: X on honest chain (work {}), Z on fork (work {})",
        x.get_block_data(&x.selected_tip().unwrap()).unwrap().blue_work,
        z.get_block_data(&z.selected_tip().unwrap()).unwrap().blue_work);
}

// ─────────────────────────────────────────────────────────────────────────────
// DAG-7 (High, DoS): per-block cost is O(|past(selected_parent)|) because
// compute_mergeset always runs compute_past (consensus/mod.rs:417); deep
// insertions and genesis siblings trigger whole-subtree reachability reindexes
// (reachability.rs:233-297, subtree_size recomputed per child => O(n·depth));
// a merge block whose mergeset is a deep side chain costs O(|mergeset|·depth)
// (candidate_anticone_blues has no k+1 early exit and there is no mergeset
// size limit).
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn dag7_dos_cost_profile() {
    let n: u64 = 12_000;
    let g = hx(0xEE, 0);
    let mut dag = GhostDAG::with_default_k();
    dag.add_genesis(g, 0);
    let mut chain = vec![g];
    let mut ext_small = std::time::Duration::ZERO;
    let t_build = Instant::now();
    for i in 1..=n {
        let h = hx(1, i);
        let t = Instant::now();
        dag.add_block(h, vec![chain[(i - 1) as usize]], i, 1).unwrap();
        if i == 1_000 { ext_small = t.elapsed(); }
        chain.push(h);
    }
    println!("built {n}-block chain in {:.2?}", t_build.elapsed());

    let t = Instant::now();
    let tip_ext = hx(2, 0);
    dag.add_block(tip_ext, vec![chain[n as usize]], n + 1, 1).unwrap();
    let ext_big = t.elapsed();
    dag.remove_block(&tip_ext);
    println!("tip extension: at h=1000 {:.2?}, at h={n} {:.2?}", ext_small, ext_big);

    // Deep sibling (what the backfill guard tries to block, bypassable via the
    // `awaited` orphan-parent path, main.rs:1110-1121).
    let mut deep = vec![];
    for (j, depth) in [n / 2, n / 4].iter().enumerate() {
        let t = Instant::now();
        let s = hx(3, j as u64);
        dag.add_block(s, vec![chain[*depth as usize]], 1, 1).unwrap();
        deep.push(t.elapsed());
    }
    println!("deep side-block insertion: {:?}", deep);

    // Siblings of genesis: each exhausts genesis' free interval -> root reindex.
    let mut worst = std::time::Duration::ZERO;
    let mut total = std::time::Duration::ZERO;
    for j in 0..80u64 {
        let t = Instant::now();
        dag.add_block(hx(4, j), vec![g], 1, 1).unwrap();
        let e = t.elapsed();
        total += e;
        worst = worst.max(e);
    }
    println!("80 genesis siblings: total {:.2?}, worst single block {:.2?}", total, worst);

    // Merge block whose mergeset is a 1,000-block side chain forked at genesis.
    let mut sc = g;
    for j in 0..1_000u64 {
        let h = hx(5, j);
        dag.add_block(h, vec![sc], 1, 1).unwrap();
        sc = h;
    }
    let t = Instant::now();
    let d = dag.add_block(hx(6, 0), vec![chain[n as usize], sc], n + 1, 1).unwrap();
    let merge_cost = t.elapsed();
    println!("merge block: mergeset {} (blues {}, reds {}) coloured in {:.2?}",
        d.mergeset_blues.len() + d.mergeset_reds.len(), d.mergeset_blues.len(),
        d.mergeset_reds.len(), merge_cost);

    assert!(ext_big > ext_small, "per-block cost grows with DAG size");
    assert!(deep.iter().max().unwrap() > &(ext_big * 5), "deep insertion is far costlier than a tip extension");
    assert!(merge_cost > ext_big * 5, "large-mergeset block is far costlier than a tip extension");
    assert!(d.mergeset_reds.len() + d.mergeset_blues.len() == 1_000, "no mergeset size limit");
}

// ─────────────────────────────────────────────────────────────────────────────
// DAG-8 (Low): GhostdagData.height = selected_parent.height + 1
// (consensus/mod.rs:1041) while accept_block requires header height =
// max(parent heights)+1 (main.rs:2012). When the selected parent is not the
// highest parent the two diverge; children are then required to declare a
// height LOWER than their parent's header height.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn dag8_dag_height_differs_from_header_height_rule() {
    let g = hx(0xEE, 0);
    let mut dag = GhostDAG::with_default_k();
    dag.add_genesis(g, 0);
    let heavy = hx(1, 1);
    dag.add_block(heavy, vec![g], 1, 1_000_000).unwrap(); // height 1, heavy
    let mut light = g;
    for i in 1..=5u64 {
        let h = hx(2, i);
        dag.add_block(h, vec![light], i, 1).unwrap(); // height 5, light
        light = h;
    }
    let b = hx(3, 1);
    let d = dag.add_block(b, vec![heavy, light], 10, 1).unwrap();
    // accept_block's rule (main.rs:2012) would require header height 6.
    let header_rule = [heavy, light].iter().map(|p| dag.get_block_data(p).unwrap().height).max().unwrap() + 1;
    println!("header height required = {header_rule}; GhostdagData.height = {}", d.height);
    assert_eq!(header_rule, 6);
    assert_eq!(d.height, 2);
}

// ─────────────────────────────────────────────────────────────────────────────
// DAG-9 (High, liveness): accept_block removes from the mempool only the txids
// of the accepted block (main.rs:2240-2241, 2310-2311); conflicting mempool
// txs are never evicted and nothing re-validates the template. The stale tx is
// put in every template (main.rs:1618), the node's own accept_block rejects
// the block (main.rs:1717-1732 `continue`), and the miner spins forever.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn dag9_conflicting_mempool_tx_is_never_evicted_and_poisons_templates() {
    let g = hx(0xEE, 0);
    let u_txid = [0x77u8; 32];
    let mut n = node(g, Some((u_txid, 0, TxOutput { value: 90_000_000, script_pubkey: vec![0x11; 20] })));

    // Victim mempool holds T1 (spends U) with a high fee.
    let t1 = spend(u_txid, 0, 10_000);
    n.mempool.add(t1.clone(), 89_990_000).expect("T1 admitted to mempool");
    // A network block confirms a DIFFERENT tx T2 spending the same U.
    let t2 = spend(u_txid, 0, 20_000);
    let b1 = block(vec![g], 1, 1, vec![coinbase(1, 1), t2.clone()]);
    assert_eq!(mirror_accept(&mut n, &b1), Ok(Disp::Extension));
    n.mempool.remove_confirmed(&b1.transactions.iter().map(|t| t.txid()).collect::<Vec<_>>());

    // The next template still contains T1, whose input no longer exists.
    let txs = n.mempool.get_for_block(2000);
    assert!(txs.iter().any(|t| t.txid() == t1.txid()), "stale conflicting tx still in mempool");
    let mut all = vec![coinbase(2, 9)];
    all.extend(txs);
    let tmpl = block(vec![b1.block_hash()], 2, 7, all);
    let err = mirror_accept(&mut n, &tmpl).unwrap_err();
    println!("own template rejected: {err}");
    assert!(err.contains("not found"));
    // Repeat: nothing changed, the next round fails identically.
    assert!(n.mempool.get_for_block(2000).iter().any(|t| t.txid() == t1.txid()));
    println!("DAG-9 CONFIRMED: miner template permanently poisoned");
}
