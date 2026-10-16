//! The node's GhostDAG against `reference/ghostdag_vectors.json`, generated
//! by the Python reference `reference/gnb_ghostdag.py`
//! (`reference/gen_ghostdag_vectors.py`; docs/CONSENSUS.md, "Coloring").
//!
//! Audit B2-T9: the candidate order of the coloring is part of consensus (the
//! coloring is greedy). The case `order/fifo-not-lowest-id` is a DAG whose
//! blue set differs between GnB's FIFO Kahn order and the other reading of
//! the old wording ("lower hash first" among ready blocks); the node must
//! produce the FIFO result, and the vector records the other reading's
//! result so this test also proves the case discriminates. The case
//! `mergeset/size-limit` pins this chain's mergeset-size limit
//! (`MERGESET_SIZE_LIMIT`, 64 merged blocks at every height).

use gnb::consensus::{BlockHash, ConsensusError, GhostDAG};
use serde_json::Value;

const VECTORS: &str = include_str!("../../reference/ghostdag_vectors.json");

fn id(v: &Value) -> BlockHash {
    let b = hex::decode(v.as_str().expect("hex id")).expect("hex");
    <[u8; 32]>::try_from(b.as_slice()).expect("32-byte id")
}

fn ids(v: &Value) -> Vec<BlockHash> {
    v.as_array().expect("id list").iter().map(id).collect()
}

fn num<T: std::str::FromStr>(v: &Value) -> T
where
    T::Err: std::fmt::Debug,
{
    v.as_str().expect("decimal string").parse().expect("number")
}

/// A block the vectors expect the rules to refuse (`expected.error`).
fn refused(b: &Value) -> Option<&str> {
    b["expected"].get("error").and_then(Value::as_str)
}

/// Build one case with the node's GhostDAG; returns the DAG. A block the
/// vectors expect to be refused must be refused, with the expected error and
/// without inserting anything.
fn build(case: &Value) -> GhostDAG {
    let k: usize = case["k"].as_u64().unwrap() as usize;
    let act: u64 = num(&case["activation_height"]);
    let mut dag = GhostDAG::with_k_and_activation(k, act);
    dag.add_genesis(id(&case["genesis"]), 0);
    for (i, b) in case["blocks"].as_array().unwrap().iter().enumerate() {
        let res = dag.add_block(id(&b["id"]), ids(&b["parents"]), i as u64 + 1, num(&b["work"]));
        match refused(b) {
            None => {
                res.unwrap_or_else(|e| panic!("[{}] add_block {}: {e}", case["id"], b["id"]));
            }
            Some("mergeset-too-large") => {
                let count = dag.block_count();
                assert!(matches!(res, Err(ConsensusError::MergesetTooLarge { .. })),
                    "[{}] block {} must be refused: {:?}", case["id"], b["id"], res.map(|d| d.height));
                assert_eq!(dag.block_count(), count, "[{}] nothing inserted", case["id"]);
                assert!(dag.get_block_data(&id(&b["id"])).is_none());
            }
            Some(other) => panic!("[{}] unknown expected error {other}", case["id"]),
        }
    }
    dag
}

#[test]
fn node_ghostdag_matches_the_reference_vectors() {
    let doc: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(doc["format"], "gnb-ghostdag-vectors/1");
    assert_eq!(doc["constants"]["k"].as_u64(), Some(gnb::core::GHOSTDAG_K as u64));
    // The limit the node applies at every height: this chain's
    // MERGESET_SIZE_LIMIT, tighter than the audit's MAX_MERGESET_SIZE - 1.
    assert_eq!(
        doc["constants"]["mergeset_size_limit"].as_u64(),
        Some(gnb::consensus::MERGESET_SIZE_LIMIT.min(gnb::consensus::MAX_MERGESET_SIZE - 1) as u64)
    );
    let cases = doc["cases"].as_array().unwrap();
    assert!(cases.len() >= 4);
    let mut blocks = 0;
    let mut refusals = 0;
    for case in cases {
        let cid = case["id"].as_str().unwrap();
        let dag = build(case);
        for b in case["blocks"].as_array().unwrap() {
            if refused(b).is_some() {
                refusals += 1; // checked by `build`
                continue;
            }
            let h = id(&b["id"]);
            let e = &b["expected"];
            let d = dag.get_block_data(&h).unwrap();
            let what = format!("[{cid}] block {}", &b["id"].as_str().unwrap()[..4]);
            assert_eq!(d.selected_parent, Some(id(&e["selected_parent"])), "{what}: selected parent");
            assert_eq!(d.height, num::<u64>(&e["dag_height"]), "{what}: DAG height");
            // The header height accept_block requires: 1 + the largest DAG
            // height over EVERY listed parent (duplicates and redundant
            // ancestors included).
            let header = d.parents.iter().map(|p| dag.get_block_data(p).unwrap().height).max().unwrap() + 1;
            assert_eq!(header, num::<u64>(&e["header_height"]), "{what}: header height");
            assert_eq!(d.mergeset_blues, ids(&e["mergeset_blues"]), "{what}: mergeset blues (in order)");
            assert_eq!(d.mergeset_reds, ids(&e["mergeset_reds"]), "{what}: mergeset reds (in order)");
            // The coloring order is the mergeset order: blues and reds are
            // each a subsequence of it.
            let order = ids(&e["mergeset_order"]);
            let mut merged = d.mergeset_blues.clone();
            merged.extend(d.mergeset_reds.iter().copied());
            merged.sort_by_key(|x| order.iter().position(|o| o == x).expect("colored block is in the order"));
            assert_eq!(merged, order, "{what}: blues and reds partition the ordered mergeset");
            assert_eq!(d.blue_score, num::<u64>(&e["blue_score"]), "{what}: blue score");
            assert_eq!(d.blue_work, num::<u128>(&e["blue_work"]), "{what}: blue work");
            // Audit B2-T10: the header rule from the activation.
            let dup = e["duplicate_parents"].as_bool().unwrap();
            assert_eq!(
                gnb::core::block_rules::check_parents_distinct(&d.parents).is_err(), dup,
                "{what}: repeated-parent verdict"
            );
            blocks += 1;
        }
        if let Some(alt) = case.get("alternative_reading") {
            let h = id(&alt["block"]);
            let d = dag.get_block_data(&h).unwrap();
            let alt_blues = ids(&alt["mergeset_blues"]);
            let mut a = alt_blues.clone();
            let mut n = d.mergeset_blues.clone();
            a.sort_unstable();
            n.sort_unstable();
            assert_ne!(a, n, "[{cid}] the other reading must give another blue set");
            assert_ne!(d.blue_work, num::<u128>(&alt["blue_work"]), "[{cid}] and another blue work");
        }
    }
    assert!(blocks >= 25, "{blocks} blocks checked");
    assert!(refusals >= 1, "the mergeset-size limit is exercised");
}
