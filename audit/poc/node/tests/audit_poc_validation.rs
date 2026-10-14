//! AUDIT PoC (validation / UTXO / storage reviewer) — NOT part of the product.
//!
//! `accept_block` and the tx-validation core live in the node BINARY
//! (src/main.rs), which integration tests cannot link. This file therefore
//! carries a VERBATIM copy of those functions (between the BEGIN/END VERBATIM
//! markers below) compiled against the node LIBRARY's modules (`gnb::…`), and
//! `copied_consensus_code_is_verbatim_from_main_rs` proves at test time that
//! every copied line appears, in order, in src/main.rs.
//!
//! Run: cargo test --release --locked -p gnb --test audit_poc_validation
#![allow(dead_code, unused_imports, unused_variables, clippy::all)]

use std::collections::HashSet;
use std::sync::Arc;
use parking_lot::RwLock;
use tokio::sync::broadcast;
use log::{info, warn, error, debug};
use gnb::{core, crypto, consensus, storage, mempool, rpc, tip, pow, reorg, coherence};

// BEGIN VERBATIM main.rs
static FINALITY_FROZEN: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

static ARCHIVE_MODE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Validate TX contents, add block to DAG + storage, update UTXO set.
/// Returns Ok(block_hash) on success.
fn accept_block(
    block:      &core::Block,
    block_hash: [u8; 32],
    height:     u64,
    dag:        &Arc<RwLock<consensus::GhostDAG>>,
    store:      &Arc<storage::Storage>,
    mempool:    &Arc<mempool::Mempool>,
    node_state: &Arc<RwLock<rpc::NodeState>>,
    // Sprint 2.c: tip-change broadcast for stratum re-notify.
    // None disables notification (tests, CLI without --stratum).
    tip_tx:     Option<&broadcast::Sender<tip::TipChanged>>,
    // Coherence C2: the node's shielded-pool engine. Block's shielded txs are
    // validated + applied here before the block is committed.
    shielded:   &Arc<RwLock<crate::coherence::ShieldedPool>>,
) -> Result<[u8; 32], String> {

    // Sprint 2.c: snapshot selected tip BEFORE any DAG mutation so we
    // can detect whether this block changed the chain's head. Nested
    // {} scope ensures the lock drops immediately.
    let old_tip = { dag.read().selected_tip() };

    // ── Early dedup ──────────────────────────────────────────────────
    // A block already in the DAG needs no re-validation. Return the same
    // "already in DAG" rejection `add_block` produces, but BEFORE tx
    // validation — so a re-gossip / IBD re-request flood of known blocks
    // stays cheap now that the finality gate below no longer rejects (and
    // thereby short-circuits) below-finality blocks.
    if dag.read().get_block_data(&block_hash).is_some() {
        return Err(format!(
            "consensus rejection: block already in DAG: {}",
            hex::encode(block_hash)
        ));
    }

    // ── Parents must be known (cheap, before anything else) ──────────
    // Height, timestamp and difficulty below are all derived from the
    // parents' DAG entries; an unknown parent would silently skew them.
    if block.header.parents.is_empty() {
        return Err("consensus rejection: non-genesis block without parents".into());
    }
    let parent_data: Vec<(u64, u64)> = {
        let d = dag.read();
        let mut v = Vec::with_capacity(block.header.parents.len());
        for p in &block.header.parents {
            match d.get_block_data(p) {
                Some(data) => v.push((data.height, data.timestamp)),
                None => return Err(format!(
                    "consensus rejection: unknown parent {}", hex::encode(p))),
            }
        }
        v
    };

    // ── FIX VULN-02: height = max parent height + 1 ──────────────────
    let expected_height = parent_data.iter().map(|(h, _)| *h).max().unwrap_or(0) + 1;
    if block.height != expected_height || height != expected_height {
        return Err(format!(
            "invalid height: block claims h={} but expected h={}",
            block.height, expected_height
        ));
    }

    // ── FIX VULN-01: difficulty bits must equal the ASERT schedule ───
    // A pure function of the parent set (latest parent timestamp) and the
    // height, shared with the miner and getblocktemplate. Checked for every
    // block, before the proof of work.
    let parent_ts = core::difficulty_parent_timestamp(parent_data.iter().map(|(_, t)| *t));
    let expected_bits = pow::expected_bits(parent_ts, block.height)
        .map_err(|e| format!("invalid difficulty: {}", e))?;
    if block.header.bits != expected_bits {
        return Err(format!(
            "invalid difficulty: block bits 0x{:08x} != expected 0x{:08x}",
            block.header.bits, expected_bits
        ));
    }

    let finalized_height = store.get_meta("finalized_height").ok().flatten()
        .and_then(|b| b.as_slice().try_into().ok().map(u64::from_le_bytes))
        .unwrap_or(0);

    // ── FIX VULN-04: Validate timestamp ──────────────────────────────
    {
        let parent_ts = block.header.parents.iter()
            .filter_map(|p| dag.read().get_block_data(p).map(|d| d.timestamp))
            .max()
            .unwrap_or(0);
        block.validate_timestamp(parent_ts)
            .map_err(|e| format!("timestamp rejected: {}", e))?;
    }

    // ── Proof of work (expensive: 64 MiB GnB-SMH, cached by block id) ─
    // Runs only after every cheap contextual check above has passed.
    if !block.validate_pow() {
        return Err("consensus rejection: invalid GnB-SMH proof of work".into());
    }

    // ── Validate non-coinbase TXs + compute fees ─────────────────────
    // Coinbase maturity uses the block's consensus-checked height, identical
    // on every honest node.
    let current_height = block.height;
    let mut spent_in_block: HashSet<([u8; 32], u32)> = HashSet::new();
    let mut total_fees: u64 = 0;

    for tx in block.transactions.iter().skip(1) {
        let fee = validate_tx_in_block_with_maturity(
            block, tx, store, &mut spent_in_block, current_height
        )?;
        total_fees = total_fees.checked_add(fee).ok_or("block fee sum overflow")?;
    }

    // ── FIX VULN-05: Validate coinbase value includes fees ───────────
    block.validate_coinbase_value(total_fees)
        .map_err(|e| format!("coinbase rejected: {}", e))?;

    // ── Add to DAG ───────────────────────────────────────────────────
    //
    // Sprint U.4 — capture the selected tip BEFORE add_block so we can
    // classify what this block did to the selected chain once GhostDAG
    // recomputes after insertion.
    let old_selected_tip = dag.read().selected_tip();

    let ts      = block.header.timestamp;
    let parents = block.header.parents.clone();
    let work    = pow::work_from_bits(block.header.bits);
    // M-9: propagate consensus rejection upward instead of panicking.
    // NoParents / DuplicateBlock here mean the caller (the sync path or
    // gossipsub) handed us a structurally-broken block; we reject with
    // a string error just like the other validation steps above.
    // Coherence C2/P1: validate + apply this block's shielded transactions
    // before committing, using the pool's configured ShieldedVerifier — RejectAll
    // by default (safe: no unverifiable value admitted), or the SP1/FRI verifier
    // with `GNB_SHIELDED_VERIFY=sp1` (feature `sp1-verify`). Transparent blocks
    // (no shielded txs) are a no-op. NOTE: the shielded state does not yet track
    // reorgs; that lands with the live SP1 verifier. Merkle-binding already
    // commits the shielded txs into the PoW, so they are non-malleable.
    shielded.write().apply_block_self(block_hash, &block.shielded_transactions)
        .map_err(|e| format!("shielded consensus rejection: {:?}", e))?;

    dag.write().add_block(block_hash, parents, ts, work)
        .map_err(|e| format!("consensus rejection: {}", e))?;

    // CONSENSUS-HALT FIX (DAG-vs-UTXO ordering): the CF_DAG /
    // CF_DAG_INTEGRITY persist that used to happen right here is DEFERRED
    // until after the disposition match below succeeds. `add_block` above is
    // still needed first (GhostDAG selection is the single source of truth
    // for classifying this block), but if the disposition is REFUSED — e.g.
    // `execute_reorg` rejects an over-deep fork flip — the in-memory
    // insertion is rolled back via `GhostDAG::remove_block` and nothing was
    // persisted, so DAG store, CF_DAG and the applied UTXO state move
    // together or not at all. Previously the insertion was persisted
    // unconditionally: a refused deep reorg left `selected_tip()` pinned to
    // the attacker fork forever (every legitimate extension misclassified as
    // ForkLoser) — a durable consensus halt.

    // Persist block body — even if this block ends up in a losing fork, we
    // keep its bytes so a future reorg can apply it without re-downloading.
    // This must happen BEFORE the disposition match: `execute_reorg` reads
    // the bodies of `to_apply` blocks (including this one) from CF_BLOCKS.
    // Block bodies are not consensus state — selected-tip / blue-work
    // decisions are driven solely by CF_DAG, which is only written after
    // success — so a body left behind by a rejected block is inert.
    // On a body-persist failure, roll the in-memory insertion back.
    if let Err(e) = store.put_block(block) {
        dag.write().remove_block(&block_hash);
        return Err(e.to_string());
    }

    // Informational only (RPC / tip notifications): the bits of the most
    // recently accepted block. Consensus never reads this; expected bits are
    // derived from each block's parents (pow::expected_bits).
    let _ = store.put_meta("current_bits", &block.header.bits.to_le_bytes());

    // ── Sprint U.4: disposition-based state application (closes C-1) ──
    //
    // Classify how this block affected the selected chain, then apply
    // UTXO mutations only when appropriate:
    //
    //   * FORK-LOSER   — the selected tip didn't move to this block.
    //                    Persist block + DAG data only; do NOT touch
    //                    UTXO set or mempool. The block lives in the DAG
    //                    and may win later (triggering a reorg).
    //
    //   * EXTENSION    — this block IS the new selected tip, and its
    //                    selected_parent is exactly the old tip. Apply
    //                    forward just like the pre-U.4 path.
    //
    //   * REORG        — this block IS the new selected tip, but its
    //                    selected_parent is NOT the old tip. The fork
    //                    that contains this block has outgrown the old
    //                    chain. Roll back old chain blocks to the LCA,
    //                    apply new chain blocks from LCA to this block,
    //                    reinject still-valid mempool txs.
    //
    // The match is exhaustive over the (old, new) tuple; unexpected
    // transitions (e.g. add_block produced no tip) log a warning and
    // leave state untouched so we don't corrupt anything.
    let new_selected_tip = dag.read().selected_tip();

    enum Disposition {
        Extension,
        ForkLoser,
        Reorg,
        Unexpected,
    }

    let disposition = match (old_selected_tip, new_selected_tip) {
        (None, Some(t)) if t == block_hash => {
            // Post-genesis first block — no prior tip. Treat as extension.
            Disposition::Extension
        }
        (Some(old), Some(new)) if new == old => Disposition::ForkLoser,
        (Some(old), Some(new)) if new == block_hash => {
            let selected_parent = dag.read()
                .get_block_data(&block_hash)
                .and_then(|d| d.selected_parent);
            if selected_parent == Some(old) {
                Disposition::Extension
            } else {
                Disposition::Reorg
            }
        }
        _ => Disposition::Unexpected,
    };

    // ── Finality invariant: below-finality blocks stay inert ─────────
    // A block at or below the finalized height is welcome in the DAG as a
    // fork-loser (its body was retained above), but it must NEVER become the
    // selected tip — that would rewrite finalized history. In practice an
    // Extension cannot reach here below finality (it extends a tip already
    // above it), and a Reorg flipping the tip below finality is over-deep and
    // also refused by MAX_REORG_DEPTH; this guard makes the invariant explicit
    // and independent of that constant. Roll the in-memory insertion back the
    // same way the refused-reorg path does (nothing is persisted to CF_DAG
    // yet; the body left in CF_BLOCKS is inert).
    if block.height <= finalized_height
        && matches!(disposition, Disposition::Extension | Disposition::Reorg)
    {
        dag.write().remove_block(&block_hash);
        return Err(format!(
            "finality: block h={} may not become the selected tip at or below finalized height {}",
            block.height, finalized_height
        ));
    }

    match disposition {
        Disposition::ForkLoser => {
            info!(
                "block h={} {} accepted into fork (not selected tip)",
                block.height, hex::encode(&block_hash[..8])
            );
            // Intentional no-op on UTXO / mempool / tip_hash. The block is
            // now reachable via CF_BLOCKS + DAG; a future reorg can bring
            // it into the selected chain.
        }

        Disposition::Extension => {
            // Apply this block's mutations forward. Uses the shared helper
            // (src/reorg.rs) so extension and reorg re-apply go through
            // identical code — they must produce byte-identical UndoData.
            // Legacy L-1: `apply_block_utxo_mutations` now propagates every
            // write error instead of silently discarding it (previously
            // only `put_undo_data` failures were even visible here). This
            // call site does NOT yet roll back or abort on failure — doing
            // so safely requires the atomic single-WriteBatch commit and
            // startup reconciliation check tracked as Legacy M-7 (not yet
            // implemented: mid-block failure here can already leave the
            // UTXO set, block body, and tip in different states, and
            // returning early now — without a rollback path — would not
            // fix that, only change WHICH state is inconsistent). Until
            // M-7 lands, a failure here is a fleet-visible, actionable
            // signal (error!, not warn!) that this node's UTXO set may have
            // diverged and needs `--verify-carryover`-style reconciliation.
            if let Err(e) = reorg::apply_block_utxo_mutations(store, block) {
                error!(
                    "U.4/L-1: apply_block_utxo_mutations FAILED for h={}: {} — this node's \
                     UTXO set may now be inconsistent with its block/DAG state (Legacy M-7: \
                     atomic commit + startup reconciliation not yet implemented). Investigate \
                     storage health immediately.",
                    block.height, e
                );
            }

            let confirmed: Vec<[u8; 32]> = block.transactions.iter().map(|t| t.txid()).collect();
            mempool.remove_confirmed(&confirmed);
            store.put_meta("tip_hash", &block_hash).ok();
        }

        Disposition::Reorg => {
            // new_selected_tip must be Some here (we matched on it).
            let new_tip = new_selected_tip.expect("reorg disposition implies Some(new_tip)");
            let old_tip = old_selected_tip.expect("reorg disposition implies Some(old_tip)");

            let plan = {
                let d = dag.read();
                reorg::compute_reorg_plan(&d, &old_tip, &new_tip)
            };
            let plan = match plan {
                Some(p) => p,
                None => {
                    // CONSENSUS-HALT FIX: roll the in-memory DAG insertion
                    // back before rejecting — nothing has been persisted to
                    // CF_DAG yet, so DAG and applied UTXO state stay in sync.
                    dag.write().remove_block(&block_hash);
                    return Err(format!(
                        "U.4: tip changed to {} via reorg but compute_reorg_plan returned None (old={}, new={})",
                        hex::encode(&new_tip[..8]),
                        hex::encode(&old_tip[..8]),
                        hex::encode(&new_tip[..8]),
                    ));
                }
            };

            info!(
                "🔀 Reorg at h={}: rollback {} blocks, apply {} blocks (lca={})",
                block.height,
                plan.to_rollback.len(),
                plan.to_apply.len(),
                hex::encode(&plan.lca[..8]),
            );

            let outcome = match reorg::execute_reorg(store, mempool, &plan) {
                Ok(o) => o,
                Err(e) => {
                    // CONSENSUS-HALT FIX: a refused reorg (e.g. deeper than
                    // reorg::MAX_REORG_DEPTH) or a failed one left the UTXO
                    // store untouched by design. The in-memory DAG insertion
                    // must be undone as well — otherwise selected_tip()
                    // permanently adopts a fork whose state was never
                    // applied, and every legitimate extension of the real
                    // chain is misclassified as ForkLoser: a durable halt.
                    // Nothing was persisted to CF_DAG (deferred until after
                    // this match), so the undo is purely in-memory.
                    if !dag.write().remove_block(&block_hash) {
                        warn!(
                            "U.4: failed to roll back DAG insertion of {} after refused reorg \
                             (block gained children concurrently?) — tip may be inconsistent",
                            hex::encode(&block_hash[..8]),
                        );
                    }
                    return Err(format!("U.4: execute_reorg failed: {}", e));
                }
            };

            info!(
                "   reorg done: rolled_back={}, applied={}, txs_reinjected={}, txs_discarded={}",
                outcome.rolled_back, outcome.applied,
                outcome.txs_reinjected, outcome.txs_discarded,
            );

            // execute_reorg already applied all to_apply blocks (including
            // the one we just accepted). Now remove those txs from mempool
            // in case any had slipped in between rollback and apply.
            let confirmed: Vec<[u8; 32]> = block.transactions.iter().map(|t| t.txid()).collect();
            mempool.remove_confirmed(&confirmed);
            store.put_meta("tip_hash", &new_tip).ok();
        }

        Disposition::Unexpected => {
            warn!(
                "U.4: unexpected selected-tip transition during accept of block h={} \
                 (old={:?}, new={:?}, block={})",
                block.height, old_selected_tip, new_selected_tip, hex::encode(&block_hash[..8])
            );
            // Refuse to mutate state on an unexpected transition.
            // CONSENSUS-HALT FIX: previously the block stayed in the DAG
            // (and was persisted) while UTXO state was left untouched — the
            // same DAG-vs-UTXO divergence as the refused-reorg case. Roll
            // the in-memory insertion back and reject, so a re-submission
            // can be classified cleanly later.
            dag.write().remove_block(&block_hash);
            return Err(format!(
                "U.4: unexpected selected-tip transition (old={:?}, new={:?}); block {} rejected",
                old_selected_tip, new_selected_tip, hex::encode(&block_hash[..8]),
            ));
        }
    }

    // CONSENSUS-HALT FIX: the DAG entry is persisted only NOW, after the
    // disposition above has been applied successfully. Every refusal path
    // above rolled the in-memory insertion back and returned Err, so CF_DAG
    // can never adopt a fork tip whose chain state was refused.
    // NOTE: bind the cloned data in its own `let` so the `dag.read()` guard is
    // released at the `;` — parking_lot's RwLock is NOT reentrant, so keeping a
    // read guard alive across `dag.write()` below deadlocks (write parks waiting
    // for the reader that this same thread holds). Harmless while Legacy left the
    // index untouched; a hard hang once the reachability gate arms `dag.write()`.
    let ddata_opt = dag.read().get_block_data(&block_hash).cloned();
    if let Some(ddata) = ddata_opt {
        // Sprint Y (M-2): atomic put to CF_DAG + CF_DAG_INTEGRITY.
        // Phase 1: when the reachability index is maintained, fold its delta
        // (which may span several blocks if this insert triggered a reindex)
        // into the SAME WriteBatch, so a crash here leaves CF_DAG and
        // CF_REACHABILITY consistent all-or-nothing. Live Legacy: unchanged.
        if dag.read().maintains_reachability_index() {
            let (upserts, removals) = dag.write().reach_take_delta();
            store.put_dag_with_integrity_and_reach(&block_hash, &ddata, &upserts, &removals).ok();
        } else {
            store.put_dag_with_integrity(&block_hash, &ddata).ok();
        }
    }

    // ── Update node state ────────────────────────────────────────────
    {
        let mut s = node_state.write();
        s.tip_blue_score = dag.read().tip_blue_score();
        s.block_count    = dag.read().block_count() as u64;
        s.mempool_size   = mempool.size();
    }
    info!("✓ block h={} accepted", height);

    // ── Update finality checkpoint ───────────────────────────────────
    // Once tip is CHECKPOINT_DEPTH ahead, finalize everything below.
    // NOTE: this MUST be the selected tip's *height*, not tip_blue_score().
    // finalized_height is compared against block.height at the finality gate
    // above; feeding it blue_score (which runs ahead of height by the DAG
    // width) makes the node "finalize" a height above its own tip once the
    // skew exceeds CHECKPOINT_DEPTH, permanently rejecting every
    // chain-extending block. Same height unit feeds the pruning block below.
    let tip_height = {
        let d = dag.read();
        d.selected_tip()
            .and_then(|h| d.get_block_data(&h).map(|data| data.height))
            .unwrap_or(0)
    };
    // [no-fork] Do not advance finality while mining through a stalled latch —
    // freezing finalized_height keeps a heavier chain able to reorg us back.
    if tip_height > core::CHECKPOINT_DEPTH
        && !FINALITY_FROZEN.load(std::sync::atomic::Ordering::Relaxed)
    {
        let new_finalized = tip_height - core::CHECKPOINT_DEPTH;
        let current_finalized = store.get_meta("finalized_height").ok().flatten()
            .and_then(|b| b.as_slice().try_into().ok().map(u64::from_le_bytes))
            .unwrap_or(0);
        if new_finalized > current_finalized {
            store.put_meta("finalized_height", &new_finalized.to_le_bytes()).ok();
        }
    }

    // ── Prune old block bodies ───────────────────────────────────────
    // Remove full block data beyond PRUNING_DEPTH (keeps height→hash, DAG, TX index)
    if ARCHIVE_MODE.load(std::sync::atomic::Ordering::Relaxed) {
        // Archival node: keep everything. Logged once per prune window so an
        // operator can see the choice is in effect rather than inferring it.
        if tip_height % 10_000 == 0 {
            info!("archival mode: retaining ALL block bodies (h={}); pruning disabled", tip_height);
        }
    } else if tip_height > core::PRUNING_DEPTH {
        let prune_below = tip_height - core::PRUNING_DEPTH;
        let last_pruned = store.pruned_height();
        if prune_below > last_pruned + 1000 { // batch: prune every 1000 blocks
            match store.prune_blocks_below(prune_below) {
                Ok(n) if n > 0 => info!("Pruned {} block bodies below h={}", n, prune_below),
                Err(e)         => warn!("Prune failed: {}", e),
                _ => {}
            }
        }
    }

    // ── Sprint 2.c: emit TipChanged if the selected tip moved ────────
    //
    // This hook runs regardless of how the block got here (network
    // gossipsub, stratum submit, orphan resurrection, miner loop —
    // miner loop has its own inline hook because it doesn't route
    // through this function). If `tip_tx` is None (no subscriber or
    // unit test) the work is skipped entirely.
    //
    // Semantics of TipChanged fields: describe the CURRENT tip
    // (post-accept). Stratum consumers use this + dag.tips() +
    // current_bits to build a fresh template for the NEXT block.
    if let Some(tip_tx) = tip_tx {
        // Bodied tip only: a header-only tip is unmineable, so stratum must
        // be notified on the best BODIED tip / parents, never a phantom.
        let has_body = |h: &[u8; 32]| store.get_block(h).ok().flatten().is_some();
        let new_tip = { dag.read().best_bodied_tip(has_body) };
        if new_tip != old_tip {
            if let Some(tip_hash) = new_tip {
                let d = dag.read();
                if let Some(data) = d.get_block_data(&tip_hash).cloned() {
                    let tips_parents: Vec<[u8; 32]> = d.bodied_tips(has_body);
                    drop(d);

                    let bits = store.get_meta("current_bits").ok().flatten()
                        .and_then(|b| b.as_slice().try_into().ok().map(u32::from_le_bytes))
                        .unwrap_or(0x1d00ffff_u32);

                    // send() returns Err(SendError) iff there are 0
                    // receivers — we intentionally ignore that case
                    // since stratum might not be running.
                    let _ = tip_tx.send(tip::TipChanged {
                        hash:       tip_hash,
                        height:     data.height,
                        blue_score: data.blue_score,
                        parents:    tips_parents,
                        bits,
                    });
                }
            }
        }
    }

    Ok(block_hash)
}

// ── Unified TX validation ────────────────────────────────────────────────────
// FIX #10: Single validation core used by all code paths.

/// Core input validation logic shared by all TX validation paths.
/// Resolves each input's UTXO, checks pubkey hash match, verifies ML-DSA-65
/// signature, and accumulates total input value.
fn validate_tx_inputs(
    tx:           &core::Transaction,
    utxo_lookup:  &dyn Fn(&[u8; 32], u32) -> Result<Option<core::TxOutput>, String>,
    mut spent_set: Option<&mut HashSet<([u8; 32], u32)>>,
) -> Result<u64, String> {
    let mut total_in = 0u64;

    // C-R3-2: the intra-tx duplicate-outpoint check is UNCONDITIONAL. The
    // standalone (gossip-relay) path passes `spent_set = None`, and the old
    // Some-gated check let a tx list the SAME outpoint N times — its value
    // was counted N times below, so a doubled-fee double-spend was admitted
    // to the mempool. `local_spent` catches duplicates within THIS tx on
    // every path; the caller's `spent_set` (when provided) still tracks
    // cross-tx conflicts inside a block.
    let mut local_spent: HashSet<([u8; 32], u32)> = HashSet::new();

    for (i, inp) in tx.inputs.iter().enumerate() {
        let outpoint = (inp.prev_txid, inp.prev_index);

        // FIX #9 + C-R3-2: double-spend within the same validation context —
        // cross-tx via the caller's set (when present), intra-tx ALWAYS via
        // the local insert-as-check.
        let cross_tx_dup = spent_set.as_ref().is_some_and(|s| s.contains(&outpoint));
        if cross_tx_dup || !local_spent.insert(outpoint) {
            return Err(format!("double-spend: {}:{} already consumed",
                hex::encode(&inp.prev_txid[..8]), inp.prev_index));
        }

        // Resolve UTXO
        let utxo = utxo_lookup(&inp.prev_txid, inp.prev_index)?
            .ok_or_else(|| format!("UTXO {}:{} not found",
                hex::encode(&inp.prev_txid[..8]), inp.prev_index))?;

        total_in = total_in.checked_add(utxo.value).ok_or("input overflow")?;

        // Parse and verify script_sig
        let (sig, pk) = core::Transaction::parse_script_sig(&inp.script_sig)
            .ok_or_else(|| format!("malformed script_sig at input {}", i))?;

        // Verify pubkey hash matches UTXO script_pubkey
        let pk_hash = {
            use sha3::{Sha3_256, Digest};
            Sha3_256::digest(&pk)[..20].to_vec()
        };
        if pk_hash != utxo.script_pubkey {
            return Err(format!("pubkey mismatch at input {}", i));
        }

        // Verify hybrid ML-DSA-65 ‖ Falcon-1024 signature. Chain-id (Roadmap #8)
        // is the node-level single source of truth — miner and validator share it
        // (see core::node_chain_id / set_node_chain_id).
        let sighash = tx.sighash(i, core::node_chain_id());
        if !crypto::verify(&pk, &sighash, &sig) {
            return Err(format!("invalid signature at input {}", i));
        }

        // Mark outpoint as spent
        if let Some(spent) = spent_set.as_mut() {
            spent.insert(outpoint);
        }
    }

    let total_out: u64 = tx.outputs.iter()
        .try_fold(0u64, |acc, o| acc.checked_add(o.value))
        .ok_or("output sum overflow")?;
    if total_in < total_out {
        return Err(format!("inputs {} < outputs {}", total_in, total_out));
    }
    let fee = total_in - total_out;
    core::check_min_fee(tx, fee)?;
    Ok(fee)
}

/// Compute the total fee the miner's OWN block template may claim across
/// `txs` (the candidate set selected from the mempool), reading prevout
/// values from the persistent UTXO set.
///
/// SECURITY (Legacy N-7): counts each of a transaction's outpoints ONCE —
/// insert-as-check, mirroring the C-R3-2 duplicate-outpoint rejection real
/// admission applies (`validate_tx_inputs`'s `local_spent`). This used to
/// `filter_map`+`sum` over `tx.inputs` unconditionally, so a transaction
/// listing the SAME outpoint N times had that outpoint's value summed N
/// times, inflating the fee the coinbase this template builds is allowed to
/// claim. Such a transaction is rejected outright by real consensus
/// validation (the identical insert-as-check, re-run when this self-mined
/// block is committed through the normal `accept_block` path) — it can never
/// legitimately contribute ANY fee, so this estimate must not act as if it
/// could either. Concretely: without this fix, a template that included such
/// a transaction would build a coinbase `validate_coinbase_value` then
/// rejects when the self-mined block is committed — wasting the mined block
/// (a liveness bug) rather than minting anything (accept_block's real,
/// non-inflating fee computation is still the actual consensus gate) — but
/// the template must not rely on that backstop to compute a correct number.
fn miner_template_total_fees(
    txs:   &[core::Transaction],
    store: &storage::Storage,
) -> u64 {
    txs.iter().map(|tx| {
        let mut seen_outpoints: HashSet<([u8; 32], u32)> = HashSet::new();
        let mut has_duplicate_outpoint = false;
        let mut total_in: u64 = 0;
        for inp in &tx.inputs {
            if !seen_outpoints.insert((inp.prev_txid, inp.prev_index)) {
                has_duplicate_outpoint = true;
                continue;
            }
            if let Ok(Some(out)) = store.get_utxo(&inp.prev_txid, inp.prev_index) {
                total_in = total_in.saturating_add(out.value);
            }
        }
        if has_duplicate_outpoint {
            return 0;
        }
        let total_out: u64 = tx.outputs.iter()
            .try_fold(0u64, |acc, o| acc.checked_add(o.value))
            .unwrap_or(u64::MAX); // overflow → caller (validate_coinbase_value) will reject
        total_in.saturating_sub(total_out)
    }).sum()
}

/// Validate a transaction within a block context.
/// Uses both in-block outputs and persistent UTXO set, with double-spend tracking.
fn validate_tx_in_block(
    block:          &core::Block,
    tx:             &core::Transaction,
    store:          &Arc<storage::Storage>,
    spent_in_block: &mut HashSet<([u8; 32], u32)>,
) -> Result<(), String> {
    validate_tx_in_block_with_maturity(block, tx, store, spent_in_block, 0)?;
    Ok(())
}

/// FIX VULN-03: Validate TX within a block, including coinbase maturity check.
/// Returns the fee (total_in - total_out) for coinbase value validation.
fn validate_tx_in_block_with_maturity(
    block:          &core::Block,
    tx:             &core::Transaction,
    store:          &Arc<storage::Storage>,
    spent_in_block: &mut HashSet<([u8; 32], u32)>,
    current_height: u64,
) -> Result<u64, String> {
    // SECURITY (Legacy C-2): build the in-block prevout map from ONLY the
    // transactions STRICTLY BEFORE `tx` in `block.transactions` — never from
    // the whole block. This used to `flat_map` over ALL of
    // `block.transactions` unconditionally, so a transaction could spend the
    // output of a LATER transaction in the same block: `tx[i]` validates
    // (and is fee-accounted, and its own outputs get created) as if it had
    // genuinely spent `tx[j]`'s (j > i) output, while the actual UTXO
    // application (`reorg::apply_block_utxo_mutations`) writes each
    // transaction's outputs THEN deletes its inputs, walking the block IN
    // ORDER — so `tx[j]`'s output is written to storage only AFTER `tx[i]`'s
    // (no-op, not-yet-existent-key) delete already ran, leaving it
    // permanently unspent. The value tx[i] was credited for spending is
    // never actually removed from the UTXO set: a supply-inflating mint,
    // out-of-order-block-only, requiring no signature forgery.
    //
    // A transaction MAY legitimately spend an EARLIER same-block
    // transaction's output (ordinary same-block chaining, e.g. a miner
    // including a child of a transaction it also included) — that is
    // exactly what the apply-order above expects and this preserves. It may
    // never spend its own or a later transaction's not-yet-created output.
    //
    // `tx` is identified by TXID (content hash) rather than by reference
    // identity so this is correct whether the caller passes a reference
    // borrowed from `block.transactions` (the real consensus path) or an
    // owned clone with identical content (as some call sites do); if `tx`'s
    // txid is not found in `block.transactions` at all (a misuse this
    // function's real callers never trigger), this falls back to the full
    // block — permissive only for that out-of-invariant case.
    let tx_txid = tx.txid();
    let cutoff = block.transactions.iter()
        .position(|t| t.txid() == tx_txid)
        .unwrap_or(block.transactions.len());
    let block_utxos: std::collections::HashMap<([u8; 32], u32), core::TxOutput> = block.transactions[..cutoff]
        .iter()
        .flat_map(|t| {
            let txid = t.txid();
            t.outputs.iter().enumerate().map(move |(i, o)| ((txid, i as u32), o.clone()))
        })
        .collect();

    // Coinbase maturity check (VULN-03). Single source of truth in
    // core::check_coinbase_maturity; this call site is one of two.
    core::check_coinbase_maturity(tx, current_height, |txid| {
        store.get_coinbase_height(txid).ok().flatten()
    })?;

    let lookup = |txid: &[u8; 32], idx: u32| -> Result<Option<core::TxOutput>, String> {
        if let Some(out) = block_utxos.get(&(*txid, idx)) {
            return Ok(Some(out.clone()));
        }
        store.get_utxo(txid, idx).map_err(|e| e.to_string())
    };

    validate_tx_inputs(tx, &lookup, Some(spent_in_block))
}


/// Standalone tx validation (for mempool / sendrawtransaction).
/// Returns the fee (total_in - total_out).
/// Also checks coinbase maturity (VULN-03).
fn validate_tx_standalone(
    tx:    &core::Transaction,
    store: &Arc<storage::Storage>,
    current_height: u64,
) -> Result<u64, String> {
    // Coinbase maturity check
    if current_height > 0 {
        for (i, inp) in tx.inputs.iter().enumerate() {
            if let Ok(Some(cb_height)) = store.get_coinbase_height(&inp.prev_txid) {
                let depth = current_height.saturating_sub(cb_height);
                if depth < core::COINBASE_MATURITY {
                    return Err(format!(
                        "coinbase maturity: input {} needs {} more confirmations",
                        i, core::COINBASE_MATURITY - depth
                    ));
                }
            }
        }
    }
    let lookup = |txid: &[u8; 32], idx: u32| -> Result<Option<core::TxOutput>, String> {
        store.get_utxo(txid, idx).map_err(|e| e.to_string())
    };

    validate_tx_inputs(tx, &lookup, None)
}
// END VERBATIM main.rs


// ═════════════════════════════════════════════════════════════════════════════
// PoC harness
// ═════════════════════════════════════════════════════════════════════════════
use gnb::core::{Block, BlockHeader, Transaction, TxInput, TxOutput};
use sha3::{Digest as _, Sha3_256};
use tempfile::TempDir;

struct Node {
    _tmp:       TempDir,
    dag:        Arc<RwLock<consensus::GhostDAG>>,
    store:      Arc<storage::Storage>,
    mempool:    Arc<mempool::Mempool>,
    node_state: Arc<RwLock<rpc::NodeState>>,
    shielded:   Arc<RwLock<coherence::ShieldedPool>>,
    tip_tx:     broadcast::Sender<tip::TipChanged>,
}

fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

fn keypair() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let (pk, sk) = crypto::generate_keypair();
    let h = Sha3_256::digest(&pk)[..20].to_vec();
    (pk, sk, h)
}

fn sign_input(tx: &mut Transaction, i: usize, sk: &[u8], pk: &[u8]) {
    let sighash = tx.sighash(i, core::node_chain_id());
    let sig = crypto::sign(sk, &sighash).expect("sign");
    tx.inputs[i].script_sig = Transaction::build_script_sig(&sig, pk);
}

fn coinbase(tag: &str, value: u64, spk: Vec<u8>) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput { prev_txid: [0u8; 32], prev_index: u32::MAX,
                               script_sig: tag.as_bytes().to_vec(), sequence: u32::MAX }],
        outputs: vec![TxOutput { value, script_pubkey: spk }],
        locktime: 0,
    }
}

fn spend(prev_txid: [u8; 32], prev_index: u32, out_value: u64, out_spk: Vec<u8>) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput { prev_txid, prev_index, script_sig: vec![], sequence: u32::MAX }],
        outputs: vec![TxOutput { value: out_value, script_pubkey: out_spk }],
        locktime: 0,
    }
}

/// Fixture genesis (same shape as main.rs's in-file tests).
fn mk_genesis(ts: u64) -> Block {
    Block {
        header: BlockHeader { version: 1, parents: vec![], merkle_root: core::MerkleRoot::ZERO,
                              timestamp: ts, bits: core::GENESIS_BITS, nonce: 0 },
        transactions: vec![coinbase("genesis", 0, vec![0u8; 20])],
        blue_score: 0, height: 0, shielded_transactions: Vec::new(),
    }
}

/// A node at genesis whose UTXO set holds `utxos` (models carryover outputs).
fn node_with(genesis: &Block, utxos: &[([u8; 32], u32, TxOutput)]) -> Node {
    let tmp = TempDir::new().unwrap();
    let store = Arc::new(storage::Storage::open(&tmp.path().join("db")).unwrap());
    let dag = Arc::new(RwLock::new(consensus::GhostDAG::with_default_k()));
    let gh = genesis.block_hash();
    store.put_block(genesis).unwrap();
    dag.write().add_genesis(gh, genesis.header.timestamp);
    let gd = dag.read().get_block_data(&gh).cloned().unwrap();
    store.put_dag_with_integrity(&gh, &gd).unwrap();
    for (t, i, o) in utxos { store.put_utxo(t, *i, o).unwrap(); }
    let (tip_tx, _) = broadcast::channel::<tip::TipChanged>(8);
    Node {
        _tmp: tmp, dag, store,
        mempool: Arc::new(mempool::Mempool::new()),
        node_state: Arc::new(RwLock::new(rpc::NodeState::default())),
        shielded: Arc::new(RwLock::new(coherence::ShieldedPool::new())),
        tip_tx,
    }
}

fn accept(n: &Node, b: &Block) -> Result<[u8; 32], String> {
    // Every network/RPC/miner ingress runs validate_structure() first.
    b.validate_structure().map_err(|e| format!("structural validation: {e}"))?;
    accept_block(b, b.block_hash(), b.height, &n.dag, &n.store, &n.mempool,
                 &n.node_state, Some(&n.tip_tx), &n.shielded)
}

fn mk_block(parent: [u8; 32], parent_ts: u64, height: u64, txs: Vec<Transaction>) -> Block {
    let bits = pow::expected_bits(parent_ts, height).unwrap();
    Block {
        header: BlockHeader { version: 1, parents: vec![parent],
                              merkle_root: Transaction::merkle_root(&txs),
                              timestamp: parent_ts + 30, bits, nonce: 0 },
        transactions: txs, blue_score: height, height, shielded_transactions: Vec::new(),
    }
}

/// Find a nonce satisfying `pred(block_hash)` AND the GnB-SMH proof
/// (validate_pow caches the id, so later accepts don't re-evaluate).
fn seal_where(b: &mut Block, pred: impl Fn(&[u8; 32]) -> bool) {
    loop {
        if pred(&b.block_hash()) && b.validate_pow() { return; }
        b.header.nonce += 1;
    }
}
fn seal(b: &mut Block) { seal_where(b, |_| true) }

fn sel_tip(n: &Node) -> Option<[u8; 32]> { n.dag.read().selected_tip() }

// ── Guard: the copied code is byte-for-byte main.rs ───────────────────────────
#[test]
fn copied_consensus_code_is_verbatim_from_main_rs() {
    let main_rs = include_str!("../src/main.rs");
    let me = include_str!("audit_poc_validation.rs");
    let begin = me.find("// BEGIN VERBATIM main.rs\n").unwrap() + "// BEGIN VERBATIM main.rs\n".len();
    let end = me.find("// END VERBATIM main.rs").unwrap();
    let main_lines: Vec<&str> = main_rs.lines().collect();
    let mut pos = 0usize;
    let mut copied = 0usize;
    for line in me[begin..end].lines().filter(|l| !l.trim().is_empty()) {
        let found = main_lines[pos..].iter().position(|m| *m == line)
            .unwrap_or_else(|| panic!("line not found verbatim (in order) in main.rs: {line:?}"));
        pos += found + 1;
        copied += 1;
    }
    assert!(copied > 600, "expected the full accept_block + validation core, got {copied} lines");
}

// ── VAL-1: tx validity is evaluated against the node's CURRENT tip, not the
//    block's own ancestry → two honest sibling blocks that both include the
//    same mempool tx partition the network permanently. ───────────────────────
#[test]
fn val1_sibling_blocks_sharing_a_tx_split_the_network_permanently() {
    let g_ts = unix_now();
    let genesis = mk_genesis(g_ts);
    let gh = genesis.block_hash();
    let (pk, sk, owner) = keypair();
    let fund = ([0x5Au8; 32], 0u32, TxOutput { value: 1_000_000, script_pubkey: owner });

    // One ordinary payment T, as two miners would both pick it from the mempool.
    let mut t = spend(fund.0, 0, 900_000, vec![0x11; 20]);
    sign_input(&mut t, 0, &sk, &pk);
    let fee = 100_000;
    let sub = core::tokenomics::block_subsidy_sat(1);

    let mut x = mk_block(gh, g_ts, 1, vec![coinbase("miner-X", sub + fee, vec![0xAA; 20]), t.clone()]);
    let mut y = mk_block(gh, g_ts, 1, vec![coinbase("miner-Y", sub + fee, vec![0xBB; 20]), t.clone()]);
    seal(&mut x);
    seal(&mut y);
    // GhostDAG tie-break between equal-work siblings: larger hash wins.
    let (w, l) = if x.block_hash() > y.block_hash() { (x, y) } else { (y, x) };
    let (wh, lh) = (w.block_hash(), l.block_hash());

    // Context-free reference: with BOTH siblings in the DAG, W is the selected tip.
    {
        let mut d = consensus::GhostDAG::with_default_k();
        d.add_genesis(gh, g_ts);
        let work = pow::work_from_bits(w.header.bits);
        d.add_block(lh, vec![gh], l.header.timestamp, work).unwrap();
        d.add_block(wh, vec![gh], w.header.timestamp, work).unwrap();
        assert_eq!(d.selected_tip(), Some(wh), "consensus rule: W must be the selected tip");
    }

    let a = node_with(&genesis, &[fund.clone()]); // receives L first
    let b = node_with(&genesis, &[fund.clone()]); // receives W first

    accept(&a, &l).expect("L is valid on A");
    let err = accept(&a, &w).expect_err("BUG: A rejects the honest, heavier-by-tiebreak W");
    assert!(err.contains("not found"), "A rejects W because T's input is already spent in A's tip state: {err}");

    accept(&b, &w).expect("W is valid on B");
    assert!(accept(&b, &l).is_err(), "B rejects L for the mirror reason");

    assert_eq!(sel_tip(&a), Some(lh));
    assert_eq!(sel_tip(&b), Some(wh));

    // The W-branch grows; A can never follow it (W stays 'invalid' on A forever).
    let mut z = mk_block(wh, w.header.timestamp, 2,
        vec![coinbase("miner-Z", core::tokenomics::block_subsidy_sat(2), vec![0xCC; 20])]);
    seal(&mut z);
    accept(&b, &z).expect("Z extends W on B");
    let e = accept(&a, &z).expect_err("A cannot connect Z");
    assert!(e.contains("unknown parent"), "{e}");
    assert!(accept(&a, &w).is_err(), "re-delivery of W is still rejected on A: permanent split");
    assert_eq!(sel_tip(&a), Some(lh));
    assert_eq!(sel_tip(&b), Some(z.block_hash()));
}

// ── VAL-2: duplicate coinbase txids (no BIP30/BIP34) + rollback deletes the
//    EARLIER block's UTXO → nodes that saw a reorg diverge from nodes that did
//    not; a later spend of that output splits the chain. ─────────────────────
#[test]
fn val2_duplicate_coinbase_txid_plus_reorg_diverges_utxo_sets() {
    let g_ts = unix_now();
    let genesis = mk_genesis(g_ts);
    let gh = genesis.block_hash();
    let (pk, sk, owner) = keypair();
    let sub = core::tokenomics::block_subsidy_sat(1);
    assert_eq!(sub, core::tokenomics::block_subsidy_sat(2), "same epoch, same subsidy");

    let cb = coinbase("same-coinbase", sub, owner.clone());
    let c = cb.txid();

    let mut b1 = mk_block(gh, g_ts, 1, vec![cb.clone()]);
    seal(&mut b1);
    let b1h = b1.block_hash();
    let mut b2 = mk_block(b1h, b1.header.timestamp, 2, vec![cb.clone()]); // identical coinbase
    seal(&mut b2);
    assert_eq!(b2.transactions[0].txid(), c, "two blocks, one coinbase txid");
    let b2h = b2.block_hash();
    let mut b2p = mk_block(b1h, b1.header.timestamp, 2,
        vec![coinbase("honest-sibling", sub, vec![0xDD; 20])]);
    seal_where(&mut b2p, |h| *h > b2h); // wins the equal-work tie-break

    let n1 = node_with(&genesis, &[]);
    accept(&n1, &b1).unwrap();
    accept(&n1, &b2).expect("BUG: duplicate coinbase txid accepted (no BIP30 check)");
    accept(&n1, &b2p).expect("sibling reorgs b2 out on n1");
    assert_eq!(sel_tip(&n1), Some(b2p.block_hash()));

    let n2 = node_with(&genesis, &[]);
    accept(&n2, &b1).unwrap();
    accept(&n2, &b2p).unwrap();
    assert_eq!(sel_tip(&n2), Some(b2p.block_hash()));

    // Same selected chain (genesis → b1 → b2p) on both nodes, different UTXO sets.
    assert!(n2.store.get_utxo(&c, 0).unwrap().is_some(), "n2: b1's coinbase output exists");
    assert!(n1.store.get_utxo(&c, 0).unwrap().is_none(),
            "BUG: n1 lost b1's coinbase output when rolling back b2");

    // Consequence: after maturity, a spend of (c,0) is valid on n2, invalid on n1.
    let mut parent = b2p.clone();
    while parent.height < 1 + core::COINBASE_MATURITY - 1 {
        let h = parent.height + 1;
        let mut nb = mk_block(parent.block_hash(), parent.header.timestamp, h,
            vec![coinbase(&format!("filler-{h}"), core::tokenomics::block_subsidy_sat(h), vec![0xEE; 20])]);
        nb.header.timestamp = parent.header.timestamp; // stay inside MAX_FUTURE_SECS
        seal(&mut nb);
        accept(&n1, &nb).unwrap();
        accept(&n2, &nb).unwrap();
        parent = nb;
    }
    let h = parent.height + 1; // depth = h - 1 = COINBASE_MATURITY
    let mut s = spend(c, 0, sub - 100_000, vec![0x77; 20]);
    sign_input(&mut s, 0, &sk, &pk);
    let mut spend_block = mk_block(parent.block_hash(), parent.header.timestamp, h,
        vec![coinbase("spender", core::tokenomics::block_subsidy_sat(h) + 100_000, vec![0xEF; 20]), s]);
    spend_block.header.timestamp = parent.header.timestamp;
    seal(&mut spend_block);
    accept(&n2, &spend_block).expect("valid on n2");
    let e = accept(&n1, &spend_block).expect_err("BUG: same block invalid on n1 -> chain split");
    assert!(e.contains("not found"), "{e}");
}

// ── VAL-3: a block may spend its OWN coinbase (maturity bypass at accept
//    time), but the reorg re-validator forbids it → nodes that saw the block
//    as an extension and nodes that saw it as a fork-loser diverge. ──────────
#[test]
fn val3_same_block_coinbase_spend_accepted_then_refused_on_reorg() {
    let g_ts = unix_now();
    let genesis = mk_genesis(g_ts);
    let gh = genesis.block_hash();
    let (pk, sk, miner) = keypair();
    let sub = core::tokenomics::block_subsidy_sat(1);
    let fee = 100_000;

    let cb = coinbase("self-spend", sub + fee, miner);
    let mut t = spend(cb.txid(), 0, sub, vec![0x22; 20]);
    sign_input(&mut t, 0, &sk, &pk);
    let mut m1 = mk_block(gh, g_ts, 1, vec![cb.clone(), t.clone()]);
    seal(&mut m1);
    let m1h = m1.block_hash();
    let mut s1 = mk_block(gh, g_ts, 1, vec![coinbase("sibling", sub, vec![0x33; 20])]);
    seal_where(&mut s1, |h| *h > m1h);
    let mut m2 = mk_block(m1h, m1.header.timestamp, 2,
        vec![coinbase("m2", core::tokenomics::block_subsidy_sat(2), vec![0x44; 20])]);
    seal(&mut m2);

    let n1 = node_with(&genesis, &[]);
    accept(&n1, &m1).expect("BUG: coinbase spent in its own block (0 confirmations) is accepted");
    assert!(n1.store.get_utxo(&t.txid(), 0).unwrap().is_some());
    assert!(n1.store.get_coinbase_height(&t.txid()).unwrap().is_none(),
            "the laundered output is a plain (immediately spendable) output");
    accept(&n1, &m2).expect("m2 extends m1 on n1");

    let n2 = node_with(&genesis, &[]);
    accept(&n2, &s1).unwrap();
    accept(&n2, &m1).expect("m1 accepted as fork-loser on n2 (same accept-time rule)");
    let e = accept(&n2, &m2).expect_err("BUG: reorg re-validation applies a stricter rule");
    assert!(e.contains("immature same-block coinbase"), "{e}");
    assert_eq!(sel_tip(&n1), Some(m2.block_hash()));
    assert_eq!(sel_tip(&n2), Some(s1.block_hash()));
    assert!(accept(&n2, &m2).is_err(), "permanent: n2 can never adopt the heavier m-chain");
}

// ── VAL-4: accept_block's commit is not atomic. A crash after the UTXO
//    mutations and before the CF_DAG write wedges the node: on restart the
//    block is unknown to the DAG but its inputs are already spent. ─────────
#[test]
fn val4_crash_between_utxo_apply_and_dag_persist_wedges_node() {
    let g_ts = unix_now();
    let genesis = mk_genesis(g_ts);
    let gh = genesis.block_hash();
    let (pk, sk, owner) = keypair();
    let fund = ([0x6Bu8; 32], 0u32, TxOutput { value: 1_000_000, script_pubkey: owner });
    let mut t = spend(fund.0, 0, 900_000, vec![0x11; 20]);
    sign_input(&mut t, 0, &sk, &pk);
    let mut x = mk_block(gh, g_ts, 1,
        vec![coinbase("x", core::tokenomics::block_subsidy_sat(1) + 100_000, vec![0xAA; 20]), t]);
    seal(&mut x);

    let n = node_with(&genesis, &[fund]);
    // accept_block's Extension path, in order, up to a crash point:
    n.store.put_block(&x).unwrap();                                  // main.rs:2120
    reorg::apply_block_utxo_mutations(&n.store, &x).unwrap();        // main.rs:2230
    // ...process dies here: put_dag_with_integrity (main.rs:2351-2356) never ran.

    // Restart: DAG is rebuilt from CF_DAG exactly as main() does.
    let mut d = consensus::GhostDAG::with_default_k();
    let entries = n.store.load_all_dag_data().unwrap();
    let im = n.store.load_all_integrity_hashes().unwrap();
    d.load_persisted_validated(entries, im).unwrap();
    assert!(!d.has_block(&x.block_hash()), "x is unknown after restart");
    *n.dag.write() = d;

    let e = accept(&n, &x).expect_err("BUG: the node can never re-accept x");
    assert!(e.contains("not found"), "{e}");
}

// ── VAL-5: block templates are not size-capped. get_for_block(2000) feeds
//    the built-in miner (main.rs:1618) and getblocktemplate (rpc:1141); any
//    mempool holding > ~1 MB of txs yields only oversize (invalid) blocks. ──
#[test]
fn val5_template_from_full_mempool_is_always_oversize() {
    let mp = mempool::Mempool::new();
    // Realistic hybrid-signature spends (~8.6 kB each); 130 of them ≈ 1.1 MB.
    let script_sig_len = 8 + core::SIG_SIZE + core::PUBKEY_SIZE;
    for i in 0..130u32 {
        let mut prev = [0u8; 32];
        prev[..4].copy_from_slice(&i.to_le_bytes());
        let mut tx = spend(prev, 0, 1_000_000, vec![0x12; 20]);
        tx.inputs[0].script_sig = vec![0xA5; script_sig_len];
        mp.add(tx, 200_000).expect("admitted");
    }
    // Template exactly as main.rs:1618-1668 builds it.
    let txs = mp.get_for_block(2000);
    assert_eq!(txs.len(), 130, "no byte budget applied when selecting");
    let all: Vec<Transaction> = std::iter::once(coinbase("gnb:h1:0", 1, vec![0x01; 20])).chain(txs).collect();
    let block = Block {
        header: BlockHeader { version: 1, parents: vec![[9u8; 32]],
            merkle_root: Transaction::merkle_root(&all), timestamp: unix_now(),
            bits: core::POW_LIMIT_BITS, nonce: 0 },
        transactions: all, blue_score: 1, height: 1, shielded_transactions: vec![],
    };
    assert!(block.size_bytes() > core::MAX_BLOCK_SIZE, "size {}", block.size_bytes());
    assert_eq!(block.validate_structure().unwrap_err(), "block too large",
               "BUG: every mined template is rejected by commit_self_mined_block / peers");
}

// ── VAL-6: script_sig (signatures) is not committed by the block id. A relay
//    can produce many byte-distinct encodings of one block id, valid or not. ─
#[test]
fn val6_block_id_does_not_commit_to_signatures() {
    let g_ts = unix_now();
    let genesis = mk_genesis(g_ts);
    let gh = genesis.block_hash();
    let (pk, sk, owner) = keypair();
    let fund = ([0x7Cu8; 32], 0u32, TxOutput { value: 1_000_000, script_pubkey: owner });
    let mut t = spend(fund.0, 0, 900_000, vec![0x11; 20]);
    sign_input(&mut t, 0, &sk, &pk);
    let mut x = mk_block(gh, g_ts, 1,
        vec![coinbase("x6", core::tokenomics::block_subsidy_sat(1) + 100_000, vec![0xAA; 20]), t]);
    seal(&mut x);
    let id = x.block_hash();

    // (a) Valid mutation: padding after the parsed sig/pk is ignored.
    let mut padded = x.clone();
    // (stays under the wire parser's 10,000-byte script_sig cap so it relays)
    padded.transactions[1].inputs[0].script_sig.extend_from_slice(&[0xEE; 1024]);
    assert_eq!(padded.block_hash(), id);
    // (b) Invalid mutation: flip a signature byte.
    let mut broken = x.clone();
    broken.transactions[1].inputs[0].script_sig[100] ^= 0xFF;
    assert_eq!(broken.block_hash(), id);

    let n1 = node_with(&genesis, &[fund.clone()]);
    accept(&n1, &padded).expect("padded encoding of the same block id is valid");
    let stored = n1.store.get_block(&id).unwrap().unwrap();
    assert_ne!(stored.to_wire_bytes(), x.to_wire_bytes(), "nodes store different bodies for one id");

    let n2 = node_with(&genesis, &[fund]);
    let e = accept(&n2, &broken).expect_err("same id, invalid body");
    assert!(e.contains("invalid signature"), "{e}");
    // Mitigation present: no invalid-block cache, so the honest body still connects.
    accept(&n2, &x).expect("honest body still accepted after the mutated one");
}

// ── VAL-5b: a mempool tx that conflicts with a confirmed tx is never evicted
//    (remove_confirmed is by txid only) and the miner never re-validates its
//    template → the victim's every self-mined block is rejected. ────────────
#[test]
fn val5b_conflicting_mempool_tx_poisons_every_template() {
    let g_ts = unix_now();
    let genesis = mk_genesis(g_ts);
    let gh = genesis.block_hash();
    let (pk, sk, owner) = keypair();
    let fund = ([0x8Du8; 32], 0u32, TxOutput { value: 1_000_000, script_pubkey: owner });
    let n = node_with(&genesis, &[fund.clone()]);

    // A reaches the victim's mempool first (validated like the gossip path).
    let mut a = spend(fund.0, 0, 900_000, vec![0x01; 20]);
    sign_input(&mut a, 0, &sk, &pk);
    let fee_a = validate_tx_standalone(&a, &n.store, 1).expect("A valid");
    n.mempool.add(a.clone(), fee_a).expect("A admitted");

    // A' (same outpoint, different txid) is confirmed in someone else's block.
    let mut a2 = spend(fund.0, 0, 880_000, vec![0x02; 20]);
    sign_input(&mut a2, 0, &sk, &pk);
    let sub = core::tokenomics::block_subsidy_sat(1);
    let mut x = mk_block(gh, g_ts, 1, vec![coinbase("other-miner", sub + 120_000, vec![0xAA; 20]), a2]);
    seal(&mut x);
    accept(&n, &x).expect("x confirms A'");
    assert!(n.mempool.contains(&a.txid()), "BUG: A survives although its input is now spent");

    // Victim's template exactly as main.rs:1618-1668, committed via accept_block.
    let txs = n.mempool.get_for_block(2000);
    let fees = miner_template_total_fees(&txs, &n.store);
    let all: Vec<Transaction> = std::iter::once(coinbase("gnb:h2:victim",
        core::tokenomics::block_subsidy_sat(2) + fees, vec![0xBB; 20])).chain(txs).collect();
    let mut blk = mk_block(x.block_hash(), x.header.timestamp, 2, all);
    seal(&mut blk);
    let e = accept(&n, &blk).expect_err("BUG: the victim's own block is rejected, every round");
    assert!(e.contains("not found"), "{e}");
}

// ── VAL-5c: the gossip admission path (validate_tx_standalone + Mempool::add)
//    has no dust check, but Block::validate_dust is consensus → one dust tx
//    from any peer poisons every template (and is never mined, so never paid).
#[test]
fn val5c_gossiped_dust_tx_poisons_every_template() {
    let g_ts = unix_now();
    let genesis = mk_genesis(g_ts);
    let gh = genesis.block_hash();
    let (pk, sk, owner) = keypair();
    let fund = ([0x9Eu8; 32], 0u32, TxOutput { value: 1_000_000, script_pubkey: owner });
    let n = node_with(&genesis, &[fund.clone()]);

    let mut d = Transaction {
        version: 1,
        inputs: vec![TxInput { prev_txid: fund.0, prev_index: 0, script_sig: vec![], sequence: u32::MAX }],
        outputs: vec![TxOutput { value: 1, script_pubkey: vec![0x03; 20] },          // dust
                      TxOutput { value: 899_999, script_pubkey: vec![0x04; 20] }],
        locktime: 0,
    };
    sign_input(&mut d, 0, &sk, &pk);
    // main.rs:1247-1250: gossip NewTransaction → validate_tx_standalone → mem.add
    let fee = validate_tx_standalone(&d, &n.store, 1).expect("BUG: dust tx passes gossip validation");
    n.mempool.add(d, fee).expect("BUG: dust tx admitted to mempool");

    let txs = n.mempool.get_for_block(2000);
    let fees = miner_template_total_fees(&txs, &n.store);
    let all: Vec<Transaction> = std::iter::once(coinbase("gnb:h1:victim",
        core::tokenomics::block_subsidy_sat(1) + fees, vec![0xBB; 20])).chain(txs).collect();
    let mut blk = mk_block(gh, g_ts, 1, all);
    seal(&mut blk);
    let e = accept(&n, &blk).expect_err("victim's template is consensus-invalid");
    assert!(e.contains("dust"), "{e}");
}

// ── VAL-7: validate_structure() (run on every ingress BEFORE accept_block's
//    expected-bits check) verifies PoW against the block's OWN bits. With
//    bits = POW_LIMIT_BITS a block needs no work at all, yet costs the
//    receiver one full 64 MiB GnB-SMH evaluation; unknown parents → orphan pool.
#[test]
fn val7_zero_work_junk_block_passes_structural_pow_gate() {
    let tx = coinbase("junk", 0, vec![0u8; 20]);
    let mut junk = Block {
        header: BlockHeader { version: 1, parents: vec![[0xD1u8; 32]], // unknown parent
            merkle_root: Transaction::merkle_root(std::slice::from_ref(&tx)),
            timestamp: unix_now(), bits: core::POW_LIMIT_BITS, nonce: 0x1234_5678 },
        transactions: vec![tx], blue_score: 0, height: 999_999, shielded_transactions: vec![],
    };
    let mut passed = 0;
    let t0 = std::time::Instant::now();
    for i in 0..4u64 {
        junk.header.nonce = 0xABCD_0000 + i; // arbitrary, no search performed
        if junk.validate_structure().is_ok() { passed += 1; }
    }
    let per_eval = t0.elapsed() / 4;
    eprintln!("VAL-7: {passed}/4 zero-work junk blocks passed validate_structure; \
               receiver cost ≈ {per_eval:?} each");
    assert_eq!(passed, 4, "every arbitrary nonce meets the pow-limit target");
}

// ── VAL-12 (latent): consensus has no script_sig size rule; the 10,000-byte
//    cap exists only in the wire parser. A block built in-process with a
//    larger field is accepted and persisted but can never be read back. ─────
#[test]
fn val12_oversized_script_sig_block_is_accepted_but_unreadable() {
    let g_ts = unix_now();
    let genesis = mk_genesis(g_ts);
    let gh = genesis.block_hash();
    let (pk, sk, owner) = keypair();
    let fund = ([0x4Fu8; 32], 0u32, TxOutput { value: 1_000_000, script_pubkey: owner });
    let mut t = spend(fund.0, 0, 900_000, vec![0x11; 20]);
    sign_input(&mut t, 0, &sk, &pk);
    t.inputs[0].script_sig.extend_from_slice(&[0u8; 4096]); // 12.6 kB, sig still valid
    let mut x = mk_block(gh, g_ts, 1,
        vec![coinbase("x12", core::tokenomics::block_subsidy_sat(1) + 100_000, vec![0xAA; 20]), t]);
    seal(&mut x);
    let n = node_with(&genesis, &[fund]);
    accept(&n, &x).expect("accepted by validate_structure + accept_block");
    let e = n.store.get_block(&x.block_hash()).expect_err("stored body cannot be decoded");
    assert!(e.to_string().contains("implausible script_sig length"), "{e}");
}
