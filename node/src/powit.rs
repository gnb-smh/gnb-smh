//! Node side of PoW + PoWit (Proof of Witnesses).
//!
//! Consensus rules live in `gnb_crypto::core::powit` and `core::witness_share`;
//! this module supplies what needs the DAG and storage:
//!
//! - [`block_state`]: validate a block's PoWit section in context (share
//!   proofs, attested blocks, share uniqueness) and compute its PoWit state
//!   from its selected parent's state.
//! - [`PowitPool`]: gossiped shares, attestations and equivocation proofs
//!   waiting for a block, admitted only after validation.
//! - [`template_body`]: the PoWit section for a block template, chosen so the
//!   template is always valid.
//! - [`WitnessDuty`]: a witness node's attestation signer, with persistent
//!   protection against ever signing two conflicting links.
//! - [`mine_share`]: one round of share mining for a payout key.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use parking_lot::Mutex;

use crate::consensus::GhostDAG;
use crate::storage::Storage;
use gnb_crypto::core::powit::{self, Attestation, BlockInput, ChainView, Checkpoint, Equivocation,
                              KeyId, PowitBody, PowitParams, PowitState};
use gnb_crypto::core::witness_share::{self, WitnessShare, SHARE_WINDOW};
use gnb_crypto::core::{self, Block};

type Hash = [u8; 32];

/// Longest selected-chain walk any lookup performs.
const MAX_WALK: usize = 8_192;

// ── Chain view over the DAG ──────────────────────────────────────────────────

/// The selected chain starting at `start` (inclusive), walked through
/// `selected_parent` links.
pub struct DagChainView<'a> {
    pub dag: &'a GhostDAG,
    pub start: Option<Hash>,
}

impl ChainView for DagChainView<'_> {
    fn selected_at(&self, slot: u64) -> Option<Hash> {
        let mut cur = self.start;
        for _ in 0..MAX_WALK {
            let h = cur?;
            let d = self.dag.get_block_data(&h)?;
            if d.height < slot {
                return Some(h);
            }
            cur = d.selected_parent;
        }
        None
    }
}

/// Selected-chain blocks from `start` down to (and including) `min_height`:
/// (hash, height), tallest first.
pub fn selected_chain_since(dag: &GhostDAG, start: Option<Hash>, min_height: u64) -> Vec<(Hash, u64)> {
    let mut out = Vec::new();
    let mut cur = start;
    while let Some(h) = cur {
        let Some(d) = dag.get_block_data(&h) else { break };
        if d.height < min_height || out.len() >= MAX_WALK {
            break;
        }
        out.push((h, d.height));
        cur = d.selected_parent;
    }
    out
}

// ── Per-block state storage ──────────────────────────────────────────────────

fn state_key(hash: &Hash) -> String {
    format!("powit/state/{}", hex::encode(hash))
}

pub fn load_state(store: &Storage, hash: &Hash) -> Option<PowitState> {
    let bytes = store.get_meta(&state_key(hash)).ok().flatten()?;
    bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).ok().map(|(s, _)| s)
}

pub fn save_state(store: &Storage, hash: &Hash, state: &PowitState) -> Result<(), String> {
    let bytes = bincode::serde::encode_to_vec(state, bincode::config::standard())
        .map_err(|e| format!("powit state encode: {e}"))?;
    store.put_meta(&state_key(hash), &bytes).map_err(|e| format!("storage: powit state: {e}"))
}

/// State a child of `parent` builds on: the parent's stored state, or the
/// genesis state when the parent is below activation.
fn base_state(dag: &GhostDAG, store: &Storage, parent: Option<Hash>) -> Result<PowitState, String> {
    let act = core::powit_height();
    let Some(p) = parent else { return Err("powit: block without a selected parent".into()) };
    let ph = dag.get_block_data(&p).map(|d| d.height).ok_or("powit: unknown selected parent")?;
    if ph < act {
        return Ok(PowitState::genesis(act, p));
    }
    load_state(store, &p).ok_or_else(|| format!("storage: missing PoWit state of {}", hex::encode(&p[..8])))
}

// ── Share verification (cached) ──────────────────────────────────────────────

static VERIFIED_SHARES: Mutex<Option<(HashMap<Hash, u128>, std::collections::VecDeque<Hash>)>> =
    parking_lot::const_mutex(None);
const SHARE_CACHE_CAP: usize = 16_384;

fn verify_share_cached(share: &WitnessShare, attested: &Block) -> Result<u128, String> {
    let id = witness_share::share_id(share);
    if let Some(w) = VERIFIED_SHARES.lock().as_ref().and_then(|(m, _)| m.get(&id).copied()) {
        return Ok(w);
    }
    let w = witness_share::verify_share(share, attested, witness_share::smh_v3).map_err(|e| e.to_string())?;
    let mut g = VERIFIED_SHARES.lock();
    let (m, order) = g.get_or_insert_with(Default::default);
    if m.insert(id, w).is_none() {
        order.push_back(id);
        if order.len() > SHARE_CACHE_CAP {
            if let Some(old) = order.pop_front() {
                m.remove(&old);
            }
        }
    }
    Ok(w)
}

/// Share ids already included on the selected chain in `recent`.
fn included_share_ids(store: &Storage, recent: &[(Hash, u64)]) -> Result<HashSet<Hash>, String> {
    let act = core::powit_height();
    let mut ids = HashSet::new();
    for (h, height) in recent {
        if *height < act {
            continue;
        }
        let b = store.get_block(h).map_err(|e| format!("storage: {e}"))?
            .ok_or_else(|| format!("storage: missing body of {}", hex::encode(&h[..8])))?;
        ids.extend(b.powit.shares.iter().map(witness_share::share_id));
    }
    Ok(ids)
}

/// Check one share against the chain a block at `height` extends: the
/// attested block is on that selected chain within the share window, the
/// share is not already included there, and its proof is valid.
fn check_share(store: &Storage, share: &WitnessShare, height: u64, recent: &[(Hash, u64)],
               included: &HashSet<Hash>) -> Result<(KeyId, u128), String> {
    if !share.payout_is_valid() {
        return Err("witness share pays an invalid script".into());
    }
    let key = share.key_id();
    let (_, ah) = recent.iter().find(|(h, _)| *h == share.attested)
        .ok_or("witness share attests a block that is not on this selected chain")?;
    if *ah >= height || height - ah > SHARE_WINDOW {
        return Err("witness share attests a block outside the share window".into());
    }
    if included.contains(&witness_share::share_id(share)) {
        return Err("witness share already included on this chain".into());
    }
    let attested = store.get_block(&share.attested).map_err(|e| format!("storage: {e}"))?
        .ok_or("storage: attested block body missing")?;
    Ok((key, verify_share_cached(share, &attested)?))
}

// ── Block validation in context ──────────────────────────────────────────────

/// Validate `block`'s PoWit section in context and compute its state.
/// `Ok(None)` below activation. Errors prefixed `storage:` are local
/// failures, never a verdict on the block.
pub fn block_state(block: &Block, block_hash: &Hash, dag: &GhostDAG, store: &Storage)
    -> Result<Option<PowitState>, String>
{
    if !core::powit_active(block.height) {
        return if block.powit.is_empty() { Ok(None) } else { Err("PoWit section before activation".into()) };
    }
    let sp = dag.preview_selected_parent(&block.header.parents);
    let base = base_state(dag, store, sp)?;
    let recent = selected_chain_since(dag, sp, block.height.saturating_sub(SHARE_WINDOW));
    let included = included_share_ids(store, &recent)?;
    let mut share_work = Vec::with_capacity(block.powit.shares.len());
    for s in &block.powit.shares {
        share_work.push(check_share(store, s, block.height, &recent, &included)?);
    }
    let input = BlockInput {
        height: block.height,
        hash: *block_hash,
        share_work: &share_work,
        attestations: &block.powit.attestations,
        evidence: &block.powit.evidence,
    };
    let view = DagChainView { dag, start: sp };
    base.apply(&powit::params(), core::node_chain_id(), &input, &view).map(Some)
}

// ── Pools ────────────────────────────────────────────────────────────────────

const POOL_CAP: usize = 4_096;

#[derive(Default)]
struct PoolInner {
    shares: BTreeMap<Hash, (WitnessShare, u64)>,
    attestations: BTreeMap<Hash, Attestation>,
    evidence: BTreeMap<KeyId, Equivocation>,
    /// Links seen per key (gossip or blocks), to build equivocation proofs.
    seen_links: HashMap<KeyId, Vec<Attestation>>,
}

/// Validated PoWit items waiting for a block.
#[derive(Default)]
pub struct PowitPool {
    inner: Mutex<PoolInner>,
}

/// The node's single pool (shared by gossip, the miner and RPC).
pub fn pool() -> &'static PowitPool {
    static POOL: std::sync::LazyLock<PowitPool> = std::sync::LazyLock::new(PowitPool::default);
    &POOL
}

/// Gossip frame kinds for `NetworkMessage::NewPowitItem`.
pub const ITEM_SHARE: u8 = 1;
pub const ITEM_ATTESTATION: u8 = 2;
pub const ITEM_EVIDENCE: u8 = 3;

pub fn item_id(kind: u8, data: &[u8]) -> Hash {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(b"GNB-POWIT-v1/item");
    h.update([kind]);
    h.update(data);
    h.finalize().into()
}

fn tip_context(dag: &GhostDAG) -> Option<(Hash, u64)> {
    let t = dag.selected_tip()?;
    Some((t, dag.get_block_data(&t)?.height))
}

impl PowitPool {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn counts(&self) -> (usize, usize, usize) {
        let g = self.inner.lock();
        (g.shares.len(), g.attestations.len(), g.evidence.len())
    }

    /// Admit a gossiped or locally mined share for the next block on the
    /// current tip. Cheap checks first; the proof (~90 ms) last.
    pub fn admit_share(&self, share: WitnessShare, dag: &GhostDAG, store: &Storage) -> Result<Hash, String> {
        let id = witness_share::share_id(&share);
        if self.inner.lock().shares.contains_key(&id) {
            return Ok(id);
        }
        let (tip, tip_h) = tip_context(dag).ok_or("no tip")?;
        let next = tip_h + 1;
        if !core::powit_active(next) {
            return Err("PoWit not active".into());
        }
        let recent = selected_chain_since(dag, Some(tip), next.saturating_sub(SHARE_WINDOW));
        let included = included_share_ids(store, &recent)?;
        let (_, _) = check_share(store, &share, next, &recent, &included)?;
        let ah = recent.iter().find(|(h, _)| *h == share.attested).map(|(_, h)| *h).unwrap_or(0);
        let mut g = self.inner.lock();
        if g.shares.len() >= POOL_CAP {
            return Err("share pool full".into());
        }
        g.shares.insert(id, (share, ah));
        Ok(id)
    }

    /// Admit an attestation that links from the tip's justified checkpoint,
    /// by a member of the target's witness set. Conflicts with a link the
    /// same key already signed become an equivocation proof.
    pub fn admit_attestation(&self, att: Attestation, dag: &GhostDAG, store: &Storage) -> Result<Hash, String> {
        let id = att.id();
        let chain = core::node_chain_id();
        let p = powit::params();
        let act = core::powit_height();
        if !att.verify_signature(chain, &p, act) {
            return Err("invalid attestation signature".into());
        }
        let key = att.key_id();
        {
            let mut g = self.inner.lock();
            if g.attestations.contains_key(&id) {
                return Ok(id);
            }
            // Equivocation detection against every link this node has seen.
            let conflicting = g.seen_links.get(&key).and_then(|v| v.iter().find(|o| {
                Equivocation { a: (*o).clone(), b: att.clone() }.verify(chain, &p, act).is_ok()
            }).cloned());
            if let Some(o) = conflicting {
                g.evidence.entry(key).or_insert(Equivocation { a: o, b: att.clone() });
            }
            let links = g.seen_links.entry(key).or_default();
            if links.len() < 64 && !links.contains(&att) {
                links.push(att.clone());
            }
        }
        let (tip, _) = tip_context(dag).ok_or("no tip")?;
        let st = load_state(store, &tip).ok_or("PoWit not active at the tip")?;
        if att.source != st.justified {
            return Err("attestation source is not the tip's justified checkpoint".into());
        }
        let te = p.epoch(st.activation, att.target.height);
        if !st.witness_set(&p, te).iter().any(|(k, _)| *k == key) {
            return Err("attester is not in the witness set".into());
        }
        let mut g = self.inner.lock();
        if g.attestations.len() >= POOL_CAP {
            return Err("attestation pool full".into());
        }
        g.attestations.insert(id, att);
        Ok(id)
    }

    /// Admit an equivocation proof (verified).
    pub fn admit_evidence(&self, ev: Equivocation) -> Result<KeyId, String> {
        let key = ev.verify(core::node_chain_id(), &powit::params(), core::powit_height()).map_err(|e| e.to_string())?;
        self.inner.lock().evidence.entry(key).or_insert(ev);
        Ok(key)
    }

    /// Forget what a new tip made stale or included.
    pub fn prune(&self, dag: &GhostDAG, store: &Storage) {
        let Some((tip, tip_h)) = tip_context(dag) else { return };
        let st = load_state(store, &tip);
        let p = powit::params();
        let mut g = self.inner.lock();
        g.shares.retain(|_, (_, ah)| tip_h < *ah + SHARE_WINDOW);
        if let Some(st) = &st {
            g.attestations.retain(|_, a| a.source == st.justified && tip_h <= a.target.height + p.vote_ttl);
            let e = st.epoch;
            g.evidence.retain(|k, _| !st.is_banned(k, e));
        }
        if g.seen_links.len() > POOL_CAP {
            g.seen_links.clear();
        }
    }

    pub fn snapshot(&self) -> (Vec<WitnessShare>, Vec<Attestation>, Vec<Equivocation>) {
        let g = self.inner.lock();
        let mut atts: Vec<Attestation> = g.attestations.values().cloned().collect();
        atts.sort_by_key(|a| a.target.height);
        (g.shares.values().map(|(s, _)| s.clone()).collect(), atts, g.evidence.values().cloned().collect())
    }
}

// ── Templates ────────────────────────────────────────────────────────────────

/// PoWit section for a template extending `tip` at `height`: every item is
/// re-checked against the template's own context, so the section is valid.
pub fn template_body(pool: &PowitPool, dag: &GhostDAG, store: &Storage, tip: Hash, height: u64) -> PowitBody {
    if !core::powit_active(height) {
        return PowitBody::default();
    }
    let Ok(base) = base_state(dag, store, Some(tip)) else { return PowitBody::default() };
    let p = powit::params();
    let chain = core::node_chain_id();
    let epoch = p.epoch(base.activation, height);
    let recent = selected_chain_since(dag, Some(tip), height.saturating_sub(SHARE_WINDOW));
    let Ok(included) = included_share_ids(store, &recent) else { return PowitBody::default() };
    let (shares, atts, evidence) = pool.snapshot();

    let mut body = PowitBody::default();
    let mut share_work = Vec::new();
    for s in shares {
        if body.shares.len() >= witness_share::MAX_SHARES_PER_BLOCK {
            break;
        }
        if let Ok((k, w)) = check_share(store, &s, height, &recent, &included) {
            if !base.is_banned(&k, epoch) && !body.shares.contains(&s) {
                body.shares.push(s);
                share_work.push((k, w));
            }
        }
    }
    let view = DagChainView { dag, start: Some(tip) };
    let try_apply = |b: &PowitBody, sw: &[(KeyId, u128)]| {
        let input = BlockInput { height, hash: [0; 32], share_work: sw, attestations: &b.attestations,
                                 evidence: &b.evidence };
        base.apply(&p, chain, &input, &view).is_ok()
    };
    for ev in evidence {
        if body.evidence.len() >= p.max_evidence_per_block {
            break;
        }
        body.evidence.push(ev);
        if !try_apply(&body, &share_work) {
            body.evidence.pop();
        }
    }
    for a in atts {
        if body.attestations.len() >= p.max_attestations_per_block {
            break;
        }
        body.attestations.push(a);
        if !try_apply(&body, &share_work) {
            body.attestations.pop();
        }
    }
    // Shares of a key barred by evidence in this same block are invalid.
    if !try_apply(&body, &share_work) {
        body.shares.clear();
        share_work.clear();
        if !try_apply(&body, &share_work) {
            return PowitBody::default();
        }
    }
    body
}

// ── Witness duty ─────────────────────────────────────────────────────────────

/// A witness's forward-secure KES key, its payout script and its persistent
/// vote record. The KES state evolves to each target's epoch (erasing every
/// earlier seed, on disk first) before signing, and the record makes a double
/// or surround vote impossible even across restarts and reorgs.
pub struct WitnessDuty {
    pub key_id: KeyId,
    pub payout_script: Vec<u8>,
    key_path: PathBuf,
    password: zeroize::Zeroizing<String>,
    signer: Mutex<gnb_crypto::core::kes::KesSigner>,
    record_path: PathBuf,
    signed: Mutex<Vec<(Checkpoint, Checkpoint)>>,
}

impl WitnessDuty {
    /// Load a KES witness key (`gnb-cli witnesskeygen`); the password is read
    /// from `password_file` (first line), never from the command line.
    pub fn load(key: &Path, password_file: &Path, payout_script: Vec<u8>, data_dir: &Path) -> Result<Self, String> {
        let pw = std::fs::read_to_string(password_file).map_err(|e| format!("witness password file: {e}"))?;
        let password = zeroize::Zeroizing::new(pw.lines().next().unwrap_or("").trim().to_string());
        let file = gnb_crypto::core::kes::KesKeyFile::load(key)?;
        let signer = file.open(&password)?;
        let key_id = signer.public().witness_id();
        let record_path = data_dir.join(format!("powit-votes-{}.json", hex::encode(key_id)));
        let signed: Vec<(Checkpoint, Checkpoint)> = std::fs::read(&record_path).ok()
            .and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        Ok(WitnessDuty {
            key_id,
            payout_script,
            key_path: key.to_path_buf(),
            password,
            signer: Mutex::new(signer),
            record_path,
            signed: Mutex::new(signed),
        })
    }

    fn conflicts(&self, source: &Checkpoint, target: &Checkpoint) -> bool {
        self.signed.lock().iter().any(|(s, t)| {
            (t.height == target.height && t != target)
                || (s.height < source.height && target.height < t.height)
                || (source.height < s.height && t.height < target.height)
        })
    }

    /// If this key is a witness for the newest checkpoint above the tip's
    /// justified one, sign that link once. Returns the new attestation.
    pub fn maybe_attest(&self, dag: &GhostDAG, store: &Storage) -> Result<Option<Attestation>, String> {
        let Some((tip, tip_h)) = tip_context(dag) else { return Ok(None) };
        let Some(st) = load_state(store, &tip) else { return Ok(None) };
        let p: PowitParams = powit::params();
        let act = st.activation;
        if tip_h < act {
            return Ok(None);
        }
        // Newest checkpoint slot at or below the next block's height.
        let next = tip_h + 1;
        let slot = act + (next - act) / p.checkpoint_interval * p.checkpoint_interval;
        if slot <= st.justified.height {
            return Ok(None);
        }
        let te = p.epoch(act, slot);
        if !st.witness_set(&p, te).iter().any(|(k, _)| *k == self.key_id) {
            return Ok(None);
        }
        // The next block's view of the slot: its selected chain starts at tip.
        let view = DagChainView { dag, start: Some(tip) };
        let Some(hash) = view.selected_at(slot) else { return Ok(None) };
        let target = Checkpoint { height: slot, hash };
        let source = st.justified;
        if self.signed.lock().iter().any(|(s, t)| *s == source && *t == target) {
            return Ok(None);
        }
        if self.conflicts(&source, &target) {
            return Ok(None);
        }
        let mut signer = self.signer.lock();
        if te < signer.epoch() {
            return Ok(None); // that epoch's leaf is gone: forward security
        }
        if te > signer.epoch() {
            // Erase every earlier seed, ON DISK FIRST, then in memory.
            let mut next_state = gnb_crypto::core::kes::KesKeyFile::load(&self.key_path)?.open(&self.password)?;
            next_state.evolve_to(te)?;
            gnb_crypto::core::kes::KesKeyFile::seal(&next_state, &self.password)?.save(&self.key_path)?;
            *signer = next_state;
        }
        let att = Attestation::sign(core::node_chain_id(), source, target, &signer)?;
        {
            let mut g = self.signed.lock();
            g.push((source, target));
            let bytes = serde_json::to_vec(&*g).map_err(|e| e.to_string())?;
            // Persist BEFORE releasing the signature.
            let tmp = self.record_path.with_extension("json.tmp");
            std::fs::write(&tmp, &bytes).map_err(|e| format!("witness vote record: {e}"))?;
            std::fs::rename(&tmp, &self.record_path).map_err(|e| format!("witness vote record: {e}"))?;
        }
        Ok(Some(att))
    }
}

// ── Share mining ─────────────────────────────────────────────────────────────

/// Try `attempts` nonces for a share attesting `attested` (normally the
/// current tip), crediting `witness` and paying `payout` (any valid script).
/// GnB-SMH v3, 4 MiB. Takes no lock: the caller reads the tip first.
pub fn mine_share(attested: &Block, attested_hash: Hash, witness: KeyId, payout: &[u8], start_nonce: u64,
                  attempts: u64, stop: &std::sync::atomic::AtomicBool) -> Option<WitnessShare> {
    let stream = witness_share::tx_stream(attested);
    let root = attested.witness_root();
    let target = witness_share::share_target(&gnb_smh::difficulty::bits_to_target(attested.header.bits));
    let mut sp = gnb_smh::v3::Scratchpad::new(gnb_smh::v3::LOG2_N);
    let mut share = WitnessShare { attested: attested_hash, witness, payout: payout.to_vec(),
                                   bits: attested.header.bits, nonce: 0 };
    for i in 0..attempts {
        if stop.load(std::sync::atomic::Ordering::Relaxed) {
            return None;
        }
        share.nonce = start_nonce.wrapping_add(i);
        let pre = witness_share::pow_preimage(&share, &root, &stream);
        let out = gnb_smh::v3::hash_with(&mut sp, &pre, share.nonce);
        if gnb_smh::difficulty::meets_target(&out, &target) {
            return Some(share);
        }
    }
    None
}

/// Equivocation proofs in the pool (for gossip).
pub fn pool_evidence() -> Vec<Equivocation> {
    pool().snapshot().2
}

/// JSON summary for `getpowitinfo`.
pub fn info_json(dag: &GhostDAG, store: &Storage) -> serde_json::Value {
    let act = core::powit_height();
    let p = powit::params();
    let tip = dag.selected_tip();
    let tip_h = tip.and_then(|t| dag.get_block_data(&t)).map(|d| d.height).unwrap_or(0);
    // The tip's state is written just after the tip is accepted; until then,
    // report the latest selected-chain block that has one instead of nothing.
    let st = selected_chain_since(dag, tip, tip_h.saturating_sub(16))
        .into_iter()
        .find_map(|(h, _)| load_state(store, &h));
    let (ps, pa, pe) = pool().counts();
    let cp = |c: &Checkpoint| serde_json::json!({
        "slot": c.height,
        "hash": hex::encode(c.hash),
        "block_height": dag.get_block_data(&c.hash).map(|d| d.height),
    });
    let ws = st.as_ref().map(|s| s.witness_set(&p, s.epoch)).unwrap_or_default();
    let total: u128 = ws.iter().map(|(_, w)| *w).sum();
    serde_json::json!({
        "activation_height": if act == u64::MAX { serde_json::Value::Null } else { act.into() },
        "active": core::powit_active(tip_h + 1),
        "pow": core::pow_algo(tip_h + 1).name(),
        "params": {
            "epoch_len": p.epoch_len, "checkpoint_interval": p.checkpoint_interval,
            "window_epochs": p.window_epochs, "max_witnesses": p.max_witnesses,
        },
        "tip_height": tip_h,
        "epoch": st.as_ref().map(|s| s.epoch),
        "justified": st.as_ref().map(|s| cp(&s.justified)),
        "finalized": st.as_ref().map(|s| cp(&s.finalized)),
        "witness_set": {
            "size": ws.len(),
            "total_weight": total.to_string(),
            "top": ws.iter().take(10).map(|(k, w)| serde_json::json!({
                "key": hex::encode(k), "weight": w.to_string() })).collect::<Vec<_>>(),
        },
        "barred_keys": st.as_ref().map(|s| s.banned.len()).unwrap_or(0),
        "pool": { "shares": ps, "attestations": pa, "evidence": pe },
    })
}

// ── Gossip ingress ───────────────────────────────────────────────────────────

/// Decode and admit one gossiped PoWit item. `Ok(())` means valid (relay).
pub fn admit_item(kind: u8, data: &[u8], dag: &GhostDAG, store: &Storage) -> Result<(), String> {
    let mut cur = std::io::Cursor::new(data);
    let done = |cur: &std::io::Cursor<&[u8]>| -> Result<(), String> {
        if cur.position() as usize == data.len() { Ok(()) } else { Err("trailing bytes".into()) }
    };
    match kind {
        ITEM_SHARE => {
            let s = WitnessShare::read_wire(&mut cur)?;
            done(&cur)?;
            pool().admit_share(s, dag, store).map(|_| ())
        }
        ITEM_ATTESTATION => {
            let a = Attestation::read_wire(&mut cur)?;
            done(&cur)?;
            pool().admit_attestation(a, dag, store).map(|_| ())
        }
        ITEM_EVIDENCE => {
            let e = Equivocation::read_wire(&mut cur)?;
            done(&cur)?;
            pool().admit_evidence(e).map(|_| ())
        }
        _ => Err("unknown PoWit item kind".into()),
    }
}

/// Encode a local item for gossip: (id, kind, data).
pub fn share_item(s: &WitnessShare) -> (Hash, u8, Vec<u8>) {
    let d = s.to_wire_bytes();
    (item_id(ITEM_SHARE, &d), ITEM_SHARE, d)
}

pub fn attestation_item(a: &Attestation) -> (Hash, u8, Vec<u8>) {
    let d = a.to_wire_bytes();
    (item_id(ITEM_ATTESTATION, &d), ITEM_ATTESTATION, d)
}

pub fn evidence_item(e: &Equivocation) -> (Hash, u8, Vec<u8>) {
    let d = e.to_wire_bytes();
    (item_id(ITEM_EVIDENCE, &d), ITEM_EVIDENCE, d)
}

// ── Finality ─────────────────────────────────────────────────────────────────

/// Pin fork choice to the checkpoint the selected tip's witness set has
/// finalized (`GhostDAG::set_finalized`): no later selection may leave it.
/// The activation checkpoint is final only by definition and never pins fork
/// choice (two chains may compete right at activation).
pub fn update_finalized(dag: &parking_lot::RwLock<GhostDAG>, store: &Storage) {
    let fin = {
        let d = dag.read();
        d.selected_tip()
            .and_then(|t| load_state(store, &t))
            .filter(|st| st.finalized.height > st.activation)
            .and_then(|st| d.get_block_data(&st.finalized.hash).map(|bd| (st.finalized.hash, bd.height)))
    };
    if let Some((hash, height)) = fin {
        dag.write().set_finalized(hash, height);
    }
}
