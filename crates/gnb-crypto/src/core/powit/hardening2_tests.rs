//! PoWit at the second hardening activation (Phase-5 audit of the PoWit
//! line, findings 1 and 4): what the state machine did before, pinned, and
//! what it does from the activation.
//!
//! Real hybrid KES keys and signatures throughout; a simulated selected chain.

use super::*;
use crate::core::kes::{KesPublic, KesSigner};
use crate::core::ChainId;
use std::cell::RefCell;

const CHAIN: ChainId = ChainId::Testnet;
const P: PowitParams = TESTNET_PARAMS;
const ACT: u64 = 1_000;

fn sha3(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn hash(fork: u8, h: u64) -> [u8; 32] {
    let mut x = [0u8; 32];
    x[..8].copy_from_slice(&h.to_le_bytes());
    x[8] = fork;
    x
}

/// A linear selected chain: `hash(fork, h)` below `tip`.
struct Chain {
    fork: u8,
    tip: u64,
}

impl ChainView for Chain {
    fn selected_at(&self, height: u64) -> Option<[u8; 32]> {
        (height < self.tip).then(|| hash(self.fork, height))
    }
}

fn cp(fork: u8, h: u64) -> Checkpoint {
    Checkpoint { height: h, hash: hash(fork, h) }
}

/// A genuine KES witness key (every leaf derived, as `gnb-cli witnesskeygen`).
struct Key {
    signer: RefCell<KesSigner>,
}

impl Key {
    fn new(seed: u8, depth: u8) -> Key {
        Key { signer: RefCell::new(KesSigner::generate(depth, [seed; 32], |_| {}).unwrap()) }
    }
    fn id(&self) -> KeyId {
        self.signer.borrow().public().witness_id()
    }
    /// Sign with the leaf of the target's epoch (evolving forward).
    fn attest(&self, source: Checkpoint, target: Checkpoint) -> Attestation {
        let e = P.epoch(ACT, target.height);
        let mut s = self.signer.borrow_mut();
        if e > s.epoch() {
            s.evolve_to(e).unwrap();
        }
        assert_eq!(e, s.epoch(), "tests sign epochs in order");
        Attestation::sign(CHAIN, source, target, &s).unwrap()
    }
}

/// Finding 1's forgery: the signed message does not depend on the witness
/// key and `kes::verify` only checks that the leaf plus the supplied path
/// reach the root, so a leaf signature re-rooted under any sibling hash is a
/// signature by another depth-1 key (one SHA3 per key).
fn reroot(a: &Attestation, sibling: [u8; 32]) -> Attestation {
    let mut a = a.clone();
    let leaf = sha3(&[b"GNB-KES-v1/pk", &a.sig.leaf_pk]);
    a.sig.path = vec![sibling];
    let root = if a.sig.index & 1 == 0 {
        sha3(&[b"GNB-KES-v1/node", &leaf, &sibling])
    } else {
        sha3(&[b"GNB-KES-v1/node", &sibling, &leaf])
    };
    a.witness = KesPublic { depth: 1, root };
    a
}

/// One depth-1 leaf's double vote (epoch 1, slot ACT + 35), re-rooted per
/// sibling into as many distinct witnesses as wanted.
struct Forger {
    a: Attestation,
    b: Attestation,
}

impl Forger {
    fn new(seed: u8) -> Forger {
        let mut s = KesSigner::generate(1, [seed; 32], |_| {}).unwrap();
        s.evolve_to(1).unwrap();
        let src = cp(0, ACT);
        let a = Attestation::sign(CHAIN, src, cp(0, ACT + 35), &s).unwrap();
        let b = Attestation::sign(CHAIN, src, cp(9, ACT + 35), &s).unwrap();
        Forger { a, b }
    }
    fn sibling(i: u64) -> [u8; 32] {
        sha3(&[b"sibling", &i.to_le_bytes()])
    }
    fn equivocation(&self, i: u64) -> Equivocation {
        let s = Self::sibling(i);
        Equivocation { a: reroot(&self.a, s), b: reroot(&self.b, s) }
    }
}

/// Digest of a state: SHA3 of its bincode encoding (the node stores states
/// with this encoding, `node/src/powit.rs`); every map is ordered.
fn state_digest(st: &PowitState) -> [u8; 32] {
    let bytes = bincode::serde::encode_to_vec(st, bincode::config::standard()).unwrap();
    sha3(&[&bytes])
}

// ── The pinned scenario ──────────────────────────────────────────────────────

/// Filler share keys: 70 ids of weight 100 per block, so the 64-member cap
/// cuts 9 of them off and the two-thirds rule depends on it.
fn fillers() -> Vec<KeyId> {
    (0..70u8).map(|i| [0x80 ^ i; 20]).collect()
}

/// What a block carries in [`scenario`].
type Step<'a> = (Vec<(KeyId, u128)>, Vec<Attestation>, Vec<Equivocation>);

/// A run through everything the PoWit transition does: shares from three
/// genuine witnesses (4,300 per block each) and 70 fillers (100 each),
/// justification and finality (c1 = ACT+45, c2 = ACT+50, c3 = ACT+55), a
/// genuine double vote that bars key 2, a forged (re-rooted) equivocation, a
/// stall long enough for inactivity decay, and votes resuming. `apply` is
/// the transition under test. Returns every state, `ACT+1..=ACT+180`.
fn scenario(apply: &dyn Fn(&PowitState, &BlockInput<'_>, &Chain) -> Result<PowitState, String>)
    -> Vec<PowitState>
{
    let keys: Vec<Key> = (1..=3).map(|s| Key::new(s, 4)).collect();
    let ids: Vec<KeyId> = keys.iter().map(Key::id).collect();
    let fill = fillers();
    let forger = Forger::new(40);
    let mut st = PowitState::genesis(ACT, hash(0, ACT));
    let mut out = Vec::new();
    let (c1, c2, c3) = (ACT + 45, ACT + 50, ACT + 55);
    for h in ACT + 1..=ACT + 180 {
        let e = P.epoch(ACT, h);
        let mut shares: Vec<(KeyId, u128)> = Vec::new();
        for (i, k) in ids.iter().enumerate() {
            if !(i == 2 && st.is_banned(k, e)) && !(i == 2 && (ACT + 57..ACT + 60).contains(&h)) {
                shares.push((*k, 4_300));
            }
        }
        shares.extend(fill.iter().map(|k| (*k, 100)));
        let src = st.justified;
        let step: Step = match h {
            _ if h == c1 + 1 || h == c2 + 1 || h == c3 + 1 => {
                let t = h - 1;
                (shares, keys.iter().map(|k| k.attest(src, cp(0, t))).collect(), vec![])
            }
            // Key 2 signs a second target for c3 (a double vote): proven.
            _ if h == c3 + 2 => {
                let other = keys[2].attest(cp(0, c2), cp(7, c3));
                let first = keys[2].attest(cp(0, c2), cp(0, c3));
                (shares, vec![], vec![Equivocation { a: first, b: other }])
            }
            // A forged proof against a key nobody holds work for.
            _ if h == c3 + 3 => (shares, vec![], vec![forger.equivocation(1)]),
            // Votes resume after the stall: every unbarred genuine key.
            _ if h >= ACT + 166 && P.is_checkpoint(ACT, h - 1) && h - 1 > st.justified.height => {
                let t = h - 1;
                let voters = keys.iter().zip(&ids).filter(|(_, id)| !st.is_banned(id, e));
                (shares, voters.map(|(k, _)| k.attest(src, cp(0, t))).collect(), vec![])
            }
            _ => (shares, vec![], vec![]),
        };
        let (sw, atts, ev) = step;
        let input = BlockInput { height: h, hash: hash(0, h), share_work: &sw, attestations: &atts, evidence: &ev };
        st = apply(&st, &input, &Chain { fork: 0, tip: h }).unwrap_or_else(|err| panic!("h={h}: {err}"));
        out.push(st.clone());
    }
    out
}

/// The digest over every state of [`scenario`] under the transition as it was
/// before the second hardening activation existed (computed on 71c2262).
const OLD_REGIME_DIGEST: &str = "32fa7a109f4e418344b0606f7120b827754dbd0348b623f07cb6b6d4845b28aa";

fn chain_digest(states: &[PowitState]) -> String {
    let mut h = Sha3_256::new();
    for s in states {
        h.update(state_digest(s));
    }
    hex::encode(h.finalize())
}

/// Below the second hardening activation the PoWit transition is
/// bit-identical to the one that produced the existing chain: the scenario's
/// states hash to the digest pinned from the code before the change.
#[test]
fn old_regime_transition_is_pinned() {
    let states = scenario(&|s, b, v| s.apply(&P, CHAIN, b, v));
    // The scenario does what it says.
    let at = |h: u64| &states[(h - ACT - 1) as usize];
    assert_eq!(at(ACT + 46).justified, cp(0, ACT + 45));
    assert_eq!(at(ACT + 51).finalized, cp(0, ACT + 45));
    assert_eq!(at(ACT + 56).finalized, cp(0, ACT + 50));
    assert_eq!(at(ACT + 57).banned.len(), 1, "key 2's double vote bars it");
    assert_eq!(at(ACT + 58).banned.len(), 2, "the forged proof bars a key nobody holds");
    assert!(!at(ACT + 160).decay.is_empty(), "the stall decays absent members");
    assert_eq!(chain_digest(&states), OLD_REGIME_DIGEST);
}

