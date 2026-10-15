//! Coherence shielded-pool primitives — the lean, portable core.
//!
//! Single source of truth shared by the node (`gnb::coherence` re-exports
//! this), any zkVM guest prover, and wallets. Implements the C1 formats:
//! SHAKE-256 note commitments, a SHAKE-256 incremental Merkle accumulator,
//! the nullifier set, and `check_spend` — the exact statement a spend proof
//! attests to. No node/std-heavy dependencies, so it compiles for a zkVM
//! target. (No guest prover lives in this repository; the node's only
//! compiled verifier is `RejectAll`.)
//!
//! # Spend statement version 2 (audit COH-1, internal CR-01)
//!
//! Version 1 of the statement took the nullifier key `nk` as a free witness:
//! anyone holding a note's plaintext could spend it, and one leaf yielded a
//! fresh nullifier for every `nk` the prover chose (8 spends of one 1,000-value
//! note all verified). Version 2 binds spending authority:
//!
//! ```text
//! sk                                  32-byte spending key (secret witness)
//! ak   = SHAKE256-32("gnb:coherence:ak:v2"  ‖ sk)
//! nk   = SHAKE256-32("gnb:coherence:nk:v2"  ‖ sk)
//! pk_d = SHAKE256-32("gnb:coherence:pkd:v2" ‖ ak ‖ nk)
//! nf   = SHAKE256-32("gnb:coherence:nf:v2"  ‖ nk ‖ cm ‖ position as u64 LE)
//! ```
//!
//! `check_spend` re-derives `ak`, `nk` and `pk_d` from the witness `sk`,
//! requires `pk_d` to equal the spent note's `pk_d`, and derives the
//! nullifier from that `nk`. SHAKE-256 is collision resistant, so a note's
//! `pk_d` determines `(ak, nk)`: each (leaf, position) has exactly one
//! nullifier, and only the holder of `sk` can produce it. `(ak, nk)` is a
//! viewing key: it recognises `pk_d` and computes nullifiers but cannot spend.
//! The byte-exact rule and golden vectors are in `docs/CONSENSUS.md`
//! ("Shielded spend statement v2"), pinned by `tests/statement_v2.rs`.

// I-4: no `unsafe` is needed anywhere in this crate (including the zkVM
// guest target), so forbid it outright rather than merely avoid it.
#![forbid(unsafe_code)]

use serde::{Serialize, Deserialize};
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};

pub const TREE_DEPTH: usize = 32;

const DOM_CM: &[u8] = b"gnb:coherence:cm:v1";
const DOM_MT: &[u8] = b"gnb:coherence:mt:v1";
// Statement v2: key hierarchy and nullifier (audit COH-1).
const DOM_AK: &[u8] = b"gnb:coherence:ak:v2";
const DOM_NK: &[u8] = b"gnb:coherence:nk:v2";
const DOM_PKD: &[u8] = b"gnb:coherence:pkd:v2";
const DOM_NF: &[u8] = b"gnb:coherence:nf:v2";

/// Version of the spend statement implemented by [`check_spend`].
///
/// Version 1 (withdrawn, audit COH-1) did not bind spending authority.
/// Version 2 derives the note's `pk_d` and the nullifier key from the
/// witness spending key (see the crate documentation).
pub const SPEND_STATEMENT_VERSION: u32 = 2;

/// True iff spend statement `version` proves spending authority: the
/// nullifier key is derived from a secret that also derives the note's
/// `pk_d`, so a note has exactly one nullifier. Version 2 and later do.
///
/// A node must never run an accepting proof verifier for a statement for
/// which this is false; the node's verifier guard checks it at compile time
/// and when a verifier is constructed.
pub const fn statement_binds_authority(version: u32) -> bool {
    version >= 2
}

/// SHAKE-256 squeezed to 32 bytes over the concatenation of `parts`.
fn shake256_32(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Shake256::default();
    for p in parts { h.update(p); }
    let mut xof = h.finalize_xof();
    let mut out = [0u8; 32];
    xof.read(&mut out);
    out
}

// ── Keys (statement v2) ──────────────────────────────────────────────────────

/// `ak = SHAKE256-32("gnb:coherence:ak:v2" ‖ sk)`: the authorizing half of the
/// viewing key.
pub fn derive_ak(sk: &[u8; 32]) -> [u8; 32] {
    shake256_32(&[DOM_AK, sk])
}

/// `nk = SHAKE256-32("gnb:coherence:nk:v2" ‖ sk)`: the nullifier key.
pub fn derive_nk(sk: &[u8; 32]) -> [u8; 32] {
    shake256_32(&[DOM_NK, sk])
}

/// `pk_d = SHAKE256-32("gnb:coherence:pkd:v2" ‖ ak ‖ nk)`: the recipient
/// value a note commits to. Computable from the viewing key `(ak, nk)`.
pub fn derive_pk_d(ak: &[u8; 32], nk: &[u8; 32]) -> [u8; 32] {
    shake256_32(&[DOM_PKD, ak, nk])
}

/// The `pk_d` of spending key `sk`: `derive_pk_d(derive_ak(sk), derive_nk(sk))`.
pub fn pk_d_from_sk(sk: &[u8; 32]) -> [u8; 32] {
    derive_pk_d(&derive_ak(sk), &derive_nk(sk))
}

// ── Notes ────────────────────────────────────────────────────────────────────

/// A shielded note (private).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Note {
    pub v: u64,
    pub pk_d: [u8; 32],
    pub rho: [u8; 32],
    pub psi: [u8; 32],
}

impl Note {
    /// cm = SHAKE256(DOM_CM ‖ v ‖ pk_d ‖ rho ‖ psi).
    pub fn commitment(&self) -> [u8; 32] {
        shake256_32(&[DOM_CM, &self.v.to_le_bytes(), &self.pk_d, &self.rho, &self.psi])
    }
    /// Statement-v2 nullifier of this note at `position` under nullifier key
    /// `nk`: `SHAKE256-32("gnb:coherence:nf:v2" ‖ nk ‖ cm ‖ position LE)`.
    ///
    /// Only the `nk` derived from the spending key that derives this note's
    /// `pk_d` gives a nullifier [`check_spend`] accepts.
    pub fn nullifier(&self, nk: &[u8; 32], position: u64) -> [u8; 32] {
        shake256_32(&[DOM_NF, nk, &self.commitment(), &position.to_le_bytes()])
    }
}

fn merkle_parent(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    shake256_32(&[DOM_MT, left, right])
}

// ── Nullifier set (sparse Merkle tree, SHAKE-256) — C1.1 ─────────────────────
//
// C1 froze "the global nullifier set" as consensus state but never defined its
// commitment; the set lived as a bare `HashSet` with no canonical root (finding
// F9 of `BLOCH-COHERENCE-UNDER-POS.md`). Under PoS that gap becomes load
// bearing: `state_root` must commit the set, so the set needs a root, and the
// root must be a function of the *set* rather than of anyone's insertion order.
//
// Ratified in `docs/specs/COHERENCE-C1.1.md`. This is an addition to C1, not a
// change to it: nothing C1 froze moves.

/// Domain tag for the nullifier-set tree. Distinct from `DOM_MT` so a node of
/// this tree can never be reinterpreted as a node of the commitment tree.
const DOM_NFSET: &[u8] = b"gnb:coherence:nfset:v1";

/// Depth of the nullifier-set tree: one level per bit of a nullifier.
///
/// The nullifier IS the key, so the tree spans the whole 256-bit keyspace and
/// membership is positional — there is no ordering to agree on and no leaf
/// index to assign. That is the difference from [`CommitmentTree`], where a
/// note's *position* is consensus (it is bound into the nullifier, §1.3) and
/// therefore insertion order is too.
pub const NFSET_DEPTH: usize = 256;

/// The leaf stored at an occupied key. Any fixed non-empty value works; this
/// one is domain-separated so it cannot collide with a hash of anything else.
fn nfset_present() -> [u8; 32] {
    shake256_32(&[DOM_NFSET, b"present"])
}

fn nfset_parent(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    shake256_32(&[DOM_NFSET, left, right])
}

/// `empty[d]` = root of an all-empty subtree of height `d`.
fn nfset_empty_roots() -> [[u8; 32]; NFSET_DEPTH + 1] {
    let mut e = [[0u8; 32]; NFSET_DEPTH + 1];
    e[0] = shake256_32(&[DOM_NFSET, b"empty-leaf"]);
    for d in 1..=NFSET_DEPTH {
        e[d] = nfset_parent(&e[d - 1], &e[d - 1]);
    }
    e
}

/// Bit `d` of `key`, MSB first — the direction taken at depth `d` walking down
/// from the root.
fn nfset_bit(key: &[u8; 32], d: usize) -> bool {
    (key[d / 8] >> (7 - (d % 8))) & 1 == 1
}

/// The spent-nullifier set and its canonical root.
///
/// A **sparse** Merkle tree keyed by the nullifier itself. Two properties are
/// the reason for choosing it over the cheaper running hash `H(prev ‖ nf)`:
///
/// 1. **The root is a function of the set.** A running hash makes insertion
///    order consensus, so two honest nodes that applied the same blocks in a
///    different order — or that undid and redid a reorg — would commit
///    different roots for identical state.
/// 2. **Non-membership is provable.** What a spend verifier actually needs is
///    "`nf` is *not* in the set as of this anchor", and a hash chain cannot
///    show that. [`NullifierSet::non_membership_proof`] returns the sibling
///    path; [`verify_non_membership`] checks it against a root, so a light
///    client or a pruning proof (§6.6.4) can be convinced without the set.
///
/// Insert-only in normal operation (§6.6.1); [`NullifierSet::remove`] exists
/// solely for reorg undo, driven by the block's recorded nullifiers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NullifierSet {
    /// Sorted for determinism: the root is computed by descending this slice,
    /// so the traversal — and therefore the hashing — is a function of the set.
    keys: Vec<[u8; 32]>,
}

impl NullifierSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from any iterator; duplicates collapse, order is irrelevant.
    pub fn from_iter<I: IntoIterator<Item = [u8; 32]>>(it: I) -> Self {
        let mut keys: Vec<[u8; 32]> = it.into_iter().collect();
        keys.sort_unstable();
        keys.dedup();
        Self { keys }
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn contains(&self, nf: &[u8; 32]) -> bool {
        self.keys.binary_search(nf).is_ok()
    }

    /// Insert `nf`. Returns false if it was already spent — which is the
    /// double-spend check itself, so callers must not ignore it.
    pub fn insert(&mut self, nf: [u8; 32]) -> bool {
        match self.keys.binary_search(&nf) {
            Ok(_) => false,
            Err(i) => {
                self.keys.insert(i, nf);
                true
            }
        }
    }

    /// Remove `nf` — **reorg undo only**. The set is monotone in normal
    /// operation; removing a nullifier that was not undone by a disconnected
    /// block would resurrect a spent note.
    pub fn remove(&mut self, nf: &[u8; 32]) -> bool {
        match self.keys.binary_search(nf) {
            Ok(i) => {
                self.keys.remove(i);
                true
            }
            Err(_) => false,
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.keys.iter()
    }

    /// The canonical root of the set.
    ///
    /// Computed by descending only where keys exist: an all-empty subtree
    /// short-circuits to its precomputed root, so the cost is bounded by the
    /// occupied paths rather than by the 2^256 keyspace.
    pub fn root(&self) -> [u8; 32] {
        let empty = nfset_empty_roots();
        Self::subtree_root(&self.keys, 0, &empty)
    }

    /// Root of the subtree at depth `d` spanning exactly `keys` (a contiguous,
    /// sorted slice of the keys that live under it).
    fn subtree_root(keys: &[[u8; 32]], d: usize, empty: &[[u8; 32]; NFSET_DEPTH + 1]) -> [u8; 32] {
        if keys.is_empty() {
            return empty[NFSET_DEPTH - d];
        }
        if d == NFSET_DEPTH {
            // A leaf: every key that reached here is the same key, since all
            // 256 bits have been consumed.
            return nfset_present();
        }
        // Sorted keys with a common prefix split on bit `d` into a zero-run
        // then a one-run, so the split point is a partition, not a filter.
        let split = keys.partition_point(|k| !nfset_bit(k, d));
        let l = Self::subtree_root(&keys[..split], d + 1, empty);
        let r = Self::subtree_root(&keys[split..], d + 1, empty);
        nfset_parent(&l, &r)
    }

    /// Sibling path proving `nf` is **absent**, root-to-leaf order reversed to
    /// leaf-to-root (index `d` is the sibling met at depth `NFSET_DEPTH-1-d`
    /// on the way up), matching [`verify_non_membership`].
    ///
    /// Returns `None` if `nf` is present — a caller asking for a proof of a
    /// spent nullifier has a bug, and a proof-shaped `None` is easier to
    /// notice than an unusable proof.
    pub fn non_membership_proof(&self, nf: &[u8; 32]) -> Option<Vec<[u8; 32]>> {
        if self.contains(nf) {
            return None;
        }
        let empty = nfset_empty_roots();
        let mut path = Vec::with_capacity(NFSET_DEPTH);
        let mut keys: &[[u8; 32]] = &self.keys;
        for d in 0..NFSET_DEPTH {
            let split = keys.partition_point(|k| !nfset_bit(k, d));
            let (mine, sibling) = if nfset_bit(nf, d) {
                (&keys[split..], &keys[..split])
            } else {
                (&keys[..split], &keys[split..])
            };
            path.push(Self::subtree_root(sibling, d + 1, &empty));
            keys = mine;
        }
        path.reverse();
        Some(path)
    }
}

/// Check a non-membership proof: walking the empty leaf up through `path` under
/// `nf`'s bits must reproduce `root`.
pub fn verify_non_membership(nf: &[u8; 32], path: &[[u8; 32]], root: &[u8; 32]) -> bool {
    if path.len() != NFSET_DEPTH {
        return false;
    }
    let empty = nfset_empty_roots();
    let mut node = empty[0];
    for (i, sibling) in path.iter().enumerate() {
        // `path` is leaf-to-root, so entry `i` is the sibling at depth
        // `NFSET_DEPTH - 1 - i`.
        let d = NFSET_DEPTH - 1 - i;
        node = if nfset_bit(nf, d) {
            nfset_parent(sibling, &node)
        } else {
            nfset_parent(&node, sibling)
        };
    }
    node == *root
}

// ── Commitment tree (incremental, fixed depth, SHAKE-256) ─────────────────────

/// `empty[d]` = root of an all-empty commitment subtree of height `d`.
fn mt_empty_roots() -> &'static [[u8; 32]; TREE_DEPTH + 1] {
    static EMPTY: std::sync::OnceLock<[[u8; 32]; TREE_DEPTH + 1]> = std::sync::OnceLock::new();
    EMPTY.get_or_init(|| {
        let mut e = [[0u8; 32]; TREE_DEPTH + 1];
        e[0] = shake256_32(&[DOM_MT, b"empty-leaf"]);
        for d in 1..=TREE_DEPTH {
            e[d] = merkle_parent(&e[d - 1], &e[d - 1]);
        }
        e
    })
}

/// Maximum number of leaves: positions must fit in `TREE_DEPTH` bits.
pub const TREE_CAPACITY: u64 = 1u64 << TREE_DEPTH;

/// Append-only Merkle accumulator of note commitments; the root is the anchor.
///
/// Incremental (audit COH-2): every node of the tree is kept, level by level,
/// so `append` and `truncate` cost `O(TREE_DEPTH)` hashes and `root` is a
/// lookup, instead of rehashing every leaf (the previous `root` and `path`
/// were `O(n)` each, which made applying a block quadratic). A node whose
/// right child does not exist yet is hashed with the empty subtree of that
/// height, exactly as the full recomputation does, so the roots and paths are
/// bit-identical to the previous implementation (property-tested against it).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommitmentTree {
    /// `levels[0]` are the leaves; `levels[d][i]` is the node of height `d`
    /// at index `i`; `levels[d].len() == ceil(len / 2^d)`. Empty until the
    /// first append, then `TREE_DEPTH + 1` levels.
    levels: Vec<Vec<[u8; 32]>>,
}

impl CommitmentTree {
    pub fn new() -> Self { Self { levels: Vec::new() } }

    /// Rebuild a tree from its leaves in order (`O(n)` hashes): used when the
    /// node reloads its persisted shielded state.
    ///
    /// # Panics
    /// If there are more than [`TREE_CAPACITY`] leaves.
    pub fn from_leaves(leaves: Vec<[u8; 32]>) -> Self {
        assert!(leaves.len() as u64 <= TREE_CAPACITY, "commitment tree over capacity");
        if leaves.is_empty() {
            return Self::new();
        }
        let empty = mt_empty_roots();
        let mut levels = Vec::with_capacity(TREE_DEPTH + 1);
        levels.push(leaves);
        for d in 1..=TREE_DEPTH {
            let below: &Vec<[u8; 32]> = &levels[d - 1];
            let next: Vec<[u8; 32]> = below
                .chunks(2)
                .map(|pair| merkle_parent(&pair[0], pair.get(1).unwrap_or(&empty[d - 1])))
                .collect();
            levels.push(next);
        }
        Self { levels }
    }

    /// Append `cm` and return its position.
    ///
    /// # Panics
    /// If the tree already holds [`TREE_CAPACITY`] leaves (callers check
    /// [`CommitmentTree::remaining_capacity`] first).
    pub fn append(&mut self, cm: [u8; 32]) -> u64 {
        let pos = self.len() as u64;
        assert!(pos < TREE_CAPACITY, "commitment tree full");
        if self.levels.is_empty() {
            self.levels = vec![Vec::new(); TREE_DEPTH + 1];
        }
        self.levels[0].push(cm);
        let mut idx = pos as usize;
        for d in 1..=TREE_DEPTH {
            idx >>= 1;
            self.set_node(d, idx);
        }
        pos
    }

    /// Recompute node `(d, idx)` from its children (d >= 1) and store it.
    fn set_node(&mut self, d: usize, idx: usize) {
        let empty = mt_empty_roots();
        let below = &self.levels[d - 1];
        let node = merkle_parent(&below[2 * idx], below.get(2 * idx + 1).unwrap_or(&empty[d - 1]));
        let level = &mut self.levels[d];
        if idx < level.len() {
            level[idx] = node;
        } else {
            level.push(node);
        }
    }

    /// Number of appended leaves (commitments).
    pub fn len(&self) -> usize { self.levels.first().map_or(0, Vec::len) }
    pub fn is_empty(&self) -> bool { self.len() == 0 }

    /// How many more leaves fit.
    pub fn remaining_capacity(&self) -> u64 { TREE_CAPACITY - self.len() as u64 }

    /// The leaves (commitments) in position order.
    pub fn leaves(&self) -> &[[u8; 32]] {
        self.levels.first().map_or(&[], Vec::as_slice)
    }

    /// Drop leaves back to the first `n` (reorg undo) in `O(TREE_DEPTH)`
    /// hashes. Truncating to a prior length restores the exact earlier root.
    pub fn truncate(&mut self, n: usize) {
        if n >= self.len() {
            return;
        }
        if n == 0 {
            self.levels.clear();
            return;
        }
        for (d, level) in self.levels.iter_mut().enumerate() {
            let keep = (n as u64 + (1u64 << d) - 1) >> d;
            level.truncate(keep as usize);
        }
        // The last node of every level may have lost its right child.
        for d in 1..=TREE_DEPTH {
            let last = self.levels[d].len() - 1;
            self.set_node(d, last);
        }
    }

    pub fn root(&self) -> [u8; 32] {
        match self.levels.get(TREE_DEPTH).and_then(|top| top.first()) {
            Some(r) => *r,
            None => mt_empty_roots()[TREE_DEPTH],
        }
    }

    /// Authentication path of the leaf at `index` (leaf-to-root siblings).
    pub fn path(&self, index: u64) -> Option<Vec<[u8; 32]>> {
        if index >= self.len() as u64 { return None; }
        let empty = mt_empty_roots();
        let mut idx = index as usize;
        let mut path = Vec::with_capacity(TREE_DEPTH);
        for (d, empty_d) in empty.iter().enumerate().take(TREE_DEPTH) {
            path.push(*self.levels[d].get(idx ^ 1).unwrap_or(empty_d));
            idx >>= 1;
        }
        Some(path)
    }
}

/// Verify a Merkle path: fold `leaf` up with `path` and compare to `root`.
///
/// `index` MUST address a leaf of a depth-`TREE_DEPTH` tree, i.e. it must fit
/// in `TREE_DEPTH` bits. The fold below consumes exactly one bit per level and
/// would otherwise silently discard everything above bit `TREE_DEPTH`, so
/// `index` and `index | (1 << TREE_DEPTH)` (and any other setting of the high
/// bits) would authenticate against the SAME path and root. That is not a
/// cosmetic laxity: a note's *position* is bound into its nullifier
/// (`Note::nullifier`, over the full `u64`), so an unconstrained high half
/// would let one note in the tree be spent under 2^(64-TREE_DEPTH) distinct
/// nullifiers — unbounded double-spend of the shielded pool. Reject instead.
pub fn verify_path(leaf: &[u8; 32], index: u64, path: &[[u8; 32]], root: &[u8; 32]) -> bool {
    if path.len() != TREE_DEPTH { return false; }
    // The fold reads TREE_DEPTH bits; anything above them must be zero.
    if index >> TREE_DEPTH != 0 { return false; }
    let mut cur = *leaf;
    let mut idx = index;
    for sib in path {
        cur = if idx & 1 == 0 { merkle_parent(&cur, sib) } else { merkle_parent(sib, &cur) };
        idx >>= 1;
    }
    &cur == root
}

// ── Spend statement (the SP1 guest logic; proved in ZK) ───────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendPublic {
    pub anchor: [u8; 32],
    pub nullifiers: Vec<[u8; 32]>,
    pub out_commitments: Vec<[u8; 32]>,
    pub fee: u64,
}

/// One spent note in the private witness.
#[derive(Clone, Serialize, Deserialize)]
pub struct SpendInput {
    pub note: Note,
    pub position: u64,
    pub path: Vec<[u8; 32]>,
    /// The spending key whose derived `pk_d` equals `note.pk_d` (statement
    /// v2). The nullifier key is derived from it, never chosen freely.
    pub sk: [u8; 32],
}

/// Redacts the spending key.
impl std::fmt::Debug for SpendInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpendInput")
            .field("note", &self.note)
            .field("position", &self.position)
            .field("path_len", &self.path.len())
            .field("sk", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendWitness {
    pub inputs: Vec<SpendInput>,
    pub outputs: Vec<Note>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpendError {
    Membership(usize),
    /// `inputs[i].position` does not fit in `TREE_DEPTH` bits, so it does not
    /// name a leaf of the commitment tree. Kept distinct from `Membership` so
    /// the rejection reason is unambiguous: the witness is malformed, not
    /// merely non-member. See [`verify_path`] for why this must be rejected.
    PositionOutOfRange(usize),
    /// `inputs[i].sk` does not derive `inputs[i].note.pk_d`: the prover does
    /// not hold the note's spending key (statement v2, audit COH-1).
    Unauthorized(usize),
    Nullifier(usize),
    /// The same commitment-tree position occurs more than once in this spend.
    DuplicateInputPosition(usize),
    OutputCommitment(usize),
    /// public.nullifiers.len() != witness.inputs.len().
    NullifierCountMismatch { public: usize, witness: usize },
    /// public.out_commitments.len() != witness.outputs.len().
    OutputCountMismatch { public: usize, witness: usize },
    Overflow,
    Unbalanced { inputs: u128, outputs: u128, fee: u64 },
}

/// Spend statement version [`SPEND_STATEMENT_VERSION`] (2): what a spend
/// proof attests to, evaluated on the PRIVATE witness.
///
/// For every input `i`: its position names a leaf of the depth-`TREE_DEPTH`
/// tree, its note commitment is a member under `public.anchor`, the witness
/// spending key derives the note's `pk_d` (spending authority), and
/// `public.nullifiers[i]` is the nullifier derived from that key's `nk`.
/// Inputs occupy distinct positions, the public vectors match the witness
/// one-for-one, every output commitment opens to its witness note, and value
/// balances (`Σ inputs = Σ outputs + fee`). A note therefore has exactly one
/// nullifier, and only the holder of its spending key can produce it.
pub fn check_spend(public: &SpendPublic, w: &SpendWitness) -> Result<(), SpendError> {
    // Bind the public vectors to the witness EXACTLY (C2 fix). Without these
    // binds a prover could append extra public out_commitments beyond the
    // witness outputs — commitments the balance check never sees — and mint
    // unbacked notes into the tree (shielded counterfeiting); likewise the
    // nullifier count must match the spent inputs one-for-one.
    if public.out_commitments.len() != w.outputs.len() {
        return Err(SpendError::OutputCountMismatch {
            public: public.out_commitments.len(),
            witness: w.outputs.len(),
        });
    }
    if public.nullifiers.len() != w.inputs.len() {
        return Err(SpendError::NullifierCountMismatch {
            public: public.nullifiers.len(),
            witness: w.inputs.len(),
        });
    }
    // A leaf is one funded input: reject repeated positions before membership
    // work so one leaf is never counted twice in one witness. (Across separate
    // spends the derived nullifier is unique per leaf, so the nullifier set
    // refuses a second spend.)
    let mut positions = std::collections::BTreeSet::new();
    for (i, input) in w.inputs.iter().enumerate() {
        if !positions.insert(input.position) {
            return Err(SpendError::DuplicateInputPosition(i));
        }
    }
    let mut in_sum: u128 = 0;
    for (i, inp) in w.inputs.iter().enumerate() {
        // The position is bound into the nullifier over the full u64, but only
        // its low TREE_DEPTH bits address a leaf. Reject the high half here
        // (mirroring the same guard inside `verify_path`) so a spend can never
        // pair one tree leaf with a second, distinct nullifier.
        if inp.position >> TREE_DEPTH != 0 {
            return Err(SpendError::PositionOutOfRange(i));
        }
        let cm = inp.note.commitment();
        if !verify_path(&cm, inp.position, &inp.path, &public.anchor) {
            return Err(SpendError::Membership(i));
        }
        // Spending authority (statement v2): the witness key must derive the
        // note's recipient value, and the nullifier key is the one it derives.
        let nk = derive_nk(&inp.sk);
        if derive_pk_d(&derive_ak(&inp.sk), &nk) != inp.note.pk_d {
            return Err(SpendError::Unauthorized(i));
        }
        let nf = inp.note.nullifier(&nk, inp.position);
        if public.nullifiers.get(i) != Some(&nf) {
            return Err(SpendError::Nullifier(i));
        }
        in_sum = in_sum.checked_add(inp.note.v as u128).ok_or(SpendError::Overflow)?;
    }
    let mut out_sum: u128 = 0;
    for (i, out) in w.outputs.iter().enumerate() {
        if public.out_commitments.get(i) != Some(&out.commitment()) {
            return Err(SpendError::OutputCommitment(i));
        }
        out_sum = out_sum.checked_add(out.v as u128).ok_or(SpendError::Overflow)?;
    }
    if in_sum != out_sum + public.fee as u128 {
        return Err(SpendError::Unbalanced { inputs: in_sum, outputs: out_sum, fee: public.fee });
    }
    Ok(())
}

// ── Shielded transaction (wire type) ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldedTx {
    pub anchor: [u8; 32],
    pub nullifiers: Vec<[u8; 32]>,
    pub outputs: Vec<[u8; 32]>,
    pub fee: u64,
    pub proof: Vec<u8>,
    pub binding_sig: Vec<u8>,
}

impl ShieldedTx {
    pub fn public(&self) -> SpendPublic {
        SpendPublic {
            anchor: self.anchor,
            nullifiers: self.nullifiers.clone(),
            out_commitments: self.outputs.clone(),
            fee: self.fee,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(v: u64, tag: u8) -> Note {
        // Statement v2: the recipient value is derived from the spending key
        // `[tag; 32]`, so `sk = [tag; 32]` is the key that may spend it.
        Note { v, pk_d: pk_d_from_sk(&[tag; 32]), rho: [tag ^ 0x11; 32], psi: [tag ^ 0x22; 32] }
    }

    #[test]
    fn commitment_and_nullifier_are_deterministic_and_distinct() {
        let n = note(100, 1);
        assert_eq!(n.commitment(), n.commitment());
        assert_ne!(n.commitment(), n.nullifier(&[9; 32], 0));
        assert_ne!(n.nullifier(&[9; 32], 0), n.nullifier(&[9; 32], 1));
    }

    #[test]
    fn merkle_membership_roundtrips() {
        let mut t = CommitmentTree::new();
        let cms: Vec<_> = (0..5u8).map(|i| note(i as u64, i).commitment()).collect();
        for cm in &cms { t.append(*cm); }
        let root = t.root();
        for (i, cm) in cms.iter().enumerate() {
            let path = t.path(i as u64).unwrap();
            assert!(verify_path(cm, i as u64, &path, &root));
        }
        assert!(!verify_path(&[0xAB; 32], 0, &t.path(0).unwrap(), &root));
    }

    #[test]
    fn check_spend_accepts_valid_and_rejects_inflation_and_forgery() {
        let mut t = CommitmentTree::new();
        let inp = note(1000, 7);
        let pos = t.append(inp.commitment());
        let anchor = t.root();
        let path = t.path(pos).unwrap();
        let sk = [7u8; 32];
        let nk = derive_nk(&sk);

        let out = note(900, 8);
        let public = SpendPublic {
            anchor, nullifiers: vec![inp.nullifier(&nk, pos)],
            out_commitments: vec![out.commitment()], fee: 100,
        };
        let w = SpendWitness {
            inputs: vec![SpendInput { note: inp.clone(), position: pos, path: path.clone(), sk }],
            outputs: vec![out],
        };
        assert_eq!(check_spend(&public, &w), Ok(()));

        // inflation
        let big = note(5000, 8);
        let pub2 = SpendPublic {
            anchor, nullifiers: vec![inp.nullifier(&nk, pos)],
            out_commitments: vec![big.commitment()], fee: 0,
        };
        let w2 = SpendWitness {
            inputs: vec![SpendInput { note: inp.clone(), position: pos, path: path.clone(), sk }],
            outputs: vec![big],
        };
        assert!(matches!(check_spend(&pub2, &w2), Err(SpendError::Unbalanced { .. })));

        // forged membership
        let bad = SpendPublic { anchor: [0xCD; 32], ..public.clone() };
        assert!(matches!(check_spend(&bad, &w), Err(SpendError::Membership(0))));
    }

    /// C2 regression: the public vectors must be bound to the witness lengths.
    /// Extra public out_commitments (unseen by the balance check) were the
    /// counterfeiting vector: a proof over N witness outputs would also attest
    /// to an N+1-th unbacked commitment entering the tree.
    #[test]
    fn check_spend_binds_public_counts_to_witness() {
        let mut t = CommitmentTree::new();
        let inp = note(1000, 7);
        let pos = t.append(inp.commitment());
        let anchor = t.root();
        let path = t.path(pos).unwrap();
        let sk = [7u8; 32];
        let nk = derive_nk(&sk);
        let out = note(900, 8);

        let honest = SpendPublic {
            anchor,
            nullifiers: vec![inp.nullifier(&nk, pos)],
            out_commitments: vec![out.commitment()],
            fee: 100,
        };
        let w = SpendWitness {
            inputs: vec![SpendInput { note: inp.clone(), position: pos, path, sk }],
            outputs: vec![out.clone()],
        };

        // (c) honest spend with matching lengths still verifies.
        assert_eq!(check_spend(&honest, &w), Ok(()));

        // (a) N witness outputs but N+1 public out_commitments must fail:
        // the smuggled commitment would mint an unbacked 1M-value note.
        let smuggled = note(1_000_000, 9);
        let mut inflated = honest.clone();
        inflated.out_commitments.push(smuggled.commitment());
        assert_eq!(
            check_spend(&inflated, &w),
            Err(SpendError::OutputCountMismatch { public: 2, witness: 1 })
        );

        // (b) N witness inputs but fewer public nullifiers must fail with the
        // distinct count-mismatch error (an input spent without publishing its
        // nullifier could be double-spent).
        let mut missing_nf = honest.clone();
        missing_nf.nullifiers.clear();
        assert_eq!(
            check_spend(&missing_nf, &w),
            Err(SpendError::NullifierCountMismatch { public: 0, witness: 1 })
        );

        // Extra public nullifiers beyond the witness inputs must also fail:
        // unproven nullifiers would burn notes the witness never opened.
        let mut extra_nf = honest.clone();
        extra_nf.nullifiers.push([0xEE; 32]);
        assert_eq!(
            check_spend(&extra_nf, &w),
            Err(SpendError::NullifierCountMismatch { public: 2, witness: 1 })
        );
    }

    /// C4 regression: the position must be constrained to TREE_DEPTH bits.
    ///
    /// `verify_path` folds exactly `TREE_DEPTH` levels, consuming one bit of
    /// `index` per level, and used to drop everything above bit `TREE_DEPTH` on
    /// the floor. `Note::nullifier`, however, hashes the FULL u64 position. So
    /// `pos` and `pos | (1 << TREE_DEPTH)` authenticated against the identical
    /// path and anchor while producing DIFFERENT nullifiers: one note in the
    /// tree, 2^(64-TREE_DEPTH) spendable identities, i.e. unbounded
    /// double-spend of the shielded pool.
    ///
    /// Both assertions below fail without the guard: the first returns `true`,
    /// the second returns `Ok(())`.
    #[test]
    fn position_high_bits_are_rejected_by_path_and_spend() {
        let mut t = CommitmentTree::new();
        let inp = note(1000, 7);
        let pos = t.append(inp.commitment());
        let anchor = t.root();
        let path = t.path(pos).unwrap();
        let sk = [7u8; 32];
        let nk = derive_nk(&sk);

        // Sanity: the honest position verifies.
        assert!(verify_path(&inp.commitment(), pos, &path, &anchor));

        // The aliased position hashes to a DIFFERENT nullifier — that is what
        // makes the missing bound a double-spend rather than a curiosity.
        let alias = pos | (1u64 << TREE_DEPTH);
        assert_ne!(inp.nullifier(&nk, pos), inp.nullifier(&nk, alias));

        // ... and it must NOT authenticate against the same path/anchor.
        assert!(
            !verify_path(&inp.commitment(), alias, &path, &anchor),
            "position {alias} aliases leaf {pos}: high bits above TREE_DEPTH were ignored"
        );

        // A few more settings of the high half, including the top bit.
        for extra in [1u64 << 32, 1u64 << 40, 1u64 << 63, u64::MAX << TREE_DEPTH] {
            assert!(!verify_path(&inp.commitment(), pos | extra, &path, &anchor));
        }

        // check_spend mirrors the guard with its own distinct error: a spend
        // that reuses the same leaf under the aliased position is rejected as
        // malformed, not accepted as a second, independent note.
        let out = note(900, 8);
        let public = SpendPublic {
            anchor,
            nullifiers: vec![inp.nullifier(&nk, alias)],
            out_commitments: vec![out.commitment()],
            fee: 100,
        };
        let w = SpendWitness {
            inputs: vec![SpendInput {
                note: inp.clone(),
                position: alias,
                path: path.clone(),
                sk,
            }],
            outputs: vec![out.clone()],
        };
        assert_eq!(check_spend(&public, &w), Err(SpendError::PositionOutOfRange(0)));

        // The honest spend at the same leaf is unaffected.
        let honest = SpendPublic {
            anchor,
            nullifiers: vec![inp.nullifier(&nk, pos)],
            out_commitments: vec![out.commitment()],
            fee: 100,
        };
        let hw = SpendWitness {
            inputs: vec![SpendInput { note: inp, position: pos, path, sk }],
            outputs: vec![out],
        };
        assert_eq!(check_spend(&honest, &hw), Ok(()));
    }
}

#[cfg(test)]
mod nfset_tests {
    use super::*;

    fn nf(b: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = b;
        k[31] = b ^ 0xFF;
        k
    }

    /// The root is a function of the SET. This is the property a running hash
    /// `H(prev ‖ nf)` cannot have, and the reason it was rejected: insertion
    /// order would become consensus, so two nodes that applied the same blocks
    /// in a different order — or undid and redid a reorg — would commit
    /// different roots for identical state.
    #[test]
    fn root_depends_on_the_set_not_the_order() {
        let a = NullifierSet::from_iter([nf(1), nf(2), nf(3)]);
        let b = NullifierSet::from_iter([nf(3), nf(1), nf(2)]);
        let c = NullifierSet::from_iter([nf(2), nf(2), nf(1), nf(3), nf(3)]);
        assert_eq!(a.root(), b.root());
        assert_eq!(a.root(), c.root(), "duplicates must collapse");

        let mut d = NullifierSet::new();
        for k in [nf(3), nf(1), nf(2)] {
            assert!(d.insert(k));
        }
        assert_eq!(a.root(), d.root(), "incremental inserts must agree with a bulk build");
    }

    /// Every distinct set commits distinctly, including the empty one — which
    /// must not be the zero root, or "no pool" and "an unset field" would be
    /// indistinguishable in the state tree.
    #[test]
    fn distinct_sets_commit_distinctly() {
        let empty = NullifierSet::new().root();
        assert_ne!(empty, [0u8; 32]);
        let one = NullifierSet::from_iter([nf(1)]).root();
        let two = NullifierSet::from_iter([nf(1), nf(2)]).root();
        assert_ne!(empty, one);
        assert_ne!(one, two);
    }

    /// Insert reports the double-spend. The return value IS the check.
    #[test]
    fn reinserting_a_spent_nullifier_is_refused() {
        let mut s = NullifierSet::new();
        assert!(s.insert(nf(7)));
        assert!(!s.insert(nf(7)));
        assert_eq!(s.len(), 1);
    }

    /// Reorg undo restores the exact earlier root — the property that makes a
    /// disconnect safe. Without it a reorg would leave the chain committing a
    /// root no honest node could reproduce.
    #[test]
    fn removing_an_undone_nullifier_restores_the_earlier_root() {
        let mut s = NullifierSet::from_iter([nf(1), nf(2)]);
        let before = s.root();
        assert!(s.insert(nf(9)));
        assert_ne!(s.root(), before);
        assert!(s.remove(&nf(9)));
        assert_eq!(s.root(), before);
    }

    /// Non-membership verifies against the root, and stops verifying the
    /// moment the nullifier is spent — which is the whole point: a spend
    /// verifier proves `nf ∉ set` at the anchor.
    #[test]
    fn non_membership_proves_absence_and_only_absence() {
        let mut s = NullifierSet::from_iter([nf(1), nf(2), nf(3)]);
        let root = s.root();
        let absent = nf(42);

        let proof = s.non_membership_proof(&absent).expect("absent key has a proof");
        assert_eq!(proof.len(), NFSET_DEPTH);
        assert!(verify_non_membership(&absent, &proof, &root));

        // The security-relevant negative: the proof must NOT verify for a key
        // that IS in the set. (It *will* verify for other absent keys whose
        // path meets the same siblings — in a sparse tree an all-empty path
        // proves the whole region empty, so one proof legitimately covers many
        // absent keys. That is a property of the structure, not a weakness:
        // what a verifier concludes is "this key is absent", which is true for
        // every key the proof covers.)
        assert!(!verify_non_membership(&nf(1), &proof, &root), "a spent key verified as absent");
        // Nor against a different root.
        let other = NullifierSet::from_iter([nf(1)]).root();
        assert!(!verify_non_membership(&absent, &proof, &other));

        // Once spent, there is no proof of absence and the old one dies.
        s.insert(absent);
        assert!(s.non_membership_proof(&absent).is_none());
        assert!(!verify_non_membership(&absent, &proof, &s.root()));
    }

    /// A tampered path is rejected. Without this the verifier could be
    /// accepting any 256 hashes of the right length.
    #[test]
    fn tampered_paths_are_rejected() {
        let s = NullifierSet::from_iter([nf(1), nf(2)]);
        let root = s.root();
        let absent = nf(200);
        let good = s.non_membership_proof(&absent).unwrap();

        for i in [0usize, 1, NFSET_DEPTH / 2, NFSET_DEPTH - 1] {
            let mut bad = good.clone();
            bad[i][0] ^= 1;
            assert!(!verify_non_membership(&absent, &bad, &root), "tamper at {i} accepted");
        }
        let mut short = good.clone();
        short.pop();
        assert!(!verify_non_membership(&absent, &short, &root));
    }

    /// The nullifier-set tree and the commitment tree must never share a node
    /// value for the same inputs — different domain tags, checked rather than
    /// assumed.
    #[test]
    fn nfset_domain_is_separate_from_the_commitment_tree() {
        let l = nf(1);
        let r = nf(2);
        assert_ne!(nfset_parent(&l, &r), merkle_parent(&l, &r));
        assert_ne!(NullifierSet::new().root(), CommitmentTree::new().root());
    }
}
