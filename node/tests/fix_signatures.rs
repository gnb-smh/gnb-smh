//! Regression tests for the transaction-signature fixes of the 2026-10-14
//! audit, gated at the hardening activation height: CRY-3 (sighash v3, the
//! transaction-version rule), CRY-2 (component-bound signatures, suite 0x0002
//! non-standard), CRY-1 (canonical witnesses: consensus from the activation,
//! policy at every height), WAL-1 (signers produce version 3 from the
//! activation; a lied amount or script invalidates the signature) and the
//! MEM-5 residual (linear sighash).
//!
//! Every test moves the activation to a small height `H` on its own thread
//! (`activation::scoped_override`), so the node rules (`accept_block`,
//! connect, reorg connect, templates, mempool admission) and the wallet
//! signers all see the same boundary. Blocks go through the REAL pipeline
//! (`fix_common::accept` -> `accept::accept_block`).
//!
//! Review follow-ups: below the activation every transaction (version 3
//! included) keeps the pre-upgrade verdict and version >= 3 is refused only by
//! relay policy; the verified-signature cache is keyed by regime and prevouts;
//! mempool admission, post-connect eviction, re-injection, templates and
//! wallets share ONE next-block height (the node's template height), also in
//! DAG shapes where a block's header height exceeds its DAG height (DAG-8);
//! `admit` re-checks that height under the acceptance lock.

mod fix_common;
use fix_common::*;

use std::sync::atomic::{AtomicU64, Ordering};

use gnb::consensus::BlockHash;
use gnb::core::sighash::{SighashV3Precomputed, SighashVersion, SIGHASH_V3_PREIMAGE_LEN};
use gnb::core::{self, activation, Block, ChainId, Transaction, TxInput, TxOutput};
use gnb::crypto;
use gnb::mempool::admission::{self, AdmissionError, AdmissionPolicy};
use gnb::mempool::relay::TxRelay;
use gnb::network::GossipVerdict;
use gnb::template;
use libp2p::PeerId;
use gnb::wallet::payment::{FeeChoice, FeePolicy};
use gnb::wallet::send;
use serde_json::{json, Value};
use sha3::{Digest, Sha3_256};

/// Activation height used by every test (blocks 1..H-1 old rules, H.. new).
const H: u64 = 4;
const FEE: u64 = 100_000;
const SAT: u64 = 100_000_000;

// ── Fixtures ─────────────────────────────────────────────────────────────────

fn chain() -> ChainId {
    core::node_chain_id()
}

fn spk_of(pk: &[u8]) -> Vec<u8> {
    Sha3_256::digest(pk)[..20].to_vec()
}

/// A genesis carry-over style key: the address commits to the RAW public key
/// (no suite envelope); the secret key is kept enveloped for the signer.
fn raw_carryover_key() -> Key {
    let k = key();
    let pk = k.pk[crypto::SUITE_HEADER_LEN..].to_vec();
    Key { spk: spk_of(&pk), pk, sk: k.sk }
}

/// The suite-0x0002 (ML-DSA-65 only) key over the SAME ML-DSA body as `k`.
fn mldsa_only_key(k: &Key) -> Key {
    let env = |body: &[u8]| {
        let mut v = vec![0xB1, 0x0C, 0x02, 0x00];
        v.extend_from_slice(body);
        v
    };
    let h = crypto::SUITE_HEADER_LEN;
    let pk = env(&k.pk[h..h + crypto::MLDSA_PUBKEY_LEN]);
    let sk = env(&k.sk[h..h + crypto::MLDSA_SECRET_LEN]);
    Key { spk: spk_of(&pk), pk, sk }
}

fn fund(tag: u8, value: u64, spk: &[u8]) -> ([u8; 32], u32, TxOutput) {
    ([tag; 32], 0, out(value, spk))
}

fn unsigned(version: u32, ins: &[([u8; 32], u32)], outs: Vec<TxOutput>) -> Transaction {
    Transaction {
        version,
        inputs: ins.iter().map(|(t, i)| TxInput { prev_txid: *t, prev_index: *i, script_sig: vec![], sequence: u32::MAX }).collect(),
        outputs: outs,
        locktime: 0,
    }
}

/// A signature that leaves room for the 1,280-byte padded Falcon form and
/// whose body does not start with the envelope magic (so the "envelope
/// stripped" mutation stays a well-defined legacy signature).
fn roomy(mut sign: impl FnMut() -> Vec<u8>) -> Vec<u8> {
    let room = crypto::SUITE_HEADER_LEN + crypto::MLDSA_SIG_LEN + crypto::falcon::padded_signature_len();
    loop {
        let s = sign();
        if s.len() < room && s[4..6] != [0xB1, 0x0C] {
            return s;
        }
    }
}

/// Sighash-v2 signatures (the historical signer) on every input.
fn sign_v2(k: &Key, mut tx: Transaction) -> Transaction {
    for i in 0..tx.inputs.len() {
        let d = tx.sighash(i, chain());
        let sig = roomy(|| crypto::sign(&k.sk, &d).unwrap());
        tx.inputs[i].script_sig = Transaction::build_script_sig(&sig, &k.pk);
    }
    tx
}

/// Version-1 (sighash v2) spend.
fn v2_spend(k: &Key, ins: &[([u8; 32], u32)], outs: Vec<TxOutput>) -> Transaction {
    sign_v2(k, unsigned(1, ins, outs))
}

/// Sighash-v3 digest of every input of `tx` spending `spent` under `suite`.
fn v3_digests(tx: &Transaction, spent: &[TxOutput], suite: u16) -> Vec<[u8; 32]> {
    let pre = SighashV3Precomputed::new(tx, spent).unwrap();
    (0..tx.inputs.len()).map(|i| pre.digest(i, suite, chain()).unwrap()).collect()
}

/// Version-3 (sighash v3) spend whose signatures commit to `spent`.
fn v3_spend(k: &Key, ins: &[([u8; 32], u32)], spent: &[TxOutput], outs: Vec<TxOutput>) -> Transaction {
    let mut tx = unsigned(3, ins, outs);
    let suite = crypto::public_key_suite(&k.pk).unwrap();
    for (i, d) in v3_digests(&tx, spent, suite).into_iter().enumerate() {
        let sig = roomy(|| crypto::sign_bound(&k.sk, &d).unwrap());
        tx.inputs[i].script_sig = Transaction::build_script_sig(&sig, &k.pk);
    }
    tx
}

/// The non-canonical witness encodings of CRY-1. Each keeps the txid.
#[derive(Clone, Copy, Debug)]
enum Mutation {
    /// The 4-byte suite envelope removed from the signature.
    EnvelopeStripped,
    /// The compact Falcon half zero-padded to Falcon's 1,280-byte form.
    PaddedFalcon,
    /// Bytes appended after the public key in `script_sig`.
    TrailingBytes,
}

const MUTATIONS: [Mutation; 3] = [Mutation::EnvelopeStripped, Mutation::PaddedFalcon, Mutation::TrailingBytes];

fn mutate(tx: &Transaction, m: Mutation) -> Transaction {
    let mut t = tx.clone();
    for inp in &mut t.inputs {
        let (sig, pk) = Transaction::parse_script_sig_exact(&inp.script_sig).unwrap();
        let (sig, pk) = (sig.to_vec(), pk.to_vec());
        inp.script_sig = match m {
            Mutation::EnvelopeStripped => Transaction::build_script_sig(&sig[crypto::SUITE_HEADER_LEN..], &pk),
            Mutation::PaddedFalcon => {
                let mut s = sig.clone();
                s.resize(crypto::SUITE_HEADER_LEN + crypto::MLDSA_SIG_LEN + crypto::falcon::padded_signature_len(), 0);
                assert_ne!(s, sig);
                Transaction::build_script_sig(&s, &pk)
            }
            Mutation::TrailingBytes => {
                let mut w = inp.script_sig.clone();
                w.extend_from_slice(&[0x00, 0x01, 0x02]);
                w
            }
        };
    }
    assert_eq!(t.txid(), tx.txid(), "witness malleation keeps the txid");
    t
}

fn tip_height(n: &Node) -> u64 {
    let d = n.dag.read();
    d.get_block_data(&d.selected_tip().unwrap()).unwrap().height
}

/// The node's ONE next-block height (`admission::pool_next_height`: the
/// template height, cached in the pool), checked against a fresh computation.
fn next_height(n: &Node) -> u64 {
    let d = n.dag.read();
    let h = admission::pool_next_height(&d, &n.store, &n.mempool);
    assert_eq!(h, template::next_template_height(&d, &n.store), "the pool's next height is current");
    h
}

fn dag_height(n: &Node, b: &BlockHash) -> u64 {
    n.dag.read().get_block_data(b).unwrap().height
}

fn fee_of(n: &Node, t: &Transaction) -> u64 {
    let ins: u64 = t.inputs.iter()
        .map(|i| n.store.get_utxo(&i.prev_txid, i.prev_index).unwrap().map(|o| o.value).unwrap_or(0))
        .sum();
    ins.saturating_sub(t.outputs.iter().map(|o| o.value).sum())
}

static TAG: AtomicU64 = AtomicU64::new(0);

/// A block on `parents` (header height = largest parent DAG height + 1)
/// carrying `txs`, its coinbase claiming subsidy + fees.
fn block_on_where(n: &Node, parents: Vec<BlockHash>, txs: Vec<Transaction>, pred: impl Fn(&BlockHash) -> bool) -> Block {
    let h = parents.iter().map(|p| dag_height(n, p)).max().unwrap() + 1;
    let fees: u64 = txs.iter().map(|t| fee_of(n, t)).sum();
    let tag = format!("fix-sig-{}-{}", h, TAG.fetch_add(1, Ordering::Relaxed));
    let mut all = vec![coinbase(&tag, core::tokenomics::block_subsidy_sat(h) + fees, vec![0xC0; 20])];
    all.extend(txs);
    mk_block_where(n, parents, all, pred)
}

/// A child of `parent` carrying `txs`, its coinbase claiming subsidy + fees.
fn child_where(n: &Node, parent: BlockHash, txs: Vec<Transaction>, pred: impl Fn(&BlockHash) -> bool) -> Block {
    block_on_where(n, vec![parent], txs, pred)
}

/// Extend the selected tip with a block carrying `txs`.
fn extend(n: &Node, txs: Vec<Transaction>) -> Result<BlockHash, String> {
    let b = child_where(n, sel_tip(n).unwrap(), txs, |_| true);
    accept(n, &b)
}

fn advance_to(n: &Node, height: u64) {
    while tip_height(n) < height {
        extend(n, vec![]).unwrap();
    }
}

fn admit(n: &Node, tx: &Transaction) -> Result<[u8; 32], AdmissionError> {
    admission::admit(&n.store, &n.mempool, tx.clone(), &AdmissionPolicy::relay(next_height(n)))
}

/// Build the template on the node's state, mine it and run it through the
/// real acceptance pipeline. Returns the template's transactions.
fn mine_template(n: &Node) -> Vec<Transaction> {
    let reserve = template::miner_coinbase(u64::MAX, u64::MAX, vec![0xCB; 20]).actual_size();
    let tmpl = template::build_block_template(&n.dag, &n.store, &n.mempool, reserve).unwrap();
    let cb = template::miner_coinbase(tmpl.height, tmpl.subsidy + tmpl.total_fees, vec![0xCB; 20]);
    let mut block = template::assemble_block(&tmpl, cb, unix_now()).expect("template self-check");
    while !block.validate_pow() {
        block.header.nonce += 1;
    }
    accept(n, &block).expect("the template block is valid");
    tmpl.transactions.into_iter().map(|(t, _)| t).collect()
}

fn spent(n: &Node, f: &([u8; 32], u32, TxOutput)) -> bool {
    n.store.get_utxo(&f.0, f.1).unwrap().is_none()
}

// ── CRY-3: the version rule at the boundary (acceptance pipeline) ────────────

/// Below H every version is verified with the v2 digest (so a version-3
/// transaction signed over the v3 digest fails there); at/after H a version-1
/// transaction is invalid, and a version-3 one signed over the v2 digest
/// fails; version 1 below H and version 3 (v3 digest) from H are valid.
#[test]
fn version_rule_at_the_activation_boundary() {
    let _g = activation::scoped_override(H);
    let k = key();
    let f: Vec<_> = (0..3u8).map(|i| fund(0x10 + i, 2 * SAT, &k.spk)).collect();
    let n = node_with(&mk_genesis(unix_now() - 10_000), &f);
    advance_to(&n, H - 2);
    let pay = |i: usize| vec![out(2 * SAT - FEE, &[0x21 + i as u8; 20])];

    // Block at H-1: a v3-digest signature is checked against the v2 digest.
    let v3 = v3_spend(&k, &[(f[0].0, 0)], std::slice::from_ref(&f[0].2), pay(0));
    let err = extend(&n, vec![v3]).unwrap_err();
    assert!(err.contains("invalid signature"), "{err}");
    assert_eq!(tip_height(&n), H - 2);
    extend(&n, vec![v2_spend(&k, &[(f[0].0, 0)], pay(0))]).expect("version 1 below the activation");
    assert!(spent(&n, &f[0]));
    assert_eq!(tip_height(&n), H - 1);

    // Block at H.
    let err = extend(&n, vec![v2_spend(&k, &[(f[1].0, 0)], pay(1))]).unwrap_err();
    assert!(err.contains("bad-txns-version"), "{err}");
    assert_eq!(tip_height(&n), H - 1);
    let v3_old_digest = sign_v2(&k, unsigned(3, &[(f[1].0, 0)], pay(1)));
    let err = extend(&n, vec![v3_old_digest]).unwrap_err();
    assert!(err.contains("invalid signature"), "{err}");
    assert_eq!(tip_height(&n), H - 1);
    extend(&n, vec![v3_spend(&k, &[(f[1].0, 0)], std::slice::from_ref(&f[1].2), pay(1))]).expect("version 3 at H");
    assert!(spent(&n, &f[1]));
    // And after H.
    extend(&n, vec![v3_spend(&k, &[(f[2].0, 0)], std::slice::from_ref(&f[2].2), pay(2))]).expect("version 3 after H");
    assert_eq!(tip_height(&n), H + 1);
}

// ── Item 5: mempool admission and templates follow the next block height ─────

/// A v2 tx admitted at H-1 is mined at H-1 or evicted at H; a v3 tx is
/// refused before H and accepted from H; templates at H-1 and H are valid.
#[test]
fn mempool_and_templates_follow_the_next_block_height() {
    let _g = activation::scoped_override(H);
    let k = key();
    let f: Vec<_> = (0..4u8).map(|i| fund(0x30 + i, 2 * SAT, &k.spk)).collect();
    let n = node_with(&mk_genesis(unix_now() - 10_000), &f);
    advance_to(&n, H - 2);
    assert_eq!(next_height(&n), H - 1);
    let pay = |i: usize| vec![out(2 * SAT - FEE, &[0x41 + i as u8; 20])];

    let a = v2_spend(&k, &[(f[0].0, 0)], pay(0));
    let b = v2_spend(&k, &[(f[1].0, 0)], pay(1));
    let c = v3_spend(&k, &[(f[2].0, 0)], std::slice::from_ref(&f[2].2), pay(2));
    admit(&n, &a).expect("v2 admitted for H-1");
    admit(&n, &b).expect("v2 admitted for H-1");
    let err = admit(&n, &c).unwrap_err();
    assert!(matches!(&err, AdmissionError::NonStandard(m) if m.contains("non-standard-version")), "{err}");

    // The template at H-1 carries both version-1 transactions.
    let tmpl = template::build_block_template(&n.dag, &n.store, &n.mempool, template::EXTERNAL_COINBASE_RESERVE).unwrap();
    assert_eq!(tmpl.height, H - 1);
    assert_eq!(tmpl.transactions.len(), 2);
    let cb = template::miner_coinbase(tmpl.height, tmpl.subsidy + tmpl.total_fees, vec![0xCB; 20]);
    template::assemble_block(&tmpl, cb, unix_now()).expect("template at H-1 passes its self-check");

    // Block H-1 mines A only: B can no longer be mined at H and is evicted.
    extend(&n, vec![a.clone()]).unwrap();
    assert!(!n.mempool.contains(&a.txid()), "A confirmed");
    assert!(!n.mempool.contains(&b.txid()), "B (version 1) evicted when the next block is H");
    assert_eq!(next_height(&n), H);

    // At H: version 1 refused, version 3 admitted (the tip change cleared the
    // recent-rejects entry of C).
    let d = v2_spend(&k, &[(f[3].0, 0)], pay(3));
    let err = admit(&n, &d).unwrap_err();
    assert!(err.to_string().contains("bad-txns-version"), "{err}");
    admit(&n, &c).expect("v3 admitted for H");

    // The template at H carries only C and is accepted.
    let mined = mine_template(&n);
    assert_eq!(mined.iter().map(|t| t.txid()).collect::<Vec<_>>(), vec![c.txid()]);
    assert_eq!(tip_height(&n), H);
    assert!(spent(&n, &f[2]) && !spent(&n, &f[1]) && !spent(&n, &f[3]));
    assert_eq!(n.mempool.size(), 0);
}

/// A version-1 transaction that is in the pool (e.g. from before the
/// upgrade) never reaches a template at or after H: the template self-check
/// evicts it instead of producing an invalid block.
#[test]
fn template_evicts_a_version_1_transaction_at_the_activation() {
    let _g = activation::scoped_override(H);
    let k = key();
    let f = fund(0x3A, 2 * SAT, &k.spk);
    let n = node_with(&mk_genesis(unix_now() - 10_000), std::slice::from_ref(&f));
    advance_to(&n, H - 1);
    let v1 = v2_spend(&k, &[(f.0, 0)], vec![out(2 * SAT - FEE, &[0x3B; 20])]);
    n.mempool.add(v1.clone(), FEE).unwrap(); // bypasses admission
    let tmpl = template::build_block_template(&n.dag, &n.store, &n.mempool, template::EXTERNAL_COINBASE_RESERVE).unwrap();
    assert_eq!(tmpl.height, H);
    assert_eq!(tmpl.evicted, 1);
    assert!(tmpl.transactions.is_empty());
    assert!(!n.mempool.contains(&v1.txid()));
}

// ── WAL-1 full fix: a lied amount or script invalidates the v3 signature ─────

#[test]
fn v3_signature_over_a_lied_amount_or_script_is_rejected() {
    let _g = activation::scoped_override(H);
    let k = key();
    let f = fund(0x50, 100 * SAT, &k.spk);
    let n = node_with(&mk_genesis(unix_now() - 10_000), std::slice::from_ref(&f));
    advance_to(&n, H - 1);
    // The audit's scenario: a 100 GNB coin reported as 1.0005 GNB; the user
    // pays 1 GNB, the "0.0005 GNB fee" would really be 99 GNB to the miner.
    let pay = vec![out(SAT, &[0x51; 20])];
    let lied_amount = TxOutput { value: SAT + 50_000, ..f.2.clone() };
    let tx = v3_spend(&k, &[(f.0, 0)], &[lied_amount], pay.clone());
    let err = admit(&n, &tx).unwrap_err();
    assert!(matches!(&err, AdmissionError::Rejected(m) if m.contains("invalid signature")), "{err}");
    let err = extend(&n, vec![tx]).unwrap_err();
    assert!(err.contains("invalid signature"), "{err}");
    assert!(!spent(&n, &f), "nothing was lost");

    // A lie about the spent script is caught the same way.
    let lied_script = TxOutput { script_pubkey: vec![0x99; 20], ..f.2.clone() };
    let tx = v3_spend(&k, &[(f.0, 0)], &[lied_script], pay.clone());
    n.mempool.clear_recent_rejects();
    let err = admit(&n, &tx).unwrap_err();
    assert!(err.to_string().contains("invalid signature"), "{err}");

    // The honest signature passes.
    let honest = v3_spend(&k, &[(f.0, 0)], std::slice::from_ref(&f.2), pay);
    admit(&n, &honest).expect("honest v3 spend");
    assert_eq!(mine_template(&n).len(), 1);
    assert!(spent(&n, &f));
}

// ── CRY-2 ────────────────────────────────────────────────────────────────────

/// The finding's attack at the transaction level: an output locked to the
/// 0x0002 key that shares the victim's ML-DSA body, spent with the ML-DSA
/// half of the victim's hybrid signature relabelled as 0x0002. Before the
/// activation (sighash v2, legacy binding) consensus accepts it — the old
/// verdict, reproduced exactly. From the activation it fails twice over:
/// the digest commits to the suite, and the component signed a message that
/// names suite 0x0001.
#[test]
fn split_hybrid_relabelled_to_mldsa_only_is_rejected_under_v3() {
    let _g = activation::scoped_override(H);
    let victim = key();
    let k2 = mldsa_only_key(&victim);
    let f1 = fund(0x60, 2 * SAT, &k2.spk);
    let f2 = fund(0x61, 2 * SAT, &k2.spk);
    let f3 = fund(0x62, 2 * SAT, &k2.spk);
    let n = node_with(&mk_genesis(unix_now() - 10_000), &[f1.clone(), f2.clone(), f3.clone()]);
    advance_to(&n, H - 2);
    let relabel = |hybrid_sig: &[u8]| {
        let mut s = vec![0xB1, 0x0C, 0x02, 0x00];
        s.extend_from_slice(&hybrid_sig[crypto::SUITE_HEADER_LEN..crypto::SUITE_HEADER_LEN + crypto::MLDSA_SIG_LEN]);
        s
    };

    // Pre-activation (v2): the split verifies — the old verdict.
    let mut t1 = unsigned(1, &[(f1.0, 0)], vec![out(2 * SAT - FEE, &[0x63; 20])]);
    let victim_sig = crypto::sign(&victim.sk, &t1.sighash(0, chain())).unwrap();
    t1.inputs[0].script_sig = Transaction::build_script_sig(&relabel(&victim_sig), &k2.pk);
    extend(&n, vec![t1]).expect("pre-activation: the legacy binding is separable (unchanged)");
    assert!(spent(&n, &f1));
    assert_eq!(next_height(&n), H);

    // From the activation (v3).
    let mut t2 = unsigned(3, &[(f2.0, 0)], vec![out(2 * SAT - FEE, &[0x64; 20])]);
    let as_hybrid = v3_digests(&t2, std::slice::from_ref(&f2.2), crypto::SUITE_MLDSA65_FALCON1024)[0];
    let as_mldsa = v3_digests(&t2, std::slice::from_ref(&f2.2), crypto::SUITE_MLDSA65_ONLY)[0];
    assert_ne!(as_hybrid, as_mldsa, "the digest commits to the suite");
    for digest in [as_hybrid, as_mldsa] {
        // The victim's hybrid v3 signature over the digest (even the one the
        // 0x0002 verifier computes), split and relabelled.
        let hybrid_sig = crypto::sign_bound(&victim.sk, &digest).unwrap();
        let forged = relabel(&hybrid_sig);
        assert!(crypto::is_canonical_signature_encoding(&forged));
        t2.inputs[0].script_sig = Transaction::build_script_sig(&forged, &k2.pk);
        let err = extend(&n, vec![t2.clone()]).unwrap_err();
        assert!(err.contains("invalid signature"), "{err}");
        n.mempool.clear_recent_rejects();
        assert!(admit(&n, &t2).is_err());
    }
    assert!(!spent(&n, &f2));

    // Control: a genuine 0x0002 v3 signature is consensus-valid.
    let genuine = v3_spend(&k2, &[(f3.0, 0)], std::slice::from_ref(&f3.2), vec![out(2 * SAT - FEE, &[0x65; 20])]);
    extend(&n, vec![genuine]).expect("suite 0x0002 stays consensus-valid");
    assert!(spent(&n, &f3));
}

/// Suite 0x0002 is non-standard at every height (mempool refuses it) and
/// consensus-valid at every height (blocks carrying it are accepted), so no
/// output that may already be locked to a 0x0002 key is frozen.
#[test]
fn mldsa_only_suite_is_nonstandard_but_consensus_valid() {
    let _g = activation::scoped_override(H);
    let k2 = mldsa_only_key(&key());
    let f1 = fund(0x70, 2 * SAT, &k2.spk);
    let f2 = fund(0x71, 2 * SAT, &k2.spk);
    let n = node_with(&mk_genesis(unix_now() - 10_000), &[f1.clone(), f2.clone()]);
    advance_to(&n, H - 2);

    let t1 = v2_spend(&k2, &[(f1.0, 0)], vec![out(2 * SAT - FEE, &[0x72; 20])]);
    let err = admit(&n, &t1).unwrap_err();
    assert!(matches!(&err, AdmissionError::NonStandard(m) if m.contains("single-algorithm")), "{err}");
    extend(&n, vec![t1]).expect("0x0002 v2 spend is consensus-valid below H");
    assert!(spent(&n, &f1));

    assert_eq!(next_height(&n), H);
    let t2 = v3_spend(&k2, &[(f2.0, 0)], std::slice::from_ref(&f2.2), vec![out(2 * SAT - FEE, &[0x73; 20])]);
    let err = admit(&n, &t2).unwrap_err();
    assert!(matches!(&err, AdmissionError::NonStandard(m) if m.contains("single-algorithm")), "{err}");
    extend(&n, vec![t2]).expect("0x0002 v3 spend is consensus-valid from H");
    assert!(spent(&n, &f2));
}

// ── CRY-1 (canonical-witness half) ───────────────────────────────────────────

/// Non-canonical witnesses (envelope stripped, padded Falcon, trailing
/// bytes): refused by relay policy at every height; accepted by consensus
/// below the activation (old rule); rejected by consensus from it.
#[test]
fn non_canonical_witnesses_policy_at_all_heights_consensus_from_activation() {
    let _g = activation::scoped_override(H);
    let k = key();
    let pre: Vec<_> = (0..3u8).map(|i| fund(0x80 + i, 2 * SAT, &k.spk)).collect();
    let post: Vec<_> = (0..3u8).map(|i| fund(0x90 + i, 2 * SAT, &k.spk)).collect();
    let n = node_with(&mk_genesis(unix_now() - 10_000), &[pre.clone(), post.clone()].concat());
    advance_to(&n, H - 2);

    // Below the activation.
    let mut mined = Vec::new();
    for (m, f) in MUTATIONS.iter().zip(&pre) {
        let canonical = v2_spend(&k, &[(f.0, 0)], vec![out(2 * SAT - FEE, &[0x84; 20])]);
        let bad = mutate(&canonical, *m);
        let err = admit(&n, &bad).unwrap_err();
        assert!(matches!(&err, AdmissionError::NonStandard(e) if e.contains("non-standard")), "{m:?}: {err}");
        mined.push(bad);
    }
    extend(&n, mined).expect("non-canonical v2 witnesses are consensus-valid below H");
    assert!(pre.iter().all(|f| spent(&n, f)));

    // From the activation.
    assert_eq!(next_height(&n), H);
    let canonical: Vec<Transaction> = post.iter()
        .map(|f| v3_spend(&k, &[(f.0, 0)], std::slice::from_ref(&f.2), vec![out(2 * SAT - FEE, &[0x94; 20])]))
        .collect();
    for (m, t) in MUTATIONS.iter().zip(&canonical) {
        let bad = mutate(t, *m);
        // Consensus-invalid for version 3 from the activation: `Rejected`,
        // not a policy refusal (review finding on the P4 merge).
        let err = admit(&n, &bad).unwrap_err();
        assert!(matches!(&err, AdmissionError::Rejected(e) if e.contains("bad-witness")), "{m:?}: {err}");
        let err = extend(&n, vec![bad]).unwrap_err();
        assert!(err.contains("non-canonical"), "{m:?}: {err}");
        assert_eq!(tip_height(&n), H - 1);
    }
    extend(&n, canonical).expect("canonical v3 witnesses are valid");
    assert!(post.iter().all(|f| spent(&n, f)));
}

/// Review finding on the P4 merge (integration open issue 1): a version-3
/// transaction whose witness is not canonical, for a block at/after the
/// activation, is consensus-INVALID (CRY-1) and no upgraded node relays it
/// (one block behind, version 3 is non-standard). Admission now answers
/// `Rejected` and the gossip relay `Reject` once penalties are in force,
/// i.e. from the block after the activation block; while the next block IS
/// the activation block, an older release (which forwards every frame
/// unvalidated) can still be an honest peer, so the frame is `Ignore` there.
/// Pre-fix the witness standardness step (which runs before the version
/// rule) mapped every failure to `NonStandard`: `Ignore` at every height, so
/// breaking the witness framing made any invalid transaction penalty-free. A
/// suite-0x0002 key stays `NonStandard` (consensus-valid, CRY-2).
#[test]
fn non_canonical_v3_witness_is_rejected_and_penalised_after_the_activation() {
    let _g = activation::scoped_override(H);
    let k = key();
    let k2 = mldsa_only_key(&key());
    let f: Vec<_> = (0..4u8).map(|i| fund(0x60 + i, 2 * SAT, &k.spk)).collect();
    let f2 = fund(0x68, 2 * SAT, &k2.spk);
    let n = node_with(&mk_genesis(unix_now() - 10_000), &[f.clone(), vec![f2.clone()]].concat());
    advance_to(&n, H - 1);
    assert_eq!(next_height(&n), H);
    let pay = |i: usize| vec![out(2 * SAT - FEE, &[0x6A + i as u8; 20])];
    let mut relay = TxRelay::new();
    assert_eq!(relay.penalty_height(), H + 1);
    let gossip = |relay: &mut TxRelay, tx: &Transaction| {
        relay.on_gossip_tx(&n.store, &n.mempool, next_height(&n), &tx.txid(), &tx.to_wire_bytes(true),
            Some(PeerId::random()), std::time::Instant::now(), unix_now())
    };

    // Next block = the activation block H.
    let bad: Vec<Transaction> = MUTATIONS.iter().enumerate()
        .map(|(i, m)| mutate(&v3_spend(&k, &[(f[i].0, 0)], std::slice::from_ref(&f[i].2), pay(i)), *m))
        .collect();
    for (m, t) in MUTATIONS.iter().zip(&bad) {
        let err = admission::check_transaction(&n.store, Some(&n.mempool), t, &AdmissionPolicy::relay(H)).unwrap_err();
        assert!(matches!(&err, AdmissionError::Rejected(e) if e.contains("bad-witness")), "{m:?}: {err}");
        let o = gossip(&mut relay, t);
        assert!(o.invalid, "{m:?}: {}", o.detail);
        assert_eq!(o.verdict, GossipVerdict::Ignore, "{m:?}: the activation block is not in the chain yet: {}", o.detail);
    }
    let t2 = v3_spend(&k2, &[(f2.0, 0)], std::slice::from_ref(&f2.2), pay(9));
    let o = gossip(&mut relay, &t2);
    assert!(!o.invalid && o.verdict == GossipVerdict::Ignore && o.detail.contains("single-algorithm"), "{:?}", o);

    // The activation block: from here on the same frames are penalised.
    extend(&n, vec![]).unwrap();
    assert_eq!(next_height(&n), H + 1);
    for (m, t) in MUTATIONS.iter().zip(&bad) {
        let o = gossip(&mut relay, t);
        assert!(o.invalid, "{m:?}: {}", o.detail);
        assert_eq!(o.verdict, GossipVerdict::Reject, "{m:?}: {}", o.detail);
    }
    let o = gossip(&mut relay, &t2);
    assert_eq!(o.verdict, GossipVerdict::Ignore, "suite 0x0002 is policy at every height: {}", o.detail);
    let good = v3_spend(&k, &[(f[3].0, 0)], std::slice::from_ref(&f[3].2), pay(3));
    assert_eq!(gossip(&mut relay, &good).verdict, GossipVerdict::Accept);
}

/// Genesis carry-over outputs (address = hash of the RAW public key) stay
/// spendable below and from the activation, through admission, the template
/// and the acceptance pipeline: the public key is never forced into an
/// envelope.
#[test]
fn raw_pubkey_carryover_outputs_stay_spendable() {
    let _g = activation::scoped_override(H);
    let kr = raw_carryover_key();
    assert_eq!(kr.pk.len(), crypto::MLDSA_PUBKEY_LEN + crypto::falcon::pubkey_len());
    let f1 = fund(0xA0, 2 * SAT, &kr.spk);
    let f2 = fund(0xA1, 2 * SAT, &kr.spk);
    let n = node_with(&mk_genesis(unix_now() - 10_000), &[f1.clone(), f2.clone()]);
    advance_to(&n, H - 2);
    admit(&n, &v2_spend(&kr, &[(f1.0, 0)], vec![out(2 * SAT - FEE, &[0xA2; 20])])).expect("raw key, v2");
    assert_eq!(mine_template(&n).len(), 1);
    assert!(spent(&n, &f1));
    assert_eq!(next_height(&n), H);
    let t = v3_spend(&kr, &[(f2.0, 0)], std::slice::from_ref(&f2.2), vec![out(2 * SAT - FEE, &[0xA3; 20])]);
    admit(&n, &t).expect("raw key, v3");
    assert_eq!(mine_template(&n).len(), 1);
    assert!(spent(&n, &f2));
}

// ── WAL-1: the wallet send flow at H-1 and H, end to end ─────────────────────

/// The JSON-RPC methods the wallet send flow uses, served from the node's
/// state. `getdaginfo` reports `next_block_height` exactly as the RPC
/// computes it (`admission::pool_next_height`); `sendrawtransaction` runs the
/// real admission at that height.
fn wallet_rpc<'a>(
    n: &'a Node,
    funds: &'a [([u8; 32], u32, TxOutput)],
    calls: &'a std::cell::RefCell<Vec<String>>,
) -> impl Fn(&str, &Value) -> Result<Value, String> + 'a {
    move |method: &str, params: &Value| -> Result<Value, String> {
        calls.borrow_mut().push(method.to_string());
        Ok(match method {
            "getdaginfo" => json!({
                "tip_height": tip_height(n),
                "next_block_height": admission::pool_next_height(&n.dag.read(), &n.store, &n.mempool),
            }),
            "getutxos" => json!({ "utxos": funds.iter().filter(|f| !spent(n, f)).map(|f| json!({
                "txid": hex::encode(f.0), "index": f.1, "value": f.2.value.to_string(),
                "script_pubkey": hex::encode(&f.2.script_pubkey) })).collect::<Vec<_>>() }),
            "getrawtransaction" => json!({ "error": "transaction body not available" }),
            "sendrawtransaction" => {
                let raw = hex::decode(params[0].as_str().unwrap()).unwrap();
                let tx = admission::decode_tx_strict(&raw)?;
                match admit(n, &tx) {
                    Ok(txid) => json!({ "txid": hex::encode(txid) }),
                    Err(e) => json!({ "error": e.to_string() }),
                }
            }
            _ => json!({ "error": "unknown method" }),
        })
    }
}

/// `gnb-cli send` / `gnb-wallet send` (`wallet::send::prepare_send`) against
/// an RPC backed by the node: it learns the next height from `getdaginfo`,
/// signs version 1 for H-1 and version 3 for H (fetching no previous
/// transaction), and both payments pass admission, the template and the
/// acceptance pipeline.
#[test]
fn wallet_send_flow_round_trips_at_both_sides_of_the_activation() {
    let _g = activation::scoped_override(H);
    let kp = gnb::wallet::generate_keypair(false);
    let spk = kp.address_bytes();
    let f1 = fund(0xB0, 3 * SAT, &spk);
    let f2 = fund(0xB1, 3 * SAT, &spk);
    let n = node_with(&mk_genesis(unix_now() - 10_000), &[f1.clone(), f2.clone()]);
    advance_to(&n, H - 2);
    let to = gnb::address::Address::from_hash([0xB2; 20], gnb::address::Network::Mainnet);
    let calls = std::cell::RefCell::new(Vec::<String>::new());
    let funds = [f1.clone(), f2.clone()];
    let rpc = wallet_rpc(&n, &funds, &calls);
    let request = send::SendRequest {
        keypair: &kp, to: &to, amount: SAT, fee: FeeChoice::AUTO, fee_policy: FeePolicy::DEFAULT,
        require_verified_inputs: false, utxo_limit: 50,
    };

    // Next block H-1: version 1; the previous transactions are requested.
    let prepared = send::prepare_send(&rpc, &request).unwrap();
    assert_eq!(prepared.payment.tx.version, 1);
    assert!(!prepared.payment.amounts_committed);
    assert!(calls.borrow().iter().any(|m| m == "getrawtransaction"));
    send::broadcast(&rpc, &prepared).expect("admitted for H-1");
    assert_eq!(mine_template(&n).len(), 1);
    assert_eq!(tip_height(&n), H - 1);

    // Next block H: version 3, nothing fetched, values committed.
    calls.borrow_mut().clear();
    let prepared = send::prepare_send(&rpc, &request).unwrap();
    assert_eq!(prepared.payment.tx.version, 3);
    assert!(prepared.payment.amounts_committed);
    assert!(!calls.borrow().iter().any(|m| m == "getrawtransaction"), "{:?}", calls.borrow());
    send::broadcast(&rpc, &prepared).expect("admitted for H");
    assert_eq!(mine_template(&n).len(), 1);
    assert_eq!(tip_height(&n), H);
    assert!(spent(&n, &f1) && spent(&n, &f2));
}

// ── Reorg connect runs the same rule ─────────────────────────────────────────

/// A fork block at H carrying a version-1 transaction is stored as a
/// fork-loser without UTXO validation; when its chain becomes the heaviest,
/// the reorg connect validates it with the shared rule and disqualifies it.
/// A fork carrying a valid version-3 spend of the same coin is then applied.
#[test]
fn reorg_connect_applies_the_version_rule() {
    let _g = activation::scoped_override(H);
    let k = key();
    let f = fund(0xC0, 2 * SAT, &k.spk);
    let n = node_with(&mk_genesis(unix_now() - 10_000), std::slice::from_ref(&f));
    advance_to(&n, H - 1);
    let t = sel_tip(&n).unwrap();
    let x = child_where(&n, t, vec![], |h| h[0] >= 0xC0);
    let xh = x.block_hash();
    accept(&n, &x).unwrap();

    // Fork Y (invalid at H) loses the tie, then Y2 makes it heavier.
    let y = child_where(&n, t, vec![v2_spend(&k, &[(f.0, 0)], vec![out(2 * SAT - FEE, &[0xC1; 20])])], |h| *h < xh);
    let yh = accept(&n, &y).expect("stored as a fork-loser, not validated yet");
    assert_eq!(applied_tip(&n), Some(xh));
    let y2 = child_where(&n, yh, vec![], |_| true);
    let err = accept(&n, &y2).unwrap_err();
    assert!(err.contains("invalid"), "{err}");
    assert_eq!(applied_tip(&n), Some(xh), "the invalid fork was disqualified on reorg connect");
    assert!(!spent(&n, &f));

    // Fork Z (valid v3 spend at H) wins the reorg.
    let z = child_where(&n, t, vec![v3_spend(&k, &[(f.0, 0)], std::slice::from_ref(&f.2), vec![out(2 * SAT - FEE, &[0xC2; 20])])], |h| *h < xh);
    let zh = accept(&n, &z).unwrap();
    let z2 = child_where(&n, zh, vec![], |_| true);
    let z2h = accept(&n, &z2).expect("reorg to the valid fork");
    assert_eq!(applied_tip(&n), Some(z2h));
    assert!(spent(&n, &f));
}

// ── Requirement 1: the never-activated regime reproduces the old verdicts ────

/// With the activation never reached, every pre-fix verdict is reproduced:
/// version 1, an arbitrary version (7) with the v2 digest, the three
/// non-canonical witness encodings, a 0x0002 spend, a raw carry-over key and
/// a version-3 transaction signed over the v2 digest are all
/// consensus-valid (relay policy refuses version >= 3, consensus does not).
#[test]
fn never_activated_regime_reproduces_the_old_verdicts() {
    let _g = activation::scoped_override(activation::NEVER);
    let k = key();
    let k2 = mldsa_only_key(&key());
    let kr = raw_carryover_key();
    let fk: Vec<_> = (0..6u8).map(|i| fund(0xD0 + i, 2 * SAT, &k.spk)).collect();
    let f2 = fund(0xDA, 2 * SAT, &k2.spk);
    let fr = fund(0xDB, 2 * SAT, &kr.spk);
    let n = node_with(&mk_genesis(unix_now() - 10_000), &[fk.clone(), vec![f2.clone(), fr.clone()]].concat());
    let o = |b: u8| vec![out(2 * SAT - FEE, &[b; 20])];
    let mut txs = vec![
        v2_spend(&k, &[(fk[0].0, 0)], o(1)),
        sign_v2(&k, unsigned(7, &[(fk[1].0, 0)], o(2))),
        v2_spend(&k2, &[(f2.0, 0)], o(3)),
        v2_spend(&kr, &[(fr.0, 0)], o(4)),
    ];
    for (m, f) in MUTATIONS.iter().zip(&fk[2..5]) {
        txs.push(mutate(&v2_spend(&k, &[(f.0, 0)], o(5)), *m));
    }
    extend(&n, txs).expect("old verdicts: all valid");
    assert!(fk[..5].iter().all(|f| spent(&n, f)) && spent(&n, &f2) && spent(&n, &fr));
    // Version 3 signed over the v2 digest (what pre-upgrade nodes check):
    // non-standard, but consensus-valid exactly as before the upgrade.
    let v3_with_v2_digest = sign_v2(&k, unsigned(3, &[(fk[5].0, 0)], o(6)));
    let err = admit(&n, &v3_with_v2_digest).unwrap_err();
    assert!(err.to_string().contains("non-standard-version"), "{err}");
    extend(&n, vec![v3_with_v2_digest]).expect("old verdict: version 3 with the v2 digest is valid");
    assert!(spent(&n, &fk[5]));
}

// ── MEM-5 residual: linear sighash ───────────────────────────────────────────

/// Signing/verifying every input of a version-3 transaction hashes O(size)
/// bytes (one precomputation + a 195-byte preimage per input); sighash v2
/// re-encodes the whole transaction per input. Counted, not timed.
#[test]
fn v3_sighash_cost_is_linear_v2_is_quadratic() {
    let cost = |n: usize| {
        let tx = Transaction {
            version: 3,
            inputs: (0..n).map(|i| TxInput { prev_txid: [i as u8; 32], prev_index: i as u32, script_sig: vec![], sequence: 0 }).collect(),
            outputs: vec![out(1_000, &[1; 20]), out(2_000, &[2; 20])],
            locktime: 0,
        };
        let spent: Vec<TxOutput> = (0..n).map(|i| out(10_000 + i as u64, &[3; 20])).collect();
        let pre = SighashV3Precomputed::new(&tx, &spent).unwrap();
        let v3 = pre.hashed_bytes + n * SIGHASH_V3_PREIMAGE_LEN;
        let v2 = n * tx.actual_size(); // each v2 digest hashes the stripped tx
        (v3, v2)
    };
    let (v3_40, v2_40) = cost(40);
    let (v3_400, v2_400) = cost(400);
    assert!(v3_400 <= 11 * v3_40, "v3 linear: {v3_40} -> {v3_400}");
    assert!(v2_400 >= 90 * v2_40, "v2 quadratic: {v2_40} -> {v2_400}");
    // The admission rule uses exactly this digest: a 40-input v3 spend
    // verifies through the shared function.
    let _g = activation::scoped_override(0);
    let k = key();
    let funds: Vec<_> = (0..40u8).map(|i| ([i; 32], 0u32, out(SAT, &k.spk))).collect();
    let ins: Vec<_> = funds.iter().map(|f| (f.0, 0)).collect();
    let spent: Vec<_> = funds.iter().map(|f| f.2.clone()).collect();
    let tx = v3_spend(&k, &ins, &spent, vec![out(40 * SAT - FEE, &[9; 20])]);
    assert_eq!(gnb::core::sighash::verify_tx_scripts(&tx, &spent, chain(), 1, 0), Ok(SighashVersion::V3));
    admission::verify_input_scripts(&tx, &spent, 1).expect("node rule");
}

// ── Review: pre-activation version 3 is consensus-valid, non-standard ────────

/// Mandated rule: below the activation a non-coinbase transaction of version
/// 3 (or higher) signed over the v2 digest — what a non-upgraded node checks
/// — is consensus-valid exactly as before the upgrade, so a block a
/// non-upgraded miner builds with it is accepted (no split before the flag
/// day). Upgraded nodes refuse it as relay policy: admission rejects it as
/// non-standard and a template never mines it.
#[test]
fn pre_activation_version_3_with_the_v2_digest_is_valid_but_non_standard() {
    let _g = activation::scoped_override(H);
    let k = key();
    let f: Vec<_> = (0..3u8).map(|i| fund(0xE0 + i, 2 * SAT, &k.spk)).collect();
    let n = node_with(&mk_genesis(unix_now() - 10_000), &f);
    advance_to(&n, H - 2);
    assert_eq!(next_height(&n), H - 1);
    let pay = |i: usize| vec![out(2 * SAT - FEE, &[0xE8 + i as u8; 20])];
    let v3_old = sign_v2(&k, unsigned(3, &[(f[0].0, 0)], pay(0)));
    let v4_old = sign_v2(&k, unsigned(4, &[(f[1].0, 0)], pay(1)));

    // Policy: refused by admission (gossip / RPC)...
    for t in [&v3_old, &v4_old] {
        let err = admit(&n, t).unwrap_err();
        assert!(matches!(&err, AdmissionError::NonStandard(m) if m.contains("non-standard-version")), "{err}");
        assert!(!n.mempool.contains(&t.txid()));
    }
    // ...and never mined from the pool: a template at H-1 evicts one that
    // got in some other way.
    n.mempool.add(v3_old.clone(), FEE).unwrap();
    let tmpl = template::build_block_template(&n.dag, &n.store, &n.mempool, template::EXTERNAL_COINBASE_RESERVE).unwrap();
    assert_eq!(tmpl.height, H - 1);
    assert!(tmpl.transactions.is_empty());
    assert_eq!(tmpl.evicted, 1);
    assert!(!n.mempool.contains(&v3_old.txid()));

    // Consensus: the block at H-1 a non-upgraded miner builds is valid.
    extend(&n, vec![v3_old, v4_old]).expect("version >= 3 with the v2 digest is consensus-valid below H");
    assert!(spent(&n, &f[0]) && spent(&n, &f[1]));
    assert_eq!(tip_height(&n), H - 1);
    // A v2-digest version-3 transaction is invalid from the activation.
    let v3_late = sign_v2(&k, unsigned(3, &[(f[2].0, 0)], pay(2)));
    assert!(extend(&n, vec![v3_late]).unwrap_err().contains("invalid signature"));
    assert!(!spent(&n, &f[2]));
}

// ── Review: the verified-signature cache is keyed by everything it depends on ─

/// The cache never returns a "valid" for another digest version, height
/// regime or prevout set: the same wtxid is verified again whenever any of
/// them changes.
#[test]
fn signature_cache_is_keyed_by_regime_and_prevouts() {
    let _g = activation::scoped_override(H);
    let k = key();
    let f = fund(0xE4, 2 * SAT, &k.spk);
    let spent_ok = std::slice::from_ref(&f.2);
    let pay = vec![out(2 * SAT - FEE, &[0xE5; 20])];

    // Version 3 over the v2 digest: valid below H (and cached), invalid at H.
    let old = sign_v2(&k, unsigned(3, &[(f.0, 0)], pay.clone()));
    admission::verify_input_scripts(&old, spent_ok, H - 1).expect("v2 regime below H");
    admission::verify_input_scripts(&old, spent_ok, H - 1).expect("cache hit, same regime");
    let err = admission::verify_input_scripts(&old, spent_ok, H).unwrap_err();
    assert!(err.contains("invalid signature"), "{err}");

    // Version 3 over the v3 digest: valid at H (and cached), invalid below H.
    let new = v3_spend(&k, &[(f.0, 0)], spent_ok, pay.clone());
    admission::verify_input_scripts(&new, spent_ok, H).expect("v3 regime at H");
    let err = admission::verify_input_scripts(&new, spent_ok, H - 1).unwrap_err();
    assert!(err.contains("invalid signature"), "{err}");

    // Same wtxid, another prevout set (a different spent amount or script).
    for lie in [TxOutput { value: f.2.value + 1, ..f.2.clone() }, TxOutput { script_pubkey: vec![0x99; 20], ..f.2.clone() }] {
        assert!(admission::verify_input_scripts(&new, std::slice::from_ref(&lie), H).is_err());
    }

    // Same height, another activation state (never activated): v2 regime.
    {
        let _never = activation::scoped_override(activation::NEVER);
        let err = admission::verify_input_scripts(&new, spent_ok, H).unwrap_err();
        assert!(err.contains("invalid signature"), "{err}");
        admission::verify_input_scripts(&old, spent_ok, H).expect("v2 regime when never activated");
    }
    admission::verify_input_scripts(&new, spent_ok, H + 5).expect("still valid in its own regime");
}

// ── Review: re-injection across the activation re-verifies the scripts ──────

/// A version-3 transaction signed over the v2 digest, mined below H by a
/// non-upgraded miner, is not re-admitted when a reorg disconnects its block
/// and the next block is at/after H: re-injection from the activation
/// verifies the scripts under sighash v3, where that signature is invalid. A
/// version-3 transaction mined under v3 is re-admitted after a reorg.
#[test]
fn reinjection_across_the_activation_reverifies_the_scripts() {
    let _g = activation::scoped_override(H);
    let k = key();
    let f = fund(0xE6, 2 * SAT, &k.spk);
    let n = node_with(&mk_genesis(unix_now() - 10_000), std::slice::from_ref(&f));
    advance_to(&n, H - 2);
    let t = sel_tip(&n).unwrap();

    // Block B at H-1 (a non-upgraded miner): the v2-signed version-3 spend.
    let old = sign_v2(&k, unsigned(3, &[(f.0, 0)], vec![out(2 * SAT - FEE, &[0xE7; 20])]));
    let bh = accept(&n, &child_where(&n, t, vec![old.clone()], |_| true)).expect("valid below H");
    assert_eq!(applied_tip(&n), Some(bh));
    assert!(spent(&n, &f));

    // A heavier fork without it (C1 at H-1 loses the tie, C2 at H wins).
    let c1 = accept(&n, &child_where(&n, t, vec![], |h| *h < bh)).unwrap();
    assert_eq!(applied_tip(&n), Some(bh));
    let c2 = accept(&n, &child_where(&n, c1, vec![], |_| true)).unwrap();
    assert_eq!(applied_tip(&n), Some(c2), "reorg");
    assert_eq!(next_height(&n), H + 1);
    assert!(!spent(&n, &f), "the coin is unspent again");
    assert!(!n.mempool.contains(&old.txid()), "not re-admitted: its signature is invalid under v3");

    // A version-3 spend under v3, mined at H+1 and then reorged away, IS
    // re-admitted (its scripts verify under v3; a cache hit).
    let new = v3_spend(&k, &[(f.0, 0)], std::slice::from_ref(&f.2), vec![out(2 * SAT - FEE, &[0xE9; 20])]);
    let dh = extend(&n, vec![new.clone()]).unwrap();
    assert!(spent(&n, &f));
    let e1 = accept(&n, &child_where(&n, c2, vec![], |h| *h < dh)).unwrap();
    assert_eq!(applied_tip(&n), Some(dh));
    let e2 = accept(&n, &child_where(&n, e1, vec![], |_| true)).unwrap();
    assert_eq!(applied_tip(&n), Some(e2), "reorg");
    assert!(n.mempool.contains(&new.txid()), "re-admitted");
}

// ── Review: ONE next-block height (DAG-8 shapes) ─────────────────────────────

/// A node whose GhostDAG instance runs the hardened rules from genesis (Kaspa
/// blue work: the work of the merged blues counts), while the transaction
/// rules follow the calling thread's activation override (`GhostDAG`
/// captures its activation height when it is constructed).
///
/// Why: under `test-pow-limit` every block carries the same work, so with the
/// legacy blue work (selected-chain work only) the heaviest tip always has
/// the greatest DAG height and a block's header height always equals its DAG
/// height. On a real chain the ASERT difficulty differs between blocks and a
/// lighter tip can have a greater DAG height below the activation too; the
/// Kaspa blue work produces the same DAG-8 shape (a merging tip heavier than
/// a longer chain) with equal-work blocks.
fn node_with_dag8_shapes(funds: &[([u8; 32], u32, TxOutput)]) -> Node {
    let _dag_rules = activation::scoped_override(0);
    node_with(&mk_genesis(unix_now() - 10_000), funds)
}

/// From the selected tip A: three siblings B1..B3 merged by S (the most blue
/// work, DAG height a+2) and a lighter linear side chain X1 -> X2 -> X (DAG
/// height a+3). Returns (S, X). Every block goes through `accept_block`.
/// Needs [`node_with_dag8_shapes`].
fn heavy_merge_and_light_long_tip(n: &Node) -> (BlockHash, BlockHash) {
    let a = sel_tip(n).unwrap();
    let ha = dag_height(n, &a);
    let bs: Vec<BlockHash> = (0..3).map(|_| accept(n, &child_where(n, a, vec![], |_| true)).unwrap()).collect();
    let s = accept(n, &block_on_where(n, bs, vec![], |_| true)).unwrap();
    let mut x = a;
    for _ in 0..3 {
        x = accept(n, &child_where(n, x, vec![], |_| true)).unwrap();
    }
    assert_eq!(sel_tip(n), Some(s), "S carries the most blue work");
    assert_eq!(applied_tip(n), Some(s));
    assert_eq!((dag_height(n, &s), dag_height(n, &x)), (ha + 2, ha + 3));
    let mut tips = n.dag.read().valid_tips();
    tips.sort();
    let mut want = vec![s, x];
    want.sort();
    assert_eq!(tips, want);
    (s, x)
}

/// Finding: admission and wallets used the selected tip's DAG height + 1
/// while templates (and the consensus header height) used the largest
/// template-parent DAG height + 1, so a lighter tip with a greater DAG height
/// put them on opposite sides of the activation (admission refused version 3,
/// the template evicted every version 1 — no user transaction could be
/// mined). Now one height: admission, the template, getdaginfo / the wallet
/// and post-connect maintenance all target the template height.
#[test]
fn light_tip_with_a_greater_dag_height_moves_every_next_height_together() {
    const ACT: u64 = 8;
    let _g = activation::scoped_override(ACT);
    let k = key();
    let kp = gnb::wallet::generate_keypair(false);
    let wallet_fund = fund(0xF3, 3 * SAT, &kp.address_bytes());
    let f: Vec<_> = (0..2u8).map(|i| fund(0xF0 + i, 2 * SAT, &k.spk)).collect();
    let n = node_with_dag8_shapes(&[f.clone(), vec![wallet_fund.clone()]].concat());
    advance_to(&n, ACT - 4);
    let pay = |i: usize| vec![out(2 * SAT - FEE, &[0xF8 + i as u8; 20])];

    // A version-1 payment pooled while the next block is ACT-3.
    let early = v2_spend(&k, &[(f[0].0, 0)], pay(0));
    assert_eq!(next_height(&n), ACT - 3);
    admit(&n, &early).expect("version 1 for ACT-3");

    let (s, x) = heavy_merge_and_light_long_tip(&n);
    assert_eq!(tip_height(&n), ACT - 2, "selected tip S");
    assert_eq!(admission::next_block_height(&n.dag.read()), ACT - 1, "selected tip DAG height + 1");
    // The ONE next height is the template height: the template merges X.
    assert_eq!(next_height(&n), ACT);
    assert_eq!(n.mempool.next_height(), ACT, "cached in the pool when X was stored");
    // The pooled version-1 payment cannot be in the node's next block: the
    // DAG change that moved the height evicted it.
    assert!(!n.mempool.contains(&early.txid()));

    // Admission at ACT: version 1 refused, version 3 admitted.
    let late_v1 = v2_spend(&k, &[(f[1].0, 0)], pay(1));
    let err = admit(&n, &late_v1).unwrap_err();
    assert!(err.to_string().contains("bad-txns-version"), "{err}");

    // The wallet learns ACT from getdaginfo (tip_height + 1 is only ACT-1)
    // and signs version 3; the node admits it.
    let calls = std::cell::RefCell::new(Vec::<String>::new());
    let funds = [wallet_fund.clone()];
    let rpc = wallet_rpc(&n, &funds, &calls);
    let daginfo = rpc("getdaginfo", &json!([])).unwrap();
    assert_eq!(daginfo["tip_height"], ACT - 2);
    assert_eq!(send::next_block_height_from_daginfo(&daginfo), Ok(ACT));
    let to = gnb::address::Address::from_hash([0xF9; 20], gnb::address::Network::Mainnet);
    let request = send::SendRequest {
        keypair: &kp, to: &to, amount: SAT, fee: FeeChoice::AUTO, fee_policy: FeePolicy::DEFAULT,
        require_verified_inputs: false, utxo_limit: 50,
    };
    let prepared = send::prepare_send(&rpc, &request).unwrap();
    assert_eq!(prepared.payment.tx.version, 3);
    send::broadcast(&rpc, &prepared).expect("admitted for ACT");
    let paid = prepared.payment.tx.txid();

    // The template on {S, X} sits at ACT, carries the payment, evicts nothing.
    let tmpl = template::build_block_template(&n.dag, &n.store, &n.mempool, template::EXTERNAL_COINBASE_RESERVE).unwrap();
    assert_eq!(tmpl.height, ACT);
    assert_eq!(tmpl.parents.len(), 2);
    assert_eq!(tmpl.evicted, 0);
    assert_eq!(tmpl.transactions.iter().map(|(t, _)| t.txid()).collect::<Vec<_>>(), vec![paid]);
    let mined = mine_template(&n);
    assert_eq!(mined.iter().map(|t| t.txid()).collect::<Vec<_>>(), vec![paid]);
    assert!(spent(&n, &wallet_fund));

    // The mined block M on {S, X}: header ACT, DAG height ACT-1. A child of
    // M alone sits at ACT, so that is the next height (not header + 1).
    let m = sel_tip(&n).unwrap();
    assert_eq!(n.store.get_block(&m).unwrap().unwrap().height, ACT);
    assert_eq!(dag_height(&n, &m), ACT - 1);
    assert_eq!(next_height(&n), ACT);
    let _ = (s, x);
}

/// Finding: post-connect eviction (and re-injection) used the new tip's
/// HEADER height + 1. A tip T that merged a parent with a greater DAG height
/// than its selected parent has header(T) = DAG(T) + 1, while a child of T
/// alone sits at DAG(T) + 1 = header(T). With the activation at header(T) + 1
/// the old code evicted every pooled version-1 payment although the next
/// block could still mine it. Now it stays pooled, is still admitted, and the
/// next template (a child of T, at header(T) = ACT-1) mines it.
#[test]
fn post_connect_maintenance_uses_the_template_height_not_the_header_height() {
    const ACT: u64 = 9;
    let _g = activation::scoped_override(ACT);
    let k = key();
    let f: Vec<_> = (0..3u8).map(|i| fund(0xF4 + i, 2 * SAT, &k.spk)).collect();
    let n = node_with_dag8_shapes(&f);
    advance_to(&n, ACT - 5);
    let pay = |i: usize| vec![out(2 * SAT - FEE, &[0xFC + i as u8; 20])];

    let (s, x) = heavy_merge_and_light_long_tip(&n);
    assert_eq!(next_height(&n), ACT - 1, "template on {{S, X}}");
    let p = v2_spend(&k, &[(f[0].0, 0)], pay(0));
    admit(&n, &p).expect("version 1 for ACT-1");

    // T on {S, X}, no transactions: header ACT-1, DAG height ACT-2.
    let t = accept(&n, &block_on_where(&n, vec![s, x], vec![], |_| true)).unwrap();
    assert_eq!(applied_tip(&n), Some(t));
    assert_eq!(n.store.get_block(&t).unwrap().unwrap().height, ACT - 1);
    assert_eq!(dag_height(&n, &t), ACT - 2);
    assert_eq!(next_height(&n), ACT - 1, "a child of T alone: DAG(T) + 1, not header(T) + 1");
    assert!(n.mempool.contains(&p.txid()), "the version-1 payment is still valid for the next block");
    let q = v2_spend(&k, &[(f[1].0, 0)], pay(1));
    admit(&n, &q).expect("version 1 is still admitted for ACT-1");

    // The next template is a child of T at ACT-1 and mines both.
    let mined = mine_template(&n);
    let mut got: Vec<_> = mined.iter().map(|t| t.txid()).collect();
    got.sort();
    let mut want = vec![p.txid(), q.txid()];
    want.sort();
    assert_eq!(got, want);
    assert_eq!(tip_height(&n), ACT - 1);
    assert!(spent(&n, &f[0]) && spent(&n, &f[1]));
    // Now the next block is ACT: version 3 from here on.
    assert_eq!(next_height(&n), ACT);
    let r = v3_spend(&k, &[(f[2].0, 0)], std::slice::from_ref(&f[2].2), pay(2));
    admit(&n, &r).expect("version 3 for ACT");
}

/// A template whose height differs from the pool's next height (only while
/// the cached height is stale) skips — never evicts — a transaction that
/// fails only the version rule at the template height but is valid at the
/// pool's height. With the heights equal the same transaction is evicted.
#[test]
fn template_skips_a_version_only_failure_at_another_height() {
    const ACT: u64 = 8;
    let _g = activation::scoped_override(ACT);
    let k = key();
    let f = fund(0xF7, 2 * SAT, &k.spk);
    let n = node_with_dag8_shapes(std::slice::from_ref(&f));
    advance_to(&n, ACT - 4);
    heavy_merge_and_light_long_tip(&n);
    assert_eq!(next_height(&n), ACT);

    let p = v2_spend(&k, &[(f.0, 0)], vec![out(2 * SAT - FEE, &[0xFB; 20])]);
    n.mempool.set_next_height(ACT - 1); // a stale pool height (simulated)
    n.mempool.add(p.clone(), FEE).unwrap();
    let tmpl = template::build_block_template(&n.dag, &n.store, &n.mempool, template::EXTERNAL_COINBASE_RESERVE).unwrap();
    assert_eq!(tmpl.height, ACT);
    assert!(tmpl.transactions.is_empty());
    assert_eq!(tmpl.evicted, 0, "skipped, not evicted");
    assert!(n.mempool.contains(&p.txid()));

    n.mempool.set_next_height(ACT);
    let tmpl = template::build_block_template(&n.dag, &n.store, &n.mempool, template::EXTERNAL_COINBASE_RESERVE).unwrap();
    assert_eq!(tmpl.evicted, 1, "invalid for the block the pool targets: evicted");
    assert!(!n.mempool.contains(&p.txid()));
}

// ── Review (P4 merge): the recent-rejects filter follows the next height ─────

/// Review finding: a refusal that depends on the next block's height (here
/// the version policy: version 3 below the activation) was remembered in the
/// recent-rejects filter, which only a TIP change cleared. A DAG change that
/// moves the template height without moving the applied tip (a lighter tip
/// with a greater DAG height, stored as a fork-loser:
/// `accept::sync_mempool_next_height`) left the stale verdict in place, so
/// a wallet's version-3 payment for the new height ACT was refused as
/// "recently rejected" (RPC and gossip) until the next tip change. Now the
/// filter is cleared whenever the next height moves, and a verdict computed
/// before such a change is never remembered after it (epoch check).
#[test]
fn recent_rejects_are_forgotten_when_the_next_height_moves_without_a_tip_change() {
    const ACT: u64 = 8;
    let _g = activation::scoped_override(ACT);
    let k = key();
    let f = fund(0xE6, 2 * SAT, &k.spk);
    let n = node_with_dag8_shapes(std::slice::from_ref(&f));
    advance_to(&n, ACT - 4);
    // S merges three siblings of A (the most blue work); X1 -> X2 is a
    // lighter side chain from A.
    let a = sel_tip(&n).unwrap();
    let bs: Vec<BlockHash> = (0..3).map(|_| accept(&n, &child_where(&n, a, vec![], |_| true)).unwrap()).collect();
    let s = accept(&n, &block_on_where(&n, bs, vec![], |_| true)).unwrap();
    let x1 = accept(&n, &child_where(&n, a, vec![], |_| true)).unwrap();
    let x2 = accept(&n, &child_where(&n, x1, vec![], |_| true)).unwrap();
    assert_eq!(applied_tip(&n), Some(s));
    assert_eq!(next_height(&n), ACT - 1);

    // A version-3 payment signed for ACT is refused for ACT-1 (policy) and
    // remembered.
    let pay = v3_spend(&k, &[(f.0, 0)], std::slice::from_ref(&f.2), vec![out(2 * SAT - FEE, &[0xE7; 20])]);
    let err = admit(&n, &pay).unwrap_err();
    assert!(matches!(&err, AdmissionError::NonStandard(m) if m.contains("non-standard-version")), "{err}");
    assert!(n.mempool.is_recently_rejected(&admission::wtxid(&pay)));

    // X (DAG height ACT-1) is stored as a fork-loser: the applied tip stays
    // S, the template merges X, the next height moves to ACT.
    let x = accept(&n, &child_where(&n, x2, vec![], |_| true)).unwrap();
    assert_eq!(applied_tip(&n), Some(s), "no tip change");
    assert_eq!(dag_height(&n, &x), ACT - 1);
    assert_eq!(next_height(&n), ACT);
    assert!(!n.mempool.is_recently_rejected(&admission::wtxid(&pay)), "the verdict for ACT-1 is forgotten");
    admit(&n, &pay).expect("valid and standard for ACT");

    // The epoch: a verdict computed before the next height moved (the filter
    // cleared) is not remembered after it.
    let w = [0x5E; 32];
    let epoch = n.mempool.recent_rejects_epoch();
    n.mempool.clear_recent_rejects();
    assert!(!n.mempool.note_rejected_in_epoch(w, epoch));
    assert!(!n.mempool.is_recently_rejected(&w));
    assert!(n.mempool.note_rejected_in_epoch(w, n.mempool.recent_rejects_epoch()));
    assert!(n.mempool.is_recently_rejected(&w));
}

// ── Review: admission re-checks the next height under the acceptance lock ───

/// A transaction checked for H-1 (outside the lock: the signature work takes
/// milliseconds) while block H-1 connects must not be inserted after the
/// post-connect eviction: `admit` re-checks the version rule and policy (and
/// coinbase maturity) against the pool's current next height under the
/// acceptance lock. Same in reverse for version 3 after a move back below H.
#[test]
fn admission_rechecks_the_next_height_under_the_acceptance_lock() {
    let _g = activation::scoped_override(H);
    let k = key();
    let f: Vec<_> = (0..2u8).map(|i| fund(0xEA + i, 2 * SAT, &k.spk)).collect();
    let n = node_with(&mk_genesis(unix_now() - 10_000), &f);
    advance_to(&n, H - 2);
    let checked_for = next_height(&n);
    assert_eq!(checked_for, H - 1);

    // Block H-1 connects between the check and the insert.
    extend(&n, vec![]).unwrap();
    assert_eq!(n.mempool.next_height(), H);
    let v1 = v2_spend(&k, &[(f[0].0, 0)], vec![out(2 * SAT - FEE, &[0xEC; 20])]);
    admission::check_transaction(&n.store, Some(&n.mempool), &v1, &AdmissionPolicy::relay(checked_for))
        .expect("valid at the height it was checked for");
    let err = admission::admit(&n.store, &n.mempool, v1.clone(), &AdmissionPolicy::relay(checked_for)).unwrap_err();
    assert!(matches!(&err, AdmissionError::NonStandard(m) if m.contains("bad-txns-version") && m.contains("moved")), "{err}");
    assert!(!n.mempool.contains(&v1.txid()));

    // Reverse: a version-3 spend checked for H, inserted after the next
    // height moved back to H-1 (simulated), is refused by the policy.
    let v3 = v3_spend(&k, &[(f[1].0, 0)], std::slice::from_ref(&f[1].2), vec![out(2 * SAT - FEE, &[0xED; 20])]);
    n.mempool.set_next_height(H - 1);
    let err = admission::admit(&n.store, &n.mempool, v3.clone(), &AdmissionPolicy::relay(H)).unwrap_err();
    assert!(matches!(&err, AdmissionError::NonStandard(m) if m.contains("non-standard-version")), "{err}");
    n.mempool.set_next_height(H);
    admission::admit(&n.store, &n.mempool, v3.clone(), &AdmissionPolicy::relay(H)).expect("current height");
    assert!(n.mempool.contains(&v3.txid()));
}
