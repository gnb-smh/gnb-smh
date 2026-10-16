//! Bridge vault: policy-tree spends through consensus validation.
//!
//! Release branch (k-of-n, no timelock), recovery branch (r-of-s after a
//! relative timelock), activation gating, a wrong branch path, and the
//! release shape a signer checks (`bridge::check_release`).
//!
//! This test binary sets the PoWit activation height (policy trees share it)
//! once for the whole process.

use gnb::address::Network;
use gnb::blockval::{validate_tx_inputs, SpendContext};
use gnb::bridge::{self, Vault, RECOVERY_BRANCH, RELEASE_BRANCH};
use gnb::core::policy::{AnyPolicyWitness, BranchWitness};
use gnb::core::{self, TxOutput};
use gnb::crypto;
use gnb::wallet::policy_spend::PolicySpend;

const ACTIVATION: u64 = 1_000;
const OLDER: u32 = 500;

fn activate() {
    let _ = core::set_node_chain_id(core::ChainId::Testnet);
    let _ = core::set_powit_height_override(ACTIVATION);
}

struct Setup {
    vault: Vault,
    signers: Vec<(Vec<u8>, Vec<u8>)>,
    cold: Vec<(Vec<u8>, Vec<u8>)>,
}

fn setup() -> Setup {
    activate();
    let signers: Vec<_> = (0..3).map(|_| crypto::generate_keypair()).collect();
    let cold: Vec<_> = (0..2).map(|_| crypto::generate_keypair()).collect();
    let vault = Vault::create(Network::Testnet, 2, signers.iter().map(|k| k.0.clone()).collect(),
                              1, cold.iter().map(|k| k.0.clone()).collect(), OLDER).unwrap();
    Setup { vault, signers, cold }
}

const DEPOSIT: ([u8; 32], u32, u64) = ([0x5A; 32], 0, 50_000_000);
const DEPOSIT_HEIGHT: u64 = 1_200;

/// Testnet has the hardening rules from genesis: every spend is version 3
/// and signs the sighash-v3 digest (`crypto::sign_bound`).
fn v3(mut spend: PolicySpend) -> PolicySpend {
    spend.target_height(DEPOSIT_HEIGHT + 1).unwrap();
    assert_eq!(spend.tx.version, core::sighash::TX_VERSION_V3);
    spend
}

fn sign_key(spend: &mut PolicySpend, pk: &[u8], sk: &[u8]) -> Result<u8, String> {
    spend.sign_digest(pk, |d, v| match v {
        core::sighash::SighashVersion::V2 => crypto::sign(sk, d),
        core::sighash::SighashVersion::V3 => crypto::sign_bound(sk, d),
    }.map_err(|e| format!("{e:?}")))
}

fn sign_all(spend: &mut PolicySpend, keys: &[(Vec<u8>, Vec<u8>)]) {
    for (pk, sk) in keys {
        sign_key(spend, pk, sk).unwrap();
    }
}

/// Validate `tx` (spending DEPOSIT, locked by the vault) in a block at `height`.
fn validate(s: &Setup, tx: &core::Transaction, height: u64) -> Result<u64, String> {
    let vault_out = TxOutput { value: DEPOSIT.2, script_pubkey: s.vault.script().unwrap() };
    let lookup = |t: &[u8; 32], i: u32| -> Result<Option<TxOutput>, String> {
        Ok((*t == DEPOSIT.0 && i == DEPOSIT.1).then(|| vault_out.clone()))
    };
    let confirm = |t: &[u8; 32]| -> Result<Option<u64>, String> { Ok((*t == DEPOSIT.0).then_some(DEPOSIT_HEIGHT)) };
    validate_tx_inputs(tx, &lookup, None, &SpendContext { height, confirm_height: &confirm })
}

fn release(s: &Setup, burn: [u8; 32], amount: u64) -> PolicySpend {
    let recipient = vec![0x11; 20];
    // The vault pays exactly `amount`: payout = amount - marker - fee, so the
    // fee must be known first; build once to learn it, then rebuild.
    let probe = PolicySpend::new_branch(Network::Testnet, s.vault.tree().unwrap(), RELEASE_BRANCH, &[DEPOSIT],
        bridge::release_outputs(&recipient, amount - bridge::MARKER_VALUE - 1, &burn), 0, 0).unwrap();
    let fee = DEPOSIT.2 - probe.outputs_total();
    v3(PolicySpend::new_branch(Network::Testnet, s.vault.tree().unwrap(), RELEASE_BRANCH, &[DEPOSIT],
        bridge::release_outputs(&recipient, amount - bridge::MARKER_VALUE - fee, &burn), fee, 0).unwrap())
}

#[test]
fn release_branch_spends_with_k_signatures_and_hides_the_recovery_keys() {
    let s = setup();
    let burn = [7u8; 32];
    let mut spend = release(&s, burn, 3_000_000);
    sign_all(&mut spend, &s.signers[..1]);
    assert!(spend.finalize().is_err(), "1 of 2 required signatures");
    sign_all(&mut spend, &s.signers[2..3]);
    let tx = PolicySpend::from_json(&spend.to_json().unwrap()).unwrap().finalize().unwrap();

    // Consensus accepts it from activation, refuses it before.
    assert!(validate(&s, &tx, DEPOSIT_HEIGHT + 1).is_ok());
    assert!(validate(&s, &tx, ACTIVATION - 1).unwrap_err().contains("before activation"));

    // The witness reveals only branch 0: no cold key appears in it.
    let w = AnyPolicyWitness::decode(&tx.inputs[0].script_sig).unwrap();
    assert!(w.is_branch());
    let raw = &tx.inputs[0].script_sig;
    for (cold_pk, _) in &s.cold {
        assert!(!raw.windows(64).any(|win| win == &cold_pk[4..68]), "recovery key leaked into a release");
    }

    // What a signer checks before co-signing.
    let inputs = vec![(DEPOSIT.2, s.vault.script().unwrap())];
    let fee = bridge::check_release(&tx.outputs, &inputs, &s.vault.script().unwrap(), &[0x11; 20], 3_000_000, &burn)
        .unwrap();
    assert!(fee <= bridge::MAX_RELEASE_FEE);
    assert!(bridge::check_release(&tx.outputs, &inputs, &s.vault.script().unwrap(), &[0x11; 20], 3_000_000, &[8u8; 32])
        .is_err(), "another burn's release is refused");
}

#[test]
fn recovery_branch_waits_for_its_relative_timelock() {
    let s = setup();
    let mut spend = v3(PolicySpend::new_branch(Network::Testnet, s.vault.tree().unwrap(), RECOVERY_BRANCH, &[DEPOSIT],
        vec![TxOutput { value: 10_000_000, script_pubkey: vec![0x22; 20] }], 0, 0).unwrap());
    sign_all(&mut spend, &s.cold[..1]);
    let tx = spend.finalize().unwrap();
    let early = DEPOSIT_HEIGHT + OLDER as u64 - 1;
    assert!(validate(&s, &tx, early).unwrap_err().contains("relative timelock"));
    assert!(validate(&s, &tx, DEPOSIT_HEIGHT + OLDER as u64).is_ok());
}

#[test]
fn signers_cannot_use_the_recovery_branch_and_paths_cannot_be_forged() {
    let s = setup();
    // Signer keys are not in branch 1.
    let mut spend = v3(PolicySpend::new_branch(Network::Testnet, s.vault.tree().unwrap(), RECOVERY_BRANCH, &[DEPOSIT],
        vec![TxOutput { value: 10_000_000, script_pubkey: vec![0x22; 20] }], 0, 0).unwrap());
    assert!(sign_key(&mut spend, &s.signers[0].0, &s.signers[0].1).unwrap_err().contains("not part of the policy"));

    // A branch witness whose path does not lead to the vault root is refused,
    // even with valid signatures for the branch it reveals.
    let mut spend = release(&s, [9u8; 32], 2_000_000);
    sign_all(&mut spend, &s.signers[..2]);
    let mut tx = spend.finalize().unwrap();
    let AnyPolicyWitness::Branch(mut w) = AnyPolicyWitness::decode(&tx.inputs[0].script_sig).unwrap() else {
        panic!("branch witness expected")
    };
    w.path[0][0] ^= 1;
    tx.inputs[0].script_sig = BranchWitness { ..w }.encode();
    assert!(validate(&s, &tx, DEPOSIT_HEIGHT + 1).unwrap_err().contains("does not match the output"));
}

#[test]
fn lock_built_by_the_tools_parses_back() {
    let s = setup();
    let vs = s.vault.script().unwrap();
    let outs = bridge::lock_outputs(&vs, 25_000_000, [0xCD; 20]);
    let lock = bridge::parse_lock(&outs, &vs, 1_000_000).unwrap();
    assert_eq!(lock.amount, 25_000_000);
    assert_eq!(lock.l2_recipient, [0xCD; 20]);
}
