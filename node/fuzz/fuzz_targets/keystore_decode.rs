//! Encrypted key files (untrusted JSON read from disk or pasted into a
//! wallet): the v1/v2 keyfile (`wallet::encryption::EncryptedKeyfile`,
//! `Wallet::from_encrypted_bytes`) and the v2/v3 keystore
//! (`wallet::EncryptedKeystore`, `Keypair::from_encrypted_bytes`).
//!
//! Every decrypt path is driven to completion only with cheap Argon2
//! parameters (both formats carry their own parameters, so the fuzzer can
//! choose them): above the fast threshold the KDF would make each execution
//! take seconds, and those inputs stop at the parsing layer, except that
//! parameters over the library's bounds must be refused before any KDF work.
//!
//! * Arbitrary bytes: parsing and every decrypt entry point never panic.
//! * Keyfile v1/v2 written by the library (fast parameters): it decrypts back
//!   to the same secret, public key, network (and seed); a wrong password
//!   and any single altered field the AEAD binds (public key, network,
//!   ciphertext, nonce, salt, version, KDF cost) are refused.
//! * Keystore v3 written by an INDEPENDENT implementation of the format
//!   (Argon2id, AES-256-GCM, the documented associated data): the library
//!   loads exactly the written key pair, and altering the network, the
//!   address, the version or the ciphertext makes it fail.
//! * The spending unlock (`Keypair::unlock_for_spending_bytes`, the entry
//!   point of the keystore v2 -> v3 migration): on arbitrary bytes it never
//!   panics, never unlocks what the plain load refuses, and never migrates
//!   without a stated network; a keystore v3 unlocks with no migration for
//!   its own network or none stated, and is refused for the other network.
//!   (The migration itself re-encrypts with the production KDF cost, seconds
//!   per execution, so it is not driven: a v2 keystore is only unlocked with
//!   no network stated, which refuses before any re-encryption.)
#![no_main]

mod common;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use common::*;
use gnb_crypto::address::Network;
use gnb_crypto::wallet::encryption::{EncryptedKeyfile, KdfParams, NetworkStr};
use gnb_crypto::wallet::{EncryptedKeystore, Keypair, Wallet, WalletError, KEYSTORE_VERSION_V3};
use libfuzzer_sys::fuzz_target;
use serde_json::{json, Value};

const PASSWORD: &str = "fuzzing-keyfile-passphrase-7";
const FAST: KdfParams = KdfParams { m_cost: 8, t_cost: 1, p_cost: 1 };

/// Argon2 parameters cheap enough to run on every fuzz input.
fn cheap(m: u32, t: u32, p: u32) -> bool {
    m <= 64 && t <= 2 && p <= 2
}
/// Over the library's bounds: refused before any KDF work.
fn over_bounds(m: u32, t: u32, p: u32) -> bool {
    m > 1024 * 1024 || t > 16 || p > 16
}

fn raw_json(bytes: &[u8]) {
    if let Ok(kf) = serde_json::from_slice::<EncryptedKeyfile>(bytes) {
        let (m, t, p) = (kf.kdf.m_cost, kf.kdf.t_cost, kf.kdf.p_cost);
        if over_bounds(m, t, p) {
            assert!(kf.decrypt(PASSWORD).is_err());
            assert!(kf.decrypt_v2(PASSWORD).is_err());
            assert!(Wallet::from_encrypted_bytes(bytes, PASSWORD).is_err());
        } else if cheap(m, t, p) {
            let _ = kf.decrypt(PASSWORD);
            let _ = kf.decrypt_v2(PASSWORD);
            let _ = Wallet::from_encrypted_bytes(bytes, PASSWORD);
        }
    }
    if let Ok(ks) = serde_json::from_slice::<EncryptedKeystore>(bytes) {
        let k = &ks.crypto.kdf_params;
        if over_bounds(k.memory_cost, k.time_cost, k.parallelism) {
            assert!(Keypair::from_encrypted_bytes(bytes, PASSWORD).is_err());
            assert!(Keypair::unlock_for_spending_bytes(bytes, PASSWORD, None).is_err());
        } else if cheap(k.memory_cost, k.time_cost, k.parallelism) {
            let loaded = Keypair::from_encrypted_bytes(bytes, PASSWORD);
            match (&loaded, Keypair::unlock_for_spending_bytes(bytes, PASSWORD, None)) {
                (Err(e), Ok(_)) => panic!("unlocked for spending a keystore the plain load refuses ({e})"),
                (Ok(k), Ok((u, migrated))) => {
                    assert!(migrated.is_none(), "migrated with no network stated");
                    assert_eq!((&u.private_key, &u.public_key), (&k.private_key, &k.public_key));
                }
                _ => {}
            }
            // A stated network only for v3 (no migration, no production KDF).
            if ks.version == KEYSTORE_VERSION_V3 {
                for n in [Network::Mainnet, Network::Testnet] {
                    if let Ok((u, migrated)) = Keypair::unlock_for_spending_bytes(bytes, PASSWORD, Some(n)) {
                        assert!(migrated.is_none(), "a keystore v3 was migrated");
                        assert_eq!(u.network().ok(), Some(n), "a keystore v3 unlocked for another network");
                    }
                }
            }
        }
    }
}

fn net(b: bool) -> Network {
    if b {
        Network::Testnet
    } else {
        Network::Mainnet
    }
}

/// Alter one field of a keyfile JSON value; returns false if nothing changed.
fn tamper_keyfile(v: &mut Value, inp: &mut Input) -> bool {
    let flip_b64 = |s: &str, at: usize, x: u8| -> String {
        let mut raw = B64.decode(s).unwrap();
        if raw.is_empty() {
            raw.push(x);
        } else {
            let i = at % raw.len();
            raw[i] ^= x;
        }
        B64.encode(raw)
    };
    let at = inp.u16() as usize;
    let x = inp.u8() | 1;
    match inp.u8() % 7 {
        0 => v["meta"]["public_key_b64"] = json!(flip_b64(v["meta"]["public_key_b64"].as_str().unwrap(), at, x)),
        1 => {
            let flipped = if v["network"] == "mainnet" { "testnet" } else { "mainnet" };
            v["network"] = json!(flipped);
        }
        2 => v["cipher"]["ciphertext_b64"] = json!(flip_b64(v["cipher"]["ciphertext_b64"].as_str().unwrap(), at, x)),
        3 => v["cipher"]["nonce_b64"] = json!(flip_b64(v["cipher"]["nonce_b64"].as_str().unwrap(), at, x)),
        4 => v["kdf"]["salt_b64"] = json!(flip_b64(v["kdf"]["salt_b64"].as_str().unwrap(), at, x)),
        5 => {
            let ver = v["version"].as_u64().unwrap();
            v["version"] = json!(ver ^ (x as u64 & 3).max(1));
        }
        _ => {
            // Another (still cheap) cost: a different key.
            v["kdf"]["t_cost"] = json!(2);
        }
    }
    true
}

fn keyfile_round_trip(inp: &mut Input, v2: bool) {
    let secret = inp.var_bytes(64);
    let public = inp.var_bytes(64);
    let seed = {
        let n = 32 + inp.below(97);
        inp.bytes(n)
    };
    let network = net(inp.bool());
    let kf = if v2 {
        EncryptedKeyfile::encrypt_seed_v2_with_params(&seed, &secret, &public, network, PASSWORD, FAST)
    } else {
        EncryptedKeyfile::encrypt_with_params(&secret, &public, network, PASSWORD, FAST)
    }
    .expect("encrypt with fast parameters");
    let json_bytes = serde_json::to_vec(&kf).unwrap();
    let back: EncryptedKeyfile = serde_json::from_slice(&json_bytes).expect("re-parse");
    if v2 {
        let (s, k, p, n) = back.decrypt_v2(PASSWORD).expect("v2 round trip");
        assert_eq!((s.as_slice(), k.as_slice(), p.as_slice(), n), (&seed[..], &secret[..], &public[..], network));
        assert!(back.decrypt(PASSWORD).is_err(), "a v2 keyfile opened as v1");
    } else {
        let (k, p, n) = back.decrypt(PASSWORD).expect("v1 round trip");
        assert_eq!((k.as_slice(), p.as_slice(), n), (&secret[..], &public[..], network));
        let w = Wallet::from_encrypted_bytes(&json_bytes, PASSWORD).expect("wallet from keyfile");
        assert_eq!((w.public_key(), w.network()), (&public[..], network));
        assert!(back.decrypt_v2(PASSWORD).is_err(), "a v1 keyfile opened as v2");
    }
    assert!(back.decrypt("wrong-password-but-long").is_err());
    assert!(back.decrypt_v2("wrong-password-but-long").is_err());

    let mut v: Value = serde_json::from_slice(&json_bytes).unwrap();
    if !tamper_keyfile(&mut v, inp) {
        return;
    }
    let tampered = serde_json::to_vec(&v).unwrap();
    if let Ok(t) = serde_json::from_slice::<EncryptedKeyfile>(&tampered) {
        assert!(t.decrypt(PASSWORD).is_err(), "a tampered v1 keyfile decrypted");
        assert!(t.decrypt_v2(PASSWORD).is_err(), "a tampered v2 keyfile decrypted");
    }
    assert!(Wallet::from_encrypted_bytes(&tampered, PASSWORD).is_err());
}

/// Keystore v3 from the format description (`wallet/mod.rs`), not the writer.
fn spec_keystore_v3(private_key: &[u8], public_key: &[u8], testnet: bool, salt: &[u8], nonce: [u8; 12]) -> Value {
    use sha3::Digest as _;
    let hash = sha3::Sha3_256::digest(public_key);
    let payload: Vec<u8> = {
        let mut p = hash[..20].to_vec();
        let check = sha3::Sha3_256::digest(sha3::Sha3_256::digest(&hash[..20]));
        p.extend_from_slice(&check[..4]);
        p
    };
    let address = format!("{}{}", if testnet { "gnb1t" } else { "gnb1q" }, hex::encode(payload));
    let network = if testnet { "testnet" } else { "mainnet" };
    let mut aad = b"GNB-KEYSTORE-v3\0".to_vec();
    aad.extend_from_slice(&3u32.to_le_bytes());
    aad.push(testnet as u8);
    aad.extend_from_slice(&(address.len() as u32).to_le_bytes());
    aad.extend_from_slice(address.as_bytes());
    let mut key = [0u8; 32];
    argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(8, 1, 1, Some(32)).unwrap(),
    )
    .hash_password_into(PASSWORD.as_bytes(), salt, &mut key)
    .unwrap();
    let plain = serde_json::to_vec(&json!({
        "private_key_hex": hex::encode(private_key),
        "public_key_hex": hex::encode(public_key),
    }))
    .unwrap();
    let ct = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key))
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: &plain, aad: &aad })
        .unwrap();
    json!({
        "version": 3,
        "address": address,
        "network": network,
        "crypto": {
            "cipher": "aes-256-gcm",
            "ciphertext": B64.encode(ct),
            "nonce": B64.encode(nonce),
            "kdf": "argon2id",
            "kdf_params": { "memory_cost": 8, "time_cost": 1, "parallelism": 1, "salt": B64.encode(salt), "output_len": 32 },
        },
        "created_at": "2026-10-15T00:00:00Z",
        "description": "fuzz",
    })
}

fn keystore_v3(inp: &mut Input) {
    let private_key = inp.var_bytes(64);
    let public_key = inp.var_bytes(64);
    let testnet = inp.bool();
    let salt_len = 8 + inp.below(25);
    let salt = inp.bytes(salt_len);
    let nonce = inp.arr::<12>();
    let v = spec_keystore_v3(&private_key, &public_key, testnet, &salt, nonce);
    let bytes = serde_json::to_vec(&v).unwrap();
    let kp = Keypair::from_encrypted_bytes(&bytes, PASSWORD).expect("library refuses a keystore v3 written to the specification");
    assert_eq!((kp.private_key.as_slice(), kp.public_key.as_slice()), (&private_key[..], &public_key[..]));
    assert_eq!(kp.address, v["address"].as_str().unwrap());
    assert!(Keypair::from_encrypted_bytes(&bytes, "wrong-password-but-long").is_err());
    for stated in [None, Some(net(testnet))] {
        let (u, migrated) = Keypair::unlock_for_spending_bytes(&bytes, PASSWORD, stated)
            .expect("a keystore v3 does not unlock for spending on its own network");
        assert!(migrated.is_none(), "a keystore v3 was migrated");
        assert_eq!((u.private_key.as_slice(), u.public_key.as_slice()), (&private_key[..], &public_key[..]));
    }
    assert!(
        Keypair::unlock_for_spending_bytes(&bytes, PASSWORD, Some(net(!testnet))).is_err(),
        "a keystore v3 unlocked for spending on the other network"
    );

    let mut t = v.clone();
    match inp.u8() % 5 {
        0 => t["network"] = json!(if testnet { "mainnet" } else { "testnet" }),
        1 => {
            // The other network's address for the same key (the checksum does
            // not cover the prefix: only the AAD catches this).
            let a = t["address"].as_str().unwrap();
            let flipped = if testnet { a.replacen("gnb1t", "gnb1q", 1) } else { a.replacen("gnb1q", "gnb1t", 1) };
            t["address"] = json!(flipped);
            t["network"] = json!(if testnet { "mainnet" } else { "testnet" });
        }
        2 => t["version"] = json!(2), // v2 = empty associated data
        3 => {
            let mut ct = B64.decode(t["crypto"]["ciphertext"].as_str().unwrap()).unwrap();
            let i = inp.below(ct.len());
            ct[i] ^= inp.u8() | 1;
            t["crypto"]["ciphertext"] = json!(B64.encode(ct));
        }
        _ => t["crypto"]["kdf_params"]["output_len"] = json!(16),
    }
    let tampered = serde_json::to_vec(&t).unwrap();
    assert!(Keypair::from_encrypted_bytes(&tampered, PASSWORD).is_err(), "a tampered keystore v3 loaded");
}

fuzz_target!(|data: &[u8]| {
    let mut inp = Input::new(data);
    match inp.u8() % 4 {
        0 => raw_json(inp.rest()),
        1 => keyfile_round_trip(&mut inp, false),
        2 => keyfile_round_trip(&mut inp, true),
        _ => keystore_v3(&mut inp),
    }
    // Keep `NetworkStr` and `WalletError` exercised in the API surface.
    let _ = (NetworkStr::from(Network::Mainnet), WalletError::WrongPassword);
});
