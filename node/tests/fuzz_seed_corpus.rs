//! Seed corpora of the cargo-fuzz targets added by the 2026-10 hardening
//! (`fuzz/fuzz_targets/{block_rules, sighash, witness_parse, wire_roundtrip,
//! undo_decode, keystore_decode, address_parse, sync_rr_codec, accept_dag}`)
//! and of `header_parse` (an original target `parser_corpus_floor.rs` does
//! not seed), and their stable-Rust floor.
//!
//! * `GNB_WRITE_FUZZ_SEEDS=1 cargo test -p gnb --test fuzz_seed_corpus`
//!   (re)writes the generated seeds `fuzz/corpus/<target>/seed_*`.
//! * Without it, `committed_seeds_are_reproducible` checks every committed
//!   `seed_*` file against what this file generates (the corpus is a
//!   reproducible asset: deterministic keys, seeded signing RNG, fixed salts),
//!   and `corpus_floor_*` replays EVERY file of those corpora (seeds and the
//!   crash reproducers added by the fuzzing campaign, `regress_*`) through
//!   the parsing entry points the targets exercise, asserting no panic.
//!
//! Each seed starts with the mode byte(s) the target reads first (see the
//! target's source), followed by the payload: real encodings (blocks valid
//! under the hardening rules, canonical witnesses with genuine signatures,
//! undo records, key files, sync frames, addresses) so the fuzzer starts
//! from the accepting paths instead of having to discover them.

use std::collections::BTreeMap;
use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use gnb::address::{Address, Network};
use gnb::core::{
    activation, block_rules, Block, BlockHeader, MerkleRoot, Transaction, TxInput, TxOutput, UndoData, UndoEntry,
};
use gnb::crypto;
use gnb::network::sync_rr::{decode_request, decode_response, encode_frame, SyncRequest, SyncResponse};
use gnb::network::SyncEntry;
use sha3::{Digest, Sha3_256};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
    fn arr32(&mut self) -> [u8; 32] {
        let mut a = [0u8; 32];
        for b in a.iter_mut() {
            *b = self.next() as u8;
        }
        a
    }
}

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus")
}

fn with(prefix: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut v = prefix.to_vec();
    v.extend_from_slice(payload);
    v
}

/// Deterministic hybrid key pair (seeded keygen).
fn keypair() -> (Vec<u8>, Vec<u8>) {
    crypto::generate_keypair_from_seed(&[0x3Cu8; 64]).expect("seeded keygen")
}

fn coinbase(script_sig: Vec<u8>, value: u64) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput { prev_txid: [0; 32], prev_index: u32::MAX, script_sig, sequence: u32::MAX }],
        outputs: vec![TxOutput { value, script_pubkey: vec![0xC0; 20] }],
        locktime: 0,
    }
}

/// A version-3 spend with a canonical witness (deterministic signature).
fn signed_spend(pk: &[u8], sk: &[u8], tag: u8) -> Transaction {
    let spent = TxOutput { value: 5_000_000, script_pubkey: Sha3_256::digest(pk)[..20].to_vec() };
    let mut tx = Transaction {
        version: 3,
        inputs: vec![TxInput { prev_txid: [tag; 32], prev_index: tag as u32, script_sig: vec![], sequence: u32::MAX }],
        outputs: vec![TxOutput { value: 4_900_000, script_pubkey: vec![tag; 20] }],
        locktime: 0,
    };
    let suite = crypto::public_key_suite(pk).unwrap();
    let d = tx.sighash_v3(&[spent], 0, suite, gnb::core::ChainId::Mainnet).unwrap();
    let sig = pqcrypto_internals::with_seeded_rng_scope(&[tag; 32], || crypto::sign_bound(sk, &d)).unwrap();
    tx.inputs[0].script_sig = Transaction::build_script_sig(&sig, pk);
    tx
}

/// A block valid under the hardening rules at `height` (commitment and tagged
/// root), not sealed (the targets that read blocks never check the proof).
fn hardened_block(height: u64, parents: Vec<[u8; 32]>, txs: Vec<Transaction>) -> Block {
    let mut all = vec![coinbase(b"seed".to_vec(), 1)];
    all.extend(txs);
    let mut b = Block {
        header: BlockHeader { version: 1, parents, merkle_root: MerkleRoot::ZERO, timestamp: 1_750_000_000 + height, bits: 0x2100_FFFF, nonce: 7 },
        transactions: all,
        blue_score: height,
        height,
        shielded_transactions: vec![],
        powit: Default::default(),
    };
    let c = block_rules::expected_coinbase_commitment(&b);
    let extra = std::mem::take(&mut b.transactions[0].inputs[0].script_sig);
    b.transactions[0].inputs[0].script_sig = block_rules::coinbase_script_sig(&c, &extra);
    b.header.merkle_root = b.body_merkle_root_at(0);
    b
}

fn legacy_block(r: &mut Rng) -> Block {
    let tx = Transaction {
        version: 1,
        inputs: vec![TxInput { prev_txid: r.arr32(), prev_index: 1, script_sig: r.bytes(30), sequence: 0 }],
        outputs: vec![TxOutput { value: 1_000, script_pubkey: r.bytes(20) }],
        locktime: 0,
    };
    let mut b = Block {
        header: BlockHeader { version: 1, parents: vec![r.arr32()], merkle_root: MerkleRoot::ZERO, timestamp: 1, bits: 0x2100_FFFF, nonce: 0 },
        transactions: vec![coinbase(b"gnb:h3:legacy".to_vec(), 50), tx],
        blue_score: 3,
        height: 3,
        shielded_transactions: vec![coherence_core::ShieldedTx {
            anchor: r.arr32(),
            nullifiers: vec![r.arr32()],
            outputs: vec![r.arr32()],
            fee: 10,
            proof: r.bytes(40),
            binding_sig: r.bytes(16),
        }],
        powit: Default::default(),
    };
    b.header.merkle_root = b.body_merkle_root_at(activation::NEVER);
    b
}

/// The v3 keystore format (`wallet/mod.rs`) written by hand with fast KDF
/// parameters and fixed salt and nonce.
fn keystore_v3_json(private_key: &[u8], public_key: &[u8], password: &str) -> Vec<u8> {
    let address = Address::from_pubkey(public_key, Network::Testnet).to_string();
    let mut aad = b"GNB-KEYSTORE-v3\0".to_vec();
    aad.extend_from_slice(&3u32.to_le_bytes());
    aad.push(1);
    aad.extend_from_slice(&(address.len() as u32).to_le_bytes());
    aad.extend_from_slice(address.as_bytes());
    let salt = [0x51u8; 16];
    let nonce = [0x4Eu8; 12];
    let mut key = [0u8; 32];
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, argon2::Params::new(8, 1, 1, Some(32)).unwrap())
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .unwrap();
    let plain = serde_json::to_vec(&serde_json::json!({
        "private_key_hex": hex::encode(private_key),
        "public_key_hex": hex::encode(public_key),
    }))
    .unwrap();
    let ct = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key))
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: &plain, aad: &aad })
        .unwrap();
    serde_json::to_vec(&serde_json::json!({
        "version": 3, "address": address, "network": "testnet",
        "crypto": { "cipher": "aes-256-gcm", "ciphertext": B64.encode(ct), "nonce": B64.encode(nonce), "kdf": "argon2id",
            "kdf_params": { "memory_cost": 8, "time_cost": 1, "parallelism": 1, "salt": B64.encode(salt), "output_len": 32 } },
        "created_at": "2026-10-15T00:00:00Z", "description": "seed",
    }))
    .unwrap()
}

/// The v1 keyfile format (`wallet/encryption.rs`) written by hand.
fn keyfile_v1_json(secret: &[u8], public: &[u8], password: &str) -> Vec<u8> {
    let salt = [0x52u8; 16];
    let nonce = [0x4Fu8; 12];
    let mut key = [0u8; 32];
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, argon2::Params::new(8, 1, 1, None).unwrap())
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .unwrap();
    let mut aad = b"bloch-kf".to_vec();
    aad.push(0);
    aad.extend_from_slice(public);
    let ct = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key))
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: secret, aad: &aad })
        .unwrap();
    serde_json::to_vec(&serde_json::json!({
        "version": 1, "network": "mainnet",
        "kdf": { "algo": "argon2id", "salt_b64": B64.encode(salt), "m_cost": 8, "t_cost": 1, "p_cost": 1 },
        "cipher": { "algo": "aes-256-gcm", "nonce_b64": B64.encode(nonce), "ciphertext_b64": B64.encode(ct) },
        "meta": { "public_key_b64": B64.encode(public), "address": Address::from_pubkey(public, Network::Mainnet).to_string() },
    }))
    .unwrap()
}

/// Every generated seed, by target.
fn seeds() -> BTreeMap<&'static str, Vec<Vec<u8>>> {
    let mut r = Rng(0x5EED_F022_2026_1015);
    let (pk, sk) = keypair();
    let mut m: BTreeMap<&'static str, Vec<Vec<u8>>> = BTreeMap::new();

    let spend_a = signed_spend(&pk, &sk, 1);
    let spend_b = signed_spend(&pk, &sk, 2);
    let hard = hardened_block(5, vec![[0x11; 32], [0x22; 32]], vec![spend_a.clone(), spend_b.clone()]);
    let hard_small = hardened_block(1, vec![[0x33; 32]], vec![]);
    let legacy = legacy_block(&mut r);
    let sixty_four = Transaction {
        version: 1,
        inputs: vec![TxInput { prev_txid: [9; 32], prev_index: 0, script_sig: vec![9; 12], sequence: u32::MAX }],
        outputs: vec![TxOutput { value: 1_000, script_pubkey: vec![0x5A; 5] }],
        locktime: 0,
    };
    let with_64 = hardened_block(2, vec![[0x44; 32]], vec![sixty_four.clone()]);

    // block_rules: [0 | id-list] and [1 | ctl(8) | block wire bytes].
    m.insert("block_rules", vec![
        with(&[0], &[3, 0]),
        with(&[0, 7, 0], &r.bytes(7 * 33)),
        with(&[0, 17, 0], &r.bytes(17 * 33)),
        with(&[1, 0, 0, 0, 0, 0, 0, 0, 0], &hard.to_wire_bytes()),
        with(&[1, 3, 1, 2, 9, 4, 0, 1, 7], &hard_small.to_wire_bytes()),
        with(&[1, 5, 2, 0, 0, 1, 0, 0, 0], &legacy.to_wire_bytes()),
        with(&[1, 0, 3, 7, 1, 0, 0, 0, 0], &with_64.to_wire_bytes()),
    ]);

    // sighash: structured bytes (index, suite, chain, field, ..., tx).
    m.insert("sighash", (0..6).map(|i| {
        let mut v = vec![i as u8, 0, 1, 0, i as u8 & 1, i as u8 * 2, 7, 0, 1, 0];
        v.extend(r.bytes(120 + 40 * i));
        v
    }).collect());

    // witness_parse: [0 | script_sig], [1 | parts], [2 | alterations].
    m.insert("witness_parse", vec![
        with(&[0], &spend_a.inputs[0].script_sig),
        with(&[0], &Transaction::build_script_sig(&[1, 2, 3], &[4, 5])),
        with(&[0], &[0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0]),
        with(&[1], &r.bytes(40)),
        with(&[2], &[0]),
        with(&[3, 2, 0, 0, 1, 0, 0x40], &[]),
        with(&[2, 3, 0, 3, 0, 0, 0x80, 2, 5, 0], &[]),
    ]);

    // wire_roundtrip: [mode | cut(2) | ...]; mode 3 carries real encodings.
    let mut wr = vec![
        with(&[0, 5, 0], &r.bytes(90)),
        with(&[1, 9, 0], &r.bytes(120)),
        with(&[2, 1, 1], &r.bytes(200)),
        with(&[3, 4, 0], &spend_a.to_wire_bytes(true)),
        with(&[3, 4, 0], &hard.header.to_wire_bytes(hard.blue_score, hard.height)),
        with(&[3, 4, 0], &legacy.to_wire_bytes()),
        with(&[3, 4, 0], &hard_small.to_wire_bytes()),
    ];
    // A non-minimal varint (0xFD 0x01 0x00 parent count) for the strictness check.
    let mut nonmin = hard_small.header.to_wire_bytes(1, 1);
    nonmin.splice(4..5, [0xFD, 0x01, 0x00]);
    wr.push(with(&[3, 0, 0], &nonmin));
    m.insert("wire_roundtrip", wr);

    // header_parse (an original target that had no corpus): raw header wire
    // bytes, parent counts 0 / 1 / 2 / 256 (the cap) / 257, near misses.
    let hdr = |parents: usize, r: &mut Rng| {
        let h = BlockHeader {
            version: 1,
            parents: (0..parents).map(|i| [i as u8; 32]).collect(),
            merkle_root: MerkleRoot(r.arr32()),
            timestamp: r.next(),
            bits: 0x2100_FFFF,
            nonce: r.next(),
        };
        h.to_wire_bytes(r.next() % 1000, r.next() % 1000)
    };
    // Its own stream, so the seeds of the other targets do not move.
    let mut rh = Rng(0x004E_ADE2_5EED);
    let h2 = hdr(2, &mut rh);
    let mut hp = vec![
        hard.header.to_wire_bytes(hard.blue_score, hard.height),
        legacy.header.to_wire_bytes(legacy.blue_score, legacy.height),
        hdr(0, &mut rh),
        h2.clone(),
        hdr(256, &mut rh),
        hdr(257, &mut rh),
        h2[..h2.len() - 1].to_vec(),
    ];
    let mut trailing = h2.clone();
    trailing.push(0);
    hp.push(trailing);
    m.insert("header_parse", hp);

    // undo_decode: [0 | stored bytes] (legacy and extended), [1 | generator].
    let mut u = UndoData::new(r.arr32(), 42);
    u.spent_utxos.push(UndoEntry { prev_txid: r.arr32(), prev_index: 1, output: TxOutput { value: 9, script_pubkey: r.bytes(20) } });
    u.created_utxo_keys.push((r.arr32(), 0));
    u.coinbase_txids.push(r.arr32());
    u.tx_index_keys.push(r.arr32());
    let legacy_undo = u.to_bytes().unwrap();
    u.overwritten.coinbase_heights.push((r.arr32(), 7));
    u.overwritten.utxos.push(UndoEntry { prev_txid: r.arr32(), prev_index: 2, output: TxOutput { value: 1, script_pubkey: vec![] } });
    let extended_undo = u.to_bytes().unwrap();
    m.insert("undo_decode", vec![
        with(&[0], &legacy_undo),
        with(&[0], &extended_undo),
        with(&[1], &r.bytes(80)),
        with(&[1], &r.bytes(200)),
    ]);

    // keystore_decode: [0 | JSON], [1/2/3 | generator bytes].
    const PW: &str = "fuzzing-keyfile-passphrase-7";
    m.insert("keystore_decode", vec![
        with(&[0], &keystore_v3_json(&r.bytes(32), &r.bytes(48), PW)),
        with(&[0], &keyfile_v1_json(&r.bytes(32), &r.bytes(40), PW)),
        with(&[0], br#"{"version":1,"network":"mainnet","kdf":{"algo":"argon2id","salt_b64":"","m_cost":4294967295,"t_cost":1,"p_cost":1},"cipher":{"algo":"aes-256-gcm","nonce_b64":"","ciphertext_b64":""},"meta":{"public_key_b64":"","address":""}}"#),
        with(&[1], &r.bytes(120)),
        with(&[2], &r.bytes(200)),
        with(&[3], &r.bytes(120)),
    ]);

    // address_parse: [0 | string], [1 | hash, network, ...].
    let a = Address::from_hash(r.bytes(20).try_into().unwrap(), Network::Mainnet).to_string();
    let t = Address::from_hash(r.bytes(20).try_into().unwrap(), Network::Testnet).to_string();
    m.insert("address_parse", vec![
        with(&[0], a.as_bytes()),
        with(&[0], t.to_uppercase().replacen("GNB1T", "gnb1t", 1).as_bytes()),
        with(&[0], t.replacen("gnb1t", "bloch1t", 1).as_bytes()),
        with(&[0], b"gnb1qshort"),
        with(&[1], &r.bytes(40)),
    ]);

    // sync_rr_codec: [0 | frame], [1 | request generator], [2 | response generator].
    let entry = |i: u8| SyncEntry { hash: [i; 32], blue_score: i as u64 * 1000, height: i as u64 };
    let frames = vec![
        encode_frame(&SyncRequest::GetBlock { block_hash: [7; 32] }).unwrap(),
        encode_frame(&SyncRequest::GetHeaders { from_blue_score: 70_000, limit: 500 }).unwrap(),
        encode_frame(&SyncRequest::GetTips).unwrap(),
        encode_frame(&SyncRequest::GetPeers).unwrap(),
        encode_frame(&SyncResponse::Block { block_hash: [8; 32], blue_score: 300, height: 299, block_data: hard_small.to_wire_bytes() }).unwrap(),
        encode_frame(&SyncResponse::BlockNotFound { block_hash: [9; 32] }).unwrap(),
        encode_frame(&SyncResponse::Headers { entries: (0..5).map(entry).collect() }).unwrap(),
        encode_frame(&SyncResponse::Tips { tips: (0..3).map(entry).collect(), locator: vec![[1; 32], [2; 32]] }).unwrap(),
        encode_frame(&SyncResponse::Peers { peers: vec!["/ip4/10.0.0.1/tcp/7333".into(), "/dns4/a.example/tcp/1".into()] }).unwrap(),
        encode_frame(&SyncResponse::Busy).unwrap(),
    ];
    let mut s: Vec<Vec<u8>> = frames.iter().map(|f| with(&[0], f)).collect();
    s.push(with(&[1], &r.bytes(48)));
    s.push(with(&[2], &r.bytes(64)));
    m.insert("sync_rr_codec", s);

    // accept_dag: [activation | restart | blocks...]: random DAG programs, and
    // each activation regime with a few blocks.
    let mut d: Vec<Vec<u8>> = (0..4).map(|i| with(&[i, 0], &r.bytes(40 + 30 * i as usize))).collect();
    d.push(vec![1, 0, 5, 0, 0, 0, 0x80, 7, 0, 0, 0, 0, 0x80, 1, 0x21, 0, 0, 1, 0, 0, 0x80, 2, 0x33]);
    d.push(vec![2, 4, 1, 0, 3, 0, 0, 0, 0x80, 7, 0x10, 0, 1, 0, 0, 0x80, 4, 0x51, 1, 0, 0, 0, 0, 0x05, 9]);
    // Historical scenarios, as accept_dag programs (layout: activation,
    // restart, u16 block count - 1, then per block: u16 parents - 1, u16
    // parent index per parent, flags, u16 timestamp step, u16 tx count, one
    // slot byte per tx, coinbase tag; then the permutation draws).
    // DAG-1: sibling blocks on the genesis carrying the same spend, delivered
    // in both orders (legacy rules, then the hardening rules from genesis).
    let siblings = |act: u8| vec![act, 1, 1, 0, 0, 0, 0, 0, 0x80, 0, 0, 1, 0, 0x00, 0xA1, 0, 0, 0, 0, 0x80, 0, 0, 1, 0, 0x00, 0xB2, 0, 0];
    d.push(siblings(0));
    d.push(siblings(1));
    // A fork that spends an output created earlier on itself (slot 0 then its
    // child spend, slot 3), against a coinbase-only sibling chain, with a
    // reload from storage.
    d.push(vec![0, 0, 3, 0, 0, 0, 0, 0, 0x80, 0, 0, 1, 0, 0x00, 0x01, 0, 0, 1, 0, 0x80, 0, 0, 1, 0, 0x03, 0x02,
        0, 0, 0, 0, 0x80, 0, 0, 0, 0, 0x03, 0, 0, 3, 0, 0x80, 0, 0, 0, 0, 0x04, 3, 0, 1, 0, 0, 0]);
    // An over-claiming coinbase (flags 5, invalid at connect time), an
    // honest sibling, and a block merging both (DAG-1: a disqualified block
    // stays in the DAG so that a merger is accepted in every order).
    d.push(vec![0, 1, 2, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0x11, 0, 0, 0, 0, 0x80, 0, 0, 0, 0, 0x12,
        1, 0, 2, 0, 1, 0, 0x80, 0, 0, 0, 0, 0x13, 2, 0, 1, 0]);
    // Wrong difficulty bits that still meet their own (easy) target (flags 3:
    // one mantissa unit below the pow limit; flags 0x48: half of it): the
    // block passes the proof-of-work check and is refused by accept_block's
    // difficulty rule, its child stays an orphan, an honest sibling is
    // accepted. Legacy rules, then the hardening rules from genesis.
    let wrong_bits = |act: u8, flags: u8| vec![act, 0, 2, 0, 0, 0, 0, 0, flags, 0, 0, 0, 0, 0x31,
        0, 0, 1, 0, 0x80, 0, 0, 0, 0, 0x32, 0, 0, 0, 0, 0x80, 0, 0, 0, 0, 0x33, 0, 0, 0, 0];
    d.push(wrong_bits(0, 3));
    d.push(wrong_bits(1, 0x48));
    m.insert("accept_dag", d);
    m
}

#[test]
fn committed_seeds_are_reproducible() {
    let write = std::env::var_os("GNB_WRITE_FUZZ_SEEDS").is_some();
    for (target, list) in seeds() {
        let dir = corpus_root().join(target);
        for (i, s) in list.iter().enumerate() {
            let path = dir.join(format!("seed_{i:04}_{}", s.len()));
            if write {
                fs::create_dir_all(&dir).unwrap();
                fs::write(&path, s).unwrap();
            } else {
                let on_disk = fs::read(&path).unwrap_or_else(|e| panic!("{}: {e} (GNB_WRITE_FUZZ_SEEDS=1 regenerates)", path.display()));
                assert_eq!(&on_disk, s, "{} differs from its generator", path.display());
            }
        }
        // Corpus budget: each target's committed corpus stays below 200 KB.
        if let Ok(rd) = fs::read_dir(&dir) {
            let total: u64 = rd.flatten().filter_map(|e| e.metadata().ok()).map(|m| m.len()).sum();
            assert!(total < 200_000, "{target} corpus is {total} bytes");
        }
    }
}

fn corpus(target: &str) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    if let Ok(rd) = fs::read_dir(corpus_root().join(target)) {
        for e in rd.flatten() {
            out.push((e.file_name().to_string_lossy().into_owned(), fs::read(e.path()).unwrap()));
        }
    }
    for s in seeds().remove(target).unwrap_or_default() {
        out.push(("generated".into(), s));
    }
    out
}

fn floor(target: &str, run: impl Fn(&[u8])) {
    let files = corpus(target);
    assert!(!files.is_empty(), "{target}: empty corpus");
    for (name, data) in files {
        let r = catch_unwind(AssertUnwindSafe(|| run(&data)));
        assert!(r.is_ok(), "{target}/{name}: parser panicked");
    }
}

fn rest(d: &[u8], skip: usize) -> &[u8] {
    d.get(skip..).unwrap_or(&[])
}

#[test]
fn corpus_floor_wire_decoders() {
    for (target, skip) in [("wire_roundtrip", 3), ("block_rules", 9), ("header_parse", 0)] {
        floor(target, |d| {
            let b = rest(d, skip);
            if let Ok(block) = Block::from_wire_bytes(b) {
                let _ = block_rules::check_block_hardened_at(&block, 0);
                let _ = block.validate_structure_without_pow_at(0);
            }
            let _ = BlockHeader::from_wire_bytes(b);
            let _ = Transaction::from_wire_bytes(b);
            let _ = gnb::mempool::admission::decode_tx_strict(b);
        });
    }
}

#[test]
fn corpus_floor_witness_parsers() {
    floor("witness_parse", |d| {
        let s = rest(d, 1);
        let _ = Transaction::parse_script_sig(s);
        let _ = Transaction::parse_script_sig_exact(s);
        let _ = gnb::core::sighash::canonical_witness(s);
    });
}

#[test]
fn corpus_floor_undo_address_keystore_sync() {
    floor("undo_decode", |d| {
        let _ = UndoData::from_bytes(rest(d, 1));
    });
    floor("address_parse", |d| {
        let _ = Address::parse(&String::from_utf8_lossy(rest(d, 1)));
    });
    floor("keystore_decode", |d| {
        let b = rest(d, 1);
        let _ = serde_json::from_slice::<gnb::wallet::encryption::EncryptedKeyfile>(b);
        let _ = serde_json::from_slice::<gnb::wallet::EncryptedKeystore>(b);
    });
    floor("sync_rr_codec", |d| {
        let _ = decode_request(rest(d, 1));
        let _ = decode_response(rest(d, 1));
    });
}

/// The seeds that carry real key files decrypt with the target's password
/// (so the fuzzer starts from the accepting path of both formats).
#[test]
fn keystore_seeds_open() {
    let s = &seeds()["keystore_decode"];
    const PW: &str = "fuzzing-keyfile-passphrase-7";
    assert!(gnb::wallet::Keypair::from_encrypted_bytes(&s[0][1..], PW).is_ok(), "keystore v3 seed");
    assert!(gnb::wallet::Wallet::from_encrypted_bytes(&s[1][1..], PW).is_ok(), "keyfile v1 seed");
    let blocks = &seeds()["block_rules"];
    let hard = Block::from_wire_bytes(&blocks[3][9..]).unwrap();
    assert_eq!(block_rules::check_block_hardened_at(&hard, 0), Ok(()), "hardened block seed is valid");
}
