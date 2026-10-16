//! Regressions for defects found by the cargo-fuzz campaign (node/fuzz,
//! docs/testing/FUZZING.md). Each test pins the minimized crashing input the
//! fuzzer reported (also committed as `fuzz/corpus/<target>/regress_*`) and
//! the root-cause property it violated.

use gnb::core::sighash::{check_input_witnesses, verify_tx_scripts, SighashVersion};
use gnb::core::{activation, block_rules, Block, BlockHeader, ChainId, MerkleRoot, Transaction, TxInput, TxOutput};
use gnb::network::sync_rr::{decode_request, decode_response, encode_frame, is_sync_protocol_violation, SyncRequest, SyncResponse};
use gnb::network::{decode_wire_message, NetworkMessage, WireDecodeError, WirePenaltyTracker, WireReaction};
use sha3::{Digest, Sha3_256};

fn bincode_of(m: &NetworkMessage) -> Vec<u8> {
    bincode::serde::encode_to_vec(m, bincode::config::standard()).unwrap()
}

fn corpus_file(path: &str) -> Vec<u8> {
    std::fs::read(format!("{}/fuzz/corpus/{path}", env!("CARGO_MANIFEST_DIR"))).expect("committed fuzz input")
}

/// The fuzz targets' input reader (`fuzz/fuzz_targets/common/mod.rs`
/// `Input`): little-endian reads, zeros past the end.
struct FuzzInput<'a> {
    data: &'a [u8],
    at: usize,
}

impl FuzzInput<'_> {
    fn u8(&mut self) -> u8 {
        let b = self.data.get(self.at).copied().unwrap_or(0);
        self.at += 1;
        b
    }
    fn u16(&mut self) -> u16 {
        u16::from_le_bytes([self.u8(), self.u8()])
    }
    fn u32(&mut self) -> u32 {
        u32::from_le_bytes([self.u8(), self.u8(), self.u8(), self.u8()])
    }
    fn u64(&mut self) -> u64 {
        let lo = self.u32() as u64;
        lo | ((self.u32() as u64) << 32)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { self.u16() as usize % n }
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.u8()).collect()
    }
    fn var_bytes(&mut self, max: usize) -> Vec<u8> {
        let n = self.below(max + 1);
        self.bytes(n)
    }
    fn arr32(&mut self) -> [u8; 32] {
        self.bytes(32).try_into().unwrap()
    }
    /// `common::gen_tx`.
    fn tx(&mut self, max_in: usize, max_out: usize, max_script: usize) -> Transaction {
        let n_in = self.below(max_in + 1);
        let n_out = self.below(max_out + 1);
        let version = self.u32();
        let inputs = (0..n_in)
            .map(|_| TxInput { prev_txid: self.arr32(), prev_index: self.u32(), script_sig: self.var_bytes(max_script), sequence: self.u32() })
            .collect();
        let outputs = (0..n_out).map(|_| TxOutput { value: self.u64(), script_pubkey: self.var_bytes(max_script) }).collect();
        Transaction { version, inputs, outputs, locktime: self.u32() }
    }
}

/// `netmsg_decode` crash: a `Version` frame whose `version` field is the
/// 5-byte bincode form (`FC 1F 00 00 00`) of 31 decoded to the same message as
/// the canonical 1-byte form. Gossipsub message ids are SHA-256 of the frame,
/// so every such variant was a fresh message id for the same message (the
/// NET-7 de-duplication bypass, without trailing bytes). Such a frame is
/// refused; it is a penalized protocol violation unless the message is one
/// an older release relays (`NewBlock`, `NewTransaction`).
#[test]
fn gossip_frame_with_a_non_minimal_varint_is_a_protocol_violation() {
    let crash = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/fuzz/corpus/netmsg_decode/regress_noncanonical_bincode_varint"))
        .expect("committed crash input");
    assert_eq!(crash, [12u8, 252, 31, 0, 0, 0, 0, 0, 0, 0]);
    let canonical = [12u8, 31, 0, 0, 0, 0];
    let m = decode_wire_message(&canonical).expect("canonical Version frame");
    assert_eq!(bincode_of(&m), canonical);
    match decode_wire_message(&crash) {
        Err(e @ WireDecodeError::NonCanonical { relayable: false }) => assert!(e.is_protocol_violation()),
        other => panic!("non-minimal frame: {other:?}"),
    }
    // The peer that sent it is penalized like any protocol violation: no
    // honest node relays a `Version` frame.
    let mut t = WirePenaltyTracker::new();
    let peer = libp2p::PeerId::random();
    assert!(matches!(t.classify(peer, &crash), WireReaction::Penalize { error: WireDecodeError::NonCanonical { .. }, .. }));

    // A block announcement: the same block id with a 3-byte `blue_score`.
    let nb = NetworkMessage::NewBlock { block_hash: [7; 32], blue_score: 5, height: 4, block_data: vec![1, 2, 3] };
    let enc = bincode_of(&nb);
    assert!(decode_wire_message(&enc).is_ok());
    let at = 1 + 32; // variant, block_hash
    assert_eq!(enc[at], 5);
    let mut wide = enc[..at].to_vec();
    wide.extend_from_slice(&[0xFB, 5, 0]);
    wide.extend_from_slice(&enc[at + 1..]);
    assert!(matches!(decode_wire_message(&wide), Err(WireDecodeError::NonCanonical { relayable: true })));

    // Refused, but not penalized: releases before the one-encoding rule
    // accept this frame and gossipsub relays the bytes they received, so it
    // can come from an honest older relay (docs/CONSENSUS.md, "Wire encoding").
    let peer2 = libp2p::PeerId::random();
    assert!(matches!(t.classify(peer2, &wide), WireReaction::IgnoreMalformed(_)));
    assert_eq!(t.score_of(&peer2), None);
}

/// The directed-sync codec had the same gap (bincode under `decode_frame`).
#[test]
fn sync_frame_with_a_non_minimal_varint_is_refused() {
    let req = SyncRequest::GetHeaders { from_blue_score: 5, limit: 1 };
    let enc = encode_frame(&req).unwrap();
    assert_eq!(enc, [1, 5, 1]);
    assert_eq!(decode_request(&enc).unwrap(), req);
    let wide = [1u8, 0xFB, 5, 0, 1];
    let err = decode_request(&wide).unwrap_err();
    assert!(is_sync_protocol_violation(&err), "{err}");

    let resp = SyncResponse::BlockNotFound { block_hash: [3; 32] };
    let enc = encode_frame(&resp).unwrap();
    assert_eq!(decode_response(&enc).unwrap(), resp);
    let mut wide = vec![0xFC, enc[0], 0, 0, 0]; // the variant index in the 5-byte form
    wide.extend_from_slice(&enc[1..]);
    assert!(is_sync_protocol_violation(&decode_response(&wide).unwrap_err()));
}

/// `wire_roundtrip` crash: a header whose parent count is `FD 01 00` decoded
/// to the header encoded with `01`. Every wire decoder now refuses
/// non-minimal varints (unit tests `wire_canonical_tests` in gnb-crypto cover
/// each field and the block framing).
#[test]
fn header_with_a_non_minimal_parent_count_is_refused() {
    let crash = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/fuzz/corpus/wire_roundtrip/regress_nonminimal_parent_count"))
        .expect("committed crash input");
    // Mode byte 3 (untrusted bytes), two cut bytes, then the header.
    assert_eq!(crash[0] % 4, 3);
    assert!(BlockHeader::from_wire_bytes(&crash[3..]).is_err(), "the fuzzer's header is still accepted");

    let h = BlockHeader { version: 1, parents: vec![[0x33; 32]], merkle_root: MerkleRoot([0x44; 32]), timestamp: 9, bits: 0x2100_FFFF, nonce: 7 };
    let enc = h.to_wire_bytes(1, 1);
    let mut wide = enc[..4].to_vec();
    wide.extend_from_slice(&[0xFD, 0x01, 0x00]);
    wide.extend_from_slice(&enc[5..]);
    assert!(BlockHeader::from_wire_bytes(&enc).is_ok());
    assert!(BlockHeader::from_wire_bytes(&wide).is_err());

    // The same through a block and a transaction.
    let tx = Transaction {
        version: 1,
        inputs: vec![TxInput { prev_txid: [1; 32], prev_index: 0, script_sig: vec![9; 4], sequence: 0 }],
        outputs: vec![TxOutput { value: 1, script_pubkey: vec![2; 20] }],
        locktime: 0,
    };
    let b = Block { header: h, transactions: vec![tx], blue_score: 1, height: 1, shielded_transactions: vec![], powit: Default::default() };
    let enc = b.to_wire_bytes();
    assert_eq!(Block::from_wire_bytes(&enc).unwrap().to_wire_bytes(), enc);
    let mut wide = enc[..4].to_vec();
    wide.extend_from_slice(&[0xFD, 0x01, 0x00]);
    wide.extend_from_slice(&enc[5..]);
    assert!(Block::from_wire_bytes(&wide).is_err());
}

// ── The first CI run of the merged tree (run 38873936215) ────────────────────
//
// Three targets written on the hardening branch failed against the merged
// relaunched mainnet line. In each case the library follows the specification
// and the TARGET's reference was stale; the targets are corrected and these
// tests pin the crashing input and the specified behaviour it exercises.

/// `witness_parse` crash (exit 77, CI input): mode 1 builds
/// `build_script_sig([], [0, 0, 0])` and appends a one-byte tail. The target
/// still asserted the historical LENIENT framing (`parse_script_sig_borrowed`
/// ignoring bytes after the public key); this chain dropped it at every
/// height in cc5c450 (a single-key `script_sig` is exactly
/// `[u32 sig_len][sig][u32 pk_len][pk]`), so the borrowed and owned parsers
/// are the exact one. A witness with trailing bytes is refused by every
/// parser and by the witness rule of both sighash regimes, also below the
/// hardening activation.
#[test]
fn witness_with_trailing_bytes_is_refused_by_every_parser() {
    let crash = corpus_file("witness_parse/regress_trailing_bytes_after_witness");
    assert_eq!(crash, [1, 0, 0, 3, 0, 0, 0, 0, 1, 0, 0, 3, 0, 0, 0, 0, 0, 0, 247, 255, 255, 0, 0, 247, 255, 255]);
    let mut inp = FuzzInput { data: &crash, at: 0 };
    assert_eq!(inp.u8() % 4, 1, "mode 1: a witness built from parts, then a tail");
    let (sig, pk, tail) = (inp.var_bytes(300), inp.var_bytes(300), inp.var_bytes(6));
    assert_eq!((sig.as_slice(), pk.as_slice(), tail.as_slice()), (&[][..], &[0u8, 0, 0][..], &[0u8][..]));

    let exact = Transaction::build_script_sig(&sig, &pk);
    assert_eq!(Transaction::parse_script_sig_exact(&exact), Some((&sig[..], &pk[..])));
    assert_eq!(Transaction::parse_script_sig_borrowed(&exact), Some((&sig[..], &pk[..])));
    let mut padded = exact.clone();
    padded.extend_from_slice(&tail);
    assert_eq!(Transaction::parse_script_sig_exact(&padded), None);
    assert_eq!(Transaction::parse_script_sig_borrowed(&padded), None, "trailing bytes ignored (lenient framing)");
    assert_eq!(Transaction::parse_script_sig(&padded), None, "trailing bytes ignored (lenient framing)");

    let spend = |script_sig: Vec<u8>, version: u32| Transaction {
        version,
        inputs: vec![TxInput { prev_txid: [1; 32], prev_index: 0, script_sig, sequence: u32::MAX }],
        outputs: vec![TxOutput { value: 50_000, script_pubkey: vec![2; 20] }],
        locktime: 0,
    };
    let prevouts = [TxOutput { value: 100_000, script_pubkey: Sha3_256::digest(&pk)[..20].to_vec() }];
    for version in [SighashVersion::V2, SighashVersion::V3] {
        assert!(check_input_witnesses(&spend(padded.clone(), 3), &prevouts, version).is_err(), "{version:?}");
    }
    // The framing is the only defect: without the tail the V2 rule accepts it.
    assert!(check_input_witnesses(&spend(exact, 1), &prevouts, SighashVersion::V2).is_ok());
    // Below the activation (sighash v2, version 1) the padded witness is refused too.
    let err = verify_tx_scripts(&spend(padded, 1), &prevouts, ChainId::Mainnet, 1, activation::NEVER).unwrap_err();
    assert!(err.contains("malformed script_sig"), "{err}");
}

/// `sighash` failure (every committed seed; this is the first): the target's
/// v2 reference was the hardening branch's digest, a bincode body under
/// version byte 0x01. This chain's sighash v2 (cc5c450,
/// `reference/gnb_sighash.py`, `SIGHASH_VERSION` = 0x02) hashes the stripped
/// transaction in the WIRE encoding: no consensus value depends on
/// serde/bincode. The library follows the specification.
#[test]
fn sighash_v2_hashes_the_wire_body() {
    let seed = corpus_file("sighash/seed_0000_130");
    // The target's reads: index, suite, chain, field, pick, delta, mismatch,
    // then the transaction (`gen_tx(8, 6, 48)`).
    let mut inp = FuzzInput { data: &seed, at: 0 };
    let index = inp.below(12);
    let _suite = inp.u16();
    let chain = if inp.u8() & 1 == 1 { ChainId::Testnet } else { ChainId::Mainnet };
    let (_field, _pick, _delta, _mismatch) = (inp.u8(), inp.u16(), inp.u8(), inp.u8());
    let tx = inp.tx(8, 6, 48);
    assert!(!tx.inputs.is_empty() && index < tx.inputs.len(), "the seed signs an existing input");

    let mut stripped = tx.clone();
    for (i, x) in stripped.inputs.iter_mut().enumerate() {
        x.script_sig = if i == index { b"GNB_SIGHASH".to_vec() } else { vec![] };
    }
    let digest = |version: u8, body: &[u8]| -> [u8; 32] {
        let mut pre = b"GNB-SIGHASH-v1\0\0".to_vec();
        pre.push(version);
        pre.extend_from_slice(&chain.to_u32().to_le_bytes());
        pre.extend_from_slice(body);
        Sha3_256::digest(&pre).into()
    };
    let wire = digest(0x02, &stripped.to_wire_bytes(true));
    let stale = digest(0x01, &bincode::serde::encode_to_vec(&stripped, bincode::config::standard()).unwrap());
    assert_eq!(tx.sighash(index, chain), wire, "sighash v2 is over the wire body");
    assert_ne!(tx.sighash(index, chain), stale, "the target's stale (bincode, 0x01) reference");
    assert_eq!(tx.sighash_v2_checked(index, chain), Ok(wire));
}

/// `block_rules` failure (reproduced on the committed seeds by a stable
/// mutation harness; the CI log section of this target was not retrievable):
/// the target repairs a decoded block to the specification (coinbase shape,
/// commitment, root) and requires the library to accept it, but its
/// specification predated re-audit B2-T10: from the activation a header
/// lists each parent once (`duplicate parent`, docs/CONSENSUS.md "Parent
/// list"). The fuzzer's block (the `hard_small` seed with its parent listed
/// twice) is refused for exactly that, and accepted once the repeat is
/// removed (commitment and root recomputed).
#[test]
fn hardened_block_with_a_repeated_parent_is_refused() {
    let crash = corpus_file("block_rules/regress_duplicate_parent");
    assert_eq!(crash[0] & 1, 1, "block mode: mode byte, 8 control bytes, block wire bytes");
    let decoded = Block::from_wire_bytes(&crash[9..]).expect("the fuzzer's block decodes");
    let parents = &decoded.header.parents;
    assert!(parents.len() == 2 && parents[0] == parents[1], "one parent listed twice");

    // Coinbase commitment and tagged root recomputed by the library: the
    // repeated parent is the only defect left.
    let seal = |mut b: Block| -> Block {
        let c = block_rules::expected_coinbase_commitment(&b);
        b.transactions[0].inputs[0].script_sig = block_rules::coinbase_script_sig(&c, b"extra");
        b.header.merkle_root = b.body_merkle_root_at(0);
        b
    };
    let repeated = seal(decoded.clone());
    assert_eq!(block_rules::check_parents_distinct(&repeated.header.parents), Err("duplicate parent"));
    assert_eq!(block_rules::check_hardened_body(&repeated), Err("duplicate parent"));
    assert_eq!(block_rules::check_block_hardened_at(&repeated, 0), Err("duplicate parent"));
    assert_eq!(repeated.validate_structure_without_pow_at(0), Err("duplicate parent"));
    // Not a rule below the activation.
    assert_eq!(block_rules::check_block_hardened_at(&repeated, activation::NEVER), Ok(()));

    let mut once = decoded;
    once.header.parents.truncate(1);
    let once = seal(once);
    assert_eq!(block_rules::check_block_hardened_at(&once, 0), Ok(()));
    assert_eq!(block_rules::check_hardened_body(&once), Ok(()));
}
