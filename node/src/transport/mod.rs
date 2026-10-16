//! Bloch-SIS Protocol — Post-Quantum Transport Primitives (Sprint A1)
//!
//! # Scope
//!
//! The live P2P transport is the libp2p security upgrade in
//! [`upgrade`]: an ephemeral **Kyber-768** key exchange authenticated by the
//! node's **libp2p identity key (Ed25519)**, followed by a
//! ChaCha20-Poly1305 stream ([`stream::KyberStream`]). This module holds
//! the pieces that upgrade is built from: the protocol constants and HKDF
//! labels, the one-directional AEAD stream halves ([`TxStream`] /
//! [`RxStream`]) with monotonic nonce counters, and the reference encoding
//! of the length-prefixed frame format ([`frame_seal`] / [`frame_open`]:
//! `KyberStream` writes the same format, and its tests decode it with them).
//!
//! M-4 (audit): the KEM here is **Kyber-768, NOT ML-KEM-768 / NIST
//! FIPS 203**. The two schemes are not the same thing and are **NOT
//! interoperable** — the key/ciphertext sizes coincide (1184/1088
//! bytes) because ML-KEM's parameter set descends from round-3 Kyber,
//! but round-3 Kyber additionally hashes the ciphertext into the
//! shared secret during encapsulation, which ML-KEM (finalized as
//! FIPS 203) does not; a node built against `pqcrypto-mlkem` cannot
//! complete a handshake with this one. `pqcrypto-kyber` wraps PQClean's
//! `kyber768`, a distinct (and, since FIPS 203 finalized, superseded)
//! implementation; PQClean ships ML-KEM separately, wrapped by the
//! different crate `pqcrypto-mlkem`. Migrating to `pqcrypto-mlkem` is a
//! wire-breaking flag day, not a rename, and is not scheduled by anything in
//! this tree.
//!
//! NET-17 (audit, re-audit): this module used to also carry a second,
//! ML-DSA-65-authenticated handshake (`Initiator` / `PendingResponder` /
//! `SessionConfirm`) that nothing in the node ever used — peers have always
//! been authenticated by their Ed25519 libp2p identity, never by ML-DSA. That
//! dead code was removed so no reader takes it for the transport (git history
//! keeps it). Peer authentication is therefore classical (Ed25519);
//! post-quantum protection covers the session KEYS (Kyber), not the peer
//! identities. ML-DSA-65 ‖ Falcon-1024 signatures are used at the consensus
//! layer (transactions, blocks), which is orthogonal to this transport.
//!
//! # Security properties claimed (of the primitives here)
//!
//! - Session nonce non-reuse: u64 monotonic counter; refuses to overflow
//! - In-session replay/reorder: rx counter must advance monotonically
//! - Frame length bound into the AEAD (truncation is detected)
//!
//! # Security properties NOT claimed
//!
//! - Side-channel resistance of pqcrypto-kyber (KyberSlash was patched in
//!   upstream reference code Dec 2023; this crate may or may not track it).
//! - Post-compromise security within a session (no ratcheting).
//! - Traffic analysis resistance (no padding; message sizes leak).
//! - Post-quantum peer AUTHENTICATION (identities are Ed25519).
//! - Formal proof of handshake security. No third-party audit.

pub mod stream;
pub mod upgrade;

use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, KeyInit, Payload}};

// ── Constants ───────────────────────────────────────────────────────────────

/// Protocol version for the PQ transport.
pub const PQ_PROTOCOL_VERSION: u8 = 1;

/// Domain-separation magic mixed into the initiator transcript hash.
pub const DOMAIN_MAGIC: &[u8] = b"BLOCH-PQ-v1-handshake";

/// HKDF label for the initiator→responder stream key.
pub const LABEL_I2R: &[u8] = b"BLOCH-PQ-v1 i->r stream";
/// HKDF label for the responder→initiator stream key.
pub const LABEL_R2I: &[u8] = b"BLOCH-PQ-v1 r->i stream";

/// Kyber768 public key size.
///
/// M-4 (audit): this is CRYSTALS-Kyber round 3 (PQClean, via `pqcrypto-kyber`
/// 0.8.1), NOT ML-KEM-768 / NIST FIPS 203. The sizes happen to coincide
/// (ML-KEM-768 also uses 1184-byte public keys) because ML-KEM's parameter
/// set descends from round-3 Kyber, but the two schemes differ in the KEM's
/// key-derivation step and are NOT wire-interoperable. This constant was
/// previously (incorrectly) annotated "(FIPS 203)".
pub const KYBER768_PK_SIZE: usize = 1184;
/// Kyber768 ciphertext size. Same FIPS-203 caveat as [`KYBER768_PK_SIZE`]:
/// this is round-3 Kyber's ciphertext, not ML-KEM's.
pub const KYBER768_CT_SIZE: usize = 1088;

/// Size of stream cipher keys (ChaCha20-Poly1305: 256 bits).
pub const STREAM_KEY_SIZE: usize = 32;
/// ChaCha20-Poly1305 nonce size (96 bits).
pub const NONCE_SIZE: usize = 12;
/// Poly1305 AEAD tag size (128 bits).
pub const TAG_SIZE: usize = 16;

/// Handshake nonce size (prevents replay of full handshakes).
pub const HANDSHAKE_NONCE_SIZE: usize = 32;
/// Transcript hash size (SHA3-256).
pub const TRANSCRIPT_SIZE: usize = 32;

// ── Stream cipher ───────────────────────────────────────────────────────────

/// Sender half of a one-directional cipher stream.
pub struct TxStream {
    key:     [u8; STREAM_KEY_SIZE],
    counter: u64,
}

impl TxStream {
    pub fn new(key: [u8; STREAM_KEY_SIZE]) -> Self {
        Self { key, counter: 0 }
    }

    /// Encrypt one plaintext message. Returns ciphertext with appended tag.
    /// The nonce is derived from the monotonic counter — not sent on wire.
    pub fn seal(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, TransportError> {
        if self.counter == u64::MAX {
            return Err(TransportError::CounterExhausted);
        }
        let nonce = counter_to_nonce(self.counter);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let ct = cipher.encrypt(
            Nonce::from_slice(&nonce),
            Payload { msg: plaintext, aad },
        ).map_err(|_| TransportError::EncryptFailed)?;
        self.counter += 1;
        Ok(ct)
    }

    pub fn counter(&self) -> u64 { self.counter }
}

/// Receiver half. Enforces monotonic counter — rejects replay + reorder.
pub struct RxStream {
    key:          [u8; STREAM_KEY_SIZE],
    next_counter: u64,
}

impl RxStream {
    pub fn new(key: [u8; STREAM_KEY_SIZE]) -> Self {
        Self { key, next_counter: 0 }
    }

    pub fn open(&mut self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, TransportError> {
        if self.next_counter == u64::MAX {
            return Err(TransportError::CounterExhausted);
        }
        let nonce = counter_to_nonce(self.next_counter);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let pt = cipher.decrypt(
            Nonce::from_slice(&nonce),
            Payload { msg: ciphertext, aad },
        ).map_err(|_| TransportError::DecryptFailed)?;
        self.next_counter += 1;
        Ok(pt)
    }

    pub fn counter(&self) -> u64 { self.next_counter }
}

/// Derive a 96-bit nonce from a u64 counter.
/// Layout: 4 zero bytes (reserved for future direction/subprotocol bits)
/// + 8 big-endian counter bytes.
fn counter_to_nonce(counter: u64) -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

// ── Framing (length-prefixed) ───────────────────────────────────────────────

/// Seal a message with length-prefixed framing for writing to a byte stream.
/// Layout: 4-byte BE ciphertext length || ciphertext (incl. 16-byte tag).
/// The length prefix is bound into the AEAD AAD, so truncation attacks fail.
pub fn frame_seal(tx: &mut TxStream, payload: &[u8]) -> Result<Vec<u8>, TransportError> {
    let ct = tx.seal(payload, &(payload.len() as u32).to_be_bytes())?;
    let mut out = Vec::with_capacity(4 + ct.len());
    out.extend_from_slice(&(ct.len() as u32).to_be_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Parse one framed message. Returns (bytes consumed, plaintext).
/// Returns IncompleteFrame if the buffer lacks a full frame — caller reads
/// more bytes and retries.
pub fn frame_open(rx: &mut RxStream, buf: &[u8]) -> Result<(usize, Vec<u8>), TransportError> {
    if buf.len() < 4 { return Err(TransportError::IncompleteFrame); }
    let ct_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    // M-8 (audit): this function had NO ceiling on `ct_len` at all — up to
    // `u32::MAX` — unlike `stream::RxStream::poll_read`'s `MAX_FRAME_PAYLOAD`
    // clamp on the exact same wire shape. Not directly exploitable through
    // THIS entry point today (it is unused by the libp2p path, and `ct` below
    // is a slice into a buffer the caller already holds, not a fresh
    // allocation sized from the declared length) — kept in sync anyway so a
    // future caller of this public function inherits the same bound the
    // streaming path enforces, rather than a silently more permissive one.
    if ct_len > crate::transport::stream::MAX_FRAME_PAYLOAD + TAG_SIZE {
        return Err(TransportError::DecryptFailed);
    }
    if buf.len() < 4 + ct_len { return Err(TransportError::IncompleteFrame); }
    let ct = &buf[4..4 + ct_len];
    let plaintext_len = ct_len.checked_sub(TAG_SIZE).ok_or(TransportError::DecryptFailed)?;
    let pt = rx.open(ct, &(plaintext_len as u32).to_be_bytes())?;
    Ok((4 + ct_len, pt))
}

// ── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("encryption failed")]                                     EncryptFailed,
    #[error("decryption failed (bad key, tag, or counter)")]          DecryptFailed,
    #[error("stream nonce counter exhausted")]                        CounterExhausted,
    #[error("incomplete frame (need more bytes)")]                    IncompleteFrame,
}
