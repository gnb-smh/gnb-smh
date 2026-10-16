//! GnB P2P transport: post-quantum security upgrade and session cipher.
//!
//! - [`upgrade`]: the libp2p security upgrade `/gnb/pq/2.0.0` — hybrid
//!   ML-KEM-768 (FIPS 203) + X25519 key exchange, hybrid Ed25519 +
//!   ML-DSA-65 ‖ Falcon-1024 mutual authentication, PQ key pinning.
//! - [`identity`]: the node's PQ identity and the per-peer PQ key pins.
//! - [`stream`] and the types below: the ChaCha20-Poly1305 session cipher
//!   with monotonic nonce counters (replay and reorder rejected) and
//!   length-prefixed framing whose length is bound into the AEAD.
//!
//! The round-3 Kyber handshake that used to live here (`Initiator` /
//! `PendingResponder` / `SessionConfirm`, ML-DSA-65 authenticated; never wired
//! into the network, audit NET-17) was removed together with the
//! `pqcrypto-kyber` dependency.

pub mod identity;
pub mod stream;
pub mod upgrade;

use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, KeyInit, Payload}};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// ── Constants ───────────────────────────────────────────────────────────────

/// Size of stream cipher keys (ChaCha20-Poly1305: 256 bits).
pub const STREAM_KEY_SIZE: usize = 32;
/// ChaCha20-Poly1305 nonce size (96 bits).
pub const NONCE_SIZE: usize = 12;
/// Poly1305 AEAD tag size (128 bits).
pub const TAG_SIZE: usize = 16;

// ── Stream cipher ───────────────────────────────────────────────────────────

/// Sender half of a one-directional cipher stream. The key is wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TxStream {
    key:     Zeroizing<[u8; STREAM_KEY_SIZE]>,
    counter: u64,
}

impl TxStream {
    pub fn new(key: [u8; STREAM_KEY_SIZE]) -> Self {
        Self::from_owned_key(Zeroizing::new(key))
    }

    // Move the derived key's cleaning owner directly into the stream.
    fn from_owned_key(key: Zeroizing<[u8; STREAM_KEY_SIZE]>) -> Self {
        Self { key, counter: 0 }
    }

    /// Encrypt one plaintext message. Returns ciphertext with appended tag.
    /// The nonce is derived from the monotonic counter — not sent on wire.
    pub fn seal(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, TransportError> {
        if self.counter == u64::MAX {
            return Err(TransportError::CounterExhausted);
        }
        let nonce = counter_to_nonce(self.counter);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(self.key.as_ref()));
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
/// The key is wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RxStream {
    key:          Zeroizing<[u8; STREAM_KEY_SIZE]>,
    next_counter: u64,
}

impl RxStream {
    pub fn new(key: [u8; STREAM_KEY_SIZE]) -> Self {
        Self::from_owned_key(Zeroizing::new(key))
    }

    // Move the derived key's cleaning owner directly into the stream.
    fn from_owned_key(key: Zeroizing<[u8; STREAM_KEY_SIZE]>) -> Self {
        Self { key, next_counter: 0 }
    }

    pub fn open(&mut self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, TransportError> {
        if self.next_counter == u64::MAX {
            return Err(TransportError::CounterExhausted);
        }
        let nonce = counter_to_nonce(self.next_counter);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(self.key.as_ref()));
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
