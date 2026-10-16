//! Sprint A1 — Post-Quantum Transport Primitives Tests
//!
//! Covers the primitives the live Kyber transport (`transport::upgrade`,
//! `transport::stream::KyberStream`) is built from:
//!   - Stream cipher roundtrip + tamper detection + replay/reorder rejection
//!   - Frame protocol roundtrip + incomplete frame handling + truncation
//!   - Independent keys give independent streams
//!
//! NET-17 (re-audit): the tests of the ML-DSA-65-authenticated handshake
//! (`Initiator` / `PendingResponder` / `SessionConfirm`) were removed with
//! that handshake, which no code path ever used (the live handshake is
//! Kyber-768 + Ed25519 libp2p identity, tested in sprint_a2_upgrade_tests.rs).
//! The stream tests below used it only to derive keys; they now use random
//! keys directly.

#[cfg(test)]
mod sprint_a1_tests {
    use gnb::transport::*;
    use rand::RngCore;

    /// The sending end of one direction of a session.
    struct Keys {
        tx_key: [u8; STREAM_KEY_SIZE],
    }

    /// The receiving end: its `rx_key` equals the sender's `tx_key`.
    struct RxKeys {
        rx_key: [u8; STREAM_KEY_SIZE],
    }

    /// One direction of a fresh session, under a random key.
    fn session() -> (Keys, RxKeys) {
        let mut k = [0u8; STREAM_KEY_SIZE];
        rand::rng().fill_bytes(&mut k);
        (Keys { tx_key: k }, RxKeys { rx_key: k })
    }

    // ── Stream cipher ─────────────────────────────────────────────────────

    #[test]
    fn stream_roundtrip_in_order() {
        let (i, r) = session();
        let mut tx = TxStream::new(i.tx_key);
        let mut rx = RxStream::new(r.rx_key);

        for n in 0..10 {
            let pt = format!("message {}", n);
            let ct = tx.seal(pt.as_bytes(), b"").unwrap();
            let decrypted = rx.open(&ct, b"").unwrap();
            assert_eq!(decrypted, pt.as_bytes());
        }
        assert_eq!(tx.counter(), 10);
        assert_eq!(rx.counter(), 10);
    }

    #[test]
    fn stream_rejects_replay() {
        let (i, r) = session();
        let mut tx = TxStream::new(i.tx_key);
        let mut rx = RxStream::new(r.rx_key);

        let ct1 = tx.seal(b"one", b"").unwrap();
        let ct2 = tx.seal(b"two", b"").unwrap();

        assert_eq!(rx.open(&ct1, b"").unwrap(), b"one");
        // Replay of ct1 now fails (counter advanced).
        assert!(rx.open(&ct1, b"").is_err());
        // Next-in-order still works.
        assert_eq!(rx.open(&ct2, b"").unwrap(), b"two");
    }

    #[test]
    fn stream_rejects_reorder() {
        let (i, r) = session();
        let mut tx = TxStream::new(i.tx_key);
        let mut rx = RxStream::new(r.rx_key);

        let _ct1 = tx.seal(b"one", b"").unwrap();
        let ct2 = tx.seal(b"two", b"").unwrap();

        // ct2 before ct1 → counter mismatch, AEAD fails.
        assert!(rx.open(&ct2, b"").is_err());
    }

    #[test]
    fn stream_rejects_tamper() {
        let (i, r) = session();
        let mut tx = TxStream::new(i.tx_key);
        let mut rx = RxStream::new(r.rx_key);

        let mut ct = tx.seal(b"hello", b"").unwrap();
        ct[0] ^= 0x01;
        assert!(rx.open(&ct, b"").is_err());
    }

    #[test]
    fn stream_aad_bound_into_tag() {
        let (i, r) = session();
        let mut tx = TxStream::new(i.tx_key);
        let mut rx1 = RxStream::new(r.rx_key);
        let mut rx2 = RxStream::new(r.rx_key);

        let ct = tx.seal(b"msg", b"AAD-value").unwrap();

        // Right AAD decrypts.
        assert_eq!(rx1.open(&ct, b"AAD-value").unwrap(), b"msg");
        // Wrong AAD fails.
        assert!(rx2.open(&ct, b"different-AAD").is_err());
    }

    #[test]
    fn stream_wrong_key_fails() {
        let (i, _r) = session();
        let mut tx = TxStream::new(i.tx_key);
        let mut rx_wrong = RxStream::new([42u8; STREAM_KEY_SIZE]);

        let ct = tx.seal(b"secret", b"").unwrap();
        assert!(rx_wrong.open(&ct, b"").is_err());
    }

    // ── Framing ───────────────────────────────────────────────────────────

    #[test]
    fn frame_roundtrip() {
        let (i, r) = session();
        let mut tx = TxStream::new(i.tx_key);
        let mut rx = RxStream::new(r.rx_key);

        let framed = frame_seal(&mut tx, b"framed payload").unwrap();
        assert!(framed.len() >= 4 + TAG_SIZE);

        let (consumed, pt) = frame_open(&mut rx, &framed).unwrap();
        assert_eq!(consumed, framed.len());
        assert_eq!(pt, b"framed payload");
    }

    #[test]
    fn frame_incomplete_buffer_returns_error() {
        let (i, _) = session();
        let mut tx = TxStream::new(i.tx_key);
        let framed = frame_seal(&mut tx, b"payload").unwrap();

        let mut rx = RxStream::new([0u8; STREAM_KEY_SIZE]);

        // Only 2 bytes: length prefix incomplete.
        assert!(matches!(frame_open(&mut rx, &framed[..2]), Err(TransportError::IncompleteFrame)));

        // Length complete but ciphertext truncated.
        assert!(matches!(frame_open(&mut rx, &framed[..6]), Err(TransportError::IncompleteFrame)));
    }

    #[test]
    fn frame_truncation_attack_fails() {
        // Attacker strips off the last byte of a framed message, leaving
        // length prefix intact. We arrive with ct_len bytes but the AEAD
        // tag check must catch the missing byte.
        let (i, r) = session();
        let mut tx = TxStream::new(i.tx_key);
        let mut rx = RxStream::new(r.rx_key);

        let mut framed = frame_seal(&mut tx, b"hello").unwrap();
        let original_len = framed.len();

        // Simulate attacker: rewrite length prefix to pretend the frame
        // is shorter than it is.
        let ct_len = u32::from_be_bytes([framed[0], framed[1], framed[2], framed[3]]) as usize;
        let new_ct_len = ct_len - 1;
        framed[..4].copy_from_slice(&(new_ct_len as u32).to_be_bytes());
        framed.truncate(4 + new_ct_len);
        assert_ne!(framed.len(), original_len);

        // Decryption must fail — AAD binding will mismatch.
        let result = frame_open(&mut rx, &framed);
        assert!(result.is_err());
    }

    // ── Independent sessions ──────────────────────────────────────────────

    #[test]
    fn independent_sessions_have_independent_keys() {
        let (i1, r1) = session();
        let (i2, r2) = session();

        assert_ne!(i1.tx_key, i2.tx_key, "fresh session must produce fresh keys");
        assert_ne!(r1.rx_key, r2.rx_key);

        // Cross-session keys don't work: ciphertext from session 1 can't
        // be decrypted by session 2's keys.
        let mut tx1 = TxStream::new(i1.tx_key);
        let mut rx2 = RxStream::new(r2.rx_key);
        let ct = tx1.seal(b"s1 msg", b"").unwrap();
        assert!(rx2.open(&ct, b"").is_err());
    }
}
