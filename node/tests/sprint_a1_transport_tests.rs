//! Session cipher and framing tests for the P2P transport.
//!
//! The handshake that derives the keys is tested end to end in
//! `sprint_a2_upgrade_tests.rs`; here the cipher runs on random keys.

#[cfg(test)]
mod transport_cipher_tests {
    use gnb::transport::*;
    use rand::RngCore;

    fn session_key() -> [u8; STREAM_KEY_SIZE] {
        let mut k = [0u8; STREAM_KEY_SIZE];
        rand::rng().fill_bytes(&mut k);
        k
    }

    // ── Stream cipher ─────────────────────────────────────────────────────

    #[test]
    fn stream_roundtrip_in_order() {
        let k = session_key();
        let mut tx = TxStream::new(k);
        let mut rx = RxStream::new(k);

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
        let k = session_key();
        let mut tx = TxStream::new(k);
        let mut rx = RxStream::new(k);

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
        let k = session_key();
        let mut tx = TxStream::new(k);
        let mut rx = RxStream::new(k);

        let _ct1 = tx.seal(b"one", b"").unwrap();
        let ct2 = tx.seal(b"two", b"").unwrap();

        // ct2 before ct1 → counter mismatch, AEAD fails.
        assert!(rx.open(&ct2, b"").is_err());
    }

    #[test]
    fn stream_rejects_tamper() {
        let k = session_key();
        let mut tx = TxStream::new(k);
        let mut rx = RxStream::new(k);

        let mut ct = tx.seal(b"hello", b"").unwrap();
        ct[0] ^= 0x01;
        assert!(rx.open(&ct, b"").is_err());
    }

    #[test]
    fn stream_aad_bound_into_tag() {
        let k = session_key();
        let mut tx = TxStream::new(k);
        let mut rx1 = RxStream::new(k);
        let mut rx2 = RxStream::new(k);

        let ct = tx.seal(b"msg", b"AAD-value").unwrap();

        // Right AAD decrypts.
        assert_eq!(rx1.open(&ct, b"AAD-value").unwrap(), b"msg");
        // Wrong AAD fails.
        assert!(rx2.open(&ct, b"different-AAD").is_err());
    }

    #[test]
    fn stream_wrong_key_fails() {
        let k = session_key();
        let mut tx = TxStream::new(k);
        let mut rx_wrong = RxStream::new([42u8; STREAM_KEY_SIZE]);

        let ct = tx.seal(b"secret", b"").unwrap();
        assert!(rx_wrong.open(&ct, b"").is_err());
    }

    // ── Framing ───────────────────────────────────────────────────────────

    #[test]
    fn frame_roundtrip() {
        let k = session_key();
        let mut tx = TxStream::new(k);
        let mut rx = RxStream::new(k);

        let framed = frame_seal(&mut tx, b"framed payload").unwrap();
        assert!(framed.len() >= 4 + TAG_SIZE);

        let (consumed, pt) = frame_open(&mut rx, &framed).unwrap();
        assert_eq!(consumed, framed.len());
        assert_eq!(pt, b"framed payload");
    }

    #[test]
    fn frame_incomplete_buffer_returns_error() {
        let k = session_key();
        let mut tx = TxStream::new(k);
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
        let k = session_key();
        let mut tx = TxStream::new(k);
        let mut rx = RxStream::new(k);

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

}
