//! Integration tests for the `/gnb/pq/2.0.0` security upgrade.
//!
//! Two nodes run a complete handshake over an in-memory duplex. Covered:
//! success and data in both directions, tampering in either direction,
//! PQ key pinning (impersonation of a known peer), downgrade to an older
//! version, a low-order X25519 point, a non-hybrid PQ key, self-connection.

#[cfg(test)]
mod pq_upgrade_tests {
    use gnb::transport::identity::{fingerprint, PeerPins, PqIdentity};
    use gnb::transport::upgrade::{Init, PqConfig, PqUpgradeError, PQ_HANDSHAKE_VERSION, PQ_PROTOCOL_ID};
    use libp2p::core::upgrade::{InboundConnectionUpgrade, OutboundConnectionUpgrade, UpgradeInfo};
    use libp2p::identity;

    use futures::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
    use futures::executor::block_on;
    use futures::future::join;

    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use std::sync::atomic::{AtomicBool, Ordering};

    /// In-memory full-duplex pipe (same pattern as Phase 1 tests).
    /// Dropping one end closes it: the other end then reads EOF, like a TCP
    /// socket, so a side that refuses the handshake does not leave the other
    /// waiting forever.
    struct PipeEnd {
        incoming: Arc<Mutex<VecDeque<u8>>>,
        outgoing: Arc<Mutex<VecDeque<u8>>>,
        in_closed: Arc<AtomicBool>,
        out_closed: Arc<AtomicBool>,
    }

    impl Drop for PipeEnd {
        fn drop(&mut self) { self.out_closed.store(true, Ordering::SeqCst); }
    }

    impl AsyncRead for PipeEnd {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<std::io::Result<usize>> {
            let mut q = self.incoming.lock().unwrap();
            if q.is_empty() {
                if self.in_closed.load(Ordering::SeqCst) {
                    return Poll::Ready(Ok(0));
                }
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let n = q.len().min(buf.len());
            for i in 0..n {
                buf[i] = q.pop_front().unwrap();
            }
            Poll::Ready(Ok(n))
        }
    }

    impl AsyncWrite for PipeEnd {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let mut q = self.outgoing.lock().unwrap();
            for b in buf { q.push_back(*b); }
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn duplex() -> (PipeEnd, PipeEnd) {
        let a_to_b = Arc::new(Mutex::new(VecDeque::new()));
        let b_to_a = Arc::new(Mutex::new(VecDeque::new()));
        pipe_pair(a_to_b, b_to_a)
    }

    fn pipe_pair(a_to_b: Arc<Mutex<VecDeque<u8>>>, b_to_a: Arc<Mutex<VecDeque<u8>>>) -> (PipeEnd, PipeEnd) {
        let a_closed = Arc::new(AtomicBool::new(false));
        let b_closed = Arc::new(AtomicBool::new(false));
        (
            PipeEnd { incoming: b_to_a.clone(), outgoing: a_to_b.clone(),
                      in_closed: b_closed.clone(), out_closed: a_closed.clone() },
            PipeEnd { incoming: a_to_b, outgoing: b_to_a,
                      in_closed: a_closed, out_closed: b_closed },
        )
    }

    /// A tamper-pipe: intercepts bytes from A→B, lets the caller flip bits.
    /// Useful for the "bad signature" tests.
    struct TamperingPipe {
        incoming: Arc<Mutex<VecDeque<u8>>>,
        outgoing: Arc<Mutex<VecDeque<u8>>>,
        tamper:   Arc<Mutex<Option<Box<dyn FnMut(&mut [u8]) + Send>>>>,
        in_closed: Arc<AtomicBool>,
        out_closed: Arc<AtomicBool>,
    }

    impl Drop for TamperingPipe {
        fn drop(&mut self) { self.out_closed.store(true, Ordering::SeqCst); }
    }

    impl AsyncRead for TamperingPipe {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<std::io::Result<usize>> {
            let mut q = self.incoming.lock().unwrap();
            if q.is_empty() {
                if self.in_closed.load(Ordering::SeqCst) {
                    return Poll::Ready(Ok(0));
                }
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let n = q.len().min(buf.len());
            for i in 0..n {
                buf[i] = q.pop_front().unwrap();
            }
            Poll::Ready(Ok(n))
        }
    }

    impl AsyncWrite for TamperingPipe {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let mut out_bytes = buf.to_vec();
            // Apply tamper function if set.
            if let Some(f) = self.tamper.lock().unwrap().as_mut() {
                f(&mut out_bytes);
            }
            let mut q = self.outgoing.lock().unwrap();
            for b in &out_bytes { q.push_back(*b); }
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────

    struct Node {
        cfg: PqConfig,
        peer_id: libp2p::PeerId,
        pq: Arc<PqIdentity>,
        pins: Arc<PeerPins>,
    }

    fn node() -> Node {
        let kp = identity::Keypair::generate_ed25519();
        let pq = Arc::new(PqIdentity::generate().expect("pq identity"));
        let pins = Arc::new(PeerPins::in_memory());
        Node { peer_id: kp.public().to_peer_id(), cfg: PqConfig::new(&kp, pq.clone(), pins.clone()), pq, pins }
    }

    fn handshake<A, B>(i: &Node, r: &Node, a: A, b: B)
        -> (Result<(libp2p::PeerId, gnb::transport::stream::KyberStream<A>), PqUpgradeError>,
            Result<(libp2p::PeerId, gnb::transport::stream::KyberStream<B>), PqUpgradeError>)
    where
        A: AsyncRead + AsyncWrite + Send + Unpin + 'static,
        B: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        block_on(join(
            i.cfg.clone().upgrade_outbound(a, PQ_PROTOCOL_ID),
            r.cfg.clone().upgrade_inbound(b, PQ_PROTOCOL_ID),
        ))
    }

    /// Write one handshake frame the way the protocol does (u32 BE length + bincode).
    fn frame<T: serde::Serialize>(msg: &T) -> Vec<u8> {
        let body = bincode::serde::encode_to_vec(msg, bincode::config::standard()).unwrap();
        let mut out = (body.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(&body);
        out
    }

    /// A valid-looking Init from a fresh identity, for crafted-message tests.
    fn crafted_init() -> Init {
        use pqcrypto_traits::kem::PublicKey as _;
        let kp = identity::Keypair::generate_ed25519();
        let pq = PqIdentity::generate().unwrap();
        let (kem_pk, _) = pqcrypto_mlkem::mlkem768::keypair();
        Init {
            version: PQ_HANDSHAKE_VERSION,
            mlkem_pk: kem_pk.as_bytes().to_vec(),
            x25519_pk: x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([7u8; 32])).to_bytes(),
            ed_pk: kp.public().encode_protobuf(),
            pq_pk: pq.public_key().to_vec(),
            nonce: [9u8; 32],
        }
    }

    /// Run only the responder against pre-written initiator bytes.
    fn respond_to(r: &Node, bytes: Vec<u8>) -> PqUpgradeError {
        let (mut attacker, victim) = duplex();
        block_on(attacker.write_all(&bytes)).unwrap();
        drop(attacker); // the responder sees EOF after the crafted bytes
        match block_on(r.cfg.clone().upgrade_inbound(victim, PQ_PROTOCOL_ID)) {
            Ok(_) => panic!("responder must refuse"),
            Err(e) => e,
        }
    }

    #[test]
    fn protocol_id_is_v2() {
        let n = node();
        assert_eq!(n.cfg.protocol_info().next(), Some("/gnb/pq/2.0.0"));
    }

    #[test]
    fn full_handshake_succeeds_and_carries_data_both_ways() {
        let (i, r) = (node(), node());
        let (a, b) = duplex();
        let (ri, rr) = handshake(&i, &r, a, b);
        let (seen_by_i, mut si) = ri.expect("initiator");
        let (seen_by_r, mut sr) = rr.expect("responder");
        assert_eq!(seen_by_i, r.peer_id);
        assert_eq!(seen_by_r, i.peer_id);

        block_on(async {
            si.write_all(b"ping over ML-KEM + X25519").await.unwrap();
            si.flush().await.unwrap();
            let mut buf = [0u8; 25];
            sr.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping over ML-KEM + X25519");
            sr.write_all(b"pong").await.unwrap();
            sr.flush().await.unwrap();
            let mut buf = [0u8; 4];
            si.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"pong");
        });

        // Both sides pinned each other's PQ key.
        assert_eq!(i.pins.pinned(&r.peer_id), Some(r.pq.fingerprint()));
        assert_eq!(r.pins.pinned(&i.peer_id), Some(i.pq.fingerprint()));
    }

    fn tampered_pair(tamper_initiator_side: bool, at: usize)
        -> (Result<(), PqUpgradeError>, Result<(), PqUpgradeError>)
    {
        let (i, r) = (node(), node());
        let a_to_b = Arc::new(Mutex::new(VecDeque::new()));
        let b_to_a = Arc::new(Mutex::new(VecDeque::new()));
        let flip: Box<dyn FnMut(&mut [u8]) + Send> = {
            let mut seen = 0usize;
            Box::new(move |bytes: &mut [u8]| {
                for b in bytes.iter_mut() {
                    if seen == at { *b ^= 0x01; }
                    seen += 1;
                }
            })
        };
        let (t_i, t_r) = if tamper_initiator_side {
            (Arc::new(Mutex::new(Some(flip))), Arc::new(Mutex::new(None)))
        } else {
            (Arc::new(Mutex::new(None)), Arc::new(Mutex::new(Some(flip))))
        };
        let a_closed = Arc::new(AtomicBool::new(false));
        let b_closed = Arc::new(AtomicBool::new(false));
        let a = TamperingPipe { incoming: b_to_a.clone(), outgoing: a_to_b.clone(), tamper: t_i,
                                in_closed: b_closed.clone(), out_closed: a_closed.clone() };
        let b = TamperingPipe { incoming: a_to_b, outgoing: b_to_a, tamper: t_r,
                                in_closed: a_closed, out_closed: b_closed };
        let (ri, rr) = handshake(&i, &r, a, b);
        (ri.map(|_| ()), rr.map(|_| ()))
    }

    #[test]
    fn tampering_with_any_initiator_byte_breaks_the_handshake() {
        // Offsets inside the Init frame (length prefix excluded) and the Finish frame.
        for at in [10, 300, 1300, 1500, 2000, 5000] {
            let (ri, rr) = tampered_pair(true, at);
            assert!(ri.is_err() || rr.is_err(), "flip at {at} must not yield a session");
            assert!(rr.is_err(), "responder must never accept a tampered initiator (flip at {at})");
        }
    }

    #[test]
    fn tampering_with_any_responder_byte_breaks_the_handshake() {
        for at in [10, 600, 1100, 1300, 3000, 7000] {
            let (ri, _rr) = tampered_pair(false, at);
            assert!(ri.is_err(), "initiator must never accept a tampered responder (flip at {at})");
        }
    }

    #[test]
    fn known_peer_presenting_a_different_pq_key_is_refused() {
        // The initiator already knows `r` under its PeerId with ANOTHER PQ key:
        // this is what an attacker able to forge Ed25519 (but not the pinned
        // PQ key) would look like.
        let (i, r) = (node(), node());
        let other = PqIdentity::generate().unwrap();
        i.pins.check_and_pin(&r.peer_id, other.fingerprint()).unwrap();
        let (a, b) = duplex();
        let (ri, _) = handshake(&i, &r, a, b);
        assert!(matches!(ri, Err(PqUpgradeError::Pin(_))), "pinned key mismatch must be refused");
    }

    #[test]
    fn pins_are_symmetric_on_the_responder() {
        let (i, r) = (node(), node());
        let other = PqIdentity::generate().unwrap();
        r.pins.check_and_pin(&i.peer_id, fingerprint(other.public_key())).unwrap();
        let (a, b) = duplex();
        let (_, rr) = handshake(&i, &r, a, b);
        assert!(matches!(rr, Err(PqUpgradeError::Pin(_))));
    }

    #[test]
    fn older_handshake_version_is_refused() {
        let r = node();
        let mut init = crafted_init();
        init.version = 1;
        assert!(matches!(respond_to(&r, frame(&init)), PqUpgradeError::UnsupportedVersion(1)));
    }

    #[test]
    fn low_order_x25519_point_is_refused() {
        let r = node();
        let mut init = crafted_init();
        init.x25519_pk = [0u8; 32];
        assert!(matches!(respond_to(&r, frame(&init)), PqUpgradeError::WeakX25519));
    }

    #[test]
    fn non_hybrid_pq_key_is_refused() {
        let r = node();
        let mut init = crafted_init();
        init.pq_pk.truncate(init.pq_pk.len() - 1793); // drop the Falcon half
        assert!(matches!(respond_to(&r, frame(&init)), PqUpgradeError::BadPqPk));
    }

    #[test]
    fn wrong_size_kem_key_is_refused() {
        let r = node();
        let mut init = crafted_init();
        init.mlkem_pk.pop();
        assert!(matches!(respond_to(&r, frame(&init)), PqUpgradeError::BadKemPk));
    }

    #[test]
    fn oversized_handshake_frame_is_refused_before_allocation() {
        let r = node();
        let bytes = (64u32 * 1024 * 1024).to_be_bytes().to_vec();
        assert!(matches!(respond_to(&r, bytes), PqUpgradeError::MessageTooLarge { .. }));
    }

    #[test]
    fn a_node_cannot_connect_to_itself() {
        let n = node();
        let (a, b) = duplex();
        let (ri, rr) = handshake(&n, &n, a, b);
        assert!(ri.is_err() && rr.is_err());
    }

    #[test]
    fn independent_sessions_use_independent_keys() {
        // Same plaintext, two sessions between the same nodes: the encrypted
        // bytes on the wire must differ (fresh ML-KEM + X25519 per session).
        let (i, r) = (node(), node());
        let mut wires = Vec::new();
        for _ in 0..2 {
            let a_to_b = Arc::new(Mutex::new(VecDeque::new()));
            let b_to_a = Arc::new(Mutex::new(VecDeque::new()));
            let (a, b) = pipe_pair(a_to_b.clone(), b_to_a);
            let (ri, rr) = handshake(&i, &r, a, b);
            let (_, mut si) = ri.unwrap();
            let (_, _sr) = rr.unwrap();
            a_to_b.lock().unwrap().clear();
            block_on(async { si.write_all(b"same plaintext").await.unwrap(); si.flush().await.unwrap(); });
            wires.push(a_to_b.lock().unwrap().iter().copied().collect::<Vec<u8>>());
        }
        assert_ne!(wires[0], wires[1]);
    }
}
