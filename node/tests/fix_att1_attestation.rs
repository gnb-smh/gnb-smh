//! Audit ATT-1 (Info, no action required): remote attestation is not used for
//! consensus or peer trust, and it fails closed. These tests pin both facts so
//! a later change cannot quietly make either untrue.
//!
//! The SEV-SNP and mobile backends are compiled only with the `sev-snp` /
//! `mobile` features; their tests run with
//! `cargo test -p gnb --features sev-snp,mobile --test fix_att1_attestation`.

use std::path::{Path, PathBuf};

use gnb::attestation::{
    current_report, verify, AttestationReport, Expected, QuoteVerifier, Tee, Verdict,
};

fn perfect_report(nonce: &str) -> AttestationReport {
    AttestationReport {
        attested: true,
        tee: Tee::SevSnp,
        nonce: Some(nonce.into()),
        measurement: Some("aa".repeat(48)),
        hostdata: Some("bb".repeat(32)),
        image_digest: Some("sha256:feed".into()),
        quote_b64: Some("cXVvdGU=".into()),
        os_roothash: Some("cc".repeat(32)),
        note: "attested".into(),
    }
}

fn expected() -> Expected {
    Expected {
        tee: Tee::SevSnp,
        image_digest: "sha256:feed".into(),
        measurement: Some("aa".repeat(48)),
        hostdata: Some("bb".repeat(32)),
        os_roothash: Some("cc".repeat(32)),
    }
}

/// `verify()` without a cryptographic quote verifier never trusts a report,
/// even one whose every self-reported field matches.
#[test]
fn verify_without_a_quote_verifier_fails_closed() {
    for tee in [Tee::SevSnp, Tee::Tdx, Tee::Tpm, Tee::Mobile, Tee::None] {
        let mut r = perfect_report("n1");
        r.tee = tee;
        let mut e = expected();
        e.tee = tee;
        match verify(&r, &e, Some("n1"), &[]) {
            Verdict::Rejected(reason) => assert!(
                reason.contains("no cryptographic quote verifier") || reason.contains("TEE mismatch"),
                "{tee:?}: {reason}"
            ),
            Verdict::Trusted => panic!("{tee:?}: trusted without a quote verifier"),
        }
    }
}

/// A verifier for a different TEE does not count.
#[test]
fn a_verifier_for_another_tee_does_not_grant_trust() {
    struct AcceptAll(Tee);
    impl QuoteVerifier for AcceptAll {
        fn tee(&self) -> Tee {
            self.0
        }
        fn verify_quote(&self, _: &AttestationReport, _: Option<&str>) -> Result<(), String> {
            Ok(())
        }
    }
    let wrong = AcceptAll(Tee::Tdx);
    assert!(matches!(verify(&perfect_report("n1"), &expected(), Some("n1"), &[&wrong]), Verdict::Rejected(_)));
}

/// The node's own report is the honest unattested one, and it is never
/// trusted, whatever verifiers are supplied.
#[test]
fn the_node_reports_unattested_and_is_never_trusted() {
    let r = current_report(Some("fresh".into()));
    assert!(!r.attested);
    assert_eq!(r.tee, Tee::None);
    assert!(r.quote_b64.is_none() && r.measurement.is_none() && r.hostdata.is_none());
    struct AcceptAll;
    impl QuoteVerifier for AcceptAll {
        fn tee(&self) -> Tee {
            Tee::None
        }
        fn verify_quote(&self, _: &AttestationReport, _: Option<&str>) -> Result<(), String> {
            Ok(())
        }
    }
    let mut e = expected();
    e.tee = Tee::None;
    assert!(matches!(verify(&r, &e, Some("fresh"), &[&AcceptAll]), Verdict::Rejected(_)));
}

/// SEV-SNP: the provider produces no report (stub), so the node falls back
/// to the unattested report.
#[cfg(all(feature = "sev-snp", target_os = "linux"))]
#[test]
fn sev_snp_provider_produces_no_report() {
    use gnb::attestation::{sev_snp::SevSnpProvider, AttestationProvider};
    assert_eq!(SevSnpProvider.tee(), Tee::SevSnp);
    assert!(SevSnpProvider.report(Some("n1".into())).is_none());
    assert!(SevSnpProvider.report(None).is_none());
    let r = current_report(Some("n1".into()));
    assert!(!r.attested, "the SEV-SNP build must still report unattested");
}

/// Mobile: both device-attestation verifiers reject everything, including
/// well-formed-looking input.
#[cfg(feature = "mobile")]
#[test]
fn mobile_verifiers_never_trust() {
    use gnb::attestation::mobile::{verify_android_key_attestation, verify_ios_app_attest, TEE};
    assert_eq!(TEE, Tee::Mobile);
    let chain = vec![vec![0x30, 0x82, 0x01, 0x00], vec![0x30, 0x03, 0x02, 0x01, 0x01]];
    for challenge in [&b""[..], b"challenge", &[0u8; 32][..]] {
        assert!(matches!(verify_android_key_attestation(&chain, challenge), Verdict::Rejected(_)));
        assert!(matches!(verify_android_key_attestation(&[], challenge), Verdict::Rejected(_)));
        assert!(matches!(verify_ios_app_attest(&[0xa1, 0x63, b'f', b'm', b't'], challenge), Verdict::Rejected(_)));
        assert!(matches!(verify_ios_app_attest(&[], challenge), Verdict::Rejected(_)));
    }
}

// ── Static check: attestation stays out of consensus and peer trust ──────────

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let p = entry.unwrap().path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push(p);
        }
    }
}

/// Every non-comment reference to the attestation module outside the module
/// itself. The only use allowed is the `getattestation` RPC returning the
/// node's own report; the two module declarations are the rest.
#[test]
fn no_consensus_or_peer_trust_code_consults_attestation() {
    const TOKENS: [&str; 8] = [
        "attestation::",
        "mod attestation",
        "AttestationReport",
        "AttestationProvider",
        "QuoteVerifier",
        "Verdict::Trusted",
        "current_report",
        "attestation::verify",
    ];
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let src = root.join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    // gnb-crypto (consensus types, transactions, wallet) must not see it at all.
    rust_files(&root.join("../crates/gnb-crypto/src"), &mut files);
    rust_files(&root.join("../crates/coherence-core/src"), &mut files);

    let mut found = Vec::new();
    for f in &files {
        if f.starts_with(src.join("attestation")) {
            continue;
        }
        let text = std::fs::read_to_string(f).unwrap();
        for (i, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            if TOKENS.iter().any(|t| code.contains(t)) {
                let rel = f.strip_prefix(root).unwrap_or(f).display().to_string();
                found.push(format!("{rel}:{}: {}", i + 1, line.trim()));
            }
        }
    }
    let allowed = |s: &str| {
        (s.starts_with("src/lib.rs:") && s.contains("pub mod attestation;"))
            || (s.starts_with("src/main.rs:") && s.contains("mod attestation;"))
            || (s.starts_with("src/rpc/mod.rs:") && s.contains("crate::attestation::current_report(nonce)"))
    };
    let unexpected: Vec<&String> = found.iter().filter(|s| !allowed(s)).collect();
    assert!(
        unexpected.is_empty(),
        "attestation is referenced outside the getattestation RPC (ATT-1: it must stay out of \
         consensus and peer trust):\n{}",
        unexpected.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("\n")
    );
    // The allowed uses are really there (the scan is not vacuous).
    assert_eq!(found.iter().filter(|s| s.starts_with("src/rpc/mod.rs:")).count(), 1, "{found:#?}");
    assert!(found.iter().any(|s| s.starts_with("src/lib.rs:")), "{found:#?}");

    // ...and the RPC use sits in the `getattestation` arm only.
    let rpc = std::fs::read_to_string(src.join("rpc/mod.rs")).unwrap();
    let at = rpc.find("crate::attestation::current_report(nonce)").unwrap();
    let arm = rpc[..at].rfind("=>").map(|p| &rpc[..p]).unwrap();
    assert!(arm.trim_end().ends_with("\"getattestation\""), "attestation used outside the getattestation RPC arm");
}
