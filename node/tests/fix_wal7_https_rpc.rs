//! Audit WAL-7 (residual): the CLI wallets' RPC client speaks HTTPS with
//! certificate and host-name verification (rustls), sends the API key over
//! HTTPS to any host, and keeps refusing it over plain HTTP to non-loopback
//! hosts. The server here is a local rustls server whose certificate is
//! issued by a throw-away CA generated per test; the CA is passed to the
//! client explicitly (`TlsTrust::Roots`).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread::JoinHandle;

use gnb::wallet::http_rpc::{call, call_with_trust, TlsTrust};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{json, Value};

struct Pki {
    ca_der: Vec<u8>,
    chain: Vec<CertificateDer<'static>>,
    key_der: Vec<u8>,
}

/// A CA and a server certificate for `names` (DNS names or IP addresses).
fn make_pki(names: &[&str]) -> Pki {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(rcgen::DnType::CommonName, "GnB WAL-7 test CA");
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let srv_key = rcgen::KeyPair::generate().unwrap();
    let srv_params =
        rcgen::CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>()).unwrap();
    let srv = srv_params.signed_by(&srv_key, &ca, &ca_key).unwrap();
    Pki { ca_der: ca.der().to_vec(), chain: vec![srv.der().clone()], key_der: srv_key.serialize_der() }
}

/// What the TLS server saw.
#[derive(Debug, Default)]
struct Seen {
    request_line: String,
    api_key: Option<String>,
    host: Option<String>,
    body: Value,
}

/// A one-shot HTTPS JSON-RPC server answering `result`.
fn tls_server(pki: &Pki, result: Value) -> (u16, JoinHandle<Option<Seen>>) {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(pki.chain.clone(), PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pki.key_der.clone())))
        .unwrap();
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let worker = std::thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
        let conn = rustls::ServerConnection::new(config).unwrap();
        let mut tls = rustls::StreamOwned::new(conn, tcp);
        let mut reader = BufReader::new(&mut tls);
        let mut seen = Seen::default();
        let mut len = 0usize;
        loop {
            let mut line = String::new();
            // A failed handshake (client refused the certificate) ends here.
            if reader.read_line(&mut line).ok()? == 0 {
                return None;
            }
            if seen.request_line.is_empty() {
                seen.request_line = line.trim_end().to_string();
                continue;
            }
            if line == "\r\n" {
                break;
            }
            let (name, value) = line.split_once(':').unwrap();
            match name.to_ascii_lowercase().as_str() {
                "x-api-key" => seen.api_key = Some(value.trim().to_string()),
                "host" => seen.host = Some(value.trim().to_string()),
                "content-length" => len = value.trim().parse().unwrap(),
                _ => {}
            }
        }
        let mut body = vec![0u8; len];
        reader.read_exact(&mut body).unwrap();
        drop(reader);
        seen.body = serde_json::from_slice(&body).unwrap();
        let reply = json!({"jsonrpc": "2.0", "id": 1, "result": result}).to_string();
        let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{reply}", reply.len());
        tls.write_all(response.as_bytes()).unwrap();
        tls.conn.send_close_notify();
        let _ = tls.flush();
        Some(seen)
    });
    (port, worker)
}

/// HTTPS with the CA passed explicitly: the call succeeds, the server is
/// reached over TLS, and the API key is sent to it (a DNS name).
#[test]
fn https_call_with_an_explicit_ca_succeeds_and_carries_the_api_key() {
    let pki = make_pki(&["localhost"]);
    let (port, server) = tls_server(&pki, json!(4242));
    let trust = TlsTrust::Roots(vec![pki.ca_der.clone()]);
    let got = call_with_trust(&format!("https://localhost:{port}"), "getblockcount", &json!([]), Some("secret-key-0123"), &trust)
        .expect("HTTPS call");
    assert_eq!(got, json!(4242));
    let seen = server.join().unwrap().expect("request received");
    assert_eq!(seen.request_line, "POST / HTTP/1.1");
    assert_eq!(seen.api_key.as_deref(), Some("secret-key-0123"));
    assert_eq!(seen.host.as_deref(), Some(format!("localhost:{port}").as_str()));
    assert_eq!(seen.body["method"], "getblockcount");
}

/// IP-address certificates work too (SAN iPAddress).
#[test]
fn https_to_an_ip_address_certificate() {
    let pki = make_pki(&["127.0.0.1"]);
    let (port, server) = tls_server(&pki, json!("ok"));
    let trust = TlsTrust::Roots(vec![pki.ca_der.clone()]);
    assert_eq!(call_with_trust(&format!("https://127.0.0.1:{port}/"), "ping", &json!([]), None, &trust).unwrap(), json!("ok"));
    assert!(server.join().unwrap().is_some());
}

/// A certificate from an untrusted CA is refused (here: the default webpki
/// roots, which do not contain the test CA), and the key never leaves.
#[test]
fn untrusted_certificate_is_refused_before_the_key_is_sent() {
    let pki = make_pki(&["localhost"]);
    let (port, server) = tls_server(&pki, json!(1));
    let err = call(&format!("https://localhost:{port}"), "getblockcount", &json!([]), Some("secret-key-0123")).unwrap_err();
    assert!(err.contains("TLS"), "{err}");
    assert!(server.join().unwrap().is_none(), "the server must not receive a request");

    // Another CA than the issuer: refused as well.
    let other = make_pki(&["localhost"]);
    let pki2 = make_pki(&["localhost"]);
    let (port, server) = tls_server(&pki2, json!(1));
    let err = call_with_trust(&format!("https://localhost:{port}"), "m", &json!([]), Some("k"),
        &TlsTrust::Roots(vec![other.ca_der.clone()])).unwrap_err();
    assert!(err.contains("TLS"), "{err}");
    assert!(server.join().unwrap().is_none());
}

/// A trusted certificate for another name is refused (host-name check).
#[test]
fn certificate_for_another_host_name_is_refused() {
    let pki = make_pki(&["rpc.gnb.example"]);
    let (port, server) = tls_server(&pki, json!(1));
    let trust = TlsTrust::Roots(vec![pki.ca_der.clone()]);
    let err = call_with_trust(&format!("https://127.0.0.1:{port}"), "m", &json!([]), Some("k"), &trust).unwrap_err();
    assert!(err.contains("TLS"), "{err}");
    assert!(server.join().unwrap().is_none());
}

/// An https endpoint is never downgraded: against a PLAIN HTTP server the
/// client sends a TLS ClientHello, never an HTTP request with the key.
#[test]
fn https_is_not_downgraded_to_plain_http() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
        let mut first = [0u8; 5];
        tcp.read_exact(&mut first).unwrap();
        let _ = tcp.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
        first
    });
    let err = call(&format!("https://127.0.0.1:{port}"), "m", &json!([]), Some("secret-key-0123")).unwrap_err();
    assert!(err.contains("TLS") || err.contains("RPC"), "{err}");
    let first = server.join().unwrap();
    assert_eq!(first[0], 0x16, "TLS handshake record expected, got {first:?}");
    assert_ne!(&first, b"POST ");
}

/// Plain HTTP keeps refusing the key for a non-loopback host.
#[test]
fn plain_http_still_refuses_the_key_for_remote_hosts() {
    let err = call("http://192.0.2.1:17210", "getblockcount", &json!([]), Some("secret-key-0123")).unwrap_err();
    assert!(err.contains("refusing to send the RPC API key over plain HTTP"), "{err}");
}

/// The CA can be given as a PEM file (`--rpc-ca` / `GNB_RPC_CA`).
#[test]
fn ca_from_a_pem_file() {
    let pki = make_pki(&["localhost"]);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ca.pem");
    let b64 = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(&pki.ca_der)
    };
    let pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        b64.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join("\n")
    );
    std::fs::write(&path, pem).unwrap();
    let trust = TlsTrust::from_cert_file(&path).unwrap();
    assert_eq!(trust, TlsTrust::Roots(vec![pki.ca_der.clone()]));
    let (port, server) = tls_server(&pki, json!(7));
    assert_eq!(call_with_trust(&format!("https://localhost:{port}"), "m", &json!([]), None, &trust).unwrap(), json!(7));
    assert!(server.join().unwrap().is_some());
    // A DER file works too.
    std::fs::write(&path, &pki.ca_der).unwrap();
    assert_eq!(TlsTrust::from_cert_file(&path).unwrap(), TlsTrust::Roots(vec![pki.ca_der.clone()]));
}
