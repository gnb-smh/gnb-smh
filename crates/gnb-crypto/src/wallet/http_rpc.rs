//! Bounded synchronous HTTP/1 JSON-RPC transport for the CLI wallets, over
//! plain HTTP or HTTPS (rustls, certificate and host-name verification).
//!
//! WAL-7 / NET-16: the API key is sent
//! * over **HTTPS** to any host — the server is authenticated by its
//!   certificate (the Mozilla roots from `webpki-roots`, or trust anchors the
//!   caller passes explicitly, e.g. a private CA), and the key is encrypted;
//! * over **plain HTTP** only when every resolved address is loopback. A
//!   remote node is reached over HTTPS (a TLS reverse proxy in front of its
//!   RPC port) or through an SSH tunnel (`ssh -L 17210:127.0.0.1:17210 node`).
//!
//! HTTPS needs the `https-rpc` feature (enabled by `wallet-cli` and by the
//! node's CLI); without it an `https://` endpoint is refused, never
//! downgraded to plain HTTP.
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};
use serde_json::Value;

const MAX_RESPONSE: usize = 64 * 1024 * 1024;
const MAX_HEADERS: usize = 64 * 1024;

fn remaining(deadline: Instant) -> Result<Duration, String> {
    deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero())
        .ok_or_else(|| "RPC deadline exceeded".into())
}

/// Which certificates authenticate an HTTPS server.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum TlsTrust {
    /// The Mozilla root programme (`webpki-roots`).
    #[default]
    WebPkiRoots,
    /// Exactly these trust anchors (DER certificates), e.g. the CA of a
    /// private deployment or a self-signed node certificate.
    Roots(Vec<Vec<u8>>),
}

impl TlsTrust {
    /// Trust anchors from a file of PEM certificates (one or more
    /// `BEGIN CERTIFICATE` blocks) or a single DER certificate.
    pub fn from_cert_file(path: &std::path::Path) -> Result<TlsTrust, String> {
        let bytes = crate::util::read_wallet_file(path, 1024 * 1024)
            .map_err(|e| format!("cannot read CA file {}: {e}", path.display()))?;
        if bytes.starts_with(b"-----BEGIN") || bytes.windows(10).any(|w| w == b"-----BEGIN") {
            #[cfg(feature = "https-rpc")]
            {
                use rustls::pki_types::{pem::PemObject, CertificateDer};
                let certs: Vec<Vec<u8>> = CertificateDer::pem_slice_iter(&bytes)
                    .map(|c| c.map(|c| c.to_vec()))
                    .collect::<Result<_, _>>()
                    .map_err(|e| format!("invalid PEM in {}: {e:?}", path.display()))?;
                if certs.is_empty() {
                    return Err(format!("no certificate in {}", path.display()));
                }
                return Ok(TlsTrust::Roots(certs));
            }
            #[cfg(not(feature = "https-rpc"))]
            return Err("this build has no TLS support (feature https-rpc)".into());
        }
        Ok(TlsTrust::Roots(vec![bytes]))
    }
}

/// A parsed RPC endpoint: `host:port`, `http://host[:port][/]` or
/// `https://host[:port][/]` (default ports 80 / 443). No credentials, path
/// or query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub tls: bool,
    /// Host as written (IPv6 without brackets).
    pub host: String,
    pub port: u16,
}

impl Endpoint {
    pub fn parse(endpoint: &str) -> Result<Endpoint, String> {
        let (tls, rest, default_port) = if let Some(r) = endpoint.strip_prefix("https://") {
            (true, r, Some(443))
        } else if let Some(r) = endpoint.strip_prefix("http://") {
            (false, r, Some(80))
        } else {
            (false, endpoint, None)
        };
        let rest = rest.strip_suffix('/').unwrap_or(rest);
        if rest.is_empty() || rest.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, '/' | '@' | '?' | '#')) {
            return Err("invalid RPC authority".into());
        }
        let (host, port) = if let Some(v6) = rest.strip_prefix('[') {
            let (h, after) = v6.split_once(']').ok_or("invalid RPC authority")?;
            match after.strip_prefix(':') {
                Some(p) => (h, Some(p)),
                None if after.is_empty() => (h, None),
                None => return Err("invalid RPC authority".into()),
            }
        } else {
            match rest.rsplit_once(':') {
                Some((h, p)) if !h.contains(':') => (h, Some(p)),
                Some(_) => return Err("invalid RPC authority (bracket IPv6 addresses)".into()),
                None => (rest, None),
            }
        };
        if host.is_empty() {
            return Err("invalid RPC authority".into());
        }
        let port = match port {
            Some(p) => p.parse::<u16>().map_err(|_| "invalid RPC port")?,
            None => default_port.ok_or("RPC authority needs a port (host:port)")?,
        };
        Ok(Endpoint { tls, host: host.to_string(), port })
    }

    /// `host:port` as used in the Host header and for name resolution.
    pub fn authority(&self) -> String {
        if self.host.contains(':') { format!("[{}]:{}", self.host, self.port) } else { format!("{}:{}", self.host, self.port) }
    }
}

/// HTTP endpoint (`host:port`, `http://…` or `https://…`). DNS resolution
/// shares the deadline; an OS resolver worker may outlive timeout. HTTPS
/// servers are authenticated against the `webpki-roots` trust anchors.
pub fn call(endpoint: &str, method: &str, params: &Value, api_key: Option<&str>) -> Result<Value, String> {
    call_with_trust(endpoint, method, params, api_key, &TlsTrust::WebPkiRoots)
}

/// [`call`] with explicit HTTPS trust anchors.
pub fn call_with_trust(endpoint: &str, method: &str, params: &Value, api_key: Option<&str>, trust: &TlsTrust)
    -> Result<Value, String>
{
    call_with_limits_trust(endpoint, method, params, api_key, MAX_RESPONSE, Duration::from_secs(30), trust)
}

#[cfg(test)]
fn call_with_limits(authority: &str, method: &str, params: &Value, api_key: Option<&str>, cap: usize, timeout: Duration) -> Result<Value, String> {
    call_with_limits_trust(authority, method, params, api_key, cap, timeout, &TlsTrust::WebPkiRoots)
}

/// The connection: plain TCP or TLS over TCP, with per-operation timeouts.
enum Conn {
    Plain(TcpStream),
    #[cfg(feature = "https-rpc")]
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Conn {
    fn socket(&self) -> &TcpStream {
        match self {
            Conn::Plain(s) => s,
            #[cfg(feature = "https-rpc")]
            Conn::Tls(s) => &s.sock,
        }
    }
    fn is_tls(&self) -> bool {
        !matches!(self, Conn::Plain(_))
    }
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Conn::Plain(s) => s.read(buf),
            #[cfg(feature = "https-rpc")]
            Conn::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Conn::Plain(s) => s.write(buf),
            #[cfg(feature = "https-rpc")]
            Conn::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Conn::Plain(s) => s.flush(),
            #[cfg(feature = "https-rpc")]
            Conn::Tls(s) => s.flush(),
        }
    }
}

/// The client TLS configuration for `trust` (ring provider, TLS 1.2/1.3,
/// certificate chain and host-name verification by rustls).
#[cfg(feature = "https-rpc")]
fn tls_config(trust: &TlsTrust) -> Result<std::sync::Arc<rustls::ClientConfig>, String> {
    let mut roots = rustls::RootCertStore::empty();
    match trust {
        TlsTrust::WebPkiRoots => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
        TlsTrust::Roots(ders) => {
            for der in ders {
                roots.add(rustls::pki_types::CertificateDer::from(der.clone()))
                    .map_err(|e| format!("invalid TLS trust anchor: {e}"))?;
            }
        }
    }
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS configuration: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(std::sync::Arc::new(config))
}

#[allow(clippy::too_many_arguments)]
fn call_with_limits_trust(endpoint: &str, method: &str, params: &Value, api_key: Option<&str>, cap: usize, timeout: Duration, trust: &TlsTrust) -> Result<Value, String> {
    let endpoint = Endpoint::parse(endpoint)?;
    #[cfg(not(feature = "https-rpc"))]
    let _ = trust;
    #[cfg(not(feature = "https-rpc"))]
    if endpoint.tls {
        return Err("https:// RPC endpoints need a build with TLS support (feature https-rpc)".into());
    }
    if api_key.is_some_and(|key| key.chars().any(|c| c.is_control())) { return Err("RPC API key contains control characters".into()); }
    let authority = endpoint.authority();
    let deadline = Instant::now().checked_add(timeout).ok_or("invalid RPC timeout")?;
    let owned = authority.clone();
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new().name("wallet-rpc-dns".into()).spawn(move || {
        let resolved = owned.to_socket_addrs().map(|addresses| addresses.take(32).collect::<Vec<_>>());
        let _ = send.send(resolved);
    }).map_err(|_| "RPC DNS worker unavailable")?;
    let addresses = receive.recv_timeout(remaining(deadline)?).map_err(|_| "RPC DNS deadline exceeded")?
        .map_err(|_| "RPC DNS resolution failed")?;
    // Over HTTPS the key is encrypted to an authenticated server; over plain
    // HTTP it may only travel to loopback.
    if api_key.is_some() && !api_key_allowed(endpoint.tls, &addresses) {
        return Err("refusing to send the RPC API key over plain HTTP to a non-loopback host; \
                    use https:// (certificate-verified) or an SSH tunnel to a loopback port".into());
    }
    let mut connected = None;
    for address in addresses {
        if let Ok(stream) = TcpStream::connect_timeout(&address, remaining(deadline)?) { connected = Some(stream); break; }
    }
    let tcp = connected.ok_or("RPC connection failed")?;
    let mut stream = if endpoint.tls {
        #[cfg(feature = "https-rpc")]
        {
            let name = rustls::pki_types::ServerName::try_from(endpoint.host.clone())
                .map_err(|_| "invalid TLS server name")?;
            let conn = rustls::ClientConnection::new(tls_config(trust)?, name)
                .map_err(|e| format!("TLS setup failed: {e}"))?;
            Conn::Tls(Box::new(rustls::StreamOwned::new(conn, tcp)))
        }
        #[cfg(not(feature = "https-rpc"))]
        unreachable!("refused above")
    } else {
        Conn::Plain(tcp)
    };
    let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}).to_string();
    let auth = api_key.map(|key| zeroize::Zeroizing::new(format!("x-api-key: {key}\r\n")));
    let request = zeroize::Zeroizing::new(format!(
        "POST / HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        auth.as_ref().map(|a| a.as_str()).unwrap_or(""), body.len()));
    let mut pending = request.as_bytes();
    while !pending.is_empty() {
        stream.socket().set_write_timeout(Some(remaining(deadline)?)).map_err(|_| "RPC socket configuration failed")?;
        let count = stream.write(pending).map_err(|e| transport_error("write", &e, stream.is_tls()))?;
        if count == 0 { return Err("RPC connection closed during write".into()); }
        pending = &pending[count..];
    }
    stream.socket().set_write_timeout(Some(remaining(deadline)?)).map_err(|_| "RPC socket configuration failed")?;
    stream.flush().map_err(|e| transport_error("write", &e, stream.is_tls()))?;
    let response = read_response(&mut stream, deadline, cap)?;
    let body = decode_response(&response, cap)?;
    let response: Value = serde_json::from_slice(&body).map_err(|_| "invalid JSON RPC response")?;
    if response.get("jsonrpc").and_then(Value::as_str) != Some("2.0") || response.get("id").and_then(Value::as_u64) != Some(1) {
        return Err("RPC envelope version or ID mismatch".into());
    }
    if let Some(error) = response.get("error").filter(|error| !error.is_null()) {
        if response.get("result").is_some() { return Err("RPC response contains result and error".into()); }
        let code = error.get("code").and_then(Value::as_i64).ok_or("malformed RPC error")?;
        if error.get("message").and_then(Value::as_str).is_none() { return Err("malformed RPC error".into()); }
        return Err(format!("RPC error code {code}"));
    }
    response.get("result").cloned().ok_or_else(|| "RPC response missing result".into())
}

/// A transport error message. TLS failures (certificate not trusted, name
/// mismatch, handshake) are reported as such; they carry no peer content.
fn transport_error(op: &str, e: &std::io::Error, tls: bool) -> String {
    if tls && e.kind() == std::io::ErrorKind::InvalidData {
        format!("TLS {op} failed: {e}")
    } else {
        format!("RPC {op} failed or deadline exceeded")
    }
}

/// The plaintext transport may carry an API key only to loopback addresses.
fn key_may_travel_to(addresses: &[std::net::SocketAddr]) -> bool {
    !addresses.is_empty() && addresses.iter().all(|a| a.ip().is_loopback())
}

/// WAL-7: the API key may be sent over TLS to any host (the server is
/// certificate-authenticated and the key encrypted), over plain HTTP only to
/// loopback addresses.
fn api_key_allowed(tls: bool, addresses: &[std::net::SocketAddr]) -> bool {
    tls || key_may_travel_to(addresses)
}

fn read_response(stream: &mut Conn, deadline: Instant, cap: usize) -> Result<Vec<u8>, String> {
    let limit = cap.checked_add(MAX_HEADERS).ok_or("invalid RPC response cap")?;
    let mut response = Vec::new();
    let mut headers_complete = false;
    loop {
        stream.socket().set_read_timeout(Some(remaining(deadline)?)).map_err(|_| "RPC socket configuration failed")?;
        let mut chunk = [0u8; 8192];
        let count = match stream.read(&mut chunk) {
            Ok(n) => n,
            // A TLS peer that closes without close_notify: treat as the end
            // of the response. Truncation is still caught by the framing
            // checks (Content-Length equality, chunk terminator).
            Err(e) if stream.is_tls() && e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
            Err(e) => return Err(transport_error("read", &e, stream.is_tls())),
        };
        remaining(deadline)?;
        if count == 0 { return Ok(response); }
        if response.len().checked_add(count).ok_or("RPC response length overflow")? > limit { return Err("RPC response exceeds byte limit".into()); }
        response.extend_from_slice(&chunk[..count]);
        if !headers_complete {
            if let Some(end) = response.windows(4).position(|w| w == b"\r\n\r\n") {
                if end > MAX_HEADERS { return Err("RPC headers exceed byte limit".into()); }
                headers_complete = true;
            } else if response.len() > MAX_HEADERS { return Err("RPC headers exceed byte limit".into()); }
        }
    }
}

fn decode_response(response: &[u8], cap: usize) -> Result<Vec<u8>, String> {
    let header_end = response.windows(4).position(|w| w == b"\r\n\r\n").ok_or("missing HTTP headers")?;
    if header_end > MAX_HEADERS { return Err("RPC headers exceed byte limit".into()); }
    let headers = std::str::from_utf8(&response[..header_end]).map_err(|_| "invalid HTTP headers")?;
    let mut lines = headers.split("\r\n");
    let mut status = lines.next().ok_or("missing HTTP status")?.split_whitespace();
    if !matches!(status.next(), Some("HTTP/1.0" | "HTTP/1.1")) { return Err("invalid HTTP version".into()); }
    let code = status.next().ok_or("missing HTTP status")?;
    if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) { return Err("invalid HTTP status".into()); }
    let code: u16 = code.parse().map_err(|_| "invalid HTTP status")?;
    if !(200..300).contains(&code) { return Err(format!("HTTP status {code}")); }
    let mut length = None;
    let mut chunked = false;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or("invalid HTTP header")?;
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
            || value.bytes().any(|b| b.is_ascii_control() && b != b'\t') {
            return Err("invalid HTTP header".into());
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() { return Err("duplicate HTTP length".into()); }
            let value = value.trim();
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) { return Err("invalid HTTP length".into()); }
            length = Some(value.parse::<usize>().map_err(|_| "invalid HTTP length")?);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if chunked || !value.trim().eq_ignore_ascii_case("chunked") { return Err("unsupported HTTP transfer encoding".into()); }
            chunked = true;
        }
    }
    if chunked && length.is_some() { return Err("ambiguous HTTP framing".into()); }
    let body_start = header_end.checked_add(4).ok_or("HTTP offset overflow")?;
    let body = &response[body_start..];
    if chunked { return decode_chunks(body, cap); }
    if length.is_some_and(|length| length != body.len()) { return Err("HTTP content length mismatch".into()); }
    if body.len() > cap { return Err("RPC response exceeds byte limit".into()); }
    Ok(body.to_vec())
}

fn decode_chunks(mut body: &[u8], cap: usize) -> Result<Vec<u8>, String> {
    let mut decoded = Vec::new();
    loop {
        let end = body.windows(2).position(|w| w == b"\r\n").ok_or("missing chunk size delimiter")?;
        let size = std::str::from_utf8(&body[..end]).map_err(|_| "invalid chunk size")?;
        if size.is_empty() || !size.bytes().all(|b| b.is_ascii_hexdigit()) { return Err("invalid chunk size".into()); }
        let size = usize::from_str_radix(size, 16).map_err(|_| "chunk size overflow")?;
        body = &body[end.checked_add(2).ok_or("chunk offset overflow")?..];
        if size == 0 {
            if body != b"\r\n" { return Err("unsupported chunk trailers or trailing bytes".into()); }
            return Ok(decoded);
        }
        if decoded.len().checked_add(size).ok_or("chunk size overflow")? > cap { return Err("RPC response exceeds byte limit".into()); }
        let framed_size = size.checked_add(2).ok_or("chunk size overflow")?;
        if body.len() < framed_size || &body[size..framed_size] != b"\r\n" { return Err("truncated or malformed chunk".into()); }
        decoded.extend_from_slice(&body[..size]);
        body = &body[framed_size..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunks_are_bytes_and_utf8_is_decoded_only_after_reassembly() {
        assert_eq!(decode_chunks(b"1\r\n\xc3\r\n1\r\n\xa9\r\n0\r\n\r\n", 2).unwrap(), "é".as_bytes());
        for malformed in [b"1\r\n\xc3\xa9\r\n0\r\n\r\n".as_slice(), b"ffffffffffffffffffffffff\r\n", b"2\r\na\r\n0\r\n\r\n", b"+1\r\na\r\n0\r\n\r\n", b"0\r\n\r\nextra", b"1\r\na\r\n"] {
            assert!(decode_chunks(malformed, 8).is_err());
        }
        assert!(decode_chunks(b"2\r\nab\r\n0\r\n\r\n", 1).is_err());
    }

    #[test]
    fn rejects_ambiguous_lengths_truncation_and_body_reflection() {
        for response in [
            b"HTTP/1.1 +200 OK\r\n\r\n".as_slice(),
            b"HTTP/1.1 0200 OK\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\na".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\na",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 999999999999999999999999\r\n\r\n",
        ] { assert!(decode_response(response, 8).is_err()); }
        let error = decode_response(b"HTTP/1.1 500 Failure\r\n\r\nprivate-peer-marker", 64).unwrap_err();
        assert_eq!(error, "HTTP status 500");
        assert_eq!(decode_response(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nab", 2).unwrap(), b"ab");
    }

    fn server(chunks: Vec<Vec<u8>>, interval: Duration) -> (String, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            stream.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut reader = std::io::BufReader::new(&mut stream);
            let mut body_len = 0;
            loop {
                let mut line = String::new();
                assert!(std::io::BufRead::read_line(&mut reader, &mut line).unwrap() > 0);
                if line == "\r\n" { break; }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    body_len = value.trim().parse::<usize>().unwrap();
                }
            }
            assert!(body_len < 4096);
            let mut request_body = vec![0; body_len];
            reader.read_exact(&mut request_body).unwrap();
            drop(reader);
            for chunk in chunks {
                if stream.write_all(&chunk).is_err() { break; }
                std::thread::sleep(interval);
            }
        });
        (address, worker)
    }

    #[test]
    fn actual_reads_are_capped_and_slow_drip_cannot_reset_absolute_deadline() {
        let mut oversized = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        oversized.extend(vec![b'x'; MAX_HEADERS.saturating_add(1024)]);
        let (address, worker) = server(vec![oversized], Duration::ZERO);
        assert!(call_with_limits(&address, "test", &Value::Null, None, 8, Duration::from_secs(2)).is_err());
        worker.join().unwrap();
        let mut chunks = vec![b"HTTP/1.1 200 OK\r\n\r\n".to_vec()];
        chunks.extend((0..15).map(|_| vec![b' ']));
        let (address, worker) = server(chunks, Duration::from_millis(10));
        let error = call_with_limits(&address, "test", &Value::Null, None, 1024, Duration::from_millis(50)).unwrap_err();
        assert!(error.contains("deadline"));
        worker.join().unwrap();
    }

    #[test]
    fn real_chunked_json_preserves_split_utf8_and_api_key_controls_are_refused() {
        let body = br#"{"jsonrpc":"2.0","id":1,"result":""#;
        let mut wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        for chunk in [body.as_slice(), b"\xc3", b"\xa9", b"\"}"] {
            wire.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            wire.extend_from_slice(chunk);
            wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
        let (address, worker) = server(vec![wire], Duration::ZERO);
        assert_eq!(call_with_limits(&address, "test", &Value::Null, None, 4096, Duration::from_secs(2)).unwrap(), "é");
        worker.join().unwrap();
        assert!(call("127.0.0.1:1", "test", &Value::Null, Some("key\r\ninjected")).unwrap_err().contains("control"));
    }

    /// WAL-7 (residual): the API key goes over TLS to any host, over plain
    /// HTTP only to loopback.
    #[test]
    fn api_key_policy_allows_tls_to_any_host_and_plain_only_to_loopback() {
        let remote: Vec<std::net::SocketAddr> = vec!["192.0.2.1:443".parse().unwrap()];
        let local: Vec<std::net::SocketAddr> = vec!["127.0.0.1:17210".parse().unwrap()];
        assert!(api_key_allowed(true, &remote));
        assert!(api_key_allowed(true, &local));
        assert!(!api_key_allowed(false, &remote));
        assert!(api_key_allowed(false, &local));
        assert!(!api_key_allowed(false, &[]));
    }

    #[test]
    fn endpoints_parse_scheme_host_and_port() {
        let e = Endpoint::parse("127.0.0.1:17210").unwrap();
        assert_eq!((e.tls, e.host.as_str(), e.port), (false, "127.0.0.1", 17210));
        let e = Endpoint::parse("http://node:8080/").unwrap();
        assert_eq!((e.tls, e.host.as_str(), e.port), (false, "node", 8080));
        let e = Endpoint::parse("https://rpc.gnb-smh.com").unwrap();
        assert_eq!((e.tls, e.host.as_str(), e.port, e.authority()), (true, "rpc.gnb-smh.com", 443, "rpc.gnb-smh.com:443".to_string()));
        let e = Endpoint::parse("https://[::1]:17211").unwrap();
        assert_eq!((e.tls, e.host.as_str(), e.port, e.authority()), (true, "::1", 17211, "[::1]:17211".to_string()));
        for bad in ["", "node", "https://", "https://user@host", "http://h/path", "https://h:99999",
                    "https://h:x", "::1:80", "https://h?q", "h:1 ", "ftp://h:1"] {
            assert!(Endpoint::parse(bad).is_err(), "{bad:?} parsed");
        }
    }

    /// Without the `https-rpc` feature an https endpoint is refused, never
    /// downgraded to plain HTTP (the WASM / no-TLS builds).
    #[cfg(not(feature = "https-rpc"))]
    #[test]
    fn https_without_tls_support_is_refused() {
        let error = call("https://127.0.0.1:1", "getblockcount", &Value::Null, Some("k")).unwrap_err();
        assert!(error.contains("TLS support"), "{error}");
    }

    /// WAL-7 regression: the API key never travels in clear to a remote host.
    #[test]
    fn api_key_is_refused_for_non_loopback_hosts() {
        let error = call("192.0.2.1:17210", "getblockcount", &Value::Null, Some("0123456789abcdef0123")).unwrap_err();
        assert!(error.contains("refusing to send the RPC API key"), "{error}");
        assert!(key_may_travel_to(&["127.0.0.1:1".parse().unwrap(), "[::1]:1".parse().unwrap()]));
        assert!(!key_may_travel_to(&["127.0.0.1:1".parse().unwrap(), "10.0.0.1:1".parse().unwrap()]));
        assert!(!key_may_travel_to(&[]));
    }

    #[test]
    fn real_json_errors_do_not_echo_peer_content() {
        for body in ["private-peer-marker", r#"{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"private-peer-marker"}}"#] {
            let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len());
            let (address, worker) = server(vec![response.into_bytes()], Duration::ZERO);
            let error = call_with_limits(&address, "test", &Value::Null, None, 4096, Duration::from_secs(2)).unwrap_err();
            assert!(!error.contains("private-peer-marker"));
            worker.join().unwrap();
        }
    }
}
