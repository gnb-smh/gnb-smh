//! Runtime PF-2 regression through the existing public CLI entry point.
//! Only synthetic policies and a local RPC fixture are used.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};

struct RpcFixture {
    endpoint: String,
    calls: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl RpcFixture {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let calls = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (seen, stopping) = (calls.clone(), stop.clone());
        let worker = std::thread::spawn(move || {
            while !stopping.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        // Accepted sockets inherit O_NONBLOCK on macOS.
                        stream.set_nonblocking(false).unwrap();
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let mut bytes = Vec::new();
                        let mut buf = [0u8; 4096];
                        let request = loop {
                            let n = stream.read(&mut buf).unwrap();
                            assert!(n > 0 && bytes.len() < 64 * 1024);
                            bytes.extend_from_slice(&buf[..n]);
                            if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                                let header = String::from_utf8_lossy(&bytes[..end]);
                                let len: usize = header
                                    .lines()
                                    .find_map(|l| {
                                        l.split_once(':')
                                            .filter(|(k, _)| {
                                                k.eq_ignore_ascii_case("content-length")
                                            })
                                            .map(|(_, v)| v.trim().parse().unwrap())
                                    })
                                    .unwrap();
                                if bytes.len() >= end + 4 + len {
                                    break serde_json::from_slice::<serde_json::Value>(
                                        &bytes[end + 4..end + 4 + len],
                                    )
                                    .unwrap();
                                }
                            }
                        };
                        let method = request["method"].as_str().unwrap().to_owned();
                        seen.lock().unwrap().push(method.clone());
                        let result = if method == "getnetworkinfo" {
                            serde_json::json!({"network":"mainnet", "hardening_activation_height":17500})
                        } else {
                            serde_json::json!({"error":"unexpected fixture RPC"})
                        };
                        let response = serde_json::json!({"jsonrpc":"2.0", "id":request["id"], "result":result}).to_string();
                        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", response.len(), response).unwrap();
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(e) => panic!("fixture accept: {e}"),
                }
            }
        });
        Self {
            endpoint,
            calls,
            stop,
            worker: Some(worker),
        }
    }
}

impl Drop for RpcFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let result = self.worker.take().unwrap().join();
        if !std::thread::panicking() {
            result.unwrap();
        }
    }
}

fn cli(args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_gnb-cli"));
    cmd.args(args)
        .env_remove("GNB_RPC_API_KEY")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // No controlling terminal: an erroneous password prompt must fail rather
    // than consuming a developer's terminal input or hanging the test.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(|| {
                extern "C" {
                    fn setsid() -> i32;
                }
                if setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let mut child = cmd.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(8);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            panic!("CLI fixture timed out");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    child.wait_with_output().unwrap()
}

#[test]
fn rpc_fixture_positive_control_reaches_existing_info_command() {
    let fixture = RpcFixture::new();
    let out = cli(&["--rpc-url", &fixture.endpoint, "getnetworkinfo"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("mainnet"));
    assert_eq!(*fixture.calls.lock().unwrap(), ["getnetworkinfo"]);
}

#[test]
fn policysign_checks_node_network_before_wallet_access() {
    let fixture = RpcFixture::new();
    let tmp = tempfile::tempdir().unwrap();
    let (pk, _) = gnb::crypto::generate_keypair();
    let policy = gnb::core::policy::SpendPolicy::new(1, vec![pk], 0, 0).unwrap();
    let spend = gnb::wallet::policy_spend::PolicySpend::new(
        gnb::address::Network::Testnet,
        policy,
        &[([7; 32], 0, 10_000_000)],
        vec![9; 20],
        1_000_000,
        50_000,
        0,
    )
    .unwrap();
    let path = tmp.path().join("spend.json");
    let original = spend.to_json().unwrap();
    std::fs::write(&path, &original).unwrap();
    let wallet = tmp.path().join("must-not-open-wallet.json");
    let out = cli(&[
        "--rpc-url",
        &fixture.endpoint,
        "policysign",
        path.to_str().unwrap(),
        wallet.to_str().unwrap(),
    ]);
    assert!(!out.status.success());
    assert_eq!(
        std::fs::read_to_string(path).unwrap(),
        original,
        "a refused spend must remain unchanged"
    );
    assert_eq!(
        *fixture.calls.lock().unwrap(),
        ["getnetworkinfo"],
        "PF-2: configured node must be checked before opening the signing wallet; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("Wallet password"),
        "wallet access preceded public preflight"
    );
}
