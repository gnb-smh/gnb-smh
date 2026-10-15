//! gnb-cli — Bloch-SIS Protocol RPC client (like bitcoin-cli)
//!
//! Usage:
//!   gnb-cli getnetworkinfo
//!   gnb-cli getbalance gnb1q...
//!   gnb-cli send &lt;wallet.json&gt; &lt;to_address&gt; &lt;amount_gnb&gt; [--fee 0.0005]
//!   gnb-cli --help

use std::process;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        print_usage();
        return;
    }

    // Parse --rpc-url flag (default: 127.0.0.1:17210)
    let mut rpc_host = "127.0.0.1".to_string();
    let mut rpc_port = 17210u16;
    // WAL-7: `--rpc-url https://node.example` (certificate-verified), with
    // `--rpc-ca <PEM/DER file>` for a private CA or self-signed certificate.
    let mut rpc_url: Option<String> = None;
    let mut rpc_ca: Option<String> = None;
    let mut allow_large_hd_wallet = false;
    // WAL-7: the network of a new wallet is an explicit choice recorded in
    // the file (keystore v3 authenticates it), never inferred from its name.
    let mut testnet = false;
    // CRY-7: `send` unlocks a v2 keystore only for an explicitly stated
    // network (--mainnet / --testnet), then rewrites it as v3.
    let mut mainnet = false;
    let mut cmd_args: Vec<&str> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--rpc-host" => { i += 1; if i < args.len() { rpc_host = args[i].clone(); } }
            "--rpc-port" => { i += 1; if i < args.len() { rpc_port = args[i].parse().unwrap_or(17210); } }
            "--rpc-url" => { i += 1; if i < args.len() { rpc_url = Some(args[i].clone()); } }
            "--rpc-ca" => { i += 1; if i < args.len() { rpc_ca = Some(args[i].clone()); } }
            "--allow-large-hd-wallet" => { allow_large_hd_wallet = true; }
            "--testnet" => { testnet = true; }
            "--mainnet" => { mainnet = true; }
            _ => { cmd_args.push(&args[i]); }
        }
        i += 1;
    }
    if testnet && mainnet {
        die("--mainnet and --testnet are mutually exclusive");
    }
    let stated_network = match (testnet, mainnet) {
        (true, _) => Some(gnb::address::Network::Testnet),
        (false, true) => Some(gnb::address::Network::Mainnet),
        (false, false) => None,
    };
    let rpc_target = RpcTarget::new(rpc_url, &rpc_host, rpc_port, rpc_ca.as_deref());

    if cmd_args.is_empty() {
        print_usage();
        return;
    }

    let method = cmd_args[0];
    let params = &cmd_args[1..];

    let (rpc_method, rpc_params) = match method {

        // ── Network ────────────────────────────────────────────────
        "getnetworkinfo" | "info" => ("getnetworkinfo", serde_json::Value::Null),
        "getblockcount"  | "height" => ("getblockcount", serde_json::Value::Null),
        "getmempoolinfo" | "mempool" => ("getmempoolinfo", serde_json::Value::Null),

        // ── Blocks ─────────────────────────────────────────────────
        "getblockhash" => {
            require_params(params, 1, "getblockhash <height>");
            let h: u64 = params[0].parse().unwrap_or_else(|_| die("height must be a number"));
            ("getblockhash", serde_json::json!([h]))
        }

        "getblock" => {
            require_params(params, 1, "getblock <hash> [verbose]");
            let verbose = params.get(1).map(|v| *v == "true" || *v == "1").unwrap_or(false);
            ("getblock", serde_json::json!([params[0], verbose]))
        }

        "getblockbyheight" | "block" => {
            require_params(params, 1, "getblockbyheight <height> [verbose]");
            let h: u64 = params[0].parse().unwrap_or_else(|_| die("height must be a number"));
            let verbose = params.get(1).map(|v| *v == "true" || *v == "1").unwrap_or(false);
            ("getblockbyheight", serde_json::json!([h, verbose]))
        }

        "getrecentblocks" | "recent" => {
            let count: u64 = params.first().and_then(|s| s.parse().ok()).unwrap_or(10);
            ("getrecentblocks", serde_json::json!([count]))
        }

        // ── Transactions ───────────────────────────────────────────
        "gettransaction" | "tx" => {
            require_params(params, 1, "gettransaction <txid>");
            ("gettransaction", serde_json::json!([params[0]]))
        }

        "sendrawtransaction" | "sendraw" => {
            require_params(params, 1, "sendrawtransaction <hex>");
            ("sendrawtransaction", serde_json::json!([params[0]]))
        }

        // ── Wallet ─────────────────────────────────────────────────
        "getbalance" | "balance" => {
            require_params(params, 1, "getbalance <address>");
            ("getbalance", serde_json::json!([params[0]]))
        }

        "getutxos" | "utxos" | "listunspent" => {
            require_params(params, 1, "getutxos <address>");
            ("getutxos", serde_json::json!([params[0]]))
        }

        // ── Phase 2: new commands ──────────────────────────────────
        "validateaddress" | "validate" => {
            require_params(params, 1, "validateaddress <address>");
            ("validateaddress", serde_json::json!([params[0]]))
        }

        "estimatefee" | "fee" => {
            ("estimatefee", serde_json::Value::Null)
        }

        "getrawmempool" | "rawmempool" => {
            let verbose = params.first().map(|v| *v == "true" || *v == "1").unwrap_or(false);
            ("getrawmempool", serde_json::json!([verbose]))
        }

        "decoderawtransaction" | "decode" => {
            require_params(params, 1, "decoderawtransaction <hex>");
            ("decoderawtransaction", serde_json::json!([params[0]]))
        }

        "getdaginfo" | "dag" => {
            ("getdaginfo", serde_json::Value::Null)
        }

        "listtransactions" | "txlist" => {
            require_params(params, 1, "listtransactions <address> [count]");
            let count: u64 = params.get(1).and_then(|s| s.parse().ok()).unwrap_or(20);
            ("listtransactions", serde_json::json!([params[0], count]))
        }

        "getpeerinfo" | "peers" => {
            ("getpeerinfo", serde_json::Value::Null)
        }

        // ── Wallet: send (builds + signs + broadcasts) ─────────────
        "send" => {
            require_params(params, 3, "send <wallet.json> <to_address> <amount_gnb> [--fee auto|GNB] [--max-fee GNB] [--yes] [--allow-unverified-inputs]");
            do_send(params, &rpc_target, stated_network);
            return;
        }

        // ── Diagnostic: key format (no secret leaked — lengths/suite only) ─────
        "keyinfo" => {
            require_params(params, 1, "keyinfo <wallet.json>");
            let pw = read_password("Wallet password: ");
            let path = std::path::Path::new(params[0]);
            match gnb::wallet::Keypair::load_encrypted(path, &pw) {
                Ok(kp) => {
                    let pk = &kp.public_key; let sk = &kp.private_key;
                    let suite = |b: &[u8]| -> String {
                        if b.len() >= 4 && b[0]==0xB1 && b[1]==0x0C {
                            format!("enveloped suite 0x{:04x}", u16::from_le_bytes([b[2],b[3]]))
                        } else { "RAW (no envelope)".into() }
                    };
                    println!("address:      {}", kp.address);
                    println!("pubkey  len:  {}  ({})", pk.len(), suite(pk));
                    println!("privkey len:  {}  ({})", sk.len(), suite(sk));
                    println!("expected: hybrid pk=3749 sk=4032+falcon(~2300); mldsa-only pk=1956 sk=4036");
                }
                Err(e) => { eprintln!("load failed: {}", e); process::exit(1); }
            }
            return;
        }

        // ── Wallet: generate ───────────────────────────────────────
        "newwallet" | "createwallet" => {
            require_params(params, 1, "newwallet <output_path.json> [--random-key] [--testnet]");
            let random_key = params[1..].contains(&"--random-key");
            do_new_wallet(params[0], testnet, random_key);
            return;
        }

        "restorewallet" => {
            require_params(params, 1, "restorewallet <output_path.json> [--testnet]");
            do_restore_wallet(params[0], testnet);
            return;
        }

        // ── Phase 3: HD Wallet commands ────────────────────────────
        "newseed" => {
            require_params(params, 1, "newseed <output_path.json> [--testnet]");
            do_newseed(params[0], testnet);
            return;
        }

        "newaddress" => {
            require_params(params, 1, "newaddress <wallet-hd.json> [label]");
            let label = params.get(1).copied().unwrap_or("new");
            do_newaddress(params[0], label, allow_large_hd_wallet);
            return;
        }

        "addresses" => {
            require_params(params, 1, "addresses <wallet-hd.json>");
            do_list_addresses(params[0], allow_large_hd_wallet);
            return;
        }

        "importfounder" | "import-founder" => {
            require_params(params, 2, "importfounder <wallet-hd.json> <founder.json>");
            do_import_founder(params[0], params[1], allow_large_hd_wallet);
            return;
        }

        // ── PoI: Proof-of-Improvement ──────────────────────────────
        "pools" | "getpools" | "treasury" | "gettreasury" => {
            // V2: aliases preserved for UX; routes to V2 multi-pool endpoint.
            ("getpools", serde_json::Value::Null)
        }

        "poiclaims" | "claims" => {
            ("getpoiclaims", serde_json::Value::Null)
        }

        "poiclaim" | "claim" => {
            require_params(params, 1, "poiclaim <claim_id_hex>");
            ("getpoiclaim", serde_json::json!([params[0]]))
        }

        "poisubmit" | "submitclaim" => {
            require_params(params, 4, "poisubmit <commit_hash> <category:0-3> <description> <address> [ci_attestation]");
            let ci = params.get(4).copied().unwrap_or("");
            ("submitpoiclaim", serde_json::json!([params[0], params[1].parse::<u64>().unwrap_or(3), params[2], params[3], ci]))
        }

        "poivote" | "vote" => {
            require_params(params, 3, "poivote <claim_id> <voter_address> <yes|no|abstain>");
            ("submitpoivote", serde_json::json!([params[0], params[1], params[2]]))
        }

        // ── eUTXO VM (node must run with --features euvm) ──────────
        // Thin passthroughs to the D5 euvm_* RPC methods; on a node built
        // without the feature they return "unknown method".
        "euvm_utxos" | "euvm_listutxos" => {
            // [validator_hash|null] [limit] [offset]
            let vh = params.get(0)
                .filter(|s| **s != "null" && !s.is_empty())
                .map(|s| serde_json::json!(s))
                .unwrap_or(serde_json::Value::Null);
            let limit: u64 = params.get(1).and_then(|s| s.parse().ok()).unwrap_or(100);
            let offset: u64 = params.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
            ("euvm_listutxos", serde_json::json!([vh, limit, offset]))
        }

        "euvm_getutxo" => {
            require_params(params, 2, "euvm_getutxo <txid_hex> <index>");
            let idx: u64 = params[1].parse().unwrap_or_else(|_| die("index must be a number"));
            ("euvm_getutxo", serde_json::json!([params[0], idx]))
        }

        "euvm_buildtx" => {
            // Takes the full build-request object as ONE JSON argument:
            //   gnb-cli euvm_buildtx '{"inputs":[...],"outputs":[...]}'
            // (May carry secret keys — the node treats it as an auth-gated
            // write; set GNB_RPC_API_KEY if the node requires auth.)
            require_params(params, 1, "euvm_buildtx '<build-request-json>'");
            let obj: serde_json::Value = serde_json::from_str(params[0])
                .unwrap_or_else(|e| die(&format!("argument must be valid JSON: {}", e)));
            ("euvm_buildtx", serde_json::json!([obj]))
        }

        // ── Help ───────────────────────────────────────────────────
        "help" => { print_usage(); return; }

        _ => {
            eprintln!("Unknown command: {}", method);
            eprintln!("Run 'gnb-cli help' for usage.");
            process::exit(1);
        }
    };

    // Make RPC call
    match rpc_call(&rpc_target, rpc_method, &rpc_params) {
        Ok(result) => {
            let pretty = serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string());
            println!("{}", pretty);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    }
}

// ── RPC client ──────────────────────────────────────────────────────────────

/// Where gnb-cli sends its RPCs (WAL-7).
struct RpcTarget {
    /// `host:port` (plain HTTP), `http://…` or `https://…`.
    endpoint: String,
    /// HTTPS trust anchors: the webpki roots, or `--rpc-ca`.
    trust: gnb::wallet::http_rpc::TlsTrust,
}

impl RpcTarget {
    fn new(rpc_url: Option<String>, host: &str, port: u16, ca: Option<&str>) -> RpcTarget {
        let endpoint = match rpc_url {
            Some(url) => url,
            None if host.contains("://") => host.to_string(),
            None if host.contains(':') && !host.starts_with('[') => format!("[{host}]:{port}"),
            None => format!("{host}:{port}"),
        };
        let trust = match ca {
            Some(path) => gnb::wallet::http_rpc::TlsTrust::from_cert_file(std::path::Path::new(path))
                .unwrap_or_else(|e| die(&e)),
            None => gnb::wallet::http_rpc::TlsTrust::WebPkiRoots,
        };
        RpcTarget { endpoint, trust }
    }
}

/// JSON-RPC over HTTP or HTTPS. WAL-7/NET-16: `GNB_RPC_API_KEY` is sent over
/// HTTPS (certificate-verified) to any host, over plain HTTP only to a
/// loopback address (remote nodes: https:// or an SSH tunnel).
fn rpc_call(target: &RpcTarget, method: &str, params: &serde_json::Value) -> Result<serde_json::Value, String> {
    let api_key = std::env::var("GNB_RPC_API_KEY").ok().map(zeroize::Zeroizing::new);
    gnb::wallet::http_rpc::call_with_trust(&target.endpoint, method, params,
        api_key.as_deref().map(String::as_str), &target.trust)
}

// ── Send command ────────────────────────────────────────────────────────────

fn do_send(params: &[&str], target: &RpcTarget, stated_network: Option<gnb::address::Network>) {
    let wallet_path = params[0];
    let to_address = params[1];
    let amount_str = params[2];

    // Fee: `auto` (default) = the consensus minimum for the signed
    // transaction's actual size; a GNB value is a floor raised to that
    // minimum. --max-fee replaces the default guard explicitly (WAL-1).
    let mut fee_arg = "auto";
    let mut max_fee_arg: Option<&str> = None;
    let mut yes = false;
    let mut allow_unverified = false;
    let mut i = 3;
    while i < params.len() {
        match params[i] {
            "--fee" if i + 1 < params.len() => { fee_arg = params[i + 1]; i += 2; }
            "--max-fee" if i + 1 < params.len() => { max_fee_arg = Some(params[i + 1]); i += 2; }
            "--yes" | "-y" => { yes = true; i += 1; }
            "--allow-unverified-inputs" => { allow_unverified = true; i += 1; }
            other => die(&format!("unknown send option {other:?}")),
        }
    }

    let amount_sats = bloch_to_sats(amount_str);
    let fee = gnb::wallet::send::parse_fee_arg(fee_arg).unwrap_or_else(|message| die(message));
    let fee_policy = gnb::wallet::send::parse_max_fee_arg(max_fee_arg).unwrap_or_else(|message| die(message));

    // Load wallet
    let password = read_password("Wallet password: ");
    let path = std::path::Path::new(wallet_path);
    // Keystore v3/v2 first (address field; bloch1q… accepted for v2), then
    // the v1 keyfile format (address derived from the public key).
    // CRY-7: a v2 keystore needs the network stated (--mainnet/--testnet);
    // it is checked against the stored address and rewritten as v3 — but only
    // once the send is confirmed, keeping the original as <file>.v2.bak.
    let (keypair, pending_migration) = match gnb::wallet::Keypair::unlock_for_spending(path, &password, stated_network) {
        Ok((kp, pending)) => {
            if pending.is_some() {
                eprintln!("Keystore {} is v2: it is rewritten as v3 (network and address authenticated) \
                           once the send is confirmed; the original is kept as a .v2.bak copy for Bloch \
                           wallets and GnB releases before v3, which read only version 2.", path.display());
            }
            (kp, pending)
        }
        Err(e2) if is_keystore_v2_or_v3(path) => die(&format!("Failed to load wallet: {e2}")),
        Err(e2) => match gnb::wallet::Wallet::load_encrypted(path, &password) {
            Ok(w) => {
                if stated_network.is_some_and(|n| n != w.network()) {
                    die("the wallet's network does not match --mainnet/--testnet");
                }
                (w.into_keypair(), None)
            }
            Err(e1) => {
                eprintln!("Failed to load wallet: {} (keystore v2/v3) / {} (keyfile v1)", e2, e1);
                process::exit(1);
            }
        },
    };
    drop(password);

    checked_destination(to_address, &keypair.address).unwrap_or_else(|message| die(message));
    let to = gnb::address::Address::parse(to_address).unwrap_or_else(|_| die("invalid destination address"));

    // Fetch UTXOs (bounded), verify the selected ones against their
    // transactions (WAL-1), build and sign under the fee guard.
    let rpc = |method: &str, p: &serde_json::Value| rpc_call(target, method, p);
    let request = gnb::wallet::send::SendRequest {
        keypair: &keypair,
        to: &to,
        amount: amount_sats,
        fee,
        fee_policy,
        // Non-interactive sends refuse unprovable inputs unless asked.
        require_verified_inputs: yes && !allow_unverified,
        utxo_limit: 50,
    };
    let prepared = gnb::wallet::send::prepare_send(&rpc, &request)
        .unwrap_or_else(|e| die(&format!("TX build failed: {e}")));

    // Show what will be signed — with the ACTUAL fee — and confirm (WAL-7).
    println!("UTXOs seen: {} ({} GNB)", prepared.utxos_seen, prepared.value_seen as f64 / 1e8);
    for (k, v) in prepared.summary(&keypair.address, to_address) {
        println!("{:<14} {}", format!("{k}:"), v);
    }
    if !yes && !gnb::wallet::send::confirm("Broadcast this transaction?") {
        die("not broadcast");
    }
    // CRY-7: the send passed every check and was confirmed.
    if let Some(pending) = pending_migration {
        match pending.commit() {
            Ok(backup) => eprintln!("Keystore {} rewritten as v3; the v2 original is kept at {} \
                                     (keep it for Bloch or older GnB releases).", path.display(), backup.display()),
            Err(e) => eprintln!("Keystore not migrated: {e}"),
        }
    }

    match gnb::wallet::send::broadcast(&rpc, &prepared) {
        Ok(txid) => println!("Broadcast OK: {txid}"),
        Err(e) => die(&format!("Broadcast failed: {e}")),
    }
}


// ── New wallet command ──────────────────────────────────────────────────────

// ── Phase 3: HD Wallet functions ────────────────────────────────────────────

/// Prompt for a new password twice (CRY-4: every copy is zeroizing).
fn read_new_password() -> zeroize::Zeroizing<String> {
    loop {
        let p1 = read_password("Set password (min 12 chars, 3 of: upper/lower/digit/special): ");
        if let Err(e) = gnb::wallet::validate_password(&p1) {
            eprintln!("Weak password: {}", e);
            continue;
        }
        let p2 = read_password("Confirm password: ");
        if *p1 != *p2 {
            eprintln!("Passwords don't match.");
            continue;
        }
        break p1;
    }
}

/// WAL-7: a file name containing "testnet" no longer selects the network.
fn warn_if_name_suggests_other_network(output_path: &str, testnet: bool) {
    if output_path.contains("testnet") && !testnet {
        eprintln!("Note: creating a MAINNET wallet; pass --testnet for a testnet wallet \
                   (the network is no longer inferred from the file name).");
    }
}

fn do_newseed(output_path: &str, testnet: bool) {
    println!("Generating HD wallet with 24-word mnemonic...");
    println!();
    warn_if_name_suggests_other_network(output_path, testnet);

    let password = read_new_password();

    let use_passphrase = read_password("Optional passphrase (press Enter to skip): ");
    let passphrase = if use_passphrase.is_empty() { None } else { Some(use_passphrase.as_str()) };

    let wallet = match gnb::hd_wallet::HdWallet::create(&password, passphrase, testnet) {
        Ok(w) => w,
        Err(e) => { eprintln!("Failed to create wallet: {}", e); process::exit(1); }
    };

    let mnemonic_str = zeroize::Zeroizing::new(wallet.mnemonic.to_string());
    let first_addr = wallet.addresses[0].1.address.clone();

    let path = std::path::Path::new(output_path);
    if let Err(e) = wallet.save(path) {
        eprintln!("Save failed: {}", e);
        process::exit(1);
    }

    println!();
    println!("══════════════════════════════════════════════════════════════");
    println!("  BACKUP YOUR MNEMONIC PHRASE (24 words)");
    println!("══════════════════════════════════════════════════════════════");
    println!();
    let words: Vec<&str> = mnemonic_str.split_whitespace().collect();
    for (i, chunk) in words.chunks(4).enumerate() {
        let line: Vec<String> = chunk.iter().enumerate().map(|(j, w)| {
            format!("{:2}. {:<10}", i * 4 + j + 1, w)
        }).collect();
        println!("  {}", line.join(" "));
    }
    println!();
    println!("══════════════════════════════════════════════════════════════");
    println!();
    println!("Write these 24 words on paper. Store offline.");
    println!("Without BOTH the mnemonic AND {}, the wallet is inaccessible.", output_path);
    if passphrase.is_some() {
        println!("Passphrase is ALSO required to unlock.");
    }
    println!();
    println!("First address: {}", first_addr);
    println!("Wallet file:   {}", output_path);
}

fn load_hd_wallet(
    path: &std::path::Path,
    mnemonic: &str,
    passphrase: Option<&str>,
    password: &str,
    allow_large: bool,
) -> Result<gnb::hd_wallet::HdWallet, String> {
    if allow_large {
        // Explicit recovery mode for a trusted historical backup. It retains
        // the parser's absolute byte ceiling but intentionally relaxes the
        // normal address and rederivation work budgets.
        gnb::hd_wallet::HdWallet::load_with_file_limit(
            path,
            mnemonic,
            passphrase,
            password,
            gnb::util::MAX_WALLET_FILE_LIMIT,
        )
    } else {
        gnb::hd_wallet::HdWallet::load_bounded(path, mnemonic, passphrase, password)
            .map_err(|error| {
                if error.contains("exceeds configured limit") || error.contains("wallet file exceeds configured") {
                    format!("{error}; for a trusted historical backup retry with --allow-large-hd-wallet")
                } else {
                    error
                }
            })
    }
}

fn do_newaddress(wallet_path: &str, label: &str, allow_large_hd_wallet: bool) {
    let password = read_password("Wallet password: ");
    let passphrase_input = read_password("Passphrase (Enter to skip): ");
    let passphrase = if passphrase_input.is_empty() { None } else { Some(passphrase_input.as_str()) };
    let mnemonic = read_password("Mnemonic (24 words): ");

    let path = std::path::Path::new(wallet_path);
    let mut wallet = match load_hd_wallet(path, &mnemonic, passphrase, &password, allow_large_hd_wallet) {
        Ok(w) => w,
        Err(e) => { eprintln!("Load failed: {}", e); process::exit(1); }
    };

    let new_addr = match wallet.new_address(label) {
        Ok(kp) => kp.address.clone(),
        Err(e) => { eprintln!("Derivation failed: {}", e); process::exit(1); }
    };

    if let Err(e) = wallet.save(path) {
        eprintln!("Save failed: {}", e);
        process::exit(1);
    }

    println!();
    println!("New address: {}", new_addr);
    println!("Label:       {}", label);
}

fn read_public_hd_wallet(
    wallet_path: &str,
    allow_large_hd_wallet: bool,
) -> Result<gnb::hd_wallet::HdWalletFile, String> {
    let path = std::path::Path::new(wallet_path);
    if allow_large_hd_wallet {
        gnb::hd_wallet::HdWalletFile::read_public_with_limits(
            path,
            gnb::util::MAX_WALLET_FILE_LIMIT,
            usize::MAX,
        )
    } else {
        gnb::hd_wallet::HdWalletFile::read_public_bounded(path).map_err(|error| {
            if error.contains("exceeds configured limit")
                || error.contains("wallet file exceeds configured")
            {
                format!("{error}; for a trusted historical backup retry with --allow-large-hd-wallet")
            } else {
                error
            }
        })
    }
}

fn do_list_addresses(wallet_path: &str, allow_large_hd_wallet: bool) {
    // Public metadata needs no password, but remains attacker-controlled input.
    let wallet = match read_public_hd_wallet(wallet_path, allow_large_hd_wallet) {
        Ok(w) => w,
        Err(e) => { eprintln!("Invalid wallet file: {}", e); process::exit(1); }
    };
    println!();
    println!("HD Wallet — {} ({})", wallet_path, wallet.network);
    println!("Created: {}", wallet.created_at);
    println!();
    println!("  {:<4} {:<56} {}", "idx", "address", "label");
    println!("  {}", "-".repeat(80));
    for addr in &wallet.addresses {
        println!("  {:<4} {:<56} {}", addr.index, addr.address, addr.label);
    }
    println!();
    println!("Total: {} address(es)", wallet.addresses.len());
}

fn do_import_founder(hd_wallet_path: &str, founder_path: &str, allow_large_hd_wallet: bool) {
    println!("Importing founder.json into HD wallet...");
    println!();

    let founder_password = read_password("founder.json password: ");
    let founder_path_p = std::path::Path::new(founder_path);
    let founder_kp = match gnb::wallet::Keypair::load_encrypted(founder_path_p, &founder_password) {
        Ok(kp) => kp,
        Err(e) => { eprintln!("Failed to load founder.json: {}", e); process::exit(1); }
    };

    println!("Founder address: {}", founder_kp.address);
    println!();

    let hd_password = read_password("HD wallet password: ");
    let hd_passphrase_input = read_password("HD wallet passphrase (Enter to skip): ");
    let hd_passphrase = if hd_passphrase_input.is_empty() { None } else { Some(hd_passphrase_input.as_str()) };
    let mnemonic = read_password("HD wallet mnemonic (24 words): ");

    let hd_path = std::path::Path::new(hd_wallet_path);
    let mut wallet = match load_hd_wallet(hd_path, &mnemonic, hd_passphrase, &hd_password, allow_large_hd_wallet) {
        Ok(w) => w,
        Err(e) => { eprintln!("Failed to load HD wallet: {}", e); process::exit(1); }
    };

    let addr = founder_kp.address.clone();
    if let Err(e) = wallet.try_import_keypair(founder_kp, "founder") {
        eprintln!("Import failed: {}", e);
        process::exit(1);
    }

    if let Err(e) = wallet.save(hd_path) {
        eprintln!("Save failed: {}", e);
        process::exit(1);
    }

    println!();
    println!("Imported: {}", addr);
    println!("Label:    founder");
}

// ── Original wallet function ────────────────────────────────────────────────

fn network_of(testnet: bool) -> gnb::address::Network {
    if testnet { gnb::address::Network::Testnet } else { gnb::address::Network::Mainnet }
}

/// WAL-7: by default the key is derived from a new 24-word recovery phrase
/// (shown once), so the encrypted file is not its only backup; the network
/// is the explicit `--testnet` choice and keystore v3 authenticates it.
fn do_new_wallet(output_path: &str, testnet: bool, random_key: bool) {
    println!("Generating hybrid ML-DSA-65 + Falcon-1024 keypair...");
    warn_if_name_suggests_other_network(output_path, testnet);

    let keypair = if random_key {
        gnb::wallet::generate_keypair(testnet)
    } else {
        let (keypair, phrase) = gnb::wallet::generate_mnemonic_keypair(network_of(testnet))
            .unwrap_or_else(|e| die(&format!("key generation failed: {e}")));
        println!();
        println!("RECOVERY PHRASE (24 words). Write them down offline; anyone with them controls the funds:");
        println!();
        for (row, chunk) in phrase.words().chunks(4).enumerate() {
            let line: Vec<String> = chunk.iter().enumerate()
                .map(|(j, w)| format!("{:2}. {:<10}", row * 4 + j + 1, w)).collect();
            println!("  {}", line.join(" "));
        }
        println!();
        if !gnb::wallet::send::confirm("I have written the 24 words down") {
            die("aborted: no wallet file was written");
        }
        keypair
    };

    let password = read_new_password();
    let path = std::path::Path::new(output_path);

    match keypair.save_encrypted(path, &password) {
        Ok(_) => {
            println!("Wallet saved: {}", output_path);
            println!("Address:      {}", keypair.address);
            println!("Network:      {}", if testnet { "testnet" } else { "mainnet" });
            println!();
            if random_key {
                println!("BACKUP THIS FILE. If lost, your GNB is gone forever.");
            } else {
                println!("The recovery phrase restores this key: gnb-cli restorewallet <path>.");
            }
        }
        Err(e) => {
            eprintln!("Failed to save wallet: {}", e);
            process::exit(1);
        }
    }
}

fn do_restore_wallet(output_path: &str, testnet: bool) {
    let phrase = read_password("Recovery phrase (24 words): ");
    let keypair = gnb::wallet::keypair_from_mnemonic(&phrase, network_of(testnet))
        .unwrap_or_else(|e| die(&format!("restore failed: {e}")));
    drop(phrase);
    println!("Address: {}", keypair.address);
    let password = read_new_password();
    match keypair.save_encrypted(std::path::Path::new(output_path), &password) {
        Ok(_) => println!("Wallet saved: {}", output_path),
        Err(e) => die(&format!("failed to save wallet: {e}")),
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// CRY-4: passwords and mnemonics are read into wiping storage.
fn read_password(prompt: &str) -> zeroize::Zeroizing<String> {
    eprint!("{}", prompt);
    zeroize::Zeroizing::new(rpassword::read_password().unwrap_or_else(|e| {
        eprintln!("Failed to read password: {}", e);
        process::exit(1);
    }))
}

fn bloch_to_sats(s: &str) -> u64 {
    checked_payment_sats(s).unwrap_or_else(|message| die(message))
}

fn checked_payment_sats(value: &str) -> Result<u64, &'static str> {
    let satoshis = gnb::wallet::parse_bloch_satoshis(value)?;
    if satoshis == 0 { return Err("payment must contain at least one satoshi"); }
    Ok(satoshis)
}

fn checked_destination(destination: &str, source: &str) -> Result<String, &'static str> {
    let destination = gnb::address::Address::parse(destination).map_err(|_| "invalid destination address")?;
    let source = gnb::address::Address::parse(source).map_err(|_| "invalid wallet address")?;
    if destination.network() != source.network() { return Err("destination address network differs from wallet"); }
    Ok(hex::encode(destination.hash()))
}

/// Test view of the production UTXO-row parser `send` uses
/// (`gnb::wallet::send::parse_utxo_rows`: number or decimal-string values,
/// malformed rows refused, never filtered).
#[cfg(test)]
fn parse_send_utxos(rows: &[serde_json::Value]) -> Result<Vec<(Vec<u8>, u32, gnb::core::TxOutput)>, String> {
    Ok(gnb::wallet::send::parse_utxo_rows(&serde_json::json!({ "utxos": rows }))?
        .into_iter().map(|u| (u.txid.to_vec(), u.index, u.output)).collect())
}

fn require_params(params: &[&str], min: usize, usage: &str) {
    if params.len() < min {
        eprintln!("Usage: gnb-cli {}", usage);
        process::exit(1);
    }
}

fn die(msg: &str) -> ! {
    eprintln!("Error: {}", msg);
    process::exit(1);
}

/// True when `path` holds a keystore v2/v3 JSON (a top-level `"version"` of 2
/// or 3), so a failure to unlock it is reported as is instead of falling back
/// to the v1 keyfile parser.
fn is_keystore_v2_or_v3(path: &std::path::Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else { return false };
    if meta.len() > gnb::util::DEFAULT_WALLET_FILE_LIMIT as u64 {
        return false;
    }
    std::fs::read(path).ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| v.get("version").and_then(serde_json::Value::as_u64))
        .is_some_and(|v| v == 2 || v == 3)
}

fn print_usage() {
    println!(r#"
  gnb-cli — Bloch-SIS Protocol RPC client

  NETWORK
    gnb-cli info                          Network info
    gnb-cli height                        Current block count
    gnb-cli mempool                       Mempool info and relay policy (getmempoolinfo)
    gnb-cli peers                         Peer info
    gnb-cli dag                           DAG info (tips, chain, scores)

  BLOCKS
    gnb-cli block <height> [verbose]      Get block by height
    gnb-cli getblock <hash> [verbose]     Get block by hash
    gnb-cli getblockhash <height>         Get block hash at height
    gnb-cli recent [count]                Recent blocks (default: 10)

  TRANSACTIONS
    gnb-cli tx <txid>                     Get transaction
    gnb-cli sendraw <hex>                 Broadcast raw transaction. Mempool policy
                                          (docs/MEMPOOL.md): it may spend outputs of
                                          unconfirmed txs (max 25 ancestors/descendants);
                                          full-RBF — a tx double-spending pooled ones
                                          REPLACES them iff it adds no new unconfirmed
                                          input, pays a higher fee rate than each, and
                                          an absolute fee >= all evicted fees + 1 sat/B
                                          of its own size, evicting <= 100 txs
    gnb-cli decode <hex>                  Decode raw TX (without broadcast)
    gnb-cli rawmempool [verbose]          List mempool transactions
    gnb-cli fee                           Estimate fee

  WALLET (simple)
    gnb-cli balance <address>             Get balance
    gnb-cli utxos <address>               List unspent outputs
    gnb-cli txlist <address> [count]      Transaction history
    gnb-cli validate <address>            Validate address format
    gnb-cli newwallet <path.json> [--random-key]
                                          New 1-key wallet from a 24-word recovery
                                          phrase (shown once); keystore v3
    gnb-cli restorewallet <path.json>     Restore a 1-key wallet from its phrase
    gnb-cli send <wallet.json> <to> <amount> [--fee auto|GNB] [--max-fee GNB]
                 [--yes] [--allow-unverified-inputs]
                                          Shows the actual fee and asks before
                                          broadcasting; verifies UTXO values

  HD WALLET (BIP39, multi-address)
    gnb-cli newseed <wallet-hd.json>      Generate 24-word mnemonic + wallet
    gnb-cli newaddress <wallet-hd.json> [label]    Add new address
    gnb-cli addresses <wallet-hd.json>    List all addresses
    gnb-cli importfounder <wallet-hd.json> <founder.json>    Import simple wallet

  eUTXO VM (node built with --features euvm)
    gnb-cli euvm_utxos [validator_hash] [limit] [offset]   List eUTXO contract UTXOs
    gnb-cli euvm_getutxo <txid> <index>   Inspect one UTXO (legacy or eUTXO, decoded)
    gnb-cli euvm_buildtx '<json>'         Build (and pre-validate) an eUTXO raw tx
                                            from a JSON build-request; broadcast the
                                            returned raw_tx with 'sendraw'

  PROOF-OF-IMPROVEMENT (PoI)
    gnb-cli treasury                      Treasury balance and stats
    gnb-cli claims                        List all PoI claims
    gnb-cli claim <claim_id>              Get claim details + vote tally
    gnb-cli submitclaim <commit> <cat:0-3> <desc> <addr> [ci_hex]    Submit improvement
    gnb-cli vote <claim_id> <voter_addr> <yes|no|abstain>            Vote on claim

  OPTIONS
    --rpc-host <host>                      RPC host (default: 127.0.0.1)
    --rpc-port <port>                      RPC port (default: 17210)
    --rpc-url <url>                        RPC endpoint URL instead of host/port:
                                           http://host:port or https://host[:port]
                                           (certificate and host name verified)
    --rpc-ca <file>                        PEM/DER trust anchor(s) for https (a
                                           private CA or self-signed certificate)
    --allow-large-hd-wallet                Trusted-backup recovery (up to 512 MiB)
    --testnet                              New wallets are testnet (newwallet,
                                           restorewallet, newseed); for send: the
                                           keystore must be a testnet key
    --mainnet                              For send: the keystore must be a mainnet
                                           key. A v2 keystore needs --mainnet or
                                           --testnet and is rewritten as v3 (CRY-7)
    GNB_RPC_API_KEY=<key>                  Sent over https to any host; over plain
                                           http only to loopback (or SSH tunnel)
    --help                                 This message
"#);
}

#[cfg(test)]
mod audit_send_inputs {
    use super::*;

    fn public_wallet_fixture(addresses: usize) -> gnb::hd_wallet::HdWalletFile {
        let crypto = gnb::wallet::KeystoreCrypto {
            cipher: "fixture".into(),
            ciphertext: String::new(),
            nonce: String::new(),
            kdf: "fixture".into(),
            kdf_params: gnb::wallet::KdfParams {
                memory_cost: 1,
                time_cost: 1,
                parallelism: 1,
                salt: String::new(),
                output_len: 32,
            },
        };
        gnb::hd_wallet::HdWalletFile {
            version: 3,
            format: "hd-wallet-v1".into(),
            network: "testnet".into(),
            mnemonic_crypto: crypto.clone(),
            addresses: (0..addresses).map(|index| gnb::hd_wallet::HdAddress {
                index: index as u32,
                address: format!("{}public-{index}", gnb::core::TESTNET_PREFIX),
                label: String::new(),
                keypair_crypto: crypto.clone(),
                derived: false,
            }).collect(),
            created_at: String::new(),
            description: String::new(),
        }
    }

    #[test]
    fn amounts_are_exact_and_refuse_sub_satoshi_or_exponent_notation() {
        for value in ["NaN", "inf", "-1", "1e30", "0.000000019", "0"] {
            assert!(checked_payment_sats(value).is_err());
        }
        assert_eq!(gnb::wallet::parse_bloch_satoshis("0"), Ok(0));
        assert_eq!(checked_payment_sats("1.25"), Ok(125_000_000));
        assert_eq!(checked_payment_sats("90071992.54740993"), Ok(9_007_199_254_740_993));
    }
    #[test]
    fn indices_and_networks_are_checked_before_information_is_discarded() {
        use gnb::address::{Address, Network};
        let main = Address::from_hash([1; 20], Network::Mainnet).to_string();
        let test = Address::from_hash([1; 20], Network::Testnet).to_string();
        assert!(checked_destination(&main, &test).is_err());
        assert!(checked_destination(&test, &main).is_err());
        assert_eq!(checked_destination(&main, &main).unwrap(), "01".repeat(20));
        let mut row = serde_json::json!({"txid": "ab".repeat(32), "index": u32::MAX,
            "value": "9007199254740993", "script_pubkey": "cd".repeat(20)});
        let parsed = parse_send_utxos(&[row.clone()]).unwrap();
        assert_eq!(parsed[0].1, u32::MAX);
        assert_eq!(parsed[0].2.value, 9_007_199_254_740_993);
        row["index"] = serde_json::json!(4294967296u64);
        assert!(parse_send_utxos(&[row]).is_err());
        assert!(parse_send_utxos(&[serde_json::json!({})]).is_err());
    }

    #[test]
    fn address_listing_is_bounded_unless_trusted_backup_override_is_explicit() {
        let path = std::env::temp_dir().join(format!(
            "gnb-cli-public-wallet-limit-{}.json",
            std::process::id()
        ));
        let fixture = public_wallet_fixture(
            gnb::hd_wallet::DEFAULT_HD_WALLET_LOAD_LIMITS.max_addresses + 1,
        );
        std::fs::write(&path, serde_json::to_vec(&fixture).unwrap()).unwrap();
        let path_str = path.to_str().unwrap();

        let rejected = read_public_hd_wallet(path_str, false).err().unwrap();
        assert!(rejected.contains("address count 1025 exceeds configured limit 1024"));
        assert!(rejected.contains("--allow-large-hd-wallet"));
        assert_eq!(read_public_hd_wallet(path_str, true).unwrap().addresses.len(), 1025);
        std::fs::remove_file(path).unwrap();
    }
}
