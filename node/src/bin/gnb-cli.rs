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
    let mut allow_large_hd_wallet = false;
    let mut cmd_args: Vec<&str> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--rpc-host" => { i += 1; if i < args.len() { rpc_host = args[i].clone(); } }
            "--rpc-port" => { i += 1; if i < args.len() { rpc_port = args[i].parse().unwrap_or(17210); } }
            "--allow-large-hd-wallet" => { allow_large_hd_wallet = true; }
            _ => { cmd_args.push(&args[i]); }
        }
        i += 1;
    }

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
            require_params(params, 3, "send <wallet.json> <to_address> <amount_gnb> [--fee 0.0005]");
            do_send(params, &rpc_host, rpc_port);
            return;
        }

        // ── Multisig / timelock policies (core::policy) ────────────
        "pubkey" => {
            require_params(params, 1, "pubkey <wallet.json>");
            let kp = load_keypair(params[0]);
            println!("{}", hex::encode(&kp.public_key));
            return;
        }
        "policyaddress" => {
            require_params(params, 2, POLICY_ADDRESS_USAGE);
            do_policy_address(params);
            return;
        }
        "policyspend" => {
            require_params(params, 3, POLICY_SPEND_USAGE);
            do_policy_spend(params);
            return;
        }
        "policysign" => {
            require_params(params, 2, "policysign <spend.json> <wallet.json>");
            do_policy_sign(params);
            return;
        }
        "policysend" => {
            require_params(params, 1, "policysend <spend.json>");
            do_policy_send(params, &rpc_host, rpc_port);
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
            require_params(params, 1, "newwallet <output_path.json>");
            do_new_wallet(params[0]);
            return;
        }

        // ── Phase 3: HD Wallet commands ────────────────────────────
        "newseed" => {
            require_params(params, 1, "newseed <output_path.json>");
            do_newseed(params[0]);
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
    match rpc_call(&rpc_host, rpc_port, rpc_method, &rpc_params) {
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

fn rpc_call(host: &str, port: u16, method: &str, params: &serde_json::Value) -> Result<serde_json::Value, String> {
    let authority = if host.contains(':') && !host.starts_with('[') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
    let api_key = std::env::var("GNB_RPC_API_KEY").ok();
    gnb::wallet::http_rpc::call(&authority, method, params, api_key.as_deref())
}

// ── Send command ────────────────────────────────────────────────────────────

/// Mempool admission limit (node/src/mempool MAX_TX_SIZE).
const MAX_TX_BYTES: usize = 400 * 1024;

fn do_send(params: &[&str], rpc_host: &str, rpc_port: u16) {
    let wallet_path = params[0];
    let to_address = params[1];
    let amount_str = params[2];

    // Fee in GNB. Default 0.0005 GNB (50,000 base units) clears the
    // consensus minimum (max(0.0001 GNB, 0.00002 GNB/kB)) for transactions up
    // to ~25 kB. The sighash chain id follows the wallet's address prefix.
    let mut fee_bloch = "0.0005";
    let mut i = 3;
    while i < params.len() {
        if params[i] == "--fee" && i + 1 < params.len() {
            fee_bloch = params[i + 1];
            i += 2;
        } else {
            i += 1;
        }
    }

    let amount_sats = bloch_to_sats(amount_str);
    let fee_sats = gnb::wallet::parse_bloch_satoshis(fee_bloch).unwrap_or_else(|message| die(message));
    amount_sats.checked_add(fee_sats).unwrap_or_else(|| die("amount plus fee exceeds u64"));

    // Load wallet
    let password = read_password("Wallet password: ");
    let path = std::path::Path::new(wallet_path);
    // Bloch/GnB keystore v2 first (address field; bloch1q… accepted), then
    // the v1 keyfile format (address derived from the public key).
    let keypair = match gnb::wallet::Keypair::load_encrypted(path, &password) {
        Ok(kp) => kp,
        Err(e2) => match gnb::wallet::Wallet::load_encrypted(path, &password) {
            Ok(w) => w.into_keypair(),
            Err(e1) => {
                eprintln!("Failed to load wallet: {} (keystore v2) / {} (keyfile v1)", e2, e1);
                process::exit(1);
            }
        },
    };

    println!("From: {}", keypair.address);
    println!("To:   {}", to_address);
    println!("Amount: {} GNB", amount_str);
    println!("Fee:    {} GNB", fee_bloch);

    // Get UTXOs via RPC
    // Pass a UTXO limit: a huge wallet (e.g. the carry-over founder set with
    // hundreds of thousands of UTXOs) otherwise returns a multi-MB response that
    // times out the client. A handful of UTXOs is plenty to cover any single spend.
    let utxos_result = match rpc_call(rpc_host, rpc_port, "getutxos", &serde_json::json!([keypair.address, 50])) {
        Ok(r) => r,
        Err(e) => { eprintln!("RPC error: {}", e); process::exit(1); }
    };

    let utxos_json = utxos_result.get("utxos").and_then(|u| u.as_array()).cloned().unwrap_or_default();
    if utxos_json.is_empty() {
        eprintln!("No UTXOs found for {}", keypair.address);
        process::exit(1);
    }

    // Refuse malformed rows before they lose width or network information.
    let available_utxos = parse_send_utxos(&utxos_json).unwrap_or_else(|message| die(message));
    let total_available = available_utxos.iter().try_fold(0u64, |total, (_, _, output)| total.checked_add(output.value))
        .unwrap_or_else(|| die("UTXO value total exceeds u64"));
    println!("Available: {} GNB ({} UTXOs)", total_available as f64 / 1e8, available_utxos.len());
    let to_addr_hex = checked_destination(to_address, &keypair.address).unwrap_or_else(|message| die(message));

    // Build and sign TX
    // Every input carries a ~8.5 kB hybrid signature + public key, so the
    // consensus minimum fee depends on how many inputs coin selection picks.
    // Build, measure, and rebuild with max(requested, minimum) until stable.
    // Falcon signatures vary in length between builds, so the fee only ever
    // rises (to the largest minimum seen) and this always settles.
    let mut fee_sats = fee_sats;
    let mut tx = None;
    for _ in 0..16 {
        let built = match gnb::wallet::TxBuilder::build(
            &keypair, &available_utxos, &to_addr_hex, amount_sats, fee_sats,
        ) {
            Ok(tx) => tx,
            Err(e) => { eprintln!("TX build failed: {}", e); process::exit(1); }
        };
        let size = built.to_wire_bytes(true).len();
        let min = gnb::core::tokenomics::min_tx_fee_sat(size);
        if fee_sats >= min {
            tx = Some(built);
            break;
        }
        fee_sats = fee_sats.max(min);
        println!("Fee raised to the consensus minimum for {} bytes: {} GNB", size, fee_sats as f64 / 1e8);
    }
    let tx = tx.unwrap_or_else(|| die("could not settle the fee for this transaction"));
    let size = tx.to_wire_bytes(true).len();
    if size > MAX_TX_BYTES {
        die(&format!(
            "transaction is {} bytes with {} inputs; the mempool limit is {} bytes. \
             Send a smaller amount (each input carries ~8.5 kB) and repeat.",
            size, tx.inputs.len(), MAX_TX_BYTES));
    }
    println!("Inputs: {} · Size: {} bytes · Fee: {} GNB", tx.inputs.len(), size, fee_sats as f64 / 1e8);

    let txid = hex::encode(tx.txid());
    println!("TXID: {}", txid);

    // Serialize and broadcast
    // Sprint 1.d: Bitcoin-format wire (replaces bincode). Infallible.
    let raw = tx.to_wire_bytes(true);
    let raw_hex = hex::encode(&raw);

    match rpc_call(rpc_host, rpc_port, "sendrawtransaction", &serde_json::json!([raw_hex])) {
        Ok(result) => {
            if let Some(err) = result.get("error").and_then(|e| e.as_str()) {
                eprintln!("Broadcast rejected: {}", err);
                process::exit(1);
            }
            println!("Broadcast OK");
        }
        Err(e) => { eprintln!("Broadcast failed: {}", e); process::exit(1); }
    }
}

// ── New wallet command ──────────────────────────────────────────────────────

// ── Phase 3: HD Wallet functions ────────────────────────────────────────────

fn do_newseed(output_path: &str) {
    println!("Generating HD wallet with 24-word mnemonic...");
    println!();

    let password = loop {
        let p1 = read_password("Set password (min 12 chars, 3 of: upper/lower/digit/special): ");
        if let Err(e) = gnb::wallet::validate_password(&p1) {
            eprintln!("Weak password: {}", e);
            continue;
        }
        let p2 = read_password("Confirm password: ");
        if p1 != p2 {
            eprintln!("Passwords don't match.");
            continue;
        }
        break p1;
    };

    let use_passphrase = read_password("Optional passphrase (press Enter to skip): ");
    let passphrase = if use_passphrase.is_empty() { None } else { Some(use_passphrase.as_str()) };

    let testnet = output_path.contains("testnet");
    let wallet = match gnb::hd_wallet::HdWallet::create(&password, passphrase, testnet) {
        Ok(w) => w,
        Err(e) => { eprintln!("Failed to create wallet: {}", e); process::exit(1); }
    };

    let mnemonic_str = wallet.mnemonic.to_string();
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

fn do_new_wallet(output_path: &str) {
    println!("Generating ML-DSA-65 keypair...");

    let password = loop {
        let p1 = read_password("Set password (min 12 chars, 3 of: upper/lower/digit/special): ");
        if let Err(e) = gnb::wallet::validate_password(&p1) {
            eprintln!("Weak password: {}", e);
            continue;
        }
        let p2 = read_password("Confirm password: ");
        if p1 != p2 {
            eprintln!("Passwords don't match.");
            continue;
        }
        break p1;
    };

    let testnet = output_path.contains("testnet");
    let keypair = gnb::wallet::generate_keypair(testnet);
    let path = std::path::Path::new(output_path);

    match keypair.save_encrypted(path, &password) {
        Ok(_) => {
            println!("Wallet saved: {}", output_path);
            println!("Address:      {}", keypair.address);
            println!("Network:      {}", if testnet { "testnet" } else { "mainnet" });
            println!();
            println!("BACKUP THIS FILE. If lost, your GNB is gone forever.");
        }
        Err(e) => {
            eprintln!("Failed to save wallet: {}", e);
            process::exit(1);
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn read_password(prompt: &str) -> String {
    eprint!("{}", prompt);
    rpassword::read_password().unwrap_or_else(|e| {
        eprintln!("Failed to read password: {}", e);
        process::exit(1);
    })
}

/// Read a satoshi-denominated response field that may be a JSON number (V3
/// nodes, and the live G3 fleet) or a decimal string (V4 rule R3,
/// docs/specs/BLOCH-RPC-V4.md — amounts exceed both `i64::MAX` and JS
/// `Number.MAX_SAFE_INTEGER`, so they travel as strings). Dual-tolerant so one
/// CLI binary talks to both wires.
fn sat_u64(v: &serde_json::Value) -> Option<u64> {
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    v.as_str().and_then(|s| s.trim().parse::<u64>().ok())
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
    // Single-key (gnb1q…/gnb1t…) or policy (gnb1m…/gnb1n…) destination.
    let (network, script) = gnb::address::destination_script(destination)
        .map_err(|_| "invalid destination address")?;
    let source = gnb::address::Address::parse(source).map_err(|_| "invalid wallet address")?;
    if network != source.network() { return Err("destination address network differs from wallet"); }
    Ok(hex::encode(script))
}

fn parse_send_utxos(rows: &[serde_json::Value]) -> Result<Vec<(Vec<u8>, u32, gnb::core::TxOutput)>, &'static str> {
    rows.iter().map(|row| {
        let txid = hex::decode(row["txid"].as_str().ok_or("UTXO missing transaction ID")?)
            .map_err(|_| "invalid UTXO transaction ID hex")?;
        if txid.len() != 32 { return Err("UTXO transaction ID must contain 32 bytes"); }
        let index = row["index"].as_u64().and_then(|value| u32::try_from(value).ok())
            .ok_or("UTXO index must fit u32")?;
        let value = sat_u64(&row["value"]).ok_or("invalid UTXO value")?;
        let script_pubkey = hex::decode(row["script_pubkey"].as_str().ok_or("UTXO missing script")?)
            .map_err(|_| "invalid UTXO script hex")?;
        Ok((txid, index, gnb::core::TxOutput { value, script_pubkey }))
    }).collect()
}

const POLICY_ADDRESS_USAGE: &str =
    "policyaddress <m> <pubkey-hex|file>... [--after HEIGHT] [--older BLOCKS] [--testnet]";
const POLICY_SPEND_USAGE: &str =
    "policyspend <policy-hex|file> <to_address> <amount_gnb> --utxo TXID:VOUT:SATS [--utxo ...] \
     [--fee 0.0005] [--locktime HEIGHT] --out spend.json";

fn load_keypair(path: &str) -> gnb::wallet::Keypair {
    let password = read_password("Wallet password: ");
    let p = std::path::Path::new(path);
    match gnb::wallet::Keypair::load_encrypted(p, &password) {
        Ok(kp) => kp,
        Err(e2) => match gnb::wallet::Wallet::load_encrypted(p, &password) {
            Ok(w) => w.into_keypair(),
            Err(e1) => die(&format!("Failed to load wallet: {} (keystore v2) / {} (keyfile v1)", e2, e1)),
        },
    }
}

/// A hex argument, or the trimmed contents of a file holding the hex.
fn hex_arg(arg: &str) -> Vec<u8> {
    let text = if std::path::Path::new(arg).is_file() {
        std::fs::read_to_string(arg).unwrap_or_else(|e| die(&format!("read {}: {}", arg, e)))
    } else {
        arg.to_string()
    };
    hex::decode(text.trim()).unwrap_or_else(|_| die(&format!("not hex (or a file of hex): {}", arg)))
}

fn flag_value<'a>(params: &[&'a str], flag: &str) -> Option<&'a str> {
    params.windows(2).find(|w| w[0] == flag).map(|w| w[1])
}

fn do_policy_address(params: &[&str]) {
    let m: u8 = params[0].parse().unwrap_or_else(|_| die("m must be a number"));
    let mut keys = Vec::new();
    let mut i = 1;
    while i < params.len() {
        match params[i] {
            "--after" | "--older" => i += 2,
            "--testnet" => i += 1,
            k => { keys.push(hex_arg(k)); i += 1; }
        }
    }
    let after: u32 = flag_value(params, "--after").map(|v| v.parse().unwrap_or_else(|_| die("--after: height"))).unwrap_or(0);
    let older: u32 = flag_value(params, "--older").map(|v| v.parse().unwrap_or_else(|_| die("--older: blocks"))).unwrap_or(0);
    let network = if params.contains(&"--testnet") { gnb::address::Network::Testnet } else { gnb::address::Network::Mainnet };
    let policy = gnb::core::policy::SpendPolicy::new(m, keys, after, older)
        .unwrap_or_else(|e| die(&format!("invalid policy: {}", e)));
    println!("address: {}", gnb::address::PolicyAddress::from_policy(&policy, network));
    println!("policy:  {}", hex::encode(policy.encode()));
    println!("{}-of-{}{}{}", policy.threshold, policy.pubkeys.len(),
        if after > 0 { format!(", spendable from height {}", after) } else { String::new() },
        if older > 0 { format!(", each deposit spendable {} blocks after it confirms", older) } else { String::new() });
    println!("Keep the policy hex: it is needed to spend, and the address alone does not reveal it.");
}

fn do_policy_spend(params: &[&str]) {
    let policy = gnb::core::policy::SpendPolicy::decode(&hex_arg(params[0]))
        .unwrap_or_else(|e| die(&format!("invalid policy: {}", e)));
    let (network, to_script) = gnb::address::destination_script(params[1])
        .unwrap_or_else(|_| die("invalid destination address"));
    let amount = bloch_to_sats(params[2]);
    let fee = gnb::wallet::parse_bloch_satoshis(flag_value(params, "--fee").unwrap_or("0.0005"))
        .unwrap_or_else(|m| die(m));
    let locktime: u32 = flag_value(params, "--locktime")
        .map(|v| v.parse().unwrap_or_else(|_| die("--locktime: height"))).unwrap_or(policy.after);
    let out = flag_value(params, "--out").unwrap_or_else(|| die("--out spend.json is required"));
    let inputs: Vec<([u8; 32], u32, u64)> = params.windows(2).filter(|w| w[0] == "--utxo").map(|w| {
        let parts: Vec<&str> = w[1].split(':').collect();
        if parts.len() != 3 { die("--utxo must be TXID:VOUT:SATS"); }
        let txid: [u8; 32] = hex::decode(parts[0]).ok().and_then(|v| v.try_into().ok())
            .unwrap_or_else(|| die("--utxo: TXID must be 32-byte hex"));
        (txid,
         parts[1].parse().unwrap_or_else(|_| die("--utxo: VOUT")),
         parts[2].parse().unwrap_or_else(|_| die("--utxo: SATS")))
    }).collect();
    let spend = gnb::wallet::policy_spend::PolicySpend::new(network, policy, &inputs, to_script, amount, fee, locktime)
        .unwrap_or_else(|e| die(&e));
    std::fs::write(out, spend.to_json().unwrap_or_else(|e| die(&e)))
        .unwrap_or_else(|e| die(&format!("write {}: {}", out, e)));
    let input_total: u64 = inputs.iter().map(|i| i.2).sum();
    println!("Unsigned spend written to {}", out);
    println!("Pays {} GNB to {}; fee {} GNB; needs {} signature(s)",
        amount as f64 / 1e8, params[1], (input_total - spend.outputs_total()) as f64 / 1e8, spend.policy.threshold);
}

fn print_spend_summary(spend: &gnb::wallet::policy_spend::PolicySpend) {
    println!("Network:  {:?}", spend.network);
    for (i, o) in spend.tx.outputs.iter().enumerate() {
        let kind = if o.script_pubkey == spend.policy.script_pubkey() { " (change, back to the policy)" } else { "" };
        println!("Output {}: {} GNB → script {}{}", i, o.value as f64 / 1e8, hex::encode(&o.script_pubkey), kind);
    }
    println!("Locktime: {}", spend.tx.locktime);
    println!("Signed by keys {:?} of {}-of-{}", spend.signers(), spend.policy.threshold, spend.policy.pubkeys.len());
}

fn do_policy_sign(params: &[&str]) {
    let text = std::fs::read_to_string(params[0]).unwrap_or_else(|e| die(&format!("read {}: {}", params[0], e)));
    let mut spend = gnb::wallet::policy_spend::PolicySpend::from_json(&text).unwrap_or_else(|e| die(&e));
    print_spend_summary(&spend);
    println!("Check the outputs above before signing.");
    let kp = load_keypair(params[1]);
    let idx = spend.sign(&kp.public_key, |m| kp.sign(m)).unwrap_or_else(|e| die(&e));
    std::fs::write(params[0], spend.to_json().unwrap_or_else(|e| die(&e)))
        .unwrap_or_else(|e| die(&format!("write {}: {}", params[0], e)));
    println!("Signed as key {}; {} of {} signatures present.", idx, spend.signers().len(), spend.policy.threshold);
}

fn do_policy_send(params: &[&str], rpc_host: &str, rpc_port: u16) {
    let text = std::fs::read_to_string(params[0]).unwrap_or_else(|e| die(&format!("read {}: {}", params[0], e)));
    let spend = gnb::wallet::policy_spend::PolicySpend::from_json(&text).unwrap_or_else(|e| die(&e));
    print_spend_summary(&spend);
    let tx = spend.finalize().unwrap_or_else(|e| die(&e));
    let raw = hex::encode(tx.to_wire_bytes(true));
    println!("TXID: {}", hex::encode(tx.txid()));
    match rpc_call(rpc_host, rpc_port, "sendrawtransaction", &serde_json::json!([raw])) {
        Ok(result) => {
            if let Some(err) = result.get("error").and_then(|e| e.as_str()) {
                die(&format!("Broadcast rejected: {}", err));
            }
            println!("Broadcast OK");
        }
        Err(e) => die(&format!("Broadcast failed: {}", e)),
    }
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

fn print_usage() {
    println!(r#"
  gnb-cli — Bloch-SIS Protocol RPC client

  NETWORK
    gnb-cli info                          Network info
    gnb-cli height                        Current block count
    gnb-cli mempool                       Mempool info
    gnb-cli peers                         Peer info
    gnb-cli dag                           DAG info (tips, chain, scores)

  BLOCKS
    gnb-cli block <height> [verbose]      Get block by height
    gnb-cli getblock <hash> [verbose]     Get block by hash
    gnb-cli getblockhash <height>         Get block hash at height
    gnb-cli recent [count]                Recent blocks (default: 10)

  TRANSACTIONS
    gnb-cli tx <txid>                     Get transaction
    gnb-cli sendraw <hex>                 Broadcast raw transaction
    gnb-cli decode <hex>                  Decode raw TX (without broadcast)
    gnb-cli rawmempool [verbose]          List mempool transactions
    gnb-cli fee                           Estimate fee

  WALLET (simple)
    gnb-cli balance <address>             Get balance
    gnb-cli utxos <address>               List unspent outputs
    gnb-cli txlist <address> [count]      Transaction history
    gnb-cli validate <address>            Validate address format
    gnb-cli newwallet <path.json>         Generate simple wallet (1 keypair)
    gnb-cli send <wallet.json> <to> <amount> [--fee 0.0005]
                                          <to> may be a policy address (gnb1m…)

  MULTISIG / TIMELOCK (policy addresses gnb1m… / gnb1n…)
    gnb-cli pubkey <wallet.json>          Print the wallet's public key (hex)
    gnb-cli policyaddress <m> <pubkey>... [--after H] [--older N] [--testnet]
                                          m-of-n address; spendable from height H
                                          and/or N blocks after each deposit
    gnb-cli policyspend <policy> <to> <amount> --utxo TXID:VOUT:SATS ...
                        [--fee 0.0005] [--locktime H] --out spend.json
                                          Unsigned spend; change returns to the policy
    gnb-cli policysign <spend.json> <wallet.json>
                                          Add this wallet's signature (run by each signer)
    gnb-cli policysend <spend.json>       Combine m signatures and broadcast

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
    --allow-large-hd-wallet                Trusted-backup recovery (up to 512 MiB)
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
