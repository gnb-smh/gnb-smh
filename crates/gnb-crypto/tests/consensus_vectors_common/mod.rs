//! Shared by the two runners of the data-driven consensus vectors
//! (`crates/gnb-crypto/tests/consensus_vectors.rs` and, through `#[path]`,
//! `node/tests/consensus_vectors.rs`): loading `reference/tx_vectors.json` /
//! `reference/block_vectors.json`, the wrapper block of a tx vector, the
//! context-free per-transaction checks a block applies, the pow-limit check,
//! and the mapping from the node's error strings to the vectors' error
//! classes (docs/testing/VECTORS.md).
#![allow(dead_code)]

use gnb_crypto::core::{block_rules, limits, Block, BlockHeader, ChainId, MerkleRoot, Transaction, TxInput, TxOutput};
use serde_json::Value;

pub fn reference_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .find(|p| p.join("reference").join(name).is_file())
        .expect("reference/ directory above the crate")
        .join("reference")
        .join(name)
}

fn load(name: &str) -> Value {
    let text = std::fs::read_to_string(reference_path(name)).expect("vector file");
    serde_json::from_str(&text).expect("vector JSON")
}

pub fn u64_of(v: &Value) -> u64 {
    match v {
        Value::String(s) => s.parse().expect("decimal u64"),
        Value::Number(n) => n.as_u64().expect("u64"),
        other => panic!("not a u64: {other}"),
    }
}

pub fn bytes_of(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string")).expect("hex")
}

pub fn h32(v: &Value) -> [u8; 32] {
    bytes_of(v).try_into().expect("32 bytes")
}

pub fn chain_of(network: &str) -> ChainId {
    match network {
        "mainnet" => ChainId::Mainnet,
        "testnet" => ChainId::Testnet,
        other => panic!("unknown network {other}"),
    }
}

#[derive(Clone, Debug)]
pub struct Prevout {
    pub txid: [u8; 32],
    pub vout: u32,
    pub amount: u64,
    pub script_pubkey: Vec<u8>,
    pub coinbase_height: Option<u64>,
    /// Output 0 of the evaluation block's own coinbase (never in the view).
    pub block_coinbase: bool,
}

impl Prevout {
    pub fn out(&self) -> TxOutput {
        TxOutput { value: self.amount, script_pubkey: self.script_pubkey.clone() }
    }
}

fn prevouts_of(v: &Value) -> Vec<Prevout> {
    v.as_array().expect("prevouts").iter().map(|p| {
        let source = p["source"].as_str().expect("source");
        assert!(source == "utxo" || source == "block-coinbase", "unknown prevout source {source}");
        let coinbase_height = if p["coinbase_height"].is_null() { None } else { Some(u64_of(&p["coinbase_height"])) };
        assert_eq!(p["is_coinbase"].as_bool().unwrap(), coinbase_height.is_some() || source == "block-coinbase");
        Prevout {
            txid: h32(&p["txid"]),
            vout: p["vout"].as_u64().unwrap() as u32,
            amount: u64_of(&p["amount"]),
            script_pubkey: bytes_of(&p["script_pubkey"]),
            coinbase_height,
            block_coinbase: source == "block-coinbase",
        }
    }).collect()
}

/// `(verdict == "valid", error_class)`.
fn expected_of(v: &Value) -> Option<String> {
    let verdict = v["verdict"].as_str().unwrap();
    let class = v["error_class"].as_str().map(str::to_string);
    match verdict {
        "valid" => {
            assert!(class.is_none());
            None
        }
        "invalid" => Some(class.expect("an invalid case names its error class")),
        other => panic!("unknown verdict {other}"),
    }
}

pub struct TxVector {
    pub id: String,
    pub network: String,
    pub activation: u64,
    pub height: u64,
    pub prevouts: Vec<Prevout>,
    pub bytes: Vec<u8>,
    /// `None`: valid.
    pub error: Option<String>,
    /// `"accept"` or `"reject"`.
    pub policy: String,
    pub policy_class: Option<String>,
    pub derived: Value,
}

pub struct TxVectors {
    pub constants: Value,
    pub cases: Vec<TxVector>,
}

pub fn load_tx_vectors() -> TxVectors {
    let d = load("tx_vectors.json");
    assert_eq!(d["format"], "gnb-consensus-tx-vectors/1");
    let cases = d["cases"].as_array().unwrap().iter().map(|c| TxVector {
        id: c["id"].as_str().unwrap().to_string(),
        network: c["network"].as_str().unwrap().to_string(),
        activation: u64_of(&c["activation_height"]),
        height: u64_of(&c["height"]),
        prevouts: prevouts_of(&c["prevouts"]),
        bytes: bytes_of(&c["tx"]),
        error: expected_of(&c["expected"]),
        policy: c["policy"]["verdict"].as_str().unwrap().to_string(),
        policy_class: c["policy"]["error_class"].as_str().map(str::to_string),
        derived: c["derived"].clone(),
    }).collect::<Vec<_>>();
    for c in &cases {
        let regime = if c.height >= c.activation { "post-activation" } else { "pre-activation" };
        let raw = d["cases"].as_array().unwrap().iter().find(|x| x["id"] == c.id.as_str()).unwrap();
        assert_eq!(raw["regime"], regime, "{}: regime label", c.id);
        assert!(c.error.is_none() || c.policy == "reject", "{}: an invalid case is never admitted", c.id);
    }
    TxVectors { constants: d["constants"].clone(), cases }
}

pub struct BlockVector {
    pub id: String,
    pub activation: u64,
    pub height: u64,
    pub scope: String,
    pub pow: String,
    pub prevouts: Vec<Prevout>,
    pub bytes: Vec<u8>,
    pub error: Option<String>,
    pub derived: Value,
}

pub fn load_block_vectors() -> Vec<BlockVector> {
    let d = load("block_vectors.json");
    assert_eq!(d["format"], "gnb-consensus-block-vectors/1");
    d["cases"].as_array().unwrap().iter().map(|c| {
        let bytes = if c["block"].is_string() {
            bytes_of(&c["block"])
        } else {
            let mut out = Vec::new();
            for part in c["block_parts"].as_array().expect("block or block_parts") {
                let unit = bytes_of(&part["hex"]);
                for _ in 0..part["repeat"].as_u64().unwrap() {
                    out.extend_from_slice(&unit);
                }
            }
            out
        };
        assert_eq!(c["network"], "mainnet");
        BlockVector {
            id: c["id"].as_str().unwrap().to_string(),
            activation: u64_of(&c["activation_height"]),
            height: u64_of(&c["height"]),
            scope: c["scope"].as_str().unwrap().to_string(),
            pow: c["pow"].as_str().unwrap().to_string(),
            prevouts: prevouts_of(&c["prevouts"]),
            bytes,
            error: expected_of(&c["expected"]),
            derived: c["derived"].clone(),
        }
    }).collect()
}

// ── The wrapper block of a tx vector ────────────────────────────────────────

pub const WRAPPER_COINBASE_SCRIPT_SIG: &[u8] = b"gnb-tx-vectors/coinbase";

/// The coinbase in front of the transaction: it pays the `block-coinbase`
/// prevout (whose txid must then be this coinbase's), or 0 to 20 zero bytes.
pub fn wrapper_coinbase(prevouts: &[Prevout]) -> Transaction {
    let out = match prevouts.iter().find(|p| p.block_coinbase) {
        Some(p) => {
            assert_eq!(p.vout, 0, "a block-coinbase prevout is output 0");
            p.out()
        }
        None => TxOutput { value: 0, script_pubkey: vec![0; 20] },
    };
    let cb = Transaction {
        version: 1,
        inputs: vec![TxInput { prev_txid: [0; 32], prev_index: u32::MAX, script_sig: WRAPPER_COINBASE_SCRIPT_SIG.to_vec(), sequence: u32::MAX }],
        outputs: vec![out],
        locktime: 0,
    };
    if let Some(p) = prevouts.iter().find(|p| p.block_coinbase) {
        assert_eq!(cb.txid(), p.txid, "block-coinbase prevout txid is the wrapper coinbase's");
    }
    cb
}

/// `[wrapper coinbase, tx]` at header height `height`. The header fields are
/// not read by any per-transaction or connect-time rule.
pub fn wrapper_block(tx: &Transaction, height: u64, prevouts: &[Prevout]) -> Block {
    Block {
        header: BlockHeader { version: 1, parents: vec![[0x11; 32]], merkle_root: MerkleRoot::ZERO, timestamp: 0, bits: 0, nonce: 0 },
        transactions: vec![wrapper_coinbase(prevouts), tx.clone()],
        blue_score: height,
        height,
        shielded_transactions: vec![],
    }
}

/// The context-free rules a block applies to each of its non-coinbase
/// transactions, in the node's order (`Block::validate_structure_without_pow_at`:
/// coinbase format, the 64-byte rule at/after the activation, dust; then
/// `accept_block`'s `limits::check_block_context_free`: encoding caps and
/// MoneyRange). The block-level rules of the wrapper (Merkle root,
/// commitment, size) are block_vectors.json's.
pub fn tx_context_free(block: &Block, activation: u64) -> Result<(), String> {
    if !block.validate_coinbase_format() {
        return Err("invalid coinbase format".into());
    }
    if block_rules::rules_active_at(block.height, activation) {
        for tx in &block.transactions[1..] {
            block_rules::check_tx_not_64_bytes(tx).map_err(str::to_string)?;
        }
    }
    block.validate_dust().map_err(str::to_string)?;
    limits::check_block_context_free(block)
}

/// Strict decode: `Transaction::from_wire_bytes` and the canonical
/// re-encoding must give back the same bytes.
pub fn decode_tx(bytes: &[u8]) -> Option<Transaction> {
    Transaction::from_wire_bytes(bytes).ok().filter(|t| t.to_wire_bytes(true) == bytes)
}

/// The pow-limit rule (`pow: limit` / `full`): bits must decode and the
/// target must be within the pow limit of the block's height.
pub fn pow_limit(block: &Block, activation: u64) -> Result<(), &'static str> {
    let target = gnb_smh::difficulty::try_bits_to_target(block.header.bits).map_err(|_| "bad-bits")?;
    if !Block::target_within_pow_limit_at(&target.0, block.height, activation) {
        return Err("pow-limit");
    }
    Ok(())
}

/// Error classes produced by the context-free stages (anything else is a
/// connect-time class).
pub const CONTEXT_FREE_CLASSES: &[&str] = &[
    "decode", "too-many-parents", "block-size", "bad-merkle-root", "coinbase-format", "tx-64-bytes",
    "cb-commitment-missing", "cb-commitment-tag", "cb-height", "cb-parents", "witness-commitment",
    "duplicate-tx", "dust", "pow-limit", "bad-bits", "bad-pow", "canonical-limit",
];

/// Input-script classes (`core::sighash::verify_tx_scripts`).
pub const SCRIPT_CLASSES: &[&str] = &["bad-version", "witness-malformed", "witness-non-canonical", "pubkey-mismatch", "bad-signature"];

/// Map a consensus error string of the node to its vector class. Panics on
/// an unknown string, so a new rejection reason must be classified here.
pub fn classify(reason: &str) -> &'static str {
    let has = |s: &str| reason.contains(s);
    if has("spends the coinbase of its own block") {
        "same-block-coinbase"
    } else if has("coinbase maturity") {
        "immature-coinbase"
    } else if has("bad-txns-version") {
        "bad-version"
    } else if has("BIP30") {
        "bip30"
    } else if has("double-spend") {
        "double-spend"
    } else if has("UTXO") && has("not found") {
        "missing-input"
    } else if has("malformed script_sig") {
        "witness-malformed"
    } else if has("non-canonical") {
        "witness-non-canonical"
    } else if has("pubkey mismatch") {
        "pubkey-mismatch"
    } else if has("invalid signature") {
        "bad-signature"
    } else if has("below consensus minimum") {
        "min-fee"
    } else if has("inputs ") && has(" < outputs ") {
        "inputs-below-outputs"
    } else if has("coinbase must have 1 output") {
        "coinbase-output-count"
    } else if has("miner coinbase output exceeds allowed amount") || has("coinbase reward computation overflowed") {
        "coinbase-value"
    } else if has("MAX_SUPPLY_SAT") || has("overflows u64") {
        "value-out-of-range"
    } else if has("64-byte transaction") {
        "tx-64-bytes"
    } else if has("below dust threshold") {
        "dust"
    } else if has("invalid coinbase format") {
        "coinbase-format"
    } else if has("duplicate transaction in block") {
        "duplicate-tx"
    } else if has("invalid merkle root") {
        "bad-merkle-root"
    } else if has("block too large") {
        "block-size"
    } else if has("too many parents") {
        "too-many-parents"
    } else if has("coinbase commitment missing") {
        "cb-commitment-missing"
    } else if has("bad coinbase commitment tag") {
        "cb-commitment-tag"
    } else if has("bad-cb-height") {
        "cb-height"
    } else if has("bad coinbase parents commitment") {
        "cb-parents"
    } else if has("bad witness commitment") {
        "witness-commitment"
    } else if has("exceed the") && has("cap") {
        "canonical-limit"
    } else {
        panic!("unclassified consensus error: {reason}")
    }
}

/// Collects mismatches and reports them all at once.
#[derive(Default)]
pub struct Report {
    pub failures: Vec<String>,
    pub checked: usize,
}

impl Report {
    pub fn expect(&mut self, id: &str, what: &str, want: &str, got: &str) {
        self.checked += 1;
        if want != got {
            self.failures.push(format!("{id}: {what}: expected {want}, got {got}"));
        }
    }

    pub fn finish(self, label: &str) {
        eprintln!("{label}: {} checks, {} failures", self.checked, self.failures.len());
        assert!(self.failures.is_empty(), "{label}: {} mismatches:\n{}", self.failures.len(), self.failures.join("\n"));
    }
}

/// `"valid"` or the class, for comparisons.
pub fn verdict(r: &Result<(), String>) -> String {
    match r {
        Ok(()) => "valid".into(),
        Err(c) => c.clone(),
    }
}

pub fn want(e: &Option<String>) -> String {
    e.clone().unwrap_or_else(|| "valid".into())
}
