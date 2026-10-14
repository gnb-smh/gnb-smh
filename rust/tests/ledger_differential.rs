//! Randomized Rust-vs-Python differential for the ledger (audit LED-1).
//!
//! `reference/ledger_oracle.py gen` builds random valid blocks with the Python
//! `FullNode` (spends, missing inputs, wrong authorization, overspends, taken
//! output keys, duplicate transactions, immature coinbases, merged twins whose
//! coinbase is forfeited). This test mutates every case at random (witness bytes,
//! transaction bytes, transaction order, height, subsidy, maturity, parents root,
//! the merged flag), sends all cases to `ledger_oracle.py eval`, and requires the
//! Rust port to reach exactly the Python verdict: the same post-state and accepted
//! flags, or the same error code and fault class.
//!
//! Seeds: a fixed set, plus `GNB_LEDGER_DIFF_SEED` if set, else one derived from
//! the clock (printed, so a failure can be replayed). Needs `python3` (>= 3.10).

use std::io::Write;
use std::process::{Command, Stdio};

use gnb_smh::ledger::{self, Context, Hash, State};
use serde_json::{json, Value};

const BASE_CASES: usize = 30;
const MUTATIONS_PER_CASE: usize = 12;

fn reference_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../reference")
}

fn python(args: &[&str], stdin: Option<&[u8]>) -> Value {
    let mut child = Command::new("python3")
        .arg("ledger_oracle.py")
        .args(args)
        .current_dir(reference_dir())
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("the ledger differential needs python3 on PATH (reference/ledger_oracle.py)");
    if let Some(input) = stdin {
        child.stdin.take().unwrap().write_all(input).unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "ledger_oracle.py {args:?} failed");
    serde_json::from_slice(&out.stdout).expect("oracle output is JSON")
}

fn h32(v: &Value) -> Hash {
    hex::decode(v.as_str().unwrap()).unwrap().try_into().unwrap()
}

fn state_json(s: &State) -> Value {
    json!({"utxo_root": hex::encode(s.utxo_root), "nullifier_root": hex::encode(s.nullifier_root)})
}

/// The Rust verdict, in the oracle's format.
fn rust_verdict(c: &Value) -> Value {
    let pre = State { utxo_root: h32(&c["pre"]["utxo_root"]), nullifier_root: h32(&c["pre"]["nullifier_root"]) };
    let ctx = Context {
        height: c["height"].as_u64().unwrap(),
        subsidy: c["subsidy"].as_u64().unwrap(),
        coinbase_maturity: c["coinbase_maturity"].as_u64().unwrap(),
        auth: ledger::test_preimage_auth,
        parents_root: h32(&c["parents_root"]),
    };
    let witness = hex::decode(c["witness_hex"].as_str().unwrap()).unwrap();
    let result = c["txs_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| ledger::decode_tx_wire(&hex::decode(t.as_str().unwrap()).unwrap()))
        .collect::<Result<Vec<_>, _>>()
        .and_then(|txs| {
            if c["merged"].as_bool().unwrap() {
                ledger::apply_merged_block_txs(&pre, &txs, &witness, &ctx)
            } else {
                ledger::apply_block_txs(&pre, &txs, &witness, &ctx)
            }
        });
    match result {
        Ok((post, accepted)) => json!({"ok": true, "post": state_json(&post), "accepted": accepted}),
        Err(e) => json!({"ok": false, "code": e.code.as_str(), "permanent": e.code.is_permanent()}),
    }
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        // splitmix64
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn hex_bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

/// One or two random mutations of a valid case.
fn mutate(rng: &mut Rng, base: &Value) -> Value {
    let mut c = base.clone();
    c.as_object_mut().unwrap().remove("verdict");
    for _ in 0..1 + rng.below(2) {
        let n_tx = c["txs_hex"].as_array().unwrap().len();
        match rng.below(12) {
            0 | 1 => {
                let mut w = hex_bytes(&c["witness_hex"]);
                if !w.is_empty() {
                    let i = rng.below(w.len());
                    w[i] ^= 1 << rng.below(8);
                }
                c["witness_hex"] = json!(hex::encode(w));
            }
            2 => {
                let w = hex_bytes(&c["witness_hex"]);
                let cut = rng.below(w.len() + 1);
                c["witness_hex"] = json!(hex::encode(&w[..cut]));
            }
            3 => {
                let mut w = hex_bytes(&c["witness_hex"]);
                for _ in 0..1 + rng.below(40) {
                    w.push(rng.next() as u8);
                }
                c["witness_hex"] = json!(hex::encode(w));
            }
            4 => {
                let i = rng.below(n_tx);
                let mut t = hex_bytes(&c["txs_hex"][i]);
                let j = rng.below(t.len());
                t[j] ^= 1 << rng.below(8);
                c["txs_hex"][i] = json!(hex::encode(t));
            }
            5 if n_tx > 1 => {
                let i = 1 + rng.below(n_tx - 1);
                c["txs_hex"].as_array_mut().unwrap().remove(i);
            }
            6 => {
                let (i, j) = (rng.below(n_tx), rng.below(n_tx));
                c["txs_hex"].as_array_mut().unwrap().swap(i, j);
            }
            7 => {
                let h = c["height"].as_u64().unwrap();
                c["height"] = json!(if rng.below(2) == 0 { h + 1 } else { h.saturating_sub(1) });
            }
            8 => {
                let s = c["subsidy"].as_u64().unwrap();
                c["subsidy"] = json!(rng.next() % (2 * s + 2));
            }
            9 => {
                let m = c["merged"].as_bool().unwrap();
                c["merged"] = json!(!m);
            }
            10 => {
                let mut p = hex_bytes(&c["parents_root"]);
                p[rng.below(32)] ^= 0x80;
                c["parents_root"] = json!(hex::encode(p));
            }
            _ => {
                c["coinbase_maturity"] = json!(rng.next() % 10);
                if n_tx > 1 && rng.below(2) == 0 {
                    let dup = c["txs_hex"][1 + rng.below(n_tx - 1)].clone();
                    c["txs_hex"].as_array_mut().unwrap().push(dup);
                }
            }
        }
    }
    c
}

fn run_seed(seed: u64) -> (usize, usize) {
    let base = python(&["gen", &seed.to_string(), &BASE_CASES.to_string()], None);
    let base = base.as_array().unwrap();
    assert_eq!(base.len(), BASE_CASES);
    let mut rng = Rng(seed ^ 0x1ED6_E5D1_FF00_0001);
    let mut cases = Vec::new();
    for b in base {
        // The unmutated case must agree with the verdict `gen` recorded.
        assert_eq!(rust_verdict(b), b["verdict"], "seed {seed}: base case disagrees: {b}");
        for _ in 0..MUTATIONS_PER_CASE {
            cases.push(mutate(&mut rng, b));
        }
    }
    let input = serde_json::to_vec(&cases).unwrap();
    let verdicts = python(&["eval"], Some(&input));
    let verdicts = verdicts.as_array().unwrap();
    assert_eq!(verdicts.len(), cases.len());
    let mut rejected = 0;
    for (c, py) in cases.iter().zip(verdicts) {
        let rs = rust_verdict(c);
        assert_eq!(&rs, py, "seed {seed}: Rust and Python disagree on case {c}");
        rejected += usize::from(!py["ok"].as_bool().unwrap());
    }
    (cases.len(), rejected)
}

#[test]
fn rust_and_python_agree_on_random_blocks() {
    let mut seeds = vec![1u64, 2, 3];
    let extra = match std::env::var("GNB_LEDGER_DIFF_SEED") {
        Ok(s) => s.parse().expect("GNB_LEDGER_DIFF_SEED must be a u64"),
        Err(_) => std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64,
    };
    seeds.push(extra);
    for seed in seeds {
        let (n, rejected) = run_seed(seed);
        eprintln!("ledger differential: seed {seed}: {n} mutated cases, {rejected} rejected, all verdicts equal");
        // The mutations must exercise both outcomes.
        assert!(rejected > n / 4 && rejected < n, "seed {seed}: {rejected} of {n} rejected");
    }
}
