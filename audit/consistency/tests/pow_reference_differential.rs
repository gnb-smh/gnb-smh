//! GnB-SMH: Rust consensus implementation vs the normative Python definition.
//!
//! The repository checks 7 fixed vectors. This test adds randomized
//! differential cases (random header lengths and bytes, the full u64 nonce
//! range, several scratchpad sizes) evaluated by `reference/gnb_smh.py`, and
//! checks that a reused scratchpad and the per-thread scratchpad used by the
//! node give the same output as a fresh one.

use proptest::prelude::*;
use proptest::strategy::ValueTree;
use proptest::test_runner::{Config, TestRunner};
use std::io::Write;
use std::process::{Command, Stdio};

const REFERENCE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../reference");

fn python_batch(cases: &[(Vec<u8>, u64, u32)]) -> Vec<[u8; 32]> {
    let script = "import sys, json\n\
                  sys.path.insert(0, sys.argv[1])\n\
                  import gnb_smh\n\
                  for c in json.load(sys.stdin):\n\
                  \x20   print(gnb_smh.gnb_smh(bytes.fromhex(c[0]), int(c[1]), int(c[2])).hex())\n";
    let payload = format!(
        "[{}]",
        cases
            .iter()
            .map(|(h, n, l)| format!("[\"{}\",\"{}\",{}]", hex(h), n, l))
            .collect::<Vec<_>>()
            .join(",")
    );
    let mut child = Command::new("python3")
        .arg("-c")
        .arg(script)
        .arg(REFERENCE_DIR)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("python3 is required for the reference differential");
    child.stdin.take().unwrap().write_all(payload.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "python reference failed");
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| {
            let mut a = [0u8; 32];
            for (i, b) in a.iter_mut().enumerate() {
                *b = u8::from_str_radix(&l[2 * i..2 * i + 2], 16).unwrap();
            }
            a
        })
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn random_cases_match_the_python_reference() {
    let mut runner = TestRunner::new(Config::default());
    let strat = (
        proptest::collection::vec(any::<u8>(), 0..400),
        any::<u64>(),
        prop_oneof![Just(1u32), Just(2), Just(5), Just(9), Just(10), Just(12)],
    );
    let cases: Vec<(Vec<u8>, u64, u32)> =
        (0..96).map(|_| strat.new_tree(&mut runner).unwrap().current()).collect();
    let expected = python_batch(&cases);
    assert_eq!(expected.len(), cases.len());
    for ((h, n, l), want) in cases.iter().zip(expected) {
        let mut sp = gnb_smh::Scratchpad::new(*l);
        assert_eq!(gnb_smh::hash_with(&mut sp, h, *n), want, "log2_n={l} nonce={n} header={}", hex(h));
    }
    println!("gnb-smh: {} random cases identical to reference/gnb_smh.py", cases.len());
}

#[test]
fn reused_scratchpad_has_no_state_leak() {
    let mut reused = gnb_smh::Scratchpad::new(11);
    for i in 0..32u64 {
        let header = vec![i as u8; (i * 7) as usize];
        let a = gnb_smh::hash_with(&mut reused, &header, i.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let b = gnb_smh::hash_with(
            &mut gnb_smh::Scratchpad::new(11),
            &header,
            i.wrapping_mul(0x9E37_79B9_7F4A_7C15),
        );
        assert_eq!(a, b);
    }
}

#[test]
fn canonical_thread_local_matches_fresh_and_python() {
    let header = b"GnB audit canonical parameter check".to_vec();
    let fresh = gnb_smh::hash(&header, 42);
    assert_eq!(gnb_smh::hash_thread_local(&header, 42), fresh);
    assert_eq!(gnb_smh::hash_thread_local(&header, 42), fresh, "second call reuses the pad");
    let py = python_batch(&[(header, 42, gnb_smh::LOG2_N)]);
    assert_eq!(py[0], fresh);
}
