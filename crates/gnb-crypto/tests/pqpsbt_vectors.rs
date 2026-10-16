//! Independently generated wallet-format vectors, not consensus vectors.
use gnb_crypto::wallet::pqpsbt::PqPsbt;
use serde_json::{json, Value};
use std::path::PathBuf;

fn reference_dir() -> PathBuf {
    std::env::var_os("GNB_PQPSBT_REFERENCE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../reference"))
}
fn vectors() -> Value {
    serde_json::from_slice(
        &std::fs::read(reference_dir().join("pqpsbt_vectors.json"))
            .expect("independent PQ-PSBT vectors are required"),
    )
    .unwrap()
}

#[test]
fn pqpsbt_independent_vectors_match_exact_bytes_and_verdicts() {
    let vectors = vectors();
    assert_eq!(vectors["schema"], 1);
    let mut count = 0;
    for case in vectors["accepted"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let binary = hex::decode(case["binary"].as_str().unwrap()).unwrap();
        let decoded = PqPsbt::from_bytes(&binary).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(decoded.to_bytes().unwrap(), binary, "{name}");
        assert_eq!(
            decoded.to_json().unwrap(),
            case["canonical_json"].as_str().unwrap(),
            "{name}"
        );
        let document: Value = serde_json::from_str(&decoded.to_json().unwrap()).unwrap();
        assert_eq!(document, case["document"], "{name}");
        assert_eq!(
            PqPsbt::from_json(&case["document"].to_string())
                .unwrap()
                .to_bytes()
                .unwrap(),
            binary,
            "{name}"
        );
        count += 1;
    }
    for case in vectors["rejected_binary"].as_array().unwrap() {
        assert!(
            PqPsbt::from_bytes(&hex::decode(case["binary"].as_str().unwrap()).unwrap()).is_err(),
            "{}",
            case["name"]
        );
        count += 1;
    }
    for case in vectors["rejected_json"].as_array().unwrap() {
        assert!(
            PqPsbt::from_json(case["json"].as_str().unwrap()).is_err(),
            "{}",
            case["name"]
        );
        count += 1;
    }
    assert!(count >= 204);
    eprintln!("PQ-PSBT independent vectors: {count} identical verdicts");
}

// The injected conversion models the actual pointer cast on either target.
// The generator below calls this same arithmetic with its real usize width.
fn mutation_index_narrowed(seed: u64, len: usize, narrow: fn(u64) -> u64) -> usize {
    // Reduce while still u64; the bounded result fits either pointer width.
    narrow(seed % len as u64) as usize
}
fn mutation_index(seed: u64, len: usize) -> usize {
    mutation_index_narrowed(seed, len, |n| (n as usize) as u64)
}

#[test]
fn pqpsbt_mutation_offsets_are_independent_of_pointer_width() {
    for seed in [0x474e4250534254, u64::MAX, 0x100000001] {
        for len in [97, 4093, 8_388_608] {
            let offset32 = mutation_index_narrowed(seed, len, |n| u64::from(n as u32));
            let offset64 = mutation_index_narrowed(seed, len, |n| n);
            assert_eq!(offset32, offset64, "seed={seed}, len={len}");
        }
    }
}

#[test]
fn pqpsbt_seeded_binary_mutations_differential_with_python() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let vectors = vectors();
    let accepted = vectors["accepted"].as_array().unwrap();
    let mut cases = Vec::new();
    let mut seed = 0x474e4250534254u64;
    for i in 0..512 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let mut bytes =
            hex::decode(accepted[i % accepted.len()]["binary"].as_str().unwrap()).unwrap();
        match i % 8 {
            0 => {} // Positive controls prevent agreement on reject-all.
            1 => bytes.push((seed & 255) as u8),
            2 => bytes.truncate(mutation_index(seed, bytes.len())),
            3 => {
                let index = mutation_index(seed, bytes.len());
                bytes[index] ^= 1 << (seed % 8);
            }
            4 => bytes[8..10].copy_from_slice(&2u16.to_le_bytes()),
            5 => bytes[10] = (seed % 4) as u8,
            6 => bytes[11..15].copy_from_slice(&(seed as u32).to_le_bytes()),
            _ => {
                let index = mutation_index(seed, bytes.len());
                bytes[index] = 0;
            }
        }
        cases.push(bytes);
    }
    let input = cases
        .iter()
        .map(|bytes| format!("{}\n", json!({"binary":hex::encode(bytes)})))
        .collect::<String>();
    let mut child = Command::new("python3")
        .arg(reference_dir().join("pqpsbt.py"))
        .arg("--jsonl")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Python reference is required");
    // Drain output concurrently with input to avoid pipe-capacity deadlock.
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || stdin.write_all(input.as_bytes()).unwrap());
    let output = child.wait_with_output().unwrap();
    writer.join().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let lines = String::from_utf8(output.stdout).unwrap();
    assert_eq!(lines.lines().count(), cases.len());
    let mut successful = 0;
    for (i, (bytes, line)) in cases.iter().zip(lines.lines()).enumerate() {
        let expected: Value = serde_json::from_str(line).unwrap();
        let actual = PqPsbt::from_bytes(bytes);
        assert_eq!(
            actual.is_ok(),
            expected["accepted"].as_bool().unwrap(),
            "mutation {i}"
        );
        if let Ok(p) = actual {
            assert_eq!(
                hex::encode(p.to_bytes().unwrap()),
                expected["binary"],
                "mutation {i}"
            );
            assert_eq!(
                serde_json::from_str::<Value>(&p.to_json().unwrap()).unwrap(),
                expected["document"],
                "mutation {i}"
            );
            assert_eq!(
                p.to_json().unwrap(),
                expected["json"].as_str().unwrap(),
                "mutation {i}"
            );
            successful += 1;
        }
    }
    assert!(successful >= 64);
    eprintln!("PQ-PSBT seeded mutations: 512 identical verdicts, {successful} accepted");
}
