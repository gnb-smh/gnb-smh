//! JSONL differential adapter. Every accepted request executes the shared API.
use gnb_crypto::wallet::descriptor::{public_request, request_from_json, MAX_POOL_BYTES};
use serde_json::{json, Value};
use std::io::{self, BufRead, Read};

// Tool transport budget, allowing six-character JSON escapes for every byte
// of a maximum pool plus envelope overhead. Not a consensus/script limit.
const MAX_LINE: usize = 8 * MAX_POOL_BYTES;

fn run(line: &[u8]) -> Value {
    match request_from_json(line).and_then(|request| public_request(&request)) {
        Ok(result) => json!({"ok":true,"result":result}),
        Err(_) => json!({"ok":false}),
    }
}

fn main() -> io::Result<()> {
    let mut input = io::stdin().lock();
    loop {
        let mut line = Vec::new();
        let read = input
            .by_ref()
            .take((MAX_LINE + 1) as u64)
            .read_until(b'\n', &mut line)?;
        if read == 0 {
            break;
        }
        if line.len() > MAX_LINE {
            if line.last() != Some(&b'\n') {
                loop {
                    let buffer = input.fill_buf()?;
                    if buffer.is_empty() {
                        break;
                    }
                    let end = buffer.iter().position(|&byte| byte == b'\n');
                    let consumed = end.map_or(buffer.len(), |index| index + 1);
                    input.consume(consumed);
                    if end.is_some() {
                        break;
                    }
                }
            }
            println!("{}", json!({"ok":false}));
        } else {
            println!("{}", run(&line));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn oracle_runs_real_shared_codec() {
        let request = json!({"action":"create","network":"mainnet","body":format!("gnbd1(mainnet,pkh({}))", "00".repeat(3745))});
        assert_eq!(
            run(&serde_json::to_vec(&request).unwrap()),
            json!({"ok":true,"result":public_request(&request).unwrap()})
        );
    }
    #[test]
    fn oracle_refuses_raw_duplicate_unknown_and_malformed_requests() {
        for bytes in [
            br#"{"action":"wipe"}"#.as_slice(),
            br#"{"op":"descriptor","op":"wipe"}"#,
            br#"{"network":"mainnet","network":"testnet"}"#,
            br#"{"extra":true}"#,
            b"null",
            b"{}x",
        ] {
            assert_eq!(run(bytes), json!({"ok":false}));
        }
    }
}
