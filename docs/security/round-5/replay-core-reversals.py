#!/usr/bin/env python3
"""Focused production reversals; final tests remain byte-identical.

Use a fresh output directory. Sources are restored even if a subprocess fails.
Never execute concurrently with edits or another build in the same worktree.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=False)
root = Path(__file__).resolve().parents[3]
os.chdir(root)
env = dict(os.environ, CARGO_TARGET_DIR="/private/tmp/gnb-r5-target-descriptor-core",
           CARGO_PROFILE_DEV_CODEGEN_UNITS="139", CARGO_PROFILE_TEST_CODEGEN_UNITS="139",
           CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0", CARGO_INCREMENTAL="0", CARGO_BUILD_JOBS="2")
codec = "crates/gnb-crypto/src/wallet/descriptor.rs"
wasm = "crates/gnb-wallet-wasm/src/lib.rs"
tests = ["crates/gnb-crypto/tests/public_descriptors.rs", "crates/gnb-wallet-wasm/tests/public_descriptors.rs"]
sha = lambda data: hashlib.sha256(data).hexdigest()
original = {path: Path(path).read_bytes() for path in [codec, wasm]}
test_hashes = {path: sha(Path(path).read_bytes()) for path in tests}

cases = [
    ("wasm-dispatch", wasm, '        "descriptor" => gnb_crypto::wallet::descriptor::public_request(req),\n', "",
     "gnb-wallet-wasm", "public_descriptor_creation_preserves_existing_script_without_a_session"),
    ("checksum", codec, "if supplied.len() != 8 || checksum(body)? != supplied {", "if supplied.len() != 8 {",
     "gnb-crypto", "checksum_is_mandatory_and_binds_network_and_every_key_byte"),
    ("request-network", codec, '            if descriptor.network != network {\n                return Err("descriptor network mismatch".into());\n            }\n', "",
     "gnb-crypto", "shared_request_rejects_wrong_network_types_fields_and_session_actions"),
    ("pool-raw-limit", codec, '        if bundle.len() > MAX_POOL_BYTES {\n            return Err("pool too large".into());\n        }\n        // Derive', "        // Derive",
     "gnb-crypto", "pool_entry_and_raw_byte_limits_have_positive_controls"),
    ("pool-duplicates", codec, 'serde_json::from_str(bundle).map_err(|e| format!("invalid pool: {e}"))?;',
     'serde_json::from_value(serde_json::from_str::<Value>(bundle).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;',
     "gnb-crypto", "pool_rejects_duplicate_unknown_fields_trailing_bytes_and_duplicate_scripts"),
    ("pool-script-uniqueness", codec, '            if !scripts.insert(entry.script_pubkey()) {\n                return Err("duplicate pool script".into());\n            }',
     '            scripts.insert(entry.script_pubkey());',
     "gnb-crypto", "pool_rejects_duplicate_unknown_fields_trailing_bytes_and_duplicate_scripts"),
    ("raw-operation-gate", wasm, 'if gnb_crypto::wallet::descriptor::mentions_descriptor_operation(input) {', 'if false {',
     "gnb-wallet-wasm", "raw_public_envelopes_cannot_redirect_or_mutate_a_live_session"),
]

records = []
try:
    for label, path, before, after, package, test in cases:
        text = original[path].decode()
        if text.count(before) != 1:
            raise RuntimeError(f"mutation does not match exactly once: {label}")
        command = ["cargo", "test", "-p", package, "--test", "public_descriptors", "--locked", "--offline", test, "--", "--exact"]
        for phase in ["reversed", "restored"]:
            Path(path).write_bytes(text.replace(before, after).encode() if phase == "reversed" else original[path])
            log = args.output / f"{label}-{phase}.log"
            with log.open("wb") as output:
                result = subprocess.run(command, env=env, stdout=output, stderr=subprocess.STDOUT)
            data = log.read_bytes()
            records.append(dict(case=label, phase=phase, command=command, exit=result.returncode,
                                log=str(log), sha256=sha(data), production_sha256=sha(Path(path).read_bytes())))
            if {p: sha(Path(p).read_bytes()) for p in tests} != test_hashes:
                raise RuntimeError("tests changed during reversal")
            expected = (result.returncode == 101 and b"test result: FAILED" in data) if phase == "reversed" else result.returncode == 0
            if not expected:
                raise RuntimeError(f"unexpected {label}/{phase} outcome: {result.returncode}")
        print(f"{label}: runtime failure confirmed; restored pass", flush=True)
finally:
    for path, data in original.items():
        Path(path).write_bytes(data)
    manifest = dict(source_revision=subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
                    env={key: env[key] for key in ["CARGO_TARGET_DIR", "CARGO_PROFILE_DEV_CODEGEN_UNITS",
                         "CARGO_PROFILE_TEST_CODEGEN_UNITS", "CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG",
                         "CARGO_INCREMENTAL", "CARGO_BUILD_JOBS"]},
                    source_hashes={path: sha(data) for path, data in original.items()}, test_hashes=test_hashes,
                    records=records, restored=all(Path(path).read_bytes() == data for path, data in original.items()))
    (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
