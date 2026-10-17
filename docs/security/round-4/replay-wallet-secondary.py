#!/usr/bin/env python3
"""Replay bounded local UI production reversals, restoring files in finally.

Usage: python3 docs/security/round-4/replay-wallet-secondary.py /path/to/node --output /new/output/directory
Run only in a clean dedicated worktree containing the completed fix. The
unchanged tests use actual pinned WASM with synthetic metadata, without network
or broadcast. This is not a mainnet or security-stress experiment.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[3]
BASE = "70ca8a2"
TEST = "site/tests/wallet-secondary.test.mjs"
MAIN = "site/wallet/main.js"
CORE = "site/wallet/core.js"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def replaced(text, old, new):
    assert text.count(old) == 1, f"Expected one replacement for {old[:90]!r}"
    return text.replace(old, new)


def send_region(text):
    start = text.index("// ── send ")
    return text[start:text.index("// ── receive", start)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("node", help="Node executable")
    parser.add_argument("--output", required=True, type=Path, help="New evidence directory; existing paths are refused")
    args = parser.parse_args()
    node = args.node
    output_dir = args.output.resolve()
    # Fail before touching production if evidence could be overwritten.
    output_dir.mkdir(parents=True, exist_ok=False)
    fixed = {path: (ROOT / path).read_bytes() for path in (MAIN, CORE)}
    baseline = {path: subprocess.check_output(["git", "show", f"{BASE}:{path}"], cwd=ROOT).decode() for path in fixed}
    tests_hash = digest((ROOT / TEST).read_bytes())
    fixed_source = {path: value.decode() for path, value in fixed.items()}
    create = '''    create: (testnet = false) => {
      if (typeof testnet !== "boolean") throw new Error("testnet must be a boolean");
      return call({ op: "create", mnemonic: true, testnet });
    },'''
    opened = '''    open: (json, password, network = "mainnet") => {
      if (network !== "mainnet" && network !== "testnet") throw new Error("unknown wallet network");
      return call({ op: "open", json, password, network });
    },'''
    cases = {
        "payment": {MAIN: replaced(fixed_source[MAIN], send_region(fixed_source[MAIN]), send_region(baseline[MAIN]))},
        "create": {CORE: replaced(fixed_source[CORE], create, '    create: () => call({ op: "create", mnemonic: true }),')},
        "open": {
            CORE: replaced(fixed_source[CORE], opened, '    open: (json, password) => call({ op: "open", json, password }),'),
            MAIN: replaced(fixed_source[MAIN], 'c.open(fileText, $("#pw").value, net.testnet ? "testnet" : "mainnet")', 'c.open(fileText, $("#pw").value)'),
        },
        "restored": {},
    }
    records = []
    try:
        for name, changes in cases.items():
            for path, data in fixed.items():
                (ROOT / path).write_bytes(data)
            for path, text in changes.items():
                (ROOT / path).write_text(text)
            assert digest((ROOT / TEST).read_bytes()) == tests_hash
            command = [node, "--test", TEST]
            run = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
            log = output_dir / f"{name}.log"
            log.write_bytes(run.stdout)
            output = run.stdout.decode()
            record = {"case": name, "production_files_reverted": list(changes), "command": command,
                      "exit_code": run.returncode, "tests_sha256": tests_hash, "log": str(log),
                      "log_sha256": digest(run.stdout), "pass": int(re.search(r"^# pass (\d+)$", output, re.M)[1]),
                      "fail": int(re.search(r"^# fail (\d+)$", output, re.M)[1]),
                      "failed_tests": re.findall(r"^not ok \d+ - (.*)$", output, re.M)}
            records.append(record)
            print(json.dumps(record), flush=True)
            assert (run.returncode == 0) == (name == "restored")
    finally:
        for path, data in fixed.items():
            (ROOT / path).write_bytes(data)
        assert digest((ROOT / TEST).read_bytes()) == tests_hash
    manifest = {"baseline": BASE, "fixed_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT).decode().strip(),
                "fixed_production_sha256": {path: digest(data) for path, data in fixed.items()}, "records": records}
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
