#!/usr/bin/env python3
"""Bounded offline production reversals; final tests remain byte-identical.

Run only in a disposable wallet package worktree. This rebuilds through the
normal script, restores all generated artifacts in finally, and never sends
transactions or connects to a node. Supply the pinned WASI SDK via WASI_SDK.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--node", required=True)
p.add_argument("--output", type=Path, required=True)
args = p.parse_args()
root = Path(__file__).resolve().parents[3]
args.output.mkdir(parents=True, exist_ok=True)
test = root / "site/tests/address-v2-wasm.test.mjs"
original_test = test.read_bytes()
paths = ["crates/gnb-wallet-wasm/src/lib.rs", "site/wallet/core.js",
         "site/wallet/gnb_wallet.wasm", "site/wallet/app.js", "site/wallet/main.js",
         "site/wallet.html", "site/explorer.html", "site/index.html", "site/brand.html"]
saved = {name: (root / name).read_bytes() for name in paths}
digest = lambda value: hashlib.sha256(value).hexdigest()
record = {"revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
          "test_sha256": digest(original_test), "results": [], "restored": False}

def run(name, command, failures=None):
    start = time.monotonic()
    log = args.output / (name + ".log")
    with log.open("w") as output:
        result = subprocess.run(command, cwd=root, stdout=output, stderr=subprocess.STDOUT)
    data = log.read_bytes()
    row = {"name": name, "command": command, "exit_code": result.returncode,
           "seconds": round(time.monotonic() - start, 2), "log_sha256": digest(data)}
    record["results"].append(row)
    assert test.read_bytes() == original_test, "final tests changed"
    if failures is None:
        assert result.returncode == 0, row
    else:
        text = data.decode()
        row["passed"] = int(re.search(r"^# pass (\d+)$", text, re.M)[1])
        row["failed"] = int(re.search(r"^# fail (\d+)$", text, re.M)[1])
        assert row["failed"] == failures and row["passed"] == 6 - failures, row
        assert result.returncode == (1 if failures else 0), row
    print(name, result.returncode, flush=True)

def tests(name, failures):
    run(name, [args.node, "--test", str(test)], failures)

try:
    tests("final-control", 0)
    lib = root / paths[0]
    final = lib.read_text()
    old = subprocess.check_output(["git", "show", "7d6a67e:crates/gnb-wallet-wasm/src/lib.rs"], cwd=root, text=True)
    start, end = '        "normalize" =>', '        "minfee" =>'
    old_arm = old[old.index(start):old.index(end)]
    lib.write_text(final[:final.index(start)] + old_arm + final[final.index(end):])
    run("without-format-build", ["scripts/build-wallet-wasm.sh"])
    tests("without-rust-format", 1)
    lib.write_bytes(saved[paths[0]])
    run("restored-rust-build", ["scripts/build-wallet-wasm.sh"])
    tests("restored-rust", 0)

    js = root / "site/wallet/core.js"
    current = js.read_text()
    new = 'normalize: (address, format = "legacy") => call({ op: "normalize", address, format }).address,'
    previous = 'normalize: (address) => call({ op: "normalize", address }).address,'
    assert current.count(new) == 1
    js.write_text(current.replace(new, previous))
    tests("without-js-format", 1)
    js.write_bytes(saved["site/wallet/core.js"])

    main = root / "site/wallet/main.js"
    old_main = subprocess.check_output(["git", "show", "7d6a67e:site/wallet/main.js"], cwd=root, text=True)
    old_pin = re.search(r'^const CORE_SHA256 = "[0-9a-f]{64}";$', old_main, re.M)[0]
    main.write_text(re.sub(r'^const CORE_SHA256 = "[0-9a-f]{64}";$', old_pin, main.read_text(), flags=re.M))
    tests("without-alternate-pin", 1)
finally:
    for name, data in saved.items():
        (root / name).write_bytes(data)
    record["restored"] = all((root / name).read_bytes() == data for name, data in saved.items())
    record["tests_unchanged"] = test.read_bytes() == original_test
    (args.output / "manifest.json").write_text(json.dumps(record, indent=2) + "\n")

tests("restored-final", 0)
(args.output / "manifest.json").write_text(json.dumps(record, indent=2) + "\n")
