#!/usr/bin/env python3
"""Revert only frontend production code, keep tests unchanged, restore always.

Run from any directory. Needs the final compiled-code WASM and its matching
pins already installed by scripts/build-wallet-wasm.sh. Logs require a new
output directory; the script never overwrites earlier evidence.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--part", choices=["cli", "rpc", "js", "all"], default="all")
    parser.add_argument("--node", default="node")
    parser.add_argument("--target", default="/private/tmp/gnb-r5-target-descriptor-frontends")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    baseline = "2848dcf6bd89a85afe4828042227c9a2c2b433f0"
    parts = {
        "cli": ("node/src/bin/gnb-cli.rs", ["cargo", "test", "-p", "gnb", "--test", "descriptor_cli", "--locked", "--offline", "--", "--nocapture"], "running 7 tests", "6 failed"),
        "rpc": ("node/src/rpc/mod.rs", ["cargo", "test", "-p", "gnb", "--lib", "descriptor_rpc", "--locked", "--offline", "--", "--nocapture"], "running 5 tests", "4 failed"),
        "js": ("site/wallet/core.js", [args.node, "--test", "site/tests/wallet-descriptor.test.mjs"], "# tests 5", "# fail 4"),
    }
    chosen = list(parts) if args.part == "all" else [args.part]
    old_files = {}
    originals = {}
    for part in chosen:
        path = parts[part][0]
        old = subprocess.check_output(["git", "show", f"{baseline}:{path}"], cwd=root)
        if part == "rpc":
            include = b'    include!("../../tests/support/address_frontends_rpc.rs");'
            if old.count(include) != 1:
                raise RuntimeError("baseline test-module anchor changed")
            old = old.replace(include, include + b'\n    include!("../../tests/support/descriptor_rpc.rs");')
        old_files[part] = old
        originals[part] = (root / path).read_bytes()
    # Fail before any mutation if the destination already exists.
    args.output.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ, CARGO_TARGET_DIR=args.target, CARGO_PROFILE_DEV_CODEGEN_UNITS="151",
               CARGO_PROFILE_TEST_CODEGEN_UNITS="151", CARGO_PROFILE_DEV_DEBUG="0",
               CARGO_PROFILE_TEST_DEBUG="0", CARGO_INCREMENTAL="0", CARGO_BUILD_JOBS="2")
    records = []
    tests = ["node/tests/descriptor_cli.rs", "node/tests/support/descriptor_rpc.rs", "site/tests/wallet-descriptor.test.mjs"]
    hashes = {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in tests}

    def run(part, phase):
        log = args.output / f"{part}-{phase}.log"
        start = time.monotonic()
        with log.open("wb") as handle:
            result = subprocess.run(parts[part][1], cwd=root, env=env, stdout=handle, stderr=subprocess.STDOUT)
        raw = log.read_bytes()
        records.append({"part": part, "phase": phase, "command": parts[part][1], "exit_code": result.returncode,
                        "seconds": round(time.monotonic() - start, 3), "log": log.name, "sha256": hashlib.sha256(raw).hexdigest()})
        return result.returncode, raw.decode("utf8", errors="replace")

    failed = []
    try:
        for part in chosen:
            path = root / parts[part][0]
            try:
                path.write_bytes(old_files[part])
                code, log = run(part, "reverted")
                if code == 0 or parts[part][2] not in log or parts[part][3] not in log:
                    failed.append(f"{part}: expected runtime regression count not observed")
            finally:
                path.write_bytes(originals[part])
            code, _ = run(part, "restored")
            if code != 0:
                failed.append(f"{part}: restored tests failed")
    finally:
        for part in chosen:
            (root / parts[part][0]).write_bytes(originals[part])
        after = {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in tests}
        if after != hashes:
            failed.append("test contents changed during replay")
        report = {"baseline": baseline, "native_cgu": 151, "test_sha256_before": hashes,
                  "test_sha256_after": after, "runs": records, "failures": failed}
        (args.output / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    if failed:
        raise SystemExit("; ".join(failed))
    print(json.dumps({"runs": len(records), "failures": failed}))


if __name__ == "__main__":
    main()
