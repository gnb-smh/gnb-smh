#!/usr/bin/env python3
"""Replay the round-4 RPC production-only reversal in an isolated worktree.

The caller must supply the test-only baseline revision and an output directory.
No core files or tests are changed. Fixed production bytes are restored in a
finally block, including when cargo fails or this process is interrupted.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--worktree", type=Path, required=True)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.worktree.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    production = ["node/src/rpc/mod.rs", "node/src/rpc/explorer.rs"]
    tests = ["node/tests/support/address_frontends_rpc.rs", "node/tests/support/address_frontends_cli.rs"]
    fixed = {name: (root / name).read_bytes() for name in production}
    test_bytes = {name: (root / name).read_bytes() for name in tests}
    original = {name: subprocess.check_output(["git", "show", f"{args.baseline}:{name}"], cwd=root) for name in production}
    command = ["cargo", "test", "-p", "gnb", "--lib", "address_frontends", "--locked", "--offline", "--", "--nocapture"]
    env = dict(os.environ, CARGO_TARGET_DIR="/private/tmp/gnb-r4-target-address-frontends",
               CARGO_BUILD_JOBS="2", CARGO_INCREMENTAL="0", CARGO_PROFILE_DEV_DEBUG="0",
               CARGO_PROFILE_TEST_DEBUG="0", CARGO_PROFILE_DEV_CODEGEN_UNITS="83",
               CARGO_PROFILE_TEST_CODEGEN_UNITS="83")
    manifest = {
        "revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
        "baseline": args.baseline, "command": command,
        "production": {name: {"fixed_sha256": digest(fixed[name]), "baseline_sha256": digest(original[name])} for name in production},
        "tests": {name: digest(data) for name, data in test_bytes.items()},
    }

    def run(label):
        for name, data in test_bytes.items():
            assert (root / name).read_bytes() == data, f"test changed: {name}"
        path = output / f"{label}.log"
        with path.open("wb") as stream:
            result = subprocess.run(command, cwd=root, env=env, stdout=stream, stderr=subprocess.STDOUT)
        return {"exit_code": result.returncode, "log": str(path), "sha256": digest(path.read_bytes())}

    guard = b"if network != expected {"
    assert fixed["node/src/rpc/mod.rs"].count(guard) == 1
    no_guard = dict(fixed)
    no_guard["node/src/rpc/mod.rs"] = no_guard["node/src/rpc/mod.rs"].replace(guard, b"if false {")
    manifest["reversals"] = {}
    for label, replacement in [("network_guard", no_guard), ("baseline_rpc", original)]:
        try:
            for name, data in replacement.items():
                (root / name).write_bytes(data)
            manifest["reversals"][label] = run(label)
        finally:
            for name, data in fixed.items():
                (root / name).write_bytes(data)
            manifest["production_restored_exactly"] = all((root / name).read_bytes() == data for name, data in fixed.items())
            manifest["tests_unchanged"] = all((root / name).read_bytes() == data for name, data in test_bytes.items())
            (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    manifest["restored"] = run("restored")
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    for label, result in manifest["reversals"].items():
        assert result["exit_code"] != 0, f"{label}: reversal did not fail"
        assert "test result: FAILED" in Path(result["log"]).read_text(), f"{label}: reversal did not reach runtime assertions"
    assert manifest["restored"]["exit_code"] == 0, "restored tests failed"
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
