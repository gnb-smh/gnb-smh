#!/usr/bin/env python3
"""Production-only reversal of the local JSONL adapter's R4-V2 correction."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worktree", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True, help="fresh output directory")
    parser.add_argument("--target", default="/private/tmp/gnb-r4-target-address-core")
    args = parser.parse_args()
    root, output = args.worktree.resolve(), args.output.resolve()
    if output.exists() and any(output.iterdir()):
        parser.error("output directory must be empty; preserve earlier evidence")
    output.mkdir(parents=True, exist_ok=True)
    relative = "crates/gnb-crypto/examples/address_v2_oracle.rs"
    path = root / relative
    original = path.read_bytes()
    marker = b"\n#[cfg(test)]"
    production, tests = original.split(marker, 1)
    baseline = subprocess.check_output(["git", "show", f"4b32fb6:{relative}"], cwd=root)
    sha = lambda data: hashlib.sha256(data).hexdigest()
    env = os.environ.copy()
    env.update({"CARGO_PROFILE_DEV_CODEGEN_UNITS": "79", "CARGO_PROFILE_TEST_CODEGEN_UNITS": "79",
                "CARGO_PROFILE_DEV_DEBUG": "0", "CARGO_PROFILE_TEST_DEBUG": "0", "CARGO_INCREMENTAL": "0",
                "CARGO_BUILD_JOBS": "2", "CARGO_TARGET_DIR": args.target})
    command = ["cargo", "test", "-p", "gnb-crypto", "--locked", "--offline", "--example", "address_v2_oracle"]
    record = {"source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
              "source_sha256": sha(original), "production_sha256": sha(production),
              "baseline_production_sha256": sha(baseline), "tests_sha256": sha(tests),
              "driver_sha256": sha(Path(__file__).read_bytes()), "codegen_units": 79, "target": args.target, "runs": []}

    def run(name, expected, expected_summary):
        assert path.read_bytes().split(marker, 1)[1] == tests
        log = output / f"{name}.log"
        with log.open("wb") as handle:
            result = subprocess.run(command, cwd=root, env=env, stdout=handle, stderr=subprocess.STDOUT)
        data = log.read_bytes()
        record["runs"].append({"name": name, "command": command, "exit": result.returncode,
                               "log": str(log), "log_sha256": sha(data)})
        assert result.returncode == expected and expected_summary in data
        if expected:
            assert b"panicked at" in data and b"error[E" not in data
        assert path.read_bytes().split(marker, 1)[1] == tests

    try:
        path.write_bytes(baseline + marker + tests)
        run("adapter-reverted", 101, b"2 passed; 3 failed")
        path.write_bytes(original)
        run("adapter-restored", 0, b"5 passed; 0 failed")
    finally:
        path.write_bytes(original)
        record["restored_sha256"] = sha(path.read_bytes())
        assert record["restored_sha256"] == record["source_sha256"]
        (output / "manifest.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({"runs": len(record["runs"]), "manifest": str(output / "manifest.json")}))


if __name__ == "__main__":
    main()
