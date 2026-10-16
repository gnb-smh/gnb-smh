#!/usr/bin/env python3
"""Replay this package's production-only reversal in its dedicated worktree.

Uses synthetic existing tests only. Refuses changed implementation/test bytes.
Run without another process editing or testing this worktree during the replay.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
from datetime import datetime, timezone


WORKTREE = Path("/Users/tiagobulhoes/worktrees/gnb-security-r3-transport-key-ownership")
TARGET = "/private/tmp/gnb-security-target-r3-transport-key-ownership"
BASE = "b425436fbb5c24f215c8b85a08a0fb4ec557292e"
CORRECTION = "4ef8664f1261d0147e42d72ca1eab1bdac87f9f2"
FILES = ("node/src/transport/mod.rs", "node/src/transport/upgrade.rs")
MARKER = b"\n#[cfg(test)]\nmod key_ownership_tests"
TEST_HASH = "1c33c262b38efd8b21b276ef4b2bd666356081975192330ad67d2fac86cca9cd"
PREFIX = "transport::upgrade::key_ownership_tests::"
CONTROLS = (
    "derived_keys_preserve_fixed_hkdf_vector_and_direction",
    "derived_keys_can_be_wiped_while_alive",
    "session_key_owners_are_not_copy",
    "stream_owners_wipe_keys_and_counters_while_alive",
)
REGRESSION = "derived_keys_require_drop_cleanup"
CARGO = [
    "cargo", "test", "--locked", "-v", "-p", "gnb", "--lib", PREFIX[:-2],
    "--", "--nocapture", "--test-threads=1",
]
BUILD_ENV = {
    "CARGO_TARGET_DIR": TARGET,
    "CARGO_PROFILE_DEV_CODEGEN_UNITS": "47",
    "CARGO_PROFILE_DEV_DEBUG": "0",
    "CARGO_INCREMENTAL": "0",
    "CARGO_BUILD_JOBS": "1",
}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def capture(*command):
    return subprocess.check_output(command, cwd=WORKTREE)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    require(Path.cwd().resolve() == WORKTREE, "Run in the dedicated R3 worktree")
    require(Path(__file__).resolve().parents[3] == WORKTREE, "Unexpected driver location")
    require(Path(capture("git", "rev-parse", "--show-toplevel").decode().strip()) == WORKTREE,
            "Unexpected Git worktree")
    output = args.output_dir.resolve()
    require(output.parent == Path("/private/tmp"), "Output must be a new directory under /private/tmp")
    output.mkdir(exist_ok=False)
    original = {name: (WORKTREE / name).read_bytes() for name in FILES}
    base = {name: capture("git", "show", f"{BASE}:{name}") for name in FILES}
    for name in FILES:
        require(not (WORKTREE / name).is_symlink(), f"Refuse symlink: {name}")
        require(original[name] == capture("git", "show", f"{CORRECTION}:{name}"),
                f"Implementation/tests differ from reviewed correction: {name}")
    upgrade = original[FILES[1]]
    require(upgrade.count(MARKER) == 1, "Expected one final test suffix")
    require(MARKER not in base[FILES[1]], "Base unexpectedly contains the test suffix")
    suffix = upgrade[upgrade.index(MARKER):]
    require(sha256(suffix) == TEST_HASH, "Final test suffix hash differs")
    reversed_files = {FILES[0]: base[FILES[0]], FILES[1]: base[FILES[1]] + suffix}

    manifest = {
        "schema": 1,
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "worktree": str(WORKTREE),
        "head_at_start": capture("git", "rev-parse", "HEAD").decode().strip(),
        "base_commit": BASE,
        "correction_commit": CORRECTION,
        "platform": platform.platform(),
        "rustc": capture("rustc", "--version").decode().strip(),
        "cargo": capture("cargo", "--version").decode().strip(),
        "command": CARGO,
        "build_environment": BUILD_ENV,
        "final_test_suffix_sha256": TEST_HASH,
        "snapshots": {},
        "runs": {},
        "status": "prepared",
    }

    def save_manifest():
        temp = output / "manifest.json.tmp"
        temp.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        temp.replace(output / "manifest.json")

    def snapshot(label, data):
        path = output / label
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        manifest["snapshots"][label] = {"sha256": sha256(data), "bytes": len(data)}

    def verify_sources(expected):
        for name in FILES:
            require((WORKTREE / name).read_bytes() == expected[name], f"Source bytes differ: {name}")
        current = (WORKTREE / FILES[1]).read_bytes()
        require(current[current.index(MARKER):] == suffix, "Final tests changed")

    def run_tests(stage):
        print(f"{stage}: running only the five package tests", flush=True)
        path = output / f"{stage}.log"
        with path.open("wb") as log:
            result = subprocess.run(CARGO, cwd=WORKTREE, env={**os.environ, **BUILD_ENV},
                                    stdout=log, stderr=subprocess.STDOUT)
        data = path.read_bytes()
        manifest["runs"][stage] = {
            "exit_code": result.returncode,
            "log": path.name,
            "log_sha256": sha256(data),
        }
        save_manifest()
        return result.returncode, data.decode(errors="replace")

    snapshot("driver.py", Path(__file__).read_bytes())
    snapshot("tests/final-suffix.rs", suffix)
    for name in FILES:
        snapshot(f"before/{Path(name).name}", original[name])
        snapshot(f"base/{Path(name).name}", base[name])
    save_manifest()
    print(f"Evidence: {output}", flush=True)

    try:
        try:
            for name in FILES:
                (WORKTREE / name).write_bytes(reversed_files[name])
            verify_sources(reversed_files)
            for name in FILES:
                snapshot(f"reversed/{Path(name).name}", (WORKTREE / name).read_bytes())
            manifest["status"] = "production_reversed_final_tests_retained"
            save_manifest()
            code, log = run_tests("reversal")
            verify_sources(reversed_files)
            require(code == 101, "Reversal must fail with Cargo exit 101")
            require("running 5 tests" in log and "could not compile" not in log,
                    "Reversal must execute five tests, not fail compilation")
            require("test result: FAILED. 4 passed; 1 failed; 0 ignored; 0 measured;" in log,
                    "Reversal must have exactly four passing controls and one runtime failure")
            for test in CONTROLS:
                require(f"test {PREFIX}{test} ... ok" in log, f"Control did not pass: {test}")
            require(f"\n    {PREFIX}{REGRESSION}\n" in log, "Wrong failed test")
            for text in ("both derived keys need cleaning owners", "left: (false, false)",
                         "right: (true, true)"):
                require(text in log, f"Missing runtime failure evidence: {text}")
            manifest["runs"]["reversal"]["validated_expected_runtime_failure"] = True
        finally:
            # Restore both originals even if setup, Cargo, validation or Ctrl-C fails.
            errors = []
            for name in FILES:
                try:
                    (WORKTREE / name).write_bytes(original[name])
                except OSError as error:
                    errors.append(f"{name}: {error}")
            require(not errors, f"Restore writes failed: {errors}")
            verify_sources(original)
            for name in FILES:
                snapshot(f"restored/{Path(name).name}", (WORKTREE / name).read_bytes())
            manifest["restoration_verified_byte_for_byte"] = True
            manifest["status"] = "sources_restored"
            save_manifest()
            print("finally: original source bytes and final tests restored and verified", flush=True)

        code, log = run_tests("restored")
        verify_sources(original)
        require(code == 0, "Restored correction must pass")
        require("test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured;" in log,
                "Restored correction must run and pass all five tests")
        for test in (*CONTROLS, REGRESSION):
            require(f"test {PREFIX}{test} ... ok" in log, f"Restored test did not pass: {test}")
        manifest["runs"]["restored"]["validated_five_passes"] = True
        manifest["status"] = "complete"
        manifest["finished_utc"] = datetime.now(timezone.utc).isoformat()
        save_manifest()
        print("PASS: runtime reversal reproduced; final five tests green; source bytes unchanged", flush=True)
    except BaseException as error:
        manifest["status"] = "failed_or_interrupted"
        manifest["error"] = f"{type(error).__name__}: {error}"
        save_manifest()
        raise


if __name__ == "__main__":
    main()
