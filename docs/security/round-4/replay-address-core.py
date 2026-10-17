#!/usr/bin/env python3
"""Replay local production-only address reversals; never modifies tests.

Run from the package worktree after its normal tests pass. Requires cached
Cargo dependencies/toolchain. Uses an external target and output directory;
does not contact nodes, sign transactions, or execute a network probe.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

BASE = "7d6a67eafa93cf7935ecedb50d601486aca4cff7"
ADDRESS = "crates/gnb-crypto/src/address.rs"
CODEC = "crates/gnb-crypto/src/address/bech32m.rs"
PARSE_TEST = "crates/gnb-crypto/tests/address_v2.rs"
RENDER_TEST = "crates/gnb-crypto/tests/address_v2_render.rs"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worktree", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, default=Path("/private/tmp/gnb-r4-address-core-reversals"))
    parser.add_argument("--target", default="/private/tmp/gnb-r4-target-address-core")
    args = parser.parse_args()
    root, output = args.worktree.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    original = {name: (root / name).read_bytes() for name in (ADDRESS, CODEC, PARSE_TEST, RENDER_TEST)}
    test_regions = {name: data.split(b"\n#[cfg(test)]", 1)[1] for name, data in original.items() if name in (ADDRESS, CODEC)}
    base = subprocess.check_output(["git", "show", f"{BASE}:{ADDRESS}"], cwd=root)
    assert base.split(b"\n#[cfg(test)]", 1)[1] == test_regions[ADDRESS]
    # The same pre-production regression bytes are available after cherry-pick
    # without depending on the package's original (possibly unpushed) commit ID.
    assert sha(original[PARSE_TEST]) == "02e1772e7001592f45f730a774a502dee747a01bf55fc30fd5a86f7dcf2a4302"
    environment = os.environ.copy()
    environment.update({"CARGO_PROFILE_DEV_CODEGEN_UNITS": "79", "CARGO_PROFILE_TEST_CODEGEN_UNITS": "79",
                        "CARGO_PROFILE_DEV_DEBUG": "0", "CARGO_PROFILE_TEST_DEBUG": "0",
                        "CARGO_INCREMENTAL": "0", "CARGO_BUILD_JOBS": "2", "CARGO_TARGET_DIR": args.target})
    manifest = {"base": BASE, "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
                "source_sha256": {name: sha(data) for name, data in original.items()},
                "inline_test_sha256": {name: sha(data) for name, data in test_regions.items()},
                "base_address_sha256": sha(base), "replay_driver_sha256": sha(Path(__file__).read_bytes()),
                "target": args.target, "codegen_units": 79, "runs": []}

    def check_tests():
        for name in (PARSE_TEST, RENDER_TEST):
            assert (root / name).read_bytes() == original[name], f"test changed: {name}"
        for name, region in test_regions.items():
            assert (root / name).read_bytes().split(b"\n#[cfg(test)]", 1)[1] == region, f"inline tests changed: {name}"

    def run(name, extra, expected_exit):
        check_tests()
        command = ["cargo", "test", "-p", "gnb-crypto", "--locked", "--offline", *extra]
        started = time.monotonic()
        log = output / f"{name}.log"
        with log.open("wb") as handle:
            completed = subprocess.run(command, cwd=root, env=environment, stdout=handle, stderr=subprocess.STDOUT)
        content = log.read_bytes()
        text = content.decode(errors="replace")
        summaries = re.findall(r"test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored", text)
        result = {"name": name, "command": command, "exit": completed.returncode,
                  "duration_seconds": round(time.monotonic() - started, 3), "log": str(log), "log_sha256": sha(content),
                  "production_sha256": {path: sha((root / path).read_bytes().split(b"\n#[cfg(test)]", 1)[0]) for path in (ADDRESS, CODEC)},
                  "passed": sum(int(row[0]) for row in summaries), "failed": sum(int(row[1]) for row in summaries)}
        manifest["runs"].append(result)
        assert completed.returncode == expected_exit, result
        assert summaries and (result["failed"] > 0 if expected_exit else result["failed"] == 0), result
        if expected_exit:
            assert "panicked at" in text and "error[E" not in text, "expected runtime failure, not compiler/setup error"
        check_tests()

    try:
        (root / ADDRESS).write_bytes(base)
        run("baseline-production", ["--test", "address_v2"], 101)
        (root / ADDRESS).write_bytes(original[ADDRESS])
        run("baseline-restored", ["--test", "address_v2"], 0)
        variants = [
            ("checksum-guard", "if polymod(hrp_words(hrp).chain(words.iter().copied())) != BECH32M {", "if false {"),
            ("padding-guard", "} else if bits >= from || ((accumulator << (to - bits)) & max_value) != 0 {", "} else if false {"),
            ("case-guard", "if s.bytes().any(|c| c.is_ascii_lowercase()) && s.bytes().any(|c| c.is_ascii_uppercase()) {", "if false {"),
        ]
        for name, old, new in variants:
            production, tests = original[CODEC].split(b"\n#[cfg(test)]", 1)
            assert production.count(old.encode()) == 1
            changed = production.replace(old.encode(), new.encode()) + b"\n#[cfg(test)]" + tests
            (root / CODEC).write_bytes(changed)
            run(name, ["--lib", "address::bech32m::tests"], 101)
            (root / CODEC).write_bytes(original[CODEC])
        production, tests = original[CODEC].split(b"\n#[cfg(test)]", 1)
        old = b"if hash.len() != expected {\n        return Err(AddressError::BadEncoding);"
        new = b"if hash.len() != expected {\n        return Err(AddressError::BadLength { got: hash.len(), expected });"
        assert production.count(old) == 1
        (root / CODEC).write_bytes(production.replace(old, new) + b"\n#[cfg(test)]" + tests)
        run("length-diagnostic", ["--test", "address_v2_render", "v2_hash_lengths_report_encoding_failure_not_character_counts"], 101)
        (root / CODEC).write_bytes(original[CODEC])
        run("guards-restored", ["--lib", "address::bech32m::tests"], 0)
        run("render-restored", ["--test", "address_v2_render"], 0)
    finally:
        for name in (ADDRESS, CODEC):
            (root / name).write_bytes(original[name])
        check_tests()
        manifest["restored_sha256"] = {name: sha((root / name).read_bytes()) for name in original}
        assert manifest["restored_sha256"] == manifest["source_sha256"]
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"runs": len(manifest["runs"]), "manifest": str(output / "manifest.json")}))


if __name__ == "__main__":
    main()
