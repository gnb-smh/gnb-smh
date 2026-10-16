#!/usr/bin/env python3
"""Production-only address web reversals. Run in a disposable worktree.

Requires the baseline git object, Node >=22 and Python >=3.9; no node/sockets.
Every replacement is restored in finally. Final tests are never modified.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

BASE = "7d6a67eafa93cf7935ecedb50d601486aca4cff7"
ROOT = Path(__file__).resolve().parents[3]
TESTS = ("site/tests/address-v2-web-paths.test.mjs", "deploy/explorer-api/test_address_v2.py")
PRODUCTION = {
    "site/assets/safe.js": "address syntax gate recognizes",
    "site/explorer.js": re.escape("../explorer.js routes"),
    "site/explorer/explorer.js": re.escape("../explorer/explorer.js routes"),
    "site/wallet/app.js": re.escape("../wallet/app.js watch"),
    "site/wallet/main.js": re.escape("../wallet/main.js watch"),
    "worker/index.js": "Worker forwards",
    "deploy/explorer-api/gnb_explorer_api.py": None,
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", default="node")
    parser.add_argument("--python", default="python3")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    source = {name: (ROOT / name).read_bytes() for name in PRODUCTION}
    tests = {name: digest((ROOT / name).read_bytes()) for name in TESTS}
    baseline = {name: subprocess.check_output(["git", "show", f"{BASE}:{name}"], cwd=ROOT) for name in PRODUCTION}
    report = {"base": BASE, "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "tests_sha256": tests, "production": {name: {"fixed_sha256": digest(data), "baseline_sha256": digest(baseline[name])} for name, data in source.items()}, "runs": []}

    def run(label, argv, expect):
        result = subprocess.run(argv, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=90)
        log = output / (label + ".log")
        log.write_bytes(result.stdout)
        row = {"label": label, "argv": argv, "exit_code": result.returncode, "log": str(log), "log_sha256": digest(result.stdout)}
        report["runs"].append(row)
        assert (result.returncode == 0) == expect, row
        if not expect:
            # Runtime assertion failure is required, not module/import/setup failure.
            assert b"AssertionError" in result.stdout or b"ERR_ASSERTION" in result.stdout, row

    node = [args.node, "--test"]
    python = [args.python, "-m", "unittest", "discover", "-s", "deploy/explorer-api", "-p", "test_address_v2.py", "-v"]
    try:
        run("fixed-js", node + [TESTS[0]], True)
        run("fixed-python", python, True)
        for index, (name, pattern) in enumerate(PRODUCTION.items()):
            (ROOT / name).write_bytes(baseline[name])
            try:
                command = python if pattern is None else node + ["--test-name-pattern", pattern, TESTS[0]]
                run(f"reverted-{index}", command, False)
            finally:
                (ROOT / name).write_bytes(source[name])
        for name in PRODUCTION:
            (ROOT / name).write_bytes(baseline[name])
        try:
            run("all-baseline-js", node + [TESTS[0]], False)
            run("all-baseline-python", python, False)
        finally:
            for name, data in source.items():
                (ROOT / name).write_bytes(data)
        run("restored-js", node + [TESTS[0]], True)
        run("restored-python", python, True)
    finally:
        for name, data in source.items():
            (ROOT / name).write_bytes(data)
        report["restored_exact"] = all((ROOT / name).read_bytes() == data for name, data in source.items())
        report["tests_unchanged"] = all(digest((ROOT / name).read_bytes()) == value for name, value in tests.items())
        (output / "manifest.json").write_text(json.dumps(report, indent=2) + "\n")
    assert report["restored_exact"] and report["tests_unchanged"]


if __name__ == "__main__":
    main()
