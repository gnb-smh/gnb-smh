#!/usr/bin/env python3
"""Re-run the mutants that gnb-smh's own tests missed against this harness.

    cargo mutants -p gnb-smh --file crates/gnb-smh/src/difficulty.rs \
        --file crates/gnb-smh/src/lib.rs --output <OUT>
    python3 audit/consistency/scripts/mutants_vs_harness.py <OUT>/mutants.out <WORKDIR>

Copies the crates the harness needs into WORKDIR, applies each missed
mutant's diff to the copy, runs `cargo test --release` in the copied
harness, and prints CAUGHT or MISSED per mutant. The repository itself is
never modified.
"""
import json
import os
import shutil
import subprocess
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
NEEDED = ["crates/gnb-smh", "crates/gnb-crypto", "crates/coherence-core",
          "crates/pqcrypto-internals", "reference", "audit/consistency"]


def main():
    mout, work = sys.argv[1], os.path.abspath(sys.argv[2])
    outcomes = json.load(open(os.path.join(mout, "outcomes.json")))["outcomes"]
    missed = [o for o in outcomes if o["summary"] == "MissedMutant"]
    for rel in NEEDED:
        dst = os.path.join(work, rel)
        if not os.path.exists(dst):
            shutil.copytree(os.path.join(REPO, rel), dst,
                            ignore=shutil.ignore_patterns("target", "*.proptest-regressions"))
    harness = os.path.join(work, "audit/consistency")
    env = dict(os.environ, CARGO_TARGET_DIR=os.path.join(work, "target"))
    base = subprocess.run(["cargo", "test", "--release", "-q"], cwd=harness, env=env,
                          capture_output=True, text=True)
    if base.returncode != 0:
        sys.exit("harness fails on unmutated code:\n" + base.stdout[-3000:] + base.stderr[-3000:])
    results = []
    for o in missed:
        m = o["scenario"]["Mutant"]
        src = os.path.join(work, m["file"])
        orig = open(src).read()
        diff = os.path.join(mout, o["diff_path"])
        subprocess.run(["patch", "-s", src, diff], check=True)
        try:
            r = subprocess.run(["cargo", "test", "--release", "-q", "--no-fail-fast"],
                               cwd=harness, env=env, capture_output=True, text=True, timeout=1200)
            status = "MISSED" if r.returncode == 0 else "CAUGHT"
        except subprocess.TimeoutExpired:
            status = "TIMEOUT"
        finally:
            open(src, "w").write(orig)
        results.append((status, m["name"]))
        print(f"{status:7} {m['name']}", flush=True)
    caught = sum(1 for s, _ in results if s != "MISSED")
    print(f"harness caught {caught} of {len(results)} mutants missed by gnb-smh's own tests")


if __name__ == "__main__":
    main()
