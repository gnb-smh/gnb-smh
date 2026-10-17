#!/usr/bin/env python3
"""Production-only PF-2 reversals, retaining final tests and restoring bytes.

Run only after green and while no other Cargo/editor process uses this worktree.
The expected hashes must identify the reviewed final frontend source exactly.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def digest(data):
    return hashlib.sha256(data).hexdigest()


def section(text, start, end):
    begin = text.index(start)
    finish = text.index(end, begin)
    return begin, finish


def replaced(current, baseline, start, end):
    a, b = section(current, start, end)
    x, y = section(baseline, start, end)
    return current[:a] + baseline[x:y] + current[b:]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli-sha", required=True)
    parser.add_argument("--rpc-sha", required=True)
    parser.add_argument("--mode", choices=("cli", "metadata", "both"), default="both")
    parser.add_argument("--logs", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    paths = {"cli": root / "node/src/bin/gnb-cli.rs", "metadata": root / "node/src/rpc/mod.rs"}
    saved = {name: path.read_bytes() for name, path in paths.items()}
    for name, expected in (("cli", args.cli_sha), ("metadata", args.rpc_sha)):
        if digest(saved[name]) != expected:
            raise SystemExit(f"refusing unexpected {name} source hash: {digest(saved[name])}")
    tests = list((root / "node/tests").glob("pqpsbt*.rs")) + list((root / "node/tests/support").glob("pqpsbt*"))
    test_hashes = {str(p): digest(p.read_bytes()) for p in tests if p.is_file()}
    rpc_test_suffix = saved["metadata"].split(b"mod audit_2026_10_rpc_tests {", 1)[1]
    baseline = {name: subprocess.check_output([
        "git", "show", f"f06b7f8dc05af107fd16f2cebdd89d62a360662a:{path.relative_to(root)}"
    ], cwd=root).decode() for name, path in paths.items()}
    env = dict(os.environ, CARGO_TARGET_DIR="/private/tmp/gnb-technology-target-pqpsbt-frontends",
               CARGO_PROFILE_DEV_CODEGEN_UNITS="61", CARGO_PROFILE_DEV_DEBUG="0",
               CARGO_INCREMENTAL="0", CARGO_BUILD_JOBS="1")
    args.logs.mkdir(parents=True, exist_ok=True)
    record = {"source_hashes": {name: digest(data) for name, data in saved.items()}, "runs": []}
    modes = ("cli", "metadata") if args.mode == "both" else (args.mode,)
    try:
        for mode in modes:
            current = saved[mode].decode()
            if mode == "cli":
                changed = replaced(current, baseline[mode], "fn do_policy_sign(", "\nfn do_policy_send(")
                old_call = "do_policy_sign(params, &rpc_target, stated_network);"
                if changed.count(old_call) != 1:
                    raise RuntimeError("unexpected policysign dispatch call")
                changed = changed.replace(old_call, "do_policy_sign(params, stated_network);")
                cargo = ["cargo", "test", "--locked", "-p", "gnb", "--test", "pqpsbt_cli_preflight", "--", "--nocapture"]
            else:
                changed = replaced(current, baseline[mode], '        "getutxos" => {', '        "sendrawtransaction" => {')
                cargo = ["cargo", "test", "--locked", "-p", "gnb", "--lib",
                         "rpc::audit_2026_10_rpc_tests::pqpsbt_getutxos", "--", "--nocapture"]
            paths[mode].write_text(changed)
            if paths["metadata"].read_bytes().split(b"mod audit_2026_10_rpc_tests {", 1)[1] != rpc_test_suffix:
                raise RuntimeError("RPC tests changed during production-only reversal")
            log_path = args.logs / f"{mode}-reversal.log"
            with log_path.open("wb") as log:
                result = subprocess.run(cargo, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT)
            record["runs"].append({"mode": mode, "returncode": result.returncode, "log": str(log_path),
                                   "reversed_sha256": digest(paths[mode].read_bytes())})
            paths[mode].write_bytes(saved[mode])
            if result.returncode != 101:
                raise RuntimeError(f"expected runtime test failure (101), got {result.returncode}; inspect {log_path}")
            text = log_path.read_text()
            if "test result: FAILED" not in text or "error[E" in text:
                raise RuntimeError(f"not an executed runtime red: inspect {log_path}")
    finally:
        for name, path in paths.items():
            path.write_bytes(saved[name])
        record["restored_source_hashes"] = {name: digest(path.read_bytes()) for name, path in paths.items()}
        record["tests_unchanged"] = all(digest(Path(p).read_bytes()) == h for p, h in test_hashes.items())
        (args.logs / "reversal-manifest.json").write_text(json.dumps(record, indent=2) + "\n")
        print(json.dumps(record, indent=2))
        if not record["tests_unchanged"]:
            raise RuntimeError("test source changed during reversal")


if __name__ == "__main__":
    main()
