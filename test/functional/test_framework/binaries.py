"""Build or locate the test-only `gnb` / `gnb-cli` binaries.

The functional tests need a build with the node's `test-pow-limit` feature
(every expected target is the pow limit: about one GnB-SMH evaluation per
block). Such a binary refuses to start on mainnet; `verify_test_build` checks
exactly that, so a production binary can never be mistaken for a test one
(and a test binary that would run on mainnet fails the suite).
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
BUILD_FEATURE = "test-pow-limit"
BIN_NAMES = ("gnb", "gnb-cli")
GUARD_MESSAGE = "refuses to run on mainnet"


class BinaryError(RuntimeError):
    pass


def cargo_build(log=None) -> dict:
    """`cargo build -p gnb --features test-pow-limit --bin gnb --bin gnb-cli
    --locked`; returns {name: executable path} from cargo's own JSON report
    (correct for any CARGO_TARGET_DIR)."""
    cmd = ["cargo", "build", "-p", "gnb", "--features", BUILD_FEATURE, "--locked",
           "--message-format=json-render-diagnostics"]
    for name in BIN_NAMES:
        cmd += ["--bin", name]
    if log:
        log.info("building test binaries: %s", " ".join(cmd))
    p = subprocess.run(cmd, cwd=REPO_ROOT, stdout=subprocess.PIPE, text=True)
    if p.returncode != 0:
        raise BinaryError(f"cargo build failed with code {p.returncode}")
    found = {}
    for line in p.stdout.splitlines():
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if msg.get("reason") == "compiler-artifact" and msg.get("executable"):
            name = msg["target"]["name"]
            if name in BIN_NAMES:
                found[name] = msg["executable"]
    missing = [n for n in BIN_NAMES if n not in found]
    if missing:
        raise BinaryError(f"cargo did not report executables for {missing}")
    return found


def default_bindir() -> str:
    target = os.environ.get("CARGO_TARGET_DIR") or os.path.join(REPO_ROOT, "target")
    return os.path.join(target, "debug")


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def snapshot(paths: dict, destdir: str) -> dict:
    """Copy the binaries into `destdir/<hash>/` so a concurrent rebuild of the
    cargo target dir cannot swap them under a running suite."""
    digest = hashlib.sha256("".join(sha256_file(paths[n]) for n in BIN_NAMES).encode()).hexdigest()[:16]
    out_dir = os.path.join(destdir, f"bin-{digest}")
    out = {n: os.path.join(out_dir, n) for n in BIN_NAMES}
    if not all(os.path.exists(p) for p in out.values()):
        os.makedirs(destdir, exist_ok=True)
        tmp = tempfile.mkdtemp(prefix="bin-", dir=destdir)
        for n in BIN_NAMES:
            shutil.copy2(paths[n], os.path.join(tmp, n))
        try:
            os.rename(tmp, out_dir)
        except OSError:  # a concurrent snapshot won the race
            shutil.rmtree(tmp, ignore_errors=True)
    out["digest"] = digest
    return out


def verify_test_build(gnb: str, workdir: str) -> None:
    """A test-pow-limit build exits with code 2 and the guard message when
    started without --testnet, before touching the data dir."""
    probe = tempfile.mkdtemp(prefix="guard-probe-", dir=workdir)
    try:
        p = subprocess.run([gnb, "--data-dir", os.path.join(probe, "d")], stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, timeout=60)
        out = p.stdout.decode("utf-8", "replace")
        if p.returncode != 2 or GUARD_MESSAGE not in out:
            raise BinaryError(
                f"{gnb} is not a {BUILD_FEATURE} build (mainnet probe exited {p.returncode}: "
                f"{out.strip()[:300]!r}). Build it with: cargo build -p gnb --features {BUILD_FEATURE} "
                f"--bin gnb --bin gnb-cli")
        if os.path.exists(os.path.join(probe, "d")):
            raise BinaryError(f"{gnb}: the mainnet refusal created the data dir; the guard must run first")
    finally:
        shutil.rmtree(probe, ignore_errors=True)


def resolve(bindir: str | None, build: bool, cachedir: str, log=None) -> dict:
    """{'gnb': path, 'gnb-cli': path, 'digest': ...}: from `bindir` (or
    $GNB_BINDIR), else from a cargo build (when `build`), else from the cargo
    target dir; snapshotted into `cachedir` and verified."""
    bindir = bindir or os.environ.get("GNB_BINDIR")
    if bindir:
        paths = {n: os.path.join(bindir, n) for n in BIN_NAMES}
    elif build:
        paths = cargo_build(log)
    else:
        d = default_bindir()
        paths = {n: os.path.join(d, n) for n in BIN_NAMES}
    for n, p in paths.items():
        if not os.path.isfile(p) or not os.access(p, os.X_OK):
            raise BinaryError(f"{n} not found at {p}")
    snap = snapshot(paths, cachedir)
    verify_test_build(snap["gnb"], cachedir)
    return snap
