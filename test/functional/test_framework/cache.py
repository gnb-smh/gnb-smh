"""Shared, reusable start states for test nodes (built once per binary).

* `carryover.tsv`: the genesis carryover snapshot, decompressed once.
* `base`: a data dir right after first boot (genesis + carryover ledger
  ingested, ~8 s and 55 MB to build). Tests with `setup_clean_chain = True`
  start every node from a copy of it.
* `chain`: `base` plus CHAIN_BLOCKS blocks mined through getblocktemplate /
  submitblock: the first WALLET_BLOCKS pay the cache wallet (a gnb-cli
  wallet, file + password kept next to the data), the rest pay a filler
  address, so all of the wallet's coinbase outputs are mature (depth >= 100)
  at the tip. Tests that need spendable coins start from it.

Every cached data dir is keyed by the binary digest, contains only `db/`
(each node creates its own P2P identity), and is published atomically; a lock
file serialises concurrent builders (test_runner builds it before running
tests in parallel).
"""

from __future__ import annotations

import fcntl
import gzip
import hashlib
import json
import os
import shutil
import tempfile

from .messages import hash_to_address
from .node import TestNode
from .util import PortAllocator

WALLET_BLOCKS = 10
FILLER_BLOCKS = 100           # core::COINBASE_MATURITY
CHAIN_BLOCKS = WALLET_BLOCKS + FILLER_BLOCKS
FILLER_ADDRESS = hash_to_address(hashlib.sha256(b"gnb-functional/filler").digest()[:20])
CACHE_API_KEY = "cache-builder-key-0123456789abcdef"


class _Lock:
    def __init__(self, path: str):
        self.path = path

    def __enter__(self):
        self.f = open(self.path, "a+")
        fcntl.flock(self.f, fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        fcntl.flock(self.f, fcntl.LOCK_UN)
        self.f.close()


def copy_datadir(src: str, dst: str) -> None:
    """Copy a node data dir's `db/`. RocksDB never rewrites an .sst file, so
    those are hard-linked (fallback: copy); everything else is copied."""
    def _copy(s, d):
        if s.endswith(".sst"):
            try:
                os.link(s, d)
                return d
            except OSError:
                pass
        return shutil.copy2(s, d)
    os.makedirs(dst, exist_ok=True)
    shutil.copytree(os.path.join(src, "db"), os.path.join(dst, "db"), copy_function=_copy)


class Cache:
    def __init__(self, cachedir: str, binaries: dict, srcdir: str, log):
        self.dir = cachedir
        self.bin = binaries
        self.srcdir = srcdir
        self.log = log
        self.data = os.path.join(cachedir, f"data-{binaries['digest']}")
        os.makedirs(self.data, exist_ok=True)

    # ── carryover ────────────────────────────────────────────────────────

    @property
    def carryover(self) -> str:
        return os.path.join(self.dir, "carryover.tsv")

    def ensure_carryover(self) -> str:
        with _Lock(os.path.join(self.dir, ".lock-carryover")):
            if not os.path.exists(self.carryover):
                src = os.path.join(self.srcdir, "genesis", "bloch-g3-carryover.tsv.gz")
                tmp = self.carryover + ".tmp"
                with gzip.open(src, "rb") as f, open(tmp, "wb") as o:
                    shutil.copyfileobj(f, o)
                os.rename(tmp, self.carryover)
        return self.carryover

    # ── data dirs ────────────────────────────────────────────────────────

    def _node(self, workdir: str, name: str, ports: PortAllocator) -> TestNode:
        return TestNode(0, os.path.join(workdir, name), gnb=self.bin["gnb"], gnb_cli=self.bin["gnb-cli"],
                        p2p_port=ports.get(), rpc_port=ports.get(), api_key=CACHE_API_KEY,
                        carryover=self.carryover, log=self.log)

    def _publish(self, workdir_datadir: str, name: str, extra_files=()) -> None:
        tmp = tempfile.mkdtemp(prefix=f"{name}-", dir=self.data)
        copy_datadir(workdir_datadir, tmp)
        for f in extra_files:
            shutil.copy2(f, tmp)
        os.rename(tmp, os.path.join(self.data, name))

    def base_dir(self, ports: PortAllocator) -> str:
        path = os.path.join(self.data, "base")
        with _Lock(os.path.join(self.data, ".lock")):
            if not os.path.isdir(path):
                self.ensure_carryover()
                work = tempfile.mkdtemp(prefix="build-base-", dir=self.data)
                try:
                    self.log.info("cache: building base data dir (genesis + carryover)")
                    node = self._node(work, "n", ports)
                    try:
                        node.start()
                        assert node.getblockcount() == 1, "fresh node must hold exactly the genesis"
                    finally:
                        node.stop()
                    self._publish(node.datadir, "base")
                finally:
                    shutil.rmtree(work, ignore_errors=True)
        return path

    def chain_dir(self, ports: PortAllocator) -> str:
        path = os.path.join(self.data, "chain")
        base = self.base_dir(ports)
        with _Lock(os.path.join(self.data, ".lock")):
            if not os.path.isdir(path):
                work = tempfile.mkdtemp(prefix="build-chain-", dir=self.data)
                try:
                    self.log.info("cache: mining %d blocks (%d to the cache wallet)", CHAIN_BLOCKS, WALLET_BLOCKS)
                    node = self._node(work, "n", ports)
                    copy_datadir(base, node.datadir)
                    wallet = os.path.join(work, "wallet.json")
                    try:
                        node.start()
                        address = node.cli_new_wallet(wallet)
                        node.generate(WALLET_BLOCKS, address)
                        node.generate(FILLER_BLOCKS, FILLER_ADDRESS)
                        info = node.getdaginfo()
                        assert info["tip_height"] == CHAIN_BLOCKS, info
                    finally:
                        node.stop()
                    meta = os.path.join(work, "chain.json")
                    with open(meta, "w") as f:
                        json.dump({"wallet_address": address, "tip": info["tip"],
                                   "height": info["tip_height"]}, f)
                    self._publish(node.datadir, "chain", extra_files=(wallet, meta))
                finally:
                    shutil.rmtree(work, ignore_errors=True)
        return path

    @staticmethod
    def chain_info(chain_dir: str) -> dict:
        with open(os.path.join(chain_dir, "chain.json")) as f:
            info = json.load(f)
        info["wallet"] = os.path.join(chain_dir, "wallet.json")
        return info
