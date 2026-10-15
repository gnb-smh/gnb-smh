"""Base class for GnB functional tests (in the style of Bitcoin Core's
test_framework.BitcoinTestFramework).

A test subclasses GnbTestFramework, sets `num_nodes` (and optionally
`setup_clean_chain`, `extra_args`) in `set_test_params()`, and implements
`run_test()`. `main()` then:

  1. resolves the binaries (cargo build of the test-pow-limit feature, or
     --bindir) and verifies they are a test build that refuses mainnet;
  2. prepares cached start states (carryover, genesis data dir, a mined chain
     with a funded gnb-cli wallet) and copies one per node into a fresh temp
     dir;
  3. starts the nodes on loopback with separate data dirs, ports and API keys,
     and connects them (`setup_network`; default: node i dials nodes 0..i-1);
  4. runs the test; on failure prints the tail of every node's log;
  5. always stops every node process and removes the temp dir (kept with
     --nocleanup, or with --keep-failed when the test failed).

Exit codes: 0 passed, 1 failed, 77 skipped (as Bitcoin Core).
"""

from __future__ import annotations

import argparse
import logging
import os
import shutil
import signal
import sys
import tempfile
import time
import traceback

from . import binaries, util
from .cache import Cache, copy_datadir
from .node import TestNode
from .util import PortAllocator, assert_equal, tail, wait_until

TEST_EXIT_PASSED = 0
TEST_EXIT_FAILED = 1
TEST_EXIT_SKIPPED = 77


class SkipTest(Exception):
    pass


class _Terminated(BaseException):
    """SIGTERM/SIGINT from test_runner's timeout or the user: unwind through
    the cleanup path."""


def _on_signal(signum, _frame):
    raise _Terminated(f"signal {signum}")


class GnbTestFramework:
    def __init__(self):
        self.num_nodes = 1
        self.setup_clean_chain = False
        self.extra_args: list | None = None
        self.nodes: list[TestNode] = []
        self.chain_info: dict = {}
        self.options = None
        self.log = logging.getLogger(type(self).__name__)

    # ── To override ──────────────────────────────────────────────────────

    def set_test_params(self) -> None:
        raise NotImplementedError

    def run_test(self) -> None:
        raise NotImplementedError

    def setup_network(self) -> None:
        """Start every node; node i dials nodes 0..i-1 (full mesh on loopback)."""
        for i, node in enumerate(self.nodes):
            node.start(peers=[self.nodes[j].p2p_addr for j in range(i)])
        self.wait_for_peers()

    # ── Driver ───────────────────────────────────────────────────────────

    def add_options(self, parser: argparse.ArgumentParser) -> None:
        pass

    def parse_args(self) -> None:
        here = os.path.dirname(os.path.abspath(__file__))
        p = argparse.ArgumentParser(description=(self.__doc__ or "").strip().splitlines()[0]
                                    if self.__doc__ else None)
        p.add_argument("--bindir", help="directory with test-pow-limit gnb and gnb-cli "
                                        "(default: $GNB_BINDIR, else cargo build)")
        p.add_argument("--no-build", action="store_true",
                       help="do not run cargo; use $CARGO_TARGET_DIR/debug (or target/debug)")
        p.add_argument("--srcdir", default=os.path.abspath(os.path.join(here, "..", "..", "..")),
                       help="repository root (default: %(default)s)")
        p.add_argument("--cachedir", default=os.environ.get("GNB_FUNCTIONAL_CACHE") or
                       os.path.join(tempfile.gettempdir(), f"gnb-functional-cache-{os.getuid()}"),
                       help="shared cache for binaries snapshots and start states (default: %(default)s)")
        p.add_argument("--tmpdir", help="root for this test's temp dir (default: system temp)")
        p.add_argument("--nocleanup", action="store_true", help="leave the temp dir and its logs")
        p.add_argument("--keep-failed", action="store_true", help="leave the temp dir if the test fails")
        p.add_argument("--portseed", type=int, default=os.getpid(), help="port window seed (test_runner sets it)")
        p.add_argument("--timeout-factor", type=float, default=1.0, help="scale every timeout")
        p.add_argument("--loglevel", default="INFO")
        self.add_options(p)
        self.options = p.parse_args()

    def main(self) -> None:
        self.parse_args()
        logging.basicConfig(level=self.options.loglevel.upper(), stream=sys.stdout,
                            format="%(asctime)s.%(msecs)03d %(name)s %(levelname)s %(message)s",
                            datefmt="%H:%M:%S")
        util.TIMEOUT_FACTOR = self.options.timeout_factor
        signal.signal(signal.SIGTERM, _on_signal)
        signal.signal(signal.SIGINT, _on_signal)
        self.set_test_params()

        root = self.options.tmpdir or None
        if root:
            os.makedirs(root, exist_ok=True)
        self.tmpdir = tempfile.mkdtemp(prefix=f"{type(self).__name__}-", dir=root)
        self.log.info("temp dir: %s", self.tmpdir)
        self.ports = PortAllocator(self.options.portseed)

        status = TEST_EXIT_FAILED
        started = time.monotonic()
        try:
            os.makedirs(self.options.cachedir, exist_ok=True)
            self.binaries = binaries.resolve(self.options.bindir, not self.options.no_build,
                                             self.options.cachedir, self.log)
            self.cache = Cache(self.options.cachedir, self.binaries, self.options.srcdir, self.log)
            self.cache.ensure_carryover()
            self.setup_nodes()
            self.setup_network()
            self.run_test()
            status = TEST_EXIT_PASSED
        except SkipTest as e:
            self.log.warning("skipped: %s", e)
            status = TEST_EXIT_SKIPPED
        except _Terminated as e:
            self.log.error("terminated (%s)", e)
        except BaseException:  # noqa: BLE001 - every failure is reported
            self.log.error("test failed:\n%s", traceback.format_exc())
        finally:
            if status == TEST_EXIT_FAILED:
                self.dump_logs()
            self.shutdown()
            if self.options.nocleanup or (self.options.keep_failed and status == TEST_EXIT_FAILED):
                self.log.info("not cleaning up %s", self.tmpdir)
            else:
                shutil.rmtree(self.tmpdir, ignore_errors=True)
        self.log.info("%s in %.1fs", {0: "PASSED", 1: "FAILED", 77: "SKIPPED"}[status],
                      time.monotonic() - started)
        logging.shutdown()
        sys.exit(status)

    # ── Nodes ────────────────────────────────────────────────────────────

    def add_node(self, index: int, extra_args=None) -> TestNode:
        node = TestNode(index, os.path.join(self.tmpdir, f"node{index}"),
                        gnb=self.binaries["gnb"], gnb_cli=self.binaries["gnb-cli"],
                        p2p_port=self.ports.get(), rpc_port=self.ports.get(),
                        api_key=f"functional-node{index}-{os.urandom(12).hex()}",
                        carryover=self.cache.carryover, log=self.log, extra_args=extra_args)
        return node

    def setup_nodes(self) -> None:
        start_dir = (self.cache.base_dir(self.ports) if self.setup_clean_chain
                     else self.cache.chain_dir(self.ports))
        if not self.setup_clean_chain:
            self.chain_info = Cache.chain_info(start_dir)
        for i in range(self.num_nodes):
            args = self.extra_args[i] if self.extra_args else None
            node = self.add_node(i, args)
            copy_datadir(start_dir, node.datadir)
            self.nodes.append(node)

    def shutdown(self) -> None:
        for node in self.nodes:
            try:
                node.stop(timeout=15)
            except Exception as e:  # noqa: BLE001
                self.log.error("stopping node%d: %r", node.index, e)
                node.kill()

    def dump_logs(self, lines: int = 80) -> None:
        """Tail of every node's log, without the per-request RPC trace lines
        (the test's own polling would crowd everything else out)."""
        for node in self.nodes:
            text = "\n".join(l for l in tail(node.stdout_path, 2000).splitlines() if "rpc_request;" not in l)
            print(f"\n----- node{node.index} log tail ({node.stdout_path}) -----\n"
                  + "\n".join(text.splitlines()[-lines:]), flush=True)

    def wallet_copy(self, name: str = "wallet.json") -> str:
        """A private copy of the cache wallet (gnb-cli keystore, funded with
        mature coinbase outputs on the cached chain)."""
        dst = os.path.join(self.tmpdir, name)
        shutil.copy2(self.chain_info["wallet"], dst)
        return dst

    # ── Synchronisation helpers ──────────────────────────────────────────

    def wait_for_peers(self, nodes=None, pairs=None, timeout: float = 60) -> None:
        """Wait until every pair (default: all pairs of `nodes`) is connected
        both ways, from the nodes' logs (the RPC peer count lags by up to the
        30 s network heartbeat), then give gossipsub two of its 1 s heartbeats
        to exchange subscriptions and graft the mesh."""
        nodes = nodes or self.nodes
        if pairs is None:
            pairs = [(a, b) for i, a in enumerate(nodes) for b in nodes[i + 1:]]
        for a, b in pairs:
            for x, y in ((a, b), (b, a)):
                pid = y.peer_id()
                wait_until(lambda x=x, pid=pid: x.sees_peer(pid), timeout=timeout,
                           desc=f"node{x.index} connected to node{y.index} ({pid[:16]}...)")
        if pairs:
            time.sleep(2)

    def sync_blocks(self, nodes=None, timeout: float = 90) -> None:
        """Wait until every node has the same selected tip and the same valid
        tips (template parents). Disqualified blocks a node keeps in its DAG
        (DAG-1) are not compared: only the node that saw one has it."""
        nodes = nodes or self.nodes

        def same():
            views = [(n.tip(), tuple(n.valid_tips())) for n in nodes]
            return all(v == views[0] for v in views)
        wait_until(same, timeout=timeout, desc="nodes agree on tip and valid tips")

    def sync_mempools(self, nodes=None, timeout: float = 60) -> None:
        nodes = nodes or self.nodes

        def same():
            pools = [n.mempool() for n in nodes]
            return all(p == pools[0] for p in pools)
        wait_until(same, timeout=timeout, desc="mempools agree")

    def sync_all(self, nodes=None) -> None:
        self.sync_blocks(nodes)
        self.sync_mempools(nodes)

    def assert_same_chain_state(self, addresses, nodes=None) -> None:
        """Same selected tip, valid tips, height, blue work and UTXO set for
        `addresses` (txid, index, value of every output) on every node — the
        closest the RPC surface comes to a UTXO digest."""
        nodes = nodes or self.nodes
        ref = None
        for n in nodes:
            info = n.getdaginfo()
            utxos = {}
            for a in addresses:
                r = n.getutxos(a, 10_000)
                assert not r["truncated"], r
                utxos[a] = sorted((u["txid"], u["index"], u["value"]) for u in r["utxos"])
            view = (info["tip"], tuple(n.valid_tips()), info["tip_height"], info["tip_blue_work"], utxos)
            if ref is None:
                ref = view
            else:
                assert_equal(view, ref, f"node{n.index} chain state differs from node{nodes[0].index}")
