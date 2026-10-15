"""One `gnb` node process under test, plus its `gnb-cli`."""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import time

from .authproxy import AuthServiceProxy, JSONRPCException
from .interactive import run_with_answers
from .messages import Block, address_to_script_pubkey, block_from_template
from . import util
from .util import AssertionFailure, tail, wait_until

# Every test node uses this password for wallets created through gnb-cli
# (12+ chars, 3 character classes: wallet::validate_password).
WALLET_PASSWORD = "Functional-Test-Pass-1"


class NodeStartError(RuntimeError):
    pass


class TestNode:
    """A node on loopback with its own data dir, P2P port, RPC port and API key.

    Always `--testnet` (the test-pow-limit build refuses mainnet), RPC bound to
    127.0.0.1 with `--rpc-api-key-file` (mode 0600) and
    `--rpc-require-auth-for-writes`; the RPC proxy presents the key.
    """

    def __init__(self, index: int, datadir: str, *, gnb: str, gnb_cli: str, p2p_port: int,
                 rpc_port: int, api_key: str, carryover: str, log=None, extra_args=None):
        self.index = index
        self.datadir = datadir
        self.gnb = gnb
        self.gnb_cli = gnb_cli
        self.p2p_port = p2p_port
        self.rpc_port = rpc_port
        self.api_key = api_key
        self.carryover = carryover
        self.extra_args = list(extra_args or [])
        self.log = log
        self.process: subprocess.Popen | None = None
        self.stdout_path = os.path.join(datadir, "node.log")
        self.key_file = os.path.join(os.path.dirname(datadir.rstrip("/")), f"node{index}.apikey")
        self.peers: list[str] = []
        self.args_used: list[str] = []
        self._log_handle = None
        self.log_offset = 0
        # Unexpected exits seen by stop(): a node that had already exited (a
        # crash), or that did not stop cleanly on SIGTERM. The framework
        # fails the test with them (GnbTestFramework.shutdown).
        self.problems: list[str] = []
        self.url = f"http://127.0.0.1:{rpc_port}/"
        self.rpc = AuthServiceProxy(self.url, api_key, timeout=60)

    # ── Process control ──────────────────────────────────────────────────

    @property
    def p2p_addr(self) -> str:
        return f"/ip4/127.0.0.1/tcp/{self.p2p_port}"

    def base_args(self) -> list:
        return [
            self.gnb, "--testnet",
            "--data-dir", self.datadir,
            "--carryover-snapshot", self.carryover,
            "--rpc-bind", "127.0.0.1",
            "--rpc-port", str(self.rpc_port),
            "--listen", self.p2p_addr,
            "--rpc-api-key-file", self.key_file,
            "--rpc-require-auth-for-writes",
        ]

    def write_key_file(self) -> None:
        fd = os.open(self.key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(self.api_key + "\n")
        os.chmod(self.key_file, 0o600)

    def start(self, extra_args=None, *, peers=None, mine: bool = False, miner_address: str | None = None,
              env: dict | None = None, wait: bool = True, use_base_args: bool = True) -> None:
        if self.process is not None and self.process.poll() is None:
            raise RuntimeError(f"node{self.index} already running")
        os.makedirs(self.datadir, exist_ok=True)
        self.write_key_file()
        self.peers = list(peers or [])
        args = self.base_args() if use_base_args else [self.gnb]
        for p in self.peers:
            args += ["--peer", p]
        if mine:
            if not miner_address:
                raise ValueError("mine=True needs miner_address")
            args += ["--mine", "--mine-threads", "1", "--miner-address", miner_address]
        args += self.extra_args + list(extra_args or [])
        self.args_used = args
        full_env = dict(os.environ)
        full_env.setdefault("RUST_LOG", "info,libp2p_gossipsub=warn,libp2p_swarm=warn")
        full_env["RUST_BACKTRACE"] = "1"
        if env:
            full_env.update(env)
        self._log_handle = open(self.stdout_path, "ab")
        self.log_offset = self._log_handle.tell()
        self._log_handle.write(f"\n===== start: {' '.join(args)}\n".encode())
        self._log_handle.flush()
        if self.log:
            self.log.debug("node%d start: %s", self.index, " ".join(args))
        # Same process group as the test: test_runner's group kill on timeout
        # reaches the nodes too.
        self.process = subprocess.Popen(args, stdout=self._log_handle, stderr=subprocess.STDOUT,
                                        stdin=subprocess.DEVNULL, env=full_env)
        if wait:
            self.wait_for_rpc_connection()

    def wait_for_rpc_connection(self, timeout: float = 90) -> None:
        deadline = time.monotonic() + timeout * util.TIMEOUT_FACTOR
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise NodeStartError(f"node{self.index} exited with code {self.process.returncode} "
                                     f"during start-up; log tail:\n{tail(self.stdout_path, 30)}")
            try:
                self.rpc.with_key(self.api_key).call("getblockcount")
                return
            except (OSError, JSONRPCException):
                time.sleep(0.2)
        raise NodeStartError(f"node{self.index} RPC not up after {timeout}s; log tail:\n"
                             f"{tail(self.stdout_path, 30)}")

    def is_running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def stop(self, timeout: float = 30, *, expect_exited: bool = False) -> None:
        """SIGTERM (the node has no stop RPC; RocksDB keeps every committed
        write across process termination), then SIGKILL after `timeout`.

        A node that had already exited (unless `expect_exited`: a start-up
        refusal the test waited for), that exits on SIGTERM with a code other
        than the signal's, or that needs SIGKILL, is recorded in `problems`;
        the framework fails the test with it, like Bitcoin Core's framework
        does for an unexpected exit code."""
        if self.process is None:
            return
        rc = self.process.poll()
        if rc is not None:
            if not expect_exited:
                self.problems.append(f"node{self.index} had exited before it was stopped "
                                     f"(exit code {rc}): it crashed or stopped on its own")
        else:
            self.process.send_signal(signal.SIGTERM)
            try:
                rc = self.process.wait(timeout=timeout)
                if rc not in (0, -signal.SIGTERM):
                    self.problems.append(f"node{self.index} exited with code {rc} on SIGTERM")
            except subprocess.TimeoutExpired:
                self.problems.append(f"node{self.index} did not stop within {timeout}s of SIGTERM; killed")
                self.process.kill()
                self.process.wait(timeout=30)
        self.process = None
        if self._log_handle:
            self._log_handle.close()
            self._log_handle = None

    def kill(self) -> None:
        """SIGKILL, deliberately (a crash the test simulates; not a problem)."""
        if self.process is not None and self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=30)
        self.process = None
        if self._log_handle:
            self._log_handle.close()
            self._log_handle = None

    def restart(self, extra_args=None, **kw) -> None:
        peers = kw.pop("peers", self.peers)
        self.stop()
        self.start(extra_args, peers=peers, **kw)

    def run_to_exit(self, args: list, *, timeout: float = 60, env: dict | None = None) -> tuple[int, str]:
        """Run the gnb binary with `args` (no base args) to completion; for
        start-up refusals. Returns (exit code, combined output)."""
        full_env = dict(os.environ)
        if env:
            full_env.update(env)
        p = subprocess.run([self.gnb] + args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           stdin=subprocess.DEVNULL, env=full_env, timeout=timeout * util.TIMEOUT_FACTOR)
        return p.returncode, p.stdout.decode("utf-8", "replace")

    def assert_start_fails(self, extra_args, expected: str, *, code: int | None = None,
                           use_base_args: bool = True, env: dict | None = None,
                           timeout: float = 60) -> str:
        """Start the node and require it to exit on its own with `code` and
        `expected` in its output. Returns the output."""
        self.start(extra_args, wait=False, use_base_args=use_base_args, env=env)
        try:
            self.process.wait(timeout=timeout * util.TIMEOUT_FACTOR)
        except subprocess.TimeoutExpired:
            self.kill()
            raise AssertionFailure(f"node{self.index} did not exit (expected failure {expected!r})")
        rc = self.process.returncode
        self.stop(expect_exited=True)
        out = tail(self.stdout_path, 40)
        if expected not in out:
            raise AssertionFailure(f"expected {expected!r} in node output; got:\n{out}")
        if code is not None and rc != code:
            raise AssertionFailure(f"expected exit code {code}, got {rc}; output:\n{out}")
        return out

    # ── Introspection ────────────────────────────────────────────────────

    def __getattr__(self, name: str):
        # node.getblockcount() → RPC, like Bitcoin Core's TestNode.
        if name.startswith("_") or name == "rpc":
            raise AttributeError(name)
        return getattr(self.rpc, name)

    def log_since_start(self) -> bytes:
        """Log output of the current run only (the log file is appended to
        across restarts)."""
        with open(self.stdout_path, "rb") as f:
            f.seek(self.log_offset)
            return f.read()

    def panics(self) -> list:
        """Panic messages anywhere in this node's log (every run). A panic in
        a spawned task (network, miner, RPC worker, the supervised message
        processor) does not end the process, so only the log shows it."""
        try:
            with open(self.stdout_path, "rb") as f:
                text = f.read().decode("utf-8", "replace")
        except FileNotFoundError:
            return []
        return [line.strip() for line in text.splitlines() if "panicked at" in line]

    def peer_id(self) -> str:
        m = re.findall(rb"P2P identity: (12D3Koo\w+)", self.log_since_start())
        if not m:
            raise RuntimeError(f"node{self.index}: peer id not in log yet")
        return m[-1].decode()

    def sees_peer(self, peer_id: str) -> bool:
        """`peer_id` connected in this run, from the log line the node writes
        on the connection (the RPC peer count says how many distinct peers
        are connected, not which)."""
        return f"✓ connected: {peer_id}".encode() in self.log_since_start()

    def tip(self) -> str:
        return self.rpc.getdaginfo()["tip"]

    def tips(self) -> list:
        """Every DAG tip, including disqualified blocks the node keeps (DAG-1)."""
        return sorted(self.rpc.getdaginfo()["tips"])

    def valid_tips(self) -> list:
        """The tips a block would build on: getblocktemplate's parents
        (bodied, not disqualified; at most MAX_PARENTS)."""
        return sorted(self.rpc.getblocktemplate()["parents"])

    def height(self) -> int:
        return int(self.rpc.getdaginfo()["tip_height"])

    def mempool(self) -> list:
        return sorted(self.rpc.getrawmempool()["txids"])

    def has_block(self, block_hash: str) -> bool:
        try:
            self.rpc.getblock(block_hash)
            return True
        except JSONRPCException:
            return False

    def log_contains(self, text: str, this_run: bool = True) -> bool:
        if this_run:
            return text.encode() in self.log_since_start()
        with open(self.stdout_path, "rb") as f:
            return text.encode() in f.read()

    # ── Mining through getblocktemplate / submitblock ────────────────────

    # The node serves a cached getblocktemplate while the template's parents
    # and height are unchanged and rebuilds it for a mempool change at most
    # this often (node/src/rpc/mod.rs TEMPLATE_CACHE_TTL, as Bitcoin Core's 5 s).
    TEMPLATE_CACHE_TTL = 5

    def get_template(self) -> dict:
        return self.rpc.getblocktemplate()

    def fresh_template(self) -> dict:
        """A template that offers every transaction now in the mempool, as
        a block mined "now" would. Right after a transaction arrives the
        cached template can lack it for up to TEMPLATE_CACHE_TTL; poll until
        it is offered, or until the cache has turned over once (then the
        node's template is the answer, whatever it leaves out)."""
        deadline = time.monotonic() + self.TEMPLATE_CACHE_TTL + 1
        while True:
            pool = set(self.mempool())
            tmpl = self.get_template()
            if pool <= {t["txid"] for t in tmpl["transactions"]} or time.monotonic() >= deadline:
                return tmpl
            time.sleep(0.25)

    def submit_block(self, block: Block, *, max_nonces: int = 32) -> str:
        """Submit `block`, searching nonces from block.nonce upward while the
        node answers "invalid PoW". Under test-pow-limit the target is about
        (1 - 2^-16) * 2^256, so the first nonce is almost always valid; the
        node computes GnB-SMH, the test never has to. Returns the block hash.
        Any other rejection raises JSONRPCException."""
        for _ in range(max_nonces):
            try:
                res = self.rpc.submitblock(block.serialize().hex())
            except JSONRPCException as e:
                if "invalid PoW" in e.message or "proof of work" in e.message:
                    block.nonce += 1
                    continue
                raise
            if res.get("hash") != block.hash_hex():
                raise AssertionFailure(f"submitblock hash {res.get('hash')} != {block.hash_hex()}")
            return res["hash"]
        raise AssertionFailure(f"no valid nonce in {max_nonces} tries (is this a test-pow-limit build?)")

    def generate(self, n: int, address: str, *, extra: bytes = b"") -> list:
        """Mine `n` blocks paying `address`, one getblocktemplate + submitblock
        each, waiting for every block to become the selected tip (no
        background miner involved: deterministic). Each block includes the
        mempool as it is when the block is mined (`fresh_template`)."""
        spk = address_to_script_pubkey(address)
        hashes = []
        for _ in range(n):
            tmpl = self.fresh_template()
            block = block_from_template(tmpl, spk, extra=extra)
            h = self.submit_block(block)
            hashes.append(h)
            wait_until(lambda: self.tip() == h, timeout=30, desc=f"node{self.index} tip == {h[:16]}")
        return hashes

    # ── gnb-cli ──────────────────────────────────────────────────────────

    def cli_env(self, with_key: bool = True) -> dict:
        env = dict(os.environ)
        env.pop("GNB_RPC_API_KEY", None)
        if with_key:
            env["GNB_RPC_API_KEY"] = self.api_key
        return env

    def cli(self, *args, with_key: bool = True, timeout: float = 60) -> subprocess.CompletedProcess:
        argv = [self.gnb_cli, "--rpc-port", str(self.rpc_port)] + [str(a) for a in args]
        return subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                              env=self.cli_env(with_key), timeout=timeout * util.TIMEOUT_FACTOR, text=True)

    def cli_json(self, *args, **kw):
        p = self.cli(*args, **kw)
        if p.returncode != 0:
            raise AssertionFailure(f"gnb-cli {' '.join(map(str, args))} failed ({p.returncode}): {p.stderr}")
        return json.loads(p.stdout)

    def cli_new_wallet(self, path: str) -> str:
        """`gnb-cli --testnet newwallet <path> --random-key` on a terminal;
        returns the wallet's address."""
        argv = [self.gnb_cli, "--testnet", "newwallet", path, "--random-key"]
        code, out = run_with_answers(argv, [("Set password", WALLET_PASSWORD),
                                            ("Confirm password", WALLET_PASSWORD)],
                                     env=self.cli_env(False), timeout=120 * util.TIMEOUT_FACTOR)
        m = re.search(r"Address:\s+(gnb1t[0-9a-f]{48})", out)
        if code != 0 or not m:
            raise AssertionFailure(f"newwallet failed ({code}):\n{out}")
        return m.group(1)

    def cli_send(self, wallet: str, to: str, amount_gnb: str, *extra) -> str:
        """`gnb-cli send <wallet> <to> <amount> --yes` on a terminal (the
        password is typed at the prompt). Returns the txid."""
        argv = [self.gnb_cli, "--rpc-port", str(self.rpc_port), "send", wallet, to, amount_gnb, "--yes",
                *extra]
        code, out = run_with_answers(argv, [("Wallet password", WALLET_PASSWORD)],
                                     env=self.cli_env(True), timeout=120 * util.TIMEOUT_FACTOR)
        m = re.search(r"Broadcast OK: ([0-9a-f]{64})", out)
        if code != 0 or not m:
            raise AssertionFailure(f"gnb-cli send failed ({code}):\n{out}")
        return m.group(1)
