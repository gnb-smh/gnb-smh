"""Tests for gnb_explorer_api.py (audit WAL-2, WAL-4). Standard library only:

    python3 -m unittest deploy/explorer-api/test_gnb_explorer_api.py
"""

import http.client
import importlib.util
import json
import os
import re
import socket
import stat
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("gnb_explorer_api", os.path.join(HERE, "gnb_explorer_api.py"))
api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api)

KEY = "k" * 40


class ApiServer:
    def __init__(self, max_connections=4, timeout=1.0, deadline=2.0):
        api.API_KEY = KEY.encode()
        api.Handler.timeout = timeout
        api.Handler.deadline = deadline
        api.rpc = lambda method, params: {"result": {"method": method, "params": params}}
        self.httpd = api.make_server("127.0.0.1", 0, max_connections)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def get(self, path, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", path, headers={"x-gnb-key": KEY, **(headers or {})})
        r = conn.getresponse()
        body = r.read()
        conn.close()
        return r.status, json.loads(body) if body else None


class ExplorerApiTests(unittest.TestCase):
    def setUp(self):
        api._cache.clear()
        api.GET_LIMIT = api.RateLimiter(1000)
        api.POST_LIMIT = api.RateLimiter(1000)
        self.server = ApiServer()

    def tearDown(self):
        self.server.close()

    def test_requires_the_shared_key(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.port, timeout=5)
        conn.request("GET", "/v1/getblockcount", headers={"x-gnb-key": "wrong"})
        self.assertEqual(conn.getresponse().status, 403)
        conn.close()
        status, doc = self.server.get("/v1/getblockcount")
        self.assertEqual(status, 200)
        self.assertEqual(doc["result"]["method"], "getblockcount")

    def test_getrawtransaction_is_allowed_with_a_hash_only(self):
        status, _ = self.server.get('/v1/getrawtransaction?p=["' + "ab" * 32 + '"]')
        self.assertEqual(status, 200)
        status, _ = self.server.get('/v1/getrawtransaction?p=["<script>"]')
        self.assertEqual(status, 400)
        status, _ = self.server.get("/v1/getdifficultyhistory?p=[500]")
        self.assertEqual(status, 400, "the node caps difficulty history at 100")

    def test_allow_list_matches_the_node_rpc(self):
        """Audit P4 / NET-12: every allowed method exists in the node's RPC
        dispatcher (KNOWN_RPC_METHODS), the Worker's cache table names no
        method the API does not serve, and the rich-list offset bound is the
        node's MAX_RICHLIST_OFFSET."""
        root = os.path.dirname(os.path.dirname(HERE))
        with open(os.path.join(root, "node", "src", "rpc", "mod.rs"), encoding="utf-8") as fh:
            src = fh.read()
        block = src[src.index("const KNOWN_RPC_METHODS"):]
        block = block[:block.index("];")]
        known = set(re.findall(r'"([a-z_]+)"', block))
        self.assertTrue(set(api.ALLOWED) <= known, sorted(set(api.ALLOWED) - known))
        with open(os.path.join(root, "worker", "index.js"), encoding="utf-8") as fh:
            worker = fh.read()
        ttl = worker[worker.index("const TTL = {"):]
        ttl = ttl[:ttl.index("};")]
        cached = set(re.findall(r"([a-z]+):\s*\d+", ttl))
        self.assertTrue(cached <= set(api.ALLOWED) | {"carryover"}, sorted(cached - set(api.ALLOWED)))
        with open(os.path.join(root, "node", "src", "analytics", "mod.rs"), encoding="utf-8") as fh:
            m = re.search(r"pub const MAX_RICHLIST_OFFSET: usize = ([0-9_]+);", fh.read())
        node_max = int(m.group(1).replace("_", ""))
        self.assertEqual(api.ALLOWED["getrichlist"][0][1](node_max), node_max)
        with self.assertRaises(ValueError):
            api.ALLOWED["getrichlist"][0][1](node_max + 1)
        status, _ = self.server.get("/v1/getrichlist?p=[100,10001]")
        self.assertEqual(status, 400)

    def test_idle_connection_is_closed_by_the_handler_timeout(self):
        s = socket.create_connection(("127.0.0.1", self.server.port), timeout=10)
        start = time.monotonic()
        data = s.recv(1024)  # send nothing: the server must hang up
        elapsed = time.monotonic() - start
        s.close()
        self.assertEqual(data, b"")
        self.assertLess(elapsed, 5)

    def test_slow_drip_client_hits_the_absolute_deadline(self):
        s = socket.create_connection(("127.0.0.1", self.server.port), timeout=10)
        start = time.monotonic()
        s.sendall(b"GET /v1/getblockcount HTTP/1.1\r\n")
        closed = False
        while time.monotonic() - start < 8:
            try:
                s.sendall(b"x-drip: 1\r\n")
            except OSError:
                closed = True
                break
            time.sleep(0.5)
            s.setblocking(False)
            try:
                if s.recv(1024) == b"":
                    closed = True
                    break
            except BlockingIOError:
                pass
            finally:
                s.setblocking(True)
        s.close()
        self.assertTrue(closed, "a dripping client must be cut off at the deadline")
        self.assertLess(time.monotonic() - start, 6)

    def test_connections_beyond_the_cap_are_refused(self):
        idle = [socket.create_connection(("127.0.0.1", self.server.port), timeout=5) for _ in range(4)]
        time.sleep(0.2)
        extra = socket.create_connection(("127.0.0.1", self.server.port), timeout=5)
        reply = extra.recv(1024)
        self.assertTrue(reply.startswith(b"HTTP/1.1 503"), reply)
        extra.close()
        for s in idle:
            s.close()
        time.sleep(1.5)  # slots are released once the idle sockets are gone
        status, _ = self.server.get("/v1/getblockcount")
        self.assertEqual(status, 200)

    def test_rate_limit_is_per_original_client(self):
        api.GET_LIMIT = api.RateLimiter(2)
        a = {"x-gnb-client-ip": "198.51.100.7"}
        b = {"x-gnb-client-ip": "203.0.113.9"}
        self.assertEqual(self.server.get("/v1/getblockcount", a)[0], 200)
        self.assertEqual(self.server.get("/v1/getblockcount", a)[0], 200)
        self.assertEqual(self.server.get("/v1/getblockcount", a)[0], 429)
        self.assertEqual(self.server.get("/v1/getblockcount", b)[0], 200)

    def test_node_errors_are_not_cached(self):
        # A cancelled heavy read on the node is an error; the next caller
        # must get a fresh computation, not the cached failure.
        answers = [{"error": "cancelled"}, {"result": {"sample_size": 10}}]
        api.rpc = lambda method, params: answers.pop(0)
        status, body = self.server.get("/v1/getblocktimepercentiles")
        self.assertEqual((status, body), (404, {"error": "cancelled"}))
        status, body = self.server.get("/v1/getblocktimepercentiles")
        self.assertEqual((status, body), (200, {"result": {"sample_size": 10}}))
        self.assertEqual(self.server.get("/v1/getblocktimepercentiles")[1], {"result": {"sample_size": 10}}, "successes are cached")

    def test_default_bind_is_loopback_and_key_file_mode_is_checked(self):
        with open(os.path.join(HERE, "gnb-explorer-api.service"), encoding="utf-8") as fh:
            self.assertIn("Environment=GNB_API_BIND=127.0.0.1", fh.read())
        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            fh.write(KEY + "\n")
        try:
            os.chmod(fh.name, 0o600)
            self.assertEqual(api.load_api_key(fh.name), KEY.encode())
            os.chmod(fh.name, 0o644)
            with self.assertRaises(SystemExit):
                api.load_api_key(fh.name)
        finally:
            os.unlink(fh.name)


if __name__ == "__main__":
    unittest.main()
