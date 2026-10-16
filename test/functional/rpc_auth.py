#!/usr/bin/env python3
"""RPC authentication: write methods are refused without the API key.

Nodes run with --rpc-api-key-file (mode 0600) and
--rpc-require-auth-for-writes, loopback NOT trusted (the default). node1 is
not connected to node0, so nothing reaches it except through its own RPC.

* Reads work without a key; a wrong key is refused even for reads.
* getblocktemplate, submitblock and sendrawtransaction (auth::WRITE_METHODS)
  without a key, or with a wrong one, answer HTTP 401 / -32001 and have no
  effect (tip and mempool unchanged); a failed key is answered slowly.
* The right key works as X-API-Key and as `Authorization: Bearer`.
* A browser Origin, or a foreign Host header, is refused (403 / -32003) even
  with the key; a batch request is refused (400 / -32600).
* gnb-cli sends GNB_RPC_API_KEY only when set; without it writes fail.
* GNB_RPC_REQUIRE_AUTH_FOR_READS=1 makes reads need the key too.
* Start-up refuses: auth required without a key, a group/world-accessible or
  empty key file; a too-short key keeps the RPC service down.
"""

import json
import os
import socket
import time
import urllib.error
import urllib.request

from test_framework.messages import address_to_script_pubkey, block_from_template, hash_to_address
from test_framework.test_framework import GnbTestFramework
from test_framework.util import assert_equal, assert_greater_than, assert_in, assert_true, wait_until

ADDR = hash_to_address(bytes(range(70, 90)))


def expect_status(proxy, method, params, status, code):
    st, body = proxy.raw(method, params)
    assert_equal(st, status, f"{method}: {body}")
    assert_equal(body["error"]["code"], code, f"{method}: {body}")
    return body


class RpcAuthTest(GnbTestFramework):
    def set_test_params(self):
        self.num_nodes = 2

    def setup_network(self):
        for n in self.nodes:
            n.start()  # not connected: node1 only learns things through its RPC

    def run_test(self):
        n0, n1 = self.nodes
        anon = n1.rpc.with_key(None)
        wrong = n1.rpc.with_key("wrong-key-0123456789abcdef")
        tip = n1.tip()

        self.log.info("reads need no key; a wrong key is refused even for reads")
        assert_equal(anon.getblockcount(), n1.getblockcount())
        expect_status(wrong, "getblockcount", None, 401, -32001)

        self.log.info("write methods without a key, or with a wrong one: 401 and no effect")
        expect_status(anon, "getblocktemplate", None, 401, -32001)
        block = block_from_template(n1.getblocktemplate(), address_to_script_pubkey(ADDR))
        expect_status(anon, "submitblock", [block.serialize().hex()], 401, -32001)
        t0 = time.monotonic()
        expect_status(wrong, "submitblock", [block.serialize().hex()], 401, -32001)
        assert_greater_than(time.monotonic() - t0, 0.2, "a failed key is answered after a delay (NET-16)")
        assert_equal(n1.tip(), tip, "a refused submitblock must not be processed")

        txid = n0.cli_send(self.wallet_copy(), ADDR, "1")
        raw = n0.getrawtransaction(txid)["hex"]
        expect_status(anon, "sendrawtransaction", [raw], 401, -32001)
        expect_status(wrong, "sendrawtransaction", [raw], 401, -32001)
        assert_equal(n1.mempool(), [], "a refused sendrawtransaction must not be processed")

        self.log.info("the right key works, as X-API-Key and as Bearer")
        bearer = n1.rpc.with_key(None).with_headers(Authorization=f"Bearer {n1.api_key}")
        st, body = bearer.raw("submitblock", [block.serialize().hex()])
        assert_equal(st, 200)
        if "error" in body["result"]:
            assert_in("invalid PoW", body["result"]["error"])  # 2^-16: retry the nonce search
            n1.submit_block(block)
        assert_equal(n1.tip(), block.hash_hex())
        assert_equal(n1.sendrawtransaction(raw)["txid"], txid)
        assert_equal(n1.mempool(), [txid])

        self.log.info("browser Origin / foreign Host are refused even with the key; batches too")
        expect_status(n1.rpc.with_headers(Origin="http://evil.example"), "getblocktemplate", None, 403, -32003)
        expect_status(n1.rpc.with_headers(Origin="http://evil.example"), "getblockcount", None, 403, -32003)
        expect_status(n1.rpc.with_headers(Host="evil.example"), "getblockcount", None, 403, -32003)
        st, body = self.batch(n1)
        assert_equal((st, body["error"]["code"]), (400, -32600))

        self.log.info("gnb-cli without GNB_RPC_API_KEY can read but not write")
        assert_equal(int(n1.cli("height", with_key=False).stdout), n1.getblockcount())
        p = n1.cli("sendraw", raw, with_key=False)
        assert_true(p.returncode != 0 and "401" in p.stderr, p.stderr)
        assert_equal(n1.mempool(), [txid], "the refused write had no effect")

        self.log.info("GNB_RPC_REQUIRE_AUTH_FOR_READS=1: reads need the key too")
        n1.restart(env={"GNB_RPC_REQUIRE_AUTH_FOR_READS": "1"})
        expect_status(n1.rpc.with_key(None), "getblockcount", None, 401, -32001)
        assert_equal(n1.getblockcount(), int(n1.cli("height").stdout))
        n1.stop()

        self.log.info("start-up refusals")
        n0.stop()
        base = [n0.gnb, "--testnet", "--data-dir", n0.datadir, "--rpc-port", str(n0.rpc_port),
                "--listen", n0.p2p_addr]
        code, out = n0.run_to_exit(base[1:] + ["--rpc-require-auth-for-writes"])
        assert_equal(code, 2, out)
        assert_in("requires --rpc-api-key", out)
        loose = os.path.join(self.tmpdir, "loose.key")
        with open(loose, "w") as f:
            f.write("loose-key-0123456789abcdef\n")
        os.chmod(loose, 0o644)
        code, out = n0.run_to_exit(base[1:] + ["--rpc-api-key-file", loose])
        assert_equal(code, 2, out)
        assert_in("accessible to other users", out)
        empty = os.path.join(self.tmpdir, "empty.key")
        with open(empty, "w"):
            pass
        os.chmod(empty, 0o600)
        code, out = n0.run_to_exit(base[1:] + ["--rpc-api-key-file", empty])
        assert_equal(code, 2, out)
        assert_in("is empty", out)

        self.log.info("a too-short key: the node runs but its RPC service stays down")
        n0.start(["--rpc-api-key", "short"], wait=False)
        wait_until(lambda: n0.log_contains("configured API key is invalid"), timeout=60,
                   desc="RPC refuses the short key")
        with socket.socket() as s:
            assert_true(s.connect_ex(("127.0.0.1", n0.rpc_port)) != 0, "RPC port must not be open")
        assert_true(n0.is_running(), "the node itself keeps running")

    @staticmethod
    def batch(node):
        req = urllib.request.Request(node.url, data=json.dumps([{"jsonrpc": "2.0", "id": 1,
                                                                   "method": "getblockcount"}]).encode(),
                                     headers={"Content-Type": "application/json", "X-API-Key": node.api_key})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())


if __name__ == "__main__":
    RpcAuthTest().main()
