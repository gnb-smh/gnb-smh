#!/usr/bin/env python3
"""The test-only build (feature test-pow-limit) refuses mainnet, runs on testnet.

* Started without --testnet, the binary exits with code 2 and the guard
  message before it creates the data dir, opens a port or reads the key file
  (main.rs `test_pow_limit_guard`), whatever other options it is given.
* Started with --testnet it runs, and the pow limit is what the template
  asks for (0x2100ffff, about one GnB-SMH evaluation per block).
"""

import os

from test_framework.test_framework import GnbTestFramework
from test_framework.util import assert_equal, assert_in, assert_true

POW_LIMIT_BITS = 0x2100FFFF


class TestBuildGuardTest(GnbTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def setup_network(self):
        pass  # the refusals run first; the node is started in run_test

    def run_test(self):
        node = self.nodes[0]
        fresh = os.path.join(self.tmpdir, "mainnet-datadir")

        self.log.info("bare mainnet start is refused with exit code 2, before the data dir exists")
        code, out = node.run_to_exit(["--data-dir", fresh])
        assert_equal(code, 2, out)
        assert_in("test-pow-limit", out)
        assert_in("refuses to run on mainnet", out)
        assert_true(not os.path.exists(fresh), "the refusal must not create the data dir")

        self.log.info("a full mainnet command line (mining, RPC, peers) is refused the same way")
        code, out = node.run_to_exit([
            "--data-dir", fresh, "--carryover-snapshot", self.cache.carryover,
            "--rpc-port", str(node.rpc_port), "--listen", node.p2p_addr,
            "--rpc-api-key", "x" * 32, "--mine", "--miner-address", "gnb1q" + "00" * 24,
        ])
        assert_equal(code, 2, out)
        assert_in("refuses to run on mainnet", out)
        assert_true(not os.path.exists(fresh), "the refusal must not create the data dir")

        self.log.info("on testnet the same binary starts and serves RPC")
        node.start()
        assert_equal(node.getblockcount(), 1)
        assert_true(node.log_contains("TEST BUILD (test-pow-limit)"), "the test build announces itself")
        tmpl = node.getblocktemplate()
        assert_equal(tmpl["bits"], POW_LIMIT_BITS, "test-pow-limit pins every target to the pow limit")
        assert_equal(tmpl["height"], 1)
        info = node.getnetworkinfo()
        assert_equal(info["network"], "testnet", "getnetworkinfo must report the node's network")


if __name__ == "__main__":
    TestBuildGuardTest().main()
