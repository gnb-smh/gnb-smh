#!/usr/bin/env python3
"""A public descriptor pool restores the same funded identity through CLI/RPC.

The synthetic public-key shape below comes from the independent Python
descriptor corpus. This observes test coins; it does not prove key possession,
restore spending keys or add a persistent watch-only wallet to the node.
"""

import hashlib
import json
from pathlib import Path

from test_framework.messages import hash_to_address
from test_framework.test_framework import GnbTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error, assert_true

# reference/descriptor_vectors.py fixture(0), testnet/pkh-raw/create. Pin the
# independent checksum here so the live test cannot generate its own oracle
# with the production descriptor codec it is intended to check.
KEY = hashlib.shake_256(b"gnb-descriptor-public-fixture-v1" + bytes(4)).digest(3745).hex()
BODY = f"gnbd1(testnet,pkh({KEY}))"
DESCRIPTOR = BODY + "#3mccwj00"
SCRIPT = "39a46cfcebe27b40c832dac1ce3decfa12f98c1d"
ADDRESS = "gnb1t39a46cfcebe27b40c832dac1ce3decfa12f98c1df915127a"
MINER = hash_to_address(bytes(range(221, 241)))


class WalletDescriptorRestoreTest(GnbTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def run_test(self):
        node = self.nodes[0]
        assert_equal(node.getbalance(ADDRESS)["satoshis"], "0", "legacy RPC control")

        self.log.info("the node resolves a checksummed public descriptor on its own network")
        info = node.getdescriptorinfo(DESCRIPTOR)
        assert_equal(info["script_pubkey"], SCRIPT)
        assert_equal(info["address"], ADDRESS)
        assert_equal(info["descriptor"], DESCRIPTOR)
        assert_equal(info["network"], "testnet")
        assert_equal(info["requires_policy_tree_activation"], False)
        assert_equal(node.deriveaddresses(DESCRIPTOR), [ADDRESS])
        assert_raises_rpc_error(None, node.getdescriptorinfo, DESCRIPTOR[:-1] + "q")

        files = Path(self.tmpdir) / "public-descriptors"
        files.mkdir()
        body_file, descriptor_file = files / "body.txt", files / "descriptor.txt"
        list_file, pool_file = files / "list.json", files / "pool.json"
        body_file.write_text(BODY, encoding="ascii")
        descriptor_file.write_text(DESCRIPTOR, encoding="ascii")
        list_file.write_text(json.dumps([DESCRIPTOR]), encoding="ascii")
        assert_equal(node.cli_json("--testnet", "descriptor", "create", body_file), info)
        assert_equal(node.cli_json("--testnet", "descriptor", "inspect", descriptor_file), info)
        exported = node.cli_json("--testnet", "descriptor", "export", list_file, pool_file)
        original_bytes = pool_file.read_bytes()
        assert_equal(original_bytes.decode("utf-8").strip(), exported["bundle"])
        assert_equal(exported["count"], 1)
        assert_equal(exported["entries"], [info])

        self.log.info("fund the described identity, then restore its public pool from disk")
        txid = node.cli_send(self.wallet_copy(), ADDRESS, "1.5")
        block = node.generate(1, MINER)[0]
        assert_equal(node.gettransaction(txid)["block_hash"], block)
        restored = node.cli_json("--testnet", "descriptor", "import", pool_file)
        assert_equal(restored, exported)
        restored_address = restored["entries"][0]["address"]
        assert_equal(node.getbalance(restored_address)["satoshis"], "150000000")
        assert_true(any(row["txid"] == txid for row in node.getutxos(restored_address)["utxos"]))

        self.log.info("wrong-network import and overwriting an existing backup are refused")
        wrong_network = node.cli("--mainnet", "descriptor", "import", pool_file)
        assert_true(wrong_network.returncode != 0, "testnet pool imported as mainnet")
        overwrite = node.cli("--testnet", "descriptor", "export", list_file, pool_file)
        assert_true(overwrite.returncode != 0, "existing public pool was overwritten")
        assert_equal(pool_file.read_bytes(), original_bytes)
        assert_equal(sorted(p.name for p in files.iterdir()),
                     ["body.txt", "descriptor.txt", "list.json", "pool.json"])


if __name__ == "__main__":
    WalletDescriptorRestoreTest().main()
