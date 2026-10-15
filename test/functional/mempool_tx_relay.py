#!/usr/bin/env python3
"""Transaction relay and mempool consistency across three nodes.

A real gnb-cli wallet (keystore v3, hybrid ML-DSA-65 + Falcon-1024 keys)
holding mature coinbase outputs sends through `gnb-cli send` on a terminal:

* the transaction enters every node's mempool with the same fee and the
  same bytes (getrawtransaction), and decodes to the requested payment;
* a block mined on another node from getblocktemplate confirms it on all
  nodes: same block, empty mempools, same balances and UTXOs everywhere;
* a second payment broadcast at the third node relays and confirms the same
  way, and gnb-cli's read commands agree with the RPC.
"""

from test_framework.messages import Tx, address_to_script_pubkey, hash_to_address
from test_framework.test_framework import GnbTestFramework
from test_framework.util import assert_equal, assert_in, assert_true, wait_until

RECIPIENT = hash_to_address(bytes(range(140, 160)))
MINER = hash_to_address(bytes(range(160, 180)))


class MempoolRelayTest(GnbTestFramework):
    def set_test_params(self):
        self.num_nodes = 3

    def run_test(self):
        n0, n1, n2 = self.nodes
        wallet = self.wallet_copy()
        sender = self.chain_info["wallet_address"]
        start_balance = int(n0.getbalance(sender)["satoshis"])
        assert_equal(int(n0.getbalance(sender)["utxo_count"]), 10)

        self.log.info("gnb-cli send at node1; the transaction reaches every mempool")
        txid = n1.cli_send(wallet, RECIPIENT, "2.5")
        self.sync_mempools()
        for n in self.nodes:
            assert_equal(n.mempool(), [txid], f"node{n.index} mempool")
        raws = {n.getrawtransaction(txid)["hex"] for n in self.nodes}
        assert_equal(len(raws), 1, "every node holds the same transaction bytes")
        raw = raws.pop()
        assert_true(n2.getrawtransaction(txid)["in_mempool"])
        fees = {n.getrawmempool(True)["transactions"][0]["fee"] for n in self.nodes}
        assert_equal(len(fees), 1, "every node computes the same fee")
        fee = int(fees.pop())
        tx = Tx.deserialize(bytes.fromhex(raw))
        assert_equal(tx.txid_hex(), txid)
        assert_equal(tx.version, 3, "at/after the activation the wallet signs version 3 (sighash v3)")
        pay = [o for o in tx.outputs if o.script_pubkey == address_to_script_pubkey(RECIPIENT)]
        assert_equal([o.value for o in pay], [250_000_000])
        decoded = n0.decoderawtransaction(raw)
        assert_equal(decoded["txid"], txid)
        assert_in("250000000", [o["value"] for o in decoded["outputs"]])

        self.log.info("a block mined at node0 confirms it on every node")
        block_hash = n0.generate(1, MINER)[0]
        self.sync_blocks()
        for n in self.nodes:
            wait_until(lambda n=n: n.mempool() == [], timeout=30, desc=f"node{n.index} mempool empty")
            assert_equal(n.gettransaction(txid)["block_hash"], block_hash)
            assert_equal(n.getbalance(RECIPIENT)["satoshis"], "250000000")
            assert_equal(int(n.getbalance(sender)["satoshis"]), start_balance - 250_000_000 - fee)
        coinbase = n2.getblock(block_hash, True)["transactions"][0]
        assert_equal(int(coinbase["outputs"][0]["value"]),
                     int(n0.getsupplyinfo()["subsidy_per_block_sat"]) + fee,
                     "the miner collects subsidy + fee")
        self.assert_same_chain_state([sender, RECIPIENT, MINER])

        self.log.info("a second payment broadcast at node2 relays and confirms the same way")
        txid2 = n2.cli_send(wallet, RECIPIENT, "0.75")
        self.sync_mempools()
        assert_equal(n0.mempool(), [txid2])
        block2 = n1.generate(1, MINER)[0]
        self.sync_blocks()
        for n in self.nodes:
            wait_until(lambda n=n: n.mempool() == [], timeout=30, desc=f"node{n.index} mempool empty")
            assert_equal(n.gettransaction(txid2)["block_hash"], block2)
            assert_equal(n.getbalance(RECIPIENT)["satoshis"], "325000000")
        self.assert_same_chain_state([sender, RECIPIENT, MINER])

        self.log.info("gnb-cli reads agree with the RPC")
        assert_equal(n0.cli_json("balance", RECIPIENT)["satoshis"], "325000000")
        assert_equal(n0.cli_json("tx", txid2)["block_hash"], block2)
        assert_equal(n0.cli_json("rawmempool")["txids"], [])


if __name__ == "__main__":
    MempoolRelayTest().main()
