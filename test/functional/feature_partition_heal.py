#!/usr/bin/env python3
"""Partition, competing chains, heal: every node converges to the same state.

1. Three connected nodes share a chain.
2. Partition: node2 is restarted without peers. Side A (node0 + node1)
   mines 2 blocks, one of them confirming a wallet payment; side B (node2)
   mines 4 blocks paying another address. The sides disagree.
3. Heal: node2 restarts dialing node0 and node1. All nodes end with the
   same selected tip (side B, the most blue work), the same valid tips
   (both branch tips, a DAG keeps both), and after a merging block one tip.
4. Same chain state everywhere: tip, height, blue work, and the UTXO set of
   every address involved (the RPC has no UTXO-set digest; per-address
   getutxos lists compared exactly are the strongest view it offers). The
   payment's status agrees on every node.
"""

from test_framework.authproxy import JSONRPCException
from test_framework.messages import hash_to_address
from test_framework.test_framework import GnbTestFramework
from test_framework.util import assert_equal, assert_not_equal, assert_true

MINER_A = hash_to_address(bytes(range(180, 200)))
MINER_B = hash_to_address(bytes(range(200, 220)))
MERGER = hash_to_address(bytes(range(220, 240)))
PAYEE = hash_to_address(bytes(range(1, 21)))


class PartitionHealTest(GnbTestFramework):
    def set_test_params(self):
        self.num_nodes = 3

    def tx_status(self, node, txid):
        try:
            return node.gettransaction(txid)["block_hash"]
        except JSONRPCException:
            return None

    def run_test(self):
        n0, n1, n2 = self.nodes
        start = self.chain_info["height"]
        sender = self.chain_info["wallet_address"]
        everyone = [MINER_A, MINER_B, MERGER, PAYEE, sender]

        self.log.info("shared history: one block, seen by all")
        n0.generate(1, MINER_A)
        self.sync_blocks()
        common = n0.tip()

        self.log.info("partition: node2 restarts without peers")
        n2.restart(peers=[])
        assert_equal(n2.tip(), common)

        self.log.info("side A mines 2 blocks (one confirms a payment); side B mines 4")
        txid = n1.cli_send(self.wallet_copy(), PAYEE, "3")
        self.sync_mempools([n0, n1])
        a_blocks = n0.generate(2, MINER_A)
        self.sync_blocks([n0, n1])
        assert_equal(self.tx_status(n1, txid), a_blocks[0])
        b_blocks = n2.generate(4, MINER_B)
        assert_equal(n0.height(), start + 3)
        assert_equal(n2.height(), start + 5)
        assert_not_equal(n0.tip(), n2.tip())
        assert_true(not n0.has_block(b_blocks[0]) and not n2.has_block(a_blocks[0]), "sides are disjoint")

        self.log.info("heal: node2 dials both; all nodes converge")
        n2.restart(peers=[n0.p2p_addr, n1.p2p_addr])
        self.wait_for_peers(pairs=[(n2, n0), (n2, n1)])
        self.sync_blocks(timeout=120)
        for n in self.nodes:
            assert_equal(n.tip(), b_blocks[-1], f"node{n.index}: the branch with more blue work is selected")
            assert_equal(n.valid_tips(), sorted([a_blocks[-1], b_blocks[-1]]), "both branch tips are kept")
            for h in a_blocks + b_blocks:
                assert_true(n.has_block(h), f"node{n.index} has every block of both sides")
        self.assert_same_chain_state(everyone)
        statuses = {self.tx_status(n, txid) for n in self.nodes}
        assert_equal(len(statuses), 1, f"the payment's status differs between nodes: {statuses}")

        self.log.info("a merging block joins both branches on every node")
        merge = n1.generate(1, MERGER)[0]
        self.sync_blocks(timeout=120)
        parents = set(n2.getblock(merge)["parents"])
        assert_equal(parents, {a_blocks[-1], b_blocks[-1]})
        for n in self.nodes:
            assert_equal(n.valid_tips(), [merge])
            assert_equal(n.height(), start + 6)
        self.assert_same_chain_state(everyone)
        statuses = {self.tx_status(n, txid) for n in self.nodes}
        assert_equal(len(statuses), 1, f"the payment's status differs between nodes: {statuses}")
        self.log.info("payment after merge: %s", "confirmed in " + statuses.pop() if statuses else "unconfirmed")


if __name__ == "__main__":
    PartitionHealTest().main()
