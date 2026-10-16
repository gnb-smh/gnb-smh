#!/usr/bin/env python3
"""Partition, competing chains, heal: every node converges to the same state.

1. Three connected nodes share a chain.
2. Partition: node2 is restarted without peers. Side A (node0 + node1)
   mines 2 blocks, one of them confirming a wallet payment; side B (node2)
   mines 4 blocks paying another address. The sides disagree.
3. Heal: node2 restarts dialing node0 and node1. All nodes end with the
   same selected tip (side B, the most blue work), the same valid tips
   (both branch tips, a DAG keeps both), and after a merging block one tip.
   Convergence is bounded by HEAL_TIMEOUT: on connect each node pulls the
   new peer's frontier directly (it used to wait about 60 s for the 30 s
   nudge / 60 s announce, the gossip announcements being dropped as
   duplicates).
4. Same chain state everywhere: tip, height, blue work, and the UTXO set of
   every address involved (the RPC has no UTXO-set digest; per-address
   getutxos lists compared exactly are the strongest view it offers).
5. The payment, by the ledger rule (docs/CONSENSUS.md, "Ledger semantics:
   selected-chain-only"): after the heal side A is not on the selected
   chain, so the payment is unconfirmed on every node, the payee holds
   nothing and the payment is back in side A's mempools; the merging block
   (mined by node1, side A) includes it, so it ends confirmed in the merging
   block on every node with the payee holding exactly 3 GNB.
"""

import time

from test_framework import util
from test_framework.authproxy import JSONRPCException
from test_framework.messages import hash_to_address
from test_framework.test_framework import GnbTestFramework
from test_framework.util import assert_equal, assert_in, assert_not_equal, assert_true, wait_until

MINER_A = hash_to_address(bytes(range(180, 200)))
MINER_B = hash_to_address(bytes(range(200, 220)))
MERGER = hash_to_address(bytes(range(220, 240)))
PAYEE = hash_to_address(bytes(range(1, 21)))
# Seconds from node2 being back up (dialing both) to agreement on every
# node. 4-7 s on loopback today, wait_for_peers' 2 s settle included; the
# 30 s nudge / 60 s announce used to take about 60 s.
HEAL_TIMEOUT = 30


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

        heal_timeout = HEAL_TIMEOUT * util.TIMEOUT_FACTOR
        self.log.info("heal: node2 dials both; all nodes converge within %.1f s", heal_timeout)
        n2.restart(peers=[n0.p2p_addr, n1.p2p_addr])
        healed = time.monotonic()
        # R1-FUNC-2: one absolute acceptance deadline includes every peer
        # wait, mesh settling and the final synchronization observation.
        # Scale the 30-second budget once, never again in the inner waits.
        deadline = healed + heal_timeout
        self.wait_for_peers(pairs=[(n2, n0), (n2, n1)], deadline=deadline)
        self.sync_blocks(deadline=deadline)
        self.log.info("converged %.1f s after the restart", time.monotonic() - healed)
        for n in self.nodes:
            assert_equal(n.tip(), b_blocks[-1], f"node{n.index}: the branch with more blue work is selected")
            assert_equal(n.valid_tips(), sorted([a_blocks[-1], b_blocks[-1]]), "both branch tips are kept")
            for h in a_blocks + b_blocks:
                assert_true(n.has_block(h), f"node{n.index} has every block of both sides")
        self.assert_same_chain_state(everyone)

        self.log.info("side A is off the selected chain: the payment is unconfirmed everywhere")
        for n in self.nodes:
            assert_equal(self.tx_status(n, txid), None, f"node{n.index}: payment confirmed off the selected chain")
            assert_equal(n.getutxos(PAYEE, 100)["utxos"], [], f"node{n.index}: payee paid off the selected chain")
        for n in (n0, n1):
            wait_until(lambda n=n: txid in n.mempool(), timeout=30,
                       desc=f"node{n.index} re-admits the payment to its mempool")

        self.log.info("a merging block joins both branches and confirms the payment on every node")
        merge = n1.generate(1, MERGER)[0]
        self.sync_blocks(timeout=HEAL_TIMEOUT)
        parents = set(n2.getblock(merge)["parents"])
        assert_equal(parents, {a_blocks[-1], b_blocks[-1]})
        assert_in(txid, n2.getblock(merge)["txids"])
        for n in self.nodes:
            assert_equal(n.valid_tips(), [merge])
            assert_equal(n.height(), start + 6)
        self.assert_same_chain_state(everyone)
        for n in self.nodes:
            assert_equal(self.tx_status(n, txid), merge, f"node{n.index}: payment not confirmed in the merging block")
            assert_equal(int(n.getbalance(PAYEE)["satoshis"]), 300_000_000, f"node{n.index}: payee balance")
            assert_equal([(u["txid"], int(u["value"])) for u in n.getutxos(PAYEE, 100)["utxos"]],
                         [(txid, 300_000_000)], f"node{n.index}: payee UTXOs")
            wait_until(lambda n=n: txid not in n.mempool(), timeout=30,
                       desc=f"node{n.index} drops the confirmed payment from its mempool")


if __name__ == "__main__":
    PartitionHealTest().main()
