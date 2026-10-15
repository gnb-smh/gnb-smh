#!/usr/bin/env python3
"""Mining and block propagation across three nodes (line topology).

node0 runs the internal GnB-SMH miner (`--mine`); node1 dials node0 and
node2 dials node1 only, so every block node0 finds reaches node2 through
node1's validate-then-relay path (NET-2). Checks:

* node2 follows node0's chain block by block (multi-hop gossip);
* after node0 stops mining, all three nodes hold the identical chain: the
  same block at every height, every coinbase paying the miner address, and
  the same UTXO set for it;
* a block submitted at the far end (node2, getblocktemplate/submitblock)
  travels back to node0;
* node0 and node2 never connected directly (PEX does not hand out loopback
  addresses without --allow-private-peers).
"""

from test_framework.messages import hash_to_address
from test_framework.test_framework import GnbTestFramework
from test_framework.util import assert_equal, assert_greater_than_or_equal, assert_true, wait_until

MINER = hash_to_address(bytes(range(100, 120)))
OTHER = hash_to_address(bytes(range(120, 140)))
TARGET_BLOCKS = 6


class BlockPropagationTest(GnbTestFramework):
    def set_test_params(self):
        self.num_nodes = 3

    def setup_network(self):
        n0, n1, n2 = self.nodes
        n0.start(mine=True, miner_address=MINER)
        n1.start(peers=[n0.p2p_addr])
        n2.start(peers=[n1.p2p_addr])
        self.wait_for_peers(pairs=[(n0, n1), (n1, n2)])

    def run_test(self):
        n0, n1, n2 = self.nodes
        start = self.chain_info["height"]

        self.log.info("node0 mines; node2 receives the blocks through node1")
        wait_until(lambda: n2.height() >= start + TARGET_BLOCKS, timeout=120,
                   desc=f"node2 reaches height {start + TARGET_BLOCKS}")
        assert_true(n0.log_contains("Block found!"), "the internal miner found the blocks")

        self.log.info("stop the miner (restart node0 without --mine, dialing node1)")
        n0.restart(peers=[n1.p2p_addr])
        self.wait_for_peers(pairs=[(n0, n1)])
        self.sync_blocks()
        tip_height = n0.height()
        assert_greater_than_or_equal(tip_height, start + TARGET_BLOCKS)

        self.log.info("all nodes hold the same block at every height, each paying the miner")
        for h in range(start + 1, tip_height + 1):
            hashes = {n.getblockhash(h) for n in self.nodes}
            assert_equal(len(hashes), 1, f"height {h}: nodes disagree {hashes}")
            block = n2.getblock(hashes.pop(), True)
            assert_equal(block["height"], h)
            cb = block["transactions"][0]
            assert_true(cb["coinbase"])
            assert_equal(cb["outputs"][0]["script_pubkey"], bytes(range(100, 120)).hex())
        self.assert_same_chain_state([MINER])
        mined = tip_height - start
        assert_equal(int(n1.getbalance(MINER)["utxo_count"]), mined)

        self.log.info("a block submitted at node2 travels back to node0 through node1")
        h = n2.generate(1, OTHER)[0]
        wait_until(lambda: n0.tip() == h, timeout=60, desc="node0 tip is node2's block")
        self.sync_blocks()
        self.assert_same_chain_state([MINER, OTHER])

        self.log.info("node0 and node2 were never directly connected")
        assert_true(not n2.sees_peer(n0.peer_id()) and not n0.sees_peer(n2.peer_id()),
                    "the relay must have gone through node1")


if __name__ == "__main__":
    BlockPropagationTest().main()
