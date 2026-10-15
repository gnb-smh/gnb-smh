#!/usr/bin/env python3
"""Restart persistence: chain state survives stop/start and a hard kill.

* node1 stopped (SIGTERM) and started again: same selected tip, tips,
  height, blue work, block at every height, balances, transaction index and
  P2P identity.
* The mempool is memory-only by design (node/src/mempool: no persistence):
  after the restart node1's pool is empty while node0 still holds the
  transaction; re-broadcasting the same bytes (sendrawtransaction) re-admits
  it under the same txid, and a block mined on node1 confirms it everywhere.
* node0 killed with SIGKILL right after accepting a block (no shutdown path
  at all) restarts on that block: RocksDB's write-ahead log keeps every
  committed acceptance.
"""

from test_framework.messages import hash_to_address
from test_framework.test_framework import GnbTestFramework
from test_framework.util import assert_equal, wait_until

MINER = hash_to_address(bytes(range(30, 50)))
PAYEE = hash_to_address(bytes(range(50, 70)))


class RestartPersistenceTest(GnbTestFramework):
    def set_test_params(self):
        self.num_nodes = 2

    def snapshot(self, node, heights):
        info = node.getdaginfo()
        return {
            "tip": info["tip"], "tips": sorted(info["tips"]), "height": info["tip_height"],
            "blue_work": info["tip_blue_work"], "block_count": info["block_count"],
            "hashes": [node.getblockhash(h) for h in heights],
            "balances": [node.getbalance(a)["satoshis"] for a in (MINER, PAYEE, self.chain_info["wallet_address"])],
        }

    def run_test(self):
        n0, n1 = self.nodes
        start = self.chain_info["height"]

        self.log.info("build some state: two blocks and an unconfirmed payment")
        n0.generate(2, MINER)
        self.sync_blocks()
        txid = n1.cli_send(self.wallet_copy(), PAYEE, "4")
        self.sync_mempools()
        raw = n0.getrawtransaction(txid)["hex"]
        heights = [0, 1, start // 2, start, start + 1, start + 2]
        before = self.snapshot(n1, heights)
        peer_id = n1.peer_id()
        coinbase_txid = n1.getblock(before["hashes"][-1])["txids"][0]

        self.log.info("stop and start node1: the chain state is unchanged")
        n1.stop()
        n1.start(peers=[n0.p2p_addr])
        assert_equal(self.snapshot(n1, heights), before)
        assert_equal(n1.peer_id(), peer_id, "the P2P identity is persistent")
        assert_equal(n1.gettransaction(coinbase_txid)["block_hash"], before["hashes"][-1])

        self.log.info("the mempool is not persisted; re-broadcasting re-admits the payment")
        assert_equal(n1.mempool(), [])
        assert_equal(n0.mempool(), [txid])
        self.wait_for_peers()
        assert_equal(n1.sendrawtransaction(raw)["txid"], txid)
        assert_equal(n1.mempool(), [txid])
        block = n1.generate(1, MINER)[0]
        self.sync_blocks()
        for n in self.nodes:
            wait_until(lambda n=n: n.mempool() == [], timeout=30, desc=f"node{n.index} mempool empty")
            assert_equal(n.gettransaction(txid)["block_hash"], block)
            assert_equal(n.getbalance(PAYEE)["satoshis"], "400000000")

        self.log.info("SIGKILL node0 right after it accepted a block; it restarts on that block")
        last = n0.generate(1, MINER)[0]
        before0 = self.snapshot(n0, heights + [start + 3, start + 4])
        n0.kill()
        n0.start()
        assert_equal(n0.tip(), last)
        assert_equal(self.snapshot(n0, heights + [start + 3, start + 4]), before0)
        n1.restart(peers=[n0.p2p_addr])
        self.wait_for_peers()
        self.sync_blocks()
        self.assert_same_chain_state([MINER, PAYEE, self.chain_info["wallet_address"]])


if __name__ == "__main__":
    RestartPersistenceTest().main()
