#!/usr/bin/env python3
"""Operator chain overrides: invalidateblock / reconsiderblock (audit DAG-6).

Bitcoin Core's `InvalidateBlock` / `ReconsiderBlock`, end to end on two nodes
(node/src/accept.rs `invalidate_block`, `reconsider_block`):

* node0 invalidates B1, the block that confirmed a payment T, with B2 on top:
  its applied chain rolls back to B1's parent in one batch (2 blocks), T is
  back in node0's mempool, its payee holds nothing there; node1, which was
  not told anything, keeps B1 and B2 and the payment.
* A block D built on B2 (node1's template) is refused by node0's
  `submitblock` (its selected parent is disqualified) and leaves node0's tip
  where it is; node1 accepts it, and node0 does not follow when it hears of it.
* While B1 is invalid, node0 mines C1 on B1's parent; it re-confirms T there.
  node1 stores C1 as a fork block and keeps its tip.
* The invalidation is persisted: after a restart node0 is still on C1.
* reconsiderblock B1 on node0 re-qualifies B1, B2 and D (D's mark was only
  inherited from B1) and moves node0 to D, the chain with more blue work:
  T is confirmed in B1 again, node0's mempool is empty, and both nodes end
  with the same chain state.
"""

from test_framework.messages import address_to_script_pubkey, block_from_template, hash_to_address
from test_framework.test_framework import GnbTestFramework
from test_framework.util import (
    assert_equal, assert_in, assert_not_in, assert_raises_rpc_error, assert_true, wait_until,
)

MINER = hash_to_address(bytes(range(180, 200)))
PAYEE = hash_to_address(bytes(range(200, 220)))


class InvalidateBlockTest(GnbTestFramework):
    def set_test_params(self):
        self.num_nodes = 2

    def run_test(self):
        n0, n1 = self.nodes
        sender = self.chain_info["wallet_address"]
        p = n0.tip()
        h0 = n0.height()

        self.log.info("a payment T, confirmed in B1; B2 on top; both nodes agree")
        txid = n0.cli_send(self.wallet_copy(), PAYEE, "3")
        self.sync_mempools()
        b1, b2 = n0.generate(2, MINER)
        self.sync_blocks()
        for n in self.nodes:
            assert_equal(n.gettransaction(txid)["block_hash"], b1)
            assert_equal(n.getbalance(PAYEE)["satoshis"], "300000000")

        self.log.info("invalidateblock B1 on node0: back to B1's parent, T back in the pool")
        r = n0.invalidateblock(b1)
        assert_equal((r["block"], r["tip"], r["tip_height"]), (b1, p, h0))
        assert_equal(r["rolled_back"], 2)
        assert_true(r["affected"] >= 2, f"B1 and B2 are disqualified: {r}")
        assert_equal(n0.tip(), p)
        assert_equal(n0.height(), h0)
        wait_until(lambda: n0.mempool() == [txid], timeout=30, desc="node0 re-admits T")
        assert_equal(n0.getbalance(PAYEE)["satoshis"], "0")
        assert_true(n0.has_block(b1) and n0.has_block(b2), "the invalidated blocks are kept")
        assert_not_in(b2, n0.valid_tips(), "an invalidated block is never a template parent")
        assert_equal(n1.tip(), b2, "node1 was not told anything")
        assert_equal(n1.getbalance(PAYEE)["satoshis"], "300000000")

        self.log.info("a block on B2 is refused by node0, accepted by node1")
        d = block_from_template(n1.get_template(), address_to_script_pubkey(MINER))
        assert_equal(n1.get_template()["parents"][0], b2)
        assert_raises_rpc_error("is invalid", n0.submit_block, d)
        assert_equal(n0.tip(), p)
        dh = n1.submit_block(d)
        wait_until(lambda: n1.tip() == dh, timeout=30, desc="node1 tip == D")
        assert_equal(n0.tip(), p, "node0 does not follow a chain through B1")

        self.log.info("node0 mines C1 on B1's parent; it confirms T there; node1 keeps D")
        # Other coinbase bytes: the same template (parent, height, T, payee)
        # would otherwise rebuild B1 itself, which node0 refuses as a known
        # invalid block.
        c1 = n0.generate(1, MINER, extra=b"C1")[0]
        assert_true(c1 != b1)
        assert_equal(n0.gettransaction(txid)["block_hash"], c1)
        assert_equal(n0.mempool(), [])
        wait_until(lambda: n1.has_block(c1), timeout=30, desc="node1 receives C1")
        assert_equal(n1.tip(), dh)
        assert_equal(n1.gettransaction(txid)["block_hash"], b1)

        self.log.info("the invalidation survives a restart")
        n0.restart(peers=[n1.p2p_addr])
        self.wait_for_peers()
        assert_equal(n0.tip(), c1)
        assert_not_in(dh, n0.valid_tips())
        assert_equal(n0.gettransaction(txid)["block_hash"], c1)

        self.log.info("reconsiderblock B1: node0 moves to D, T confirmed in B1 again")
        r = n0.reconsiderblock(b1)
        assert_equal(r["tip"], dh)
        assert_equal(r["rolled_back"], 1, f"C1 rolled back: {r}")
        assert_equal(r["connected"], 3, f"B1, B2, D connected: {r}")
        assert_equal(n0.tip(), dh)
        assert_equal(n0.gettransaction(txid)["block_hash"], b1)
        wait_until(lambda: n0.mempool() == [], timeout=30, desc="node0 mempool empty")
        self.sync_blocks()
        assert_in(c1, n0.tips(), "the fork block is kept")
        for n in self.nodes:
            assert_equal(n.getbalance(PAYEE)["satoshis"], "300000000")
        self.assert_same_chain_state([MINER, PAYEE, sender])


if __name__ == "__main__":
    InvalidateBlockTest().main()
