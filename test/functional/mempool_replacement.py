#!/usr/bin/env python3
"""Full-RBF replacement end to end on three nodes (audit MEM-6, docs/MEMPOOL.md).

The cache wallet pays A at node0; A reaches every mempool. The same wallet
then pays someone else the same amount from the same coins (`gnb-cli send`
selects deterministically from the confirmed coins, ties broken by txid), so
the second transaction conflicts with A:

* at A's fee it fails the replacement rules (rule 6, a higher fee rate than
  every conflict, or rule 4, additional fee for its own size) and A stays
  everywhere;
* with a higher fee (above A's fee plus the incremental relay fee for its own
  size, rules 3 and 4) it replaces A on the node it is sent to, is relayed,
  and replaces A on the two other nodes as well;
* a block mined at the third node confirms the replacement on every node:
  A's payee holds nothing, the replacement's payee the amount, and all three
  nodes end with the same chain state.
"""

from test_framework.messages import Tx, hash_to_address
from test_framework.test_framework import GnbTestFramework
from test_framework.util import (
    AssertionFailure, assert_equal, assert_in, assert_raises_rpc_error, assert_true, wait_until,
)

PAYEE_A = hash_to_address(bytes(range(220, 240)))
PAYEE_B = hash_to_address(bytes(range(1, 21)))
MINER = hash_to_address(bytes(range(21, 41)))


def gnb_amount(sat: int) -> str:
    return f"{sat // 10**8}.{sat % 10**8:08d}"


class MempoolReplacementTest(GnbTestFramework):
    def set_test_params(self):
        self.num_nodes = 3

    def outpoints(self, node, txid):
        tx = Tx.deserialize(bytes.fromhex(node.getrawtransaction(txid)["hex"]))
        return {(i.prev_txid.hex(), i.prev_index) for i in tx.inputs}

    def run_test(self):
        n0, n1, n2 = self.nodes
        wallet = self.wallet_copy()
        sender = self.chain_info["wallet_address"]

        self.log.info("A, paid at node0, reaches every mempool")
        a = n0.cli_send(wallet, PAYEE_A, "2")
        self.sync_mempools()
        for n in self.nodes:
            assert_equal(n.mempool(), [a])
        fee_a = int(n0.getrawmempool(True)["transactions"][0]["fee"])
        # A's inputs, read now: once B is relayed, every node replaces A
        # within milliseconds and no longer finds it (not pooled, not
        # confirmed), so A is never queried after B is sent.
        a_inputs = self.outpoints(n0, a)

        self.log.info("a conflicting payment at A's fee is refused; A stays")
        try:
            n2.cli_send(wallet, PAYEE_B, "2", "--fee", gnb_amount(fee_a))
            raise AssertionError("a conflict paying no more than A must not replace it")
        except AssertionFailure as e:
            # Rule 6 when the new transaction is not smaller than A, else
            # rule 4 (no additional fee): Falcon signatures vary in length,
            # so which one bites depends on the two sizes.
            assert_in("replacement rejected: replacement", str(e))
            assert_true("fee rate does not exceed" in str(e) or "adds 0 sat of fee" in str(e), str(e))
        for n in self.nodes:
            assert_equal(n.mempool(), [a])

        self.log.info("a conflicting payment with a higher fee replaces A on every node")
        fee_b = fee_a + 100_000
        b = n1.cli_send(wallet, PAYEE_B, "2", "--fee", gnb_amount(fee_b), "--max-fee", gnb_amount(2 * fee_b))
        assert_true(self.outpoints(n1, b) & a_inputs, "B spends A's coins")
        self.sync_mempools()
        for n in self.nodes:
            wait_until(lambda n=n: n.mempool() == [b], timeout=30, desc=f"node{n.index} holds B only")
            # Replaced A is gone: neither pooled nor confirmed, so no node
            # serves it (why A's inputs were read before B was sent).
            assert_raises_rpc_error("transaction not found", n.getrawtransaction, a)
        assert_equal(int(n2.getrawmempool(True)["transactions"][0]["fee"]), fee_b)

        self.log.info("a block mined at node2 confirms B everywhere; A is gone")
        block = n2.generate(1, MINER)[0]
        self.sync_blocks()
        for n in self.nodes:
            wait_until(lambda n=n: n.mempool() == [], timeout=30, desc=f"node{n.index} mempool empty")
            assert_equal(n.gettransaction(b)["block_hash"], block)
            assert_equal(n.getbalance(PAYEE_A)["satoshis"], "0")
            assert_equal(n.getbalance(PAYEE_B)["satoshis"], "200000000")
        self.assert_same_chain_state([sender, PAYEE_A, PAYEE_B, MINER])


if __name__ == "__main__":
    MempoolReplacementTest().main()
