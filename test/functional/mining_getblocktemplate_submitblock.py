#!/usr/bin/env python3
"""External mining: getblocktemplate + submitblock, block built in Python.

* The template's hardening fields and coinbase commitment match an
  independent Python encoding of the consensus rules (messages.py).
* A block assembled from the template is accepted, gets the id Python
  computes, becomes the tip and is relayed to the peer.
* The next template builds on it immediately (no stale cached template:
  the template cache is keyed on the DAG tips).
* A resubmission is refused as a duplicate.
* A mempool transaction is offered with its fee once the template cache
  turns over (within TEMPLATE_CACHE_TTL, 5 s, of the pool change, as
  Bitcoin Core); a coinbase that claims one
  satoshi more than subsidy + fees is refused and not relayed; the exact
  claim is accepted and confirms the transaction on both nodes.
* Two blocks on the same template (a DAG fork) are both accepted, and the
  next template merges them.
"""

import time

from test_framework.authproxy import JSONRPCException
from test_framework.messages import (
    COINBASE_COMMITMENT_TAG, Tx, address_to_script_pubkey, block_from_template, coinbase_commitment,
    hash_to_address,
)
from test_framework.test_framework import GnbTestFramework
from test_framework.util import (
    assert_equal, assert_in, assert_not_in, assert_raises_rpc_error, assert_true, wait_until,
)

MINER = hash_to_address(bytes(range(40, 60)))
RECIPIENT = hash_to_address(bytes(range(60, 80)))
POW_LIMIT_BITS = 0x2100FFFF


class GetBlockTemplateTest(GnbTestFramework):
    def set_test_params(self):
        self.num_nodes = 2

    def run_test(self):
        n0, n1 = self.nodes
        spk = address_to_script_pubkey(MINER)
        start_height = self.chain_info["height"]

        self.log.info("template fields and commitment agree with the Python consensus encoding")
        tmpl = n0.getblocktemplate()
        assert_equal(tmpl["hardening_active"], True)
        assert_equal(tmpl["hardening_activation_height"], 0)
        assert_equal(tmpl["merkle_rule"], "gnb-tagged-v1")
        assert_equal(tmpl["size_rule"], "wire")
        assert_equal((tmpl["pow"], tmpl["pow_log2_n"]), ("gnb-smh-v1", 19))
        assert_equal(tmpl["bits"], POW_LIMIT_BITS)
        assert_equal(tmpl["height"], start_height + 1)
        assert_equal(tmpl["parents"], [n0.tip()])
        assert_equal(tmpl["transactions"], [])
        block = block_from_template(tmpl, spk)
        assert_equal(tmpl["coinbase_script_sig_prefix"],
                     coinbase_commitment(block.height, block.parents, block.txs).hex())

        self.log.info("a block built from the template is accepted, becomes the tip; the next template builds on it at once")
        assert_equal(n0.getblocktemplate()["parents"], tmpl["parents"])  # cached, keyed on the current tips
        h1 = n0.submit_block(block)
        tmpl2 = n0.getblocktemplate()  # well inside the cache TTL: only the new tip can miss it
        assert_equal(tmpl2["parents"], [h1], "template must not be served stale after a new tip")
        assert_equal(tmpl2["height"], start_height + 2)
        assert_equal(h1, block.hash_hex())
        assert_equal(n0.tip(), h1)

        self.log.info("the block is relayed")
        self.sync_blocks()
        assert_equal(n1.getblock(h1)["height"], start_height + 1)

        self.log.info("resubmitting the same block is refused as a duplicate")
        assert_raises_rpc_error("duplicate block", n0.submitblock, block.serialize().hex())

        self.log.info("the coinbase pays the template's script and carries the commitment")
        cb_txid = n1.getblock(h1, True)["transactions"][0]["txid"]
        cb = Tx.deserialize(bytes.fromhex(n1.getrawtransaction(cb_txid)["hex"]))
        assert_equal(cb.outputs[0].script_pubkey, spk)
        assert_equal(cb.outputs[0].value, int(tmpl["subsidy_sat"]))
        assert_true(cb.inputs[0].script_sig.startswith(COINBASE_COMMITMENT_TAG))

        self.log.info("a mempool transaction is offered with its fee")
        wallet = self.wallet_copy()
        txid = n1.cli_send(wallet, RECIPIENT, "1.5")
        self.sync_mempools()
        assert_equal(n0.mempool(), [txid])
        offered = time.monotonic()
        wait_until(lambda: [t["txid"] for t in n0.getblocktemplate()["transactions"]] == [txid], timeout=15,
                   desc="the template offers the pool transaction")
        assert_true(time.monotonic() - offered < 5 + 3, "a pool change shows in the template within the 5 s TTL")
        tmpl3 = n0.getblocktemplate()
        assert_equal([t["txid"] for t in tmpl3["transactions"]], [txid])
        fee = int(tmpl3["transactions"][0]["fee"])
        assert_true(fee > 0)
        assert_equal(int(tmpl3["total_fees"]), fee)

        self.log.info("claiming subsidy + fees + 1 is refused and the block is not relayed")
        greedy = block_from_template(tmpl3, spk, coinbase_value=int(tmpl3["subsidy_sat"]) + fee + 1)
        assert_raises_rpc_error("exceeds", n0.submit_block, greedy)
        # DAG-1: the node keeps the disqualified block in its DAG (so it is
        # never re-validated) but never selects it or builds on it.
        assert_in(greedy.hash_hex(), n0.tips())
        assert_equal(n0.tip(), h1)
        assert_not_in(greedy.hash_hex(), n0.valid_tips())
        assert_raises_rpc_error("known invalid", n0.submitblock, greedy.serialize().hex())
        assert_equal(n0.mempool(), [txid], "the transaction stays in the pool")

        self.log.info("the exact claim confirms the transaction on both nodes")
        honest = block_from_template(tmpl3, spk)
        h3 = n0.submit_block(honest)
        self.sync_blocks()
        assert_true(not n1.has_block(greedy.hash_hex()), "the refused block was never relayed")
        for n in self.nodes:
            wait_until(lambda n=n: n.mempool() == [], timeout=30, desc=f"node{n.index} mempool empty")
            loc = n.gettransaction(txid)
            assert_equal(loc["block_hash"], h3)
        assert_equal(int(n1.getbalance(RECIPIENT)["satoshis"]), 150_000_000)
        cb = n1.getblock(h3, True)["transactions"][0]
        assert_equal(int(cb["outputs"][0]["value"]), int(tmpl3["subsidy_sat"]) + fee)

        self.log.info("two blocks on one template are both accepted; the next template merges them")
        tmpl4 = n0.getblocktemplate()
        a = block_from_template(tmpl4, spk, extra=b"fork-a")
        b = block_from_template(tmpl4, spk, extra=b"fork-b")
        ha = n0.submit_block(a)
        hb = n0.submit_block(b)
        assert_equal(n0.valid_tips(), sorted([ha, hb]))
        self.sync_blocks()
        tmpl5 = n0.getblocktemplate()
        assert_equal(sorted(tmpl5["parents"]), sorted([ha, hb]))
        assert_equal(tmpl5["parents"][0], n0.tip(), "the selected parent comes first")
        hm = n0.submit_block(block_from_template(tmpl5, spk))
        self.sync_blocks()
        for n in self.nodes:
            assert_equal(n.valid_tips(), [hm])
            assert_equal(n.height(), start_height + 4)
        assert_equal(n1.tips(), [hm], "node1 never saw the disqualified block")
        self.assert_same_chain_state([MINER, RECIPIENT, self.chain_info["wallet_address"]])

        self.log.info("a template is refused without the API key (getblocktemplate is a write method)")
        try:
            n0.rpc.with_key(None).getblocktemplate()
            raise AssertionError("getblocktemplate without a key must be refused")
        except JSONRPCException as e:
            assert_equal(e.http_status, 401)


if __name__ == "__main__":
    GetBlockTemplateTest().main()
