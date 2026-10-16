#!/usr/bin/env python3
"""External mining of a FULL template: submitblock carries a large block.

Regression (audit B1-T4): every RPC request body was capped at 1 MiB, and
submitblock carries the block as hex (twice its wire size), so any block
above about 524 kB (a template built from a mempool holding more than
0.6 MB of transactions) was refused with HTTP 413 before the node looked at
it: an external miner or pool lost the block and its proof of work. Bitcoin
Core accepts RPC bodies up to 32 MiB; the node now accepts submitblock
bodies up to 4 MiB (room for a 1,000,000-byte block), every other method
keeps the 1 MiB cap.

* Two fresh wallets get 40 coinbase outputs each (a coinbase has one
  output), then the outputs mature.
* Each wallet pays 39 coinbase values: 40 hybrid-signed inputs, about
  340 kB per transaction; the mempool holds more than 0.6 MB.
* The template offers both; the block built from it (more than 600 kB, a
  submitblock body above 1 MiB) is accepted, becomes the tip, confirms both
  transactions and is relayed to the peer.
"""

import os

from test_framework.messages import address_to_script_pubkey, block_from_template, hash_to_address
from test_framework.test_framework import GnbTestFramework
from test_framework.util import assert_equal, assert_true, wait_until

MINER = hash_to_address(bytes(range(90, 110)))
RECIPIENT = hash_to_address(bytes(range(110, 130)))
FILLER = hash_to_address(bytes(range(130, 150)))
INPUTS = 40                  # coinbase outputs per wallet; getutxos returns up to 50
COINBASE_MATURITY = 100      # core::COINBASE_MATURITY
OLD_BODY_CAP = 1024 * 1024   # the cap every RPC body had (B1-T4)


def gnb_amount(sat: int) -> str:
    return f"{sat // 100_000_000}.{sat % 100_000_000:08d}"


class FullTemplateTest(GnbTestFramework):
    def set_test_params(self):
        self.num_nodes = 2

    def run_test(self):
        n0, n1 = self.nodes

        self.log.info("two fresh wallets get %d coinbase outputs each", INPUTS)
        wallets = []
        for i in range(2):
            path = os.path.join(self.tmpdir, f"payer{i}.json")
            wallets.append((path, n0.cli_new_wallet(path)))
        for _, addr in wallets:
            n0.generate(INPUTS, addr)
        # The last output needs COINBASE_MATURITY confirmations at the next
        # block's height (the wallet's maturity rule, getutxos coinbase_height).
        n0.generate(COINBASE_MATURITY - 1, FILLER)

        self.log.info("each wallet pays %d coinbase values: %d inputs per transaction", INPUTS - 1, INPUTS)
        txids = []
        for path, addr in wallets:
            coins = n0.getutxos(addr)["utxos"]
            assert_equal(len(coins), INPUTS)
            value = int(coins[0]["value"])
            assert_true(all(int(c["value"]) == value for c in coins))
            txids.append(n0.cli_send(path, RECIPIENT, gnb_amount((INPUTS - 1) * value)))
        pool = n0.getmempoolinfo()
        assert_equal(sorted(n0.mempool()), sorted(txids))
        assert_true(pool["bytes"] > 600_000, f"mempool holds {pool['bytes']} bytes")
        self.log.info("mempool: %d transactions, %d bytes", pool["size"], pool["bytes"])

        self.log.info("the template offers both; its block needs a submitblock body above 1 MiB")
        tmpl = n0.fresh_template()
        assert_equal(sorted(t["txid"] for t in tmpl["transactions"]), sorted(txids))
        block = block_from_template(tmpl, address_to_script_pubkey(MINER))
        size = len(block.serialize())
        assert_true(size > 600_000, f"block of {size} bytes")
        assert_true(2 * size > OLD_BODY_CAP, "the hex alone exceeds the old 1 MiB body cap")
        self.log.info("block: %d bytes, submitblock body about %d bytes", size, 2 * size)

        h = n0.submit_block(block)
        assert_equal(h, block.hash_hex())
        wait_until(lambda: n0.tip() == h, timeout=30, desc="the full block is the tip")
        for txid in txids:
            assert_equal(n0.gettransaction(txid)["block_hash"], h)
        assert_equal(n0.mempool(), [])

        self.log.info("the block is relayed")
        self.sync_blocks()
        for txid in txids:
            assert_equal(n1.gettransaction(txid)["block_hash"], h)
        assert_equal(int(n1.getbalance(RECIPIENT)["satoshis"]), 2 * (INPUTS - 1) * value)


if __name__ == "__main__":
    FullTemplateTest().main()
