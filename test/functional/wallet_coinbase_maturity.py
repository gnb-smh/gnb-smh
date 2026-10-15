#!/usr/bin/env python3
"""gnb-cli send never spends an immature coinbase output.

Regression: the wallet's coin selection had no maturity information (getutxos
did not say which outputs are coinbases), so a miner's wallet holding a fresh
coinbase output selected it (largest-first) and every node refused the
broadcast ("coinbase maturity: ... only 1 confirmations (need 100)"), although
mature coins covered the payment.

* getutxos marks coinbase outputs with `coinbase_height`;
* a wallet holding mature coinbase outputs plus a fresh, larger one pays
  1.5 GNB from mature outputs only, and the payment confirms;
* a wallet holding only an immature coinbase output refuses before signing,
  saying why, and nothing reaches the mempool.
"""

from test_framework.messages import Tx, hash_to_address
from test_framework.test_framework import GnbTestFramework
from test_framework.util import AssertionFailure, assert_equal, assert_in, assert_true

PAYEE = hash_to_address(bytes(range(201, 221)))
OTHER = hash_to_address(bytes(range(221, 241)))


class WalletCoinbaseMaturityTest(GnbTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def run_test(self):
        node = self.nodes[0]
        wallet = self.wallet_copy()
        addr = self.chain_info["wallet_address"]

        self.log.info("the wallet gets a fresh coinbase worth more than each mature one")
        node.cli_send(wallet, OTHER, "0.5")       # a fee for the next block
        fresh = node.generate(1, addr)[0]
        height = node.height()
        rows = node.getutxos(addr)["utxos"]
        cb_txid = node.getblock(fresh)["txids"][0]
        by_txid = {r["txid"]: r for r in rows}
        assert_equal(by_txid[cb_txid].get("coinbase_height"), height, "getutxos marks the fresh coinbase")
        mature = [r for r in rows if r.get("coinbase_height") is not None and r["txid"] != cb_txid]
        assert_equal(len(mature), 9, "nine untouched mature coinbase outputs remain")
        assert_true(all(height + 1 - r["coinbase_height"] >= 100 for r in mature))
        assert_true(int(by_txid[cb_txid]["value"]) > max(int(r["value"]) for r in mature),
                    "the immature output is the largest coin (largest-first would pick it)")

        self.log.info("a 1.5 GNB payment is built from mature outputs only and confirms")
        txid = node.cli_send(wallet, PAYEE, "1.5")
        tx = Tx.deserialize(bytes.fromhex(node.getrawtransaction(txid)["hex"]))
        spent = {i.prev_txid.hex() for i in tx.inputs}
        assert_true(cb_txid not in spent, "the immature coinbase output was selected")
        block = node.generate(1, OTHER)[0]
        assert_equal(node.gettransaction(txid)["block_hash"], block)
        assert_equal(node.getbalance(PAYEE)["satoshis"], "150000000")

        self.log.info("a wallet holding only an immature coinbase output refuses before signing")
        miner_wallet = f"{self.tmpdir}/miner.json"
        miner = node.cli_new_wallet(miner_wallet)
        node.generate(1, miner)
        try:
            node.cli_send(miner_wallet, PAYEE, "0.1")
        except AssertionFailure as e:
            assert_in("still immature", str(e))
        else:
            raise AssertionFailure("a wallet without a spendable coin must not send")
        assert_equal(node.mempool(), [], "nothing was broadcast")


if __name__ == "__main__":
    WalletCoinbaseMaturityTest().main()
