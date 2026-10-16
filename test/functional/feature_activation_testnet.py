#!/usr/bin/env python3
"""The hardening activation on testnet (activation height 0), end to end.

On testnet the hardening block rules (docs/CONSENSUS.md, "Block rules at the
hardening activation") apply from height 1, the first block after genesis
(`rules_active_at(h, A)` = h >= 1 and h >= A). Starting from genesis:

* getblocktemplate announces it: hardening_active, activation height 0,
  tagged Merkle rule, wire size rule, a coinbase commitment prefix for
  height 1 that matches the Python encoding.
* At height 1, a block in the pre-activation format (SHA-256d Merkle tree,
  no coinbase commitment) is rejected, so are blocks with only one of the
  two changes, and a block with both is accepted and relayed.
* The internal miner (node1 --mine) produces blocks that satisfy the rules:
  every mined block's coinbase starts with the 80-byte commitment for its
  height, parents and witness root, and its header root is the tagged tree
  of its transaction ids, checked in Python on block data read back from
  the node over RPC.

The other side of the boundary (mainnet, 17,500) cannot be reached by this
test-only binary, which refuses mainnet; it is covered by the Rust tests
that move the activation height (activation::scoped_override). Transaction
rules at the activation are exercised by mempool_tx_relay.py (gnb-cli signs
version 3) and p2p_invalid_blocks_txs.py (version 1 refused).
"""

import struct

from test_framework.messages import (
    COINBASE_COMMITMENT_TAG, Tx, address_to_script_pubkey, block_from_template, coinbase_commitment,
    hash_to_address, tagged_merkle_root,
)
from test_framework.test_framework import GnbTestFramework
from test_framework.util import (
    assert_equal, assert_greater_than_or_equal, assert_raises_rpc_error, assert_true, wait_until,
)

MINER = hash_to_address(bytes(range(5, 25)))
INTERNAL_MINER = hash_to_address(bytes(range(25, 45)))
MINED_BLOCKS = 3


class ActivationTestnetTest(GnbTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_network(self):
        n0, n1 = self.nodes
        n0.start()
        n1.start(peers=[n0.p2p_addr])
        self.wait_for_peers()

    def check_hardened(self, node, block_hash):
        """Read the block back over RPC and check the hardening encodings."""
        info = node.getblock(block_hash, True)
        txs = [Tx.deserialize(bytes.fromhex(node.getrawtransaction(t["txid"])["hex"]))
               for t in info["transactions"]]
        parents = [bytes.fromhex(p) for p in info["parents"]]
        ss = txs[0].inputs[0].script_sig
        assert_true(ss.startswith(COINBASE_COMMITMENT_TAG + struct.pack("<Q", info["height"])),
                    f"block {block_hash[:16]}: coinbase commitment tag/height")
        assert_equal(ss[:80], coinbase_commitment(info["height"], parents, txs))
        assert_equal(info["merkle_root"], tagged_merkle_root([t.txid() for t in txs]).hex())

    def run_test(self):
        n0, n1 = self.nodes
        spk = address_to_script_pubkey(MINER)

        self.log.info("the template at height 1 announces the hardening rules")
        assert_equal(n0.getblockcount(), 1)
        tmpl = n0.getblocktemplate()
        assert_equal(tmpl["height"], 1)
        assert_equal((tmpl["hardening_active"], tmpl["hardening_activation_height"]), (True, 0))
        assert_equal((tmpl["merkle_rule"], tmpl["size_rule"]), ("gnb-tagged-v1", "wire"))
        good = block_from_template(tmpl, spk)
        assert_equal(tmpl["coinbase_script_sig_prefix"], coinbase_commitment(1, good.parents, good.txs).hex())

        self.log.info("height 1: the pre-activation block format is rejected")
        legacy = block_from_template(tmpl, spk, extra=b"legacy")
        legacy.txs[0].inputs[0].script_sig = b"gnb:h1:legacy"
        legacy.merkle_root = legacy.legacy_root()
        assert_raises_rpc_error("invalid merkle root", n0.submit_block, legacy)

        self.log.info("height 1: commitment with the legacy root, and tagged root without commitment")
        half = block_from_template(tmpl, spk, extra=b"half-a")
        half.merkle_root = half.legacy_root()
        assert_raises_rpc_error("invalid merkle root", n0.submit_block, half)
        half = block_from_template(tmpl, spk, extra=b"half-b")
        half.txs[0].inputs[0].script_sig = b"gnb:h1:no-commitment"
        half.merkle_root = half.tagged_root()
        assert_raises_rpc_error("coinbase commitment missing", n0.submit_block, half)
        assert_equal(n0.getblockcount(), 1, "nothing was stored")

        self.log.info("height 1: the hardened block is accepted and relayed")
        h1 = n0.submit_block(good)
        self.sync_blocks()
        assert_equal(n1.tip(), h1)
        self.check_hardened(n1, h1)

        self.log.info("the internal miner produces hardened blocks")
        # Solo (no --peer): a miner told to join a network waits for the
        # 30 s peer-count heartbeat and a remote tip before mining.
        n1.restart(mine=True, miner_address=INTERNAL_MINER, peers=[])
        wait_until(lambda: n1.height() >= 1 + MINED_BLOCKS, timeout=120,
                   desc=f"node1 mines {MINED_BLOCKS} blocks")
        n1.restart(peers=[n0.p2p_addr])
        self.wait_for_peers()
        self.sync_blocks()
        top = n0.height()
        assert_greater_than_or_equal(top, 1 + MINED_BLOCKS)
        for h in range(2, top + 1):
            bh = n0.getblockhash(h)
            assert_equal(n0.getblock(bh, True)["transactions"][0]["outputs"][0]["script_pubkey"],
                         address_to_script_pubkey(INTERNAL_MINER).hex())
            self.check_hardened(n0, bh)
        self.assert_same_chain_state([MINER, INTERNAL_MINER])


if __name__ == "__main__":
    ActivationTestnetTest().main()
