#!/usr/bin/env python3
"""Misbehaviour through the RPC submit paths: invalid blocks and transactions
are rejected with the right reason, change nothing and are never relayed.

(A raw TCP / libp2p adversary peer is out of scope for this framework; the
gossip ingress runs the same `accept_block` / `admission::admit` code, and
node/tests + node/fuzz cover the wire decoders.)

node0 is the target, node1 a connected observer that must never RECEIVE an
invalid object, node2 an isolated node used only to obtain a genuinely
signed transaction T (gnb-cli wallet) that node0 has never seen.

"Never relayed" is checked on delivery, not on storage: node1 would drop
most invalid objects itself, so "node1 does not have it" proves nothing.
node1 logs every gossiped block it receives (`← block h=<height> <hash>`,
info) and, with the debug target `gnb_gossip_rx_tx`, every gossiped
transaction (`← tx <txid>`); no rejected block hash or transaction id may
appear there. T and the valid blocks do appear (positive control: the trace
sees a relayed object).

Transactions (sendrawtransaction at node0): bad hex, garbage, trailing bytes,
a coinbase, a duplicated input, a missing input, outputs above inputs, a
dust output, version 1 at/after the activation, a forged amount (signature
no longer valid); then T itself is accepted and relayed, and a conflicting
copy and T again are refused.

Blocks (submitblock at node0), each built from a valid template with one
defect: bad hex, truncated, trailing bytes, bad Merkle root, legacy Merkle
root, missing / wrong-height / wrong-parents / wrong-witness coinbase
commitment, no coinbase, two coinbases, duplicate transaction, undecodable
compact bits, bits other than expected, wrong height, unknown parent,
timestamps in the future and before the parent, coinbase over-claim, two
coinbase outputs, a transaction already confirmed (BIP30: its outputs are
unspent). The
selected tip never moves, node1 never receives any of them, and a valid
block afterwards is relayed at once.

Not reachable here: a target above the pow limit (POW-9, POW-3). The test
build pins every target, and the pow limit, to 0x2100ffff, the largest
target compact bits can encode; any easier `bits` fails to decode first
(the vector above). The Rust tests cover the limit itself
(`validate_pow_enforces_the_height_pow_limit`).
"""

import re
import time

from test_framework.messages import (
    Tx, TxOut, address_to_script_pubkey, block_from_template, coinbase_commitment, create_coinbase,
    hash_to_address, ZERO32,
)
from test_framework.test_framework import GnbTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error, assert_true, wait_until

MINER = hash_to_address(bytes(range(90, 110)))
PAYEE = hash_to_address(bytes(range(110, 130)))


class InvalidBlocksTxsTest(GnbTestFramework):
    def set_test_params(self):
        self.num_nodes = 3

    def setup_network(self):
        n0, n1, n2 = self.nodes
        n0.start()
        # node1 traces every gossiped transaction it receives (debug target).
        n1.start(peers=[n0.p2p_addr],
                 env={"RUST_LOG": "info,libp2p_gossipsub=warn,libp2p_swarm=warn,gnb_gossip_rx_tx=debug"})
        n2.start()  # isolated signer
        self.wait_for_peers(pairs=[(n0, n1)])

    def received_by_node1(self) -> tuple:
        """(block hash prefixes, txid prefixes) node1 received over gossip."""
        log = self.nodes[1].log_since_start().decode("utf-8", "replace")
        return (set(re.findall(r"← block h=\d+ ([0-9a-f]{16})", log)),
                set(re.findall(r"← tx ([0-9a-f]{16})", log)))

    # ── helpers ──────────────────────────────────────────────────────────

    def tx_rejected(self, raw_hex: str, reason: str):
        assert_raises_rpc_error(reason, self.nodes[0].sendrawtransaction, raw_hex)
        self.note_rejected_tx(raw_hex)

    def note_rejected_tx(self, raw_hex: str):
        """Remember the txid of a rejected, decodable transaction that is not
        T itself (T is relayed legitimately)."""
        try:
            txid = Tx.deserialize(bytes.fromhex(raw_hex)).txid_hex()
        except Exception:  # noqa: BLE001 - malformed: it has no txid, nothing to trace
            return
        if txid != self.txid:
            self.rejected_txs.append(txid)

    def block_rejected(self, block, reason: str, *, search_nonce: bool = True):
        n0, n1 = self.nodes[0], self.nodes[1]
        tip = n0.tip()
        if search_nonce:
            assert_raises_rpc_error(reason, n0.submit_block, block)
        else:
            assert_raises_rpc_error(reason, n0.submitblock, block.serialize().hex())
        assert_equal(n0.tip(), tip, f"a rejected block ({reason}) must not move the tip")
        self.rejected.append(block.hash_hex())

    def template(self):
        return self.nodes[0].fresh_template()  # offers T once it is in the pool

    # ── test ─────────────────────────────────────────────────────────────

    def run_test(self):
        n0, n1, n2 = self.nodes
        spk = address_to_script_pubkey(MINER)
        self.rejected = []
        self.rejected_txs = []

        self.log.info("a signed payment T, made on the isolated node2")
        txid = n2.cli_send(self.wallet_copy(), PAYEE, "2")
        self.txid = txid
        raw = n2.getrawtransaction(txid)["hex"]
        tx = Tx.deserialize(bytes.fromhex(raw))
        assert_equal(n0.mempool(), [])

        def variant(mutate):
            t = Tx.deserialize(bytes.fromhex(raw))
            mutate(t)
            return t.serialize().hex()

        self.log.info("malformed and invalid transactions are refused")
        self.tx_rejected("zz", "invalid hex")
        self.tx_rejected("00" * 7, "deserialise failed")
        self.tx_rejected(raw + "00", "deserialise failed")
        coinbase_txid = n0.getblock(n0.getblockhash(5))["txids"][0]
        self.tx_rejected(n0.getrawtransaction(coinbase_txid)["hex"], "coinbase not accepted")
        self.tx_rejected(variant(lambda t: t.inputs.append(t.inputs[0])), "double-spend")

        def missing(t):
            t.inputs[0].prev_txid = bytes(31) + b"\x01"
        self.tx_rejected(variant(missing), "not found")

        def inflate(t):
            t.outputs[0].value += 10**12
        self.tx_rejected(variant(inflate), "inputs")

        def dust(t):
            t.outputs.append(TxOut(100, address_to_script_pubkey(PAYEE)))
        self.tx_rejected(variant(dust), "dust")

        def version1(t):
            t.version = 1
        self.tx_rejected(variant(version1), "version")

        def forged(t):
            t.outputs[0].value -= 1  # a bigger fee: valid amounts, forged signature
        e = assert_raises_rpc_error(None, n0.sendrawtransaction, variant(forged))
        assert_true("signature" in e.message.lower() or "verify" in e.message.lower(), e.message)
        self.note_rejected_tx(variant(forged))
        assert_equal(n0.mempool(), [])

        self.log.info("T itself is accepted and relayed; a conflicting copy and T again are refused")
        assert_equal(n0.sendrawtransaction(raw)["txid"], txid)
        wait_until(lambda: n1.mempool() == [txid], timeout=30, desc="node1 receives T")
        conflict = variant(lambda t: setattr(t.outputs[0], "value", t.outputs[0].value - 20_000))
        self.tx_rejected(conflict, "conflicts with a mempool tx")
        self.tx_rejected(raw, "duplicate")

        self.log.info("malformed blocks are refused")
        tmpl = self.template()
        good = block_from_template(tmpl, spk)
        assert_raises_rpc_error("invalid hex", n0.submitblock, "zz")
        assert_raises_rpc_error("deserialise failed", n0.submitblock, good.serialize().hex()[:-20])
        assert_raises_rpc_error("deserialise failed", n0.submitblock, good.serialize().hex() + "00")

        self.log.info("structurally invalid blocks are refused")
        b = block_from_template(tmpl, spk)
        b.merkle_root = bytes([b.merkle_root[0] ^ 1]) + b.merkle_root[1:]
        self.block_rejected(b, "invalid merkle root")
        b = block_from_template(tmpl, spk)
        b.merkle_root = b.legacy_root()
        self.block_rejected(b, "invalid merkle root")
        b = block_from_template(tmpl, spk)
        b.txs[0].inputs[0].script_sig = b"no commitment"
        b.merkle_root = b.tagged_root()
        self.block_rejected(b, "coinbase commitment missing")
        b = block_from_template(tmpl, spk)
        b.txs[0].inputs[0].script_sig = coinbase_commitment(b.height + 1, b.parents, b.txs)
        b.merkle_root = b.tagged_root()
        self.block_rejected(b, "bad-cb-height")
        b = block_from_template(tmpl, spk)
        b.txs[0].inputs[0].script_sig = coinbase_commitment(b.height, [ZERO32], b.txs)
        b.merkle_root = b.tagged_root()
        self.block_rejected(b, "parents commitment")
        b = block_from_template(tmpl, spk)  # commitment over [coinbase] only, then T appended
        b.txs.append(tx)
        b.merkle_root = b.tagged_root()
        self.block_rejected(b, "witness commitment")
        b = block_from_template(tmpl, spk, txs=[])
        b.txs = [tx]
        b.merkle_root = b.tagged_root()
        self.block_rejected(b, "invalid coinbase format")
        b = block_from_template(tmpl, spk, txs=[create_coinbase(1000, spk, b"second")])
        self.block_rejected(b, "invalid coinbase format")
        b = block_from_template(tmpl, spk, txs=[tx, tx])
        self.block_rejected(b, "duplicate transaction")
        b = block_from_template(tmpl, spk)
        b.bits = 0x2200FFFF  # undecodable compact bits (mantissa overflow); not POW-9, see the docstring
        self.block_rejected(b, "invalid PoW", search_nonce=False)

        self.log.info("contextually invalid blocks are refused")
        b = block_from_template(tmpl, spk)
        b.bits = 0x2100FFFE  # valid PoW, but not the expected bits
        self.block_rejected(b, "invalid difficulty")
        bad = dict(tmpl, height=tmpl["height"] + 1)
        self.block_rejected(block_from_template(bad, spk), "invalid height")
        bad = dict(tmpl, parents=["11" * 32])
        self.block_rejected(block_from_template(bad, spk), "unknown parent")
        self.block_rejected(block_from_template(tmpl, spk, timestamp=int(time.time()) + 3600),
                            "too far in the future")
        self.block_rejected(block_from_template(tmpl, spk, timestamp=int(tmpl["min_time"]) - 1),
                            "before parent")
        fee = int(tmpl["total_fees"])
        greedy = block_from_template(tmpl, spk, coinbase_value=int(tmpl["subsidy_sat"]) + fee + 1)
        self.block_rejected(greedy, "exceeds")
        b = block_from_template(tmpl, spk)
        b.txs[0].outputs.append(TxOut(1000, spk))
        b.commit()
        self.block_rejected(b, "1 output")

        self.log.info("a block repeating a confirmed transaction is refused")
        confirmed = n0.generate(1, MINER)[0]
        assert_equal(n0.gettransaction(txid)["block_hash"], confirmed)
        tmpl2 = self.template()
        # BIP30: its outputs exist, unspent, so the repeat would overwrite them.
        self.block_rejected(block_from_template(tmpl2, spk, txs=[tx]),
                            f"BIP30: output {txid[:16]}:0 would overwrite an unspent coin")

        self.log.info("node1 never received a rejected block or transaction")
        blocks, txs = self.received_by_node1()
        assert_equal((len(self.rejected), len(self.rejected_txs)), (18, 8), "every vector is traced")
        leaked = ([f"block {b[:16]}" for b in self.rejected if b[:16] in blocks]
                  + [f"tx {t[:16]}" for t in self.rejected_txs if t[:16] in txs])
        assert_equal(leaked, [], "rejected objects reached node1")

        self.log.info("the trace sees what node0 does relay; a valid block is relayed at once")
        self.sync_blocks([n0, n1])
        h = n0.generate(1, MINER)[0]
        wait_until(lambda: n1.tip() == h, timeout=30, desc="node1 receives the valid block")
        self.assert_same_chain_state([MINER, PAYEE], [n0, n1])
        blocks, txs = self.received_by_node1()
        assert_true({confirmed[:16], h[:16]} <= blocks, f"node1's block trace misses relayed blocks: {blocks}")
        assert_true(txid[:16] in txs, f"node1's transaction trace misses T: {txs}")


if __name__ == "__main__":
    InvalidBlocksTxsTest().main()
