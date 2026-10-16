"""Tests for the GnB ledger reference (standard library only): python3 test_ledger.py"""

from __future__ import annotations

import copy
import dataclasses
import json
import pathlib
import random
import unittest

import gnb_ledger as L

HERE = pathlib.Path(__file__).resolve().parent
VECTORS = json.loads((HERE / "ledger_vectors.json").read_text())


def state_of(d: dict) -> L.State:
    return L.State(bytes.fromhex(d["utxo_root"]), bytes.fromhex(d["nullifier_root"]))


def ctx_of(v: dict) -> L.Context:
    return L.Context(height=v["height"], subsidy=v["subsidy"], auth=L.test_preimage_auth,
                     coinbase_maturity=v["coinbase_maturity"])


def run_vector(v: dict):
    wires = [bytes.fromhex(h) for h in v["txs_hex"]]
    return L.validate_block(state_of(v["pre"]), bytes.fromhex(v["header_hex"]), int(v["nonce"]), wires,
                            bytes.fromhex(v["witness_hex"]), ctx_of(v), log2_n=v["log2_n"])


class SparseMerkleTreeTest(unittest.TestCase):
    def test_vectors(self):
        smt = VECTORS["smt"]
        self.assertEqual(L.EMPTY_ROOT.hex(), smt["empty_root"])
        self.assertEqual(L.DEFAULTS[1].hex(), smt["default_1"])
        self.assertEqual(L.DEFAULTS[255].hex(), smt["default_255"])
        self.assertEqual(L.State().commitment().hex(), smt["genesis_state_commitment"])
        t = L.SparseMerkleTree()
        values = {}
        for s in smt["steps"]:
            k = bytes.fromhex(s["key"])
            if s["op"] == "insert":
                values[k] = bytes.fromhex(s["value"])
                t.set(k, L.leaf_hash(k, values[k]))
            else:
                del values[k]
                t.set(k, L.EMPTY)
            self.assertEqual(t.root().hex(), s["root"])
        root = bytes.fromhex(smt["final_root"])
        for p in smt["proofs"]:
            k = bytes.fromhex(p["key"])
            sibs, end = L.decode_proof(bytes.fromhex(p["proof"]))
            self.assertEqual(end, len(p["proof"]) // 2)
            leaf = L.leaf_hash(k, values[k]) if p["present"] else L.EMPTY
            self.assertEqual(L.root_from(k, leaf, sibs), root)
            # the same siblings must not prove the opposite claim
            other = L.EMPTY if p["present"] else L.leaf_hash(k, bytes(32))
            self.assertNotEqual(L.root_from(k, other, sibs), root)
        with self.assertRaises(L.InvalidBlock) as cm:
            L.decode_proof(bytes.fromhex(smt["noncanonical_proof"]))
        self.assertEqual(cm.exception.code, "noncanonical-proof")

    def test_random_operations_against_proofs(self):
        rng = random.Random(7)
        t = L.SparseMerkleTree()
        keys = [rng.randbytes(32) for _ in range(120)]
        live: dict[bytes, bytes] = {}
        for step in range(400):
            k = rng.choice(keys)
            if k in live and rng.random() < 0.45:
                sibs, _ = L.decode_proof(t.proof(k))
                self.assertEqual(L.root_from(k, L.leaf_hash(k, live[k]), sibs), t.root())
                expected = L.root_from(k, L.EMPTY, sibs)
                t.set(k, L.EMPTY)
                del live[k]
            else:
                v = rng.randbytes(32)
                sibs, _ = L.decode_proof(t.proof(k))
                expected = L.root_from(k, L.leaf_hash(k, v), sibs)
                t.set(k, L.leaf_hash(k, v))
                live[k] = v
            self.assertEqual(t.root(), expected, f"step {step}")
        for k in list(live):
            t.set(k, L.EMPTY)
        self.assertEqual(t.root(), L.EMPTY_ROOT)
        self.assertEqual(t._nodes, {})

    def test_truncated_proofs(self):
        t = L.SparseMerkleTree()
        k = bytes(range(32))
        t.set(k, L.leaf_hash(k, bytes(32)))
        t.set(bytes(31) + b"\x01", L.leaf_hash(bytes(31) + b"\x01", bytes(32)))
        p = t.proof(k)
        self.assertGreater(len(p), 32)
        for cut in (0, 10, 31, len(p) - 1):
            with self.assertRaises(L.InvalidBlock) as cm:
                L.decode_proof(p[:cut])
            self.assertEqual(cm.exception.code, "witness-format")


class LedgerVectorTest(unittest.TestCase):
    def test_chain_and_synthetic(self):
        for v in VECTORS["chain"] + VECTORS["synthetic"]:
            with self.subTest(v["name"]):
                post, accepted = run_vector(v)
                self.assertEqual(post, state_of(v["post"]))
                self.assertEqual(accepted, v["accepted"])
                txs = [L.decode_tx_wire(bytes.fromhex(h)) for h in v["txs_hex"]]
                self.assertEqual([L.txid(t).hex() for t in txs], v["txids"])
                self.assertEqual([L.wtxid(bytes.fromhex(h)).hex() for h in v["txs_hex"]], v["wtxids"])
                self.assertEqual([L.tx_wire(t).hex() for t in txs], v["txs_hex"])

    def test_chain_links(self):
        chain = VECTORS["chain"]
        for prev, nxt in zip(chain, chain[1:]):
            self.assertEqual(prev["post"], nxt["pre"])
            parent = L.block_id(bytes.fromhex(prev["header_hex"]), int(prev["nonce"]))
            self.assertEqual(L.Header.decode(bytes.fromhex(nxt["header_hex"])).parents_root, parent)

    def test_mergeset(self):
        """LED-1 mergeset coinbase-collision vectors (applied without a header)."""
        self.assertEqual(len(VECTORS["mergeset"]), 6)
        for v in VECTORS["mergeset"]:
            with self.subTest(v["name"]):
                ctx = L.Context(height=v["height"], subsidy=v["subsidy"], auth=L.test_preimage_auth,
                                coinbase_maturity=v["coinbase_maturity"],
                                parents_root=bytes.fromhex(v["parents_root"]))
                txs = [L.decode_tx_wire(bytes.fromhex(h)) for h in v["txs_hex"]]
                run = lambda: L.apply_block_txs(state_of(v["pre"]), txs, bytes.fromhex(v["witness_hex"]),
                                                ctx, merged=v["merged"])
                if "expected_error" in v:
                    with self.assertRaises(L.InvalidBlock) as cm:
                        run()
                    self.assertEqual((cm.exception.code, cm.exception.permanent),
                                     (v["expected_error"], v["permanent"]))
                else:
                    post, accepted = run()
                    self.assertEqual((post, accepted), (state_of(v["post"]), v["accepted"]))

    def test_invalid_blocks(self):
        for v in VECTORS["invalid"]:
            with self.subTest(v["name"]):
                with self.assertRaises(L.InvalidBlock) as cm:
                    run_vector(v)
                self.assertEqual(cm.exception.code, v["expected_error"])
                self.assertEqual(cm.exception.permanent, v["permanent"])


class LimitsTest(unittest.TestCase):
    """Consensus limits over committed data bound the work a block can demand."""

    ctx = L.Context(height=1, subsidy=0, auth=L.test_preimage_auth)

    def _cb(self) -> L.Tx:
        return L.Tx(L.TX_COINBASE, (), (L.TxOut(0, bytes(32)),), 1, b"")

    def test_block_key_limit(self):
        per_tx = L.MAX_OUTPUTS + 1                       # 1 input + MAX_OUTPUTS outputs
        n = L.MAX_BLOCK_KEYS // per_tx + 1
        txs = [self._cb()] + [
            L.Tx(L.TX_REGULAR, (L.Outpoint(bytes([i]) * 32, 0),),
                 tuple(L.TxOut(0, bytes(32)) for _ in range(L.MAX_OUTPUTS)), auth=(b"",))
            for i in range(n)]
        self.assertGreater(sum(len(t.inputs) + len(t.outputs) for t in txs), L.MAX_BLOCK_KEYS)
        with self.assertRaises(L.InvalidBlock) as cm:
            L.check_block_txs(txs, self.ctx)
        self.assertEqual((cm.exception.code, cm.exception.permanent), ("isolation", True))
        L.check_block_txs(txs[:-1], self.ctx)            # one transaction fewer fits

    def test_auth_entry_length(self):
        ok = L.Tx(L.TX_REGULAR, (L.Outpoint(bytes(32), 0),), (L.TxOut(1, bytes(32)),),
                  auth=(bytes(L.MAX_AUTH_LEN),))
        L.check_tx_isolation(ok)
        self.assertEqual(L.decode_tx_wire(L.tx_wire(ok)), ok)
        long = L.Tx(L.TX_REGULAR, ok.inputs, ok.outputs, auth=(bytes(L.MAX_AUTH_LEN + 1),))
        for f in (lambda: L.check_tx_isolation(long), lambda: L.decode_tx_wire(L.tx_wire(long))):
            with self.assertRaises(L.InvalidBlock) as cm:
                f()
            self.assertEqual(cm.exception.code, "isolation")

    def test_block_bytes_limit_is_checked_after_tx_root(self):
        filler = L.Tx(L.TX_REGULAR, (L.Outpoint(bytes(32), 0),), (L.TxOut(1, bytes(32)),),
                      auth=(bytes(L.MAX_AUTH_LEN),))
        wires = [L.tx_wire(self._cb())] + [L.tx_wire(filler)] * (L.MAX_BLOCK_TX_BYTES // L.MAX_AUTH_LEN + 1)
        self.assertGreater(sum(map(len, wires)), L.MAX_BLOCK_TX_BYTES)
        good_root = L.tx_root([L.wtxid(w) for w in wires])
        hdr = L.Header(bytes(32), good_root, L.witness_commitment(b""), bytes(32), 0, 1 << 255)
        with self.assertRaises(L.InvalidBlock) as cm:
            L.validate_body(L.State(), hdr, wires, b"", self.ctx)
        self.assertEqual((cm.exception.code, cm.exception.permanent), ("isolation", True))
        wrong = L.Header(bytes(32), bytes(32), L.witness_commitment(b""), bytes(32), 0, 1 << 255)
        with self.assertRaises(L.InvalidBlock) as cm:
            L.validate_body(L.State(), wrong, wires, b"", self.ctx)
        self.assertEqual((cm.exception.code, cm.exception.permanent), ("tx-root", False))
        # A bundle that does not hash to witness_root: transient, before any rule is judged.
        with self.assertRaises(L.InvalidBlock) as cm:
            L.validate_body(L.State(), hdr, wires, b"\x00", self.ctx)
        self.assertEqual((cm.exception.code, cm.exception.permanent), ("witness-commitment", False))

    def test_witness_size_cap(self):
        """LED-1: a bundle above MAX_WITNESS_BYTES is refused before it is hashed
        (transient: it cannot be attributed to the header); one at the cap is hashed."""
        cb = self._cb()
        wires = [L.tx_wire(cb)]
        big = bytes(L.MAX_WITNESS_BYTES + 1)
        hdr = L.Header(bytes(32), L.tx_root([L.wtxid(w) for w in wires]), L.witness_commitment(big),
                       bytes(32), 0, 1 << 255)
        with self.assertRaises(L.InvalidBlock) as cm:
            L.validate_body(L.State(), hdr, wires, big, self.ctx)
        self.assertEqual((cm.exception.code, cm.exception.permanent), ("witness-size", False))
        at_cap = bytes(L.MAX_WITNESS_BYTES)
        at_hdr = dataclasses.replace(hdr, witness_root=L.witness_commitment(at_cap))
        with self.assertRaises(L.InvalidBlock) as cm:     # hashed, then judged as a bundle
            L.validate_body(L.State(), at_hdr, wires, at_cap, self.ctx)
        self.assertEqual((cm.exception.code, cm.exception.permanent), ("witness-format", True))

    def test_permanence_classes(self):
        # LED-1 added witness-size (an oversized bundle is refused unhashed).
        self.assertEqual(set(L.InvalidBlock.CODES) - L.InvalidBlock.PERMANENT,
                         {"tx-root", "witness-size", "witness-commitment"})
        for code in L.InvalidBlock.CODES:
            self.assertEqual(L.InvalidBlock(code).permanent, code in L.InvalidBlock.PERMANENT)


class CoinbaseBindingTest(unittest.TestCase):
    """The coinbase commits to the block height and the header's parents_root."""

    def test_parents_root_is_encoded_and_checked(self):
        pr = bytes(range(32))
        cb = L.Tx(L.TX_COINBASE, (), (L.TxOut(0, bytes(32)),), 1, b"x", parents_root=pr)
        wire = L.tx_wire(cb)
        self.assertEqual(wire[13:45], pr)                 # right after the height
        self.assertEqual(L.decode_tx_wire(wire), cb)
        ctx = L.Context(height=1, subsidy=0, auth=L.test_preimage_auth)
        with self.assertRaises(L.InvalidBlock) as cm:
            L.check_block_txs([cb], ctx)
        self.assertEqual((cm.exception.code, str(cm.exception)), ("isolation", "isolation: coinbase parents root"))
        L.check_block_txs([cb], L.Context(height=1, subsidy=0, auth=L.test_preimage_auth, parents_root=pr))
        # Same height, payee and extra on another parent set: a different coinbase txid.
        other = L.Tx(L.TX_COINBASE, (), cb.outputs, 1, b"x", parents_root=bytes(32))
        self.assertNotEqual(L.txid(cb), L.txid(other))

    def test_regular_tx_cannot_carry_one(self):
        tx = L.Tx(L.TX_REGULAR, (L.Outpoint(bytes(32), 0),), (L.TxOut(1, bytes(32)),), auth=(b"",),
                  parents_root=bytes(range(32)))
        with self.assertRaises(L.InvalidBlock) as cm:
            L.check_tx_isolation(tx)
        self.assertEqual(cm.exception.code, "isolation")

    def test_header_layout(self):
        h = L.Header(b"\x01" * 32, b"\x02" * 32, b"\x03" * 32, b"\x04" * 32, 5, 6)
        b = h.encode()
        self.assertEqual(len(b), L.HEADER_LEN)
        self.assertEqual(L.Header.decode(b), h)
        self.assertEqual(b[68:100], b"\x03" * 32)            # witness_root after tx_root


class MergesetCoinbaseTest(unittest.TestCase):
    """LED-1: two blocks on the same parents at the same height with identical
    coinbases share their coinbase output keys. When a chain block merges the
    second (a twin of a block already applied), the twin forfeits its coinbase and
    the merging block stays valid; on its own the twin's entry is still invalid."""

    PR = bytes(range(32))

    def setUp(self):
        self.alice, self.bob = L.test_owner(b"alice"), L.test_owner(b"bob")
        self.node = L.FullNode()
        self.funding = L.Tx(L.TX_COINBASE, (), (L.TxOut(500, self.bob),), 1, b"fund")
        self.node.insert(L.outpoint_key(L.txid(self.funding), 0), L.UtxoRecord(500, self.bob, 1, False))
        self.ctx = L.Context(height=5, subsidy=1_000, auth=L.test_preimage_auth, coinbase_maturity=1,
                             parents_root=self.PR)
        self.cb = L.Tx(L.TX_COINBASE, (), (L.TxOut(1_000, self.alice), L.TxOut(0, self.bob)), 5, b"same",
                       parents_root=self.PR)
        # The selected-chain block A pays the coinbase first.
        self.state = self.node.state()
        witness, _, _ = self.node.build([self.cb], self.ctx)
        self.state, _ = L.apply_block_txs(self.state, [self.cb], witness, self.ctx)
        self.assertEqual(self.state, self.node.state())

    def _spend(self):
        return L.Tx(L.TX_REGULAR, (L.Outpoint(L.txid(self.funding), 0),), (L.TxOut(400, self.alice),),
                    auth=(b"bob",))

    def test_twin_forfeits_its_coinbase_when_merged(self):
        txs = [self.cb, self._spend()]
        witness, accepted, _ = self.node.build(txs, self.ctx, merged=True)
        self.assertEqual(accepted, [False, True])
        post, flags = L.apply_block_txs(self.state, txs, witness, self.ctx, merged=True)
        self.assertEqual((post, flags), (self.node.state(), [False, True]))
        # The coinbase was paid once: A's outputs are the ones in the tree.
        self.assertEqual(self.node.utxos[L.outpoint_key(L.txid(self.cb), 0)].amount, 1_000)

    def test_the_same_entry_is_invalid_outside_a_mergeset(self):
        txs = [self.cb, self._spend()]
        witness, _, _ = copy.deepcopy(self.node).build(txs, self.ctx, merged=True)
        with self.assertRaises(L.InvalidBlock) as cm:
            L.apply_block_txs(self.state, txs, witness, self.ctx)
        self.assertEqual((cm.exception.code, cm.exception.permanent), ("coinbase", True))
        with self.assertRaises(L.InvalidBlock) as cm:
            copy.deepcopy(self.node).build(txs, self.ctx)
        self.assertEqual(cm.exception.code, "coinbase")

    def test_collision_must_be_with_an_identical_coinbase_output(self):
        node = L.FullNode()
        key = L.outpoint_key(L.txid(self.cb), 0)
        node.insert(key, L.UtxoRecord(1_000, self.alice, 4, True))   # another height: not a twin
        witness, _, _ = copy.deepcopy(node).build([self.cb], self.ctx, merged=True)
        with self.assertRaises(L.InvalidBlock) as cm:
            L.apply_block_txs(node.state(), [self.cb], witness, self.ctx, merged=True)
        self.assertEqual((cm.exception.code, str(cm.exception)),
                         ("coinbase", "coinbase: colliding output is not an identical coinbase output"))

    def test_merged_overclaim_is_still_invalid(self):
        greedy = L.Tx(L.TX_COINBASE, (), (L.TxOut(1_001, self.alice),), 5, b"same", parents_root=self.PR)
        with self.assertRaises(L.InvalidBlock) as cm:
            copy.deepcopy(self.node).build([greedy], self.ctx, merged=True)
        self.assertEqual(cm.exception.code, "coinbase")

    def test_fee_claiming_twin_forfeits_when_merged(self):
        """Review follow-up: twins come from one template, so the second carries
        the first one's transactions. Merged, those are rejected (inputs already
        spent) and its fees are 0, while its identical coinbase still claims
        subsidy + the first one's fees. The forfeit is exempt from the claim
        check; before, the merged twin -- and every block merging it -- was
        permanently invalid (coinbase)."""
        node = L.FullNode()
        funding = L.Tx(L.TX_COINBASE, (), (L.TxOut(500, self.bob),), 1, b"fund")
        node.insert(L.outpoint_key(L.txid(funding), 0), L.UtxoRecord(500, self.bob, 1, False))
        T = L.Tx(L.TX_REGULAR, (L.Outpoint(L.txid(funding), 0),), (L.TxOut(400, self.alice),), auth=(b"bob",))
        cb = L.Tx(L.TX_COINBASE, (), (L.TxOut(1_100, self.alice),), 5, b"fee-twin", parents_root=self.PR)
        txs = [cb, T]
        s0 = node.state()
        # B on its own parent is valid (fee 100 covers the claim).
        wb, acc_b, fees_b = copy.deepcopy(node).build(txs, self.ctx)
        self.assertEqual((L.apply_block_txs(s0, txs, wb, self.ctx)[1], fees_b), ([True, True], 100))
        # A (same template) is applied first.
        wa, acc_a, _ = node.build(txs, self.ctx)
        s1, flags_a = L.apply_block_txs(s0, txs, wa, self.ctx)
        self.assertEqual((s1, flags_a, acc_a), (node.state(), [True, True], [True, True]))
        # Merging B: T is rejected (input spent), the coinbase is forfeited, nothing changes.
        w, accepted, fees = node.build(txs, self.ctx, merged=True)
        self.assertEqual((accepted, fees), ([False, False], 0))
        post, flags = L.apply_block_txs(s1, txs, w, self.ctx, merged=True)
        self.assertEqual((post, flags), (node.state(), [False, False]))
        self.assertEqual(post, s1, "the forfeited twin mints nothing")
        # Outside a mergeset the same block is still invalid (claim check first).
        with self.assertRaises(L.InvalidBlock) as cm:
            L.apply_block_txs(s1, txs, w, self.ctx)
        self.assertEqual((cm.exception.code, cm.exception.permanent), ("coinbase", True))
        self.assertIn("claims more", str(cm.exception))
        with self.assertRaises(L.InvalidBlock) as cm:
            copy.deepcopy(node).build(txs, self.ctx)
        self.assertEqual(cm.exception.code, "coinbase")

    def test_forfeit_exemption_needs_a_valid_forfeit(self):
        """The exemption covers only a proven identical twin: an overclaiming
        coinbase colliding with a different record is still invalid, and a
        forfeit entry whose proof does not verify is a witness fault."""
        node = L.FullNode()
        greedy = L.Tx(L.TX_COINBASE, (), (L.TxOut(1_100, self.alice),), 5, b"greedy", parents_root=self.PR)
        key = L.outpoint_key(L.txid(greedy), 0)
        node.insert(key, L.UtxoRecord(1_100, self.alice, 4, True))      # another height: not a twin
        w, _, _ = copy.deepcopy(node).build([greedy], self.ctx, merged=True)
        with self.assertRaises(L.InvalidBlock) as cm:
            L.apply_block_txs(node.state(), [greedy], w, self.ctx, merged=True)
        self.assertEqual((cm.exception.code, str(cm.exception)),
                         ("coinbase", "coinbase: colliding output is not an identical coinbase output"))
        twin = L.FullNode()
        twin.insert(key, L.UtxoRecord(1_100, self.alice, 5, True))
        w, _, _ = copy.deepcopy(twin).build([greedy], self.ctx, merged=True)
        bad = bytearray(w)
        bad[4 + 1 + 4] ^= 1         # count, tag, output index, then the claimed value: proof fails
        with self.assertRaises(L.InvalidBlock) as cm:
            L.apply_block_txs(twin.state(), [greedy], bytes(bad), self.ctx, merged=True)
        self.assertEqual(cm.exception.code, "witness-mismatch")

    def test_a_non_identical_sibling_is_paid(self):
        sibling = L.Tx(L.TX_COINBASE, (), (L.TxOut(1_000, self.bob),), 5, b"other", parents_root=self.PR)
        witness, accepted, _ = self.node.build([sibling], self.ctx, merged=True)
        post, flags = L.apply_block_txs(self.state, [sibling], witness, self.ctx, merged=True)
        self.assertEqual((post, flags, accepted), (self.node.state(), [True], [True]))


class DifferentialTest(unittest.TestCase):
    """The producer decides outcomes from the full UTXO map; the validator only sees roots
    and witnesses. Random blocks must lead both to the same state, block after block."""

    def test_random_blocks(self):
        rng = random.Random(2026)
        people = [f"p{i}".encode() for i in range(6)]
        owner = {p: L.test_owner(p) for p in people}
        node = L.FullNode()
        state = node.state()
        known: list[tuple[bytes, int, bytes, int]] = []   # (txid, vout, secret, amount), possibly spent
        for height in range(1, 26):
            ctx = L.Context(height=height, subsidy=1_000, auth=L.test_preimage_auth, coinbase_maturity=3)
            regular = []
            for _ in range(rng.randrange(0, 7)):
                if not known:
                    break
                picks = rng.sample(known, min(len(known), rng.randrange(1, 3)))
                total = sum(p[3] for p in picks)
                spend_more = rng.random() < 0.15
                out_total = total + 1 if spend_more else rng.randrange(0, total + 1)
                cut = rng.randrange(0, out_total + 1)
                signers = [p[2] if rng.random() > 0.1 else b"wrong" for p in picks]
                tx = L.Tx(L.TX_REGULAR, tuple(L.Outpoint(p[0], p[1]) for p in picks),
                          (L.TxOut(cut, owner[rng.choice(people)]),
                           L.TxOut(out_total - cut, owner[rng.choice(people)])),
                          auth=tuple(signers))
                regular.append(tx)
            dry = copy.deepcopy(node)
            cb0 = L.Tx(L.TX_COINBASE, (), (L.TxOut(0, owner[people[0]]),), height, b"dry")
            _, _, fees = dry.build([cb0] + regular, ctx)
            payee = rng.choice(people)
            cb = L.Tx(L.TX_COINBASE, (), (L.TxOut(1_000 + fees, owner[payee]),), height, b"cb")
            txs = [cb] + regular
            witness, accepted, _ = node.build(txs, ctx)
            new_state, flags = L.apply_block_txs(state, txs, witness, ctx)
            self.assertEqual(new_state, node.state(), f"height {height}")
            self.assertEqual(flags, accepted)
            state = new_state
            for tx, ok in zip(txs, accepted):
                if ok:
                    secret_of = {owner[p]: p for p in people}
                    tid = L.txid(tx)
                    for o, out in enumerate(tx.outputs):
                        known.append((tid, o, secret_of[out.owner], out.amount))
            # keep old entries around on purpose: they produce double-spend attempts
        self.assertGreater(len(node.utxos), 0)


if __name__ == "__main__":
    unittest.main(verbosity=1)
