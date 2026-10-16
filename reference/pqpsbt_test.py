"""Tests of the independent PQ-PSBT oracle, including deliberate invalid controls."""
import copy
import json
import subprocess
import sys
import unittest
from unittest.mock import patch

import pqpsbt as p
import pqpsbt_vectors as v


class ReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(v.VECTOR_FILE.read_text())
        cls.base = cls.manifest["accepted"][0]["document"]

    def test_committed_acceptance_and_exact_bytes(self):
        for case in self.manifest["accepted"]:
            with self.subTest(case=case["name"]):
                raw = bytes.fromhex(case["binary"])
                self.assertEqual(p.decode(raw), case["document"])
                self.assertEqual(p.encode(case["document"]), raw)
                self.assertEqual(p.to_json(case["document"]), case["canonical_json"])
                self.assertEqual(p.from_json(case["canonical_json"]), case["document"])

    def test_committed_rejections(self):
        for kind, field in (("rejected_binary", "binary"), ("rejected_json", "json")):
            for case in self.manifest[kind]:
                with self.subTest(case=case["name"], encoding=field):
                    self.assertEqual(p.check_case({field: case[field]}), {"accepted": False})

    def test_deterministic_regeneration(self):
        self.assertEqual(v.VECTOR_FILE.read_text(), v.render())
        self.assertEqual(self.manifest["seeded_cases"], 64)
        self.assertEqual(sum(c["name"].startswith("seeded-") for c in self.manifest["accepted"] + self.manifest["rejected_binary"]), 64)

    def test_jsonl_batch_protocol(self):
        cases = [{"binary": case["binary"]} for case in self.manifest["accepted"] + self.manifest["rejected_binary"]]
        cases += [{"json": case["json"]} for case in self.manifest["rejected_json"]]
        result = subprocess.run([sys.executable, str(v.HERE / "pqpsbt.py"), "--jsonl"], input="".join(json.dumps(c) + "\n" for c in cases), text=True, capture_output=True, timeout=30, check=True)
        actual = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(actual, [p.check_case(case) for case in cases])

    def test_all_truncation_positions(self):
        raw = p.encode(self.base)
        for position in range(len(raw)):
            with self.assertRaises(p.Invalid, msg=f"prefix {position}"):
                p.decode(raw[:position])

    def test_binary_size_before_parsing(self):
        with patch.object(p, "Reader", side_effect=AssertionError("must not parse")):
            with self.assertRaises(p.Invalid):
                p.decode(bytes(p.MAX_BINARY + 1))

    def test_complete_binary_exact_limit_and_one_past(self):
        doc = v.make_document(count=9)
        unsigned = p.transaction(bytes.fromhex(doc["transaction"]))
        script = bytes.fromhex(doc["inputs"][0]["script"])
        # Nine large previous transactions with the same non-witness txid;
        # distinct selected output indices avoid duplicated outpoints.
        previous = {"version": 1, "inputs": [{"txid": b"p" * 32, "index": i, "script": b"", "sequence": 0xffffffff} for i in range(9)], "outputs": [{"value": 100000, "script": script} for _ in range(9)], "locktime": 0}
        txid = p.transaction_id(previous)
        for i, inp in enumerate(unsigned["inputs"]):
            inp.update(txid=txid, index=i)
        doc["transaction"] = p.transaction_bytes(unsigned).hex()
        available = p.MAX_BINARY - len(p.encode(doc))
        per_previous, extra = divmod(available, 9)
        empty_size = len(p.transaction_bytes(previous))
        for i, metadata in enumerate(doc["inputs"]):
            target = per_previous + (extra if i == 8 else 0)
            per_script, remainder = divmod(target - empty_size - 4 * 9, 9)
            for j, inp in enumerate(previous["inputs"]):
                inp["script"] = bytes(per_script + (remainder if j == 8 else 0))
            raw = p.transaction_bytes(previous)
            self.assertEqual(len(raw), target)
            metadata["previous_tx"] = raw.hex()
        encoded = p.encode(doc)
        self.assertEqual(len(encoded), p.MAX_BINARY)
        self.assertEqual(p.decode(encoded), doc)
        # The derived allowance preserves JSON equivalence at the binary cap.
        text = p.to_json(doc)
        self.assertGreater(len(text), 16 * 1024 * 1024)
        self.assertLessEqual(len(text), p.MAX_JSON)
        self.assertEqual(p.encode(p.from_json(text)), encoded)
        previous["inputs"][0]["script"] += b"x"
        doc["inputs"][-1]["previous_tx"] = p.transaction_bytes(previous).hex()
        with self.assertRaisesRegex(p.Invalid, "complete binary size"):
            p.encode(doc)

    def test_canonical_json_metadata_bound(self):
        # Empty payload hex strings isolate metadata. Values need not form a
        # valid transaction: independently maximizing every bounded field is
        # a conservative upper bound, even when amount sums constrain them.
        item = {"value": str(p.U64_MAX), "script": "", "previous_tx": None,
                "derivations": [{"key_index": i, "fingerprint": "ffffffff", "path": [0xffffffff] * 16} for i in range(7)],
                "signatures": [{"key_index": i, "signature": ""} for i in range(7)]}
        doc = {"format": "gnb-pqpsbt", "version": 1, "network": "mainnet", "transaction": "", "policy": "", "tree": None, "branch": None, "inputs": [item] * 64}
        measured = len(json.dumps(doc, separators=(",", ":")))
        conservative = 256 + 64 * (256 + 7 * (128 + 16 * 11) + 7 * 64)
        self.assertEqual(measured, 121337)
        self.assertEqual(conservative, 181504)
        self.assertLessEqual(measured, conservative)
        self.assertLessEqual(conservative, p.MAX_JSON - 2 * p.MAX_BINARY)
        self.assertEqual(p.MAX_JSON, 17039360)

    def test_json_size_before_parsing(self):
        with patch.object(p.json, "loads", side_effect=AssertionError("must not parse")):
            with self.assertRaises(p.Invalid):
                p.from_json(" " * (p.MAX_JSON + 1))
            with self.assertRaises(p.Invalid):
                p.from_json("é" * (p.MAX_JSON // 2 + 1))

    def test_field_length_before_copy(self):
        reader = p.Reader(p.integer(p.MAX_TX + 1, 4))
        with self.assertRaisesRegex(p.Invalid, "count limit"):
            reader.blob(p.MAX_TX)
        self.assertEqual(reader.offset, 4)

    def test_programmatic_objects_revalidated(self):
        doc = copy.deepcopy(self.base)
        doc["inputs"][0]["value"] = "1"
        for operation in (p.encode, p.to_json, p.validate):
            with self.assertRaisesRegex(p.Invalid, "negative fee"):
                operation(doc)

    def test_json_order_whitespace_and_exact_integers(self):
        case = next(c for c in self.manifest["accepted"] if c["name"] == "v3-u64-max-exact")
        text = json.dumps(dict(reversed(list(case["document"].items()))), indent=3)
        doc = p.from_json(text)
        self.assertEqual(doc["inputs"][0]["value"], "18446744073709551615")
        self.assertEqual(p.encode(doc).hex(), case["binary"])
        self.assertEqual(list(doc), list(p.TOP))

    def test_huge_json_number_is_a_rejection_not_exception(self):
        text = p.to_json(self.base).replace('"version":1', '"version":' + "9" * 5000)
        self.assertEqual(p.check_case({"json": text}), {"accepted": False})

    def test_json_negative_zero_and_float_integer_aliases(self):
        text = p.to_json(self.base)
        for lexical in ("-0", "1.0", "1e0", "NaN", "Infinity"):
            with self.subTest(lexical=lexical):
                self.assertEqual(p.check_case({"json": text.replace('"version":1', '"version":' + lexical)}), {"accepted": False})

    def test_previous_tx_binding_and_witness_semantics(self):
        for coinbase in (False, True):
            doc = v.make_document(previous=True, coinbase=coinbase)
            old_binary = p.encode(doc)
            previous = p.transaction(bytes.fromhex(doc["inputs"][0]["previous_tx"]))
            previous["inputs"][0]["script"] += b"x"
            doc["inputs"][0]["previous_tx"] = p.transaction_bytes(previous).hex()
            if coinbase:
                with self.assertRaisesRegex(p.Invalid, "previous transaction hash"):
                    p.encode(doc)
            else:
                self.assertNotEqual(p.encode(doc), old_binary)
                self.assertEqual(p.decode(p.encode(doc)), doc)

    def test_policy_tree_hash_has_fixed_independent_anchor(self):
        # A hand-built two-leaf commitment, independent of tree_script control flow.
        branch = bytes.fromhex(self.base["policy"])
        leaf = p.hashlib.sha3_256(b"GNB-POLICY-v2/leaf" + branch).digest()
        root = p.hashlib.sha3_256(b"GNB-POLICY-v2/node" + leaf + leaf).digest()
        expected = b"\x02" + p.hashlib.sha3_256(b"GNB-POLICY-v1\x02\x02" + root).digest()
        self.assertEqual(p.tree_script(b"\x02\x02" + p.blob(branch) * 2, 1, branch), expected)

    def test_invalid_control_detects_accept_all_oracle(self):
        # The checker must fail when its rejection verdict is deliberately broken.
        rejected = self.manifest["rejected_binary"][0]
        with patch.object(p, "decode", return_value=self.base):
            self.assertNotEqual(p.check_case({"binary": rejected["binary"]}), {"accepted": False})

    def test_invalid_control_detects_changed_vector_bytes(self):
        doc = copy.deepcopy(self.base)
        doc["network"] = "testnet"
        self.assertNotEqual(p.encode(doc).hex(), self.manifest["accepted"][0]["binary"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
