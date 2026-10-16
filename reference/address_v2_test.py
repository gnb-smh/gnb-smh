"""Contract tests for the independent GnB address-v2 reference.

Generic checksum vectors originate in BIP350/BIP173 (BSD-2-Clause):
https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki#test-vectors-for-bech32m
https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#test-vectors
Application semantics and deterministic synthetic vectors are GnB-specific.
"""
import json
from pathlib import Path
import subprocess
import sys
import unittest

import address_v2 as a
import address_v2_vectors as v


BIP350_VALID = (
    "A1LQFN3A", "a1lqfn3a",
    "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
    "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
    "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
    "split1checkupstagehandshakeupstreamerranterredcaperredlc445v", "?1v759aa",
)
BIP350_INVALID = (
    "\x201xj0phk", "\x7f1g6xzxy", "\x801vctc34",
    "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
    "qyrz8wqd2c9m", "1qyrz8wqd2c9m", "y1b0jsk6g", "lt1igcx5c0",
    "in1muywd", "mm1crxm3i", "au1s5cgom", "M1VUXWEZ", "16plkw9", "1p2gdwpf",
)
BIP173_VALID = (
    "A12UEL5L", "a12uel5l",
    "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
    "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
    "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
    "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w", "?1ezyfcl",
)


class AddressV2Tests(unittest.TestCase):
    def test_generic_bip350_valid(self):
        for address in BIP350_VALID:
            with self.subTest(address=address):
                hrp, words = a._decode_words(address)
                self.assertEqual(a._encode_words(hrp, words), address.lower())

    def test_generic_bip350_invalid(self):
        for address in BIP350_INVALID:
            with self.subTest(address=address), self.assertRaises(a.AddressError):
                a._decode_words(address)

    def test_bech32_checksums_are_not_bech32m(self):
        for address in BIP173_VALID:
            with self.subTest(address=address), self.assertRaises(a.AddressError):
                a._decode_words(address)

    def test_generic_checksum_success_is_not_application_success(self):
        for address in BIP350_VALID:
            with self.subTest(address=address), self.assertRaises(a.AddressError):
                a.decode(address)

    def test_v2_reference_does_not_claim_legacy_parsing(self):
        # The shared corpus omits this valid legacy destination because the
        # production unified parser must accept it; this oracle is v2-only.
        with self.assertRaises(a.AddressError):
            a.decode("gnb1q89747fe8bda0f0fbad1f107d9852bb5523d446e0db89ce31")

    def test_vectors_are_byte_reproducible(self):
        self.assertEqual(v.VECTOR_FILE.read_bytes(), v.serialized())
        self.assertEqual(v.serialized(), v.serialized())

    def test_every_corpus_verdict_and_script(self):
        corpus = json.loads(v.VECTOR_FILE.read_text())
        self.assertEqual(corpus["format"], "gnb-address-v2-v1")
        names = [case["name"] for case in corpus["cases"]]
        self.assertEqual(len(names), len(set(names)))
        for case in corpus["cases"]:
            with self.subTest(name=case["name"]):
                reply = a.oracle({"op": "decode", "address": case["address"], **({"expected_network": case["expected_network"]} if "expected_network" in case else {})})
                self.assertEqual(reply["ok"], case["valid"])
                if case["valid"]:
                    for field in ("network", "kind", "hash_hex", "script_hex"):
                        self.assertEqual(reply[field], case[field])
                    self.assertEqual(reply["address"], case["canonical"])
                    self.assertEqual(a.encode(case["network"], case["kind"], bytes.fromhex(case["hash_hex"])), case["canonical"])

    def test_output_script_mapping_and_lengths(self):
        for network, hrp in a.HRPS.items():
            for kind, (_, length) in a.KINDS.items():
                payload = bytes(range(length))
                address = a.encode(network, kind, payload)
                decoded = a.decode(address)
                expected_script = payload if kind == "single-key" else b"\x02" + payload
                self.assertEqual(bytes.fromhex(decoded["script_hex"]), expected_script)
                self.assertEqual(len(address), len(hrp) + 1 + 2 + (length * 8 + 4) // 5 + 6)

    def test_recomputed_other_network_is_valid_but_wrong_for_caller(self):
        for kind, (_, length) in a.KINDS.items():
            payload = bytes([0x42]) * length
            main = a.encode("mainnet", kind, payload)
            test = a.encode("testnet", kind, payload)
            self.assertEqual(a.decode(main)["script_hex"], a.decode(test)["script_hex"])
            with self.assertRaises(a.AddressError):
                a.decode(test, "mainnet")
            with self.assertRaises(a.AddressError):
                a.decode("t" + main)

    def test_strict_padding_even_with_valid_checksum(self):
        words = [2, 1] + a._hash_words(bytes(32))
        for bits in range(1, 16):
            with self.subTest(bits=bits), self.assertRaises(a.AddressError):
                a.decode(a._encode_words("gnb", words[:-1] + [bits]))
        for words in ([2, 0] + [0] * 33, [2, 1] + [0] * 53):
            with self.subTest(words=len(words)), self.assertRaises(a.AddressError):
                a.decode(a._encode_words("gnb", words))

    def test_encoder_rejects_wrong_types_lengths_and_metadata(self):
        for network, kind, payload in (
            ("regtest", "single-key", bytes(20)), ("mainnet", "unknown", bytes(20)),
            ("mainnet", "single-key", bytes(19)), ("mainnet", "single-key", bytes(21)),
            ("mainnet", "policy", bytes(31)), ("mainnet", "policy", bytes(33)),
            ("mainnet", "single-key", "00" * 20), ([], "single-key", bytes(20)),
        ):
            with self.subTest(network=network, kind=kind), self.assertRaises(a.AddressError):
                a.encode(network, kind, payload)

    def test_oracle_schema_errors_are_rejections(self):
        base = {"op": "encode", "network": "mainnet", "kind": "single-key", "hash_hex": "00" * 20}
        for request in (None, [], {}, {"op": "unknown"}, {**base, "secret": "not-accepted"}, {**base, "hash_hex": "AA" * 20}, {**base, "hash_hex": "0 " * 20}, {"op": "decode", "address": 42}, {"op": "decode", "address": a.encode("mainnet", "single-key", bytes(20)), "expected_network": []}):
            with self.subTest(request=request):
                self.assertEqual(a.oracle(request), {"ok": False})
        self.assertTrue(a.oracle(base)["ok"])

    def test_json_lines_oracle_process(self):
        request = {"op": "encode", "network": "testnet", "kind": "policy", "hash_hex": "00" * 32}
        proc = subprocess.run([sys.executable, str(Path(a.__file__))], input=json.dumps(request) + "\n{bad json\n", text=True, capture_output=True, check=True, timeout=10)
        self.assertEqual([json.loads(line) for line in proc.stdout.splitlines()], [a.oracle(request), {"ok": False}])
        self.assertEqual(proc.stderr, "")


if __name__ == "__main__":
    unittest.main()
