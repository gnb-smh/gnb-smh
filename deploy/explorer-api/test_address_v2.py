"""Standalone deployed decoder and carryover identity; no socket or node required."""
import hashlib
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("address_v2_api", Path(__file__).with_name("gnb_explorer_api.py"))
api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api)
V2 = "gnb1zqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdaq6uw"
CASES = (
    (V2, "gnb1q", bytes(20)),
    ("tgnb1zqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqtxkpzc", "gnb1t", bytes(20)),
    ("gnb1zpqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqggmvny", "gnb1m", bytes(32)),
    ("tgnb1zpqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqht5fkx", "gnb1n", bytes(32)),
)

def legacy(prefix, payload):
    body = (prefix.encode() if len(payload) == 32 else b"") + payload
    checksum = hashlib.sha3_256(hashlib.sha3_256(body).digest()).digest()[:4]
    return prefix + (payload + checksum).hex()

# Independent bounded vector construction, using a bit-string conversion.
def encoded(words, hrp="gnb", constant=0x2bc830a3):
    alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    reg = 1
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    for word in expanded + words + [0] * 6:
        high = reg >> 25
        reg = ((reg & 0x1ffffff) << 5) ^ word
        for bit, polynomial in enumerate((0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)):
            if high & (1 << bit):
                reg ^= polynomial
    reg ^= constant
    return hrp + "1" + "".join(alphabet[w] for w in words + [(reg >> s) & 31 for s in range(25, -1, -5)])


class AddressV2Tests(unittest.TestCase):
    def setUp(self):
        self.saved = api._carry.copy()
        api._carry.clear()

    def tearDown(self):
        api._carry.clear()
        api._carry.update(self.saved)

    def test_legacy_control_unchanged(self):
        a = legacy("gnb1q", bytes(20))
        api._carry[a] = [12345, 2, 67890]
        self.assertEqual(api.ADDRESS(a), a)
        self.assertEqual(api.carryover_of(a)["result"]["amount"], "12345")

    def test_alias_gate_and_carryover_share_identity(self):
        for index, (a, prefix, payload) in enumerate(CASES):
            canonical = legacy(prefix, payload)
            api._carry[canonical] = [12345 + index, index + 2, 67890 + index]
            expected = api.carryover_of(canonical)["result"]
            for alias in (a, a.upper()):
                with self.subTest(alias=alias):
                    self.assertEqual(api.ADDRESS(alias), alias)
                    result = api.carryover_of(alias)["result"]
                    self.assertEqual(result, expected)
        # A testnet alias must not retrieve a mainnet allocation.
        api._carry.pop(legacy("gnb1t", bytes(20)))
        self.assertFalse(api.carryover_of(CASES[1][0])["result"]["in_carryover"])

    def test_nonzero_payload_and_recomputed_checksum_rejections(self):
        for size, kind in ((20, 0), (32, 1)):
            payload = bytes(range(size))
            bits = "".join(f"{b:08b}" for b in payload)
            bits += "0" * (-len(bits) % 5)
            words = [int(bits[i:i+5], 2) for i in range(0, len(bits), 5)]
            for hrp, prefix in (("gnb", "gnb1q" if kind == 0 else "gnb1m"), ("tgnb", "gnb1t" if kind == 0 else "gnb1n")):
                a = encoded([2, kind] + words, hrp)
                canonical = legacy(prefix, payload)
                api._carry[canonical] = [42, 1, 100]
                self.assertEqual(api.carryover_of(a)["result"], api.carryover_of(canonical)["result"])
        invalid = [encoded([1, 0] + [0] * 32), encoded([2, 2] + [0] * 32),
                   encoded([2, 0] + [0] * 31), encoded([2, 0] + [0] * 33),
                   encoded([2, 1] + [0] * 51 + [1]), encoded([2, 1] + [0] * 53),
                   encoded([2, 0] + [0] * 32, constant=1), encoded([2, 0] + [0] * 32, hrp="other")]
        for a in invalid:
            with self.subTest(address=a), self.assertRaises(ValueError):
                api.carryover_of(a)

    def test_syntax_rejects_markup_separators_and_mixed_case(self):
        for a in (V2 + '"', V2 + "/more", V2 + "\n", "G" + V2[1:], V2[:-1], None):
            with self.subTest(address=a), self.assertRaises(ValueError):
                api.ADDRESS(a)

    def test_carryover_rejects_invalid_checksum_instead_of_empty_result(self):
        for a in (V2[:-1] + "q", V2.replace("gnb1", "tgnb1"), "G" + V2[1:]):
            with self.subTest(address=a), self.assertRaises(ValueError):
                api.carryover_of(a)

if __name__ == "__main__":
    unittest.main()
