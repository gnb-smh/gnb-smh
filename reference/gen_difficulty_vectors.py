"""Generate difficulty_vectors.json from the reference (gnb_difficulty.py).

Deterministic: the "random" cases come from SHAKE-256 of a fixed label, so the
file is reproducible byte for byte (CI regenerates it and diffs).
"""

import hashlib
import json
import pathlib

import gnb_difficulty as d

HERE = pathlib.Path(__file__).resolve().parent


class Rng:
    """SHAKE-256 counter-mode stream: identical on every platform and Python."""

    def __init__(self, label: bytes):
        self.label = label
        self.i = 0

    def below(self, n: int) -> int:
        self.i += 1
        x = int.from_bytes(hashlib.shake_256(self.label + self.i.to_bytes(8, "little")).digest(40), "little")
        return x % n

    def between(self, lo: int, hi: int) -> int:
        return lo + self.below(hi - lo + 1)


def hex256(t: int) -> str:
    return t.to_bytes(32, "big").hex()


def compact_vectors():
    cases = [
        0x1F0E9036, 0x2100FFFF, 0x1D00FFFF, 0x1F00FFFF, 0x2000FFFF, 0x1B0404CB,
        0x03007FFF, 0x0300FFFF, 0x02008000, 0x01003456, 0x0400FFFF, 0x207FFFFF,
        0x21010000, 0x2200FFFF, 0x2201_0000, 0x22000001, 0x23000001, 0x0480_0001,
        0x2000_0000, 0xFF00FFFF, 0x0100_0001, 0x00123456, 0x01120000, 0x04123456,
        0x05009234, 0x20123456, 0x1E7FFFFF, 0,
    ]
    rng = Rng(b"gnb-difficulty-vectors/compact")
    for _ in range(20):
        cases.append(rng.below(1 << 32))
    for _ in range(40):
        cases.append((rng.between(0, 0x22) << 24) | rng.between(1, 0x7FFFFF))
    out = []
    for bits in cases:
        try:
            t = d.bits_to_target(bits)
            out.append({"bits": bits, "target_hex": hex256(t), "work": str(d.work(t)),
                        "reencoded_bits": d.target_to_bits(t)})
        except d.BitsError as e:
            out.append({"bits": bits, "error": e.kind, "work": "0"})
    return out


def target_vectors():
    targets = [0, 1, 2, 0xFF, 0x80, 0x7FFFFF, 0x800000, 0xFFFFFF, 0x1000000,
               (1 << 128) - 1, 1 << 128, (1 << 128) + 1, (2 << 128) - 1, 2 << 128,
               1 << 192, (1 << 192) - 1, 1 << 255, (1 << 255) + 1, (1 << 256) - 1,
               (1 << 256) - (1 << 128), (1 << 256) - (1 << 128) - 1,
               d.bits_to_target(d.GENESIS_BITS), d.bits_to_target(d.POW_LIMIT_BITS),
               d.bits_to_target(d.POW_LIMIT_BITS) + 1, 0x1234567890ABCDEF << 100]
    rng = Rng(b"gnb-difficulty-vectors/targets")
    for _ in range(40):
        bits = rng.between(1, 256)
        targets.append(rng.below(1 << bits))
    return [{"target_hex": hex256(t), "bits": d.target_to_bits(t), "work": str(d.work(t))}
            for t in targets]


GNB = {"target_spacing": d.TARGET_SPACING, "halflife": d.HALFLIFE,
       "pow_limit_bits": d.POW_LIMIT_BITS}
GENESIS_ANCHOR = {"height": d.GENESIS_HEIGHT, "bits": d.GENESIS_BITS,
                  "timestamp": d.GENESIS_TIMESTAMP}


def asert_case(params, anchor, parent_time, height, note=""):
    kw = dict(anchor_height=anchor["height"], anchor_bits=anchor["bits"],
              anchor_time=anchor["timestamp"], target_spacing=params["target_spacing"],
              halflife=params["halflife"], pow_limit_bits=params["pow_limit_bits"])
    v = {"params": params, "anchor": anchor, "parent_time": parent_time, "height": height}
    if note:
        v["note"] = note
    try:
        t = d.asert_next_target(parent_time, height, **kw)
        v["target_hex"] = hex256(t)
        v["bits"] = d.target_to_bits(t)
    except d.AsertError as e:
        v["error"] = e.kind
    return v


def asert_vectors():
    out = []
    g, a = GNB, GENESIS_ANCHOR
    t0 = a["timestamp"]

    def on_schedule(h, anchor=a, params=g):
        return anchor["timestamp"] + params["target_spacing"] * (h - anchor["height"] - 1)

    for h in (1, 2, 100, 10_000, 1_000_000, 1 << 32):
        out.append(asert_case(g, a, on_schedule(h), h, "on schedule keeps the anchor bits"))
    for skew in (1, 59, 600, 3_599, 7_199, 7_200, 7_201, 14_400, 57_600, 86_400,
                 -1, -59, -600, -7_199, -7_200, -7_201, -57_601, -86_400, -1_000_000):
        out.append(asert_case(g, a, on_schedule(1000) + skew, 1000, f"skew {skew} s"))
    out.append(asert_case(g, a, t0 - 1, 1,
                          "floor, not truncation: exponent -10, aserti3-2d's C++ `/` gives -9"))
    out.append(asert_case(g, a, t0 + 365 * 86_400, 1, "late chain clamps to the pow limit"))
    out.append(asert_case(g, a, t0, 50_000_000, "far behind clamps to target 1"))
    out.append(asert_case(g, a, d.I64_MAX, 1, "i64::MAX parent time"))
    out.append(asert_case(g, a, d.I64_MIN, d.U64_MAX, "extremes"))
    out.append(asert_case(g, a, t0, 0, "height at the anchor"))
    rng = Rng(b"gnb-difficulty-vectors/asert-gnb")
    for i in range(80):
        h = rng.between(1, 1 << 32)
        span = 630_720_000 if i % 2 else 150_000  # +-20 years, or +-21 half-lives
        skew = rng.between(-span, span)
        out.append(asert_case(g, a, on_schedule(h) + skew, h))

    # Generic anchors and parameters (the library rule).
    high = {"height": 0, "bits": 0x2100A34E, "timestamp": 1_000_000}
    out.append(asert_case(g, high, high["timestamp"] - 57_601, 1,
                          "AUD-1: anchor near the pow limit, eight half-lives behind"))
    at_limit = {"height": 0, "bits": d.POW_LIMIT_BITS, "timestamp": 1_000_000}
    for ahead in (1, 60, 3_600, -1, -7_200):
        out.append(asert_case(g, at_limit, at_limit["timestamp"] + ahead, 1))
    out.append(asert_case(g, {"height": 0, "bits": 0xFF00FFFF, "timestamp": 0}, 0, 1, "invalid anchor"))
    bch = {"target_spacing": 600, "halflife": 172_800, "pow_limit_bits": 0x1D00FFFF}
    bch_anchor = {"height": 661_647, "bits": 0x1804DAFE, "timestamp": 1_605_447_844}
    for blocks, skew in ((1, 0), (2, 600), (1_000, -86_400), (100_000, 3_000_000)):
        h = bch_anchor["height"] + blocks
        out.append(asert_case(bch, bch_anchor, on_schedule(h, bch_anchor, bch) + skew, h))
    huge = {"target_spacing": d.I64_MAX, "halflife": 1, "pow_limit_bits": d.POW_LIMIT_BITS}
    out.append(asert_case(huge, {"height": 0, "bits": d.GENESIS_BITS, "timestamp": 0}, 0, d.U64_MAX,
                          "ahead * 65536 overflows i128"))
    rng = Rng(b"gnb-difficulty-vectors/asert-generic")
    for i in range(80):
        if rng.below(4) == 0:
            bits = (0x21 << 24) | rng.between(1, 0xFFFF)
        else:
            bits = (rng.between(4, 0x20) << 24) | rng.between(0x10000, 0x7FFFFF)
        anchor = {"height": rng.between(0, 1_000_000), "bits": bits,
                  "timestamp": rng.between(0, 2_000_000_000)}
        blocks = rng.between(1, 10_000_000)
        h = anchor["height"] + blocks
        span = 100_000_000 if i % 2 else 1_000_000
        skew = rng.between(-span, span)
        out.append(asert_case(g, anchor, on_schedule(h, anchor) + skew, h))
    return out


def expected_bits_vectors():
    """GnB-level rule: latest parent timestamp, max parent height + 1."""
    t0 = d.GENESIS_TIMESTAMP
    sets = [
        [(0, t0)],
        [(0, t0), (1, t0 + 30)],
        [(5, t0 + 120), (3, t0 + 900), (4, t0 + 30)],
        [(3, t0 + 900), (5, t0 + 120), (4, t0 + 30)],
        [(100, t0 + 2_970), (99, t0 + 2_960)],
        [(100, t0 + 2_970), (40, t0 + 9_000)],
        [(10, t0 - 5_000), (12, t0 - 4_000)],
        [(7, t0 + 400_000), (8, t0 + 1)],
        [(1, d.I64_MAX)],
        [(1, d.I64_MAX + 1), (2, t0)],
    ]
    out = []
    for parents in sets:
        parent_time, height = d.difficulty_input(parents)
        v = {"parents": [{"height": h, "timestamp": t} for h, t in parents],
             "parent_time": parent_time, "height": height}
        try:
            v["bits"] = d.expected_bits(parents)
        except ValueError:
            v["error"] = "ParentTimestampOutOfRange"
        out.append(v)
    return out


def build() -> dict:
    return {
        "description": "GnB difficulty vectors from reference/gnb_difficulty.py: compact bits, "
                       "target encoding, chain work and ASERT. Targets are 32-byte big-endian hex; "
                       "work is a decimal string (u128).",
        "gnb": {"target_spacing": d.TARGET_SPACING, "halflife": d.HALFLIFE,
                "pow_limit_bits": d.POW_LIMIT_BITS, "genesis_bits": d.GENESIS_BITS,
                "genesis_timestamp": d.GENESIS_TIMESTAMP, "genesis_height": d.GENESIS_HEIGHT},
        "compact": compact_vectors(),
        "targets": target_vectors(),
        "asert": asert_vectors(),
        "gnb_expected_bits": expected_bits_vectors(),
    }


def render(doc: dict) -> str:
    return json.dumps(doc, indent=1) + "\n"


def main():
    doc = build()
    (HERE / "difficulty_vectors.json").write_text(render(doc))
    print(f"{len(doc['compact'])} compact, {len(doc['targets'])} target, "
          f"{len(doc['asert'])} ASERT, {len(doc['gnb_expected_bits'])} expected-bits vectors")


if __name__ == "__main__":
    main()
