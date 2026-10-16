"""GnB difficulty -- executable reference specification.

Compact `bits` <-> 256-bit target, chain work, and the ASERT retarget rule
(aserti3-2d construction) exactly as GnB consensus applies them. This file is
the normative definition; `crates/gnb-smh/src/difficulty.rs` and
`crates/gnb-crypto` must reproduce `difficulty_vectors.json` exactly
(`crates/gnb-smh/tests/difficulty_vectors.rs`,
`crates/gnb-crypto/tests/difficulty_vectors.rs`). Python integers are
unbounded, so every quantity below is exact; the only bounds are the ones the
consensus code enforces explicitly (i128 intermediates, u64 heights, i64
times).

    target(bits)  Bitcoin nBits decoding; every malformed encoding is an error
    bits(target)  Bitcoin nBits encoding (keeps the top 3 bytes, rounds down)
    work(t)       = max(floor((2^128 - 1) / (floor(t / 2^128) + 1)), 1), work(0) = 0
    valid        <=> be256(GnB-SMH output) < target(bits)

ASERT, for a block at `height` whose parents' latest timestamp is
`parent_time`, anchored at a block (`anchor_height`, `anchor_bits`,
`anchor_time` = the anchor block's own timestamp):

    ahead    = parent_time - anchor_time - T * (height - anchor_height - 1)
    exponent = floor(ahead * 65536 / halflife)           # rounds toward -infinity
    shifts   = floor(exponent / 65536);  frac = exponent mod 65536
    factor   = 65536 + ((195766423245049*frac + 971821376*frac^2 + 5127*frac^3 + 2^47) >> 48)
    target   = floor(anchor_target * factor * 2^(shifts - 16)), clamped to [1, pow_limit]

The rounding of `exponent` is floor (toward -infinity). BCHN's aserti3-2d
uses C++ `/`, which truncates toward zero; the two differ by one unit of
2^-16 half-life when `ahead * 65536` is negative and not a multiple of the
half-life. GnB measures time from the anchor block itself and counts the
blocks from the anchor up to and including the parent, where BCHN uses the
anchor's parent time and `height_diff + 1`; the schedules are the same.

GnB's consensus inputs (docs/CONSENSUS.md): the anchor is the genesis block;
`parent_time` is the latest timestamp over ALL parents of the block (not the
GhostDAG selected parent's), and `height` is max(parent heights) + 1.

Pow limit (audit POW-3): for a block at header height `height` the clamp is
`pow_limit_bits_at(height, activation_height)`: the genesis target
(GENESIS_BITS) when 1 <= height and height >= activation_height (the
hardening activation, mainnet 25,800), POW_LIMIT_BITS before.
"""

from __future__ import annotations

# ── GnB consensus constants ──────────────────────────────────────────────────
TARGET_SPACING = 30              # seconds
HALFLIFE = 2 * 60 * 60           # seconds (240 blocks)
POW_LIMIT_BITS = 0x2100FFFF
HARDENED_POW_LIMIT_BITS = 0x1F0E9036   # = GENESIS_BITS (POW-3)
MAINNET_HARDENING_ACTIVATION_HEIGHT = 25_800   # activation.rs (110_000 before 2026-10-16)
GENESIS_BITS = 0x1F0E9036
GENESIS_TIMESTAMP = 1791429092
GENESIS_HEIGHT = 0

U64_MAX = (1 << 64) - 1
I64_MIN, I64_MAX = -(1 << 63), (1 << 63) - 1
I128_MIN, I128_MAX = -(1 << 127), (1 << 127) - 1


class BitsError(ValueError):
    """`kind` is one of NegativeFlag, ZeroMantissa, ExponentOutOfRange,
    MantissaOverflow, ZeroTarget (the Rust `BitsError` variants)."""

    def __init__(self, kind: str):
        super().__init__(kind)
        self.kind = kind


class AsertError(ValueError):
    """`kind` is one of HeightNotAboveAnchor, InvalidAnchor, ArithmeticOverflow."""

    def __init__(self, kind: str):
        super().__init__(kind)
        self.kind = kind


# ── Compact bits ─────────────────────────────────────────────────────────────

def bits_to_target(bits: int) -> int:
    """Decode compact bits. Errors, checked in this order: the sign bit
    0x00800000 is set; the 23-bit mantissa is zero; the exponent places the
    mantissa beyond 31 bytes of shift; the target is 2^256 or more; the
    target is zero (an exponent <= 3 shifts the mantissa right, rounding
    down)."""
    if not 0 <= bits <= 0xFFFFFFFF:
        raise ValueError("bits must be a u32")
    if bits & 0x00800000:
        raise BitsError("NegativeFlag")
    exponent = bits >> 24
    mantissa = bits & 0x007FFFFF
    if mantissa == 0:
        raise BitsError("ZeroMantissa")
    if exponent <= 3:
        target = mantissa >> (8 * (3 - exponent))
    else:
        if exponent - 3 > 31:
            raise BitsError("ExponentOutOfRange")
        target = mantissa << (8 * (exponent - 3))
        if target >> 256:
            raise BitsError("MantissaOverflow")
    if target == 0:
        raise BitsError("ZeroTarget")
    return target


def bits_to_target_or_zero(bits: int) -> int:
    """Consensus decode: malformed bits map to the zero target, which no
    output meets (and which carries zero work)."""
    try:
        return bits_to_target(bits)
    except BitsError:
        return 0


def target_to_bits(target: int) -> int:
    """Encode in compact form, keeping the three most significant bytes (so
    decode(encode(t)) <= t). The zero target encodes as 0."""
    if not 0 <= target < 1 << 256:
        raise ValueError("target must be in [0, 2^256 - 1]")
    if target == 0:
        return 0
    size = (target.bit_length() + 7) // 8
    if size <= 3:
        mantissa = target << (8 * (3 - size))
    else:
        mantissa = target >> (8 * (size - 3))
    if mantissa & 0x00800000:
        mantissa >>= 8
        size += 1
    return (size << 24) | (mantissa & 0x007FFFFF)


# ── Chain work ───────────────────────────────────────────────────────────────

def work(target: int) -> int:
    """Chain-work contribution of a block with this target (consensus).

    work(t) = max(floor((2^128 - 1) / (floor(t / 2^128) + 1)), 1) for
    1 <= t <= 2^256 - 1, and work(0) = 0. This approximates 2^256 / t: it
    never exceeds floor(2^256 / t) nor Bitcoin Core's floor(2^256 / (t + 1)),
    and saturates at 2^128 - 1 for t < 2^128. Blue work is the sum of work()
    over a block's blue set; it fits a u128 in the Rust code.
    """
    if not 0 <= target < 1 << 256:
        raise ValueError("target must be in [0, 2^256 - 1]")
    if target == 0:
        return 0
    return max(((1 << 128) - 1) // ((target >> 128) + 1), 1)


def work_from_bits(bits: int) -> int:
    """work() of the decoded target; malformed bits carry zero work."""
    return work(bits_to_target_or_zero(bits))


# ── ASERT ────────────────────────────────────────────────────────────────────

def _i128(x: int) -> int:
    if not I128_MIN <= x <= I128_MAX:
        raise AsertError("ArithmeticOverflow")
    return x


def asert_next_target(parent_time: int, height: int, *,
                      anchor_height: int = GENESIS_HEIGHT,
                      anchor_bits: int = GENESIS_BITS,
                      anchor_time: int = GENESIS_TIMESTAMP,
                      target_spacing: int = TARGET_SPACING,
                      halflife: int = HALFLIFE,
                      pow_limit_bits: int = POW_LIMIT_BITS) -> int:
    """Target of the block at `height` whose parent time is `parent_time`.

    Domains (as in the Rust signature): parent_time, anchor_time and
    target_spacing are i64; height and anchor_height are u64; halflife is a
    positive i64. Errors, in this order: height <= anchor_height; anchor bits
    malformed; an intermediate (T * blocks, ahead, ahead * 65536) outside the
    i128 range.
    """
    if not (I64_MIN <= parent_time <= I64_MAX and I64_MIN <= anchor_time <= I64_MAX
            and I64_MIN <= target_spacing <= I64_MAX):
        raise ValueError("times and spacing are i64")
    if not (0 <= height <= U64_MAX and 0 <= anchor_height <= U64_MAX):
        raise ValueError("heights are u64")
    if not 0 < halflife <= I64_MAX:
        raise ValueError("halflife must be a positive i64")
    if height <= anchor_height:
        raise AsertError("HeightNotAboveAnchor")
    try:
        anchor_target = bits_to_target(anchor_bits)
    except BitsError as e:
        raise AsertError("InvalidAnchor") from e
    pow_limit = bits_to_target_or_zero(pow_limit_bits)

    blocks = height - anchor_height - 1        # anchor .. parent, parent included
    schedule = _i128(target_spacing * blocks)
    ahead = _i128((parent_time - anchor_time) - schedule)
    exponent = _i128(ahead * 65536) // halflife  # floor: rounds toward -infinity
    shifts = exponent >> 16                      # floor
    frac = exponent & 0xFFFF                     # 0..65535
    factor = 65536 + ((195766423245049 * frac + 971821376 * frac ** 2
                       + 5127 * frac ** 3 + (1 << 47)) >> 48)

    if shifts >= 256:  # 2^256 * anchor_target: above every limit
        return pow_limit
    net = shifts - 16
    product = anchor_target * factor
    target = product << net if net >= 0 else product >> -net
    if target > pow_limit:
        target = pow_limit
    if target == 0:
        target = 1
    return target


def asert_next_bits(parent_time: int, height: int, **kw) -> int:
    """Compact bits of asert_next_target (what consensus compares)."""
    return target_to_bits(asert_next_target(parent_time, height, **kw))


# ── GnB's difficulty input ───────────────────────────────────────────────────

def difficulty_input(parents: list[tuple[int, int]]) -> tuple[int, int]:
    """(parent_time, height) of a block with these parents, each given as
    (dag_height, timestamp): the LATEST timestamp over all parents and
    max(parent heights) + 1. Neither depends on the GhostDAG selected parent
    or on the parents' order."""
    if not parents:
        raise ValueError("a non-genesis block has at least one parent")
    return max(t for _, t in parents), max(h for h, _ in parents) + 1


def pow_limit_bits_at(height: int, activation_height: int) -> int:
    """Pow limit of a block at header height `height` (POW-3): the genesis
    target at/after the hardening activation (never for the genesis itself),
    POW_LIMIT_BITS before."""
    if height >= 1 and height >= activation_height:
        return HARDENED_POW_LIMIT_BITS
    return POW_LIMIT_BITS


def expected_bits(parents: list[tuple[int, int]],
                  activation_height: int = MAINNET_HARDENING_ACTIVATION_HEIGHT) -> int:
    """`bits` a GnB block with these parents must carry under the given
    hardening activation height (mainnet by default). A parent timestamp
    above i64::MAX is an error (the Rust code converts u64 -> i64)."""
    parent_time, height = difficulty_input(parents)
    if parent_time > I64_MAX:
        raise ValueError("parent timestamp out of range")
    return asert_next_bits(parent_time, height,
                           pow_limit_bits=pow_limit_bits_at(height, activation_height))
