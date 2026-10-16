"""Independent, stdlib-only GnB address-v2 reference and JSON-lines oracle.

The contract is docs/ADDRESS-V2.md. This is a GnB application of the generic
Bech32m checksum in BIP350, not a Bitcoin Segwit address implementation. The
codec was written from that contract and BIP173/350, without the Rust v2 codec.
No key derivation, network I/O, legacy-address decoding or signing occurs here.
"""
from __future__ import annotations

import json
import sys

ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32M = 0x2BC830A3
GENERATORS = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
HRPS = {"mainnet": "gnb", "testnet": "tgnb"}
KINDS = {"single-key": (0, 20), "policy": (1, 32)}
MAX_ADDRESS_LENGTH = 90


class AddressError(ValueError):
    """Invalid v2 encoding or a mismatch with the caller's expected network."""


def _polymod(symbols):
    # Generic checksum definition: BIP173, with the BIP350 final constant.
    # https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki#bech32m
    register = 1
    for symbol in symbols:
        high = register >> 25
        register = ((register & 0x1FFFFFF) << 5) ^ symbol
        for bit, generator in enumerate(GENERATORS):
            if high & (1 << bit):
                register ^= generator
    return register


def _expanded_hrp(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _encode_words(hrp, words, *, constant=BECH32M):
    """Unchecked application framing, also used to build malformed vectors."""
    remainder = _polymod(_expanded_hrp(hrp) + list(words) + [0] * 6) ^ constant
    checksum = [(remainder >> shift) & 31 for shift in range(25, -1, -5)]
    return hrp + "1" + "".join(ALPHABET[word] for word in list(words) + checksum)


def _decode_words(address):
    """Generic Bech32m validation; GnB semantics are checked by decode()."""
    if not isinstance(address, str) or not 8 <= len(address) <= MAX_ADDRESS_LENGTH:
        raise AddressError("address length")
    if any(not 33 <= ord(c) <= 126 for c in address):
        raise AddressError("address must be printable ASCII")
    if address != address.lower() and address != address.upper():
        raise AddressError("mixed case")
    lower = address.lower()
    separator = lower.rfind("1")
    if separator < 1 or separator + 7 > len(lower):
        raise AddressError("separator or checksum length")
    hrp, data = lower[:separator], lower[separator + 1:]
    try:
        words = [ALPHABET.index(c) for c in data]
    except ValueError as exc:
        raise AddressError("data alphabet") from exc
    if _polymod(_expanded_hrp(hrp) + words) != BECH32M:
        raise AddressError("Bech32m checksum")
    return hrp, words[:-6]


def _hash_words(payload):
    # Deliberately use a bit-string formulation rather than a streaming
    # accumulator: hashes are bounded to 32 bytes by the public encoder.
    bits = "".join(f"{byte:08b}" for byte in payload)
    bits += "0" * (-len(bits) % 5)
    return [int(bits[offset:offset + 5], 2) for offset in range(0, len(bits), 5)]


def _words_hash(words):
    bits = "".join(f"{word:05b}" for word in words)
    padding = len(bits) % 8
    if padding >= 5 or (padding and "1" in bits[-padding:]):
        raise AddressError("non-canonical padding")
    usable = len(bits) - padding
    return bytes(int(bits[offset:offset + 8], 2) for offset in range(0, usable, 8))


def encode(network, kind, payload):
    """Encode exactly a 20-byte key hash or a 32-byte policy hash."""
    if not isinstance(network, str) or network not in HRPS:
        raise AddressError("unknown network")
    if not isinstance(kind, str) or kind not in KINDS:
        raise AddressError("unknown kind")
    tag, length = KINDS[kind]
    if not isinstance(payload, bytes) or len(payload) != length:
        raise AddressError("hash length")
    return _encode_words(HRPS[network], [2, tag] + _hash_words(payload))


def decode(address, expected_network=None):
    """Return canonical address, network, kind, hash and unchanged output script."""
    if expected_network is not None and (
        not isinstance(expected_network, str) or expected_network not in HRPS
    ):
        raise AddressError("unknown expected network")
    hrp, words = _decode_words(address)
    networks = {value: key for key, value in HRPS.items()}
    if hrp not in networks:
        raise AddressError("unknown HRP")
    if len(words) < 2 or words[0] != 2:
        raise AddressError("unknown format version")
    kinds = {value[0]: key for key, value in KINDS.items()}
    if words[1] not in kinds:
        raise AddressError("unknown kind")
    kind = kinds[words[1]]
    payload = _words_hash(words[2:])
    if len(payload) != KINDS[kind][1]:
        raise AddressError("hash length")
    network = networks[hrp]
    if expected_network is not None and network != expected_network:
        raise AddressError("wrong network")
    script = payload if kind == "single-key" else b"\x02" + payload
    return {
        "address": encode(network, kind, payload),
        "network": network,
        "kind": kind,
        "hash_hex": payload.hex(),
        "script_hex": script.hex(),
    }


def oracle(request):
    """Stable JSON request/reply API. Error wording is intentionally not exposed."""
    try:
        if not isinstance(request, dict):
            raise AddressError("request object")
        operation = request.get("op")
        if operation == "decode":
            if set(request) - {"op", "address", "expected_network"}:
                raise AddressError("unknown field")
            result = decode(request["address"], request.get("expected_network"))
        elif operation == "encode":
            if set(request) != {"op", "network", "kind", "hash_hex"}:
                raise AddressError("request fields")
            value = request["hash_hex"]
            if not isinstance(value, str) or len(value) not in (40, 64):
                raise AddressError("hash hex length")
            if any(c not in "0123456789abcdef" for c in value):
                raise AddressError("canonical hash hex")
            result = decode(encode(request["network"], request["kind"], bytes.fromhex(value)))
        else:
            raise AddressError("unknown operation")
        return {"ok": True, **result}
    except (AddressError, KeyError):
        return {"ok": False}


def main():
    for line in sys.stdin:
        try:
            result = oracle(json.loads(line))
        except (ValueError, UnicodeError):
            result = {"ok": False}
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
