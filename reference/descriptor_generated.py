"""Deterministic generated descriptor comparisons, separate from pinned vectors.

This is a bounded generated test campaign, not a coverage-guided fuzz run.
Every eighth request starts a new shape. Public key bytes are SHAKE fixtures,
not private keys or signatures. The PRNG seed and exact count are reported.
"""
import hashlib
import random

import descriptor as d

DEFAULT_SEED = 0x474E424435
DEFAULT_REQUESTS = 128


def cases(count=DEFAULT_REQUESTS, seed=DEFAULT_SEED):
    if not isinstance(count, int) or not 0 <= count <= 4096:
        raise ValueError("generated request count must be 0..4096")
    rng = random.Random(seed)
    emitted = 0
    group = 0
    while emitted < count:
        network = d.NETWORKS[group % 2]
        kind = ("pkh", "policy", "tree")[group % 3]
        keys = []

        def key():
            material = f"gnb-descriptor-generated-v1:{seed}:{group}:{len(keys)}".encode("ascii")
            raw = hashlib.shake_256(material).digest(d.RAW_KEY_BYTES)
            # Include length-first raw-envelope-prefix classification as well
            # as both ordinary serialization forms.
            if (group + len(keys)) % 11 == 0:
                raw = b"\xb1\x0c\xff\xff" + raw[4:]
            if rng.randrange(2):
                raw = b"\xb1\x0c\x01\x00" + raw
            value = raw.hex()
            keys.append(value)
            return value

        def policy():
            size = rng.randint(1, 7)
            threshold = rng.randint(1, size)
            choices = (0, 1, 17499, 17500, 0xFFFFFFFF, rng.getrandbits(32))
            after, older = rng.choice(choices), rng.choice(choices)
            ordered = [key() for _ in range(size)]
            rng.shuffle(ordered)
            return f"policy({threshold},{after},{older},{','.join(ordered)})"

        if kind == "pkh":
            expression = f"pkh({key()})"
        elif kind == "policy":
            expression = policy()
        else:
            branches = [policy() for _ in range(2 + (group // 3) % 3)]
            rng.shuffle(branches)
            expression = "tree(" + ",".join(branches) + ")"
        body = f"gnbd1({network},{expression})"
        descriptor = d.add_checksum(body)
        # Change one byte of public material, preserving its accepted shape.
        original = keys[0]
        position = 8 if len(original) == (d.RAW_KEY_BYTES + 4) * 2 else 0
        mutated = original[:position] + f"{int(original[position:position + 2], 16) ^ 1:02x}" + original[position + 2:]
        alternate_body = body.replace(original, mutated)
        alternate_descriptor = d.add_checksum(alternate_body)
        opposite = "testnet" if network == "mainnet" else "mainnet"
        bad_checksum = descriptor[:-1] + ("q" if descriptor[-1] != "q" else "p")
        bundle = d.compact({"format": d.POOL_FORMAT, "network": network, "descriptors": [descriptor, alternate_descriptor]})
        rows = [
            ("create", {"action": "create", "network": network, "body": body}, True),
            ("inspect", {"op": "descriptor", "action": "inspect", "network": network, "descriptor": descriptor}, True),
            ("changed-public-bytes", {"action": "create", "network": network, "body": alternate_body}, True),
            ("wrong-network", {"action": "inspect", "network": opposite, "descriptor": descriptor}, False),
            ("checksum-substitution", {"action": "inspect", "network": network, "descriptor": bad_checksum}, False),
            ("noncanonical-grammar", {"action": "create", "network": network, "body": body.replace("gnbd1(", "gnbd1( ")}, False),
            ("pool-roundtrip", {"action": "import", "network": network, "bundle": bundle}, True),
            ("pool-duplicate-field", {"action": "import", "network": network, "bundle": bundle[:-1] + ',"network":' + d.compact(network) + "}"}, False),
        ]
        for label, request, accepted in rows:
            if emitted == count:
                return
            yield f"generated/{group}/{network}/{kind}/{label}", d.compact(request), accepted
            emitted += 1
        group += 1
