"""Generate merkle_vectors.json from the reference (gnb_merkle.py).

Deterministic: every pseudo-random byte comes from SHAKE-256 of a fixed
label, so the file is reproducible byte for byte (CI regenerates it and
diffs). The script also asserts the properties the rules exist for (a
duplicated last transaction keeps the legacy root but not the tagged one;
a padded witness keeps every txid but not the witness root).
"""

import hashlib
import json
import pathlib

import gnb_merkle as m

HERE = pathlib.Path(__file__).resolve().parent


class Rng:
    def __init__(self, label: bytes):
        self.label = label
        self.i = 0

    def bytes(self, n: int) -> bytes:
        self.i += 1
        return hashlib.shake_256(self.label + self.i.to_bytes(8, "little")).digest(n)


def tx_json(tx: m.Tx) -> dict:
    return {
        "version": tx.version,
        "inputs": [{"prev_txid": i.prev_txid.hex(), "prev_index": i.prev_index,
                    "script_sig": i.script_sig.hex(), "sequence": i.sequence} for i in tx.inputs],
        "outputs": [{"value": o.value, "script_pubkey": o.script_pubkey.hex()} for o in tx.outputs],
        "locktime": tx.locktime,
    }


def spend(rng: Rng, n_in: int, n_out: int, sig_len: int, spk_len: int) -> m.Tx:
    return m.Tx(
        version=1,
        inputs=[m.TxIn(rng.bytes(32), k, rng.bytes(sig_len)) for k in range(n_in)],
        outputs=[m.TxOut(1_000 + k, rng.bytes(spk_len)) for k in range(n_out)],
        locktime=0,
    )


def coinbase(script_sig: bytes, value: int = 5_000_000_000) -> m.Tx:
    return m.Tx(version=1, inputs=[m.TxIn(m.ZERO32, 0xFFFFFFFF, script_sig)],
                outputs=[m.TxOut(value, bytes([0xC0]) * 20)], locktime=0)


def merkle_vectors():
    rng = Rng(b"gnb-merkle-vectors/ids")
    out = []
    for n in list(range(0, 10)) + [15, 16, 17, 33]:
        ids = [rng.bytes(32) for _ in range(n)]
        out.append({
            "ids": [i.hex() for i in ids],
            "legacy_root": m.legacy_merkle_root(ids).hex(),
            "tagged_root": m.tagged_merkle_root(ids).hex(),
            "legacy_coinbase_branch": [b.hex() for b in m.coinbase_merkle_branch(ids, False)],
            "tagged_coinbase_branch": [b.hex() for b in m.coinbase_merkle_branch(ids, True)],
        })
        for hardened in (False, True):
            if n:
                br = m.coinbase_merkle_branch(ids, hardened)
                assert m.fold_coinbase_branch(ids[0], br, hardened) == m.merkle_root(ids, hardened)
    return out


def mutation_vectors():
    """CVE-2012-2459 shapes: the legacy root collides, the tagged one does not."""
    rng = Rng(b"gnb-merkle-vectors/mutation")
    out = []
    for n, dup in ((3, 1), (5, 1), (6, 2), (7, 1), (10, 2)):
        ids = [rng.bytes(32) for _ in range(n)]
        mutated = ids + ids[n - dup:]
        assert m.legacy_merkle_root(ids) == m.legacy_merkle_root(mutated)
        assert m.tagged_merkle_root(ids) != m.tagged_merkle_root(mutated)
        out.append({"ids": [i.hex() for i in ids], "mutated_ids": [i.hex() for i in mutated],
                    "legacy_root": m.legacy_merkle_root(ids).hex(),
                    "tagged_root": m.tagged_merkle_root(ids).hex(),
                    "mutated_tagged_root": m.tagged_merkle_root(mutated).hex()})
    return out


def transaction_vectors():
    rng = Rng(b"gnb-merkle-vectors/tx")
    txs = [
        ("one-in-one-out, 5-byte script: 64-byte txid preimage", spend(rng, 1, 1, 12, 5)),
        ("4-byte script: 63 bytes", spend(rng, 1, 1, 12, 4)),
        ("6-byte script: 65 bytes", spend(rng, 1, 1, 12, 6)),
        ("standard payment shape", spend(rng, 2, 2, 40, 20)),
        ("253-byte script_sig (3-byte varint)", spend(rng, 1, 1, 253, 20)),
        ("legacy coinbase", coinbase(b"gnb:h7:0123456789abcdef")),
        ("coinbase with a commitment-shaped script_sig", coinbase(b"GNB-CB01" + bytes(72) + b"x")),
    ]
    out = []
    for note, tx in txs:
        out.append({
            "note": note,
            "tx": tx_json(tx),
            "wire_hex": tx.wire(True).hex(),
            "txid_preimage_len": len(tx.txid_preimage()),
            "txid": tx.txid().hex(),
            "wtxid": tx.wtxid().hex(),
            "forbidden_64": m.is_forbidden_64(tx),
        })
    assert out[0]["forbidden_64"] and not any(v["forbidden_64"] for v in out[1:])
    return out


def block_vectors():
    """Blocks at/after the activation: commitment, witness root, header roots."""
    rng = Rng(b"gnb-merkle-vectors/block")
    out = []
    shapes = ((1, [], 1), (2, [(1, 1)], 2), (110_000, [(2, 2), (1, 3), (1, 1)], 3), (2**40 + 5, [(1, 1)] * 4, 1))
    for height, spends, n_parents in shapes:
        parents = [rng.bytes(32) for _ in range(n_parents)]
        others = [spend(rng, a, b, 30, 20) for a, b in spends]
        extra = rng.bytes(8)
        placeholder = [coinbase(b"")] + others
        wroot = m.witness_root(placeholder)
        commit = m.coinbase_commitment(height, parents, wroot)
        txs = [coinbase(commit + extra)] + others
        assert m.check_coinbase_commitment(height, parents, txs) is None
        ids = [t.txid() for t in txs]
        out.append({
            "height": height,
            "parents": [p.hex() for p in parents],
            "transactions": [tx_json(t) for t in txs],
            "parents_commitment": m.parents_commitment(parents).hex(),
            "witness_root": wroot.hex(),
            "coinbase_commitment": commit.hex(),
            "tagged_header_root": m.header_root(m.tagged_merkle_root(ids), height).hex(),
            "legacy_header_root": m.header_root(m.legacy_merkle_root(ids), height).hex(),
        })
        # CRY-1: padding one witness keeps every txid, breaks the commitment.
        if others:
            padded = [coinbase(commit + extra)] + [m.Tx(t.version, [m.TxIn(i.prev_txid, i.prev_index, i.script_sig + bytes(16), i.sequence) for i in t.inputs], t.outputs, t.locktime) for t in others]
            assert [t.txid() for t in padded] == ids
            assert m.check_coinbase_commitment(height, parents, padded) == "witness"
    return out


def build() -> dict:
    return {
        "description": "GnB hardening block rules from reference/gnb_merkle.py: tagged and legacy "
                       "Merkle roots, coinbase branches, transaction ids, the 64-byte rule and the "
                       "coinbase commitment. All byte strings are hex.",
        "constants": {
            "merkle_leaf_tag": m.MERKLE_LEAF_TAG.decode(),
            "merkle_node_tag": m.MERKLE_NODE_TAG.decode(),
            "parents_tag": m.PARENTS_TAG.decode(),
            "coinbase_commitment_tag": m.COINBASE_COMMITMENT_TAG.decode(),
            "coinbase_commitment_len": m.COINBASE_COMMITMENT_LEN,
            "coinbase_wtxid": m.COINBASE_WTXID.hex(),
            "forbidden_txid_preimage_len": m.FORBIDDEN_TXID_PREIMAGE_LEN,
            "mainnet_hardening_activation_height": m.MAINNET_HARDENING_ACTIVATION_HEIGHT,
        },
        "merkle": merkle_vectors(),
        "mutation": mutation_vectors(),
        "transactions": transaction_vectors(),
        "blocks": block_vectors(),
    }


def render(doc: dict) -> str:
    return json.dumps(doc, indent=1) + "\n"


def main():
    doc = build()
    (HERE / "merkle_vectors.json").write_text(render(doc))
    print(f"{len(doc['merkle'])} merkle, {len(doc['mutation'])} mutation, "
          f"{len(doc['transactions'])} transaction, {len(doc['blocks'])} block vectors")


if __name__ == "__main__":
    main()
