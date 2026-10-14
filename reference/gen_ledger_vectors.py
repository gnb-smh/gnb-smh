"""Generate ledger_vectors.json from the reference: a four-block chain, a synthetic
REJECT_OUTPUT_EXISTS case, sparse-Merkle-tree vectors, and single-fault invalid blocks
with the error code every implementation must raise.

PoW runs at log2_n = 4 with an easy target so the vectors stay fast; the canonical
GnB-SMH size is checked by test_vectors.json, not here.
"""

from __future__ import annotations

import copy
import dataclasses
import json
import pathlib
import struct
import sys

import gnb_smh
import gnb_ledger as L

HERE = pathlib.Path(__file__).resolve().parent
LOG2_N = 4
EASY_TARGET = 1 << 255
MATURITY = 2
SUBSIDY = 50_000

SECRETS = {name: name.encode() for name in ("alice", "bob", "carol", "dave", "mallory")}
OWNER = {name: L.test_owner(s) for name, s in SECRETS.items()}


def ctx(height: int, parents_root: bytes = L.EMPTY) -> L.Context:
    return L.Context(height=height, subsidy=SUBSIDY, auth=L.test_preimage_auth, coinbase_maturity=MATURITY,
                     parents_root=parents_root)


def wires(txs: list[L.Tx]) -> list[bytes]:
    return [L.tx_wire(t) for t in txs]


def root_of(ws: list[bytes]) -> bytes:
    return L.tx_root([L.wtxid(w) for w in ws])


def mine(header: bytes, target: int) -> int:
    nonce = 0
    while not gnb_smh.meets_target(gnb_smh.gnb_smh(header, nonce, LOG2_N), target):
        nonce += 1
    return nonce


def coinbase(height: int, outputs: list[tuple[str, int]], extra: bytes = b"gnb",
             parents_root: bytes = L.EMPTY) -> L.Tx:
    return L.Tx(L.TX_COINBASE, (), tuple(L.TxOut(a, OWNER[n]) for n, a in outputs), height, extra,
                parents_root=parents_root)


def spend(inputs: list[tuple[bytes, int]], signer: list[str], outputs: list[tuple[str, int]]) -> L.Tx:
    return L.Tx(L.TX_REGULAR, tuple(L.Outpoint(t, v) for t, v in inputs),
                tuple(L.TxOut(a, OWNER[n]) for n, a in outputs),
                auth=tuple(SECRETS[s] for s in signer))


def fees_of(node: L.FullNode, regular: list[L.Tx], height: int) -> int:
    dry = copy.deepcopy(node)
    _, _, fees = dry.build([coinbase(height, [("alice", 0)], b"dry-run")] + regular, ctx(height))
    return fees


def header_for(parent_id: bytes, txs: list[L.Tx], witness: bytes, commitment: bytes, timestamp: int,
               target: int = EASY_TARGET) -> tuple[bytes, int]:
    hb = L.Header(parent_id, root_of(wires(txs)), L.witness_commitment(witness), commitment, timestamp,
                  target).encode()
    return hb, mine(hb, target) if 1 <= target else 0


def state_json(s: L.State) -> dict:
    return {"utxo_root": s.utxo_root.hex(), "nullifier_root": s.nullifier_root.hex()}


def block(name: str, node: L.FullNode, parent_id: bytes, height: int, payee: str,
          regular: list[L.Tx], timestamp: int) -> tuple[dict, bytes]:
    fees = fees_of(node, regular, height)
    txs = [coinbase(height, [(payee, SUBSIDY + fees)], parents_root=parent_id)] + regular
    pre = node.state()
    witness, accepted, got = node.build(txs, ctx(height, parent_id))
    assert got == fees
    post = node.state()
    hb, nonce = header_for(parent_id, txs, witness, post.commitment(), timestamp)
    v = {
        "name": name, "height": height, "subsidy": SUBSIDY, "coinbase_maturity": MATURITY,
        "log2_n": LOG2_N, "header_hex": hb.hex(), "nonce": str(nonce),
        "txs_hex": [w.hex() for w in wires(txs)], "txids": [L.txid(t).hex() for t in txs],
        "wtxids": [L.wtxid(w).hex() for w in wires(txs)],
        "witness_hex": witness.hex(), "witness_bytes": len(witness),
        "pre": state_json(pre), "post": state_json(post), "accepted": accepted,
    }
    return v, L.block_id(hb, nonce)


# ----------------------------------------------------------------- witness surgery for invalid cases

def parse_witness(txs: list[L.Tx], witness: bytes) -> list[dict]:
    """Structural split of a witness bundle (no verification), in processing order."""
    r = L._Reader(witness, "witness-format")
    assert r.u32() == len(txs)
    entries = []
    for tx in txs[1:] + txs[:1]:
        tag = r.u8()
        e: dict = {"tag": tag}
        if tag in (L.ACCEPT, L.REJECT_CONTEXT):
            e["spends"] = []
            for _ in tx.inputs:
                rec = r.take(L.RECORD_LEN)
                start = r.pos
                r.proof()
                e["spends"].append([rec, witness[start:r.pos]])
            if tag == L.ACCEPT:
                e["creates"] = []
                for _ in tx.outputs:
                    start = r.pos
                    r.proof()
                    e["creates"].append(witness[start:r.pos])
        elif tag == L.REJECT_MISSING_INPUT:
            e["index"] = r.u32()
            start = r.pos
            r.proof()
            e["proof"] = witness[start:r.pos]
        elif tag == L.REJECT_OUTPUT_EXISTS:
            e["index"] = r.u32()
            e["value"] = r.take(32)
            start = r.pos
            r.proof()
            e["proof"] = witness[start:r.pos]
        entries.append(e)
    assert r.done()
    return entries


def encode_witness(entries: list[dict], count: int | None = None) -> bytes:
    out = [struct.pack("<I", len(entries) if count is None else count)]
    for e in entries:
        out.append(bytes([e["tag"]]))
        if e["tag"] in (L.ACCEPT, L.REJECT_CONTEXT):
            for rec, proof in e["spends"]:
                out += [rec, proof]
            for proof in e.get("creates", []):
                out.append(proof)
        elif e["tag"] == L.REJECT_MISSING_INPUT:
            out += [struct.pack("<I", e["index"]), e["proof"]]
        elif e["tag"] == L.REJECT_OUTPUT_EXISTS:
            out += [struct.pack("<I", e["index"]), e["value"], e["proof"]]
    return b"".join(out)


def flip_first_sibling(proof: bytes) -> bytes:
    assert len(proof) > 32, "proof has no listed sibling"
    return proof[:32] + bytes([proof[32] ^ 0x01]) + proof[33:]


def with_listed_default(proof: bytes) -> bytes:
    """Same proof, but also listing a default sibling at the lowest default height."""
    sibs, _ = L.decode_proof(proof)
    h = next(i for i in range(L.DEPTH) if sibs[i] == L.DEFAULTS[i])
    bitmap = bytearray(proof[:32])
    bitmap[h >> 3] |= 1 << (h & 7)
    body = [s for i, s in enumerate(sibs) if s != L.DEFAULTS[i] or i == h]
    return bytes(bitmap) + b"".join(body)


def main() -> None:
    node = L.FullNode()
    genesis_id = bytes(32)
    chain = []

    b1, id1 = block("b1-coinbase", node, genesis_id, 1, "alice", [], 1_000)
    chain.append(b1)
    cb1 = bytes.fromhex(b1["txids"][0])

    immature = spend([(cb1, 0)], ["alice"], [("bob", 10_000)])
    b2, id2 = block("b2-immature-spend-rejected", node, id1, 2, "bob", [immature], 1_030)
    chain.append(b2)
    cb2 = bytes.fromhex(b2["txids"][0])

    t1 = spend([(cb1, 0)], ["alice"], [("bob", 20_000), ("alice", 29_000)])
    t1id = L.txid(t1)
    t2 = spend([(t1id, 0)], ["bob"], [("carol", 19_500)])
    t3 = spend([(cb1, 0)], ["alice"], [("dave", 50_000)])
    t4 = spend([(t1id, 1)], ["mallory"], [("mallory", 29_000)])
    t5 = spend([(t1id, 1)], ["alice"], [("dave", 30_000)])
    node_before_b3 = copy.deepcopy(node)
    b3, id3 = block("b3-mixed", node, id2, 3, "carol", [t1, t2, t3, t4, t5], 1_060)
    chain.append(b3)
    assert b3["accepted"] == [True, True, True, False, False, False]

    t6 = spend([(cb2, 0)], ["bob"], [("dave", 49_000)])
    b4, _ = block("b4-mature-coinbase-spend", node, id3, 4, "alice", [t6], 1_090)
    chain.append(b4)
    assert b4["accepted"] == [True, True]

    # Synthetic: an output key of t7 already holds a record, so t7 must be rejected with proof.
    syn = copy.deepcopy(node)
    t7 = spend([(t1id, 1)], ["alice"], [("carol", 28_000)])
    squatter = L.UtxoRecord(1, OWNER["mallory"], 4, False)
    syn.insert(L.outpoint_key(L.txid(t7), 0), squatter)
    b5, _ = block("b5-output-exists-rejected", syn, id3, 5, "bob", [t7], 1_120)
    assert b5["accepted"] == [True, False]
    witness_tags = [e["tag"] for e in parse_witness(
        [L.decode_tx_wire(bytes.fromhex(h)) for h in b5["txs_hex"]], bytes.fromhex(b5["witness_hex"]))]
    assert witness_tags == [L.REJECT_OUTPUT_EXISTS, L.ACCEPT]
    synthetic = [b5]

    # ------------------------------------------------------------- invalid blocks derived from b3
    txs3 = [L.decode_tx_wire(bytes.fromhex(h)) for h in b3["txs_hex"]]
    w3 = bytes.fromhex(b3["witness_hex"])
    h3 = bytes.fromhex(b3["header_hex"])
    hdr3 = L.Header.decode(h3)
    entries = parse_witness(txs3, w3)       # [t1, t2, t3, t4, t5, coinbase]
    invalid = []

    def add(name: str, code: str, *, witness: bytes = w3, header: bytes | None = None,
            nonce: int | None = None, txs: list[L.Tx] = txs3, raw: list[bytes] | None = None,
            in_transit: bool = False) -> None:
        """A changed witness is committed by a re-mined header (the producer's fault,
        permanent) unless `in_transit`, where it arrives under the original header."""
        ws = wires(txs) if raw is None else raw
        if header is None and witness != w3 and not in_transit:
            header, nonce = remined(ws, witness=witness)
        hb = h3 if header is None else header
        n = int(b3["nonce"]) if nonce is None else nonce
        try:
            L.validate_block(node_before_b3.state(), hb, n, ws, witness, ctx(3), log2_n=LOG2_N)
        except L.InvalidBlock as e:
            assert e.code == code, (name, e.code, code)
            permanent = e.permanent
        else:
            raise AssertionError(f"{name} unexpectedly valid")
        invalid.append({
            "name": name, "expected_error": code, "permanent": permanent, "height": 3,
            "subsidy": SUBSIDY, "coinbase_maturity": MATURITY, "log2_n": LOG2_N,
            "header_hex": hb.hex(), "nonce": str(n), "txs_hex": [w.hex() for w in ws],
            "witness_hex": witness.hex(), "pre": b3["pre"],
        })

    def remined(ws: list[bytes], commitment: bytes = hdr3.state_commitment, target: int = EASY_TARGET,
                tx_root: bytes | None = None, witness: bytes = w3) -> tuple[bytes, int]:
        root = root_of(ws) if tx_root is None else tx_root
        hb = L.Header(hdr3.parents_root, root, L.witness_commitment(witness), commitment, hdr3.timestamp,
                      target).encode()
        return hb, (mine(hb, target) if target > 1 else 0)

    def mutated(index: int, change) -> bytes:
        e2 = copy.deepcopy(entries)
        change(e2[index])
        return encode_witness(e2)

    add("spend-proof-sibling-flipped", "witness-mismatch",
        witness=mutated(0, lambda e: e["spends"][0].__setitem__(1, flip_first_sibling(e["spends"][0][1]))))
    add("spend-record-amount-changed", "witness-mismatch",
        witness=mutated(0, lambda e: e["spends"][0].__setitem__(
            0, struct.pack("<Q", struct.unpack_from("<Q", e["spends"][0][0])[0] + 1) + e["spends"][0][0][8:])))
    add("create-proof-sibling-flipped", "witness-mismatch",
        witness=mutated(0, lambda e: e["creates"].__setitem__(0, flip_first_sibling(e["creates"][0]))))

    def claim_missing(e):
        proof = e["spends"][0][1]
        e.clear()
        e.update({"tag": L.REJECT_MISSING_INPUT, "index": 0, "proof": proof})
    add("present-input-claimed-missing", "witness-mismatch", witness=mutated(0, claim_missing))

    def claim_reject(e):
        e["tag"] = L.REJECT_CONTEXT
        del e["creates"]
    add("valid-tx-claimed-context-reject", "reject-invalid", witness=mutated(0, claim_reject))

    def claim_accept(e):
        e["tag"] = L.ACCEPT
        e["creates"] = []
    add("overspend-claimed-accepted", "accept-invalid", witness=mutated(4, claim_accept))

    add("default-sibling-listed", "noncanonical-proof",
        witness=mutated(0, lambda e: e["spends"][0].__setitem__(1, with_listed_default(e["spends"][0][1]))))
    add("trailing-byte", "witness-format", witness=w3 + b"\x00")
    # The same damage applied by a relaying peer: the bundle no longer hashes to the
    # header's witness_root, which is checked before any proof (one hash, transient).
    add("witness-damaged-in-transit", "witness-commitment", in_transit=True,
        witness=mutated(0, lambda e: e["spends"][0].__setitem__(1, flip_first_sibling(e["spends"][0][1]))))
    add("entry-count-off-by-one", "witness-format", witness=encode_witness(entries, count=len(entries) + 1))
    add("unknown-tag", "witness-format", witness=mutated(2, lambda e: e.__setitem__("tag", 7)))
    add("coinbase-entry-not-accept", "witness-format",
        witness=mutated(len(entries) - 1, lambda e: e.__setitem__("tag", L.REJECT_CONTEXT)))

    # A relaying peer swaps t1's authorization: before the fix this flipped t1 to REJECT and
    # let the conflicting t3 win under the same header. Now the body no longer matches tx_root.
    swapped = wires(txs3)
    swapped[1] = L.tx_wire(dataclasses.replace(txs3[1], auth=(b"garbage",)))
    add("auth-swapped-in-transit", "tx-root", raw=swapped)

    over = [coinbase(3, [("carol", SUBSIDY + 1_500 + 1)], parents_root=hdr3.parents_root)] + txs3[1:]
    hb, n = remined(wires(over))
    add("coinbase-claims-one-more", "coinbase", header=hb, nonce=n, txs=over)

    cb_height = [coinbase(4, [("carol", SUBSIDY + 1_500)], parents_root=hdr3.parents_root)] + txs3[1:]
    hb, n = remined(wires(cb_height))
    add("coinbase-height-mismatch", "isolation", header=hb, nonce=n, txs=cb_height)

    # Coinbase uniqueness: the coinbase must commit to the header's parents_root.
    cb_parents = [coinbase(3, [("carol", SUBSIDY + 1_500)], parents_root=bytes(32))] + txs3[1:]
    hb, n = remined(wires(cb_parents))
    add("coinbase-parents-root-mismatch", "isolation", header=hb, nonce=n, txs=cb_parents)

    dup = txs3[:1] + [spend([(cb1, 0), (cb1, 0)], ["alice", "alice"], [("bob", 1)])]
    hb, n = remined(wires(dup))
    add("duplicate-input", "isolation", header=hb, nonce=n, txs=dup)

    undecodable = wires(txs3) + [struct.pack("<I", 2) + b"\x00"]
    hb, n = remined(undecodable)
    add("committed-tx-undecodable", "isolation", header=hb, nonce=n, raw=undecodable)

    hb, n = remined(wires(txs3), commitment=node_before_b3.state().commitment())
    add("state-commitment-is-parent", "state-commitment", header=hb, nonce=n)

    hb, n = remined(wires(txs3), tx_root=bytes(32))
    add("tx-root-zero", "tx-root", header=hb, nonce=n)

    hb, n = remined(wires(txs3), target=1)
    add("pow-target-one", "pow", header=hb, nonce=n)

    hb = h3[:140] + bytes(32)
    add("target-zero", "target", header=hb)
    add("header-short", "header", header=h3[:-1])

    # A coinbase whose output key is already taken: the witness can prove it (permanent).
    taken = copy.deepcopy(node)
    cb5 = coinbase(5, [("bob", SUBSIDY)])
    cb5_key = L.outpoint_key(L.txid(cb5), 0)
    taken.insert(cb5_key, L.UtxoRecord(7, OWNER["mallory"], 4, False))
    pre5 = taken.state()
    ws5 = wires([cb5])
    proof5 = taken.tree.proof(cb5_key)
    value5 = L.utxo_value(taken.utxos[cb5_key])
    for name, code, proof in (("coinbase-output-taken-proven", "coinbase", proof5),
                              ("coinbase-output-taken-bad-proof", "witness-mismatch", flip_first_sibling(proof5))):
        w = struct.pack("<I", 1) + bytes([L.REJECT_OUTPUT_EXISTS]) + struct.pack("<I", 0) + value5 + proof
        hb5 = L.Header(bytes(32), root_of(ws5), L.witness_commitment(w), pre5.commitment(), 1_150,
                       EASY_TARGET).encode()
        n5 = mine(hb5, EASY_TARGET)
        c5 = ctx(5)
        try:
            L.validate_block(pre5, hb5, n5, ws5, w, c5, log2_n=LOG2_N)
        except L.InvalidBlock as e:
            assert e.code == code, (name, e.code)
            permanent = e.permanent
        else:
            raise AssertionError(name)
        invalid.append({
            "name": name, "expected_error": code, "permanent": permanent, "height": 5,
            "subsidy": SUBSIDY, "coinbase_maturity": MATURITY, "log2_n": LOG2_N,
            "header_hex": hb5.hex(), "nonce": str(n5), "txs_hex": [x.hex() for x in ws5],
            "witness_hex": w.hex(), "pre": state_json(pre5),
        })

    # ------------------------------------------------------------- sparse Merkle tree vectors
    t = L.SparseMerkleTree()
    keys = [L._h(L._prefix(b"vector-key"), bytes([i])) for i in range(6)]
    steps = []
    for i, k in enumerate(keys[:5]):
        value = L._h(L._prefix(b"vector-value"), bytes([i]))
        t.set(k, L.leaf_hash(k, value))
        steps.append({"op": "insert", "key": k.hex(), "value": value.hex(), "root": t.root().hex()})
    t.set(keys[2], L.EMPTY)
    steps.append({"op": "delete", "key": keys[2].hex(), "root": t.root().hex()})
    proofs = [
        {"key": keys[0].hex(), "present": True, "proof": t.proof(keys[0]).hex()},
        {"key": keys[2].hex(), "present": False, "proof": t.proof(keys[2]).hex()},
        {"key": keys[5].hex(), "present": False, "proof": t.proof(keys[5]).hex()},
    ]
    smt = {
        "empty_leaf": L.EMPTY.hex(), "default_1": L.DEFAULTS[1].hex(), "default_255": L.DEFAULTS[255].hex(),
        "empty_root": L.EMPTY_ROOT.hex(), "genesis_state_commitment": L.State().commitment().hex(),
        "steps": steps, "final_root": t.root().hex(), "proofs": proofs,
        "noncanonical_proof": with_listed_default(t.proof(keys[0])).hex(),
    }

    doc = {
        "ledger": "GnB ledger v1 (stateless validation)",
        "version": L.VERSION,
        "note": "auth = test_preimage_auth (TEST ONLY). nonce is a decimal string. Blocks are "
                "validated with GnB-SMH at log2_n = 4; each invalid case has exactly one fault. "
                "permanent = the block itself is invalid (the header commits to the transactions "
                "and the witness bundle); otherwise the body or witness received does not hash "
                "to the header's commitments.",
        "params": {"log2_n": LOG2_N, "coinbase_maturity": MATURITY, "subsidy": SUBSIDY},
        "smt": smt,
        "chain": chain,
        "synthetic": synthetic,
        "invalid": invalid,
    }
    (HERE / "ledger_vectors.json").write_text(json.dumps(doc, indent=1) + "\n")
    print(f"{len(chain)} chain blocks, {len(synthetic)} synthetic, {len(invalid)} invalid cases", file=sys.stderr)
    for b in chain + synthetic:
        print(f"  {b['name']}: {len(b['txs_hex'])} txs, witness {b['witness_bytes']} B, "
              f"accepted {b['accepted']}", file=sys.stderr)


if __name__ == "__main__":
    main()
