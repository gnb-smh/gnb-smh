"""Randomized Rust-vs-Python differential for the ledger (audit LED-1).

    python3 ledger_oracle.py gen <seed> <count>   random valid blocks from FullNode, with verdicts
    python3 ledger_oracle.py eval                 verdicts for the JSON list of cases on stdin

rust/tests/ledger_differential.rs runs `gen`, mutates every case at random
(witness bytes, transaction bytes, order, context, merged flag), sends all of
them to `eval`, and requires the Rust port to reach exactly the same verdict:
the same post-state and accepted flags, or the same error code and class.

A case is {"pre": {...}, "height", "subsidy", "coinbase_maturity",
"parents_root", "merged", "txs_hex", "witness_hex"}. It is evaluated as
decode_tx_wire on every transaction, then
apply_block_txs(pre, txs, witness, ctx, merged=merged). A verdict is
{"ok": true, "post": {...}, "accepted": [...]} or
{"ok": false, "code": ..., "permanent": ...}; any other exception in the
reference is reported as code "python-exception" so the test fails loudly.
"""

from __future__ import annotations

import copy
import json
import random
import sys

import gnb_ledger as L

SECRETS = [b"alice", b"bob", b"carol", b"dave", b"erin"]
OWNERS = [L.test_owner(s) for s in SECRETS]


def state_json(s: L.State) -> dict:
    return {"utxo_root": s.utxo_root.hex(), "nullifier_root": s.nullifier_root.hex()}


def state_of(d: dict) -> L.State:
    return L.State(bytes.fromhex(d["utxo_root"]), bytes.fromhex(d["nullifier_root"]))


def ctx_of(c: dict) -> L.Context:
    return L.Context(height=c["height"], subsidy=c["subsidy"], auth=L.test_preimage_auth,
                     coinbase_maturity=c["coinbase_maturity"], parents_root=bytes.fromhex(c["parents_root"]))


def evaluate(c: dict) -> dict:
    try:
        txs = [L.decode_tx_wire(bytes.fromhex(h)) for h in c["txs_hex"]]
        post, accepted = L.apply_block_txs(state_of(c["pre"]), txs, bytes.fromhex(c["witness_hex"]),
                                           ctx_of(c), merged=c["merged"])
    except L.InvalidBlock as e:
        return {"ok": False, "code": e.code, "permanent": e.permanent}
    except Exception as e:  # a crash of the reference is itself a finding
        return {"ok": False, "code": "python-exception", "permanent": True, "detail": repr(e)}
    return {"ok": True, "post": state_json(post), "accepted": accepted}


def random_case(rng: random.Random) -> dict:
    node = L.FullNode()
    height = rng.randrange(3, 40)
    maturity = rng.randrange(1, 6)
    known = []                                      # (txid, vout, secret index, record)
    for i in range(rng.randrange(1, 12)):
        tid = rng.randbytes(32)
        rec = L.UtxoRecord(rng.randrange(0, 5_000), OWNERS[rng.randrange(len(OWNERS))],
                           rng.randrange(0, height), rng.random() < 0.3)
        node.insert(L.outpoint_key(tid, i % 3), rec)
        known.append((tid, i % 3, OWNERS.index(rec.owner), rec))
    parents_root = rng.randbytes(32)
    ctx = L.Context(height=height, subsidy=rng.randrange(0, 3_000), auth=L.test_preimage_auth,
                    coinbase_maturity=maturity, parents_root=parents_root)

    regular = []
    for _ in range(rng.randrange(0, 6)):
        roll = rng.random()
        if roll < 0.1 and regular:
            regular.append(rng.choice(regular))     # a duplicate: its inputs are gone
            continue
        picks = rng.sample(known, min(len(known), rng.randrange(1, 3)))
        inputs = [L.Outpoint(t, v) for t, v, _, _ in picks]
        if roll < 0.2:
            inputs.append(L.Outpoint(rng.randbytes(32), 0))          # missing input
        total = sum(r.amount for _, _, _, r in picks)
        out_total = total + 1 if roll > 0.9 else rng.randrange(0, total + 1)
        cut = rng.randrange(0, out_total + 1)
        auth = [SECRETS[s] if rng.random() > 0.1 else b"wrong" for _, _, s, _ in picks]
        auth += [b"x"] * (len(inputs) - len(auth))
        outs = [L.TxOut(cut, OWNERS[rng.randrange(len(OWNERS))])]
        if out_total - cut or rng.random() < 0.5:
            outs.append(L.TxOut(out_total - cut, OWNERS[rng.randrange(len(OWNERS))]))
        tx = L.Tx(L.TX_REGULAR, tuple(inputs), tuple(outs), auth=tuple(auth))
        if roll > 0.85:                              # an output key is already taken
            node.insert(L.outpoint_key(L.txid(tx), 0), L.UtxoRecord(1, OWNERS[0], 1, False))
        regular.append(tx)

    payee = OWNERS[rng.randrange(len(OWNERS))]
    probe = L.Tx(L.TX_COINBASE, (), (L.TxOut(0, payee),), height, b"probe", parents_root=parents_root)
    _, _, fees = copy.deepcopy(node).build([probe] + regular, ctx)
    amount = ctx.subsidy + fees - (rng.randrange(0, 3) if rng.random() < 0.3 else 0)
    outs = [L.TxOut(max(amount, 0), payee)]
    if rng.random() < 0.3:
        outs.append(L.TxOut(0, OWNERS[rng.randrange(len(OWNERS))]))
    cb = L.Tx(L.TX_COINBASE, (), tuple(outs), height, rng.choice([b"", b"cb", b"twin"]), parents_root=parents_root)
    merged = rng.random() < 0.35
    if merged and rng.random() < 0.6:
        # The twin of this block was applied first: its coinbase outputs exist.
        for o, out in enumerate(cb.outputs):
            node.insert(L.outpoint_key(L.txid(cb), o), L.UtxoRecord(out.amount, out.owner, height, True))
    txs = [cb] + regular
    pre = node.state()
    witness, _, _ = node.build(txs, ctx, merged=merged)
    case = {"pre": state_json(pre), "height": height, "subsidy": ctx.subsidy, "coinbase_maturity": maturity,
            "parents_root": parents_root.hex(), "merged": merged,
            "txs_hex": [L.tx_wire(t).hex() for t in txs], "witness_hex": witness.hex()}
    case["verdict"] = evaluate(case)
    assert case["verdict"]["ok"] and case["verdict"]["post"] == state_json(node.state()), case["verdict"]
    return case


def main() -> None:
    if sys.argv[1:2] == ["gen"]:
        rng = random.Random(int(sys.argv[2]))
        print(json.dumps([random_case(rng) for _ in range(int(sys.argv[3]))]))
    elif sys.argv[1:2] == ["eval"]:
        print(json.dumps([evaluate(c) for c in json.load(sys.stdin)]))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
