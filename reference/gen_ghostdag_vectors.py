"""Generate ghostdag_vectors.json from the reference (gnb_ghostdag.py).

Deterministic (no randomness). Each case is a small DAG, inserted in the
listed order, with every block's expected GhostDAG data under the rules at
or after the hardening activation (activation height 0). The script also
asserts the property each case exists for:

* order/fifo-not-lowest-id (audit B2-T9): the candidate order of the last
  block decides its blue set, and the other reading of the order (always the
  lowest ready id) gives a different blue set and blue work;
* parents/duplicate and parents/redundant-ancestor (audit B2-T10): what a
  repeated parent and a parent that is an ancestor of another parent do to
  the GhostDAG data (nothing) and to the header height (a redundant parent
  can raise it), and the header verdict of a repeated parent in both
  regimes.

`node/tests/ghostdag_vectors.rs` builds every case with the node's
`GhostDAG` and compares; CI regenerates this file and diffs it.
"""

import json
import pathlib

import gnb_ghostdag as g

HERE = pathlib.Path(__file__).resolve().parent


def bid(first: int, second: int = 0) -> bytes:
    return bytes([first, second]) + bytes(30)


def block_json(dag: g.Dag, h: bytes) -> dict:
    d = dag.data[h]
    return {
        "id": h.hex(),
        "parents": [p.hex() for p in dag.parents[h]],
        "work": str(dag.work[h]),
        "expected": {
            "selected_parent": d.selected_parent.hex() if d.selected_parent else None,
            "dag_height": str(d.dag_height),
            "header_height": str(d.header_height),
            "mergeset_order": [x.hex() for x in d.mergeset_order],
            "mergeset_blues": [x.hex() for x in d.blues],
            "mergeset_reds": [x.hex() for x in d.reds],
            "blue_score": str(d.blue_score),
            "blue_work": str(d.blue_work),
            # Header rule from the hardening activation (B2-T10).
            "duplicate_parents": g.duplicate_parents(dag.parents[h]),
        },
    }


def case(cid: str, description: str, dag: g.Dag, order: list, extra: dict | None = None) -> dict:
    out = {
        "id": cid,
        "description": description,
        "k": dag.k,
        "activation_height": "0",
        "genesis": order[0].hex(),
        "blocks": [block_json(dag, h) for h in order[1:]],
    }
    if extra:
        out.update(extra)
    return out


def order_case() -> dict:
    """B2-T9: block B merges T1..T11 (children of P, siblings of its selected
    parent sp) and U (a child of T1). U has the LOWEST id but becomes ready
    only after T1 is taken, so the FIFO order is T1..T11, U and the blues are
    T1..T10; the lowest-id reading takes U second and colors T1, U, T2..T9."""
    dag = g.Dag(k=10)
    G, P, SP, U = bid(0x00, 0x47), bid(0x50), bid(0xF0), bid(0x01)
    T = [bid(0x10 + i) for i in range(1, 12)]
    order = [G, P, SP] + T + [U]
    dag.add_genesis(G)
    dag.add_block(P, [G], 1)
    dag.add_block(SP, [P], 100)  # the heaviest parent of B: its selected parent
    for t in T:
        dag.add_block(t, [P], 1)
    dag.add_block(U, [T[0]], 3)
    B = bid(0xB0)
    b_parents = [SP] + T[1:] + [U]
    # The other reading, on a copy, before B is added for real.
    alt = g.Dag(k=10)
    alt.add_genesis(G)
    for h in order[1:]:
        alt.add_block(h, dag.parents[h], dag.work[h])
    alt_b = alt.add_block(B, b_parents, 1, reading="min-id")
    d = dag.add_block(B, b_parents, 1)
    order.append(B)
    assert d.selected_parent == SP
    assert d.mergeset_order == T + [U]
    assert d.blues == T[:10] and d.reds == [T[10], U]
    assert alt_b.mergeset_order == [T[0], U] + T[1:]
    assert alt_b.blues == [T[0], U] + T[1:9]
    assert set(alt_b.blues) != set(d.blues) and alt_b.blue_work != d.blue_work
    assert d.header_height == 4 and d.dag_height == 3
    return case(
        "order/fifo-not-lowest-id",
        "Audit B2-T9. k = 10. B's parents are its selected parent sp (the heaviest), T2..T11 and U; "
        "T1..T11 and sp are children of P, U is a child of T1. The mergeset is T1..T11 and U. U has the "
        "lowest id but becomes ready only when T1 is taken, so GnB's FIFO order is T1..T11, U: blues "
        "T1..T10, reds T11 and U. The other reading (always the lowest ready id) gives T1, U, T2..T11: "
        "blues T1, U, T2..T9 and a different blue work (`alternative_reading`). B's header height (4) "
        "also differs from its DAG height (3): U has DAG height 3.",
        dag, order,
        {"alternative_reading": {
            "block": B.hex(),
            "reading": "lowest ready id first (NOT GnB's rule)",
            "mergeset_order": [x.hex() for x in alt_b.mergeset_order],
            "mergeset_blues": [x.hex() for x in alt_b.blues],
            "blue_work": str(alt_b.blue_work),
        }},
    )


def duplicate_case() -> dict:
    """B2-T10: a repeated parent changes no GhostDAG data (the parent list is
    a set for the DAG); from the hardening activation it is invalid."""
    dag = g.Dag(k=10)
    G, A, C = bid(0x00, 0x47), bid(0xA1), bid(0xC1)
    D_DUP_MERGED, D_DUP_SELECTED, D_PLAIN = bid(0xD1), bid(0xD2), bid(0xD3)
    dag.add_genesis(G)
    dag.add_block(A, [G], 2)
    dag.add_block(C, [G], 1)
    dag.add_block(D_DUP_MERGED, [A, C, C], 1)
    dag.add_block(D_DUP_SELECTED, [A, C, A], 1)
    dag.add_block(D_PLAIN, [A, C], 1)
    for h in (D_DUP_MERGED, D_DUP_SELECTED):
        x, y = dag.data[h], dag.data[D_PLAIN]
        assert (x.selected_parent, x.dag_height, x.header_height, x.blues, x.reds, x.blue_score, x.blue_work) == \
               (y.selected_parent, y.dag_height, y.header_height, y.blues, y.reds, y.blue_score, y.blue_work)
        assert g.duplicate_parents(dag.parents[h])
    assert not g.duplicate_parents(dag.parents[D_PLAIN])
    return case(
        "parents/duplicate",
        "Audit B2-T10. D1 lists the merged parent C twice, D2 the selected parent A twice, D3 neither: "
        "their GhostDAG data are identical (the DAG treats the parent list as a set). The header rule "
        "`duplicate_parents` is the verdict from the hardening activation: a block with a repeated "
        "parent is invalid at or after it (`block_rules::check_parents_distinct`) and valid below it.",
        dag, [G, A, C, D_DUP_MERGED, D_DUP_SELECTED, D_PLAIN],
    )


def redundant_case() -> dict:
    """B2-T10: a parent in the past of another parent is valid at every
    height. It is never the selected parent and adds nothing to the
    mergeset, but it counts in the header height."""
    dag = g.Dag(k=10)
    G, H, A1, A2, A3 = bid(0x00, 0x47), bid(0x48), bid(0xA1), bid(0xA2), bid(0xA3)
    X, R, R2 = bid(0x58), bid(0x52, 1), bid(0x52, 2)
    dag.add_genesis(G)
    dag.add_block(H, [G], 100)
    dag.add_block(A1, [G], 1)
    dag.add_block(A2, [A1], 1)
    dag.add_block(A3, [A2], 1)
    dag.add_block(X, [H, A3], 1)
    dag.add_block(R, [X, A3], 1)   # A3 is in past(X): redundant
    dag.add_block(R2, [X], 1)
    x, r, r2 = dag.data[X], dag.data[R], dag.data[R2]
    assert x.selected_parent == H and x.dag_height == 2 and x.header_height == 4
    assert A3 in dag.past(X)
    assert r.selected_parent == X and r.mergeset_order == [] and r2.mergeset_order == []
    assert (r.blue_score, r.blue_work, r.dag_height) == (r2.blue_score, r2.blue_work, r2.dag_height)
    assert (r.header_height, r2.header_height) == (4, 3)
    return case(
        "parents/redundant-ancestor",
        "Audit B2-T10. X merges the chain A1..A3 under the heavier selected parent H, so X has DAG "
        "height 2 but header height 4. R lists X and A3, which is already in X's past; R2 lists X only. "
        "A redundant ancestor is valid at every height: it is never the selected parent and adds nothing "
        "to the mergeset (R and R2 have the same GhostDAG data), but the header height is taken over "
        "every listed parent, so R's header height is 4 and R2's is 3.",
        dag, [G, H, A1, A2, A3, X, R, R2],
    )


def build() -> dict:
    return {
        "format": "gnb-ghostdag-vectors/1",
        "description": "GhostDAG data of small DAGs under the rules at/after the hardening activation "
                       "(reference/gnb_ghostdag.py; docs/CONSENSUS.md, \"Coloring\" and \"Parent list\"). "
                       "Blocks are inserted in the listed order; ids are 32-byte hex; works, heights, "
                       "scores and blue works are decimal strings. `mergeset_order` is the normative "
                       "candidate order (FIFO Kahn, ids ascending among the blocks a step makes ready).",
        "generator": "reference/gen_ghostdag_vectors.py",
        "constants": {"k": g.K, "max_mergeset_size": g.MAX_MERGESET_SIZE},
        "cases": [order_case(), duplicate_case(), redundant_case()],
    }


def render(doc: dict) -> str:
    return json.dumps(doc, indent=1) + "\n"


def main():
    doc = build()
    (HERE / "ghostdag_vectors.json").write_text(render(doc))
    print(f"{len(doc['cases'])} GhostDAG vector cases, "
          f"{sum(len(c['blocks']) for c in doc['cases'])} blocks")


if __name__ == "__main__":
    main()
