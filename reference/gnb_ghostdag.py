"""GnB GHOSTDAG reference (docs/CONSENSUS.md, "GhostDAG rules").

Executable definition of what one block's GhostDAG data is under the rules
in force AT/AFTER the hardening activation (testnet and regtest from
genesis, mainnet from 110,000): the selected parent, the two heights, the
mergeset, the order in which its candidates are colored, the exact
GHOSTDAG k-cluster coloring, blue score and Kaspa blue work. Brute force
over pasts: written for clarity and small vector DAGs, not speed.

The candidate order is normative (audit B2-T9). The coloring is greedy, so
the order decides which candidates become blue. It is Kahn's algorithm with
a FIFO queue, NOT "the lowest id among the blocks ready now":

1. in-degree of a candidate = the number of its distinct parents that are
   themselves in the mergeset;
2. the queue starts with the candidates of in-degree 0, in ascending byte
   order of their 32-byte block ids;
3. repeatedly take the FRONT of the queue; the candidates whose in-degree
   drops to 0 by that removal are appended at the BACK of the queue, in
   ascending byte order of their ids.

A candidate that becomes ready later is processed after every candidate
already queued, whatever its id. `candidate_order(..., reading="min-id")`
computes the other reading (always the lowest ready id) only so the vectors
can show that the two differ; it is not GnB's rule.

Not modeled here: the pre-activation coloring (mainnet below 110,000), the
merge-depth bound (MERGE_DEPTH = 360 blue score) and the PoWit finalized
checkpoint (from the PoWit height; it restricts which tips fork choice may
select, `GhostDAG::set_finalized`, never a block's GhostDAG data). The
mergeset-size limit is: at most MERGESET_SIZE_LIMIT = 64 blocks merged
besides the selected parent, at every height (this chain's rule, tighter
than the audit's hardened `MAX_MERGESET_SIZE - 1` = 179, so the one limit on
both sides of the activation).

Each block's `work` is given: the node derives it from the header,
`core::block_work(bits, height)` (GnB-SMH v3 blocks, from the PoWit height,
count `work_from_bits(bits) >> POW_V3_DIFFICULTY_SHIFT`).

`gen_ghostdag_vectors.py` writes `ghostdag_vectors.json` from this file;
`node/tests/ghostdag_vectors.rs` checks the node's GhostDAG against it.
"""

from collections import deque
from dataclasses import dataclass, field

K = 10
MERGESET_SIZE_LIMIT = 64  # blocks merged besides the selected parent, every height


class MergesetTooLarge(Exception):
    pass


@dataclass
class BlockData:
    selected_parent: bytes | None
    dag_height: int      # GhostdagData::height = selected parent's + 1
    header_height: int   # Block::height = max over the listed parents + 1
    mergeset_order: list  # the candidates, in coloring order
    blues: list           # mergeset_blues (selected parent excluded), in order
    reds: list            # mergeset_reds, in order
    blue_score: int
    blue_work: int
    blue_set: frozenset = field(repr=False)  # blue(B), B itself excluded


class Dag:
    def __init__(self, k: int = K):
        self.k = k
        self.parents: dict[bytes, list[bytes]] = {}
        self.work: dict[bytes, int] = {}
        self.data: dict[bytes, BlockData] = {}
        self._past: dict[bytes, frozenset] = {}

    # ── structure ────────────────────────────────────────────────────────

    def past(self, h: bytes) -> frozenset:
        """past(h): every ancestor of h, h excluded."""
        if h not in self._past:
            s = set()
            for p in self.parents[h]:
                s.add(p)
                s |= self.past(p)
            self._past[h] = frozenset(s)
        return self._past[h]

    def anticone(self, a: bytes, b: bytes) -> bool:
        return a != b and a not in self.past(b) and b not in self.past(a)

    # ── the rules ────────────────────────────────────────────────────────

    def selected_parent(self, parents: list) -> bytes:
        """The parent with the largest (blue_work, blue_score, id)."""
        return max(set(parents), key=lambda p: (self.data[p].blue_work, self.data[p].blue_score, p))

    def add_genesis(self, h: bytes) -> BlockData:
        self.parents[h] = []
        self.work[h] = 0
        d = BlockData(None, 0, 0, [], [], [], 0, 0, frozenset())
        self.data[h] = d
        return d

    def add_block(self, h: bytes, parents: list, work: int, reading: str = "fifo") -> BlockData:
        assert parents and h not in self.data and all(p in self.data for p in parents)
        sp = self.selected_parent(parents)
        spd = self.data[sp]
        self.parents[h] = list(parents)
        self.work[h] = work
        past_b = set(parents)
        for p in parents:
            past_b |= self.past(p)
        mergeset = past_b - self.past(sp) - {sp}
        if len(mergeset) > MERGESET_SIZE_LIMIT:
            del self.parents[h], self.work[h]
            raise MergesetTooLarge(len(mergeset))
        order = candidate_order(mergeset, self.parents, reading)
        blue = set(spd.blue_set) | {sp}
        blues, reds = [], []
        for c in order:
            ac = [x for x in blue if self.anticone(c, x)]
            if len(ac) > self.k or any(
                sum(1 for y in blue if self.anticone(x, y)) + 1 > self.k for x in ac
            ):
                reds.append(c)
            else:
                blues.append(c)
                blue.add(c)
        d = BlockData(
            selected_parent=sp,
            dag_height=spd.dag_height + 1,
            header_height=max(self.data[p].dag_height for p in parents) + 1,
            mergeset_order=order,
            blues=blues,
            reds=reds,
            blue_score=spd.blue_score + len(blues) + 1,
            blue_work=spd.blue_work + sum(self.work[b] for b in blues) + work,
            blue_set=frozenset(blue),
        )
        self.data[h] = d
        return d


def candidate_order(mergeset: set, parents_of: dict, reading: str = "fifo") -> list:
    """The coloring order of `mergeset` (see the module docstring).
    `reading="fifo"` is GnB's rule; `"min-id"` is the other reading."""
    indeg = {b: len({p for p in parents_of[b] if p in mergeset}) for b in mergeset}
    children = {b: sorted({c for c in mergeset if b in parents_of[c]}) for b in mergeset}
    out = []
    if reading == "fifo":
        queue = deque(sorted(b for b in mergeset if indeg[b] == 0))
        while queue:
            b = queue.popleft()
            out.append(b)
            ready = []
            for c in children[b]:
                indeg[c] -= 1
                if indeg[c] == 0:
                    ready.append(c)
            queue.extend(sorted(ready))
    elif reading == "min-id":
        ready = sorted(b for b in mergeset if indeg[b] == 0)
        while ready:
            b = ready.pop(0)
            out.append(b)
            for c in children[b]:
                indeg[c] -= 1
                if indeg[c] == 0:
                    ready.append(c)
            ready.sort()
    else:
        raise ValueError(reading)
    assert len(out) == len(mergeset)
    return out


def duplicate_parents(parents: list) -> bool:
    """The header rule from the hardening activation (audit B2-T10): a
    parent listed twice is invalid (`block_rules::check_parents_distinct`)."""
    return len(set(parents)) != len(parents)
