"""basic blocks + dominators over the IR.

only branches that mean something at source level end up as conditional
blocks (emit decides which, see Decompiler.kind_of), the rest are the
compiler's NULL checks and we cut the error edge off. structuring itself
(if/loops/try) is in emit.py, this file is just the graph.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set

from .ir import Ins


def payload(x: Ins) -> bool:
    # "does this insn do anything visible". error epilogues are all DECREF /
    # RERAISE / return NULL, so they have none of it
    if x.kind in ("stmt", "assign"):
        return not (x.text or "").startswith(
            ("RERAISE", "CHECK_ERROR", "PyErr_", "EXC_FETCH", "EXC_RESTORE"))
    return False  # ret doesn't count, both edges end in the same epilogue


@dataclass
class Block:
    id: int
    ins: List[Ins] = field(default_factory=list)
    succs: List[int] = field(default_factory=list)   # [true_edge, false_edge] for cond blocks
    preds: List[int] = field(default_factory=list)
    cond: Optional[Ins] = None                          # semantic branch ending the block

    @property
    def start(self) -> int:
        return self.ins[0].addr if self.ins else -1


class CFG:
    def __init__(self, ins: List[Ins], semantic: Callable[[Ins], str],
                 resolve: Callable[[Ins], Optional[str]] = lambda x: None):
        self.ins = ins
        self.semantic = semantic
        self.resolve = resolve                 # -> "taken" | "fall" | None
        self.blocks: List[Block] = []
        self._build()
        self._reach()
        self.idom = self._dominators(self.entry, self._succ, self._pred)
        self.ipdom = self._dominators(None, self._succ_x, self._pred_x)

    def _build(self):
        ins = self.ins
        addr_idx: Dict[int, int] = {}
        for i, x in enumerate(ins):
            addr_idx[x.addr] = i
            for lab in x.labels:
                addr_idx.setdefault(lab, i)
        leaders: Set[int] = {0}
        for i, x in enumerate(ins):
            if x.kind in ("goto", "ret", "br"):
                leaders.add(i + 1)
                if x.target is not None and x.target in addr_idx:
                    leaders.add(addr_idx[x.target])
        leaders = sorted(x for x in leaders if x < len(ins))
        idx_block: Dict[int, int] = {}
        for bid, start in enumerate(leaders):
            end = leaders[bid + 1] if bid + 1 < len(leaders) else len(ins)
            b = Block(bid, ins[start:end])
            self.blocks.append(b)
            for k in range(start, end):
                idx_block[k] = bid
        self.idx_block = idx_block

        def blk_of_addr(a: int) -> Optional[int]:
            i = addr_idx.get(a)
            return idx_block.get(i) if i is not None else None

        for bid, b in enumerate(self.blocks):
            last = b.ins[-1] if b.ins else None
            nxt = bid + 1 if bid + 1 < len(self.blocks) else None
            if last is None:
                continue
            if last.kind == "ret":
                continue
            if last.kind == "goto":
                t = blk_of_addr(last.target)
                if t is not None:
                    b.succs = [t]
                continue
            if last.kind == "br":
                t = blk_of_addr(last.target)
                if t is None:
                    if nxt is not None:
                        b.succs = [nxt]
                    continue
                # je = jump if zero/NULL, so the taken edge is the false one
                if last.mnem == "je":
                    b.succs = [nxt, t] if nxt is not None else [t, t]
                else:
                    b.succs = [t, nxt] if nxt is not None else [t, t]
                if self.semantic(last):
                    b.cond = last
                continue
            if nxt is not None:
                b.succs = [nxt]
        self.entry = 0
        self.exc_succ: Dict[int, int] = {}     # protected block -> handler entry
        self._prune_error_edges()
        for b in self.blocks:
            for s in b.succs:
                self.blocks[s].preds.append(b.id)
        for b, h in self.exc_succ.items():
            self.blocks[h].preds.append(b)

    def handler_of(self, b: int) -> Optional[int]:
        # follow jump-only blocks from b; if the first real thing is an
        # EXC_FETCH this is an except handler entry
        seen: Set[int] = set()
        while b not in seen:
            seen.add(b)
            blk = self.blocks[b]
            for x in blk.ins:
                if x.kind == "assign" and (x.text or "").startswith("EXC_FETCH("):
                    return b
                if payload(x):
                    return None
            if blk.cond is not None or len(blk.succs) != 1:
                return None
            b = blk.succs[0]
        return None

    def _prune_error_edges(self):
        # non-semantic br = NULL check. one side is real code, the other goes
        # into an epilogue with no payload -> drop that edge. if it goes into
        # a handler instead, remember it in exc_succ for the try/except pass
        dead: Dict[int, bool] = {}

        def is_dead(b: int, seen: Set[int]) -> bool:
            if b in dead:
                return dead[b]
            if b in seen:
                return True
            seen.add(b)
            blk = self.blocks[b]
            if any(payload(x) for x in blk.ins) or blk.cond is not None:
                dead[b] = False
                return False
            r = all(is_dead(s, seen) for s in blk.succs)
            dead[b] = r
            return r

        for b in self.blocks:
            if len(b.succs) == 2 and b.cond is None:
                # succs is [taken, fall] for jne but [fall, taken] for je, see _build
                fall, taken = (b.succs[0], b.succs[1]) if b.ins[-1].mnem == "je" \
                    else (b.succs[1], b.succs[0])
                known = self.resolve(b.ins[-1])
                ht, hf = self.handler_of(taken), self.handler_of(fall)
                if ht is not None and hf is None:
                    b.succs, self.exc_succ[b.id] = [fall], ht
                elif hf is not None and ht is None:
                    b.succs, self.exc_succ[b.id] = [taken], hf
                elif known == "taken":
                    b.succs = [taken]
                elif known == "fall":
                    b.succs = [fall]
                elif is_dead(fall, set()) and not is_dead(taken, set()):
                    b.succs = [taken]
                else:
                    # both alive or both dead... keep fallthrough, was right
                    # more often than not
                    b.succs = [fall]

    def _reach(self):
        seen: Set[int] = set()
        stack = [self.entry]
        while stack:
            b = stack.pop()
            if b in seen:
                continue
            seen.add(b)
            stack.extend(self.all_succ(b))
        self.reachable = seen

    def all_succ(self, b: int) -> List[int]:
        s = list(self.blocks[b].succs)
        if b in self.exc_succ:
            s.append(self.exc_succ[b])
        return s

    # dominators, the simple iterative one (cooper/harvey/kennedy). functions
    # are small, no point in lengauer-tarjan
    def _succ(self, b): return [s for s in self.all_succ(b) if s in self.reachable]
    def _pred(self, b): return [p for p in self.blocks[b].preds if p in self.reachable]

    # same thing on the reversed graph for post-dominators, None = virtual exit
    def _succ_x(self, b):
        if b is None:
            return [x for x in self.reachable if not self._succ(x)]
        return self._pred(b)

    def _pred_x(self, b):
        if b is None:
            return []
        s = self._succ(b)
        return s if s else [None]

    def _dominators(self, root, succ, pred) -> Dict:
        order = []
        seen = set()

        def dfs(n):
            seen.add(n)
            for s in succ(n):
                if s not in seen:
                    dfs(s)
            order.append(n)
        dfs(root)
        rpo = order[::-1]
        pos = {n: i for i, n in enumerate(rpo)}
        idom = {root: root}
        changed = True
        while changed:
            changed = False
            for n in rpo[1:]:
                ps = [p for p in pred(n) if p in idom]
                if not ps:
                    continue
                new = ps[0]
                for p in ps[1:]:
                    new = self._intersect(new, p, idom, pos)
                if n not in idom or idom[n] != new:
                    idom[n] = new
                    changed = True
        return idom

    @staticmethod
    def _intersect(a, b, idom, pos):
        while a != b:
            while pos[a] > pos[b]:
                a = idom[a]
            while pos[b] > pos[a]:
                b = idom[b]
        return a

    def dominates(self, a, b) -> bool:
        while True:
            if a == b:
                return True
            if b == self.entry or b not in self.idom:
                return False
            nb = self.idom[b]
            if nb == b:
                return False
            b = nb

    def loops(self) -> Dict[int, Set[int]]:
        # header -> blocks of the natural loop (merged over all back edges)
        out: Dict[int, Set[int]] = {}
        for b in self.reachable:
            for s in self._succ(b):
                if self.dominates(s, b):
                    body = {s}
                    stack = [b]
                    while stack:
                        n = stack.pop()
                        if n in body:
                            continue
                        body.add(n)
                        stack.extend(p for p in self._pred(n) if p != s)
                    out.setdefault(s, set()).update(body)
        return out
