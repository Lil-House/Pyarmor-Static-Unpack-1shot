"""parse the lifter's text output back into records for the emitter.

lifter lines look like

    0x00033f  t6 = CALL t3(*t4, **t5)
    0x000348  je L0x000464 ; t6
   L0x000464:
    0x00265b  return None

yes, going text -> IR is a bit silly, but it kept the lifter dumb (one insn in,
one line out) and the .txt listing stays useful on its own.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

JCC = ("je", "jne", "js", "jns", "jle", "jg", "ja", "jae", "jb", "jbe", "jl", "jge")

# refcount / error-check scaffolding around every op, nothing to see here
NOISE_PREFIX = ("INCREF(", "DECREF(", "CHECK_ERROR(", "PyErr_Occurred(",
                "PyErr_Clear(", "memset(", "PyEval_GetGlobals(", "BIND_ARGS(",
                "# line", "# phi")

LINE_RE = re.compile(r"^\s*(0x[0-9a-f]+)\s\s(.*)$")
LABEL_RE = re.compile(r"^\s*L(0x[0-9a-f]+):$")
ASSIGN_RE = re.compile(r"^(t\d+) = (.*)$")
PHI_NOTE_RE = re.compile(r"^\s*0x[0-9a-f]+\s\s# phi (PHI\(.*\)) :: (.*)$")


def phi_sources(lines: List[str]) -> Dict[str, Dict[str, List[int]]]:
    # PHI(a, b) -> {a: [addr of the jump that brought a, ...], b: [...]}
    out: Dict[str, Dict[str, List[int]]] = {}
    for ln in lines:
        m = PHI_NOTE_RE.match(ln)
        if not m:
            continue
        srcs = out.setdefault(m.group(1), {})
        for part in m.group(2).split(" || "):
            leaf, _, addrs = part.rpartition(" <- ")
            if leaf:
                srcs.setdefault(leaf, []).extend(int(a, 16) for a in addrs.split(","))
    return out


@dataclass
class Ins:
    addr: int
    kind: str                      # stmt | assign | br | goto | ret
    text: str = ""                 # statement / expression text
    dest: Optional[str] = None     # tN for assignments
    target: Optional[int] = None   # branch/goto target
    mnem: str = ""                 # jcc mnemonic
    cond: str = ""                 # symbolic value the jcc tested
    labels: List[int] = field(default_factory=list)


def parse(lines: List[str]) -> List[Ins]:
    out: List[Ins] = []
    pending: List[int] = []
    for ln in lines:
        m = LABEL_RE.match(ln)
        if m:
            pending.append(int(m.group(1), 16))
            continue
        m = LINE_RE.match(ln)
        if not m:
            continue
        addr = int(m.group(1), 16)
        body = m.group(2).strip()
        ins = _one(addr, body)
        if ins is None:
            continue  # labels carry over to the next real insn
        ins.labels = pending
        pending = []
        out.append(ins)
    return out


def _one(addr: int, body: str) -> Optional[Ins]:
    word = body.split(" ", 1)[0]
    if word in JCC:
        rest = body.split(" ", 1)[1]
        tgt, _, cond = rest.partition(" ; ")
        return Ins(addr, "br", target=int(tgt[1:], 16), mnem=word, cond=cond.strip())
    if word == "goto":
        tgt = body.split(" ", 1)[1]
        if not tgt.startswith("L0x"):
            return None
        return Ins(addr, "goto", target=int(tgt[1:], 16))
    if word == "return":
        return Ins(addr, "ret", text=body[7:].strip())
    if word == "call":
        return None
    m = ASSIGN_RE.match(body)
    if m:
        expr = m.group(2)
        if any(expr.startswith(n) for n in NOISE_PREFIX):
            return None
        return Ins(addr, "assign", text=expr, dest=m.group(1))
    if any(body.startswith(n) for n in NOISE_PREFIX) or body.startswith("UNPACK("):
        return None  # bare UNPACK is arg binding, real tuple unpacks come as assigns
    return Ins(addr, "stmt", text=body)
