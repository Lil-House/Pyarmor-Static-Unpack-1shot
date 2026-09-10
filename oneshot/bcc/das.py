"""dig the BCC stub metadata out of the .das that shot.py writes.

every native function leaves a stub code object like

    [Constants]
        None
        '__pyarmor_bcc_4183__'
        ( 'logger' 'error' 'exc_info' 'sys' 'exit' 1 )   <- this is the pool

the tuple after the marker is what the native code indexes as pool[0x18+8*i].
marker ids are sequential and the stubs come in the same order as the ELF
descriptors, so i-th stub == i-th native function. (held on all samples,
fingers crossed)

nested defs are different: they leave a nest_NNNN trampoline in the parent's
pool, no marker, no pool (they use the parent's), but arg names are there.

NB: this parses the *text* of the .das. ugly but the das format is stable and
I didn't want to touch shot.py internals for this.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field, replace
from typing import Dict, Iterator, List, Optional, Tuple

MARKER = re.compile(r"^'__pyarmor_bcc_(\d+)__'$")
NESTED = re.compile(r"^nest_\d+$")


@dataclass
class Stub:
    marker: int
    name: str
    qualname: str
    argcount: int
    kwonly: int
    flags: str
    args: List[str]
    pool: list
    docstring: Optional[str] = None
    stack_size: int = 0
    names: List[str] = field(default_factory=list)


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _parse_const(lines: List[str], i: int, base_indent: int):
    # -> (value, next line index)
    raw = lines[i].rstrip("\n")
    txt = raw.strip()
    if txt == "(":
        items = []
        i += 1
        while i < len(lines) and lines[i].strip() != ")":
            v, i = _parse_const(lines, i, _indent(lines[i]))
            items.append(v)
        return tuple(items), i + 1
    if txt.startswith("[Code]"):
        name = "?"
        j = i + 1
        depth = _indent(lines[i])
        while j < len(lines) and (_indent(lines[j]) > depth or not lines[j].strip()):
            s = lines[j].strip()
            if s.startswith("Object Name:"):
                name = s.split(":", 1)[1].strip()
            j += 1
        return f"<CODE {name}>", j
    # mix-str constants get a "   # b'...'" trailer, drop it
    if "   # b" in txt:
        txt = txt.split("   # b", 1)[0].rstrip()
    try:
        return ast.literal_eval(txt), i + 1
    except Exception:
        # print("cant eval const:", txt)
        return txt, i + 1


def _code_objects(lines: List[str]) -> Iterator[Tuple[dict, List[str], List[str], list]]:
    # yields (header, locals, names, consts) per [Code] block
    i = 0
    n = len(lines)
    while i < n:
        if lines[i].strip() != "[Code]":
            i += 1
            continue
        depth = _indent(lines[i])
        hdr = {}
        j = i + 1
        while j < n and lines[j].strip() and not lines[j].strip().startswith("["):
            k, _, v = lines[j].strip().partition(":")
            hdr[k.strip()] = v.strip()
            j += 1
        args: List[str] = []
        names: List[str] = []
        consts: list = []
        # only this code object's own sub-blocks (indent == depth+4)
        while j < n and _indent(lines[j]) > depth:
            s = lines[j].strip()
            if _indent(lines[j]) == depth + 4 and s == "[Locals+Names]":
                j += 1
                while j < n and _indent(lines[j]) == depth + 8:
                    args.append(ast.literal_eval(lines[j].strip()))
                    j += 1
                continue
            if _indent(lines[j]) == depth + 4 and s == "[Names]":
                j += 1
                while j < n and _indent(lines[j]) == depth + 8:
                    try:
                        names.append(ast.literal_eval(lines[j].strip()))
                    except Exception:
                        names.append(lines[j].strip())
                    j += 1
                continue
            if _indent(lines[j]) == depth + 4 and s == "[Constants]":
                j += 1
                while j < n and _indent(lines[j]) >= depth + 8:
                    # nested [Code] is handled by the outer loop, _parse_const
                    # just skips over it and leaves a <CODE name> placeholder
                    v, j = _parse_const(lines, j, depth + 8)
                    consts.append(v)
                continue
            if _indent(lines[j]) == depth + 4 and s == "[Disassembly]":
                break
            j += 1
        yield hdr, args, names, consts
        i += 1


def _stub(hdr: dict, args: List[str], names: List[str], consts: list,
          marker: int, pool: Optional[list]) -> Stub:
    doc = consts[0] if consts and isinstance(consts[0], str) and not MARKER.match(repr(consts[0])) else None
    return Stub(
        marker=marker,
        name=hdr.get("Object Name", "?"),
        qualname=hdr.get("Qualified Name", hdr.get("Object Name", "?")),
        argcount=int(hdr.get("Arg Count", 0)),
        kwonly=int(hdr.get("KW Only Arg Count", 0)),
        flags=hdr.get("Flags", ""),
        args=[a for a in args if a != "__assert_bcc__"],
        pool=pool or [],
        docstring=doc,
        stack_size=int(hdr.get("Stack Size", 0)),
        names=names,
    )


def parse_das(path: str) -> List[Stub]:
    lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    stubs: List[Stub] = []
    for hdr, args, names, consts in _code_objects(lines):
        marker = None
        pool = None
        for k, c in enumerate(consts):
            if isinstance(c, str) and MARKER.match(repr(c)):
                marker = int(MARKER.match(repr(c)).group(1))
                if k + 1 < len(consts) and isinstance(consts[k + 1], tuple):
                    pool = list(consts[k + 1])
                break
        if marker is not None:
            stubs.append(_stub(hdr, args, names, consts, marker, pool))
    stubs.sort(key=lambda s: s.marker)
    return stubs


def parse_nested(path: str) -> Dict[str, Stub]:
    lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    out: Dict[str, Stub] = {}
    for hdr, args, names, consts in _code_objects(lines):
        name = hdr.get("Object Name", "")
        if NESTED.match(name) and name not in out:
            # locals = params + one freevar with the native proxy, cut the latter
            n = int(hdr.get("Arg Count", 0)) + int(hdr.get("KW Only Arg Count", 0))
            if "CO_VARARGS" in hdr.get("Flags", ""):
                n += 1
            if "CO_VARKEYWORDS" in hdr.get("Flags", ""):
                n += 1
            out[name] = _stub(hdr, args[:n], names, consts, -1, None)
    return out


def with_pool(stub: Stub, pool: list) -> Stub:
    return replace(stub, pool=list(pool))
