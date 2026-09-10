"""lifted ops -> python source.

    .elf --lift--> op lines --ir--> records --(this)--> exprs + control flow --> .py

the CFG is full of NULL-check branches (one after every op basically). a
branch only counts as real control flow if it tests a BOOL(), a NEXT() or an
exception-match, everything else gets cut in cfg.py. what's left nests like
the original source because pyarmor emits blocks in bytecode order, so
recursing over spans gets if/else/for/while/with/try back.

local names are gone (stub only keeps arg names), non-arg locals are v1, v2...
when unsure leave a marked comment, don't guess.

this file grew way past what I planned.
"""

from __future__ import annotations

import argparse
import ast
import bisect
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from . import ir as bcc_ir
from .cfg import CFG, Block, payload
from .elf import BccElf
from .ir import Ins
from .lift import Lifter, load_stubs
from .das import Stub

UNPACK_RE = re.compile(r"UNPACK\((.+), n=(\d+)\)\[(\d+)\]")
EXC_MATCH_RE = re.compile(r"\((.+?) exception-match (.+)\)")
EXC_SLOT_RE = re.compile(r"\bexc_(type|value|tb)\b")
EXC_SLOT = {"type": 0, "value": 1, "tb": 2}      # the fetched triple, as sys.exc_info()
LITERAL_RE = re.compile(r"True|False|None|-?\d+|'.*'|\".*\"")
STMT_OPS = ("STORE_GLOBAL ", "DELETE_GLOBAL(", "STORE ", "SETITEM ", "SETATTR ")

TMP_RE = re.compile(r"\bt(\d+)\b")
ATTR_RE = re.compile(r"\.'([A-Za-z_]\w*)'")
LOCAL_RE = re.compile(r"\bL(\d+)\b")


def split_args(s: str) -> List[str]:
    # "a, b(c, d), 'e,f'" -> ["a", "b(c, d)", "'e,f'"]. yes we're parsing our
    # own text output again. see ir.py
    out, depth, cur, quote = [], 0, [], None
    i = 0
    while i < len(s):
        ch = s[i]
        if quote:
            cur.append(ch)
            if ch == "\\":
                if i + 1 < len(s):
                    cur.append(s[i + 1])
                    i += 2
                    continue
            elif ch == quote:
                quote = None
        else:
            if ch in "\"'":
                quote = ch
                cur.append(ch)
            elif ch in "([{":
                depth += 1
                cur.append(ch)
            elif ch in ")]}":
                depth -= 1
                cur.append(ch)
            elif ch == "," and depth == 0:
                out.append("".join(cur).strip())
                cur = []
            else:
                cur.append(ch)
        i += 1
    tail = "".join(cur).strip()
    if tail:
        out.append(tail)
    return out


def call_parts(text: str, head: str) -> Optional[Tuple[str, str]]:
    # "HEAD(inner)rest" -> (inner, rest), balanced parens
    if not text.startswith(head + "("):
        return None
    inner = text[len(head) + 1:]
    depth, quote = 1, None
    for i, ch in enumerate(inner):
        if quote:
            if ch == quote and inner[i - 1] != "\\":
                quote = None
            continue
        if ch in "\"'":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                return inner[:i], inner[i + 1:]
    return None


AUG_RE = re.compile(r"^(\s*)(.+?) = \(\2 ([-+*/%|&^]|//|\*\*|<<|>>)= (.*)\)$")
INPLACE_RE = re.compile(r"\((.+?) ([-+*/%|&^]|//|\*\*|<<|>>)= (.*)\)")


def assignable(target: str) -> bool:
    # can this be the lhs of `+=`? PHI(...) can't
    try:
        tree = ast.parse(target, mode="eval")
    except SyntaxError:
        return False
    return isinstance(tree.body, (ast.Name, ast.Attribute, ast.Subscript))


def fix_aug(line: str) -> str:
    # x = (x += 1)  ->  x += 1
    m = AUG_RE.fullmatch(line)
    return f"{m.group(1)}{m.group(2)} {m.group(3)}= {m.group(4)}" if m else line


def fbody(s: str) -> Optional[str]:
    # body of an f-string literal we emitted before, or None
    for q in ("'''", '"""', "'", '"'):
        if s.startswith("f" + q) and s.endswith(q) and len(s) >= 2 * len(q) + 1:
            return s[len(q) + 1:-len(q)]
    return None


Seg = Tuple[bool, str]      # (is replacement field, text)


def fsplit(body: str) -> List[Seg]:
    segs: List[Seg] = []
    i, lit = 0, []
    while i < len(body):
        ch = body[i]
        if ch == "{" and body[i + 1:i + 2] != "{":
            if lit:
                segs.append((False, "".join(lit)))
                lit = []
            depth, quote, j = 1, None, i + 1
            while j < len(body) and depth:
                c = body[j]
                if quote:
                    if c == quote:
                        quote = None
                elif c in "'\"":
                    quote = c
                elif c in "([{":
                    depth += 1
                elif c in ")]}":
                    depth -= 1
                j += 1
            segs.append((True, body[i:j]))
            i = j
            continue
        if ch in "{}" and body[i + 1:i + 2] == ch:
            lit.append(ch + ch)
            i += 2
            continue
        if ch == "\\" and body[i + 1:i + 2] in ("'", '"'):
            lit.append(body[i + 1])
            i += 2
            continue
        lit.append(ch)
        i += 1
    if lit:
        segs.append((False, "".join(lit)))
    return segs


def fquote(segs: List[Seg]) -> str:
    # pick a quote none of the {fields} use. <3.12 can't reuse the outer quote
    # inside a field, and split_args would choke on it anyway
    fields = "".join(t for is_field, t in segs if is_field)
    if "'" not in fields:
        q = "'"
    elif '"' not in fields:
        q = '"'
    else:
        q = "'''"
    body = "".join(
        t if is_field or len(q) > 1 else t.replace(q, "\\" + q) for is_field, t in segs)
    return f"f{q}{body}{q}"


def fstring(parts: List[str]) -> str:
    # BUILD_STRING(lit, FORMAT_VALUE(x), lit, ...) -> f'lit{x}lit'
    segs: List[Seg] = []
    for p in parts:
        fv = call_parts(p, "FORMAT_VALUE")
        if fv is not None and not fv[1]:
            inner = fv[0]
            spliced = fbody(inner)
            if spliced is not None:  # nested f-string, splice
                segs += fsplit(spliced)
                continue
            segs.append((True, "{" + inner + "}"))
            continue
        spliced = fbody(p)
        if spliced is not None:
            segs += fsplit(spliced)
            continue
        if len(p) >= 2 and p[0] in "'\"" and p[-1] == p[0]:
            try:
                lit = ast.literal_eval(p)
            except Exception:
                lit = p
            if not isinstance(lit, str):
                segs.append((True, "{" + p + "}"))
                continue
            esc = repr(lit)[1:-1].replace(r"\'", "'").replace(r'\"', '"')
            segs.append((False, esc.replace("{", "{{").replace("}", "}}")))
            continue
        segs.append((True, "{" + p + "}"))
    out = fquote(segs)
    try:
        ast.parse(out, mode="eval")
    except SyntaxError:
        # backslash inside a field etc, fall back to ''.join
        return fconcat(segs)
    return out


def fconcat(segs: List[Seg]) -> str:
    pieces = []
    for is_field, t in segs:
        if not is_field:
            lit = ast.literal_eval(fquote([(False, t)])[1:])
            pieces.append(repr(lit.replace("{{", "{").replace("}}", "}")))
            continue
        inner = t[1:-1]
        conv = spec = None
        m = re.search(r":([^'\"()\[\]{}:!]*)$", inner)
        if m and m.start() > 0:
            inner, spec = inner[:m.start()], m.group(1)
        m = re.search(r"!([rsa])$", inner)
        if m:
            inner, conv = inner[:m.start()], m.group(1)
        if conv:
            inner = {"r": "repr", "s": "str", "a": "ascii"}[conv] + f"({inner})"
        pieces.append(f"format({inner}, {spec!r})" if spec else f"format({inner})")
    return "''.join([" + ", ".join(pieces) + "])"


class Expr:
    # one lifted op -> python expression text

    def __init__(self, locals_name):
        self.lname = locals_name

    def __call__(self, text: str) -> str:
        t = text.strip()
        for head, fn in (
            ("LOAD_GLOBAL", self._name_of),
            ("BUILD_TUPLE", lambda a: self._seq(a, "(", ")", tuple_=True)),
            ("BUILD_LIST", lambda a: self._seq(a, "[", "]")),
            ("BUILD_SET", lambda a: self._seq(a, "{", "}", empty="set()")),
            ("BUILD_DICT", self._dict),
            ("BUILD_STRING", lambda a: fstring(split_args(a))),
            ("BOOL", lambda a: self(a)),
            ("ITER", lambda a: f"iter({self(a)})"),
            ("NEXT", lambda a: f"next({self(a)})"),
            ("PyList_New", lambda a: "[]"),
            ("PySet_New", lambda a: "set()"),
            ("PyCell_Get", lambda a: self(a)),
            ("PyCell_New", lambda a: "None" if a.strip() == "0" else self(a)),
            ("FORMAT_VALUE", self._format_value),
        ):
            got = call_parts(t, head)
            if got is not None and not got[1]:
                return fn(got[0])

        got = call_parts(t, "UNPACK")
        if got is not None and re.fullmatch(r"\[\d+\]", got[1]):
            return f"{self(split_args(got[0])[0])}{got[1]}"

        m = EXC_MATCH_RE.fullmatch(t)
        if m:
            exc = m.group(1) if m.group(1).isidentifier() and m.group(1) != "None" \
                and not m.group(1).startswith("exc_") else "sys.exc_info()[1]"
            return f"isinstance({exc}, {m.group(2)})"

        got = call_parts(t, "PySlice_New")
        if got is not None and not got[1]:
            a = [x if x != "None" else "" for x in split_args(got[0])]
            while len(a) < 3:
                a.append("")
            return ":".join(a[:2]) + (f":{a[2]}" if a[2] else "")

        got = call_parts(t, "IMPORT")
        if got is not None and not got[1]:
            a = split_args(got[0])
            return f"__import__({a[0]})"

        for head in ("PyObject_CallFunction", "PyObject_CallFunctionObjArgs",
                     "PyObject_CallMethod"):
            got = call_parts(t, head)
            if got is not None:
                a = split_args(got[0])
                return f"{a[0]}({', '.join(a[3:]) if len(a) > 3 else ''})"

        if t.startswith("CALL "):
            return self._call(t[5:])
        for head in ("MAKE_FUNCTION", "MAKE_CLOSURE"):
            got = call_parts(t, head)
            if got is not None:
                return self._func_ref(split_args(got[0]))
        return t

    @staticmethod
    def _format_value(a: str) -> str:
        # FORMAT_VALUE(x!r:'spec') -> f'{x!r:spec}'
        inner = split_args(a)[0]
        m = re.fullmatch(r"(.*?)(![rsa])?:f?(['\"])(.*)\3", inner)
        if m:
            inner = f"{m.group(1)}{m.group(2) or ''}:{m.group(4)}"
        return fquote([(True, "{" + inner + "}")])

    @staticmethod
    def _func_ref(args: List[str]) -> str:
        # MAKE_FUNCTION/MAKE_CLOSURE: &nest_NNNN if we know the native body,
        # else the code object name (lambda, genexpr... those stay bytecode)
        for a in args:
            if a.startswith("&"):
                return a[1:]
        for a in args:
            m = re.fullmatch(r"'<CODE (.+)>'", a)
            if m:
                name = m.group(1)
                return name if name.isidentifier() else "__" + name.strip("<>") + "__"
        return "__function__"

    def _name_of(self, arg: str) -> str:
        arg = arg.strip()
        if len(arg) >= 2 and arg[0] in "'\"":
            return arg[1:-1]
        return f"globals()[{arg}]"

    def _seq(self, arg: str, o: str, c: str, tuple_=False, empty=None) -> str:
        items = split_args(arg)
        if not items:
            return empty or (o + c)
        if tuple_ and len(items) == 1:
            return f"({items[0]},)"
        return o + ", ".join(items) + c

    @staticmethod
    def _dict(arg: str) -> str:
        # BUILD_DICT(...) with runtime count -> nothing to recover, emit {}
        a = arg.strip()
        return a if a.startswith("{") and a.endswith("}") else "{}"

    def _call(self, rest: str) -> str:
        # CALL f(*(a, b), **{'k': v}) -> f(a, b, k=v)
        m = re.match(r"^(.*?)\((.*)\)$", rest, re.S)
        if not m:
            return rest
        func, inner = m.group(1), m.group(2)
        args: List[str] = []
        for part in split_args(inner):
            if part.startswith("**"):
                d = part[2:].strip()
                if d.startswith("{") and d.endswith("}"):
                    for kv in split_args(d[1:-1]):
                        k, _, v = kv.partition(":")
                        k = k.strip()
                        if len(k) >= 2 and k[0] in "'\"" and re.fullmatch(
                                r"[A-Za-z_]\w*", k[1:-1] or "x"):
                            args.append(f"{k[1:-1]}={v.strip()}")
                        else:
                            args.append(f"**{{{kv}}}")
                else:
                    args.append(f"**{d}")
            elif part.startswith("*"):
                seq = part[1:].strip()
                if seq.startswith("(") and seq.endswith(")"):
                    inner_items = split_args(seq[1:-1])
                    args.extend(x for x in inner_items if x)
                else:
                    args.append(f"*{seq}")
            else:
                args.append(part)
        return f"{func}({', '.join(args)})"


@dataclass
class Arm:
    # one arm of an emitted if: blocks it covered + where its lines are
    blocks: set = field(default_factory=set)
    lines: List[str] = field(default_factory=list)
    start: int = 0
    end: int = 0

    def ends_flow(self) -> bool:
        return bool(self.lines) and self.lines[-1].strip().split(" ")[0] in (
            "return", "raise", "continue", "break")


class Decompiler:
    def __init__(self, ins: List[Ins], stub: Optional[Stub], name: str,
                 phi_src: Optional[Dict[str, Dict[str, List[int]]]] = None):
        self.ins = ins
        self.stub = stub
        self.name = name
        self.phi_src = phi_src or {}       # PHI(..) -> leaf -> addrs of the edges carrying it
        self.by_addr: Dict[int, int] = {}
        for i, x in enumerate(ins):
            self.by_addr[x.addr] = i
            for lab in x.labels:
                self.by_addr.setdefault(lab, i)
        self._addrs = sorted(self.by_addr)
        self.defs: Dict[str, Ins] = {x.dest: x for x in ins if x.dest}
        self._fold_bool_values()
        self.modules: Dict[str, str] = {}
        self.imported: Dict[str, set] = {}     # import tmp -> names it binds
        self.alias: Dict[int, str] = {}        # local index -> source name
        self.exit_tmps: set = set()
        self.skip_ins: set = set()
        self.ret_pushed: set = set()
        self.pending_indent = 0
        self.uses: Dict[str, int] = {}
        for x in ins:
            for t in TMP_RE.findall(x.text or ""):
                self.uses["t" + t] = self.uses.get("t" + t, 0) + 1
        self.expr = Expr(self._local)
        self.inlined: Dict[str, str] = {}
        self.consumed: set = set()
        self.warnings: List[str] = []
        self.rebound: set = set()      # module globals this function assigns
        # only "real" branches count as a use of their operand
        self.cond_used = {t for x in ins if self.kind_of(x)
                          for t in ("t" + n for n in TMP_RE.findall(x.cond or ""))}
        for x in ins:
            if x.kind != "assign":
                continue
            if ".'__enter__'" in (x.text or ""):
                mgr = x.text.split(".'__enter__'")[0]
                if re.fullmatch(r"t\d+", mgr):
                    self.uses[mgr] = 1  # `with <mgr>:` reads it once
            if ".'__exit__'" in (x.text or "") and x.dest:
                self.exit_tmps.add(x.dest)
            m = re.fullmatch(r"NEXT\((t\d+)\)", x.text or "")
            if m:
                self.uses[m.group(1)] = 1  # `for .. in <seq>` same
        # a, b = t3  counts as one use of t3 no matter how many parts
        parts = [x for x in ins if x.kind == "assign" and UNPACK_RE.fullmatch(x.text or "")]
        others = [x for x in ins if x not in parts]
        for x in parts:
            for leaf in phi_leaves(UNPACK_RE.fullmatch(x.text).group(1)):
                if re.fullmatch(r"t\d+", leaf) and not any(
                        re.search(rf"\b{leaf}\b", o.text or "") for o in others):
                    self.uses[leaf] = 1
        self.phi_alias: Dict[str, str] = {}    # merged value -> variable holding it
        self.phi_arm: Dict[str, int] = {}      # variable -> block whose `if` assigned it

    def _local(self, idx: int) -> str:
        args = self.stub.args[:self.stub.argcount] if self.stub else []
        if idx < len(args):
            return args[idx]
        return self.alias.get(idx, f"v{idx}")

    def _global(self, name: str) -> str:
        n = self.render(name).strip().strip("'\"")
        if n.isidentifier():
            self.rebound.add(n)
            return n
        return f"globals()[{self.render(name)}]"

    def _fix_names(self, s: str) -> str:
        s = ATTR_RE.sub(lambda m: "." + m.group(1), s)
        return LOCAL_RE.sub(lambda m: self._local(int(m.group(1))), s)

    def value(self, tmp: str) -> str:
        # text for tN, inlined if used once
        if tmp in self.inlined:
            return self.inlined[tmp]
        d = self.defs.get(tmp)
        if d is None:
            return tmp
        text = self.render(d.text)
        if self.uses.get(tmp, 0) <= 1:
            self.inlined[tmp] = text
            self.consumed.add(tmp)
            return text
        self.inlined[tmp] = tmp
        return tmp

    def render(self, text: str) -> str:
        for phi in sorted(self.phi_alias, key=len, reverse=True):
            text = text.replace(phi, self.phi_alias[phi])
        text = TMP_RE.sub(lambda m: self.value("t" + m.group(1)), text)
        out = self.expr(self._fix_names(text))
        for tmp in self.modules:
            out = re.sub(rf"\b{tmp}\.", "", out)
        out = EXC_SLOT_RE.sub(lambda m: f"sys.exc_info()[{EXC_SLOT[m.group(1)]}]", out)
        return collapse_phi(out)

    def _def_text(self, cond: str) -> str:
        d = self.defs.get(cond.split(" ")[0])
        return d.text if d else ""

    def kind_of(self, b: Ins) -> str:
        if b.kind != "br":
            return ""
        cond = b.cond
        if cond.endswith("cmp -1") or b.mnem not in ("je", "jne"):
            return ""  # error check on a C int
        t = self._def_text(cond)
        if self._touches_exit(t):
            return ""  # with-cleanup, not control flow
        if t.startswith("BOOL("):
            inner = self._def_text(t[5:-1])
            return "except" if "exception-match" in inner else "if"
        if t.startswith("NEXT("):
            return "iter"
        return ""  # raw exception-match result = NULL check

    NONNULL_RE = re.compile(r"True|False|None|-?[1-9]\d*|'.*'|\".*\"|L\d+|args|ctx")

    def static_edge(self, b: Ins) -> Optional[str]:
        # NULL checks with a known answer: literals/pool/bound locals are never
        # NULL, PyErr_Occurred() is NULL on the path we keep, cmp -1 = C error
        if b.kind != "br" or b.mnem not in ("je", "jne"):
            return None
        cond = b.cond
        if cond.endswith("cmp -1"):
            return "fall" if b.mnem == "je" else "taken"
        args = set(self.stub.args[:self.stub.argcount]) if self.stub else set()
        if all(self.NONNULL_RE.fullmatch(c) or c in args for c in cond.split(" || ")):
            return "fall" if b.mnem == "je" else "taken"
        if self._def_text(cond).startswith("PyErr_Occurred("):
            return "taken" if b.mnem == "je" else "fall"
        return None

    def _touches_exit(self, text: str, depth: int = 3) -> bool:
        if not self.exit_tmps or depth < 0:
            return False
        tmps = {"t" + n for n in TMP_RE.findall(text or "")}
        if tmps & self.exit_tmps:
            return True
        return any(self._touches_exit((self.defs[t].text if t in self.defs else ""),
                                      depth - 1) for t in tmps)

    def run(self) -> List[str]:
        self.cfg = CFG(self.ins, self.kind_of, self.static_edge)
        self.loop_body = self.cfg.loops()
        self.done: set = set()
        self._find_tries()
        body = self.region(self.cfg.entry, set(), 1, [])
        while body and body[-1].strip() in ("return", "continue", "pass"):
            body.pop()
        body = self._fill_suites(body)
        head = self._signature()
        return head + (body or ["    pass"])

    @staticmethod
    def _fill_suites(lines: List[str]) -> List[str]:
        # `if x:` followed by nothing (all dropped as cleanup) needs a pass
        out: List[str] = []
        for i, ln in enumerate(lines):
            out.append(ln)
            if not ln.rstrip().endswith(":") or ln.lstrip().startswith("#"):
                continue
            ind = len(ln) - len(ln.lstrip())
            nxt = next((x for x in lines[i + 1:] if x.strip()), None)
            if nxt is None or (len(nxt) - len(nxt.lstrip())) <= ind \
                    or nxt.lstrip().startswith("#"):
                out.append(" " * (ind + 4) + "pass")
        return out

    def _signature(self) -> List[str]:
        args = self.stub.args[:self.stub.argcount] if self.stub else []
        out = [f"def {self.name}({', '.join(args)}):"]
        if self.stub and self.stub.docstring:
            out.append("    " + repr(self.stub.docstring))
        if self.rebound:
            out.append("    global " + ", ".join(sorted(self.rebound)))
        return out

    def _find_tries(self):
        # group protected blocks by handler. try opens at the first protected
        # block, handler chain = except clauses. handlers that call __exit__
        # are a `with` and get emitted from the __enter__ side instead
        self.try_at: Dict[int, int] = {}          # first protected block -> handler
        by_h: Dict[int, List[int]] = {}
        for b, h in self.cfg.exc_succ.items():
            if b in self.cfg.reachable:
                by_h.setdefault(h, []).append(b)
        for h, prot in by_h.items():
            if self._handler_ins(h, self.exit_tmps):
                continue
            s = min(prot, key=lambda b: self.cfg.blocks[b].start)
            self.try_at[self._stmt_before_check(s)] = h

    def _stmt_before_check(self, s: int) -> int:
        # if the first protected block is just the `jne rax` after a
        # SETITEM/SETATTR, the try really starts one statement earlier
        blk = self.cfg.blocks[s]
        if len(blk.ins) != 1 or blk.ins[0].kind != "br" or blk.cond is not None:
            return s
        preds = self.cfg._pred(s)
        if len(preds) != 1:
            return s
        p = self.cfg.blocks[preds[0]]
        if p.succs != [s] or p.cond is not None or not p.ins \
                or p.ins[-1].kind != "stmt" or preds[0] in self.cfg.exc_succ:
            return s
        return preds[0]

    def _handler_ins(self, h: int, tmps: set) -> bool:
        seen, todo = set(), [h]
        while todo and len(seen) < 8:
            n = todo.pop(0)
            if n in seen:
                continue
            seen.add(n)
            for x in self.cfg.blocks[n].ins:
                if any(t in (x.text or "") + (x.cond or "") for t in tmps):
                    return True
            todo += self.cfg.blocks[n].succs
        return False

    def _join_after(self, h: int) -> Optional[int]:
        # where the handler rejoins: lowest block reachable from h that also
        # has a pred outside the handler. the shared epilogue qualifies too
        # but it's further down so min() picks the right one
        seen, todo = set(), [h]
        while todo:
            n = todo.pop()
            if n in seen:
                continue
            seen.add(n)
            todo += self.cfg.blocks[n].succs
        cands = [n for n in seen if n != h and any(
            p not in seen and p in self.cfg.reachable for p in self.cfg.blocks[n].preds)]
        return min(cands, key=lambda n: self.cfg.blocks[n].start) if cands else None

    def _try(self, s: int, stop: set, depth: int,
             lstack) -> Tuple[List[str], Optional[int]]:
        pad = "    " * depth
        h = self.try_at.pop(s)
        join = self._join_after(h)
        inner = stop | ({join} if join is not None else set())
        out = [pad + "try:"]
        before = set(self.done)
        lines = self.region(s, inner, depth + 1, lstack)
        lines += self._arm_return(join, self.done - before, lines, depth + 1)
        out += lines or [pad + "    pass"]
        b = h
        while b is not None and b not in self.done:
            m = self._match_clause(b)
            before = set(self.done)
            if m is None:
                out.append(pad + "except:")
                lines = self.region(b, inner, depth + 1, lstack)
                lines += self._arm_return(join, self.done - before, lines, depth + 1)
                out += lines or [pad + "    pass"]
                break
            cls, yes, no = m
            lines = self.region(yes, inner, depth + 1, lstack)
            lines += self._arm_return(join, self.done - before, lines, depth + 1)
            out.append(pad + f"except {cls}{self._exc_as(lines)}:")
            out += lines or [pad + "    pass"]
            if no is None or self._reraise_only(no):
                break
            b = no
        return out, join

    @staticmethod
    def _exc_as(lines: List[str]) -> str:
        # first stmt is `e = sys.exc_info()[1]` -> move it into `except X as e`
        for i, ln in enumerate(lines):
            if not ln.strip():
                continue
            m = re.fullmatch(r"\s*(\w+) = sys\.exc_info\(\)\[1\]", ln)
            if m:
                del lines[i]
                return f" as {m.group(1)}"
            break
        return ""

    def _match_clause(self, b: int):
        # -> (cls, matched_block, unmatched_block or None) for the
        # exception-match at the head of a handler chain, or None
        seen = set()
        while b is not None and b not in seen and len(seen) < 16:
            seen.add(b)
            blk = self.cfg.blocks[b]
            for x in blk.ins:
                if x.kind in ("br", "goto") or id(x) in self.skip_ins:
                    continue
                if x.kind == "assign" and (x.text or "").startswith("EXC_FETCH("):
                    continue
                if x.kind == "assign" and self.uses.get(x.dest, 0) <= 1:
                    continue  # feeds the match test
                return None
            if blk.cond is not None:
                if self.kind_of(blk.cond) != "except":
                    return None
                m = re.search(r"exception-match (.+?)\)$",
                              self._def_text(self._def_text(blk.cond.cond)[5:-1]))
                if m is None:
                    return None
                for x in blk.ins:
                    if x.kind == "assign":
                        self.consumed.add(x.dest)
                for n in seen:
                    self.done.add(n)
                yes, no = blk.succs[0], blk.succs[1]
                if blk.cond.cond.endswith("cmp 1"):
                    yes, no = no, yes
                return self.render(m.group(1)), yes, no
            b = blk.succs[0] if len(blk.succs) == 1 else None
        return None

    def _reraise_only(self, b: int) -> bool:
        seen = set()
        while b is not None and b not in seen:
            seen.add(b)
            blk = self.cfg.blocks[b]
            if any(payload(x) for x in blk.ins) or blk.cond is not None:
                return False
            b = blk.succs[0] if len(blk.succs) == 1 else None
        return True

    def region(self, b: Optional[int], stop: set, depth: int,
               lstack: List[Tuple[int, Optional[int]]], entering: bool = False) -> List[str]:
        out: List[str] = []
        while b is not None and b not in stop:
            pad = "    " * depth
            for hdr, exit_b in reversed(lstack) if not entering else ():
                if b == hdr:
                    out.append(pad + "continue")
                    return out
                if exit_b is not None and b == exit_b:
                    out.append(pad + "break")
                    return out
            if b in self.done:
                # already emitted. usually the shared epilogue, fine. if not,
                # leave a marker, something's off
                if not self._epilogue_only(b):
                    out.append(pad + f"# re-enters block at "
                                     f"{self.cfg.blocks[b].start:#x}")
                return out
            self.done.add(b)
            entering = False
            if b in self.try_at:
                self.done.discard(b)
                lines, b = self._try(b, stop, depth, lstack)
                out += lines
                continue
            if b in self.loop_body and not any(h == b for h, _ in lstack):
                lines, b = self._loop(b, stop, depth, lstack)
                out += lines
                continue
            blk = self.cfg.blocks[b]
            out += self._block_body(blk, depth)
            depth += self.pending_indent  # `with` nests the rest of the region
            if blk.cond is not None:
                lines, b = self._if(blk, stop, depth, lstack)
                out += lines
                continue
            b = blk.succs[0] if len(blk.succs) == 1 else None
        return out

    def _epilogue_only(self, b: int) -> bool:
        for x in self.cfg.blocks[b].ins:
            if x.kind == "ret" and self.render(x.text) in ("0", "None", ""):
                continue
            if x.kind in ("br", "goto"):
                continue
            if x.kind == "assign" and self.uses.get(x.dest, 0) <= 1:
                continue
            return False
        return True

    def _block_body(self, blk: Block, depth: int) -> List[str]:
        out: List[str] = []
        extra = 0
        for x in blk.ins:
            if x.kind in ("br", "goto"):
                continue
            w = self._with_head(x, depth + extra)
            if w is not None:
                out.append(w)
                extra += 1
                continue
            if self.exit_tmps and any(
                    t in ((x.text or "") + (x.cond or "")) for t in self.exit_tmps):
                continue  # __exit__ plumbing
            out += self.stmt(x, "    " * (depth + extra))
        self.pending_indent = extra
        return out

    def _with_head(self, x: Ins, depth: int) -> Optional[str]:
        if x.kind != "assign" or not x.text.startswith("PyObject_CallFunction("):
            return None
        a = split_args(call_parts(x.text, "PyObject_CallFunction")[0])
        d = self.defs.get(a[0].strip())
        if d is None or ".'__enter__'" not in (d.text or ""):
            return None
        mgr = d.text.split(".'__enter__'")[0]
        var = f"v{x.dest[1:]}"
        i = self.ins.index(x)
        for nx in self.ins[i + 1:i + 4]:  # `with m as f` stores right away
            m = re.fullmatch(r"STORE (L\d+) = " + re.escape(x.dest), nx.text or "")
            if m:
                var = self._fix_names(m.group(1))
                self.skip_ins.add(id(nx))
                break
        self.inlined[x.dest] = var
        self.consumed.add(x.dest)
        return "    " * depth + f"with {self.render(mgr)} as {var}:"

    def _if(self, blk: Block, stop: set, depth: int,
            lstack) -> Tuple[List[str], Optional[int]]:
        d = depth
        pad = "    " * d
        raw = self._def_text(blk.cond.cond)
        t, f = blk.succs[0], blk.succs[1]
        if raw.startswith("NEXT("):
            # first FOR_ITER of a bottom-tested loop, not an if
            h = self._loop_after(t)
            if h is not None:
                return [], h
        if blk.cond.cond.endswith("cmp 1"):  # cmp 1; jne  jumps when false
            t, f = f, t
        cond = self.render(raw)
        cond, t, f = self._fold_short_circuit(cond, t, f)
        follow = self.cfg.ipdom.get(blk.id)      # None = the virtual exit
        then_b, else_b = t, f
        if then_b == follow:
            cond, then_b, else_b = f"not ({cond})", else_b, None
        elif else_b == follow:
            else_b = None
        out = [pad + f"if {cond}:"]
        inner = stop | ({follow} if follow is not None else set())
        before = set(self.done)
        arms: List[Arm] = []
        for arm, head in ((then_b, None), (else_b, pad + "else:")):
            if arm is None:
                arms.append(Arm())
                continue
            if head:
                out.append(head)
            start = len(out)
            arm_done = set(self.done)
            lines = self.region(arm, inner, d + 1, lstack)
            lines += self._arm_return(follow, self.done - arm_done, lines, d + 1)
            out += lines or [pad + "    pass"]
            arms.append(Arm(self.done - arm_done, lines, start, len(out)))
        out = self._resolve_phis(blk.id, before, arms, out, pad)
        folded = self._fold_bool_phi(cond, out, pad, [then_b, else_b, follow])
        if folded is not None:
            return folded, follow
        return out, follow

    def _phis(self) -> List[str]:
        # every distinct PHI(...) in the IR, innermost (shortest) first
        found = set()
        for x in self.ins:
            for text in (x.text or "", x.cond or ""):
                for m in re.finditer(r"PHI\(", text):
                    got = call_parts(text[m.start():], "PHI")
                    if got is not None:
                        found.add("PHI(" + got[0] + ")")
        # tie-break on the text too, otherwise tmp numbering (and once in a
        # while which PHI gets resolved) depends on PYTHONHASHSEED
        return sorted(found, key=lambda p: (len(p), p))

    def _idx_at(self, addr: int) -> Optional[int]:
        i = bisect.bisect_right(self._addrs, addr) - 1
        return self.by_addr[self._addrs[i]] if i >= 0 else None

    def _block_at(self, addr: int) -> Optional[int]:
        i = self._idx_at(addr)
        return self.cfg.idx_block.get(i) if i is not None else None

    def _fold_bool_values(self) -> None:
        # `not x` / `y = a == b` compile to a branch whose arms load True and
        # False into the same reg -> PHI(True, False). rewrite to the tested
        # expr and turn the branch into a plain jmp so cfg ignores it
        leaders = {0}
        for i, x in enumerate(self.ins):
            if x.kind in ("goto", "ret", "br"):
                leaders.add(i + 1)
                if x.target in self.by_addr:
                    leaders.add(self.by_addr[x.target])
        starts = sorted(i for i in leaders if i < len(self.ins))

        def blk(i: Optional[int]) -> Optional[int]:
            return bisect.bisect_right(starts, i) - 1 if i is not None else None

        subst: Dict[str, str] = {}
        for phi, leaves in self.phi_src.items():
            if set(leaves) != {"True", "False"}:
                if not self._fold_same_def(phi, leaves, subst):
                    self._fold_shortcircuit(phi, leaves, subst)
                continue
            bt = {blk(self._idx_at(a)) for a in leaves["True"]}
            bf = {blk(self._idx_at(a)) for a in leaves["False"]}
            if len(bt) != 1 or len(bf) != 1 or bt == bf:
                continue
            for i, x in enumerate(self.ins):
                if x.kind != "br" or x.mnem not in ("je", "jne") \
                        or not re.fullmatch(r"t\d+", x.cond) or x.target not in self.by_addr:
                    continue
                taken, fall = blk(self.by_addr[x.target]), blk(i + 1)
                if {taken, fall} != bt | bf or taken == fall:
                    continue
                negated = (bt == {taken}) == (x.mnem == "je")
                subst[phi] = f"(not {x.cond})" if negated else x.cond
                x.mnem = "jmp"
                break
        if not subst:
            return

        def fix(s: str) -> str:
            for phi, rep in sorted(subst.items(), key=lambda kv: -len(kv[0])):
                s = s.replace(phi, rep)
            return s

        for x in self.ins:
            x.text, x.cond = fix(x.text or ""), fix(x.cond or "")
        self.phi_src = {fix(k): {fix(leaf): a for leaf, a in v.items()}
                        for k, v in self.phi_src.items() if k not in subst}

    def _fold_same_def(self, phi: str, leaves: Dict[str, List[int]],
                       subst: Dict[str, str]) -> bool:
        # both arms computed the same thing (global reloaded per branch etc)
        texts = set()
        for leaf in leaves:
            d = self.defs.get(leaf)
            if not re.fullmatch(r"t\d+", leaf) or d is None or not d.text:
                return False
            texts.add(d.text)
        if len(texts) != 1:
            return False
        subst[phi] = min(leaves, key=lambda leaf: self.defs[leaf].addr)
        return True

    def _fold_shortcircuit(self, phi: str, leaves: Dict[str, List[int]],
                           subst: Dict[str, str]) -> None:
        # `a and b` / `a or b` = PHI(a, b) where one edge is the short circuit
        # out of BOOL(a)
        if len(leaves) != 2:
            return
        for a, b in (tuple(leaves), tuple(reversed(list(leaves)))):
            for x in self.ins:
                if x.kind != "br" or x.mnem not in ("je", "jne") \
                        or x.addr not in leaves[a] or not self._tests(x.cond, a):
                    continue
                # je = jumped because a was false = `and`
                subst[phi] = f"({a} or {b})" if x.mnem == "jne" else f"({a} and {b})"
                return

    def _tests(self, cond: str, val: str) -> bool:
        # is cond BOOL(val)? (bare `je ; val` is a NULL check, doesn't count)
        d = self.defs.get(cond)
        return d is not None and (d.text or "") == f"BOOL({val})"

    def _leaf_sources(self, phi: str, leaf: str) -> set:
        srcs: set = set()
        for key, leaves in self.phi_src.items():
            if key in phi and leaf in leaves:
                srcs.update(self._block_at(a) for a in leaves[leaf])
        srcs.discard(None)
        return srcs

    def _leaf_arm(self, leaf: str, arms: List["Arm"], before: set,
                  phi: Optional[str] = None) -> Optional[int]:
        # which arm produces leaf: 0/1, -1 = existed before the if, None = dunno
        if leaf in self.phi_alias:
            b = self.phi_arm.get(self.phi_alias[leaf])
            for i, arm in enumerate(arms):
                if b in arm.blocks:
                    return i
            return -1 if b in before else None
        d = self.defs.get(leaf)
        if d is not None:
            for i, arm in enumerate(arms):
                if any(d in self.cfg.blocks[b].ins for b in arm.blocks):
                    return i
            if any(d in self.cfg.blocks[b].ins for b in before):
                return -1
        if phi is None:
            return None
        # literal/local, no def to place. use the edge info from the lifter
        srcs = self._leaf_sources(phi, leaf)
        if not srcs:
            return None
        for i, arm in enumerate(arms):
            if srcs <= arm.blocks:
                return i
        if srcs <= before:
            return -1
        return None

    def _edge_arms(self, phi: str, arms: List["Arm"], before: set) -> List[Optional[int]]:
        # arms feeding PHI(a, b) in lifter order: fallthrough edge first,
        # then the jump straight onto the join label. this ordering took
        # embarrassingly long to get right
        use = next((i for i, x in enumerate(self.ins)
                    if phi in (x.text or "") or phi in (x.cond or "")), None)
        if use is None:
            return [None, None]
        j = self.cfg.idx_block[use]
        seen = set()
        while j not in seen and len(self.cfg._pred(j)) == 1:
            seen.add(j)
            j = self.cfg._pred(j)[0]
        preds = self.cfg._pred(j)
        first = self.cfg.blocks[j].ins[0]
        join = max(first.labels) if first.labels else first.addr
        if len(preds) != 2:
            return [None, None]

        def key(p: int):
            last = self.cfg.blocks[p].ins[-1]
            direct = last.kind in ("goto", "br") and last.target == join
            return (direct, last.addr)

        def arm_of(p: int) -> Optional[int]:
            for i, arm in enumerate(arms):
                if p in arm.blocks:
                    return i
            return -1 if p in before else None

        return [arm_of(p) for p in sorted(preds, key=key)]

    def _resolve_phis(self, at: int, before: set, arms: List["Arm"],
                      out: List[str], pad: str) -> List[str]:
        # PHI(a, b) over the two arms of this if -> a variable each arm assigns
        for phi in self._phis():
            if phi in self.phi_alias:
                continue
            leaves = split_args(phi[4:-1])
            if len(leaves) != 2:
                continue
            owner = [self._leaf_arm(leaf, arms, before, phi) for leaf in leaves]
            if owner.count(None) == 1:
                # literal without a def -> must be the other arm
                k = owner.index(None)
                if LITERAL_RE.fullmatch(leaves[k]) and owner[1 - k] in (0, 1):
                    owner[k] = 1 - owner[1 - k]
            elif owner == [None, None] and all(LITERAL_RE.fullmatch(x) for x in leaves):
                owner = self._edge_arms(phi, arms, before)
            if None in owner or owner[0] == owner[1]:
                continue
            if any(i not in owner and arms[i].lines for i in (0, 1)):
                continue  # an arm the merge doesn't see
            if any(arms[i].ends_flow() for i in owner if i >= 0):
                continue
            name = self._phi_name(phi)
            self.phi_alias[phi] = name
            self.phi_arm[name] = at
            pre: List[str] = []
            for leaf, i in zip(leaves, owner):
                if i < 0:
                    pre += self._assign(name, self.render(leaf), pad)
                    continue
                arm = arms[i]
                new = self._assign(name, self.render(leaf), pad + "    ")
                if not new:
                    continue
                if not arm.lines and arm.end == 0:  # there was no else, add one
                    out.append(pad + "else:")
                    arm.start, arm.end = len(out), len(out)
                    out += new
                    shift = len(new)
                elif not arm.lines:  # replace the pass
                    out[arm.start:arm.start + 1] = new
                    shift = len(new) - 1
                else:
                    out[arm.end:arm.end] = new
                    shift = len(new)
                for a in arms:
                    if a.start >= arm.end:
                        a.start += shift
                        a.end += shift
                arm.end += shift
                arm.lines += new
            # all this index shifting is horrible. rewrite with a proper tree
            # some day
            for a in arms:
                a.start += len(pre)
                a.end += len(pre)
            out = pre + out
        return out

    def _phi_name(self, phi: str) -> str:
        for x in self.ins:
            m = re.fullmatch(r"STORE (L\d+) = " + re.escape(phi), x.text or "")
            if m:
                self.skip_ins.add(id(x))
                return self._fix_names(m.group(1))
        return f"tmp{len(self.phi_alias) + 1}"

    def _arm_return(self, follow: Optional[int], blocks: set, lines: List[str],
                    depth: int) -> List[str]:
        # both arms of an if fall into the same `return tN` epilogue. if tN was
        # computed in this arm the source had the return right here
        if follow is None or not blocks:
            return []
        ret, b, hops = None, follow, 0
        while b is not None and hops < 6:  # epilogue = only jumps, then ret
            fb = self.cfg.blocks[b]
            if any(x.kind not in ("br", "goto", "ret") for x in fb.ins):
                return []
            ret = next((x for x in fb.ins if x.kind == "ret"), None)
            if ret is not None:
                break
            b = fb.succs[0] if len(fb.succs) == 1 else None
            hops += 1
        if ret is None:
            return []
        if lines and lines[-1].strip().split(" ")[0] in ("return", "raise", "continue", "break"):
            return []
        cands = phi_leaves((ret.text or "").strip())
        mine = [c for c in cands if c in self.defs
                and any(self.defs[c] in self.cfg.blocks[b].ins for b in blocks)]
        if len(cands) > 1 and not mine:
            # returns something it didn't compute (literal/local), use edge info
            mine = [c for c in cands if c not in self.defs
                    and self._leaf_sources(ret.text.strip(), c)
                    and self._leaf_sources(ret.text.strip(), c) <= blocks]
        if len(mine) == 1:
            tmp = mine[0]
        else:
            # none of our temps reach the epilogue -> this arm returned a
            # literal, if the merge has exactly one
            lits = [c for c in cands if not re.fullmatch(r"t\d+", c)]
            if mine or len(lits) != 1 or len(cands) < 2 or lits[0] == "None":
                return []
            tmp = lits[0]
        ind = "    " * depth
        if lines:
            last = lines[-1]
            ind = " " * (len(last) - len(last.lstrip()))
            if last.rstrip().endswith(":"):
                ind += "    "
        self.ret_pushed.add(id(ret))
        return [ind + f"return {self.render(tmp)}"]

    def _next_cond(self, b: int) -> Optional[int]:
        # next test block reachable through blocks that emit nothing, else None
        # (a statement in between = real nested if)
        seen = set()
        while b is not None and b not in seen and b not in self.done:
            seen.add(b)
            blk = self.cfg.blocks[b]
            if blk.cond is not None:
                return b
            if any(self._emits(x) for x in blk.ins):
                return None
            b = blk.succs[0] if len(blk.succs) == 1 else None
        return None

    def _emits(self, x: Ins) -> bool:
        # would stmt() print this? must NOT call render() here, rendering
        # inlines temps and has to happen in emission order. learned the
        # hard way
        if id(x) in self.skip_ins or x.kind in ("br", "goto"):
            return False
        if x.kind == "ret":
            return True
        if x.kind == "assign":
            if self.uses.get(x.dest, 0) == 1 or x.dest in self.consumed:
                return False
            return not (self.uses.get(x.dest, 0) == 0 and x.dest in self.cond_used)
        return not (x.text or "").startswith("#")

    def _fold_short_circuit(self, cond: str, t: int, f: int) -> Tuple[str, int, int]:
        # if a and b / if a or b = two tests sharing a target
        while True:
            nb = self._next_cond(t)
            if nb is not None and self.cfg.blocks[nb].succs[1] == f and nb not in self.loop_body:
                c2 = self.render(self._def_text(self.cfg.blocks[nb].cond.cond))
                self._mark_done_path(t, nb)
                cond, t = f"{cond} and {c2}", self.cfg.blocks[nb].succs[0]
                continue
            nb = self._next_cond(f)
            if nb is not None and self.cfg.blocks[nb].succs[0] == t and nb not in self.loop_body:
                c2 = self.render(self._def_text(self.cfg.blocks[nb].cond.cond))
                self._mark_done_path(f, nb)
                cond, f = f"{cond} or {c2}", self.cfg.blocks[nb].succs[1]
                continue
            return cond, t, f

    def _mark_done_path(self, b: int, last: int):
        while True:
            self.done.add(b)
            if b == last:
                return
            b = self.cfg.blocks[b].succs[0]

    def _fold_bool_phi(self, cond: str, out: List[str], pad: str,
                       cands: List[Optional[int]]) -> Optional[List[str]]:
        # if c: x = False / else: x = True   ->   x = not c
        skeleton = {"if " + cond + ":", "else:", "pass"}
        for b in cands:
            if b is None:
                continue
            phi = self._phi_store(b)
            if phi is None:
                continue
            lhs, a, c = phi
            if {a, c} != {"True", "False"}:
                continue
            rest = [ln for ln in out
                    if ln.strip() not in skeleton and ln.strip() != f"{lhs} = not {cond}"]
            if rest:
                continue
            self.skip_ins.add(self._phi_ins)
            return [pad + f"{lhs} = not {cond}"]
        return None

    def _phi_store(self, b: int):
        for x in self.cfg.blocks[b].ins:
            if x.kind in ("br", "goto"):
                continue
            t = x.text or ""
            m = re.fullmatch(r"STORE (\S+) = PHI\((.+?), (.+?)\)", t)
            if m:
                self._phi_ins = id(x)
                return self._fix_names(m.group(1)), m.group(2), m.group(3)
            return None
        return None

    def _loop(self, h: int, stop: set, depth: int,
              lstack) -> Tuple[List[str], Optional[int]]:
        pad = "    " * depth
        body = self.loop_body[h]
        exits = [s for x in body for s in self.cfg._succ(x) if s not in body]
        exit_b = exits[0] if exits else None
        latch = None
        for x in body:
            blk = self.cfg.blocks[x]
            if blk.cond is not None and h in blk.succs and \
                    self._def_text(blk.cond.cond).startswith("NEXT("):
                latch = blk
        header = self.cfg.blocks[h]
        if latch is not None:  # bottom tested for
            head, start = self._for_head(h, latch, pad)
        elif header.cond is not None and any(s not in body for s in header.succs):
            cond = self.render(self._def_text(header.cond.cond))
            inner = [s for s in header.succs if s in body]
            exit_b = [s for s in header.succs if s not in body][0]
            if header.succs[0] not in body:
                cond = f"not ({cond})"
            self.done.add(h)
            head, start = [pad + f"while {cond}:"], (inner[0] if inner else None)
        else:
            head, start = [pad + "while True:"], h
        inner_stop = stop | ({exit_b} if exit_b is not None else set())
        self.done.discard(h)
        lines = self.region(start, inner_stop, depth + 1,
                            lstack + [(h, exit_b)], entering=True) or [pad + "    pass"]
        while lines and lines[-1].strip() == "continue":
            lines.pop()
        return head + (lines or [pad + "    pass"]), exit_b

    def _loop_after(self, b: int) -> Optional[int]:
        # b if it's a loop header, or the header behind a pre-header that
        # only parks the iterator in a local
        if b in self.loop_body:
            return b
        blk = self.cfg.blocks[b]
        if len(blk.succs) != 1 or blk.succs[0] not in self.loop_body:
            return None
        parked = []
        for x in blk.ins:
            if x.kind in ("br", "goto"):
                continue
            m = re.fullmatch(r"STORE (L\d+) = (t\d+)", x.text or "")
            if not m or not self._def_text(m.group(2)).startswith("ITER("):
                return None
            parked.append(x)
        for x in parked:
            self.skip_ins.add(id(x))
        self.done.add(b)
        return blk.succs[0]

    def _iter_source(self, it: str) -> str:
        if it in self.defs:
            seq = self.render(self.defs[it].text)
        elif it.startswith("L"):
            seq = self._fix_names(it)
            for x in self.ins:
                m = re.fullmatch(r"STORE " + it + r" = (t\d+)", x.text or "")
                if m and self._def_text(m.group(1)).startswith("ITER("):
                    seq = self.render(self.defs[m.group(1)].text)
                    self.skip_ins.add(id(x))
                    break
        else:
            return ""
        if seq.startswith("iter(") and seq.endswith(")"):
            seq = seq[5:-1]
        return seq

    def _for_head(self, h: int, latch: Block, pad: str) -> Tuple[List[str], int]:
        got = call_parts(self._def_text(latch.cond.cond), "NEXT")
        seq = self._iter_source(got[0]) if got else ""
        note = ""
        if not seq:
            seq, note = "...", "  # iterable unresolved"
        var = "_"
        for x in self._leading_ins(h):
            t = x.text or ""
            if not t.startswith("STORE ") or " = " not in t:
                continue
            lhs, rhs = t[6:].split(" = ", 1)
            d = self._def_text(rhs)
            if d.startswith("NEXT("):
                var = self._fix_names(lhs)
                self.skip_ins.add(id(x))
                break
            m = UNPACK_RE.fullmatch(d)
            if m and any(self._def_text(leaf).startswith("NEXT(")
                         for leaf in phi_leaves(m.group(1))):
                targets = self._unpack_targets(m.group(1), int(m.group(2)))
                if targets is not None:
                    var = ", ".join(targets)
                break
        self.done.add(h)
        return [pad + f"for {var} in {seq}:{note}"], h

    def _leading_ins(self, b: int, limit: int = 8) -> List[Ins]:
        # straight line insns from b, stepping over the error checks
        out: List[Ins] = []
        seen = set()
        while b is not None and b not in seen and len(seen) < limit:
            seen.add(b)
            blk = self.cfg.blocks[b]
            out += blk.ins
            if blk.cond is not None and self.kind_of(blk.cond) != "":
                break
            nxt = [s for s in blk.succs if s in self.cfg.reachable]
            if blk.cond is not None:
                nxt = [s for s in nxt if not self._epilogue_only(s)]
            b = nxt[0] if len(nxt) == 1 else None
        return out

    def _unpack_targets(self, src: str, n: int) -> Optional[List[str]]:
        # locals the n parts of UNPACK(src) go into, or None if any part
        # doesn't have exactly one store
        by_part: Dict[int, Ins] = {}
        for x in self.ins:
            m = re.fullmatch(r"STORE (L\d+) = (t\d+)", x.text or "")
            if not m:
                continue
            d = UNPACK_RE.fullmatch(self._def_text(m.group(2)))
            if d and d.group(1) == src and int(d.group(2)) == n:
                if int(d.group(3)) in by_part:
                    return None
                by_part[int(d.group(3))] = x
        if len(by_part) != n:
            return None
        for x in by_part.values():
            self.skip_ins.add(id(x))
            self.consumed.add(x.text.split(" = ")[1])
        return [self._fix_names(by_part[i].text[6:].split(" = ")[0]) for i in range(n)]

    def stmt(self, x: Ins, pad: str) -> List[str]:
        if id(x) in self.skip_ins:
            return []
        if x.kind == "ret":
            if id(x) in self.ret_pushed:
                return [pad + "return"]  # value already returned inside its arm
            v = self.render(x.text)
            if v in ("0", "None", ""):
                return [pad + "return"]
            return [pad + f"return {v}"]
        if x.kind in ("br", "goto"):
            return []
        if x.kind == "assign":
            uses = self.uses.get(x.dest, 0)
            if uses == 1 or x.dest in self.consumed:
                return []  # inlined at the use
            if call_parts(x.text, "IMPORT") is not None:
                line = self._import(x)
                self.modules[x.dest] = line
                return [pad + line]
            if uses == 0 and (x.text.startswith(STMT_OPS)
                              or call_parts(x.text, "PyCell_Set") is not None):
                # C status code nobody reads -> it's a statement
                return self.stmt(Ins(x.addr, "stmt", x.text), pad)
            if x.text.startswith(("EXC_FETCH(", "EXC_RESTORE(")):
                # try/except we failed to structure
                return [pad + "# exception state saved/restored here"]
            text = self.render(x.text)
            m = INPLACE_RE.fullmatch(text)
            if m:
                # x += 1 returns x, later uses read x
                self.inlined[x.dest] = m.group(1)
                return [pad + f"{m.group(1)} {m.group(2)}= {m.group(3)}"]
            if uses == 0:
                if x.dest in self.cond_used or text.isidentifier():
                    return []  # branch renders it
                return [pad + text]  # expression statement
            return [pad + f"{x.dest} = {text}"]
        t = x.text
        for head, fmt in (("PyList_Append", "{0}.append({1})"),
                          ("PySet_Add", "{0}.add({1})"),
                          ("PyObject_DelItem", "del {0}[{1}]"),
                          ("PyCell_Set", "{0} = {1}")):
            got = call_parts(t, head)
            if got is not None:
                a = [self.render(v) for v in split_args(got[0])]
                while len(a) < 2:
                    a.append("?")
                return [pad + fmt.format(*a[:2])]
        if t.startswith("STORE "):
            lhs, _, rhs = t[6:].partition(" = ")
            m = UNPACK_RE.fullmatch(self._def_text(rhs.strip()))
            if m:
                targets = self._unpack_targets(m.group(1), int(m.group(2)))
                if targets is not None:
                    return [pad + f"{', '.join(targets)} = {self.render(m.group(1))}"]
            m = re.fullmatch(r"PHI\((.+?), (.+?)\)", rhs.strip())
            if m:
                # couldn't attribute the guarding test, say so instead of
                # making one up
                return [pad + f"# {self._fix_names(lhs)} = {m.group(1)} or "
                              f"{m.group(2)} (merged, condition unresolved)"]
            rhs_r = self.render(rhs)
            bound = self._import_binding(rhs.strip(), rhs_r)
            ml = LOCAL_RE.fullmatch(lhs.strip())
            if bound and ml and int(ml.group(1)) >= (self.stub.argcount if self.stub else 0):
                self.alias[int(ml.group(1))] = bound  # `import x` binds local x
                return []
            return self._assign(self._fix_names(lhs), rhs_r.strip(), pad)
        if t.startswith("SETITEM "):
            return [pad + self.render(t[8:])]
        if t.startswith("SETATTR "):
            return [pad + self.render(t[8:])]
        if t.startswith("STORE_GLOBAL "):
            lhs, _, rhs = t[13:].partition(" = ")
            return [pad + f"{self._global(lhs)} = {self.render(rhs)}"]
        if t.startswith("DELETE_GLOBAL("):
            return [pad + f"del {self._global(t[14:-1])}"]
        if t.startswith("RAISE "):
            return [pad + "raise " + self.render(t[6:])]
        if t.startswith("RERAISE("):
            return [pad + "raise"]
        if t.startswith("#"):
            return []
        return [pad + f"# {self.render(t)}"]

    def _assign(self, lhs: str, rhs: str, pad: str) -> List[str]:
        m = INPLACE_RE.fullmatch(rhs)
        if m:
            if not assignable(m.group(1)):
                # PHI(..) += 1 is not a thing, keep it as a binary op
                return [pad + f"{lhs} = ({m.group(1)} {m.group(2)} {m.group(3)})"]
            aug = pad + f"{m.group(1)} {m.group(2)}= {m.group(3)}"
            if m.group(1) == lhs:
                return [aug]
            return [aug, pad + f"{lhs} = {m.group(1)}"]
        if rhs == lhs:
            return []
        return [pad + f"{lhs} = {rhs}"]

    def _import(self, x: Ins) -> str:
        got = call_parts(x.text, "IMPORT")
        a = split_args(got[0])
        mod = a[0].strip("'\"")
        fromlist = a[1].split("=", 1)[1] if "=" in a[1] else "None"
        names = self.render(fromlist)
        if names in ("None", "0"):
            self.imported[x.dest] = {mod.split(".")[0]}
            return f"import {mod}"
        names = names.strip("()").rstrip(",").replace("'", "")
        self.imported[x.dest] = {n.strip() for n in names.split(",")}
        return f"from {mod} import {names}"

    def _import_binding(self, rhs: str, rendered: str) -> Optional[str]:
        # name a STORE of an import result binds: `m` for import m, `a` for
        # from m import a
        if rhs in self.imported and rendered.startswith("import "):
            return next(iter(self.imported[rhs]))
        d = self.defs.get(rhs)
        m = re.fullmatch(r"(t\d+)\.'(\w+)'", d.text if d else rhs)
        if m and m.group(2) in self.imported.get(m.group(1), ()):
            return m.group(2)
        return None


def decompile_module(elf_path: str, das_path: Optional[str],
                     only: Optional[str] = None) -> Tuple[str, int, int]:
    elf = BccElf(open(elf_path, "rb").read())
    stubs = load_stubs(elf, das_path)
    lines = [f"# reconstructed from {os.path.basename(elf_path)} by oneshot.bcc",
             "# native BCC functions lifted back to Python; locals are unnamed (v1, v2, ...)",
             ""]
    ok = tot = 0
    for f, stub in zip(elf.functions, stubs):
        name = stub.name if stub and f.nested else stub.qualname if stub else f.name
        if only and only not in name:
            continue
        tot += 1
        lifted = Lifter(elf, stub, abbreviate=False).lift(f)
        records = bcc_ir.parse(lifted)
        try:
            body = Decompiler(records, stub, name.replace(".", "_"),
                              bcc_ir.phi_sources(lifted)).run()
        except Exception as e:
            # import traceback; traceback.print_exc()
            body = [f"def {name.replace('.', '_')}(*a, **kw):",
                    f"    raise NotImplementedError({str(e)!r})"]
        body = prune_empty_arms(close_tries([fix_aug(ln) for ln in body]))
        src = "\n".join(body)
        if _syntax_ok(src):
            ok += 1
        else:
            src = "\n".join("# " + ln for ln in body)
            src = f"# NOTE: emitted source below did not parse, kept as comment\n{src}"
        where = f", nested in {f.parent}" if f.nested else ""
        lines += [f"# --- {f.name} @ {f.start:#x} ({f.size} bytes{where})", src, "", ""]
    return "\n".join(lines), ok, tot


IF_RE = re.compile(r"(\s*)if (.+):$")
CMP_FLIP = {ast.Eq: "!=", ast.NotEq: "==", ast.In: "not in", ast.NotIn: "in",
            ast.Is: "is not", ast.IsNot: "is"}


def negate(cond: str) -> str:
    try:
        node = ast.parse(cond, mode="eval").body
    except SyntaxError:
        return f"not ({cond})"
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return ast.unparse(node.operand)
    if isinstance(node, ast.Compare) and len(node.ops) == 1 \
            and type(node.ops[0]) in CMP_FLIP:
        flipped = CMP_FLIP[type(node.ops[0])]
        return f"({ast.unparse(node.left)} {flipped} {ast.unparse(node.comparators[0])})"
    return f"not {cond}" if isinstance(node, (ast.Name, ast.Attribute,
                                              ast.Subscript, ast.Call)) \
        else f"not ({cond})"


def _arm(lines: List[str], head: int) -> int:
    # index just past the suite opened at lines[head]
    ind = len(lines[head]) - len(lines[head].lstrip())
    i = head + 1
    while i < len(lines) and (not lines[i].strip()
                              or len(lines[i]) - len(lines[i].lstrip()) > ind):
        i += 1
    return i


def prune_empty_arms(lines: List[str]) -> List[str]:
    # if c: pass / else: X  ->  if not c: X
    # if c: X / else: pass  ->  if c: X
    # if c: pass (no else)  ->  nothing, the test was the compiler's
    # text based, on the emitted lines. yes. it works though
    out = list(lines)
    changed = True
    while changed:
        changed = False
        for i, ln in enumerate(out):
            m = IF_RE.fullmatch(ln)
            if not m:
                continue
            pad, cond = m.group(1), m.group(2)
            end = _arm(out, i)
            empty = [x for x in out[i + 1:end] if x.strip()] == [pad + "    pass"]
            has_else = end < len(out) and out[end] == pad + "else:"
            if empty and has_else:
                out[i:end + 1] = [pad + f"if {negate(cond)}:"]
            elif has_else and [x for x in out[end + 1:_arm(out, end)] if x.strip()] \
                    == [pad + "    pass"]:
                del out[end:_arm(out, end)]
            elif empty and not has_else and "(" not in cond \
                    and not out[i - 1].rstrip().endswith(":"):
                del out[i:end]
            else:
                continue
            changed = True
            break
    return out if _syntax_ok("\n".join(out)) else lines


def close_tries(lines: List[str]) -> List[str]:
    # `try:` with no except/finally attached -> `if True:` + note. inventing
    # an except clause would be guessing
    out = list(lines)
    for i, ln in enumerate(out):
        body = ln.lstrip()
        if body != "try:":
            continue
        ind = len(ln) - len(body)
        for nxt in out[i + 1:]:
            if not nxt.strip():
                continue
            k = len(nxt) - len(nxt.lstrip())
            if k > ind:
                continue
            if k == ind and nxt.lstrip().startswith(("except", "finally")):
                break
            out[i] = " " * ind + "if True:  # try, handler not recovered"
            break
        else:
            out[i] = " " * ind + "if True:  # try, handler not recovered"
    return out


def collapse_phi(text: str) -> str:
    # PHI(x, x) -> x
    while True:
        m = re.search(r"PHI\(", text)
        if m is None:
            return text
        got = call_parts(text[m.start():], "PHI")
        if got is None:
            return text
        inner = collapse_phi(got[0])
        leaves = split_args(inner)
        if len(set(leaves)) != 1:
            return text[:m.start()] + f"PHI({inner})" \
                + collapse_phi(text[m.start() + len(got[0]) + 5:])
        text = text[:m.start()] + leaves[0] + text[m.start() + len(got[0]) + 5:]


def phi_leaves(text: str) -> List[str]:
    # PHI(a, PHI(b, c)) -> [a, b, c]
    if not text.startswith("PHI(") or not text.endswith(")"):
        return [text]
    out: List[str] = []
    for part in split_args(text[4:-1]):
        out += phi_leaves(part.strip())
    return out


def _syntax_ok(src: str) -> bool:
    try:
        compile(src, "<bcc>", "exec")
        return True
    except SyntaxError:
        return False


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("elf")
    ap.add_argument("-d", "--das")
    ap.add_argument("-o", "--out")
    ap.add_argument("-f", "--function")
    a = ap.parse_args()
    das = a.das
    if das is None:
        guess = a.elf.split(".1shot.bcc.")[0] + ".1shot.das"
        if os.path.exists(guess):
            das = guess
    src, ok, tot = decompile_module(a.elf, das, a.function)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(src)
        print(f"wrote {a.out}: {ok}/{tot} functions parse as Python")
    else:
        print(src)
        print(f"# {ok}/{tot} functions parse as Python", file=sys.stderr)


if __name__ == "__main__":
    main()
