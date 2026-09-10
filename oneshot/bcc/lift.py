"""lift BCC native code back to a pseudo-bytecode listing.

the good news about BCC: the generated x86 never touches CPython directly,
every single op is a `call [api+off]` and every name/const is loaded from the
pool tuple that's still in the stub .pyc. so the machine code is basically the
bytecode interpreter unrolled, and a symbolic register/stack sweep gets the
op sequence back. the bad news is everything else in this file.

    python3 -m oneshot.bcc.lift <module>.1shot.bcc.win-x64.elf [-d <module>.1shot.das] [-o out.txt]
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Callable, Dict, List, Optional, Tuple

import capstone
from capstone.x86 import (X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP,
                          X86_REG_RSP)

from . import api
from .elf import BccElf, BccFunc
from .das import Stub, parse_das, parse_nested, with_pool

ARG_REGS = ["rcx", "rdx", "r8", "r9"]

_GPR = ["ax", "bx", "cx", "dx", "si", "di", "bp", "sp"]
REG64: Dict[int, int] = {}
for _n in _GPR:
    _full = getattr(capstone.x86, f"X86_REG_R{_n.upper()}")
    for _sub in (f"E{_n.upper()}", _n.upper(), _n[0].upper() + "L" if _n[1] == "x" else _n.upper() + "L",
                 _n[0].upper() + "H" if _n[1] == "x" else None):
        if _sub and hasattr(capstone.x86, f"X86_REG_{_sub}"):
            REG64[getattr(capstone.x86, f"X86_REG_{_sub}")] = _full
    REG64[_full] = _full
for _i in range(8, 16):
    _full = getattr(capstone.x86, f"X86_REG_R{_i}")
    for _suf in ("", "D", "W", "B"):
        REG64[getattr(capstone.x86, f"X86_REG_R{_i}{_suf}")] = _full


def r64(reg: int) -> int:
    return REG64.get(reg, reg)


class Val:
    __slots__ = ("kind", "a", "b")

    def __init__(self, kind, a=None, b=None):
        self.kind, self.a, self.b = kind, a, b

    def __repr__(self):
        k = self.kind
        if k == "imm":
            return str(self.a) if -256 < self.a < 256 else hex(self.a)
        if k == "pool":
            return self.b if self.b is not None else f"pool[{self.a}]"
        if k == "local":
            return self.b if self.b is not None else f"L{self.a}"
        if k == "tmp":
            return f"t{self.a}"
        if k == "const":
            return str(self.a)
        if k == "stackptr":
            return f"&s{self.a:x}"
        if k == "stack":
            return f"s{self.a:x}"
        if k == "api":
            return "API"
        if k == "apislot":
            return f"API.{self.a}"
        if k == "poolbase":
            return "POOL"
        if k == "cstr":
            return repr(self.a)
        if k == "arg":
            return self.a
        if k == "phi":
            return f"PHI({self.a}, {self.b})"
        if k == "isnull":
            return self.a
        if k == "exc":
            return f"exc_{self.a}"
        if k == "func":
            return f"&{self.a}"
        return f"<{k}>"


IMM0 = Val("imm", 0)


def _snap_key(snaps) -> str:
    return repr(sorted((k, sorted((r, str(v)) for r, v in regs.items()),
                        sorted((s, str(v)) for s, v in stack.items()), sp)
                       for k, (regs, stack, sp) in snaps.items()))


_PHI_KINDS = ("tmp", "pool", "const", "phi", "local")
_ADDR_KINDS = ("poolbase", "api", "apislot")


def _leaves(v: Val) -> set:
    if v.kind != "phi":
        return {repr(v)}
    return _leaves(v.a) | _leaves(v.b)


def _same(cur: Val, v: Val, sa: Dict[int, Val], sb: Dict[int, Val],
          slot_of: Callable[[int], int], stores: Dict[int, set]) -> Optional[Val]:
    # tN and the local it was stored into are the same value, one path just
    # kept the register and the other reloaded the slot. prefer the local name
    # unless only the reloading path has it there
    for t, loc, held in ((cur, v, sb), (v, cur, sa)):
        if t.kind != "tmp" or loc.kind != "local":
            continue
        slot = slot_of(loc.a)
        if repr(held.get(slot)) == repr(t):
            other = sa if held is sb else sb
            return loc if repr(other.get(slot)) == repr(t) else t
        if repr(t) in stores.get(loc.a, ()):
            return loc
    return None


def _merge(a: Dict[int, Val], b: Dict[int, Val],
           tmpdef: Optional[Dict[int, str]] = None,
           stacks: Optional[Tuple[Dict[int, Val], Dict[int, Val], Callable[[int], int], Dict[int, set]]] = None
           ) -> Dict[int, Val]:
    # join of two states. the compiler puts NULL in the reg on the error edge
    # and the real thing on the ok edge, so on disagreement take the non-null
    out = dict(a)
    for k, v in b.items():
        if k not in out:
            out[k] = v
            continue
        cur = out[k]
        if repr(cur) == repr(v):
            continue
        one = _same(cur, v, *stacks) if stacks else None
        if one is not None:
            out[k] = one
        elif (cur.kind in _ADDR_KINDS) != (v.kind in _ADDR_KINDS):
            # pool/api base regs never really change, if one side says
            # otherwise it's us being imprecise
            out[k] = cur if cur.kind in _ADDR_KINDS else v
        elif cur.kind == "imm" and cur.a == 0:
            out[k] = v
        elif v.kind == "imm" and v.a == 0:
            pass
        elif cur.kind == "const" and cur.a == "None" and v.kind in ("local", "pool", "tmp", "phi"):
            out[k] = v  # error edge parks None here
        elif v.kind == "const" and v.a == "None" and cur.kind in ("local", "pool", "tmp", "phi"):
            pass
        elif cur.kind == "tmp" and v.kind == "tmp" and tmpdef is not None \
                and tmpdef.get(cur.a) is not None and tmpdef.get(cur.a) == tmpdef.get(v.a):
            pass  # same op re-emitted on the loop latch
        elif cur.kind in _PHI_KINDS and v.kind in _PHI_KINDS:
            # `return a` vs `return b` meeting in the epilogue. keep both,
            # emit.py sorts out which arm gets which
            lc, lv = _leaves(cur), _leaves(v)
            if lc < lv:
                out[k] = v
            elif not lv <= lc:
                out[k] = Val("phi", cur, v)
        elif cur.kind != "tmp" and v.kind == "tmp":
            out[k] = v
        # else: keep cur. yes this loses info, see _PHI_KINDS above
    return out


class Lifter:
    def __init__(self, elf: BccElf, stub: Optional[Stub] = None, abbreviate: bool = True):
        self.elf = elf
        self.stub = stub
        self.abbreviate = abbreviate       # shorten long pool strings in listings
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.md.detail = True

    def _pool(self, idx: int) -> Val:
        label = None
        if self.stub and 0 <= idx < len(self.stub.pool):
            label = repr(self.stub.pool[idx])
            if self.abbreviate and len(label) > 60:
                label = label[:57] + "...'"
        return Val("pool", idx, label)

    def _cstr_at(self, off: int) -> Optional[Val]:
        # rip-relative lea into the string blob (module names for import etc)
        s = self.elf.strings
        if s is None or not (s.offset <= off < s.offset + s.size):
            return None
        try:
            return Val("cstr", self.elf._cstr(off))
        except ValueError:
            return None

    def _local(self, idx: int) -> Val:
        name = None
        if self.stub and 0 <= idx < len(self.stub.args):
            name = self.stub.args[idx]
        return Val("local", idx, name)

    def lift(self, f: BccFunc) -> List[str]:
        # one forward sweep doesn't see what comes in over back edges (loops,
        # with/try exits jumping back into the shared epilogue). so sweep again
        # seeded with last pass' join states until nothing moves. 6 was enough
        # for everything I threw at it
        snaps: Dict[int, Tuple[Dict[int, Val], Dict[int, Val], int]] = {}
        self._edges: Dict[int, Dict[int, Tuple[Dict[int, Val], Dict[int, Val]]]] = {}
        self._locals_hint = None
        self._locals_end: Optional[int] = None
        self._decref_slots: set = set()
        self._tmpdef: Dict[int, str] = {}
        self._stores: Dict[int, set] = {}      # local index -> temporaries stored into it
        self._nested = f.nested
        self._scratch: set = set()
        for _ in range(6):
            out, nxt = self._sweep(f, snaps)
            if self._locals_hint is None and self._decref_slots:
                # no BIND_ARGS/UNPACK to tell us where the locals array is,
                # but the epilogue DECREFs every local from its slot, so the
                # lowest decref'd slot is the base. hacky but works
                self._locals_hint = min(self._decref_slots)
                snaps = {}
                continue
            if _snap_key(nxt) == _snap_key(snaps):
                break
            snaps = nxt
        return out

    def _sweep(self, f: BccFunc, seed: Dict[int, Tuple[Dict[int, Val], Dict[int, Val], int]]):
        code = self.elf.code(f)
        insns = list(self.md.disasm(code, f.start))
        targets = set()
        for ins in insns:
            if ins.group(capstone.CS_GRP_JUMP) and ins.operands and ins.operands[0].type == X86_OP_IMM:
                targets.add(ins.operands[0].imm)

        regs: Dict[int, Val] = {
            capstone.x86.X86_REG_RCX: Val("arg", "ctx"),
            capstone.x86.X86_REG_RDX: Val("arg", "args"),
        }
        stack: Dict[int, Val] = {}
        rsp = 0                      # offset relative to function entry
        locals_base: Optional[int] = self._locals_hint
        locals_end: Optional[int] = self._locals_end
        frame_seen = bound_seen = False
        tmpno = 0
        tmpdef = self._tmpdef        # numbering is stable across sweeps
        out: List[str] = []
        snapshots: Dict[int, Tuple[Dict[int, Val], Dict[int, Val], int]] = \
            {k: (dict(r), dict(s), sp) for k, (r, s, sp) in seed.items()}
        prev_flow_breaks = False
        phi_seen: set = set()
        edges = self._edges           # target -> {jump address: state on that edge}

        def slot_of(idx: int) -> int:
            return (locals_base or 0) + 8 * idx

        same = (slot_of, self._stores)

        def snap(target: int, regs: Dict[int, Val], stack: Dict[int, Val], src: int):
            old = snapshots.get(target)
            snapshots[target] = (dict(regs), dict(stack), rsp) if old is None else \
                (_merge(old[0], regs, tmpdef, (old[1], stack) + same),
                 _merge(old[1], stack, tmpdef), old[2])
            edges.setdefault(target, {})[src] = (dict(regs), dict(stack))

        def report_phis(addr: int, merged: Dict[int, Val], incoming) -> None:
            # "# phi PHI(a,b) :: a <- 0x.. || b <- 0x.." so emit knows which
            # edge brought what
            for key, v in merged.items():
                if v.kind != "phi" or repr(v) in phi_seen:
                    continue
                leaves = _leaves(v)
                srcs: Dict[str, List[int]] = {}
                for src, state in incoming:
                    ev = state.get(key)
                    if ev is not None and ev.kind != "phi" and repr(ev) in leaves:
                        srcs.setdefault(repr(ev), []).append(src)
                if srcs:
                    phi_seen.add(repr(v))
                    desc = " || ".join(f"{leaf} <- {','.join(f'{s:#x}' for s in sorted(set(ss)))}"
                                       for leaf, ss in srcs.items())
                    emit(addr, f"# phi {v} :: {desc}")

        def rname(r):
            return self.md.reg_name(r)

        def get(r) -> Val:
            r = r64(r)
            return regs.get(r, Val("arg", rname(r)))

        def is_local(off: int) -> bool:
            return locals_base is not None and off >= locals_base \
                and (locals_end is None or off < locals_end) \
                and (off - locals_base) % 8 == 0 and off not in self._scratch

        def frame_off(mem) -> Optional[int]:
            # [rsp+x] or [rbp+x] where the prologue did lea rbp,[rsp+y]
            if mem.index != 0:
                return None
            if mem.base == X86_REG_RSP:
                return rsp + mem.disp
            base = regs.get(r64(mem.base)) if mem.base else None
            if base is not None and base.kind == "stackptr":
                return base.a + mem.disp
            return None

        def mem_val(op) -> Optional[Val]:
            m = op.mem
            if m.base == X86_REG_RIP:
                return None
            off = frame_off(m)
            if off is not None:
                if is_local(off):
                    return self._local((off - locals_base) // 8)
                return stack.get(off, Val("stack", off))
            base = regs.get(r64(m.base))
            if base is None:
                return None
            if base.kind == "poolbase" and m.index == 0 and m.disp >= 0x18:
                return self._pool((m.disp - 0x18) // 8)
            if self._nested and base.kind == "arg" and base.a == "ctx" and m.index == 0:
                # nested bodies get the parent's pool through ctx directly,
                # entries start right after the header (0x18). took me a
                # while to notice these don't go through [ctx+rax*8+0x10]
                if m.disp == 0x18:
                    return Val("poolbase")
                if m.disp > 0x18:
                    return self._pool((m.disp - 0x18) // 8)
            if base.kind == "api":
                disp = m.disp
                if m.index != 0:
                    idx = regs.get(r64(m.index))
                    if idx is None or idx.kind != "imm":
                        return None
                    disp += idx.a * max(m.scale, 1)
                slot = api.API.get(disp)
                if slot and disp in api.DATA_SLOTS:
                    return Val("const", api.DATA_SLOTS[disp])
                if slot:
                    return Val("apislot", slot[0])
            return None

        def args_of(n: int) -> List[Val]:
            vals = []
            for i in range(n):
                if i < 4:
                    vals.append(get(getattr(capstone.x86, "X86_REG_" + ARG_REGS[i].upper())))
                else:
                    vals.append(stack.get(rsp + 0x20 + (i - 4) * 8, Val("stack", rsp + 0x20 + (i - 4) * 8)))
            return vals

        def emit(addr, text):
            out.append(f"  {addr:#08x}  {text}")

        # flags state for the next jcc
        last_cmp: List[Optional[str]] = [None]
        last_test: List[Optional[str]] = [None]     # `test x, x`: the value NULL-checked
        flags_inverted = [False]                    # ZF set means "all non-NULL"

        prev_addr = f.start
        for ins in insns:
            if ins.address in targets:
                out.append(f" L{ins.address:#08x}:")
                if ins.address in snapshots:
                    sregs, sstack, srsp = snapshots[ins.address]
                    incoming = list(edges.get(ins.address, {}).items())
                    if prev_flow_breaks:
                        regs, stack, rsp = dict(sregs), dict(sstack), srsp
                    else:
                        incoming.append((prev_addr, (dict(regs), dict(stack))))
                        regs = _merge(regs, sregs, tmpdef, (stack, sstack) + same)
                        stack = _merge(stack, sstack, tmpdef)
                    report_phis(ins.address, regs, [(s, st[0]) for s, st in incoming])
                    report_phis(ins.address, stack, [(s, st[1]) for s, st in incoming])
            prev_flow_breaks = False
            prev_addr = ins.address
            m = ins.mnemonic
            ops = ins.operands

            if m == "push":
                rsp -= 8
                continue
            if m == "pop":
                rsp += 8
                continue
            if m in ("sub", "add") and ops and ops[0].type == X86_OP_REG and ops[0].reg == X86_REG_RSP \
                    and ops[1].type == X86_OP_IMM:
                rsp += -ops[1].imm if m == "sub" else ops[1].imm
                continue

            if m in ("call", "jmp") and ops:
                op = ops[0]
                callee = None
                if op.type == X86_OP_MEM and op.mem.base != X86_REG_RIP:
                    base = regs.get(r64(op.mem.base))
                    if base is not None and base.kind == "api":
                        disp = op.mem.disp
                        if op.mem.index != 0:
                            idx = regs.get(r64(op.mem.index))
                            if idx is not None and idx.kind == "imm":
                                disp += idx.a * max(op.mem.scale, 1)
                        slot = api.API.get(disp)
                        callee = slot[0] if slot else f"API+{disp:#x}"
                    elif frame_off(op.mem) is not None:
                        v = stack.get(frame_off(op.mem))
                        if v is not None and v.kind == "apislot":
                            callee = v.a
                elif op.type == X86_OP_REG:
                    v = regs.get(r64(op.reg))
                    if v is not None and v.kind == "apislot":
                        callee = v.a
                if callee is None:
                    if m == "call":
                        emit(ins.address, f"call {ins.op_str}")
                        regs.pop(capstone.x86.X86_REG_RAX, None)
                    else:
                        if op.type == X86_OP_IMM:
                            emit(ins.address, f"goto L{op.imm:#08x}")
                            snap(op.imm, regs, stack, ins.address)
                        else:
                            emit(ins.address, f"goto {ins.op_str}")
                        prev_flow_breaks = True
                    continue

                text, nres = self._format_call(callee, args_of, stack, rsp)
                if callee == "Py_DecRef" and locals_base is None:
                    a0 = args_of(1)[0]
                    if a0.kind == "stack":
                        self._decref_slots.add(a0.a)
                if callee == "memset" and not frame_seen:
                    # prologue memsets the frame: 4 bookkeeping qwords then
                    # the fast locals. above that = spills, not variables
                    frame_seen = True
                    a = args_of(3)
                    if a[0].kind == "stackptr" and a[2].kind == "imm" and a[2].a >= 0x28 \
                            and locals_base is None:
                        locals_base = self._locals_hint = a[0].a + 0x20
                        locals_end = self._locals_end = a[0].a + a[2].a
                if callee in ("BIND_ARGS", "UNPACK") and not bound_seen:
                    # first unpack is the parameters -> that's where locals
                    # live. later UNPACKs are `for k, v in ...` into scratch
                    src, p = args_of(4)[1], args_of(4)[3]
                    if p.kind == "stackptr" and (src.kind == "arg" and src.a == "args" or locals_base is None):
                        bound_seen = True
                        if p.a != locals_base:
                            locals_base = self._locals_hint = p.a
                            locals_end = self._locals_end = None
                if callee == "UNPACK" and locals_base is not None:
                    src, n, dst = args_of(4)[1:]
                    if dst.kind == "stackptr" and dst.a != locals_base \
                            and n.kind == "imm" and 0 < n.a <= 16:
                        for i in range(n.a):
                            tmpno += 1
                            part = Val("tmp", tmpno)
                            tmpdef[tmpno] = f"UNPACK({src}, n={n.a})[{i}]"
                            stack[dst.a + 8 * i] = part
                            self._scratch.add(dst.a + 8 * i)
                            emit(ins.address, f"{part} = {tmpdef[tmpno]}")
                        regs.pop(capstone.x86.X86_REG_RAX, None)
                        for r in (capstone.x86.X86_REG_RCX, capstone.x86.X86_REG_RDX,
                                  capstone.x86.X86_REG_R8, capstone.x86.X86_REG_R9,
                                  capstone.x86.X86_REG_R10, capstone.x86.X86_REG_R11):
                            regs.pop(r, None)
                        continue
                if nres:
                    tmpno += 1
                    res = Val("tmp", tmpno)
                    regs[capstone.x86.X86_REG_RAX] = res
                    tmpdef[tmpno] = text
                    emit(ins.address, f"{res} = {text}")
                else:
                    regs.pop(capstone.x86.X86_REG_RAX, None)
                    emit(ins.address, text)
                # volatile regs are gone after a call
                for r in (capstone.x86.X86_REG_RCX, capstone.x86.X86_REG_RDX,
                          capstone.x86.X86_REG_R8, capstone.x86.X86_REG_R9,
                          capstone.x86.X86_REG_R10, capstone.x86.X86_REG_R11):
                    regs.pop(r, None)
                if m == "jmp":
                    emit(ins.address, "return (tail call)")
                    prev_flow_breaks = True
                continue

            if m == "ret":
                emit(ins.address, f"return {get(capstone.x86.X86_REG_RAX)}")
                prev_flow_breaks = True
                continue

            if m in ("mov", "movsxd", "movzx", "lea"):
                dst, src = ops[0], ops[1]
                v = None
                if src.type == X86_OP_IMM:
                    v = Val("imm", src.imm)
                elif src.type == X86_OP_REG:
                    v = get(src.reg)
                elif src.type == X86_OP_MEM:
                    if m == "lea":
                        if src.mem.base != X86_REG_RIP and frame_off(src.mem) is not None:
                            v = Val("stackptr", frame_off(src.mem))
                        elif src.mem.base == X86_REG_RIP:
                            tgt = ins.address + ins.size + src.mem.disp
                            v = self._cstr_at(tgt)
                            if v is None and self.elf.slots and \
                                    self.elf.slots.offset <= tgt < self.elf.slots.offset + self.elf.slots.size:
                                nested = self.elf.slot_func.get((tgt - self.elf.slots.offset) // 8)
                                if nested:
                                    v = Val("func", nested)
                    else:
                        if src.mem.base == X86_REG_RIP:
                            tgt = ins.address + ins.size + src.mem.disp
                            if self.elf.slots and tgt == self.elf.slots.offset:
                                v = Val("api")
                        elif src.mem.index != 0 and src.mem.disp == 0x10:
                            # mov rX,[ctx+rax*8+0x10] = pool base
                            # FIXME assumes base is ctx, never checked
                            v = Val("poolbase")
                        else:
                            v = mem_val(src)
                if dst.type == X86_OP_REG:
                    if v is None:
                        regs.pop(r64(dst.reg), None)
                    else:
                        regs[r64(dst.reg)] = v
                elif dst.type == X86_OP_MEM and frame_off(dst.mem) is not None:
                    off = frame_off(dst.mem)
                    if v is None:
                        stack.pop(off, None)
                    else:
                        stack[off] = v
                    if is_local(off) and v is not None \
                            and v.kind in ("tmp", "pool", "const", "phi", "exc"):
                        idx = (off - locals_base) // 8
                        if v.kind == "tmp":
                            self._stores.setdefault(idx, set()).add(repr(v))
                        emit(ins.address, f"STORE {self._local(idx)} = {v}")
                continue

            if m == "xor" and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG \
                    and ops[0].reg == ops[1].reg:
                regs[r64(ops[0].reg)] = IMM0
                continue

            if m in ("test", "cmp"):
                a = get(ops[0].reg) if ops[0].type == X86_OP_REG else None
                b = (get(ops[1].reg) if ops[1].type == X86_OP_REG else
                     Val("imm", ops[1].imm) if ops[1].type == X86_OP_IMM else None)
                if a is not None and b is not None:
                    same_reg = m == "test" and repr(a) == repr(b)
                    last_cmp[0] = f"{a}" if same_reg else f"{a} {m} {b}"
                    last_test[0] = last_cmp[0] if same_reg else None
                else:
                    last_cmp[0] = last_test[0] = None
                flags_inverted[0] = a is not None and a.kind == "isnull" and same_reg and not a.b
                continue

            if m in ("sete", "setne") and ops[0].type == X86_OP_REG:
                # NULL test materialised as a byte, gets or-ed with another below
                if last_test[0]:
                    regs[r64(ops[0].reg)] = Val("isnull", last_test[0], m == "setne")
                else:
                    regs.pop(r64(ops[0].reg), None)
                continue

            if m == "or" and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG:
                a, b = regs.get(r64(ops[0].reg)), regs.get(r64(ops[1].reg))
                if a is not None and b is not None and a.kind == b.kind == "isnull" and not a.b and not b.b:
                    # x==NULL || y==NULL, result is 0 iff both set
                    v = Val("isnull", f"{a.a} || {b.a}", False)
                    regs[r64(ops[0].reg)] = v
                    last_cmp[0] = last_test[0] = v.a
                    flags_inverted[0] = True
                else:
                    regs.pop(r64(ops[0].reg), None)
                    last_cmp[0] = last_test[0] = None
                    flags_inverted[0] = False
                continue

            if m in ("je", "jne", "js", "jns", "jle", "jg", "ja", "jae", "jb", "jbe", "jl", "jge"):
                cond = f" ; {last_cmp[0]}" if last_cmp[0] else ""
                if flags_inverted[0] and m in ("je", "jne"):
                    m = "jne" if m == "je" else "je"    # flip so it reads as a test of the values
                emit(ins.address, f"{m} L{ops[0].imm:#08x}{cond}")
                snap(ops[0].imm, regs, stack, ins.address)
                continue

            # everything else: dst is garbage now
            if ops and ops[0].type == X86_OP_REG:
                regs.pop(r64(ops[0].reg), None)
            # if m not in ("nop", "and", "movaps", "movups", "xorps"):
            #     print("unhandled", hex(ins.address), m, ins.op_str, file=sys.stderr)

        return out, snapshots

    def _format_call(self, callee: str, args_of, stack, rsp) -> Tuple[str, bool]:
        A = api.ARITY.get(callee)
        if callee == "Py_IncRef" or callee == "Py_DecRef":
            return f"{'INCREF' if callee.endswith('IncRef') else 'DECREF'}({args_of(1)[0]})", False
        if callee == "memset":
            a = args_of(3)
            return f"memset({a[0]}, {a[1]}, {a[2]})", False
        if callee == "GLOBAL":
            a = args_of(3)
            mode = a[2]
            if mode.kind == "imm":
                if mode.a == 0:
                    return f"DELETE_GLOBAL({a[1]})", True
                if mode.a == 1:
                    return f"LOAD_GLOBAL({a[1]})", True
                # 4/5 only show up around `with` blocks
                if mode.a == 4:
                    return f"{a[1]}.'__enter__'", True
                if mode.a == 5:
                    return f"{a[1]}.'__exit__'", True
            if mode.kind not in ("imm",):
                return f"STORE_GLOBAL {a[1]} = {mode}", True
            return f"GLOBAL({a[1]}, mode={mode})", True
        if callee == "BUILD":
            a = args_of(4)
            kindv, cntv = a[0], a[1]
            kind = api.BUILD_KIND.get(kindv.a & 3, "?") if kindv.kind == "imm" else "?"
            n = cntv.a if cntv.kind == "imm" else None
            if n is None:
                # count is in a register we lost track of
                return f"BUILD_{kind.upper()}(...)", True
            if kind == "dict":
                items = args_of(2 + 2 * n)[2:]
                pairs = ", ".join(f"{items[i]}: {items[i+1]}" for i in range(0, len(items) - 1, 2))
                return f"BUILD_DICT({{{pairs}}})", True
            body = ", ".join(str(x) for x in args_of(2 + n)[2:])
            return f"BUILD_{kind.upper()}({body})", True
        if callee == "CALL":
            a = args_of(4)
            argv = stack.get(rsp + 0x20, Val("stack", rsp + 0x20))
            kwv = stack.get(rsp + 0x28, Val("stack", rsp + 0x28))
            self_ = a[0]
            func = a[1]
            parts = []
            if a[2].kind == "imm" and a[2].a:
                parts.append(f"*{argv}")
            if a[3].kind == "imm" and a[3].a:
                parts.append(f"**{kwv}")
            pre = "" if self_.kind == "imm" and self_.a == 0 else f"{self_}."
            return f"CALL {pre}{func}({', '.join(parts)})", True
        if callee == "BINARY_OP":
            a = args_of(3)
            opname = api.BINARY_OPS.get(a[2].a, f"op{a[2]}") if a[2].kind == "imm" else f"op{a[2]}"
            return f"({a[0]} {opname} {a[1]})", True
        if callee == "COMPARE_OP":
            a = args_of(4)
            opname = api.COMPARE_OPS.get(a[1].a, f"cmp{a[1]}") if a[1].kind == "imm" else f"cmp{a[1]}"
            return f"({a[2]} {opname} {a[3]})", True
        if callee == "UNARY_OP":
            a = args_of(2)
            opname = api.UNARY_OPS.get(a[1].a, f"un{a[1]}") if a[1].kind == "imm" else f"un{a[1]}"
            return f"({opname}{a[0]})", True
        if callee == "FORMAT":
            a = args_of(4)
            if a[0].kind == "imm" and a[0].a == 0:
                conv = api.FORMAT_CONV.get(a[2].a, f"conv{a[2]}") if a[2].kind == "imm" else f"conv{a[2]}"
                spec = "" if (a[3].kind == "imm" and a[3].a == 0) else f":{a[3]}"
                return f"FORMAT_VALUE({a[1]}{conv}{spec})", True
            n = a[0].a if a[0].kind == "imm" else 3
            parts = args_of(1 + n)[1:]
            return f"BUILD_STRING({', '.join(str(x) for x in parts)})", True
        if callee == "EXC_FETCH":
            a = args_of(3)
            for p, part in zip(a, ("type", "value", "tb")):
                if p.kind == "stackptr":
                    stack[p.a] = Val("exc", part)  # slots hold the caught exc from here on
            return f"EXC_FETCH({a[0]}, {a[1]}, {a[2]})", True
        if callee == "EXC_RESTORE":
            a = args_of(3)
            return f"RERAISE({a[0]}, {a[1]}, {a[2]})", False
        if callee == "RAISE":
            a = args_of(3)
            cause = "" if (a[2].kind == "imm" and a[2].a == 0) else f" from {a[2]}"
            return f"RAISE {a[1]}{cause}", False
        if callee == "SET_LINENO":
            return f"# line {args_of(1)[0]}", False
        if callee == "UNPACK":
            a = args_of(4)
            return f"UNPACK({a[1]}, n={a[2]}) -> {a[3]}", False
        if callee == "BIND_ARGS":
            a = args_of(4)
            return f"BIND_ARGS({', '.join(str(x) for x in a)})", False
        if callee == "PyObject_GetAttr":
            a = args_of(2)
            return f"{a[0]}.{a[1]}", True
        if callee == "PyObject_SetAttr":
            a = args_of(3)
            return f"SETATTR {a[0]}.{a[1]} = {a[2]}", False
        if callee == "PyObject_GetItem":
            a = args_of(2)
            return f"{a[0]}[{a[1]}]", True
        if callee == "PyObject_SetItem":
            a = args_of(3)
            return f"SETITEM {a[0]}[{a[1]}] = {a[2]}", False
        if callee == "PyObject_IsTrue":
            return f"BOOL({args_of(1)[0]})", True
        if callee == "PyObject_GetIter":
            return f"ITER({args_of(1)[0]})", True
        if callee == "FOR_ITER":
            return f"NEXT({args_of(1)[0]})", True
        if callee == "PyImport_ImportModuleLevel":
            a = args_of(5)
            return f"IMPORT({a[0]}, fromlist={a[3]}, level={a[4]})", True
        if callee == "MAKE_FUNCTION":
            a = args_of(3)
            return f"MAKE_FUNCTION({a[0]}, {a[1]}, {a[2]})", True
        if callee == "MAKE_CLOSURE":
            a = args_of(4)
            return f"MAKE_CLOSURE({', '.join(str(x) for x in a)})", True
        if callee in ("CHECK_ERROR", "PyErr_Occurred"):
            return f"{callee}({', '.join(str(x) for x in args_of(api.ARITY.get(callee, 1)))})", True
        if callee in ("PyObject_CallFunction", "PyObject_CallMethod",
                      "PyObject_CallFunctionObjArgs"):
            # varargs, would need to parse the format string. TODO
            a = args_of(4)
            return f"{callee}({', '.join(str(x) for x in a)}, ...)", True
        if A is None or A < 0:
            return f"{callee}(...)", True
        return f"{callee}({', '.join(str(x) for x in args_of(A))})", True


NOISE = ("INCREF(", "DECREF(", "CHECK_ERROR(", "PyErr_Occurred(", "PyErr_Clear(",
         "memset(", "PyEval_GetGlobals(", "BIND_ARGS(", "UNPACK(")
JCC = ("je", "jne", "js", "jns", "jle", "jg", "ja", "jae", "jb", "jbe", "jl", "jge")


def _clean(lines: List[str]) -> List[str]:
    # -c: hide the refcount/nullcheck noise, keep just the python level ops
    out = []
    for ln in lines:
        s = ln.strip()
        if not s or s.startswith("L0x"):
            continue
        body = s.split("  ", 1)[-1] if s.startswith("0x") else s
        body = body.split(" = ", 1)[-1]
        if body.startswith("goto ") or body.startswith("call "):
            continue
        if body.split(" ")[0] in JCC:
            continue
        if any(body.startswith(n) for n in NOISE):
            continue
        out.append(ln)
    return out


def load_stubs(elf: BccElf, das_path: Optional[str]) -> List[Optional[Stub]]:
    # one Stub (or None) per elf.functions entry. top level pairs by order,
    # nested ones get their trampoline stub + the parent's pool
    if not das_path or not os.path.exists(das_path):
        return [None] * len(elf.functions)
    stubs = parse_das(das_path)
    top = [f for f in elf.functions if not f.nested]
    if len(stubs) != len(top):
        # never happened so far but if it does, better no names than wrong names
        print(f"warning: {len(stubs)} stubs vs {len(top)} native functions; "
              "names may be misaligned", file=sys.stderr)
        return [None] * len(elf.functions)
    by_name = {f.name: s for f, s in zip(top, stubs)}
    nested = parse_nested(das_path)
    out: List[Optional[Stub]] = []
    for f in elf.functions:
        if not f.nested:
            out.append(by_name[f.name])
        elif f.name in nested and f.parent in by_name:
            out.append(with_pool(nested[f.name], by_name[f.parent].pool))
        else:
            out.append(None)
    return out


def run(elf_path: str, das_path: Optional[str], out_path: Optional[str], only: Optional[str],
        clean: bool = False):
    elf = BccElf(open(elf_path, "rb").read())
    stubs = load_stubs(elf, das_path)

    lines: List[str] = []
    lines.append(f"# {os.path.basename(elf_path)}")
    lines.append(f"# {len(elf.functions)} native functions, "
                 f"code {elf.text.size} bytes")
    lines.append("")
    for f, stub in zip(elf.functions, stubs):
        if only and stub and only not in stub.qualname:
            continue
        if only and not stub and only not in f.name:
            continue
        title = f.name
        if stub:
            title = f"{stub.qualname}({', '.join(stub.args[:stub.argcount])})"
        lines.append("=" * 78)
        lines.append(f"{title}")
        lines.append(f"  native {f.name} @ {f.start:#x} ({f.size} bytes)"
                     + (f", stub __pyarmor_bcc_{stub.marker}__" if stub and stub.marker >= 0 else "")
                     + (f", nested in {f.parent}" if f.nested else ""))
        if stub and stub.docstring:
            lines.append(f'  doc: {stub.docstring.strip()[:200]!r}')
        if stub and stub.pool:
            lines.append("  pool: " + ", ".join(
                f"{j}:{v!r}" if len(repr(v)) < 40 else f"{j}:{repr(v)[:37]}..."
                for j, v in enumerate(stub.pool)))
        lines.append("")
        body = Lifter(elf, stub).lift(f)
        lines.extend(_clean(body) if clean else body)
        lines.append("")

    text = "\n".join(lines)
    if out_path:
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"wrote {out_path} ({len(text)} bytes)")
    else:
        print(text)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("elf")
    ap.add_argument("-d", "--das", help=".1shot.das with the stub metadata")
    ap.add_argument("-o", "--out")
    ap.add_argument("-f", "--function", help="only lift functions matching this name")
    ap.add_argument("-c", "--clean", action="store_true",
                    help="hide refcount/null-check scaffolding")
    a = ap.parse_args()
    das = a.das
    if das is None:
        guess = a.elf.split(".1shot.bcc.")[0] + ".1shot.das"
        if os.path.exists(guess):
            das = guess
    run(a.elf, das, a.out, a.function, a.clean)


if __name__ == "__main__":
    main()
