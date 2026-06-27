"""BCC native-mode disassembler (opcode-annotated assembly).

PyArmor's BCC mode compiles each Python function's *bytecode* into a native
x86-64 ELF fragment that dispatches every operation through a runtime ``got0``
helper table assembled at load time. The normal 1shot pipeline only extracts
that ELF (``*.1shot.bcc.<arch>.elf``); the function bodies show up in the
``.das`` as the marker ``__pyarmor_bcc_NNNNN__``.

This module disassembles those fragments and resolves the ``got0`` dispatch
table back to CPython opcodes, annotating each constant-pool read with its
value from the ``.das``. Output: ``*.1shot.bcc.<arch>.asm.txt`` (``dump_asm``).

The got0 -> opcode map is ground truth: recovered by dumping the live fragment
dispatch table from a running runtime and resolving each slot to the libpython
C-API it calls (see ghiha/dyn/dump_table2_gdb.py). It is stable across builds,
Python versions (3.10-3.13) and OS; only the ABI (SysV vs Win64) differs, and
that is auto-detected per fragment.

Requires: capstone.  Supports win-x64 / linux-x64 (x86-64) fragments;
aarch64 (darwin-arm64) is skipped.
"""
from __future__ import annotations
import os
import re
import ast
import glob
import struct
import logging

logger = logging.getLogger("shot")

# --- got0 offset -> CPython opcode --------------------------------------------
# GROUND TRUTH: the fragment got0 (a2) was DUMPED LIVE from a running openaps
# 8.5.9/py3.11 process by hooking the BCC loader sub_0x17f20 and resolving every
# entry via `info symbol` (see ghiha/dyn/dump_table2_gdb.py). The high half
# (>=0xe0) are DIRECT libpython C-API pointers, alphabetically ordered by symbol
# name -> stable across builds. The low half (0x20-0xb8) are runtime .so handlers
# (structural VMC ops) named by Rosetta source-alignment (stable cross-build).
OPC = {
    # --- structural VMC ops (got0 -> runtime .so handler) ---
    0x008: "INIT_FRAME",       # frame alloc/zero (uses got0[0x08]=memset; arg=frame size)
    0x098: "BIND_ARGS",        # bind N params to frame (argc = param count)
    0x060: "LOAD_GLOBAL",      # custom global+builtins lookup (operand = name)
    0x030: "CALL",             # call dispatch (argc in r8)
    0x028: "PUSH_ARGS",        # precall arg build (mode in rcx: 2=pos, 3=+kwargs)
    0x058: "BINARY_OP",        # mode in rcx (2=+, 5=*)
    0x040: "COMPARE_OP",       # ==, is ; operand = rhs
    0x020: "STORE_NAME",       # store to global/name ; operand = target
    0x070: "FOR_ITER",         # loop step
    0x038: "RETURN_VALUE",     # leave / return
    0x0a0: "MAKE_FUNCTION",    # PyFunction_NewWithQualName
    0x0a8: "MAKE_FUNCTION",    # PyFunction_NewWithQualName (+PyCMethod_New: closure/method)
    # exception machinery (per-op error-cleanup / reraise; so+0x19xxx handlers calling
    # PyErr_Fetch/NormalizeException/SetTraceback/Restore). 0x050 is NOT LOAD_FAST.
    0x050: "SETUP_EXC?",       # exc normalize/restore
    0x080: "PUSH_EXC?",        # exc fetch/setup
    0x088: "RERAISE?",         # exc reraise/cleanup
    0x090: "RAISE_MSG",        # PyErr_SetString (e.g. unbound-local / name error)
    # --- object opcodes (got0 -> DIRECT libpython C-API; names = the API) ---
    0x0e0: "LOAD_NONE",        # _Py_None
    0x0e8: "LOAD_TRUE",        # _Py_True
    0x0f0: "LOAD_FALSE",       # _Py_False
    0x100: "BYTES_ASSTRING",   # PyBytes_AsStringAndSize
    0x108: "LOAD_DEREF",       # PyCell_Get
    0x110: "MAKE_CELL",        # PyCell_New
    0x118: "STORE_DEREF",      # PyCell_Set
    0x120: "ERR_CLEAR",        # PyErr_Clear      (cleanup/teardown)
    0x128: "ERR_OCCURRED",     # PyErr_Occurred   (per-op error check)
    0x130: "RAISE",            # PyErr_SetObject
    0x138: "LOAD_GLOBALS_NS",  # PyEval_GetGlobals (once at entry)
    0x140: "IMPORT_NAME",      # PyImport_ImportModule
    0x148: "IMPORT_NAME_LVL",  # PyImport_ImportModuleLevel
    0x150: "LIST_APPEND",      # PyList_Append
    0x158: "BUILD_LIST",       # PyList_New
    0x160: "CALL_FUNCTION",    # _PyObject_CallFunction_SizeT
    0x168: "CALL_FUNCTION",    # PyObject_CallFunctionObjArgs
    0x170: "CALL_METHOD",      # _PyObject_CallMethod_SizeT
    0x178: "DELETE_SUBSCR",    # PyObject_DelItem
    0x180: "LOAD_ATTR",        # PyObject_GetAttr
    0x188: "BINARY_SUBSCR",    # PyObject_GetItem
    0x190: "GET_ITER",         # PyObject_GetIter
    0x198: "POP_JUMP_IF",      # PyObject_IsTrue  (to-bool / conditional jump)
    0x1a0: "STORE_ATTR",       # PyObject_SetAttr
    0x1a8: "STORE_SUBSCR",     # PyObject_SetItem
    0x1b0: "SET_ADD",          # PySet_Add
    0x1b8: "BUILD_SET",        # PySet_New
    0x1c0: "BUILD_SLICE",      # PySlice_New
    0x1c8: "TUPLE_GETITEM",    # PyTuple_GetItem (unpack / tuple subscript)
    0x1d0: "DECREF",           # Py_DecRef   (refcount bookkeeping, folded as noise)
    0x1d8: "INCREF",           # Py_IncRef   (refcount bookkeeping, folded as noise)
    # NOTE: 0x1a0 is STORE_ATTR (PyObject_SetAttr), NOT the 011098 build's BUILD_LIST.
    # Corrected from Rosetta guesses (now proven by live table dump): 0x198 was
    # "LIST_APPEND" (->POP_JUMP_IF), 0x1a8 was "CALL_KW" (->STORE_SUBSCR), 0x1d8 was
    # "XDECREF" (->INCREF), 0x150/0x158/0x160 were "COMPREH?" (->APPEND/BUILD_LIST/CALL).
}
BINMODE = {0: "+", 2: "+", 5: "*", 3: "-"}   # BINARY_OP (0x58) mode in rcx -> operator


# ----------------------------------------------------------------------------- ELF
class _Sec:
    __slots__ = ("idx", "type", "flags", "addr", "off", "size")

    def __init__(self, idx, type, flags, addr, off, size):
        self.idx, self.type, self.flags = idx, type, flags
        self.addr, self.off, self.size = addr, off, size


def _parse_sections(d: bytes):
    if d[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    if d[4] != 2:
        raise ValueError("only 64-bit ELF supported")
    e_shoff = struct.unpack_from("<Q", d, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", d, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", d, 0x3C)[0]
    secs = []
    for i in range(e_shnum):
        b = e_shoff + i * e_shentsize
        name, typ, flags, addr, off, size = struct.unpack_from("<IIQQQQ", d, b)
        secs.append(_Sec(i, typ, flags, addr, off, size))
    return secs


SHF_WRITE = 0x1
SHF_EXEC = 0x4


def _locate(d: bytes, secs):
    """Return (text_sec, got_off, export_sec). Generic, no hardcoded offsets."""
    text = next((s for s in secs if s.flags & SHF_EXEC and s.size), None)
    if text is None:
        raise ValueError("no executable section found")
    wa = [s for s in secs if (s.flags & SHF_WRITE) and s.size]

    # export table = a WA section whose 0x20-stride entries name 'bcc_*' fragments
    export = None
    for s in wa:
        ok = 0
        for j in range(0, min(s.size, 0x20 * 4), 0x20):
            no, co, fl, z = struct.unpack_from("<QQQQ", d, s.off + j)
            if 0 < no < len(d):
                nm = d[no:d.index(b"\x00", no)] if b"\x00" in d[no:no + 32] else b""
                if nm.startswith(b"bcc_") and text.off <= co < text.off + text.size:
                    ok += 1
        if ok >= 1:
            export = s
            break
    if export is None:
        raise ValueError("could not locate BCC export table")

    # GOT = the non-exec section most referenced by `mov reg,[rip+disp]` in .text
    from collections import Counter
    rip_targets = Counter()
    code = d[text.off:text.off + text.size]
    # cheap scan: find RIP-relative loads via capstone over a sample is overkill;
    # instead let the lifter recompute. Pick the WA section that is not export and
    # is small (the got slot table); fall back to first such.
    cand = [s for s in wa if s is not export]
    got_off = min(cand, key=lambda s: s.size).off if cand else export.off
    return text, got_off, export


def _read_fragments(d: bytes, text, export):
    """Return (frags, ends) in EXPORT-TABLE order (== .das definition order),
    with trampoline entries resolved to their real body.

    PyArmor deduplicates structurally-identical functions: many export names are
    16-byte trampolines (``endbr64; jmp body``) that jump into a SHARED native
    body, and each function's real names come from its own const pool supplied at
    runtime. Sorting fragments by address (the old behaviour) broke the
    das[i] <-> fragment[i] correspondence (e.g. a 19-const method matched to a
    16-byte stub). Keeping table order + following trampolines restores an exact
    1:1 match with the .das BCC functions.
    """
    import bisect
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    text_end = text.off + text.size
    raw = []
    for j in range(0, export.size, 0x20):
        no, co, fl, z = struct.unpack_from("<QQQQ", d, export.off + j)
        if not (text.off <= co < text_end):
            continue
        if not (0 < no < len(d)):
            continue
        end = d.index(b"\x00", no)
        nm = d[no:end].decode("latin-1", "replace")
        if not nm.startswith("bcc_"):
            continue
        raw.append((nm, co))
    starts = sorted(set(c for _, c in raw)) + [text_end]

    def body_end(a):
        i = bisect.bisect_right(starts, a)
        return starts[i] if i < len(starts) else text_end

    def resolve(co):
        # tiny trampoline ``endbr64; jmp rel32`` -> follow to the real body
        for x in md.disasm(d[co:co + 16], co):
            if x.mnemonic == "jmp":
                try:
                    return int(x.op_str, 16)
                except ValueError:
                    return co
            if x.mnemonic not in ("endbr64", "nop"):
                break
        return co

    frags, ends = [], []
    for nm, co in raw:
        body = resolve(co)
        frags.append((nm, body))
        ends.append(body_end(body))
    return frags, ends


# ----------------------------------------------------------------------------- .das consts
def _parse_das_bcc(das_text: str):
    """Return ordered list of (objname, argnames, consts) for BCC functions."""
    out = []
    for b in re.split(r"\n(?=\s*Object Name:)", das_text):
        mo = re.search(r"Object Name: (\S+)", b)
        if not mo or "__pyarmor_bcc_" not in b:
            continue
        m = re.search(r"\[Constants\]\n(.*?)\n\s*\[Disassembly\]", b, re.S)
        consts = []
        if m:
            seg = m.group(1)
            pi = seg.find("(")
            if pi >= 0:
                depth = 0
                for line in seg[pi:].splitlines():
                    s = re.sub(r"\s+# b['\"].*$", "", line.strip())
                    if s == "(":
                        depth += 1
                        continue
                    if s == ")":
                        depth -= 1
                        if depth == 0:
                            break
                        continue
                    if s:
                        try:
                            consts.append(ast.literal_eval(s))
                        except Exception:
                            consts.append(s)
        ln = re.search(r"\[Locals\+Names\]\n(.*?)\n\s*\[", b, re.S)
        argnames = []
        if ln:
            for line in ln.group(1).splitlines():
                t = line.strip().strip("'")
                if t and t != "__assert_bcc__":
                    argnames.append(t)
        out.append((mo.group(1), argnames, consts))
    return out


# ----------------------------------------------------------------------------- names
def _pool_reads(ins, md, cn, consts):
    """{instruction index -> consts[] index} for genuine pool reads `mov reg,[cbase+0x18+8i]`.

    cbase = the consts-tuple base. A LINEAR scan corrupts which register is the cbase
    (PyArmor riddles the body with side blocks that reuse the cbase reg then branch away,
    and with return epilogues), so this runs a proper basic-block MUST-reaching-definitions:
    a register counts as cbase at a use only if it holds the cbase on EVERY path that
    reaches it (intersection at merges -> never a false positive; at worst misses one).
    """
    from capstone.x86 import (X86_INS_MOV, X86_INS_CALL, X86_INS_LEA, X86_INS_XOR,
                              X86_OP_REG, X86_OP_MEM, X86_REG_RIP)
    if not ins or not consts:
        return {}
    REGS = frozenset(("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                      "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"))
    VOL = ("rax", "rcx", "rdx", "r8", "r9", "r10", "r11")   # clobbered by any CALL (both ABIs)
    n = len(ins)
    addr2idx = {x.address: k for k, x in enumerate(ins)}

    def _jtgt(x):
        if x.mnemonic.startswith("j"):
            try:
                return int(x.op_str, 16)
            except ValueError:
                return None
        return None

    def _is_idxload(s):       # mov reg,[frame+idx*8+0x10]  -> the consts-tuple base
        return s.type == X86_OP_MEM and s.mem.index != 0 and s.mem.disp == 0x10

    # --- Pass A (linear): discover the cbase SPILL SLOTS (prologue spill is pre-branch). ---
    cslot = set(); cbaseA = set()
    for x in ins:
        o = x.operands
        if x.id == X86_INS_MOV and o and o[0].type == X86_OP_REG:
            dst = cn(o[0].reg); s = o[1]
            if _is_idxload(s):
                cbaseA.add(dst)
            elif s.type == X86_OP_MEM and s.mem.index == 0 and s.mem.base != X86_REG_RIP \
                    and f"{cn(s.mem.base)}{s.mem.disp:+#x}" in cslot:
                cbaseA.add(dst)
            elif s.type == X86_OP_REG and cn(s.reg) in cbaseA:
                cbaseA.add(dst)
            else:
                cbaseA.discard(dst)
        elif x.id == X86_INS_MOV and o and o[0].type == X86_OP_MEM and o[0].mem.index == 0 \
                and o[1].type == X86_OP_REG and cn(o[1].reg) in cbaseA:
            cslot.add(f"{cn(o[0].mem.base)}{o[0].mem.disp:+#x}")
        elif o and o[0].type == X86_OP_REG and x.id in (X86_INS_LEA, X86_INS_XOR):
            cbaseA.discard(cn(o[0].reg))

    # --- basic blocks ---
    leaders = {0}
    for k, x in enumerate(ins):
        tg = _jtgt(x)
        if tg is not None:
            if tg in addr2idx:
                leaders.add(addr2idx[tg])
            if k + 1 < n:
                leaders.add(k + 1)
        elif x.mnemonic.startswith("ret") and k + 1 < n:
            leaders.add(k + 1)
    starts = sorted(leaders)
    nb = len(starts)
    blk_of = {}
    for bi, st in enumerate(starts):
        end = starts[bi + 1] if bi + 1 < nb else n
        for j in range(st, end):
            blk_of[j] = bi
    succ = [[] for _ in range(nb)]; pred = [[] for _ in range(nb)]
    for bi, st in enumerate(starts):
        end = starts[bi + 1] if bi + 1 < nb else n
        last = ins[end - 1]; tg = _jtgt(last); nxt = bi + 1 if bi + 1 < nb else None
        outs = []
        if last.mnemonic == "jmp":
            if tg in addr2idx:
                outs = [blk_of[addr2idx[tg]]]
        elif last.mnemonic.startswith("j"):
            if nxt is not None:
                outs.append(nxt)
            if tg in addr2idx:
                outs.append(blk_of[addr2idx[tg]])
        elif last.mnemonic.startswith("ret"):
            outs = []
        elif nxt is not None:
            outs = [nxt]
        for ob in outs:
            succ[bi].append(ob); pred[ob].append(bi)

    def _transfer(cin, st, end, emit=None):
        cur = set(cin)
        for j in range(st, end):
            x = ins[j]; o = x.operands
            if x.id == X86_INS_MOV and o and o[0].type == X86_OP_REG:
                dst = cn(o[0].reg); s = o[1]
                if _is_idxload(s):
                    cur.add(dst); continue
                if s.type == X86_OP_MEM and s.mem.index == 0 and s.mem.base != X86_REG_RIP \
                        and f"{cn(s.mem.base)}{s.mem.disp:+#x}" in cslot:
                    cur.add(dst); continue
                if s.type == X86_OP_MEM and s.mem.index == 0 and s.mem.base != X86_REG_RIP \
                        and cn(s.mem.base) in cur and s.mem.disp >= 0x18 and (s.mem.disp - 0x18) % 8 == 0:
                    if emit is not None:
                        i = (s.mem.disp - 0x18) // 8
                        if i < len(consts):
                            emit[j] = i
                    cur.discard(dst); continue
                if s.type == X86_OP_REG and cn(s.reg) in cur:
                    cur.add(dst); continue
                cur.discard(dst)
            elif o and o[0].type == X86_OP_REG and x.id in (X86_INS_LEA, X86_INS_XOR):
                cur.discard(cn(o[0].reg))
            elif x.id == X86_INS_CALL:
                cur.difference_update(VOL)
        return cur

    from collections import deque
    cout = [set(REGS) for _ in range(nb)]; cin = [set() for _ in range(nb)]
    wl = deque(range(nb)); inq = [True] * nb; guard = 0; gmax = nb * (len(REGS) + 4) + 4096
    while wl and guard < gmax:
        guard += 1
        bi = wl.popleft(); inq[bi] = False
        if bi == 0:
            ni_ = set()
        elif not pred[bi]:
            # CFG gap: a block with no predecessors usually means an in-edge was dropped
            # (jump target outside the fragment, or capstone desync on some builds —
            # e.g. the 011098/py3.12 win-x64 build). Treating it as an entry (cin=empty)
            # wipes the cbase and the loss propagates downstream, killing const-pool name
            # resolution for the whole function. Seed instead with the linearly-confirmed
            # cbase regs (Pass A) so a lost edge doesn't erase resolution. Still sound:
            # emission requires the exact `[cbase+0x18+8i]` pattern with a valid index.
            ni_ = set(cbaseA)
        else:
            ni_ = set(REGS)
            for p in pred[bi]:
                ni_ &= cout[p]
        cin[bi] = ni_
        st = starts[bi]; end = starts[bi + 1] if bi + 1 < nb else n
        no_ = _transfer(ni_, st, end)
        if no_ != cout[bi]:
            cout[bi] = no_
            for sc in succ[bi]:
                if not inq[sc]:
                    wl.append(sc); inq[sc] = True

    poolread = {}
    for bi in range(nb):
        st = starts[bi]; end = starts[bi + 1] if bi + 1 < nb else n
        _transfer(cin[bi], st, end, emit=poolread)
    return poolread


def _name_idx(ins, md, consts):
    """{call_addr: consts index} for LOAD_ATTR(0x180)/LOAD_GLOBAL(0x60) name operands.

    The lifter's forward per-register pool-index tracking loses the link across
    spills / register reuse (~23% of names show `<stripped>` even though the name
    IS in the .das pool). This does it robustly: a FORWARD pass marks the genuine
    pool reads (`mov reg,[cbase+0x18+8i]`, cbase = a confirmed consts-tuple base, so
    a `[got0+0x28]` is never mistaken for a const), then a BACKWARD def-use chase from
    each name-op follows the name register (through reg-copies and stack spills) to
    the pool read that produced it.
    """
    from capstone.x86 import (X86_INS_MOV, X86_INS_CALL, X86_INS_LEA, X86_INS_POP,
                              X86_INS_XOR, X86_OP_REG, X86_OP_MEM, X86_REG_RIP)
    if not ins or not consts:
        return {}, set()
    Cm = {"eax":"rax","ecx":"rcx","edx":"rdx","ebx":"rbx","esi":"rsi","edi":"rdi","ebp":"rbp",
          "r8d":"r8","r9d":"r9","r10d":"r10","r11d":"r11","r12d":"r12","r13d":"r13","r14d":"r14","r15d":"r15"}
    cn = lambda r: Cm.get(md.reg_name(r), md.reg_name(r))
    # registers clobbered by a CALL -> stop the backward chase if it is following one.
    # Use the set that is volatile on BOTH ABIs: {rax,rcx,rdx,r8-r11}. rdi/rsi are
    # volatile on SysV but CALLEE-SAVED on Win64, so they legitimately carry a value
    # across a call there; on SysV a value never lives across a call in rdi/rsi (the
    # compiler would spill), so excluding them is safe on both.
    SAVED = ("rax", "rcx", "rdx", "r8", "r9", "r10", "r11")

    # genuine pool reads `mov reg,[cbase+0x18+8i]` -> consts index (CFG must-dataflow)
    poolread = _pool_reads(ins, md, cn, consts)

    # chase returns: int = resolved consts index; "NOISE" = the name register provably
    # comes from a non-pool OBJECT FIELD (`mov reg,[obj+off]`, obj not the const pool nor
    # a stack slot) -> this is the per-op reraise/error-cleanup tail re-touching live
    # objects (decref'd then re-read), which has NO co_names operand; None = undetermined.
    # chase -> (verdict, term_j): verdict is int consts index / "NOISE" / None;
    # term_j is the pool-read instruction the name resolved through (or None).
    def chase(k, reg):
        target = reg
        for j in range(k - 1, max(k - 400, -1), -1):
            x = ins[j]
            if x.id == X86_INS_CALL and isinstance(target, str) and target in SAVED:
                return None, None
            if x.id != X86_INS_MOV:
                continue
            o = x.operands
            if isinstance(target, str) and o[0].type == X86_OP_REG and cn(o[0].reg) == target:
                if j in poolread:
                    return poolread[j], j
                s = o[1]
                if s.type == X86_OP_REG:
                    target = cn(s.reg); continue
                if s.type == X86_OP_MEM and s.mem.index == 0 and s.mem.base != X86_REG_RIP \
                        and cn(s.mem.base) in ("rsp", "rbp"):
                    target = ("s", f"{cn(s.mem.base)}{s.mem.disp:+#x}"); continue
                # a non-pool, non-stack, non-rip memory load = an object field. A real
                # LOAD_ATTR/GLOBAL name is ALWAYS a pool const, so this is reraise noise.
                if s.type == X86_OP_MEM and s.mem.base != X86_REG_RIP and s.mem.index == 0:
                    return "NOISE", None
                return None, None
            if isinstance(target, tuple) and o[0].type == X86_OP_MEM and o[0].mem.index == 0 \
                    and o[1].type == X86_OP_REG \
                    and f"{cn(o[0].mem.base)}{o[0].mem.disp:+#x}" == target[1]:
                target = cn(o[1].reg); continue
        return None, None

    # Detect the ABI ONCE per fragment so the chase follows the RIGHT name register.
    # LOAD_ATTR/GLOBAL is `op(obj, name)`: obj=arg0, name=arg1. SysV arg0/arg1 = rdi/rsi;
    # Win64 = rcx/rdx. Reading the wrong one latches a stale, unrelated value (on Win64
    # `rsi` is just a leftover) which then traces to a bogus pool read -> wrong name
    # (e.g. a `'true'`/`'sec-fetch-dest'` *string literal* mislabelled as an attr name).
    win = lin = 0
    for k, x in enumerate(ins):
        if x.mnemonic == "call" and ("0x180" in x.op_str or "0x60" in x.op_str):
            for j in range(k - 1, max(k - 6, -1), -1):
                y = ins[j]
                if y.id == X86_INS_MOV and y.operands and y.operands[0].type == X86_OP_REG:
                    r = cn(y.operands[0].reg)
                    if r == "rcx":
                        win += 1; break
                    if r == "rdi":
                        lin += 1; break
    namereg = "rdx" if win >= lin else "rsi"

    # pass 1: resolve every name-op, recording the pool-read instruction each used
    tmp = {}; noise = set(); name_pr = set()
    for k, x in enumerate(ins):
        if x.mnemonic != "call":
            continue
        op0 = x.operands[0]
        off = op0.mem.disp if (op0.type == X86_OP_MEM and op0.mem.base != X86_REG_RIP and op0.mem.index == 0) else None
        if off in (0x180, 0x60):
            r, term = chase(k, namereg)    # only the real name arg for this ABI
            if isinstance(r, int):
                tmp[x.address] = (r, term)
                name_pr.add(term)
            elif r == "NOISE":
                noise.add(x.address)

    # The BCC pool MERGES co_names + co_consts with no separator, so a name register
    # can trace to a *literal* entry (e.g. a `headers.get('same-site')` arg) — that is
    # NOT an attribute name. A real co_name index is only ever read AS a name; a literal
    # index is also read as a plain value (LOAD_CONST etc.). So any pool index that some
    # NON-name pool read also loads is a const -> reject it as a name (leave it blank).
    const_idx = {idx for j, idx in poolread.items() if j not in name_pr}
    out = {}; ambiguous = {}
    for addr, (idx, _term) in tmp.items():
        if idx not in const_idx:
            out[addr] = idx            # used exclusively as a name -> trust it
        else:
            ambiguous[addr] = idx      # chased to a pool const that is ALSO read as a
                                       # plain literal: name-vs-literal ambiguous (the
                                       # merged co_names+co_consts pool) -> caller may show
                                       # it with a `?` rather than blank.
    return out, noise, ambiguous


# ----------------------------------------------------------------------------- lifter
def _op_1a0_signal(ins, md, canon):
    """(store_votes, build_votes) for 0x1a0 in *ins* by return width: a 32-bit eax use
    (int status) can ONLY be STORE_ATTR; a 64-bit rax use (pointer) is BUILD_LIST."""
    from capstone.x86 import X86_INS_CALL, X86_OP_REG, X86_OP_MEM
    s = b = 0
    for k in range(len(ins)):
        x = ins[k]
        if x.id == X86_INS_CALL and x.operands and x.operands[0].type == X86_OP_MEM \
                and x.operands[0].mem.index == 0 and x.operands[0].mem.disp == 0x1a0:
            for y in ins[k + 1:k + 4]:
                rn = None
                if y.mnemonic == "test" and y.operands and y.operands[0].type == X86_OP_REG \
                        and canon(y.operands[0].reg) == "rax":
                    rn = md.reg_name(y.operands[0].reg)
                elif y.mnemonic in ("mov", "movsxd") and len(y.operands) > 1 \
                        and y.operands[1].type == X86_OP_REG and canon(y.operands[1].reg) == "rax":
                    rn = md.reg_name(y.operands[1].reg)
                if rn == "eax":
                    s += 1; break
                if rn == "rax":
                    b += 1; break
    return s, b


# ----------------------------------------------------------------------------- asm view
def _asm_fragment(d, co, end, got, consts, P, op_1a0=None):
    """Disassemble ONE fragment and print the raw x86-64 with each got0 dispatch labelled
    by its mapped opcode (`call [rax+0x180]  ; ==> LOAD_ATTR`) and each constant-pool read
    annotated with its value (`mov rsi,[r12+0x18]  ; consts[0] = 'session'`). No bytecode
    lifting — just the native code with the got0 table + const pool resolved."""
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86 import (X86_INS_MOV, X86_INS_CALL, X86_INS_LEA, X86_INS_POP,
                              X86_INS_XOR, X86_OP_REG, X86_OP_MEM, X86_OP_IMM, X86_REG_RIP)
    md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True
    CM = {"eax": "rax", "ecx": "rcx", "edx": "rdx", "ebx": "rbx", "esi": "rsi", "edi": "rdi",
          "ebp": "rbp", "r8d": "r8", "r9d": "r9", "r10d": "r10", "r11d": "r11", "r12d": "r12",
          "r13d": "r13", "r14d": "r14", "r15d": "r15"}
    canon = lambda r: CM.get(md.reg_name(r), md.reg_name(r))
    ins = list(md.disasm(d[co:end], co))
    if op_1a0 is None:
        s, b = _op_1a0_signal(ins, md, canon)
        op_1a0 = "STORE_ATTR" if s else ("BUILD_LIST" if b else None)
    label = lambda off: (op_1a0 if off == 0x1a0 and op_1a0 else OPC.get(off, f"OP_{off:#05x}"))

    # constant-pool reads (instr index -> consts[] index) and the resolved name for each
    # LOAD_ATTR/GLOBAL dispatch (call_addr -> consts[] index) — both via the same CFG
    # must-dataflow the lifter uses, so the annotations are exact, not guessed.
    poolread = _pool_reads(ins, md, canon, consts) if consts else {}
    try:
        name_idx, _, name_amb = _name_idx(ins, md, consts)
    except Exception:
        name_idx = {}; name_amb = {}

    def cval(v):
        # show the FULL constant value; repr() escapes newlines so it stays one line
        return repr(v)

    # got0-base tracking (same robustness as the lifter: reg copies + stack spill/reload +
    # &got0 pointer deref) so every dispatch is recognised even inside loop bodies.
    gotset = set(); gotptr = set(); gotslots = set(); regmap = {}; slotmap = {}; memoff = {}; imm = {}
    for i, x in enumerate(ins):
        ops = x.operands; note = ""
        if i in poolread:
            note = f"; consts[{poolread[i]}] = {cval(consts[poolread[i]])}"
        isgl = (x.id == X86_INS_MOV and len(ops) > 1 and ops[1].type == X86_OP_MEM
                and ops[1].mem.base == X86_REG_RIP and (x.address + x.size + ops[1].mem.disp) == got)
        is_gotptr = (x.id == X86_INS_LEA and ops[1].type == X86_OP_MEM and ops[1].mem.base == X86_REG_RIP
                     and (x.address + x.size + ops[1].mem.disp) == got)
        is_gotptr = is_gotptr or (x.id == X86_INS_MOV and ops[0].type == X86_OP_REG
                                  and ops[1].type == X86_OP_REG and canon(ops[1].reg) in gotptr)
        via_ptr = (x.id == X86_INS_MOV and ops[1].type == X86_OP_MEM and ops[1].mem.index == 0
                   and ops[1].mem.disp == 0 and canon(ops[1].mem.base) in gotptr)
        got_from_reg = (x.id == X86_INS_MOV and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG
                        and canon(ops[1].reg) in gotset)
        got_from_slot = (x.id == X86_INS_MOV and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_MEM
                         and ops[1].mem.index == 0 and ops[1].mem.base != X86_REG_RIP
                         and f"{canon(ops[1].mem.base)}{ops[1].mem.disp:+#x}" in gotslots)
        if via_ptr or got_from_reg or got_from_slot:
            isgl = True
        if isgl:
            note = "; got0 base"
        elif is_gotptr:
            note = "; &got0"
        if x.id == X86_INS_MOV and ops[0].type == X86_OP_MEM and ops[1].type == X86_OP_REG and ops[0].mem.index == 0:
            k = f"{canon(ops[0].mem.base)}{ops[0].mem.disp:+#x}"
            if canon(ops[1].reg) in gotset:
                gotslots.add(k); note = "; spill got0 base"
            else:
                gotslots.discard(k)
        if x.id == X86_INS_MOV and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_IMM:
            imm[canon(ops[0].reg)] = ops[1].imm
        if x.id == X86_INS_MOV and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_MEM \
                and ops[1].mem.index == 0 and ops[1].mem.base != X86_REG_RIP:
            memoff[canon(ops[0].reg)] = ops[1].mem.disp
        cached = False
        if x.id == X86_INS_MOV and ops[1].type == X86_OP_MEM and ops[1].mem.index == 0 \
                and canon(ops[1].mem.base) in gotset:
            regmap[canon(ops[0].reg)] = ops[1].mem.disp; cached = True
            note = f"; got0+{ops[1].mem.disp:#x} = {label(ops[1].mem.disp)} -> {md.reg_name(ops[0].reg)}"
        if x.id == X86_INS_MOV and ops[0].type == X86_OP_MEM and ops[1].type == X86_OP_REG \
                and canon(ops[1].reg) in regmap:
            slotmap[x.op_str.split(",")[0].strip()] = regmap[canon(ops[1].reg)]
        # the dispatch itself
        if x.id == X86_INS_CALL:
            op0 = ops[0]; off = None
            if op0.type == X86_OP_MEM and op0.mem.index == 0 and canon(op0.mem.base) in gotset:
                off = op0.mem.disp
            elif op0.type == X86_OP_MEM and op0.mem.base != X86_REG_RIP and x.op_str.strip() in slotmap:
                off = slotmap[x.op_str.strip()]
            elif op0.type == X86_OP_REG and canon(op0.reg) in regmap:
                off = regmap[canon(op0.reg)]
            if off is not None:
                extra = ""
                if off in (0x180, 0x60):
                    ni = name_idx.get(x.address)
                    if ni is not None and ni < len(consts) and isinstance(consts[ni], str):
                        extra = f"  {consts[ni]!r}"
                    else:
                        # name-vs-literal ambiguous in the merged co_names+co_consts pool:
                        # show the chased value with a trailing `?` instead of blank.
                        na = name_amb.get(x.address)
                        if na is not None and na < len(consts) and isinstance(consts[na], str):
                            extra = f"  {consts[na]!r}?"
                elif off == 0x30 and imm.get("r8") is not None:
                    extra = f"  (argc={imm['r8']})"
                elif off == 0x58 and imm.get("rcx") is not None:
                    extra = f"  ({BINMODE.get(imm['rcx'], imm['rcx'])})"
                elif off == 0x98 and imm.get("r8") is not None:
                    extra = f"  (nparams={imm['r8']})"
                note = f"; ==> {label(off)}{extra}"
        P(f"  0x{x.address:08x}:  {x.mnemonic:<8}{(' ' + x.op_str) if x.op_str else ''}"
          + (f"   {note}" if note else ""))
        # state updates (mirror the lifter so tracking survives the whole fragment)
        if x.id == X86_INS_CALL:
            gotset.discard("rax"); regmap.pop("rax", None); imm.pop("r8", None); imm.pop("rcx", None)
            for r in ("rax", "rdi", "rsi", "rdx", "rcx", "r8", "r9", "r10", "r11"):
                memoff.pop(r, None)
        elif ops and ops[0].type == X86_OP_REG and x.id in (X86_INS_MOV, X86_INS_LEA, X86_INS_POP, X86_INS_XOR):
            dc = canon(ops[0].reg)
            if not isgl and not cached:
                gotset.discard(dc); regmap.pop(dc, None)
            if not is_gotptr:
                gotptr.discard(dc)
        if isgl and ops[0].type == X86_OP_REG:
            gotset.add(canon(ops[0].reg))
        if is_gotptr and ops[0].type == X86_OP_REG:
            gotptr.add(canon(ops[0].reg))


def dump_asm(elf_path: str, das_path: str | None, out_path: str) -> int:
    """Dump every BCC fragment as opcode-annotated x86-64 assembly (the `--asm` view)."""
    d = open(elf_path, "rb").read()
    secs = _parse_sections(d)
    text, got, export = _locate(d, secs)
    frags, ends = _read_fragments(d, text, export)
    das_funcs = []
    if das_path and os.path.exists(das_path):
        das_funcs = _parse_das_bcc(open(das_path, encoding="utf-8", errors="replace").read())

    # build-level 0x1a0 = STORE_ATTR vs BUILD_LIST (any int-status return proves STORE_ATTR)
    from capstone import Cs as _Cs, CS_ARCH_X86 as _A, CS_MODE_64 as _M
    _md = _Cs(_A, _M); _md.detail = True
    _CM = {"eax": "rax", "ecx": "rcx", "edx": "rdx", "ebx": "rbx", "esi": "rsi", "edi": "rdi",
           "ebp": "rbp", "r8d": "r8", "r9d": "r9", "r10d": "r10", "r11d": "r11", "r12d": "r12",
           "r13d": "r13", "r14d": "r14", "r15d": "r15"}
    _canon = lambda r: _CM.get(_md.reg_name(r), _md.reg_name(r))
    _S = _B = 0
    for _co, _end in zip((c for _, c in frags), ends):
        try:
            s, b = _op_1a0_signal(list(_md.disasm(d[_co:_end], _co)), _md, _canon); _S += s; _B += b
        except Exception:
            pass
    build_op_1a0 = "STORE_ATTR" if _S else ("BUILD_LIST" if _B else None)

    with open(out_path, "w", encoding="utf-8", errors="replace") as f:
        def P(s):
            f.write(s + "\n")
        P("# PyArmor BCC native x86-64 with the got0 dispatch table resolved to opcodes.")
        P(f"# source ELF: {os.path.basename(elf_path)}   ({len(frags)} fragments)   got0 @ 0x{got:x}")
        for i, ((nm, co), end) in enumerate(zip(frags, ends)):
            fn = das_funcs[i] if i < len(das_funcs) else None
            hdr = (f"{fn[0]}({', '.join(fn[1])})" if fn and fn[1] else (fn[0] if fn else nm))
            P(f"\n===== {hdr}   [{nm} @0x{co:x}]  ({end - co} bytes) =====")
            consts = das_funcs[i][2] if i < len(das_funcs) else []
            try:
                _asm_fragment(d, co, end, got, consts, P, op_1a0=build_op_1a0)
            except Exception as e:
                P(f"    <asm failed: {e}>")
    logger.info(f"Dumped BCC asm: {out_path} ({len(frags)} fragments)")
    return len(frags)


# ----------------------------------------------------------------------------- entry points
def dump_for_dest(dest_path: str) -> None:
    """Auto-dump any ``<dest>.1shot.bcc.*.elf`` to opcode-annotated assembly.

    Called from the pipeline after pycdc has written the ``.das``. Emits the native
    x86-64 with the got0 dispatch table + const pool resolved (``*.asm.txt``).
    """
    elves = sorted(glob.glob(glob.escape(dest_path) + ".1shot.bcc.*.elf"))
    if not elves:
        return
    try:
        import capstone  # noqa: F401
    except ImportError:
        logger.warning("BCC asm dump skipped: capstone not installed (pip install capstone)")
        return
    das = dest_path + ".1shot.das"
    for elf in elves:
        if elf.endswith((".aarch64.elf", ".darwin-arm64.elf")):
            logger.warning(f"BCC dump: skipping non-x86 fragment {os.path.basename(elf)}")
            continue
        out = elf[:-4] + ".asm.txt"  # ...elf -> ...asm.txt
        try:
            dump_asm(elf, das, out)
        except Exception as e:
            logger.error(f"BCC asm dump failed for {os.path.basename(elf)}: {e}")


def _cli():
    import argparse
    ap = argparse.ArgumentParser(description="Dump opcode-annotated x86-64 assembly from a PyArmor BCC native ELF")
    ap.add_argument("elf", help="path to *.1shot.bcc.<arch>.elf")
    ap.add_argument("--das", help="matching *.1shot.das (for const/arg names)", default=None)
    ap.add_argument("-o", "--out", help="output path (default: <elf>.asm.txt)", default=None)
    ap.add_argument("--asm", action="store_true", help="(accepted for back-compat; asm is the only mode)")
    a = ap.parse_args()
    das = a.das
    if das is None:
        guess = re.sub(r"\.1shot\.bcc\.[^.]+\.elf$", ".1shot.das", a.elf)
        das = guess if os.path.exists(guess) else None
    out = a.out or (a.elf[:-4] + ".asm.txt")
    n = dump_asm(a.elf, das, out)
    print(f"wrote {out} ({n} fragments)")


if __name__ == "__main__":
    _cli()
