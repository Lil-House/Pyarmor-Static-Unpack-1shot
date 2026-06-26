"""BCC native-mode bytecode dumper.

PyArmor's BCC mode compiles each Python function's *bytecode* into a native
x86-64 ELF fragment (per-opcode transliteration that dispatches through a
runtime ``got0`` helper table). The normal 1shot pipeline only extracts that
ELF (``*.1shot.bcc.<arch>.elf``); the function bodies show up in the ``.das``
as the marker ``__pyarmor_bcc_NNNNN__``.

This module lifts those native fragments back to a readable CPython
*bytecode-IR* listing, using a ``got0`` offset -> opcode map recovered by
behavioural ("Rosetta") alignment against known source. Output:
``*.1shot.bcc.bytecode.txt``.

Requires: capstone.  Currently supports the win-x64 / linux-x64 (x86-64)
fragments; aarch64 (darwin-arm64) is not yet handled.

NEED MORE TEST TO FULLY OPCODE
"""
from __future__ import annotations
import os
import re
import ast
import glob
import struct
import logging

logger = logging.getLogger("shot")

# --- got0 offset -> CPython opcode (confirmed by Rosetta alignment) -----------
# '?' marks slots inferred from context but not yet byte-proven.
OPC = {
    0x008: "INIT_FRAME",       # frame alloc (arg = frame size)
    0x098: "BIND_ARGS",        # bind N params to frame (argc = param count)
    0x138: "LOAD_GLOBALS_NS",  # load module globals namespace (once at entry)
    0x060: "LOAD_GLOBAL",      # operand = name
    0x180: "LOAD_ATTR",        # operand = attr/method name
    0x030: "CALL",             # argc in r8
    0x028: "PUSH_ARGS",        # precall arg build (mode in rcx: 2=pos, 3=+kwargs)
    0x058: "BINARY_OP",        # mode in rcx (2=+, 5=*)
    0x188: "BINARY_SUBSCR",    # obj[k]
    0x040: "COMPARE_OP",       # ==, is ; operand = rhs
    0x020: "STORE_NAME",       # store to global/name ; operand = target
    0x070: "FOR_ITER",         # GET_ITER / FOR_ITER (loop)
    0x1a0: "STORE_ATTR/BUILD_LIST?",  # 8.5.9: STORE_ATTR(target,name,val->int); 011098: BUILD_LIST
    0x1c0: "BUILD_SLICE",      # build slice (before BINARY_SUBSCR)
    0x038: "RETURN_VALUE",     # leave / return
    0x198: "LIST_APPEND",      # container add (listcomp append / MAP_ADD)
    0x190: "GET_ITER",         # iter(x): proven `range(len(..)) -> 0x190 -> FOR_ITER(0x70)`
    0x050: "LOAD_FAST?",       # load local / temp
    0x128: "LEAVE?",           # frame teardown (paired near end)
    0x120: "LEAVE?",           # frame teardown
    0x150: "COMPREH?",         # comprehension scaffold
    0x158: "COMPREH?",
    0x160: "COMPREH?",
    0x088: "OP_0x088?",
    0x1a8: "CALL_KW",          # call w/ kwargs: LOAD_ATTR callable; PUSH_ARGS; 0x1a8 (rdi/rsi/rdx)
    # --- PyArmor 8.5.9 codegen (verified on armorshot-regtest, linux+win x64) ---
    # In this build, DECREF is a helper call (it was inlined in the 011098 build),
    # so these flood the stream; they are refcount bookkeeping, not real opcodes.
    0x1d0: "DECREF",           # Py_DecRef(obj)         (arg: rdi SysV / rcx win)
    0x1d8: "XDECREF",          # Py_XDECREF(obj)        (win build only)
    # NOTE: high slots (>=0x120) are BUILD-DEPENDENT. In 8.5.9, 0x1a0 = STORE_ATTR
    # (3-arg target,name,value -> int status), NOT BUILD_LIST as in the 011098 build.
    # 0x128 + 0x120 = frame / exception-state teardown pair at function exit;
    # 0xe0 = Py_None / return-value slot. INCREF and LOAD_FAST/STORE_FAST stay inline.
}
# refcount helpers folded out of the listing (pure noise; absent in the 011098 build)
NOISE = {0x1d0, 0x1d8}
# all known got0 slot offsets — used as a fallback to recognise an indirect call as
# a got0 op when base-register tracking was lost across a basic-block boundary.
_GOT_OFFSETS = set(OPC) | NOISE | {0xe0}
BINMODE = {0: "+", 2: "+", 5: "*", 3: "-"}


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
        if bi == 0 or not pred[bi]:
            ni_ = set()
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
    out = {}
    for addr, (idx, _term) in tmp.items():
        if idx not in const_idx:
            out[addr] = idx            # used exclusively as a name -> trust it
    return out, noise


# ----------------------------------------------------------------------------- liveness
def _dead_addrs(ins, md, consts):
    """Value-flow dead-op elimination. Returns the set of instruction addresses of
    PURE value-producing got0 ops / const-loads whose result never reaches an
    observable ROOT (a CALL / STORE / the returned value). PyArmor's per-op reraise
    cleanup re-loads names and builds a throwaway list (LOAD_CONST/GLOBAL + LIST_APPEND)
    that flows only into internal cleanup ops -> dead. A real try/except handler's
    values flow into real CALLs/STOREs/return -> live, so it is preserved.

    Tracks every value through registers and stack slots (mov / spill / reload /
    clobber), builds a use->def graph, and runs backward liveness from the roots.
    """
    from capstone.x86 import (X86_INS_MOV, X86_INS_CALL, X86_INS_RET, X86_INS_LEA,
                              X86_INS_POP, X86_INS_XOR, X86_OP_REG, X86_OP_MEM,
                              X86_OP_IMM, X86_REG_RIP)
    if not ins:
        return set()
    C = {"eax":"rax","ecx":"rcx","edx":"rdx","ebx":"rbx","esi":"rsi","edi":"rdi","ebp":"rbp",
         "r8d":"r8","r9d":"r9","r10d":"r10","r11d":"r11","r12d":"r12","r13d":"r13","r14d":"r14","r15d":"r15"}
    def cn(r): n = md.reg_name(r); return C.get(n, n)
    ARGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
    PURE = {0x60, 0x180, 0x188, 0x58, 0x40, 0x190, 0x1c0, 0x198, 0x28, 0x108}  # droppable if dead
    ROOT = {0x30, 0x1a8, 0x1a0, 0x20, 0x70, 0x138, 0x98}  # CALL/STORE/FOR_ITER/frame: always live
    NOISE_ = {0x1d0, 0x1d8, 0x128, 0x120, 0x8, 0xe0, 0x88}  # cleanup consumers (don't keep value alive)

    def coff(idx):
        x = ins[idx]
        if x.id != X86_INS_CALL:
            return None
        o = x.operands[0]
        if o.type == X86_OP_MEM:
            return o.mem.disp if (o.mem.base != X86_REG_RIP and o.mem.index == 0) else None
        if o.type == X86_OP_REG:
            r = cn(o.reg)
            for j in range(idx - 1, max(idx - 14, -1), -1):
                y = ins[j]
                if y.id == X86_INS_MOV and y.operands[0].type == X86_OP_REG and cn(y.operands[0].reg) == r:
                    s = y.operands[1]
                    return s.mem.disp if (s.type == X86_OP_MEM and s.mem.index == 0 and s.mem.base != X86_REG_RIP) else None
            return None
        return None

    val = {}      # reg -> producer instr index (value currently in reg)
    sval = {}     # "slot" -> producer index
    cbase = set()
    producer_off = {}   # instr index -> got0 offset (for value producers)
    consumed_by = {}    # consumer index -> list of producer indices it reads
    is_root = set()     # producer indices that are roots
    slot = lambda m: f"{cn(m.mem.base)}{m.mem.disp:+#x}"

    for i, x in enumerate(ins):
        ops = x.operands
        # cbase: mov reg,[base+idx*8+0x10]
        if x.id == X86_INS_MOV and len(ops) > 1 and ops[1].type == X86_OP_MEM and ops[1].mem.index != 0 and ops[1].mem.disp == 0x10:
            cbase.add(cn(ops[0].reg))
        # pool const load: mov reg,[cbase+0x18+8i]  -> a value producer (this instr)
        if x.id == X86_INS_MOV and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_MEM \
                and ops[1].mem.index == 0 and cn(ops[1].mem.base) in cbase \
                and ops[1].mem.disp >= 0x18 and (ops[1].mem.disp - 0x18) % 8 == 0:
            producer_off[i] = -1   # const
            val[cn(ops[0].reg)] = i
            continue
        h = coff(i)
        if h is not None:   # a got0 call
            # consume arg-register values
            for r in ARGS:
                p = val.get(r)
                if p is not None:
                    consumed_by.setdefault(i, []).append(p)
            if h in PURE or h in ROOT:
                producer_off[i] = h
                if h in ROOT:
                    is_root.add(i)
                # result in rax; LIST_APPEND/PUSH continue their container in rdi too
                val["rax"] = i
                if h in (0x198, 0x28):
                    val["rdi"] = i
            # clobber caller-saved
            for r in ("rsi", "rdx", "rcx", "r8", "r9", "r10", "r11"):
                val.pop(r, None)
            continue
        if x.id == X86_INS_RET:
            p = val.get("rax")
            if p is not None:
                is_root.add(p)
            continue
        # data movement
        if x.id == X86_INS_MOV and ops[0].type == X86_OP_REG:
            d = cn(ops[0].reg); s = ops[1]
            if s.type == X86_OP_REG and cn(s.reg) in val:
                val[d] = val[cn(s.reg)]
            elif s.type == X86_OP_MEM and s.mem.index == 0 and s.mem.base != X86_REG_RIP and slot(s) in sval:
                val[d] = sval[slot(s)]
            else:
                val.pop(d, None)
        elif x.id == X86_INS_MOV and ops[0].type == X86_OP_MEM and ops[1].type == X86_OP_REG and ops[0].mem.index == 0:
            sk = slot(ops[0]); sr = cn(ops[1].reg)
            if sr in val:
                sval[sk] = val[sr]
            else:
                sval.pop(sk, None)
        elif ops and ops[0].type == X86_OP_REG and x.id in (X86_INS_LEA, X86_INS_POP, X86_INS_XOR):
            val.pop(cn(ops[0].reg), None)

    # backward liveness from roots: a live op keeps the producers it consumes live
    live = set(is_root)
    stack = list(live)
    while stack:
        c = stack.pop()
        for p in consumed_by.get(c, ()):
            if p not in live:
                live.add(p)
                stack.append(p)
    # dead = pure producers not live
    dead = set()
    for i, off in producer_off.items():
        if i not in live and (off == -1 or off in PURE):
            dead.add(ins[i].address)
    return dead


# ----------------------------------------------------------------------------- CFG
def _main_addrs(ins, md):
    """Addresses on the MAIN path. PyArmor lays the whole per-op error-handler /
    cleanup region (decref chains + the const-name re-load tail) AFTER the function's
    main teardown — the block that does the frame-leave (got0 +0x128/+0x120) and the
    final ``ret``. We locate that teardown and keep only instructions up to it; the
    cleanup tail (all at higher addresses, reached solely via error jumps) is dropped.

    This is deliberately conservative: it never touches the main body's own branches
    or loops (all at addresses <= the teardown), so it cannot cut real code.
    """
    from capstone.x86 import (X86_INS_CALL, X86_INS_MOV, X86_INS_RET,
                              X86_OP_MEM, X86_OP_REG, X86_REG_RIP)
    if not ins:
        return set()

    def call_off(idx):
        # got0-call offset of ins[idx]: `call [reg+disp]` -> disp; `call reg` ->
        # scan back for `mov reg,[base+disp]`. None if not an indirect call.
        x = ins[idx]
        if x.id != X86_INS_CALL:
            return None
        op0 = x.operands[0]
        if op0.type == X86_OP_MEM:
            if op0.mem.base != X86_REG_RIP and op0.mem.index == 0:
                return op0.mem.disp
            return None
        if op0.type == X86_OP_REG:
            reg = md.reg_name(op0.reg)
            for j in range(idx - 1, max(idx - 14, -1), -1):
                y = ins[j]
                if y.id == X86_INS_MOV and y.operands[0].type == X86_OP_REG \
                        and md.reg_name(y.operands[0].reg) == reg:
                    src = y.operands[1]
                    if src.type == X86_OP_MEM and src.mem.index == 0 and src.mem.base != X86_REG_RIP:
                        return src.mem.disp
                    return -1
            return -1
        return None

    addr2i = {x.address: i for i, x in enumerate(ins)}
    n = len(ins)
    SIXTYFOUR = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "r8", "r9",
                 "r10", "r11", "r12", "r13", "r14", "r15"}
    NEAR = 0x40   # forward NULL-check jumps within this are inline incref/decref guards

    def jtgt(x):
        try:
            return int(x.op_str, 16)
        except ValueError:
            return None

    def cond(x):
        return x.mnemonic[0] == "j" and x.mnemonic != "jmp"

    # leaders -> basic blocks
    leaders = {ins[0].address}
    for i, x in enumerate(ins):
        if x.mnemonic == "jmp" or cond(x):
            t = jtgt(x)
            if t in addr2i:
                leaders.add(t)
            if i + 1 < n:
                leaders.add(ins[i + 1].address)
        elif x.mnemonic == "ret" and i + 1 < n:
            leaders.add(ins[i + 1].address)
    order = sorted(leaders)
    blk = {}
    for bi, a in enumerate(order):
        si = addr2i[a]
        ei = addr2i[order[bi + 1]] if bi + 1 < len(order) else n
        blk[a] = (si, ei)

    # the main teardown = first `ret`; the per-op error handlers + cleanup tail are
    # laid out entirely after it. A FORWARD conditional jump that crosses past it is
    # a per-op error edge into the cleanup region. (Early-return continuation lives
    # before the real teardown and is reached by fall-through, so it's preserved;
    # in-body branches/loops stay within [start, R].)
    R = next((x.address for x in ins if x.id == X86_INS_RET), None)

    def succs(a):
        """(target, is_error) per successor. An error edge is a 64-bit pointer
        NULL-check `test rXX,rXX; jcc <far handler>` (not a near incref guard, not
        FOR_ITER's loop-exit). Real Python branches use `test eax`/`cmp` and so are
        never treated as errors -> early-return continuation is preserved."""
        si, ei = blk[a]
        last = ins[ei - 1]
        if last.mnemonic == "ret":
            return []
        if last.mnemonic == "jmp":
            t = jtgt(last)
            return [(t, False)] if t in blk else []
        if not cond(last):
            return [(ins[ei].address, False)] if ei < n else []
        t = jtgt(last)
        ft = ins[ei].address if ei < n else None
        # A forward conditional jump landing past the main teardown ret = error edge
        # into the per-op handler / cleanup region. FOR_ITER's loop-exit also jumps
        # forward but lands in the MAIN body (<= R), so it's never misclassified.
        err = bool(R is not None and t in blk and t > R and t > last.address)
        out = []
        if err:
            if ft is not None and ft in blk:
                out.append((ft, False))
            out.append((t, True))
        else:
            if t in blk:
                out.append((t, False))
            if ft is not None and ft in blk:
                out.append((ft, False))
        return out

    seen = set()
    stack = [ins[0].address]
    while stack:
        a = stack.pop()
        if a in seen or a not in blk:
            continue
        seen.add(a)
        for tt, is_err in succs(a):
            if not is_err and tt in blk and tt not in seen:
                stack.append(tt)
    if len(seen) == len(blk):
        return None   # nothing excluded
    out = set()
    for a in seen:
        si, ei = blk[a]
        for j in range(si, ei):
            out.add(ins[j].address)
    return out

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


def _lift(d, co, end, got, consts, P, op_1a0=None):
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86 import (
        X86_INS_MOV, X86_INS_CALL, X86_INS_RET, X86_INS_LEA, X86_INS_POP,
        X86_INS_XOR, X86_INS_CMP, X86_OP_REG, X86_OP_MEM, X86_OP_IMM, X86_REG_RIP,
    )
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    def canon(r):
        n = md.reg_name(r)
        m = {"eax": "rax", "ecx": "rcx", "edx": "rdx", "ebx": "rbx", "esi": "rsi",
             "edi": "rdi", "ebp": "rbp", "r8d": "r8", "r9d": "r9", "r10d": "r10",
             "r11d": "r11", "r12d": "r12", "r13d": "r13", "r14d": "r14", "r15d": "r15"}
        return m.get(n, n)

    ins = list(md.disasm(d[co:end], co))
    n = len(ins)

    # 0x1a0 = STORE_ATTR (8.5.9, int-status return) vs BUILD_LIST (011098, list-pointer
    # return) — ONE op per build. Prefer a build-level decision passed in by the caller;
    # otherwise fall back to this fragment's own signal. An int (eax) return PROVES
    # STORE_ATTR (a list build never returns a 32-bit status), so any eax wins.
    if op_1a0 is None:
        _s1a0, _b1a0 = _op_1a0_signal(ins, md, canon)
        if _s1a0:
            op_1a0 = "STORE_ATTR"
        elif _b1a0:
            op_1a0 = "BUILD_LIST"
    # NOTE: control-flow cutting of the cleanup tail is disabled — PyArmor's per-op
    # reraise cleanup and a real source try/except handler are reached the SAME way
    # (error edges), so a CFG cut can't tell them apart. Instead the dead-value pass
    # below drops value-loads whose result is never consumed (the reraise re-loads
    # name consts but never uses them), which is exact and never touches real code.
    main_addrs = None
    # NOTE: full value-flow liveness (_dead_addrs) was tried to excise the reraise tail
    # but hit the SAME wall as the CFG cut: PyArmor's reraise contains its OWN internal
    # CALLs/STOREs, which are "roots", so backward-liveness keeps it alive — and it also
    # over-cut real except-block chains the (necessarily incomplete) tracking missed.
    # The only signal that cleanly separates reraise noise from real code is an unused
    # LOAD_CONST / unresolved LOAD_GLOBAL (below), which is exact and never over-cuts.
    dead = set()
    # robust name recovery: backward def-use chase of each LOAD_ATTR/GLOBAL name reg
    # to its pool read (resolves names the forward per-register tracking loses).
    try:
        name_idx, name_noise = _name_idx(ins, md, consts)
    except Exception:
        name_idx, name_noise = {}, set()
    noise = [False] * n
    for i, x in enumerate(ins):
        if x.id == X86_INS_CMP and x.op_str.replace(" ", "").endswith("0xbfffffff"):
            j = i
            while j > max(0, i - 6) and not (ins[j].mnemonic == "mov" and "[" in ins[j].op_str):
                j -= 1
            k = i
            while k < min(n - 1, i + 6) and not (ins[k].mnemonic == "mov" and ins[k].op_str.startswith("dword ptr [")):
                k += 1
            for t in range(j, k + 1):
                noise[t] = True

    gotset = set(); cbase = set(); regmap = {}; slotmap = {}; imm = {}; last_str = [None]
    gotptr = set()   # regs holding &got0 (lea reg,[rip->got]); deref reaches got0 base
    gotslots = set() # stack slots currently holding the got0 base (spill/reload)
    memoff = {}      # reg -> last memory-load offset (register-direct got0-call fallback)
    last_cidx = [None]   # last emitted LOAD_CONST index (collapse cleanup-region repeats)
    pidx = {}     # reg  -> consts[] index it currently holds (name/const pool)
    sidx = {}     # "rsp+N" stack slot -> consts[] index spilled there
    pc = [0]

    ARG_PREF = ("rsi", "rdx", "rcx", "r8", "r9", "rdi")  # name-arg first (SysV/win)

    def _slot_key(memop):
        return f"{canon(memop.mem.base)}{memop.mem.disp:+#x}"

    _IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

    def _ok(v, identonly):
        if not isinstance(v, str):
            return False
        if not identonly:
            return True
        # attr/global names are always identifiers; reject the code-object const
        # prefix that sits at pool[0..2] (docstring / None / __pyarmor_bcc_N__ marker)
        return bool(_IDENT.match(v)) and not v.startswith("__pyarmor")

    def resolve_name(identonly=True):
        """Name for the current op: last LOAD_CONST, else the pool string sitting
        in an argument register (dataflow). Object args carry no pool index, so
        the single arg reg that does hold one is the name. For LOAD_ATTR/GLOBAL the
        name must be an identifier, which filters out docstring/marker false hits."""
        if _ok(last_str[0], identonly):
            return last_str[0]
        for r in ARG_PREF:
            ci = pidx.get(r)
            if ci is not None and ci < len(consts) and _ok(consts[ci], identonly):
                return consts[ci]
        return None

    def short(v):
        s = repr(v)
        return s if len(s) <= 62 else s[:59] + "...'"

    # dead-value elimination: PyArmor appends a per-op error-handler block after
    # every op (`test rax,rax; je <handler>`); those handlers re-LOAD globals/consts
    # only to decref them, producing floods of value-loads whose result is DISCARDED.
    # Buffer ops, track which value-load produced each register, and drop a value-load
    # if its result is decref'd without ever being consumed by a real op.
    records = []           # [text, alive]
    prod = {}              # reg -> record index of the value-load that produced it
    prod_s = {}            # stack slot -> record index (spilled value-load result)
    used = set()           # record indices whose result was consumed by a real op (never dead)
    entry_seen = set()     # entry-only ops already emitted (suppress cleanup re-inits)
    VALUE_OPS = {0x60, 0x180, 0x188, 0x40, 0x190, 0x1c0}  # pure loads (droppable if discarded)

    def emit(s, vload=False):
        records.append([s, True, vload])   # [text, alive, is_value_load]
        return len(records) - 1

    for i, x in enumerate(ins):
        ops = x.operands
        # whether this instruction is on the main path (emit) — register state is
        # still tracked for non-main instructions to keep continuity across blocks.
        in_main = (main_addrs is None) or (x.address in main_addrs)
        isgl = (x.id == X86_INS_MOV and ops[1].type == X86_OP_MEM and ops[1].mem.base == X86_REG_RIP
                and (x.address + x.size + ops[1].mem.disp) == got)
        # got0 base reached via a cached pointer (used inside loop bodies):
        #   lea reg,[rip->got]   then   mov r,[reg]   == got0 base
        is_gotptr = (x.id == X86_INS_LEA and ops[1].type == X86_OP_MEM and ops[1].mem.base == X86_REG_RIP
                     and (x.address + x.size + ops[1].mem.disp) == got)
        # propagate &got0 through reg->reg moves (e.g. `mov r15, rbx`)
        gotptr_mov = (x.id == X86_INS_MOV and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG
                      and canon(ops[1].reg) in gotptr)
        is_gotptr = is_gotptr or gotptr_mov
        via_ptr = (x.id == X86_INS_MOV and ops[1].type == X86_OP_MEM and ops[1].mem.index == 0
                   and ops[1].mem.disp == 0 and canon(ops[1].mem.base) in gotptr)
        # got0 base also propagates through reg<->reg copies and stack spills/reloads
        got_from_reg = (x.id == X86_INS_MOV and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG
                        and canon(ops[1].reg) in gotset)
        got_from_slot = (x.id == X86_INS_MOV and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_MEM
                         and ops[1].mem.index == 0 and ops[1].mem.base != X86_REG_RIP
                         and f"{canon(ops[1].mem.base)}{ops[1].mem.disp:+#x}" in gotslots)
        if via_ptr or got_from_reg or got_from_slot:
            isgl = True   # treat the dest exactly like a direct got0-base load
        # spill got0 base to a stack slot:  mov [rsp+X], gotreg
        if x.id == X86_INS_MOV and ops[0].type == X86_OP_MEM and ops[1].type == X86_OP_REG \
                and ops[0].mem.index == 0:
            _k = f"{canon(ops[0].mem.base)}{ops[0].mem.disp:+#x}"
            if canon(ops[1].reg) in gotset:
                gotslots.add(_k)
            else:
                gotslots.discard(_k)
        if x.id == X86_INS_MOV and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_IMM:
            imm[canon(ops[0].reg)] = ops[1].imm
        if x.id == X86_INS_MOV and ops[1].type == X86_OP_MEM and ops[1].mem.index != 0 and ops[1].mem.disp == 0x10:
            cbase.add(canon(ops[0].reg))
        # memoff: last offset each reg was loaded from memory at (index 0). Used as a
        # fallback for register-direct got0 calls `mov r10,[base+off]; call r10` when
        # the base wasn't confirmed as got0 across a block boundary.
        if x.id == X86_INS_MOV and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_MEM \
                and ops[1].mem.index == 0 and ops[1].mem.base != X86_REG_RIP:
            memoff[canon(ops[0].reg)] = ops[1].mem.disp
        cached = False
        if x.id == X86_INS_MOV and ops[1].type == X86_OP_MEM and ops[1].mem.index == 0 and canon(ops[1].mem.base) in gotset:
            regmap[canon(ops[0].reg)] = ops[1].mem.disp
            cached = True
        if x.id == X86_INS_MOV and ops[0].type == X86_OP_MEM and ops[1].type == X86_OP_REG and canon(ops[1].reg) in regmap:
            slotmap[x.op_str.split(",")[0].strip()] = regmap[canon(ops[1].reg)]
        # const/name pool load:  reg <- [poolbase + 0x18 + 8*i]
        pool_load = None
        if (not cached) and x.id == X86_INS_MOV and ops[1].type == X86_OP_MEM \
                and canon(ops[1].mem.base) in cbase and ops[1].mem.index == 0:
            off = ops[1].mem.disp
            if off >= 0x18 and (off - 0x18) % 8 == 0 and (off - 0x18) // 8 < len(consts):
                pool_load = (off - 0x18) // 8
        if in_main and (not noise[i]) and pool_load is not None and x.address not in dead:
            val = consts[pool_load]
            if isinstance(val, str):
                last_str[0] = val
            # collapse consecutive identical const reads (PyArmor error-cleanup blocks
            # re-read the same pool slot many times -> real bytecode never does this)
            if pool_load != last_cidx[0]:
                ci_idx = emit(f"LOAD_CONST   {pool_load:<3} {short(val)}", vload=True)
                prod[canon(ops[0].reg)] = ci_idx   # const value lands in this reg
                last_cidx[0] = pool_load

        # ---- pool-index dataflow: which reg / stack-slot holds consts[i] ----
        if x.id == X86_INS_MOV and ops[0].type == X86_OP_REG:
            dst = canon(ops[0].reg); src = ops[1]
            if pool_load is not None:
                pidx[dst] = pool_load
            elif src.type == X86_OP_REG and canon(src.reg) in pidx:
                pidx[dst] = pidx[canon(src.reg)]
            elif src.type == X86_OP_MEM and src.mem.index == 0 and _slot_key(src) in sidx:
                pidx[dst] = sidx[_slot_key(src)]
            else:
                pidx.pop(dst, None)
            # propagate prod (value-load record) through the same move
            if pool_load is not None:
                pass  # already set prod[dst] at the LOAD_CONST emit above
            elif src.type == X86_OP_REG and canon(src.reg) in prod:
                prod[dst] = prod[canon(src.reg)]
            elif src.type == X86_OP_MEM and src.mem.index == 0 and _slot_key(src) in prod_s:
                prod[dst] = prod_s[_slot_key(src)]
            elif not isgl:
                prod.pop(dst, None)
        elif x.id == X86_INS_MOV and ops[0].type == X86_OP_MEM and ops[1].type == X86_OP_REG:
            key = _slot_key(ops[0]); srcr = canon(ops[1].reg)
            if srcr in pidx:
                sidx[key] = pidx[srcr]
            else:
                sidx.pop(key, None)
            if srcr in prod:
                prod_s[key] = prod[srcr]
            else:
                prod_s.pop(key, None)
        helper = None
        if x.id == X86_INS_CALL:
            op0 = ops[0]
            if op0.type == X86_OP_MEM and op0.mem.index == 0 and canon(op0.mem.base) in gotset:
                helper = op0.mem.disp
            elif op0.type == X86_OP_MEM and op0.mem.base != X86_REG_RIP and x.op_str.strip() in slotmap:
                helper = slotmap[x.op_str.strip()]
            elif op0.type == X86_OP_REG and canon(op0.reg) in regmap:
                helper = regmap[canon(op0.reg)]
            # NOTE: a blind "disp in _GOT_OFFSETS" fallback was removed — it misfired on
            # non-got0 indirect calls in cleanup blocks (e.g. labelling `call [obj+0x8]`
            # as INIT_FRAME). got0 base is now tracked through reg-copies + stack spills
            # (gotset/gotptr/gotslots) so the real calls are recognised without guessing.
        if helper in NOISE:
            # DECREF/XDECREF: if it discards a value-load result that was never consumed
            # by a real op, that load was PyArmor error-handler noise -> drop it.
            for r in ("rdi", "rcx"):           # decref arg: rdi (SysV) / rcx (win)
                d = prod.pop(r, None)
                if d is not None and d not in used:
                    records[d][1] = False      # discarded without ever being consumed
            helper = None
        # entry-only ops (INIT_FRAME / LOAD_GLOBALS_NS / BIND_ARGS) occur exactly once,
        # at the prologue. A second occurrence is a PyArmor error-handler re-init in a
        # cleanup block (or a got0 misdetection) -> suppress it.
        if helper in (0x8, 0x138, 0x98):
            if helper in entry_seen:
                helper = None
            else:
                entry_seen.add(helper)
        if in_main and (not noise[i]) and helper is not None:
            # this real op consumes its argument registers -> mark those loads as USED
            # (a later decref of the same value is normal refcounting, not a discard)
            for r in ("rdi", "rsi", "rdx", "rcx", "r8", "r9"):
                d = prod.pop(r, None)
                if d is not None:
                    used.add(d)
            if x.address in dead:
                helper = None   # value-flow dead op (reraise noise) -> drop
        if (not noise[i]) and in_main and helper is not None and x.address not in dead:
            opc = OPC.get(helper, f"OP_{helper:#05x}")
            if helper == 0x1a0 and op_1a0 is not None:
                opc = op_1a0          # per-fragment build-consistent STORE_ATTR / BUILD_LIST
            arg = ""
            unresolved_global = False
            drop_noise = False
            if helper in (0x60, 0x180):
                # attribute / global NAME. Forward last-const/dataflow resolver is PRIMARY
                # (reads the name from the op's own local setup); the ABI-correct backward
                # chase only FILLS the blanks it leaves and never overrides it.
                nm_ = resolve_name(identonly=True)
                if nm_ is None:
                    ni = name_idx.get(x.address)
                    nm_ = consts[ni] if (ni is not None and ni < len(consts)
                                         and isinstance(consts[ni], str) and _IDENT.match(consts[ni])
                                         and not consts[ni].startswith("__pyarmor")) else None
                arg = f" {nm_!r}" if nm_ is not None else "  <name in stripped co_names/consts>"
                unresolved_global = (helper == 0x60 and nm_ is None)
                # confirmed object-field reraise noise (name reg traces to a decref'd object
                # field, never the const pool) -> drop, but only when otherwise unresolved
                # (a real except-block name resolves to a pool read and is kept).
                if nm_ is None and x.address in name_noise:
                    drop_noise = True
            elif helper == 0x40:
                # COMPARE_OP rhs — a value, may be a non-identifier const
                nm_ = resolve_name(identonly=False)
                arg = f" {nm_!r}" if nm_ is not None else ""
            elif helper == 0x30:
                a = imm.get("r8")
                arg = f" (argc={a})" if a is not None else ""
            elif helper == 0x58:
                m_ = imm.get("rcx")
                arg = f" ({BINMODE.get(m_, m_)})"
            elif helper == 0x98:
                a = imm.get("r8")
                arg = f" (nparams={a})" if a is not None else ""
            if not drop_noise:
                op_idx = emit(f"{opc:<15}{arg}", vload=unresolved_global)
                if helper in VALUE_OPS:
                    prod["rax"] = op_idx   # droppable if its result is later discarded
            last_str[0] = None; last_cidx[0] = None
        if in_main and x.id == X86_INS_RET:
            # the value in rax is returned -> its producing load is live, not dead
            d = prod.get("rax")
            if d is not None:
                used.add(d)
            emit("RETURN_VALUE   (ret)")
        if x.id == X86_INS_CALL:
            gotset.discard("rax"); regmap.pop("rax", None); imm.pop("r8", None); imm.pop("rcx", None)
            for r in ("rax", "rdi", "rsi", "rdx", "rcx", "r8", "r9", "r10", "r11"):
                pidx.pop(r, None); memoff.pop(r, None)  # caller-saved regs clobbered
            for r in ("rdi", "rsi", "rdx", "rcx", "r8", "r9", "r10", "r11"):
                prod.pop(r, None)  # arg regs clobbered; KEEP rax (holds the result)
        elif ops and ops[0].type == X86_OP_REG and x.id in (X86_INS_MOV, X86_INS_LEA, X86_INS_POP, X86_INS_XOR):
            dc = canon(ops[0].reg)
            if not isgl and not cached:
                gotset.discard(dc); regmap.pop(dc, None)
            if not is_gotptr:
                gotptr.discard(dc)
            if x.id in (X86_INS_LEA, X86_INS_POP, X86_INS_XOR):
                pidx.pop(dc, None); prod.pop(dc, None)  # MOV handled in dataflow block above
        if isgl and ops[0].type == X86_OP_REG:
            gotset.add(canon(ops[0].reg))
        if is_gotptr and ops[0].type == X86_OP_REG:
            gotptr.add(canon(ops[0].reg))

    # dead-load sweep: a LOAD_CONST / unresolved LOAD_GLOBAL whose result is never
    # consumed by a real op and never returned = PyArmor reraise noise -> drop. (The
    # only signal that separates reraise from real code without over-cutting.)
    for idx, rec in enumerate(records):
        if rec[2] and idx not in used:
            rec[1] = False

    # flush buffered records
    for text, alive, _ in records:
        if alive:
            P(f"    {pc[0]:>4}  {text}")
            pc[0] += 1


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
        name_idx, _ = _name_idx(ins, md, consts)
    except Exception:
        name_idx = {}

    def short(v):
        r = repr(v)
        return r if len(r) <= 46 else r[:43] + "..."

    # got0-base tracking (same robustness as the lifter: reg copies + stack spill/reload +
    # &got0 pointer deref) so every dispatch is recognised even inside loop bodies.
    gotset = set(); gotptr = set(); gotslots = set(); regmap = {}; slotmap = {}; memoff = {}; imm = {}
    for i, x in enumerate(ins):
        ops = x.operands; note = ""
        if i in poolread:
            note = f"; consts[{poolread[i]}] = {short(consts[poolread[i]])}"
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
def dump_bytecode(elf_path: str, das_path: str | None, out_path: str) -> int:
    """Lift every BCC fragment in *elf_path* to a bytecode-IR listing.

    Returns the number of fragments dumped.
    """
    d = open(elf_path, "rb").read()
    secs = _parse_sections(d)
    text, got, export = _locate(d, secs)
    frags, ends = _read_fragments(d, text, export)

    das_funcs = []
    if das_path and os.path.exists(das_path):
        das_funcs = _parse_das_bcc(open(das_path, encoding="utf-8", errors="replace").read())

    # decide 0x1a0 (STORE_ATTR vs BUILD_LIST) ONCE for the whole build: any int-status
    # (eax) return across all fragments proves STORE_ATTR; only an all-pointer build is
    # BUILD_LIST. Keeps every 0x1a0 in the dump consistently labelled.
    from capstone import Cs as _Cs, CS_ARCH_X86 as _A, CS_MODE_64 as _M
    _md = _Cs(_A, _M); _md.detail = True
    _CANON = {"eax": "rax", "ecx": "rcx", "edx": "rdx", "ebx": "rbx", "esi": "rsi", "edi": "rdi",
              "ebp": "rbp", "r8d": "r8", "r9d": "r9", "r10d": "r10", "r11d": "r11", "r12d": "r12",
              "r13d": "r13", "r14d": "r14", "r15d": "r15"}
    _canon = lambda r: _CANON.get(_md.reg_name(r), _md.reg_name(r))
    _S = _B = 0
    for _co, _end in zip((c for _, c in frags), ends):
        try:
            _s, _b = _op_1a0_signal(list(_md.disasm(d[_co:_end], _co)), _md, _canon)
            _S += _s; _B += _b
        except Exception:
            pass
    build_op_1a0 = "STORE_ATTR" if _S else ("BUILD_LIST" if _B else None)

    with open(out_path, "w", encoding="utf-8", errors="replace") as f:
        def P(s):
            f.write(s + "\n")
        P("# CPython bytecode-IR recovered from PyArmor BCC native fragments")
        P(f"# source ELF: {os.path.basename(elf_path)}   ({len(frags)} fragments)")
        P("# got0 offset -> opcode map recovered by Rosetta alignment; '?' = inferred.")
        P("# NOTE: linear op stream (no control-flow recovery yet); operands exact from .das consts.\n")
        for i, ((nm, co), end) in enumerate(zip(frags, ends)):
            fn = das_funcs[i] if i < len(das_funcs) else None
            if fn:
                objname, argnames, consts = fn
                hdr = f"{objname}({', '.join(argnames)})" if argnames else objname
                P(f"\n===== {hdr}   [{nm} @0x{co:x}]  consts={len(consts)} =====")
            else:
                consts = []
                P(f"\n===== {nm} @0x{co:x}  (no .das consts) =====")
            try:
                _lift(d, co, end, got, consts, P, op_1a0=build_op_1a0)
            except Exception as e:  # never abort the whole dump on one frag
                P(f"    <lift failed: {e}>")
    logger.info(f"Dumped BCC bytecode: {out_path} ({len(frags)} fragments)")
    return len(frags)


def dump_for_dest(dest_path: str) -> None:
    """Auto-dump any ``<dest>.1shot.bcc.*.elf`` to opcode-annotated assembly.

    Called from the pipeline after pycdc has written the ``.das``. Emits the native
    x86-64 with the got0 dispatch table + const pool resolved (``*.asm.txt``). The
    bytecode-IR lifter (``dump_bytecode``) is kept for direct use but not wired here
    yet — its name/cleanup heuristics still need work; the asm view is exact.
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
    ap = argparse.ArgumentParser(description="Dump CPython bytecode-IR from a PyArmor BCC native ELF")
    ap.add_argument("elf", help="path to *.1shot.bcc.<arch>.elf")
    ap.add_argument("--das", help="matching *.1shot.das (for const/arg names)", default=None)
    ap.add_argument("-o", "--out", help="output path", default=None)
    ap.add_argument("--asm", action="store_true",
                    help="dump opcode-annotated x86-64 assembly instead of bytecode-IR")
    a = ap.parse_args()
    das = a.das
    if das is None:
        guess = re.sub(r"\.1shot\.bcc\.[^.]+\.elf$", ".1shot.das", a.elf)
        das = guess if os.path.exists(guess) else None
    if a.asm:
        out = a.out or (a.elf[:-4] + ".asm.txt")
        n = dump_asm(a.elf, das, out)
    else:
        out = a.out or (a.elf[:-4] + ".bytecode.txt")
        n = dump_bytecode(a.elf, das, out)
    print(f"wrote {out} ({n} fragments)")


if __name__ == "__main__":
    _cli()
