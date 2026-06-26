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
    0x1a0: "BUILD_LIST",       # build list from N stack items
    0x1c0: "BUILD_SLICE",      # build slice (before BINARY_SUBSCR)
    0x038: "RETURN_VALUE",     # leave / return
    0x198: "LIST_APPEND",      # container add (listcomp append / MAP_ADD)
    0x190: "BUILD_MAP?",       # dict / comprehension accumulator
    0x050: "LOAD_FAST?",       # load local / temp
    0x128: "LEAVE?",           # frame teardown (paired near end)
    0x120: "LEAVE?",           # frame teardown
    0x150: "COMPREH?",         # comprehension scaffold
    0x158: "COMPREH?",
    0x160: "COMPREH?",
    0x088: "OP_0x088?",
}
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
    frags = []
    for j in range(0, export.size, 0x20):
        no, co, fl, z = struct.unpack_from("<QQQQ", d, export.off + j)
        if not (text.off <= co < text.off + text.size):
            continue
        if not (0 < no < len(d)):
            continue
        end = d.index(b"\x00", no)
        nm = d[no:end].decode("latin-1", "replace")
        if not nm.startswith("bcc_"):
            continue
        frags.append((nm, co))
    frags.sort(key=lambda x: x[1])
    text_end = text.off + text.size
    ends = [frags[i + 1][1] if i + 1 < len(frags) else text_end for i in range(len(frags))]
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


# ----------------------------------------------------------------------------- lifter
def _lift(d, co, end, got, consts, P):
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
    pc = [0]

    def short(v):
        s = repr(v)
        return s if len(s) <= 62 else s[:59] + "...'"

    def emit(s):
        P(f"    {pc[0]:>4}  {s}")
        pc[0] += 1

    for i, x in enumerate(ins):
        ops = x.operands
        isgl = (x.id == X86_INS_MOV and ops[1].type == X86_OP_MEM and ops[1].mem.base == X86_REG_RIP
                and (x.address + x.size + ops[1].mem.disp) == got)
        if x.id == X86_INS_MOV and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_IMM:
            imm[canon(ops[0].reg)] = ops[1].imm
        if x.id == X86_INS_MOV and ops[1].type == X86_OP_MEM and ops[1].mem.index != 0 and ops[1].mem.disp == 0x10:
            cbase.add(canon(ops[0].reg))
        cached = False
        if x.id == X86_INS_MOV and ops[1].type == X86_OP_MEM and ops[1].mem.index == 0 and canon(ops[1].mem.base) in gotset:
            regmap[canon(ops[0].reg)] = ops[1].mem.disp
            cached = True
        if x.id == X86_INS_MOV and ops[0].type == X86_OP_MEM and ops[1].type == X86_OP_REG and canon(ops[1].reg) in regmap:
            slotmap[x.op_str.split(",")[0].strip()] = regmap[canon(ops[1].reg)]
        if (not noise[i]) and not cached and x.id == X86_INS_MOV and ops[1].type == X86_OP_MEM and canon(ops[1].mem.base) in cbase and ops[1].mem.index == 0:
            off = ops[1].mem.disp
            if off >= 0x18 and (off - 0x18) % 8 == 0:
                ci = (off - 0x18) // 8
                if ci < len(consts):
                    val = consts[ci]
                    if isinstance(val, str):
                        last_str[0] = val
                    emit(f"LOAD_CONST   {ci:<3} {short(val)}")
        helper = None
        if x.id == X86_INS_CALL:
            op0 = ops[0]
            if op0.type == X86_OP_MEM and op0.mem.index == 0 and canon(op0.mem.base) in gotset:
                helper = op0.mem.disp
            elif op0.type == X86_OP_MEM and op0.mem.base != X86_REG_RIP and x.op_str.strip() in slotmap:
                helper = slotmap[x.op_str.strip()]
            elif op0.type == X86_OP_REG and canon(op0.reg) in regmap:
                helper = regmap[canon(op0.reg)]
        if (not noise[i]) and helper is not None:
            opc = OPC.get(helper, f"OP_{helper:#05x}")
            arg = ""
            if helper in (0x60, 0x180, 0x40) and last_str[0] is not None:
                arg = f" {last_str[0]!r}"
            elif helper == 0x30:
                a = imm.get("r8")
                arg = f" (argc={a})" if a is not None else ""
            elif helper == 0x58:
                m_ = imm.get("rcx")
                arg = f" ({BINMODE.get(m_, m_)})"
            elif helper == 0x98:
                a = imm.get("r8")
                arg = f" (nparams={a})" if a is not None else ""
            emit(f"{opc:<15}{arg}")
            last_str[0] = None
        if x.id == X86_INS_RET:
            emit("RETURN_VALUE   (ret)")
        if x.id == X86_INS_CALL:
            gotset.discard("rax"); regmap.pop("rax", None); imm.pop("r8", None); imm.pop("rcx", None)
        elif ops and ops[0].type == X86_OP_REG and x.id in (X86_INS_MOV, X86_INS_LEA, X86_INS_POP, X86_INS_XOR):
            dc = canon(ops[0].reg)
            if not isgl and not cached:
                gotset.discard(dc); regmap.pop(dc, None)
        if isgl and ops[0].type == X86_OP_REG:
            gotset.add(canon(ops[0].reg))


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
                _lift(d, co, end, got, consts, P)
            except Exception as e:  # never abort the whole dump on one frag
                P(f"    <lift failed: {e}>")
    logger.info(f"Dumped BCC bytecode: {out_path} ({len(frags)} fragments)")
    return len(frags)


def dump_for_dest(dest_path: str) -> None:
    """Auto-dump any ``<dest>.1shot.bcc.*.elf`` produced for *dest_path*.

    Called from the pipeline after pycdc has written the ``.das``.
    """
    elves = sorted(glob.glob(glob.escape(dest_path) + ".1shot.bcc.*.elf"))
    if not elves:
        return
    try:
        import capstone  # noqa: F401
    except ImportError:
        logger.warning("BCC bytecode dump skipped: capstone not installed (pip install capstone)")
        return
    das = dest_path + ".1shot.das"
    for elf in elves:
        if elf.endswith((".aarch64.elf", ".darwin-arm64.elf")):
            logger.warning(f"BCC dump: skipping non-x86 fragment {os.path.basename(elf)}")
            continue
        out = elf[:-4] + ".bytecode.txt"  # ...elf -> ...bytecode.txt
        try:
            dump_bytecode(elf, das, out)
        except Exception as e:
            logger.error(f"BCC bytecode dump failed for {os.path.basename(elf)}: {e}")


def _cli():
    import argparse
    ap = argparse.ArgumentParser(description="Dump CPython bytecode-IR from a PyArmor BCC native ELF")
    ap.add_argument("elf", help="path to *.1shot.bcc.<arch>.elf")
    ap.add_argument("--das", help="matching *.1shot.das (for const/arg names)", default=None)
    ap.add_argument("-o", "--out", help="output path", default=None)
    a = ap.parse_args()
    das = a.das
    if das is None:
        guess = re.sub(r"\.1shot\.bcc\.[^.]+\.elf$", ".1shot.das", a.elf)
        das = guess if os.path.exists(guess) else None
    out = a.out or (a.elf[:-4] + ".bytecode.txt")
    n = dump_bytecode(a.elf, das, out)
    print(f"wrote {out} ({n} fragments)")


if __name__ == "__main__":
    _cli()
