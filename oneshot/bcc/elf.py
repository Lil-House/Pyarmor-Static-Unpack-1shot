"""reader for the "ELF" pyarmor stuffs into the pyc in BCC mode.

it's ET_REL-ish but don't trust anything: 4 sections, no symtab, no relocs,
e_shstrndx points to nowhere. layout (so far, every sample I had):

  sec 0 (X)  code
  sec 1 (W)  slot table, slot 0 gets the api struct ptr from pyarmor_runtime
  sec 2 (S)  strings (function names, imported names)
  sec 3 (W)  function descriptors, 32 bytes each:
        u64 name_off   file offset into sec 2
        u64 code_off   file offset into sec 0
        u64 kind       always 1 ?
        u64 0          (no size! next descriptor = end)

nested defs are NOT in the table. the parent builds the descriptor at runtime
into 3 slots of sec 1:

    lea rax,[rip+name] ; mov [rip+slot],rax
    lea rax,[rip+code] ; mov [rip+slot+8],rax
    mov dword [rip+slot+16],1

and passes &slot to MAKE_CLOSURE/MAKE_FUNCTION. we pattern-match that.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from typing import Dict, List, Optional

_NESTED_DESC = re.compile(
    rb"\x48\x8d\x05(....)\x48\x89\x05(....)"        # lea rax,[rip+name]; mov [rip+slot],rax
    rb"\x48\x8d\x05(....)\x48\x89\x05(....)"        # lea rax,[rip+code]; mov [rip+slot+8],rax
    rb"\xc7\x05(....)\x01\x00\x00\x00", re.S)        # mov dword [rip+slot+16],1


@dataclass
class BccFunc:
    name: str
    start: int
    end: int
    parent: Optional[str] = None      # enclosing function, for nested bodies
    slot: Optional[int] = None        # section-1 slot holding its descriptor

    @property
    def nested(self) -> bool:
        return self.parent is not None

    @property
    def size(self) -> int:
        return self.end - self.start


@dataclass
class Section:
    stype: int
    flags: int
    addr: int
    offset: int
    size: int


class BccElf:
    def __init__(self, data: bytes):
        if not data.startswith(b"\x7fELF"):
            raise ValueError("not an ELF blob")
        self.data = data
        (_, self.etype, self.machine, _, _, _, shoff, _, _, _, _, shentsize,
         shnum, _) = struct.unpack_from("<16sHHIQQQIHHHHHH", data, 0)
        self.sections: List[Section] = []
        for i in range(shnum):
            (_, stype, flags, addr, offset, size, _, _, _,
             _) = struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize)
            self.sections.append(Section(stype, flags, addr, offset, size))

        self.text = self._pick(lambda s: s.flags & 0x4)
        rw = [s for s in self.sections if (s.flags & 0x3) == 0x3]
        self.strings = self._pick(lambda s: s.flags & 0x20)
        # two RW sections, the one that is 32*n and whose first rec points
        # into the string blob is the descriptor table, other is the slots
        self.symtab = None
        self.slots = None
        for s in rw:
            if s.size % 32 == 0 and s.size and self._looks_like_symtab(s):
                self.symtab = s
            else:
                self.slots = s
        if self.text is None or self.symtab is None:
            raise ValueError("unrecognised BCC layout")  # TODO other arches will end up here

        self.functions = self._read_functions()
        self.slot_func: Dict[int, str] = {}   # slot index -> nested function name
        self._read_nested()

    def _pick(self, pred):
        for s in self.sections:
            if pred(s):
                return s
        return None

    def _looks_like_symtab(self, s: Section) -> bool:
        name_off, code_off, kind, _ = struct.unpack_from("<QQQQ", self.data, s.offset)
        if self.strings is None:
            return False
        return (self.strings.offset <= name_off < self.strings.offset + self.strings.size
                and self.text.offset <= code_off < self.text.offset + self.text.size
                and kind == 1)

    def _cstr(self, off: int) -> str:
        end = self.data.index(b"\0", off)
        return self.data[off:end].decode("utf-8", "replace")

    def _read_functions(self) -> List[BccFunc]:
        out = []
        for i in range(self.symtab.size // 32):
            rec = self.symtab.offset + i * 32
            name_off, code_off, kind, _ = struct.unpack_from("<QQQQ", self.data, rec)
            if not name_off and not code_off:
                continue  # padding rec
            out.append(BccFunc(self._cstr(name_off), code_off, 0))
        self._set_ends(out)
        return out

    def _set_ends(self, funcs: List[BccFunc]):
        funcs.sort(key=lambda f: f.start)
        text_end = self.text.offset + self.text.size
        for i, f in enumerate(funcs):
            f.end = funcs[i + 1].start if i + 1 < len(funcs) else text_end

    def _in(self, s: Section, off: int) -> bool:
        return s.offset <= off < s.offset + s.size

    def _read_nested(self):
        found: List[BccFunc] = []
        for m in _NESTED_DESC.finditer(self.data, self.text.offset,
                                       self.text.offset + self.text.size):
            def rel(i: int, extra: int = 0) -> int:
                return m.start(i) + 4 + extra + struct.unpack("<i", m.group(i))[0]
            name_off, slot, code, slot8, slot16 = rel(1), rel(2), rel(3), rel(4), rel(5, 4)
            if not (self._in(self.strings, name_off) and self._in(self.text, code)
                    and self.slots is not None and self._in(self.slots, slot)
                    and slot8 == slot + 8 and slot16 == slot + 16):
                continue  # false positive of the regex, happens
            # print(hex(m.start()), self._cstr(name_off), hex(code), (slot - self.slots.offset) // 8)
            parent = next((f for f in self.functions if f.start <= code < f.end), None)
            if parent is None:
                continue
            idx = (slot - self.slots.offset) // 8
            found.append(BccFunc(self._cstr(name_off), code, 0, parent.name, idx))
            self.slot_func[idx] = found[-1].name
        if found:
            self.functions += found
            self._set_ends(self.functions)

    def code(self, f: BccFunc) -> bytes:
        return self.data[f.start:f.end]

    def imported_names(self) -> List[str]:
        blob = self.data[self.strings.offset:self.strings.offset + self.strings.size]
        return [x.decode("utf-8", "replace") for x in blob.split(b"\0") if x]
