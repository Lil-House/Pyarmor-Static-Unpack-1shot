"""python3 -m oneshot.bcc /path/to/scripts [-o out_dir] [--lift-only]

For every <module>.1shot.bcc.win-x64.elf (needs the <module>.1shot.das next to
it for names / constants) writes:

    <module>.1shot.bcc.txt   lifted operation listing (one line per runtime call)
    <module>.1shot.bcc.py    python-ish reconstruction, one def per native function.
                             functions that don't parse are kept as a commented block

local variable names are gone in BCC output, you get v1, v2, ... instead.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import List

try:
    import capstone  # noqa: F401
except ImportError:
    sys.exit("oneshot.bcc needs capstone: pip install capstone")

from .elf import BccElf
from .emit import decompile_module
from .lift import Lifter, load_stubs

ELF_SUFFIX = ".1shot.bcc.win-x64.elf"


def find_blobs(path: str) -> List[str]:
    if os.path.isfile(path):
        return [path]
    found = []
    for dirpath, dirnames, names in os.walk(path):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        found += [os.path.join(dirpath, n) for n in names if n.endswith(ELF_SUFFIX)]
    return sorted(found)


def lift_module(elf_path: str, das_path: str) -> str:
    elf = BccElf(open(elf_path, "rb").read())
    stubs = load_stubs(elf, das_path if os.path.exists(das_path) else None)
    out: List[str] = []
    for f, stub in zip(elf.functions, stubs):
        title = f"{stub.qualname}({', '.join(stub.args[:stub.argcount])})" if stub else f.name
        out += ["=" * 78, title,
                f"  native {f.name} @ {f.start:#x} ({f.size} bytes)"
                + (f", nested in {f.parent}" if f.nested else "")]
        if stub and stub.docstring:
            out.append(f"  doc: {stub.docstring.strip()[:300]!r}")
        out += [""] + Lifter(elf, stub).lift(f) + [""]
        # if stub is None:
        #     print("no stub for", f.name, file=sys.stderr)
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python3 -m oneshot.bcc", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", help="directory already processed by shot.py, or one .elf")
    ap.add_argument("-o", "--output", help="write results here instead of in place")
    ap.add_argument("--lift-only", action="store_true",
                    help="only write the operation listing, skip source reconstruction")
    a = ap.parse_args(argv)

    blobs = find_blobs(a.path)
    if not blobs:
        print(f"no *{ELF_SUFFIX} under {a.path}", file=sys.stderr)
        return 1
    root = a.path if os.path.isdir(a.path) else os.path.dirname(a.path)
    total_ok = total = 0
    for elf_path in blobs:
        base = elf_path[: -len(ELF_SUFFIX)] if elf_path.endswith(ELF_SUFFIX) \
            else elf_path.rsplit(".", 1)[0]
        das_path = base + ".1shot.das"
        if a.output:
            base = os.path.join(a.output, os.path.relpath(base, root))
            os.makedirs(os.path.dirname(base) or ".", exist_ok=True)
        try:
            with open(base + ".1shot.bcc.txt", "w", encoding="utf-8") as fh:
                fh.write(lift_module(elf_path, das_path))
            if a.lift_only:
                print(f"{elf_path}: lifted")
                continue
            src, ok, tot = decompile_module(
                elf_path, das_path if os.path.exists(das_path) else None)
            with open(base + ".1shot.bcc.py", "w", encoding="utf-8") as fh:
                fh.write(src)
        except Exception as e:
            # don't let one bad blob kill the whole run
            print(f"{elf_path}: failed: {e}", file=sys.stderr)
            continue
        total_ok += ok
        total += tot
        print(f"{elf_path}: {ok}/{tot} functions reconstructed as valid Python")
    if total:
        print(f"total: {total_ok}/{total}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
