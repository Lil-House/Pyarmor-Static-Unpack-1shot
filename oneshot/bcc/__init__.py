"""Static analysis for the native part of pyarmor BCC mode (win-x64 only for now).

In BCC mode the .1shot.das stub is just a trampoline, the real function body
lives in the .1shot.bcc.win-x64.elf blob next to it. This package reads that
blob and lifts the functions back to something readable.

    python3 -m oneshot.bcc <path>
"""
