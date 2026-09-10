"""the runtime api struct of pyarmor BCC (9.x, win-x64).

slot 0 of the RW section gets a pointer to this struct from pyarmor_runtime
and the native code does everything via `call [api+off]`. >= 0xe0 are plain
CPython functions copied from the IAT, below that are pyarmor's own opcode
helpers. recovered from the init routine in pyarmor_runtime.pyd that fills
the struct, then double checked against what the code actually does with the
return values.

some of the helper names are mine, pyarmor doesn't export them.
"""

# offset -> (label, kind)   "c" = cpython, "h" = pyarmor helper
API = {
    0x08: ("memset", "h"),
    0x18: ("crt_thunk", "h"),
    0x20: ("BINARY_OP", "h"),
    0x28: ("BUILD", "h"),
    0x30: ("CALL", "h"),
    0x38: ("CHECK_ERROR", "h"),      # (mode): 1 = "is an exception set?", 3 = set RuntimeError if none
    0x40: ("COMPARE_OP", "h"),       # (_, op, left, right)
    0x48: ("nop_zero", "h"),
    0x50: ("EXC_FETCH", "h"),        # (&type, &value, &tb)   PyErr_Fetch
    0x58: ("FORMAT", "h"),           # (count, ...) count>0: join strings; 0: FORMAT_VALUE(value, conv, spec)
    0x60: ("GLOBAL", "h"),           # (_, name, mode)
    0x68: ("ERR_MKFUNC", "h"),       # raises NotImplementedError("op_mkfunc not available in bcc mode")
    0x70: ("FOR_ITER", "h"),         # (iterator) -> next or NULL (StopIteration swallowed)
    0x78: ("BIND_ARGS", "h"),        # (args, kwargs, ...) binds call arguments into the locals array
    0x80: ("RAISE", "h"),            # (_, exc, cause)
    0x88: ("EXC_RESTORE", "h"),      # (type, value, tb) re-raise a fetched exception, chaining __context__
    0x90: ("UNARY_OP", "h"),         # (obj, op) 0x1e neg, 0x20 pos, 0x1b invert
    0x98: ("UNPACK", "h"),           # (_, seq, n, out[])
    0xA0: ("MAKE_FUNCTION", "h"),
    0xA8: ("MAKE_CLOSURE", "h"),
    0xB0: ("SET_LINENO", "h"),       # (lineno) writes frame->f_lineno then CHECK_ERROR(1)
    0xB8: ("RUNTIME_CALL", "h"),     # PyThreadState_Get + _PyDict_GetItemWithError + _PyObject_FastCall
    0xE0: ("Py_None", "c"),
    0xE8: ("Py_True", "c"),
    0xF0: ("Py_False", "c"),
    0x100: ("PyBytes_AsStringAndSize", "c"),
    0x108: ("PyCell_Get", "c"),
    0x110: ("PyCell_New", "c"),
    0x118: ("PyCell_Set", "c"),
    0x120: ("PyErr_Clear", "c"),
    0x128: ("PyErr_Occurred", "c"),
    0x130: ("PyErr_SetObject", "c"),
    0x138: ("PyEval_GetGlobals", "c"),
    0x140: ("PyImport_ImportModule", "c"),
    0x148: ("PyImport_ImportModuleLevel", "c"),
    0x150: ("PyList_Append", "c"),
    0x158: ("PyList_New", "c"),
    0x160: ("PyObject_CallFunction", "c"),
    0x168: ("PyObject_CallFunctionObjArgs", "c"),
    0x170: ("PyObject_CallMethod", "c"),
    0x178: ("PyObject_DelItem", "c"),
    0x180: ("PyObject_GetAttr", "c"),
    0x188: ("PyObject_GetItem", "c"),
    0x190: ("PyObject_GetIter", "c"),
    0x198: ("PyObject_IsTrue", "c"),
    0x1A0: ("PyObject_SetAttr", "c"),
    0x1A8: ("PyObject_SetItem", "c"),
    0x1B0: ("PySet_Add", "c"),
    0x1B8: ("PySet_New", "c"),
    0x1C0: ("PySlice_New", "c"),
    0x1C8: ("PyTuple_GetItem", "c"),
    0x1D0: ("Py_DecRef", "c"),
    0x1D8: ("Py_IncRef", "c"),
}

# how many args the call actually eats (rcx, rdx, r8, r9, then stack)
# -1 = variadic, count comes from one of the args
ARITY = {
    "BINARY_OP": 3,
    "BUILD": -1,
    "CALL": -1,
    "CHECK_ERROR": 1,
    "COMPARE_OP": 4,
    "EXC_FETCH": 3,
    "FORMAT": -1,
    "RAISE": 3,
    "EXC_RESTORE": 3,
    "UNARY_OP": 2,
    "SET_LINENO": 1,
    "GLOBAL": 3,
    "FOR_ITER": 1,
    "BIND_ARGS": -1,
    "UNPACK": 4,
    "MAKE_FUNCTION": 3,
    "MAKE_CLOSURE": 4,
    "PyObject_GetAttr": 2,
    "PyObject_SetAttr": 3,
    "PyObject_GetItem": 2,
    "PyObject_SetItem": 3,
    "PyObject_DelItem": 2,
    "PyObject_GetIter": 1,
    "PyObject_IsTrue": 1,
    "PyObject_CallFunctionObjArgs": -1,
    "PyList_Append": 2,
    "PyList_New": 1,
    "PySet_Add": 2,
    "PySet_New": 1,
    "PySlice_New": 3,
    "PyTuple_GetItem": 2,
    "PyImport_ImportModule": 1,
    "PyImport_ImportModuleLevel": 5,
    "Py_IncRef": 1,
    "Py_DecRef": 1,
    "PyErr_Occurred": 0,
    "PyErr_Clear": 0,
    "PyEval_GetGlobals": 0,
    "PyCell_Get": 1,
    "PyCell_New": 1,
    "PyCell_Set": 2,
    "PyObject_CallFunction": -1,
    "PyObject_CallMethod": -1,
}

# not functions, just object pointers
DATA_SLOTS = {0xE0: "None", 0xE8: "True", 0xF0: "False"}

# BUILD: low 2 bits of arg0
BUILD_KIND = {0: "tuple", 1: "tuple", 2: "list", 3: "dict"}

# GLOBAL mode (arg 2). 1 = load (globals then builtins). a pointer sized value
# = store that object. other small ints exist in the helper but I never saw
# them in real code so not decoded. TODO
GLOBAL_MODE = {1: "LOAD_GLOBAL"}

# COMPARE_OP arg1. 0..5 go straight to PyObject_RichCompare (Py_LT..Py_GE),
# rest is handled in the helper
COMPARE_OPS = {0: "<", 1: "<=", 2: "==", 3: "!=", 4: ">", 5: ">=",
               6: "in", 7: "not in", 8: "is", 9: "is not", 10: "exception-match"}

UNARY_OPS = {0x1E: "-", 0x20: "+", 0x1B: "~"}

# FORMAT_VALUE conversion (arg2 when count==0). -1 shows up as 0xffffffff
# because it's passed as a 32-bit imm, keep both
FORMAT_CONV = {0: "", -1: "", 0xFFFFFFFF: "", 0x72: "!r", 0x73: "!s", 0x61: "!a"}

# BINARY_OP arg2, from the helper's jump table. the numbering is alphabetical
# by PyNumber_* name which is why there are holes (Add=7, And=8, ..., InPlace*)
# 75/76 matmul are separate at the end. ids missing below never showed up in
# any sample
BINARY_OPS = {
    7: "+",
    8: "&",
    12: "//",
    14: "+=",
    15: "&=",
    16: "//=",
    17: "<<=",
    18: "*=",
    19: "|=",
    20: "**=",
    21: "%=",
    22: ">>=",
    23: "-=",
    24: "/=",
    25: "^=",
    28: "<<",
    29: "*",
    31: "|",
    33: "**",
    34: "%",
    35: ">>",
    36: "-",
    37: "/",
    38: "^",
    75: "@",
    76: "@=",
}
