// Auto-generated depyo lib declarations for the TypeScript path alias:
//   "@depyo/*": ["./node_modules/depyo/lib/*"]
// Source: https://github.com/skuznetsov/depyo.js @ 1093891
// Generated from lib/**/*.js declaration emit, then wrapped as ambient @depyo/* modules.

declare module "@depyo/BinaryReader" {
  export class BinaryReader {
    constructor(code: any)
    _reader: any
    _pc: number
    set pc(pos: number)
    get pc(): number
    get EOF(): boolean
    get Reader(): any
    readChar(): string
    readByte(): any
    readUInt16(): any
    readUInt16BE(): any
    readInt16(): any
    readInt16BE(): any
    readInt32(): any
    readInt32BE(): any
    readUInt32(): any
    readUInt32BE(): any
    readLong(): {
      low: any
      high: any
    }
    readLongBE(): {
      low: any
      high: any
    }
    readULong(): {
      low: any
      high: any
    }
    readULongBE(): {
      low: any
      high: any
    }
    readFloat(): any
    readFloatBE(): any
    readDouble(): any
    readDoubleBE(): any
    readBytes(length: any): any
    readString(length: any): any
  }
}

declare module "@depyo/OpCode" {
  export = OpCode
  class OpCode {
    constructor(opcode: any, name: any, opts: any)
    OpCodeID: number
    InstructionName: any
    HasArgument: boolean
    Argument: number
    HasName: boolean
    Name: any
    HasJumpRelative: boolean
    HasJumpAbsolute: boolean
    HasNegativeOffset: boolean
    HasConstant: boolean
    Constant: any
    ConstantObject: any
    HasCompare: boolean
    CompareOperator: any
    HasLocal: boolean
    LocalName: any
    HasBinaryOp: boolean
    BinaryOp: any
    HasIntrisic1: boolean
    Intrisic1: any
    HasIntrisic2: boolean
    Intrisic2: any
    HasFree: boolean
    FreeName: any
    Offset: number
    LineNo: number
    CodeBlock: any
    InstructionIndex: number
    Size: number
    get Prev(): any
    get Next(): any
    get JumpTarget(): number
    get Label(): any
    Clone(): OpCode
  }
}

declare module "@depyo/OpCodes" {
  export = OpCodes
  class OpCodes {
    static STOP_CODE: number
    static POP_TOP: number
    static ROT_TWO: number
    static ROT_THREE: number
    static DUP_TOP: number
    static DUP_TOP_TWO: number
    static UNARY_POSITIVE: number
    static UNARY_NEGATIVE: number
    static UNARY_NOT: number
    static UNARY_CONVERT: number
    static UNARY_CALL: number
    static UNARY_INVERT: number
    static BINARY_POWER: number
    static BINARY_MULTIPLY: number
    static BINARY_DIVIDE: number
    static BINARY_MODULO: number
    static BINARY_ADD: number
    static BINARY_SUBTRACT: number
    static BINARY_SUBSCR: number
    static BINARY_CALL: number
    static SLICE_0: number
    static SLICE_1: number
    static SLICE_2: number
    static SLICE_3: number
    static STORE_SLICE_0: number
    static STORE_SLICE_1: number
    static STORE_SLICE_2: number
    static STORE_SLICE_3: number
    static DELETE_SLICE_0: number
    static DELETE_SLICE_1: number
    static DELETE_SLICE_2: number
    static DELETE_SLICE_3: number
    static STORE_SUBSCR: number
    static DELETE_SUBSCR: number
    static BINARY_LSHIFT: number
    static BINARY_RSHIFT: number
    static BINARY_AND: number
    static BINARY_XOR: number
    static BINARY_OR: number
    static PRINT_EXPR: number
    static PRINT_ITEM: number
    static PRINT_NEWLINE: number
    static BREAK_LOOP: number
    static RAISE_EXCEPTION: number
    static LOAD_LOCALS: number
    static RETURN_VALUE: number
    static LOAD_GLOBALS: number
    static EXEC_STMT: number
    static BUILD_FUNCTION: number
    static POP_BLOCK: number
    static END_FINALLY: number
    static BUILD_CLASS: number
    static ROT_FOUR: number
    static NOP: number
    static LIST_APPEND: number
    static BINARY_FLOOR_DIVIDE: number
    static BINARY_TRUE_DIVIDE: number
    static INPLACE_FLOOR_DIVIDE: number
    static INPLACE_TRUE_DIVIDE: number
    static GET_LEN: number
    static MATCH_MAPPING: number
    static MATCH_SEQUENCE: number
    static MATCH_KEYS: number
    static NOT_TAKEN: number
    static COPY_DICT_WITHOUT_KEYS: number
    static STORE_MAP: number
    static INPLACE_ADD: number
    static INPLACE_SUBTRACT: number
    static INPLACE_MULTIPLY: number
    static INPLACE_DIVIDE: number
    static INPLACE_MODULO: number
    static INPLACE_POWER: number
    static GET_ITER: number
    static PRINT_ITEM_TO: number
    static PRINT_NEWLINE_TO: number
    static INPLACE_LSHIFT: number
    static INPLACE_RSHIFT: number
    static INPLACE_AND: number
    static INPLACE_XOR: number
    static INPLACE_OR: number
    static WITH_CLEANUP: number
    static WITH_CLEANUP_START: number
    static WITH_CLEANUP_FINISH: number
    static IMPORT_STAR: number
    static SETUP_ANNOTATIONS: number
    static YIELD_VALUE: number
    static LOAD_BUILD_CLASS: number
    static STORE_LOCALS: number
    static POP_EXCEPT: number
    static SET_ADD: number
    static YIELD_FROM: number
    static BINARY_MATRIX_MULTIPLY: number
    static INPLACE_MATRIX_MULTIPLY: number
    static GET_AITER: number
    static GET_ANEXT: number
    static BEFORE_ASYNC_WITH: number
    static GET_YIELD_FROM_ITER: number
    static GET_AWAITABLE: number
    static BEGIN_FINALLY: number
    static END_ASYNC_FOR: number
    static RERAISE: number
    static WITH_EXCEPT_START: number
    static LOAD_ASSERTION_ERROR: number
    static LIST_TO_TUPLE: number
    static CACHE: number
    static PUSH_NULL: number
    static PUSH_EXC_INFO: number
    static CHECK_EXC_MATCH: number
    static CHECK_EG_MATCH: number
    static BEFORE_WITH: number
    static RETURN_GENERATOR: number
    static ASYNC_GEN_WRAP: number
    static PREP_RERAISE_STAR: number
    static INTERPRETER_EXIT: number
    static END_FOR: number
    static END_SEND: number
    static RESERVED: number
    static BINARY_SLICE: number
    static STORE_SLICE: number
    static CLEANUP_THROW: number
    static PYC_HAVE_ARG: number
    static STORE_NAME_A: number
    static DELETE_NAME_A: number
    static UNPACK_TUPLE_A: number
    static UNPACK_LIST_A: number
    static UNPACK_ARG_A: number
    static STORE_ATTR_A: number
    static DELETE_ATTR_A: number
    static STORE_GLOBAL_A: number
    static DELETE_GLOBAL_A: number
    static ROT_N_A: number
    static UNPACK_VARARG_A: number
    static LOAD_CONST_A: number
    static LOAD_NAME_A: number
    static BUILD_TUPLE_A: number
    static BUILD_LIST_A: number
    static BUILD_MAP_A: number
    static LOAD_ATTR_A: number
    static COMPARE_OP_A: number
    static IMPORT_NAME_A: number
    static IMPORT_FROM_A: number
    static ACCESS_MODE_A: number
    static JUMP_FORWARD_A: number
    static JUMP_IF_FALSE_A: number
    static JUMP_IF_TRUE_A: number
    static JUMP_ABSOLUTE_A: number
    static FOR_LOOP_A: number
    static LOAD_LOCAL_A: number
    static LOAD_GLOBAL_A: number
    static SET_FUNC_ARGS_A: number
    static SETUP_LOOP_A: number
    static SETUP_EXCEPT_A: number
    static SETUP_FINALLY_A: number
    static RESERVE_FAST_A: number
    static LOAD_FAST_A: number
    static STORE_FAST_A: number
    static DELETE_FAST_A: number
    static GEN_START_A: number
    static SET_LINENO_A: number
    static STORE_ANNOTATION_A: number
    static RAISE_VARARGS_A: number
    static CALL_FUNCTION_A: number
    static MAKE_FUNCTION_A: number
    static MAKE_FUNCTION: number
    static BUILD_SLICE_A: number
    static CALL_FUNCTION_VAR_A: number
    static CALL_FUNCTION_KW_A: number
    static CALL_FUNCTION_VAR_KW_A: number
    static CALL_FUNCTION_EX_A: number
    static UNPACK_SEQUENCE_A: number
    static FOR_ITER_A: number
    static DUP_TOPX_A: number
    static BUILD_SET_A: number
    static JUMP_IF_FALSE_OR_POP_A: number
    static JUMP_IF_TRUE_OR_POP_A: number
    static POP_JUMP_IF_FALSE_A: number
    static POP_JUMP_IF_TRUE_A: number
    static CONTINUE_LOOP_A: number
    static MAKE_CLOSURE_A: number
    static LOAD_CLOSURE_A: number
    static LOAD_DEREF_A: number
    static STORE_DEREF_A: number
    static DELETE_DEREF_A: number
    static EXTENDED_ARG_A: number
    static SETUP_WITH_A: number
    static SET_ADD_A: number
    static MAP_ADD_A: number
    static UNPACK_EX_A: number
    static LIST_APPEND_A: number
    static LOAD_CLASSDEREF_A: number
    static MATCH_CLASS_A: number
    static BUILD_LIST_UNPACK_A: number
    static BUILD_MAP_UNPACK_A: number
    static BUILD_MAP_UNPACK_WITH_CALL_A: number
    static BUILD_TUPLE_UNPACK_A: number
    static BUILD_SET_UNPACK_A: number
    static SETUP_ASYNC_WITH_A: number
    static FORMAT_VALUE_A: number
    static BUILD_CONST_KEY_MAP_A: number
    static BUILD_STRING_A: number
    static BUILD_TUPLE_UNPACK_WITH_CALL_A: number
    static LOAD_METHOD_A: number
    static CALL_METHOD_A: number
    static CALL_FINALLY_A: number
    static POP_FINALLY_A: number
    static IS_OP_A: number
    static CONTAINS_OP_A: number
    static RERAISE_A: number
    static JUMP_IF_NOT_EXC_MATCH_A: number
    static LIST_EXTEND_A: number
    static SET_UPDATE_A: number
    static DICT_MERGE_A: number
    static DICT_UPDATE_A: number
    static SWAP_A: number
    static POP_JUMP_FORWARD_IF_FALSE_A: number
    static POP_JUMP_FORWARD_IF_TRUE_A: number
    static COPY_A: number
    static BINARY_OP_A: number
    static SEND_A: number
    static POP_JUMP_FORWARD_IF_NOT_NONE_A: number
    static POP_JUMP_FORWARD_IF_NONE_A: number
    static GET_AWAITABLE_A: number
    static JUMP_BACKWARD_NO_INTERRUPT_A: number
    static MAKE_CELL_A: number
    static JUMP_BACKWARD_A: number
    static COPY_FREE_VARS_A: number
    static RESUME_A: number
    static PRECALL_A: number
    static CALL_A: number
    static KW_NAMES_A: number
    static POP_JUMP_BACKWARD_IF_NOT_NONE_A: number
    static POP_JUMP_BACKWARD_IF_NONE_A: number
    static POP_JUMP_BACKWARD_IF_FALSE_A: number
    static POP_JUMP_BACKWARD_IF_TRUE_A: number
    static RETURN_CONST_A: number
    static LOAD_FAST_CHECK_A: number
    static POP_JUMP_IF_NOT_NONE_A: number
    static POP_JUMP_IF_NONE_A: number
    static LOAD_SUPER_ATTR_A: number
    static LOAD_FAST_AND_CLEAR_A: number
    static YIELD_VALUE_A: number
    static CALL_INTRINSIC_1_A: number
    static CALL_INTRINSIC_2_A: number
    static LOAD_FROM_DICT_OR_GLOBALS_A: number
    static LOAD_FROM_DICT_OR_DEREF_A: number
    static INSTRUMENTED_NOT_TAKEN_A: number
    static INSTRUMENTED_POP_ITER_A: number
    static INSTRUMENTED_END_ASYNC_FOR_A: number
    static INSTRUMENTED_CALL_KW_A: number
    static INSTRUMENTED_LOAD_SUPER_ATTR_A: number
    static INSTRUMENTED_POP_JUMP_IF_NONE_A: number
    static INSTRUMENTED_POP_JUMP_IF_NOT_NONE_A: number
    static INSTRUMENTED_RESUME_A: number
    static INSTRUMENTED_CALL_A: number
    static INSTRUMENTED_RETURN_VALUE_A: number
    static INSTRUMENTED_YIELD_VALUE_A: number
    static INSTRUMENTED_CALL_FUNCTION_EX_A: number
    static INSTRUMENTED_JUMP_FORWARD_A: number
    static INSTRUMENTED_JUMP_BACKWARD_A: number
    static INSTRUMENTED_RETURN_CONST_A: number
    static INSTRUMENTED_FOR_ITER_A: number
    static INSTRUMENTED_POP_JUMP_IF_FALSE_A: number
    static INSTRUMENTED_POP_JUMP_IF_TRUE_A: number
    static INSTRUMENTED_END_FOR_A: number
    static INSTRUMENTED_END_SEND_A: number
    static INSTRUMENTED_INSTRUCTION_A: number
    static INSTRUMENTED_LINE_A: number
    static CALL_INTRINSIC_1: number
    static CALL_INTRINSIC_2: number
    static CALL_INTRINSIC_1A: number
    static CALL_INTRINSIC_2A: number
    static EXIT_INIT_CHECK: number
    static FORMAT_SIMPLE: number
    static FORMAT_WITH_SPEC: number
    static TO_BOOL: number
    static BUILD_TEMPLATE: number
    static LOAD_FAST_BORROW_A: number
    static LOAD_SMALL_INT_A: number
    static LOAD_FAST_LOAD_FAST_A: number
    static STORE_FAST_LOAD_FAST_A: number
    static SET_FUNCTION_ATTRIBUTE_A: number
    static POP_ITER: number
    static WITH_EXCEPT_START_A: number
    static END_ASYNC_FOR_A: number
    static POP_BLOCK_A: number
    static CALL_FUNCTION_EX: number
    static CALL_KW_A: number
    static CONVERT_VALUE_A: number
    static JUMP_A: number
    static JUMP_NO_INTERRUPT_A: number
    static LOAD_COMMON_CONSTANT_A: number
    static LOAD_FAST_BORROW_LOAD_FAST_BORROW_A: number
    static LOAD_SPECIAL_A: number
    static SETUP_CLEANUP_A: number
    static STORE_FAST_MAYBE_NULL_A: number
    static STORE_FAST_STORE_FAST_A: number
    static ANNOTATIONS_PLACEHOLDER_A: number
    static BUILD_INTERPOLATION_A: number
    static ENTER_EXECUTOR_A: number
    static LOAD_SUPER_METHOD_A: number
    static LOAD_ZERO_SUPER_ATTR_A: number
    static LOAD_ZERO_SUPER_METHOD_A: number
    static TRACE_RECORD_A: number
    static CompareOpNames: string[]
    OpCodeList: any[]
    Instructions: any[]
    CurrentInstructionIndex: number
    get HasInstructionsToProcess(): boolean
    CodeObject: any[]
    get Current(): any
    GetOpCodeID(code: any, offset: any): any
    ReadExtendedArg(code: any, opOffset: any): any[]
    SetupByteCode(co: any): void
    CanGoNext(offset?: number): boolean
    GoNext(offset?: number): boolean
    GoToOffset(offset: any): boolean
    MoveBack(): string
    GetNextInstruction(offset?: number): any
    get Prev(): any
    get Next(): any
    PeekNextInstruction(position?: number): any
    PeekInstructionAt(position: any): any
    PeekInstructionAtOffset(offset: any): any
    PeekInstructionBeforeOffset(offset: any, backOffset?: number): any
    get LastOffset(): any
    GetIndexByOffset(offset: any): number
    GetIndexByOpCode(opCodeID: any): number
    GetOpCodeByID(opCodeID: any, fromOffset?: number, toOffset?: number): any
    GetOpCodeByName(opCodeName: any, fromOffset?: number, toOffset?: number): any
    GetOffsetByOpCode(opCodeID: any, fromOffset?: number, toOffset?: number): any
    GetReversedOffsetByOpCode(opCodeID: any, startOffset?: number, endOffset?: number): any
    GetOffsetByOpCodeName(opName: any): any
    GetBackOffsetByOpCodeName(opName: any): any
    GetLineOffsetRangeForOffset(offset: any): any[]
    CountSpecificOpCodes(opCodes: any, offset?: number, endOffset?: number): number
    CheckIfOpCodesExistsInLine(opCodes: any, startOffset: any, endOffset: any): boolean
    DOMINATORS: number[]
    FindEndOfBlock(originalOffset: any, currentOffset?: number): any[]
    extractImportNames(fromlist: any, callback: any): void
  }
}

declare module "@depyo/PycDecompiler" {
  export = PycDecompiler
  class PycDecompiler {
    static opCodeHandlers: {}
    static setupHandlers(): void
    constructor(obj: any)
    cleanBuild: boolean
    errors: any[]
    object: any
    code: any
    /**
     * Debug logging helper - only logs if --debug flag is set
     * @param {string} message - Debug message to log
     */
    debug(message: string): void
    blocks: any[]
    unpack: number
    starPos: number
    skipNextJump: boolean
    else_pop: boolean
    variable_annotations: any
    need_try: any
    defBlock: any
    curBlock: any
    dataStack: any[]
    handlers: {}
    unreachableUntil: number
    currentMatch: any
    matchSubject: any
    inMatchPattern: boolean
    currentCase: any
    matchParentBlock: any
    patternOps: any[]
    potentialMatchSubject: any
    matchCandidateStart: number
    lastLoadOffset: number
    caseBodyStartIndex: number
    matchPreNodesStart: number
    pendingConditionalExprs: any[]
    OpCodes: any
    activeExceptionStarts: Set<any>
    inExceptionTableHandler: boolean
    maxExceptionHandlerEnd: number
    decompile(): AST.ASTNodeList
    foldLambdaConditional(body: any): void
    append_to_chain_store(chainStore: any, item: any): void
    enrichGenericAnnotations(root: any): void
    checkIfExpr(): void
    maybeCompleteConditionalExpr(): void
    closeEndedBlocks(): void
    ensureExceptionTableBlocks(): void
    _withExceptRanges: Set<any>
    findExceptionHandlerEnd(offset: any): number
    statements(): AST.ASTNodeList
    exceptionHandlerOffsets: Set<any>
    appendExceptionExprs: boolean
    transformExceptionGroups(root: any): void
    mergeOrphanedEgHandlers(root: any): boolean
    tryConvertExceptStar(block: any): void
    isExceptStarPattern(block: any): boolean
    removeEgHelperArtifacts(node: any): void
    flattenNestedExcepts(root: any): void
    cleanupExceptBlocks(node: any): void
    pruneEmptyExcepts(root: any): void
    isPrepReraiseBlock(block: any): boolean
    isEgCleanupElseBlock(block: any, prev: any): boolean
    isEgCleanupNode(node: any, aliasName: any): boolean
    rewriteClassDefinitions(root: any): void
    _collectStatementNodes(container: any): any[]
    _rewriteClassDefsInNodes(nodes: any, hasDataclass: any, visited: any): void
    _maybeRewriteClassStore(node: any, hasDataclass: any): void
    isDecoratedClassCall(call: any): boolean
    _buildDecoratorExpr(call: any): any
    _childContainers(node: any): any[][]
    isPlainClassCall(call: any): boolean
    isClassCallWithOnlyKwargs(call: any): boolean
    astHasDataclassImport(root: any): boolean
    cleanupClassBody(classNode: any): void
    isSyntheticClassAssignment(node: any): boolean
    removeNullSentinelComparisons(root: any): void
    removeDuplicateReturns(root: any): void
    cleanupExcMatchArtifacts(root: any): void
    cleanupPre311ExceptAsArtifacts(root: any): void
    hoistNestedExceptBlocks(root: any): void
    dedupeExceptHandlers(root: any): void
    pruneNullSentinels(nodes: any, visited?: Set<any>): void
    isNullSentinelBlock(node: any): boolean
    wrapFunctionExceptionGroups(root: any): void
    rewriteExceptionGroupsInList(listNode: any): void
    rewriteGenericWrappers(root: any): void
    isExceptStarBlock(node: any): boolean
    isPlainExceptBlock(node: any): boolean
    isEgHoistableSetupNode(node: any): boolean
    /**
     * Recursively checks if a block ends with a terminating keyword (break/continue/return)
     * Used to prevent generating additional continue statements after breaks in nested blocks
     */
    hasTerminatingKeyword(block: any): any
    /**
     * Look ahead from current COPY after LOAD to detect match pattern
     * Strategy: Find next POP_JUMP_IF_FALSE, check if its target is another COPY
     * This confirms match/case pattern before first case is processed
     */
    lookAheadForMatchPattern(): boolean
  }
  import AST = require("@depyo/ast/ast_node")
}

declare module "@depyo/PycDisassembler" {
  export = PycDisassembler
  class PycDisassembler {
    static Disassemble(reader: any, obj: any, parentPrefix: any): string
  }
}

declare module "@depyo/PycReader" {
  export class PycReader {
    static LoadError: {
      new (
        msg: any,
        filename: any,
        pc: any
      ): {
        FileName: any
        position: number
        name: string
        message: string
        stack?: string
        cause?: unknown
      }
    }
    static ResolveVersionTag(tag: any): any
    static ListSupportedVersions(desc?: boolean): any[]
    static GuessVersion(buffer: any): any
    static ScanMarshalCandidates(buffer: any): {
      versionInfo: any
      score: number
      remaining: number
      unknown: number
      total: number
      unknownRatio: number
    }[]
    static CountUnknownOpcodes(
      codeObject: any,
      reader: any,
      opCodeList: any
    ): {
      unknown: number
      total: number
    }
    static TryParseMarshal(
      buffer: any,
      versionInfo: any
    ): {
      score: number
      remaining: number
      unknown: number
      total: number
      unknownRatio: number
    }
    static ConvertBytesToString(bytes: any): any
    static DumpObject(obj: any, level: any): string
    static GetMethodParametersString(codeObject: any): string
    constructor(data: any, options?: {})
    Strings: any[]
    Objects: any[]
    m_rdr: any
    m_filename: any
    m_version: any
    get Reader(): any
    get OpCodes(): any
    ReadObject(): any
    ReadString(size: any): any
    ReadCodeObject(): PythonCodeObject
    ParseExceptionTable(exceptTableObject: any): {
      start: number
      end: number
      target: number
      depth: number
      lasti: number
    }[]
    UnpackLineNumbers(codeObject: any): void
    getInstructionWordSize(): 1 | 2
    splitLocalsPlus(
      localsPlusNames: any,
      localsPlusKinds: any
    ): {
      locals: any[]
      cellVars: any[]
      freeVars: any[]
    }
    scanVarint(
      buffer: any,
      offset: any
    ): {
      value: number
      next: any
    }
    scanSignedVarint(
      buffer: any,
      offset: any
    ): {
      value: number
      next: any
    }
    getLineDeltaFromEntry(buffer: any, offset: any): number
    advanceLineTableOffset(buffer: any, offset: any): any
    UnpackNewLineNumbers(codeObject: any): void
    versionCompare(major: any, minor: any): number
  }
  import { PythonCodeObject } from "@depyo/PythonObject"
}

declare module "@depyo/PycResult" {
  export = PycResult
  class PycResult {
    constructor(lines: any, doNotIndent?: boolean)
    result: any[]
    indent: number
    doNotIndent: boolean
    get length(): number
    get last(): any
    get hasResult(): boolean
    increaseIndent(): void
    decreaseIndent(): void
    clear(): void
    add(line: any): void
    lastLineAppend(data: any, shouldTrim?: boolean): void
    chop(suffix: any): void
    toString(): string
  }
}

declare module "@depyo/PythonObject" {
  export class PythonObject {
    constructor(class_name: any, value: any)
    ClassName: any
    Value: any
    add(po: any): void
    get length(): any
    toReprString(): any
    toString(): any
  }
  export class PythonCodeObject extends PythonObject {
    ClassName: string
    ArgCount: number
    PosOnlyArgCount: number
    KWOnlyArgCount: number
    NumLocals: number
    StackSize: number
    Flags: number
    Code: any
    Consts: any[]
    Names: any[]
    VarNames: any[]
    FreeVars: any[]
    CellVars: any[]
    FileName: any
    Name: any
    FirstLineNo: number
    LineNoTab: any[]
    LineNoTabObject: any
    ExceptionTable: any
    Methods: any[]
    SourceCode: any
    FuncParams: any
    FuncDecos: any
    FuncName: any
    ASTTree: any[]
    Globals: Set<any>
    CachedLineNo: number
    getLineNumber(offset: any, isVer310?: boolean): number
  }
}

declare module "@depyo/Unpickle" {
  const _empty: {}
  export = _empty
}

declare module "@depyo/ast/ast_node" {
  export class ASTNode {
    static calculateSpacing(prevNode: any, node: any): number
    static renderList(list: any, openBracket: any, closeBracket: any, callback: any): PycResult
    m_lineNo: number
    m_prevSibling: any
    m_nextSibling: any
    m_skip: boolean
    set line(lineNo: number)
    get line(): number
    get lastLine(): number
    set prevSibling(value: any)
    get prevSibling(): any
    set nextSibling(value: any)
    get nextSibling(): any
    set skip(value: boolean)
    get skip(): boolean
    codeFragment(): any
    toASTString(): string
  }
  export class ASTNone extends ASTNode {
    constructor(override: any)
    m_override: any
    codeFragment(): any
  }
  export class ASTLocals extends ASTNode {
    codeFragment(): any
  }
  export class ASTNodeList extends ASTNode {
    constructor(nodes: any)
    m_list: any[]
    m_isModuleLevel: boolean
    get list(): any[]
    get line(): any
    get last(): any
    get lastLine(): any
    set isModuleLevel(value: boolean)
    get isModuleLevel(): boolean
    emptyBlock(): boolean
    codeFragment(): any
    isEgCleanupElse(): any
    requiresModuleSpacing(prevNode: any, node: any): boolean
  }
  export class ASTChainStore extends ASTNodeList {
    constructor(nodes: any, src: any)
    m_src: any
    get source(): any
    set line(value: any)
    get line(): any
    append(element: any): void
    codeFragment(): any
    shouldSkipEgCleanupBlock(): boolean
  }
  export class ASTObject extends ASTNode {
    constructor(op: any)
    m_obj: any
    set object(value: any)
    get object(): any
    codeFragment(): any
  }
  export class ASTUnary extends ASTNode {
    static UnaryOp: {
      Positive: number
      Negative: number
      Invert: number
      Not: number
      Await: number
    }
    static UnaryOpString: string[]
    constructor(operand: any, op: any)
    m_op: any
    m_operand: any
    get op(): any
    get operand(): any
    codeFragment(): any
  }
  export class ASTBinary extends ASTNode {
    static BinOp: {
      Attr: number
      Power: number
      Multiply: number
      Divide: number
      FloorDivide: number
      Modulo: number
      Add: number
      Subtract: number
      LeftShift: number
      RightShift: number
      And: number
      Xor: number
      Or: number
      LogicalAnd: number
      LogicalOr: number
      MatrixMultiply: number
      InplaceAdd: number
      InplaceSubtract: number
      InplaceMultiply: number
      InplaceDivide: number
      InplaceModulo: number
      InplacePower: number
      InplaceLeftShift: number
      InplaceRightShift: number
      InplaceAnd: number
      InplaceXor: number
      InplaceOr: number
      InplaceFloorDivide: number
      InplaceMatrixMultiply: number
      InvalidOp: number
    }
    static from_opcode(opcode: any): any
    static from_binary_op(operand: any): number
    constructor(left: any, right: any, op: any)
    m_op: any
    m_left: any
    m_right: any
    get left(): any
    get right(): any
    get op(): any
    set line(value: any)
    get line(): any
    get lastLine(): any
    get isInplace(): boolean
    op_str(): string
    codeFragment(): any
  }
  export class ASTCompare extends ASTBinary {
    static CompareOp: {
      Less: number
      LessEqual: number
      Equal: number
      NotEqual: number
      Greater: number
      GreaterEqual: number
      In: number
      NotIn: number
      Is: number
      IsNot: number
      Exception: number
      Bad: number
    }
    codeFragment(): any
  }
  export class ASTSlice extends ASTBinary {
    static SliceOp: {
      Slice0: number
      Slice1: number
      Slice2: number
      Slice3: number
    }
    codeFragment(): any
  }
  export class ASTStore extends ASTNode {
    constructor(src: any, dest: any)
    m_src: any
    m_dest: any
    m_decorators: any[]
    set src(value: any)
    get src(): any
    set dest(value: any)
    get dest(): any
    set decorators(value: any[])
    get decorators(): any[]
    addDecorator(decorator: any): void
    codeFragment(): any
    extractAnnotationFromDefault(argName: any, defaultNode: any): any
    extractAnnotationKey(node: any): any
    renderAnnotationValue(node: any): any
  }
  export class ASTReturn extends ASTNode {
    static RetType: {
      Return: number
      Yield: number
      YieldFrom: number
    }
    constructor(value: any, rettype?: number)
    m_value: any
    m_rettype: number
    m_inlambda: boolean
    get value(): any
    get rettype(): number
    set inLambda(value: boolean)
    get inLambda(): boolean
    codeFragment(): any
  }
  export class ASTNamedExpr extends ASTNode {
    constructor(target: any, value: any)
    m_target: any
    m_value: any
    m_requireParens: boolean
    get target(): any
    get value(): any
    set requireParens(value: boolean)
    get requireParens(): boolean
    codeFragment(): any
  }
  export class ASTName extends ASTNode {
    constructor(name: any)
    m_name: any
    set name(value: any)
    get name(): any
    codeFragment(): any
  }
  export class ASTDelete extends ASTNode {
    constructor(value: any, rettype: any)
    m_value: any
    get value(): any
    codeFragment(): any
  }
  export class ASTFunction extends ASTNode {
    static CodeFlags: {
      CO_OPTIMIZED: number
      CO_NEWLOCALS: number
      CO_VARARGS: number
      CO_VARKEYWORDS: number
      CO_NESTED: number
      CO_GENERATOR: number
      CO_NOFREE: number
      CO_COROUTINE: number
      CO_ITERABLE_COROUTINE: number
      CO_ASYNC_GENERATOR: number
      CO_GENERATOR_ALLOWED: number
      CO_FUTURE_DIVISION: number
      CO_FUTURE_ABSOLUTE_IMPORT: number
      CO_FUTURE_WITH_STATEMENT: number
      CO_FUTURE_PRINT_FUNCTION: number
      CO_FUTURE_UNICODE_LITERALS: number
      CO_FUTURE_BARRY_AS_BDFL: number
      CO_FUTURE_GENERATOR_STOP: number
    }
    constructor(code: any, defargs?: any[], kwdefargs?: any[])
    m_code: any
    m_defargs: any
    m_kwdefargs: any
    m_decorators: any[]
    m_annotations: {}
    m_typeParams: any[]
    get code(): any
    get defargs(): any
    get kwdefargs(): any
    get line(): any
    get lastLine(): any
    add_decorator(name: any): void
    get decorators(): any[]
    set annotations(map: {})
    get annotations(): {}
    set typeParams(params: any[])
    get typeParams(): any[]
    codeFragment(): any
  }
  export class ASTClass extends ASTNode {
    constructor(code: any, bases: any, name: any)
    m_code: any
    m_bases: any
    m_name: any
    m_typeParams: any[]
    m_kwargs: any[]
    m_decorators: any[]
    add_decorator(decorator: any): void
    get decorators(): any[]
    get code(): any
    get bases(): any
    get name(): any
    set kwargs(value: any[])
    get kwargs(): any[]
    set typeParams(params: any[])
    get typeParams(): any[]
    get line(): any
    get lastLine(): any
    codeFragment(): any
  }
  export class ASTCall extends ASTNode {
    constructor(func: any, pparams: any, kwparams: any)
    m_func: any
    m_pparams: any
    m_kwparams: any
    m_var: any
    m_kw: any
    get func(): any
    get pparams(): any
    get kwparams(): any
    set var(value: any)
    get var(): any
    set kw(value: any)
    get kw(): any
    get hasVar(): boolean
    get hasKw(): boolean
    codeFragment(): any
  }
  export class ASTImport extends ASTNode {
    constructor(name: any, fromlist: any, alias?: any)
    m_name: any
    m_alias: any
    m_stores: any[]
    m_fromlist: any
    get name(): any
    set alias(alias: any)
    get alias(): any
    get stores(): any[]
    get fromlist(): any
    add_store(store: any): void
    codeFragment(): any
  }
  export class ASTTuple extends ASTNode {
    constructor(values: any)
    m_values: any[]
    m_requireParens: boolean
    get values(): any[]
    set requireParens(value: boolean)
    get requireParens(): boolean
    add(name: any): void
    codeFragment(): any
  }
  export class ASTList extends ASTNode {
    constructor(values: any)
    m_values: any[]
    get values(): any[]
    get line(): any
    get lastLine(): any
    codeFragment(): any
  }
  export class ASTSet extends ASTNode {
    constructor(values: any)
    m_values: any[]
    get values(): any[]
    get line(): any
    get lastLine(): any
    add(value: any): void
    codeFragment(): any
  }
  export class ASTMap extends ASTNode {
    constructor(values: any)
    m_values: any[]
    get values(): any[]
    get lastLine(): any
    add(key: any, value: any): void
    codeFragment(): any
  }
  export class ASTMapUnpack extends ASTNode {
    constructor(items: any)
    m_items: any[]
    get items(): any[]
    codeFragment(): any
  }
  export class ASTKwNamesMap extends ASTNode {
    constructor(values: any)
    m_values: any[]
    get values(): any[]
    get lastLine(): any
    add(key: any, value: any): void
    codeFragment(): any
  }
  export class ASTConstMap extends ASTNode {
    constructor(keys: any, values: any)
    m_keys: {}
    m_values: {}
    get values(): {}
    get keys(): {}
    get lastLine(): any
    codeFragment(): any
  }
  export class ASTSubscr extends ASTNode {
    constructor(name: any, key: any)
    m_name: any
    m_key: any
    get name(): any
    get key(): any
    get lastLine(): any
    codeFragment(): any
  }
  export class ASTPrint extends ASTNode {
    constructor(value: any, stream: any)
    m_values: any[]
    m_stream: any
    m_eol: boolean
    get values(): any[]
    get stream(): any
    set eol(eol: boolean)
    get eol(): boolean
    get lastLine(): any
    add(value: any): void
    codeFragment(): any
  }
  export class ASTConvert extends ASTNode {
    constructor(name: any)
    m_name: any
    get name(): any
    codeFragment(): any
  }
  export class ASTKeyword extends ASTNode {
    static Word: {
      Pass: number
      Break: number
      Continue: number
    }
    constructor(key: any)
    m_key: any
    get key(): any
    get word(): string
    codeFragment(): any
  }
  export class ASTRaise extends ASTNode {
    constructor(params: any, fromClause?: boolean)
    m_params: any[]
    m_fromClause: boolean
    get params(): any[]
    get lastLine(): any
    codeFragment(): any
  }
  export class ASTExec extends ASTNode {
    constructor(stmt: any, glob: any, loc: any)
    m_stmt: any
    m_glob: any
    m_loc: any
    get statement(): any
    get globals(): any
    get locals(): any
    codeFragment(): any
  }
  export class ASTBlock extends ASTNode {
    static BlockType: {
      Main: number
      If: number
      Else: number
      Elif: number
      Try: number
      Container: number
      Except: number
      Finally: number
      While: number
      For: number
      With: number
      AsyncFor: number
      AsyncWith: number
    }
    constructor(blockType: any, start?: number, end?: number, inited?: number)
    m_blockType: number
    m_nodes: any[]
    m_start: number
    m_end: number
    m_inited: number
    m_isExceptStar: boolean
    get blockType(): number
    get nodes(): any[]
    set isExceptStar(value: boolean)
    get isExceptStar(): boolean
    get size(): number
    set start(value: number)
    get start(): number
    set end(value: number)
    get end(): number
    get inited(): number
    set line(lineNo: any)
    get line(): any
    get lastLine(): any
    get type_str(): string
    init(value?: number): void
    removeFirst(): void
    removeLast(): void
    append(node: any): void
    empty(): boolean
    /**
     * Check if this block contains any nested blocks (if/elif/else/while/for/etc.)
     * Used for elif detection to avoid converting nested if to elif
     */
    hasNestedBlocks(): boolean
    codeFragment(): any
  }
  export class ASTCondBlock extends ASTBlock {
    static InitCondition: {
      Uninited: number
      Popped: number
      PrePopped: number
    }
    constructor(blockType: any, start: number, end: number, cond: any, negative: any)
    m_cond: any
    m_negative: boolean
    set condition(cond: any)
    get condition(): any
    set negative(neg: boolean)
    get negative(): boolean
    codeFragment(): any
    __rendering: boolean
    _codeFragmentImpl(result: any): any
  }
  export class ASTIterBlock extends ASTBlock {
    constructor(blockType: any, start: number, end: number, iter: any)
    m_iter: any
    m_idx: any
    m_cond: any
    m_comp: boolean
    get start(): number
    set iter(value: any)
    get iter(): any
    set index(value: any)
    get index(): any
    set condition(value: any)
    get condition(): any
    set comprehension(value: boolean)
    get comprehension(): boolean
    codeFragment(): any
  }
  export class ASTContainerBlock extends ASTBlock {
    constructor(start: number, _finally: any, except?: number)
    m_finally: number
    m_except: number
    set finally(value: number)
    get finally(): number
    get hasFinally(): boolean
    set except(value: number)
    get except(): number
    get hasExcept(): boolean
    codeFragment(): any
  }
  export class ASTWithBlock extends ASTBlock {
    constructor(start?: number, end?: number)
    m_expr: any
    m_var: any
    set expr(value: any)
    get expr(): any
    set var(value: any)
    get var(): any
    codeFragment(): any
  }
  export class ASTAsyncWithBlock extends ASTBlock {
    constructor(start?: number, end?: number)
    m_expr: any
    m_var: any
    set expr(value: any)
    get expr(): any
    set var(value: any)
    get var(): any
    codeFragment(): any
  }
  export class ASTComprehension extends ASTNode {
    static LIST: number
    static SET: number
    static DICT: number
    static GENERATOR: number
    constructor(result: any, key?: any)
    m_kind: number
    m_key: any
    m_result: any
    m_generators: any[]
    set kind(value: number)
    get kind(): number
    set key(value: any)
    get key(): any
    get result(): any
    get generators(): any[]
    get lastLine(): any
    addGenerator(generator: any): void
    codeFragment(): any
  }
  export class ASTLoadBuildClass extends ASTNode {
    constructor(obj: any)
    m_obj: any
    get object(): any
    codeFragment(): any
  }
  export class ASTAwaitable extends ASTNode {
    constructor(expr: any)
    m_expr: any
    get expression(): any
    codeFragment(): any
  }
  export class ASTFormattedValue extends ASTNode {
    static ConversionFlag: {
      None: number
      Str: number
      Repr: number
      ASCII: number
      FmtSpec: number
    }
    constructor(val: any, conversion: any, format_spec: any)
    m_val: any
    m_conversion: any
    m_format_spec: any
    get val(): any
    get conversion(): any
    get format_spec(): any
    codeFragment(outerQuote?: any): any
  }
  export class ASTJoinedStr extends ASTNode {
    constructor(values: any)
    m_values: any
    get values(): any
    get lastLine(): any
    codeFragment(quoteChar?: string, bareInnerForFormatSpec?: boolean): any
  }
  export class ASTAnnotatedVar extends ASTNode {
    constructor(name: any, type: any)
    m_name: any
    m_type: any
    get name(): any
    get annotation(): any
    formatIdentifier(node: any): any
    codeFragment(): any
  }
  export class ASTTypeAlias extends ASTNode {
    constructor(name: any, value: any)
    m_name: any
    m_value: any
    get name(): any
    get value(): any
    formatName(): any
    codeFragment(): any
  }
  export class ASTTernary extends ASTNode {
    constructor(if_block: any, if_expr: any, else_expr: any)
    m_if_block: any
    m_if_expr: any
    m_else_expr: any
    get if_block(): any
    get if_expr(): any
    get else_expr(): any
    get lastLine(): any
    codeFragment(): any
  }
  export class ASTMatch extends ASTNode {
    constructor(subject: any, cases?: any[])
    m_subject: any
    m_cases: any[]
    get subject(): any
    get cases(): any[]
    addCase(caseNode: any): void
    codeFragment(): any
  }
  export class ASTCase extends ASTNode {
    constructor(pattern: any, body: any, guard?: any)
    m_pattern: any
    m_guard: any
    m_body: any
    get pattern(): any
    get guard(): any
    get body(): any
    codeFragment(): any
  }
  export class ASTPattern extends ASTNode {
    static PatternType: {
      Literal: number
      Variable: number
      Wildcard: number
      Sequence: number
      Mapping: number
      Class: number
      Or: number
      As: number
    }
    constructor(type: any, value: any)
    m_type: any
    m_value: any
    get type(): any
    get value(): any
    codeFragment(): any
  }
  export class ASTIteratorValue extends ASTNode {
    constructor(value: any)
    m_value: any
    get value(): any
  }
  import PycResult = require("@depyo/PycResult")
}

declare module "@depyo/bytecode/python_1_0" {
  export = Python1_0_OpCodes
  class Python1_0_OpCodes extends OpCodes {
    constructor(co: any)
    PopulateOpCodes(opCodeList: any): void
  }
  import OpCodes = require("@depyo/OpCodes")
}

declare module "@depyo/bytecode/python_1_1" {
  export = Python1_1_OpCodes
  class Python1_1_OpCodes extends OpCodes {
    constructor(co: any)
    PopulateOpCodes(opCodeList: any): void
  }
  import OpCodes = require("@depyo/OpCodes")
}

declare module "@depyo/bytecode/python_1_3" {
  export = Python1_3_OpCodes
  class Python1_3_OpCodes extends OpCodes {
    constructor(co: any)
    PopulateOpCodes(opCodeList: any): void
  }
  import OpCodes = require("@depyo/OpCodes")
}

declare module "@depyo/bytecode/python_1_4" {
  export = Python1_4_OpCodes
  class Python1_4_OpCodes extends OpCodes {
    constructor(co: any)
    PopulateOpCodes(opCodeList: any): void
  }
  import OpCodes = require("@depyo/OpCodes")
}

declare module "@depyo/bytecode/python_1_5" {
  export = Python1_5_OpCodes
  class Python1_5_OpCodes extends OpCodes {
    constructor(co: any)
    PopulateOpCodes(opCodeList: any): void
  }
  import OpCodes = require("@depyo/OpCodes")
}

declare module "@depyo/bytecode/python_1_6" {
  export = Python1_6_OpCodes
  class Python1_6_OpCodes extends OpCodes {
    constructor(co: any)
    PopulateOpCodes(opCodeList: any): void
  }
  import OpCodes = require("@depyo/OpCodes")
}

declare module "@depyo/bytecode/python_2_0" {
  export = Python2_0_OpCodes
  class Python2_0_OpCodes extends OpCodes {
    constructor(co: any)
    PopulateOpCodes(opCodeList: any): void
  }
  import OpCodes = require("@depyo/OpCodes")
}

declare module "@depyo/bytecode/python_2_1" {
  export = Python2_1_OpCodes
  class Python2_1_OpCodes extends OpCodes {
    constructor(co: any)
    PopulateOpCodes(opCodeList: any): void
  }
  import OpCodes = require("@depyo/OpCodes")
}

declare module "@depyo/bytecode/python_2_2" {
  export = Python2_2_OpCodes
  class Python2_2_OpCodes extends OpCodes {
    constructor(co: any)
    PopulateOpCodes(opCodeList: any): void
  }
  import OpCodes = require("@depyo/OpCodes")
}

declare module "@depyo/bytecode/python_2_3" {
  export = Python2_3_OpCodes
  class Python2_3_OpCodes extends OpCodes {
    constructor(co: any)
    PopulateOpCodes(opCodeList: any): void
  }
  import OpCodes = require("@depyo/OpCodes")
}

declare module "@depyo/bytecode/python_2_4" {
  export = Python2_4_OpCodes
  class Python2_4_OpCodes extends OpCodes {
    constructor(co: any)
    PopulateOpCodes(opCodeList: any): void
  }
  import OpCodes = require("@depyo/OpCodes")
}

declare module "@depyo/bytecode/python_2_5" {
  export = Python2_5_OpCodes
  class Python2_5_OpCodes extends OpCodes {
    constructor(co: any)
    PopulateOpCodes(opCodeList: any): void
  }
  import OpCodes = require("@depyo/OpCodes")
}

declare module "@depyo/bytecode/python_2_6" {
  export = Python2_6_OpCodes
  class Python2_6_OpCodes extends OpCodes {
    constructor(co: any)
    PopulateOpCodes(opCodeList: any): void
  }
  import OpCodes = require("@depyo/OpCodes")
}

declare module "@depyo/bytecode/python_2_7" {
  export = Python2_7_OpCodes
  class Python2_7_OpCodes extends OpCodes {
    constructor(co: any)
    PopulateOpCodes(opCodeList: any): void
  }
  import OpCodes = require("@depyo/OpCodes")
}

declare module "@depyo/bytecode/python_3_0" {
  export = Python3_0_OpCodes
  class Python3_0_OpCodes extends OpCodes {
    constructor(co: any)
    PopulateOpCodes(opCodeList: any): void
  }
  import OpCodes = require("@depyo/OpCodes")
}

declare module "@depyo/bytecode/python_3_1" {
  export = Python3_1_OpCodes
  class Python3_1_OpCodes extends OpCodes {
    constructor(co: any)
    PopulateOpCodes(opCodeList: any): void
  }
  import OpCodes = require("@depyo/OpCodes")
}

declare module "@depyo/bytecode/python_3_10" {
  export = Python3_10_OpCodes
  class Python3_10_OpCodes extends OpCodes {
    constructor(co: any)
    PopulateOpCodes(opCodeList: any): void
  }
  import OpCodes = require("@depyo/OpCodes")
}

declare module "@depyo/bytecode/python_3_11" {
  export = Python3_11_OpCodes
  class Python3_11_OpCodes extends OpCodes {
    constructor(co: any)
    PopulateOpCodes(opCodeList: any): void
  }
  import OpCodes = require("@depyo/OpCodes")
}

declare module "@depyo/bytecode/python_3_12" {
  export = Python3_12_OpCodes
  class Python3_12_OpCodes extends OpCodes {
    constructor(co: any)
    PopulateOpCodes(opCodeList: any): void
  }
  import OpCodes = require("@depyo/OpCodes")
}

declare module "@depyo/bytecode/python_3_13" {
  export = Python3_13_OpCodes
  class Python3_13_OpCodes extends OpCodes {
    constructor(co: any)
    PopulateOpCodes(opCodeList: any): void
  }
  import OpCodes = require("@depyo/OpCodes")
}

declare module "@depyo/bytecode/python_3_14" {
  export = Python3_14_OpCodes
  class Python3_14_OpCodes extends OpCodes {
    constructor(co: any)
    PopulateOpCodes(opCodeList: any): void
  }
  import OpCodes = require("@depyo/OpCodes")
}

declare module "@depyo/bytecode/python_3_15" {
  export = Python3_15_OpCodes
  class Python3_15_OpCodes extends OpCodes {
    constructor(co: any)
    PopulateOpCodes(opCodeList: any): void
  }
  import OpCodes = require("@depyo/OpCodes")
}

declare module "@depyo/bytecode/python_3_2" {
  export = Python3_2_OpCodes
  class Python3_2_OpCodes extends OpCodes {
    constructor(co: any)
    PopulateOpCodes(opCodeList: any): void
  }
  import OpCodes = require("@depyo/OpCodes")
}

declare module "@depyo/bytecode/python_3_3" {
  export = Python3_3_OpCodes
  class Python3_3_OpCodes extends OpCodes {
    constructor(co: any)
    PopulateOpCodes(opCodeList: any): void
  }
  import OpCodes = require("@depyo/OpCodes")
}

declare module "@depyo/bytecode/python_3_4" {
  export = Python3_4_OpCodes
  class Python3_4_OpCodes extends OpCodes {
    constructor(co: any)
    PopulateOpCodes(opCodeList: any): void
  }
  import OpCodes = require("@depyo/OpCodes")
}

declare module "@depyo/bytecode/python_3_5" {
  export = Python3_5_OpCodes
  class Python3_5_OpCodes extends OpCodes {
    constructor(co: any)
    PopulateOpCodes(opCodeList: any): void
  }
  import OpCodes = require("@depyo/OpCodes")
}

declare module "@depyo/bytecode/python_3_6" {
  export = Python3_6_OpCodes
  class Python3_6_OpCodes extends OpCodes {
    constructor(co: any)
    PopulateOpCodes(opCodeList: any): void
  }
  import OpCodes = require("@depyo/OpCodes")
}

declare module "@depyo/bytecode/python_3_7" {
  export = Python3_7_OpCodes
  class Python3_7_OpCodes extends OpCodes {
    constructor(co: any)
    PopulateOpCodes(opCodeList: any): void
  }
  import OpCodes = require("@depyo/OpCodes")
}

declare module "@depyo/bytecode/python_3_8" {
  export = Python3_8_OpCodes
  class Python3_8_OpCodes extends OpCodes {
    constructor(co: any)
    PopulateOpCodes(opCodeList: any): void
  }
  import OpCodes = require("@depyo/OpCodes")
}

declare module "@depyo/bytecode/python_3_9" {
  export = Python3_9_OpCodes
  class Python3_9_OpCodes extends OpCodes {
    constructor(co: any)
    PopulateOpCodes(opCodeList: any): void
  }
  import OpCodes = require("@depyo/OpCodes")
}

declare module "@depyo/code_reader" {
  export = CodeReader
  class CodeReader {
    constructor(code: any, endian: any)
    endian: any
    _reader: any
    _pc: number
    set pc(pos: number)
    get pc(): number
    get length(): any
    get EOF(): boolean
    _read(label: any, size: any, fn: any): any
    readByte(): any
    readUShort(): any
    readShort(): any
    readInt(): any
    readUInt(): any
    readLong(): {
      low: any
      high: any
    }
    readULong(): {
      low: any
      high: any
    }
    readFloat(): any
    readDouble(): any
    readBytes(length: any): any
    readString(length: any): any
    peekByte(): any
  }
  namespace CodeReader {
    export { CodeReaderError }
  }
  class CodeReaderError extends Error {
    constructor(message: any, pc: any, length: any)
    pc: any
    length: any
  }
}

declare module "@depyo/handlers/binary_ops" {
  export function handleBinaryOr(): void
  export function handleBinaryAdd(): void
  export function handleBinaryAnd(): void
  export function handleBinaryDivide(): void
  export function handleBinaryFloorDivide(): void
  export function handleBinaryLshift(): void
  export function handleBinaryModulo(): void
  export function handleBinaryMultiply(): void
  export function handleBinaryPower(): void
  export function handleBinaryRshift(): void
  export function handleBinarySubtract(): void
  export function handleBinaryTrueDivide(): void
  export function handleBinaryXor(): void
  export function handleBinaryMatrixMultiply(): void
  export function handleInplaceAdd(): void
  export function handleInplaceAnd(): void
  export function handleInplaceDivide(): void
  export function handleInplaceFloorDivide(): void
  export function handleInplaceLShift(): void
  export function handleInplaceModulo(): void
  export function handleInplaceMultiply(): void
  export function handleInplaceOr(): void
  export function handleInplacePower(): void
  export function handleInplaceRshift(): void
  export function handleInplaceSubtract(): void
  export function handleInplaceTrueDivide(): void
  export function handleInplaceXor(): void
  export function handleInplaceMatrixMultiply(): void
  export function handleBinaryOpA(): void
}

declare module "@depyo/handlers/collections_update" {
  export function handleSetAdd(): void
  export function handleSetAddA(): void
  export function handleListAppend(): void
  export function handleListAppendA(): void
  export function handleSetUpdateA(): void
  export function handleListExtendA(): void
  export function handleDictMergeA(): void
  export function handleDictUpdateA(): void
}

declare module "@depyo/handlers/comparisons" {
  export function handleCompareOpA(): void
  export class handleCompareOpA {
    matchSubject: any
    currentMatch: AST.ASTMatch
    matchParentBlock: any
    patternOps: any[]
    matchPreNodesStart: any
    inMatchPattern: boolean
  }
  export function handleContainsOpA(): void
  export function handleIsOpA(): void
  import AST = require("@depyo/ast/ast_node")
}

declare module "@depyo/handlers/context_managers" {
  /**
   * Handler for BEFORE_WITH opcode (Python 3.11+)
   *
   * In Python 3.11+, context managers use BEFORE_WITH instead of SETUP_WITH.
   * BEFORE_WITH:
   *   - Pops the context manager from the stack
   *   - Calls __enter__() on it
   *   - Pushes the result (which the next STORE_* will capture as the 'as' variable)
   *
   * The with block boundaries come from the exception table, not from jump targets.
   */
  export function handleBeforeWith(): void
  export class handleBeforeWith {
    curBlock: any
  }
  /**
   * Handler for BEFORE_ASYNC_WITH (Python 3.5-3.10).
   *
   * Bytecode pattern for `async with EXPR [as VAR]:`:
   *   LOAD_*               EXPR (context manager)
   *   BEFORE_ASYNC_WITH    <-- we are here
   *   GET_AWAITABLE
   *   LOAD_CONST None
   *   YIELD_FROM
   *   SETUP_ASYNC_WITH +N  (N targets WITH_CLEANUP_START — end of body)
   *   POP_TOP | STORE_FAST VAR
   *   ... body ...
   *   POP_BLOCK
   *   LOAD_CONST None
   *   WITH_CLEANUP_START   (closes block, see handleWithCleanup)
   *   GET_AWAITABLE
   *   LOAD_CONST None
   *   YIELD_FROM
   *   WITH_CLEANUP_FINISH
   *   END_FINALLY
   *
   * We pop the context manager off the data stack, then use GoNext to consume
   * the entire setup epilogue. This bypasses the GET_AWAITABLE / YIELD_FROM
   * handlers (which would otherwise emit `await await(EXPR.__aenter__)` noise)
   * and creates a clean ASTAsyncWithBlock for the body.
   */
  export function handleBeforeAsyncWith(): void
  export class handleBeforeAsyncWith {
    curBlock: any
  }
  export function handleSetupWithA(): void
  export class handleSetupWithA {
    curBlock: any
  }
  export function handleWithCleanupStart(): void
  export function handleWithCleanup(): void
  export class handleWithCleanup {
    curBlock: any
  }
  export function handleWithCleanupFinish(): void
  export function handleSetupAsyncWithA(): void
}

declare module "@depyo/handlers/control_flow_jumps" {
  export function handleJumpIfFalseA(): void
  export function handleJumpIfTrueA(): void
  export function handleJumpIfFalseOrPopA(): void
  export function handleJumpIfTrueOrPopA(): void
  export function handlePopJumpIfFalseA(): void
  export function handlePopJumpIfTrueA(): void
  export function handlePopJumpForwardIfFalseA(): void
  export function handlePopJumpForwardIfTrueA(): void
  export function handlePopJumpForwardIfNoneA(): void
  export function handlePopJumpForwardIfNotNoneA(): void
  export function handlePopJumpBackwardIfNoneA(): void
  export function handlePopJumpBackwardIfNotNoneA(): void
  export function handlePopJumpIfNoneA(): void
  export function handlePopJumpIfNotNoneA(): void
  export function handleInstrumentedPopJumpIfFalseA(): void
  export function handleInstrumentedPopJumpIfTrueA(): void
  export function handleInstrumentedPopJumpIfNoneA(): void
  export function handleInstrumentedPopJumpIfNotNoneA(): void
  export function handleJumpAbsoluteA(): void
  export class handleJumpAbsoluteA {
    skipNextJump: boolean
    curBlock: any
  }
  export function handleJumpForwardA(): void
  export function handleInstrumentedJumpForwardA(): void
  export function handleJumpA(): void
  export function handleJumpNoInterruptA(): void
  export function handleJumpBackwardA(): void
  export function handleJumpBackwardNoInterruptA(): void
  export function handleJumpIfNotExcMatchA(): void
  export function handleNotTaken(): void
  export function handleInstrumentedNotTakenA(): void
  export function resolveBoolChainFrames(ctx: any, atOffset: any): void
}

declare module "@depyo/handlers/exceptions_blocks" {
  export function handleEndFinally(): void
  export class handleEndFinally {
    curBlock: any
    unreachableUntil: any
  }
  export function handlePopBlock(): void
  export class handlePopBlock {
    curBlock: any
  }
  export function handlePopExcept(): void
  export class handlePopExcept {
    curBlock: any
    inExceptionGroup: boolean
    inExceptionTableHandler: boolean
    pendingEgMatchType: any
  }
  export function handleRaiseVarargsA(): void
  export class handleRaiseVarargsA {
    curBlock: any
  }
  export function handleSetupExceptA(): void
  export class handleSetupExceptA {
    curBlock: any
    need_try: boolean
  }
  export function handleSetupFinallyA(): void
  export class handleSetupFinallyA {
    curBlock: any
    need_try: boolean
  }
  export function handleSetupCleanupA(): void
  export function handleBeginFinally(): void
  export function handleCallFinallyA(): void
  export function handlePopFinallyA(): void
  export function handleWithExceptStart(): void
  export function handleWithExceptStartA(): void
  export function handleLoadAssertionError(): void
  export function handleReraise(): void
  export class handleReraise {
    curBlock: any
    inExceptionGroup: boolean
    inExceptionTableHandler: boolean
  }
  export function handleReraiseA(): void
  export function handlePushExcInfo(): void
  export class handlePushExcInfo {
    inExceptionGroup: boolean
  }
  export function handleCheckExcMatch(): void
  export function handleCheckEgMatch(): void
  export class handleCheckEgMatch {
    inExceptionGroup: boolean
    pendingEgMatchType: any
    egMatchTypeStack: any[]
  }
  export function handlePrepReraiseStar(): void
  export class handlePrepReraiseStar {
    ignoreNextConditional: boolean
    cleanupStackDepth: any
    inExceptionGroup: boolean
  }
}

declare module "@depyo/handlers/formatting" {
  export function handleBuildTemplate(): void
  export function handleBuildInterpolationA(): void
}

declare module "@depyo/handlers/function_calls" {
  export function handleKwNamesA(): void
  export function handleCallA(): void
  export function handleCallKwA(): void
  export function handleInstrumentedCallKwA(): void
  export function handleCallFunctionA(): void
  export function handleInstrumentedCallA(): void
  export class handleInstrumentedCallA {
    _py314WithCtxMgrForStore: any
  }
  export function handleCallFunctionVarA(): void
  export function handleCallFunctionKwA(): void
  export function handleCallFunctionVarKwA(): void
  export function handleCallMethodA(): void
  export function handlePrecallA(): void
  export function handleBinaryCall(): void
  export function handleCallFunctionExA(): void
  export function handleCallIntrinsic1(): void
  export function handleCallIntrinsic2(): void
  export class handleCallIntrinsic2 {
    ignoreNextConditional: boolean
    cleanupStackDepth: any
    inExceptionGroup: boolean
  }
  export function handleCallIntrinsic1A(): void
  export function handleCallIntrinsic2A(): void
  export function handleEnterExecutorA(): void
}

declare module "@depyo/handlers/function_class_build" {
  export function handleBuildClass(): void
  export function handleBuildFunction(): void
  export function handleBuildListA(): void
  export function handleBuildSetA(): void
  export function handleBuildMapA(): void
  export function handleBuildConstKeyMapA(): void
  export function handleBuildStringA(): void
  export function handleBuildTupleA(): void
  export function handleLoadBuildClass(): void
  export function handleLoadClosureA(): void
  export function handleCopyFreeVarsA(): void
  export function handleMakeClosureA(): void
  export function handleMakeFunction(): void
  export function handleMakeFunctionA(): void
  export function handleMakeCellA(): void
  export function handleSetFunctionAttributeA(): void
  export function handleListToTuple(): void
}

declare module "@depyo/handlers/generators_async" {
  export function handleGetAwaitable(): void
  export class handleGetAwaitable {
    insideAwait: boolean
  }
  export function handleGetAwaitableA(): void
  export function handleYieldFrom(): void
  export function handleInstrumentedYieldValueA(): void
  export function handleYieldValueA(): void
  export function handleYieldValue(): void
  export class handleYieldValue {
    curBlock: any
  }
  export function handleEndSend(): void
  export class handleEndSend {
    insideAwait: boolean
  }
  export function handleInstrumentedEndSendA(): void
  export function handleCleanupThrow(): void
  export function handleSendA(): void
  export function handleResumeA(): void
  export function handleInstrumentedResumeA(): void
  export function handleGenStartA(): void
}

declare module "@depyo/handlers/imports" {
  export function handleImportNameA(): void
  export function handleImportFromA(): void
  export function handleImportStar(): void
}

declare module "@depyo/handlers/load_store_names" {
  export function handleDeleteAttrA(): void
  export function handleDeleteGlobalA(): void
  export function handleDeleteNameA(): void
  export function handleDeleteFastA(): void
  export function handleDeleteDerefA(): void
  export function handleLoadAttrA(): void
  export function handleLoadConstA(): void
  export function handleLoadDerefA(): void
  export function handleLoadClassderefA(): void
  export function handleLoadFastA(): void
  export function handleLoadFastCheckA(): void
  export function handleLoadFastAndClearA(): void
  export class handleLoadFastAndClearA {
    _inlineCompSavedVar: any
  }
  export function handleLoadFastBorrowA(): void
  export function handleLoadFastBorrowLoadFastBorrowA(): void
  export function handleLoadFastLoadFastA(): void
  export function handleLoadGlobalA(): void
  export function handleLoadCommonConstantA(): void
  export function handleLoadLocals(): void
  export function handleLoadSmallIntA(): void
  export function handleStoreLocals(): void
  export function handleLoadMethodA(): void
  export function handleLoadNameA(): void
  export function handleLoadSpecialA(): void
  export class handleLoadSpecialA {
    _py314WithContextMgr: any
    potentialMatchSubject: any
    matchCandidateStart: number
    curBlock: any
    _py314WithCtxMgrForStore: any
  }
  export function handleLoadSuperAttrA(): void
  export function handleLoadSuperMethodA(): void
  export function handleLoadZeroSuperAttrA(): void
  export function handleLoadZeroSuperMethodA(): void
  export function handleLoadFromDictOrDerefA(): void
  export function handleLoadFromDictOrGlobalsA(): void
  export function handleStoreAttrA(): void
  export function handleStoreDerefA(): void
  export function handleStoreFastA(): void
  export function handleStoreFastLoadFastA(): void
  export function handleStoreFastStoreFastA(): void
  export function handleStoreGlobalA(): void
  export function handleStoreNameA(): void
  export function handleStoreAnnotationA(): void
  export function handleReserveFastA(): void
}

declare module "@depyo/handlers/loop_iterator" {
  export function handleBreakLoop(): void
  export class handleBreakLoop {
    unreachableUntil: any
  }
  export function handleContinueLoopA(): void
  export function handleEndFor(): void
  export class handleEndFor {
    curBlock: any
    _inlineCompSavedVar: any
  }
  export function handleInstrumentedEndForA(): void
  export function handleInstrumentedPopIterA(): void
  export function handleForIterA(): void
  export function handleInstrumentedForIterA(): void
  export class handleInstrumentedForIterA {
    curBlock: any
  }
  export function handleForLoopA(): void
  export class handleForLoopA {
    curBlock: any
  }
  export function handleGetAiter(): void
  export class handleGetAiter {
    curBlock: any
  }
  export function handleGetAnext(): void
  export function handleGetIter(): void
  export function handleGetYieldFromIter(): void
  export function handleSetupLoopA(): void
  export class handleSetupLoopA {
    curBlock: any
  }
}

declare module "@depyo/handlers/misc_other" {
  export function beginMatchCaseFromPattern(options?: {}): boolean
  export class beginMatchCaseFromPattern {
    constructor(options?: {})
    caseBodyStartIndex: any
    currentCase: AST.ASTCase
    inMatchPattern: boolean
    patternOps: any[]
  }
  export function flushCurrentCaseBody(): boolean
  export class flushCurrentCaseBody {
    currentCase: any
  }
  export function handleExecStmt(): void
  export function handleFormatValueA(): void
  export function handleFormatSimple(): void
  export function handleFormatWithSpec(): void
  export function handlePopTop(): void
  export class handlePopTop {
    curBlock: any
  }
  export function handlePopIter(): any
  export function handlePrintExpr(): void
  export function handlePrintItem(): void
  export function handlePrintItemTo(): void
  export function handlePrintNewline(): void
  export function handlePrintNewlineTo(): void
  export function handleReturnGenerator(): void
  export function handleInstrumentedReturnValueA(): void
  export function handleReturnValue(): void
  export class handleReturnValue {
    curBlock: any
  }
  export function handleInstrumentedReturnConstA(): void
  export function handleReturnConstA(): void
  export function handleSetLinenoA(): void
  export function handleSetupAnnotations(): void
  export class handleSetupAnnotations {
    variable_annotations: boolean
  }
  export function handleEndAsyncFor(): void
  export class handleEndAsyncFor {
    curBlock: any
    unreachableUntil: any
  }
  export function handleInstrumentedEndAsyncForA(): void
  export function handleInstrumentedInstructionA(): void
  export function handleInstrumentedLineA(): void
  import AST = require("@depyo/ast/ast_node")
}

declare module "@depyo/handlers/pattern_matching" {
  export function handleMatchSequence(): void
  export class handleMatchSequence {
    inMatchPattern: boolean
    patternOps: {
      type: string
    }[]
  }
  export function handleGetLen(): void
  export function handleMatchMapping(): void
  export function handleMatchClassA(): void
  export class handleMatchClassA {
    inMatchPattern: boolean
    patternOps: any[]
  }
  export function handleMatchKeys(): void
}

declare module "@depyo/handlers/stack_ops" {
  export function handleDupTop(): void
  export class handleDupTop {
    potentialMatchSubject: any
    matchCandidateStart: any
    lastLoadOffset: any
    matchParentBlock: any
    matchPreNodesStart: any
    matchSubject: any
    currentMatch: AST.ASTMatch
    inMatchPattern: boolean
    patternOps: any[]
    skipNextJump: boolean
    isWalrusOperator: boolean
  }
  export function handleCopyA(): void
  export class handleCopyA {
    potentialMatchSubject: any
  }
  export function handleDupTopTwo(): void
  export function handleDupTopxA(): void
  export function handleSwapA(): void
  export function handleRotTwo(): void
  export function handleRotThree(): void
  export function handleRotFour(): void
  export function handlePushNull(): void
  export function handleCache(): void
  export function handleNop(): void
  export function handleStopCode(): void
  import AST = require("@depyo/ast/ast_node")
}

declare module "@depyo/handlers/subscript_slice" {
  export function handleBinarySubscr(): void
  export function handleMapAddA(): void
  export function handleStoreMap(): void
  export function handleBuildSliceA(): void
  export function handleDeleteSlice0(): void
  export function handleDeleteSlice1(): void
  export function handleDeleteSlice2(): void
  export function handleDeleteSlice3(): void
  export function handleDeleteSubscr(): void
  export function handleSlice0(): void
  export function handleSlice1(): void
  export function handleSlice2(): void
  export function handleSlice3(): void
  export function handleStoreSlice0(): void
  export function handleStoreSlice1(): void
  export function handleStoreSlice2(): void
  export function handleStoreSlice3(): void
  export function handleBinarySlice(): void
  export function handleStoreSlice(): void
  export function handleStoreSubscr(): void
}

declare module "@depyo/handlers/unary_ops" {
  export function handleUnaryCall(): void
  export function handleConvertValueA(): void
  export function handleUnaryConvert(): void
  export function handleUnaryInvert(): void
  export function handleUnaryNegative(): void
  export function handleUnaryNot(): void
  export function handleUnaryPositive(): void
  export function handleToBool(): void
  export class handleToBool {
    potentialMatchSubject: any
    matchCandidateStart: number
  }
  export function handleExitInitCheck(): void
}

declare module "@depyo/handlers/unpack" {
  export function handleUnpackListA(): void
  export function handleUnpackTupleA(): void
  export function handleUnpackSequenceA(): void
  export function handleUnpackArgA(): void
  export function handleUnpackExA(): void
  export class handleUnpackExA {
    unpack: number
    starPos: number
  }
  export function handleBuildListUnpackA(): void
  export function handleBuildTupleUnpackA(): void
  export function handleBuildTupleUnpackWithCallA(): void
  export function handleBuildSetUnpackA(): void
  export function handleBuildMapUnpackA(): void
  export function handleBuildMapUnpackWithCallA(): void
}

declare module "@depyo/stack_history" {
  export = StackHistory
  class StackHistory {
    history: any[]
    push(historyElement: any): void
    top(): any
    pop(): any
    set length(value: number)
    get length(): number
    empty(): boolean
  }
}

declare module "@depyo/zip_reader" {
  export = ZipReader
  class ZipReader {
    constructor(filename: any)
    filename: any
    reader: Reader
    _entries: any
    set position(pos: number)
    get position(): number
    readLocalEntry(): {
      header: any
      version: any
      flags: any
      method: any
      modificationTime: any
      modificationDate: any
      crc32: any
      compressedSize: any
      uncompressedSize: any
      fileNameLength: any
      extraFieldLength: any
      fileName: any
      extraField: any
      offset: number
    }
    readCDEntry(): {
      header: any
      versionMade: any
      minVersion: any
      flags: any
      method: any
      modificationTime: any
      modificationDate: any
      crc32: any
      compressedSize: any
      uncompressedSize: any
      fileNameLength: any
      extraFieldLength: any
      commentLength: any
      diskNum: any
      internalFileAttributes: any
      externalFileAttributes: any
      localHeaderOffseet: any
      fileName: any
      extraField: any
      comment: any
    }
    readEOCD(): {
      header: any
      diskNum: any
      cdDisk: any
      cdRecordsCurrent: any
      cdRecordsTotal: any
      cdSize: any
      cdOffset: any
    }
    readEntry(entry: any): any
    open(): void
    readSignature(): any
    isZipFile(): boolean
    findEOCD(): boolean
    entries(): Generator<
      {
        header: any
        versionMade: any
        minVersion: any
        flags: any
        method: any
        modificationTime: any
        modificationDate: any
        crc32: any
        compressedSize: any
        uncompressedSize: any
        fileNameLength: any
        extraFieldLength: any
        commentLength: any
        diskNum: any
        internalFileAttributes: any
        externalFileAttributes: any
        localHeaderOffseet: any
        fileName: any
        extraField: any
        comment: any
      },
      any,
      unknown
    >
    findEntry(filename: any): any
  }
  import Reader = require("@depyo/code_reader")
}
