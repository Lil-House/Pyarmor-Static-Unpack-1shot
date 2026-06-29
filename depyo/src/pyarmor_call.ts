import { type HandlerFunction, PycDecompiler } from "./depyo_override.ts"
import Opcodes from "@depyo/OpCodes"
import { PythonObject } from "@depyo/PythonObject"
import {
  ASTBinary,
  ASTCall,
  ASTImport,
  ASTName,
  ASTNode,
  ASTObject,
  ASTStore,
  ASTTuple,
} from "@depyo/ast/ast_node"
import { newPycReaderFrom } from "./pyarmor_marshal.ts"
import { pyarmorMixStringDecrypt } from "./pyarmor_mix_string.ts"

const CALLS: number[] = [
  Opcodes.CALL_A,
  Opcodes.CALL_KW_A,
  Opcodes.CALL_FUNCTION_A,
  Opcodes.CALL_FUNCTION_VAR_A,
  Opcodes.CALL_FUNCTION_KW_A,
  Opcodes.CALL_FUNCTION_VAR_KW_A,
  Opcodes.CALL_FUNCTION_EX_A,
  Opcodes.CALL_METHOD_A,
]

const STORES: number[] = [
  Opcodes.STORE_DEREF_A,
  Opcodes.STORE_FAST_A,
  Opcodes.STORE_GLOBAL_A,
  Opcodes.STORE_NAME_A,
]

if (!(PycDecompiler.prototype as any)._ArmorShot_Hooked_OpcodeHandlers) {
  // Only wrap the values of record `PycDecompiler.opCodeHandlers`.
  // The handlers themselves are not affected.

  for (const opCodeId of CALLS) {
    const origin = PycDecompiler.opCodeHandlers[opCodeId]
    if (typeof origin === "function") {
      PycDecompiler.opCodeHandlers[opCodeId] = wrappedCallCheckPyarmorBuiltins(
        origin as HandlerFunction
      )
    } else {
      throw new Error(`PycDecompiler.opCodeHandlers[${opCodeId}] is not a function`)
    }
  }

  for (const opCodeId of STORES) {
    const origin = PycDecompiler.opCodeHandlers[opCodeId]
    if (typeof origin === "function") {
      PycDecompiler.opCodeHandlers[opCodeId] = wrappedStoreCheckPyarmorImports(
        origin as HandlerFunction
      )
    } else {
      throw new Error(`PycDecompiler.opCodeHandlers[${opCodeId}] is not a function`)
    }
  }

  for (const opCodeId of [Opcodes.JUMP_FORWARD_A]) {
    const origin = PycDecompiler.opCodeHandlers[opCodeId]
    if (typeof origin === "function") {
      PycDecompiler.opCodeHandlers[opCodeId] = wrappedJumpForwardCheckTopLevel(
        origin as HandlerFunction
      )
    } else {
      throw new Error(`PycDecompiler.opCodeHandlers[${opCodeId}] is not a function`)
    }
  }
}
;(PycDecompiler.prototype as any)._ArmorShot_Hooked_OpcodeHandlers = true

function wrappedCallCheckPyarmorBuiltins(origin: HandlerFunction): HandlerFunction {
  return function (this: PycDecompiler, ...args: unknown[]): void {
    origin.apply(this, args)
    postCallCheckPyarmorBuiltins.call(this)
  }
}

function wrappedJumpForwardCheckTopLevel(origin: HandlerFunction): HandlerFunction {
  return function (this: PycDecompiler, ...args: unknown[]): void {
    // This implementation is probably wrong
    // Pyarmor jumps forward on top level scope
    if (!Object.is(this.blocks.at(-1), this.defBlock)) {
      origin.apply(this, args)
      return
    }

    let offs = this.code.Current.Argument
    if (this.object.Reader.versionCompare(3, 10) >= 0) {
      offs *= 2
    }
    const insn_offs = offs / 2
    this.code.GoNext(insn_offs)
  }
}

function wrappedStoreCheckPyarmorImports(origin: HandlerFunction): HandlerFunction {
  return function (this: PycDecompiler, ...args: unknown[]): void {
    // The only test condition
    // Satisfied -> pyarmor import, no origin
    // Unsatisfied -> origin
    if (!(this.unpack > 0 && this.dataStack.at(-2) instanceof ASTImport)) {
      origin.apply(this, args)
      return
    }

    const name =
      this.code.Current.OpCodeID === Opcodes.STORE_DEREF_A
        ? this.code.Current.FreeName
        : this.code.Current.Name
    const nameNode = new ASTName(name)

    const tupleNode = this.dataStack.at(-1)
    if (tupleNode instanceof ASTTuple) {
      tupleNode.add(nameNode)
    } else {
      if ((global as any).g_cliArgs?.debug) {
        console.error(
          "wrappedStoreCheckPyarmorImports: During unpacking, data stack top (names to store) is not ASTTuple, got %s. Current name: %s.",
          tupleNode?.constructor?.name,
          name
        )
      }
      return
    }

    if (--this.unpack <= 0) {
      this.dataStack.pop()
      const seqNode = this.dataStack.pop() as ASTImport

      const fromlist = (seqNode.fromlist ?? []) as ASTName[]
      const store_names = tupleNode.values
      const real_import = new ASTImport(seqNode.name, null)
      for (let i = 0; i < fromlist.length && i < store_names.length; i++) {
        real_import.add_store(new ASTStore(fromlist[i], store_names[i]))
      }
      this.curBlock.append(real_import)
    }
  }
}

function pyarmorAssertBytesToAst(input: Buffer, decompiler: PycDecompiler): ASTNode {
  let { decrypted, result } = pyarmorMixStringDecrypt(
    input,
    decompiler.object.Reader.pyarmor_aes_key,
    decompiler.object.Reader.pyarmor_mix_str_aes_nonce
  )
  if (!decrypted) {
    result = result.subarray(1)
  }

  switch (input[0]! & 0x7f) {
    case 1: {
      return new ASTObject(new PythonObject("Py_Unicode", result.toString("utf8")))
    }
    case 2: {
      const new_reader = newPycReaderFrom(decompiler.object.Reader, result)
      return new ASTObject(new_reader.ReadObject())
    }
    case 3: {
      return new ASTImport(new ASTName(result.toString("utf8")), null)
    }
    case 4: {
      const new_reader = newPycReaderFrom(decompiler.object.Reader, result)
      const obj = new ASTObject(new_reader.ReadObject())
      // (pyarmor__1, pyarmor__2, pyarmor__3) = ('builtins', ('enumerate', 'ImportError', 'hasattr'), 0)
      //                                        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
      if (obj.object.ClassName !== "Py_Tuple") {
        console.error(
          "__pyarmor_assert__ bytes type 4 did not load a tuple, got object type %d",
          obj.object.ClassName
        )
        return obj
      }
      const tuple = obj.object.Value as PythonObject[]
      if (tuple.length < 2) {
        console.error(
          "__pyarmor_assert__ bytes type 4 did not load a tuple of length >= 2, got length %d",
          tuple.length
        )
        return obj
      }
      const import_name = tuple[0]
      const fromlist_tuple_strs = tuple[1]
      if (typeof import_name?.Value !== "string" || fromlist_tuple_strs?.ClassName !== "Py_Tuple") {
        console.error(
          "__pyarmor_assert__ bytes type 4 did not load a tuple of (str, tuple, ..), got (%s, %s, ..)",
          import_name?.ClassName,
          fromlist_tuple_strs?.ClassName
        )
        return obj
      }
      const fromlist_tuple = fromlist_tuple_strs.Value as PythonObject[]
      const fromlist = []
      for (const item of fromlist_tuple) {
        if (typeof item?.Value !== "string") {
          console.error(
            "__pyarmor_assert__ bytes type 4 loaded fromlist with non-string type, got %s",
            item?.ClassName
          )
          return obj
        }
        fromlist.push(new ASTName(item.Value as string))
      }
      return new ASTImport(new ASTName(import_name.Value as string), fromlist)
    }
    default: {
      console.error("Unknown __pyarmor_assert__ bytes type: %d", input[0]! & 0x7f)
      const new_buffer = Buffer.alloc(result.length + 1)
      new_buffer[0] = input[0]! & 0x7f
      result.copy(new_buffer, 1)
      return new ASTObject(new PythonObject("Py_Unicode", new_buffer.toString("utf8")))
    }
  }
}

function postCallCheckPyarmorBuiltins(this: PycDecompiler): void {
  if (!(this.dataStack.at(-1) instanceof ASTCall)) return

  const call = this.dataStack.at(-1) as ASTCall
  if (!(call.func instanceof ASTObject) || typeof call.func.object.Value !== "string") return

  const func_name = call.func.object.Value
  if (!func_name.startsWith("__pyarmor_") || func_name.startsWith("__pyarmor_bcc_")) return

  if (!func_name.includes("__pyarmor_assert_")) {
    const new_str = new PythonObject("Py_Unicode", func_name + "(...)")
    this.dataStack.pop()
    // this.dataStack.push(new ASTObject(new_str))
    this.curBlock.append(new ASTObject(new_str))
    // str '__pyarmor_enter_12345__(...)'
    return
  }

  if (call.pparams?.length !== 1)
    // pyarmor_assert takes exactly one parameter
    return

  const param = call.pparams[0]

  if (param instanceof ASTObject && param.object.Value instanceof Buffer) {
    const new_node = pyarmorAssertBytesToAst(param.object.Value, this)
    this.dataStack.pop()
    this.dataStack.push(new_node)
    // result of __pyarmor_assert__(b'something')
    return
  }

  if (param instanceof ASTTuple) {
    if (param.values.length <= 1 || param.values.length > 3) return
    if (
      !(param.values[1] instanceof ASTObject) ||
      !(param.values[1].object.Value instanceof Buffer)
    )
      return
    const attr_name = pyarmorAssertBytesToAst(param.values[1].object.Value, this)
    if (!(attr_name instanceof ASTObject) || typeof attr_name.object.Value !== "string") return
    const name_str = attr_name.object.Value as string
    const attr_ref = new ASTBinary(param.values[0], new ASTName(name_str), ASTBinary.BinOp.Attr)
    if (param.values.length === 2) {
      this.dataStack.pop()
      this.dataStack.push(attr_ref)
      // __pyarmor_assert__((from, b'enc_attr')) -> from.enc_attr
      return
    }
    if (param.values.length === 3) {
      this.dataStack.pop()
      this.curBlock.append(new ASTStore(param.values[2], attr_ref))
      // __pyarmor_assert__((from, b'enc_attr', value)) -> from.enc_attr = value
      return
    }
  }

  if (param instanceof ASTName) {
    this.dataStack.pop()
    this.dataStack.push(param)
    // __pyarmor_assert__(name) -> name
    return
  }
}

export { PycDecompiler }
