import OpCodesMap from "@depyo/OpCodes"
import PycDecompiler from "@depyo/PycDecompiler"
import { ASTClass } from "@depyo/ast/ast_node"

// Reason: Depyo lib assumes a global variable g_cliArgs exists.
// Sync: depyo.js#L13
//#region CLI

if ((global as any).g_cliArgs === undefined) {
  ;(global as any).g_cliArgs = {
    debug: false,
    raw: false,
    rawSpacing: false,
    dump: false,
    asm: false,
    stats: false,
    skipSource: false,
    skipPath: false,
    sendToStdout: false,
    marshal: false,
    marshalScan: false,
    strict: false,
    pyVersion: null,
    silent: false,
    fileExt: "py",
    baseDir: null,
    filenames: [],
  }
}

//#endregion CLI

// Reason: Depyo lib `require`s handler modules from `handlers/*.js`, but we want to bundle them with Rolldown.
// Sync: PycDecompiler.setupHandlers
//#region Opcode Handlers

export type HandlerFunction = (...args: unknown[]) => unknown
type HandlerModule = Record<string, HandlerFunction>

if (Object.keys(PycDecompiler.opCodeHandlers).length == 0) {
  const handlerModules = import.meta.glob<HandlerModule>("/node_modules/depyo/lib/handlers/*.js", {
    eager: true,
  })

  for (const fileExports of Object.values(handlerModules)) {
    for (const [handlerName, handler] of Object.entries(fileExports)) {
      if (typeof handler === "function" && handlerName.startsWith("handle")) {
        // Convert handler name (e.g., "handleJumpForwardA") to opcode name ("JUMP_FORWARD_A").
        // Primary rule: camelCase → SNAKE_CASE with explicit runs-of-caps handling
        // (HandleABCDef → ABC_DEF). Some legacy handlers like handleCallIntrinsic1A
        // still map via the looser regex — OpCodes.js provides both _1A and _1_A aliases.
        const body = handlerName.replace(/^handle/, "")
        let opCodeName = body
          .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
          .replace(/([A-Z])([A-Z][a-z])/g, "$1_$2")
          .toUpperCase()
        if (!(opCodeName in OpCodesMap)) {
          const legacy = body
            .replaceAll(/([A-Z][a-z]+)/g, (m) => m.toUpperCase() + "_")
            .replace(/_$/, "")
          if (legacy in OpCodesMap) opCodeName = legacy
        }

        if (opCodeName in OpCodesMap) {
          const opCodeId = (OpCodesMap as any)[opCodeName]
          const handlerFunc = fileExports[handlerName]

          if (PycDecompiler.opCodeHandlers[opCodeId]) {
            throw new Error(
              `Static handler collision: OpCode ${opCodeName} (${opCodeId}) already bound; refusing silent overwrite from ${handlerName}.`
            )
          }
          PycDecompiler.opCodeHandlers[opCodeId] = handlerFunc
        } else {
          throw new Error(
            `Static handler mapping failed: "${opCodeName}" (from ${handlerName}) is not in OpCodes. Rename the handler to match a known opcode, or add the opcode to lib/OpCodes.js.`
          )
        }
      }
    }
  }
}

//#endregion Opcode Handlers

// Reason: Depyo `ASTClass` has a `line` getter, but no setter. Setter is needed at `classNode.line = this.code.Current.LineNo;`.
// Sync: ASTClass
//#region ASTClass.line

Object.defineProperty(ASTClass.prototype, "line", {
  get: function (this: ASTClass): number {
    return this.code.line
  },
  set: function (this: ASTClass, value: number) {
    this.code.line = value
  },
})

//#endregion ASTClass.line

export { PycDecompiler }
