import type { BinaryReader } from "@depyo/BinaryReader"
import type { PythonCodeObject } from "@depyo/PythonObject"

export function peekUInt8(reader: BinaryReader, relativeOffset: number = 0): number {
  return reader.Reader.readUInt8(reader.pc + relativeOffset)
}

export function peekInt8(reader: BinaryReader, relativeOffset: number = 0): number {
  return reader.Reader.readInt8(reader.pc + relativeOffset)
}

export function peekInt16(reader: BinaryReader, relativeOffset: number = 0): number {
  return reader.Reader.readInt16LE(reader.pc + relativeOffset)
}

export function peekInt32(reader: BinaryReader, relativeOffset: number = 0): number {
  return reader.Reader.readInt32LE(reader.pc + relativeOffset)
}

export function qualNameOrName(codeObject: PythonCodeObject): string {
  return typeof codeObject.QualName?.Value === "string"
    ? codeObject.QualName.Value
    : codeObject.Name
}
