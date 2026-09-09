import fs from "fs/promises"
import { BinaryReader } from "@depyo/BinaryReader"
import { PycReader } from "./pyarmor_code_object.ts"
import { peekInt8, peekInt16, peekInt32, peekUInt8 } from "./util.ts"

export async function loadFromOneshotSequenceFile(filePath: string): Promise<PycReader> {
  const buffer = await fs.readFile(filePath)
  const reader = new BinaryReader(buffer)

  let pyarmor_aes_key = Buffer.alloc(16)
  let pyarmor_mix_str_aes_nonce = Buffer.alloc(12)
  let oneshot_seq_header = true
  while (oneshot_seq_header) {
    const indicator = reader.readByte()
    switch (indicator) {
      case 0xa1:
        reader.readBytes(16).copy(pyarmor_aes_key)
        break
      case 0xa2:
        reader.readBytes(12).copy(pyarmor_mix_str_aes_nonce)
        break
      case 0xf0:
        break
      case 0xff:
        oneshot_seq_header = false
        break
      default:
        console.error("Unknown 1-shot sequence indicator", indicator)
        break
    }
  }

  const pyarmor_header = reader.readBytes(64)
  const major = pyarmor_header.readUInt8(9)
  const minor = pyarmor_header.readUInt8(10)
  const remain_header_length = pyarmor_header.readUInt32LE(28) - 64
  if (remain_header_length > 0) {
    reader.pc += remain_header_length
  }

  const pycReader = new PycReader(buffer, {
    marshal: true,
    pyVersion: `${major}.${minor}`,
  })
  pycReader.m_rdr = reader
  pycReader.pyarmor_aes_key = pyarmor_aes_key
  pycReader.pyarmor_mix_str_aes_nonce = pyarmor_mix_str_aes_nonce

  // For 1-shot sequence, the following part has been decrypted once.
  const code_object_offset = reader.readUInt32()
  const xor_key_procedure_length = reader.readUInt32()
  pycReader.pyarmor_co_code_aes_nonce_xor_enabled = xor_key_procedure_length > 0
  const remain_second_part_length = code_object_offset - 8
  if (remain_second_part_length > 0) {
    reader.pc += remain_second_part_length
  }

  if (pycReader.pyarmor_co_code_aes_nonce_xor_enabled) {
    const procedure_buffer = reader.readBytes(xor_key_procedure_length)
    pycReader.pyarmor_co_code_aes_nonce_xor_key =
      pyarmorCoCodeAesNonceXorKeyCalculate(procedure_buffer)
  }

  return pycReader
}

export function newPycReaderFrom(source: PycReader, buffer: Buffer): PycReader {
  const target = new PycReader(buffer, {
    marshal: true,
    versionInfo: source.m_version,
  })
  target.pyarmor_aes_key = Buffer.copyBytesFrom(source.pyarmor_aes_key)
  target.pyarmor_mix_str_aes_nonce = Buffer.copyBytesFrom(source.pyarmor_mix_str_aes_nonce)
  target.pyarmor_co_code_aes_nonce_xor_enabled = source.pyarmor_co_code_aes_nonce_xor_enabled
  target.pyarmor_co_code_aes_nonce_xor_key = Buffer.copyBytesFrom(
    source.pyarmor_co_code_aes_nonce_xor_key
  )
  return target
}

function pyarmorCoCodeAesNonceXorKeyCalculate(input: Buffer): Buffer {
  const end = input.length
  const reader = new BinaryReader(input)
  reader.pc = 16
  const out_buffer = Buffer.alloc(12).fill(0)
  const registers = new Int32Array(8).fill(0)
  const valid_index = [0, 1, 2, 3, 4, 5, -1, 7 /* origin is 15 */, -1, -1, -1, -1, -1, -1, -1, -1]

  function getRealOperand2AndAddReaderPc(reader: BinaryReader): number {
    const low_nibble = peekUInt8(reader, 1) & 0xf
    if (valid_index[low_nibble] !== -1) {
      reader.pc += 2
      return registers[low_nibble]!
    }
    const size = peekUInt8(reader, 1) & 0x7
    switch (size) {
      case 1: {
        const value = peekInt8(reader, 2)
        reader.pc += 3
        return value
      }
      case 2: {
        const value = peekInt16(reader, 2)
        reader.pc += 4
        return value
      }
      default: {
        const value = peekInt32(reader, 2)
        reader.pc += 6
        return value
      }
    }
  }

  while (reader.pc < end) {
    let operand_2 /*: i32 */ = 0
    let high_nibble /*: u4 */ = 0
    let reg /*: u8 */ = 0
    switch (peekUInt8(reader)) {
      case 1:
        // terminator
        reader.pc++
        break
      case 2:
        high_nibble = peekUInt8(reader, 1) >> 4
        operand_2 = getRealOperand2AndAddReaderPc(reader)
        registers[high_nibble]! += operand_2
        break
      case 3:
        high_nibble = peekUInt8(reader, 1) >> 4
        operand_2 = getRealOperand2AndAddReaderPc(reader)
        registers[high_nibble]! -= operand_2
        break
      case 4:
        high_nibble = peekUInt8(reader, 1) >> 4
        operand_2 = getRealOperand2AndAddReaderPc(reader)
        registers[high_nibble]! *= operand_2
        /** We found that in x86_64, machine code is
         *     imul reg64, reg/imm
         * so we get the low bits of the result.
         */
        break
      case 5:
        high_nibble = peekUInt8(reader, 1) >> 4
        operand_2 = getRealOperand2AndAddReaderPc(reader)
        registers[high_nibble]! /= operand_2
        /** We found that in x86_64, machine code is
         *     mov r10d, imm32  ; when necessary
         *     mov rax, reg64
         *     cqo
         *     idiv r10/reg64   ; r10/reg64 is the operand_2
         *     mov reg64, rax
         * so rax (0) is tampered.
         */
        registers[0] = registers[high_nibble]!
        break
      case 6:
        high_nibble = peekUInt8(reader, 1) >> 4
        operand_2 = getRealOperand2AndAddReaderPc(reader)
        registers[high_nibble]! ^= operand_2
        break
      case 7:
        high_nibble = peekUInt8(reader, 1) >> 4
        operand_2 = getRealOperand2AndAddReaderPc(reader)
        registers[high_nibble] = operand_2
        break
      case 8:
        /** We found that in x86_64, machine code is
         *     mov reg1, ptr [reg2]
         * This hardly happens.
         */
        reader.pc += 2
        break
      case 9:
        reg = peekUInt8(reader, 1) & 0x7
        out_buffer.writeInt32LE(registers[reg]!, 0)
        reader.pc += 2
        break
      case 0xa:
        /**
         * This happens when 4 bytes of total 12 bytes nonce are calculated,
         * and the result is to be stored in the memory. So the address from
         * register 7 (15) is moved to one of the registers.
         *
         * We don't really care about the address and the register number.
         * So we just skip 6 bytes (0A ... and 02 ...).
         *
         * For example:
         *
         * [0A [1F] 00] - [00][011][111] - mov  rbx<3>, [rbp<7>-18h]
         *                               [rbp-18h] is the address
         * [02 [39] 0C] - [0011][1][001] - add  rbx<3>, 0Ch
         *                               0Ch is a fixed offset
         * [09 [98]   ] - [10][011][000] - mov  [rbx<3>], eax<0>
         *                               eax<0> is the value to be stored
         *
         * Another example:
         *
         * [0A [07] 00] - [00][000][111] - mov  rax<0>, [rbp<7>-18h]
         * [02 [09] 0C] - [0000][1][001] - add  rax<0>, 0Ch
         * [0B [83] 04] - [10][000][011] - mov  [rax<0>+4], ebx<3>
         *                               4 means [4..8] of 12 bytes nonce
         */
        reader.pc += 6
        break
      case 0xb:
        reg = peekUInt8(reader, 1) & 0x7
        out_buffer.writeInt32LE(registers[reg]!, peekUInt8(reader, 2))
        reader.pc += 3
        break
      default:
        console.error("FATAL: Unknown opcode %d at %lld\n", peekUInt8(reader), reader.pc)
        out_buffer.fill(0)
        reader.pc = end
        break
    }
  }
  return out_buffer
}
