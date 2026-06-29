import aesjs from "aes-js"
import { BinaryReader } from "@depyo/BinaryReader"
import { PycReader } from "@depyo/PycReader"
import type { PythonCodeObject } from "@depyo/PythonObject"
import { peekUInt8, qualNameOrName } from "./util.ts"

export const CO_OBFUSCATED = 0x20000000

if (!(PycReader.prototype as any)._ArmorShot_Hooked_ReadCodeObject) {
  const _originalReadCodeObject = PycReader.prototype.ReadCodeObject

  PycReader.prototype.ReadCodeObject = function (this: PycReader): PythonCodeObject {
    const code_object = _originalReadCodeObject.call(this)

    if (!(code_object.Flags & CO_OBFUSCATED)) {
      return code_object
    }

    const extra_length = this.m_rdr.readByte()
    const extra_data = this.m_rdr.readBytes(extra_length)
    const extra_reader = new BinaryReader(extra_data)

    const pyarmor_fn_count = peekUInt8(extra_reader) & 3
    const pyarmor_co_descriptor_count = (peekUInt8(extra_reader) >> 2) & 3
    // const _pyarmor_bcc = (peekUInt8(extra_reader) >> 4) & 1
    if (pyarmor_co_descriptor_count > 1) {
      console.error(
        "Multiple Pyarmor CO descriptors detected (%d in total)\n",
        pyarmor_co_descriptor_count
      )
    }

    extra_reader.pc += 4
    for (let i = 0; i < pyarmor_fn_count; i++) {
      const item_length = (peekUInt8(extra_reader) >> 6) + 2
      // Ignore the details
      extra_reader.pc += item_length
    }
    for (let i = 0; i < pyarmor_co_descriptor_count; i++) {
      const item_length = (peekUInt8(extra_reader) >> 6) + 2
      const item_end = extra_reader.pc + item_length
      // Ignore low 6 bits
      extra_reader.pc++
      let consts_index = 0
      while (extra_reader.pc < item_end) {
        consts_index = (consts_index << 8) | peekUInt8(extra_reader)
        extra_reader.pc++
      }

      pyarmorDecryptCoCode(consts_index, code_object, this)
    }

    return code_object
  }
}
;(PycReader.prototype as any)._ArmorShot_Hooked_ReadCodeObject = true

function pyarmorDecryptCoCode(
  consts_index: number,
  code_object: PythonCodeObject,
  pycReader: PycReader
): void {
  const descriptor = code_object.Consts.Value[consts_index]
  if (!(descriptor?.Value instanceof Buffer) || descriptor.Value.length < 20) {
    console.error(
      "Invalid Pyarmor CO descriptor at consts index %d of code object %s",
      consts_index,
      qualNameOrName(code_object)
    )
    return
  }

  const flags = descriptor.Value.readUInt8(8)
  const short_nonce_index = descriptor.Value.readUInt8(9)
  // const _ = descriptor.Value.readUInt8(10)
  const decrypt_begin_index = descriptor.Value.readUInt8(11)
  const decrypt_length = descriptor.Value.readUInt32LE(12)
  // const _enter_count = descriptor.Value.readUInt32LE(16)

  const copy_prologue = flags & 0x8
  const xor_aes_nonce = flags & 0x4
  const short_code = flags & 0x2

  const nonce_index = short_code
    ? short_nonce_index
    : short_nonce_index + decrypt_begin_index + decrypt_length

  const nonce = Buffer.alloc(16).fill(0)
  code_object.Code.Value.subarray(nonce_index, nonce_index + 12).copy(nonce, 0, 0, 12)
  nonce[15] = 2

  if (xor_aes_nonce) {
    if (!pycReader.pyarmor_co_code_aes_nonce_xor_enabled) {
      console.error(
        "Pyarmor CO code AES nonce XOR is not enabled but used for code object %s",
        qualNameOrName(code_object)
      )
    } else {
      for (let i = 0; i < 12; i++) {
        nonce[i]! ^= pycReader.pyarmor_co_code_aes_nonce_xor_key[i]!
      }
    }
  }

  const code_bytes = Buffer.copyBytesFrom(code_object.Code.Value)

  const aes_ctr = new aesjs.ModeOfOperation.ctr(pycReader.pyarmor_aes_key, new aesjs.Counter(nonce))
  const decrypted_code = aes_ctr.decrypt(
    code_bytes.subarray(decrypt_begin_index, decrypt_begin_index + decrypt_length)
  )
  code_bytes.set(decrypted_code, decrypt_begin_index)

  if (copy_prologue) {
    code_bytes.set(code_bytes.subarray(decrypt_length, decrypt_length + decrypt_begin_index), 0)
    // Assume tail of code is not used there
    code_bytes.fill(
      pycReader.m_version.minor == 13 ? 30 : pycReader.m_version.minor == 14 ? 27 : 9, // NOP
      decrypt_length,
      decrypt_length + decrypt_begin_index
    )
  }

  code_object.Code.Value.set(code_bytes, 0)
  descriptor.Value.set(new TextEncoder().encode("<COAddr>"), 0)
}

export { PycReader }
