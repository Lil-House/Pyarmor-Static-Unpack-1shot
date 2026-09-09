import aesjs from "aes-js"

export function pyarmorMixStringDecrypt(
  source: Buffer,
  aesKey: Buffer,
  aesNonce: Buffer
): {
  decrypted: boolean
  result: Buffer
} {
  if (
    source.length === 0 ||
    !(source[0]! & 0x80) ||
    (source[0]! & 0x7f) == 0 ||
    (source[0]! & 0x7f) > 4
  ) {
    return {
      decrypted: false,
      result: Buffer.copyBytesFrom(source),
    }
  }

  const nonce = Buffer.alloc(16).fill(0)
  aesNonce.copy(nonce, 0, 0, 12)
  nonce[15] = 2

  const aes_ctr = new aesjs.ModeOfOperation.ctr(aesKey, new aesjs.Counter(nonce))
  const decrypted = Buffer.from(aes_ctr.decrypt(source.subarray(1)))

  return {
    decrypted: true,
    result: decrypted,
  }
}
