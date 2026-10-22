import { BIP39_ENGLISH } from "./wordlist.js";
import { exportVaultKeyRaw, importVaultKeyRaw } from "./derive.js";
import { toBuffer } from "./encoding.js";
import type { RecoveryPhrase } from "./types.js";

const crypto = globalThis.crypto;

/** Read `count` bits starting at bit `offset` from a byte array (MSB-first). */
function readBits(bytes: Uint8Array, offset: number, count: number): number {
  let value = 0;
  for (let i = 0; i < count; i++) {
    const byteIdx = Math.floor((offset + i) / 8);
    const bitIdx = 7 - ((offset + i) % 8);
    value = (value << 1) | ((bytes[byteIdx]! >> bitIdx) & 1);
  }
  return value;
}

/** Write `count` bits of `value` starting at bit `offset` into a byte array (MSB-first). */
function writeBits(
  bytes: Uint8Array,
  offset: number,
  count: number,
  value: number,
): void {
  for (let i = 0; i < count; i++) {
    const byteIdx = Math.floor((offset + i) / 8);
    const bitIdx = 7 - ((offset + i) % 8);
    if ((value >> (count - 1 - i)) & 1) {
      bytes[byteIdx]! |= 1 << bitIdx;
    }
  }
}

/**
 * Encode a 256-bit vault key as a 24-word BIP39 mnemonic.
 *
 * BIP39 encodes 256 bits of entropy + 8-bit SHA-256 checksum = 264 bits = 24 words (11 bits each).
 * The recovery phrase IS the vault key — no derivation needed on recovery.
 */
export async function generateRecoveryPhrase(
  vaultKey: CryptoKey,
): Promise<RecoveryPhrase> {
  const entropy = await exportVaultKeyRaw(vaultKey);
  if (entropy.length !== 32) {
    throw new Error("vault key must be 256 bits");
  }

  const hash = await crypto.subtle.digest("SHA-256", toBuffer(entropy));
  const checksum = new Uint8Array(hash)[0]!;

  // 256 bits entropy + 8 bits checksum = 264 bits
  const bits = new Uint8Array(33);
  bits.set(entropy);
  bits[32] = checksum;

  const words: string[] = [];
  for (let i = 0; i < 24; i++) {
    const value = readBits(bits, i * 11, 11);
    const word = BIP39_ENGLISH[value];
    if (!word) throw new Error(`invalid word index: ${value}`);
    words.push(word);
  }

  return {
    words: Object.freeze(words),
    phrase: words.join(" "),
  };
}

/**
 * Recover a vault key from a 24-word BIP39 mnemonic.
 * Validates the checksum before returning.
 */
export async function recoverVaultKey(phrase: string): Promise<CryptoKey> {
  const words = phrase.trim().toLowerCase().split(/\s+/);
  if (words.length !== 24) {
    throw new Error("recovery phrase must be exactly 24 words");
  }

  const indices: number[] = [];
  for (const word of words) {
    const idx = BIP39_ENGLISH.indexOf(word);
    if (idx === -1) throw new Error(`unknown word: "${word}"`);
    indices.push(idx);
  }

  // Reconstruct 264 bits (256 entropy + 8 checksum)
  const bits = new Uint8Array(33);
  for (let i = 0; i < 24; i++) {
    writeBits(bits, i * 11, 11, indices[i]!);
  }

  const entropy = bits.slice(0, 32);
  const checksumByte = bits[32]!;

  const hash = await crypto.subtle.digest("SHA-256", toBuffer(entropy));
  const expectedChecksum = new Uint8Array(hash)[0]!;
  if (checksumByte !== expectedChecksum) {
    throw new Error("invalid recovery phrase (checksum mismatch)");
  }

  return importVaultKeyRaw(entropy);
}

/**
 * Validate a recovery phrase without importing the key.
 * Returns true if the phrase is well-formed and checksum-valid.
 */
export async function validateRecoveryPhrase(phrase: string): Promise<boolean> {
  try {
    await recoverVaultKey(phrase);
    return true;
  } catch {
    return false;
  }
}
