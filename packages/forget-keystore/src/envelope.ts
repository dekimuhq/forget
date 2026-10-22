import { encryptField, decryptField, type EncryptionKey } from "@dekimuhq/crypto";

/**
 * Wrap a raw DEK under the workspace KEK. The DEK is base64-encoded then
 * AES-256-GCM encrypted via @dekimuhq/crypto, yielding an `enc:v1:` string.
 */
export function wrapDek(dek: Uint8Array, kek: EncryptionKey): string {
  if (dek.length !== 32) throw new Error("DEK must be 32 bytes");
  return encryptField(Buffer.from(dek).toString("base64"), kek);
}

/**
 * Unwrap a wrapped DEK. Returns null if decryption fails (wrong KEK, tampered,
 * or the row was shredded and a stale copy is being probed) — never throws.
 */
export function unwrapDek(wrapped: string, kek: EncryptionKey): Uint8Array | null {
  const b64 = decryptField(wrapped, kek);
  if (b64 === "" || b64 === wrapped) return null; // "" = decrypt failed; ===wrapped = not enc:v1: prefixed
  const bytes = Buffer.from(b64, "base64");
  if (bytes.length !== 32) return null;
  return new Uint8Array(bytes);
}
