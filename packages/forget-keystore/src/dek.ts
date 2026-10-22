import { randomBytes } from "node:crypto";
import type { EncryptionKey } from "@dekimuhq/crypto";

/** A fresh random 32-byte data-encryption key for one subject. */
export function generateDek(): Uint8Array {
  return new Uint8Array(randomBytes(32));
}

/**
 * Adapt a raw DEK into the EncryptionKey shape @dekimuhq/crypto's
 * encryptField/decryptField expect. The DEK IS the per-subject key.
 */
export function dekKey(dek: Uint8Array): EncryptionKey {
  if (dek.length !== 32) throw new Error("DEK must be 32 bytes");
  return { bytes: Buffer.from(dek) };
}
