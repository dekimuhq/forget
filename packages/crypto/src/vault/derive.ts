import { KDF_ITERATIONS, SALT_BYTES } from "./types.js";
import { toBuffer } from "./encoding.js";

const crypto = globalThis.crypto;

/** Generate a random salt for key derivation. */
export function generateSalt(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(SALT_BYTES));
}

/**
 * Derive a master key from a password + salt using PBKDF2-SHA-256.
 *
 * The returned CryptoKey is non-extractable and scoped to wrapKey/unwrapKey —
 * it only ever wraps/unwraps the vault key via AES-256-GCM, never leaves
 * the WebCrypto boundary.
 */
export async function deriveKey(
  password: string,
  salt: Uint8Array,
): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: toBuffer(salt),
      iterations: KDF_ITERATIONS,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["wrapKey", "unwrapKey"],
  );
}

/** Generate a random 256-bit AES-GCM vault key. */
export async function generateVaultKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["wrapKey", "unwrapKey"],
  );
}

/** Export vault key as raw bytes (for BIP39 encoding). */
export async function exportVaultKeyRaw(
  vaultKey: CryptoKey,
): Promise<Uint8Array> {
  const raw = await crypto.subtle.exportKey("raw", vaultKey);
  return new Uint8Array(raw);
}

/** Import raw bytes as a vault key. */
export async function importVaultKeyRaw(
  raw: Uint8Array,
): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    toBuffer(raw),
    { name: "AES-GCM", length: 256 },
    true,
    ["wrapKey", "unwrapKey"],
  );
}
