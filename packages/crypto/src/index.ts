import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

export type { Signer } from "./signer";

/**
 * AES-256-GCM field encryption for application data.
 *
 * Wire format: `enc:v1:<base64(iv || tag || ciphertext)>`
 * - `iv`: 12 bytes, random per encrypt
 * - `tag`: 16 bytes (GCM authentication tag)
 * - `ciphertext`: UTF-8 plaintext, AES-256-GCM encrypted
 *
 * The `enc:v1:` prefix is how callers identify already-encrypted values
 * without keeping a parallel schema of encrypted-vs-plain fields.
 * Rotating versions: bump the prefix (`enc:v2:`) and add a second codepath
 * that handles both on decrypt, writes v2 on encrypt.
 *
 * Key management: every caller passes a 32-byte key (base64-decoded from
 * `DATA_ENCRYPTION_KEY` or equivalent). The package intentionally does
 * not read env vars — that keeps callers explicit about which key powers
 * which field and makes testing trivial.
 */

const PREFIX = "enc:v1:";
const IV_BYTES = 12;
const TAG_BYTES = 16;

export interface EncryptionKey {
  readonly bytes: Buffer;
}

/**
 * Wrap a 32-byte key buffer. Validates length once so downstream calls
 * can assume the key is sane.
 */
export function loadKey(rawBase64: string): EncryptionKey {
  if (!rawBase64) throw new Error("encryption key is required");
  const bytes = Buffer.from(rawBase64, "base64");
  if (bytes.length !== 32) {
    throw new Error("encryption key must decode to 32 bytes (base64)");
  }
  return { bytes };
}

export function encryptField(plain: string, key: EncryptionKey): string {
  if (plain === "") return "";
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key.bytes, iv);
  const ct = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return PREFIX + Buffer.concat([iv, tag, ct]).toString("base64");
}

export function decryptField(value: string, key: EncryptionKey): string {
  if (value === "" || !value.startsWith(PREFIX)) return value;
  try {
    const payload = Buffer.from(value.slice(PREFIX.length), "base64");
    if (payload.length < IV_BYTES + TAG_BYTES) return "";
    const iv = payload.subarray(0, IV_BYTES);
    const tag = payload.subarray(IV_BYTES, IV_BYTES + TAG_BYTES);
    const ct = payload.subarray(IV_BYTES + TAG_BYTES);
    const decipher = createDecipheriv("aes-256-gcm", key.bytes, iv);
    decipher.setAuthTag(tag);
    const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
    return pt.toString("utf8");
  } catch {
    return "";
  }
}

export function isEncrypted(value: string): boolean {
  return value.startsWith(PREFIX);
}

/**
 * Encrypt every string-valued field whose key is in `fieldList`. Fields
 * absent from the object are left untouched. Non-string values on listed
 * keys are left unchanged (callers should not register non-string keys).
 *
 * Shape is preserved — the returned object is a shallow clone with only
 * the listed fields replaced.
 */
export function encryptFields<T extends Record<string, unknown>>(
  obj: T,
  fieldList: readonly (keyof T)[],
  key: EncryptionKey,
): T {
  const out = { ...obj };
  for (const field of fieldList) {
    const current = out[field];
    if (typeof current === "string" && current !== "" && !isEncrypted(current)) {
      (out as Record<string, unknown>)[field as string] = encryptField(
        current,
        key,
      );
    }
  }
  return out;
}

export function decryptFields<T extends Record<string, unknown>>(
  obj: T,
  fieldList: readonly (keyof T)[],
  key: EncryptionKey,
): T {
  const out = { ...obj };
  for (const field of fieldList) {
    const current = out[field];
    if (typeof current === "string" && isEncrypted(current)) {
      (out as Record<string, unknown>)[field as string] = decryptField(
        current,
        key,
      );
    }
  }
  return out;
}
