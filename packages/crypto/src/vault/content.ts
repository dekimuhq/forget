import { IV_BYTES, VAULT_VERSION } from "./types.js";
import type { EncryptedContent } from "./types.js";
import { toBase64Url, fromBase64Url, toBuffer } from "./encoding.js";
import { computeKidForKey } from "./keypair.js";

const crypto = globalThis.crypto;

/**
 * `kid` travels in the clear, outside the ciphertext, so on its own it is
 * attacker-malleable — and this design treats the server that stores blobs as
 * the attacker. Binding it as AES-GCM additional authenticated data makes tampering
 * loud: strip or swap it and the GCM tag check fails instead of silently
 * re-classifying which era a blob belongs to.
 *
 * Empty AAD is identical to omitted AAD in AES-GCM, so a blob written before
 * `kid` existed (no AAD) still decrypts under `aad("")`. That equivalence is
 * what makes this additive rather than a wire break — it is pinned by the
 * "legacy blob written without AAD" test.
 */
function aad(kid: string | undefined): Uint8Array {
  return new TextEncoder().encode(kid ?? "");
}

/**
 * Encrypt content using hybrid encryption:
 * 1. Generate random AES-256-GCM content key
 * 2. Encrypt plaintext with content key
 * 3. Wrap content key with recipient's RSA-OAEP public key
 *
 * The server sees only ciphertext and a wrapped key it cannot unwrap.
 */
export async function encryptContent(
  plaintext: string,
  recipientPublicKey: CryptoKey,
  kid?: string,
): Promise<EncryptedContent> {
  const encoder = new TextEncoder();

  // A kid that does not belong to recipientPublicKey would stamp a blob as
  // "migrated to key K" while actually being decryptable only by some other
  // key — undecryptable-but-believed-done, which no server-side repair can fix
  // when the server holds only wrapped keys. The check is a public-key export plus a SHA-256
  // against an RSA-4096 wrap that dominates the call; verifying beats trusting.
  if (kid !== undefined) {
    if (!kid) throw new Error("kid must be a non-empty string");
    const expected = await computeKidForKey(recipientPublicKey);
    if (expected !== kid) {
      throw new Error("kid does not match recipientPublicKey");
    }
  }

  const contentKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt"],
  );

  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: toBuffer(iv), additionalData: toBuffer(aad(kid)) },
    contentKey,
    encoder.encode(plaintext),
  );

  const wrappedKey = await crypto.subtle.wrapKey(
    "raw",
    contentKey,
    recipientPublicKey,
    { name: "RSA-OAEP" },
  );

  return {
    v: VAULT_VERSION,
    // Conditional spread, not `kid: kid` — emitting `kid: undefined` would
    // survive into stored JSON in some serializers and blur the absent/present
    // distinction the migration's idempotence predicate depends on.
    ...(kid ? { kid } : {}),
    iv: toBase64Url(iv),
    data: toBase64Url(new Uint8Array(ciphertext)),
    key: toBase64Url(new Uint8Array(wrappedKey)),
  };
}

/**
 * Decrypt content using the recipient's RSA-OAEP private key:
 * 1. Unwrap the content key with the private key
 * 2. Decrypt the ciphertext with the content key
 */
export async function decryptContent(
  encrypted: EncryptedContent,
  recipientPrivateKey: CryptoKey,
): Promise<string> {
  const iv = fromBase64Url(encrypted.iv);
  const ciphertext = fromBase64Url(encrypted.data);
  const wrappedKey = fromBase64Url(encrypted.key);

  const contentKey = await crypto.subtle.unwrapKey(
    "raw",
    toBuffer(wrappedKey),
    recipientPrivateKey,
    { name: "RSA-OAEP" },
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );

  const plainBuffer = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: toBuffer(iv),
      additionalData: toBuffer(aad(encrypted.kid)),
    },
    contentKey,
    toBuffer(ciphertext),
  );

  return new TextDecoder().decode(plainBuffer);
}
