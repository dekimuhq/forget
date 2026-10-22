import { RSA_ALGORITHM, IV_BYTES, KID_BYTES, VAULT_VERSION } from "./types.js";
import type { EncryptedBlob, ExportedPublicKey } from "./types.js";
import { toBase64Url, fromBase64Url, toBuffer } from "./encoding.js";

const crypto = globalThis.crypto;

/** Generate an RSA-OAEP-4096 keypair for hybrid encryption. */
export async function generateKeypair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(RSA_ALGORITHM, true, [
    "encrypt",
    "decrypt",
    "wrapKey",
    "unwrapKey",
  ]) as Promise<CryptoKeyPair>;
}

/** Export a public key as a serializable object for server storage. */
export async function exportPublicKey(
  publicKey: CryptoKey,
): Promise<ExportedPublicKey> {
  const spki = await crypto.subtle.exportKey("spki", publicKey);
  return {
    v: VAULT_VERSION,
    spki: toBase64Url(new Uint8Array(spki)),
  };
}

/** Import a public key from its serialized form. */
export async function importPublicKey(
  exported: ExportedPublicKey,
): Promise<CryptoKey> {
  const spki = fromBase64Url(exported.spki);
  return crypto.subtle.importKey("spki", toBuffer(spki), RSA_ALGORITHM, true, [
    "encrypt",
    "wrapKey",
  ]);
}

/**
 * Derive a key id from an exported public key: base64url(SHA-256(spki)[0..16]).
 *
 * Deterministic and self-verifying — given a public key you can recompute the
 * kid and confirm a blob claims that key, with no lookup table to keep in sync.
 * A new keypair yields a new kid for free.
 */
export async function computeKid(exported: ExportedPublicKey): Promise<string> {
  const spki = fromBase64Url(exported.spki);
  return kidFromSpki(toBuffer(spki));
}

/**
 * computeKid for a live CryptoKey. Lets encryptContent verify that a caller's
 * kid actually belongs to the recipient key it was handed, rather than trusting
 * the pairing.
 *
 * Requires an extractable public key. Public keys are public — there is no
 * reason to import one non-extractable, and both importPublicKey and
 * generateKeypair produce extractable ones.
 */
export async function computeKidForKey(publicKey: CryptoKey): Promise<string> {
  const spki = await crypto.subtle.exportKey("spki", publicKey);
  return kidFromSpki(spki);
}

async function kidFromSpki(spki: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", spki);
  return toBase64Url(new Uint8Array(digest).slice(0, KID_BYTES));
}

/**
 * Export an RSA private key as base64url PKCS8 — the payload that gets wrapped
 * to a workspace member via encryptContent().
 */
export async function exportPrivateKeyPkcs8(
  privateKey: CryptoKey,
): Promise<string> {
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", privateKey);
  return toBase64Url(new Uint8Array(pkcs8));
}

/**
 * Import a base64url PKCS8 RSA private key. Always non-extractable.
 *
 * There is deliberately no `extractable` option. Re-wrapping a workspace key to
 * another member never needs one: the granter re-derives the PKCS8 from their
 * own wrap (decryptContent(wrap, personalPriv)) and holds it transiently, so an
 * exportable handle at rest buys nothing and only widens what an XSS payload
 * can walk off with. If a future caller thinks it needs `extractable: true`,
 * that is the signal to re-read the grant flow, not to add the flag back.
 */
export async function importPrivateKeyPkcs8(b64: string): Promise<CryptoKey> {
  const pkcs8 = fromBase64Url(b64);
  return crypto.subtle.importKey(
    "pkcs8",
    toBuffer(pkcs8),
    RSA_ALGORITHM,
    false,
    ["decrypt", "unwrapKey"],
  );
}

/**
 * Encrypt an RSA private key with the vault key (AES-256-GCM wrapping).
 * The result is an opaque blob that requires the vault key to unwrap.
 */
export async function encryptPrivateKey(
  privateKey: CryptoKey,
  vaultKey: CryptoKey,
): Promise<EncryptedBlob> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const wrapped = await crypto.subtle.wrapKey("pkcs8", privateKey, vaultKey, {
    name: "AES-GCM",
    iv: toBuffer(iv),
  });
  return {
    v: VAULT_VERSION,
    iv: toBase64Url(iv),
    data: toBase64Url(new Uint8Array(wrapped)),
  };
}

/** Decrypt an RSA private key using the vault key. */
export async function decryptPrivateKey(
  blob: EncryptedBlob,
  vaultKey: CryptoKey,
): Promise<CryptoKey> {
  const iv = fromBase64Url(blob.iv);
  const wrapped = fromBase64Url(blob.data);
  return crypto.subtle.unwrapKey(
    "pkcs8",
    toBuffer(wrapped),
    vaultKey,
    { name: "AES-GCM", iv: toBuffer(iv) },
    RSA_ALGORITHM,
    true,
    ["decrypt", "unwrapKey"],
  );
}

/**
 * Encrypt the vault key with the master key (password-derived).
 * Used to store the vault key on the server, protected by the user's password.
 */
export async function encryptVaultKey(
  vaultKey: CryptoKey,
  masterKey: CryptoKey,
): Promise<EncryptedBlob> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const wrapped = await crypto.subtle.wrapKey("raw", vaultKey, masterKey, {
    name: "AES-GCM",
    iv: toBuffer(iv),
  });
  return {
    v: VAULT_VERSION,
    iv: toBase64Url(iv),
    data: toBase64Url(new Uint8Array(wrapped)),
  };
}

/** Decrypt the vault key using the master key. */
export async function decryptVaultKey(
  blob: EncryptedBlob,
  masterKey: CryptoKey,
): Promise<CryptoKey> {
  const iv = fromBase64Url(blob.iv);
  const wrapped = fromBase64Url(blob.data);
  return crypto.subtle.unwrapKey(
    "raw",
    toBuffer(wrapped),
    masterKey,
    { name: "AES-GCM", iv: toBuffer(iv) },
    { name: "AES-GCM", length: 256 },
    true,
    ["wrapKey", "unwrapKey"],
  );
}
