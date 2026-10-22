/**
 * @dekimuhq/crypto/vault — end-to-end encryption client module.
 *
 * All operations use the WebCrypto API (browser, or Node >=22). The design
 * keeps plaintext content and unwrapped keys on the client: the server stores
 * ciphertext and wrapped keys only.
 *
 * Key architecture (3-layer):
 *   password → PBKDF2 → master key → decrypts → vault key → decrypts → RSA private key
 *                                                   ↑
 *                                    recovery phrase encodes this
 *
 * Content encryption (hybrid):
 *   plaintext → AES-256-GCM (random content key) → ciphertext
 *   content key → RSA-OAEP (recipient public key) → wrapped key
 */

// Key derivation
export { generateSalt, deriveKey, generateVaultKey } from "./derive.js";

// Keypair management
export {
  generateKeypair,
  exportPublicKey,
  importPublicKey,
  computeKid,
  computeKidForKey,
  exportPrivateKeyPkcs8,
  importPrivateKeyPkcs8,
  encryptPrivateKey,
  decryptPrivateKey,
  encryptVaultKey,
  decryptVaultKey,
} from "./keypair.js";

// Content encryption
export { encryptContent, decryptContent } from "./content.js";

// Recovery
export {
  generateRecoveryPhrase,
  recoverVaultKey,
  validateRecoveryPhrase,
} from "./recovery.js";

// Types
export type {
  EncryptedBlob,
  EncryptedContent,
  ExportedPublicKey,
  VaultBundle,
  RecoveryPhrase,
} from "./types.js";

export { VAULT_VERSION, KID_BYTES } from "./types.js";

// ── High-level flows ──────────────────────────────────────────────

import { generateSalt, deriveKey, generateVaultKey } from "./derive.js";
import {
  generateKeypair,
  exportPublicKey,
  encryptPrivateKey,
  decryptPrivateKey,
  encryptVaultKey,
  decryptVaultKey,
} from "./keypair.js";
import { generateRecoveryPhrase, recoverVaultKey } from "./recovery.js";
import { toBase64Url } from "./encoding.js";
import type { VaultBundle, RecoveryPhrase } from "./types.js";

export interface ProvisionResult {
  bundle: VaultBundle;
  recoveryPhrase: RecoveryPhrase;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}

/**
 * Provision a new vault for a user at signup.
 * Returns everything the server needs to store + the recovery phrase to show once.
 */
export async function provisionVault(
  password: string,
): Promise<ProvisionResult> {
  const salt = generateSalt();
  const masterKey = await deriveKey(password, salt);
  const vaultKey = await generateVaultKey();
  const keypair = await generateKeypair();

  const [encVaultKey, encPrivateKey, pubKey, recovery] = await Promise.all([
    encryptVaultKey(vaultKey, masterKey),
    encryptPrivateKey(keypair.privateKey, vaultKey),
    exportPublicKey(keypair.publicKey),
    generateRecoveryPhrase(vaultKey),
  ]);

  return {
    bundle: {
      encryptedVaultKey: encVaultKey,
      encryptedPrivateKey: encPrivateKey,
      publicKey: pubKey,
      salt: toBase64Url(salt),
    },
    recoveryPhrase: recovery,
    privateKey: keypair.privateKey,
    publicKey: keypair.publicKey,
  };
}

export interface UnlockResult {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  vaultKey: CryptoKey;
}

/**
 * Unlock a vault on login using the user's password.
 */
export async function unlockVault(
  password: string,
  bundle: VaultBundle,
): Promise<UnlockResult> {
  const { fromBase64Url } = await import("./encoding.js");
  const salt = fromBase64Url(bundle.salt);
  const masterKey = await deriveKey(password, salt);
  const vaultKey = await decryptVaultKey(bundle.encryptedVaultKey, masterKey);
  const [privateKey, publicKey] = await Promise.all([
    decryptPrivateKey(bundle.encryptedPrivateKey, vaultKey),
    (await import("./keypair.js")).importPublicKey(bundle.publicKey),
  ]);

  return { privateKey, publicKey, vaultKey };
}

/**
 * Unlock a vault using a recovery phrase (password lost).
 */
export async function unlockVaultWithRecovery(
  phrase: string,
  bundle: VaultBundle,
): Promise<UnlockResult> {
  const vaultKey = await recoverVaultKey(phrase);
  const [privateKey, publicKey] = await Promise.all([
    decryptPrivateKey(bundle.encryptedPrivateKey, vaultKey),
    (await import("./keypair.js")).importPublicKey(bundle.publicKey),
  ]);

  return { privateKey, publicKey, vaultKey };
}

/**
 * Change password: re-encrypt the vault key with a new master key.
 * Returns the updated encrypted vault key blob. Recovery phrase unchanged.
 */
export async function changePassword(
  oldPassword: string,
  newPassword: string,
  bundle: VaultBundle,
): Promise<VaultBundle> {
  const { fromBase64Url } = await import("./encoding.js");
  const salt = fromBase64Url(bundle.salt);

  const oldMasterKey = await deriveKey(oldPassword, salt);
  const vaultKey = await decryptVaultKey(bundle.encryptedVaultKey, oldMasterKey);

  // New salt for new password derivation
  const newSalt = generateSalt();
  const newMasterKey = await deriveKey(newPassword, newSalt);
  const newEncVaultKey = await encryptVaultKey(vaultKey, newMasterKey);

  return {
    ...bundle,
    encryptedVaultKey: newEncVaultKey,
    salt: toBase64Url(newSalt),
  };
}

/**
 * Reset password using a recovery phrase (password lost).
 * Validates the phrase against the bundle, then re-encrypts the vault key
 * with a new password-derived master key. Recovery phrase unchanged.
 */
export async function resetPasswordWithRecovery(
  phrase: string,
  newPassword: string,
  bundle: VaultBundle,
): Promise<VaultBundle> {
  const vaultKey = await recoverVaultKey(phrase);

  // Verify phrase matches this bundle by decrypting the private key
  await decryptPrivateKey(bundle.encryptedPrivateKey, vaultKey);

  const newSalt = generateSalt();
  const newMasterKey = await deriveKey(newPassword, newSalt);
  const newEncVaultKey = await encryptVaultKey(vaultKey, newMasterKey);

  return {
    ...bundle,
    encryptedVaultKey: newEncVaultKey,
    salt: toBase64Url(newSalt),
  };
}
