/** Version prefix for all vault wire formats. */
export const VAULT_VERSION = "zkv1" as const;

/** PBKDF2 iteration count — OWASP 2023 recommendation for SHA-256. */
export const KDF_ITERATIONS = 600_000;

/** Salt length in bytes. */
export const SALT_BYTES = 32;

/** AES-GCM IV length in bytes. */
export const IV_BYTES = 12;

/** Key-id length in bytes — truncated SHA-256 of the SPKI public key. */
export const KID_BYTES = 16;

/** RSA modulus length in bits. */
export const RSA_MODULUS_LENGTH = 4096;

/** RSA key algorithm parameters (OAEP + SHA-256). */
export const RSA_ALGORITHM: RsaHashedKeyGenParams = {
  name: "RSA-OAEP",
  modulusLength: RSA_MODULUS_LENGTH,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: "SHA-256",
};

/** Encrypted blob stored on the server — opaque without the decryption key. */
export interface EncryptedBlob {
  /** Wire format version. */
  v: typeof VAULT_VERSION;
  /** Base64url-encoded IV. */
  iv: string;
  /** Base64url-encoded ciphertext. */
  data: string;
}

/** Encrypted content with its own wrapped content key. */
export interface EncryptedContent {
  /** Wire format version. */
  v: typeof VAULT_VERSION;
  /**
   * Recipient key id — truncated SHA-256 of the recipient's SPKI public key.
   * Absent means a user-era blob wrapped to a personal key; present means it is
   * wrapped to the workspace key with this id. Without it the two eras are
   * indistinguishable and a migration has no idempotence predicate.
   */
  kid?: string;
  /** Base64url-encoded IV used for content encryption. */
  iv: string;
  /** Base64url-encoded AES-256-GCM ciphertext. */
  data: string;
  /** Base64url-encoded content key, RSA-OAEP encrypted with the recipient's public key. */
  key: string;
}

/** Serializable public key for server storage. */
export interface ExportedPublicKey {
  /** Wire format version. */
  v: typeof VAULT_VERSION;
  /** Base64url-encoded SPKI public key. */
  spki: string;
}

/** Everything the server stores for a user's vault. */
export interface VaultBundle {
  /** Encrypted vault key (decryptable with master key derived from password). */
  encryptedVaultKey: EncryptedBlob;
  /** Encrypted RSA private key (decryptable with vault key). */
  encryptedPrivateKey: EncryptedBlob;
  /** Plaintext public key for sharing/workspace encryption. */
  publicKey: ExportedPublicKey;
  /** PBKDF2 salt — stored plaintext, unique per user. */
  salt: string;
}

/** Recovery phrase shown once at signup. */
export interface RecoveryPhrase {
  /** Ordered word list (24 words for 256-bit vault key). */
  words: readonly string[];
  /** Space-separated phrase for display. */
  phrase: string;
}
