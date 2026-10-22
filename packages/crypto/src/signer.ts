/**
 * Detached-signature signer contract shared by the receipt packages
 * (`@dekimuhq/forget-receipt`, `@dekimuhq/forget-roster`). The signer carries
 * a key id + algorithm and signs canonical bytes; production callers back
 * `sign` with a KMS/HSM, tests with an in-memory Ed25519 key.
 *
 * Declared once, here, so an algorithm-agility change (for example a
 * post-quantum signature algorithm) is one edit instead of several drifting
 * copies.
 *
 * NOTE: this is the receipt-signing contract: sign canonical bytes, return raw
 * signature bytes. It is not a general keypair abstraction (no generate or
 * verify, no explicit key material).
 */
export interface Signer {
  /** Key id embedded in the receipt so verifiers can resolve the public key. */
  readonly keyId: string;
  /** Signature algorithm. Ed25519 today; widen here for PQC agility. */
  readonly alg: "Ed25519";
  /** Sign canonical bytes; sync or async (a KMS/HSM signer may be async). */
  sign(bytes: Uint8Array): Uint8Array | Promise<Uint8Array>;
}
