import { ed25519 } from "@noble/curves/ed25519";
import type { Signer } from "@dekimuhq/crypto";

// Shared receipt-signer contract (single source of truth in @dekimuhq/crypto).
export type { Signer };

export function ed25519Signer(seed: Uint8Array, keyId: string): Signer {
  return { keyId, alg: "Ed25519", sign: (bytes) => ed25519.sign(bytes, seed) };
}

export function publicKeyOf(seed: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(seed);
}
