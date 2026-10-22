import { ed25519 } from "@noble/curves/ed25519";
import { canonicalize } from "./canonicalize";
import { bytesToBase64url, base64urlToBytes } from "./b64";
import type { Signer } from "./signer";

export interface RootHead {
  readonly root: string;
  readonly leafCount: number;
  readonly generatedAt: string;
  readonly prevRoot: string | null;
}

export interface SignedRoot extends RootHead {
  readonly kind: "forget.roster.v1";
  readonly alg: "Ed25519";
  readonly keyId: string;
  readonly signature: string; // base64url over canonicalize({ kind, alg, root, leafCount, generatedAt, prevRoot })
}

function signedBytes(head: RootHead): Uint8Array {
  return new TextEncoder().encode(
    canonicalize({ kind: "forget.roster.v1", alg: "Ed25519", root: head.root, leafCount: head.leafCount, generatedAt: head.generatedAt, prevRoot: head.prevRoot }),
  );
}

export async function signRoot(head: RootHead, signer: Signer): Promise<SignedRoot> {
  const sig = await signer.sign(signedBytes(head));
  return { kind: "forget.roster.v1", alg: "Ed25519", keyId: signer.keyId, signature: bytesToBase64url(sig), ...head };
}

/**
 * resolveKey IS THE TRUST ANCHOR:
 * it must map keyId -> public key only for keys in a trusted issuer registry,
 * and throw otherwise. A resolveKey that trusts any keyId defeats the model.
 */
export function verifyRoot(signed: SignedRoot, resolveKey: (keyId: string) => Uint8Array): boolean {
  try {
    if (signed.kind !== "forget.roster.v1" || signed.alg !== "Ed25519") return false;
    const bytes = signedBytes(signed);
    const pub = resolveKey(signed.keyId);
    return ed25519.verify(base64urlToBytes(signed.signature), bytes, pub);
  } catch {
    return false;
  }
}
