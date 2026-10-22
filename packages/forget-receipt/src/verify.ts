import { ed25519 } from "@noble/curves/ed25519";
import { canonicalize } from "./canonicalize";
import { base64urlToBytes } from "./b64";
import { signedView } from "./create";
import type { DestructionReceipt } from "./types";

/**
 * resolveKey IS THE TRUST ANCHOR: map signerKeyId -> public key only for trusted
 * issuer keys; throw otherwise. Verify recomputes the signed view, so any tamper
 * to a signed field invalidates the signature.
 */
export function verifyDestructionReceipt(receipt: DestructionReceipt, resolveKey: (keyId: string) => Uint8Array): boolean {
  try {
    if (receipt.kind !== "forget.destruction.v1" || receipt.alg !== "Ed25519") return false;
    const bytes = new TextEncoder().encode(canonicalize(signedView(receipt)));
    const pub = resolveKey(receipt.signerKeyId);
    return ed25519.verify(base64urlToBytes(receipt.signature), bytes, pub);
  } catch {
    return false;
  }
}
