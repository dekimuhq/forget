import { canonicalize } from "./canonicalize";
import { bytesToBase64url } from "./b64";
import type { DestructionInput, DestructionReceipt, Signer } from "./types";

/** The exact object that gets signed. Verify recomputes this byte-for-byte. */
export function signedView(input: DestructionInput) {
  return {
    kind: "forget.destruction.v1" as const,
    alg: "Ed25519" as const,
    subjectKeyIdHash: input.subjectKeyIdHash,
    kekKeyId: input.kekKeyId,
    destroyedAt: input.destroyedAt,
    priorRosterRoot: input.priorRosterRoot,
    newRosterRoot: input.newRosterRoot,
  };
}

export async function createDestructionReceipt(input: DestructionInput, signer: Signer): Promise<DestructionReceipt> {
  const bytes = new TextEncoder().encode(canonicalize(signedView(input)));
  const sig = await signer.sign(bytes);
  return {
    kind: "forget.destruction.v1",
    alg: "Ed25519",
    ...input,
    signerKeyId: signer.keyId,
    signature: bytesToBase64url(sig),
  };
}
