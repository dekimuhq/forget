import { canonicalize } from "./canonicalize";
import { bytesToBase64url, base64urlToBytes } from "./b64";
import { sanitizeRationale } from "./text";
import { isDisposition, requiresEvidence } from "./types";
import type { ModelDispositionInput, ModelDispositionReceipt, ModelDispositionEvidence, DestructionReceipt, Signer } from "./types";
import { ed25519 } from "@noble/curves/ed25519";
import { verifyNonInclusionSigned, verifyMembershipSigned } from "@dekimuhq/forget-roster";
import { verifyDestructionReceipt } from "./verify";

/** The exact object that gets signed. Verify recomputes this byte-for-byte. */
export function signedView(input: ModelDispositionInput) {
  return {
    kind: "forget.model-disposition.v1" as const,
    alg: "Ed25519" as const,
    subjectKeyIdHash: input.subjectKeyIdHash,
    destructionClaimId: input.destructionClaimId,
    disposition: input.disposition,
    rationale: input.rationale,
    // canonicalize() omits undefined keys, so optional roots drop out consistently
    // for not_trained/scoped_exclusion at BOTH sign and verify.
    trainingRootBefore: input.trainingRootBefore,
    trainingRootAfter: input.trainingRootAfter,
    disposedAt: input.disposedAt,
  };
}

/** Reject malformed input before signing: enforce the per-disposition shape invariant. */
function assertShape(input: ModelDispositionInput): void {
  if (!isDisposition(input.disposition)) throw new Error("model-disposition: unknown disposition");
  const hasRoots = input.trainingRootBefore !== undefined || input.trainingRootAfter !== undefined;
  if (requiresEvidence(input.disposition)) {
    if (input.trainingRootBefore === undefined || input.trainingRootAfter === undefined) {
      throw new Error(`model-disposition: ${input.disposition} requires trainingRootBefore + trainingRootAfter`);
    }
  } else if (hasRoots) {
    throw new Error(`model-disposition: ${input.disposition} must not carry training roots`);
  }
  if (!input.destructionClaimId.startsWith("forget:")) {
    throw new Error("model-disposition: destructionClaimId must bind a forget destruction claim");
  }
}

export async function createModelDispositionReceipt(
  input: ModelDispositionInput,
  signer: Signer,
): Promise<ModelDispositionReceipt> {
  const normalized: ModelDispositionInput = { ...input, rationale: sanitizeRationale(input.rationale) };
  assertShape(normalized);
  const bytes = new TextEncoder().encode(canonicalize(signedView(normalized)));
  const sig = await signer.sign(bytes);
  return {
    kind: "forget.model-disposition.v1",
    alg: "Ed25519",
    ...normalized,
    signerKeyId: signer.keyId,
    signature: bytesToBase64url(sig),
  };
}

export interface VerifyModelDispositionOpts {
  /** Required for retrained|unlearned; ignored otherwise. */
  readonly evidence?: ModelDispositionEvidence;
  /** OPTIONAL: the destruction receipt this disposition binds to (checks the PoF link). */
  readonly destruction?: DestructionReceipt;
}

/**
 * Offline verifier. resolveKey IS THE TRUST ANCHOR (throws for untrusted keys).
 * Fails closed on every check. Checks, in order:
 *   1. kind/alg/disposition shape
 *   2. signature recompute under resolveKey
 *   3. per-disposition evidence-presence invariant
 *   4. (retrained|unlearned) non-inclusion of the subject against trainingRootAfter (+ optional membership before)
 *   5. PoF binding against the supplied destruction receipt (when given)
 */
export function verifyModelDisposition(
  receipt: ModelDispositionReceipt,
  opts: VerifyModelDispositionOpts,
  resolveKey: (keyId: string) => Uint8Array,
): boolean {
  try {
    if (receipt.kind !== "forget.model-disposition.v1" || receipt.alg !== "Ed25519") return false;
    if (!isDisposition(receipt.disposition)) return false;

    // (2) signature
    const bytes = new TextEncoder().encode(canonicalize(signedView(receipt)));
    if (!ed25519.verify(base64urlToBytes(receipt.signature), bytes, resolveKey(receipt.signerKeyId))) return false;

    // (3) shape invariant (defence-in-depth; mint already enforces it)
    const needsEvidence = requiresEvidence(receipt.disposition);
    const hasRoots = receipt.trainingRootBefore !== undefined && receipt.trainingRootAfter !== undefined;
    if (needsEvidence && !hasRoots) return false;
    if (!needsEvidence && (receipt.trainingRootBefore !== undefined || receipt.trainingRootAfter !== undefined)) return false;

    // (4) Merkle evidence for retrained|unlearned
    if (needsEvidence) {
      const ev = opts.evidence;
      if (!ev) return false;
      if (ev.trainingAfterSignedRoot.root !== receipt.trainingRootAfter) return false;
      if (!verifyNonInclusionSigned(receipt.subjectKeyIdHash, ev.nonInclusionAfter, ev.trainingAfterSignedRoot, resolveKey)) {
        return false;
      }
      // membership-before is optional but, if supplied, must check out
      if (ev.trainingBeforeSignedRoot && ev.membershipBefore) {
        if (ev.trainingBeforeSignedRoot.root !== receipt.trainingRootBefore) return false;
        if (!verifyMembershipSigned(receipt.subjectKeyIdHash, ev.membershipBefore, ev.trainingBeforeSignedRoot, resolveKey)) {
          return false;
        }
      }
    }

    // (5) PoF binding
    if (opts.destruction) {
      const d = opts.destruction;
      if (d.subjectKeyIdHash !== receipt.subjectKeyIdHash) return false;
      if (receipt.destructionClaimId !== `forget:${d.subjectKeyIdHash}:${d.newRosterRoot}`) return false;
    }

    return true;
  } catch {
    return false;
  }
}

/**
 * Full "deleted AND model-dimension addressed" verdict: the shipped destruction-receipt
 * check AND the disposition check, with the disposition's PoF binding verified against
 * THIS destruction receipt. Pass evidence in opts for retrained|unlearned dispositions.
 */
export function verifyForgottenEndToEnd(
  destruction: DestructionReceipt,
  disposition: ModelDispositionReceipt,
  opts: Pick<VerifyModelDispositionOpts, "evidence">,
  resolveKey: (keyId: string) => Uint8Array,
): boolean {
  if (!verifyDestructionReceipt(destruction, resolveKey)) return false;
  return verifyModelDisposition(disposition, { ...opts, destruction }, resolveKey);
}
