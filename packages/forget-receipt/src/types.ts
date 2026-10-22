// Shared receipt-signer contract (single source of truth in @dekimuhq/crypto).
export type { Signer } from "@dekimuhq/crypto";

/** Inputs the caller supplies to mint a destruction receipt. */
export interface DestructionInput {
  /** subjectValue(subjectKeyId) — the roster leaf value; never a raw identifier. */
  readonly subjectKeyIdHash: string;
  /** KEK id (destruction authority). NEVER the destroyed DEK. */
  readonly kekKeyId: string;
  readonly destroyedAt: string; // ISO-8601
  readonly priorRosterRoot: string; // root that still contained the subject
  readonly newRosterRoot: string; // root that no longer contains the subject
}

export interface DestructionReceipt extends DestructionInput {
  readonly kind: "forget.destruction.v1";
  readonly alg: "Ed25519";
  readonly signerKeyId: string; // Ed25519 signing key id (distinct from kekKeyId)
  readonly signature: string; // base64url over canonicalize of the signed view (see create.ts)
}

import type { NonInclusionProof, MembershipProof, SignedRoot } from "@dekimuhq/forget-roster";

/** How the subject's personal data was handled in the MODEL dimension after an erasure request is executed. */
export type Disposition =
  | "not_trained" // data never entered any training/fine-tuning pipeline
  | "retrained" // model retrained from a set with the subject removed
  | "unlearned" // machine-unlearning applied (approximate removal)
  | "scoped_exclusion"; // held but excluded from training by a documented filter

const DISPOSITIONS: readonly Disposition[] = ["not_trained", "retrained", "unlearned", "scoped_exclusion"];
export function isDisposition(v: unknown): v is Disposition {
  return typeof v === "string" && (DISPOSITIONS as readonly string[]).includes(v);
}

/** Dispositions that REQUIRE training-set Merkle evidence (subject absent from the post-removal set). */
export function requiresEvidence(d: Disposition): boolean {
  return d === "retrained" || d === "unlearned";
}

/** Inputs the caller supplies to mint a model-disposition receipt. */
export interface ModelDispositionInput {
  /** subjectValue(subjectKeyId) — the roster leaf value; never a raw identifier. */
  readonly subjectKeyIdHash: string;
  /** "forget:<subjectKeyIdHash>:<newRosterRoot>" — binds this to the PoF destruction receipt. */
  readonly destructionClaimId: string;
  readonly disposition: Disposition;
  /** Free text, normalized + control/bidi-stripped at mint (see sanitizeRationale). */
  readonly rationale: string;
  /** Training-set roster root that INCLUDED the subject. Present ONLY for retrained|unlearned. */
  readonly trainingRootBefore?: string;
  /** Training-set roster root AFTER removal. Present ONLY for retrained|unlearned. */
  readonly trainingRootAfter?: string;
  readonly disposedAt: string; // ISO-8601
}

export interface ModelDispositionReceipt extends ModelDispositionInput {
  readonly kind: "forget.model-disposition.v1";
  readonly alg: "Ed25519";
  readonly signerKeyId: string;
  readonly signature: string; // base64url over canonicalize(signedView)
}

/** Merkle evidence passed to verify for retrained|unlearned (NOT part of the signed view). */
export interface ModelDispositionEvidence {
  /** Signed roster root whose `root` === receipt.trainingRootAfter. */
  readonly trainingAfterSignedRoot: SignedRoot;
  /** Non-inclusion of subjectKeyIdHash against trainingAfterSignedRoot. */
  readonly nonInclusionAfter: NonInclusionProof;
  /** OPTIONAL: signed root whose `root` === receipt.trainingRootBefore. */
  readonly trainingBeforeSignedRoot?: SignedRoot;
  /** OPTIONAL: membership of subjectKeyIdHash against trainingBeforeSignedRoot. */
  readonly membershipBefore?: MembershipProof;
}
