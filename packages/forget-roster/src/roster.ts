import { subjectValue, intervalLeaf, MIN, MAX } from "./hash";
import { merkleRoot, proveInclusion, verifyInclusion, type InclusionProof } from "./merkle";
import { verifyRoot, type SignedRoot } from "./root";

export interface Roster {
  /** Sorted, de-duplicated subject values (excludes sentinels). */
  readonly values: readonly string[];
  /** boundary = [MIN, ...values, MAX]; intervals are consecutive pairs. */
  readonly boundary: readonly string[];
  /** Interval leaf digests, one per consecutive boundary pair. */
  readonly leaves: readonly string[];
  readonly root: string;
  /** = leaves.length = values.length + 1. Bound into the signed root. */
  readonly leafCount: number;
}

export interface MembershipProof {
  readonly lo: string; // === the subject value
  readonly hi: string;
  readonly inclusion: InclusionProof;
}

export interface NonInclusionProof {
  readonly lo: string;
  readonly hi: string;
  readonly inclusion: InclusionProof;
}

/** Build a roster from raw subjectKeyIds (hashed internally). Input order-independent. */
export function buildRoster(subjectKeyIds: readonly string[]): Roster {
  const values = [...new Set(subjectKeyIds.map(subjectValue))].sort();
  const boundary = [MIN, ...values, MAX];
  const leaves = boundary.slice(0, -1).map((lo, i) => intervalLeaf(lo, boundary[i + 1]!));
  return { values, boundary, leaves, root: merkleRoot(leaves), leafCount: leaves.length };
}

/** Index of the interval (lo,hi) with lo < value < hi (value absent), or -1 if present/out of range. */
function gapIntervalIndex(r: Roster, value: string): number {
  if (value <= MIN || value >= MAX) return -1;
  for (let i = 0; i < r.boundary.length - 1; i++) {
    if (r.boundary[i]! < value && value < r.boundary[i + 1]!) return i;
  }
  return -1; // value equals a boundary => present, not a gap
}

export function proveMembership(r: Roster, subjectKeyId: string): MembershipProof | null {
  const v = subjectValue(subjectKeyId);
  const pos = r.values.indexOf(v);
  if (pos < 0) return null;
  // boundary = [MIN, v0, v1, ...]; value v == boundary[pos+1]; the interval STARTING at v is leaf index pos+1.
  const intervalIndex = pos + 1;
  return { lo: r.boundary[intervalIndex]!, hi: r.boundary[intervalIndex + 1]!, inclusion: proveInclusion(r.leaves, intervalIndex) };
}

export function verifyMembership(value: string, proof: MembershipProof, root: string): boolean {
  try {
    if (proof.lo !== value) return false;
    return verifyInclusion(intervalLeaf(proof.lo, proof.hi), proof.inclusion, root);
  } catch {
    return false;
  }
}

export function proveNonInclusion(r: Roster, value: string): NonInclusionProof | null {
  const i = gapIntervalIndex(r, value);
  if (i < 0) return null;
  return { lo: r.boundary[i]!, hi: r.boundary[i + 1]!, inclusion: proveInclusion(r.leaves, i) };
}

export function verifyNonInclusion(value: string, proof: NonInclusionProof, root: string, leafCount: number): boolean {
  try {
    if (!Number.isInteger(leafCount) || leafCount < 1) return false;
    if (!(proof.lo < value && value < proof.hi)) return false; // interval must strictly bracket the value
    return verifyInclusion(intervalLeaf(proof.lo, proof.hi), proof.inclusion, root);
  } catch {
    return false;
  }
}

/**
 * Misuse-resistant absence check: authenticate the signed root (which binds leafCount
 * and the Merkle root under the issuer signature) BEFORE verifying the non-inclusion
 * proof against it. Prefer this over calling verifyNonInclusion with a bare root —
 * it cannot be misused by skipping the signature check. resolveKey is the trust anchor.
 */
export function verifyNonInclusionSigned(
  value: string,
  proof: NonInclusionProof,
  signed: SignedRoot,
  resolveKey: (keyId: string) => Uint8Array,
): boolean {
  if (!verifyRoot(signed, resolveKey)) return false;
  return verifyNonInclusion(value, proof, signed.root, signed.leafCount);
}

/** Misuse-resistant membership check: authenticate the signed root, then verify membership. */
export function verifyMembershipSigned(
  value: string,
  proof: MembershipProof,
  signed: SignedRoot,
  resolveKey: (keyId: string) => Uint8Array,
): boolean {
  if (!verifyRoot(signed, resolveKey)) return false;
  return verifyMembership(value, proof, signed.root);
}
