import { internalNode } from "./hash";

/**
 * Merkle root over an ordered list of leaf digests. Odd nodes are carried up
 * unchanged (RFC 6962 style) rather than duplicated, avoiding duplicate-leaf
 * malleability. Caller guarantees at least one leaf (rosters always carry the
 * (MIN,MAX) interval).
 */
export function merkleRoot(leaves: readonly string[]): string {
  if (leaves.length === 0) throw new Error("merkleRoot requires >= 1 leaf");
  let level = leaves.slice();
  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length ? internalNode(level[i]!, level[i + 1]!) : level[i]!);
    }
    level = next;
  }
  return level[0]!;
}

export interface InclusionProof {
  /** Sibling digests from leaf to root. `side` is the sibling's position. */
  readonly siblings: ReadonlyArray<{ readonly hash: string; readonly side: "L" | "R" }>;
}

/**
 * Build an inclusion proof for the leaf at `index`. Mirrors merkleRoot's
 * carry-up: a carried (odd, last) node contributes no sibling at that level.
 */
export function proveInclusion(leaves: readonly string[], index: number): InclusionProof {
  if (index < 0 || index >= leaves.length) throw new Error("index out of range");
  const siblings: Array<{ hash: string; side: "L" | "R" }> = [];
  let idx = index;
  let level = leaves.slice();
  while (level.length > 1) {
    if (idx % 2 === 0) {
      if (idx + 1 < level.length) siblings.push({ hash: level[idx + 1]!, side: "R" });
      // else carried up: no sibling at this level
    } else {
      siblings.push({ hash: level[idx - 1]!, side: "L" });
    }
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length ? internalNode(level[i]!, level[i + 1]!) : level[i]!);
    }
    idx = Math.floor(idx / 2);
    level = next;
  }
  return { siblings };
}

/** Recompute the root from a leaf digest + proof; compare to the trusted root.
 *  Fail-closed: any malformed input (bad-length sibling) returns false, never throws. */
export function verifyInclusion(leafHash: string, proof: InclusionProof, root: string): boolean {
  try {
    let h = leafHash;
    for (const s of proof.siblings) {
      h = s.side === "L" ? internalNode(s.hash, h) : internalNode(h, s.hash);
    }
    return h === root;
  } catch {
    return false;
  }
}
