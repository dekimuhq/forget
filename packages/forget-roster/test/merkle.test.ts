import { describe, it, expect } from "vitest";
import { subjectValue, intervalLeaf, internalNode, MIN, MAX } from "../src/hash";
import { merkleRoot, proveInclusion, verifyInclusion } from "../src/merkle";

describe("hash primitives", () => {
  it("subjectValue is deterministic 64-hex and domain-separated from intervalLeaf", () => {
    const v = subjectValue("subject-A");
    expect(v).toMatch(/^[0-9a-f]{64}$/);
    expect(subjectValue("subject-A")).toBe(v);
    expect(intervalLeaf(MIN, MAX)).not.toBe(v);
  });

  it("MIN < every subjectValue < MAX (hex order)", () => {
    const v = subjectValue("anything");
    expect(MIN < v).toBe(true);
    expect(v < MAX).toBe(true);
  });
});

describe("merkleRoot", () => {
  it("is stable for a fixed leaf list", () => {
    const leaves = [intervalLeaf(MIN, "aa".repeat(32)), intervalLeaf("aa".repeat(32), MAX)];
    expect(merkleRoot(leaves)).toBe(merkleRoot(leaves));
  });

  it("changes when any leaf changes", () => {
    const a = [intervalLeaf(MIN, "aa".repeat(32)), intervalLeaf("aa".repeat(32), MAX)];
    const b = [intervalLeaf(MIN, "bb".repeat(32)), intervalLeaf("bb".repeat(32), MAX)];
    expect(merkleRoot(a)).not.toBe(merkleRoot(b));
  });

  it("handles 1, 2, 3 leaves (odd carry-up) without throwing", () => {
    const L = (n: number) => Array.from({ length: n }, (_, i) => intervalLeaf(MIN, i.toString(16).padStart(64, "0")));
    expect(merkleRoot(L(1))).toMatch(/^[0-9a-f]{64}$/);
    expect(merkleRoot(L(2))).toMatch(/^[0-9a-f]{64}$/);
    expect(merkleRoot(L(3))).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("inclusion proofs", () => {
  const leaves = Array.from({ length: 5 }, (_, i) =>
    intervalLeaf(i.toString(16).padStart(64, "0"), (i + 1).toString(16).padStart(64, "0")),
  );
  const root = merkleRoot(leaves);

  it("every leaf has a proof that reconstructs the root", () => {
    for (let i = 0; i < leaves.length; i++) {
      const proof = proveInclusion(leaves, i);
      expect(verifyInclusion(leaves[i]!, proof, root)).toBe(true);
    }
  });

  it("rejects a proof against the wrong leaf value", () => {
    const proof = proveInclusion(leaves, 2);
    expect(verifyInclusion(intervalLeaf(MIN, MAX), proof, root)).toBe(false);
  });

  it("rejects a proof with a tampered sibling", () => {
    const proof = proveInclusion(leaves, 2);
    const tampered = { ...proof, siblings: proof.siblings.map((s, idx) => (idx === 0 ? { ...s, hash: "ab".repeat(32) } : s)) };
    expect(verifyInclusion(leaves[2]!, tampered, root)).toBe(false);
  });

  it("works for single-leaf and two-leaf trees", () => {
    const one = [intervalLeaf(MIN, MAX)];
    expect(verifyInclusion(one[0]!, proveInclusion(one, 0), merkleRoot(one))).toBe(true);
    const two = leaves.slice(0, 2);
    expect(verifyInclusion(two[1]!, proveInclusion(two, 1), merkleRoot(two))).toBe(true);
  });
});

describe("fixed-length operand guard (closes re-split forgery)", () => {
  it("intervalLeaf throws on non-64-hex bounds", () => {
    expect(() => intervalLeaf("aabb", "ccdd")).toThrow();
    expect(() => intervalLeaf("aa", "bbccdd")).toThrow(); // the old ambiguity pair — both must now throw
    expect(() => intervalLeaf("00".repeat(40), "ff".repeat(40))).toThrow();
  });
  it("internalNode throws on non-64-hex operands", () => {
    expect(() => internalNode("ab", "cd")).toThrow();
  });
});
