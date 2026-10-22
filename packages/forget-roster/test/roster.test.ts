import { describe, it, expect } from "vitest";
import { subjectValue, MIN, MAX } from "../src/hash";
import { proveInclusion } from "../src/merkle";
import {
  buildRoster,
  proveMembership,
  verifyMembership,
  proveNonInclusion,
  verifyNonInclusion,
} from "../src/roster";

describe("roster", () => {
  const subjects = ["alice", "bob", "carol"];

  it("buildRoster: leafCount = subjects + 1 (interval count) and a stable root", () => {
    const r = buildRoster(subjects);
    expect(r.leafCount).toBe(subjects.length + 1);
    expect(r.root).toMatch(/^[0-9a-f]{64}$/);
    expect(buildRoster(subjects).root).toBe(r.root); // order-independent input
    expect(buildRoster([...subjects].reverse()).root).toBe(r.root);
  });

  it("present subject: membership proof verifies, non-inclusion does NOT", () => {
    const r = buildRoster(subjects);
    const v = subjectValue("alice");
    const m = proveMembership(r, "alice");
    expect(m).not.toBeNull();
    expect(verifyMembership(v, m!, r.root)).toBe(true);
    expect(proveNonInclusion(r, v)).toBeNull(); // cannot prove absence of a present subject
  });

  it("absent subject: non-inclusion proof verifies, membership does NOT", () => {
    const r = buildRoster(subjects);
    const v = subjectValue("dave"); // not in roster
    const ni = proveNonInclusion(r, v);
    expect(ni).not.toBeNull();
    expect(verifyNonInclusion(v, ni!, r.root, r.leafCount)).toBe(true);
    expect(proveMembership(r, "dave")).toBeNull();
  });

  it("after removing a subject, the new roster proves non-inclusion of it", () => {
    const before = buildRoster(subjects);
    const v = subjectValue("bob");
    expect(verifyMembership(v, proveMembership(before, "bob")!, before.root)).toBe(true);

    const after = buildRoster(subjects.filter((s) => s !== "bob"));
    const ni = proveNonInclusion(after, v)!;
    expect(verifyNonInclusion(v, ni, after.root, after.leafCount)).toBe(true);
  });

  it("boundary: value below first and above last real value are non-included", () => {
    const r = buildRoster(subjects);
    const low = "00".repeat(31) + "01";
    const high = "ff".repeat(31) + "fe";
    expect(verifyNonInclusion(low, proveNonInclusion(r, low)!, r.root, r.leafCount)).toBe(true);
    expect(verifyNonInclusion(high, proveNonInclusion(r, high)!, r.root, r.leafCount)).toBe(true);
  });

  it("empty roster: single (MIN,MAX) interval proves non-inclusion of anything", () => {
    const r = buildRoster([]);
    expect(r.leafCount).toBe(1);
    const v = subjectValue("nobody");
    expect(verifyNonInclusion(v, proveNonInclusion(r, v)!, r.root, r.leafCount)).toBe(true);
  });

  it("ADVERSARIAL: a non-inclusion proof whose interval does not bracket t is rejected", () => {
    const r = buildRoster(subjects);
    const dave = subjectValue("dave");
    const ni = proveNonInclusion(r, dave)!;
    const alice = subjectValue("alice");
    // reuse dave's interval proof but claim it covers alice (a present value)
    expect(verifyNonInclusion(alice, ni, r.root, r.leafCount)).toBe(false);
  });
});

describe("forgery resistance", () => {
  it("verifyNonInclusion returns false (never throws) on malformed-length bounds", () => {
    const r = buildRoster(["alice"]);
    const value = "11".repeat(32); // valid 64-hex, brackets between the malformed bounds below
    const proof = { lo: "00".repeat(40), hi: "ff".repeat(40), inclusion: { siblings: [] as ReadonlyArray<{ hash: string; side: "L" | "R" }> } };
    let result: boolean | undefined;
    expect(() => { result = verifyNonInclusion(value, proof, r.root, r.leafCount); }).not.toThrow();
    expect(result).toBe(false);
  });

  it("re-split of a genuine leaf cannot prove a present subject absent", () => {
    // Reproduce the reviewer's attack shape: take a real interval (lo,hi), concat, re-split at a
    // byte boundary into wrong-length (lo2,hi2). The fixed-length guard must make the recompute fail
    // (-> verifyNonInclusion false), so no present subject can be re-labeled as absent.
    const r = buildRoster(["alice", "bob", "carol"]);
    const lo = r.boundary[r.boundary.length - 2]!;
    const hi = r.boundary[r.boundary.length - 1]!;
    const concat = lo + hi; // 128 hex
    const lo2 = concat.slice(0, 114); // 57 bytes
    const hi2 = concat.slice(114);    // 7 bytes
    const idx = r.boundary.length - 2;
    const forged = { lo: lo2, hi: hi2, inclusion: proveInclusion(r.leaves, idx) };
    for (const present of ["alice", "bob", "carol"]) {
      expect(verifyNonInclusion(subjectValue(present), forged, r.root, r.leafCount)).toBe(false);
    }
  });
});
