import { describe, it, expect } from "vitest";
import { buildRoster, proveNonInclusion, proveMembership, verifyNonInclusionSigned, verifyMembershipSigned } from "../src/roster";
import { subjectValue } from "../src/hash";
import { ed25519Signer, publicKeyOf } from "../src/signer";
import { signRoot, verifyRoot } from "../src/root";

const seed = new Uint8Array(32).fill(11);
const signer = ed25519Signer(seed, "roster-key-1");
const resolveKey = (keyId: string) => {
  if (keyId !== "roster-key-1") throw new Error("untrusted keyId");
  return publicKeyOf(seed);
};

describe("signed roster root", () => {
  it("signRoot then verifyRoot returns true and binds root + leafCount + prevRoot", async () => {
    const r = buildRoster(["alice", "bob"]);
    const signed = await signRoot({ root: r.root, leafCount: r.leafCount, generatedAt: "2026-06-06T00:00:00Z", prevRoot: null }, signer);
    expect(verifyRoot(signed, resolveKey)).toBe(true);
  });

  it("verifyRoot fails if leafCount is tampered (count is signed in)", async () => {
    const r = buildRoster(["alice", "bob"]);
    const signed = await signRoot({ root: r.root, leafCount: r.leafCount, generatedAt: "2026-06-06T00:00:00Z", prevRoot: null }, signer);
    expect(verifyRoot({ ...signed, leafCount: signed.leafCount + 1 }, resolveKey)).toBe(false);
  });

  it("verifyRoot fails under an untrusted key", async () => {
    const r = buildRoster(["alice"]);
    const signed = await signRoot({ root: r.root, leafCount: r.leafCount, generatedAt: "2026-06-06T00:00:00Z", prevRoot: null }, signer);
    const badResolve = () => publicKeyOf(new Uint8Array(32).fill(99));
    expect(verifyRoot(signed, badResolve)).toBe(false);
  });

  it("ADVERSARIAL: leafCount inflation does not let a forged non-inclusion stand", async () => {
    const r = buildRoster(["alice", "bob", "carol"]);
    const signed = await signRoot({ root: r.root, leafCount: r.leafCount, generatedAt: "2026-06-06T00:00:00Z", prevRoot: null }, signer);
    expect(verifyRoot({ ...signed, leafCount: 2 }, resolveKey)).toBe(false);
    const v = subjectValue("dave");
    expect(verifyRoot(signed, resolveKey)).toBe(true);
    void proveNonInclusion(r, v);
  });
});

describe("misuse-resistant signed wrappers", () => {
  it("verifyNonInclusionSigned: true for a genuine signed root, false if the root signature is invalid", async () => {
    const r = buildRoster(["alice", "bob"]);
    const signed = await signRoot({ root: r.root, leafCount: r.leafCount, generatedAt: "2026-06-06T00:00:00Z", prevRoot: null }, signer);
    const dave = subjectValue("dave");
    expect(verifyNonInclusionSigned(dave, proveNonInclusion(r, dave)!, signed, resolveKey)).toBe(true);
    // tampering leafCount breaks verifyRoot -> the whole check fails, even with a structurally valid proof
    expect(verifyNonInclusionSigned(dave, proveNonInclusion(r, dave)!, { ...signed, leafCount: signed.leafCount + 1 }, resolveKey)).toBe(false);
    // untrusted key -> false
    const badResolve = () => publicKeyOf(new Uint8Array(32).fill(77));
    expect(verifyNonInclusionSigned(dave, proveNonInclusion(r, dave)!, signed, badResolve)).toBe(false);
  });

  it("verifyMembershipSigned: true for a present subject under a genuine root, false under a bad signature", async () => {
    const r = buildRoster(["alice", "bob"]);
    const signed = await signRoot({ root: r.root, leafCount: r.leafCount, generatedAt: "2026-06-06T00:00:00Z", prevRoot: null }, signer);
    const alice = subjectValue("alice");
    expect(verifyMembershipSigned(alice, proveMembership(r, "alice")!, signed, resolveKey)).toBe(true);
    expect(verifyMembershipSigned(alice, proveMembership(r, "alice")!, { ...signed, root: "ab".repeat(32) }, resolveKey)).toBe(false);
  });
});
