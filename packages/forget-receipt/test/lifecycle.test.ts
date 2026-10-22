import { describe, it, expect } from "vitest";
import { loadKey } from "@dekimuhq/crypto";
import { Keystore, type KeyRegistry } from "@dekimuhq/forget-keystore";
import {
  buildRoster, proveMembership, verifyMembership,
  proveNonInclusion, verifyNonInclusion,
  signRoot, verifyRoot, ed25519Signer as rosterSigner, publicKeyOf as rosterPub,
  subjectValue,
} from "@dekimuhq/forget-roster";
import { createDestructionReceipt, verifyDestructionReceipt, ed25519Signer, publicKeyOf } from "../src/index";

function memRegistry(): KeyRegistry {
  const m = new Map<string, string>();
  return { get: (id) => m.get(id) ?? null, put: (id, w) => void m.set(id, w), del: (id) => void m.delete(id) };
}

describe("proof-of-forgetting end-to-end", () => {
  const kek = loadKey(Buffer.alloc(32, 2).toString("base64"));
  const rSeed = new Uint8Array(32).fill(21);
  const rSigner = rosterSigner(rSeed, "roster-1");
  const resolveRoster = (id: string) => { if (id !== "roster-1") throw new Error("untrusted"); return rosterPub(rSeed); };
  const sSeed = new Uint8Array(32).fill(31);
  const signer = ed25519Signer(sSeed, "sign-1");
  const resolveSigner = (id: string) => { if (id !== "sign-1") throw new Error("untrusted"); return publicKeyOf(sSeed); };

  it("erase(bob): shred key, rebuild roster, mint receipt, verify the whole chain offline", async () => {
    const ks = new Keystore(memRegistry(), kek);
    const subjects = ["alice", "bob", "carol"];
    for (const s of subjects) ks.createSubject(s);
    const bobCipher = ks.encrypt("bob", "bob@example.com");

    const before = buildRoster(subjects);
    const signedBefore = await signRoot({ root: before.root, leafCount: before.leafCount, generatedAt: "2026-06-06T00:00:00Z", prevRoot: null }, rSigner);
    expect(verifyRoot(signedBefore, resolveRoster)).toBe(true);
    const bobVal = subjectValue("bob");
    expect(verifyMembership(bobVal, proveMembership(before, "bob")!, signedBefore.root)).toBe(true);

    ks.shred("bob");
    const after = buildRoster(subjects.filter((s) => s !== "bob"));
    const signedAfter = await signRoot({ root: after.root, leafCount: after.leafCount, generatedAt: "2026-06-06T01:00:00Z", prevRoot: signedBefore.root }, rSigner);
    const receipt = await createDestructionReceipt({
      subjectKeyIdHash: bobVal,
      kekKeyId: "kek-prod",
      destroyedAt: "2026-06-06T01:00:00Z",
      priorRosterRoot: signedBefore.root,
      newRosterRoot: signedAfter.root,
    }, signer);

    expect(verifyDestructionReceipt(receipt, resolveSigner)).toBe(true);
    expect(verifyRoot(signedAfter, resolveRoster)).toBe(true);
    expect(signedAfter.prevRoot).toBe(signedBefore.root);
    expect(verifyNonInclusion(bobVal, proveNonInclusion(after, bobVal)!, signedAfter.root, signedAfter.leafCount)).toBe(true);
    expect(verifyMembership(bobVal, proveMembership(before, "bob")!, signedBefore.root)).toBe(true);

    expect(() => ks.decrypt("bob", bobCipher)).toThrow(/no key|shredded/i);
    expect(ks.decrypt("alice", ks.encrypt("alice", "x"))).toBe("x");
  });

  it("ADVERSARIAL: a rolled-back roster (old root presented as current) is detectable via prevRoot chain", async () => {
    const subjects = ["alice", "bob"];
    const r0 = buildRoster(subjects);
    const s0 = await signRoot({ root: r0.root, leafCount: r0.leafCount, generatedAt: "2026-06-06T00:00:00Z", prevRoot: null }, rSigner);
    const r1 = buildRoster(["alice"]);
    const s1 = await signRoot({ root: r1.root, leafCount: r1.leafCount, generatedAt: "2026-06-06T01:00:00Z", prevRoot: s0.root }, rSigner);
    expect(s1.prevRoot).toBe(s0.root);
    expect(verifyNonInclusion(subjectValue("bob"), proveNonInclusion(r1, subjectValue("bob"))!, s1.root, s1.leafCount)).toBe(true);
  });

  it("ADVERSARIAL: receipt's newRosterRoot must equal the roster the non-inclusion is proven against", async () => {
    const after = buildRoster(["alice", "carol"]);
    const signedAfter = await signRoot({ root: after.root, leafCount: after.leafCount, generatedAt: "2026-06-06T01:00:00Z", prevRoot: "00".repeat(32) }, rSigner);
    const bobVal = subjectValue("bob");
    const receipt = await createDestructionReceipt({
      subjectKeyIdHash: bobVal, kekKeyId: "kek", destroyedAt: "2026-06-06T01:00:00Z",
      priorRosterRoot: "11".repeat(32), newRosterRoot: signedAfter.root,
    }, signer);
    expect(receipt.newRosterRoot).toBe(signedAfter.root);
    expect(verifyNonInclusion(bobVal, proveNonInclusion(after, bobVal)!, receipt.newRosterRoot, signedAfter.leafCount)).toBe(true);
  });
});
