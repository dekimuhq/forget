import { describe, it, expect } from "vitest";
import { ed25519Signer, publicKeyOf } from "../src/signer";
import { createDestructionReceipt } from "../src/create";
import { verifyDestructionReceipt } from "../src/verify";
import type { DestructionInput } from "../src/types";

const seed = new Uint8Array(32).fill(5);
const signer = ed25519Signer(seed, "sign-key-1");
const resolveKey = (keyId: string) => {
  if (keyId !== "sign-key-1") throw new Error("untrusted");
  return publicKeyOf(seed);
};

const input: DestructionInput = {
  subjectKeyIdHash: "ab".repeat(32),
  kekKeyId: "kek-prod-1",
  destroyedAt: "2026-06-06T12:00:00Z",
  priorRosterRoot: "11".repeat(32),
  newRosterRoot: "22".repeat(32),
};

describe("destruction receipt", () => {
  it("creates a forget.destruction.v1 receipt that verifies", async () => {
    const r = await createDestructionReceipt(input, signer);
    expect(r.kind).toBe("forget.destruction.v1");
    expect(r.signerKeyId).toBe("sign-key-1");
    expect(verifyDestructionReceipt(r, resolveKey)).toBe(true);
  });

  it("ADVERSARIAL: tampering any signed field breaks verification (recompute-on-verify)", async () => {
    const r = await createDestructionReceipt(input, signer);
    expect(verifyDestructionReceipt({ ...r, newRosterRoot: "33".repeat(32) }, resolveKey)).toBe(false);
    expect(verifyDestructionReceipt({ ...r, destroyedAt: "2026-06-07T00:00:00Z" }, resolveKey)).toBe(false);
    expect(verifyDestructionReceipt({ ...r, subjectKeyIdHash: "cd".repeat(32) }, resolveKey)).toBe(false);
    expect(verifyDestructionReceipt({ ...r, priorRosterRoot: "44".repeat(32) }, resolveKey)).toBe(false);
    expect(verifyDestructionReceipt({ ...r, kekKeyId: "evil" }, resolveKey)).toBe(false);
  });

  it("ADVERSARIAL: an untrusted signer key is rejected", async () => {
    const r = await createDestructionReceipt(input, signer);
    const bad = () => publicKeyOf(new Uint8Array(32).fill(1));
    expect(verifyDestructionReceipt(r, bad)).toBe(false);
  });

  it("the signed view binds BOTH roster roots (receipt cannot be replayed across rosters)", async () => {
    const r = await createDestructionReceipt(input, signer);
    expect(verifyDestructionReceipt({ ...r, priorRosterRoot: r.newRosterRoot, newRosterRoot: r.priorRosterRoot }, resolveKey)).toBe(false);
  });
});
