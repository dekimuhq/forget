import { describe, it, expect } from "vitest";
import { ed25519Signer, publicKeyOf } from "../src/signer";
import { createModelDispositionReceipt, verifyForgottenEndToEnd } from "../src/model-disposition";
import type { ModelDispositionInput } from "../src/types";
import { verifyModelDisposition } from "../src/model-disposition";
import { createDestructionReceipt } from "../src/create";
import {
  buildRoster, signRoot, subjectValue, proveNonInclusion, proveMembership, ed25519Signer as rosterSigner,
} from "@dekimuhq/forget-roster";

const seed = new Uint8Array(32).fill(7);
const signer = ed25519Signer(seed, "sign-key-1");

const skid = "ab".repeat(32);
const notTrained: ModelDispositionInput = {
  subjectKeyIdHash: skid,
  destructionClaimId: `forget:${skid}:${"22".repeat(32)}`,
  disposition: "not_trained",
  rationale: "no model training/fine-tuning pipeline; data never used to train any model",
  disposedAt: "2026-06-30T12:00:00Z",
};

const resolveKey = (keyId: string) => {
  if (keyId !== "sign-key-1") throw new Error("untrusted");
  return publicKeyOf(seed);
};

describe("createModelDispositionReceipt", () => {
  it("mints a forget.model-disposition.v1 receipt", async () => {
    const r = await createModelDispositionReceipt(notTrained, signer);
    expect(r.kind).toBe("forget.model-disposition.v1");
    expect(r.alg).toBe("Ed25519");
    expect(r.signerKeyId).toBe("sign-key-1");
    expect(r.disposition).toBe("not_trained");
    expect(typeof r.signature).toBe("string");
  });

  it("NFC-normalizes rationale at mint", async () => {
    const nfd = "cafe" + String.fromCodePoint(0x0301);
    const r = await createModelDispositionReceipt({ ...notTrained, rationale: nfd }, signer);
    expect(r.rationale).toBe(nfd.normalize("NFC"));
  });

  it("ADVERSARIAL: rejects not_trained carrying training roots (shape invariant)", async () => {
    await expect(
      createModelDispositionReceipt({ ...notTrained, trainingRootAfter: "33".repeat(32) }, signer),
    ).rejects.toThrow();
  });

  it("ADVERSARIAL: rejects retrained WITHOUT both training roots", async () => {
    await expect(
      createModelDispositionReceipt({ ...notTrained, disposition: "retrained" }, signer),
    ).rejects.toThrow();
  });
});

describe("verifyModelDisposition", () => {
  it("verifies a not_trained receipt (no evidence needed)", async () => {
    const r = await createModelDispositionReceipt(notTrained, signer);
    expect(verifyModelDisposition(r, {}, resolveKey)).toBe(true);
  });

  it("ADVERSARIAL: tampering any signed field breaks verification", async () => {
    const r = await createModelDispositionReceipt(notTrained, signer);
    expect(verifyModelDisposition({ ...r, disposition: "retrained" }, {}, resolveKey)).toBe(false);
    expect(verifyModelDisposition({ ...r, rationale: "edited" }, {}, resolveKey)).toBe(false);
    expect(verifyModelDisposition({ ...r, subjectKeyIdHash: "cd".repeat(32) }, {}, resolveKey)).toBe(false);
    expect(verifyModelDisposition({ ...r, destructionClaimId: "forget:x:y" }, {}, resolveKey)).toBe(false);
  });

  it("ADVERSARIAL: untrusted signer rejected", async () => {
    const r = await createModelDispositionReceipt(notTrained, signer);
    expect(verifyModelDisposition(r, {}, () => publicKeyOf(new Uint8Array(32).fill(1)))).toBe(false);
  });

  it("verifies a retrained receipt with valid non-inclusion evidence", async () => {
    const rs = rosterSigner(seed, "sign-key-1");
    const before = buildRoster(["subject-X", "keep-1", "keep-2"]);
    const after = buildRoster(["keep-1", "keep-2"]);
    const beforeSigned = await signRoot({ root: before.root, leafCount: before.leafCount, generatedAt: "2026-06-30T00:00:00Z", prevRoot: null }, rs);
    const afterSigned = await signRoot({ root: after.root, leafCount: after.leafCount, generatedAt: "2026-06-30T01:00:00Z", prevRoot: before.root }, rs);
    const skidX = subjectValue("subject-X");
    const input = {
      subjectKeyIdHash: skidX,
      destructionClaimId: `forget:${skidX}:${"22".repeat(32)}`,
      disposition: "retrained" as const,
      rationale: "retrained excluding the subject",
      trainingRootBefore: before.root,
      trainingRootAfter: after.root,
      disposedAt: "2026-06-30T02:00:00Z",
    };
    const r = await createModelDispositionReceipt(input, signer);
    const evidence = {
      trainingAfterSignedRoot: afterSigned,
      nonInclusionAfter: proveNonInclusion(after, skidX)!,
      trainingBeforeSignedRoot: beforeSigned,
      membershipBefore: proveMembership(before, "subject-X")!,
    };
    expect(verifyModelDisposition(r, { evidence }, resolveKey)).toBe(true);
  });

  it("ADVERSARIAL: retrained with NO evidence supplied → false", async () => {
    const skidX = subjectValue("subject-X");
    const r = await createModelDispositionReceipt({
      subjectKeyIdHash: skidX, destructionClaimId: `forget:${skidX}:${"22".repeat(32)}`,
      disposition: "retrained", rationale: "x", trainingRootBefore: "11".repeat(32), trainingRootAfter: "22".repeat(32),
      disposedAt: "2026-06-30T02:00:00Z",
    }, signer);
    expect(verifyModelDisposition(r, {}, resolveKey)).toBe(false);
  });

  it("ADVERSARIAL: binding mismatch (destruction receipt for a different subject) → false", async () => {
    const r = await createModelDispositionReceipt(notTrained, signer);
    const other = await createDestructionReceipt({
      subjectKeyIdHash: "cd".repeat(32), kekKeyId: "kek-1", destroyedAt: "2026-06-30T00:00:00Z",
      priorRosterRoot: "11".repeat(32), newRosterRoot: "22".repeat(32),
    }, signer);
    expect(verifyModelDisposition(r, { destruction: other }, resolveKey)).toBe(false);
  });

  it("verifies binding when the matching destruction receipt is supplied", async () => {
    const matching = await createDestructionReceipt({
      subjectKeyIdHash: skid, kekKeyId: "kek-1", destroyedAt: "2026-06-30T00:00:00Z",
      priorRosterRoot: "11".repeat(32), newRosterRoot: "22".repeat(32),
    }, signer);
    const r = await createModelDispositionReceipt(notTrained, signer);
    expect(verifyModelDisposition(r, { destruction: matching }, resolveKey)).toBe(true);
  });
});

describe("verifyForgottenEndToEnd", () => {
  it("true only when BOTH the destruction receipt and bound disposition verify", async () => {
    const destruction = await createDestructionReceipt({
      subjectKeyIdHash: skid, kekKeyId: "kek-1", destroyedAt: "2026-06-30T00:00:00Z",
      priorRosterRoot: "11".repeat(32), newRosterRoot: "22".repeat(32),
    }, signer);
    const disposition = await createModelDispositionReceipt(notTrained, signer);
    expect(verifyForgottenEndToEnd(destruction, disposition, {}, resolveKey)).toBe(true);
  });

  it("false when the destruction receipt is tampered", async () => {
    const destruction = await createDestructionReceipt({
      subjectKeyIdHash: skid, kekKeyId: "kek-1", destroyedAt: "2026-06-30T00:00:00Z",
      priorRosterRoot: "11".repeat(32), newRosterRoot: "22".repeat(32),
    }, signer);
    const disposition = await createModelDispositionReceipt(notTrained, signer);
    expect(verifyForgottenEndToEnd({ ...destruction, newRosterRoot: "99".repeat(32) }, disposition, {}, resolveKey)).toBe(false);
  });
});
