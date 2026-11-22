import { describe, it, expect, beforeAll } from "vitest";
import {
  provisionVault,
  unlockVault,
  unlockVaultWithRecovery,
  unlockVaultWithVaultKey,
  derivePublicKeyFromPrivate,
  verifyPublicKeyBinding,
  VaultKeyMismatchError,
  generateKeypair,
  exportPublicKey,
  computeKid,
  computeKidForKey,
  encryptContent,
  decryptContent,
  type VaultBundle,
  type ProvisionResult,
} from "../src/vault/index.js";

const PASSWORD = "correct horse battery staple";

let honest: ProvisionResult;
let attackerPublic: VaultBundle["publicKey"];
let vaultKey: CryptoKey;

beforeAll(async () => {
  honest = await provisionVault(PASSWORD);
  vaultKey = (await unlockVault(PASSWORD, honest.bundle)).vaultKey;
  attackerPublic = await exportPublicKey((await generateKeypair()).publicKey);
});

function tampered(): VaultBundle {
  return { ...honest.bundle, publicKey: attackerPublic };
}

describe("public key binding at unlock", () => {
  it("honest bundle unlocks and returns the matching public key", async () => {
    const r = await unlockVault(PASSWORD, honest.bundle);
    expect(await computeKidForKey(r.publicKey)).toBe(
      await computeKid(honest.bundle.publicKey),
    );
    const enc = await encryptContent("hello", r.publicKey);
    expect(await decryptContent(enc, r.privateKey)).toBe("hello");
  });

  it("rejects a substituted bundle public key (password path)", async () => {
    await expect(unlockVault(PASSWORD, tampered())).rejects.toBeInstanceOf(
      VaultKeyMismatchError,
    );
  });

  it("rejects a substituted bundle public key (recovery path)", async () => {
    await expect(
      unlockVaultWithRecovery(honest.recoveryPhrase.phrase, tampered()),
    ).rejects.toBeInstanceOf(VaultKeyMismatchError);
  });

  it("rejects a malformed bundle public key", async () => {
    const bad: VaultBundle = {
      ...honest.bundle,
      publicKey: { ...honest.bundle.publicKey, spki: "!!not-base64!!" },
    };
    await expect(unlockVault(PASSWORD, bad)).rejects.toBeInstanceOf(
      VaultKeyMismatchError,
    );
  });
});

describe("unlockVaultWithVaultKey (raw vault key path)", () => {
  it("unlocks an honest bundle", async () => {
    const r = await unlockVaultWithVaultKey(honest.bundle, vaultKey);
    const enc = await encryptContent("hi", r.publicKey);
    expect(await decryptContent(enc, r.privateKey)).toBe("hi");
  });

  it("rejects a substituted bundle public key", async () => {
    await expect(
      unlockVaultWithVaultKey(tampered(), vaultKey),
    ).rejects.toBeInstanceOf(VaultKeyMismatchError);
  });
});

describe("derivePublicKeyFromPrivate / verifyPublicKeyBinding", () => {
  it("derives the exact public key of the pair", async () => {
    const pair = await generateKeypair();
    const derived = await derivePublicKeyFromPrivate(pair.privateKey);
    expect(await exportPublicKey(derived)).toEqual(
      await exportPublicKey(pair.publicKey),
    );
    expect(derived.extractable).toBe(true);
    expect(derived.usages.sort()).toEqual(["encrypt", "wrapKey"]);
  });

  it("returns the derived key when the claim matches", async () => {
    const pair = await generateKeypair();
    const claimed = await exportPublicKey(pair.publicKey);
    const k = await verifyPublicKeyBinding(pair.privateKey, claimed);
    expect(await exportPublicKey(k)).toEqual(claimed);
  });

  it("throws when the claimed key belongs to another pair", async () => {
    const pair = await generateKeypair();
    await expect(
      verifyPublicKeyBinding(pair.privateKey, attackerPublic),
    ).rejects.toBeInstanceOf(VaultKeyMismatchError);
  });

  it("checks an expected kid and fails on mismatch", async () => {
    const pair = await generateKeypair();
    const claimed = await exportPublicKey(pair.publicKey);
    const kid = await computeKid(claimed);
    await expect(
      verifyPublicKeyBinding(pair.privateKey, claimed, { kid }),
    ).resolves.toBeDefined();
    await expect(
      verifyPublicKeyBinding(pair.privateKey, claimed, {
        kid: await computeKid(attackerPublic),
      }),
    ).rejects.toBeInstanceOf(VaultKeyMismatchError);
  });

  it("is a typed error with a stable name", async () => {
    const pair = await generateKeypair();
    const err = await verifyPublicKeyBinding(
      pair.privateKey,
      attackerPublic,
    ).catch((e) => e);
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe("VaultKeyMismatchError");
  });
});
