import { describe, it, expect } from "vitest";
import {
  generateKeypair,
  exportPublicKey,
  computeKid,
  encryptContent,
  decryptContent,
  exportPrivateKeyPkcs8,
  importPrivateKeyPkcs8,
} from "../src/vault/index.js";

describe("computeKid", () => {
  it("is deterministic for the same public key", async () => {
    const pair = await generateKeypair();
    const exported = await exportPublicKey(pair.publicKey);
    const a = await computeKid(exported);
    const b = await computeKid(exported);
    expect(a).toBe(b);
  });

  it("differs across keypairs", async () => {
    const [p1, p2] = await Promise.all([generateKeypair(), generateKeypair()]);
    const [e1, e2] = await Promise.all([
      exportPublicKey(p1.publicKey),
      exportPublicKey(p2.publicKey),
    ]);
    expect(await computeKid(e1)).not.toBe(await computeKid(e2));
  });

  it("is a 22-char base64url string (16 bytes)", async () => {
    const pair = await generateKeypair();
    const kid = await computeKid(await exportPublicKey(pair.publicKey));
    expect(kid).toMatch(/^[A-Za-z0-9_-]{22}$/);
  });
});

describe("encryptContent kid stamping", () => {
  it("omits kid when not supplied (legacy user-era blob)", async () => {
    const pair = await generateKeypair();
    const enc = await encryptContent("hello", pair.publicKey);
    expect(enc.kid).toBeUndefined();
    expect("kid" in enc).toBe(false);
  });

  it("stamps kid when supplied and still round-trips", async () => {
    const pair = await generateKeypair();
    const exported = await exportPublicKey(pair.publicKey);
    const kid = await computeKid(exported);
    const enc = await encryptContent("hello", pair.publicKey, kid);
    expect(enc.kid).toBe(kid);
    expect(await decryptContent(enc, pair.privateKey)).toBe("hello");
  });

  it("kid does not affect the ciphertext envelope version", async () => {
    const pair = await generateKeypair();
    const kid = await computeKid(await exportPublicKey(pair.publicKey));
    const enc = await encryptContent("hello", pair.publicKey, kid);
    expect(enc.v).toBe("zkv1");
  });

  it("refuses a kid that does not belong to the recipient key", async () => {
    const pair = await generateKeypair();
    const other = await generateKeypair();
    const wrongKid = await computeKid(await exportPublicKey(other.publicKey));
    await expect(
      encryptContent("hello", pair.publicKey, wrongKid),
    ).rejects.toThrow("kid does not match recipientPublicKey");
  });

  it("refuses a garbage kid rather than stamping it", async () => {
    const pair = await generateKeypair();
    await expect(encryptContent("hello", pair.publicKey, "abc")).rejects.toThrow(
      "kid does not match recipientPublicKey",
    );
  });

  it("refuses an empty kid instead of silently treating it as absent", async () => {
    const pair = await generateKeypair();
    await expect(encryptContent("hello", pair.publicKey, "")).rejects.toThrow(
      "kid must be a non-empty string",
    );
  });
});

describe("kid is bound into the AEAD", () => {
  it("stripping kid makes decryption fail loudly, not silently reclassify", async () => {
    const pair = await generateKeypair();
    const kid = await computeKid(await exportPublicKey(pair.publicKey));
    const enc = await encryptContent("secret", pair.publicKey, kid);

    const stripped = { ...enc };
    delete stripped.kid;
    await expect(decryptContent(stripped, pair.privateKey)).rejects.toThrow();
  });

  it("swapping kid for another valid-looking one fails the tag check", async () => {
    const pair = await generateKeypair();
    const other = await generateKeypair();
    const kid = await computeKid(await exportPublicKey(pair.publicKey));
    const otherKid = await computeKid(await exportPublicKey(other.publicKey));
    const enc = await encryptContent("secret", pair.publicKey, kid);

    await expect(
      decryptContent({ ...enc, kid: otherKid }, pair.privateKey),
    ).rejects.toThrow();
  });

  it("a legacy blob written with NO aad still decrypts (wire compat)", async () => {
    // Reproduces a pre-kid blob at the WebCrypto level rather than trusting the
    // aad("") === no-aad equivalence. This is the test that says the change is
    // additive; if it ever fails, every stored blob is unreadable.
    const pair = await generateKeypair();
    const contentKey = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt"],
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv }, // no additionalData — exactly what shipped before
      contentKey,
      new TextEncoder().encode("legacy note"),
    );
    const wrappedKey = await crypto.subtle.wrapKey(
      "raw",
      contentKey,
      pair.publicKey,
      { name: "RSA-OAEP" },
    );
    const b64 = (b: Uint8Array) =>
      Buffer.from(b).toString("base64url");

    const legacy = {
      v: "zkv1" as const,
      iv: b64(iv),
      data: b64(new Uint8Array(ciphertext)),
      key: b64(new Uint8Array(wrappedKey)),
    };
    expect(await decryptContent(legacy, pair.privateKey)).toBe("legacy note");
  });
});

describe("pkcs8 private key round-trip", () => {
  it("exports to base64url and re-imports to a usable key", async () => {
    const pair = await generateKeypair();
    const b64 = await exportPrivateKeyPkcs8(pair.privateKey);
    expect(b64).toMatch(/^[A-Za-z0-9_-]+$/);

    const reimported = await importPrivateKeyPkcs8(b64);
    const enc = await encryptContent("secret", pair.publicKey);
    expect(await decryptContent(enc, reimported)).toBe("secret");
  });

  it("imports non-extractable by default", async () => {
    const pair = await generateKeypair();
    const b64 = await exportPrivateKeyPkcs8(pair.privateKey);
    const reimported = await importPrivateKeyPkcs8(b64);
    expect(reimported.extractable).toBe(false);
    await expect(
      crypto.subtle.exportKey("pkcs8", reimported),
    ).rejects.toThrow();
  });

  it("cannot be coaxed into an extractable key by a stray argument", async () => {
    const pair = await generateKeypair();
    const b64 = await exportPrivateKeyPkcs8(pair.privateKey);
    const reimported = await (
      importPrivateKeyPkcs8 as (b: string, x?: unknown) => Promise<CryptoKey>
    )(b64, true);
    expect(reimported.extractable).toBe(false);
  });
});

describe("workspace key wrapping — the full composition", () => {
  it("wraps ws-priv to a member and lets them decrypt workspace content", async () => {
    // Workspace keypair, generated in the creator's browser.
    const wsPair = await generateKeypair();
    const wsPub = await exportPublicKey(wsPair.publicKey);
    const kid = await computeKid(wsPub);

    // Two members, each with a personal vault keypair.
    const alice = await generateKeypair();
    const bob = await generateKeypair();

    // Alice provisions: wrap ws-priv to her own personal public key.
    const wsPrivPkcs8 = await exportPrivateKeyPkcs8(wsPair.privateKey);
    const aliceWrap = await encryptContent(wsPrivPkcs8, alice.publicKey);

    // Content is encrypted to the WORKSPACE key, stamped with its kid.
    const blob = await encryptContent("Q3 revenue target", wsPair.publicKey, kid);
    expect(blob.kid).toBe(kid);

    // Alice unlocks: unwrap ws-priv from her wrap, decrypt the content.
    const aliceWsPriv = await importPrivateKeyPkcs8(
      await decryptContent(aliceWrap, alice.privateKey),
    );
    expect(await decryptContent(blob, aliceWsPriv)).toBe("Q3 revenue target");

    // Alice grants Bob: re-derive the pkcs8 from her wrap, re-wrap to Bob.
    // Note she never needs an extractable ws-priv to do this.
    const rederived = await decryptContent(aliceWrap, alice.privateKey);
    const bobWrap = await encryptContent(rederived, bob.publicKey);

    // Bob unlocks with HIS personal key and reads the same content.
    const bobWsPriv = await importPrivateKeyPkcs8(
      await decryptContent(bobWrap, bob.privateKey),
    );
    expect(await decryptContent(blob, bobWsPriv)).toBe("Q3 revenue target");
  });

  it("a non-member's personal key cannot decrypt workspace content", async () => {
    const wsPair = await generateKeypair();
    const outsider = await generateKeypair();
    const kid = await computeKid(await exportPublicKey(wsPair.publicKey));
    const blob = await encryptContent("secret", wsPair.publicKey, kid);
    await expect(decryptContent(blob, outsider.privateKey)).rejects.toThrow();
  });

  it("a member's wrap is useless to anyone but that member", async () => {
    const wsPair = await generateKeypair();
    const alice = await generateKeypair();
    const bob = await generateKeypair();
    const wrap = await encryptContent(
      await exportPrivateKeyPkcs8(wsPair.privateKey),
      alice.publicKey,
    );
    await expect(decryptContent(wrap, bob.privateKey)).rejects.toThrow();
  });
});
