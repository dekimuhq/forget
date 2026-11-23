import { describe, it, expect, beforeAll } from "vitest";
import { hkdfSync, createCipheriv, randomBytes } from "node:crypto";
import {
  generateKeypair,
  generateVaultKey,
  exportPublicKey,
  computeKid,
  exportPrivateKeyPkcs8,
  importPrivateKeyPkcs8,
  encryptContent,
  encryptBlob,
  decryptBlob,
  deriveWorkspaceDataKey,
  derivePersonalDataKey,
  blobAad,
  BlobContextError,
} from "../src/vault/index.js";
import { importVaultKeyRaw } from "../src/vault/derive.js";
import type {
  BlobContext,
  DataKey,
  EncryptedContentV2,
} from "../src/vault/index.js";
import kat from "./fixtures/zkv2-kat.json";

/**
 * Context-bound envelope v2. Every negative test has a positive control next to
 * it, built from the same fixture, so a test cannot pass just because the
 * fixture is broken.
 */

let pair: CryptoKeyPair;
let kid: string;
let wdk: DataKey;
let pdk: DataKey;
let ctx: BlobContext;

beforeAll(async () => {
  pair = await generateKeypair();
  kid = await computeKid(await exportPublicKey(pair.publicKey));
  wdk = await deriveWorkspaceDataKey(pair.privateKey, "ws1", kid);
  pdk = await derivePersonalDataKey(await generateVaultKey(), "u1");
  ctx = {
    scope: "ws:ws1",
    kid,
    epoch: 1,
    purpose: "field",
    coll: "notes",
    rec: "r1",
    field: "body",
    ver: 2,
  };
});

const b64u = (b: Uint8Array): string => Buffer.from(b).toString("base64url");

/**
 * What a party that has the public key and knows the format, but not the
 * workspace secret, can build: a well-formed member blob with the correct AAD
 * under some key it chose.
 */
function forgeMember(c: BlobContext, plaintext: string): EncryptedContentV2 {
  const key = randomBytes(32);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(blobAad("member", c)));
  const ct = Buffer.concat([
    cipher.update(plaintext),
    cipher.final(),
    cipher.getAuthTag(),
  ]);
  return { v: "zkv2", cls: "member", ...c, iv: b64u(iv), data: b64u(ct) };
}

describe("member round trip", () => {
  it("workspace data key: encrypt then decrypt", async () => {
    const enc = await encryptBlob("hello", wdk, ctx);
    expect(enc.v).toBe("zkv2");
    expect(enc.cls).toBe("member");
    expect(enc.key).toBeUndefined();
    expect(await decryptBlob(enc, { dataKey: wdk }, ctx)).toEqual({
      plaintext: "hello",
      cls: "member",
    });
  });

  it("personal data key: encrypt then decrypt", async () => {
    const c = { ...ctx, scope: "u:u1" as const };
    const enc = await encryptBlob("hello", pdk, c);
    expect((await decryptBlob(enc, { dataKey: pdk }, c)).plaintext).toBe("hello");
  });

  it("the PKCS8 path derives the same key as the extractable-key path", async () => {
    const pkcs8 = await exportPrivateKeyPkcs8(pair.privateKey);
    const fromPkcs8 = await deriveWorkspaceDataKey(pkcs8, "ws1", kid);
    const enc = await encryptBlob("x", wdk, ctx);
    expect((await decryptBlob(enc, { dataKey: fromPkcs8 }, ctx)).plaintext).toBe("x");
  });
});

describe("forgery: a well-formed blob with valid AAD but no key", () => {
  it("is refused under member", async () => {
    const forged = forgeMember(ctx, "attacker text");
    await expect(decryptBlob(forged, { dataKey: wdk }, ctx)).rejects.toThrow();
  });

  it("negative control: the same construction with the real key decrypts", async () => {
    // The same bytes path, but sealed by a key holder through encryptBlob.
    const real = await encryptBlob("attacker text", wdk, ctx);
    expect({ ...real, iv: "", data: "" }).toEqual({
      ...forgeMember(ctx, "attacker text"),
      iv: "",
      data: "",
    });
    expect((await decryptBlob(real, { dataKey: wdk }, ctx)).plaintext).toBe(
      "attacker text",
    );
  });

  it("a forged inbound blob cannot replace a member blob at ver > 0", async () => {
    const at0 = { ...ctx, ver: 0 };
    const inbound = await encryptBlob("form text", pair.publicKey, at0);
    // Relabelled to ver 2 and served where a member blob is expected.
    await expect(
      decryptBlob({ ...inbound, ver: 2 }, { dataKey: wdk, privateKey: pair.privateKey }, ctx),
    ).rejects.toThrow(BlobContextError);
  });
});

describe("splicing: a blob moved elsewhere fails", () => {
  const moves: Array<[string, Partial<BlobContext>]> = [
    ["record", { rec: "r2" }],
    ["field", { field: "title" }],
    ["collection", { coll: "tasks" }],
    ["purpose", { purpose: "backup" }],
    ["epoch", { epoch: 2 }],
    ["kid", { kid: "AAAAAAAAAAAAAAAAAAAAAA" }],
  ];

  for (const [name, change] of moves) {
    it(`to another ${name}: header copied from the blob is refused`, async () => {
      const enc = await encryptBlob("secret", wdk, ctx);
      await expect(
        decryptBlob(enc, { dataKey: wdk }, { ...ctx, ...change }),
      ).rejects.toThrow(BlobContextError);
    });

    it(`to another ${name}: header rewritten to match still fails the tag`, async () => {
      const enc = await encryptBlob("secret", wdk, ctx);
      const target = { ...ctx, ...change };
      // A key-id change is refused by the data-key check before the tag; the
      // tag check below is what stops every other rewrite.
      await expect(
        decryptBlob({ ...enc, ...change }, { dataKey: wdk }, target),
      ).rejects.toThrow();
    });
  }

  it("to another workspace: refused even with that workspace's key", async () => {
    const otherWs = await deriveWorkspaceDataKey(pair.privateKey, "ws2", kid);
    const enc = await encryptBlob("secret", wdk, ctx);
    const target = { ...ctx, scope: "ws:ws2" as const };
    await expect(
      decryptBlob({ ...enc, scope: "ws:ws2" }, { dataKey: otherWs }, target),
    ).rejects.toThrow();
  });

  it("negative control: the unmoved blob decrypts", async () => {
    const enc = await encryptBlob("secret", wdk, ctx);
    expect((await decryptBlob(enc, { dataKey: wdk }, ctx)).plaintext).toBe("secret");
  });

  it("the data key of one scope cannot be used for another", async () => {
    await expect(
      encryptBlob("x", wdk, { ...ctx, scope: "ws:ws2" }),
    ).rejects.toThrow(BlobContextError);
    await expect(
      decryptBlob(await encryptBlob("x", wdk, ctx), { dataKey: pdk }, ctx),
    ).rejects.toThrow(BlobContextError);
  });
});

describe("version binding", () => {
  it("a blob served at an older ver than requested fails", async () => {
    const old = await encryptBlob("v1 text", wdk, { ...ctx, ver: 1 });
    await expect(decryptBlob(old, { dataKey: wdk }, ctx)).rejects.toThrow(
      BlobContextError,
    );
    await expect(
      decryptBlob({ ...old, ver: 2 }, { dataKey: wdk }, ctx),
    ).rejects.toThrow();
  });

  it("negative control: the same blob at its own ver decrypts", async () => {
    const old = await encryptBlob("v1 text", wdk, { ...ctx, ver: 1 });
    const res = await decryptBlob(old, { dataKey: wdk }, { ...ctx, ver: 1 });
    expect(res.plaintext).toBe("v1 text");
  });

  it("rejects malformed ver/epoch", async () => {
    for (const ver of [-1, 1.5, Number.NaN, 2 ** 53]) {
      await expect(encryptBlob("x", wdk, { ...ctx, ver })).rejects.toThrow(
        BlobContextError,
      );
    }
  });
});

describe("inbound", () => {
  it("round-trips at ver 0 and reports cls inbound", async () => {
    const at0 = { ...ctx, ver: 0 };
    const enc = await encryptBlob("form text", pair.publicKey, at0);
    expect(enc.cls).toBe("inbound");
    expect(typeof enc.key).toBe("string");
    expect(
      await decryptBlob(enc, { privateKey: pair.privateKey }, at0),
    ).toEqual({ plaintext: "form text", cls: "inbound" });
  });

  it("cannot be written above ver 0", async () => {
    await expect(encryptBlob("x", pair.publicKey, ctx)).rejects.toThrow(
      "only allowed at ver 0",
    );
  });

  it("is refused when the reader expects ver > 0, even if built by hand", async () => {
    // Bypass encryptBlob's write-side check: wrap a key directly.
    const key = randomBytes(32);
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    cipher.setAAD(Buffer.from(blobAad("inbound", ctx)));
    const data = Buffer.concat([cipher.update("x"), cipher.final(), cipher.getAuthTag()]);
    const aes = await crypto.subtle.importKey("raw", key, "AES-GCM", true, ["encrypt"]);
    const wrapped = await crypto.subtle.wrapKey("raw", aes, pair.publicKey, { name: "RSA-OAEP" });
    const enc: EncryptedContentV2 = {
      v: "zkv2",
      cls: "inbound",
      ...ctx,
      iv: b64u(iv),
      data: b64u(data),
      key: b64u(new Uint8Array(wrapped)),
    };
    await expect(
      decryptBlob(enc, { privateKey: pair.privateKey }, ctx),
    ).rejects.toThrow("only accepted at ver 0");
    // Negative control: the same construction at ver 0 decrypts.
    const at0 = { ...ctx, ver: 0 };
    const c0 = createCipheriv("aes-256-gcm", key, iv);
    c0.setAAD(Buffer.from(blobAad("inbound", at0)));
    const d0 = Buffer.concat([c0.update("x"), c0.final(), c0.getAuthTag()]);
    const ok = await decryptBlob(
      { ...enc, ver: 0, data: b64u(d0) },
      { privateKey: pair.privateKey },
      at0,
    );
    expect(ok).toEqual({ plaintext: "x", cls: "inbound" });
  });

  it("relabelling cls inbound -> member fails", async () => {
    const at0 = { ...ctx, ver: 0 };
    const enc = await encryptBlob("x", pair.publicKey, at0);
    await expect(
      decryptBlob({ ...enc, cls: "member" }, { dataKey: wdk }, at0),
    ).rejects.toThrow(BlobContextError);
  });

  it("refuses a kid that does not belong to the recipient key", async () => {
    await expect(
      encryptBlob("x", pair.publicKey, { ...ctx, ver: 0, kid: "AAAAAAAAAAAAAAAAAAAAAA" }),
    ).rejects.toThrow("kid does not match");
  });
});

describe("zkv1 compatibility", () => {
  it("still decrypts through decryptBlob", async () => {
    const v1 = await encryptContent("legacy", pair.publicKey, kid);
    expect(
      await decryptBlob(v1, { privateKey: pair.privateKey }, ctx),
    ).toEqual({ plaintext: "legacy", cls: "legacy" });
  });

  it("is refused when the scope is flagged as migrated", async () => {
    const v1 = await encryptContent("legacy", pair.publicKey, kid);
    await expect(
      decryptBlob(v1, { privateKey: pair.privateKey }, { ...ctx, rejectV1: true }),
    ).rejects.toThrow("zkv1 blob refused");
  });

  it("negative control: zkv2 is still accepted with rejectV1", async () => {
    const enc = await encryptBlob("new", wdk, ctx);
    const res = await decryptBlob(enc, { dataKey: wdk }, { ...ctx, rejectV1: true });
    expect(res.plaintext).toBe("new");
  });

  it("an unknown version is refused", async () => {
    const enc = await encryptBlob("x", wdk, ctx);
    await expect(
      decryptBlob({ ...enc, v: "zkv3" as "zkv2" }, { dataKey: wdk }, ctx),
    ).rejects.toThrow("unknown version");
  });
});

describe("derivation inputs", () => {
  it("refuses a non-extractable private key and points at PKCS8", async () => {
    const pkcs8 = await exportPrivateKeyPkcs8(pair.privateKey);
    const handle = await importPrivateKeyPkcs8(pkcs8);
    await expect(deriveWorkspaceDataKey(handle, "ws1", kid)).rejects.toThrow(
      "pass its PKCS8",
    );
  });

  it("refuses a kid that does not belong to the workspace key", async () => {
    await expect(
      deriveWorkspaceDataKey(pair.privateKey, "ws1", "AAAAAAAAAAAAAAAAAAAAAA"),
    ).rejects.toThrow("kid does not match");
  });

  it("refuses empty ids", async () => {
    await expect(deriveWorkspaceDataKey(pair.privateKey, "", kid)).rejects.toThrow();
    await expect(derivePersonalDataKey(await generateVaultKey(), "")).rejects.toThrow();
  });

  it("derived keys are not extractable", () => {
    expect(wdk.key.extractable).toBe(false);
    expect(pdk.key.extractable).toBe(false);
  });
});

describe("known-answer vectors (reference: node:crypto hkdfSync + AES-GCM)", () => {
  it("AAD canonical form is pinned", () => {
    const { v: _v, cls: _c, iv: _i, data: _d, ...wsCtx } = kat.ws.blob;
    expect(new TextDecoder().decode(blobAad("member", wsCtx as BlobContext))).toBe(
      kat.ws.aad,
    );
    expect(kat.ws.aad).toBe(
      '{"cls":"member","coll":"notes","epoch":1,"field":"body","kid":"noDKTzAijIFzVDzqXREK7A","purpose":"field","rec":"r1","scope":"ws:ws_kat_1","v":"zkv2","ver":3}',
    );
  });

  it("AAD escapes strings the JCS way and orders keys by code unit", () => {
    const aad = blobAad("member", {
      ...ctx,
      kid: "k",
      rec: 'a"\\\u0001é😀',
    });
    expect(new TextDecoder().decode(aad)).toContain('"rec":"a\\"\\\\\\u0001é😀"');
  });

  it("refuses lone surrogates in AAD strings", () => {
    expect(() => blobAad("member", { ...ctx, rec: "\uD800" })).toThrow(BlobContextError);
  });

  it("wdk matches the reference HKDF and opens the pinned blob", async () => {
    const jwk = await crypto.subtle.exportKey(
      "jwk",
      await crypto.subtle.importKey(
        "pkcs8",
        Buffer.from(kat.pkcs8, "base64url"),
        { name: "RSA-OAEP", hash: "SHA-256" },
        true,
        ["decrypt"],
      ),
    );
    const ref = Buffer.from(
      hkdfSync("sha256", Buffer.from(jwk.d!, "base64url"), "ws_kat_1", `dekimu/wdk/v1|${kat.kid}`, 32),
    ).toString("hex");
    expect(ref).toBe("5367579400f38b2ada66142356ac54deecb1e884285aa3b416309cd67ccbb776");
    expect(kat.wdk).toBe(ref);

    const dk = await deriveWorkspaceDataKey(kat.pkcs8, "ws_kat_1", kat.kid);
    const { v: _v, cls: _c, iv: _i, data: _d, ...expected } = kat.ws.blob;
    const res = await decryptBlob(
      kat.ws.blob as EncryptedContentV2,
      { dataKey: dk },
      expected as BlobContext,
    );
    expect(res.plaintext).toBe("known answer");
  });

  it("pdk matches the reference HKDF and opens the pinned blob", async () => {
    const raw = new Uint8Array([...Array(32).keys()]);
    const ref = Buffer.from(hkdfSync("sha256", raw, "user_kat_1", "dekimu/pdk/v1", 32)).toString("hex");
    expect(ref).toBe("40db11ecdc1bf8c8c8c7243a8195a71090b416711aba36cde53056569ec5dc90");
    expect(kat.pdk).toBe(ref);

    const dk = await derivePersonalDataKey(await importVaultKeyRaw(raw), "user_kat_1");
    const { v: _v, cls: _c, iv: _i, data: _d, ...expected } = kat.u.blob;
    const res = await decryptBlob(
      kat.u.blob as EncryptedContentV2,
      { dataKey: dk },
      expected as BlobContext,
    );
    expect(res.plaintext).toBe("known answer");
  });

  it("negative control: a different salt does not open the pinned blob", async () => {
    const raw = new Uint8Array([...Array(32).keys()]);
    const wrong = await derivePersonalDataKey(await importVaultKeyRaw(raw), "user_kat_2");
    const { v: _v, cls: _c, iv: _i, data: _d, ...expected } = kat.u.blob;
    await expect(
      decryptBlob(
        kat.u.blob as EncryptedContentV2,
        { dataKey: { ...wrong, scope: "u:user_kat_1" } },
        expected as BlobContext,
      ),
    ).rejects.toThrow();
  });
});
