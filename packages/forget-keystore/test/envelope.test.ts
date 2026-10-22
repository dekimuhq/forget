import { describe, it, expect } from "vitest";
import { loadKey } from "@dekimuhq/crypto";
import { generateDek, dekKey } from "../src/dek";
import { wrapDek, unwrapDek } from "../src/envelope";

describe("dek", () => {
  it("generates a 32-byte DEK", () => {
    const dek = generateDek();
    expect(dek).toBeInstanceOf(Uint8Array);
    expect(dek.length).toBe(32);
  });

  it("generates a different DEK each call", () => {
    expect(Buffer.from(generateDek())).not.toEqual(Buffer.from(generateDek()));
  });

  it("adapts a DEK into an @dekimuhq/crypto EncryptionKey of 32 bytes", () => {
    const dek = generateDek();
    const key = dekKey(dek);
    expect(key.bytes.length).toBe(32);
    expect(Buffer.from(key.bytes)).toEqual(Buffer.from(dek));
  });
});

describe("envelope", () => {
  const kek = loadKey(Buffer.alloc(32, 7).toString("base64")); // deterministic test KEK

  it("round-trips a DEK through wrap/unwrap", () => {
    const dek = generateDek();
    const wrapped = wrapDek(dek, kek);
    expect(typeof wrapped).toBe("string");
    expect(wrapped.startsWith("enc:v1:")).toBe(true);
    const back = unwrapDek(wrapped, kek);
    expect(back).not.toBeNull();
    expect(Buffer.from(back!)).toEqual(Buffer.from(dek));
  });

  it("returns null when unwrapping under the wrong KEK (shredded/forged)", () => {
    const dek = generateDek();
    const wrapped = wrapDek(dek, kek);
    const otherKek = loadKey(Buffer.alloc(32, 9).toString("base64"));
    expect(unwrapDek(wrapped, otherKek)).toBeNull();
  });

  it("returns null on a garbage wrapped value", () => {
    expect(unwrapDek("not-a-wrapped-dek", kek)).toBeNull();
    expect(unwrapDek("enc:v1:zzzz", kek)).toBeNull();
  });
});
