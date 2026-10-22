import { describe, it, expect } from "vitest";
import { randomBytes } from "node:crypto";
import {
  loadKey,
  encryptField,
  decryptField,
  isEncrypted,
  encryptFields,
  decryptFields,
} from "../src/index";

const KEY = loadKey(randomBytes(32).toString("base64"));
const OTHER_KEY = loadKey(randomBytes(32).toString("base64"));

describe("loadKey", () => {
  it("accepts a 32-byte base64 key", () => {
    expect(() => loadKey(randomBytes(32).toString("base64"))).not.toThrow();
  });

  it("REJECTS empty input", () => {
    expect(() => loadKey("")).toThrow();
  });

  it("REJECTS short keys", () => {
    expect(() => loadKey(randomBytes(16).toString("base64"))).toThrow();
  });

  it("REJECTS over-long keys", () => {
    expect(() => loadKey(randomBytes(64).toString("base64"))).toThrow();
  });
});

describe("encryptField + decryptField round-trip", () => {
  it("round-trips ASCII", () => {
    const ct = encryptField("hello world", KEY);
    expect(decryptField(ct, KEY)).toBe("hello world");
  });

  it("round-trips UTF-8 (emoji + Spanish + CJK)", () => {
    const plain = "héllo · 世界 · 🔒";
    const ct = encryptField(plain, KEY);
    expect(decryptField(ct, KEY)).toBe(plain);
  });

  it("passes through empty string without prefix", () => {
    expect(encryptField("", KEY)).toBe("");
    expect(decryptField("", KEY)).toBe("");
  });

  it("emits the v1 prefix on every ciphertext", () => {
    expect(encryptField("anything", KEY).startsWith("enc:v1:")).toBe(true);
  });

  it("produces a different ciphertext on every encrypt (random IV)", () => {
    const a = encryptField("same plaintext", KEY);
    const b = encryptField("same plaintext", KEY);
    expect(a).not.toBe(b);
    expect(decryptField(a, KEY)).toBe(decryptField(b, KEY));
  });
});

describe("decryptField — failure paths", () => {
  it("returns plain value when input lacks the prefix", () => {
    expect(decryptField("not encrypted", KEY)).toBe("not encrypted");
  });

  it("returns empty string on tampered ciphertext (GCM tag mismatch)", () => {
    const ct = encryptField("secret", KEY);
    const tampered = ct.slice(0, -2) + "AA";
    expect(decryptField(tampered, KEY)).toBe("");
  });

  it("returns empty string on wrong key", () => {
    const ct = encryptField("secret", KEY);
    expect(decryptField(ct, OTHER_KEY)).toBe("");
  });

  it("returns empty string on truncated payload", () => {
    expect(decryptField("enc:v1:AA", KEY)).toBe("");
  });
});

describe("isEncrypted", () => {
  it("returns true for prefixed ciphertext", () => {
    expect(isEncrypted(encryptField("x", KEY))).toBe(true);
  });

  it("returns false for plain text", () => {
    expect(isEncrypted("plain")).toBe(false);
  });

  it("returns false for empty string", () => {
    expect(isEncrypted("")).toBe(false);
  });
});

describe("encryptFields", () => {
  interface Row {
    id: string;
    taxId: string;
    notes: string;
    amount: number;
  }

  const row: Row = {
    id: "u1",
    taxId: "B12345678",
    notes: "internal",
    amount: 42,
  };

  it("encrypts only the listed string fields", () => {
    const out = encryptFields(row, ["taxId", "notes"], KEY);
    expect(isEncrypted(out.taxId)).toBe(true);
    expect(isEncrypted(out.notes)).toBe(true);
    expect(out.id).toBe("u1");
    expect(out.amount).toBe(42);
  });

  it("does not double-encrypt already-encrypted fields", () => {
    const once = encryptFields(row, ["taxId"], KEY);
    const twice = encryptFields(once, ["taxId"], KEY);
    expect(twice.taxId).toBe(once.taxId);
  });

  it("leaves non-string fields untouched even when listed", () => {
    const out = encryptFields(row, ["amount" as keyof Row], KEY);
    expect(out.amount).toBe(42);
  });

  it("leaves missing fields absent (no synthesis)", () => {
    const sparse: Partial<Row> = { id: "u1" };
    const out = encryptFields(sparse, ["taxId" as keyof Row], KEY);
    expect("taxId" in out).toBe(false);
  });

  it("returns a shallow clone — does not mutate input", () => {
    const before = JSON.stringify(row);
    encryptFields(row, ["taxId"], KEY);
    expect(JSON.stringify(row)).toBe(before);
  });
});

describe("decryptFields", () => {
  it("decrypts only the listed encrypted fields", () => {
    const encrypted = encryptFields(
      { taxId: "B12345678", notes: "internal", id: "u1" },
      ["taxId", "notes"],
      KEY,
    );
    const decrypted = decryptFields(encrypted, ["taxId", "notes"], KEY);
    expect(decrypted.taxId).toBe("B12345678");
    expect(decrypted.notes).toBe("internal");
    expect(decrypted.id).toBe("u1");
  });

  it("leaves plain fields untouched", () => {
    const out = decryptFields(
      { taxId: "B12345678", id: "u1" },
      ["taxId"],
      KEY,
    );
    expect(out.taxId).toBe("B12345678");
  });
});
