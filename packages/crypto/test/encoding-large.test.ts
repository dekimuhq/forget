import { describe, it, expect } from "vitest";
import { toBase64Url, fromBase64Url } from "../src/vault/encoding";
import { generateKeypair, encryptContent, decryptContent } from "../src/vault/index";

// Regression: toBase64Url used String.fromCharCode(...bytes), which throws
// RangeError ("Maximum call stack size exceeded") on payloads of ~64k+ bytes.

function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  // getRandomValues is capped at 65536 bytes per call
  for (let i = 0; i < n; i += 65536) {
    crypto.getRandomValues(out.subarray(i, Math.min(i + 65536, n)));
  }
  return out;
}

describe("large payloads", () => {
  it("base64url round-trips 300 KB of random bytes", () => {
    const bytes = randomBytes(300 * 1024 + 7);
    const enc = toBase64Url(bytes);
    expect(enc).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(fromBase64Url(enc)).toEqual(bytes);
  });

  it("encryptContent/decryptContent round-trips a ~300 KB string", async () => {
    const kp = await generateKeypair();
    const plain = "x".repeat(300 * 1024) + "end-é✓";
    const enc = await encryptContent(plain, kp.publicKey);
    expect(await decryptContent(enc, kp.privateKey)).toBe(plain);
  });
});
