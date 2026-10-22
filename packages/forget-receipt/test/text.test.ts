import { describe, it, expect } from "vitest";
import { sanitizeRationale } from "../src/text";

const NUL = String.fromCodePoint(0x00);
const ZERO_WIDTH = String.fromCodePoint(0x200b); // zero-width space
const RTL_OVERRIDE = String.fromCodePoint(0x202e); // right-to-left override (bidi)

describe("sanitizeRationale", () => {
  it("NFC-normalizes and passes plain text through", () => {
    // "e" + combining acute (NFD) normalizes to the single NFC codepoint
    const nfd = "cafe" + String.fromCodePoint(0x0301);
    expect(sanitizeRationale(nfd)).toBe(nfd.normalize("NFC"));
    expect(sanitizeRationale("no training pipeline")).toBe("no training pipeline");
  });

  it("ADVERSARIAL: rejects control, zero-width, and bidi-override codepoints", () => {
    expect(() => sanitizeRationale("evil" + NUL + "nul")).toThrow();
    expect(() => sanitizeRationale("zero" + ZERO_WIDTH + "width")).toThrow();
    expect(() => sanitizeRationale("bidi" + RTL_OVERRIDE + "override")).toThrow();
  });

  it("rejects empty / oversized input", () => {
    expect(() => sanitizeRationale("")).toThrow();
    expect(() => sanitizeRationale("x".repeat(2001))).toThrow();
  });
});
