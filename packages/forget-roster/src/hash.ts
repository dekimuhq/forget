import { sha256 } from "@noble/hashes/sha2";

/** 32 zero bytes / 32 0xff bytes as lowercase hex — sentinel interval bounds. */
export const MIN = "00".repeat(32);
export const MAX = "ff".repeat(32);

export function toHex(bytes: Uint8Array): string {
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex;
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("odd-length hex");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Subject value = sha256(0x02 ‖ utf8(subjectKeyId)). This is the receipt's subjectKeyIdHash. */
export function subjectValue(subjectKeyId: string): string {
  const data = new TextEncoder().encode(subjectKeyId);
  return toHex(sha256(new Uint8Array([0x02, ...data])));
}

const HEX64 = /^[0-9a-f]{64}$/;

/** Leaf = sha256(0x00 ‖ lo ‖ hi) over two 32-byte hex bounds. Bounds MUST be exactly
 *  64 lowercase hex chars — fixed length removes the concatenation ambiguity that would
 *  otherwise let intervalLeaf("aabb","ccdd") === intervalLeaf("aa","bbccdd"). */
export function intervalLeaf(lo: string, hi: string): string {
  if (!HEX64.test(lo) || !HEX64.test(hi)) throw new Error("intervalLeaf bounds must be 64 lowercase hex chars (32 bytes)");
  return toHex(sha256(new Uint8Array([0x00, ...hexToBytes(lo), ...hexToBytes(hi)])));
}

/** Internal node = sha256(0x01 ‖ left ‖ right) over two 32-byte hex digests. */
export function internalNode(left: string, right: string): string {
  if (!HEX64.test(left) || !HEX64.test(right)) throw new Error("internalNode operands must be 64 lowercase hex chars (32 bytes)");
  return toHex(sha256(new Uint8Array([0x01, ...hexToBytes(left), ...hexToBytes(right)])));
}
