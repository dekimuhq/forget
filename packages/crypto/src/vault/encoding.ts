/**
 * Convert a Uint8Array to a plain ArrayBuffer.
 * Needed because TS 5.x WebCrypto types reject Uint8Array<ArrayBufferLike>
 * where BufferSource (backed by ArrayBuffer, not SharedArrayBuffer) is expected.
 */
export function toBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength,
  ) as ArrayBuffer;
}

/** Base64url encode a Uint8Array (no padding). */
export function toBase64Url(bytes: Uint8Array): string {
  // Chunked: String.fromCharCode(...bytes) spreads the whole array as
  // arguments and throws RangeError on large payloads (~64k+ elements) —
  // encrypted vault content can easily exceed that.
  const CHUNK = 0x8000;
  let bin = "";
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Base64url decode to Uint8Array. */
export function fromBase64Url(str: string): Uint8Array {
  const base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad = (4 - (base64.length % 4)) % 4;
  const bin = atob(base64 + "=".repeat(pad));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    bytes[i] = bin.charCodeAt(i);
  }
  return bytes;
}
