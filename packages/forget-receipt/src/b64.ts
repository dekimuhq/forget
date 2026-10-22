const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

export function bytesToBase64url(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i]!, b1 = bytes[i + 1] ?? 0, b2 = bytes[i + 2] ?? 0;
    const n = (b0 << 16) | (b1 << 8) | b2;
    out += ALPHABET[(n >> 18) & 63]! + ALPHABET[(n >> 12) & 63]!;
    if (i + 1 < bytes.length) out += ALPHABET[(n >> 6) & 63]!;
    if (i + 2 < bytes.length) out += ALPHABET[n & 63]!;
  }
  return out;
}

export function base64urlToBytes(s: string): Uint8Array {
  const lookup = new Map([...ALPHABET].map((c, i) => [c, i] as const));
  const val = (ch: string | undefined): number => {
    const v = ch === undefined ? undefined : lookup.get(ch);
    if (v === undefined) throw new Error("invalid base64url");
    return v;
  };
  const bytes: number[] = [];
  for (let i = 0; i < s.length; ) {
    if (i + 1 >= s.length) throw new Error("invalid base64url length");
    const c0 = val(s[i++]), c1 = val(s[i++]);
    bytes.push((c0 << 2) | (c1 >> 4));
    if (i < s.length) {
      const c2 = val(s[i++]);
      bytes.push(((c1 & 15) << 4) | (c2 >> 2));
      if (i < s.length) {
        const c3 = val(s[i++]);
        bytes.push(((c2 & 3) << 6) | c3);
      }
    }
  }
  return new Uint8Array(bytes);
}
