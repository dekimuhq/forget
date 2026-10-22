/**
 * RFC 8785 (JCS) JSON canonicalization — deterministic, sorted-key,
 * whitespace-free serialization for stable signing/hashing.
 *
 * Vendored as a zero-dependency primitive. The output MUST stay byte-identical
 * across releases: verification recomputes it, so any drift would make
 * already-signed roots/receipts fail to verify.
 */
export function canonicalize(value: unknown): string {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "number") {
    if (!Number.isFinite(value as number)) throw new Error("canonicalize: non-finite number");
    return JSON.stringify(value);
  }
  if (t === "boolean" || t === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map((v) => canonicalize(v)).join(",") + "]";
  }
  if (t === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalize(obj[k])).join(",") + "}";
  }
  throw new Error(`canonicalize: unsupported type ${t}`);
}
