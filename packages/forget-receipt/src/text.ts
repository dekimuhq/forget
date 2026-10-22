/**
 * Normalize + validate free text that will be SIGNED into a receipt. NFC-normalize
 * for canonical stability, then reject disallowed Unicode (C0/C1 controls, zero-width,
 * bidi controls) so a rationale cannot smuggle invisible/bidi-injection payloads.
 * Allowlist-complement style: permit everything except the named dangerous ranges.
 */
const MAX_LEN = 2000;

/** True for codepoints we refuse to sign into a receipt. */
function isDisallowed(cp: number): boolean {
  if (cp <= 0x1f) return cp !== 0x09 && cp !== 0x0a && cp !== 0x0d; // C0 controls except tab/LF/CR
  if (cp >= 0x7f && cp <= 0x9f) return true; // DEL + C1 controls
  if (cp >= 0x200b && cp <= 0x200f) return true; // zero-width + LRM/RLM
  if (cp >= 0x202a && cp <= 0x202e) return true; // bidi embeddings/overrides
  if (cp >= 0x2066 && cp <= 0x2069) return true; // bidi isolates
  if (cp === 0xfeff) return true; // zero-width no-break space (BOM)
  return false;
}

export function sanitizeRationale(input: string): string {
  const s = input.normalize("NFC");
  if (s.length === 0) throw new Error("rationale: empty");
  if (s.length > MAX_LEN) throw new Error("rationale: exceeds max length");
  for (const ch of s) {
    if (isDisallowed(ch.codePointAt(0)!)) {
      throw new Error("rationale: contains disallowed control/format codepoint");
    }
  }
  return s;
}
