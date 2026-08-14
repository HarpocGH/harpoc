export interface Encoding {
  label: string;
  needle: string;
}

/**
 * The shapes a credential can wear on its way out. Sanitization that matches
 * only the raw string is defeated by any of the others. Encodings that
 * collapse onto an earlier one for a given secret are dropped, so a hit is
 * always attributed to the first encoding that produces it.
 */
export function encodingsOf(secret: string): Encoding[] {
  const buf = Buffer.from(secret, "utf8");
  const candidates: Encoding[] = [
    { label: "raw", needle: secret },
    { label: "base64", needle: buf.toString("base64") },
    { label: "base64url", needle: buf.toString("base64url") },
    { label: "hex", needle: buf.toString("hex") },
    { label: "hexUpper", needle: buf.toString("hex").toUpperCase() },
    { label: "urlEncoded", needle: encodeURIComponent(secret) },
    // No `jsonEscaped` needle: it reproduced V8's convention only, and `scan`
    // now matches every needle above tolerantly, covering the whole class
    // (review 2026-08-14, F1). A hit through an escape is labelled
    // "<encoding>+jsonEscaped", so attribution survives the change.
  ];

  const seen = new Set<string>();
  return candidates.filter((e) => {
    if (e.needle.length === 0 || seen.has(e.needle)) return false;
    seen.add(e.needle);
    return true;
  });
}
