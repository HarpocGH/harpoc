export interface Needle {
  label: string;
  value: string;
}

/**
 * A private key leaks either verbatim (armored, wrapped at 64 chars) or
 * re-encoded, so both the first base64 line and the unwrapped body are needles.
 */
export function keyNeedles(label: string, pem: string): Needle[] {
  const lines = pem
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith("-----"));
  return [
    { label: `${label} (first base64 line)`, value: lines[0] as string },
    { label: `${label} (unwrapped base64 body)`, value: lines.join("") },
  ];
}

/**
 * Line breaks are not part of a needle's identity: an armored key reaches a raw
 * response body wrapped at real newlines and a stringified one wrapped at `\n`
 * escapes, while the unwrapped-body needle carries neither. Stripping both from
 * both sides is what lets that needle fire at all.
 */
export function canon(text: string): string {
  return text.replaceAll("\\n", "").replaceAll("\n", "");
}
