/**
 * Base64 for the wire's `value` fields (create and rotate both parse a
 * base64-validated string).
 *
 * `btoa` alone is not it: it is a Latin-1 byte encoder and throws
 * `InvalidCharacterError` on any code point above U+00FF, so a passphrase with
 * an umlaut or a check mark in it would be the one value the UI could not
 * deliver. The text is encoded to UTF-8 bytes first — the encoding the API
 * decodes with — and `btoa` only ever sees a byte string.
 */
export function toBase64(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}
