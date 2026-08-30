/**
 * Byte-bounded reads of WHATWG response bodies, shared by the HTTP injector
 * and the ACME client (E80 / E86a). Pure over the web-streams API: the
 * caller maps a refused read onto its own error code.
 */
export type CappedBodyRead = { ok: true; bytes: Uint8Array } | { ok: false; reason: "too_large" };

/** True when a declared Content-Length exceeds `maxBytes`; absent or unparseable ⇒ false. */
export function contentLengthExceeds(
  headers: { get(name: string): string | null },
  maxBytes: number,
): boolean {
  const declared = headers.get("content-length");
  if (declared === null) return false;
  const length = Number(declared);
  return Number.isFinite(length) && length > maxBytes;
}

/**
 * Read `body` up to `maxBytes`. Past the cap the stream is cancelled and the
 * read refused — nothing is truncated, because a body cut mid-string can
 * split an echoed credential past the redactor. A null body reads as empty.
 */
export async function readBodyCapped(
  body: ReadableStream<Uint8Array> | null,
  maxBytes: number,
): Promise<CappedBodyRead> {
  if (body === null) return { ok: true, bytes: new Uint8Array(0) };
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value === undefined) continue;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => undefined);
        return { ok: false, reason: "too_large" };
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { ok: true, bytes };
}
