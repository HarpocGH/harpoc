import { Transform } from "node:stream";
import type { TransformCallback } from "node:stream";

/** The replacement marker — the one core's `redactSecretEncodings` writes (`output-sanitizer.ts`). */
export const REDACTION_MARKER = "[REDACTED]";

const MARKER = Buffer.from(REDACTION_MARKER);

/** A response-body transform; `changed` is final once the stream has ended. */
export interface RedactingTransform extends Transform {
  readonly changed: boolean;
}

/**
 * Best-effort exact-value redaction of a brokered response (DB-8): every
 * occurrence of a needle becomes {@link REDACTION_MARKER}, leftmost first and
 * the longest needle at one position, with the last `maxNeedleLength − 1`
 * bytes carried across chunk boundaries and flushed at the end. Byte-based,
 * so a needle split inside a UTF-8 sequence is found the same way. The
 * transform holds its own copies of the needles and zero-fills them at its
 * end or destroy; empty needles are dropped, and none left is a pass-through.
 */
export function createRedactingTransform(values: readonly Uint8Array[]): RedactingTransform {
  return new RedactingStream(values);
}

/** The same match over one complete value — a response header's. */
export function redactBytes(
  input: Uint8Array,
  values: readonly Uint8Array[],
): { output: Buffer; changed: boolean } {
  const needles = ownNeedles(values);
  const { output, replaced } = scan(Buffer.from(input), needles, true);
  for (const needle of needles) needle.fill(0);
  return { output, changed: replaced };
}

class RedactingStream extends Transform implements RedactingTransform {
  private readonly needles: Buffer[];
  private carry: Buffer = Buffer.alloc(0);
  private replaced = false;

  constructor(values: readonly Uint8Array[]) {
    super();
    this.needles = ownNeedles(values);
  }

  get changed(): boolean {
    return this.replaced;
  }

  override _transform(chunk: Buffer, _encoding: BufferEncoding, callback: TransformCallback): void {
    if (this.needles.length === 0) {
      callback(null, chunk);
      return;
    }
    const buf = this.carry.length === 0 ? chunk : Buffer.concat([this.carry, chunk]);
    const result = scan(buf, this.needles, false);
    this.carry = result.carry;
    this.replaced ||= result.replaced;
    callback(null, result.output.length > 0 ? result.output : undefined);
  }

  override _flush(callback: TransformCallback): void {
    const result = scan(this.carry, this.needles, true);
    this.carry = Buffer.alloc(0);
    this.replaced ||= result.replaced;
    this.wipe();
    callback(null, result.output.length > 0 ? result.output : undefined);
  }

  override _destroy(error: Error | null, callback: (error?: Error | null) => void): void {
    this.wipe();
    callback(error);
  }

  private wipe(): void {
    for (const needle of this.needles) needle.fill(0);
  }
}

function ownNeedles(values: readonly Uint8Array[]): Buffer[] {
  const needles: Buffer[] = [];
  for (const value of values) {
    if (value.length > 0 && !needles.some((needle) => needle.equals(value))) {
      needles.push(Buffer.from(value));
    }
  }
  return needles.sort((a, b) => b.length - a.length);
}

/**
 * Replace every match that starts where the whole of every needle is already
 * in `buf`; on a non-final scan the tail a match could still extend into —
 * at most `longest − 1` bytes — comes back as `carry`.
 */
function scan(
  buf: Buffer,
  needles: readonly Buffer[],
  final: boolean,
): { output: Buffer; carry: Buffer; replaced: boolean } {
  const longest = needles[0]?.length ?? 0;
  const limit = final ? buf.length : buf.length - (longest - 1);
  const next = needles.map((needle) => buf.indexOf(needle));
  const pieces: Buffer[] = [];
  let from = 0;
  for (;;) {
    let at = -1;
    let length = 0;
    for (let k = 0; k < needles.length; k++) {
      const index = next[k] as number;
      if (index !== -1 && (at === -1 || index < at)) {
        at = index;
        length = (needles[k] as Buffer).length;
      }
    }
    if (at === -1 || at >= limit) break;
    pieces.push(buf.subarray(from, at), MARKER);
    from = at + length;
    for (let k = 0; k < needles.length; k++) {
      const index = next[k] as number;
      if (index !== -1 && index < from) next[k] = buf.indexOf(needles[k] as Buffer, from);
    }
  }
  const cut = Math.max(from, Math.min(limit, buf.length));
  pieces.push(buf.subarray(from, cut));
  return {
    output: Buffer.concat(pieces),
    carry: Buffer.from(buf.subarray(cut)),
    replaced: pieces.length > 1,
  };
}
