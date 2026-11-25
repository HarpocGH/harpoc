import { MAX_RENDER_PATH_BYTES, MAX_RENDER_PATH_SEGMENT_BYTES } from "./constants.js";
import type { RenderEntry } from "./schemas.js";

/** The characters a value may hold beside other text in a render template (design 5 § 6.6). */
export const RENDER_MIXED_VALUE_REGEX = /^[A-Za-z0-9._~+/=:@%-]+$/;

const UNPRINTED_CHARACTER = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;
const TEMP_NAME_HEX = /^[0-9a-f]{32}$/;
const TEMP_NAME_INFIX = ".harpoc-";
const RENDER_ENTRY_TAG = "harpoc-render-entry-v1";

/** The UTF-8 length of `text` in bytes; `null` where it holds an unpaired surrogate. */
export function utf8ByteLength(text: string): number | null {
  let bytes = 0;
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    if (unit < 0x80) {
      bytes += 1;
    } else if (unit < 0x800) {
      bytes += 2;
    } else if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = text.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return null;
      bytes += 4;
      i++;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return null;
    } else {
      bytes += 3;
    }
  }
  return bytes;
}

/** The temporary name a render writes before its rename: `.<last segment>.harpoc-<32 lower-case hex>.tmp`. */
export function renderTempName(lastSegment: string, hex32: string): string {
  return `.${lastSegment}${TEMP_NAME_INFIX}${hex32}.tmp`;
}

/** Whether `segment` has the temporary name's form, of `lastSegment` where it is given. */
export function isRenderTempName(segment: string, lastSegment?: string): boolean {
  return (
    segment.length >= 46 &&
    segment.startsWith(".") &&
    segment.endsWith(".tmp") &&
    segment.slice(-44, -36) === TEMP_NAME_INFIX &&
    TEMP_NAME_HEX.test(segment.slice(-36, -4)) &&
    (lastSegment === undefined || segment.slice(1, -44) === lastSegment)
  );
}

/**
 * A remote path in normal form (design 5 § 6.1): absolute, at most
 * `MAX_RENDER_PATH_BYTES` bytes of UTF-8, no control or format character and no
 * line or paragraph separator (a listing or an audit row would show the path
 * other than it is), no empty, `.` or `..` segment, no trailing `/`, and a last
 * segment of at most `MAX_RENDER_PATH_SEGMENT_BYTES` bytes that does not have
 * the temporary name's form.
 */
export function isNormalRemotePath(path: string): boolean {
  const bytes = utf8ByteLength(path);
  if (bytes === null || bytes > MAX_RENDER_PATH_BYTES) return false;
  if (!path.startsWith("/") || UNPRINTED_CHARACTER.test(path)) return false;
  const segments = path.slice(1).split("/");
  if (segments.some((segment) => segment === "" || segment === "." || segment === "..")) {
    return false;
  }
  const last = segments[segments.length - 1] as string;
  return (
    (utf8ByteLength(last) as number) <= MAX_RENDER_PATH_SEGMENT_BYTES && !isRenderTempName(last)
  );
}

/**
 * The bytes an approval's digest is taken over (design 5 § 6.1): a
 * version tag, then the host, the port, the user, the path, the host key lines
 * sorted by UTF-16 code unit with their count, and the template — each string
 * as a 4-byte big-endian length and its UTF-8 bytes, the port and the count as
 * 4-byte big-endian integers. The entry's name is not among them.
 */
export function renderEntryCanonicalBytes(
  entry: Pick<RenderEntry, "host" | "port" | "user" | "path" | "host_keys" | "template">,
): Uint8Array {
  const encoder = new TextEncoder();
  const parts: Uint8Array[] = [];
  const u32 = (value: number): void => {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value);
    parts.push(bytes);
  };
  const str = (text: string): void => {
    const bytes = encoder.encode(text);
    u32(bytes.length);
    parts.push(bytes);
  };
  str(RENDER_ENTRY_TAG);
  str(entry.host);
  u32(entry.port);
  str(entry.user);
  str(entry.path);
  const hostKeys = [...entry.host_keys].sort();
  u32(hostKeys.length);
  for (const line of hostKeys) str(line);
  str(entry.template);
  const out = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
