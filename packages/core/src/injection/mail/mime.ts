import { randomBytes, randomUUID } from "node:crypto";

export interface MimeAttachment {
  filename: string;
  contentType: string;
  data: Buffer;
}

/**
 * Input to {@link assembleMessage}. `bcc` is deliberately absent — bcc
 * recipients go to the SMTP envelope only (the injector's job), never into
 * the assembled message headers.
 */
export interface MimeInput {
  from: string;
  to: string[];
  cc?: string[];
  subject: string;
  text?: string;
  html?: string;
  attachments?: MimeAttachment[];
  extraHeaders?: Record<string, string>;
}

const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"] as const;
const MONTHS = [
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
] as const;

// Header names this module writes itself. extraHeaders may not set any of
// these — the module's own invariant (bcc never becomes a header line; the
// SMTP envelope is the only bcc channel) must hold regardless of what a
// caller passes, not just because an upstream schema happens to filter it.
const RESERVED_HEADER_NAMES = new Set([
  "from",
  "to",
  "cc",
  "bcc",
  "subject",
  "date",
  "message-id",
  "mime-version",
  "content-type",
]);

const MAX_HEADER_LINE = 78;
// Bytes per RFC 2047 encoded-word chunk. Kept well under the 75-octet
// encoded-word cap so "Name: " plus the first chunk, and a single leading
// fold space plus any later chunk, both stay under MAX_HEADER_LINE for any
// header name used in this module.
const ENCODED_CHUNK_BYTE_LIMIT = 30;
const BASE64_LINE_WIDTH = 76;

function toCrlf(text: string): string {
  return text.replace(/\r\n/g, "\n").replace(/\r/g, "\n").replace(/\n/g, "\r\n");
}

function isAsciiSafe(value: string): boolean {
  // Printable ASCII only — excludes CR, LF, TAB, other controls and any
  // non-ASCII byte. A value failing this is header-injection-encoded below
  // rather than written raw.
  return /^[\x20-\x7E]*$/.test(value);
}

function encodeWords(value: string): string {
  const chunks: string[] = [];
  let current = "";
  let currentBytes = 0;
  for (const ch of value) {
    const chBytes = Buffer.byteLength(ch, "utf8");
    if (currentBytes + chBytes > ENCODED_CHUNK_BYTE_LIMIT && current.length > 0) {
      chunks.push(current);
      current = "";
      currentBytes = 0;
    }
    current += ch;
    currentBytes += chBytes;
  }
  if (current.length > 0) {
    chunks.push(current);
  }
  return chunks
    .map((chunk) => `=?utf-8?B?${Buffer.from(chunk, "utf8").toString("base64")}?=`)
    .join("\r\n ");
}

function foldPlain(name: string, value: string): string {
  const words = value.length === 0 ? [] : value.split(" ");
  const lines: string[] = [];
  let current = `${name}:`;
  for (const word of words) {
    const candidate = `${current} ${word}`;
    if (candidate.length > MAX_HEADER_LINE && current !== `${name}:`) {
      lines.push(current);
      current = ` ${word}`;
    } else {
      current = candidate;
    }
  }
  lines.push(current);
  return lines.map((line) => `${line}\r\n`).join("");
}

/**
 * Renders one header field, CRLF-terminated (possibly folded across several
 * physical lines). Any value containing CR/LF or a non-ASCII byte is RFC 2047
 * encoded-worded rather than written raw — this is the header-injection
 * defense: an attacker-controlled value (e.g. an agent-supplied subject)
 * cannot smuggle a second header line into the message.
 */
function buildHeader(name: string, rawValue: string): string {
  if (isAsciiSafe(rawValue)) {
    return foldPlain(name, rawValue);
  }
  return `${name}: ${encodeWords(rawValue)}\r\n`;
}

function sanitizeHeaderName(name: string): string {
  return name.replace(/[\r\n:]+/g, "");
}

function sanitizeFilenameForHeader(filename: string): string {
  return filename
    .replace(/[\r\n]+/g, " ")
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"');
}

function sanitizeContentTypeForHeader(contentType: string): string {
  // A content-type is a structured ASCII token (RFC 2045 §5.1), not free
  // text — it doesn't support RFC 2047 encoded-words as a bare value, so
  // unlike buildHeader's other values this is neutralized by stripping
  // rather than encoding. Anything outside printable ASCII (CR/LF, other
  // controls, non-ASCII) is dropped, so a value like
  // "text/plain\r\nX-Injected: evil" can never terminate the line and start
  // a second header.
  return contentType.replace(/[^\x20-\x7E]/g, "");
}

function formatRfc5322Date(date: Date): string {
  const day = DAYS[date.getUTCDay()] as string;
  const dd = String(date.getUTCDate()).padStart(2, "0");
  const mon = MONTHS[date.getUTCMonth()] as string;
  const yyyy = date.getUTCFullYear();
  const hh = String(date.getUTCHours()).padStart(2, "0");
  const mm = String(date.getUTCMinutes()).padStart(2, "0");
  const ss = String(date.getUTCSeconds()).padStart(2, "0");
  return `${day}, ${dd} ${mon} ${yyyy} ${hh}:${mm}:${ss} +0000`;
}

function generateBoundary(): string {
  return `----=_Part_${randomBytes(16).toString("hex")}`;
}

function renderSimplePart(contentType: string, body: string): string {
  return (
    `Content-Type: ${contentType}\r\n` +
    `Content-Transfer-Encoding: 8bit\r\n` +
    `\r\n` +
    toCrlf(body)
  );
}

function wrapPart(boundary: string, part: string): string {
  return `--${boundary}\r\n${part}\r\n`;
}

function buildAlternativeBody(boundary: string, text: string, html: string): string {
  const textPart = renderSimplePart("text/plain; charset=utf-8", text);
  const htmlPart = renderSimplePart("text/html; charset=utf-8", html);
  return wrapPart(boundary, textPart) + wrapPart(boundary, htmlPart) + `--${boundary}--\r\n`;
}

function wrapBase64(b64: string, width: number): string {
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += width) {
    lines.push(b64.slice(i, i + width));
  }
  return lines.join("\r\n");
}

function renderAttachmentPart(attachment: MimeAttachment): string {
  const safeName = sanitizeFilenameForHeader(attachment.filename);
  const safeContentType = sanitizeContentTypeForHeader(attachment.contentType);
  const encoded = wrapBase64(attachment.data.toString("base64"), BASE64_LINE_WIDTH);
  return (
    `Content-Type: ${safeContentType}; name="${safeName}"\r\n` +
    `Content-Transfer-Encoding: base64\r\n` +
    `Content-Disposition: attachment; filename="${safeName}"\r\n` +
    `\r\n` +
    encoded
  );
}

/**
 * Builds an RFC 5322 message: text-only is a single `text/plain` part;
 * text+html is `multipart/alternative` (text part first); attachments add an
 * outer `multipart/mixed` wrapping that alternative (or the single text/html
 * part) followed by the base64 attachment parts. CRLF line endings
 * throughout, crypto-random boundaries and Message-ID. Dot-stuffing is
 * deliberately NOT performed here — that is the SMTP client's job (Task 7);
 * a body line beginning with "." survives this function verbatim.
 */
export function assembleMessage(input: MimeInput): { message: string; messageId: string } {
  const messageId = `<${randomUUID()}@harpoc.local>`;

  const headerLines: string[] = [
    buildHeader("From", input.from),
    buildHeader("To", input.to.join(", ")),
  ];
  if (input.cc && input.cc.length > 0) {
    headerLines.push(buildHeader("Cc", input.cc.join(", ")));
  }
  headerLines.push(buildHeader("Subject", input.subject));
  headerLines.push(buildHeader("Date", formatRfc5322Date(new Date())));
  headerLines.push(`Message-ID: ${messageId}\r\n`);
  headerLines.push(`MIME-Version: 1.0\r\n`);
  if (input.extraHeaders) {
    for (const [key, value] of Object.entries(input.extraHeaders)) {
      const sanitizedKey = sanitizeHeaderName(key);
      if (RESERVED_HEADER_NAMES.has(sanitizedKey.toLowerCase())) {
        throw new Error(
          `extraHeaders may not set reserved header "${sanitizedKey}" — use the dedicated MimeInput field, or the SMTP envelope for bcc`,
        );
      }
      headerLines.push(buildHeader(sanitizedKey, value));
    }
  }

  const attachments = input.attachments ?? [];
  const hasText = input.text !== undefined;
  const hasHtml = input.html !== undefined;

  let contentPart: string;
  if (hasText && hasHtml) {
    const altBoundary = generateBoundary();
    contentPart =
      `Content-Type: multipart/alternative; boundary="${altBoundary}"\r\n\r\n` +
      buildAlternativeBody(altBoundary, input.text as string, input.html as string);
  } else if (hasHtml) {
    contentPart = renderSimplePart("text/html; charset=utf-8", input.html as string);
  } else {
    contentPart = renderSimplePart("text/plain; charset=utf-8", input.text ?? "");
  }

  let bodySection: string;
  if (attachments.length > 0) {
    const outerBoundary = generateBoundary();
    const parts = [
      contentPart,
      ...attachments.map((attachment) => renderAttachmentPart(attachment)),
    ];
    const mixedBody =
      parts.map((part) => wrapPart(outerBoundary, part)).join("") + `--${outerBoundary}--\r\n`;
    bodySection = `Content-Type: multipart/mixed; boundary="${outerBoundary}"\r\n\r\n${mixedBody}`;
  } else {
    bodySection = contentPart;
  }

  return { message: headerLines.join("") + bodySection, messageId };
}
