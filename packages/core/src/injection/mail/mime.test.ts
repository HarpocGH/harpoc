import { describe, expect, it } from "vitest";
import type { MimeInput } from "./mime.js";
import { assembleMessage } from "./mime.js";

// Test-only helpers: unfold and (where present) RFC 2047-decode a header so
// assertions can check the *value* independent of the specific fold points
// assembleMessage chose.

function extractHeaderLines(message: string, name: string): string[] {
  const lines = message.split("\r\n");
  const prefix = `${name}:`.toLowerCase();
  const collected: string[] = [];
  let collecting = false;
  for (const line of lines) {
    if (line === "") break;
    if (collecting && (line.startsWith(" ") || line.startsWith("\t"))) {
      collected.push(line);
      continue;
    }
    collecting = false;
    if (line.toLowerCase().startsWith(prefix)) {
      collected.push(line);
      collecting = true;
    }
  }
  return collected;
}

function extractHeaderValue(message: string, name: string): string {
  const lines = extractHeaderLines(message, name);
  if (lines.length === 0) return "";
  const first = lines[0] as string;
  const rest = lines.slice(1);
  const prefixLen = `${name}:`.length;
  return (first.slice(prefixLen) + rest.join("")).trim();
}

function decodeEncodedWordHeader(value: string): string {
  const matches = [...value.matchAll(/=\?utf-8\?B\?([A-Za-z0-9+/=]+)\?=/gi)];
  if (matches.length === 0) return value;
  const buffers = matches.map((m) => Buffer.from(m[1] as string, "base64"));
  return Buffer.concat(buffers).toString("utf8");
}

describe("assembleMessage", () => {
  it("(a) text-only message: single part, no multipart, CRLF-only line endings", () => {
    const { message } = assembleMessage({
      from: "alice@example.com",
      to: ["bob@example.com"],
      subject: "Hello",
      text: "Hello world.\nSecond line.",
    });

    expect(message).toContain("Content-Type: text/plain; charset=utf-8");
    expect(message).not.toMatch(/multipart/);
    // No bare LF anywhere — every line ending is CRLF.
    expect(/(?<!\r)\n/.test(message)).toBe(false);
  });

  it("(b) text+html: multipart/alternative with the text part first", () => {
    const { message } = assembleMessage({
      from: "alice@example.com",
      to: ["bob@example.com"],
      subject: "Hi",
      text: "plain body",
      html: "<p>html body</p>",
    });

    expect(message).toContain("Content-Type: multipart/alternative");
    const textIdx = message.indexOf("text/plain");
    const htmlIdx = message.indexOf("text/html");
    expect(textIdx).toBeGreaterThan(-1);
    expect(htmlIdx).toBeGreaterThan(-1);
    expect(textIdx).toBeLessThan(htmlIdx);
  });

  it("(c) attachments: outer multipart/mixed wraps the alternative, base64 wrapped at 76 cols and round-trips", () => {
    const fileData = Buffer.from("attachment payload ".repeat(20), "utf8");
    const { message } = assembleMessage({
      from: "alice@example.com",
      to: ["bob@example.com"],
      subject: "With attachment",
      text: "plain",
      html: "<p>html</p>",
      attachments: [{ filename: "notes.txt", contentType: "text/plain", data: fileData }],
    });

    expect(message).toContain("Content-Type: multipart/mixed");
    expect(message).toContain("Content-Type: multipart/alternative");
    expect(message).toContain('Content-Disposition: attachment; filename="notes.txt"');

    const dispositionIdx = message.indexOf('Content-Disposition: attachment; filename="notes.txt"');
    const afterDisposition = message.slice(dispositionIdx);
    const bodyStart = afterDisposition.indexOf("\r\n\r\n") + 4;
    const nextBoundary = afterDisposition.indexOf("\r\n--", bodyStart);
    const rawB64Section = afterDisposition.slice(bodyStart, nextBoundary);
    const b64Lines = rawB64Section.split("\r\n");

    expect(b64Lines.length).toBeGreaterThan(1);
    for (const line of b64Lines) {
      expect(line.length).toBeLessThanOrEqual(76);
    }

    const decoded = Buffer.from(b64Lines.join(""), "base64");
    expect(decoded.equals(fileData)).toBe(true);
  });

  it("(d) a non-ASCII subject is RFC 2047 encoded-word and decodes back to the original", () => {
    const subject = "Grüße ✓";
    const { message } = assembleMessage({
      from: "alice@example.com",
      to: ["bob@example.com"],
      subject,
      text: "body",
    });

    const rawValue = extractHeaderValue(message, "Subject");
    expect(rawValue).toMatch(/^=\?utf-8\?B\?/i);
    expect(decodeEncodedWordHeader(rawValue)).toBe(subject);
  });

  it("(e) a long ASCII subject folds across multiple lines, each under 78 chars", () => {
    const subject =
      "This is a deliberately long subject line intended to exceed the seventy eight character per line limit imposed by RFC 5322 several times over";
    const { message } = assembleMessage({
      from: "alice@example.com",
      to: ["bob@example.com"],
      subject,
      text: "body",
    });

    const lines = extractHeaderLines(message, "Subject");
    expect(lines.length).toBeGreaterThan(1);
    for (const line of lines) {
      expect(line.length).toBeLessThanOrEqual(78);
    }
    expect(extractHeaderValue(message, "Subject")).toBe(subject);
  });

  it("(f) two calls produce different boundaries and Message-IDs", () => {
    const input: MimeInput = {
      from: "alice@example.com",
      to: ["bob@example.com"],
      subject: "Same input",
      text: "plain",
      html: "<p>html</p>",
    };
    const first = assembleMessage(input);
    const second = assembleMessage(input);

    expect(first.messageId).not.toBe(second.messageId);

    const boundaryOf = (msg: string): string => {
      const m = /boundary="([^"]+)"/.exec(msg);
      return m ? (m[1] as string) : "";
    };
    expect(boundaryOf(first.message)).not.toBe("");
    expect(boundaryOf(first.message)).not.toBe(boundaryOf(second.message));
  });

  it("(g) a CRLF-injecting subject arrives encoded, never as a raw header line", () => {
    const malicious = "x\r\nBcc: e@vil";
    const { message } = assembleMessage({
      from: "alice@example.com",
      to: ["bob@example.com"],
      subject: malicious,
      text: "body",
    });

    expect(/^Bcc:/m.test(message)).toBe(false);
    const decoded = decodeEncodedWordHeader(extractHeaderValue(message, "Subject"));
    expect(decoded).toBe(malicious);
  });

  it("(h) dot-stuffing is not applied — a body line of exactly '.' survives verbatim", () => {
    const text = "Before\n.\nAfter";
    const { message } = assembleMessage({
      from: "alice@example.com",
      to: ["bob@example.com"],
      subject: "Dot test",
      text,
    });

    expect(message).toContain("Before\r\n.\r\nAfter");
  });

  it("(i) a CRLF-injecting attachment contentType arrives neutralized, never as a raw header line", () => {
    const { message } = assembleMessage({
      from: "alice@example.com",
      to: ["bob@example.com"],
      subject: "Attachment contentType injection",
      text: "body",
      attachments: [
        {
          filename: "notes.txt",
          contentType: "text/plain\r\nX-Injected: evil",
          data: Buffer.from("data", "utf8"),
        },
      ],
    });

    expect(/^X-Injected:/m.test(message)).toBe(false);
    expect(/(?<!\r)\n/.test(message)).toBe(false);
  });

  it("(j) extraHeaders rejects a reserved header name (e.g. Bcc) without leaking the value", () => {
    let caught: unknown;
    try {
      assembleMessage({
        from: "alice@example.com",
        to: ["bob@example.com"],
        subject: "Reserved header test",
        text: "body",
        extraHeaders: { Bcc: "x@evil.com" },
      });
    } catch (err) {
      caught = err;
    }

    expect(caught).toBeInstanceOf(Error);
    const message = (caught as Error).message;
    expect(message).toMatch(/bcc/i);
    expect(message).not.toContain("x@evil.com");
  });

  it("(k) an extraHeaders value with a CRLF injection arrives encoded, never as a raw header line", () => {
    const malicious = "a\r\nBcc: evil";
    const { message } = assembleMessage({
      from: "alice@example.com",
      to: ["bob@example.com"],
      subject: "Extra header injection",
      text: "body",
      extraHeaders: { "X-Test": malicious },
    });

    expect(/^Bcc:/m.test(message)).toBe(false);
    const decoded = decodeEncodedWordHeader(extractHeaderValue(message, "X-Test"));
    expect(decoded).toBe(malicious);
  });
});
