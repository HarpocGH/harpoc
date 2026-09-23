import { readFileSync } from "node:fs";
import { createServer } from "node:https";
import type { Server } from "node:https";
import type { AddressInfo } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { ErrorCode, MAX_HTTP_RESPONSE_BYTES } from "@harpoc/shared";
import type { AuditLogger } from "../audit/audit-logger.js";

// The fixture certificate names fixture.example.com; the partial mock pins that
// name to the loopback server (the http-injector.pinning.test.ts idiom), so the
// handshake verifies a real certificate against a real hostname.
vi.mock("./url-validator.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./url-validator.js")>();
  return {
    ...actual,
    validateUrl: vi.fn(async (urlStr: string) => {
      const url = new URL(urlStr);
      if (url.hostname === "fixture.example.com") {
        return { url, resolvedAddresses: ["127.0.0.1"] };
      }
      return actual.validateUrl(urlStr);
    }),
  };
});

import { HttpInjector } from "./http-injector.js";

const CERTS = join(dirname(fileURLToPath(import.meta.url)), "..", "__fixtures__", "certs");
const CERT_PEM = readFileSync(join(CERTS, "rsa-cert.pem"), "utf8");
const KEY_PEM = readFileSync(join(CERTS, "rsa-key.pem"), "utf8");
const SECRET = new Uint8Array(Buffer.from("tok"));

describe("HTTP private-CA pin (http.ca_pem, D2h)", () => {
  let server: Server;
  let base: string;
  const log = vi.fn();
  const injector = new HttpInjector({ log } as unknown as AuditLogger);

  beforeAll(async () => {
    server = createServer({ cert: CERT_PEM, key: KEY_PEM }, (req, res) => {
      if (req.url === "/hop") {
        res.statusCode = 302;
        res.setHeader("location", `${base}/final`);
        res.end();
        return;
      }
      if (req.url === "/big") {
        res.setHeader("content-length", String(MAX_HTTP_RESPONSE_BYTES + 1));
        res.setHeader("content-type", "application/json");
        res.end();
        return;
      }
      res.setHeader("content-type", "application/json");
      res.end('{"ok":true}');
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `https://fixture.example.com:${(server.address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  beforeEach(() => log.mockClear());

  const request = (path: string, caPem?: string) => ({
    method: "GET" as const,
    url: `${base}${path}`,
    urlAllowlist: [`${base}/*`],
    ...(caPem === undefined ? {} : { caPem }),
  });
  const lastRow = () => (log.mock.calls.at(-1)?.[0] as { detail: Record<string, unknown> }).detail;

  it("an unpinned request to the self-signed server is refused TLS_ERROR and its failed row carries no ca_pinned", async () => {
    const result = await injector.executeWithSecret(
      request("/"),
      SECRET,
      { type: "bearer" },
      "same-origin",
      "sid-1",
    );
    expect(result).toEqual({ type: "http", status: null, error: ErrorCode.TLS_ERROR });
    expect(lastRow()).toMatchObject({ context: "http", error: ErrorCode.TLS_ERROR });
    expect(lastRow()).not.toHaveProperty("ca_pinned");
  });

  it("a pinned request verifies the fixture CA, answers 200, and its secret.use row is ca_pinned", async () => {
    const result = await injector.executeWithSecret(
      request("/", CERT_PEM),
      SECRET,
      { type: "bearer" },
      "same-origin",
      "sid-1",
    );
    expect(result).toMatchObject({ type: "http", status: 200 });
    expect(lastRow()).toMatchObject({ context: "http", status: 200, ca_pinned: true });
  });

  it("the one pinned dispatcher serves the redirect hop too", async () => {
    const result = await injector.executeWithSecret(
      request("/hop", CERT_PEM),
      SECRET,
      { type: "bearer" },
      "same-origin",
      "sid-1",
    );
    expect(result).toMatchObject({ type: "http", status: 200 });
  });

  it("a pinned refusal row carries ca_pinned too (RESPONSE_TOO_LARGE)", async () => {
    await expect(
      injector.executeWithSecret(
        request("/big", CERT_PEM),
        SECRET,
        { type: "bearer" },
        "same-origin",
        "sid-1",
      ),
    ).rejects.toMatchObject({ code: ErrorCode.RESPONSE_TOO_LARGE });
    expect(lastRow()).toMatchObject({ error: ErrorCode.RESPONSE_TOO_LARGE, ca_pinned: true });
  });
});
