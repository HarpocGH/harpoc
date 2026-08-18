import { createHash } from "node:crypto";
import type { Server } from "node:http";
import { createServer } from "node:net";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { ErrorCode } from "@harpoc/shared";
import { Http01Solver, dns01TxtValue } from "./challenge-solver.js";

const TOKEN = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA";
const KEY_AUTHORIZATION = `${TOKEN}.mock-thumbprint-value`;

const acmeFailed = expect.objectContaining({ code: ErrorCode.CERT_ACME_FAILED });

const challengeUrl = (port: number, path: string): string => `http://127.0.0.1:${port}${path}`;

describe("Http01Solver", () => {
  let solver: Http01Solver | undefined;

  afterEach(async () => {
    await solver?.stop();
    solver = undefined;
  });

  it("serves the exact challenge path with the key authorization as text/plain", async () => {
    solver = new Http01Solver();
    const port = await solver.start(TOKEN, KEY_AUTHORIZATION, 0);
    const response = await fetch(challengeUrl(port, `/.well-known/acme-challenge/${TOKEN}`));
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("text/plain");
    expect(await response.text()).toBe(KEY_AUTHORIZATION);
  });

  it("returns 404 for a path other than the challenge path", async () => {
    solver = new Http01Solver();
    const port = await solver.start(TOKEN, KEY_AUTHORIZATION, 0);
    const response = await fetch(challengeUrl(port, "/.well-known/acme-challenge/other"));
    expect(response.status).toBe(404);
  });

  it("returns 404 for the wrong token and never leaks the key authorization in the body", async () => {
    solver = new Http01Solver();
    const port = await solver.start(TOKEN, KEY_AUTHORIZATION, 0);
    const response = await fetch(challengeUrl(port, "/.well-known/acme-challenge/wrong-token"));
    expect(response.status).toBe(404);
    const body = await response.text();
    expect(body).not.toContain(KEY_AUTHORIZATION);
  });

  it("returns 404 for a POST to the challenge path", async () => {
    solver = new Http01Solver();
    const port = await solver.start(TOKEN, KEY_AUTHORIZATION, 0);
    const response = await fetch(challengeUrl(port, `/.well-known/acme-challenge/${TOKEN}`), {
      method: "POST",
    });
    expect(response.status).toBe(404);
  });

  it("returns 404 for a HEAD request to the challenge path", async () => {
    solver = new Http01Solver();
    const port = await solver.start(TOKEN, KEY_AUTHORIZATION, 0);
    const response = await fetch(challengeUrl(port, `/.well-known/acme-challenge/${TOKEN}`), {
      method: "HEAD",
    });
    expect(response.status).toBe(404);
  });

  it("serves the challenge path with a query string, ignoring the query", async () => {
    solver = new Http01Solver();
    const port = await solver.start(TOKEN, KEY_AUTHORIZATION, 0);
    const response = await fetch(
      challengeUrl(port, `/.well-known/acme-challenge/${TOKEN}?foo=bar`),
    );
    expect(response.status).toBe(200);
    expect(await response.text()).toBe(KEY_AUTHORIZATION);
  });

  it("resolves to the OS-assigned port when started with port 0", async () => {
    solver = new Http01Solver();
    const port = await solver.start(TOKEN, KEY_AUTHORIZATION, 0);
    expect(port).toBeGreaterThan(0);
  });

  it("refuses a second start without an intervening stop", async () => {
    solver = new Http01Solver();
    await solver.start(TOKEN, KEY_AUTHORIZATION, 0);
    await expect(solver.start(TOKEN, KEY_AUTHORIZATION, 0)).rejects.toThrow(acmeFailed);
  });

  it("stop() closes the server so a subsequent fetch is refused", async () => {
    solver = new Http01Solver();
    const port = await solver.start(TOKEN, KEY_AUTHORIZATION, 0);
    await solver.stop();
    await expect(
      fetch(challengeUrl(port, `/.well-known/acme-challenge/${TOKEN}`)),
    ).rejects.toThrow();
  });

  it("stop() is a no-op when never started", async () => {
    solver = new Http01Solver();
    await expect(solver.stop()).resolves.toBeUndefined();
  });

  it("stop() is idempotent across repeated calls", async () => {
    solver = new Http01Solver();
    await solver.start(TOKEN, KEY_AUTHORIZATION, 0);
    await solver.stop();
    await expect(solver.stop()).resolves.toBeUndefined();
  });

  it("bind failure names the port but never the cause", async () => {
    const blocker = createServer();
    await new Promise<void>((resolve) => {
      blocker.listen(0, "0.0.0.0", () => resolve());
    });
    const port = (blocker.address() as AddressInfo).port;
    solver = new Http01Solver();
    try {
      // details: undefined pins the whole object, not just code/message — the
      // errno and interface are deliberately discarded (D6, 2026-08-18 tranche);
      // this key catches a future change that starts attaching a details cause.
      await expect(solver.start(TOKEN, KEY_AUTHORIZATION, port)).rejects.toMatchObject({
        code: ErrorCode.CERT_ACME_FAILED,
        message: `ACME operation failed: http-01 challenge server failed to start on port ${port}`,
        details: undefined,
      });
    } finally {
      await new Promise<void>((resolve) => {
        blocker.close(() => resolve());
      });
    }
  });

  it("removes the start-time error listener once listening, so a later server error cannot corrupt stop() or leak the socket", async () => {
    solver = new Http01Solver();
    const port = await solver.start(TOKEN, KEY_AUTHORIZATION, 0);
    const server = (solver as unknown as { server: Server }).server;
    expect(server.listenerCount("error")).toBe(0);
    // With no listener left, EventEmitter throws synchronously from emit()
    // for an unhandled "error" event; if the start-time handler were still
    // attached (the bug), this emit would be swallowed instead of throwing.
    expect(() => server.emit("error", new Error("simulated post-listen error"))).toThrow();
    await solver.stop();
    await expect(
      fetch(challengeUrl(port, `/.well-known/acme-challenge/${TOKEN}`)),
    ).rejects.toThrow();
  });
});

describe("dns01TxtValue", () => {
  it("matches base64url(SHA-256(keyAuthorization)) per RFC 8555 §8.4", () => {
    const keyAuthorization = `${TOKEN}.mock-thumbprint-value`;
    const expected = createHash("sha256").update(keyAuthorization).digest("base64url");
    expect(dns01TxtValue(keyAuthorization)).toBe(expected);
  });

  it("is 43 characters with no base64 padding", () => {
    const value = dns01TxtValue(KEY_AUTHORIZATION);
    expect(value).toHaveLength(43);
    expect(value).not.toContain("=");
  });
});
