import { request } from "node:http";
import type { AddressInfo } from "node:net";
import { Hono } from "hono";
import { serve } from "@hono/node-server";
import { describe, expect, it } from "vitest";
import { ErrorCode, MAX_REQUEST_BODY_BYTES } from "@harpoc/shared";
import type { Context } from "hono";
import { errorHandler } from "../middleware/error-handler.js";
import type { HarpocEnv } from "../types.js";
import { readJsonBody } from "./read-json-body.js";

function app(): Hono<HarpocEnv> {
  const a = new Hono<HarpocEnv>();
  a.onError(errorHandler);
  a.post("/echo", async (c) => c.json({ keys: Object.keys(await readJsonBody(c)) }));
  return a;
}

// `app.request` drops a hand-set content-length, so the declared-length branch
// is driven through the two fields readJsonBody reads.
function declared(contentLength: string, body: string | null): Context<HarpocEnv> {
  return {
    req: {
      raw: new Request("http://vault.test/echo", {
        method: "POST",
        headers: { "content-length": contentLength },
        body,
      }),
    },
  } as unknown as Context<HarpocEnv>;
}

const TOO_LARGE = { error: ErrorCode.INVALID_INPUT, message: "Request body too large" };
const TOO_LARGE_THROWN = { code: ErrorCode.INVALID_INPUT, message: "Request body too large" };

describe("readJsonBody — the request-body cap (P1F-7)", () => {
  it("refuses a declared Content-Length over the cap before reading", async () => {
    await expect(
      readJsonBody(declared(String(MAX_REQUEST_BODY_BYTES + 1), "{}")),
    ).rejects.toMatchObject(TOO_LARGE_THROWN);
  });

  it("a malformed Content-Length counts as exceeding (fail-closed)", async () => {
    await expect(readJsonBody(declared("abc", "{}"))).rejects.toMatchObject(TOO_LARGE_THROWN);
  });

  it("accepts a declared Content-Length of exactly the cap", async () => {
    const pad = "x".repeat(MAX_REQUEST_BODY_BYTES - '{"a":""}'.length);
    await expect(
      readJsonBody(declared(String(MAX_REQUEST_BODY_BYTES), `{"a":"${pad}"}`)),
    ).resolves.toEqual({ a: pad });
  });

  it("refuses a streamed body over the cap with the cap's message, not the framing one", async () => {
    const res = await app().request("/echo", {
      method: "POST",
      body: "x".repeat(MAX_REQUEST_BODY_BYTES + 1),
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual(TOO_LARGE);
  });

  it("accepts a streamed body of exactly the cap", async () => {
    const pad = "x".repeat(MAX_REQUEST_BODY_BYTES - '{"a":""}'.length);
    const res = await app().request("/echo", { method: "POST", body: `{"a":"${pad}"}` });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ keys: ["a"] });
  });

  it("an empty body and a malformed body keep the framing message", async () => {
    for (const body of [undefined, "{not json", "[]"]) {
      const res = await app().request("/echo", { method: "POST", body });
      expect(res.status).toBe(400);
      expect(await res.json()).toEqual({
        error: ErrorCode.SCHEMA_VALIDATION_ERROR,
        message: "Request body must be valid JSON",
      });
    }
  });

  it("a UTF-8 BOM before the JSON is stripped, as the fetch body decode did", async () => {
    const res = await app().request("/echo", { method: "POST", body: "\uFEFF" + '{"a":1}' });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ keys: ["a"] });
  });
});

function listen(): Promise<{ port: number; close: () => Promise<void> }> {
  let server: ReturnType<typeof serve> | undefined;
  return new Promise((resolve) => {
    server = serve({ fetch: app().fetch, port: 0, hostname: "127.0.0.1" }, (info: AddressInfo) =>
      resolve({
        port: info.port,
        close: () => new Promise<void>((done) => server?.close(() => done())),
      }),
    );
  });
}

function postChunked(
  port: number,
  total: number,
  pauseMs: number,
): Promise<{ status: number | undefined; body: unknown; writtenAtResponse: number }> {
  return new Promise((resolve, reject) => {
    let written = 0;
    let answered = false;
    const chunk = Buffer.alloc(65_536, 0x78);
    const req = request({ host: "127.0.0.1", port, path: "/echo", method: "POST" }, (res) => {
      answered = true;
      const writtenAtResponse = written;
      let text = "";
      res.setEncoding("utf8");
      res.on("data", (d: string) => (text += d));
      res.on("end", () =>
        resolve({ status: res.statusCode, body: JSON.parse(text), writtenAtResponse }),
      );
    });
    req.on("error", (err) => {
      if (!answered) reject(err);
    });
    void (async () => {
      while (written < total && !answered) {
        const n = Math.min(chunk.length, total - written);
        const ok = req.write(n === chunk.length ? chunk : chunk.subarray(0, n));
        written += n;
        if (!ok) await new Promise((r) => req.once("drain", r));
        if (pauseMs > 0) await new Promise((r) => setTimeout(r, pauseMs));
      }
      if (!answered) req.end();
    })().catch(reject);
  });
}

describe("readJsonBody — the cap over a real socket (P1c-30)", () => {
  it("refuses a chunked body one byte over the cap", async () => {
    const listener = await listen();
    try {
      const res = await postChunked(listener.port, MAX_REQUEST_BODY_BYTES + 1, 0);
      expect(res.status).toBe(400);
      expect(res.body).toEqual(TOO_LARGE);
    } finally {
      await listener.close();
    }
  });

  it("refuses a trickled body before the client has sent it all", { timeout: 15_000 }, async () => {
    const total = 6 * 1024 * 1024;
    const listener = await listen();
    try {
      const res = await postChunked(listener.port, total, 5);
      expect(res.status).toBe(400);
      expect(res.body).toEqual(TOO_LARGE);
      expect(res.writtenAtResponse).toBeLessThan(total);
    } finally {
      await listener.close();
    }
  });
});
