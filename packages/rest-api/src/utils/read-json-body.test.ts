import { Hono } from "hono";
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
