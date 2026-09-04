import { describe, expect, it } from "vitest";
import { Hono } from "hono";
import { buildAllowedHostSet } from "@harpoc/shared";
import { errorHandler } from "./error-handler.js";
import { hostAllowlistMiddleware } from "./host-allowlist.js";
import type { HarpocEnv } from "../types.js";

function app(allowed: ReadonlySet<string>): Hono<HarpocEnv> {
  const instance = new Hono<HarpocEnv>();
  instance.onError(errorHandler);
  instance.use("*", hostAllowlistMiddleware(allowed));
  instance.get("/ping", (c) => c.json({ ok: true }));
  return instance;
}

describe("hostAllowlistMiddleware (R11/D61)", () => {
  const allowed = buildAllowedHostSet("127.0.0.1", ["vault.example"]);

  it("admits an allowed Host with any port", async () => {
    expect(
      (
        await app(allowed).request("/ping", {
          headers: { host: "vault.example:3000" },
        })
      ).status,
    ).toBe(200);
    expect((await app(allowed).request("/ping", { headers: { host: "localhost" } })).status).toBe(
      200,
    );
  });

  it("refuses an unlisted Host with 421 MISDIRECTED_REQUEST, naming the parsed hostname only", async () => {
    const res = await app(allowed).request("/ping", {
      headers: { host: "evil.example:3000" },
    });
    expect(res.status).toBe(421);
    const body = (await res.json()) as { error: string; message: string };
    expect(body.error).toBe("MISDIRECTED_REQUEST");
    expect(body.message).toContain("the Host header names evil.example");
    expect(body.message).not.toContain("3000");
  });

  it("refuses an unlisted or opaque Origin when one is present", async () => {
    const res = await app(allowed).request("/ping", {
      headers: { host: "vault.example", origin: "http://evil.example" },
    });
    expect(res.status).toBe(421);
    expect(((await res.json()) as { message: string }).message).toContain(
      "the Origin header names evil.example",
    );
    const opaque = await app(allowed).request("/ping", {
      headers: { host: "vault.example", origin: "null" },
    });
    expect(opaque.status).toBe(421);
    expect(((await opaque.json()) as { message: string }).message).toContain(
      "missing or unparsable",
    );
  });
});
