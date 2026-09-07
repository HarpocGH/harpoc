import type { AddressInfo } from "node:net";
import { describe, expect, it, vi } from "vitest";
import { Hono } from "hono";
import { serve } from "@hono/node-server";
import type { VaultApiToken } from "@harpoc/shared";
import type { HarpocEnv } from "../types.js";
import { callerOf, socketPeer } from "./caller.js";
import { isConnectionRefused, isIpv6BindUnavailable } from "@harpoc/test-utils";

const TOKEN: VaultApiToken = {
  sub: "test-agent",
  vault_id: "vault-1",
  scope: ["read", "list"],
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
  jti: "jti-1",
  principal_type: "agent",
};

function peerApp(): Hono<HarpocEnv> {
  const app = new Hono<HarpocEnv>();
  app.use("*", async (c, next) => {
    c.set("token", TOKEN);
    const peer = socketPeer(c);
    if (peer !== undefined) c.set("remoteAddress", peer);
    await next();
  });
  app.get("/peer", (c) => c.json({ peer: socketPeer(c) ?? null, caller: callerOf(c) }));
  return app;
}

describe("socketPeer / callerOf (E75i)", () => {
  it("is undefined under app.request — no connection, a NULL ip_address", async () => {
    const res = await peerApp().request("/peer", {
      headers: { "x-forwarded-for": "203.0.113.9" },
    });
    expect(await res.json()).toEqual({
      peer: null,
      caller: {
        principal_type: "agent",
        principal_id: "test-agent",
        interface: "rest",
      },
    });
  });

  it("is the socket peer off a real listener — never the forwarded header", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const app = peerApp();
    let server: ReturnType<typeof serve> | undefined;
    const port = await new Promise<number>((resolve) => {
      server = serve({ fetch: app.fetch, port: 0, hostname: "127.0.0.1" }, (info: AddressInfo) =>
        resolve(info.port),
      );
    });
    try {
      const res = await fetch(`http://127.0.0.1:${port}/peer`, {
        headers: { "x-forwarded-for": "203.0.113.9" },
      });
      expect(await res.json()).toEqual({
        peer: "127.0.0.1",
        caller: {
          principal_type: "agent",
          principal_id: "test-agent",
          interface: "rest",
          remote_address: "127.0.0.1",
        },
      });
    } finally {
      await new Promise<void>((resolve) => server?.close(() => resolve()));
    }
  });

  /**
   * A dual-stack listener (`::`) reports an IPv4 peer as `::ffff:127.0.0.1`
   * (D9): one client would then occupy two `audit_log.ip_address` values
   * depending on which address the operator bound. Null where the host has no
   * IPv6 stack (the bind refuses EAFNOSUPPORT / EADDRNOTAVAIL), or binds `::`
   * v6-only (the IPv4 connect is refused), so the shape cannot arise at all —
   * and only there: any other failure is the test's to report (R6,
   * 2026-09-07). `fetchImpl` is the seam for the pin that says so.
   */
  async function dualStackPeerBody(fetchImpl: typeof fetch = fetch): Promise<unknown | null> {
    const app = peerApp();
    let server: ReturnType<typeof serve> | undefined;
    try {
      let port: number;
      try {
        port = await new Promise<number>((resolve, reject) => {
          const started = serve(
            { fetch: app.fetch, port: 0, hostname: "::" },
            (info: AddressInfo) => resolve(info.port),
          );
          server = started;
          started.once("error", reject);
        });
      } catch (err) {
        if (!isIpv6BindUnavailable(err)) throw err;
        return null;
      }
      let res: Response;
      try {
        res = await fetchImpl(`http://127.0.0.1:${String(port)}/peer`);
      } catch (err) {
        if (!isConnectionRefused(err)) throw err;
        return null;
      }
      return await res.json();
    } finally {
      const started = server;
      if (started !== undefined) {
        await new Promise<void>((resolve) => started.close(() => resolve()));
      }
    }
  }

  it("records a dual-stack IPv4 peer in dotted form (D9)", async (ctx) => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const body = await dualStackPeerBody();
    if (body === null) return ctx.skip();
    expect(body).toEqual({
      peer: "127.0.0.1",
      caller: {
        principal_type: "agent",
        principal_id: "test-agent",
        interface: "rest",
        remote_address: "127.0.0.1",
      },
    });
  });

  // A post-bind failure is a failure, not a skip: the helper's tolerant
  // catches are gated on the two host conditions the docblock names, and
  // nothing else (R6, 2026-09-07).
  it("a failure after the bind rejects instead of skipping", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    await expect(dualStackPeerBody(() => Promise.reject(new Error("boom")))).rejects.toThrow(
      "boom",
    );
  });
});
